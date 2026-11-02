"""What a MySQL session reports about itself. Tier 0: a fake cursor answers
the reads with rows in the shape MySQL 8.4.13 gave through PyMySQL 1.2.3, and
fails as MariaDB 10.11.19 did on a setting it lacks."""

from __future__ import annotations

from typing import Any

import pytest

from sopuli.driver.mysql import grants
from sopuli.driver.mysql.scope import (
    NO_ROW_HINT,
    READ_ONLY,
    READ_ONLY_SETTINGS,
    READ_WRITE,
    TLS_VERSION,
    UNENCRYPTED_HINT,
    VERSION,
    NotMysqlError,
    ReadOnlyTargetError,
    SystemUserError,
    observe,
    require_read_write,
)
from sopuli.driver.protocol import ADMIN_REFUSED, ENCRYPTION_NONE, ENCRYPTION_TLS, SERVER, UNKNOWN
from sopuli.exit_codes import ExitCode


class UnknownVariableError(Exception):
    """MariaDB's answer to `@@super_read_only`: `1193`."""


#: What 8.4.13 printed for an account with only `CREATE USER`.
OWN_LINES = ("GRANT CREATE USER ON *.* TO `sopuli_admin`@`%`",)


class FakeCursor:
    def __init__(
        self,
        version: str,
        flags: tuple[int, int, int],
        tls: str | None,
        *,
        roles: tuple[tuple[str, str], ...] = (),
        lines: tuple[str, ...] = OWN_LINES,
    ) -> None:
        self.version = version
        self.answers: dict[str, Any] = {
            VERSION: (version,),
            READ_ONLY_SETTINGS: flags,
            TLS_VERSION: None if tls is None else ("Ssl_version", tls),
        }
        self.roles = roles
        self.lines = lines
        self.last: str | None = None
        self.queries: list[tuple[str, Any]] = []

    def execute(self, query: Any, args: Any = None, /) -> None:
        if query == READ_ONLY_SETTINGS and "MariaDB" in self.version:
            raise UnknownVariableError(1193, "Unknown system variable 'super_read_only'")
        self.last = query
        self.queries.append((query, args))

    def fetchone(self) -> Any:
        assert self.last is not None
        return self.answers[self.last]

    def fetchall(self) -> Any:
        assert self.last is not None
        if self.last == grants.DIRECT_ROLES:
            return list(self.roles)
        assert self.last.startswith("show grants")
        return [(line,) for line in self.lines]


def _observe(
    version: str = "8.4.13",
    flags: tuple[int, int, int] = (0, 0, 0),
    tls: str | None = "TLSv1.3",
    **grant_rows: Any,
) -> Any:
    return observe(FakeCursor(version, flags, tls, **grant_rows), target="mysql-dev")


def test_a_writable_server_over_tls() -> None:
    scope = _observe()

    assert scope.type == SERVER
    assert scope.db_version == "8.4.13"
    assert scope.open_mode == READ_WRITE
    assert scope.read_write is True
    assert scope.encryption.method == ENCRYPTION_TLS
    assert scope.encryption.protocol == "tcp"
    assert scope.capabilities == frozenset()


def test_a_version_suffix_is_not_reported() -> None:
    assert _observe(version="8.0.46-log").db_version == "8.0.46"


@pytest.mark.parametrize("flags", [(1, 0, 0), (0, 1, 0), (0, 0, 1)])
def test_each_read_only_setting_makes_the_session_read_only(flags: tuple[int, int, int]) -> None:
    """`read_only`, `super_read_only` and the session's `transaction_read_only`."""
    scope = _observe(flags=flags)

    assert scope.open_mode == READ_ONLY
    assert scope.read_write is False


def test_a_plain_connection_is_unencrypted_and_says_what_to_set() -> None:
    """An empty `Ssl_version` is a plain connection."""
    encryption = _observe(tls="").encryption

    assert encryption.method == ENCRYPTION_NONE
    assert encryption.hint == UNENCRYPTED_HINT


def test_no_ssl_version_row_is_unknown_not_unencrypted() -> None:
    encryption = _observe(tls=None).encryption

    assert encryption.method == UNKNOWN
    assert encryption.hint == NO_ROW_HINT


@pytest.mark.parametrize(
    ("version", "product"),
    [("10.11.19-MariaDB-ubu2204", "MariaDB"), ("8.0.11-TiDB-v7.5.0", "TiDB")],
)
def test_another_product_is_refused_before_its_settings_are_read(
    version: str, product: str
) -> None:
    """The fake fails on the settings query for MariaDB, as 10.11.19 does, so
    the refusal must come from the version alone."""
    with pytest.raises(NotMysqlError) as caught:
        _observe(version=version)

    assert caught.value.category == "config"
    assert caught.value.exit_code == ExitCode.CONFIG_INVALID
    assert f'declares type "mysql", and the server is {product}' in str(caught.value)


def test_an_account_with_system_user_is_refused_before_the_settings_are_read() -> None:
    cursor = FakeCursor(
        "8.4.13",
        (0, 0, 0),
        "TLSv1.3",
        lines=(
            "GRANT CREATE USER ON *.* TO `sopuli_admin`@`%`",
            "GRANT BACKUP_ADMIN,SYSTEM_USER ON *.* TO `sopuli_admin`@`%`",
        ),
    )

    with pytest.raises(SystemUserError) as refused:
        observe(cursor, target="mysql-dev")

    assert refused.value.code == ADMIN_REFUSED
    assert refused.value.category == "config"
    assert refused.value.exit_code == ExitCode.CONFIG_INVALID
    assert str(refused.value).startswith(
        'target "mysql-dev" connects as an account that can use SYSTEM_USER'
    )
    assert READ_ONLY_SETTINGS not in [query for query, _ in cursor.queries]


def test_system_user_through_a_role_that_is_not_active_is_refused() -> None:
    """Every role granted to the account is named in `USING`, so the server
    expands one that is not active, as 8.0.46, 8.4.13 and 9.7.4 did."""
    cursor = FakeCursor(
        "8.4.13",
        (0, 0, 0),
        "TLSv1.3",
        roles=(("acme_ops", "%"), ("acme_ro", "%")),
        lines=(
            "GRANT CREATE USER ON *.* TO `sopuli_admin`@`%`",
            "GRANT SYSTEM_USER ON *.* TO `sopuli_admin`@`%`",
            "GRANT `acme_ops`@`%`,`acme_ro`@`%` TO `sopuli_admin`@`%`",
        ),
    )

    with pytest.raises(SystemUserError):
        observe(cursor, target="mysql-dev")

    assert (
        grants.GRANTS_USING.format(roles="%s@%s, %s@%s"),
        ["acme_ops", "%", "acme_ro", "%"],
    ) in cursor.queries


def test_an_account_with_no_role_reads_its_own_grants() -> None:
    cursor = FakeCursor("8.4.13", (0, 0, 0), "TLSv1.3")

    observe(cursor, target="mysql-dev")

    assert (grants.OWN_GRANTS, None) in cursor.queries


def test_a_write_on_a_read_only_session_is_refused_before_anything_is_sent() -> None:
    with pytest.raises(ReadOnlyTargetError, match="READ ONLY and cannot be written to"):
        require_read_write(_observe(flags=(0, 1, 0)), target="mysql-dev")


def test_a_writable_session_passes() -> None:
    require_read_write(_observe(), target="mysql-dev")
