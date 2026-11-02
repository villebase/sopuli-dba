"""What a MySQL session reports about itself. Tier 0: a fake cursor answers
the reads with rows in the shape MySQL 8.4.13 gave through PyMySQL 1.2.3, and
fails as MariaDB 10.11.19 did on a setting it lacks."""

from __future__ import annotations

from typing import Any

import pytest

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
    observe,
    require_read_write,
)
from sopuli.driver.protocol import ENCRYPTION_NONE, ENCRYPTION_TLS, SERVER, UNKNOWN
from sopuli.exit_codes import ExitCode


class UnknownVariableError(Exception):
    """MariaDB's answer to `@@super_read_only`: `1193`."""


class FakeCursor:
    def __init__(self, version: str, flags: tuple[int, int, int], tls: str | None) -> None:
        self.version = version
        self.answers: dict[str, Any] = {
            VERSION: (version,),
            READ_ONLY_SETTINGS: flags,
            TLS_VERSION: None if tls is None else ("Ssl_version", tls),
        }
        self.last: str | None = None

    def execute(self, query: Any, args: Any = None, /) -> None:
        if query == READ_ONLY_SETTINGS and "MariaDB" in self.version:
            raise UnknownVariableError(1193, "Unknown system variable 'super_read_only'")
        self.last = query

    def fetchone(self) -> Any:
        assert self.last is not None
        return self.answers[self.last]


def _observe(
    version: str = "8.4.13",
    flags: tuple[int, int, int] = (0, 0, 0),
    tls: str | None = "TLSv1.3",
) -> Any:
    return observe(FakeCursor(version, flags, tls), target="mysql-dev")


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


def test_a_write_on_a_read_only_session_is_refused_before_anything_is_sent() -> None:
    with pytest.raises(ReadOnlyTargetError, match="READ ONLY and cannot be written to"):
        require_read_write(_observe(flags=(0, 1, 0)), target="mysql-dev")


def test_a_writable_session_passes() -> None:
    require_read_write(_observe(), target="mysql-dev")
