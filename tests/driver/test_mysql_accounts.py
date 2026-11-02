"""Reading MySQL accounts. Tier 0: a fake cursor answers `mysql.user` reads with
rows in the shape PyMySQL 1.2.3 gave on 8.4.13, where `account_locked` and
`password_expired` came back as strings."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from sopuli.driver.mysql.accounts import (
    EXPIRED,
    EXPIRED_AND_LOCKED,
    NO_CHANGE_DATE,
    OPEN,
    OTHER_PLUGIN_HINT,
    ROWS_FOR_USER,
    BareAccountError,
    OtherPluginError,
    describe,
    same_host,
    split,
    survey,
)
from sopuli.exit_codes import ExitCode

CHANGED = datetime(2026, 10, 1, 12, 0, 0)
#: Before the 90-day lifetime runs out.
NOW = datetime(2026, 11, 2, tzinfo=UTC)


def _row(
    user: str = "acme_app",
    host: str = "10.%",
    plugin: str = "caching_sha2_password",
    locked: str = "N",
    expired: str = "N",
    changed: datetime | None = CHANGED,
    lifetime: int | None = None,
) -> tuple[Any, ...]:
    return (user, host, plugin, locked, expired, changed, lifetime)


class _Cursor:
    def __init__(self, rows: list[tuple[Any, ...]]) -> None:
        self.rows = rows
        self.calls: list[tuple[str, Any]] = []
        self._user = ""

    def execute(self, query: Any, args: Any = None, /) -> None:
        assert query == ROWS_FOR_USER
        self.calls.append((query, args))
        self._user = args[0]

    def fetchone(self) -> Any:
        raise AssertionError("not used")

    def fetchall(self) -> Any:
        # As the server: User's collation is binary and pads with spaces, so
        # case counts and trailing spaces do not.
        return [row for row in self.rows if _decoded(row[0]).rstrip() == self._user.rstrip()]


def _decoded(value: Any) -> Any:
    return value.decode("utf-8") if isinstance(value, bytes) else value


def test_split_at_the_last_at_sign() -> None:
    assert split("acme_app@10.%") == ("acme_app", "10.%")
    assert split("ops@acme@localhost") == ("ops@acme", "localhost")


@pytest.mark.parametrize("bare", ["acme_app", "acme_app@", "@10.%"])
def test_a_bare_name_is_a_config_error(bare: str) -> None:
    with pytest.raises(BareAccountError) as caught:
        split(bare)

    assert caught.value.exit_code == ExitCode.CONFIG_INVALID


def test_describe_reads_the_account_by_user_and_host() -> None:
    cursor = _Cursor([_row(), _row(host="localhost", locked="Y")])

    state = describe(cursor, "acme_app@10.%", target="mysql-dev", now=NOW)

    assert state is not None
    assert state.name == "acme_app@10.%"
    assert state.status == OPEN
    assert state.locked is False
    assert state.password_changed_at == CHANGED.replace(tzinfo=UTC)
    assert state.password_expires_at is None
    assert state.failed_logins is None
    assert cursor.calls == [(ROWS_FOR_USER, ("acme_app",))]


def test_the_host_compares_without_case_and_the_name_is_the_servers() -> None:
    cursor = _Cursor([_row(host="db.example.com")])

    state = describe(cursor, "acme_app@DB.example.com", target="mysql-dev")

    assert state is not None
    assert state.name == "acme_app@db.example.com"


def test_the_user_name_compares_exactly() -> None:
    cursor = _Cursor([_row(user="Acme_App")])

    assert describe(cursor, "acme_app@10.%", target="mysql-dev", now=NOW) is None


def test_a_locked_expired_account_with_a_lifetime() -> None:
    cursor = _Cursor([_row(locked="Y", expired="Y", lifetime=90)])

    state = describe(cursor, "acme_app@10.%", target="mysql-dev", now=NOW)

    assert state is not None
    assert state.status == EXPIRED_AND_LOCKED
    assert state.deliberately_locked is True
    assert state.expired is True
    assert state.password_expires_at == datetime(2026, 12, 30, 12, 0, 0, tzinfo=UTC)


def test_bytes_columns_are_read_as_text_and_no_change_date_is_said() -> None:
    cursor = _Cursor([(b"acme_app", b"10.%", b"caching_sha2_password", b"N", b"N", None, 0)])

    state = describe(cursor, "acme_app@10.%", target="mysql-dev", now=NOW)

    assert state is not None
    assert state.password_changed_unknown == NO_CHANGE_DATE
    assert state.password_expires_at is None


def test_a_system_account_is_vendor_maintained() -> None:
    cursor = _Cursor([_row(user="mysql.sys", host="localhost")])

    state = describe(cursor, "mysql.sys@localhost", target="mysql-dev")

    assert state is not None
    assert state.vendor_maintained is True


def test_another_plugin_is_refused_naming_it() -> None:
    cursor = _Cursor([_row(plugin="mysql_native_password")])

    with pytest.raises(OtherPluginError) as caught:
        describe(cursor, "acme_app@10.%", target="mysql-dev", now=NOW)

    assert caught.value.exit_code == ExitCode.CONFIG_INVALID
    assert str(caught.value).startswith(
        'account "acme_app@10.%" on target "mysql-dev" uses mysql_native_password'
    )


def test_survey_reports_missing_other_plugin_and_undeclared_hosts() -> None:
    cursor = _Cursor(
        [
            _row(),
            _row(host="localhost"),
            _row(user="acme_web", host="%", plugin="sha256_password"),
        ]
    )

    lines = survey(cursor, ["acme_app@10.%", "acme_web@%", "acme_batch@%"])

    assert lines == (
        "acme_app@localhost exists and the config does not declare it: it logs in as "
        "acme_app with a password of its own, which the tool does not change. "
        "Declare it, or drop it",
        "acme_web@% uses sha256_password, and sopuli changes only caching_sha2_password "
        f"accounts: {OTHER_PLUGIN_HINT}",
        "acme_batch@% does not exist on this server: create it, or remove it from the "
        "config. The tool does not create accounts",
    )


def test_survey_reads_each_user_name_once() -> None:
    cursor = _Cursor([_row(), _row(host="localhost")])

    assert survey(cursor, ["acme_app@10.%", "acme_app@LOCALHOST"]) == ()
    assert len(cursor.calls) == 1


def test_a_lifetime_that_has_run_out_is_expired() -> None:
    """`password_expired` stays N when the lifetime runs out: only `PASSWORD
    EXPIRE` sets it. The date says the password has stopped working."""
    cursor = _Cursor([_row(lifetime=30)])

    state = describe(cursor, "acme_app@10.%", target="mysql-dev", now=NOW)

    assert state is not None
    assert state.expired is True
    assert state.status == EXPIRED


def test_a_name_with_trailing_spaces_is_another_user() -> None:
    """The binary collation pads with spaces, so the server's `=` matches it;
    the driver compares again."""
    cursor = _Cursor([_row()])

    assert describe(cursor, "acme_app @10.%", target="mysql-dev", now=NOW) is None


def test_only_ascii_letters_fold_in_a_host() -> None:
    assert same_host("DB.example.com", "db.example.com")
    assert not same_host("ÄB.example.com", "äb.example.com")
