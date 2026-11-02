"""Reading MySQL accounts. Tier 0: a fake cursor answers `mysql.user` reads with
rows in the shape PyMySQL 1.2.3 gave on 8.4.13, where `account_locked` and
`password_expired` came back as strings, and matches user names as the server
does: by case, with trailing spaces dropped."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from sopuli.driver.mysql import admin
from sopuli.driver.mysql.accounts import (
    DEFAULT_LIFETIME,
    EXPIRED,
    EXPIRED_AND_LOCKED,
    NO_CHANGE_DATE,
    OPEN,
    OTHER_PLUGIN_HINT,
    BareAccountError,
    OtherPluginError,
    describe,
    same_host,
    split,
    survey,
)
from sopuli.exit_codes import ExitCode

CHANGED = datetime(2026, 10, 1, 12, 0, 0)
#: Before a 90-day lifetime runs out, after a 30-day one.
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


def _decoded(value: Any) -> Any:
    return value.decode("utf-8") if isinstance(value, bytes) else value


class _Cursor:
    def __init__(self, rows: list[tuple[Any, ...]], default_lifetime: int | None = 0) -> None:
        self.rows = rows
        self.default_lifetime = default_lifetime
        #: The account's `*_priv` row, for guardrail 9's read; none by default.
        self.global_row: tuple[str, ...] | None = None
        self.queries: list[tuple[str, Any]] = []
        self._last = ""
        self._users: tuple[str, ...] = ()

    def execute(self, query: Any, args: Any = None, /) -> None:
        self.queries.append((query, args))
        self._last = query
        if query.startswith("select User,"):
            assert query.count("%s") == len(args)
            self._users = tuple(user.rstrip(" ") for user in args)

    def fetchone(self) -> Any:
        if self._last == DEFAULT_LIFETIME:
            return (self.default_lifetime,)
        if self._last == admin.MANDATORY_ROLES:
            return ("",)
        if self._last == admin.PARTIAL_REVOKES:
            return (0,)
        assert self._last == admin.GLOBAL_ROW
        return self.global_row

    def fetchall(self) -> Any:
        if self._last.startswith("select User,"):
            return [row for row in self.rows if _decoded(row[0]) in self._users]
        # The other grant tables of guardrail 9's read: nothing held.
        return []


def _reads(cursor: _Cursor) -> int:
    return sum(query.startswith("select User,") for query, _ in cursor.queries)


def test_split_at_the_last_at_sign() -> None:
    assert split("acme_app@10.%") == ("acme_app", "10.%")
    assert split("ops@acme@localhost") == ("ops@acme", "localhost")


def test_split_drops_trailing_spaces_in_the_user_name_as_the_server_does() -> None:
    """`User` is char(32): 8.4.13 refused `CREATE USER 'tsp '` beside
    `'tsp'` with 1396, so the two are one account."""
    assert split("acme_app @10.%") == ("acme_app", "10.%")


@pytest.mark.parametrize("bare", ["acme_app", "acme_app@", "@10.%", " @10.%"])
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
    assert state.vendor_maintained is False


def test_the_host_compares_without_case_and_the_name_is_the_servers() -> None:
    cursor = _Cursor([_row(host="db.example.com")])

    state = describe(cursor, "acme_app@DB.example.com", target="mysql-dev", now=NOW)

    assert state is not None
    assert state.name == "acme_app@db.example.com"


def test_the_user_name_compares_by_case() -> None:
    cursor = _Cursor([_row(user="Acme_App")])

    assert describe(cursor, "acme_app@10.%", target="mysql-dev", now=NOW) is None


def test_a_name_with_a_trailing_space_is_the_same_account() -> None:
    cursor = _Cursor([_row()])

    state = describe(cursor, "acme_app @10.%", target="mysql-dev", now=NOW)

    assert state is not None
    assert state.name == "acme_app@10.%"


def test_a_locked_expired_account_with_a_lifetime() -> None:
    cursor = _Cursor([_row(locked="Y", expired="Y", lifetime=90)])

    state = describe(cursor, "acme_app@10.%", target="mysql-dev", now=NOW)

    assert state is not None
    assert state.status == EXPIRED_AND_LOCKED
    assert state.deliberately_locked is True
    assert state.expired is True
    assert state.password_expires_at == datetime(2026, 12, 30, 12, 0, 0, tzinfo=UTC)


def test_a_lifetime_that_has_run_out_is_expired() -> None:
    """`password_expired` stays N when the lifetime runs out: only `PASSWORD
    EXPIRE` sets it. The date says the password has stopped working."""
    cursor = _Cursor([_row(lifetime=30)])

    state = describe(cursor, "acme_app@10.%", target="mysql-dev", now=NOW)

    assert state is not None
    assert state.expired is True
    assert state.status == EXPIRED


@pytest.mark.parametrize(("default", "expired"), [(30, True), (90, False), (0, False)])
def test_a_null_lifetime_follows_the_servers_default(default: int, expired: bool) -> None:
    cursor = _Cursor([_row(lifetime=None)], default_lifetime=default)

    state = describe(cursor, "acme_app@10.%", target="mysql-dev", now=NOW)

    assert state is not None
    assert state.expired is expired
    assert (state.password_expires_at is None) is (default == 0)


def test_an_own_lifetime_of_zero_overrides_the_default() -> None:
    cursor = _Cursor([_row(lifetime=0)], default_lifetime=30)

    state = describe(cursor, "acme_app@10.%", target="mysql-dev", now=NOW)

    assert state is not None
    assert state.expired is False


def test_bytes_columns_are_read_as_text_and_no_change_date_is_said() -> None:
    cursor = _Cursor([(b"acme_app", b"10.%", b"caching_sha2_password", b"N", b"N", None, 0)])

    state = describe(cursor, "acme_app@10.%", target="mysql-dev", now=NOW)

    assert state is not None
    assert state.password_changed_unknown == NO_CHANGE_DATE
    assert state.password_expires_at is None


@pytest.mark.parametrize(
    ("user", "host", "vendor"),
    [("mysql.sys", "localhost", True), ("mysql.backup", "10.%", False)],
)
def test_only_the_servers_own_accounts_are_vendor_maintained(
    user: str, host: str, vendor: bool
) -> None:
    cursor = _Cursor([_row(user=user, host=host)])

    state = describe(cursor, f"{user}@{host}", target="mysql-dev", now=NOW)

    assert state is not None
    assert state.vendor_maintained is vendor


def test_describe_reads_the_global_privileges_guardrail_9_refuses() -> None:
    cursor = _Cursor([_row()])
    cursor.global_row = tuple(
        "Y" if column == "Super_priv" else "N" for column in admin.PRIV_COLUMNS
    )

    state = describe(cursor, "acme_app@10.%", target="mysql-dev", now=NOW)

    assert state is not None
    assert state.global_privileges == {"SUPER ON *.*"}


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
        "Declare it, or lock or drop it",
        "acme_web@% uses sha256_password, and sopuli changes only caching_sha2_password "
        f"accounts: {OTHER_PLUGIN_HINT}",
        "acme_batch@% does not exist on this server: create it, or remove it from the "
        "config. The tool does not create accounts",
    )


def test_survey_does_not_report_a_locked_account_or_a_role_at_another_host() -> None:
    """A role is a locked account with an expired password (8.4.13)."""
    cursor = _Cursor([_row(), _row(host="%", locked="Y", expired="Y")])

    assert survey(cursor, ["acme_app@10.%"]) == ()


def test_survey_reads_every_user_name_in_one_read() -> None:
    cursor = _Cursor([_row(), _row(host="localhost"), _row(user="acme_web", host="%")])

    assert survey(cursor, ["acme_app@10.%", "acme_app@LOCALHOST", "acme_web@%"]) == ()
    assert _reads(cursor) == 1


def test_only_ascii_letters_fold_in_a_host() -> None:
    assert same_host("DB.example.com", "db.example.com")
    assert not same_host("ÄB.example.com", "äb.example.com")
