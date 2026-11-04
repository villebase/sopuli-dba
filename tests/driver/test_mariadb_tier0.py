"""The MariaDB driver's pure parts: the scope, the tool account's audit, and
the survey of declared accounts (#1268). Tier 0, with a fake cursor."""

from __future__ import annotations

from typing import Any

import pytest

from sopuli.driver.mariadb import accounts, privileges
from sopuli.driver.mariadb.scope import (
    READ_ONLY,
    READ_ONLY_SETTINGS,
    READ_WRITE,
    VERSION,
    NotMariadbError,
    observe,
    writable,
)
from sopuli.driver.mysql_family.encryption import TLS_VERSION
from sopuli.driver.protocol import ENCRYPTION_NONE, ENCRYPTION_TLS, SERVER
from sopuli.exit_codes import ExitCode


class FakeCursor:
    """Answers by query, as the server would; records what was asked."""

    def __init__(self, answers: dict[str, Any]) -> None:
        self.answers = answers
        self.last: str | None = None
        self.queries: list[tuple[str, Any]] = []

    def execute(self, query: Any, args: Any = None, /) -> None:
        self.last = query
        self.queries.append((query, args))

    def fetchone(self) -> Any:
        assert self.last is not None
        return self.answers[self.last]

    def fetchall(self) -> Any:
        assert self.last is not None
        return self.answers[self.last]


# ------------------------------------------------------------------ scope ---


def scope_cursor(version: str, read_only: object = 0, tls: str = "TLSv1.3") -> FakeCursor:
    return FakeCursor(
        {
            VERSION: (version,),
            READ_ONLY_SETTINGS: (read_only, 0),
            TLS_VERSION: ("Ssl_version", tls),
        }
    )


def test_a_mariadb_server_is_a_server_with_its_version() -> None:
    scope = observe(scope_cursor("11.8.9-MariaDB-ubu2404-log"), target="mariadb-dev")

    assert scope.type == SERVER
    assert scope.db_version == "11.8.9"
    assert scope.open_mode == READ_WRITE
    assert scope.encryption.method == ENCRYPTION_TLS
    assert scope.capabilities == frozenset()


def test_a_plain_session_names_the_mariadb_block() -> None:
    scope = observe(scope_cursor("10.11.19-MariaDB-log", tls=""), target="mariadb-dev")

    assert scope.encryption.method == ENCRYPTION_NONE
    assert "`mariadb.ssl_mode`" in str(scope.encryption.hint)


def test_a_mysql_server_is_refused_before_anything_else_is_read() -> None:
    cursor = scope_cursor("8.4.13")

    with pytest.raises(NotMariadbError) as caught:
        observe(cursor, target="mariadb-dev")

    assert caught.value.exit_code == ExitCode.CONFIG_INVALID
    assert "set `type: mysql`" in str(caught.value.hint)
    assert [query for query, _ in cursor.queries] == [VERSION]


@pytest.mark.parametrize(
    ("read_only", "tx_read_only", "expected"),
    [(0, 0, True), ("OFF", 0, True), (1, 0, False), ("ON", 0, False), (0, 1, False)],
)
def test_read_only_reads_as_a_number_or_as_12_3s_word(
    read_only: object, tx_read_only: int, expected: bool
) -> None:
    """`read_only` is `0` on 10.11.19, 11.4.13 and 11.8.9 and `OFF` on 12.3.3."""
    assert writable(read_only, tx_read_only) is expected


def test_a_read_only_server_is_reported_so() -> None:
    scope = observe(scope_cursor("12.3.3-MariaDB", read_only="ON"), target="mariadb-dev")

    assert scope.open_mode == READ_ONLY
    assert scope.read_write is False


# ------------------------------------------------------------------ audit ---

FULL = privileges.Grants(
    global_=(("CREATE USER", False),),
    table=tuple((table, "SELECT", False) for table in privileges.TABLES_READ),
    column=tuple((privileges.USER_TABLE, column, "SELECT", False) for column in privileges.COLUMNS),
)


def test_section_2_1_exactly_is_held_and_nothing_is_missing_or_over() -> None:
    audit = privileges.classify(user="sopuli_admin@%", grants=FULL, roles=())

    assert audit.missing == ()
    assert audit.over_granted == ()
    assert len(audit.held) == 1 + len(privileges.COLUMNS) + len(privileges.TABLES_READ)
    assert audit.unaudited == ()


def test_a_grant_that_reads_every_stored_value_is_over_granted() -> None:
    grants = privileges.Grants(
        global_=(("CREATE USER", False), ("SET USER", False)),
        table=(*FULL.table, ("mysql.global_priv", "SELECT", False)),
        column=(*FULL.column, (privileges.USER_TABLE, "authentication_string", "SELECT", False)),
        schema=(("mysql", "SELECT", False),),
    )

    audit = privileges.classify(user="sopuli_admin@%", grants=grants, roles=())

    assert audit.over_granted == (
        "SELECT (authentication_string) ON mysql.user",
        "SELECT ON mysql.*",
        "SELECT ON mysql.global_priv",
        "SET USER ON *.*",
    )
    assert privileges.OVER_GRANTED_REMEDY in audit.remedies


def test_what_is_missing_is_spelled_as_the_grant_to_issue() -> None:
    audit = privileges.classify(user="sopuli_admin@%", grants=privileges.Grants(), roles=())

    assert "CREATE USER" in audit.missing
    assert "SELECT ON mysql.roles_mapping" in audit.missing
    assert "GRANT CREATE USER ON *.* TO `sopuli_admin`@`%`;" in str(audit.hint)
    assert "02-mariadb-privileges.md section 2.1" in str(audit.hint)


def test_a_grant_option_is_over_granted() -> None:
    grants = privileges.Grants(global_=(("CREATE USER", True),))

    audit = privileges.classify(user="sopuli_admin@%", grants=grants, roles=())

    assert "GRANT OPTION ON *.*" in audit.over_granted


def test_a_role_leaves_what_it_gives_unaudited() -> None:
    audit = privileges.classify(user="sopuli_admin@%", grants=FULL, roles=("tool_role",))

    assert audit.roles == ("tool_role",)
    assert audit.unaudited == (privileges.ROLES_UNAUDITED,)
    assert privileges.ROLES_REMEDY in audit.remedies


def test_the_audit_asks_by_its_own_grantee() -> None:
    """With `SELECT` on `mysql.*`, information_schema shows every account's
    rows, so each read names the tool account's own (RD1)."""
    cursor = FakeCursor(
        {
            privileges.SELF: ("sopuli_admin@%",),
            privileges.GLOBAL_PRIVILEGES: [("CREATE USER", "NO")],
            privileges.SCHEMA_PRIVILEGES: [],
            privileges.TABLE_PRIVILEGES: [],
            privileges.COLUMN_PRIVILEGES: [],
            privileges.ROLES: [],
        }
    )

    privileges.audit(cursor)

    asked = {args for _, args in cursor.queries if args is not None}
    assert asked == {("'sopuli_admin'@'%'",)}


# ----------------------------------------------------------------- survey ---


def survey_cursor(rows: list[tuple[str, str, str]]) -> FakeCursor:
    class Rows(FakeCursor):
        def fetchall(self) -> Any:
            return rows

    return Rows({})


def test_the_survey_names_a_missing_account_another_plugin_and_an_undeclared_host() -> None:
    cursor = survey_cursor(
        [
            ("acme_app", "%", "ed25519"),
            ("acme_app", "localhost", "mysql_native_password"),
            ("acme_old", "%", "unix_socket"),
        ]
    )

    lines = accounts.survey(cursor, ["acme_app@%", "acme_api@%", "acme_old@%"])

    assert lines == (
        "acme_app@localhost exists and the config does not declare it: unless it is "
        "locked, which the tool cannot read on MariaDB, it logs in as acme_app with a "
        "password of its own, which the tool does not change. Declare it, or lock or drop it",
        "acme_api@% does not exist on this server: create it, or remove it from the config. "
        "The tool does not create accounts",
        f"acme_old@% uses unix_socket: {accounts.OTHER_PLUGIN_HINT}",
    )


def test_both_supported_plugins_pass_and_hosts_compare_without_case() -> None:
    cursor = survey_cursor(
        [("acme_app", "app.example.com", "mysql_native_password"), ("acme_api", "%", "ed25519")]
    )

    assert accounts.survey(cursor, ["acme_app@APP.example.com", "acme_api@%"]) == ()


def test_the_survey_reads_no_role_and_no_stored_value() -> None:
    assert "is_role = 'N'" in accounts.ROWS_FOR_USERS
    for column in ("authentication_string", "Password", "global_priv"):
        assert column not in accounts.ROWS_FOR_USERS
