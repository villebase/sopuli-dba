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
from sopuli.driver.mysql_family.accounts import CURRENT_USER
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
        answer = self.answers.get(query)
        if isinstance(answer, Exception):
            raise answer

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
    [
        (0, 0, True),
        ("OFF", 0, True),
        (b"OFF", b"0", True),
        (0, "OFF", True),
        (1, 0, False),
        ("ON", 0, False),
        (0, 1, False),
        ("NO_LOCK", 0, False),
        (b"weird", 0, False),
    ],
)
def test_read_only_reads_as_a_number_or_as_12_3s_word(
    read_only: object, tx_read_only: object, expected: bool
) -> None:
    """`read_only` is `0` on 10.11.19, 11.4.13 and 11.8.9 and `OFF` on 12.3.3.
    Bytes and words read the same way, and an unknown spelling counts as on."""
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
    # Grants to PUBLIC are never in what the audit reads, so this is always said.
    assert audit.unaudited == (privileges.PUBLIC_UNAUDITED,)


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
    assert audit.unaudited == (privileges.ROLES_UNAUDITED, privileges.PUBLIC_UNAUDITED)
    assert privileges.ROLES_REMEDY in audit.remedies


def test_the_audit_asks_by_its_own_grantee_and_reads_every_applicable_role() -> None:
    """With `SELECT` on `mysql.*`, information_schema shows every account's
    privilege rows, so each privilege read names the tool account's own (RD1).
    `APPLICABLE_ROLES` lists only the session's roles, nested ones included,
    and spells its grantee without quotes, so it is read whole (#1287)."""
    cursor = FakeCursor(
        {
            CURRENT_USER: ("sopuli_admin@%",),
            privileges.GLOBAL_PRIVILEGES: [("CREATE USER", "NO")],
            privileges.SCHEMA_PRIVILEGES: [],
            privileges.TABLE_PRIVILEGES: [],
            privileges.COLUMN_PRIVILEGES: [],
            privileges.ROLES: [("tool_role",), ("nested_role",)],
            privileges.CURRENT_ROLE: (None,),
            **REFUSED_READS,
        }
    )

    audit = privileges.audit(cursor)

    asked = {args for _, args in cursor.queries if args is not None}
    assert asked == {("'sopuli_admin'@'%'",)}
    assert (privileges.ROLES, None) in cursor.queries
    assert audit.roles == ("nested_role", "tool_role")
    assert audit.unaudited == (privileges.ROLES_UNAUDITED, privileges.PUBLIC_UNAUDITED)
    assert audit.over_granted == ()


class RefusedError(Exception):  # noqa: N818 -- stands in for PyMySQL's own
    """PyMySQL's error for a read the server refuses: its number first."""


#: The hash reads, each refused as the server refuses them for §2.1 alone.
REFUSED_READS: dict[str, Any] = {
    statement: RefusedError(1142 if "global_priv" in statement else 1143, "denied")
    for statement in privileges.HASH_READS.values()
}


def test_a_hash_read_the_server_allows_is_over_granted_by_any_route() -> None:
    """A role, PUBLIC or a broader grant: the read is tried, so the route does
    not matter (#1287)."""
    reads = {**REFUSED_READS, privileges.HASH_READS["SELECT ON mysql.global_priv"]: []}

    assert privileges.allowed_reads(FakeCursor(reads)) == ("SELECT ON mysql.global_priv",)


def test_each_role_is_set_in_turn_and_the_session_role_is_restored() -> None:
    """A role that is not active hides what it gives until the account sets
    it. The audit sets each, tries the reads, and puts back the role the
    session had: here none, so `SET ROLE NONE`. A role that cannot be set alone
    is skipped (#1287)."""

    class RoleCursor(FakeCursor):
        def __init__(self) -> None:
            super().__init__({**REFUSED_READS, privileges.CURRENT_ROLE: (None,)})
            self.active: str | None = None

        def execute(self, query: Any, args: Any = None, /) -> None:
            if query.startswith("set role "):
                self.queries.append((query, args))
                if "nested" in query:
                    raise RefusedError(1959, "Invalid role specification")
                self.active = None if query == privileges.NO_ROLE else query
                return
            if self.active and "global_priv" in str(query):
                self.last = query
                self.queries.append((query, args))
                self.answers[query] = []
                return
            self.answers.update(REFUSED_READS)
            super().execute(query, args)

    cursor = RoleCursor()

    reads = privileges.allowed_reads(cursor, ["tool_role", "nested"])

    assert reads == ("SELECT ON mysql.global_priv (through role tool_role)",)
    assert cursor.queries[-1] == (privileges.NO_ROLE, None)


def test_a_failure_that_is_not_a_refusal_is_raised() -> None:
    reads = {
        **REFUSED_READS,
        privileges.HASH_READS["SELECT ON mysql.global_priv"]: RefusedError(2013),
    }

    with pytest.raises(RefusedError):
        privileges.allowed_reads(FakeCursor(reads))


@pytest.mark.parametrize("schema", ["%", "m_sql", "my%"])
def test_a_schema_pattern_that_covers_mysql_is_broad(schema: str) -> None:
    grants = privileges.Grants(schema=((schema, "SELECT", False),))

    audit = privileges.classify(user="sopuli_admin@%", grants=grants, roles=())

    assert audit.missing == ("CREATE USER",)


def test_a_schema_pattern_that_misses_mysql_is_not_broad() -> None:
    grants = privileges.Grants(schema=(("acme\\_%", "SELECT", False),))

    audit = privileges.classify(user="sopuli_admin@%", grants=grants, roles=())

    assert "SELECT ON mysql.roles_mapping" in audit.missing


def test_select_on_the_whole_view_holds_its_columns_and_is_over_granted() -> None:
    grants = privileges.Grants(table=((privileges.USER_TABLE, "SELECT", False),))

    audit = privileges.classify(user="sopuli_admin@%", grants=grants, roles=())

    assert not any(missing.startswith("SELECT (") for missing in audit.missing)
    assert "SELECT ON mysql.user" in audit.over_granted


def test_a_broad_select_holds_what_it_covers_and_is_over_granted() -> None:
    """`SELECT ON mysql.*` reads everything §2.1 grants, so nothing is missing
    but `CREATE USER`, and the grant is over-granted (#1287)."""
    grants = privileges.Grants(schema=(("mysql", "SELECT", False),))

    audit = privileges.classify(user="sopuli_admin@%", grants=grants, roles=())

    assert audit.missing == ("CREATE USER",)
    assert "SELECT ON mysql.*" in audit.over_granted


# ----------------------------------------------------------------- survey ---


def survey_cursor(rows: list[tuple[str, ...]]) -> FakeCursor:
    """Rows as the view gives them; ``password_expired`` defaults to ``N``."""
    full = [row if len(row) == 4 else (*row, "N") for row in rows]

    class Rows(FakeCursor):
        def fetchall(self) -> Any:
            return full

    return Rows({})


# --------------------------------------------------------------- describe ---


def test_an_account_on_another_plugin_is_refused_by_name() -> None:
    cursor = survey_cursor([("acme_app", "%", "parsec")])

    with pytest.raises(accounts.OtherPluginError) as caught:
        accounts.read_one(cursor, "acme_app@%", target="mariadb-dev")

    assert caught.value.exit_code == ExitCode.CONFIG_INVALID
    assert 'account "acme_app@%" on target "mariadb-dev" uses parsec' in str(caught.value)


def test_an_expired_account_reads_as_expired_and_never_as_locked() -> None:
    """The view's `password_expired` is the expiry (LK3); the lock is never
    read (#1267, decision 2), and the time of a change is beside the hash."""
    found = accounts.read_one(
        survey_cursor([("acme_app", "%", "ed25519", "Y")]), "acme_app@%", target="t"
    )
    assert found is not None

    state = accounts.state_of(found)

    assert (state.status, state.expired, state.locked) == ("EXPIRED", True, False)
    assert state.password_changed_at is None
    assert state.password_changed_unknown == accounts.NO_CHANGE_DATE


def test_a_missing_account_is_none() -> None:
    assert accounts.read_one(survey_cursor([]), "acme_app@%", target="t") is None


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


# ------------------------------------------------------------- doctor gaps ---


@pytest.mark.parametrize("survey_refused", [False, True])
def test_doctor_names_both_gaps_whether_or_not_the_survey_read(
    monkeypatch: pytest.MonkeyPatch, survey_refused: bool
) -> None:
    """Check 9's gap and the unseen second method (#1301), after the survey's
    lines or after the line that says it was refused."""
    session_module = pytest.importorskip("sopuli.driver.mariadb.session")
    from sopuli.config.model import ExpandedTarget, Target
    from sopuli.driver.protocol import DriverError, PrivilegeAudit, Timeouts

    answers: list[Any] = [
        PrivilegeAudit(),
        DriverError("refused", code="1143") if survey_refused else ("a survey line",),
    ]

    def read(reader: Any, **_: Any) -> Any:
        answer = answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return answer

    session = session_module.MariadbSession(
        connection=None,
        target=ExpandedTarget(
            target=Target(name="mariadb-dev", type="mariadb", dsn="mariadb-dev.example.com:3306")
        ),
        correlation_id="tier0",
        timeouts=Timeouts(),
    )
    monkeypatch.setattr(session, "_read", read)

    remedies = session.privileges(accounts=("acme_app@%",)).remedies

    assert remedies[-2:] == session_module.ACCOUNT_GAPS
    assert ("the declared accounts were not read" in remedies[0]) is survey_refused
