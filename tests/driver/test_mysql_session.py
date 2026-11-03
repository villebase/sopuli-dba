"""The MySQL session on a scripted connection. Tier 0, with PyMySQL installed.

What this build does past connecting is refuse, so the refusals are the
behaviour: ``SOPULI-20006`` for an operation not written yet, an absent
capability named, a session without TLS refused where the mode requires it,
and PyMySQL's own failure of a plain login reported as what it is.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime
from typing import Any

import pytest

from sopuli.config.model import ExpandedTarget, Runtime, Target, TargetMysql
from sopuli.driver.protocol import (
    ACCOUNT_UNLOCK,
    EXPIRE_PASSWORD,
    KEEP_ROLLOVER,
    PASSWORD_EXPIRE,
    PASSWORD_ROLLOVER,
    PASSWORD_SET,
    ROLE_LOOKUP,
    ROLLOVER_FINISH,
    AccountAttributes,
    Credential,
    Driver,
    DriverContext,
    DriverError,
    PartialAccountChangeError,
    Session,
    Timeouts,
    UnsupportedCapabilityError,
)
from sopuli.driver.registry import DRIVER_NOT_IMPLEMENTED
from sopuli.exit_codes import ExitCode
from sopuli.secrets import Secret

session_module = pytest.importorskip("sopuli.driver.mysql.session")
scope_module = pytest.importorskip("sopuli.driver.mysql.scope")
grants_module = pytest.importorskip("sopuli.driver.mysql.grants")
privileges_module = pytest.importorskip("sopuli.driver.mysql.privileges")
accounts_module = pytest.importorskip("sopuli.driver.mysql.accounts")


class _Cursor:
    def __init__(self, connection: _Connection) -> None:
        self._connection = connection
        self._rows = {
            scope_module.VERSION: (connection.version,),
            scope_module.READ_ONLY_SETTINGS: (0, 0, 0),
            scope_module.TLS_VERSION: ("Ssl_version", connection.tls),
            privileges_module.SELF: ("sopuli_admin@%",),
            accounts_module.DEFAULT_LIFETIME: (0,),
            "select @@global.caching_sha2_password_digest_rounds": (connection.rounds,),
            session_module.SERVER_NOW: (connection.now,),
            session_module.SERVER_UUID: ("8747dbf7-d699-11f1-a32f-ce3a34795652",),
        }
        self._last = ""

    def execute(self, query: str, args: Any = None, /) -> None:
        self._connection.queries.append(query)
        self._last = query
        if query.startswith("select User,") and self._connection.refuse is not None:
            raise self._connection.refuse
        if " IDENTIFIED WITH " in query and self._connection.fail_alter is not None:
            raise self._connection.fail_alter
        if query.endswith("ACCOUNT UNLOCK") and self._connection.fail_unlock is not None:
            raise self._connection.fail_unlock
        bare_expire = query.endswith("PASSWORD EXPIRE") and "IDENTIFIED" not in query
        if bare_expire and self._connection.fail_expire is not None:
            raise self._connection.fail_expire
        if query.endswith("DISCARD OLD PASSWORD") and self._connection.fail_discard is not None:
            raise self._connection.fail_discard
        if "digest_rounds" in query and self._connection.fail_rounds is not None:
            raise self._connection.fail_rounds

    def fetchone(self) -> Any:
        """Guardrail 9's reads find nothing held: no `*_priv` row, and no
        mandatory role."""
        if self._last.startswith("select Select_priv"):
            return None
        if self._last == "select @@global.mandatory_roles":
            return ("",)
        if self._last == "select @@global.partial_revokes":
            return (0,)
        return self._rows[self._last]

    def fetchall(self) -> Any:
        """No role, and only `CREATE USER`, as 8.4.13 printed it. Accounts
        from the connection."""
        if self._last in (grants_module.DIRECT_ROLES, privileges_module.ALL_ROLES):
            return []
        if self._last.startswith("select User,"):
            return self._connection.accounts
        if not self._last.startswith("show grants"):
            # Guardrail 9's grant-table reads: nothing held.
            return []
        return [("GRANT CREATE USER ON *.* TO `sopuli_admin`@`%`",)]


class _Connection:
    def __init__(self, tls: str = "TLSv1.3", version: str = "8.4.13") -> None:
        self.tls = tls
        self.version = version
        self.closed = 0
        self.queries: list[str] = []
        #: `mysql.user` rows, and an error the read of them raises instead.
        self.accounts: list[tuple[Any, ...]] = []
        self.refuse: Exception | None = None
        #: An error the statement that sets a password raises instead.
        self.fail_alter: Exception | None = None
        #: An error `ACCOUNT UNLOCK` raises instead.
        self.fail_unlock: Exception | None = None
        #: An error a bare `PASSWORD EXPIRE` raises instead.
        self.fail_expire: Exception | None = None
        #: The server's `caching_sha2_password_digest_rounds`.
        self.rounds = 5000
        #: The server's clock, as `select now()` returns it: naive, UTC.
        self.now = datetime(2026, 11, 2, 12, 0, 0)
        #: An error `DISCARD OLD PASSWORD` raises instead.
        self.fail_discard: Exception | None = None
        #: An error the read of the rounds raises instead.
        self.fail_rounds: Exception | None = None

    @contextmanager
    def cursor(self) -> Iterator[_Cursor]:
        yield _Cursor(self)

    def close(self) -> None:
        self.closed += 1


def _target(mode: str = "VERIFY_IDENTITY") -> ExpandedTarget:
    return ExpandedTarget(
        target=Target(
            name="mysql-dev",
            type="mysql",
            dsn="mysql-dev.example.com:3306",
            mysql=TargetMysql(ssl_mode=mode),
        )
    )


def _session(tls: str = "TLSv1.3") -> Any:
    return session_module.MysqlSession(
        connection=_Connection(tls),
        target=_target(),
        correlation_id="tier0",
        timeouts=Timeouts(),
    )


def test_the_session_and_the_driver_satisfy_the_protocol() -> None:
    driver = session_module.build_driver(
        DriverContext(env={}, correlation_id="run", runtime=Runtime())
    )

    assert isinstance(driver, Driver)
    assert isinstance(_session(), Session)


def test_the_scope_is_read_once_and_cached() -> None:
    session = _session()

    first = session.scope()

    assert first.type == "server"
    assert session.scope() is first


def test_what_is_not_written_refuses_with_20006() -> None:
    with pytest.raises(DriverError) as caught:
        _session().apply_attributes("acme_app@%", AccountAttributes())

    assert caught.value.code == DRIVER_NOT_IMPLEMENTED
    assert caught.value.exit_code == ExitCode.CONFIG_INVALID
    assert 'target "mysql-dev" is a MySQL server' in str(caught.value)


@pytest.mark.parametrize(
    "call",
    [
        lambda s: s.resolve_profile("dev_users"),
        lambda s: s.accounts_matching(profile="dev_users"),
    ],
)
def test_a_profile_rule_is_refused_by_capability(call: Any) -> None:
    """MySQL has no profiles: exit 5, as on PostgreSQL (#1225)."""
    with pytest.raises(UnsupportedCapabilityError) as caught:
        call(_session())

    assert caught.value.exit_code == ExitCode.UNSUPPORTED_CAPABILITY
    assert "profile_management" in str(caught.value)
    assert "MySQL has no profiles" in str(caught.value.hint)


def test_the_server_can_look_up_a_role_whatever_its_rounds() -> None:
    """`role_lookup` comes from §2.1's grants, not from the server, so a
    server without the rounds variable reports it too. `expire_password` comes
    with the variable: the expiry sends DISCARD OLD PASSWORD, which a server
    that old may not know, so it is refused at plan time (#1225)."""
    assert _session().scope().supports(ROLE_LOOKUP)
    assert _session().scope().supports(EXPIRE_PASSWORD)
    session = _session()
    session.connection.fail_rounds = session_module.pymysql.err.OperationalError(
        1193, "Unknown system variable 'caching_sha2_password_digest_rounds'"
    )
    assert session.scope().capabilities == frozenset({ROLE_LOOKUP})
    with pytest.raises(UnsupportedCapabilityError, match=EXPIRE_PASSWORD):
        session.expire_password("acme_app@10.%")
    assert _altered(session) == []


def test_accounts_matching_takes_exactly_one_rule() -> None:
    with pytest.raises(ValueError, match="exactly one"):
        _session().accounts_matching()
    with pytest.raises(ValueError, match="exactly one"):
        _session().accounts_matching(profile="p", role="r@%")


def test_a_server_with_the_rounds_variable_can_keep_a_second_password() -> None:
    """#1224: `password_rollover` where the tool can set a password at all."""
    assert _session().scope().supports(PASSWORD_ROLLOVER)


def test_a_server_without_the_rounds_variable_has_no_rollover() -> None:
    """A server that answers 1193 is refused by capability, exit 5 (invariant 4)."""
    session = _session()
    session.connection.fail_rounds = session_module.pymysql.err.OperationalError(
        1193, "Unknown system variable 'caching_sha2_password_digest_rounds'"
    )

    assert not session.scope().supports(PASSWORD_ROLLOVER)
    with pytest.raises(UnsupportedCapabilityError, match=PASSWORD_ROLLOVER) as caught:
        session.require_rollover("acme_app@%")
    assert caught.value.exit_code == ExitCode.UNSUPPORTED_CAPABILITY


def test_a_rollover_needs_the_account_to_exist() -> None:
    with pytest.raises(DriverError, match="does not exist"):
        _session().require_rollover("acme_app@%")


def test_a_rollover_retains_and_sends_no_discard() -> None:
    """#1224, DP6: RETAIN on the statement, and no DISCARD after it."""
    session = _session()
    session.connection.accounts = [_account_row("10.%")]

    session.set_password("acme_app@10.%", Secret("Acme-App-pw1"), old_password="retain")

    (statement,) = [q for q in session.connection.queries if q.startswith("ALTER USER")]
    assert statement.endswith(" RETAIN CURRENT PASSWORD")


def test_a_re_set_keeps_what_is_retained() -> None:
    """#1224, DP4: neither RETAIN nor DISCARD."""
    session = _session()
    session.connection.accounts = [_account_row("10.%")]

    session.set_password("acme_app@10.%", Secret("Acme-App-pw1"), old_password="keep")

    (statement,) = [q for q in session.connection.queries if q.startswith("ALTER USER")]
    assert "RETAIN" not in statement


def test_finish_rollover_always_discards_and_reports_a_change() -> None:
    """#1224: the tool cannot read whether a password is retained, and the
    server accepts DISCARD with none (DP1), so it is sent every time."""
    session = _session()
    session.connection.accounts = [_account_row("%")]

    first = session.finish_rollover("acme_app@%")
    second = session.finish_rollover("acme_app@%")

    sent = [q for q in session.connection.queries if q.startswith("ALTER USER")]
    assert sent == ["ALTER USER `acme_app`@`%` DISCARD OLD PASSWORD"] * 2
    assert (first.changed, second.changed) == (True, True)


def test_finish_rollover_of_a_missing_account_sends_nothing() -> None:
    session = _session()

    with pytest.raises(DriverError, match="does not exist"):
        session.finish_rollover("acme_app@%")
    assert not any(q.startswith("ALTER USER") for q in session.connection.queries)


def test_audit_coverage_never_raises() -> None:
    assert _session().audit_coverage("acme_app@%").audited is None


def test_the_privilege_audit_reads_the_tool_accounts_grants() -> None:
    """The fake account holds only `CREATE USER`, so the column grant is
    missing and nothing is over-granted."""
    audit = _session().privileges()

    assert audit.held == ("CREATE USER",)
    assert "SELECT (account_locked) ON mysql.user" in audit.missing
    assert audit.over_granted == ()
    assert audit.unaudited == ()


def _account_row(host: str) -> tuple[Any, ...]:
    return ("acme_app", host, "caching_sha2_password", "N", "N", None, None)


def test_the_audit_adds_a_line_for_each_declared_account_finding() -> None:
    session = _session()
    session.connection.accounts = [_account_row("10.%"), _account_row("localhost")]

    audit = session.privileges(accounts=("acme_app@10.%",))

    assert audit.unreadable == ()
    assert audit.remedies[-1].startswith("acme_app@localhost exists and the config")


def test_a_refused_read_of_mysql_user_makes_the_audit_partial() -> None:
    session = _session()
    session.connection.refuse = session_module.pymysql.err.OperationalError(
        1143, "SELECT command denied to user for column 'plugin' in table 'user'"
    )

    audit = session.privileges(accounts=("acme_app@10.%",))

    assert audit.unreadable == ("mysql.user",)
    assert audit.held == ("CREATE USER",)


def test_any_other_failure_of_the_read_keeps_the_tool_accounts_audit() -> None:
    """A pre-flight still sees a missing grant, and `doctor` the rest."""
    session = _session()
    session.connection.refuse = session_module.pymysql.err.OperationalError(2013, "Lost connection")

    audit = session.privileges(accounts=("acme_app@10.%",))

    assert audit.unreadable == ("mysql.user",)
    assert "SELECT (plugin) ON mysql.user" in audit.missing
    assert audit.remedies[-1].startswith("the declared accounts were not read: 2013")


def test_describe_user_refused_a_grant_table_names_section_2_1() -> None:
    """The server's own hint names only the table."""
    session = _session()
    session.connection.refuse = session_module.pymysql.err.OperationalError(
        1142, "SELECT command denied to user for table 'global_grants'"
    )

    with pytest.raises(DriverError) as caught:
        session.describe_user("acme_app@10.%")

    assert caught.value.code == "1142"
    assert caught.value.hint == session_module.MISSING_GRANT_HINT


def test_set_password_sends_the_hash_then_discards_a_retained_password() -> None:
    """#1223: a password someone retained would survive the change (probe 03,
    DP4), and the tool cannot see it, so it is always discarded."""
    session = _session()
    session.connection.accounts = [_account_row("10.%")]

    result = session.set_password("acme_app@10.%", Secret("Acme-App-pw1"))

    statement, discard = [q for q in session.connection.queries if q.startswith("ALTER USER")]
    assert statement.startswith(
        "ALTER USER `acme_app`@`10.%` IDENTIFIED WITH caching_sha2_password AS 0x2441243030352"
    )
    assert discard == "ALTER USER `acme_app`@`10.%` DISCARD OLD PASSWORD"
    assert "Acme-App-pw1" not in statement
    assert result.changed is True


def _altered(session: Any) -> list[str]:
    return [q for q in session.connection.queries if q.startswith("ALTER USER")]


@pytest.mark.parametrize("expire", [True, False], ids=["seen", "unseen"])
def test_a_reset_unlocks_sets_and_discards(expire: bool) -> None:
    """#1225: decision 1's unlock, the hash with PASSWORD EXPIRE on the seen
    path, then DISCARD OLD PASSWORD, as LE6 and LE7 measured them."""
    session = _session()
    session.connection.accounts = [_account_row("10.%")]

    rows = session.reset_password("acme_app@10.%", Secret("Acme-App-pw1"), expire=expire)

    unlock, statement, discard = _altered(session)
    assert unlock == "ALTER USER `acme_app`@`10.%` ACCOUNT UNLOCK"
    assert statement.startswith(
        "ALTER USER `acme_app`@`10.%` IDENTIFIED WITH caching_sha2_password AS 0x"
    )
    assert statement.endswith(" PASSWORD EXPIRE") is expire
    assert "Acme-App-pw1" not in statement
    assert discard == "ALTER USER `acme_app`@`10.%` DISCARD OLD PASSWORD"
    assert [(row.action, row.changed) for row in rows] == [
        (ACCOUNT_UNLOCK, True),
        (PASSWORD_SET, True),
        (ROLLOVER_FINISH, True),
    ]
    assert "cannot be read" in str(rows[0].detail)


@pytest.mark.parametrize(
    ("accounts", "keep", "words"),
    [
        ([_account_row("10.%")], True, KEEP_ROLLOVER),
        ([], False, "does not exist"),
        ([("acme_app", "10.%", "caching_sha2_password", "Y", "N", None, None)], False, "locked"),
        ([_account_row("10.%")], False, "is empty"),
    ],
    ids=["keep-rollover", "missing", "locked", "empty"],
)
def test_a_reset_refuses_before_anything_is_sent(
    accounts: list[Any], keep: bool, words: str
) -> None:
    session = _session()
    session.connection.accounts = accounts
    password = "" if words == "is empty" else "Acme-App-pw1"

    with pytest.raises(DriverError, match=words) as caught:
        session.reset_password("acme_app@10.%", Secret(password), expire=True, keep_rollover=keep)

    assert _altered(session) == []
    assert caught.value.password_sent is False
    if keep:
        assert caught.value.exit_code == ExitCode.UNSUPPORTED_CAPABILITY


def test_a_failed_unlock_changed_nothing() -> None:
    session = _session()
    session.connection.accounts = [_account_row("10.%")]
    session.connection.fail_unlock = session_module.pymysql.err.OperationalError(
        1227, "Access denied; you need the CREATE USER privilege"
    )

    with pytest.raises(DriverError) as caught:
        session.reset_password("acme_app@10.%", Secret("Acme-App-pw1"), expire=True)

    assert not isinstance(caught.value, PartialAccountChangeError)
    assert caught.value.password_sent is False
    assert len(_altered(session)) == 1


def test_a_failed_set_after_the_unlock_carries_the_unlock() -> None:
    session = _session()
    session.connection.accounts = [_account_row("10.%")]
    session.connection.fail_alter = session_module.pymysql.err.OperationalError(
        1827, "The password hash doesn't have the expected format near 0x24412430"
    )

    with pytest.raises(PartialAccountChangeError) as caught:
        session.reset_password("acme_app@10.%", Secret("Acme-App-pw1"), expire=True)

    assert [row.action for row in caught.value.completed] == [ACCOUNT_UNLOCK]
    assert caught.value.password_sent is True
    assert "0x24412430" not in str(caught.value)


def test_a_failed_discard_after_the_set_says_what_to_assume() -> None:
    session = _session()
    session.connection.accounts = [_account_row("10.%")]
    session.connection.fail_discard = session_module.pymysql.err.OperationalError(
        1227, "Access denied; you need the CREATE USER privilege"
    )

    with pytest.raises(PartialAccountChangeError) as caught:
        session.reset_password("acme_app@10.%", Secret("Acme-App-pw1"), expire=False)

    assert [row.action for row in caught.value.completed] == [ACCOUNT_UNLOCK, PASSWORD_SET]
    assert caught.value.password_sent is True
    assert "ALTER USER `acme_app`@`10.%` DISCARD OLD PASSWORD" in str(caught.value.hint)


def _row(*, locked: str = "N", expired: str = "N") -> tuple[Any, ...]:
    return ("acme_app", "10.%", "caching_sha2_password", locked, expired, None, None)


@pytest.mark.parametrize(
    ("locked", "sent", "changed"),
    [("N", ["ALTER USER `acme_app`@`10.%` ACCOUNT LOCK"], True), ("Y", [], False)],
    ids=["open", "already-locked"],
)
def test_suspend_locks_once(locked: str, sent: list[str], changed: bool) -> None:
    """#1225: ACCOUNT LOCK, and nothing where `account_locked` is Y, because
    the server accepts a second lock silently (LE2) and invariant 9 asks for
    `changed: false`."""
    session = _session()
    session.connection.accounts = [_row(locked=locked)]

    change = session.suspend_account("acme_app@10.%")

    assert _altered(session) == sent
    assert change.changed is changed


@pytest.mark.parametrize("call", ["suspend_account", "expire_password"])
def test_a_missing_account_is_refused_before_anything_is_sent(call: str) -> None:
    session = _session()

    with pytest.raises(DriverError, match="does not exist"):
        getattr(session, call)("acme_app@10.%")

    assert _altered(session) == []


def test_expire_discards_then_expires() -> None:
    """Decision 3: a retained password survives PASSWORD EXPIRE (LE9), so the
    discard goes first."""
    session = _session()
    session.connection.accounts = [_row()]

    rows = session.expire_password("acme_app@10.%")

    assert _altered(session) == [
        "ALTER USER `acme_app`@`10.%` DISCARD OLD PASSWORD",
        "ALTER USER `acme_app`@`10.%` PASSWORD EXPIRE",
    ]
    assert [(row.action, row.changed) for row in rows] == [
        (ROLLOVER_FINISH, True),
        (PASSWORD_EXPIRE, True),
    ]


def test_a_password_past_its_lifetime_is_expired_and_reported_so() -> None:
    """`password_expired` is N, so the verb expires it; the row's status is
    the one read, EXPIRED, as `describe_user` reports it."""
    session = _session()
    session.connection.accounts = [
        ("acme_app", "10.%", "caching_sha2_password", "N", "N", datetime(2020, 1, 1), 1)
    ]

    rows = session.expire_password("acme_app@10.%")

    assert [row.changed for row in rows] == [True, True]
    assert {row.status for row in rows} == {"EXPIRED"}


def test_an_expired_password_is_left_alone() -> None:
    """Invariant 9: `password_expired` is Y, so nothing is sent and a second
    run reports no change."""
    session = _session()
    session.connection.accounts = [_row(expired="Y")]

    rows = session.expire_password("acme_app@10.%")

    assert _altered(session) == []
    assert not any(row.changed for row in rows)
    assert rows[-1].detail == "the password is already expired"


def test_a_failed_expiry_after_the_discard_carries_the_discard() -> None:
    session = _session()
    session.connection.accounts = [_row()]
    session.connection.fail_expire = session_module.pymysql.err.OperationalError(
        1227, "Access denied; you need the CREATE USER privilege"
    )

    with pytest.raises(PartialAccountChangeError) as caught:
        session.expire_password("acme_app@10.%")

    assert [row.action for row in caught.value.completed] == [ROLLOVER_FINISH]


def test_a_failed_discard_before_the_expiry_changed_nothing() -> None:
    session = _session()
    session.connection.accounts = [_row()]
    session.connection.fail_discard = session_module.pymysql.err.OperationalError(
        1227, "Access denied; you need the CREATE USER privilege"
    )

    with pytest.raises(DriverError) as caught:
        session.expire_password("acme_app@10.%")

    assert not isinstance(caught.value, PartialAccountChangeError)
    assert len(_altered(session)) == 1


def test_a_failed_discard_says_the_password_was_set() -> None:
    session = _session()
    session.connection.accounts = [_account_row("10.%")]
    session.connection.fail_discard = session_module.pymysql.err.OperationalError(
        1227, "Access denied; you need the CREATE USER privilege"
    )

    with pytest.raises(DriverError, match="the password was set, but discarding") as caught:
        session.set_password("acme_app@10.%", Secret("Acme-App-pw1"))

    assert caught.value.password_sent is True


@pytest.mark.parametrize(
    ("accounts", "password", "words"),
    [
        ([], "Acme-App-pw1", "does not exist"),
        ([_account_row("10.%")], "", "is empty"),
    ],
)
def test_set_password_refuses_before_anything_is_sent(
    accounts: list[Any], password: str, words: str
) -> None:
    session = _session()
    session.connection.accounts = accounts

    with pytest.raises(DriverError, match=words) as caught:
        session.set_password("acme_app@10.%", Secret(password))

    assert caught.value.password_sent is False
    assert not any(q.startswith("ALTER USER") for q in session.connection.queries)


def test_a_failure_once_sent_says_so_and_does_not_quote_the_hash() -> None:
    session = _session()
    session.connection.accounts = [_account_row("10.%")]
    session.connection.fail_alter = session_module.pymysql.err.OperationalError(
        1827, "The password hash doesn't have the expected format near 0x24412430"
    )

    with pytest.raises(DriverError) as caught:
        session.set_password("acme_app@10.%", Secret("Acme-App-pw1"))

    assert caught.value.password_sent is True
    assert "0x24412430" not in str(caught.value)
    assert "0x***" in str(caught.value)
    # PyMySQL's error keeps the message as sent; a traceback would print it.
    assert caught.value.__cause__ is None
    assert caught.value.__suppress_context__ is True


def test_a_message_that_quotes_the_hash_as_text_does_not_keep_it() -> None:
    session = _session()
    session.connection.accounts = [_account_row("10.%")]
    session.connection.fail_alter = session_module.pymysql.err.OperationalError(
        1827, "The password hash doesn't have the expected format: $A$005$abc/DEF.ghi"
    )

    with pytest.raises(DriverError) as caught:
        session.set_password("acme_app@10.%", Secret("Acme-App-pw1"))

    assert "abc/DEF" not in str(caught.value)
    assert "$A$***" in str(caught.value)


def test_a_server_without_the_rounds_variable_is_refused_before_sending() -> None:
    session = _session()
    session.connection.accounts = [_account_row("10.%")]
    session.connection.fail_rounds = session_module.pymysql.err.OperationalError(
        1193, "Unknown system variable 'caching_sha2_password_digest_rounds'"
    )

    with pytest.raises(DriverError, match="has no caching_sha2_password_digest_rounds") as caught:
        session.set_password("acme_app@10.%", Secret("Acme-App-pw1"))

    assert caught.value.code == "1193"
    assert caught.value.password_sent is False
    assert not any(q.startswith("ALTER USER") for q in session.connection.queries)


def test_byte_limit_is_256_bytes_of_utf8() -> None:
    limit = _session().byte_limit()

    assert (limit.max_bytes, limit.encoding) == (256, "utf-8")


def test_apply_finds_the_hooks_it_looks_up_by_name() -> None:
    """`creds apply` reads these with getattr, outside the protocol, and a
    missing `verifies_before_change` means a login before the change: the
    lockout #1223 exists to prevent. A rename must fail here."""
    session = _session()

    assert getattr(session, "verifies_before_change", True) is False
    assert callable(getattr(session, "confirm_change", None))


def _changed_at(host: str, changed: datetime) -> tuple[Any, ...]:
    return ("acme_app", host, "caching_sha2_password", "N", "N", changed, None)


def test_a_change_no_login_can_check_is_confirmed_as_stored() -> None:
    """`acme_app@10.%` is not a sole `%` account, so no login reaches it; the
    server's change time, no earlier than its clock before the statement,
    stands in for one (#1223)."""
    session = _session()
    session.connection.accounts = [_changed_at("10.%", datetime(2026, 11, 2, 12, 0, 0))]
    session.set_password("acme_app@10.%", Secret("Acme-App-pw1"))

    confirmed = session.confirm_change("acme_app@10.%")

    assert confirmed is not None
    assert (confirmed.method, confirmed.result) == ("none", "stored")
    assert "2026-11-02 12:00:00 UTC" in str(confirmed.detail)


def test_a_change_time_before_the_statement_confirms_nothing() -> None:
    session = _session()
    session.connection.accounts = [_changed_at("10.%", datetime(2026, 11, 2, 11, 59, 59))]
    session.set_password("acme_app@10.%", Secret("Acme-App-pw1"))

    assert session.confirm_change("acme_app@10.%") is None


def test_an_account_a_login_reaches_is_never_confirmed_by_time() -> None:
    """A sole `user@%` account is verified by login, never by the clock."""
    session = _session()
    session.connection.accounts = [_changed_at("%", datetime(2026, 11, 2, 12, 0, 1))]
    session.set_password("acme_app@%", Secret("Acme-App-pw1"))

    assert session.confirm_change("acme_app@%") is None


def test_an_account_this_session_did_not_change_is_not_confirmed() -> None:
    session = _session()
    session.connection.accounts = [_changed_at("10.%", datetime(2026, 11, 2, 12, 0, 1))]

    assert session.confirm_change("acme_app@10.%") is None
    assert not any(q == session_module.SERVER_NOW for q in session.connection.queries)


def test_password_constraints_reports_nothing_and_reads_nothing() -> None:
    """The server's rules never see a hash (probe 08), so there is nothing to
    read."""
    session = _session()
    sent = len(session.connection.queries)

    assert session.password_constraints("acme_app@10.%") is None
    assert len(session.connection.queries) == sent


def test_a_message_that_quotes_from_inside_the_hash_does_not_keep_it() -> None:
    session = _session()
    session.connection.accounts = [_account_row("10.%")]
    session.connection.fail_alter = session_module.pymysql.err.ProgrammingError(
        1064, "You have an error in your SQL syntax near '2430303524416a4b3c' at line 1"
    )

    with pytest.raises(DriverError) as caught:
        session.set_password("acme_app@10.%", Secret("Acme-App-pw1"))

    assert "2430303524416a4b3c" not in str(caught.value)
    assert "near '***'" in str(caught.value)


def test_rounds_the_stored_hash_cannot_write_are_refused_before_sending() -> None:
    """The stored hash writes the rounds in thousands."""
    session = _session()
    session.connection.accounts = [_account_row("10.%")]
    session.connection.rounds = 5500

    with pytest.raises(DriverError, match="not a multiple of 1000") as caught:
        session.set_password("acme_app@10.%", Secret("Acme-App-pw1"))

    assert caught.value.password_sent is False
    assert not any(q.startswith("ALTER USER") for q in session.connection.queries)


def test_describe_user_reads_the_account() -> None:
    session = _session()
    session.connection.accounts = [_account_row("10.%")]

    state = session.describe_user("acme_app@10.%")

    assert state is not None
    assert state.name == "acme_app@10.%"
    assert session.describe_user("acme_app@192.0.2.%") is None


def test_close_is_safe_twice() -> None:
    session = _session()
    connection = session.connection

    session.close()
    session.close()

    assert connection.closed == 1


def _encryption(method: str, hint: str | None = "the hint") -> Any:
    from sopuli.driver.protocol import Encryption

    return Encryption(method=method, hint=hint)


@pytest.mark.parametrize("mode", ["REQUIRED", "VERIFY_CA", "VERIFY_IDENTITY"])
def test_a_mode_that_requires_tls_refuses_a_session_without_it(mode: str) -> None:
    """Read from the session, so the rule does not rest on PyMySQL alone."""
    with pytest.raises(session_module.UnencryptedSessionError) as caught:
        session_module.require_tls(_encryption("none"), _target(mode))

    assert caught.value.category == "connectivity"
    assert caught.value.code == "2026"
    assert f"without TLS under `ssl_mode: {mode}`" in str(caught.value)


def test_a_session_not_known_to_be_tls_is_refused_in_its_own_words() -> None:
    with pytest.raises(session_module.UnencryptedSessionError) as caught:
        session_module.require_tls(_encryption("unknown"), _target("REQUIRED"))

    assert "could not confirm TLS" in str(caught.value)
    assert caught.value.hint == "the hint"


def test_an_unknown_encryption_without_a_hint_still_says_something() -> None:
    with pytest.raises(session_module.UnencryptedSessionError) as caught:
        session_module.require_tls(_encryption("unknown", hint=None), _target("REQUIRED"))

    assert caught.value.hint
    assert caught.value.hint != "None"


@pytest.mark.parametrize("mode", ["DISABLED", "PREFERRED"])
def test_a_mode_that_does_not_require_tls_accepts_any_session(mode: str) -> None:
    session_module.require_tls(_encryption("none"), _target(mode))


def test_a_session_with_tls_passes_the_check() -> None:
    session_module.require_tls(_encryption("tls"), _target("REQUIRED"))


def _connected(monkeypatch: pytest.MonkeyPatch, connection: _Connection) -> Any:
    monkeypatch.setattr(session_module.pymysql, "connect", lambda **arguments: connection)
    return session_module.MysqlDriver(correlation_id="run").connect(
        _target("REQUIRED"), _credential()
    )


def test_connect_closes_a_session_it_refuses(monkeypatch: pytest.MonkeyPatch) -> None:
    connection = _Connection(tls="")

    with pytest.raises(session_module.UnencryptedSessionError):
        _connected(monkeypatch, connection)

    assert connection.closed == 1


def test_connect_reads_only_the_encryption_and_the_scope_does_not_read_it_again(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = _Connection(tls="TLSv1.3")

    session = _connected(monkeypatch, connection)

    assert connection.queries == [scope_module.TLS_VERSION]
    assert session.scope().encryption.method == "tls"
    assert connection.queries.count(scope_module.TLS_VERSION) == 1


def test_a_mariadb_server_connects_and_is_refused_by_its_scope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Not at connect: `doctor` reports a server that answered and is the
    wrong product as a configuration error, not as unreachable."""
    session = _connected(monkeypatch, _Connection(version="10.11.19-MariaDB-ubu2204-log"))

    with pytest.raises(scope_module.NotMysqlError):
        session.scope()


def _credential() -> Credential:
    return Credential(username="sopuli_svc", secret=Secret("Tr0ub4dor-and-3"))


def test_pymysqls_failure_of_a_plain_login_is_reported_as_what_it_is(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Measured on 8.4.13: a login the server has not cached fails inside
    PyMySQL 1.2.3 with an AttributeError over a plain connection."""

    def fail(**arguments: Any) -> Any:
        raise AttributeError("'NoneType' object has no attribute 'is_auth_switch_request'")

    monkeypatch.setattr(session_module.pymysql, "connect", fail)
    driver = session_module.MysqlDriver(correlation_id="run")

    with pytest.raises(session_module.PlainLoginError) as caught:
        driver.connect(_target("DISABLED"), _credential())

    assert caught.value.category == "connectivity"
    assert caught.value.code == "2000"
    assert "VERIFY_IDENTITY" in str(caught.value.hint)


@pytest.mark.parametrize("mode", ["DISABLED", "PREFERRED"])
def test_any_other_attribute_error_is_not_hidden(
    monkeypatch: pytest.MonkeyPatch, mode: str
) -> None:
    """Only PyMySQL's measured failure, by its exact text, is reported as a
    plain-login failure. Anything else is a fault, and surfaces as one."""

    def fail(**arguments: Any) -> Any:
        raise AttributeError("something else")

    monkeypatch.setattr(session_module.pymysql, "connect", fail)
    driver = session_module.MysqlDriver(correlation_id="run")

    with pytest.raises(AttributeError, match="something else"):
        driver.connect(_target(mode), _credential())


def test_a_failed_connect_is_classified_as_a_connect(monkeypatch: pytest.MonkeyPatch) -> None:
    import pymysql

    def fail(**arguments: Any) -> Any:
        raise pymysql.err.OperationalError(1045, "Access denied for user 'sopuli_svc'@'%'")

    monkeypatch.setattr(session_module.pymysql, "connect", fail)
    driver = session_module.MysqlDriver(correlation_id="run")

    with pytest.raises(DriverError) as caught:
        driver.connect(_target(), _credential())

    assert caught.value.code == "1045"
    assert caught.value.exit_code == ExitCode.AUTH_FAILURE
