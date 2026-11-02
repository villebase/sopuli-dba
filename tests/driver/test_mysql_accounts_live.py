"""Reading MySQL accounts against the tier-1 `mysql` service (8.4.13). Tier 1.

The tool account holds the grants of `02-mysql-privileges.md` §2.1, so it reads
the columns of `mysql.user` the driver needs. Each test creates its own
accounts, with random names, and drops them.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from contextlib import suppress
from dataclasses import dataclass, field
from typing import Any

import pytest

from sopuli.config.model import ExpandedTarget, Target, TargetMysql
from sopuli.driver.protocol import Credential
from sopuli.secrets import Secret

pymysql = pytest.importorskip("pymysql")
session_module = pytest.importorskip("sopuli.driver.mysql.session")
accounts_module = pytest.importorskip("sopuli.driver.mysql.accounts")

#: The columns the survey reads, revoked in one test.
COLUMNS = (
    "User, Host, plugin, account_locked, password_expired, password_last_changed, password_lifetime"
)


@dataclass
class Stage:
    """A session as a tool account with §2.1's grants, and the accounts a test
    created, dropped afterwards."""

    live: Any
    tool: str
    session: Any
    created: list[tuple[str, str]] = field(default_factory=list)

    def admin(self, statement: str, args: tuple[Any, ...] = ()) -> None:
        with self.live.connect() as admin, admin.cursor() as cursor:
            cursor.execute(statement, args)

    def account(self, host: str, user: str | None = None, *, extra: str = "") -> str:
        """Create `user@host` with a password, and return the user name."""
        name = user or f"acme_app_{uuid.uuid4().hex[:8]}"
        self.created.append((name, host))
        self.admin(f"create user %s@%s identified {extra or 'by %s'}", (name, host, "Acme-pw1"))
        return name


@pytest.fixture
def stage(live_mysql: Any) -> Iterator[Stage]:
    tool, password = f"sopuli_tool_{uuid.uuid4().hex[:8]}", uuid.uuid4().hex
    with live_mysql.connect() as admin, admin.cursor() as cursor:
        cursor.execute("create user %s@'%%' identified by %s", (tool, password))
    live_mysql.grant_section_2(tool)
    target = ExpandedTarget(
        target=Target(
            name="tier1-mysql",
            type="mysql",
            dsn=live_mysql.dsn,
            mysql=TargetMysql(ssl_mode="REQUIRED"),
        )
    )
    session = session_module.MysqlDriver(correlation_id="tier1").connect(
        target, Credential(username=tool, secret=Secret(password))
    )
    staged = Stage(live=live_mysql, tool=tool, session=session)
    try:
        yield staged
    finally:
        session.close()
        with live_mysql.connect() as admin, admin.cursor() as cursor:
            for user, host in [(tool, "%"), *staged.created]:
                with suppress(pymysql.Error):
                    cursor.execute("drop user %s@%s", (user, host))


def test_describe_reads_a_locked_account_at_its_host(stage: Stage) -> None:
    user = stage.account("10.%")
    stage.account("localhost", user)
    stage.admin("alter user %s@'10.%%' account lock", (user,))

    state = stage.session.describe_user(f"{user}@10.%")

    assert state is not None
    assert state.name == f"{user}@10.%"
    assert state.locked is True
    assert state.status == accounts_module.LOCKED
    assert state.password_changed_at is not None
    assert stage.session.describe_user(f"{user}@192.0.2.%") is None


def test_the_tool_s_own_account_is_the_session_s_and_only_check_7_refuses_it(
    stage: Stage,
) -> None:
    """`CURRENT_USER()` names the tool account, which holds `CREATE USER ON
    *.*`. Check 7 refuses it and `--force` waives that; check 9 exempts it, so
    #1059's rotation of the tool's own password works on MySQL (#1225)."""
    from sopuli.driver import guardrails

    own = stage.session.describe_user(f"{stage.tool}@%")
    other = stage.session.describe_user(f"{stage.account('%')}@%")

    assert own is not None
    assert other is not None
    assert own.session_account is True
    assert other.session_account is False
    assert any(held.startswith("CREATE USER ON *.*") for held in own.global_privileges)

    reviewed = guardrails.review(own, declared=(own.name,))
    assert [refusal.check for refusal in reviewed.refusals] == [guardrails.OWN_ACCOUNT]
    assert guardrails.review(own, declared=(own.name,), force=True).permitted


PASSWORD = "Acme-pw1"


def test_check_logs_in_as_a_user_s_only_account_at_any_host(stage: Stage) -> None:
    """The one kind of account a login can only reach (#1223)."""
    user = stage.account("%")
    stage.admin("alter user %s@'%%' identified by %s", (user, PASSWORD))

    right = stage.session.verify_password(f"{user}@%", Secret(PASSWORD))
    wrong = stage.session.verify_password(f"{user}@%", Secret("Not-the-pw9"))

    assert right.result == "pass"
    assert right.latency_ms is not None
    assert "lockout guard is unavailable" in str(right.detail)
    assert wrong.result == "fail"
    assert "(1045)" in str(wrong.detail)


def test_an_expired_password_that_logs_in_passes(stage: Stage) -> None:
    """PyMySQL 1.2.3 meets `1862` at connect, after the password was accepted."""
    user = stage.account("%")
    stage.admin("alter user %s@'%%' identified by %s password expire", (user, PASSWORD))

    result = stage.session.verify_password(f"{user}@%", Secret(PASSWORD))

    assert result.result == "pass"
    assert "(1862)" in str(result.detail)


def test_a_locked_account_is_not_logged_in_as(stage: Stage) -> None:
    user = stage.account("%")
    stage.admin("alter user %s@'%%' account lock", (user,))

    result = stage.session.verify_password(f"{user}@%", Secret(PASSWORD))

    assert result.result == "unavailable"
    assert "no login was attempted" in str(result.detail)


@pytest.mark.parametrize("hosts", [("10.%",), ("%", "10.%")])
def test_an_account_another_host_could_answer_for_is_not_logged_in_as(
    stage: Stage, hosts: tuple[str, ...]
) -> None:
    """Measured: a login from the tool's host reaches the `%` account, so the
    `10.%` account's own password is refused with 1045 (#1223)."""
    user = stage.account(hosts[0])
    for host in hosts[1:]:
        stage.account(host, user)

    result = stage.session.verify_password(f"{user}@{hosts[-1]}", Secret(PASSWORD))

    assert result.result == "unavailable"
    assert result.latency_ms is None, "no login was made"


def test_an_anonymous_account_at_a_named_host_stops_the_login(stage: Stage) -> None:
    """`''@localhost` would win over `acme_app@%` for a client on localhost, so
    the tool does not log in where one exists (#1223)."""
    user = stage.account("%")
    stage.created.append(("", "localhost"))
    stage.admin("create user ''@'localhost'")

    result = stage.session.verify_password(f"{user}@%", Secret(PASSWORD))

    assert result.result == "unavailable"
    assert "anonymous account ''@localhost" in str(result.detail)
    assert result.latency_ms is None, "no login was made"


def test_an_account_on_another_plugin_is_refused_before_a_login(stage: Stage) -> None:
    """As `describe_user` refuses it: the tool manages no other plugin."""
    user = stage.account("%", extra="with sha256_password by %s")

    with pytest.raises(accounts_module.OtherPluginError, match="uses sha256_password"):
        stage.session.verify_password(f"{user}@%", Secret(PASSWORD))


def test_hash_verification_is_refused_by_capability(stage: Stage) -> None:
    from sopuli.driver.protocol import UnsupportedCapabilityError

    user = stage.account("%")
    with pytest.raises(UnsupportedCapabilityError, match="offline_verify"):
        stage.session.verify_password(f"{user}@%", Secret(PASSWORD), method="hash")


def test_another_plugin_is_refused(stage: Stage) -> None:
    """8.4.13 ships sha256_password, deprecated; mysql_native_password is off."""
    user = stage.account("%", extra="with sha256_password by %s")

    with pytest.raises(accounts_module.OtherPluginError, match="uses sha256_password"):
        stage.session.describe_user(f"{user}@%")


def test_check_privileges_reports_the_declared_accounts(stage: Stage) -> None:
    user = stage.account("10.%")
    stage.account("localhost", user)

    audit = stage.session.privileges(accounts=(f"{user}@10.%", "acme_none@%"))

    assert audit.missing == ()
    assert audit.unreadable == ()
    assert any(
        f"{user}@localhost exists and the config does not declare it" in line
        for line in audit.remedies
    )
    assert any("acme_none@% does not exist on this server" in line for line in audit.remedies)


def test_global_privileges_are_read_through_every_path(stage: Stage) -> None:
    """As the tool account, with only §2.1's grants: a static and a dynamic
    global privilege through a role two levels down, a schema pattern that
    matches `mysql`, a column of `mysql.user`, and a mandatory role. A proxy
    grant needs root@localhost, which this fixture does not reach; tier 0
    covers it."""
    admin_module = pytest.importorskip("sopuli.driver.mysql.admin")
    user = stage.account("10.%")
    outer, inner, mandatory = (f"acme_r{n}_{uuid.uuid4().hex[:6]}" for n in range(3))
    for role in (outer, inner, mandatory):
        stage.admin("create role %s", (role,))
        stage.created.append((role, "%"))
    stage.admin("grant %s to %s", (inner, outer))
    stage.admin("grant %s to %s@'10.%%'", (outer, user))
    stage.admin("grant reload, backup_admin on *.* to %s", (inner,))
    stage.admin("grant select on `mysq%%`.* to %s", (inner,))
    stage.admin("grant select (authentication_string) on mysql.user to %s@'10.%%'", (user,))
    stage.admin("grant process on *.* to %s", (mandatory,))
    stage.admin("set global mandatory_roles = %s", (mandatory,))
    try:
        with stage.session.connection.cursor() as cursor:
            found = admin_module.global_privileges(cursor, admin_module.Principal(user, "10.%"))
    finally:
        stage.admin("set global mandatory_roles = ''")

    assert found == {
        f"RELOAD ON *.* through {inner}@%",
        f"BACKUP_ADMIN ON *.* through {inner}@%",
        f"SELECT ON mysql.* through {inner}@%",
        "SELECT (authentication_string) ON mysql.user",
        f"PROCESS ON *.* through {mandatory}@%",
    }


def test_guardrail_9_refuses_a_described_account_with_a_global_privilege(stage: Stage) -> None:
    """End to end: the driver reads the privilege, and the guardrail refuses
    the account even with --force."""
    from sopuli.driver import guardrails

    user = stage.account("10.%")
    stage.admin("grant select on *.* to %s@'10.%%'", (user,))
    name = f"{user}@10.%"

    state = stage.session.describe_user(name)

    assert state is not None
    assert state.global_privileges == {"SELECT ON *.*"}
    review = guardrails.review(state, declared=[name], force=True)
    assert [refusal.check for refusal in review.refusals] == [guardrails.GLOBAL_PRIVILEGE]


def test_a_password_set_by_the_driver_reaches_no_log_and_logs_in(
    stage: Stage, live_mysql: Any
) -> None:
    """Invariant 15 on MySQL. With the general log on, written to a table, and
    performance_schema's long statement history on, the driver sets a
    password. The statement is in both, and the password is in neither. The
    account then logs in with it."""
    user = stage.account("%")
    password = f"Acme-Leak-{uuid.uuid4().hex[:12]}"
    consumer = (
        "select enabled from performance_schema.setup_consumers "
        "where name = 'events_statements_history_long'"
    )
    with live_mysql.connect() as admin, admin.cursor() as cursor:
        cursor.execute("select @@global.log_output, @@global.general_log")
        log_output, general_log = cursor.fetchone()
        cursor.execute(consumer)
        (enabled,) = cursor.fetchone()
    stage.admin("set global log_output = 'TABLE'")
    stage.admin("set global general_log = 'ON'")
    stage.admin(
        "update performance_schema.setup_consumers set enabled = 'YES' "
        "where name = 'events_statements_history_long'"
    )
    try:
        result = stage.session.set_password(f"{user}@%", Secret(password))
        with live_mysql.connect() as admin, admin.cursor() as cursor:
            cursor.execute(
                "select convert(argument using utf8mb4) from mysql.general_log "
                "where convert(argument using utf8mb4) like %s",
                (f"%{user}%",),
            )
            logged = [row[0] for row in cursor.fetchall()]
            cursor.execute(
                "select sql_text from performance_schema.events_statements_history_long "
                "where sql_text like %s",
                (f"%{user}%",),
            )
            history = [row[0] for row in cursor.fetchall()]
    finally:
        # The server as it was, and none of the rows this test made it log.
        stage.admin("set global general_log = 'OFF'")
        stage.admin("truncate table mysql.general_log")
        stage.admin("set global log_output = %s", (log_output,))
        stage.admin("set global general_log = %s", (general_log,))
        stage.admin(
            "update performance_schema.setup_consumers set enabled = %s "
            "where name = 'events_statements_history_long'",
            (enabled,),
        )

    assert result.changed is True
    assert any("ALTER USER" in line for line in logged), "the log saw the statement"
    assert any("ALTER USER" in line for line in history), "the history saw it"
    assert not any(password in line for line in [*logged, *history])
    login = live_mysql.connect_as(user, password)
    login.close()


@pytest.mark.parametrize("sql_mode", ["", "NO_BACKSLASH_ESCAPES", "ANSI_QUOTES"])
def test_a_name_with_a_quote_and_a_backslash_gets_its_password(
    stage: Stage, live_mysql: Any, sql_mode: str
) -> None:
    """The statement names the account between backquotes, which no
    `sql_mode` reads differently."""
    user = stage.account("%", f"acme_o'b\\{uuid.uuid4().hex[:8]}")
    stage.session.connection.query(f"set session sql_mode = '{sql_mode}'")
    password = f"Acme-Mode-{uuid.uuid4().hex[:12]}"

    result = stage.session.set_password(f"{user}@%", Secret(password))

    assert result.changed is True
    login = live_mysql.connect_as(user, password)
    login.close()


def test_without_the_column_grant_mysql_user_is_unreadable(stage: Stage) -> None:
    """A column privilege applies to the session's next statement. The server
    refuses the read, and the audit is partial rather than failed."""
    user = stage.account("%")
    stage.admin(f"revoke select ({COLUMNS}) on mysql.user from %s@'%%'", (stage.tool,))

    audit = stage.session.privileges(accounts=(f"{user}@%",))

    assert audit.unreadable == ("mysql.user",)
    assert "SELECT (plugin) ON mysql.user" in audit.missing
