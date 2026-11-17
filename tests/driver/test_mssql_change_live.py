"""SQL Server's password change, against the tier-1 server (#1551).

``02-mssql-privileges.md`` §6.2's order, one step at a time, as a tool login
with §2.1's grant and ``VIEW ANY DEFINITION``, which guardrail 9 needs to let a
change through (#1567). The fixture's own tool login holds the first alone, so
this module makes one of its own, and drops what it made.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest

pytest.importorskip("pyodbc")

from sopuli.config.model import ExpandedTarget, Target, TargetMssql  # noqa: E402
from sopuli.driver.protocol import FAIL, PASS, Credential  # noqa: E402
from sopuli.policy_flags import PolicyFlags  # noqa: E402
from sopuli.secrets import Secret  # noqa: E402

TOOL, TOOL_PASSWORD = "w1_tool", "W1-tool-pw-1"
LOGIN, OLD, NEW = "w1_acme_app", "W1-old-pw-1", "W1-new-pw-2"


def flags(stack: Any) -> tuple[bool, bool]:
    connection = stack.connect()
    try:
        row = (
            connection.cursor()
            .execute(
                "SELECT is_policy_checked, is_expiration_checked FROM sys.sql_logins "
                "WHERE name = ?",
                LOGIN,
            )
            .fetchone()
        )
        return bool(row[0]), bool(row[1])
    finally:
        connection.close()


@pytest.fixture
def tool_session(live_mssql: Any) -> Iterator[Any]:
    from sopuli.driver.mssql.session import MssqlDriver

    connection = live_mssql.connect()
    cursor = connection.cursor()
    for login in (TOOL, LOGIN):
        cursor.execute(f"IF SUSER_ID(N'{login}') IS NOT NULL DROP LOGIN [{login}]")
    cursor.execute(f"CREATE LOGIN [{TOOL}] WITH PASSWORD = N'{TOOL_PASSWORD}', CHECK_POLICY = ON")
    cursor.execute(f"GRANT ALTER ANY LOGIN TO [{TOOL}]")
    cursor.execute(f"GRANT VIEW ANY DEFINITION TO [{TOOL}]")
    cursor.execute(
        f"CREATE LOGIN [{LOGIN}] WITH PASSWORD = N'{OLD}', CHECK_POLICY = ON, CHECK_EXPIRATION = ON"
    )
    target = ExpandedTarget(
        target=Target(
            name="mssql-dev",
            type="mssql",
            dsn=live_mssql.dsn,
            mssql=TargetMssql(trust_server_certificate=True),
        )
    )
    opened = MssqlDriver(correlation_id="w1-change").connect(
        target, Credential(username=TOOL, secret=Secret(TOOL_PASSWORD))
    )
    try:
        yield opened
    finally:
        opened.close()
        for login in (LOGIN, TOOL):
            cursor.execute(f"IF SUSER_ID(N'{login}') IS NOT NULL DROP LOGIN [{login}]")
        connection.close()


def test_the_change_runs_in_order_and_sets_the_flags_back(
    tool_session: Any, live_mssql: Any
) -> None:
    assert tool_session.verify_password(LOGIN, Secret(OLD)).result == PASS
    before = tool_session.policy_flags(LOGIN)
    assert before == PolicyFlags(check_policy=True, check_expiration=True)

    assert tool_session.set_password(LOGIN, Secret(NEW)).changed
    # Step 2 turned the policy off, and expiry with it (mssql-policy-off).
    assert flags(live_mssql) == (False, False)
    assert tool_session.verify_password(LOGIN, Secret(NEW)).result == PASS
    assert tool_session.verify_password(LOGIN, Secret(OLD)).result == FAIL

    assert tool_session.restore_policy(LOGIN, before)
    assert flags(live_mssql) == (True, True)
    assert tool_session.verify_password(LOGIN, Secret(NEW)).result == PASS


def test_guardrail_9_reads_the_paths_with_view_any_definition(tool_session: Any) -> None:
    state = tool_session.describe_user(LOGIN)
    assert state is not None
    assert state.admin_unread is None
    assert state.global_privileges == frozenset()
