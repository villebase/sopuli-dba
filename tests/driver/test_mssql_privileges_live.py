"""The SQL Server tool login's audit against a live server.

Tier 1 (#1550). The tool login reads itself: `HAS_PERMS_BY_NAME`,
`IS_SRVROLEMEMBER`, its grants on one login through nested roles, and its
user in `msdb`. What only a server can answer: that the reads work for a
login with `ALTER ANY LOGIN` alone, that the tool login sees its own nested
roles without `VIEW ANY DEFINITION`, and that `msdb`'s `guest` does not read
as a user. Everything set up is undone after, whatever the tool login held before.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from contextlib import suppress
from typing import Any

import pytest

from sopuli.config.model import ExpandedTarget, Target, TargetMssql
from sopuli.driver.mssql.privileges import MSDB_USER
from sopuli.driver.protocol import Credential, PrivilegeAudit
from sopuli.secrets import Secret

session_module = pytest.importorskip("sopuli.driver.mssql.session")


def _audit(live_mssql: Any) -> PrivilegeAudit:
    target = ExpandedTarget(
        target=Target(
            name="tier1-mssql",
            type="mssql",
            dsn=live_mssql.dsn,
            mssql=TargetMssql(trust_server_certificate=True),
        )
    )
    credential = Credential(username=live_mssql.tool_user, secret=Secret(live_mssql.tool_password))
    opened = session_module.MssqlDriver(correlation_id="t1-1550").connect(target, credential)
    try:
        audit: PrivilegeAudit = opened.privileges(accounts=())
        return audit
    finally:
        opened.close()


def _held(cursor: Any, tool: str, permission: str) -> bool:
    cursor.execute(
        "SELECT COUNT(*) FROM sys.server_permissions WHERE class = 100 AND state IN ('G', 'W') "
        "AND permission_name = ? AND grantee_principal_id = SUSER_ID(?)",
        permission,
        tool,
    )
    return bool(cursor.fetchone()[0])


def _undo(cursor: Any, statements: list[str]) -> None:
    """Each statement on its own: one that fails, say because the setup
    stopped before its object existed, does not keep the rest from running."""
    for statement in statements:
        with suppress(Exception):
            cursor.execute(statement)


@pytest.fixture
def nested(live_mssql: Any) -> Iterator[tuple[Any, str, str]]:
    """The tool login in a role nested in a role that holds IMPERSONATE on
    a login, and CONTROL on a server role. Yields `sa`'s cursor, the login's
    name and that role's; undoes everything, and puts back VIEW ANY
    DEFINITION as it was."""
    tag = uuid.uuid4().hex[:6]
    login, outer, inner = f"acme_t1_imp_{tag}", f"acme_t1_outer_{tag}", f"acme_t1_inner_{tag}"
    controlled = f"acme_t1_ctl_{tag}"
    tool = live_mssql.tool_user
    sa = live_mssql.connect()
    cursor = sa.cursor()
    had_view = _held(cursor, tool, "VIEW ANY DEFINITION")
    try:
        cursor.execute(
            f"CREATE LOGIN [{login}] WITH PASSWORD = N'Acme-Imp-pw1', CHECK_POLICY = OFF"
        )
        cursor.execute(f"CREATE SERVER ROLE [{outer}]")
        cursor.execute(f"CREATE SERVER ROLE [{inner}]")
        cursor.execute(f"CREATE SERVER ROLE [{controlled}]")
        cursor.execute(f"ALTER SERVER ROLE [{outer}] ADD MEMBER [{inner}]")
        cursor.execute(f"ALTER SERVER ROLE [{inner}] ADD MEMBER [{tool}]")
        cursor.execute(f"GRANT IMPERSONATE ON LOGIN::[{login}] TO [{outer}]")
        cursor.execute(f"GRANT CONTROL ON SERVER ROLE::[{controlled}] TO [{outer}]")
        yield cursor, login, controlled
    finally:
        verb = "GRANT" if had_view else "REVOKE"
        _undo(
            cursor,
            [
                f"ALTER SERVER ROLE [{inner}] DROP MEMBER [{tool}]",
                f"ALTER SERVER ROLE [{outer}] DROP MEMBER [{inner}]",
                f"DROP SERVER ROLE [{inner}]",
                f"DROP SERVER ROLE [{outer}]",
                f"DROP SERVER ROLE [{controlled}]",
                f"DROP LOGIN [{login}]",
                f"REVOKE VIEW ANY SECURITY DEFINITION FROM [{tool}]",
                f"{verb} VIEW ANY DEFINITION {'TO' if had_view else 'FROM'} [{tool}]",
            ],
        )
        sa.close()


def test_the_documented_grant_reads_as_held(live_mssql: Any) -> None:
    sa = live_mssql.connect()
    try:
        if _held(sa.cursor(), live_mssql.tool_user, "VIEW ANY DEFINITION"):
            pytest.skip("another test left VIEW ANY DEFINITION granted")
    finally:
        sa.close()
    found = _audit(live_mssql)
    assert found.held == ("ALTER ANY LOGIN",)
    assert found.missing == ()
    assert found.over_granted == ()
    assert found.unaudited == ()
    assert any("GRANT VIEW ANY DEFINITION" in remedy for remedy in found.remedies)


def test_a_grant_through_a_nested_role_is_seen_with_or_without_view_any_definition(
    live_mssql: Any, nested: tuple[Any, str, str]
) -> None:
    """The tool login sees its own roles' memberships, nested ones included,
    with ALTER ANY LOGIN alone, where it does not see another login's (PA2).
    A grant on a server role is the same class, and is not a grant on a
    login."""
    cursor, login, controlled = nested
    tool = live_mssql.tool_user
    cursor.execute(f"REVOKE VIEW ANY DEFINITION FROM [{tool}]")
    without = _audit(live_mssql)
    cursor.execute(f"GRANT VIEW ANY DEFINITION TO [{tool}]")
    with_grant = _audit(live_mssql)

    for found in (without, with_grant):
        assert f"IMPERSONATE ON LOGIN::[{login}]" in found.over_granted
        assert not any(controlled in held for held in found.over_granted)
        assert found.unaudited == ()
    assert "VIEW ANY DEFINITION" not in without.held
    assert "VIEW ANY DEFINITION" in with_grant.held


def test_a_denied_view_any_security_definition_leaves_the_grants_unchecked(
    live_mssql: Any, nested: tuple[Any, str, str]
) -> None:
    """FR5: the denial hides the rows, and the audit says so rather than
    reading as clean. The fixture revokes the denial."""
    cursor, login, _ = nested
    cursor.execute(f"DENY VIEW ANY SECURITY DEFINITION TO [{live_mssql.tool_user}]")
    found = _audit(live_mssql)

    assert f"IMPERSONATE ON LOGIN::[{login}]" not in found.over_granted
    assert found.unaudited == ("CONTROL or IMPERSONATE on a login",)


def test_a_user_in_msdb_is_over_granted_and_guest_is_not(live_mssql: Any) -> None:
    tool = live_mssql.tool_user
    assert MSDB_USER not in _audit(live_mssql).over_granted
    sa = live_mssql.connect()
    try:
        sa.cursor().execute(f"USE msdb; CREATE USER [{tool}] FOR LOGIN [{tool}]; USE master;")
        try:
            assert MSDB_USER in _audit(live_mssql).over_granted
        finally:
            sa.cursor().execute(f"USE msdb; DROP USER [{tool}]; USE master;")
    finally:
        sa.close()


def test_a_closed_msdb_guest_leaves_the_rest_of_the_audit(live_mssql: Any) -> None:
    """With guest's CONNECT revoked in msdb the read is refused; the audit
    says it could not read msdb, and gives the rest."""
    sa = live_mssql.connect()
    try:
        sa.cursor().execute("USE msdb; REVOKE CONNECT FROM guest; USE master;")
        try:
            found = _audit(live_mssql)
        finally:
            sa.cursor().execute("USE msdb; GRANT CONNECT TO guest; USE master;")
    finally:
        sa.close()

    assert found.unreadable == ("msdb.sys.database_principals",)
    assert "ALTER ANY LOGIN" in found.held
