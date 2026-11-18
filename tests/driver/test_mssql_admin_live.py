"""Guardrail 9's catalog read against a live SQL Server.

Tier 1 (#1553). `sa` sets up one login per path of `02-mssql-privileges.md`
§5, and the tool login reads the catalog as the tool does: with `ALTER ANY
LOGIN` alone first, then with `VIEW ANY DEFINITION` as well. What only a
server can answer: that the read sees each path, and that without the grant
it reads nothing. `public`'s path is left to tier 0: a grant to `public`
would reach every other test on the server.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

import pytest

from sopuli.config.model import ExpandedTarget, Target, TargetMssql
from sopuli.driver.mssql.admin import (
    MISSING_GRANT,
    PARTIAL_READ,
    Catalog,
    assess,
    read_catalog,
)
from sopuli.driver.protocol import Credential, UnsupportedCapabilityError
from sopuli.secrets import Secret

pyodbc = pytest.importorskip("pyodbc")

#: A test password, not a credential.
PASSWORD = "Acme-Guard-pw1"


class Paths:
    """The logins and roles one module run makes, each named with a suffix
    of its own, so that a run left behind by a crash does not collide."""

    def __init__(self) -> None:
        tag = uuid.uuid4().hex[:6]
        self.tag = tag
        self.plain = f"acme_t1_plain_{tag}"
        self.ctl = f"acme_t1_ctl_{tag}"
        self.nest = f"acme_t1_nest_{tag}"
        self.owned = f"acme_t1_owned_{tag}"
        self.other = f"acme_t1_other_{tag}"

    def holder(self, path: str) -> str:
        return f"acme_t1_{path}_{self.tag}"


#: Each path: the statements `sa` runs for it, with `{h}` the holder, and the
#: findings the guardrail reports, with `{ctl}` and the others the names.
PATHS: dict[str, tuple[tuple[str, ...], frozenset[str]]] = {
    "none": ((), frozenset()),
    "sysadmin": (("ALTER SERVER ROLE [sysadmin] ADD MEMBER [{h}]",), frozenset({"sysadmin"})),
    "server": (("GRANT CONTROL SERVER TO [{h}]",), frozenset({"CONTROL SERVER"})),
    "roles": (("GRANT ALTER ANY SERVER ROLE TO [{h}]",), frozenset({"ALTER ANY SERVER ROLE"})),
    "control": (
        ("GRANT CONTROL ON LOGIN::[{plain}] TO [{h}]",),
        frozenset({"CONTROL ON LOGIN::[{plain}]"}),
    ),
    "impersonate": (
        ("GRANT IMPERSONATE ON LOGIN::[{plain}] TO [{h}]",),
        frozenset({"IMPERSONATE ON LOGIN::[{plain}]"}),
    ),
    "alter_role": (
        ("GRANT ALTER ON SERVER ROLE::[{ctl}] TO [{h}]",),
        frozenset({"ALTER ON SERVER ROLE::[{ctl}]"}),
    ),
    "take_role": (
        ("GRANT TAKE OWNERSHIP ON SERVER ROLE::[{ctl}] TO [{h}]",),
        frozenset({"TAKE OWNERSHIP ON SERVER ROLE::[{ctl}]"}),
    ),
    "other_role": (("GRANT CONTROL ON SERVER ROLE::[{other}] TO [{h}]",), frozenset()),
    "owner": (
        ("ALTER AUTHORIZATION ON SERVER ROLE::[{owned}] TO [{h}]",),
        frozenset({"ownership of SERVER ROLE::[{owned}]"}),
    ),
    "nested": (
        ("ALTER SERVER ROLE [{nest}] ADD MEMBER [{h}]",),
        frozenset({"CONTROL SERVER through [{ctl}]"}),
    ),
}


def _names(paths: Paths, holder: str) -> dict[str, str]:
    return {
        "h": holder,
        "plain": paths.plain,
        "ctl": paths.ctl,
        "nest": paths.nest,
        "owned": paths.owned,
        "other": paths.other,
    }


@pytest.fixture(scope="module")
def server(live_mssql: Any) -> Iterator[tuple[Any, Paths, bool]]:
    """`sa`'s setup, the names, and whether the server has
    `##MS_LoginManager##`; everything is dropped after."""
    paths = Paths()
    holders = [paths.holder(path) for path in PATHS] + [paths.holder("loginmanager")]
    sa = live_mssql.connect()
    cursor = sa.cursor()
    try:
        for login in (paths.plain, *holders):
            cursor.execute(
                f"CREATE LOGIN [{login}] WITH PASSWORD = N'{PASSWORD}', CHECK_POLICY = OFF"
            )
        for role in (paths.ctl, paths.nest, paths.owned, paths.other):
            cursor.execute(f"CREATE SERVER ROLE [{role}]")
        cursor.execute(f"GRANT CONTROL SERVER TO [{paths.ctl}]")
        cursor.execute(f"GRANT CONTROL SERVER TO [{paths.owned}]")
        cursor.execute(f"ALTER SERVER ROLE [{paths.ctl}] ADD MEMBER [{paths.nest}]")
        for path, (statements, _) in PATHS.items():
            for statement in statements:
                cursor.execute(statement.format(**_names(paths, paths.holder(path))))
        cursor.execute("SELECT SUSER_ID(N'##MS_LoginManager##')")
        manager = cursor.fetchone()[0] is not None
        if manager:
            cursor.execute(
                "ALTER SERVER ROLE [##MS_LoginManager##] ADD MEMBER "
                f"[{paths.holder('loginmanager')}]"
            )
        yield sa, paths, manager
    finally:
        # Logins own roles and sit in them, so the roles go first.
        for role in (paths.nest, paths.ctl, paths.owned, paths.other):
            cursor.execute(
                f"IF SUSER_ID(N'{role}') IS NOT NULL BEGIN "
                f"ALTER AUTHORIZATION ON SERVER ROLE::[{role}] TO [sa]; "
                f"DECLARE @drop nvarchar(max) = N''; "
                "SELECT @drop += N'ALTER SERVER ROLE ' + QUOTENAME(r.name) + N' DROP MEMBER ' "
                "+ QUOTENAME(m.name) + N';' FROM sys.server_role_members AS x "
                "JOIN sys.server_principals AS r ON r.principal_id = x.role_principal_id "
                "JOIN sys.server_principals AS m ON m.principal_id = x.member_principal_id "
                f"WHERE x.role_principal_id = SUSER_ID(N'{role}') "
                f"OR x.member_principal_id = SUSER_ID(N'{role}'); "
                f"EXEC (@drop); DROP SERVER ROLE [{role}] END"
            )
        # The holders first: a grant on `plain` keeps it, 15173.
        for login in (*holders, paths.plain):
            cursor.execute(f"IF SUSER_ID(N'{login}') IS NOT NULL DROP LOGIN [{login}]")
        sa.close()


def _read(live_mssql: Any) -> Catalog:
    tool = live_mssql.connect_as(live_mssql.tool_user, live_mssql.tool_password)
    try:
        return read_catalog(tool.cursor())
    finally:
        tool.close()


@contextmanager
def _view_definitions(sa: Any, tool_user: str, *, held: bool) -> Iterator[None]:
    """The tool login with `VIEW ANY DEFINITION` or without it, and then as
    it was before: another module may have granted it."""
    cursor = sa.cursor()
    cursor.execute(
        "SELECT COUNT(*) FROM sys.server_permissions WHERE class = 100 "
        "AND permission_name = 'VIEW ANY DEFINITION' AND state IN ('G', 'W') "
        "AND grantee_principal_id = SUSER_ID(?)",
        tool_user,
    )
    before = cursor.fetchone()[0] > 0
    grant = f"GRANT VIEW ANY DEFINITION TO [{tool_user}]"
    revoke = f"REVOKE VIEW ANY DEFINITION FROM [{tool_user}]"
    cursor.execute(grant if held else revoke)
    try:
        yield
    finally:
        if before != held:
            cursor.execute(grant if before else revoke)


def _id(sa: Any, name: str) -> int:
    cursor = sa.cursor()
    cursor.execute("SELECT SUSER_ID(?)", name)
    return int(cursor.fetchone()[0])


def test_without_view_any_definition_the_read_refuses_every_login(
    live_mssql: Any, server: tuple[Any, Paths, bool]
) -> None:
    """#1567: the tool login of §2.1 alone reads nothing for the guardrail."""
    sa, paths, _ = server
    with _view_definitions(sa, live_mssql.tool_user, held=False):
        read = _read(live_mssql)

    assert not read.complete
    assert assess(_id(sa, paths.plain), read).unread == MISSING_GRANT


def test_a_deny_on_one_role_refuses_every_login(
    live_mssql: Any, server: tuple[Any, Paths, bool]
) -> None:
    """The review of #1573: the denial hides the role's row while
    HAS_PERMS_BY_NAME still answers 1, and its grant rows name an id the read
    has no row for."""
    sa, paths, _ = server
    deny = f"DENY VIEW DEFINITION ON SERVER ROLE::[{paths.ctl}] TO [{live_mssql.tool_user}]"
    with _view_definitions(sa, live_mssql.tool_user, held=True):
        sa.cursor().execute(deny)
        try:
            read = _read(live_mssql)
        finally:
            sa.cursor().execute(deny.replace("DENY", "REVOKE", 1))

    assert read == Catalog(unread=PARTIAL_READ)
    assert assess(_id(sa, paths.plain), read).unread == PARTIAL_READ


def test_with_view_any_definition_every_path_is_seen(
    live_mssql: Any, server: tuple[Any, Paths, bool]
) -> None:
    """PA4: with the grant, the read sees each role, its owner, and a role
    nested in another, and the guardrail finds every path."""
    sa, paths, manager = server
    with _view_definitions(sa, live_mssql.tool_user, held=True):
        read = _read(live_mssql)

    assert read.complete
    got = {path: assess(_id(sa, paths.holder(path)), read) for path in PATHS}
    expected = {
        path: frozenset(f.format(**_names(paths, paths.holder(path))) for f in findings)
        for path, (_, findings) in PATHS.items()
    }
    assert {path: found.grants for path, found in got.items()} == expected
    assert all(found.unread is None for found in got.values())
    assert assess(_id(sa, paths.plain), read).grants == frozenset()
    if manager:
        # FR2: the role gives ALTER ANY LOGIN and has no permission rows.
        found = assess(_id(sa, paths.holder("loginmanager")), read)
        assert found.grants == frozenset({"##MS_LoginManager##"})


def test_the_session_reads_the_catalog_once(
    live_mssql: Any, server: tuple[Any, Paths, bool]
) -> None:
    """`admin_assessment` through the driver's own connection: one read per
    session, whatever the number of logins assessed."""
    session_module = pytest.importorskip("sopuli.driver.mssql.session")
    sa, paths, _ = server
    target = ExpandedTarget(
        target=Target(
            name="tier1-mssql",
            type="mssql",
            dsn=live_mssql.dsn,
            mssql=TargetMssql(trust_server_certificate=True),
        )
    )
    credential = Credential(username=live_mssql.tool_user, secret=Secret(live_mssql.tool_password))
    with _view_definitions(sa, live_mssql.tool_user, held=True):
        session = session_module.MssqlDriver(correlation_id="t1-1553").connect(target, credential)
        try:
            server_found = session.admin_assessment(_id(sa, paths.holder("server")))
            catalog = session._catalog
            plain = session.admin_assessment(_id(sa, paths.plain))
            assert session._catalog is catalog
        finally:
            session.close()

    assert server_found.grants == frozenset({"CONTROL SERVER"})
    assert plain.grants == frozenset()


def _session(live_mssql: Any) -> Any:
    session_module = pytest.importorskip("sopuli.driver.mssql.session")
    target = ExpandedTarget(
        target=Target(
            name="tier1-mssql",
            type="mssql",
            dsn=live_mssql.dsn,
            mssql=TargetMssql(trust_server_certificate=True),
        )
    )
    credential = Credential(username=live_mssql.tool_user, secret=Secret(live_mssql.tool_password))
    return session_module.MssqlDriver(correlation_id="t1-1554").connect(target, credential)


def test_a_role_rule_follows_nested_server_roles(
    live_mssql: Any, server: tuple[Any, Paths, bool]
) -> None:
    """#1554, Q6: a `role:` names a server role, and its members are
    followed through nested server roles. The holder is in `nest`, which
    is in `ctl`."""
    sa, paths, _ = server
    holder = paths.holder("nested")
    with _view_definitions(sa, live_mssql.tool_user, held=True):
        session = _session(live_mssql)
        try:
            spelled = session.resolve_role(paths.ctl.upper())
            members = session.accounts_matching(role=paths.ctl)
            state = session.describe_user(holder)
            missing = session.resolve_role(f"acme_t1_nobody_{paths.tag}")
        finally:
            session.close()

    assert spelled == paths.ctl
    assert holder in members
    assert paths.plain not in members
    assert state is not None
    assert {paths.nest.upper(), paths.ctl.upper()} <= state.roles
    assert missing is None


def test_without_view_any_definition_a_role_rule_is_refused_naming_the_grant(
    live_mssql: Any, server: tuple[Any, Paths, bool]
) -> None:
    sa, paths, _ = server
    with _view_definitions(sa, live_mssql.tool_user, held=False):
        session = _session(live_mssql)
        try:
            with pytest.raises(UnsupportedCapabilityError) as caught:
                session.resolve_role(paths.ctl)
        finally:
            session.close()

    assert caught.value.capability == "role_lookup"
    assert "GRANT VIEW ANY DEFINITION" in (caught.value.remedy or "")


def test_the_tool_login_reads_its_own_grant(
    live_mssql: Any, server: tuple[Any, Paths, bool]
) -> None:
    """The tool login holds ALTER ANY LOGIN; check 9 exempts it as the
    session's own login (#1222), and the read still reports it."""
    sa, _, _ = server
    with _view_definitions(sa, live_mssql.tool_user, held=True):
        read = _read(live_mssql)

    assert "ALTER ANY LOGIN" in assess(_id(sa, live_mssql.tool_user), read).grants
