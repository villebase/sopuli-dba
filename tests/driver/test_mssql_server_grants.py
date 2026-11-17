"""The server-level privileges of SQL Server logins
(:mod:`sopuli.driver.mssql.server_grants`, #1555). Tier 0."""

from __future__ import annotations

from typing import Any

from sopuli.driver.grants import OBJECT, GrantRow
from sopuli.driver.mssql import server_grants
from sopuli.driver.mssql.admin import VIEW_DEFINITIONS
from sopuli.driver.mssql.server_grants import (
    DENIED_SECURITY,
    FIXED_ROLE_LEVEL,
    NO_DEFINITIONS,
    PARTIAL_READ,
    PUBLIC_GRANTEE,
    SERVER_LEVEL,
    WINDOWS_GROUPS,
    Permission,
    Principal,
)

APP, OPS, SVC = 270, 271, 272
PUBLIC_ID, SYSADMIN, READERS, MONITORS = 2, 3, 300, 301
ENDPOINT = 4

PRINCIPALS = [
    Principal(APP, "acme_app_user", "S"),
    Principal(OPS, "acme_ops_user", "S"),
    Principal(SVC, "EXAMPLE\\acme_svc", "U"),
    Principal(PUBLIC_ID, "public", "R", fixed=False),
    Principal(SYSADMIN, "sysadmin", "R", fixed=True),
    Principal(READERS, "acme_readers", "R"),
    Principal(MONITORS, "acme_monitors", "R"),
]
#: acme_app_user is in acme_readers, which is in acme_monitors; acme_ops_user
#: is in sysadmin.
MEMBERSHIPS = [(READERS, APP), (MONITORS, READERS), (SYSADMIN, OPS)]
PERMISSIONS = [
    Permission(PUBLIC_ID, "CONNECT SQL", 100, "SERVER", 0, "G"),
    Permission(PUBLIC_ID, "VIEW ANY DATABASE", 100, "SERVER", 0, "G"),
    Permission(APP, "CONNECT SQL", 100, "SERVER", 0, "G"),
    Permission(APP, "IMPERSONATE", 101, "SERVER_PRINCIPAL", SVC, "W"),
    Permission(READERS, "VIEW SERVER STATE", 100, "SERVER", 0, "G"),
    Permission(MONITORS, "VIEW ANY DEFINITION", 100, "SERVER", 0, "G"),
    Permission(MONITORS, "CONNECT", 105, "ENDPOINT", ENDPOINT, "G", "TSQL Default TCP"),
    Permission(MONITORS, "ALTER", 108, "AVAILABILITY GROUP", 65536, "G"),
    Permission(APP, "ALTER TRACE", 100, "SERVER", 0, "D"),
]


def survey(accounts: tuple[str, ...] = ("acme_app_user",), **kw: Any) -> Any:
    return server_grants.survey(PRINCIPALS, MEMBERSHIPS, PERMISSIONS, accounts, **kw)


def privileges(rows: tuple[GrantRow, ...] | None) -> set[tuple[str, str, tuple[str, ...]]]:
    assert rows is not None
    return {(row.grantee, row.privilege, row.path) for row in rows}


def test_server_permissions_come_with_each_path_through_nested_roles() -> None:
    found = survey(public=False)

    assert privileges(found.system) == {
        ("acme_app_user", "CONNECT SQL", ()),
        ("acme_app_user", "VIEW SERVER STATE", ("acme_readers",)),
        ("acme_app_user", "VIEW ANY DEFINITION", ("acme_readers", "acme_monitors")),
    }
    assert all(row.level == SERVER_LEVEL for row in found.system)


def test_a_role_path_is_active_without_set_role() -> None:
    found = survey(public=False)

    by_path = {row.path: row.first_role_default for row in found.system}
    assert by_path[()] is None
    assert by_path[("acme_readers",)] is True


def test_a_deny_is_not_listed() -> None:
    """The wider reach, never the narrower."""
    assert "ALTER TRACE" not in {row.privilege for row in survey(public=False).system}


def test_permissions_on_a_login_an_endpoint_and_another_securable_are_objects() -> None:
    found = survey(public=False)
    objects = {(row.privilege, row.object_type, row.name, row.grantable) for row in found.objects}

    assert objects == {
        ("IMPERSONATE", "LOGIN", "EXAMPLE\\acme_svc", True),
        ("CONNECT", "ENDPOINT", "TSQL Default TCP", False),
        ("ALTER", "AVAILABILITY GROUP", "#65536", False),
    }
    assert all(row.kind == OBJECT for row in found.objects)


def test_a_fixed_role_is_listed_under_its_own_name() -> None:
    """No catalog row says what a fixed role gives (probe 13)."""
    found = survey(("acme_ops_user",), public=False)

    assert [(row.privilege, row.level, row.path) for row in found.system] == [
        ("sysadmin", FIXED_ROLE_LEVEL, ("sysadmin",))
    ]


def test_roles_are_the_direct_memberships_all_active() -> None:
    roles = survey(public=False).roles

    assert [(role.grantee, role.role, role.default_role) for role in roles] == [
        ("acme_app_user", "acme_readers", True)
    ]
    assert roles[0].admin_option is False
    assert roles[0].set_option is None


def test_public_s_grants_are_listed_once_when_asked_for() -> None:
    without = survey(public=False)
    assert PUBLIC_GRANTEE not in {row.grantee for row in without.system}

    found = survey(public=True)
    public = {(row.privilege, row.path) for row in found.system if row.grantee == PUBLIC_GRANTEE}
    assert public == {("CONNECT SQL", ()), ("VIEW ANY DATABASE", ())}


def test_a_name_with_no_login_holds_nothing() -> None:
    found = survey(("acme_gone_user",), public=False)

    assert (found.system, found.objects, found.roles) == ((), (), ())


def test_without_the_grant_the_paths_are_not_checked_and_the_roles_are_kept() -> None:
    found = survey(public=False, unread=NO_DEFINITIONS)

    assert found.system is None
    assert found.objects is None
    assert found.unread == NO_DEFINITIONS
    assert [role.role for role in found.roles] == ["acme_readers"]


def test_a_principal_with_no_row_makes_the_read_partial() -> None:
    """A denial hides a principal's row, not the rows naming it (FR5)."""
    hidden = [p for p in PRINCIPALS if p.principal_id != MONITORS]
    found = server_grants.survey(hidden, MEMBERSHIPS, PERMISSIONS, ("acme_app_user",), public=False)

    assert found.unread == PARTIAL_READ
    assert found.system is None


class FakeCursor:
    """Answers each read in turn."""

    def __init__(self, view: tuple[Any, ...] | None, *reads: list[tuple[Any, ...]]) -> None:
        self.view = view
        self.reads = list(reads)
        self.sent: list[str] = []

    def execute(self, statement: str, parameters: Any = None, /) -> None:
        self.sent.append(statement)

    def fetchone(self) -> Any:
        return self.view

    def fetchall(self) -> Any:
        return self.reads.pop(0) if self.reads else []


VIEWS = (
    [(APP, "acme_app_user", "S", 0), (READERS, "acme_readers", "R", 0)],
    [(READERS, APP)],
    [(READERS, "VIEW SERVER STATE", 100, "SERVER", 0, "G ", None)],
)


def test_read_without_view_any_definition_reads_the_roles_alone() -> None:
    cursor = FakeCursor((0, None), *VIEWS)
    found = server_grants.read(cursor, ["acme_app_user"], public=False)

    assert found.unread == NO_DEFINITIONS
    assert found.system is None
    assert [role.role for role in found.roles] == ["acme_readers"]
    # The permissions are not read: they could not be used (#1589 review).
    assert server_grants.PERMISSIONS not in cursor.sent


def test_read_with_a_denied_security_definition_reads_nothing_more() -> None:
    """The denial hides every row (FR5)."""
    cursor = FakeCursor((1, 0), *VIEWS)
    found = server_grants.read(cursor, ["acme_app_user"], public=False)

    assert found.unread == DENIED_SECURITY
    assert found.roles == ()
    assert cursor.sent == [VIEW_DEFINITIONS]


def test_without_the_grant_a_zero_for_security_definition_is_not_a_denial() -> None:
    """Without VIEW ANY DEFINITION, HAS_PERMS_BY_NAME answers 0 for VIEW ANY
    SECURITY DEFINITION because it is not held: the live test reads that."""
    found = server_grants.read(FakeCursor((0, 0), *VIEWS), ["acme_app_user"], public=False)

    assert found.unread == NO_DEFINITIONS
    assert [role.role for role in found.roles] == ["acme_readers"]


def test_a_windows_login_on_a_server_with_a_windows_group_names_the_gap() -> None:
    """The server keeps no record of a group's members (#1589 review)."""
    group = Principal(273, "EXAMPLE\\acme_admins", "G")
    found = server_grants.survey(
        [*PRINCIPALS, group], MEMBERSHIPS, PERMISSIONS, ("EXAMPLE\\acme_svc",), public=False
    )

    assert found.gaps == (WINDOWS_GROUPS,)
    assert found.system is not None
    assert survey(public=False).gaps == ()
    without_group = server_grants.survey(
        PRINCIPALS, MEMBERSHIPS, PERMISSIONS, ("EXAMPLE\\acme_svc",), public=False
    )
    assert without_group.gaps == ()


def test_read_with_the_grant_reads_the_paths() -> None:
    cursor = FakeCursor((1, 1), *VIEWS)
    found = server_grants.read(cursor, ["acme_app_user"], public=False)

    assert found.unread is None
    assert privileges(found.system) == {("acme_app_user", "VIEW SERVER STATE", ("acme_readers",))}
    assert cursor.sent[1:] == [
        server_grants.PRINCIPALS,
        server_grants.MEMBERSHIPS,
        server_grants.PERMISSIONS,
    ]
    assert "password_hash" not in " ".join(cursor.sent)
