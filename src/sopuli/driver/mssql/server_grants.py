"""The server-level privileges of SQL Server logins, for `report privileges`
(UC-5 §5, #1555). Tier 0, but for :func:`read`.

The mapping is the maintainer's, decision 4 on #1555:

- **system**: the permissions on the server itself (``sys.server_permissions``
  class 100), each with its path through nested server roles, at level
  ``server``. A fixed server role the login reaches, such as ``sysadmin`` or
  ``##MS_LoginManager##``, is listed as a privilege of its own name, at level
  ``fixed server role``: no catalog row says what it gives
  (``13_fixed_roles_probe.py``), as PostgreSQL lists its ``pg_*`` roles.
- **objects**: the permissions on one server principal, a login or a server
  role (class 101), on an endpoint (105), and on any other server-level
  securable, by its ``class_desc``.

The database level, the *schemas* and *columns* parts and the rest of
*objects*, is #1555's part 4.

**Every role is active at login.** A login holds the permissions of each
server role it is a member of, through any chain, with no ``SET ROLE``. So
each path's ``first_role_default`` is ``True``, and each role's
``default_role`` too. SQL Server has no admin option: a role's owner, or a
holder of ``ALTER`` on it, adds members.

**``public``.** Every login is a member of the server role ``public`` without
a membership row. Its grants are listed once, under ``PUBLIC``, when
``--public`` asks for them, as every product's are.

**A ``DENY`` is not listed.** The report lists what is granted, so a login
denied what a role grants it reads as holding it: the wider reach, never the
narrower. ``WITH GRANT OPTION`` (state ``W``) makes a row grantable.

**Only a complete read is listed.** Without ``VIEW ANY DEFINITION``, the tool
login sees no user-defined server role's row and no role's membership of
another (``12_guardrail_paths_probe.py``, PA2), so the paths are not known:
*system* and *objects* are ``None``, with the grant named. The roles list then
holds the direct memberships the tool login can see. A denial of ``VIEW ANY
SECURITY DEFINITION``, and a read that names a principal it has no row for,
are refused the same way (:mod:`~sopuli.driver.mssql.admin`).
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass

from sopuli.driver.grants import OBJECT, SYSTEM, GrantRow, RoleGrant
from sopuli.driver.mssql.admin import (
    DENIED_SECURITY,
    GRANTED,
    PARTIAL_READ,
    PRINCIPAL_CLASS,
    PUBLIC,
    READS,
    ROLE_TYPE,
    SERVER_CLASS,
    VIEW_DEFINITIONS,
)
from sopuli.driver.protocol import Cursor

#: The name every product's report gives the grants to everyone.
PUBLIC_GRANTEE = "PUBLIC"

#: :attr:`GrantRow.level` of a permission on the server or one securable in it.
SERVER_LEVEL = "server"
#: :attr:`GrantRow.level` of a fixed server role the login reaches.
FIXED_ROLE_LEVEL = "fixed server role"

#: ``sys.server_permissions.class`` of an endpoint.
ENDPOINT_CLASS = 105

#: Why the server level is not checked without ``VIEW ANY DEFINITION``.
NO_DEFINITIONS = (
    "server-level privileges: the tool login does not hold VIEW ANY DEFINITION, so it "
    "cannot see user-defined server roles or one role's membership of another; "
    "GRANT VIEW ANY DEFINITION to the tool login (02-mssql-privileges.md §2.2)"
)

PRINCIPALS = "SELECT principal_id, name, type, is_fixed_role FROM sys.server_principals"
MEMBERSHIPS = "SELECT role_principal_id, member_principal_id FROM sys.server_role_members"
#: Every server-level grant, with the endpoint's name where the row is on one.
PERMISSIONS = (
    "SELECT p.grantee_principal_id, p.permission_name, p.class, p.class_desc, "
    "p.major_id, p.state, e.name "
    "FROM sys.server_permissions AS p "
    f"LEFT JOIN sys.endpoints AS e ON p.class = {ENDPOINT_CLASS} AND e.endpoint_id = p.major_id"
)


@dataclass(frozen=True)
class Principal:
    """One row of ``sys.server_principals``."""

    principal_id: int
    name: str
    type: str
    fixed: bool = False

    @property
    def is_role(self) -> bool:
        return self.type == ROLE_TYPE


@dataclass(frozen=True)
class Permission:
    """One row of ``sys.server_permissions``, a grant or a denial."""

    grantee_id: int
    permission: str
    class_: int
    class_desc: str
    major_id: int
    state: str
    #: The endpoint's name, for a row on an endpoint.
    endpoint: str | None = None


@dataclass(frozen=True)
class ServerGrants:
    """The server level of a :class:`~sopuli.driver.grants.GrantSurvey`.

    ``system`` and ``objects`` are ``None`` where the read was not complete,
    and ``unread`` then says why.
    """

    roles: tuple[RoleGrant, ...]
    system: tuple[GrantRow, ...] | None
    objects: tuple[GrantRow, ...] | None
    unread: str | None = None


def read(cursor: Cursor, accounts: Sequence[str], *, public: bool) -> ServerGrants:
    """The server level for ``accounts``, as the tool login reads it.

    Without ``VIEW ANY DEFINITION`` the views are read for the roles alone.
    A read that names a principal it has no row for is made again, once, as
    guardrail 9's is (:func:`~sopuli.driver.mssql.admin.read_catalog`)."""
    cursor.execute(VIEW_DEFINITIONS)
    row = cursor.fetchone()
    unread: str | None = None
    if row is None or row[0] != 1:
        unread = NO_DEFINITIONS
    elif row[1] == 0:
        unread = DENIED_SECURITY
    found = ServerGrants(roles=(), system=None, objects=None, unread=PARTIAL_READ)
    for _ in range(READS):
        principals, memberships, permissions = _read_views(cursor)
        found = survey(principals, memberships, permissions, accounts, public=public, unread=unread)
        if found.unread != PARTIAL_READ or unread is not None:
            break
    return found


def _read_views(
    cursor: Cursor,
) -> tuple[list[Principal], list[tuple[int, int]], list[Permission]]:
    cursor.execute(PRINCIPALS)
    principals = [
        Principal(int(pid), str(name), str(kind).strip(), bool(fixed))
        for pid, name, kind, fixed in cursor.fetchall()
    ]
    cursor.execute(MEMBERSHIPS)
    memberships = [(int(role), int(member)) for role, member in cursor.fetchall()]
    cursor.execute(PERMISSIONS)
    permissions = [
        Permission(
            int(grantee),
            str(name),
            int(class_),
            str(desc),
            int(major),
            str(state).strip(),
            None if endpoint is None else str(endpoint),
        )
        for grantee, name, class_, desc, major, state, endpoint in cursor.fetchall()
    ]
    return principals, memberships, permissions


def survey(
    principals: Iterable[Principal],
    memberships: Iterable[tuple[int, int]],
    permissions: Iterable[Permission],
    accounts: Sequence[str],
    *,
    public: bool,
    unread: str | None = None,
) -> ServerGrants:
    """The server level for ``accounts``, from the rows read. ``unread`` is
    why the read is not complete before it is looked at, such as the grant
    missing."""
    by_id = {p.principal_id: p for p in principals}
    pairs = frozenset(memberships)
    rows = tuple(permissions)
    by_name = {p.name: p for p in by_id.values() if not p.is_role}
    if unread is None and not _names_known(by_id, pairs, rows):
        unread = PARTIAL_READ
    roles = tuple(
        RoleGrant(
            grantee=name,
            role=by_id[role_id].name,
            admin_option=False,
            default_role=True,
            authentication="NONE",
        )
        for name in dict.fromkeys(accounts)
        if name in by_name
        for role_id, member_id in sorted(pairs)
        if member_id == by_name[name].principal_id and role_id in by_id
    )
    if unread is not None:
        return ServerGrants(roles=roles, system=None, objects=None, unread=unread)
    parents: dict[int, list[int]] = {}
    for role_id, member_id in pairs:
        parents.setdefault(member_id, []).append(role_id)
    granted: dict[int, list[Permission]] = {}
    for row in rows:
        if row.state in GRANTED:
            granted.setdefault(row.grantee_id, []).append(row)
    found: list[GrantRow] = []
    for name in dict.fromkeys(accounts):
        login = by_name.get(name)
        if login is None:
            continue
        for path in _paths(login.principal_id, parents):
            holder = by_id[path[-1]] if path else login
            names = tuple(by_id[role_id].name for role_id in path)
            if holder.is_role and holder.fixed:
                found.append(_row(name, SYSTEM, holder.name, names, FIXED_ROLE_LEVEL))
            found.extend(
                _grant(name, row, names, by_id) for row in granted.get(holder.principal_id, ())
            )
    if public:
        everyone = next((p for p in by_id.values() if p.is_role and p.name == PUBLIC), None)
        if everyone is not None:
            found.extend(
                _grant(PUBLIC_GRANTEE, row, (), by_id)
                for row in granted.get(everyone.principal_id, ())
            )
    return ServerGrants(
        roles=roles,
        system=tuple(row for row in found if row.kind == SYSTEM),
        objects=tuple(row for row in found if row.kind == OBJECT),
    )


def _names_known(
    by_id: Mapping[int, Principal], pairs: frozenset[tuple[int, int]], rows: tuple[Permission, ...]
) -> bool:
    """Whether every principal a membership or a grant names has a row: a
    denial hides a principal's row, not the rows that name it (FR5)."""
    named = {
        *(id_ for pair in pairs for id_ in pair),
        *(row.grantee_id for row in rows if row.state in GRANTED),
        *(row.major_id for row in rows if row.state in GRANTED and row.class_ == PRINCIPAL_CLASS),
    }
    return named <= by_id.keys()


def _paths(start: int, parents: Mapping[int, list[int]]) -> list[tuple[int, ...]]:
    """``()`` for the login's own grants, then every chain of roles up from
    it, one per path, with no role twice in a chain."""
    found: list[tuple[int, ...]] = [()]
    stack: list[tuple[int, ...]] = [(role,) for role in sorted(parents.get(start, ()))]
    while stack:
        path = stack.pop()
        found.append(path)
        stack.extend(
            (*path, role)
            for role in sorted(parents.get(path[-1], ()))
            if role not in path and role != start
        )
    return found


def _grant(
    grantee: str, row: Permission, path: tuple[str, ...], by_id: Mapping[int, Principal]
) -> GrantRow:
    if row.class_ == SERVER_CLASS:
        return _row(grantee, SYSTEM, row.permission, path, SERVER_LEVEL, row.state == "W")
    if row.class_ == PRINCIPAL_CLASS:
        on = by_id[row.major_id]
        kind, name = ("SERVER ROLE" if on.is_role else "LOGIN"), on.name
    elif row.class_ == ENDPOINT_CLASS and row.endpoint is not None:
        kind, name = "ENDPOINT", row.endpoint
    else:
        # Not measured: named by its class and id, never dropped.
        kind, name = row.class_desc, f"#{row.major_id}"
    return GrantRow(
        grantee=grantee,
        kind=OBJECT,
        privilege=row.permission,
        owner=None,
        name=name,
        object_type=kind,
        column=None,
        path=path,
        first_role_default=True if path else None,
        grantable=row.state == "W",
        level=SERVER_LEVEL,
    )


def _row(
    grantee: str,
    kind: str,
    privilege: str,
    path: tuple[str, ...],
    level: str,
    grantable: bool = False,
) -> GrantRow:
    return GrantRow(
        grantee=grantee,
        kind=kind,
        privilege=privilege,
        owner=None,
        name=None,
        object_type=None,
        column=None,
        path=path,
        first_role_default=True if path else None,
        grantable=grantable,
        level=level,
    )
