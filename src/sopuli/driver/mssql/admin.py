"""The grants that make a SQL Server login one the tool must not manage.

Guardrail 9 on SQL Server (`02-mssql-privileges.md` §5, decision 5 of
#1538, #1567). The tool login's ``ALTER ANY LOGIN`` sets the password of any
login the server does not protect, and the server does not protect a login
that can reach ``CONTROL SERVER`` in a step or two (GR4, PA1). So the tool
refuses a managed login that, itself or through a server role:

- is a member of ``sysadmin``, ``securityadmin`` or ``##MS_LoginManager##``;
- holds ``CONTROL SERVER``, ``ALTER ANY LOGIN``, ``IMPERSONATE ANY LOGIN`` or
  ``ALTER ANY SERVER ROLE``;
- holds ``CONTROL``, ``ALTER`` or ``IMPERSONATE`` on one login;
- holds ``CONTROL``, ``ALTER`` or ``TAKE OWNERSHIP`` on a server role this
  list refuses, or owns such a role.

Membership is followed through a role that is a member of another role, and
every login is a member of ``public``, which has no membership rows, so
``public``'s grants count as every login's. A role refuses its members when
it meets the list itself, or through a role it is a member of, so the rule is
a fixed point: a role that owns a refused role is refused, and so is a role
that holds ``ALTER`` on that one.

**Only a complete read is assessed.** With ``ALTER ANY LOGIN`` alone, the
tool login sees no user-defined server role's row, so no owner, and no role's
membership of another role (``12_guardrail_paths_probe.py``, PA2). No login
can then be shown to own no refused role, so :func:`assess` refuses every
login and names the missing grant (#1567). A denial hides rows from a tool
login that holds the grant (``13_fixed_roles_probe.py``, FR5), so
:class:`Catalog` checks that every id its rows name has a principal row, and
refuses every login where one does not. :func:`read_catalog` is the module's
one read; everything else is tier 0.

A ``DENY`` row is not read for the list: a member of ``sysadmin`` ignores it,
and counting only grants refuses more, never less.

Each finding is spelled as ``GRANT`` names it, such as ``CONTROL SERVER`` or
``ALTER ON SERVER ROLE::[acme_ops]``, with `` through [<role>]`` where a role
gives it. Guardrail 9 prints them after "the account holds".
"""

from __future__ import annotations

from collections import deque
from collections.abc import Iterable, Mapping, Set
from dataclasses import dataclass, field
from functools import cached_property

from sopuli.driver.protocol import Cursor

#: ``sys.server_permissions.class``: the server itself, and one server
#: principal, a login or a server role.
SERVER_CLASS = 100
PRINCIPAL_CLASS = 101

#: ``sys.server_principals.type`` of a server role. Every other type is a
#: login: a SQL login, a Windows login or group, or one mapped to a
#: certificate or an asymmetric key.
ROLE_TYPE = "R"

#: ``sys.server_principals.type`` for a SQL login, the one kind with a
#: password the tool sets (:data:`~sopuli.driver.mssql.accounts.SQL_LOGIN`).
SQL_LOGIN_TYPE = "S"

#: ``sys.server_permissions.state`` of a grant, and of a grant with
#: ``WITH GRANT OPTION``. A ``DENY`` is ``D``, and is not read.
GRANTED = frozenset({"G", "W"})

#: The fixed server roles whose members the list refuses, by name. A fixed
#: role has no rows in ``sys.server_permissions``, so what it gives is read
#: from its name. These are the three that give a permission of the list:
#: ``sysadmin`` all four, and ``securityadmin`` and, from 2022,
#: ``##MS_LoginManager##`` ``ALTER ANY LOGIN`` (``13_fixed_roles_probe.py``,
#: FR1 and FR2).
ADMIN_ROLES = ("sysadmin", "securityadmin", "##MS_LoginManager##")

#: The role every login is a member of without a membership row.
PUBLIC = "public"

#: Server permissions the list refuses.
SERVER_PERMISSIONS = frozenset(
    {"CONTROL SERVER", "ALTER ANY LOGIN", "IMPERSONATE ANY LOGIN", "ALTER ANY SERVER ROLE"}
)

#: Permissions on one login the list refuses. ``TAKE OWNERSHIP`` on a login
#: cannot be granted (PA3, #1567).
LOGIN_PERMISSIONS = frozenset({"CONTROL", "ALTER", "IMPERSONATE"})

#: Permissions on one server role the list refuses, where the role is refused.
ROLE_PERMISSIONS = frozenset({"CONTROL", "ALTER", "TAKE OWNERSHIP"})

#: Guardrail 9's reason on every login when the tool login lacks the grant.
MISSING_GRANT = (
    "the tool login does not hold VIEW ANY DEFINITION, so the tool cannot see "
    "which server roles this login owns or reaches; grant it to the tool login "
    "(02-mssql-privileges.md §2.1)"
)

#: Guardrail 9's reason on every login when the tool login is denied
#: ``VIEW ANY SECURITY DEFINITION`` (2022 and later), which hides every
#: principal, grant and membership row although ``VIEW ANY DEFINITION`` is
#: held (``13_fixed_roles_probe.py``, FR5).
DENIED_SECURITY = (
    "the tool login is denied VIEW ANY SECURITY DEFINITION, so the tool cannot "
    "see which server roles this login owns or reaches; revoke the denial "
    "(02-mssql-privileges.md §5)"
)

#: Guardrail 9's reason on every login when the read has an id with no
#: principal row: one a DENY hides from the tool login, or one made while the
#: statements ran, twice.
PARTIAL_READ = (
    "the tool's read of the server's principals names a principal it has no "
    "row for, one a DENY hides from the tool login or one made during the "
    "read, so the tool cannot see every path to an administrative grant; "
    "revoke any DENY of VIEW DEFINITION to the tool login, and run the "
    "command again (02-mssql-privileges.md §5)"
)

#: Guardrail 9's reason when a complete read has no row for the login: a
#: DENY of VIEW DEFINITION on the login hides it, or it was made or dropped
#: since the tool read its id.
MISSING_LOGIN = (
    "the tool's read of the server's principals has no row for this login, so "
    "the tool cannot see what it holds; revoke any DENY of VIEW DEFINITION on "
    "the login to the tool login, and run the command again "
    "(02-mssql-privileges.md §5)"
)

#: Guardrail 9's reason when a complete read has no row for ``public``.
MISSING_PUBLIC = (
    "the tool's read of the server's principals has no row for the role public, "
    "whose grants every login holds, so the tool cannot see what they are"
)


@dataclass(frozen=True)
class Principal:
    """One row of ``sys.server_principals``."""

    principal_id: int
    name: str
    #: ``type``: :data:`ROLE_TYPE` for a server role.
    type: str
    #: The owner of a user-defined server role, and ``None`` for a login, a
    #: fixed role and ``public``. The server names ``sa`` as the owner of the
    #: fixed roles and ``public``, and :func:`read_catalog` leaves that out:
    #: ``sa`` is a member of ``sysadmin`` anyway.
    owner_id: int | None = None

    @property
    def is_role(self) -> bool:
        return self.type == ROLE_TYPE


@dataclass(frozen=True)
class Permission:
    """One row of ``sys.server_permissions``."""

    grantee_id: int
    #: ``permission_name``, such as ``CONTROL SERVER`` or ``ALTER``.
    permission: str
    #: ``class``: :data:`SERVER_CLASS` or :data:`PRINCIPAL_CLASS` for the rows
    #: the list reads. Other classes, such as an endpoint, are not read.
    class_: int
    #: ``major_id``: the principal a :data:`PRINCIPAL_CLASS` row is on.
    major_id: int
    #: ``state``: a row outside :data:`GRANTED` is not read.
    state: str = "G"


@dataclass(frozen=True)
class Catalog:
    """What the tool login read of the server's principals.

    ``unread`` is ``None`` for a complete read. Otherwise it says why the
    read is not complete, the catalog has no rows, and :func:`assess`
    refuses every login with it.
    """

    unread: str | None = None
    principals: Mapping[int, Principal] = field(default_factory=dict)
    #: ``sys.server_role_members`` as ``(role_principal_id,
    #: member_principal_id)``.
    memberships: frozenset[tuple[int, int]] = frozenset()
    permissions: tuple[Permission, ...] = ()

    @property
    def complete(self) -> bool:
        return self.unread is None

    @classmethod
    def read(
        cls,
        principals: Iterable[Principal],
        memberships: Iterable[tuple[int, int]],
        permissions: Iterable[Permission],
    ) -> Catalog:
        """The catalog of these rows, or one not complete, with
        :data:`PARTIAL_READ`, where a membership, a grant or an owner names an
        id with no principal row.

        A denial hides a principal's row and not the rows that name it
        (``13_fixed_roles_probe.py``, FR5), so this is how a hidden principal
        shows. Denials are left out: they are not read for the list.
        """
        by_id = {p.principal_id: p for p in principals}
        pairs = frozenset(memberships)
        rows = tuple(permissions)
        named = {
            *(id_ for pair in pairs for id_ in pair),
            *(p.owner_id for p in by_id.values() if p.owner_id is not None),
            *(row.grantee_id for row in rows if row.state in GRANTED),
            *(
                row.major_id
                for row in rows
                if row.state in GRANTED and row.class_ == PRINCIPAL_CLASS
            ),
        }
        if not named <= by_id.keys():
            return cls(unread=PARTIAL_READ)
        return cls(principals=by_id, memberships=pairs, permissions=rows)

    # Indexes, built once per catalog: a target has one, and every managed
    # login on it is assessed against it.

    @cached_property
    def parents(self) -> Mapping[int, tuple[int, ...]]:
        """Each member's roles, one step up."""
        found: dict[int, list[int]] = {}
        for role_id, member_id in self.memberships:
            found.setdefault(member_id, []).append(role_id)
        return {member: tuple(roles) for member, roles in found.items()}

    @cached_property
    def granted(self) -> Mapping[int, tuple[Permission, ...]]:
        """Each grantee's grants, denials left out."""
        found: dict[int, list[Permission]] = {}
        for row in self.permissions:
            if row.state in GRANTED:
                found.setdefault(row.grantee_id, []).append(row)
        return {grantee: tuple(rows) for grantee, rows in found.items()}

    @cached_property
    def owned(self) -> Mapping[int, tuple[Principal, ...]]:
        """Each owner's server roles."""
        found: dict[int, list[Principal]] = {}
        for role in self.principals.values():
            if role.is_role and role.owner_id is not None:
                found.setdefault(role.owner_id, []).append(role)
        return {owner: tuple(roles) for owner, roles in found.items()}

    @cached_property
    def children(self) -> Mapping[int, tuple[int, ...]]:
        """Each role's members, one step down."""
        found: dict[int, list[int]] = {}
        for role_id, member_id in self.memberships:
            found.setdefault(role_id, []).append(member_id)
        return {role: tuple(members) for role, members in found.items()}

    def server_roles(self, name: str) -> tuple[Principal, ...]:
        """The server roles ``name`` names, compared by ``upper()`` as a verb
        compares a login's roles with the rule (#1554, Q6). More than one only
        on a case-sensitive server that holds the name in two cases, which
        the caller refuses as ambiguous: the listing and a verb must admit
        the same logins."""
        wanted = name.upper()
        return tuple(p for p in self.principals.values() if p.is_role and p.name.upper() == wanted)

    def members(self, role_id: int) -> tuple[Principal, ...]:
        """Every SQL login that holds ``role_id``, through any chain of nested
        server roles, by name (#1554, Q6). A Windows or Entra login or group,
        or a login mapped to a certificate, has no password the tool can set,
        so a `role:` rule does not name it."""
        found = (
            self.principals[member_id]
            for member_id in _reach(self.children, role_id)
            if member_id in self.principals
        )
        return tuple(
            sorted(
                (p for p in found if not p.is_role and p.type == SQL_LOGIN_TYPE),
                key=lambda p: p.name,
            )
        )

    def roles_of(self, principal_id: int) -> frozenset[str]:
        """Every server role ``principal_id`` holds, directly or through
        nested roles, upper-cased as :attr:`UserState.roles
        <sopuli.driver.protocol.UserState.roles>` holds them: what a `role:`
        rule is compared with."""
        return frozenset(
            self.principals[role_id].name.upper()
            for role_id in _roles_of(self, principal_id)
            if role_id in self.principals
        )

    @cached_property
    def public_id(self) -> int | None:
        """The id of ``public``, or ``None`` where the read has no row for it."""
        return next(
            (p.principal_id for p in self.principals.values() if p.is_role and p.name == PUBLIC),
            None,
        )

    @cached_property
    def refused(self) -> frozenset[int]:
        """Every server role whose members the list refuses.

        A fixed point: a role is refused when it meets the list itself, or is
        a member of a refused role, and holding a grant on a refused role, or
        owning one, meets the list. So the set grows until a pass adds
        nothing.
        """
        roles = [p.principal_id for p in self.principals.values() if p.is_role]
        refused: set[int] = set()
        grew = True
        while grew:
            grew = False
            for role_id in roles:
                if role_id in refused:
                    continue
                if _own(self, role_id, refused) or any(
                    parent in refused for parent in self.parents.get(role_id, ())
                ):
                    refused.add(role_id)
                    grew = True
        return frozenset(refused)


@dataclass(frozen=True)
class Assessment:
    """Guardrail 9's input for one login.

    ``grants`` fills ``UserState.global_privileges``, and ``unread`` fills
    ``UserState.admin_unread``. Either refuses the login.
    """

    grants: frozenset[str] = frozenset()
    unread: str | None = None


#: Whether the tool login holds ``VIEW ANY DEFINITION``, itself, through a
#: role, or through ``CONTROL SERVER``; and whether it is denied ``VIEW ANY
#: SECURITY DEFINITION``, 0, which 2022 added. 2019 answers ``NULL`` for a
#: permission it does not have (``13_fixed_roles_probe.py``, FR5).
VIEW_DEFINITIONS = (
    "SELECT HAS_PERMS_BY_NAME(NULL, NULL, 'VIEW ANY DEFINITION'), "
    "HAS_PERMS_BY_NAME(NULL, NULL, 'VIEW ANY SECURITY DEFINITION')"
)

#: The three reads of §5's table. Only the two classes the list names are
#: read from ``sys.server_permissions``.
PRINCIPALS = (
    "SELECT principal_id, name, type, owning_principal_id, is_fixed_role FROM sys.server_principals"
)
MEMBERSHIPS = "SELECT role_principal_id, member_principal_id FROM sys.server_role_members"
PERMISSIONS = (
    "SELECT grantee_principal_id, permission_name, class, major_id, state "
    f"FROM sys.server_permissions WHERE class IN ({SERVER_CLASS}, {PRINCIPAL_CLASS})"
)

#: How many times :func:`read_catalog` reads the three views before it takes
#: :data:`PARTIAL_READ` as the answer. A principal made during one read is
#: seen by the next; a denial hides it every time.
READS = 2


def read_catalog(cursor: Cursor) -> Catalog:
    """What guardrail 9 reads, as the tool login.

    Without ``VIEW ANY DEFINITION``, or where ``VIEW ANY SECURITY
    DEFINITION`` is denied, nothing more is read, and the catalog is not
    complete: a partial read would pass a login whose role it cannot see
    (PA2, #1567).

    **The read checks itself** (:meth:`Catalog.read`). The three statements
    are not one snapshot, and the principals are read first, so a principal
    made later is named only by the rows read after it, and the check sees
    it. Such a read is made again, once.

    Each statement goes without parameters: pyodbc binds a ``None`` as one.
    """
    cursor.execute(VIEW_DEFINITIONS)
    row = cursor.fetchone()
    if row is None or row[0] != 1:
        return Catalog(unread=MISSING_GRANT)
    if row[1] == 0:
        return Catalog(unread=DENIED_SECURITY)
    read = Catalog(unread=PARTIAL_READ)
    for _ in range(READS):
        read = _read_views(cursor)
        if read.unread != PARTIAL_READ:
            break
    return read


def _read_views(cursor: Cursor) -> Catalog:
    cursor.execute(PRINCIPALS)
    principals = [
        Principal(
            int(pid),
            str(name),
            str(kind).strip(),
            # sa "owns" the fixed roles and public, which hands it nothing.
            None if owner is None or fixed or name == PUBLIC else int(owner),
        )
        for pid, name, kind, owner, fixed in cursor.fetchall()
    ]
    cursor.execute(MEMBERSHIPS)
    memberships = [(int(role), int(member)) for role, member in cursor.fetchall()]
    cursor.execute(PERMISSIONS)
    permissions = [
        Permission(int(grantee), str(name), int(class_), int(major), str(state).strip())
        for grantee, name, class_, major, state in cursor.fetchall()
    ]
    return Catalog.read(principals, memberships, permissions)


def bracketed(name: str) -> str:
    """``name`` as a bracketed identifier, as SQL Server writes one."""
    return "[" + name.replace("]", "]]") + "]"


def _roles_of(catalog: Catalog, principal_id: int) -> list[int]:
    """Every role ``principal_id`` is a member of, nested roles followed."""
    return _reach(catalog.parents, principal_id)


def _reach(edges: Mapping[int, tuple[int, ...]], start: int) -> list[int]:
    """Every id reachable from ``start`` along ``edges``, breadth first, each
    once and never ``start`` itself, so a cycle ends: up through
    :attr:`Catalog.parents`, or down through :attr:`Catalog.children`."""
    seen: set[int] = set()
    order: list[int] = []
    queue = deque(edges.get(start, ()))
    while queue:
        found = queue.popleft()
        if found in seen or found == start:
            continue
        seen.add(found)
        order.append(found)
        queue.extend(edges.get(found, ()))
    return order


def _own(catalog: Catalog, holder_id: int, refused: Set[int]) -> list[str]:
    """What ``holder_id`` holds on the list itself, not through a role.

    ``refused`` is the set of roles known so far to be refused. Every id a
    grant names has a principal row: :meth:`Catalog.read` checks it.
    """
    found: list[str] = []
    holder = catalog.principals[holder_id]
    if holder.is_role and holder.name in ADMIN_ROLES:
        found.append(holder.name)
    for row in catalog.granted.get(holder_id, ()):
        if row.class_ == SERVER_CLASS and row.permission in SERVER_PERMISSIONS:
            found.append(row.permission)
        elif row.class_ == PRINCIPAL_CLASS:
            on = catalog.principals[row.major_id]
            if not on.is_role and row.permission in LOGIN_PERMISSIONS:
                found.append(f"{row.permission} ON LOGIN::{bracketed(on.name)}")
            elif on.is_role and row.permission in ROLE_PERMISSIONS and on.principal_id in refused:
                found.append(f"{row.permission} ON SERVER ROLE::{bracketed(on.name)}")
    for owned in catalog.owned.get(holder_id, ()):
        if owned.principal_id in refused:
            found.append(f"ownership of SERVER ROLE::{bracketed(owned.name)}")
    return found


def refused_roles(catalog: Catalog) -> frozenset[int]:
    """Every server role whose members the list refuses: :attr:`Catalog.refused`."""
    return catalog.refused


def assess(principal_id: int, catalog: Catalog) -> Assessment:
    """Guardrail 9's findings for the login ``principal_id``.

    Where the catalog is not complete, every login is refused with its
    ``unread``. A complete one that has no row for the login, or none for
    ``public``, refuses it too, with :data:`MISSING_LOGIN` or
    :data:`MISSING_PUBLIC`: a path the read did not see never passes.
    """
    if catalog.unread is not None:
        return Assessment(unread=catalog.unread)
    if principal_id not in catalog.principals:
        return Assessment(unread=MISSING_LOGIN)
    public_id = catalog.public_id
    if public_id is None:
        return Assessment(unread=MISSING_PUBLIC)

    refused = catalog.refused
    found = set(_own(catalog, principal_id, refused))
    holders = _roles_of(catalog, principal_id)
    if public_id not in holders:
        holders.append(public_id)
    for role_id in holders:
        through = f" through {bracketed(catalog.principals[role_id].name)}"
        for grant in _own(catalog, role_id, refused):
            # A fixed role names itself: "sysadmin", not "sysadmin through
            # [sysadmin]".
            found.add(grant if grant in ADMIN_ROLES else grant + through)
    return Assessment(grants=frozenset(found))
