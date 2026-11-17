"""The grants that make a SQL Server login one the tool must not manage. Tier 0.

Guardrail 9 on SQL Server (`02-mssql-privileges.md` §5, decision 5 of
#1538, #1567). The tool login's ``ALTER ANY LOGIN`` sets the password of any
login the server does not protect, and the server does not protect a login
that can reach ``CONTROL SERVER`` in a step or two (GR4, PA1). So the tool
refuses a managed login that, itself or through a server role:

- is a member of ``sysadmin`` or ``securityadmin``;
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

**Only a catalog read with ``VIEW ANY DEFINITION`` is complete.** With
``ALTER ANY LOGIN`` alone, the tool login sees no user-defined server role's
row, so no owner, and no role's membership of another role
(``12_guardrail_paths_probe.py``, PA2). No login can then be shown to own no
refused role, so :func:`assess` refuses every login and names the missing
grant (#1567). The session reads the catalog only when the tool login holds
the grant, and otherwise passes an empty :class:`Catalog` with ``complete``
false.

**Two rules keep the answer on the safe side.** A ``DENY`` row is not read:
a member of ``sysadmin`` ignores it, and counting only grants refuses more,
never less. A grant on a principal the catalog has no row for counts as a
grant on a refused one, and a membership of such a principal as a membership
of a refused role.

Each finding is spelled as ``GRANT`` names it, such as ``CONTROL SERVER`` or
``ALTER ON SERVER ROLE::[acme_ops]``, with `` through [<role>]`` where a role
gives it. Guardrail 9 prints them after "the account holds".
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field

#: ``sys.server_permissions.class``: the server itself, and one server
#: principal, a login or a server role.
SERVER_CLASS = 100
PRINCIPAL_CLASS = 101

#: ``sys.server_principals.type`` of a server role. Every other type is a
#: login: a SQL login, a Windows login or group, or one mapped to a
#: certificate or an asymmetric key.
ROLE_TYPE = "R"

#: ``sys.server_permissions.state`` of a grant, and of a grant with
#: ``WITH GRANT OPTION``. A ``DENY`` is ``D``, and is not read.
GRANTED = frozenset({"G", "W"})

#: The fixed server roles whose members the list refuses by name.
ADMIN_ROLES = ("sysadmin", "securityadmin")

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

#: Guardrail 9's reason on every login when the catalog is not complete.
MISSING_GRANT = (
    "the tool login does not hold VIEW ANY DEFINITION, so the tool cannot see "
    "which server roles this login owns or reaches; grant it to the tool login "
    "(02-mssql-privileges.md §2.1)"
)


@dataclass(frozen=True)
class Principal:
    """One row of ``sys.server_principals``."""

    principal_id: int
    name: str
    #: ``type``: :data:`ROLE_TYPE` for a server role.
    type: str
    #: ``owning_principal_id``: the owner of a user-defined server role, and
    #: ``None`` for a login and a fixed role.
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

    ``complete`` says that the read was made with ``VIEW ANY DEFINITION``.
    Without it, the session passes no rows, and :func:`assess` refuses every
    login.
    """

    complete: bool
    principals: Mapping[int, Principal] = field(default_factory=dict)
    #: ``sys.server_role_members`` as ``(role_principal_id,
    #: member_principal_id)``.
    memberships: frozenset[tuple[int, int]] = frozenset()
    permissions: tuple[Permission, ...] = ()

    @classmethod
    def read(
        cls,
        principals: Iterable[Principal],
        memberships: Iterable[tuple[int, int]],
        permissions: Iterable[Permission],
    ) -> Catalog:
        """A complete catalog, from the rows the session read."""
        return cls(
            complete=True,
            principals={p.principal_id: p for p in principals},
            memberships=frozenset(memberships),
            permissions=tuple(permissions),
        )


@dataclass(frozen=True)
class Assessment:
    """Guardrail 9's input for one login.

    ``grants`` fills ``UserState.global_privileges``, and ``unread`` fills
    ``UserState.admin_unread``. Either refuses the login.
    """

    grants: frozenset[str] = frozenset()
    unread: str | None = None


def bracketed(name: str) -> str:
    """``name`` as a bracketed identifier, as SQL Server writes one."""
    return "[" + name.replace("]", "]]") + "]"


def _roles_of(catalog: Catalog, principal_id: int) -> list[int]:
    """Every role ``principal_id`` is a member of, nested roles followed."""
    parents: dict[int, list[int]] = {}
    for role_id, member_id in catalog.memberships:
        parents.setdefault(member_id, []).append(role_id)
    seen: list[int] = []
    queue = list(parents.get(principal_id, ()))
    while queue:
        role_id = queue.pop(0)
        if role_id in seen or role_id == principal_id:
            continue
        seen.append(role_id)
        queue.extend(parents.get(role_id, ()))
    return seen


def _own(catalog: Catalog, holder_id: int, refused: set[int]) -> list[str]:
    """What ``holder_id`` holds on the list itself, not through a role.

    ``refused`` is the set of roles known so far to be refused.
    """
    found: list[str] = []
    holder = catalog.principals.get(holder_id)
    if holder is not None and holder.is_role and holder.name in ADMIN_ROLES:
        found.append(holder.name)
    for row in catalog.permissions:
        if row.grantee_id != holder_id or row.state not in GRANTED:
            continue
        if row.class_ == SERVER_CLASS and row.permission in SERVER_PERMISSIONS:
            found.append(row.permission)
        elif row.class_ == PRINCIPAL_CLASS:
            on = catalog.principals.get(row.major_id)
            if on is None:
                if row.permission in LOGIN_PERMISSIONS | ROLE_PERMISSIONS:
                    found.append(f"{row.permission} ON principal #{row.major_id}")
            elif not on.is_role and row.permission in LOGIN_PERMISSIONS:
                found.append(f"{row.permission} ON LOGIN::{bracketed(on.name)}")
            elif on.is_role and row.permission in ROLE_PERMISSIONS and on.principal_id in refused:
                found.append(f"{row.permission} ON SERVER ROLE::{bracketed(on.name)}")
    for owned in catalog.principals.values():
        if owned.is_role and owned.owner_id == holder_id and owned.principal_id in refused:
            found.append(f"ownership of SERVER ROLE::{bracketed(owned.name)}")
    return found


def _public_id(catalog: Catalog) -> int | None:
    return next(
        (p.principal_id for p in catalog.principals.values() if p.is_role and p.name == PUBLIC),
        None,
    )


def refused_roles(catalog: Catalog) -> set[int]:
    """Every server role whose members the list refuses.

    A fixed point: a role is refused when it meets the list itself, or is a
    member of a refused role, and holding a grant on a refused role, or owning
    one, meets the list. So the set grows until a pass adds nothing.
    """
    roles = [p.principal_id for p in catalog.principals.values() if p.is_role]
    refused: set[int] = set()
    grew = True
    while grew:
        grew = False
        for role_id in roles:
            if role_id in refused:
                continue
            if _own(catalog, role_id, refused) or any(
                parent in refused or parent not in catalog.principals
                for parent in _roles_of(catalog, role_id)
            ):
                refused.add(role_id)
                grew = True
    return refused


def assess(principal_id: int, catalog: Catalog) -> Assessment:
    """Guardrail 9's findings for the login ``principal_id``.

    Without a complete catalog, every login is refused with
    :data:`MISSING_GRANT`. A login the catalog has no row for is refused the
    same way: the session read the login's id from the same server, so a
    missing row means the read did not see it.
    """
    if not catalog.complete or principal_id not in catalog.principals:
        return Assessment(unread=MISSING_GRANT)

    refused = refused_roles(catalog)
    found = set(_own(catalog, principal_id, refused))
    holders = _roles_of(catalog, principal_id)
    public_id = _public_id(catalog)
    if public_id is not None and public_id not in holders:
        holders.append(public_id)
    for role_id in holders:
        role = catalog.principals.get(role_id)
        if role is None:
            # A membership row names a role the catalog has no row for. It
            # counts as a refused one.
            found.add(f"membership of principal #{role_id}")
            continue
        through = f" through {bracketed(role.name)}"
        for grant in _own(catalog, role_id, refused):
            # A fixed role names itself: "sysadmin", not "sysadmin through
            # [sysadmin]".
            found.add(grant if grant in ADMIN_ROLES else grant + through)
    return Assessment(grants=frozenset(found))
