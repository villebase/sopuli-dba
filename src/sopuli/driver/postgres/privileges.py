"""What the tool account on a PostgreSQL cluster holds, needs and should not hold.
Tier 0.

``02-postgres-privileges.md`` §2.4 says what this reads and §3 what must not be
granted. Every read is of a catalog any role can read (``pg_roles``,
``pg_auth_members``, ``pg_attribute``), so the audit needs no grant of its own.
It reports and never refuses: over-granting warns (P5).

**Whether the server requires ``ADMIN OPTION`` is read from the catalog**, not
from a version number (invariant 3). From 16, ``CREATEROLE`` needs ``ADMIN
OPTION`` on a role before it may change the role's password, and the same
release added the ``set_option`` column to ``pg_auth_members``. On a server
without that column ``CREATEROLE`` alone is enough, and any membership in a
managed role lets the tool account ``SET ROLE`` to it, so a membership there is
over-granted.

**The built-in roles are read from ``pg_auth_members``, not from
``pg_has_role``.** ``pg_has_role`` answers true for every role when the tool
account is a superuser, so it would list every built-in role of §3 as held. For
the same reason a superuser's managed roles are not reported one by one: the
``SUPERUSER`` finding covers them. For a managed role ``pg_has_role`` is the
server's own answer to what the tool can do with the role, through any chain
of grants, and that is what it is asked.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Protocol

from sopuli.driver.protocol import PrivilegeAudit

CREATEROLE = "CREATEROLE"
SUPERUSER = "SUPERUSER"

#: The role attributes the audit reads, spelled as ``ALTER ROLE`` spells them,
#: and the ``pg_roles`` column of each.
ATTRIBUTES = {
    SUPERUSER: "rolsuper",
    CREATEROLE: "rolcreaterole",
    "REPLICATION": "rolreplication",
    "BYPASSRLS": "rolbypassrls",
}

#: The tool account's name for the hint, and its :data:`ATTRIBUTES` in order.
SELF_ROW = (
    f"select current_user, {', '.join(ATTRIBUTES.values())} "
    "from pg_roles where rolname = current_user"
)

#: Whether a grant can carry ``INHERIT`` and ``SET`` options, which is also
#: whether ``CREATEROLE`` needs ``ADMIN OPTION`` (module docstring).
GRANT_OPTIONS_ROW = (
    "select exists (select 1 from pg_attribute "
    "where attrelid = 'pg_catalog.pg_auth_members'::regclass "
    "and attname = 'set_option' and not attisdropped)"
)

#: The tool account's own oid, inside the queries below.
ME = "(select oid from pg_roles where rolname = current_user)"

#: Every role the tool account is a member of, through any chain of grants, and
#: whether any chain to it gives the tool something of the role. ``union``
#: rather than ``union all`` ends the walk: a role is reached at most twice,
#: once usable and once not. ``{edge}`` is :data:`USABLE_EDGE` or ``true``.
MEMBERSHIPS = (
    "with recursive held(oid, usable) as ("
    f"select m.roleid, {{edge}} from pg_auth_members m where m.member = {ME} "
    "union "
    "select m.roleid, h.usable and {edge} from pg_auth_members m "
    "join held h on m.member = h.oid"
    ") select r.rolname, bool_or(held.usable) from pg_roles r "
    "join held on r.oid = held.oid group by r.rolname"
)

#: Where grants carry options, a grant with ``INHERIT FALSE`` and ``SET FALSE``
#: gives the member nothing of the role, so a role reached only through it is
#: held and not usable. Before 16 every grant is usable.
USABLE_EDGE = "(m.inherit_option or m.set_option)"

#: What the tool account can do with each managed role that exists, and whether
#: a grant straight to the tool account is what gives it. The mode is a
#: parameter: ``SET`` where grants carry the option, and ``MEMBER`` before,
#: where every member can ``SET ROLE``. ``{direct}`` is :data:`DIRECT_USABLE` or
#: :data:`DIRECT_MEMBER`.
MANAGED_ROLES = (
    "select r.rolname, "
    "pg_has_role(current_user, r.oid, 'USAGE WITH ADMIN OPTION'), "
    "pg_has_role(current_user, r.oid, 'USAGE'), "
    "pg_has_role(current_user, r.oid, %s), "
    "{direct} "
    "from pg_roles r where r.rolname = any(%s)"
)
DIRECT_USABLE = (
    "coalesce((select bool_or(m.inherit_option or m.set_option) from pg_auth_members m "
    f"where m.roleid = r.oid and m.member = {ME}), false)"
)
DIRECT_MEMBER = (
    f"exists (select 1 from pg_auth_members m where m.roleid = r.oid and m.member = {ME})"
)

#: §3's attributes. ``SUPERUSER`` is listed for a caller that reaches the audit
#: as one: ``02-postgres-privileges.md`` §1 says the tool account never is.
FORBIDDEN_ATTRIBUTES = (SUPERUSER, "REPLICATION", "BYPASSRLS")

#: §3's built-in roles. ``pg_monitor`` includes ``pg_read_all_stats``, so an
#: account granted it reports both.
FORBIDDEN_ROLES = (
    "pg_execute_server_program",
    "pg_read_server_files",
    "pg_write_server_files",
    "pg_read_all_data",
    "pg_write_all_data",
    "pg_signal_backend",
    "pg_read_all_stats",
    "pg_monitor",
)

DOCUMENT = "02-postgres-privileges.md"


class Cursor(Protocol):
    """The part of a psycopg cursor this module uses."""

    def execute(self, query: Any, params: Any = None, /) -> Any: ...

    def fetchone(self) -> Any: ...

    def fetchall(self) -> Any: ...


@dataclass(frozen=True)
class ManagedRole:
    """What the tool account can do with one managed role, from ``pg_has_role``,
    and whether a grant straight to the tool account gives it (``direct``)."""

    name: str
    admin: bool
    inherits: bool
    can_set: bool
    direct: bool = True


def classify(
    *,
    user: str,
    attributes: frozenset[str],
    grant_options: bool,
    memberships: dict[str, bool],
    accounts: Sequence[str],
    managed: Sequence[ManagedRole],
) -> PrivilegeAudit:
    """§2's and §3's lists against what was read. Pure, and the whole judgement.

    ``attributes`` holds the role attributes that are true, spelled as
    ``ALTER ROLE`` spells them. ``memberships`` is every role held, and whether
    the tool can use it. ``accounts`` is every role the config declares on this
    target, and ``managed`` the ones of them that exist.
    """
    found = {name for name in FORBIDDEN_ATTRIBUTES if name in attributes}
    found |= {name for name in FORBIDDEN_ROLES if memberships.get(name)}
    held = [CREATEROLE] if CREATEROLE in attributes else []
    missing = [] if held else [CREATEROLE]
    remedies: list[str] = []

    by_name = {role.name: role for role in managed}
    for account in accounts:
        role = by_name.get(account)
        if role is None:
            if grant_options:
                missing.append(f"ADMIN OPTION ON {account}")
            remedies.append(
                f"{account} does not exist on this cluster, and the tool does not create roles"
            )
            continue
        if grant_options:
            (held if role.admin else missing).append(f"ADMIN OPTION ON {account}")
        if SUPERUSER in attributes:
            continue
        over = _over_granted(account, role, grant_options=grant_options)
        if over:
            found |= set(over)
            remedies.append(_remedy(account, user, role, grant_options=grant_options))

    return PrivilegeAudit(
        over_granted=tuple(sorted(found)),
        held=tuple(sorted(held)),
        missing=tuple(sorted(missing)),
        roles=tuple(sorted(memberships)),
        remedies=tuple(remedies),
        hint=f"{DOCUMENT} section 2 has the grants for the tool account `{user}`",
    )


def _over_granted(account: str, role: ManagedRole, *, grant_options: bool) -> list[str]:
    """What the tool can do with one managed role beyond changing its password."""
    if not grant_options:
        return [f"MEMBER OF {account}"] if role.can_set else []
    found = []
    if role.inherits:
        found.append(f"INHERIT TRUE ON {account}")
    if role.can_set:
        found.append(f"SET TRUE ON {account}")
    return found


def _remedy(account: str, user: str, role: ManagedRole, *, grant_options: bool) -> str:
    """The statement that removes one managed role's over-grant, or where to look
    when the role arrives through another role."""
    if not role.direct:
        return (
            f"the tool account reaches {account} through another role it is a member "
            "of: revoke that membership. `privileges.roles` in --output json lists "
            "every role it holds"
        )
    if grant_options:
        return (
            f"GRANT {_identifier(account)} TO {_identifier(user)} WITH INHERIT FALSE, "
            "SET FALSE keeps the ADMIN OPTION and gives the tool none of the role's "
            "privileges"
        )
    return (
        f"REVOKE {_identifier(account)} FROM {_identifier(user)}: CREATEROLE alone "
        "changes its password on this server"
    )


def _identifier(name: str) -> str:
    """``name`` as a quoted identifier, so a pasted statement names that role."""
    return '"' + name.replace('"', '""') + '"'


def audit(cursor: Cursor, accounts: Sequence[str]) -> PrivilegeAudit:
    """Read the tool account and the managed roles, and classify what comes back.

    Four reads. A role the config declares and the cluster does not have is
    reported, and is not an error: the tool does not create roles.
    """
    cursor.execute(SELF_ROW)
    user, *flags = cursor.fetchone()
    attributes = frozenset(name for name, value in zip(ATTRIBUTES, flags, strict=True) if value)
    cursor.execute(GRANT_OPTIONS_ROW)
    grant_options = bool(cursor.fetchone()[0])
    cursor.execute(MEMBERSHIPS.format(edge=USABLE_EDGE if grant_options else "true"))
    memberships = {str(name): bool(usable) for name, usable in cursor.fetchall()}
    managed: list[ManagedRole] = []
    if accounts:
        query = MANAGED_ROLES.format(direct=DIRECT_USABLE if grant_options else DIRECT_MEMBER)
        cursor.execute(query, ("SET" if grant_options else "MEMBER", list(accounts)))
        managed = [ManagedRole(str(name), *map(bool, rest)) for name, *rest in cursor.fetchall()]
    return classify(
        user=str(user),
        attributes=attributes,
        grant_options=grant_options,
        memberships=memberships,
        accounts=accounts,
        managed=managed,
    )
