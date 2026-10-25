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

**Membership is read from ``pg_auth_members``, not from ``pg_has_role``**, for
the built-in roles. ``pg_has_role`` answers true for every role when the tool
account is a superuser, so it would list all six built-in roles of §3 as held.
For a managed role ``pg_has_role`` is the server's own answer to what the tool
can do with the role, through any chain of grants, and that is what it is
asked.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Protocol

from sopuli.driver.protocol import PrivilegeAudit

CREATEROLE = "CREATEROLE"

#: The role attributes the audit reads, spelled as ``ALTER ROLE`` spells them,
#: and the ``pg_roles`` column of each.
ATTRIBUTES = {
    "SUPERUSER": "rolsuper",
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

#: Every role the tool account is a member of, through any chain of grants.
#: ``union`` rather than ``union all`` ends the walk, since a role reached twice
#: adds no row. ``{edge}`` is empty, or :data:`USABLE_EDGE`.
MEMBERSHIPS = (
    "with recursive held(oid) as ("
    "select roleid from pg_auth_members "
    "where member = (select oid from pg_roles where rolname = current_user){edge} "
    "union "
    "select m.roleid from pg_auth_members m join held h on m.member = h.oid{edge}"
    ") select r.rolname from pg_roles r join held on r.oid = held.oid"
)

#: Where grants carry options, a grant with ``INHERIT FALSE`` and ``SET FALSE``
#: gives the member nothing of the role. The walk does not follow it, so the
#: tool's own grant on a managed role does not report what that role holds.
USABLE_EDGE = " and (inherit_option or set_option)"

#: What the tool account can do with each managed role that exists. The last
#: column's mode is a parameter: ``SET`` where grants carry the option, and
#: ``MEMBER`` before, where every member can ``SET ROLE``.
MANAGED_ROLES = (
    "select rolname, "
    "pg_has_role(current_user, oid, 'USAGE WITH ADMIN OPTION'), "
    "pg_has_role(current_user, oid, 'USAGE'), "
    "pg_has_role(current_user, oid, %s) "
    "from pg_roles where rolname = any(%s)"
)

#: §3's attributes. ``SUPERUSER`` is listed although the run refuses a
#: superuser, so the audit reads the same whoever calls it.
FORBIDDEN_ATTRIBUTES = ("SUPERUSER", "REPLICATION", "BYPASSRLS")

#: §3's built-in roles.
FORBIDDEN_ROLES = (
    "pg_execute_server_program",
    "pg_read_server_files",
    "pg_write_server_files",
    "pg_read_all_data",
    "pg_write_all_data",
    "pg_signal_backend",
    "pg_read_all_stats",
)

DOCUMENT = "02-postgres-privileges.md"


class Cursor(Protocol):
    """The part of a psycopg cursor this module uses."""

    def execute(self, query: Any, params: Any = None, /) -> Any: ...

    def fetchone(self) -> Any: ...

    def fetchall(self) -> Any: ...


@dataclass(frozen=True)
class ManagedRole:
    """What the tool account can do with one managed role, from ``pg_has_role``."""

    name: str
    admin: bool
    inherits: bool
    can_set: bool


def classify(
    *,
    user: str,
    attributes: frozenset[str],
    grant_options: bool,
    memberships: frozenset[str],
    accounts: Sequence[str],
    managed: Sequence[ManagedRole],
) -> PrivilegeAudit:
    """§2's and §3's lists against what was read. Pure, and the whole judgement.

    ``attributes`` holds the role attributes that are true, spelled as
    ``ALTER ROLE`` spells them. ``accounts`` is every role the config declares
    on this target, and ``managed`` the ones of them that exist.
    """
    found = {name for name in FORBIDDEN_ATTRIBUTES if name in attributes}
    found |= {name for name in FORBIDDEN_ROLES if name in memberships}
    held = [CREATEROLE] if CREATEROLE in attributes else []
    missing = [] if held else [CREATEROLE]
    remedies: list[str] = []

    by_name = {role.name: role for role in managed}
    for account in accounts:
        role = by_name.get(account)
        if role is None:
            missing.append(f"role {account}, which does not exist")
            continue
        if grant_options:
            (held if role.admin else missing).append(f"ADMIN OPTION ON {account}")
            if role.inherits:
                found.add(f"INHERIT TRUE ON {account}")
            if role.can_set:
                found.add(f"SET TRUE ON {account}")
            if role.inherits or role.can_set:
                remedies.append(
                    f"GRANT {account} TO {user} WITH INHERIT FALSE, SET FALSE keeps the "
                    "ADMIN OPTION and gives the tool none of the role's privileges"
                )
        elif role.can_set:
            found.add(f"MEMBER OF {account}")
            remedies.append(
                f"REVOKE {account} FROM {user}: CREATEROLE alone changes its password "
                "on this server"
            )

    return PrivilegeAudit(
        over_granted=tuple(sorted(found)),
        held=tuple(sorted(held)),
        missing=tuple(sorted(missing)),
        roles=tuple(sorted(memberships)),
        remedies=tuple(remedies),
        hint=f"{DOCUMENT} section 2 has the grants for the tool account `{user}`",
    )


def audit(cursor: Cursor, accounts: Sequence[str]) -> PrivilegeAudit:
    """Read the tool account and the managed roles, and classify what comes back.

    Four reads. A role the config declares and the cluster does not have is
    reported as missing, and is not an error: the tool does not create roles.
    """
    cursor.execute(SELF_ROW)
    user, *flags = cursor.fetchone()
    attributes = frozenset(name for name, value in zip(ATTRIBUTES, flags, strict=True) if value)
    cursor.execute(GRANT_OPTIONS_ROW)
    grant_options = bool(cursor.fetchone()[0])
    cursor.execute(MEMBERSHIPS.format(edge=USABLE_EDGE if grant_options else ""))
    memberships = frozenset(str(row[0]) for row in cursor.fetchall())
    managed: list[ManagedRole] = []
    if accounts:
        cursor.execute(MANAGED_ROLES, ("SET" if grant_options else "MEMBER", list(accounts)))
        managed = [ManagedRole(str(name), *map(bool, rest)) for name, *rest in cursor.fetchall()]
    return classify(
        user=str(user),
        attributes=attributes,
        grant_options=grant_options,
        memberships=memberships,
        accounts=accounts,
        managed=managed,
    )
