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
#: whether some chain gives the tool something of the role. A role's privileges
#: pass down a chain whose every grant has ``INHERIT``, and ``SET ROLE`` reaches
#: down a chain whose every grant has ``SET``, so the two are carried
#: separately: a chain of one of each gives neither. ``union`` rather than
#: ``union all`` ends the walk, since each role has at most four rows.
#: ``{inherit}`` and ``{set}`` are the grant's columns, or ``true`` before 16,
#: where every member can ``SET ROLE``.
MEMBERSHIPS = (
    "with recursive held(oid, inherits, sets) as ("
    f"select m.roleid, {{inherit}}, {{set}} from pg_auth_members m where m.member = {ME} "
    "union "
    "select m.roleid, h.inherits and {inherit}, h.sets and {set} from pg_auth_members m "
    "join held h on m.member = h.oid"
    ") select r.rolname, bool_or(held.inherits or held.sets) from pg_roles r "
    "join held on r.oid = held.oid group by r.rolname"
)
GRANT_COLUMNS = {"inherit": "m.inherit_option", "set": "m.set_option"}
NO_GRANT_COLUMNS = {"inherit": "true", "set": "true"}

#: What the tool account can do with each managed role that exists, and how it
#: reaches it: by a grant straight to the tool account that gives it something
#: (``{direct}``, :data:`DIRECT_USABLE` or :data:`DIRECT_MEMBER`), and through
#: another role it is a member of (the last column). The mode is a parameter:
#: ``SET`` where grants carry the option, and ``MEMBER`` before. Names are
#: compared by ``upper()``, as the config compares account names.
MANAGED_ROLES = (
    "select r.rolname, "
    "pg_has_role(current_user, r.oid, 'USAGE WITH ADMIN OPTION'), "
    "pg_has_role(current_user, r.oid, 'USAGE'), "
    "pg_has_role(current_user, r.oid, %s), "
    "{direct}, "
    f"exists (select 1 from pg_auth_members m where m.member = {ME} "
    "and m.roleid <> r.oid and pg_has_role(m.roleid, r.oid, 'MEMBER')) "
    "from pg_roles r where upper(r.rolname) = any(%s)"
)
DIRECT_USABLE = (
    "coalesce((select bool_or(m.inherit_option or m.set_option) from pg_auth_members m "
    f"where m.roleid = r.oid and m.member = {ME}), false)"
)
DIRECT_MEMBER = (
    f"exists (select 1 from pg_auth_members m where m.roleid = r.oid and m.member = {ME})"
)

#: §3's attributes. ``SUPERUSER`` is listed for a caller that audits without
#: the session's scope: :func:`~sopuli.driver.postgres.scope.observe` refuses a
#: superuser first, so `doctor` never reaches the audit as one.
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
    """What the tool account can do with one managed role, from ``pg_has_role``.
    ``direct``: a grant straight to the tool account gives it something.
    ``indirect``: the tool account also reaches it through another role."""

    name: str
    admin: bool
    inherits: bool
    can_set: bool
    direct: bool = True
    indirect: bool = False


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
    target, and ``managed`` the ones of them that exist. A name matches as
    written first, and by ``upper()`` after; findings use the cluster's spelling.

    A declared role the cluster lacks is in neither ``held`` nor ``missing``:
    no grant fixes it. A remedies line says so.
    """
    found = {name for name in FORBIDDEN_ATTRIBUTES if name in attributes}
    found |= {name for name in FORBIDDEN_ROLES if memberships.get(name)}
    held = [CREATEROLE] if CREATEROLE in attributes else []
    missing = [] if held else [CREATEROLE]
    remedies: list[str] = []

    exact = {role.name: role for role in managed}
    folded: dict[str, ManagedRole] = {}
    for one in managed:
        folded.setdefault(one.name.upper(), one)
    for account in accounts:
        role = exact.get(account) or folded.get(account.upper())
        if role is None:
            remedies.append(
                f"{account} does not exist on this cluster: create it, or remove it from "
                "the config. The tool does not create roles"
            )
            continue
        if grant_options:
            (held if role.admin else missing).append(f"ADMIN OPTION ON {role.name}")
        if SUPERUSER in attributes:
            continue
        over = _over_granted(role, grant_options=grant_options)
        if over:
            found |= set(over)
            remedies.extend(_remedies(role, user, grant_options=grant_options))

    return PrivilegeAudit(
        over_granted=tuple(sorted(found)),
        held=tuple(sorted(held)),
        missing=tuple(sorted(missing)),
        roles=tuple(sorted(memberships)),
        remedies=tuple(remedies),
        hint=f"{DOCUMENT} section 2 has the grants for the tool account `{user}`",
    )


def _over_granted(role: ManagedRole, *, grant_options: bool) -> list[str]:
    """What the tool can do with one managed role beyond changing its password."""
    if not grant_options:
        return [f"MEMBER OF {role.name}"] if role.can_set else []
    found = []
    if role.inherits:
        found.append(f"INHERIT TRUE ON {role.name}")
    if role.can_set:
        found.append(f"SET TRUE ON {role.name}")
    return found


def _remedies(role: ManagedRole, user: str, *, grant_options: bool) -> list[str]:
    """What removes one managed role's over-grant: a statement for the grant
    made straight to the tool account, and a pointer for a path through another
    role, which a statement about the direct grant would leave in place."""
    lines = []
    name, tool = _identifier(role.name), _identifier(user)
    if role.direct and grant_options:
        keeps = (
            "keeps the ADMIN OPTION and gives the tool none of the role's privileges"
            if role.admin
            else "gives the tool the ADMIN OPTION it needs and none of the role's privileges"
        )
        options = (
            "INHERIT FALSE, SET FALSE" if role.admin else "ADMIN OPTION, INHERIT FALSE, SET FALSE"
        )
        lines.append(
            f"GRANT {name} TO {tool} WITH {options} {keeps}. Run it as the role that made "
            "the grant, or it adds a second grant beside the first"
        )
    elif role.direct:
        lines.append(
            f"REVOKE {name} FROM {tool}: CREATEROLE alone changes its password on this server"
        )
    if role.indirect or not role.direct:
        also = "also " if role.direct else ""
        lines.append(
            f"the tool account {also}reaches {role.name} through another role it is a "
            "member of: revoke that membership. `privileges.roles` in --output json lists "
            "every role it holds"
        )
    return lines


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
    cursor.execute(MEMBERSHIPS.format(**(GRANT_COLUMNS if grant_options else NO_GRANT_COLUMNS)))
    memberships = {str(name): bool(usable) for name, usable in cursor.fetchall()}
    managed: list[ManagedRole] = []
    if accounts:
        query = MANAGED_ROLES.format(direct=DIRECT_USABLE if grant_options else DIRECT_MEMBER)
        mode = "SET" if grant_options else "MEMBER"
        cursor.execute(query, (mode, [account.upper() for account in accounts]))
        managed = [ManagedRole(str(name), *map(bool, rest)) for name, *rest in cursor.fetchall()]
    return classify(
        user=str(user),
        attributes=attributes,
        grant_options=grant_options,
        memberships=memberships,
        accounts=accounts,
        managed=managed,
    )
