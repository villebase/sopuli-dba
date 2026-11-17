"""What the tool login on a SQL Server instance holds, needs and should not
hold. Tier 0.

``02-mssql-privileges.md`` §2.1 says what the tool login needs, and §3 what
must not be granted. Every read here is of the tool login itself, which any
login can make: ``HAS_PERMS_BY_NAME`` and ``IS_SRVROLEMEMBER`` answer for the
session, through any role and through ``sysadmin``; its own rows in
``sys.server_permissions``; and its user in ``msdb``. It reports and never
refuses: over-granting warns (P5).

**Needed:** ``ALTER ANY LOGIN``. Without it the tool changes no login.

**Needed to change a password:** ``VIEW ANY DEFINITION``. Without it guardrail
9 refuses every managed login on the password verbs (§5, #1567). `creds
check`, `doctor` and the reports work without it, so §2.1 documents it as the
grant a password-changing estate adds. A missing one is a remedy, not a
missing grant: an estate that only reads is installed as documented.

**A database user in ``msdb`` is read from ``msdb.sys.database_principals``**,
by the tool login's SID, in a read of its own. ``HAS_DBACCESS('msdb')``
answers 1 for every login, because ``msdb``'s ``guest`` is enabled (measured
on 16.0.4325.4, #1550). Where ``guest`` is closed, the read is refused, and
the audit says it could not read ``msdb`` rather than failing.

**A grant on one login is read from the tool login's own rows**, and those of
``public`` and of each role it is a member of, nested roles followed. The
tool login sees the memberships of its own roles, nested ones included, with
``ALTER ANY LOGIN`` alone, where it does not see another login's (PA2;
measured on 16.0.4325.4, #1550). A denial of ``VIEW ANY SECURITY
DEFINITION``, 2022 and later, hides such rows (``13_fixed_roles_probe.py``,
FR5), and its own ``CONNECT SQL`` row with them, which is how the audit
tells: under it these grants are reported as not checked.
"""

from __future__ import annotations

from dataclasses import dataclass

from sopuli.driver.mssql.admin import GRANTED, PRINCIPAL_CLASS, ROLE_TYPE, bracketed
from sopuli.driver.protocol import Cursor, PrivilegeAudit

ALTER_ANY_LOGIN = "ALTER ANY LOGIN"
VIEW_ANY_DEFINITION = "VIEW ANY DEFINITION"
VIEW_ANY_SECURITY_DEFINITION = "VIEW ANY SECURITY DEFINITION"

#: The server permissions of §3, each read with ``HAS_PERMS_BY_NAME``.
FORBIDDEN_PERMISSIONS = (
    "CONTROL SERVER",
    "ALTER ANY SERVER ROLE",
    "IMPERSONATE ANY LOGIN",
    "VIEW SERVER STATE",
)

#: The fixed server roles of §3.
FORBIDDEN_ROLES = ("sysadmin", "securityadmin")

#: §3's database user in ``msdb``, as the audit names it.
MSDB_USER = "a database user in msdb"

#: §3's grants on one login.
LOGIN_GRANTS = ("CONTROL", "IMPERSONATE")

#: What the audit names as not checked where the denial hides the rows.
LOGIN_GRANTS_HIDDEN = "CONTROL or IMPERSONATE on a login"

#: The read that is refused where ``msdb``'s ``guest`` is closed.
MSDB_READ = "msdb.sys.database_principals"

#: Each column of :data:`SELF_ROW`, in order, with the expression that reads
#: it. One list, so the statement and the reading of its row cannot drift.
SELF_COLUMNS: tuple[tuple[str, str], ...] = (
    ("name", "SUSER_SNAME()"),
    (ALTER_ANY_LOGIN, f"HAS_PERMS_BY_NAME(NULL, NULL, '{ALTER_ANY_LOGIN}')"),
    (VIEW_ANY_DEFINITION, f"HAS_PERMS_BY_NAME(NULL, NULL, '{VIEW_ANY_DEFINITION}')"),
    # The tool login's own CONNECT SQL row: every login that connects holds
    # it, and a denial of VIEW ANY SECURITY DEFINITION hides it, with or
    # without VIEW ANY DEFINITION. HAS_PERMS_BY_NAME of that permission
    # cannot tell, without VIEW ANY DEFINITION: it answers 0 whether the
    # permission is denied or only not held (measured on 16.0.4325.4, #1550).
    (
        VIEW_ANY_SECURITY_DEFINITION,
        "(SELECT COUNT(*) FROM sys.server_permissions WHERE class = 100 "
        "AND permission_name = 'CONNECT SQL' AND grantee_principal_id = SUSER_ID())",
    ),
    *((name, f"HAS_PERMS_BY_NAME(NULL, NULL, '{name}')") for name in FORBIDDEN_PERMISSIONS),
    *((name, f"IS_SRVROLEMEMBER('{name}')") for name in FORBIDDEN_ROLES),
)

#: The tool login's name, what it needs, and what §3 lists, in one round trip.
SELF_ROW = "SELECT " + ", ".join(expression for _, expression in SELF_COLUMNS)

#: The tool login's user in ``msdb``, by its SID.
MSDB_ROW = f"SELECT COUNT(*) FROM {MSDB_READ} WHERE sid = SUSER_SID()"

_GRANTED_STATES = ", ".join(f"'{state}'" for state in sorted(GRANTED))

#: §3's grants on one login, held by the tool login, ``public`` or a role the
#: tool login is a member of, nested roles followed. A grant on a server role
#: is the same class, and is left out. Columns, not one concatenated string:
#: the catalog's columns differ in collation, ``451``.
LOGIN_GRANT_ROWS = (
    "WITH mine (principal_id) AS ("
    "SELECT SUSER_ID() UNION ALL SELECT principal_id FROM sys.server_principals "
    "WHERE name = 'public' AND type = 'R' UNION ALL "
    "SELECT m.role_principal_id FROM sys.server_role_members AS m "
    "JOIN mine ON m.member_principal_id = mine.principal_id) "
    "SELECT DISTINCT p.permission_name, o.name, p.major_id FROM sys.server_permissions AS p "
    "LEFT JOIN sys.server_principals AS o ON o.principal_id = p.major_id "
    f"WHERE p.class = {PRINCIPAL_CLASS} AND p.state IN ({_GRANTED_STATES}) "
    f"AND p.permission_name IN ({', '.join(repr(g) for g in LOGIN_GRANTS)}) "
    f"AND (o.type IS NULL OR o.type <> '{ROLE_TYPE}') "
    "AND p.grantee_principal_id IN (SELECT principal_id FROM mine) "
    "OPTION (MAXRECURSION 100)"
)


@dataclass(frozen=True)
class Self:
    """What :data:`SELF_ROW` read."""

    name: str
    alter_any_login: bool
    view_any_definition: bool
    #: Whether the tool login sees its own ``CONNECT SQL`` row: ``False``
    #: where a denial of ``VIEW ANY SECURITY DEFINITION`` hides its rows.
    security_definitions_visible: bool
    over_granted: tuple[str, ...]


def read_self(cursor: Cursor) -> Self:
    cursor.execute(SELF_ROW)
    row = tuple(cursor.fetchone())
    if len(row) != len(SELF_COLUMNS):
        raise ValueError(f"the audit's read gave {len(row)} columns, not {len(SELF_COLUMNS)}")
    read = {name: value for (name, _), value in zip(SELF_COLUMNS, row, strict=True)}
    forbidden = (*FORBIDDEN_PERMISSIONS, *FORBIDDEN_ROLES)
    return Self(
        name=str(read["name"]),
        alter_any_login=read[ALTER_ANY_LOGIN] == 1,
        view_any_definition=read[VIEW_ANY_DEFINITION] == 1,
        security_definitions_visible=bool(read[VIEW_ANY_SECURITY_DEFINITION]),
        over_granted=tuple(held for held in forbidden if read[held] == 1),
    )


def read_msdb_user(cursor: Cursor) -> bool:
    """Whether the tool login has a user in ``msdb``. The session makes this
    read on its own, so a refusal leaves the rest of the audit."""
    cursor.execute(MSDB_ROW)
    row = cursor.fetchone()
    return bool(row and row[0])


def read_login_grants(cursor: Cursor) -> tuple[str, ...]:
    """§3's grants on one login, as ``IMPERSONATE ON LOGIN::[x]``."""
    cursor.execute(LOGIN_GRANT_ROWS)
    return tuple(
        f"{permission} ON LOGIN::{bracketed(str(name))}"
        if name is not None
        else f"{permission} ON principal #{major}"
        for permission, name, major in cursor.fetchall()
    )


def audit(cursor: Cursor, *, msdb_user: bool | None) -> PrivilegeAudit:
    """The tool login's audit (§2.1, §3). ``msdb_user`` is what
    :func:`read_msdb_user` answered, or ``None`` where it was refused."""
    found = read_self(cursor)
    over = set(found.over_granted)
    unaudited: list[str] = []
    remedies: list[str] = []
    if found.security_definitions_visible:
        over.update(read_login_grants(cursor))
    else:
        unaudited.append(LOGIN_GRANTS_HIDDEN)
        remedies.append(
            f"the tool login is denied {VIEW_ANY_SECURITY_DEFINITION}, which hides its "
            "grants on one login; revoke the denial (02-mssql-privileges.md §5)"
        )
    if msdb_user:
        over.add(MSDB_USER)
    me = bracketed(found.name)
    held = tuple(
        sorted(
            grant
            for grant, has in (
                (ALTER_ANY_LOGIN, found.alter_any_login),
                (VIEW_ANY_DEFINITION, found.view_any_definition),
            )
            if has
        )
    )
    missing = () if found.alter_any_login else (f"GRANT {ALTER_ANY_LOGIN} TO {me}",)
    if not found.view_any_definition:
        remedies.append(
            f"the tool login does not hold {VIEW_ANY_DEFINITION}, so guardrail 9 refuses "
            f"every managed login on the verbs that set a password; GRANT "
            f"{VIEW_ANY_DEFINITION} TO {me} to change passwords here "
            "(02-mssql-privileges.md §2.1)"
        )
    return PrivilegeAudit(
        over_granted=tuple(sorted(over)),
        held=held,
        missing=missing,
        unaudited=tuple(unaudited),
        unreadable=() if msdb_user is not None else (MSDB_READ,),
        remedies=tuple(remedies),
        hint=(
            None
            if not missing
            else "run the GRANT as an administrator, as 02-mssql-privileges.md §2.1 shows"
        ),
    )
