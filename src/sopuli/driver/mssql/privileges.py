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
by the tool login's SID. ``HAS_DBACCESS('msdb')`` answers 1 for every login,
because ``msdb``'s ``guest`` is enabled (measured on 16.0.4325.4, #1550).

**A grant on one login is read from the tool login's own rows**, and those of
``public`` and of each role it is a member of, nested roles followed. The
tool login sees the memberships of its own roles, nested ones included, with
``ALTER ANY LOGIN`` alone, where it does not see another login's (PA2;
measured on 16.0.4325.4, #1550). So nothing here needs ``VIEW ANY
DEFINITION``.
"""

from __future__ import annotations

from dataclasses import dataclass

from sopuli.driver.mssql.admin import bracketed
from sopuli.driver.protocol import Cursor, PrivilegeAudit

ALTER_ANY_LOGIN = "ALTER ANY LOGIN"
VIEW_ANY_DEFINITION = "VIEW ANY DEFINITION"

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


#: The tool login's name, what it needs, what §3 lists, and its user in
#: ``msdb``, in one round trip.
SELF_ROW = (
    "SELECT SUSER_SNAME(), "
    f"HAS_PERMS_BY_NAME(NULL, NULL, '{ALTER_ANY_LOGIN}'), "
    f"HAS_PERMS_BY_NAME(NULL, NULL, '{VIEW_ANY_DEFINITION}'), "
    + "".join(f"HAS_PERMS_BY_NAME(NULL, NULL, '{name}'), " for name in FORBIDDEN_PERMISSIONS)
    + "".join(f"IS_SRVROLEMEMBER('{name}'), " for name in FORBIDDEN_ROLES)
    + "(SELECT COUNT(*) FROM msdb.sys.database_principals WHERE sid = SUSER_SID())"
)

#: §3's grants on one login, held by the tool login, ``public`` or a role the
#: tool login is a member of, nested roles followed. Columns, not one
#: concatenated string: the catalog's columns differ in collation, ``451``.
LOGIN_GRANT_ROWS = (
    "WITH mine (principal_id) AS ("
    "SELECT SUSER_ID() UNION ALL SELECT 2 UNION ALL "
    "SELECT m.role_principal_id FROM sys.server_role_members AS m "
    "JOIN mine ON m.member_principal_id = mine.principal_id "
    "WHERE mine.principal_id <> 2) "
    "SELECT DISTINCT p.permission_name, o.name, p.major_id FROM sys.server_permissions AS p "
    "LEFT JOIN sys.server_principals AS o ON o.principal_id = p.major_id "
    "WHERE p.class = 101 AND p.state IN ('G', 'W') "
    f"AND p.permission_name IN ({', '.join(repr(g) for g in LOGIN_GRANTS)}) "
    "AND p.grantee_principal_id IN (SELECT principal_id FROM mine) "
    "OPTION (MAXRECURSION 100)"
)


@dataclass(frozen=True)
class Self:
    """What :data:`SELF_ROW` read."""

    name: str
    alter_any_login: bool
    view_any_definition: bool
    over_granted: tuple[str, ...]


def read_self(cursor: Cursor) -> Self:
    cursor.execute(SELF_ROW)
    row = cursor.fetchone()
    name, alter_any_login, view_any_definition, *rest = row
    flags = dict(zip((*FORBIDDEN_PERMISSIONS, *FORBIDDEN_ROLES), rest, strict=False))
    over = [held for held, answer in flags.items() if answer == 1]
    if rest[-1]:
        over.append(MSDB_USER)
    return Self(
        name=str(name),
        alter_any_login=alter_any_login == 1,
        view_any_definition=view_any_definition == 1,
        over_granted=tuple(over),
    )


def read_login_grants(cursor: Cursor) -> tuple[str, ...]:
    """§3's grants on one login, as ``IMPERSONATE ON LOGIN::[x]``."""
    cursor.execute(LOGIN_GRANT_ROWS)
    return tuple(
        f"{permission} ON LOGIN::{bracketed(str(name))}"
        if name is not None
        else f"{permission} ON principal #{major}"
        for permission, name, major in cursor.fetchall()
    )


def audit(cursor: Cursor) -> PrivilegeAudit:
    """The tool login's audit (§2.1, §3)."""
    found = read_self(cursor)
    over = sorted({*found.over_granted, *read_login_grants(cursor)})
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
    remedies: list[str] = []
    if not found.view_any_definition:
        remedies.append(
            f"the tool login does not hold {VIEW_ANY_DEFINITION}, so guardrail 9 refuses "
            f"every managed login on the verbs that set a password; GRANT "
            f"{VIEW_ANY_DEFINITION} TO {me} to change passwords here "
            "(02-mssql-privileges.md §2.1)"
        )
    return PrivilegeAudit(
        over_granted=tuple(over),
        held=held,
        missing=missing,
        remedies=tuple(remedies),
        hint=(
            None
            if not missing
            else "run the GRANT as an administrator, as 02-mssql-privileges.md §2.1 shows"
        ),
    )
