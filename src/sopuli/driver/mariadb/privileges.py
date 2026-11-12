"""What the tool account on a MariaDB server holds, needs and should not hold.
Tier 0.

``02-mariadb-privileges.md`` §2.1 says what the tool account is granted, and
§3 what it must not hold. The audit reads ``information_schema``'s privilege
tables, which show any account its own grants without a grant of their own
(TG5), and never ``SHOW GRANTS``, which on MariaDB prints the account's own
stored value (§2.2). It reports and never refuses: over-granting warns (P5).

**Everything outside §2.1 is over-granted**, as on MySQL: the audit keeps no
list of dangerous privileges. The ones that read every stored value, such as
``SELECT`` on ``mysql.*`` or ``mysql.global_priv``, are among them.

``information_schema`` shows only the grants made to the account itself. What a
role gives it is not there, so where the account holds a role, the audit says
that those privileges were not checked.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from contextlib import suppress
from dataclasses import dataclass

from sopuli.driver.mysql_family.accounts import Principal, current_user, split, text
from sopuli.driver.protocol import Cursor, PrivilegeAudit

DOCUMENT = "02-mariadb-privileges.md"

CREATE_USER = "CREATE USER"
USAGE = "USAGE"
USER_TABLE = "mysql.user"

#: §2.1's columns of the ``mysql.user`` view: an account's identity, plugin and
#: expiry, and every ``*_priv`` column guardrail 9 reads.
COLUMNS = (
    "User",
    "Host",
    "plugin",
    "password_expired",
    "is_role",
    "Select_priv",
    "Insert_priv",
    "Update_priv",
    "Delete_priv",
    "Create_priv",
    "Drop_priv",
    "Reload_priv",
    "Shutdown_priv",
    "Process_priv",
    "File_priv",
    "Grant_priv",
    "References_priv",
    "Index_priv",
    "Alter_priv",
    "Show_db_priv",
    "Super_priv",
    "Create_tmp_table_priv",
    "Lock_tables_priv",
    "Execute_priv",
    "Repl_slave_priv",
    "Repl_client_priv",
    "Create_view_priv",
    "Show_view_priv",
    "Create_routine_priv",
    "Alter_routine_priv",
    "Create_user_priv",
    "Event_priv",
    "Trigger_priv",
    "Create_tablespace_priv",
    "Delete_history_priv",
)

#: Columns of the view the tool account may also read, with a column grant,
#: and does without: held where granted, never missing (§2.1). The default
#: role, for the privilege report (#1411, R3, #1483). It holds a role's name
#: only.
OPTIONAL_COLUMNS = ("default_role",)

#: Views the tool account may also read, with ``SELECT`` on each, and does
#: without: held where granted, never missing. The optional view the reports
#: read the lock, the lifetime and the time of the last change from (§2.1,
#: #1491). It holds no stored value; its definer reads ``global_priv``.
OPTIONAL_TABLES = ("sopuli.account_state",)

#: §2.1's whole-table reads: roles, and the privilege tables guardrail 9 reads.
#: None holds a stored value (checked on 10.11.19, 11.4.13, 11.8.9 and 12.3.3).
TABLES_READ = (
    "mysql.roles_mapping",
    "mysql.db",
    "mysql.tables_priv",
    "mysql.columns_priv",
    "mysql.procs_priv",
    "mysql.proxies_priv",
)
GLOBAL_PRIVILEGES = (
    "select PRIVILEGE_TYPE, IS_GRANTABLE from information_schema.USER_PRIVILEGES where GRANTEE = %s"
)
SCHEMA_PRIVILEGES = (
    "select TABLE_SCHEMA, PRIVILEGE_TYPE, IS_GRANTABLE from information_schema.SCHEMA_PRIVILEGES "
    "where GRANTEE = %s"
)
TABLE_PRIVILEGES = (
    "select TABLE_SCHEMA, TABLE_NAME, PRIVILEGE_TYPE, IS_GRANTABLE "
    "from information_schema.TABLE_PRIVILEGES where GRANTEE = %s"
)
COLUMN_PRIVILEGES = (
    "select TABLE_SCHEMA, TABLE_NAME, COLUMN_NAME, PRIVILEGE_TYPE, IS_GRANTABLE "
    "from information_schema.COLUMN_PRIVILEGES where GRANTEE = %s"
)
#: Every role the tool account can use, nested ones included. Not filtered by
#: grantee: ``APPLICABLE_ROLES`` already lists only the session account's, and
#: spells its grantee ``user@host`` without quotes, and a nested role's grantee
#: as the role that holds it (measured on 11.8.9, #1287).
ROLES = "select distinct ROLE_NAME from information_schema.APPLICABLE_ROLES order by ROLE_NAME"

OVER_GRANTED_REMEDY = (
    "revoke each over-granted privilege from the tool account: it needs only what "
    f"{DOCUMENT} section 2.1 lists, and SELECT on mysql.* or mysql.global_priv reads "
    "every account's stored value"
)
ROLES_UNAUDITED = "privileges the tool account gets through a role"

#: Grants to ``PUBLIC`` (10.11 and later) reach every account and show in no
#: ``information_schema`` row the tool account reads (measured on 11.8.9,
#: #1287). The reads below catch the ones that matter most; the rest are not
#: audited, and the caveat says so on every run.
PUBLIC_UNAUDITED = (
    "privileges granted to PUBLIC, apart from reading stored values, which is tried "
    "directly; SHOW GRANTS FOR PUBLIC lists them"
)

#: Reads that return every account's stored value, tried with ``LIMIT 0`` so
#: that a read that is allowed still returns nothing. Refused, ``1142`` or
#: ``1143``, for an account with §2.1 alone. Allowed by any route at all, a
#: direct grant, a role, ``PUBLIC`` or a broader grant, they are over-granted.
HASH_READS = {
    "SELECT ON mysql.global_priv": "select 1 from mysql.global_priv limit 0",
    "SELECT (authentication_string) ON mysql.user": (
        "select authentication_string from mysql.user limit 0"
    ),
    "SELECT (Password) ON mysql.user": "select Password from mysql.user limit 0",
}

#: The answers that mean a read was refused.
REFUSED = frozenset({1142, 1143})
ROLES_REMEDY = (
    "information_schema shows only the tool account's own grants: check what each role "
    "in `privileges.roles` gives, or grant §2.1 to the account directly and revoke the roles"
)


@dataclass(frozen=True)
class Grants:
    """The tool account's own grants, as ``information_schema`` lists them."""

    #: ``(privilege, grantable)`` on ``*.*``.
    global_: tuple[tuple[str, bool], ...] = ()
    #: ``(schema, privilege, grantable)``.
    schema: tuple[tuple[str, str, bool], ...] = ()
    #: ``(schema.table, privilege, grantable)``.
    table: tuple[tuple[str, str, bool], ...] = ()
    #: ``(schema.table, column, privilege, grantable)``.
    column: tuple[tuple[str, str, str, bool], ...] = ()


def grantee(user: str) -> str:
    """``information_schema``'s spelling of an account, ``'user'@'host'``."""
    name, host = split(user)
    return f"'{name}'@'{host}'"


def classify(
    *, user: str, grants: Grants, roles: Iterable[str], reads: Iterable[str] = ()
) -> PrivilegeAudit:
    """§2.1 against what was read. Pure, and the whole judgement.

    ``reads`` are the :data:`HASH_READS` the server allowed. A broader
    ``SELECT``, on ``*.*`` or ``mysql.*``, counts as holding every §2.1 read it
    covers, as on MySQL, and is over-granted too: the tool can read what it
    needs, and reads more.
    """
    held: set[str] = set()
    over: set[str] = set(reads)
    broad = False
    for privilege, grantable in grants.global_:
        if grantable:
            over.add("GRANT OPTION ON *.*")
        if privilege == CREATE_USER:
            held.add(CREATE_USER)
        elif privilege != USAGE:
            over.add(f"{privilege} ON *.*")
            broad = broad or privilege == "SELECT"
    for schema, privilege, grantable in grants.schema:
        if grantable:
            over.add(f"GRANT OPTION ON {schema}.*")
        over.add(f"{privilege} ON {schema}.*")
        broad = broad or (_covers_mysql(schema) and privilege == "SELECT")
    if broad:
        held.update(_column(name) for name in (*COLUMNS, *OPTIONAL_COLUMNS))
        held.update(_table(table) for table in TABLES_READ)
    for table, privilege, grantable in grants.table:
        if grantable:
            over.add(f"GRANT OPTION ON {table}")
        if table in (*TABLES_READ, *OPTIONAL_TABLES) and privilege == "SELECT":
            held.add(_table(table))
            continue
        if table == USER_TABLE and privilege == "SELECT":
            # The whole view: every §2.1 column, and the stored values too.
            held.update(_column(name) for name in (*COLUMNS, *OPTIONAL_COLUMNS))
        over.add(f"{privilege} ON {table}")
    for table, column, privilege, grantable in grants.column:
        if grantable:
            over.add(f"GRANT OPTION ON {table}")
        needed = _needed_column(column) if table == USER_TABLE else None
        if privilege == "SELECT" and needed is not None:
            held.add(_column(needed))
        else:
            over.add(f"{privilege} ({column}) ON {table}")

    no_create_user = CREATE_USER not in held
    columns = [name for name in COLUMNS if _column(name) not in held]
    tables = [table for table in TABLES_READ if _table(table) not in held]
    missing = (
        ([CREATE_USER] if no_create_user else [])
        + [_column(name) for name in columns]
        + [_table(table) for table in tables]
    )
    held_roles = tuple(sorted(set(roles)))
    remedies = ((OVER_GRANTED_REMEDY,) if over else ()) + ((ROLES_REMEDY,) if held_roles else ())
    return PrivilegeAudit(
        over_granted=tuple(sorted(over)),
        held=tuple(sorted(held)),
        missing=tuple(sorted(missing)),
        roles=held_roles,
        unaudited=((ROLES_UNAUDITED,) if held_roles else ()) + (PUBLIC_UNAUDITED,),
        remedies=remedies,
        hint=_hint(user, create_user=no_create_user, columns=columns, tables=tables),
    )


def _hint(user: str, *, create_user: bool, columns: list[str], tables: list[str]) -> str:
    """Where §2.1 is, and the statements that grant what is missing."""
    hint = f"{DOCUMENT} section 2.1 has the grants for the tool account `{user}`"
    name, host = split(user)
    account = Principal(name, host).sql()
    statements = []
    if create_user:
        statements.append(f"GRANT CREATE USER ON *.* TO {account};")
    if columns:
        statements.append(f"GRANT SELECT ({', '.join(columns)}) ON {USER_TABLE} TO {account};")
    statements += [f"GRANT SELECT ON {table} TO {account};" for table in tables]
    return f"{hint}: {' '.join(statements)}" if statements else hint


def _covers_mysql(schema: str) -> bool:
    """Whether a database-level grant's name, which may be a ``LIKE`` pattern
    such as ``%`` or ``m_sql``, covers the ``mysql`` schema. ``\\_`` and
    ``\\%`` are the literal characters."""
    pattern = ""
    escaped = False
    for character in schema:
        if escaped:
            pattern += re.escape(character)
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == "%":
            pattern += ".*"
        elif character == "_":
            pattern += "."
        else:
            pattern += re.escape(character)
    return re.fullmatch(pattern, "mysql") is not None


def _needed_column(column: str) -> str | None:
    """§2.1's spelling of ``column``, or ``None`` where §2.1 does not grant it,
    either as needed or as optional. Column names compare without case."""
    for name in (*COLUMNS, *OPTIONAL_COLUMNS):
        if name.lower() == column.lower():
            return name
    return None


def _column(name: str) -> str:
    return f"SELECT ({name}) ON {USER_TABLE}"


def _table(table: str) -> str:
    return f"SELECT ON {table}"


def _yes(value: object) -> bool:
    return str(value).upper() == "YES"


def read(cursor: Cursor, user: str) -> Grants:
    """The account's own grants, from ``information_schema``, by its grantee."""
    who = (grantee(user),)
    cursor.execute(GLOBAL_PRIVILEGES, who)
    global_ = tuple((str(p), _yes(g)) for p, g in cursor.fetchall())
    cursor.execute(SCHEMA_PRIVILEGES, who)
    schema = tuple((str(s), str(p), _yes(g)) for s, p, g in cursor.fetchall())
    cursor.execute(TABLE_PRIVILEGES, who)
    table = tuple((f"{s}.{t}", str(p), _yes(g)) for s, t, p, g in cursor.fetchall())
    cursor.execute(COLUMN_PRIVILEGES, who)
    column = tuple((f"{s}.{t}", str(c), str(p), _yes(g)) for s, t, c, p, g in cursor.fetchall())
    return Grants(global_=global_, schema=schema, table=table, column=column)


def audit(cursor: Cursor) -> PrivilegeAudit:
    """Read the tool account's grants and roles, and classify them."""
    user = current_user(cursor)
    grants = read(cursor, user)
    cursor.execute(ROLES)
    roles = [str(row[0]) for row in cursor.fetchall()]
    return classify(user=user, grants=grants, roles=roles, reads=allowed_reads(cursor, roles))


#: Activating one role at a time, and going back to the role the session had.
#: A role the account can only reach through another cannot be set alone, and
#: is tried through the role that holds it: ``SET ROLE`` activates the nested
#: ones too. MariaDB has no ``SET ROLE DEFAULT`` (``1064`` on 11.8.9), so the
#: session's role is read first and set back, or ``NONE`` where it had none.
SET_ROLE = "set role {role}"
#: ``ER_INVALID_ROLE``: the role cannot be set alone, as one the account holds
#: only through another.
INVALID_ROLE = 1959
CURRENT_ROLE = "select current_role()"
NO_ROLE = "set role none"


def allowed_reads(cursor: Cursor, roles: Iterable[str] = ()) -> tuple[str, ...]:
    """The :data:`HASH_READS` the server allows: first with no role active, so a
    bare entry is a direct grant, ``PUBLIC`` or a broader grant, then with each
    of ``roles`` active in turn. Each read returns no row.

    A role that is not a default role is not active, so a read through it is
    refused until the account sets it, which it can do at any time. So each
    role is set and the reads tried again, and the session's role is set back
    afterwards. A role the account holds only through another is refused
    alone with ``1959`` and skipped: the role that holds it activates it. Any
    other failure is raised, and a failure to set the role back never hides
    it. A read's refusal is ``1142`` or ``1143``.
    """
    roles = tuple(roles)
    if not roles:
        return tuple(_reads(cursor))
    cursor.execute(CURRENT_ROLE)
    current = cursor.fetchone()[0]
    restore = NO_ROLE if current is None else SET_ROLE.format(role=_backquote(text(current)))
    try:
        cursor.execute(NO_ROLE)
        allowed = dict.fromkeys(_reads(cursor))
        for role in roles:
            try:
                cursor.execute(SET_ROLE.format(role=_backquote(role)))
            except Exception as error:  # noqa: BLE001 -- PyMySQL's, which this module does not import
                if error.args and error.args[0] == INVALID_ROLE:
                    continue
                raise
            for read in _reads(cursor):
                if read not in allowed:
                    allowed[f"{read} (through role {role})"] = None
    except BaseException:
        with suppress(Exception):
            cursor.execute(restore)
        raise
    cursor.execute(restore)
    return tuple(allowed)


def _reads(cursor: Cursor) -> list[str]:
    allowed = []
    for name, statement in HASH_READS.items():
        try:
            cursor.execute(statement)
            cursor.fetchall()
        except Exception as error:  # noqa: BLE001 -- PyMySQL's, which this module does not import
            if error.args and error.args[0] in REFUSED:
                continue
            raise
        allowed.append(name)
    return allowed


def _backquote(name: str) -> str:
    return "`" + name.replace("`", "``") + "`"
