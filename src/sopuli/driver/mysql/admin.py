"""The privileges that make a MySQL account one the tool must not manage. Tier 0.

#1222, decided on 2026-11-02 under #1202's decision 7. The tool account's
``CREATE USER`` changes the password of any account that does not hold
``SYSTEM_USER`` (``05_identity_grants_probe.py``, TG3). So the tool refuses a
managed account that holds, or can activate, any of these:

- any privilege ``ON *.*`` but ``USAGE``, static or dynamic;
- any privilege on the ``mysql`` schema or one of its tables or columns;
- any ``PROXY`` grant.

Guardrail check 9 refuses such an account, and no flag waives it.

**Where each one is.** ``SHOW GRANTS FOR`` another account needs ``SELECT``
on all of ``mysql.user``, hashes included, so the tool reads the grant tables
instead, each with ``SELECT`` on only what it needs
(``06_rollover_privileges_probe.py``, PV1 to PV7):

- static global privileges: the ``*_priv`` columns of ``mysql.user``;
- dynamic global privileges: ``mysql.global_grants``;
- the ``mysql`` schema: ``mysql.db``, ``mysql.tables_priv``,
  ``mysql.columns_priv``;
- proxies: ``mysql.proxies_priv``;
- roles: ``mysql.role_edges``, and ``@@global.mandatory_roles``, which holds a
  mandatory role with no row in ``role_edges`` (PV6).

**Roles count whether they are active or not.** The account can ``SET ROLE``
to any role granted to it, and to a role granted to that role, so the tool
follows ``role_edges`` to the end. That is the rule
:mod:`~sopuli.driver.mysql.scope` applies to the tool account itself. A
default role is a granted role, so ``mysql.default_roles`` adds nothing.

Each finding is ``<privilege> ON <object>``, with `` through <role>`` where a
role gives it.
"""

from __future__ import annotations

from sopuli.driver.mysql.grants import top_level, unquote
from sopuli.driver.mysql_family.accounts import Principal, text
from sopuli.driver.mysql_family.grant_tables import follow, object_grants
from sopuli.driver.protocol import Cursor

#: Each ``*_priv`` column of ``mysql.user`` and ``mysql.db``, and the
#: privilege it records, as ``GRANT`` spells it. The 31 columns of
#: ``mysql.user`` on 8.0.46, 8.4.13 and 9.7.4 (PV1); ``mysql.db`` has the ones
#: that apply to a schema.
PRIV_COLUMNS = {
    "Select_priv": "SELECT",
    "Insert_priv": "INSERT",
    "Update_priv": "UPDATE",
    "Delete_priv": "DELETE",
    "Create_priv": "CREATE",
    "Drop_priv": "DROP",
    "Reload_priv": "RELOAD",
    "Shutdown_priv": "SHUTDOWN",
    "Process_priv": "PROCESS",
    "File_priv": "FILE",
    "Grant_priv": "GRANT OPTION",
    "References_priv": "REFERENCES",
    "Index_priv": "INDEX",
    "Alter_priv": "ALTER",
    "Show_db_priv": "SHOW DATABASES",
    "Super_priv": "SUPER",
    "Create_tmp_table_priv": "CREATE TEMPORARY TABLES",
    "Lock_tables_priv": "LOCK TABLES",
    "Execute_priv": "EXECUTE",
    "Repl_slave_priv": "REPLICATION SLAVE",
    "Repl_client_priv": "REPLICATION CLIENT",
    "Create_view_priv": "CREATE VIEW",
    "Show_view_priv": "SHOW VIEW",
    "Create_routine_priv": "CREATE ROUTINE",
    "Alter_routine_priv": "ALTER ROUTINE",
    "Create_user_priv": "CREATE USER",
    "Event_priv": "EVENT",
    "Trigger_priv": "TRIGGER",
    "Create_tablespace_priv": "CREATE TABLESPACE",
    "Create_role_priv": "CREATE ROLE",
    "Drop_role_priv": "DROP ROLE",
}

#: The ``*_priv`` columns of ``mysql.db``: every one of
#: :data:`PRIV_COLUMNS` that applies to a schema.
DB_PRIV_COLUMNS = (
    "Select_priv",
    "Insert_priv",
    "Update_priv",
    "Delete_priv",
    "Create_priv",
    "Drop_priv",
    "Grant_priv",
    "References_priv",
    "Index_priv",
    "Alter_priv",
    "Create_tmp_table_priv",
    "Lock_tables_priv",
    "Create_view_priv",
    "Show_view_priv",
    "Create_routine_priv",
    "Alter_routine_priv",
    "Execute_priv",
    "Event_priv",
    "Trigger_priv",
)

GLOBAL_ROW = f"select {', '.join(PRIV_COLUMNS)} from mysql.user where User = %s and Host = %s"
DYNAMIC = "select PRIV from mysql.global_grants where USER = %s and HOST = %s"
#: ``'mysql' like Db``: a schema grant may name a pattern, such as ``mysq%``,
#: and a pattern that matches ``mysql`` reaches it.
SCHEMA = (
    f"select {', '.join(DB_PRIV_COLUMNS)} from mysql.db "
    "where User = %s and Host = %s and 'mysql' like Db"
)
#: With ``partial_revokes`` on, the server reads ``%`` and ``_`` in a schema
#: grant as themselves, so only a grant on ``mysql`` itself reaches it.
SCHEMA_LITERAL = (
    f"select {', '.join(DB_PRIV_COLUMNS)} from mysql.db "
    "where User = %s and Host = %s and Db = 'mysql'"
)
PARTIAL_REVOKES = "select @@global.partial_revokes"
ROLE_EDGES = "select FROM_USER, FROM_HOST from mysql.role_edges where TO_USER = %s and TO_HOST = %s"
MANDATORY_ROLES = "select @@global.mandatory_roles"

#: Every table the tool account reads, for §2.1's grant and the audit.
TABLES_READ = (
    "mysql.global_grants",
    "mysql.db",
    "mysql.tables_priv",
    "mysql.columns_priv",
    "mysql.procs_priv",
    "mysql.proxies_priv",
    "mysql.role_edges",
)


def mandatory_roles(setting: str | None) -> tuple[Principal, ...]:
    """``@@global.mandatory_roles`` as roles. The server accepts ``r``,
    ``r@h``, ``'r'@'h'`` and ```r```@```h```, comma-separated; a role named
    without a host is at ``%``. Commas and ``@`` inside a quoted name are part
    of the name, so the split is the one :mod:`~sopuli.driver.mysql.grants`
    uses on ``SHOW GRANTS``."""
    found = []
    for item in top_level(setting or "", ","):
        parts = top_level(item, "@")
        name = unquote(parts[0]) if parts else ""
        host = unquote(parts[1]) if len(parts) > 1 else "%"
        if name:
            found.append(Principal(name, host))
    return tuple(found)


def roles_of(cursor: Cursor, account: Principal) -> tuple[Principal, ...]:
    """Every role the account can activate: granted to it, or to a role it
    can activate, followed to the end, and every mandatory role. Sorted."""
    seen = follow(cursor, [account, *read_mandatory_roles(cursor)], ROLE_EDGES)
    seen.pop(account.key(), None)
    return tuple(sorted(seen.values()))


def read_mandatory_roles(cursor: Cursor) -> tuple[Principal, ...]:
    """The server's ``@@global.mandatory_roles``, as roles."""
    cursor.execute(MANDATORY_ROLES)
    row = cursor.fetchone()
    return mandatory_roles(text(row[0]) if row and row[0] else None)


def held_by(cursor: Cursor, principal: Principal, *, literal_db: bool = False) -> tuple[str, ...]:
    """What one account or role holds itself, by the rule of the module
    docstring. Roles granted to it are not followed here. ``literal_db``: the
    server has ``partial_revokes`` on, so a schema grant names no pattern."""
    args = (principal.user, principal.host)
    found: list[str] = []

    cursor.execute(GLOBAL_ROW, args)
    row = cursor.fetchone()
    if row is not None:
        found += [
            f"{name} ON *.*"
            for name, flag in zip(PRIV_COLUMNS.values(), row, strict=True)
            if text(flag) == "Y"
        ]

    cursor.execute(DYNAMIC, args)
    found += [f"{text(priv)} ON *.*" for (priv,) in cursor.fetchall()]

    cursor.execute(SCHEMA_LITERAL if literal_db else SCHEMA, args)
    for row in cursor.fetchall():
        found += [
            f"{PRIV_COLUMNS[column]} ON mysql.*"
            for column, flag in zip(DB_PRIV_COLUMNS, row, strict=True)
            if text(flag) == "Y"
        ]

    found += object_grants(cursor, principal)
    return tuple(found)


def global_privileges(cursor: Cursor, account: Principal) -> frozenset[str]:
    """Everything of the module docstring's kind the account holds or can
    activate, each naming the role it comes through."""
    cursor.execute(PARTIAL_REVOKES)
    row = cursor.fetchone()
    literal_db = bool(row and row[0] and int(row[0]))
    found = set(held_by(cursor, account, literal_db=literal_db))
    for role in roles_of(cursor, account):
        found |= {f"{held} through {role}" for held in held_by(cursor, role, literal_db=literal_db)}
    return frozenset(found)
