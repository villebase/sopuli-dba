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

from collections.abc import Iterable
from dataclasses import dataclass

from sopuli.driver.mysql.grants import top_level, unquote
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
TABLE_GRANTS = (
    "select Table_name, Table_priv from mysql.tables_priv "
    "where User = %s and Host = %s and Db = 'mysql'"
)
COLUMN_GRANTS = (
    "select Table_name, Column_name, Column_priv from mysql.columns_priv "
    "where User = %s and Host = %s and Db = 'mysql'"
)
#: A stored routine in the ``mysql`` schema, by its type and name.
ROUTINE_GRANTS = (
    "select Routine_type, Routine_name, Proc_priv from mysql.procs_priv "
    "where User = %s and Host = %s and Db = 'mysql'"
)
PROXIES = "select Proxied_user, Proxied_host from mysql.proxies_priv where User = %s and Host = %s"
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


@dataclass(frozen=True, order=True)
class Principal:
    """An account or a role: both are a user name and a host."""

    user: str
    host: str

    def __str__(self) -> str:
        return f"{self.user}@{self.host}"

    def key(self) -> tuple[str, str]:
        """The server's identity of it: the host without case (ID3), folding
        only ASCII letters, as ``ascii_general_ci`` does."""
        return (self.user, self.host.translate(_ASCII_LOWER))


_ASCII_LOWER = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")


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


def text(value: object) -> str:
    """PyMySQL returns some ``mysql`` table columns as bytes."""
    return value.decode("utf-8") if isinstance(value, bytes) else str(value)


def roles_of(cursor: Cursor, account: Principal) -> tuple[Principal, ...]:
    """Every role the account can activate: granted to it, or to a role it
    can activate, followed to the end, and every mandatory role. Sorted."""
    cursor.execute(MANDATORY_ROLES)
    row = cursor.fetchone()
    pending = [account, *mandatory_roles(text(row[0]) if row and row[0] else None)]
    seen: dict[tuple[str, str], Principal] = {}
    while pending:
        current = pending.pop()
        if current.key() in seen:
            continue
        seen[current.key()] = current
        cursor.execute(ROLE_EDGES, (current.user, current.host))
        pending.extend(Principal(text(user), text(host)) for user, host in cursor.fetchall())
    seen.pop(account.key(), None)
    return tuple(sorted(seen.values()))


def held_by(cursor: Cursor, principal: Principal) -> tuple[str, ...]:
    """What one account or role holds itself, by the rule of the module
    docstring. Roles granted to it are not followed here."""
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

    cursor.execute(SCHEMA, args)
    for row in cursor.fetchall():
        found += [
            f"{PRIV_COLUMNS[column]} ON mysql.*"
            for column, flag in zip(DB_PRIV_COLUMNS, row, strict=True)
            if text(flag) == "Y"
        ]

    cursor.execute(TABLE_GRANTS, args)
    for table, privileges in cursor.fetchall():
        found += [f"{priv} ON mysql.{text(table)}" for priv in _set(privileges)]

    cursor.execute(COLUMN_GRANTS, args)
    for table, column, privileges in cursor.fetchall():
        found += [f"{priv} ({text(column)}) ON mysql.{text(table)}" for priv in _set(privileges)]

    cursor.execute(ROUTINE_GRANTS, args)
    for kind, routine, privileges in cursor.fetchall():
        found += [
            f"{priv} ON {text(kind).upper()} mysql.{text(routine)}" for priv in _set(privileges)
        ]

    cursor.execute(PROXIES, args)
    empty = "''"
    found += [
        f"PROXY ON {text(user) or empty}@{text(host) or empty}" for user, host in cursor.fetchall()
    ]
    return tuple(found)


def _set(value: object) -> Iterable[str]:
    """A ``SET`` column as its members, upper-cased as ``GRANT`` spells them.
    PyMySQL returns a ``SET`` as a string or a set, depending on the column."""
    if isinstance(value, (set, frozenset)):
        members = [text(member) for member in value]
    else:
        members = text(value).split(",") if value else []
    return sorted(member.strip().upper() for member in members if member.strip())


def global_privileges(cursor: Cursor, account: Principal) -> frozenset[str]:
    """Everything of the module docstring's kind the account holds or can
    activate, each naming the role it comes through."""
    found = set(held_by(cursor, account))
    for role in roles_of(cursor, account):
        found |= {f"{held} through {role}" for held in held_by(cursor, role)}
    return frozenset(found)
