"""The privileges that make a MariaDB account one the tool must not manage.
Tier 0.

#1269, decided on #1267 (decision 4, option D). Nothing protects root on
MariaDB: the tool account's ``CREATE USER`` changes the password of any
account (``05_identity_grants_probe.py``, TG3). So the tool refuses a managed
account that holds, or gets through a role, any of these, as MySQL's check 9
does (:mod:`sopuli.driver.mysql.admin`):

- any global privilege but ``USAGE``;
- any privilege on the ``mysql`` schema or one of its tables, columns or
  routines;
- any ``PROXY`` grant.

Guardrail check 9 refuses such an account, and no flag waives it.

**Where each one is** (``02-mariadb-privileges.md`` §5), each read with §2.1's
grants and none holding a stored value:

- global privileges: the ``*_priv`` columns of the ``mysql.user`` view.
  ``Repl_client_priv`` is ``BINLOG MONITOR``;
- the ``mysql`` schema: ``mysql.db``, ``mysql.tables_priv``,
  ``mysql.columns_priv`` and ``mysql.procs_priv``;
- proxies: ``mysql.proxies_priv``;
- roles: ``mysql.roles_mapping``, followed to the end. A role is a row of the
  view at host ``''``, so its privileges read as an account's do.

**``PUBLIC`` counts for every account.** It is a role every account holds,
always active: what it holds, and what a role granted to it holds, any account
uses with no ``SET ROLE`` (``10_role_reads_probe.py``, RR3). So the reads start
from the account and from ``PUBLIC``, as MySQL's start from the mandatory
roles.

**What this cannot see**: the nine privileges split from ``SUPER`` that set no
column of the view, such as ``SET USER``. They are only in
``mysql.global_priv``, beside every hash, so check 9 does not read them. That is
the accepted risk of decision 4.

Each finding is ``<privilege> ON <object>``, with `` through <role>`` where a
role or ``PUBLIC`` gives it.
"""

from __future__ import annotations

from sopuli.driver.mysql_family.accounts import Principal, text
from sopuli.driver.mysql_family.grant_tables import follow, object_grants
from sopuli.driver.protocol import Cursor

#: Each ``*_priv`` column of the ``mysql.user`` view, the same 30 on 10.11.19,
#: 11.4.13, 11.8.9 and 12.3.3 (``02-mariadb-privileges.md`` §2.1). §2.1 grants
#: the tool account ``SELECT`` on exactly these, so they are named, not ``*``.
VIEW_PRIV_COLUMNS = (
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

#: A column whose privilege ``GRANT`` does not spell as the column's words.
_SPELLED = {
    "Grant": "GRANT OPTION",
    "Show_db": "SHOW DATABASES",
    "Create_tmp_table": "CREATE TEMPORARY TABLES",
    "Repl_slave": "REPLICATION SLAVE",
    # MariaDB renamed REPLICATION CLIENT; SHOW GRANTS prints the new name.
    "Repl_client": "BINLOG MONITOR",
}

#: The role every account holds, always active (RR3).
PUBLIC = Principal("PUBLIC", "")

GLOBAL_ROW = f"select {', '.join(VIEW_PRIV_COLUMNS)} from mysql.user where User = %s and Host = %s"
#: ``mysql.db``'s ``*_priv`` columns, read once per account: they differ
#: between releases, and 11.8.9 has ``Show_create_routine_priv``.
DB_COLUMNS = r"show columns from mysql.db like '%\_priv'"
#: ``'mysql' like Db``: a schema grant may name a pattern, such as ``mysq%``,
#: and a pattern that matches ``mysql`` reaches it. ``Db`` names it.
SCHEMA = "select Db, {columns} from mysql.db where User = %s and Host = %s and 'mysql' like Db"
#: A role is at host ``''``, so the next step is the role and an empty host.
ROLE_EDGES = "select Role, '' from mysql.roles_mapping where User = %s and Host = %s"


def privilege(column: str) -> str:
    """The privilege a ``*_priv`` column records, as ``GRANT`` spells it."""
    words = column.removesuffix("_priv")
    return _SPELLED.get(words, words.replace("_", " ").upper())


def db_columns(cursor: Cursor) -> tuple[str, ...]:
    """The ``*_priv`` columns this server's ``mysql.db`` has."""
    cursor.execute(DB_COLUMNS)
    return tuple(text(row[0]) for row in cursor.fetchall())


def held_by(
    cursor: Cursor, principal: Principal, schema_columns: tuple[str, ...]
) -> tuple[str, ...]:
    """What one account or role holds itself, by the rule of the module
    docstring. Roles granted to it are not followed here. ``schema_columns``
    is :func:`db_columns`."""
    args = (principal.user, principal.host)
    found: list[str] = []

    cursor.execute(GLOBAL_ROW, args)
    row = cursor.fetchone()
    if row is not None:
        found += [
            f"{privilege(column)} ON *.*"
            for column, flag in zip(VIEW_PRIV_COLUMNS, row, strict=True)
            if text(flag) == "Y"
        ]

    cursor.execute(SCHEMA.format(columns=", ".join(schema_columns)), args)
    for db, *flags in cursor.fetchall():
        # A pattern is named as the grant names it, so the DBA can revoke it.
        schema = "mysql" if text(db) == "mysql" else f"`{text(db)}`"
        found += [
            f"{privilege(column)} ON {schema}.*"
            for column, flag in zip(schema_columns, flags, strict=True)
            if text(flag) == "Y"
        ]

    found += object_grants(cursor, principal)
    return tuple(found)


def roles_of(cursor: Cursor, account: Principal) -> tuple[Principal, ...]:
    """Every role whose privileges the account has or can activate: granted
    to it, or to ``PUBLIC``, or to a role either reaches, followed to the end.
    ``PUBLIC`` itself is one of them. Sorted."""
    seen = follow(cursor, [account, PUBLIC], ROLE_EDGES)
    seen.pop(account.key(), None)
    return tuple(sorted(seen.values()))


def global_privileges(cursor: Cursor, account: Principal) -> frozenset[str]:
    """Everything of the module docstring's kind the account holds or can get,
    each naming the role it comes through.

    The host is read in lower case: MariaDB stores a host so, and its grant
    tables compare it byte for byte, so ``Example.COM`` would match no row
    (``05_identity_grants_probe.py``, ID3)."""
    account = Principal(account.user, account.key()[1])
    columns = db_columns(cursor)
    found = set(held_by(cursor, account, columns))
    for role in roles_of(cursor, account):
        # A role is at host '' (RR1), so its name alone names it.
        found |= {f"{held} through {role.user}" for held in held_by(cursor, role, columns)}
    return frozenset(found)
