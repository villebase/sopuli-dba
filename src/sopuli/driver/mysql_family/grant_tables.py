"""Reading the grant tables MySQL and MariaDB share. Tier 0.

Guardrail 9 reads the ``mysql`` schema's grant tables on both products, and
both return their columns in the same shapes. Nothing here imports PyMySQL.
"""

from __future__ import annotations

from collections.abc import Iterable

from sopuli.driver.mysql_family.accounts import Principal
from sopuli.driver.protocol import Cursor

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


def object_grants(cursor: Cursor, principal: Principal) -> list[str]:
    """What one account or role holds itself on a table, column or routine of
    the ``mysql`` schema, and its ``PROXY`` grants, each as
    ``<privilege> ON <object>``."""
    args = (principal.user, principal.host)
    found: list[str] = []

    cursor.execute(TABLE_GRANTS, args)
    for table, privileges in cursor.fetchall():
        found += [f"{priv} ON mysql.{text(table)}" for priv in set_members(privileges)]

    cursor.execute(COLUMN_GRANTS, args)
    for table, column, privileges in cursor.fetchall():
        found += [
            f"{priv} ({text(column)}) ON mysql.{text(table)}" for priv in set_members(privileges)
        ]

    cursor.execute(ROUTINE_GRANTS, args)
    for kind, routine, privileges in cursor.fetchall():
        found += [
            f"{priv} ON {text(kind).upper()} mysql.{text(routine)}"
            for priv in set_members(privileges)
        ]

    cursor.execute(PROXIES, args)
    empty = "''"
    found += [
        f"PROXY ON {text(user) or empty}@{text(host) or empty}" for user, host in cursor.fetchall()
    ]
    return found


def text(value: object) -> str:
    """PyMySQL returns some ``mysql`` table columns as bytes."""
    return value.decode("utf-8") if isinstance(value, bytes) else str(value)


def follow(
    cursor: Cursor, start: Iterable[Principal], edges: str
) -> dict[tuple[str, str], Principal]:
    """Every principal ``edges`` reaches from ``start``, followed to the end,
    ``start`` included, by :meth:`Principal.key`. ``edges`` takes a user and a
    host and returns the user and host of each principal one step on."""
    pending = list(start)
    seen: dict[tuple[str, str], Principal] = {}
    while pending:
        current = pending.pop()
        if current.key() in seen:
            continue
        seen[current.key()] = current
        cursor.execute(edges, (current.user, current.host))
        pending.extend(Principal(text(user), text(host)) for user, host in cursor.fetchall())
    return seen


def set_members(value: object) -> Iterable[str]:
    """A ``SET`` column as its members, upper-cased as ``GRANT`` spells them.
    PyMySQL returns a ``SET`` as a string or a set, depending on the column."""
    if isinstance(value, (set, frozenset)):
        members = [text(member) for member in value]
    else:
        members = text(value).split(",") if value else []
    names = (member.strip().upper() for member in members if member.strip())
    # The SET member is `Grant`; GRANT and REVOKE spell it GRANT OPTION.
    return sorted("GRANT OPTION" if name == "GRANT" else name for name in names)
