"""The grant tables MySQL and MariaDB read the same way, for `report
privileges` (UC-5 §5, #1482, #1483). Tier 0.

``tables_priv``, ``columns_priv``, ``procs_priv`` and ``proxies_priv`` have
the same columns on both products, each read whole, once, with §2.1's grants
of ``02-mysql-privileges.md`` and ``02-mariadb-privileges.md``. None holds a
stored value. Each product's own module reads its global and schema levels,
which differ, and hands every :class:`Held` to
:func:`~sopuli.driver.mysql_family.privilege_survey.survey`.

The levels, as :attr:`~sopuli.driver.grants.GrantRow.level` names them:

- ``table``, ``routine`` and ``proxy``: the ``objects`` part.
  ``tables_priv`` does not say whether the object is a table or a view, so
  its type is ``TABLE``. A proxy grant's object is the account it proxies.
- ``column``: the ``columns`` part.

``GRANT OPTION`` is listed as a privilege of its level, as ``SHOW GRANTS``
spells it, and each privilege of the same holder and level is grantable. A
column grant's ``GRANT OPTION`` is kept on its table in ``tables_priv``, so
it makes the table's column privileges grantable too. Measured on MySQL
8.4.13 (#1482), and by hand on MariaDB 10.11.19, 11.4.13, 11.8.9 and 12.3.3
(#1483): ``GRANT UPDATE (total) ... WITH GRANT OPTION`` writes ``Grant`` in
``tables_priv`` and ``Update`` alone in ``columns_priv``.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Any

from sopuli.driver.grants import COLUMN, OBJECT, SCHEMA
from sopuli.driver.mysql_family.accounts import Principal, text
from sopuli.driver.mysql_family.grant_tables import set_members
from sopuli.driver.mysql_family.privilege_survey import Held

DATABASE = "database"
TABLE = "table"
COLUMN_LEVEL = "column"
ROUTINE = "routine"
PROXY = "proxy"

GRANT_OPTION = "GRANT OPTION"

TABLES = "select User, Host, Db, Table_name, Table_priv from mysql.tables_priv"
COLUMNS = "select User, Host, Db, Table_name, Column_name, Column_priv from mysql.columns_priv"
ROUTINES = "select User, Host, Db, Routine_name, Routine_type, Proc_priv from mysql.procs_priv"
PROXIES = "select User, Host, Proxied_user, Proxied_host, With_grant from mysql.proxies_priv"


def read_schema_rows(
    cursor: Any, query: str, columns: Sequence[str], named: Callable[[str], str]
) -> list[Held]:
    """The ``database`` level: ``query`` reads ``User, Host, Db`` and then
    ``columns``, the ``*_priv`` columns of ``mysql.db``, whose privileges
    ``named`` spells. The owner is the schema as stored, which may be a
    pattern."""
    held: list[Held] = []
    cursor.execute(query)
    for user, host, db, *flags in cursor.fetchall():
        pairs = zip(columns, flags, strict=True)
        names = [named(column) for column, flag in pairs if yes(flag)]
        held += level(Principal(text(user), text(host)), SCHEMA, DATABASE, names, owner=text(db))
    return held


def read_object_tables(cursor: Any) -> list[Held]:
    """The ``table``, ``column``, ``routine`` and ``proxy`` levels."""
    held: list[Held] = []
    cursor.execute(TABLES)
    grant_option: set[tuple[tuple[str, str], str, str]] = set()
    for user, host, db, table, privileges in cursor.fetchall():
        holder = Principal(text(user), text(host))
        names = list(set_members(privileges))
        if GRANT_OPTION in names:
            grant_option.add((holder.key(), text(db), text(table)))
        held += level(
            holder, OBJECT, TABLE, names, owner=text(db), name=text(table), object_type="TABLE"
        )
    cursor.execute(COLUMNS)
    for user, host, db, table, column, privileges in cursor.fetchall():
        holder = Principal(text(user), text(host))
        held += level(
            holder,
            COLUMN,
            COLUMN_LEVEL,
            list(set_members(privileges)),
            owner=text(db),
            name=text(table),
            column=text(column),
            grantable=(holder.key(), text(db), text(table)) in grant_option,
        )
    cursor.execute(ROUTINES)
    for user, host, db, routine, kind, privileges in cursor.fetchall():
        held += level(
            Principal(text(user), text(host)),
            OBJECT,
            ROUTINE,
            list(set_members(privileges)),
            owner=text(db),
            name=text(routine),
            object_type=text(kind).upper(),
        )
    cursor.execute(PROXIES)
    for user, host, proxied_user, proxied_host, with_grant in cursor.fetchall():
        held.append(
            Held(
                holder=Principal(text(user), text(host)),
                kind=OBJECT,
                level=PROXY,
                privilege="PROXY",
                name=str(Principal(text(proxied_user), text(proxied_host))),
                object_type="ACCOUNT",
                grantable=yes(with_grant),
            )
        )
    return held


def level(
    holder: Principal,
    kind: str,
    level_name: str,
    names: list[str],
    *,
    owner: str | None = None,
    name: str | None = None,
    object_type: str | None = None,
    column: str | None = None,
    grantable: bool = False,
) -> list[Held]:
    """One :class:`Held` per privilege of one grant, each grantable where the
    grant holds ``GRANT OPTION``, or where ``grantable`` says so."""
    grantable = grantable or GRANT_OPTION in names
    return [
        Held(
            holder=holder,
            kind=kind,
            level=level_name,
            privilege=privilege,
            owner=owner,
            name=name,
            object_type=object_type,
            column=column,
            grantable=grantable,
        )
        for privilege in names
    ]


def yes(value: Any) -> bool:
    """``Y`` in an ``enum('N','Y')`` column, or ``1`` in a flag."""
    return text(value).upper() in ("Y", "1")
