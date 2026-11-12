"""Every privilege the surveyed accounts hold on a MySQL server, for
`report privileges` (UC-5 §5, #1482).

The reads are §2.4 of ``02-mysql-privileges.md``, with §2.1's grants. Each
privilege level has its own table, read whole, once, and the shared survey
(:mod:`~sopuli.driver.mysql_family.privilege_survey`) follows the roles and
gives one row per path. ``10_report_read_probe.py`` measured the reads, and
the cost: about 510 accounts and roles and 1000 tables read in well under a
second. No table read holds a hash.

The levels, as :attr:`~sopuli.driver.grants.GrantRow.level` names them:

- ``global static``: the ``*_priv`` columns of ``mysql.user``, and
  ``global dynamic``: ``mysql.global_grants``. The ``system`` part.
- ``database``: ``mysql.db``. The ``schemas`` part, with the schema as the
  owner. A schema grant may name a pattern, such as ``acme%``, and the
  owner is the pattern as stored.
- ``table``, ``routine`` and ``proxy``: ``tables_priv``, ``procs_priv`` and
  ``proxies_priv``. The ``objects`` part. ``tables_priv`` does not say
  whether the object is a table or a view, so its type is ``TABLE``. A proxy
  grant's object is the account it proxies.
- ``column``: ``columns_priv``. The ``columns`` part.

``GRANT OPTION`` is listed as a privilege of its level, as ``SHOW GRANTS``
spells it, and each privilege of the same holder and level is grantable.

**Not checked:**

- **global privileges, where ``@@partial_revokes`` is on** (#1411, M5). A
  revoke on one schema of a global privilege is kept only in
  ``User_attributes``, beside a retained password's hash, so a global
  privilege may not reach every schema. The ``system`` part is ``None``.
- **default roles, without the optional ``SELECT`` on
  ``mysql.default_roles``** (M4). Without it, the server refuses the read,
  ``1142``, and whether a role is active without ``SET ROLE`` is unknown, not
  checked. With ``@@activate_all_roles_on_login`` on, every role is active
  and the table is not read.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from sopuli.driver.grants import COLUMN, OBJECT, SCHEMA, SYSTEM
from sopuli.driver.mysql.admin import DB_PRIV_COLUMNS, PRIV_COLUMNS, read_mandatory_roles
from sopuli.driver.mysql_family.accounts import Principal, text
from sopuli.driver.mysql_family.grant_tables import set_members
from sopuli.driver.mysql_family.privilege_survey import Activation, Edge, Held

GLOBAL_STATIC = "global static"
GLOBAL_DYNAMIC = "global dynamic"
DATABASE = "database"
TABLE = "table"
COLUMN_LEVEL = "column"
ROUTINE = "routine"
PROXY = "proxy"

GRANT_OPTION = "GRANT OPTION"

SETTINGS = "select @@global.partial_revokes, @@global.activate_all_roles_on_login"
EDGES = "select FROM_USER, FROM_HOST, TO_USER, TO_HOST, WITH_ADMIN_OPTION from mysql.role_edges"
DEFAULTS_TABLE = "mysql.default_roles"
DEFAULTS = f"select USER, HOST, DEFAULT_ROLE_USER, DEFAULT_ROLE_HOST from {DEFAULTS_TABLE}"
GLOBAL_ROWS = f"select User, Host, {', '.join(PRIV_COLUMNS)} from mysql.user"
#: Every account and role, for which mandatory roles exist.
PRINCIPALS = "select User, Host from mysql.user"
DYNAMIC = "select USER, HOST, PRIV, WITH_GRANT_OPTION from mysql.global_grants"
SCHEMA_ROWS = f"select User, Host, Db, {', '.join(DB_PRIV_COLUMNS)} from mysql.db"
TABLES = "select User, Host, Db, Table_name, Table_priv from mysql.tables_priv"
COLUMNS = "select User, Host, Db, Table_name, Column_name, Column_priv from mysql.columns_priv"
ROUTINES = "select User, Host, Db, Routine_name, Routine_type, Proc_priv from mysql.procs_priv"
PROXIES = "select User, Host, Proxied_user, Proxied_host, With_grant from mysql.proxies_priv"

PARTIAL_REVOKES = (
    "global privileges: @@partial_revokes is on, and a revoke of a global privilege on one "
    "schema is kept only in mysql.user.User_attributes, beside a retained password's hash, "
    "which the tool account does not read"
)
NO_DEFAULTS = (
    "whether a role is active without SET ROLE: the tool account has no SELECT on "
    f"{DEFAULTS_TABLE}, the optional grant of 02-mysql-privileges.md §2.1"
)


def read_settings(cursor: Any) -> tuple[bool, bool]:
    """``(partial_revokes, activate_all_roles_on_login)``."""
    cursor.execute(SETTINGS)
    partial, all_active = cursor.fetchone()
    return _on(partial), _on(all_active)


def read_defaults(cursor: Any) -> frozenset[tuple[tuple[str, str], tuple[str, str]]]:
    """Each default role, as ``(account key, role key)``. Refused, ``1142``,
    without the optional grant."""
    cursor.execute(DEFAULTS)
    return frozenset(
        (
            Principal(text(user), text(host)).key(),
            Principal(text(role_user), text(role_host)).key(),
        )
        for user, host, role_user, role_host in cursor.fetchall()
    )


def read_edges(cursor: Any) -> list[Edge]:
    cursor.execute(EDGES)
    return [
        Edge(
            member=Principal(text(to_user), text(to_host)),
            role=Principal(text(from_user), text(from_host)),
            admin_option=_yes(admin),
        )
        for from_user, from_host, to_user, to_host, admin in cursor.fetchall()
    ]


def activation(
    cursor: Any,
    defaults: frozenset[tuple[tuple[str, str], tuple[str, str]]] | None,
    *,
    all_active: bool,
) -> Activation:
    """What activates a role at login. A mandatory role that names no row of
    ``mysql.user`` is left out: the server takes such a name and ignores it
    at login."""
    mandatory = read_mandatory_roles(cursor)
    if mandatory:
        cursor.execute(PRINCIPALS)
        existing = {Principal(text(user), text(host)).key() for user, host in cursor.fetchall()}
        mandatory = tuple(role for role in mandatory if role.key() in existing)
    return Activation(defaults=defaults, all_active=all_active, mandatory=mandatory)


def read_system(cursor: Any) -> list[Held]:
    """The ``global static`` and ``global dynamic`` levels."""
    held: list[Held] = []
    cursor.execute(GLOBAL_ROWS)
    for user, host, *flags in cursor.fetchall():
        holder = Principal(text(user), text(host))
        held += _level(holder, SYSTEM, GLOBAL_STATIC, _flagged(PRIV_COLUMNS, flags))
    cursor.execute(DYNAMIC)
    for user, host, privilege, grant_option in cursor.fetchall():
        held.append(
            Held(
                holder=Principal(text(user), text(host)),
                kind=SYSTEM,
                level=GLOBAL_DYNAMIC,
                privilege=text(privilege).upper(),
                grantable=_yes(grant_option),
            )
        )
    return held


def read_objects(cursor: Any) -> list[Held]:
    """The ``database``, ``table``, ``column``, ``routine`` and ``proxy`` levels."""
    held: list[Held] = []
    cursor.execute(SCHEMA_ROWS)
    for user, host, db, *flags in cursor.fetchall():
        names = _flagged(DB_PRIV_COLUMNS, flags)
        held += _level(Principal(text(user), text(host)), SCHEMA, DATABASE, names, owner=text(db))
    cursor.execute(TABLES)
    for user, host, db, table, privileges in cursor.fetchall():
        held += _level(
            Principal(text(user), text(host)),
            OBJECT,
            TABLE,
            list(set_members(privileges)),
            owner=text(db),
            name=text(table),
            object_type="TABLE",
        )
    cursor.execute(COLUMNS)
    for user, host, db, table, column, privileges in cursor.fetchall():
        held += _level(
            Principal(text(user), text(host)),
            COLUMN,
            COLUMN_LEVEL,
            list(set_members(privileges)),
            owner=text(db),
            name=text(table),
            column=text(column),
        )
    cursor.execute(ROUTINES)
    for user, host, db, routine, kind, privileges in cursor.fetchall():
        held += _level(
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
                grantable=_yes(with_grant),
            )
        )
    return held


def _level(
    holder: Principal,
    kind: str,
    level: str,
    names: list[str],
    *,
    owner: str | None = None,
    name: str | None = None,
    object_type: str | None = None,
    column: str | None = None,
) -> list[Held]:
    """One :class:`Held` per privilege of one grant, each grantable where the
    grant holds ``GRANT OPTION``."""
    grantable = GRANT_OPTION in names
    return [
        Held(
            holder=holder,
            kind=kind,
            level=level,
            privilege=privilege,
            owner=owner,
            name=name,
            object_type=object_type,
            column=column,
            grantable=grantable,
        )
        for privilege in names
    ]


def _flagged(columns: Iterable[str], flags: list[Any]) -> list[str]:
    """The privilege of each ``*_priv`` column that reads ``Y``."""
    return [PRIV_COLUMNS[column] for column, flag in zip(columns, flags, strict=True) if _yes(flag)]


def _yes(value: Any) -> bool:
    """``Y`` in an ``enum('N','Y')`` column, or ``1`` in a flag."""
    return text(value).upper() in ("Y", "1")


def _on(value: Any) -> bool:
    return text(value).upper() in ("1", "ON")
