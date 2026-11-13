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
  owner, as stored. With ``partial_revokes`` off it may be a pattern, such
  as ``acme%``. With it on, the server reads ``%`` and ``_`` as themselves,
  so it is one schema's name.
- ``table``, ``routine``, ``proxy`` and ``column``: ``tables_priv``,
  ``procs_priv``, ``proxies_priv`` and ``columns_priv``, which MariaDB reads
  the same way (:mod:`~sopuli.driver.mysql_family.privilege_reads`).

``GRANT OPTION`` is listed as a privilege of its level, as ``SHOW GRANTS``
spells it, and each privilege of the same holder and level is grantable.

**Not checked:**

- **global privileges, where ``@@partial_revokes`` is on, without the
  optional view** (#1411, M5). A revoke on one schema of a global privilege
  is kept only in ``User_attributes``, beside a retained password's hash, so
  a global privilege may not reach every schema. The ``system`` part is
  ``None``. With the view ``sopuli.account_state`` (#1502), the revokes are
  read from it, and each static global privilege names the schemas it is
  revoked on (:attr:`~sopuli.driver.grants.GrantRow.except_schemas`).
- **default roles, without the optional ``SELECT`` on
  ``mysql.default_roles``** (M4). Without it, the server refuses the read,
  ``1142``, and whether a role is a default role is not checked, nor,
  unless ``@@activate_all_roles_on_login`` is on, whether it is active
  without ``SET ROLE``. The table is read in either case, so the roles list
  says which are default roles.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import replace
from typing import Any

from sopuli.driver.grants import SYSTEM
from sopuli.driver.mysql.account_state import (
    UNKNOWN_PRIVILEGE,
    Restrictions,
    RevokesNotKnownError,
)
from sopuli.driver.mysql.admin import DB_PRIV_COLUMNS, PRIV_COLUMNS, read_mandatory_roles
from sopuli.driver.mysql_family.accounts import Principal, text
from sopuli.driver.mysql_family.privilege_reads import (
    level,
    read_object_tables,
    read_schema_rows,
    yes,
)
from sopuli.driver.mysql_family.privilege_survey import Activation, Edge, Held

GLOBAL_STATIC = "global static"
GLOBAL_DYNAMIC = "global dynamic"

SETTINGS = "select @@global.partial_revokes, @@global.activate_all_roles_on_login"
EDGES = "select FROM_USER, FROM_HOST, TO_USER, TO_HOST, WITH_ADMIN_OPTION from mysql.role_edges"
DEFAULTS_TABLE = "mysql.default_roles"
DEFAULTS = f"select USER, HOST, DEFAULT_ROLE_USER, DEFAULT_ROLE_HOST from {DEFAULTS_TABLE}"
GLOBAL_ROWS = f"select User, Host, {', '.join(PRIV_COLUMNS)} from mysql.user"
#: Every account and role, for which mandatory roles exist.
PRINCIPALS = "select User, Host from mysql.user"
DYNAMIC = "select USER, HOST, PRIV, WITH_GRANT_OPTION from mysql.global_grants"
SCHEMA_ROWS = f"select User, Host, Db, {', '.join(DB_PRIV_COLUMNS)} from mysql.db"

#: The start of the reason the global level is not checked, where
#: ``@@partial_revokes`` is on and the optional view gave no revokes; the
#: view's own reason follows.
PARTIAL_REVOKES = "global privileges: @@partial_revokes is on"
NO_DEFAULTS = (
    "whether a role is a default role, and so active without SET ROLE: the tool account "
    f"has no SELECT on {DEFAULTS_TABLE}, the optional grant of 02-mysql-privileges.md §2.1"
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
            admin_option=yes(admin),
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


def read_system(cursor: Any, restrictions: Restrictions | None = None) -> list[Held]:
    """The ``global static`` and ``global dynamic`` levels.

    ``restrictions`` are the partial revokes, read from the optional view
    where ``@@partial_revokes`` is on (#1502): each static privilege a holder
    has revoked on some schemas carries those schemas. A revoke applies to
    static privileges only; a dynamic one is global alone. A holder of a
    static privilege that the view does not list, or a revoke of a privilege
    the tool has no name for, raises
    :class:`~sopuli.driver.mysql.account_state.RevokesNotKnownError`: its
    revokes are not known, and reading none would claim every schema.
    """
    known = frozenset(PRIV_COLUMNS.values())
    held: list[Held] = []
    cursor.execute(GLOBAL_ROWS)
    for user, host, *flags in cursor.fetchall():
        holder = Principal(text(user), text(host))
        rows = level(holder, SYSTEM, GLOBAL_STATIC, _flagged(PRIV_COLUMNS, flags))
        revoked = restrictions.of(holder.user, holder.host) if restrictions and rows else {}
        if set(revoked) - known:
            raise RevokesNotKnownError(UNKNOWN_PRIVILEGE)
        held += [
            replace(row, except_schemas=tuple(sorted(revoked[row.privilege])))
            if row.privilege in revoked
            else row
            for row in rows
        ]
    cursor.execute(DYNAMIC)
    for user, host, privilege, grant_option in cursor.fetchall():
        held.append(
            Held(
                holder=Principal(text(user), text(host)),
                kind=SYSTEM,
                level=GLOBAL_DYNAMIC,
                privilege=text(privilege).upper(),
                grantable=yes(grant_option),
            )
        )
    return held


def read_objects(cursor: Any) -> list[Held]:
    """The ``database``, ``table``, ``column``, ``routine`` and ``proxy`` levels."""
    held = read_schema_rows(cursor, SCHEMA_ROWS, DB_PRIV_COLUMNS, PRIV_COLUMNS.__getitem__)
    return held + read_object_tables(cursor)


def _flagged(columns: Iterable[str], flags: list[Any]) -> list[str]:
    """The privilege of each ``*_priv`` column that reads ``Y``."""
    return [PRIV_COLUMNS[column] for column, flag in zip(columns, flags, strict=True) if yes(flag)]


def _on(value: Any) -> bool:
    return text(value).upper() in ("1", "ON")
