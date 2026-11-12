"""Every privilege the surveyed accounts hold on a MariaDB server, for
`report privileges` (UC-5 §5, #1483).

The reads are §2.4 of ``02-mariadb-privileges.md``, with §2.1's grants. Each
level has its own table, read whole, once, and the shared survey
(:mod:`~sopuli.driver.mysql_family.privilege_survey`) follows the roles and
gives one row per path. ``15_report_read_probe.py`` measured the reads (RE2,
RE3) and their cost (RE5). No table read holds a stored value.

The levels, as :attr:`~sopuli.driver.grants.GrantRow.level` names them:

- ``database``: ``mysql.db``. The ``schemas`` part, with the schema as the
  owner, as stored; it may be a pattern, such as ``acme%``. Its ``*_priv``
  columns differ between releases (11.4 and later add
  ``Show_create_routine_priv``), so they are read from the table first.
- ``table``, ``column``, ``routine`` and ``proxy``: as on MySQL
  (:mod:`~sopuli.driver.mysql_family.privilege_reads`).

**Roles.** ``mysql.roles_mapping`` holds each grant of a role. A role has no
host, so it is named alone. An account's default role is the ``mysql.user``
view's ``default_role``: it is active at login, and so is every role it
holds. The server takes only a role granted to the account itself as its
default: one held through another role is refused, ``1959`` (checked on
10.11.19, 11.4.13, 11.8.9 and 12.3.3). Any other role is not active until
``SET ROLE``, unless ``PUBLIC`` reaches it.

**``PUBLIC``** is a role every account holds, always active (RR3), and so is
every role it reaches, also where an account holds that role itself. Its
grants are rows whose user is ``PUBLIC`` and whose host is empty (RE3). They
are listed once, under ``PUBLIC``, when the report asks for them.

**Not checked:**

- **the global level, without the optional view** (#1483, decision A). The
  privileges split from ``SUPER``, such as ``CONNECTION ADMIN``, set no
  column of the ``mysql.user`` view: they are only in ``mysql.global_priv``,
  beside the stored value (``08_split_privileges_probe.py``). An account
  holding only ``CONNECTION ADMIN`` would read as holding no global
  privilege, so without the view the ``system`` part is ``None``, with the
  reason. With ``sopuli.global_privileges`` it is read there, for accounts
  (decision C, :mod:`~sopuli.driver.mariadb.global_privileges`); a role's
  and ``PUBLIC``'s global level are not checked even then.
- **default roles, without §2.1's optional column grant** on the view's
  ``default_role`` (R3). Without it, the server refuses the read, ``1143``,
  and whether a role is a default role, and so active without ``SET ROLE``,
  is not checked.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from sopuli.driver.mariadb.admin import PUBLIC, db_columns, privilege
from sopuli.driver.mysql_family.accounts import Principal, text
from sopuli.driver.mysql_family.privilege_reads import read_object_tables, read_schema_rows, yes
from sopuli.driver.mysql_family.privilege_survey import Edge, Held

EDGES = "select User, Host, Role, Admin_option from mysql.roles_mapping"
DEFAULTS = "select User, Host, default_role from mysql.user where default_role <> ''"
SCHEMA_ROWS = "select User, Host, Db, {columns} from mysql.db"

GLOBAL_NOT_CHECKED = (
    "global privileges: MariaDB keeps the privileges split from SUPER, such as CONNECTION "
    "ADMIN, only in mysql.global_priv, beside the stored value, and they set no column of "
    "the mysql.user view, so the global level as the tool account reads it would be "
    "incomplete"
)
NO_DEFAULTS = (
    "whether a role is a default role, and so active without SET ROLE: the tool account "
    "has no SELECT on the mysql.user view's default_role column, the optional column grant "
    "of 02-mariadb-privileges.md §2.1"
)


def read_edges(cursor: Any) -> list[Edge]:
    """Each grant of a role, to an account or a role. A role is at host ``''``."""
    cursor.execute(EDGES)
    return [
        Edge(
            member=Principal(text(user), text(host)),
            role=Principal(text(role), ""),
            admin_option=yes(admin),
        )
        for user, host, role, admin in cursor.fetchall()
    ]


def read_defaults(cursor: Any) -> frozenset[tuple[tuple[str, str], tuple[str, str]]]:
    """Each account's default role, as ``(account key, role key)``. Refused,
    ``1143``, without the optional column grant."""
    cursor.execute(DEFAULTS)
    return frozenset(
        (Principal(text(user), text(host)).key(), Principal(text(role), "").key())
        for user, host, role in cursor.fetchall()
    )


def read_objects(cursor: Any) -> list[Held]:
    """The ``database``, ``table``, ``column``, ``routine`` and ``proxy`` levels."""
    columns = db_columns(cursor)
    query = SCHEMA_ROWS.format(columns=", ".join(columns))
    return read_schema_rows(cursor, query, columns, privilege) + read_object_tables(cursor)


def role_name(role: Principal) -> str:
    """A role as the report names it: alone, because a MariaDB role has no
    host (``05_identity_grants_probe.py``, TG7) and ``GRANT`` names it so.
    ``PUBLIC`` is a role too."""
    return role.user


def public_reach(edges: Iterable[Edge]) -> frozenset[tuple[str, str]]:
    """The key of each role ``PUBLIC`` holds, directly or through another
    role. Each is active at login for every account (RR3), whatever the
    account's default role."""
    by_member: dict[tuple[str, str], list[Principal]] = {}
    for edge in edges:
        by_member.setdefault(edge.member.key(), []).append(edge.role)
    reached: set[tuple[str, str]] = set()
    pending = list(by_member.get(PUBLIC.key(), ()))
    while pending:
        role = pending.pop()
        if role.key() not in reached:
            reached.add(role.key())
            pending += by_member.get(role.key(), ())
    return frozenset(reached)
