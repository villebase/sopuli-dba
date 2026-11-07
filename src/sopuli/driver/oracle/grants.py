"""Every privilege the surveyed accounts hold, for UC-5's privilege report.

Probe 19 measured the shapes these queries take (``02-oracle-privileges.md`` §2,
*What the report commands read*):

* **One recursive query per grant view, one row per path.** A recursive ``WITH``
  over ``DBA_ROLE_PRIVS``, started from the grantee, reaches every role the
  grantee holds, however deep. Joined to the grant view, it gives each
  privilege once for each path that reaches it. A privilege granted directly
  and through two roles comes back three times, and the report merges them.
* **A column grant is in ``DBA_COL_PRIVS`` only.** ``DBA_TAB_PRIVS`` has no row
  for it.
* **``PUBLIC``'s grants are reached only from ``PUBLIC``.** They are read once,
  as the grantee ``PUBLIC``, and only when the caller asks.

``DBA_ROLE_PRIVS`` and ``DBA_ROLES`` are in the baseline grants, so a refusal
there raises. The three grant views are behind the optional
``grant_report_reads`` switch: a refusal there makes that part ``None``, with a
reason naming the grant, and the view is not asked again in this survey.

No statement reads a password or verifier column. The only bind is the grantee's
name, as the dictionary spells it.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from sopuli.driver.grants import COLUMN, OBJECT, SYSTEM, GrantRow, GrantSurvey, RoleGrant
from sopuli.driver.oracle.accounts import DictionaryUnreadableError, first_shape
from sopuli.driver.oracle.errors import INSTALL_SCRIPT
from sopuli.driver.oracle.privileges import is_yes
from sopuli.driver.protocol import Cursor

#: The grantee for the grants every account holds.
PUBLIC = "PUBLIC"

#: Between two role names in a path. ``CHR(0)``, because an Oracle identifier,
#: quoted or not, cannot contain it, so no role name can be split by it.
PATH_SEPARATOR = "\x00"

#: Every role the grantee holds, with the path to it and whether the first role
#: of that path is a default role. ``CYCLE`` stops the recursion if a role is
#: ever reached again. Oracle refuses to build a circular grant (``ORA-01934``),
#: so this is a guard, as ``NOCYCLE`` is in ``accounts.ROLES_QUERY``. The anchor
#: is cast to ``VARCHAR2(4000)`` so the path can grow past one name.
_ROLES = (
    "with roles (granted_role, path, first_default) as ("
    "select granted_role, cast(granted_role as varchar2(4000)), default_role "
    "from dba_role_privs where grantee = :grantee "
    "union all "
    "select p.granted_role, r.path || chr(0) || p.granted_role, r.first_default "
    "from dba_role_privs p join roles r on p.grantee = r.granted_role"
    ") cycle granted_role set is_cycle to 'Y' default 'N' "
)

#: System privileges: (path, first_default, privilege, admin_option).
SYS_PRIVS_QUERY = (
    _ROLES + "select cast(null as varchar2(4000)), cast(null as varchar2(3)), "
    "s.privilege, s.admin_option "
    "from dba_sys_privs s where s.grantee = :grantee "
    "union all "
    "select r.path, r.first_default, s.privilege, s.admin_option "
    "from roles r join dba_sys_privs s on s.grantee = r.granted_role "
    "where r.is_cycle = 'N'"
)

#: Object privileges: (path, first_default, privilege, owner, table_name, type,
#: grantable).
TAB_PRIVS_QUERY = (
    _ROLES + "select cast(null as varchar2(4000)), cast(null as varchar2(3)), "
    "t.privilege, t.owner, t.table_name, t.type, t.grantable "
    "from dba_tab_privs t where t.grantee = :grantee "
    "union all "
    "select r.path, r.first_default, t.privilege, t.owner, t.table_name, t.type, t.grantable "
    "from roles r join dba_tab_privs t on t.grantee = r.granted_role "
    "where r.is_cycle = 'N'"
)

#: :data:`TAB_PRIVS_QUERY` for a release with no ``DBA_TAB_PRIVS.TYPE``, with
#: ``NULL`` in its place.
TAB_PRIVS_QUERY_LEGACY = (
    _ROLES + "select cast(null as varchar2(4000)), cast(null as varchar2(3)), "
    "t.privilege, t.owner, t.table_name, cast(null as varchar2(24)), t.grantable "
    "from dba_tab_privs t where t.grantee = :grantee "
    "union all "
    "select r.path, r.first_default, t.privilege, t.owner, t.table_name, "
    "cast(null as varchar2(24)), t.grantable "
    "from roles r join dba_tab_privs t on t.grantee = r.granted_role "
    "where r.is_cycle = 'N'"
)

#: Column privileges: (path, first_default, privilege, owner, table_name,
#: column_name, grantable).
COL_PRIVS_QUERY = (
    _ROLES + "select cast(null as varchar2(4000)), cast(null as varchar2(3)), "
    "c.privilege, c.owner, c.table_name, c.column_name, c.grantable "
    "from dba_col_privs c where c.grantee = :grantee "
    "union all "
    "select r.path, r.first_default, c.privilege, c.owner, c.table_name, c.column_name, "
    "c.grantable "
    "from roles r join dba_col_privs c on c.grantee = r.granted_role "
    "where r.is_cycle = 'N'"
)

#: The roles granted directly to the grantee, each with its own authentication:
#: (granted_role, admin_option, default_role, authentication_type).
ROLE_GRANTS_QUERY = (
    "select p.granted_role, p.admin_option, p.default_role, r.authentication_type "
    "from dba_role_privs p join dba_roles r on r.role = p.granted_role "
    "where p.grantee = :grantee"
)

#: :data:`ROLE_GRANTS_QUERY` for a release with no
#: ``DBA_ROLES.AUTHENTICATION_TYPE``, reading ``PASSWORD_REQUIRED`` instead.
#: Its ``YES`` and ``NO`` are given in the newer column's words.
ROLE_GRANTS_QUERY_LEGACY = (
    "select p.granted_role, p.admin_option, p.default_role, r.password_required "
    "from dba_role_privs p join dba_roles r on r.role = p.granted_role "
    "where p.grantee = :grantee"
)

_LEGACY_AUTHENTICATION = {"YES": "PASSWORD", "NO": "NONE"}


def survey_grants(cursor: Cursor, accounts: Sequence[str], *, public: bool) -> GrantSurvey:
    """Every grant ``accounts`` hold, and ``PUBLIC``'s once when ``public``.

    ``accounts`` are names as the dictionary spells them, bound unchanged.
    Rows come back sorted, so two runs print the same report.
    """
    grantees = list(dict.fromkeys(accounts))
    if public and PUBLIC not in grantees:
        grantees.append(PUBLIC)
    elif not public:
        grantees = [grantee for grantee in grantees if grantee != PUBLIC]

    roles: list[RoleGrant] = []
    parts: dict[str, list[GrantRow] | None] = {SYSTEM: [], OBJECT: [], COLUMN: []}
    reasons: dict[str, str] = {}
    for grantee in grantees:
        roles.extend(_roles(cursor, grantee))
        for kind, shapes, view in _PARTS:
            rows = parts[kind]
            if rows is None:
                continue
            try:
                _, answered = first_shape(cursor, shapes, view, _fetch_all, {"grantee": grantee})
            except DictionaryUnreadableError as refused:
                parts[kind] = None
                reasons[kind] = (
                    f"{view} could not be read ({refused.code}): GRANT SELECT ON "
                    f"SYS.{view} to the service account, or run {INSTALL_SCRIPT} "
                    "with grant_report_reads=Y"
                )
                continue
            rows.extend(_row(grantee, kind, answered_row) for answered_row in answered)

    return GrantSurvey(
        roles=tuple(sorted(roles, key=lambda grant: (grant.grantee, grant.role))),
        system=_sorted(parts[SYSTEM]),
        objects=_sorted(parts[OBJECT]),
        columns=_sorted(parts[COLUMN]),
        unreadable=tuple(reasons[kind] for kind in (SYSTEM, OBJECT, COLUMN) if kind in reasons),
    )


#: Each part: its kind, its query shapes in the order to try them, and its view.
_PARTS: tuple[tuple[str, tuple[str, ...], str], ...] = (
    (SYSTEM, (SYS_PRIVS_QUERY,), "DBA_SYS_PRIVS"),
    (OBJECT, (TAB_PRIVS_QUERY, TAB_PRIVS_QUERY_LEGACY), "DBA_TAB_PRIVS"),
    (COLUMN, (COL_PRIVS_QUERY,), "DBA_COL_PRIVS"),
)


def _fetch_all(cursor: Cursor) -> list[Any]:
    return list(cursor.fetchall())


def _roles(cursor: Cursor, grantee: str) -> list[RoleGrant]:
    """The roles granted directly to ``grantee``. A refusal raises."""
    query, rows = first_shape(
        cursor,
        (ROLE_GRANTS_QUERY, ROLE_GRANTS_QUERY_LEGACY),
        "DBA_ROLE_PRIVS",
        _fetch_all,
        {"grantee": grantee},
    )
    legacy = query == ROLE_GRANTS_QUERY_LEGACY
    grants = []
    for role, admin, default, authentication in rows:
        word = str(authentication or "")
        if legacy:
            word = _LEGACY_AUTHENTICATION.get(word.upper(), word)
        grants.append(
            RoleGrant(
                grantee=grantee,
                role=str(role),
                admin_option=is_yes(admin),
                default_role=is_yes(default),
                authentication=word,
            )
        )
    return grants


def _row(grantee: str, kind: str, row: Any) -> GrantRow:
    """One answered row as a :class:`GrantRow`. Columns by the query's order."""
    path = tuple(str(row[0]).split(PATH_SEPARATOR)) if row[0] else ()
    first_default = is_yes(row[1]) if path else None
    if kind == SYSTEM:
        return GrantRow(
            grantee=grantee,
            kind=kind,
            privilege=str(row[2]),
            owner=None,
            name=None,
            object_type=None,
            column=None,
            path=path,
            first_role_default=first_default,
            grantable=is_yes(row[3]),
        )
    return GrantRow(
        grantee=grantee,
        kind=kind,
        privilege=str(row[2]),
        owner=str(row[3]),
        name=str(row[4]),
        object_type=str(row[5]) if kind == OBJECT and row[5] is not None else None,
        column=str(row[5]) if kind == COLUMN else None,
        path=path,
        first_role_default=first_default,
        grantable=is_yes(row[6]),
    )


def _sorted(rows: list[GrantRow] | None) -> tuple[GrantRow, ...] | None:
    if rows is None:
        return None
    return tuple(
        sorted(
            rows,
            key=lambda row: (
                row.grantee,
                row.privilege,
                row.owner or "",
                row.name or "",
                row.column or "",
                row.path,
            ),
        )
    )
