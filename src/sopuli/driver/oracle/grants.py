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

``DBA_ROLE_PRIVS`` is in the baseline grants, so a refusal there raises.
``DBA_ROLES`` is granted by the install but required by no pre-flight, so it is
read only with the ``role_lookup`` capability. The three grant views are
behind the optional
``grant_report_reads`` switch: a refusal there makes that part ``None``, with a
reason naming the grant, and the view is not asked again in this survey.

**A statement surveys up to :data:`CHUNK` grantees.** Each one is anchored on
``grantee IN (:g0, :g1, …)``, and the recursive ``WITH`` carries the grantee it
started from, so each row keeps its grantee. The survey sends four statements
for each chunk. ``PUBLIC``, when asked for, is one more grantee in the last
chunk.

No statement reads a password or verifier column. The only binds are the
grantees' names, as the dictionary spells them; no name is written into the
statement's text.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from sopuli.driver.grants import COLUMN, OBJECT, SYSTEM, GrantRow, GrantSurvey, RoleGrant
from sopuli.driver.oracle.accounts import DictionaryUnreadableError, fetch_all, first_shape
from sopuli.driver.oracle.errors import INSTALL_SCRIPT
from sopuli.driver.oracle.privileges import is_yes
from sopuli.driver.protocol import Cursor

#: The grantee for the grants every account holds.
PUBLIC = "PUBLIC"

#: Between two role names in a path. ``CHR(0)``, because an Oracle identifier,
#: quoted or not, cannot contain it, so no role name can be split by it.
PATH_SEPARATOR = "\x00"

#: The most grantees one statement binds. Oracle refuses an ``IN`` list of more
#: than 1,000 expressions (``ORA-01795``). 250, not 1,000, because the first
#: parse of a statement grows faster than its list, so a large target surveyed
#: with a cold shared pool is faster in smaller chunks. Probe 20
#: (``sql/oracle/20_grant_chunk_probe.py``) measured it; the result is in
#: ``docs/measurements.md``.
CHUNK = 250

#: Where :func:`statement` puts the bind list in each query below.
GRANTEES = "{grantees}"

#: Every role each grantee holds, with the grantee it started from, the path to
#: the role and whether the first role of that path is a default role. ``CYCLE``
#: stops the recursion if a role is ever reached again on one path. Oracle
#: refuses to build a circular grant (``ORA-01934``), so this is a guard, as
#: ``NOCYCLE`` is in ``accounts.ROLES_QUERY``. The anchor is cast to
#: ``VARCHAR2(4000)`` so the path can grow past one name.
_ROLES = (
    "with roles (grantee, granted_role, path, first_default) as ("
    "select grantee, granted_role, cast(granted_role as varchar2(4000)), default_role "
    f"from dba_role_privs where grantee in ({GRANTEES}) "
    "union all "
    "select r.grantee, p.granted_role, r.path || chr(0) || p.granted_role, r.first_default "
    "from dba_role_privs p join roles r on p.grantee = r.granted_role"
    ") cycle granted_role set is_cycle to 'Y' default 'N' "
)

#: System privileges: (grantee, path, first_default, privilege, admin_option).
SYS_PRIVS_QUERY = (
    _ROLES + "select s.grantee, cast(null as varchar2(4000)), cast(null as varchar2(3)), "
    "s.privilege, s.admin_option "
    f"from dba_sys_privs s where s.grantee in ({GRANTEES}) "
    "union all "
    "select r.grantee, r.path, r.first_default, s.privilege, s.admin_option "
    "from roles r join dba_sys_privs s on s.grantee = r.granted_role "
    "where r.is_cycle = 'N'"
)

#: Object privileges: (grantee, path, first_default, privilege, owner,
#: table_name, type, grantable).
TAB_PRIVS_QUERY = (
    _ROLES + "select t.grantee, cast(null as varchar2(4000)), cast(null as varchar2(3)), "
    "t.privilege, t.owner, t.table_name, t.type, t.grantable "
    f"from dba_tab_privs t where t.grantee in ({GRANTEES}) "
    "union all "
    "select r.grantee, r.path, r.first_default, t.privilege, t.owner, t.table_name, t.type, "
    "t.grantable "
    "from roles r join dba_tab_privs t on t.grantee = r.granted_role "
    "where r.is_cycle = 'N'"
)

#: :data:`TAB_PRIVS_QUERY` for a release with no ``DBA_TAB_PRIVS.TYPE``, with
#: ``NULL`` in its place.
TAB_PRIVS_QUERY_LEGACY = (
    _ROLES + "select t.grantee, cast(null as varchar2(4000)), cast(null as varchar2(3)), "
    "t.privilege, t.owner, t.table_name, cast(null as varchar2(24)), t.grantable "
    f"from dba_tab_privs t where t.grantee in ({GRANTEES}) "
    "union all "
    "select r.grantee, r.path, r.first_default, t.privilege, t.owner, t.table_name, "
    "cast(null as varchar2(24)), t.grantable "
    "from roles r join dba_tab_privs t on t.grantee = r.granted_role "
    "where r.is_cycle = 'N'"
)

#: Column privileges: (grantee, path, first_default, privilege, owner,
#: table_name, column_name, grantable).
COL_PRIVS_QUERY = (
    _ROLES + "select c.grantee, cast(null as varchar2(4000)), cast(null as varchar2(3)), "
    "c.privilege, c.owner, c.table_name, c.column_name, c.grantable "
    f"from dba_col_privs c where c.grantee in ({GRANTEES}) "
    "union all "
    "select r.grantee, r.path, r.first_default, c.privilege, c.owner, c.table_name, "
    "c.column_name, c.grantable "
    "from roles r join dba_col_privs c on c.grantee = r.granted_role "
    "where r.is_cycle = 'N'"
)

#: The roles granted directly to each grantee, each with its own
#: authentication: (grantee, granted_role, admin_option, default_role,
#: authentication_type).
ROLE_GRANTS_QUERY = (
    "select p.grantee, p.granted_role, p.admin_option, p.default_role, r.authentication_type "
    "from dba_role_privs p join dba_roles r on r.role = p.granted_role "
    f"where p.grantee in ({GRANTEES})"
)

#: :data:`ROLE_GRANTS_QUERY` for a release with no
#: ``DBA_ROLES.AUTHENTICATION_TYPE``, reading ``PASSWORD_REQUIRED`` instead.
#: Its ``YES`` and ``NO`` are given in the newer column's words.
ROLE_GRANTS_QUERY_LEGACY = (
    "select p.grantee, p.granted_role, p.admin_option, p.default_role, r.password_required "
    "from dba_role_privs p join dba_roles r on r.role = p.granted_role "
    f"where p.grantee in ({GRANTEES})"
)

#: The directly granted roles without ``DBA_ROLES``, for a session without the
#: ``role_lookup`` capability. ``DBA_ROLES`` is granted by the install, but no
#: pre-flight requires it (``privileges.PREDICATE_READS``), so it can be absent.
ROLE_GRANTS_QUERY_NO_ROLES = (
    "select p.grantee, p.granted_role, p.admin_option, p.default_role, "
    "cast(null as varchar2(11)) "
    f"from dba_role_privs p where p.grantee in ({GRANTEES})"
)


def statement(query: str, count: int) -> str:
    """``query`` for ``count`` grantees, bound as ``:g0`` to ``:g{count-1}``."""
    return query.replace(GRANTEES, ", ".join(f":g{index}" for index in range(count)))


def binds(grantees: Sequence[str]) -> dict[str, str]:
    """The binds for :func:`statement`'s list, in the same order."""
    return {f"g{index}": grantee for index, grantee in enumerate(grantees)}


_LEGACY_AUTHENTICATION = {"YES": "PASSWORD", "NO": "NONE"}

#: :attr:`RoleGrant.authentication` where the role's authentication was not
#: read: ``DBA_ROLES`` is not readable, or its column is empty. Not one of
#: Oracle's words, so it cannot be taken for one.
UNKNOWN_AUTHENTICATION = "UNKNOWN"

#: Why every role's authentication is :data:`UNKNOWN_AUTHENTICATION`.
_NO_ROLE_LOOKUP = (
    "DBA_ROLES could not be read, so each role's authentication is UNKNOWN: GRANT "
    f"SELECT ON SYS.DBA_ROLES to the service account, or run {INSTALL_SCRIPT}"
)


def survey_grants(
    cursor: Cursor, accounts: Sequence[str], *, public: bool, role_lookup: bool = True
) -> GrantSurvey:
    """Every grant ``accounts`` hold, and ``PUBLIC``'s once when ``public``.

    ``accounts`` are names as the dictionary spells them, bound unchanged.
    ``role_lookup`` is whether the session may read ``DBA_ROLES``. Without it the
    roles are read from ``DBA_ROLE_PRIVS`` alone, each role's authentication is
    :data:`UNKNOWN_AUTHENTICATION`, and ``unreadable`` says why.

    Rows that differ only in their grantor are merged, and the merged row is
    grantable when any of them is. Rows come back sorted, so two runs print the
    same report. The grantees are surveyed :data:`CHUNK` at a time. The first
    query shape the server accepts is kept for every later chunk, so a release
    that needs a narrower shape refuses the wider one once.
    """
    grantees = list(dict.fromkeys(accounts))
    if public and PUBLIC not in grantees:
        grantees.append(PUBLIC)
    elif not public:
        grantees = [grantee for grantee in grantees if grantee != PUBLIC]

    role_shapes = (
        (ROLE_GRANTS_QUERY, ROLE_GRANTS_QUERY_LEGACY)
        if role_lookup
        else (ROLE_GRANTS_QUERY_NO_ROLES,)
    )
    shapes = {kind: part_shapes for kind, part_shapes, _ in _PARTS}
    roles: list[RoleGrant] = []
    parts: dict[str, list[GrantRow] | None] = {SYSTEM: [], OBJECT: [], COLUMN: []}
    reasons: dict[str, str] = {}
    for start in range(0, len(grantees), CHUNK):
        chunk = grantees[start : start + CHUNK]
        values = binds(chunk)
        query, role_rows = _first(cursor, role_shapes, len(chunk), "DBA_ROLE_PRIVS", values)
        role_shapes = (query,)
        roles.extend(_roles(role_rows, legacy=query == ROLE_GRANTS_QUERY_LEGACY))
        for kind, _, view in _PARTS:
            rows = parts[kind]
            if rows is None:
                continue
            try:
                query, answered = _first(cursor, shapes[kind], len(chunk), view, values)
            except DictionaryUnreadableError as refused:
                parts[kind] = None
                reasons[kind] = (
                    f"{view} could not be read ({refused.code}): GRANT SELECT ON "
                    f"SYS.{view} to the service account, or run {INSTALL_SCRIPT} "
                    "with grant_report_reads=Y"
                )
                continue
            shapes[kind] = (query,)
            rows.extend(_row(kind, answered_row) for answered_row in answered)

    unreadable = [reasons[kind] for kind in (SYSTEM, OBJECT, COLUMN) if kind in reasons]
    if not role_lookup:
        unreadable.append(_NO_ROLE_LOOKUP)
    return GrantSurvey(
        roles=tuple(sorted(roles, key=lambda grant: (grant.grantee, grant.role))),
        system=_merged(parts[SYSTEM]),
        objects=_merged(parts[OBJECT]),
        columns=_merged(parts[COLUMN]),
        unreadable=tuple(unreadable),
    )


#: Each part: its kind, its query shapes in the order to try them, and its view.
_PARTS: tuple[tuple[str, tuple[str, ...], str], ...] = (
    (SYSTEM, (SYS_PRIVS_QUERY,), "DBA_SYS_PRIVS"),
    (OBJECT, (TAB_PRIVS_QUERY, TAB_PRIVS_QUERY_LEGACY), "DBA_TAB_PRIVS"),
    (COLUMN, (COL_PRIVS_QUERY,), "DBA_COL_PRIVS"),
)


def _first(
    cursor: Cursor, queries: tuple[str, ...], count: int, view: str, values: dict[str, str]
) -> tuple[str, Any]:
    """:func:`first_shape` over ``queries`` for ``count`` grantees.

    Gives back the query, not its statement, so the caller can keep the shape
    for a chunk of another size.
    """
    statements = tuple(statement(query, count) for query in queries)
    sent, rows = first_shape(cursor, statements, view, fetch_all, values)
    return queries[statements.index(sent)], rows


def _roles(rows: Any, *, legacy: bool) -> list[RoleGrant]:
    """The roles granted directly to each grantee, from the answered rows."""
    grants = []
    for grantee, role, admin, default, authentication in rows:
        word = str(authentication) if authentication else UNKNOWN_AUTHENTICATION
        if legacy:
            word = _LEGACY_AUTHENTICATION.get(word.upper(), word)
        grants.append(
            RoleGrant(
                grantee=str(grantee),
                role=str(role),
                admin_option=is_yes(admin),
                default_role=is_yes(default),
                authentication=word,
            )
        )
    return grants


def _row(kind: str, answered: Any) -> GrantRow:
    """One answered row as a :class:`GrantRow`. Columns by the query's order,
    the grantee first."""
    grantee, row = str(answered[0]), answered[1:]
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


def _merged(rows: list[GrantRow] | None) -> tuple[GrantRow, ...] | None:
    """``rows`` with one row per path, sorted.

    ``DBA_TAB_PRIVS`` and ``DBA_COL_PRIVS`` hold one row per grantor, so one
    privilege granted by two owners, on one path, comes back twice. The merged
    row is grantable when any of them is.
    """
    if rows is None:
        return None
    merged: dict[tuple[Any, ...], GrantRow] = {}
    for row in rows:
        key = (
            row.grantee,
            row.privilege,
            row.owner or "",
            row.name or "",
            row.column or "",
            row.path,
        )
        seen = merged.get(key)
        if seen is None or (row.grantable and not seen.grantable):
            merged[key] = row
    return tuple(merged[key] for key in sorted(merged))
