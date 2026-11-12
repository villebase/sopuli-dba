"""Every privilege the surveyed roles hold, as UC-5's `report privileges` reads it. Tier 0.

Question 4 of #1411 decided the terms. Every catalog read here is readable with
the tool account's own grants (``02-postgres-privileges.md`` §2.5, measured by
``10_report_read_probe.py``, #1443). Nothing is bound but role names and oids,
and no password column is read.

**The four parts** (:mod:`sopuli.driver.grants`):

==============  ===========================================================
part            PostgreSQL, with each row's level
==============  ===========================================================
``system``      the attributes ``SUPERUSER``, ``CREATEROLE``, ``CREATEDB``,
                ``REPLICATION`` and ``BYPASSRLS`` (level ``attribute``), and
                ``SET`` and ``ALTER SYSTEM`` on a parameter, from
                ``pg_parameter_acl`` where the server has it (level
                ``parameter``)
``schemas``     a database's privileges, from ``pg_database``, for every
                database of the cluster (level ``database``), and a schema's,
                from ``pg_namespace`` (level ``schema``)
``objects``     tables, views, sequences, functions, procedures, languages,
                types, large objects, foreign-data wrappers, foreign servers
                and tablespaces; and default privileges, from
                ``pg_default_acl`` (level ``default for <role>``: what that
                role's future objects will grant)
``columns``     column grants, from ``pg_attribute``
==============  ===========================================================

**Defaults and owners.** An object nobody has granted or revoked on has a NULL
ACL, and ``aclexplode()`` gives no row for it, though its owner holds every
privilege on it and ``PUBLIC`` holds some, such as ``EXECUTE`` on a function.
``acldefault()`` gives those, so they are read too (§2.5). A grant to ``PUBLIC``
is grantee 0, which ``pg_roles`` has no row for; it is listed as
:data:`PUBLIC`, and only when asked for.

**Through roles.** Memberships are walked from each surveyed role, with the
path. A role's privileges reach the member when every grant on the path
inherits, and are active without ``SET ROLE``. They are reachable by ``SET
ROLE`` when the member can ``SET ROLE`` to a role on the path (every grant up
to it has the ``SET`` option) and every grant after it inherits; they are then
marked as not active. A path with neither gives the member nothing, so its
privileges are not listed, though the membership is. Before 16, a grant has
neither option: it inherits when the member is ``INHERIT``, and every member
may ``SET ROLE``. The options are read through ``to_jsonb``, so one query
serves every release (invariant 3). From 16, one role can be granted to
another by several grantors, each with its own options; the grants of one
pair are merged first, each option held by any of them. An attribute is never
inherited, so a role's attributes reach a member only by ``SET ROLE`` to that
role itself.

**Predefined roles.** ``pg_read_all_data``, ``pg_write_all_data``,
``pg_maintain`` and the other built-in ``pg_*`` roles give privileges that no
ACL shows. Each one a surveyed role reaches is listed in ``system`` as a
privilege of its own name (level ``predefined role``), with its path, so a
member of ``pg_read_all_data`` never reads as holding nothing.

**One database.** A session reads the schemas and objects of the database it
is connected to. The cluster's other databases are named in ``unreadable``,
so the report says what it could not see (#1411, question 4). Their own
database privileges are in ``pg_database``, which every database shares, and
are read.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from sopuli.driver.grants import COLUMN, OBJECT, SCHEMA, SYSTEM, GrantRow, GrantSurvey, RoleGrant
from sopuli.driver.postgres.roles import FIRST_NORMAL_OID
from sopuli.driver.protocol import Cursor

#: The grantee every role holds through, as the report names it.
PUBLIC = "PUBLIC"

#: Levels, in each part's own words.
ATTRIBUTE = "attribute"
PARAMETER = "parameter"
DATABASE = "database"
SCHEMA_LEVEL = "schema"
DEFAULT_FOR = "default for "
PREDEFINED = "predefined role"

#: Whether the role ``g`` is one of the built-in ``pg_*`` roles: made by
#: ``initdb`` and named ``pg_``. The bootstrap superuser is made by ``initdb``
#: too, and is not one.
_IS_PREDEFINED = f"(g.oid < {FIRST_NORMAL_OID} and starts_with(g.rolname::text, 'pg_'))"

#: The five attributes that are privileges, with ``pg_roles``' column for each.
ATTRIBUTES = (
    ("SUPERUSER", "rolsuper"),
    ("CREATEROLE", "rolcreaterole"),
    ("CREATEDB", "rolcreatedb"),
    ("REPLICATION", "rolreplication"),
    ("BYPASSRLS", "rolbypassrls"),
)

#: One row per member and role, the grants of every grantor merged: whether
#: any inherits, any has ``SET``, and any has ``ADMIN OPTION``. ``x`` is the
#: member.
_EDGES = (
    "select m.member, m.roleid, "
    "bool_or(coalesce((to_jsonb(m) ->> 'inherit_option')::boolean, x.rolinherit)) as inherits, "
    "bool_or(coalesce((to_jsonb(m) ->> 'set_option')::boolean, true)) as sets, "
    "bool_or(m.admin_option) as admin "
    "from pg_auth_members m join pg_roles x on x.oid = m.member group by m.member, m.roleid"
)

#: Every chain of memberships from each surveyed role: the path of role
#: names; whether every grant on it inherits (``inherits``); whether every one
#: has ``SET``, so the member can ``SET ROLE`` to the last role (``sets``);
#: whether the last role's privileges are reachable by ``SET ROLE`` to a role on
#: the path and inheriting after it (``reach``); ``ADMIN OPTION`` on the first
#: grant only; and whether the last role is a built-in ``pg_*`` role. The path
#: stops at a role already on it.
WALK_QUERY = (
    f"with recursive edge as ({_EDGES}), "
    "walk(account, roleid, path, inherits, sets, reach, admin, predefined) as ("
    "select x.rolname::text, e.roleid, array[g.rolname::text], e.inherits, e.sets, e.sets, "
    f"e.admin, {_IS_PREDEFINED} "
    "from pg_roles x join edge e on e.member = x.oid "
    "join pg_roles g on g.oid = e.roleid where x.rolname = any(%s) "
    "union all "
    "select w.account, e.roleid, w.path || g.rolname::text, w.inherits and e.inherits, "
    "w.sets and e.sets, (w.sets and e.sets) or (w.reach and e.inherits), false, "
    f"{_IS_PREDEFINED} "
    "from walk w join edge e on e.member = w.roleid join pg_roles g on g.oid = e.roleid "
    "where not g.rolname::text = any(w.path)"
    ") select account, path, inherits, sets, reach, admin, predefined from walk"
)

#: The attributes of each named role.
ATTRIBUTES_QUERY = (
    "select r.rolname::text, "
    + ", ".join(f"r.{column}" for _, column in ATTRIBUTES)
    + " from pg_roles r where r.rolname = any(%s)"
)

#: Whether the server has ``pg_parameter_acl`` (15 and later): the catalog,
#: probed, not the version (invariant 3).
HAS_PARAMETER_ACL = "select to_regclass('pg_catalog.pg_parameter_acl') is not null"

#: The other databases of the cluster that a session could connect to. A
#: template is not one: nothing runs in it, and a new database copies it.
OTHER_DATABASES = (
    "select d.datname::text from pg_database d where d.datname <> current_database() "
    "and d.datallowconn and not d.datistemplate order by 1"
)

_RELKIND = (
    "case c.relkind when 'r' then 'TABLE' when 'p' then 'PARTITIONED TABLE' "
    "when 'v' then 'VIEW' when 'm' then 'MATERIALIZED VIEW' "
    "when 'f' then 'FOREIGN TABLE' when 'S' then 'SEQUENCE' end"
)
_PROKIND = (
    "case p.prokind when 'p' then 'PROCEDURE' when 'a' then 'AGGREGATE' "
    "when 'w' then 'WINDOW FUNCTION' else 'FUNCTION' end"
)
_DEFACLTYPE = (
    "case d.defaclobjtype when 'r' then 'TABLE' when 'S' then 'SEQUENCE' "
    "when 'f' then 'FUNCTION' when 'T' then 'TYPE' when 'n' then 'SCHEMA' "
    "when 'L' then 'LARGE OBJECT' end"
)


def _acl(
    kind: str,
    level: str,
    owner: str,
    name: str,
    object_type: str,
    column: str,
    acl: str,
    source: str,
    where: str | None = None,
) -> str:
    """One catalog's ACL items, each column cast to ``text`` so the branches of
    the union agree. ``where`` limits the catalog's rows; ``wanted`` is the
    surveyed roles' oids (:func:`privileges_query`). The SQL expressions are
    this module's own, never input."""
    return (
        f"select {kind}::text, {level}::text, {owner}::text, {name}::text, "
        f"{object_type}::text, {column}::text, e.grantee, e.privilege_type, e.is_grantable "
        f"from {source} cross join lateral aclexplode({acl}) e"
        + ("" if where is None else f" where {where}")
    )


#: Each catalog's ACL. A NULL ACL is the catalog's default for the object's
#: owner, from ``acldefault()``.
_ACLS = (
    _acl(
        f"'{SCHEMA}'",
        f"'{DATABASE}'",
        "d.datname",
        "null",
        "'DATABASE'",
        "null",
        "coalesce(d.datacl, acldefault('d', d.datdba))",
        "pg_database d",
    ),
    _acl(
        f"'{SCHEMA}'",
        f"'{SCHEMA_LEVEL}'",
        "n.nspname",
        "null",
        "'SCHEMA'",
        "null",
        "coalesce(n.nspacl, acldefault('n', n.nspowner))",
        "pg_namespace n",
    ),
    _acl(
        f"'{OBJECT}'",
        "null",
        "n.nspname",
        "c.relname",
        _RELKIND,
        "null",
        "coalesce(c.relacl, acldefault("
        "case when c.relkind = 'S' then 's' else 'r' end::\"char\", c.relowner))",
        "pg_class c join pg_namespace n on n.oid = c.relnamespace "
        "and c.relkind in ('r', 'p', 'v', 'm', 'f', 'S')",
    ),
    _acl(
        f"'{COLUMN}'",
        "null",
        "n.nspname",
        "c.relname",
        _RELKIND,
        "a.attname",
        "a.attacl",
        "pg_attribute a join pg_class c on c.oid = a.attrelid "
        "and a.attacl is not null and not a.attisdropped "
        "join pg_namespace n on n.oid = c.relnamespace",
    ),
    _acl(
        f"'{OBJECT}'",
        "null",
        "n.nspname",
        # The input types only, as a GRANT names the function.
        "p.proname || '(' || array_to_string(p.proargtypes::oid[]::regtype[], ', ') || ')'",
        _PROKIND,
        "null",
        "coalesce(p.proacl, acldefault('f', p.proowner))",
        "pg_proc p join pg_namespace n on n.oid = p.pronamespace",
    ),
    _acl(
        f"'{OBJECT}'",
        "null",
        "null",
        "l.lanname",
        "'LANGUAGE'",
        "null",
        "coalesce(l.lanacl, acldefault('l', l.lanowner))",
        "pg_language l",
    ),
    # A type's array type, a range's multirange type and a table's row type
    # follow the type, the range or the table, and are not listed. A domain
    # over an array type is its own type, though it shares the category.
    _acl(
        f"'{OBJECT}'",
        "null",
        "n.nspname",
        "t.typname",
        "case t.typtype when 'd' then 'DOMAIN' else 'TYPE' end",
        "null",
        "coalesce(t.typacl, acldefault('T', t.typowner))",
        "pg_type t join pg_namespace n on n.oid = t.typnamespace "
        "and not (t.typtype = 'b' and t.typcategory = 'A') and t.typtype <> 'm' and not exists "
        "(select 1 from pg_class rc where rc.oid = t.typrelid and rc.relkind <> 'c')",
    ),
    _acl(
        f"'{OBJECT}'",
        "null",
        "null",
        "o.oid",
        "'LARGE OBJECT'",
        "null",
        "coalesce(o.lomacl, acldefault('L', o.lomowner))",
        # A large object's default gives its owner alone, so one nobody has
        # granted on matters only when a surveyed role owns it. A database can
        # hold millions.
        "pg_largeobject_metadata o",
        "o.lomacl is not null or o.lomowner in (select oid from wanted)",
    ),
    _acl(
        f"'{OBJECT}'",
        "null",
        "null",
        "w.fdwname",
        "'FOREIGN DATA WRAPPER'",
        "null",
        "coalesce(w.fdwacl, acldefault('F', w.fdwowner))",
        "pg_foreign_data_wrapper w",
    ),
    _acl(
        f"'{OBJECT}'",
        "null",
        "null",
        "s.srvname",
        "'FOREIGN SERVER'",
        "null",
        "coalesce(s.srvacl, acldefault('S', s.srvowner))",
        "pg_foreign_server s",
    ),
    _acl(
        f"'{OBJECT}'",
        "null",
        "null",
        "t.spcname",
        "'TABLESPACE'",
        "null",
        "coalesce(t.spcacl, acldefault('t', t.spcowner))",
        "pg_tablespace t",
    ),
    _acl(
        f"'{OBJECT}'",
        f"'{DEFAULT_FOR}' || r.rolname",
        "n.nspname",
        "null",
        _DEFACLTYPE,
        "null",
        "d.defaclacl",
        "pg_default_acl d join pg_roles r on r.oid = d.defaclrole "
        "left join pg_namespace n on n.oid = d.defaclnamespace",
    ),
)
_PARAMETER_ACL = _acl(
    f"'{SYSTEM}'",
    f"'{PARAMETER}'",
    "null",
    "p.parname",
    "'PARAMETER'",
    "null",
    "p.paracl",
    "pg_parameter_acl p",
)


def privileges_query(*, parameters: bool) -> str:
    """Every ACL item of the named roles, and ``PUBLIC``'s when the second
    parameter is true: grantee, kind, level, owner, name, object type, column,
    privilege and whether it is grantable. ``parameters`` is whether the server
    has ``pg_parameter_acl``."""
    acls = " union all ".join((*_ACLS, _PARAMETER_ACL) if parameters else _ACLS)
    return (
        "with wanted as (select r.oid from pg_roles r where r.rolname = any(%s)), "
        "acl(kind, level, owner, name, object_type, col, grantee, privilege, grantable) "
        f"as ({acls}) "
        f"select coalesce(g.rolname::text, '{PUBLIC}'), kind, level, owner, name, "
        "object_type, col, privilege, grantable "
        "from acl left join pg_roles g on g.oid = acl.grantee "
        "where acl.grantee in (select oid from wanted) or (%s and acl.grantee = 0)"
    )


def survey_grants(cursor: Cursor, accounts: Sequence[str], *, public: bool) -> GrantSurvey:
    """Every privilege ``accounts`` hold, one row per path, and ``PUBLIC``'s once
    when ``public``. ``accounts`` are role names as ``pg_roles`` spells them.

    A role may be named ``"PUBLIC"``: only the lower-case ``public`` is
    reserved. It is surveyed like any other, but with ``public`` its rows and
    the pseudo-role's share the name :data:`PUBLIC`, and the report lists them
    together.
    """
    names = list(dict.fromkeys(accounts))
    cursor.execute(WALK_QUERY, (names,))
    walks = [_Walk(*row) for row in cursor.fetchall()]
    # Only the roles whose privileges or attributes reach the account: a path
    # with neither option gives nothing, so its role's ACLs are not read.
    reached = sorted({walk.path[-1] for walk in walks if walk.inherits or walk.reach or walk.sets})
    grantees = sorted({*names, *reached})

    cursor.execute(ATTRIBUTES_QUERY, (grantees,))
    attributes = {str(row[0]): row[1:] for row in cursor.fetchall()}
    cursor.execute(HAS_PARAMETER_ACL)
    parameters = bool(cursor.fetchone()[0])
    cursor.execute(privileges_query(parameters=parameters), (grantees, public))
    held: dict[str, list[tuple[Any, ...]]] = {}
    for row in cursor.fetchall():
        held.setdefault(str(row[0]), []).append(tuple(row[1:]))
    cursor.execute(OTHER_DATABASES)
    others = [str(row[0]) for row in cursor.fetchall()]

    rows: list[GrantRow] = []
    for name in names:
        rows.extend(_attributes(name, attributes.get(name), (), active=None))
        rows.extend(_rows(name, held.get(name, ()), (), active=None))
    for walk in walks:
        role = walk.path[-1]
        if walk.sets:
            rows.extend(_attributes(walk.account, attributes.get(role), walk.path, active=False))
        if not (walk.inherits or walk.reach):
            continue
        rows.extend(_rows(walk.account, held.get(role, ()), walk.path, active=walk.inherits))
        if walk.predefined:
            rows.append(_predefined(walk))
    if public:
        rows.extend(_rows(PUBLIC, held.get(PUBLIC, ()), (), active=None))

    unreadable: tuple[str, ...] = ()
    if others:
        unreadable = (
            "the schemas and objects of the cluster's other databases were not read ("
            + ", ".join(others)
            + "): a target reads only the database it connects to, so declare a "
            "target for each database to report on it",
        )
    return GrantSurvey(
        roles=_roles(walks),
        system=_part(rows, SYSTEM),
        objects=_part(rows, OBJECT),
        columns=_part(rows, COLUMN),
        schemas=_part(rows, SCHEMA),
        unreadable=unreadable,
    )


class _Walk:
    """One :data:`WALK_QUERY` row."""

    def __init__(
        self,
        account: Any,
        path: Any,
        inherits: Any,
        sets: Any,
        reach: Any,
        admin: Any,
        predefined: Any,
    ) -> None:
        self.account = str(account)
        self.path = tuple(str(role) for role in path)
        self.inherits = bool(inherits)
        self.sets = bool(sets)
        self.reach = bool(reach)
        self.admin = bool(admin)
        self.predefined = bool(predefined)


def _predefined(walk: _Walk) -> GrantRow:
    """A built-in ``pg_*`` role the member reaches, as a privilege of its name:
    what it gives is in no ACL."""
    return GrantRow(
        grantee=walk.account,
        kind=SYSTEM,
        privilege=walk.path[-1],
        owner=None,
        name=None,
        object_type=None,
        column=None,
        path=walk.path,
        first_role_default=walk.inherits,
        grantable=False,
        level=PREDEFINED,
    )


def _attributes(
    grantee: str, flags: Sequence[Any] | None, path: tuple[str, ...], *, active: bool | None
) -> list[GrantRow]:
    if flags is None:
        return []
    return [
        GrantRow(
            grantee=grantee,
            kind=SYSTEM,
            privilege=attribute,
            owner=None,
            name=None,
            object_type=None,
            column=None,
            path=path,
            first_role_default=active,
            grantable=False,
            level=ATTRIBUTE,
        )
        for (attribute, _), flag in zip(ATTRIBUTES, flags, strict=True)
        if flag
    ]


def _rows(
    grantee: str, items: Sequence[tuple[Any, ...]], path: tuple[str, ...], *, active: bool | None
) -> list[GrantRow]:
    return [
        GrantRow(
            grantee=grantee,
            kind=str(kind),
            privilege=str(privilege),
            owner=_text(owner),
            name=_text(name),
            object_type=_text(object_type),
            column=_text(column),
            path=path,
            first_role_default=active,
            grantable=bool(grantable),
            level=_text(level),
        )
        for kind, level, owner, name, object_type, column, privilege, grantable in items
    ]


def _roles(walks: Sequence[_Walk]) -> tuple[RoleGrant, ...]:
    """Each role granted straight to a surveyed role, with its options. The
    query has merged the grants of several grantors already."""
    return tuple(
        sorted(
            (
                RoleGrant(
                    grantee=walk.account,
                    role=walk.path[0],
                    admin_option=walk.admin,
                    default_role=walk.inherits,
                    authentication="NONE",
                    set_option=walk.sets,
                )
                for walk in walks
                if len(walk.path) == 1
            ),
            key=lambda grant: (grant.grantee, grant.role),
        )
    )


def _part(rows: Sequence[GrantRow], kind: str) -> tuple[GrantRow, ...]:
    """One part's rows, each once, in a stable order."""
    unique = dict.fromkeys(row for row in rows if row.kind == kind)
    return tuple(
        sorted(
            unique,
            key=lambda row: (
                row.grantee,
                row.level or "",
                row.privilege,
                row.owner or "",
                row.name or "",
                row.column or "",
                row.object_type or "",
                row.path,
                row.first_role_default is True,
                row.grantable,
            ),
        )
    )


def _text(value: object) -> str | None:
    return None if value is None else str(value)
