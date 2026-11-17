"""The database-level privileges of SQL Server logins, for `report privileges`
(UC-5 §5, #1555). Tier 0, but for the reads.

The mapping is the maintainer's, decision 4 on #1555. A login reaches a
database through its user there, the one whose ``sid`` is the login's, or as
``dbo`` in a database it owns. Each database's catalog is read with
three-part names, as the tool login connected to ``master``:

- **schemas**: the permissions on the database itself (class 0), at level
  ``database``, with the database as the owner; and on one schema (class 3),
  at level ``schema``, named ``database.schema``. A fixed database role the
  user reaches, such as ``db_owner`` or ``db_datareader``, is listed as a
  privilege of its own name, at level ``fixed database role``, as the fixed
  server roles are. A schema the user, or a role on its path, owns is listed
  as ``CONTROL`` at level ``schema owner``: the owner holds every permission
  on it without a row.
- **objects**: the permissions on one object (class 1), named
  ``database.schema`` and the object, with its ``type_desc``; and on any other
  database securable, by its ``class_desc`` and id.
- **columns**: the permissions on one column (class 1, ``minor_id`` > 0).
- **roles**: the user's database roles, named ``database.role``.

Every database role is active at login, as every server role is. A ``DENY``
is not listed, so the report shows the wider reach. ``public``'s grants in each
database, and ``guest``'s where ``guest`` may connect, are listed under
``PUBLIC`` when ``--public`` asks for them; ``guest``'s with the path
``database.guest``.

**What is not checked.** A database that is not online, and one that refuses
the tool login (``916``, without ``CONNECT ANY DATABASE``), is named in one
reason. Both grants are needed: ``CONNECT ANY DATABASE`` alone opens a
database and sees no row of another user (``07_report_reads_probe.py``, RP4).
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence, Set
from dataclasses import dataclass

from sopuli.driver.grants import COLUMN, OBJECT, SCHEMA, GrantRow, RoleGrant
from sopuli.driver.mssql.admin import GRANTED, bracketed
from sopuli.driver.mssql.server_grants import PUBLIC_GRANTEE
from sopuli.driver.protocol import Cursor

DATABASE_LEVEL = "database"
SCHEMA_LEVEL = "schema"
FIXED_ROLE_LEVEL = "fixed database role"
SCHEMA_OWNER_LEVEL = "schema owner"
OBJECT_OWNER_LEVEL = "object owner"

#: ``sys.database_permissions.class`` of the database, an object or column,
#: and a schema.
DATABASE_CLASS, OBJECT_CLASS, SCHEMA_CLASS = 0, 1, 3

#: ``sys.database_principals.principal_id`` of ``guest``.
GUEST_ID = 2
PUBLIC_ROLE = "public"
ONLINE = "ONLINE"

#: Every database, with its state and its owner's SID.
DATABASES = "SELECT name, state_desc FROM sys.databases ORDER BY name"

#: ``sys.database_principals.type`` of a Windows group user and an Entra
#: group user, through which a Windows or Entra login reaches a database
#: (#1555, Q5).
GROUP_USER_TYPES = frozenset({"G", "X"})

#: Errors a database that is ``ONLINE`` in ``sys.databases`` can still answer
#: to a read: an Availability Group secondary that takes no reads, or only
#: with read intent, or is in neither role (976, 978, 983), one in
#: single-user use (924), one dropped or taken offline since (911, 942), or
#: in recovery (922, 952). Each names that database as not checked, with
#: the server's message, and the others are still read. Not measured; by
#: Microsoft's documentation of the numbers.
UNREADABLE_DATABASE = frozenset({"911", "922", "924", "942", "952", "976", "978", "983"})


def principals_query(database: str) -> str:
    return (
        "SELECT principal_id, name, type, sid, is_fixed_role "
        f"FROM {bracketed(database)}.sys.database_principals"
    )


def members_query(database: str) -> str:
    return (
        "SELECT role_principal_id, member_principal_id "
        f"FROM {bracketed(database)}.sys.database_role_members"
    )


def schemas_query(database: str) -> str:
    return f"SELECT schema_id, name, principal_id FROM {bracketed(database)}.sys.schemas"


def owned_objects_query(database: str) -> str:
    """Every object whose owner is set apart from its schema's, by
    ``ALTER AUTHORIZATION ON OBJECT::``. Its owner holds every permission on
    it without a row in ``sys.database_permissions``."""
    db = bracketed(database)
    return (
        "SELECT s.name, o.name, o.type_desc, o.principal_id "
        f"FROM {db}.sys.all_objects AS o JOIN {db}.sys.schemas AS s "
        "ON s.schema_id = o.schema_id WHERE o.principal_id IS NOT NULL"
    )


def permissions_query(database: str) -> str:
    """Every grant in ``database``, with the object's, schema's and column's
    names where the row is on one."""
    db = bracketed(database)
    return (
        "SELECT p.grantee_principal_id, p.permission_name, p.class, p.class_desc, "
        "p.major_id, p.minor_id, p.state, o.name, s.name, o.type_desc, c.name "
        f"FROM {db}.sys.database_permissions AS p "
        # all_objects and all_columns: a grant on a system object, such as
        # public's in master, has a negative id that sys.objects leaves out.
        f"LEFT JOIN {db}.sys.all_objects AS o ON p.class = {OBJECT_CLASS} "
        "AND o.object_id = p.major_id "
        f"LEFT JOIN {db}.sys.schemas AS s ON s.schema_id = "
        f"CASE WHEN p.class = {SCHEMA_CLASS} THEN p.major_id ELSE o.schema_id END "
        f"LEFT JOIN {db}.sys.all_columns AS c ON p.class = {OBJECT_CLASS} AND p.minor_id > 0 "
        "AND c.object_id = p.major_id AND c.column_id = p.minor_id"
    )


@dataclass(frozen=True)
class Database:
    """One row of ``sys.databases``."""

    name: str
    state: str


@dataclass(frozen=True)
class Principal:
    """One row of a database's ``sys.database_principals``."""

    principal_id: int
    name: str
    type: str
    sid: bytes | None
    fixed: bool = False

    @property
    def is_role(self) -> bool:
        return self.type == "R"


@dataclass(frozen=True)
class Permission:
    """One row of a database's ``sys.database_permissions``, with names."""

    grantee_id: int
    permission: str
    class_: int
    class_desc: str
    major_id: int
    minor_id: int
    state: str
    object_name: str | None = None
    schema_name: str | None = None
    object_type: str | None = None
    column_name: str | None = None


@dataclass(frozen=True)
class Catalog:
    """What the tool login read of one database."""

    principals: tuple[Principal, ...]
    memberships: tuple[tuple[int, int], ...]
    permissions: tuple[Permission, ...]
    #: ``(schema name, owner principal id)`` per schema.
    schemas: tuple[tuple[str, int], ...] = ()
    #: ``(schema, object, type_desc, owner principal id)`` per object owned
    #: apart from its schema.
    owned_objects: tuple[tuple[str, str, str, int], ...] = ()

    @property
    def group_users(self) -> bool:
        """Whether the database has a Windows or Entra group user, through
        which a Windows or Entra login may reach it."""
        return any(p.type in GROUP_USER_TYPES for p in self.principals)

    @property
    def complete(self) -> bool:
        """Whether every principal a membership, a grant or a schema names
        has a row. A denial hides a principal's row and not the rows that
        name it, as on the server (``13_fixed_roles_probe.py``, FR5), so a
        hidden role would drop its members' paths unseen."""
        known = {p.principal_id for p in self.principals}
        named = {
            *(id_ for pair in self.memberships for id_ in pair),
            *(row.grantee_id for row in self.permissions if row.state in GRANTED),
            *(owner for _, owner in self.schemas),
            *(owner for *_, owner in self.owned_objects),
        }
        return named <= known


@dataclass(frozen=True)
class DatabaseGrants:
    """One database's rows, for the surveyed logins and ``PUBLIC``."""

    roles: tuple[RoleGrant, ...] = ()
    rows: tuple[GrantRow, ...] = ()


def read_databases(cursor: Cursor) -> list[Database]:
    cursor.execute(DATABASES)
    return [Database(str(name), str(state)) for name, state in cursor.fetchall()]


def read_catalog(
    cursor: Cursor, database: str, *, sids: Set[bytes] = frozenset(), public: bool = True
) -> Catalog:
    """One database's principals, memberships, schemas, owned objects and
    grants. A database that refuses the tool login raises ``916`` on the
    first read.

    The principals come first. Where no user has one of ``sids``, the
    surveyed logins' SIDs, and ``public`` is not asked for, nothing in the
    database can add a row, so the rest is not read: an instance with many
    databases costs one read for each that holds no surveyed login."""
    cursor.execute(principals_query(database))
    principals = tuple(
        Principal(
            int(pid), str(name), str(kind).strip(), None if sid is None else bytes(sid), bool(fixed)
        )
        for pid, name, kind, sid, fixed in cursor.fetchall()
    )
    if not public and not any(p.sid in sids for p in principals if not p.is_role):
        return Catalog(principals, (), ())
    cursor.execute(members_query(database))
    memberships = tuple((int(role), int(member)) for role, member in cursor.fetchall())
    cursor.execute(schemas_query(database))
    schemas = tuple((str(name), int(owner)) for _, name, owner in cursor.fetchall())
    cursor.execute(permissions_query(database))
    permissions = tuple(
        Permission(
            int(grantee),
            str(name),
            int(class_),
            str(desc),
            int(major),
            int(minor),
            str(state).strip(),
            *(None if value is None else str(value) for value in names),
        )
        for grantee, name, class_, desc, major, minor, state, *names in cursor.fetchall()
    )
    cursor.execute(owned_objects_query(database))
    owned = tuple(
        (str(schema), str(name), str(kind), int(owner))
        for schema, name, kind, owner in cursor.fetchall()
    )
    return Catalog(principals, memberships, permissions, schemas, owned)


def survey(
    database: Database,
    catalog: Catalog,
    logins: Mapping[str, bytes],
    accounts: Sequence[str],
    *,
    public: bool,
) -> DatabaseGrants:
    """One database's rows for ``accounts``, from what was read.

    ``logins`` is each login's SID, by name. A login reaches the database as
    the user with its SID. The database owner is the one whose SID ``dbo``
    has, which the database itself records: after a restore from another
    server it can differ from ``sys.databases.owner_sid``, so that is not
    read."""
    by_id = {p.principal_id: p for p in catalog.principals}
    by_sid = {p.sid: p for p in catalog.principals if not p.is_role and p.sid}
    parents: dict[int, list[int]] = {}
    for role_id, member_id in catalog.memberships:
        parents.setdefault(member_id, []).append(role_id)
    granted: dict[int, list[Permission]] = {}
    for row in catalog.permissions:
        if row.state in GRANTED:
            granted.setdefault(row.grantee_id, []).append(row)
    owned: dict[int, list[str]] = {}
    for schema, owner in catalog.schemas:
        holder = by_id.get(owner)
        # Each fixed role owns an empty schema of its own name, kept for
        # compatibility; listing it would say nothing.
        if holder is not None and holder.fixed and holder.name == schema:
            continue
        owned.setdefault(owner, []).append(schema)
    owned_objects: dict[int, list[tuple[str, str, str]]] = {}
    for schema, object_name, kind, owner in catalog.owned_objects:
        owned_objects.setdefault(owner, []).append((schema, object_name, kind))
    name = database.name

    def role_name(role_id: int) -> str:
        return qualified(name, by_id[role_id].name)

    rows: list[GrantRow] = []
    roles: list[RoleGrant] = []
    for account in dict.fromkeys(accounts):
        sid = logins.get(account)
        if sid is None:
            continue
        user = by_sid.get(sid)
        if user is None:
            continue
        roles.extend(
            RoleGrant(
                grantee=account,
                role=role_name(role_id),
                admin_option=False,
                default_role=True,
                authentication="NONE",
            )
            for role_id in sorted(parents.get(user.principal_id, ()))
            if role_id in by_id
        )
        for path in _paths(user.principal_id, parents, by_id):
            holder = by_id[path[-1]] if path else user
            names = tuple(role_name(role_id) for role_id in path)
            if holder.is_role and holder.fixed:
                rows.append(_database_row(account, holder.name, name, names, FIXED_ROLE_LEVEL))
            rows.extend(
                _schema_owner(account, qualified(name, schema), names)
                for schema in owned.get(holder.principal_id, ())
            )
            rows.extend(
                _object_owner(account, qualified(name, schema), object_name, kind, names)
                for schema, object_name, kind in owned_objects.get(holder.principal_id, ())
            )
            rows.extend(
                _grant(account, row, name, names) for row in granted.get(holder.principal_id, ())
            )
    if public:
        everyone = next((p for p in by_id.values() if p.is_role and p.name == PUBLIC_ROLE), None)
        if everyone is not None:
            rows.extend(
                _grant(PUBLIC_GRANTEE, row, name, ())
                for row in granted.get(everyone.principal_id, ())
            )
        if _guest_connects(granted):
            rows.extend(
                _grant(PUBLIC_GRANTEE, row, name, (qualified(name, "guest"),))
                for row in granted.get(GUEST_ID, ())
            )
    return DatabaseGrants(roles=tuple(roles), rows=tuple(rows))


def qualified(*names: str) -> str:
    """``names`` joined by dots, as the report names a database's role,
    schema or object. A name that holds a dot is bracketed, so `a.b`'s
    schema `c` and `a`'s schema `b.c` stay two owners."""
    return ".".join(bracketed(name) if "." in name else name for name in names)


def not_read_reason(names: Iterable[str], why: str) -> str:
    """One reason naming every database in ``names``."""
    return f"the databases {', '.join(names)}: {why}"


#: Why a database that refuses the tool login is not checked.
REFUSED = (
    "the tool login cannot open them; GRANT CONNECT ANY DATABASE and VIEW ANY "
    "DEFINITION to the tool login (02-mssql-privileges.md §2.2)"
)
#: Why a database that is not online is not checked.
NOT_ONLINE = "they are not online, so their catalogs cannot be read"
#: Why a database whose read names a principal it has no row for is not
#: checked: a hidden role would drop its members' paths unseen.
PARTIAL = (
    "the read names a database principal the tool login has no row for, one a DENY of "
    "VIEW DEFINITION hides or one made during the read; revoke any such DENY to the "
    "tool login, and run the report again (02-mssql-privileges.md §2.2)"
)


def unreadable_reason(database: str, message: str) -> str:
    """Why one database that answered a read with an error is not checked,
    in the server's own words."""
    return f"the database {database}: {message}"


#: Why no database is read where the server level was not.
SERVER_NOT_READ = (
    "database-level privileges in every database: the server's principals were not "
    "read completely, so no login's user can be followed (see the server-level reason)"
)


def _guest_connects(granted: Mapping[int, list[Permission]]) -> bool:
    """Whether ``guest`` may connect: it holds ``CONNECT`` on the database."""
    return any(
        row.class_ == DATABASE_CLASS and row.permission == "CONNECT"
        for row in granted.get(GUEST_ID, ())
    )


def _paths(
    start: int, parents: Mapping[int, list[int]], by_id: Mapping[int, Principal]
) -> list[tuple[int, ...]]:
    """``()``, then every chain of roles up from ``start``, no role twice."""
    found: list[tuple[int, ...]] = [()]
    stack: list[tuple[int, ...]] = [
        (role,) for role in sorted(parents.get(start, ())) if role in by_id
    ]
    while stack:
        path = stack.pop()
        found.append(path)
        stack.extend(
            (*path, role)
            for role in sorted(parents.get(path[-1], ()))
            if role not in path and role in by_id
        )
    return found


def _grant(grantee: str, row: Permission, database: str, path: tuple[str, ...]) -> GrantRow:
    grantable = row.state == "W"
    active = True if path else None
    if row.class_ == DATABASE_CLASS:
        return _database_row(grantee, row.permission, database, path, DATABASE_LEVEL, grantable)
    if row.class_ == SCHEMA_CLASS:
        return GrantRow(
            grantee=grantee,
            kind=SCHEMA,
            privilege=row.permission,
            owner=qualified(database, row.schema_name or f"#{row.major_id}"),
            name=None,
            object_type="SCHEMA",
            column=None,
            path=path,
            first_role_default=active,
            grantable=grantable,
            level=SCHEMA_LEVEL,
        )
    if row.class_ == OBJECT_CLASS:
        # An object the tool login cannot see keeps its id, and a grant on
        # one of its columns stays a column grant, never the wider object's.
        column = row.minor_id > 0
        seen = row.object_name is not None
        return GrantRow(
            grantee=grantee,
            kind=COLUMN if column else OBJECT,
            privilege=row.permission,
            owner=qualified(database, row.schema_name) if seen and row.schema_name else database,
            name=row.object_name if seen else f"#{row.major_id}",
            object_type=row.object_type if seen else row.class_desc,
            column=(row.column_name or f"#{row.minor_id}") if column else None,
            path=path,
            first_role_default=active,
            grantable=grantable,
        )
    # Another securable, such as a type or a certificate: not measured, so
    # named by its class and id, never dropped.
    return GrantRow(
        grantee=grantee,
        kind=OBJECT,
        privilege=row.permission,
        owner=database,
        name=f"#{row.major_id}",
        object_type=row.class_desc,
        column=None,
        path=path,
        first_role_default=active,
        grantable=grantable,
    )


def _database_row(
    grantee: str,
    privilege: str,
    database: str,
    path: tuple[str, ...],
    level: str,
    grantable: bool = False,
) -> GrantRow:
    return GrantRow(
        grantee=grantee,
        kind=SCHEMA,
        privilege=privilege,
        owner=database,
        name=None,
        object_type="DATABASE",
        column=None,
        path=path,
        first_role_default=True if path else None,
        grantable=grantable,
        level=level,
    )


def _schema_owner(grantee: str, schema: str, path: tuple[str, ...]) -> GrantRow:
    return GrantRow(
        grantee=grantee,
        kind=SCHEMA,
        privilege="CONTROL",
        owner=schema,
        name=None,
        object_type="SCHEMA",
        column=None,
        path=path,
        first_role_default=True if path else None,
        grantable=True,
        level=SCHEMA_OWNER_LEVEL,
    )


def _object_owner(
    grantee: str, schema: str, name: str, kind: str, path: tuple[str, ...]
) -> GrantRow:
    """``CONTROL`` on an object the user, or a role on its path, owns apart
    from its schema: the owner holds every permission on it without a row."""
    return GrantRow(
        grantee=grantee,
        kind=OBJECT,
        privilege="CONTROL",
        owner=schema,
        name=name,
        object_type=kind,
        column=None,
        path=path,
        first_role_default=True if path else None,
        grantable=True,
        level=OBJECT_OWNER_LEVEL,
    )
