"""The database-level privileges of SQL Server logins
(:mod:`sopuli.driver.mssql.db_grants`, #1555). Tier 0."""

from __future__ import annotations

from typing import Any

from sopuli.driver.grants import COLUMN, OBJECT, SCHEMA
from sopuli.driver.mssql import db_grants
from sopuli.driver.mssql.db_grants import (
    DATABASE_LEVEL,
    FIXED_ROLE_LEVEL,
    SCHEMA_LEVEL,
    SCHEMA_OWNER_LEVEL,
    Catalog,
    Database,
    Permission,
    Principal,
)
from sopuli.driver.mssql.server_grants import PUBLIC_GRANTEE

APP_SID, OWNER_SID, OTHER_SID = b"\x82\x01", b"\x82\x02", b"\x82\x03"
LOGINS = {"acme_app_user": APP_SID, "acme_owner_user": OWNER_SID, "acme_none_user": OTHER_SID}
DB = Database("acme", "ONLINE", OWNER_SID)

PUBLIC, DBO, GUEST, APP, READ, OUTER, DATAREADER = 0, 1, 2, 5, 6, 7, 16390
DB_OWNER = 16384
CATALOG = Catalog(
    principals=(
        Principal(PUBLIC, "public", "R", None),
        Principal(DBO, "dbo", "S", b"\x01"),
        Principal(GUEST, "guest", "S", b"\x00"),
        Principal(APP, "acme_app_user", "S", APP_SID),
        Principal(READ, "acme_read", "R", None),
        Principal(OUTER, "acme_outer", "R", None),
        Principal(DATAREADER, "db_datareader", "R", None, fixed=True),
        Principal(DB_OWNER, "db_owner", "R", None, fixed=True),
    ),
    memberships=((READ, APP), (OUTER, READ), (DATAREADER, APP), (DB_OWNER, DBO)),
    permissions=(
        Permission(APP, "CONNECT", 0, "DATABASE", 0, 0, "G"),
        Permission(APP, "CREATE TABLE", 0, "DATABASE", 0, 0, "W"),
        Permission(
            READ, "SELECT", 1, "OBJECT_OR_COLUMN", 90, 0, "G", "orders", "sales", "USER_TABLE"
        ),
        Permission(
            APP,
            "UPDATE",
            1,
            "OBJECT_OR_COLUMN",
            90,
            2,
            "G",
            "orders",
            "sales",
            "USER_TABLE",
            "total",
        ),
        Permission(OUTER, "EXECUTE", 3, "SCHEMA", 5, 0, "G", None, "sales"),
        Permission(APP, "REFERENCES", 6, "TYPE", 257, 0, "G"),
        Permission(
            APP, "DELETE", 1, "OBJECT_OR_COLUMN", 90, 0, "D", "orders", "sales", "USER_TABLE"
        ),
        Permission(PUBLIC, "VIEW ANY COLUMN MASTER KEY DEFINITION", 0, "DATABASE", 0, 0, "G"),
        Permission(GUEST, "CONNECT", 0, "DATABASE", 0, 0, "G"),
        Permission(GUEST, "SELECT", 1, "OBJECT_OR_COLUMN", 91, 0, "G", "items", "sales", "VIEW"),
    ),
    schemas=(("dbo", DBO), ("sales", OUTER), ("db_datareader", DATAREADER)),
)


def survey(accounts: tuple[str, ...] = ("acme_app_user",), **kw: Any) -> Any:
    kw.setdefault("public", False)
    return db_grants.survey(DB, CATALOG, LOGINS, accounts, **kw)


def rows(found: Any, grantee: str = "acme_app_user") -> set[tuple[Any, ...]]:
    return {
        (row.kind, row.privilege, row.owner, row.name, row.column, row.path, row.level)
        for row in found.rows
        if row.grantee == grantee
    }


def test_a_user_s_grants_come_with_each_path_through_nested_roles() -> None:
    found = rows(survey())

    assert (SCHEMA, "CONNECT", "acme", None, None, (), DATABASE_LEVEL) in found
    assert (OBJECT, "SELECT", "acme.sales", "orders", None, ("acme.acme_read",), None) in found
    assert (
        SCHEMA,
        "EXECUTE",
        "acme.sales",
        None,
        None,
        ("acme.acme_read", "acme.acme_outer"),
        SCHEMA_LEVEL,
    ) in found
    assert (COLUMN, "UPDATE", "acme.sales", "orders", "total", (), None) in found


def test_a_fixed_database_role_is_listed_under_its_own_name() -> None:
    found = rows(survey())

    assert (
        SCHEMA,
        "db_datareader",
        "acme",
        None,
        None,
        ("acme.db_datareader",),
        FIXED_ROLE_LEVEL,
    ) in found


def test_a_schema_a_role_owns_gives_control_but_not_a_fixed_role_s_own_schema() -> None:
    found = rows(survey())

    assert (
        SCHEMA,
        "CONTROL",
        "acme.sales",
        None,
        None,
        ("acme.acme_read", "acme.acme_outer"),
        SCHEMA_OWNER_LEVEL,
    ) in found
    assert not any(row[2] == "acme.db_datareader" for row in found)


def test_a_deny_is_not_listed_and_grant_option_is_grantable() -> None:
    found = survey()

    assert "DELETE" not in {row.privilege for row in found.rows}
    create = next(row for row in found.rows if row.privilege == "CREATE TABLE")
    assert create.grantable is True


def test_another_securable_is_named_by_its_class_and_id() -> None:
    other = next(row for row in survey().rows if row.privilege == "REFERENCES")

    assert (other.kind, other.object_type, other.owner, other.name) == (
        OBJECT,
        "TYPE",
        "acme",
        "#257",
    )


def test_the_owner_of_the_database_is_its_dbo() -> None:
    found = rows(survey(("acme_owner_user",)), "acme_owner_user")

    assert (SCHEMA, "db_owner", "acme", None, None, ("acme.db_owner",), FIXED_ROLE_LEVEL) in found
    assert (SCHEMA, "CONTROL", "acme.dbo", None, None, (), SCHEMA_OWNER_LEVEL) in found


def test_a_login_with_no_user_holds_nothing_there() -> None:
    found = survey(("acme_none_user", "acme_gone_user"))

    assert found.rows == ()
    assert found.roles == ()


def test_roles_are_named_with_their_database_and_all_active() -> None:
    roles = survey().roles

    assert [(role.role, role.default_role, role.admin_option) for role in roles] == [
        ("acme.acme_read", True, False),
        ("acme.db_datareader", True, False),
    ]


def test_public_and_guest_are_listed_under_public_when_asked_for() -> None:
    assert not rows(survey(), PUBLIC_GRANTEE)

    found = rows(survey(public=True), PUBLIC_GRANTEE)

    assert (
        SCHEMA,
        "VIEW ANY COLUMN MASTER KEY DEFINITION",
        "acme",
        None,
        None,
        (),
        DATABASE_LEVEL,
    ) in found
    assert (OBJECT, "SELECT", "acme.sales", "items", None, ("acme.guest",), None) in found


def test_guest_without_connect_gives_nothing() -> None:
    closed = Catalog(
        CATALOG.principals,
        CATALOG.memberships,
        tuple(row for row in CATALOG.permissions if row.grantee_id != GUEST or row.class_ != 0),
        CATALOG.schemas,
    )
    found = db_grants.survey(DB, closed, LOGINS, (), public=True)

    assert not any(row.path == ("acme.guest",) for row in found.rows)


def test_a_database_name_is_bracketed_in_every_read() -> None:
    name = "acme]x"
    for query in (
        db_grants.principals_query(name),
        db_grants.members_query(name),
        db_grants.schemas_query(name),
        db_grants.permissions_query(name),
    ):
        assert "[acme]]x].sys." in query


class FakeCursor:
    def __init__(self, *reads: list[tuple[Any, ...]]) -> None:
        self.reads = list(reads)
        self.sent: list[str] = []

    def execute(self, statement: str, parameters: Any = None, /) -> None:
        self.sent.append(statement)

    def fetchall(self) -> Any:
        return self.reads.pop(0)

    def fetchone(self) -> Any:
        raise AssertionError("every read here is a fetchall")


def test_read_catalog_reads_four_views_with_nothing_bound() -> None:
    cursor = FakeCursor(
        [(APP, "acme_app_user", "S ", APP_SID, 0)],
        [(READ, APP)],
        [(5, "sales", OUTER)],
        [(APP, "CONNECT", 0, "DATABASE", 0, 0, "G ", None, None, None, None)],
    )
    catalog = db_grants.read_catalog(cursor, "acme")

    assert catalog.principals == (Principal(APP, "acme_app_user", "S", APP_SID),)
    assert catalog.schemas == (("sales", OUTER),)
    assert catalog.permissions[0].state == "G"
    assert len(cursor.sent) == 4
    assert "password_hash" not in " ".join(cursor.sent)
