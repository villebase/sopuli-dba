"""`MssqlSession.survey_privileges` against a live server: the server level
and each database (#1555).

Tier 1. `sa` makes a database with a user in a nested database role and in
`db_datareader`, with grants on the database, a schema, a table and a column.
Two readers of its own read it: one with `ALTER ANY LOGIN`, `VIEW ANY
DEFINITION` and `CONNECT ANY DATABASE` (`02-mssql-privileges.md` §2.2), and
one without `CONNECT ANY DATABASE`, which every other database refuses. The
shared tool login is left as it is. Everything this file makes starts `w2_`
and is dropped after.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest

pytest.importorskip("pyodbc")
session_module = pytest.importorskip("sopuli.driver.mssql.session")

from sopuli.config.model import ExpandedTarget, Target, TargetMssql  # noqa: E402
from sopuli.driver.grants import COLUMN, OBJECT, SCHEMA  # noqa: E402
from sopuli.driver.mssql.db_grants import FIXED_ROLE_LEVEL, REFUSED  # noqa: E402
from sopuli.driver.protocol import Credential  # noqa: E402
from sopuli.secrets import Secret  # noqa: E402

DB = "w2_acme_rp_db"
USER = "w2_acme_rp_dbuser"
FULL, NO_CONNECT = "w2_acme_rp_dbfull", "w2_acme_rp_dbnoconn"
PASSWORD = "W2-reader-pw1"


def _sa(live_mssql: Any, *statements: str, database: str = "master") -> None:
    connection = live_mssql.connect()
    try:
        cursor = connection.cursor()
        if database != "master":
            cursor.execute(f"USE [{database}]")
        for statement in statements:
            cursor.execute(statement)
    finally:
        connection.close()


def _drop(live_mssql: Any) -> None:
    _sa(
        live_mssql,
        f"IF DB_ID(N'{DB}') IS NOT NULL BEGIN ALTER DATABASE [{DB}] SET SINGLE_USER "
        f"WITH ROLLBACK IMMEDIATE; DROP DATABASE [{DB}]; END",
        *(
            f"IF SUSER_ID(N'{name}') IS NOT NULL DROP LOGIN [{name}]"
            for name in (USER, FULL, NO_CONNECT)
        ),
    )


@pytest.fixture
def made(live_mssql: Any) -> Iterator[Any]:
    _drop(live_mssql)
    try:
        _sa(
            live_mssql,
            f"CREATE DATABASE [{DB}]",
            f"CREATE LOGIN [{USER}] WITH PASSWORD = N'W2-dbuser-pw1', CHECK_POLICY = OFF",
            f"CREATE LOGIN [{FULL}] WITH PASSWORD = N'{PASSWORD}', CHECK_POLICY = OFF",
            f"GRANT ALTER ANY LOGIN TO [{FULL}]",
            f"GRANT VIEW ANY DEFINITION TO [{FULL}]",
            f"GRANT CONNECT ANY DATABASE TO [{FULL}]",
            f"CREATE LOGIN [{NO_CONNECT}] WITH PASSWORD = N'{PASSWORD}', CHECK_POLICY = OFF",
            f"GRANT ALTER ANY LOGIN TO [{NO_CONNECT}]",
            f"GRANT VIEW ANY DEFINITION TO [{NO_CONNECT}]",
        )
        _sa(
            live_mssql,
            "CREATE SCHEMA acme",
            "CREATE TABLE acme.orders (n int, total int)",
            f"CREATE USER [{USER}] FOR LOGIN [{USER}]",
            "CREATE ROLE acme_read",
            "CREATE ROLE acme_outer",
            f"ALTER ROLE acme_read ADD MEMBER [{USER}]",
            "ALTER ROLE acme_outer ADD MEMBER acme_read",
            f"ALTER ROLE db_datareader ADD MEMBER [{USER}]",
            "GRANT SELECT ON acme.orders TO acme_read",
            f"GRANT UPDATE (total) ON acme.orders TO [{USER}]",
            "GRANT EXECUTE ON SCHEMA::acme TO acme_outer",
            f"GRANT CREATE TABLE TO [{USER}] WITH GRANT OPTION",
            database=DB,
        )
        yield live_mssql
    finally:
        _drop(live_mssql)


def _survey(live_mssql: Any, reader: str) -> Any:
    target = ExpandedTarget(
        target=Target(
            name="tier1-mssql",
            type="mssql",
            dsn=live_mssql.dsn,
            mssql=TargetMssql(trust_server_certificate=True),
        )
    )
    driver = session_module.MssqlDriver(correlation_id="tier1")
    session = driver.connect(target, Credential(reader, Secret(PASSWORD)))
    try:
        return session.survey_privileges([USER], public=False)
    finally:
        session.close()


def _rows(rows: Any) -> set[tuple[Any, ...]]:
    return {(row.kind, row.privilege, row.owner, row.name, row.column, row.path) for row in rows}


def test_with_both_grants_every_database_is_read(made: Any) -> None:
    found = _survey(made, FULL)

    assert found.unreadable == ()
    assert (OBJECT, "SELECT", f"{DB}.acme", "orders", None, (f"{DB}.acme_read",)) in _rows(
        found.objects
    )
    assert (COLUMN, "UPDATE", f"{DB}.acme", "orders", "total", ()) in _rows(found.columns)
    schemas = _rows(found.schemas)
    assert (SCHEMA, "CREATE TABLE", DB, None, None, ()) in schemas
    assert (
        SCHEMA,
        "EXECUTE",
        f"{DB}.acme",
        None,
        None,
        (f"{DB}.acme_read", f"{DB}.acme_outer"),
    ) in schemas
    fixed = [row for row in found.schemas if row.level == FIXED_ROLE_LEVEL]
    assert [(row.privilege, row.owner) for row in fixed] == [("db_datareader", DB)]
    assert {role.role for role in found.roles} == {f"{DB}.acme_read", f"{DB}.db_datareader"}


def test_without_connect_any_database_each_refusing_database_is_named(made: Any) -> None:
    found = _survey(made, NO_CONNECT)

    refused = [reason for reason in found.unreadable if reason.endswith(REFUSED)]
    assert len(refused) == 1
    assert DB in refused[0]
    # master is the session's own database, and is read.
    assert "master," not in refused[0]
    assert found.schemas is not None


def test_a_role_hidden_by_a_deny_makes_its_database_not_checked(made: Any) -> None:
    """The DENY hides the role's row and not the membership naming it, so
    the read is partial, and the database is named, never read as complete
    (#1591 review)."""
    _sa(made, f"CREATE USER [{FULL}] FOR LOGIN [{FULL}]", database=DB)
    _sa(made, f"DENY VIEW DEFINITION ON ROLE::acme_outer TO [{FULL}]", database=DB)

    found = _survey(made, FULL)

    assert any(reason.startswith(f"the database {DB}:") for reason in found.unreadable)
    assert DB not in {row.owner for row in found.schemas or ()}
    # The other databases are still read.
    assert found.schemas is not None
