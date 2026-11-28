"""`run_statement` on SQL Server, against the tier-1 server (UC-3, #1731).

The run-as login is a login of its own, with a user in a database of this
module's own, read and written by three-part names from ``master``, as UC-3's
session is (#1728, Q3). The module drops what it made.
"""

from __future__ import annotations

import threading
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any

import pytest

pytest.importorskip("pyodbc")

from sopuli.config.model import ExpandedTarget, Target, TargetMssql  # noqa: E402
from sopuli.driver.protocol import Credential, DriverError, Timeouts  # noqa: E402
from sopuli.secrets import Secret  # noqa: E402
from sopuli.sql.guard import RowGuard  # noqa: E402
from sopuli.sql.statement import Dialect, classify  # noqa: E402

RUN_AS, PASSWORD = "w1_uc3_runas", "W1-uc3-pw-1"
DATABASE = "w1_uc3"
T = f"{DATABASE}.dbo.t"


def _sql(text: str) -> Any:
    return classify(text, dialect=Dialect.MSSQL)


@pytest.fixture
def stack(live_mssql: Any) -> Iterator[Any]:
    """The database, its tables and the run-as login, made as ``sa`` and
    dropped after."""
    connection = live_mssql.connect()
    cursor = connection.cursor()

    def drop() -> None:
        cursor.execute(
            f"IF DB_ID(N'{DATABASE}') IS NOT NULL BEGIN "
            f"ALTER DATABASE [{DATABASE}] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; "
            f"DROP DATABASE [{DATABASE}] END"
        )
        cursor.execute(f"IF SUSER_ID(N'{RUN_AS}') IS NOT NULL DROP LOGIN [{RUN_AS}]")

    drop()
    cursor.execute(f"CREATE DATABASE [{DATABASE}]")
    cursor.execute(f"CREATE LOGIN [{RUN_AS}] WITH PASSWORD = N'{PASSWORD}', CHECK_POLICY = OFF")
    cursor.execute(f"USE [{DATABASE}]")
    for sql in (
        "CREATE TABLE dbo.t (id int PRIMARY KEY, v int NOT NULL)",
        "INSERT INTO dbo.t VALUES (1, 0), (2, 0), (3, 0), (4, 0), (5, 0)",
        "CREATE TABLE dbo.audit (id int PRIMARY KEY, n int NOT NULL)",
        "INSERT INTO dbo.audit VALUES (1, 0), (2, 0), (3, 0), (4, 0), (5, 0)",
        "CREATE TABLE dbo.tt (id int PRIMARY KEY, v int NOT NULL)",
        "INSERT INTO dbo.tt VALUES (1, 0)",
        f"CREATE USER [{RUN_AS}] FOR LOGIN [{RUN_AS}]",
        f"ALTER ROLE db_datareader ADD MEMBER [{RUN_AS}]",
        f"ALTER ROLE db_datawriter ADD MEMBER [{RUN_AS}]",
        f"GRANT CREATE TABLE TO [{RUN_AS}]",
        f"GRANT ALTER ON SCHEMA::dbo TO [{RUN_AS}]",
        # An AFTER trigger that changes five rows of another table, under
        # NOCOUNT OFF, so pyodbc's first count is the trigger's (probe 17, S5).
        "CREATE TRIGGER dbo.tt_after ON dbo.tt AFTER UPDATE AS UPDATE dbo.audit SET n = n + 1",
    ):
        cursor.execute(sql)
    cursor.execute("USE master")
    try:
        yield live_mssql
    finally:
        drop()
        connection.close()


@pytest.fixture
def runner(stack: Any) -> Iterator[Any]:
    from sopuli.driver.mssql.session import MssqlDriver

    target = ExpandedTarget(
        target=Target(
            name="mssql-dev",
            type="mssql",
            dsn=stack.dsn,
            mssql=TargetMssql(trust_server_certificate=True),
        )
    )
    opened = MssqlDriver(correlation_id="w1-uc3", timeouts=Timeouts(query_s=30)).connect(
        target, Credential(username=RUN_AS, secret=Secret(PASSWORD))
    )
    try:
        yield opened
    finally:
        opened.close()


def _value(stack: Any, sql: str) -> Any:
    connection = stack.connect()
    try:
        return connection.cursor().execute(sql).fetchone()[0]
    finally:
        connection.close()


def _settings(runner: Any) -> tuple[int, int, int]:
    row = (
        runner.connection.cursor()
        .execute("SELECT @@LOCK_TIMEOUT, @@OPTIONS & 16384, @@TRANCOUNT")
        .fetchone()
    )
    return int(row[0]), int(row[1]), int(row[2])


def test_who_and_where(runner: Any) -> None:
    assert runner.session_user() == RUN_AS
    assert runner.current_user() == RUN_AS
    server, database = runner.database_identity()
    assert server
    assert database == "master"


def test_a_read_by_three_part_name(runner: Any) -> None:
    result = runner.run_statement(
        _sql(f"SELECT id, v FROM {T} ORDER BY id"),
        guard=None,
        commit=False,
        max_rows=10,
        timeout_ms=5000,
    )

    assert result.columns == ("id", "v")
    assert result.rows == ((1, 0), (2, 0), (3, 0), (4, 0), (5, 0))
    assert _settings(runner) == (-1, 0, 0), "the session's own settings are back"


def test_a_capped_read_leaves_the_session_usable(runner: Any) -> None:
    capped = runner.run_statement(
        _sql(f"SELECT id FROM {T} ORDER BY id"), guard=None, commit=False, max_rows=2, timeout_ms=0
    )

    assert (capped.row_count, capped.truncated) == (2, True)
    again = runner.run_statement(
        _sql(f"SELECT COUNT(*) AS n FROM {T}"), guard=None, commit=False, max_rows=1, timeout_ms=0
    )
    assert again.rows == ((5,),)


def test_a_write_that_passes_its_guard_commits(runner: Any, stack: Any) -> None:
    result = runner.run_statement(
        _sql(f"UPDATE {T} SET v = 7 WHERE id <= 2"),
        guard=RowGuard(expect=2),
        commit=True,
        max_rows=1,
        timeout_ms=5000,
    )

    assert (result.row_count, result.committed, result.guard_passed) == (2, True, True)
    assert _value(stack, f"SELECT SUM(v) FROM {T}") == 14


@pytest.mark.parametrize(
    ("guard", "commit"), [(RowGuard(expect=1), True), (RowGuard(expect=2), False)]
)
def test_a_write_that_does_not_commit_changes_nothing(
    runner: Any, stack: Any, guard: RowGuard, commit: bool
) -> None:
    result = runner.run_statement(
        _sql(f"UPDATE {T} SET v = 9 WHERE id <= 2"),
        guard=guard,
        commit=commit,
        max_rows=1,
        timeout_ms=0,
    )

    assert result.row_count == 2
    assert not result.committed
    assert _value(stack, f"SELECT SUM(v) FROM {T}") == 0
    assert _settings(runner)[2] == 0, "no transaction is left open"


def test_the_row_count_is_the_statements_own_where_a_trigger_fires(runner: Any, stack: Any) -> None:
    result = runner.run_statement(
        _sql(f"UPDATE {DATABASE}.dbo.tt SET v = 1 WHERE id = 1"),
        guard=RowGuard(expect=1),
        commit=False,
        max_rows=1,
        timeout_ms=0,
    )

    assert result.row_count == 1, "the trigger's five rows are not the statement's"
    assert _value(stack, f"SELECT SUM(n) FROM {DATABASE}.dbo.audit") == 0


def test_a_select_into_is_refused_and_rolled_back(runner: Any, stack: Any) -> None:
    with pytest.raises(DriverError, match="no rows to show"):
        runner.run_statement(
            _sql(f"SELECT id INTO {DATABASE}.dbo.made FROM {T}"),
            guard=None,
            commit=False,
            max_rows=1,
            timeout_ms=0,
        )

    assert _value(stack, f"SELECT OBJECT_ID(N'{DATABASE}.dbo.made')") is None


def test_a_lock_wait_ends_at_the_timeout_and_the_session_stays_usable(
    runner: Any, stack: Any
) -> None:
    holder = stack.connect()
    holder.autocommit = False
    holder.cursor().execute(f"UPDATE {T} SET v = 1 WHERE id = 3")
    try:
        with pytest.raises(DriverError) as raised:
            runner.run_statement(
                _sql(f"UPDATE {T} SET v = 2 WHERE id = 3"),
                guard=RowGuard(expect=1),
                commit=True,
                max_rows=1,
                timeout_ms=1000,
            )
    finally:
        holder.rollback()
        holder.close()

    assert raised.value.code == "1222"
    assert not runner.connection_lost
    assert _settings(runner) == (-1, 0, 0)
    assert _value(stack, f"SELECT v FROM {T} WHERE id = 3") == 0


def test_a_session_the_server_kills_is_lost(runner: Any, stack: Any) -> None:
    """A KILL gives 596 as HY000, not 08S01 (review of #1736)."""
    spid = runner.connection.cursor().execute("SELECT @@SPID").fetchone()[0]
    holder = stack.connect()
    holder.autocommit = False
    holder.cursor().execute(f"UPDATE {T} SET v = 1 WHERE id = 4")
    failed: list[BaseException] = []

    def kill() -> None:
        try:
            _value_after(stack, f"KILL {spid}")
        except BaseException as error:  # noqa: BLE001 - checked after the join
            failed.append(error)

    killer = threading.Timer(1.5, kill)
    killer.start()
    try:
        # The lock timeout ends the wait if the KILL fails, so the test
        # cannot hang (review of #1736).
        with pytest.raises(DriverError) as raised:
            runner.run_statement(
                _sql(f"UPDATE {T} SET v = 2 WHERE id = 4"),
                guard=RowGuard(expect=1),
                commit=True,
                max_rows=1,
                timeout_ms=10000,
            )
    finally:
        killer.join()
        holder.rollback()
        holder.close()

    assert failed == []
    # 596 on Windows; on Linux, in the tier-1 CI job, the ODBC driver's own
    # HY000 record (#1736). Not the lock timeout's 1222 either way.
    assert raised.value.code in ("596", "HY000"), raised.value.message
    assert runner.connection_lost, raised.value.message
    assert _value(stack, f"SELECT v FROM {T} WHERE id = 4") == 0


def _value_after(stack: Any, sql: str) -> None:
    connection = stack.connect()
    try:
        connection.cursor().execute(sql)
    finally:
        connection.close()


def test_a_datetimeoffset_and_a_hierarchyid_are_read(runner: Any) -> None:
    result = runner.run_statement(
        _sql(
            "SELECT CAST('2026-11-28 12:34:56.1234567 +02:30' AS datetimeoffset) AS d, "
            "CAST('/1/2/' AS hierarchyid) AS h"
        ),
        guard=None,
        commit=False,
        max_rows=1,
        timeout_ms=0,
    )

    ((when, node),) = result.rows
    assert datetime.fromisoformat(when).astimezone(UTC) == datetime(
        2026, 11, 28, 10, 4, 56, 123456, tzinfo=UTC
    )
    assert isinstance(node, str)
    assert node


def test_a_spatial_value_is_its_bytes_in_hex(runner: Any) -> None:
    result = runner.run_statement(
        _sql("SELECT geometry::Point(1, 2, 0) AS g"),
        guard=None,
        commit=False,
        max_rows=1,
        timeout_ms=0,
    )

    assert result.rows == (("00000000010c000000000000f03f0000000000000040",),)


def test_a_type_the_driver_cannot_read_names_the_cast(runner: Any) -> None:
    """A sql_variant that holds an int is pyodbc's HY106, text first in its
    error (#1731). The session stays usable."""
    with pytest.raises(DriverError) as raised:
        runner.run_statement(
            _sql("SELECT CAST(1 AS sql_variant) AS v"),
            guard=None,
            commit=False,
            max_rows=1,
            timeout_ms=0,
        )

    assert raised.value.code == "HY106"
    assert "CAST" in (raised.value.hint or "")
    assert not runner.connection_lost
    assert _settings(runner) == (-1, 0, 0)
