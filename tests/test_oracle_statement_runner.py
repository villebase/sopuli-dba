"""`sql run`'s Oracle runner against a real server (UC-3, #1661). Tier 1.

A throwaway table is created in the test schema for each test and dropped
afterwards. The runner's contract is what the tests pin: a read cannot write, a
write commits only when the caller says so, the guard passes and a row changed,
and a call that waits too long is rolled back and mapped.
"""

from __future__ import annotations

import contextlib
import os
import time
import uuid
from collections.abc import Iterator
from typing import Any

import pytest

from oracle_harness import Environment
from sopuli.driver.protocol import DriverError
from sopuli.sql.guard import RowGuard
from sopuli.sql.statement import classify

USER = os.environ.get("SOPULI_TEST_ORACLE_USER", "system")
PASSWORD = os.environ.get("SOPULI_TEST_ORACLE_PASSWORD", "sopuli-test")


def _run(runner: Any, text: str, **options: Any) -> Any:
    settings: dict[str, Any] = {"guard": None, "commit": False, "max_rows": 100, "timeout_ms": 0}
    settings.update(options)
    return runner.run_statement(classify(text), **settings)


def _hand_built_read(text: str) -> Any:
    """A read `Statement` over text `classify` would call a write.

    The check is by keyword and runs before the runner. This builds the case
    the check cannot see, so the test shows the server is the second guard.
    """
    from sopuli.sql.statement import Statement, StatementKind

    return Statement(text=text, kind=StatementKind.READ, keyword="SELECT")


def _execute(connection: Any, text: str) -> None:
    with connection.cursor() as cursor:
        cursor.execute(text)


@pytest.fixture(scope="module")
def _table_name(oracle_target: Environment) -> Iterator[str]:
    """``(k NUMBER, v VARCHAR2)``, created once for the module and dropped at its end.

    Once, because a read-only transaction that touches a table created in the
    same second fails with ORA-01466. The rows are put back before each test.
    """
    oracledb = pytest.importorskip("oracledb")
    if oracle_target.unreachable_reason:
        pytest.skip(oracle_target.unreachable_reason)
    name = f"SOPULI_RUN_{uuid.uuid4().hex[:8].upper()}"
    connection = oracledb.connect(user=USER, password=PASSWORD, dsn=oracle_target.dsn)
    try:
        _execute(connection, f"CREATE TABLE {name} (k NUMBER, v VARCHAR2(20))")
        _execute(connection, f"CREATE TABLE {name}_L (k NUMBER, body LONG)")
        _execute(connection, f"CREATE SEQUENCE {name}_S")
        with connection.cursor() as cursor:
            cursor.execute(f"INSERT INTO {name}_L VALUES (1, :text)", text="y" * 5000)
        connection.commit()
        time.sleep(2)
        yield name
    finally:
        for drop in (
            f"DROP TABLE {name} PURGE",
            f"DROP TABLE {name}_L PURGE",
            f"DROP SEQUENCE {name}_S",
        ):
            with contextlib.suppress(Exception):
                _execute(connection, drop)
        connection.close()


@pytest.fixture
def table(live_oracle: Environment, _table_name: str) -> str:
    """The module's table holding rows 1 to 5."""
    oracledb = pytest.importorskip("oracledb")
    connection = oracledb.connect(user=USER, password=PASSWORD, dsn=live_oracle.dsn)
    try:
        _execute(connection, f"DELETE FROM {_table_name}")
        for k in range(1, 6):
            _execute(connection, f"INSERT INTO {_table_name} VALUES ({k}, 'v{k}')")
        connection.commit()
    finally:
        connection.close()
    return _table_name


@pytest.fixture
def second_connection(live_oracle: Environment) -> Iterator[Any]:
    oracledb = pytest.importorskip("oracledb")
    connection = oracledb.connect(user=USER, password=PASSWORD, dsn=live_oracle.dsn)
    try:
        yield connection
    finally:
        connection.close()


def _count(connection: Any, text: str) -> int:
    with connection.cursor() as cursor:
        cursor.execute(text)
        return int(cursor.fetchone()[0])


def test_the_session_is_a_statement_runner(session: Any) -> None:
    from sopuli.driver.protocol import StatementRunner

    assert isinstance(session, StatementRunner)


def test_read_returns_columns_and_rows(session: Any, table: str) -> None:
    result = _run(session, f"SELECT k, v FROM {table} ORDER BY k")
    assert result.columns == ("K", "V")
    assert result.rows[0] == (1, "v1")
    assert len(result.rows) == 5
    assert result.row_count == 5
    assert result.truncated is False
    assert result.committed is False
    assert result.guard_passed is None


def test_read_truncates(session: Any, table: str) -> None:
    result = _run(session, f"SELECT k FROM {table} ORDER BY k", max_rows=3)
    assert [row[0] for row in result.rows] == [1, 2, 3]
    assert result.row_count == 3
    assert result.truncated is True


def test_read_cannot_write(session: Any, table: str) -> None:
    statement = _hand_built_read(f"UPDATE {table} SET v = 'changed'")
    with pytest.raises(DriverError) as raised:
        session.run_statement(statement, guard=None, commit=False, max_rows=10, timeout_ms=0)
    assert raised.value.code == "ORA-01456"
    assert "ORA-01456" in raised.value.message
    assert _count(session.connection, f"SELECT COUNT(*) FROM {table} WHERE v = 'changed'") == 0


def test_select_for_update_is_refused_by_the_server(session: Any, table: str) -> None:
    """Measured on 23.26.3.0.0: ORA-01456, so no row is locked."""
    with pytest.raises(DriverError) as raised:
        _run(session, f"SELECT k FROM {table} FOR UPDATE")
    assert raised.value.code == "ORA-01456"


def test_a_sequence_can_be_read_in_a_read_only_transaction(session: Any, table: str) -> None:
    """Measured on 23.26.3.0.0: NEXTVAL is not refused, and the sequence moves.
    UC-3 §3 accepts that."""
    first = _run(session, f"SELECT {table}_S.NEXTVAL FROM dual").rows[0][0]
    second = _run(session, f"SELECT {table}_S.NEXTVAL FROM dual").rows[0][0]
    assert isinstance(first, int)
    assert second == first + 1


def test_a_long_column_is_cut_and_marked(session: Any, table: str) -> None:
    result = _run(session, f"SELECT body FROM {table}_L")
    assert result.rows == (("y" * 4000,),)
    assert result.truncated is True


def test_write_commits_when_guard_passes(session: Any, table: str, second_connection: Any) -> None:
    result = _run(
        session,
        f"UPDATE {table} SET v = 'changed' WHERE k = 2",
        guard=RowGuard(expect=1),
        commit=True,
    )
    assert (result.row_count, result.committed, result.guard_passed) == (1, True, True)
    assert result.columns == ()
    assert result.rows == ()
    assert _count(second_connection, f"SELECT COUNT(*) FROM {table} WHERE v = 'changed'") == 1


def test_write_rolls_back_when_guard_fails(
    session: Any, table: str, second_connection: Any
) -> None:
    result = _run(
        session,
        f"UPDATE {table} SET v = 'changed' WHERE k IN (1, 2)",
        guard=RowGuard(expect=1),
        commit=True,
    )
    assert (result.row_count, result.committed, result.guard_passed) == (2, False, False)
    assert _count(second_connection, f"SELECT COUNT(*) FROM {table} WHERE v = 'changed'") == 0
    assert _count(session.connection, f"SELECT COUNT(*) FROM {table} WHERE v = 'changed'") == 0


def test_dry_run_write_never_commits(session: Any, table: str, second_connection: Any) -> None:
    result = _run(
        session, f"DELETE FROM {table} WHERE k <= 3", guard=RowGuard(maximum=3), commit=False
    )
    assert (result.row_count, result.committed, result.guard_passed) == (3, False, True)
    assert _count(second_connection, f"SELECT COUNT(*) FROM {table}") == 5
    assert _count(session.connection, f"SELECT COUNT(*) FROM {table}") == 5


def test_write_of_zero_rows_rolls_back(session: Any, table: str) -> None:
    result = _run(
        session, f"UPDATE {table} SET v = 'x' WHERE k = 99", guard=RowGuard(maximum=5), commit=True
    )
    assert (result.row_count, result.committed, result.guard_passed) == (0, False, True)


def test_commit_without_a_guard_is_refused(session: Any, table: str) -> None:
    with pytest.raises(ValueError, match="guard"):
        _run(session, f"UPDATE {table} SET v = 'x' WHERE k = 1", commit=True)
    assert _count(session.connection, f"SELECT COUNT(*) FROM {table} WHERE v = 'x'") == 0


def test_a_transaction_left_open_does_not_break_a_read(session: Any, table: str) -> None:
    """The runner ends any open transaction first, or SET TRANSACTION READ ONLY
    would be ORA-01453."""
    _execute(session.connection, f"UPDATE {table} SET v = 'left' WHERE k = 1")
    result = _run(session, f"SELECT COUNT(*) FROM {table}")
    assert result.rows == ((5,),)


def test_database_identity(session: Any) -> None:
    unique_name, container = session.database_identity()
    assert unique_name
    assert container


def test_session_user(session: Any) -> None:
    assert session.session_user() == USER.upper()


def test_current_user_is_the_session_user_and_no_user_is_a_member(session: Any) -> None:
    # One user is never granted to another on Oracle (#1700).
    assert session.current_user() == session.session_user()
    assert session.member_of("SYS") is False


def test_values_convert(session: Any) -> None:
    result = _run(
        session,
        "SELECT CAST(NULL AS VARCHAR2(5)) AS nul,"
        " DATE '2026-11-23' AS d,"
        " TIMESTAMP '2026-11-23 10:11:12.5' AS ts,"
        " CAST(12.50 AS NUMBER(10,2)) AS dec,"
        " CAST(7 AS NUMBER(38)) AS whole,"
        " TO_CLOB(RPAD('x', 4000, 'x')) || TO_CLOB(RPAD('y', 1000, 'y')) AS big,"
        " HEXTORAW('DEADBEEF') AS r"
        " FROM dual",
    )
    assert result.columns == ("NUL", "D", "TS", "DEC", "WHOLE", "BIG", "R")
    nul, day, stamp, dec, whole, big, raw = result.rows[0]
    assert nul is None
    assert day == "2026-11-23T00:00:00"
    assert stamp == "2026-11-23T10:11:12.500000"
    assert dec == "12.5"
    assert whole == 7
    assert isinstance(big, str)
    assert len(big) == 4000
    assert raw == "deadbeef"
    assert result.truncated is True


def test_lock_wait_times_out(session: Any, table: str, second_connection: Any) -> None:
    """One UPDATE changes rows 1 to 4 and then waits on row 5, which another
    session holds. After the timeout the rows it had changed are locked by
    nobody, which only a rollback does, and nothing is committed."""
    assert session.connection_lost is False
    _execute(second_connection, f"UPDATE {table} SET v = 'held' WHERE k = 5")
    try:
        with pytest.raises(DriverError) as raised:
            _run(
                session,
                f"UPDATE {table} SET v = 'mine'",
                guard=RowGuard(expect=5),
                commit=True,
                timeout_ms=2000,
            )
        # The client closes the connection on a call timeout and reports DPY-4011;
        # ORA-03156 is in its message, and the mapped hint says what happened.
        assert raised.value.code == "DPY-4011"
        assert "ORA-03156" in raised.value.message
        assert "rolls this statement's transaction back" in (raised.value.hint or "")
        assert session.connection_lost is True
    finally:
        # The server process of the closed session is still waiting on row 5. It
        # notices the lost client when the wait ends, and only then rolls back.
        second_connection.rollback()
    # Rows 1 to 4 become free, and unchanged: the abandoned transaction is gone.
    deadline = time.monotonic() + 15
    while True:
        try:
            with second_connection.cursor() as cursor:
                cursor.execute(f"SELECT k FROM {table} WHERE k < 5 FOR UPDATE NOWAIT")
                assert len(cursor.fetchall()) == 4
            break
        except Exception:
            if time.monotonic() > deadline:
                raise
            time.sleep(0.5)
    second_connection.rollback()
    assert _count(second_connection, f"SELECT COUNT(*) FROM {table} WHERE v = 'mine'") == 0


def test_the_call_timeout_is_restored(session: Any, table: str) -> None:
    before = session.connection.call_timeout
    _run(session, f"SELECT k FROM {table}", timeout_ms=5000)
    assert session.connection.call_timeout == before
