"""`run_statement` on SQL Server without a server (UC-3, #1731). Tier 0 where
pyodbc is installed: nothing here opens a socket.

A fake pyodbc connection records what the runner sends, in order, with the
timeout each cursor was made with, so these tests pin the transaction, the
bounds and their undoing. ``test_mssql_statement_run_live.py`` checks the same
against a server.
"""

from __future__ import annotations

import struct
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

import pytest

from sopuli.config.model import ExpandedTarget, Target
from sopuli.driver.mssql.capabilities import END_TRANSACTION
from sopuli.driver.mssql.statement_run import (
    DATETIMEOFFSET,
    OUTPUT_CONVERTERS,
    VALUE_LIMIT,
    XACT_ABORT_BIT,
    _datetimeoffset,
    lock_timeout,
    query_timeout,
)
from sopuli.driver.protocol import DriverError, InternalFaultError, StatementRunner, Timeouts
from sopuli.sql.guard import RowGuard
from sopuli.sql.statement import classify

pyodbc = pytest.importorskip("pyodbc")
session = pytest.importorskip("sopuli.driver.mssql.session")

TARGET = ExpandedTarget(target=Target(name="mssql-dev", type="mssql", dsn="127.0.0.1:1433"))
READ = classify("SELECT a, b FROM acme.dbo.t")
WRITE = classify("UPDATE acme.dbo.t SET v = 1 WHERE k = 2")
SETTINGS = "SELECT @@LOCK_TIMEOUT, @@OPTIONS"
BEGIN = f"{END_TRANSACTION}; BEGIN TRANSACTION"
COMMIT = "COMMIT TRANSACTION"
#: The session's budget, which every cursor but the statement's and the
#: COMMIT's is made with.
BUDGET = 30


def _error(state: str, text: str, number: int = 0, *, server: bool = True) -> Exception:
    """A pyodbc error as ODBC Driver 18 words it."""
    source = "[Microsoft][ODBC Driver 18 for SQL Server]" + ("[SQL Server]" if server else "")
    error: Exception = pyodbc.Error(state, f"[{state}] {source}{text} ({number}) (SQLExecDirectW)")
    return error


LOCK_TIMED_OUT = _error("HY000", "Lock request time out period exceeded.", 1222)
QUERY_TIMED_OUT = _error("HYT00", "Query timeout expired", server=False)
LINK_FAILURE = _error("08S01", "Communication link failure", 10054, server=False)
#: What a session gets when the server KILLs it (review of #1736).
KILLED = pyodbc.Error(
    "HY000",
    "[HY000] [Microsoft][ODBC Driver 18 for SQL Server]Unspecified error occurred on SQL "
    "Server. Connection may have been terminated by the server. (0) (SQLExecDirectW); "
    "[HY000] [Microsoft][ODBC Driver 18 for SQL Server][SQL Server]Cannot continue the "
    "execution because the session is in the kill state. (596)",
)


class _Cursor:
    def __init__(self, connection: _Connection) -> None:
        self.connection = connection
        self.timeout = connection.timeout
        self.description: tuple[tuple[str], ...] | None = None
        self._rows: list[tuple[Any, ...]] = []
        self.cancelled = False

    def execute(self, sql: str) -> None:
        connection = self.connection
        connection.sent.append(sql)
        connection.timeouts.append((sql, self.timeout))
        failure = connection.failures.get(sql)
        if failure is not None:
            raise failure
        if sql == SETTINGS:
            self._rows = [connection.settings]
        elif sql == "SELECT @@ROWCOUNT":
            self._rows = [(connection.rowcount,)]
        elif sql.startswith("SELECT ORIGINAL_LOGIN()"):
            self._rows = [("dba_alpha", "dba_alpha")]
        elif sql.startswith("SELECT CAST(SERVERPROPERTY"):
            self._rows = [("mssql-dev-1", "master")]
        elif sql == READ.text:
            self.description = (("a",), ("b",))
            self._rows = list(connection.rows)
        else:
            self.description = None
            self._rows = []

    def fetchone(self) -> tuple[Any, ...]:
        return self._rows.pop(0)

    def fetchmany(self, size: int) -> list[tuple[Any, ...]]:
        taken, self._rows = self._rows[:size], self._rows[size:]
        return taken

    def nextset(self) -> bool:
        return False

    def cancel(self) -> None:
        self.cancelled = True
        self.connection.cancelled = True

    def close(self) -> None:
        pass


class _Connection:
    def __init__(self) -> None:
        self.sent: list[str] = []
        self.timeouts: list[tuple[str, int]] = []
        self.failures: dict[str, Exception] = {}
        self.settings: tuple[int, int] = (-1, 0)
        self.rowcount = 1
        self.rows: list[tuple[Any, ...]] = [(1, "x"), (2, "y")]
        self.timeout = BUDGET
        self.converters: dict[int, Any] = {}
        self.cancelled = False

    def cursor(self) -> _Cursor:
        return _Cursor(self)

    def add_output_converter(self, sqltype: int, convert: Any) -> None:
        self.converters[sqltype] = convert

    def remove_output_converter(self, sqltype: int) -> None:
        del self.converters[sqltype]


def _session(connection: _Connection | None = None) -> Any:
    return session.MssqlSession(
        connection=connection or _Connection(), target=TARGET, timeouts=Timeouts(query_s=BUDGET)
    )


def _restore(lock: int = -1, *, xact_abort: bool = False) -> str:
    return (
        f"SET XACT_ABORT {'ON' if xact_abort else 'OFF'}; SET NOCOUNT OFF; SET LOCK_TIMEOUT {lock}"
    )


def test_the_session_is_a_statement_runner() -> None:
    assert isinstance(_session(), StatementRunner)


def test_a_read_runs_in_a_transaction_that_is_rolled_back() -> None:
    connection = _Connection()

    result = _session(connection).run_statement(
        READ, guard=None, commit=False, max_rows=10, timeout_ms=5000
    )

    assert connection.sent == [
        SETTINGS,
        "SET XACT_ABORT ON; SET NOCOUNT OFF; SET LOCK_TIMEOUT 5000",
        BEGIN,
        READ.text,
        END_TRANSACTION,
        _restore(),
    ]
    assert (result.columns, result.rows, result.row_count) == (("a", "b"), ((1, "x"), (2, "y")), 2)
    assert not result.truncated
    assert not result.committed
    assert connection.converters == {}, "the converters are removed after the statement"


def test_a_write_that_passes_its_guard_is_committed() -> None:
    connection = _Connection()

    result = _session(connection).run_statement(
        WRITE, guard=RowGuard(expect=1), commit=True, max_rows=10, timeout_ms=5000
    )

    assert connection.sent[3:] == [WRITE.text, "SELECT @@ROWCOUNT", COMMIT, _restore()]
    assert (result.row_count, result.committed, result.guard_passed) == (1, True, True)


@pytest.mark.parametrize(
    ("rowcount", "guard", "commit", "passed"),
    [
        (3, RowGuard(expect=1), True, False),
        (0, RowGuard(maximum=5), True, True),
        (1, RowGuard(expect=1), False, True),
    ],
    ids=["guard-fails", "no-rows", "dry-run"],
)
def test_a_write_that_does_not_commit_is_rolled_back(
    rowcount: int, guard: RowGuard, commit: bool, passed: bool
) -> None:
    connection = _Connection()
    connection.rowcount = rowcount

    result = _session(connection).run_statement(
        WRITE, guard=guard, commit=commit, max_rows=10, timeout_ms=0
    )

    assert COMMIT not in connection.sent
    assert connection.sent[-2:] == [END_TRANSACTION, _restore()]
    assert (result.row_count, result.committed, result.guard_passed) == (rowcount, False, passed)


def test_the_statement_has_the_timeout_and_the_commit_none() -> None:
    connection = _Connection()

    _session(connection).run_statement(
        WRITE, guard=RowGuard(expect=1), commit=True, max_rows=10, timeout_ms=1500
    )

    made_with = dict(connection.timeouts)
    assert made_with[WRITE.text] == 3, "one second past LOCK_TIMEOUT, in whole seconds"
    assert made_with[COMMIT] == 0, "nothing may cut the COMMIT"
    assert made_with[SETTINGS] == made_with["SELECT @@ROWCOUNT"] == BUDGET
    assert connection.timeout == BUDGET, "the session's budget is put back"


@pytest.mark.parametrize(
    ("requested", "existing", "expected"),
    [(5000, -1, 5000), (5000, 2000, 2000), (2000, 5000, 2000), (0, -1, -1), (0, 3000, 3000)],
)
def test_lock_timeout_keeps_a_lower_one(requested: int, existing: int, expected: int) -> None:
    assert lock_timeout(requested, existing) == expected


@pytest.mark.parametrize(("ms", "seconds"), [(0, 0), (1, 2), (1000, 2), (1500, 3)])
def test_query_timeout_is_one_second_past(ms: int, seconds: int) -> None:
    assert query_timeout(ms) == seconds


def test_the_sessions_own_settings_are_put_back() -> None:
    connection = _Connection()
    connection.settings = (2000, XACT_ABORT_BIT)

    _session(connection).run_statement(READ, guard=None, commit=False, max_rows=10, timeout_ms=0)

    assert connection.sent[1] == "SET XACT_ABORT ON; SET NOCOUNT OFF; SET LOCK_TIMEOUT 2000"
    assert connection.sent[-1] == _restore(2000, xact_abort=True)


def test_a_lock_timeout_is_an_error_and_the_session_stays_usable() -> None:
    connection = _Connection()
    connection.failures[WRITE.text] = LOCK_TIMED_OUT
    one = _session(connection)

    with pytest.raises(DriverError) as raised:
        one.run_statement(WRITE, guard=RowGuard(expect=1), commit=True, max_rows=1, timeout_ms=1)

    assert raised.value.code == "1222"
    assert "--timeout" in (raised.value.hint or "")
    assert not one.connection_lost
    assert not raised.value.commit_failed
    assert connection.sent[-2:] == [END_TRANSACTION, _restore()]


def test_a_query_timeout_leaves_the_session_usable() -> None:
    connection = _Connection()
    connection.failures[READ.text] = QUERY_TIMED_OUT
    one = _session(connection)

    with pytest.raises(DriverError) as raised:
        one.run_statement(READ, guard=None, commit=False, max_rows=1, timeout_ms=1000)

    assert raised.value.code == "HYT00"
    assert raised.value.category == "database", "the statement's, not the connection's"
    assert "client stopped it" in (raised.value.hint or "")
    assert not one.connection_lost


def test_a_killed_session_is_lost_and_its_commit_unknown() -> None:
    """The server's 596 comes as HY000, not 08S01 (review of #1736)."""
    connection = _Connection()
    connection.failures[COMMIT] = KILLED
    one = _session(connection)

    with pytest.raises(DriverError) as raised:
        one.run_statement(WRITE, guard=RowGuard(expect=1), commit=True, max_rows=1, timeout_ms=0)

    assert one.connection_lost
    assert raised.value.commit_failed
    assert connection.sent[-1] == COMMIT, "nothing is sent after it"
    for read in (one.session_user, one.database_identity):
        with pytest.raises(DriverError, match="lost under an earlier statement"):
            read()


def test_any_commit_that_fails_has_an_unknown_outcome() -> None:
    """A fatal server error can end the session with a number other than
    596, so a COMMIT the server answered with a number is unknown too
    (review of #1736)."""
    connection = _Connection()
    connection.failures[COMMIT] = _error("HY000", "Some fatal error.", 3314)
    one = _session(connection)

    with pytest.raises(DriverError) as raised:
        one.run_statement(WRITE, guard=RowGuard(expect=1), commit=True, max_rows=1, timeout_ms=0)

    assert raised.value.commit_failed
    assert "unknown" in (raised.value.hint or "")


def test_a_timeout_around_the_statement_names_the_budget_not_the_flag() -> None:
    connection = _Connection()
    connection.failures[SETTINGS] = QUERY_TIMED_OUT

    with pytest.raises(DriverError) as raised:
        _session(connection).run_statement(READ, guard=None, commit=False, max_rows=1, timeout_ms=0)

    assert "db.query_timeout_s" in (raised.value.hint or "")
    assert "--timeout" not in (raised.value.hint or "")


def test_the_rollback_is_sent_where_the_begin_failed() -> None:
    """The BEGIN's batch may fail after BEGIN TRANSACTION ran (review of
    #1736). END_TRANSACTION reads @@TRANCOUNT, so it is safe to send."""
    connection = _Connection()
    connection.failures[BEGIN] = QUERY_TIMED_OUT

    with pytest.raises(DriverError):
        _session(connection).run_statement(READ, guard=None, commit=False, max_rows=1, timeout_ms=0)

    assert connection.sent[-2:] == [END_TRANSACTION, _restore()]


def test_a_session_read_that_finds_the_connection_gone_marks_it_lost() -> None:
    connection = _Connection()
    connection.failures["SELECT ORIGINAL_LOGIN(), SUSER_SNAME()"] = LINK_FAILURE
    one = _session(connection)

    with pytest.raises(DriverError):
        one.session_user()

    assert one.connection_lost


def test_a_rollback_that_fails_marks_the_session_lost() -> None:
    connection = _Connection()
    connection.failures[END_TRANSACTION] = QUERY_TIMED_OUT
    one = _session(connection)

    one.run_statement(READ, guard=None, commit=False, max_rows=5, timeout_ms=0)

    assert one.connection_lost, "the transaction may still be open"
    assert connection.sent[-1] == END_TRANSACTION, "the settings are not sent after it"


def test_a_lost_connection_sends_nothing_more() -> None:
    connection = _Connection()
    connection.failures[WRITE.text] = LINK_FAILURE
    one = _session(connection)

    with pytest.raises(DriverError) as raised:
        one.run_statement(WRITE, guard=RowGuard(expect=1), commit=True, max_rows=1, timeout_ms=0)

    assert one.connection_lost
    assert not raised.value.commit_failed, "no COMMIT was sent"
    assert connection.sent[-1] == WRITE.text
    with pytest.raises(DriverError, match="lost under an earlier statement"):
        one.run_statement(READ, guard=None, commit=False, max_rows=1, timeout_ms=0)


def test_a_commit_whose_connection_is_lost_has_an_unknown_outcome() -> None:
    connection = _Connection()
    connection.failures[COMMIT] = LINK_FAILURE

    with pytest.raises(DriverError) as raised:
        _session(connection).run_statement(
            WRITE, guard=RowGuard(expect=1), commit=True, max_rows=1, timeout_ms=0
        )

    assert raised.value.commit_failed
    assert "unknown" in (raised.value.hint or "")


def test_a_capped_read_cancels_the_rest() -> None:
    connection = _Connection()
    connection.rows = [(n, "x") for n in range(5)]

    result = _session(connection).run_statement(
        READ, guard=None, commit=False, max_rows=2, timeout_ms=0
    )

    assert result.row_count == 2
    assert result.truncated
    assert connection.cancelled
    assert connection.sent[-2:] == [END_TRANSACTION, _restore()]


def test_a_select_that_returns_no_rows_is_refused() -> None:
    statement = classify("SELECT a INTO acme.dbo.t2 FROM acme.dbo.t")
    connection = _Connection()

    with pytest.raises(DriverError, match="no rows to show"):
        _session(connection).run_statement(
            statement, guard=None, commit=False, max_rows=1, timeout_ms=0
        )

    assert connection.sent[-2:] == [END_TRANSACTION, _restore()]


def test_commit_needs_a_guard() -> None:
    connection = _Connection()

    with pytest.raises(ValueError, match="row guard"):
        _session(connection).run_statement(WRITE, guard=None, commit=True, max_rows=1, timeout_ms=0)

    assert connection.sent == []


def test_a_closed_session_is_a_fault() -> None:
    one = session.MssqlSession(connection=None, target=TARGET)

    with pytest.raises(InternalFaultError):
        one.run_statement(READ, guard=None, commit=False, max_rows=1, timeout_ms=0)


def test_who_and_where() -> None:
    one = _session()

    assert (one.session_user(), one.current_user()) == ("dba_alpha", "dba_alpha")
    assert one.database_identity() == ("mssql-dev-1", "master")
    assert not one.member_of("acme_owner")


def test_every_converter_is_removed_after_a_failure() -> None:
    connection = _Connection()
    connection.failures[READ.text] = QUERY_TIMED_OUT

    with pytest.raises(DriverError):
        _session(connection).run_statement(READ, guard=None, commit=False, max_rows=1, timeout_ms=0)

    assert connection.converters == {}
    assert set(OUTPUT_CONVERTERS) >= {DATETIMEOFFSET}


def test_a_datetimeoffset_reads_as_an_aware_datetime() -> None:
    raw = struct.pack("<6hI2h", 2026, 11, 28, 12, 34, 56, 123456700, 2, 30)

    value = _datetimeoffset(raw)

    offset = timezone(timedelta(hours=2, minutes=30))
    assert value == datetime(2026, 11, 28, 12, 34, 56, 123456, tzinfo=offset)
    assert value is not None
    assert value.astimezone(UTC).hour == 10
    assert _datetimeoffset(None) is None


def test_a_long_value_is_cut() -> None:
    connection = _Connection()
    connection.rows = [(b"\x01" * (VALUE_LIMIT + 1), "y" * (VALUE_LIMIT + 1))]

    result = _session(connection).run_statement(
        READ, guard=None, commit=False, max_rows=5, timeout_ms=0
    )

    cut_bytes, cut_text = result.rows[0]
    assert cut_bytes == "01" * VALUE_LIMIT
    assert cut_text == "y" * VALUE_LIMIT
    assert result.truncated
