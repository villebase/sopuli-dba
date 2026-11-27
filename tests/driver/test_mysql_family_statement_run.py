"""`run_statement` on MySQL and MariaDB without a server (UC-3, #1716). Tier 0.

A fake PyMySQL connection records what the runner sends, in order, so these
tests pin the transaction, the bounds and their undoing. The live tests in
``test_mysql_family_statement_run_live.py`` check the same against servers.
"""

from __future__ import annotations

from datetime import timedelta
from decimal import Decimal
from typing import Any

import pytest

pymysql = pytest.importorskip("pymysql")

from sopuli.config.model import ExpandedTarget, Target  # noqa: E402
from sopuli.driver.mariadb.session import MariadbSession  # noqa: E402
from sopuli.driver.mysql.session import MysqlSession  # noqa: E402
from sopuli.driver.mysql_family.accounts import CURRENT_USER  # noqa: E402
from sopuli.driver.mysql_family.connection import UTC_SESSION  # noqa: E402
from sopuli.driver.mysql_family.statement_run import (  # noqa: E402
    SERVER_STATUS_IN_TRANS,
    SERVER_TIME_ZONE,
    VALUE_LIMIT,
)
from sopuli.driver.protocol import (  # noqa: E402
    DriverError,
    InternalFaultError,
    StatementRunner,
    Timeouts,
)
from sopuli.sql.guard import RowGuard  # noqa: E402
from sopuli.sql.statement import classify  # noqa: E402

IN_TRANS = pymysql.constants.SERVER_STATUS.SERVER_STATUS_IN_TRANS

#: Plain statements, which every dialect reads the same way.
READ = classify("SELECT a, b FROM t")
WRITE = classify("UPDATE t SET v = 1 WHERE k = 2")

#: What the fake answers to each bound read, on each product.
MYSQL_BOUNDS = (0, 50, 31536000)
MARIADB_BOUNDS = (Decimal("0.000000"),)


class _Cursor:
    def __init__(self, connection: _Connection) -> None:
        self.connection = connection
        self.rowcount = -1
        self.description: tuple[tuple[str], ...] | None = None
        self._rows: list[tuple[Any, ...]] = []

    def __enter__(self) -> _Cursor:
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def execute(self, sql: str, *args: object) -> None:
        connection = self.connection
        assert not args, "the runner passes no parameters, so PyMySQL formats nothing"
        connection.sent.append(sql)
        failure = connection.failures.get(sql)
        if failure is not None:
            if failure.args[0] in (2006, 2013):
                connection.open = False
            raise failure
        if sql.startswith("SELECT @@session."):
            self._rows = [connection.bounds]
        elif sql.startswith("SELECT @@global."):
            self._rows = [connection.identity]
        elif sql == CURRENT_USER:
            self._rows = [(connection.account,)]
        elif sql in (READ.text,):
            if connection.columns:
                self.description = tuple((name,) for name in connection.columns)
            self._rows = list(connection.rows)
        elif sql == WRITE.text:
            self.rowcount = connection.rowcount

    def fetchone(self) -> tuple[Any, ...]:
        return self._rows[0]

    def fetchmany(self, size: int) -> list[tuple[Any, ...]]:
        return self._rows[:size]

    def close(self) -> None:
        """An unbuffered cursor reads the rest of its result here."""
        self.connection.drained = True


class _Connection:
    def __init__(self, *, bounds: tuple[Any, ...], read_timeout: float | None = 30) -> None:
        self.bounds = bounds
        self.sent: list[str] = []
        self.failures: dict[str, Exception] = {}
        self.open = True
        self.server_status = 0
        self._read_timeout = read_timeout
        self.timeout_at_commit: float | None = -1
        self.cursor_classes: list[Any] = []
        self.columns: tuple[str, ...] = ("a", "b")
        self.rows: list[tuple[Any, ...]] = [(1, "x"), (2, "y")]
        self.rowcount = 1
        self.identity: tuple[Any, ...] = ("uuid-1", "acme")
        self.account = "dba_alpha@%"
        self.drained = False
        self.closed = False
        #: PyMySQL's unbuffered result in flight, or ``None``.
        self._result: Any = None

    def close(self) -> None:
        self.closed = True
        self.open = False

    def cursor(self, cursor_class: Any = None) -> _Cursor:
        self.cursor_classes.append(cursor_class)
        return _Cursor(self)

    def commit(self) -> None:
        self.sent.append("COMMIT")
        self.timeout_at_commit = self._read_timeout
        failure = self.failures.get("COMMIT")
        if failure is not None:
            self.open = False
            raise failure

    def rollback(self) -> None:
        self.sent.append("ROLLBACK")


def _target(product: str) -> ExpandedTarget:
    return ExpandedTarget(
        target=Target(name=f"{product}-dev", type=product, dsn=f"{product}-dev.example.com:3306")
    )


def _mysql(**kwargs: Any) -> tuple[MysqlSession, _Connection]:
    connection = _Connection(bounds=MYSQL_BOUNDS, **kwargs)
    session = MysqlSession(
        connection=connection, target=_target("mysql"), correlation_id="t", timeouts=Timeouts()
    )
    return session, connection


def _mariadb(**kwargs: Any) -> tuple[MariadbSession, _Connection]:
    connection = _Connection(bounds=MARIADB_BOUNDS, **kwargs)
    session = MariadbSession(
        connection=connection, target=_target("mariadb"), correlation_id="t", timeouts=Timeouts()
    )
    return session, connection


def _run(session: Any, statement: Any = WRITE, **kwargs: Any) -> Any:
    arguments: dict[str, Any] = {
        "guard": RowGuard(expect=1),
        "commit": True,
        "max_rows": 100,
        "timeout_ms": 5000,
    }
    arguments.update(kwargs)
    return session.run_statement(statement, **arguments)


def test_the_in_transaction_flag_is_pymysqls() -> None:
    assert SERVER_STATUS_IN_TRANS == IN_TRANS


@pytest.mark.parametrize("build", [_mysql, _mariadb], ids=["mysql", "mariadb"])
def test_both_sessions_are_statement_runners(build: Any) -> None:
    session, _ = build()
    assert isinstance(session, StatementRunner)


def test_a_mysql_read_runs_read_only_bounded_and_rolled_back() -> None:
    session, connection = _mysql()
    result = _run(session, READ, guard=None, commit=False)

    assert connection.sent == [
        "SELECT @@session.max_execution_time, @@session.innodb_lock_wait_timeout, "
        "@@session.lock_wait_timeout",
        "SET SESSION max_execution_time = 5000, innodb_lock_wait_timeout = 5, "
        "lock_wait_timeout = 5",
        SERVER_TIME_ZONE,
        "START TRANSACTION READ ONLY",
        READ.text,
        "ROLLBACK",
        "SET SESSION max_execution_time = 0, innodb_lock_wait_timeout = 50, "
        "lock_wait_timeout = 31536000",
        UTC_SESSION,
    ]
    assert pymysql.cursors.SSCursor in connection.cursor_classes
    assert result.columns == ("a", "b")
    assert result.rows == ((1, "x"), (2, "y"))
    assert result.committed is False
    assert connection._read_timeout == 30
    assert connection.closed is False
    assert session.connection_lost is False


def test_a_read_cut_at_max_rows_closes_the_connection_rather_than_drain_it() -> None:
    session, connection = _mysql()
    result = _run(session, READ, guard=None, commit=False, max_rows=1)

    assert result.rows == ((1, "x"),)
    assert result.truncated is True
    assert connection.drained is False
    assert connection.closed is True
    assert session.connection_lost is True
    assert session.connection is None
    session.close()


def test_a_select_into_variables_is_refused() -> None:
    session, connection = _mariadb()
    connection.columns = ()
    with pytest.raises(DriverError, match="no rows to show") as raised:
        _run(session, READ, guard=None, commit=False)
    assert raised.value.hint is not None
    assert "INTO" in raised.value.hint
    assert "ROLLBACK" in connection.sent


def test_a_mariadb_write_lifts_its_bound_before_the_commit() -> None:
    session, connection = _mariadb()
    result = _run(session)

    assert connection.sent == [
        "SELECT @@session.max_statement_time",
        "SET SESSION max_statement_time = 5.000000",
        SERVER_TIME_ZONE,
        "START TRANSACTION READ WRITE",
        WRITE.text,
        "SET SESSION max_statement_time = 0",
        "COMMIT",
        "SET SESSION max_statement_time = 0.000000",
        UTC_SESSION,
    ]
    assert result.committed is True
    assert result.guard_passed is True
    assert result.row_count == 1
    assert connection.timeout_at_commit is None


@pytest.mark.parametrize(("existing", "text"), [(0.0004, "0.000400"), (1e-7, "0.000001")])
def test_a_mariadb_bound_keeps_its_microseconds(existing: float, text: str) -> None:
    session, connection = _mariadb()
    connection.bounds = (existing,)
    _run(session)
    assert f"SET SESSION max_statement_time = {text}" in connection.sent
    assert connection.sent[-2] == f"SET SESSION max_statement_time = {text}"


def test_the_statement_runs_in_the_servers_time_zone_and_the_session_returns_to_utc() -> None:
    session, connection = _mysql()
    _run(session, timeout_ms=0)
    start = connection.sent.index("START TRANSACTION READ WRITE")
    assert connection.sent[start - 1] == SERVER_TIME_ZONE
    assert connection.sent[-1] == UTC_SESSION


def test_the_statements_before_the_operators_keep_the_query_budget() -> None:
    session, connection = _mysql()
    budgets: dict[str, float | None] = {}
    execute = _Cursor.execute

    def watch(cursor: _Cursor, sql: str, *args: object) -> None:
        budgets[sql] = connection._read_timeout
        execute(cursor, sql, *args)

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(_Cursor, "execute", watch)
        _run(session, timeout_ms=0)

    assert budgets[SERVER_TIME_ZONE] == 30
    assert budgets["START TRANSACTION READ WRITE"] == 30
    assert budgets[WRITE.text] is None, "--timeout 0 is no bound"


def test_an_interrupted_read_closes_the_connection_rather_than_drain_it() -> None:
    session, connection = _mysql()

    class _Streaming:
        unbuffered_active = True

    def interrupted(cursor: _Cursor, size: int) -> list[tuple[Any, ...]]:
        connection._result = _Streaming()
        raise KeyboardInterrupt

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(_Cursor, "fetchmany", interrupted)
        with pytest.raises(KeyboardInterrupt):
            _run(session, READ, guard=None, commit=False)

    assert connection.closed is True
    assert connection.drained is False
    assert "ROLLBACK" not in connection.sent
    assert session.connection_lost is True


def test_a_session_after_a_capped_read_refuses_as_lost_not_as_a_fault() -> None:
    session, _ = _mysql()
    _run(session, READ, guard=None, commit=False, max_rows=1)
    with pytest.raises(DriverError, match="closed under an earlier statement") as raised:
        _run(session, READ, guard=None, commit=False)
    assert not isinstance(raised.value, InternalFaultError)


def test_a_mysql_write_puts_its_own_lock_timeouts_back_before_the_commit() -> None:
    session, connection = _mysql()
    _run(session)
    restore = (
        "SET SESSION max_execution_time = 0, innodb_lock_wait_timeout = 50, "
        "lock_wait_timeout = 31536000"
    )
    commit = connection.sent.index("COMMIT")
    assert connection.sent[commit - 1] == restore


@pytest.mark.parametrize("build", [_mysql, _mariadb], ids=["mysql", "mariadb"])
def test_the_session_query_budget_does_not_cap_the_timeout(build: Any) -> None:
    session, connection = build(read_timeout=2)
    seen: list[float | None] = []
    execute = _Cursor.execute

    def watch(cursor: _Cursor, sql: str, *args: object) -> None:
        if sql == WRITE.text:
            seen.append(connection._read_timeout)
        execute(cursor, sql, *args)

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(_Cursor, "execute", watch)
        _run(session, timeout_ms=60000)

    # MySQL bounds the call one second past --timeout; MariaDB's server does.
    assert seen == ([61] if build is _mysql else [None])
    assert connection.timeout_at_commit is None
    assert connection._read_timeout == 2


def test_a_connection_lost_before_the_commit_is_not_a_failed_commit() -> None:
    session, connection = _mariadb()
    connection.failures["SET SESSION max_statement_time = 0"] = pymysql.err.OperationalError(
        2013, "Lost connection"
    )
    with pytest.raises(DriverError) as raised:
        _run(session)
    assert raised.value.commit_failed is False
    assert "COMMIT" not in connection.sent


def test_a_mysql_write_bounds_the_client_and_lifts_it_before_the_commit() -> None:
    session, connection = _mysql(read_timeout=None)
    seen: list[float | None] = []
    execute = _Cursor.execute

    def watch(cursor: _Cursor, sql: str, *args: object) -> None:
        if sql == WRITE.text:
            seen.append(connection._read_timeout)
        execute(cursor, sql, *args)

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(_Cursor, "execute", watch)
        _run(session)

    assert seen == [6]
    assert connection.timeout_at_commit is None
    assert connection._read_timeout is None


def test_a_lower_bound_the_account_already_has_stays() -> None:
    session, connection = _mysql()
    connection.bounds = (1000, 2, 3)
    _run(session, timeout_ms=30000)
    assert (
        "SET SESSION max_execution_time = 1000, innodb_lock_wait_timeout = 2, "
        "lock_wait_timeout = 3" in connection.sent
    )
    assert connection._read_timeout == 30


def test_a_zero_timeout_sets_no_bound() -> None:
    session, connection = _mariadb()
    _run(session, timeout_ms=0)
    assert not [sql for sql in connection.sent if "max_statement_time" in sql]


@pytest.mark.parametrize("build", [_mysql, _mariadb], ids=["mysql", "mariadb"])
@pytest.mark.parametrize(
    ("guard", "count", "passed"),
    [(RowGuard(expect=1), 2, False), (RowGuard(maximum=5), 0, True), (None, 3, None)],
    ids=["guard-fails", "zero-rows", "no-guard"],
)
def test_a_write_that_must_not_stay_is_rolled_back(
    build: Any, guard: RowGuard | None, count: int, passed: bool | None
) -> None:
    session, connection = build()
    connection.rowcount = count
    result = _run(session, guard=guard, commit=guard is not None)

    assert "COMMIT" not in connection.sent
    assert "ROLLBACK" in connection.sent
    assert result.committed is False
    assert result.row_count == count
    assert result.guard_passed is passed


def test_a_dry_run_rolls_back_a_write_that_passes() -> None:
    session, connection = _mariadb()
    result = _run(session, commit=False)
    assert "COMMIT" not in connection.sent
    assert result.committed is False
    assert result.guard_passed is True


def test_a_commit_needs_a_guard() -> None:
    session, connection = _mysql()
    with pytest.raises(ValueError, match="row guard"):
        _run(session, guard=None, commit=True)
    assert connection.sent == []


def test_an_open_transaction_is_rolled_back_before_the_new_one() -> None:
    session, connection = _mysql()
    connection.server_status = IN_TRANS
    _run(session, READ, guard=None, commit=False, timeout_ms=0)
    assert connection.sent[:3] == ["ROLLBACK", SERVER_TIME_ZONE, "START TRANSACTION READ ONLY"]


@pytest.mark.parametrize("build", [_mysql, _mariadb], ids=["mysql", "mariadb"])
def test_a_lock_wait_timeout_rolls_back_with_its_hint(build: Any) -> None:
    session, connection = build()
    connection.failures[WRITE.text] = pymysql.err.OperationalError(
        1205, "Lock wait timeout exceeded; try restarting transaction"
    )
    with pytest.raises(DriverError) as raised:
        _run(session)

    assert raised.value.code == "1205"
    assert "Lock wait timeout exceeded" in raised.value.message
    assert raised.value.hint is not None
    assert "lock another session holds" in raised.value.hint
    assert raised.value.commit_failed is False
    after = connection.sent[connection.sent.index(WRITE.text) + 1 :]
    assert after[0] == "ROLLBACK"
    assert after[-1] == UTC_SESSION
    assert session.connection_lost is False


def test_a_read_that_writes_has_the_read_hint() -> None:
    session, connection = _mariadb()
    connection.failures[READ.text] = pymysql.err.InternalError(
        1792, "Cannot execute statement in a READ ONLY transaction"
    )
    with pytest.raises(DriverError) as raised:
        _run(session, READ, guard=None, commit=False)
    assert raised.value.hint is not None
    assert "read-only transaction" in raised.value.hint
    assert "ROLLBACK" in connection.sent


@pytest.mark.parametrize("build", [_mysql, _mariadb], ids=["mysql", "mariadb"])
def test_a_commit_lost_with_its_connection_has_an_unknown_outcome(build: Any) -> None:
    session, connection = build()
    connection.failures["COMMIT"] = pymysql.err.OperationalError(
        2013, "Lost connection to MySQL server during query (timed out)"
    )
    with pytest.raises(DriverError) as raised:
        _run(session)

    assert raised.value.commit_failed is True
    assert raised.value.hint is not None
    assert "whether it took effect is unknown" in raised.value.hint
    assert "rolls it back" not in raised.value.hint
    assert session.connection_lost is True
    assert connection.sent[-1] == "COMMIT", "nothing is sent on a closed connection"


def test_a_statement_lost_with_its_connection_is_not_a_failed_commit() -> None:
    session, connection = _mysql()
    connection.failures[WRITE.text] = pymysql.err.OperationalError(2013, "Lost connection")
    with pytest.raises(DriverError) as raised:
        _run(session)
    assert raised.value.commit_failed is False
    assert session.connection_lost is True
    assert raised.value.hint is not None
    assert "--timeout" in raised.value.hint


def test_a_lost_session_refuses_before_sending_anything() -> None:
    session, connection = _mysql()
    session._connection_lost = True
    with pytest.raises(DriverError, match="closed under an earlier statement"):
        _run(session)
    assert connection.sent == []


def test_rows_are_capped_and_long_values_cut() -> None:
    session, connection = _mariadb()
    connection.columns = ("t", "b", "d", "n")
    long_bytes = b"\x01" * (VALUE_LIMIT + 1)
    connection.rows = [
        ("x" * (VALUE_LIMIT + 1), long_bytes, timedelta(hours=-12), Decimal("1.50")),
        ("y", b"\x02", timedelta(hours=838), Decimal(2)),
    ]
    result = _run(session, READ, guard=None, commit=False, max_rows=1)

    assert result.truncated is True
    assert result.row_count == 1
    (row,) = result.rows
    assert row[0] == "x" * VALUE_LIMIT
    assert row[1] == "01" * VALUE_LIMIT
    assert row[2] == "-P0DT12H0M0S"
    assert row[3] == "1.50"


@pytest.mark.parametrize(
    ("size", "cut"), [(3000, False), (VALUE_LIMIT, False), (VALUE_LIMIT + 1, True)]
)
def test_a_binary_value_is_cut_by_its_bytes_not_its_hex(size: int, cut: bool) -> None:
    session, connection = _mysql()
    connection.columns = ("b",)
    connection.rows = [(b"\xab" * size,)]
    result = _run(session, READ, guard=None, commit=False)

    assert result.rows[0][0] == "ab" * min(size, VALUE_LIMIT)
    assert result.truncated is cut


@pytest.mark.parametrize(
    ("account", "user"),
    [("dba_alpha@%", "dba_alpha"), ("a@b@192.0.2.%", "a@b"), ("@localhost", "")],
)
def test_the_session_user_is_the_matched_account_without_its_host(account: str, user: str) -> None:
    session, connection = _mysql()
    connection.account = account
    assert session.session_user() == user
    assert session.current_user() == account
    assert connection.sent == [CURRENT_USER], "it is read once"


@pytest.mark.parametrize(
    ("build", "query"),
    [
        (_mysql, "SELECT @@global.server_uuid, DATABASE()"),
        (_mariadb, "SELECT @@global.server_uid, DATABASE()"),
    ],
    ids=["mysql", "mariadb"],
)
def test_the_identity_is_the_server_and_its_default_database(build: Any, query: str) -> None:
    session, connection = build()
    connection.identity = ("id-1", None)
    assert session.database_identity() == ("id-1", "")
    assert connection.sent == [query]


def test_no_account_is_held_as_a_role_yet() -> None:
    session, connection = _mysql()
    assert session.member_of("sopuli_svc") is False
    assert connection.sent == []
