"""`sql run`'s MySQL and MariaDB runner against the tier-1 servers (UC-3, #1716).

Tier 1. The runner's contract is what the tests pin, on each product: a read
cannot write, a write commits only when the caller says so, the guard passes
and a row matched, the row count is the rows matched, two statements in one
text are refused by the server, and a statement that waits on a lock past the
timeout ends and leaves the session usable. The run-as account is an ordinary
account with every privilege on its own schema, as a DBA's personal account
would have on an application's.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from contextlib import suppress
from dataclasses import dataclass
from typing import Any

import pytest

from sopuli.config.model import ExpandedTarget, Target, TargetMysql
from sopuli.driver.protocol import Credential, DriverError
from sopuli.secrets import Secret
from sopuli.sql.guard import RowGuard
from sopuli.sql.statement import Statement, StatementKind, classify

pymysql = pytest.importorskip("pymysql")


@dataclass
class RunAs:
    """The run-as account, its schema, the server, and its session."""

    product: str
    live: Any
    user: str
    password: str
    schema: str
    session: Any = None

    def values(self) -> list[tuple[Any, ...]]:
        with self.live.connect() as root, root.cursor() as cursor:
            cursor.execute(f"select k, v from {self.schema}.t order by k")
            return list(cursor.fetchall())


def _driver(product: str) -> Any:
    if product == "mysql":
        from sopuli.driver.mysql.session import MysqlDriver

        return MysqlDriver(correlation_id="sqlrun")
    from sopuli.driver.mariadb.session import MariadbDriver

    return MariadbDriver(correlation_id="sqlrun")


@pytest.fixture(params=["mysql", "mariadb"])
def run_as(request: pytest.FixtureRequest) -> Iterator[RunAs]:
    """An account with every privilege on its own schema, which holds an
    InnoDB table ``t (k, v)`` with three rows and a table ``bodies`` with one
    long text, and a session as it, built the way `sql run` builds one.
    Dropped afterwards."""
    product = request.param
    live = request.getfixturevalue(f"live_{product}")
    suffix = uuid.uuid4().hex[:8]
    state = RunAs(
        product=product,
        live=live,
        user=f"dba_{suffix}",
        password=uuid.uuid4().hex,
        schema=f"sopuli_run_{suffix}",
    )
    with live.connect() as root, root.cursor() as cursor:
        cursor.execute(f"create database {state.schema}")
        cursor.execute("create user %s@'%%' identified by %s", (state.user, state.password))
        cursor.execute(f"grant all on {state.schema}.* to %s@'%%'", (state.user,))
        cursor.execute(
            f"create table {state.schema}.t (k int primary key, v varchar(10)) engine=InnoDB"
        )
        cursor.execute(f"insert into {state.schema}.t values (1, 'a'), (2, 'b'), (3, 'c')")
        cursor.execute(f"create table {state.schema}.bodies (body text) engine=InnoDB")
        cursor.execute(f"insert into {state.schema}.bodies values (repeat('y', 5000))")
    block = TargetMysql(ssl_mode="REQUIRED")
    name, dsn = f"tier1-{product}", live.dsn
    if product == "mysql":
        built = Target(name=name, type=product, dsn=dsn, mysql=block)
    else:
        built = Target(name=name, type=product, dsn=dsn, mariadb=block)
    target = ExpandedTarget(target=built)
    state.session = _driver(product).connect(
        target, Credential(username=state.user, secret=Secret(state.password))
    )
    try:
        yield state
    finally:
        state.session.close()
        with live.connect() as root, root.cursor() as cursor:
            with suppress(pymysql.Error):
                cursor.execute(f"drop database {state.schema}")
            with suppress(pymysql.Error):
                cursor.execute("drop user %s@'%%'", (state.user,))


def _run(state: RunAs, text: str | Statement, **options: Any) -> Any:
    settings: dict[str, Any] = {"guard": None, "commit": False, "max_rows": 100, "timeout_ms": 0}
    settings.update(options)
    statement = classify(text) if isinstance(text, str) else text
    return state.session.run_statement(statement, **settings)


def _hand_built(text: str, kind: StatementKind) -> Statement:
    """A `Statement` over text the check would refuse or classify otherwise.
    The check runs before the runner; this builds the case it cannot see, so
    the test shows the server is the second guard."""
    keyword = "SELECT" if kind is StatementKind.READ else "UPDATE"
    return Statement(text=text, kind=kind, keyword=keyword)


def test_the_session_user_and_the_identity(run_as: RunAs) -> None:
    session = run_as.session
    assert session.session_user() == run_as.user
    assert session.current_user() == f"{run_as.user}@%"
    server, database = session.database_identity()
    assert server
    assert database == ""
    assert session.member_of(run_as.user) is False


def test_a_read_returns_rows_capped_and_cut(run_as: RunAs) -> None:
    long = _run(run_as, f"SELECT body FROM {run_as.schema}.bodies")
    assert len(long.rows[0][0]) == 4000
    assert long.truncated is True
    assert run_as.session.connection_lost is False

    result = _run(run_as, f"SELECT k, v FROM {run_as.schema}.t ORDER BY k", max_rows=2)
    assert result.columns == ("k", "v")
    assert result.rows == ((1, "a"), (2, "b"))
    assert result.truncated is True
    # The third row is left on the server: the connection is closed, not drained.
    assert run_as.session.connection_lost is True


def test_the_statement_runs_in_the_servers_time_zone(run_as: RunAs) -> None:
    (zones,) = _run(run_as, "SELECT @@session.time_zone, @@global.time_zone").rows
    assert zones[0] == zones[1]
    with run_as.session.connection.cursor() as cursor:
        cursor.execute("SELECT @@session.time_zone")
        assert cursor.fetchone() == ("+00:00",), "the tool's own reads are in UTC again"


def test_a_percent_sign_is_sent_as_written(run_as: RunAs) -> None:
    assert _run(run_as, "SELECT '100%' AS p").rows == (("100%",),)


def test_a_read_cannot_write(run_as: RunAs) -> None:
    write = _hand_built(f"UPDATE {run_as.schema}.t SET v = 'z' WHERE k = 1", StatementKind.READ)
    with pytest.raises(DriverError) as raised:
        _run(run_as, write)
    assert raised.value.code == "1792"
    assert raised.value.hint is not None
    assert "read-only transaction" in raised.value.hint
    assert run_as.values()[0] == (1, "a")
    assert run_as.session.connection_lost is False


def test_two_statements_in_one_text_are_refused_by_the_server(run_as: RunAs) -> None:
    text = f"UPDATE {run_as.schema}.t SET v = 'z' WHERE k = 1; DELETE FROM {run_as.schema}.t"
    with pytest.raises(DriverError) as raised:
        _run(run_as, _hand_built(text, StatementKind.WRITE), guard=RowGuard(maximum=9))
    assert raised.value.code == "1064"
    assert len(run_as.values()) == 3


def test_a_write_commits_when_the_guard_passes(run_as: RunAs) -> None:
    result = _run(
        run_as,
        f"UPDATE {run_as.schema}.t SET v = 'z' WHERE k = 1",
        guard=RowGuard(expect=1),
        commit=True,
        timeout_ms=5000,
    )
    assert result.committed is True
    assert result.row_count == 1
    assert run_as.values()[0] == (1, "z")


def test_the_row_count_is_the_rows_matched(run_as: RunAs) -> None:
    result = _run(
        run_as,
        f"UPDATE {run_as.schema}.t SET v = 'a' WHERE k = 1",
        guard=RowGuard(expect=1),
        commit=True,
    )
    assert result.row_count == 1, "FOUND_ROWS: a row set to its own value is counted"
    assert result.committed is True


@pytest.mark.parametrize(
    ("guard", "commit"),
    [(RowGuard(expect=1), True), (RowGuard(maximum=5), False)],
    ids=["guard-fails", "dry-run"],
)
def test_a_write_that_must_not_stay_is_rolled_back(
    run_as: RunAs, guard: RowGuard, commit: bool
) -> None:
    result = _run(run_as, f"UPDATE {run_as.schema}.t SET v = 'z'", guard=guard, commit=commit)
    assert result.committed is False
    assert result.row_count == 3
    assert run_as.values() == [(1, "a"), (2, "b"), (3, "c")]


def test_a_zero_row_write_is_not_committed(run_as: RunAs) -> None:
    result = _run(
        run_as,
        f"DELETE FROM {run_as.schema}.t WHERE k = 99",
        guard=RowGuard(maximum=1),
        commit=True,
    )
    assert result.row_count == 0
    assert result.committed is False


def test_a_lock_wait_past_the_timeout_ends_and_the_session_stays_usable(
    run_as: RunAs,
) -> None:
    with run_as.live.connect() as holder, holder.cursor() as cursor:
        cursor.execute("start transaction")
        cursor.execute(f"select v from {run_as.schema}.t where k = 2 for update")
        with pytest.raises(DriverError) as raised:
            _run(
                run_as,
                f"UPDATE {run_as.schema}.t SET v = 'z' WHERE k = 2",
                guard=RowGuard(expect=1),
                commit=True,
                timeout_ms=1000,
            )
        cursor.execute("rollback")
    expected = "1205" if run_as.product == "mysql" else "1969"
    assert raised.value.code == expected
    assert raised.value.commit_failed is False
    assert run_as.session.connection_lost is False
    assert _run(run_as, "SELECT 1 AS one").rows == ((1,),)
    assert run_as.values()[1] == (2, "b")


def test_the_session_keeps_its_own_bounds_afterwards(run_as: RunAs) -> None:
    variables = (
        "@@session.max_execution_time, @@session.innodb_lock_wait_timeout"
        if run_as.product == "mysql"
        else "@@session.max_statement_time, @@session.innodb_lock_wait_timeout"
    )

    def bounds() -> tuple[Any, ...]:
        return tuple(_run(run_as, f"SELECT {variables}").rows[0])

    before = bounds()
    _run(
        run_as,
        f"UPDATE {run_as.schema}.t SET v = 'z' WHERE k = 3",
        guard=RowGuard(expect=1),
        commit=True,
        timeout_ms=2000,
    )
    assert bounds() == before
