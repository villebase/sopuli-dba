"""`sql run`'s PostgreSQL runner against the tier-1 `postgres` service (UC-3, #1693).

Tier 1. The runner's contract is what the tests pin: a read cannot write, a
write commits only when the caller says so, the guard passes and a row
matched, a text with two statements is refused by the server, and a statement
past the timeout is cancelled and leaves the session usable. The run-as role
is an ordinary login role that owns its test table, as a DBA's personal
account would.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Iterator
from contextlib import suppress
from typing import Any

import pytest

from sopuli.config.model import ExpandedTarget, Runtime, Target, TargetPostgres
from sopuli.driver.protocol import Credential, DriverContext, DriverError
from sopuli.secrets import Secret
from sopuli.sql.guard import RowGuard
from sopuli.sql.statement import Dialect, Statement, StatementKind, classify


def _connect(live_postgres: Any, user: str, password: str) -> Any:
    import psycopg

    return psycopg.connect(
        host=live_postgres.host,
        port=live_postgres.port,
        user=user,
        password=password,
        dbname="postgres",
        sslmode="disable",
        autocommit=True,
    )


def _run(session: Any, text: str, **options: Any) -> Any:
    settings: dict[str, Any] = {"guard": None, "commit": False, "max_rows": 100, "timeout_ms": 0}
    settings.update(options)
    return session.run_statement(classify(text, dialect=Dialect.POSTGRESQL), **settings)


def _hand_built_read(text: str) -> Statement:
    """A read `Statement` over text the check would refuse or call a write.

    The check runs before the runner. This builds the case it cannot see, so
    the test shows the server is the second guard.
    """
    return Statement(text=text, kind=StatementKind.READ, keyword="SELECT")


@pytest.fixture
def role(live_postgres: Any) -> Iterator[dict[str, str]]:
    """An ordinary login role with its own schema, and a table ``t (k, v)`` with
    three rows, a ``bodies`` table with one long text, and a table whose
    deferred unique constraint fails only at the commit. Dropped afterwards."""
    import psycopg
    from psycopg import sql

    name = f"sopuli_run_{uuid.uuid4().hex[:8]}"
    password = uuid.uuid4().hex
    superuser = (live_postgres.user, live_postgres.password)
    with _connect(live_postgres, *superuser) as admin:
        admin.execute(
            sql.SQL("create role {} login password {}").format(
                sql.Identifier(name), sql.Literal(password)
            )
        )
        admin.execute(
            sql.SQL("create schema {} authorization {}").format(
                sql.Identifier(name), sql.Identifier(name)
            )
        )
    try:
        with _connect(live_postgres, name, password) as owner:
            owner.execute("create table t (k int primary key, v text)")
            owner.execute("insert into t values (1, 'a'), (2, 'b'), (3, 'c')")
            owner.execute("create table bodies (body text)")
            owner.execute("insert into bodies values (repeat('y', 5000))")
            owner.execute("create sequence s")
            owner.execute("create table d (k int, unique (k) deferrable initially deferred)")
            owner.execute("insert into d values (1)")
        yield {"name": name, "password": password}
    finally:
        with _connect(live_postgres, *superuser) as admin:
            with suppress(psycopg.Error):
                admin.execute(f'drop schema "{name}" cascade')
            with suppress(psycopg.Error):
                admin.execute(f'drop role "{name}"')


@pytest.fixture
def session(live_postgres: Any, role: dict[str, str]) -> Iterator[Any]:
    """A session as the run-as role, built the way `sql run` builds one."""
    from sopuli.driver.postgres.session import build_driver

    driver = build_driver(DriverContext(env=os.environ, correlation_id="sqlrun", runtime=Runtime()))
    target = ExpandedTarget(
        target=Target(
            name="tier1-postgres",
            type="postgresql",
            dsn=live_postgres.dsn,
            postgres=TargetPostgres(sslmode="disable"),
        )
    )
    opened = driver.connect(
        target, Credential(username=role["name"], secret=Secret(role["password"]))
    )
    try:
        yield opened
    finally:
        opened.close()


def _values(live_postgres: Any, role: dict[str, str]) -> list[tuple[Any, ...]]:
    with _connect(live_postgres, role["name"], role["password"]) as check:
        return list(check.execute("select k, v from t order by k").fetchall())


def test_the_session_user_and_the_identity(session: Any, role: dict[str, str]) -> None:
    assert session.session_user() == role["name"]
    system, database = session.database_identity()
    assert system.isdigit()
    assert database == "postgres"


def test_a_read_returns_columns_and_rows(session: Any) -> None:
    result = _run(session, "SELECT k, v FROM t ORDER BY k;")

    assert result.columns == ("k", "v")
    assert result.rows == ((1, "a"), (2, "b"), (3, "c"))
    assert (result.row_count, result.truncated, result.committed) == (3, False, False)
    assert result.guard_passed is None


def test_a_read_stops_at_max_rows(session: Any) -> None:
    result = _run(session, "SELECT k FROM t ORDER BY k", max_rows=2)

    assert result.rows == ((1,), (2,))
    assert result.truncated is True


def test_a_long_text_is_cut(session: Any) -> None:
    result = _run(session, "SELECT body FROM bodies")

    assert result.rows[0][0] == "y" * 4000
    assert result.truncated is True


def test_values_become_json(session: Any) -> None:
    result = _run(
        session,
        "SELECT 1.50::numeric, 12345678901234567890::numeric, "
        "'6f2b8a3e-4d1c-4b7a-9e2f-0a1b2c3d4e5f'::uuid, '192.0.2.10'::inet, "
        "'{\"a\": [1, 0.10000000000000000001]}'::jsonb, ARRAY[1.5, 2], '\\x0a0b'::bytea, "
        "interval '1 day 2 hours', int4range(1, 5), '2026-11-25'::date",
    )

    assert result.rows[0] == (
        "1.50",
        "12345678901234567890",
        "6f2b8a3e-4d1c-4b7a-9e2f-0a1b2c3d4e5f",
        "192.0.2.10",
        # The server's text: a float would round the number.
        '{"a": [1, 0.10000000000000000001]}',
        '["1.5", 2]',
        "0a0b",
        "P1DT2H0M0S",
        "[1, 5)",
        "2026-11-25",
    )


@pytest.mark.parametrize(
    "text",
    [
        "UPDATE t SET v = 'x'",
        "SELECT nextval('s')",
        "WITH gone AS (DELETE FROM t RETURNING k) SELECT count(*) FROM gone",
        "SELECT * INTO t2 FROM t",
    ],
)
def test_a_read_cannot_write(
    session: Any, live_postgres: Any, role: dict[str, str], text: str
) -> None:
    with pytest.raises(DriverError) as raised:
        session.run_statement(
            _hand_built_read(text), guard=None, commit=False, max_rows=100, timeout_ms=0
        )

    assert raised.value.code == "25006"
    assert "--write" in (raised.value.hint or "")
    assert _values(live_postgres, role) == [(1, "a"), (2, "b"), (3, "c")]
    assert session.connection_lost is False


def test_two_statements_in_one_text_are_refused_by_the_server(
    session: Any, live_postgres: Any, role: dict[str, str]
) -> None:
    write = Statement(
        text="UPDATE t SET v = 'x' WHERE k = 1; DELETE FROM t",
        kind=StatementKind.WRITE,
        keyword="UPDATE",
    )

    with pytest.raises(DriverError) as raised:
        session.run_statement(
            write, guard=RowGuard(maximum=10), commit=True, max_rows=100, timeout_ms=0
        )

    assert raised.value.code == "42601"
    assert _values(live_postgres, role) == [(1, "a"), (2, "b"), (3, "c")]


def test_a_write_commits_when_the_guard_passes(
    session: Any, live_postgres: Any, role: dict[str, str]
) -> None:
    result = _run(
        session, "UPDATE t SET v = 'z' WHERE k = 2", guard=RowGuard(expect=1), commit=True
    )

    assert (result.row_count, result.committed, result.guard_passed) == (1, True, True)
    assert _values(live_postgres, role) == [(1, "a"), (2, "z"), (3, "c")]


def test_a_dry_run_rolls_back_and_reports_the_count(
    session: Any, live_postgres: Any, role: dict[str, str]
) -> None:
    result = _run(session, "DELETE FROM t", guard=RowGuard(maximum=5), commit=False)

    assert (result.row_count, result.committed, result.guard_passed) == (3, False, True)
    assert _values(live_postgres, role) == [(1, "a"), (2, "b"), (3, "c")]


def test_a_guard_that_fails_rolls_back(
    session: Any, live_postgres: Any, role: dict[str, str]
) -> None:
    result = _run(session, "UPDATE t SET v = 'x'", guard=RowGuard(expect=1), commit=True)

    assert (result.row_count, result.committed, result.guard_passed) == (3, False, False)
    assert _values(live_postgres, role) == [(1, "a"), (2, "b"), (3, "c")]


def test_a_write_that_matches_no_row_is_not_committed(session: Any) -> None:
    result = _run(
        session, "UPDATE t SET v = 'x' WHERE k = 99", guard=RowGuard(maximum=1), commit=True
    )

    assert (result.row_count, result.committed, result.guard_passed) == (0, False, True)


def test_a_commit_needs_a_guard(session: Any) -> None:
    with pytest.raises(ValueError, match="row guard"):
        _run(session, "UPDATE t SET v = 'x'", commit=True)


def test_a_lock_wait_counts_toward_the_timeout(
    session: Any, live_postgres: Any, role: dict[str, str]
) -> None:
    holder = _connect(live_postgres, role["name"], role["password"])
    try:
        holder.autocommit = False
        holder.execute("SELECT * FROM t WHERE k = 1 FOR UPDATE")
        with pytest.raises(DriverError) as raised:
            _run(
                session,
                "UPDATE t SET v = 'x' WHERE k = 1",
                guard=RowGuard(expect=1),
                commit=True,
                timeout_ms=500,
            )
    finally:
        holder.rollback()
        holder.close()

    assert raised.value.code == "57014"
    assert "lock" in (raised.value.hint or "")
    assert session.connection_lost is False
    # The session is still usable, and nothing was changed.
    assert _run(session, "SELECT v FROM t WHERE k = 1").rows == (("a",),)


def test_a_statement_past_the_timeout_is_cancelled(session: Any) -> None:
    with pytest.raises(DriverError) as raised:
        _run(session, "SELECT pg_sleep(5)", timeout_ms=300)

    assert raised.value.code == "57014"
    assert session.connection_lost is False
    assert _run(session, "SELECT 1").rows == ((1,),)


def test_a_failed_commit_is_marked(session: Any) -> None:
    # The deferred unique constraint is checked at the commit, so the
    # statement passes and the COMMIT fails.
    with pytest.raises(DriverError) as raised:
        _run(session, "INSERT INTO d VALUES (1)", guard=RowGuard(expect=1), commit=True)

    assert raised.value.code == "23505"
    assert raised.value.commit_failed is True


def test_a_statement_failure_is_not_a_failed_commit(session: Any) -> None:
    with pytest.raises(DriverError) as raised:
        _run(session, "UPDATE t SET k = 1", guard=RowGuard(maximum=5), commit=True)

    assert raised.value.code == "23505"
    assert raised.value.commit_failed is False
