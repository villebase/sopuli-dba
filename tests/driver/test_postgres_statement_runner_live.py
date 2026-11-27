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
import threading
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
            owner.execute("create table slow (k int)")
            owner.execute(
                "create function slow_check() returns trigger language plpgsql as "
                "$$ begin perform pg_sleep(2); return null; end $$"
            )
            owner.execute(
                "create constraint trigger slow_commit after insert on slow "
                "deferrable initially deferred for each row execute function slow_check()"
            )
        yield {"name": name, "password": password}
    finally:
        with _connect(live_postgres, *superuser) as admin:
            with suppress(psycopg.Error):
                admin.execute(f'drop schema "{name}" cascade')
            with suppress(psycopg.Error):
                admin.execute(f'drop role "{name}"')


def _open(live_postgres: Any, role: dict[str, str]) -> Any:
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
    return driver.connect(
        target, Credential(username=role["name"], secret=Secret(role["password"]))
    )


@pytest.fixture
def session(live_postgres: Any, role: dict[str, str]) -> Iterator[Any]:
    opened = _open(live_postgres, role)
    try:
        yield opened
    finally:
        opened.close()


def _values(live_postgres: Any, role: dict[str, str]) -> list[tuple[Any, ...]]:
    with _connect(live_postgres, role["name"], role["password"]) as check:
        return list(check.execute("select k, v from t order by k").fetchall())


def test_the_session_user_and_the_identity(session: Any, role: dict[str, str]) -> None:
    assert session.session_user() == role["name"]
    assert session.current_user() == role["name"]
    system, database = session.database_identity()
    assert system.isdigit()
    assert database == "postgres"


@pytest.fixture
def service(live_postgres: Any, role: dict[str, str]) -> Iterator[dict[str, str]]:
    """A stand-in for the service role, ``svc``, and a role ``mid`` between it
    and the run-as role when a test grants one. NOLOGIN, dropped afterwards."""
    import psycopg

    suffix = uuid.uuid4().hex[:8]
    names = {"svc": f"sopuli_svc_{suffix}", "mid": f"sopuli_mid_{suffix}"}
    with _connect(live_postgres, live_postgres.user, live_postgres.password) as admin:
        for name in names.values():
            admin.execute(f'create role "{name}" nologin')
    try:
        yield names
    finally:
        with _connect(live_postgres, live_postgres.user, live_postgres.password) as admin:
            with suppress(psycopg.Error):
                admin.execute(f'alter role "{role["name"]}" reset role')
            for name in names.values():
                with suppress(psycopg.Error):
                    admin.execute(f'drop role "{name}"')


def _as_superuser(live_postgres: Any, *statements: str) -> None:
    with _connect(live_postgres, live_postgres.user, live_postgres.password) as admin:
        for statement in statements:
            admin.execute(statement)


def test_a_role_that_is_not_a_member_is_not(session: Any, service: dict[str, str]) -> None:
    assert session.member_of(service["svc"]) is False


def test_a_direct_member_is_one(
    live_postgres: Any, role: dict[str, str], service: dict[str, str]
) -> None:
    _as_superuser(live_postgres, f'grant "{service["svc"]}" to "{role["name"]}"')
    opened = _open(live_postgres, role)
    try:
        assert opened.member_of(service["svc"]) is True
        # Compared by upper(), as invariant 5 compares names.
        assert opened.member_of(service["svc"].upper()) is True
    finally:
        opened.close()


def test_a_member_through_another_role_is_one(
    live_postgres: Any, role: dict[str, str], service: dict[str, str]
) -> None:
    # Without INHERIT on the path, too: SET ROLE still reaches it.
    _as_superuser(
        live_postgres,
        f'grant "{service["svc"]}" to "{service["mid"]}"',
        f'grant "{service["mid"]}" to "{role["name"]}"',
        f'alter role "{role["name"]}" noinherit',
    )
    opened = _open(live_postgres, role)
    try:
        assert opened.member_of(service["svc"]) is True
    finally:
        opened.close()
        _as_superuser(live_postgres, f'alter role "{role["name"]}" inherit')


def test_a_superuser_is_not_counted(
    live_postgres: Any, role: dict[str, str], service: dict[str, str]
) -> None:
    _as_superuser(
        live_postgres,
        f'grant "{service["svc"]}" to "{role["name"]}"',
        f'alter role "{role["name"]}" superuser',
    )
    opened = _open(live_postgres, role)
    try:
        assert opened.member_of(service["svc"]) is False
    finally:
        opened.close()
        _as_superuser(live_postgres, f'alter role "{role["name"]}" nosuperuser')


def test_a_default_role_is_the_current_user(
    live_postgres: Any, role: dict[str, str], service: dict[str, str]
) -> None:
    _as_superuser(
        live_postgres,
        f'grant "{service["svc"]}" to "{role["name"]}"',
        f'alter role "{role["name"]}" set role = "{service["svc"]}"',
    )
    opened = _open(live_postgres, role)
    try:
        assert opened.session_user() == role["name"]
        assert opened.current_user() == service["svc"]
    finally:
        opened.close()


def test_a_superuser_starting_as_a_member_is_one(
    live_postgres: Any, role: dict[str, str], service: dict[str, str]
) -> None:
    # The login is a superuser and no member, but its statements run as
    # `mid`, which is an ordinary role and a member of the service role.
    _as_superuser(
        live_postgres,
        f'grant "{service["svc"]}" to "{service["mid"]}"',
        f'alter role "{role["name"]}" superuser',
        f'alter role "{role["name"]}" set role = "{service["mid"]}"',
    )
    opened = _open(live_postgres, role)
    try:
        assert opened.current_user() == service["mid"]
        assert opened.member_of(service["svc"]) is True
    finally:
        opened.close()
        _as_superuser(live_postgres, f'alter role "{role["name"]}" nosuperuser')


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


def test_dates_python_cannot_hold_are_the_servers_text(session: Any) -> None:
    # `account reset-password` sets VALID UNTIL 'infinity', so a read of
    # pg_roles meets one.
    result = _run(
        session,
        "SELECT 'infinity'::timestamptz, '-infinity'::timestamp, 'infinity'::date, "
        "'0044-03-15 BC'::date, '10000-01-01'::date, '2026-11-25 10:00:00+00'::timestamptz",
    )

    assert result.rows[0][:5] == (
        "infinity",
        "-infinity",
        "infinity",
        "0044-03-15 BC",
        "10000-01-01",
    )
    # A date Python holds is still read as one.
    assert result.rows[0][5].startswith("2026-11-25T")


def test_a_record_is_json_text_and_a_long_value_is_cut(session: Any) -> None:
    result = _run(session, "SELECT ROW(1, 'a'), repeat('x', 5000)::xml")

    assert result.rows[0][0] == '["1", "a"]'
    assert result.rows[0][1] == "x" * 4000
    assert result.truncated is True


@pytest.mark.parametrize(
    ("text", "code"),
    [
        # A read is declared as a cursor, which takes a query only.
        ("UPDATE t SET v = 'x'", "42601"),
        ("SELECT * INTO t2 FROM t", "42601"),
        ("WITH gone AS (DELETE FROM t RETURNING k) SELECT count(*) FROM gone", "0A000"),
        # The read-only transaction refuses what the cursor accepts.
        ("SELECT nextval('s')", "25006"),
        ("SELECT * FROM t FOR UPDATE", "25006"),
    ],
)
def test_a_read_cannot_write(
    session: Any, live_postgres: Any, role: dict[str, str], text: str, code: str
) -> None:
    with pytest.raises(DriverError) as raised:
        session.run_statement(
            _hand_built_read(text), guard=None, commit=False, max_rows=100, timeout_ms=0
        )

    assert raised.value.code == code
    assert "--write" not in (raised.value.hint or "")
    assert _values(live_postgres, role) == [(1, "a"), (2, "b"), (3, "c")]
    assert session.connection_lost is False


def test_two_statements_in_a_read_are_refused_by_the_server(session: Any) -> None:
    with pytest.raises(DriverError) as raised:
        session.run_statement(
            _hand_built_read("SELECT 1; SELECT 2"),
            guard=None,
            commit=False,
            max_rows=100,
            timeout_ms=0,
        )

    assert raised.value.code == "42601"


def test_a_read_fetches_only_up_to_max_rows(session: Any) -> None:
    # A client-side cursor would load all ten million rows first.
    result = _run(session, "SELECT g FROM generate_series(1, 10000000) g", max_rows=2)

    assert result.rows == ((1,), (2,))
    assert result.truncated is True


def test_a_transaction_left_open_is_ended_before_a_read(
    session: Any, live_postgres: Any, role: dict[str, str]
) -> None:
    session.connection.execute("begin")

    with pytest.raises(DriverError) as raised:
        session.run_statement(
            _hand_built_read("SELECT nextval('s')"),
            guard=None,
            commit=False,
            max_rows=100,
            timeout_ms=0,
        )

    assert raised.value.code == "25006"


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


def test_a_commit_the_server_refused_was_rolled_back(
    session: Any, live_postgres: Any, role: dict[str, str]
) -> None:
    # The deferred unique constraint is checked at the commit, so the
    # statement passes and the COMMIT fails. The server rolled it back, so
    # the outcome is known.
    with pytest.raises(DriverError) as raised:
        _run(session, "INSERT INTO d VALUES (1)", guard=RowGuard(expect=1), commit=True)

    assert raised.value.code == "23505"
    assert raised.value.commit_failed is False
    with _connect(live_postgres, role["name"], role["password"]) as check:
        assert check.execute("select count(*) from d").fetchone() == (1,)


def test_a_commit_whose_connection_is_lost_is_marked(session: Any, live_postgres: Any) -> None:
    # The deferred trigger sleeps in the COMMIT, and another session ends
    # this one there, so whether it committed is unknown.
    pid = session.connection.info.backend_pid

    def terminate() -> None:
        with _connect(live_postgres, live_postgres.user, live_postgres.password) as admin:
            admin.execute("select pg_terminate_backend(%s)", (pid,))

    # The COMMIT starts within milliseconds and sleeps for 2 s, so 1 s lands in it
    # with a wide margin on each side.
    timer = threading.Timer(1.0, terminate)
    timer.start()
    try:
        with pytest.raises(DriverError) as raised:
            _run(session, "INSERT INTO slow VALUES (1)", guard=RowGuard(expect=1), commit=True)
    finally:
        timer.join()

    assert raised.value.commit_failed is True
    assert session.connection_lost is True


def test_no_timeout_bounds_the_commit(
    session: Any, live_postgres: Any, role: dict[str, str]
) -> None:
    # The deferred trigger sleeps for 2 s in the COMMIT, past the 300 ms bound.
    result = _run(
        session,
        "INSERT INTO slow VALUES (2)",
        guard=RowGuard(expect=1),
        commit=True,
        timeout_ms=300,
    )

    assert result.committed is True
    with _connect(live_postgres, role["name"], role["password"]) as check:
        assert check.execute("select count(*) from slow").fetchone() == (1,)


def test_a_lower_timeout_on_the_role_is_kept(live_postgres: Any, role: dict[str, str]) -> None:
    from psycopg import sql

    with _connect(live_postgres, live_postgres.user, live_postgres.password) as admin:
        admin.execute(
            sql.SQL("alter role {} set statement_timeout = 300").format(
                sql.Identifier(role["name"])
            )
        )
    opened = _open(live_postgres, role)
    try:
        with pytest.raises(DriverError) as raised:
            _run(opened, "SELECT pg_sleep(3)", timeout_ms=30_000)
    finally:
        opened.close()

    assert raised.value.code == "57014"


def test_a_refused_identity_read_is_named(session: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    # pg_authid stands in for a revoked pg_control_system(): the role may not
    # read it, so the server refuses with the same 42501, and the shared
    # server's grants are left alone.
    monkeypatch.setattr(
        "sopuli.driver.postgres.session.STATEMENT_IDENTITY",
        "select rolname, rolname from pg_authid",
    )

    with pytest.raises(DriverError) as raised:
        session.database_identity()

    assert raised.value.code == "42501"
    assert "pg_control_system()" in (raised.value.hint or "")


def test_a_write_needs_prepared_statements(session: Any) -> None:
    from sopuli.driver.protocol import InternalFaultError

    session.connection.prepare_threshold = None

    with pytest.raises(InternalFaultError, match="prepared statements"):
        _run(session, "UPDATE t SET v = 'x' WHERE k = 1", guard=RowGuard(expect=1), commit=True)


@pytest.mark.parametrize(
    ("text", "word"),
    [
        ("SELECT nextval('s')", "cannot run one that writes"),
        ("SELECT * INTO t2 FROM t", "SELECT ... INTO"),
        ("WITH gone AS (DELETE FROM t RETURNING k) SELECT 1", "WITH query that writes"),
    ],
)
def test_a_refused_read_has_a_hint_for_a_read(session: Any, text: str, word: str) -> None:
    with pytest.raises(DriverError) as raised:
        _run(session, text)

    assert word in (raised.value.hint or "")
    assert "--write" not in (raised.value.hint or "")


def test_a_statement_failure_is_not_a_failed_commit(session: Any) -> None:
    with pytest.raises(DriverError) as raised:
        _run(session, "UPDATE t SET k = 1", guard=RowGuard(maximum=5), commit=True)

    assert raised.value.code == "23505"
    assert raised.value.commit_failed is False
