"""sopuli-dba : what `sql run` (UC-3) relies on, on PostgreSQL

#1691. `sql run` connects as a run-as role, runs a read in a read-only
transaction and rolls it back, and commits a write only when its row guard
passes (uc-03-run-statement.md §3 to §5). This measures, as a run-as role
with no grants but its own schema, unless a step says otherwise:

  S1   which statements BEGIN READ ONLY refuses: CREATE TABLE, SELECT ...
       INTO, INSERT, UPDATE, DELETE, MERGE, nextval(), SELECT ... FOR UPDATE
       and FOR SHARE, a data-modifying CTE, and a VOLATILE and a STABLE
       function that writes. Then an INSERT into a temporary table and
       nextval() of a temporary sequence. Each is rolled back, and the
       table and the sequence are read afterwards
  S1g  dblink_exec(), inside BEGIN READ ONLY, inserting a row into a second
       database on the same server, and whether the row is there after the
       rollback. The superuser installs dblink where the server lacks it,
       and grants the run-as role EXECUTE on dblink_exec(text, text) alone
  S2  what psycopg does with two statements in one text, an UPDATE and a
       DELETE, and two SELECTs: cursor.execute(text), execute(text, ()) and
       execute(text, prepare=True). Then the same three calls on a text with
       a % inside a literal
  S3   SET LOCAL statement_timeout on pg_sleep(3), and SET LOCAL lock_timeout
       and statement_timeout on an UPDATE of a row another session holds
       locked. The SQLSTATE, the time, the transaction state after, and
       whether a ROLLBACK and a SELECT 1 then work. Three runs each
  S4   whether statement_timeout bounds a COMMIT that runs a deferred
       constraint trigger that sleeps 2 s: with SET LOCAL, and with a
       session's SET. Whether the row is kept. Three runs each
  S5   cursor.rowcount after an UPDATE to the values the rows hold, an
       UPDATE, INSERT ... ON CONFLICT DO NOTHING with one new row and one
       conflict, MERGE, DELETE, UPDATE ... RETURNING and an UPDATE of no row
  S6   the Python type psycopg returns for each PostgreSQL type a result
       can hold
  S7   system_identifier, current_database() and session_user, read by the
       run-as role
  S8   what psycopg raises for a wrong password and for a role that does not
       exist, and what sopuli's driver (src/sopuli/driver/postgres/errors.py)
       makes of it

It MEASURES and decides nothing.

STATUS: run on 13.23, 14.24, 15.19, 16.15, 17.11 and 18.6, the postgres:13 to
postgres:18 images of test/compose.yaml profile postgres-matrix, and on
16.15, the postgres:16-alpine image of the tier-1 postgres service, on
2026-11-25 (#1691). The client was psycopg 3.3.6 with libpq 18.4, Python
3.13.12, on Windows 11 AMD64. Twice with this version of the probe. Four
earlier runs of earlier versions, which granted the run-as role every
function of dblink, had a third S4 case, and two of which had no SELECT ...
INTO case, are not counted; they agreed. Exit 0 each time, and the same
result each time but for system_identifier and the timings, which are the
ranges below.

RESULTS

  S1   BEGIN READ ONLY refuses every write, with 25006: "cannot execute
       CREATE TABLE in a read-only transaction", and so for SELECT INTO,
       INSERT, UPDATE, DELETE, MERGE, nextval(), SELECT FOR UPDATE and
       SELECT FOR SHARE. The data-modifying CTE is refused as "cannot
       execute SELECT in a read-only transaction". The VOLATILE function is
       refused at its INSERT, 25006. The STABLE function is refused before
       that, 0A000, "INSERT is not allowed in a non-volatile function". 13
       and 14 have no MERGE: 42601, "syntax error at or near "MERGE"". After
       the rollbacks the table has its 3 rows and the sequence was never
       called. An INSERT into a temporary table and nextval() of a temporary
       sequence run
  S1g  dblink_exec() runs inside BEGIN READ ONLY, and its row is in the
       second database after the rollback. EXECUTE on dblink_exec(text,
       text) is the one grant it needs. The read-only transaction does not
       reach the connection dblink opens, which commits on its own. In an
       earlier, uncounted run, through 127.0.0.1, it was refused, 2F003,
       "password or GSSAPI delegated credentials required": the images
       trust a loopback login, and dblink refuses a role that is not a
       superuser a connection that used no password. So the probe connects
       through the server's own address
  S2   execute(text) and execute(text, ()) run both statements, and give two
       result sets. execute(text, prepare=True) refuses them, 42601, "cannot
       insert multiple commands into a prepared statement". With a % in a
       literal, execute(text) and execute(text, prepare=True) run;
       execute(text, ()) raises ProgrammingError, "only '%s', '%b', '%t' are
       allowed as placeholders", in the client
  S3   statement_timeout cancels pg_sleep(3), 57014, "canceling statement
       due to statement timeout". lock_timeout cancels the UPDATE of the
       locked row, 55P03, "canceling statement due to lock timeout", and
       statement_timeout cancels it with 57014. Each fires at 0.50 to 0.51
       s, in all three runs. The transaction is then INERROR, and a ROLLBACK and a
       SELECT 1 work: the session stays usable
  S4   statement_timeout does not bound the COMMIT, in either of the two
       ways. Each COMMIT takes 2.00 to 2.02 s, ends IDLE, and keeps the row
  S5   rowcount is 3 for the UPDATE to the values the rows hold: the rows
       matched, not the rows changed. It is 1 for the one-row UPDATE, 1 for
       INSERT ... ON CONFLICT DO NOTHING (the new row only), 3 for the MERGE
       on 15 to 18, 2 for the DELETE, 2 for UPDATE ... RETURNING, which also
       returns its 2 rows, and 0 for the UPDATE of no row
  S6   numeric is decimal.Decimal, NaN included. float8 is float, inf
       included. bigint is int. json and jsonb are dict, and arrays are list.
       uuid is uuid.UUID. inet is ipaddress.IPv4Address and cidr
       ipaddress.IPv4Network. interval is datetime.timedelta, and a year and
       month interval becomes days: '1 year 2 months' is 425 days. bytea is
       bytes. int4range is psycopg.types.range.Range. timestamptz is an aware
       datetime, timestamp a naive one, date and time are date and time.
       money, regclass, xml and char(3) are str, money with a dollar sign
       before it, and char(3) padded with spaces. oid is int. A text of 5000
       characters comes back whole
  S7   the run-as role reads all three. session_user is its own name
  S8   psycopg raises OperationalError with sqlstate None for both. The
       driver reads the message, and raises AuthenticationError, code 28P01,
       for both. A role that does not exist reads as a wrong password, as
       pg-connect-sqlstate in docs/README.md says

  So BEGIN READ ONLY stops every write a statement can make in its own
  database, SELECT INTO and a data-modifying CTE included, but not one that
  dblink makes on another connection. psycopg runs both statements of a text
  that holds two, with no parameters or an empty tuple of them. Only
  prepare=True is refused, and it does not read % as a placeholder. The
  probe does not see the protocol. psycopg's documentation gives it as the
  reason: a query with parameters is bound on the server and holds one
  statement, and one without has no such limit ("Multiple statements in the
  same query", https://www.psycopg.org/psycopg3/docs/basic/from_pg2.html).
  A timeout cancels the statement and
  leaves the session usable, and it never bounds a COMMIT.

HOW TO RUN, against the matrix (test/README.md), from the repo root, with the
repo's virtual environment:

    .venv/Scripts/python sql/postgres/12_statement_run_probe.py
    .venv/Scripts/python sql/postgres/12_statement_run_probe.py --tier1

The ports follow SOPULI_TEST_POSTGRES13_PORT to SOPULI_TEST_POSTGRES18_PORT,
and SOPULI_TEST_POSTGRES_PORT for --tier1, so a second clone's servers are the
ones it uses. S8 imports sopuli from src/.

THROWAWAY SERVERS ONLY. It creates the role sopuli_probe_runas, its schema
sopuli_probe and the database sopuli_probe_db2, and drops them at the end.
It creates the extension dblink only where the server lacks it, and drops it
only then. Before it starts, it drops what an interrupted run left, but not
dblink, which an interrupted run may leave behind. A cleanup that fails is
printed, and the next release still runs.
"""

from __future__ import annotations

import os
import sys
import time
from typing import Any

import psycopg
from psycopg import sql

VERSIONS = (13, 14, 15, 16, 17, 18)
#: Tier 0's public test password, from test/compose.yaml.
SUPERUSER_PASSWORD = "sopuli-test"
#: The run-as role's password. A marker on a throwaway server.
RUN_AS_PASSWORD = "sopuli-probe-runas"
RUN_AS = "sopuli_probe_runas"
SCHEMA = "sopuli_probe"
DB2 = "sopuli_probe_db2"
#: How often a step that waits on a timer runs.
REPEAT = 3
TIMEOUT_MS = 500


def _port(version: int | None) -> str:
    """A matrix server's port, or the tier-1 `postgres` service's for None."""
    if version is None:
        return os.environ.get("SOPULI_TEST_POSTGRES_PORT", "5432")
    return os.environ.get(f"SOPULI_TEST_POSTGRES{version}_PORT", f"54{version}")


def _connect(
    version: int | None,
    user: str = "postgres",
    password: str = SUPERUSER_PASSWORD,
    dbname: str = "postgres",
    autocommit: bool = True,
) -> psycopg.Connection[Any]:
    return psycopg.connect(
        host="127.0.0.1",
        port=_port(version),
        user=user,
        password=password,
        dbname=dbname,
        autocommit=autocommit,
        connect_timeout=10,
    )


def _run_as(version: int | None) -> psycopg.Connection[Any]:
    return _connect(version, RUN_AS, RUN_AS_PASSWORD)


def _one(conn: psycopg.Connection[Any], query: Any, params: Any = None) -> Any:
    row = conn.execute(query, params).fetchone()
    if row is None:
        raise RuntimeError(f"no row from: {query}")
    return row[0]


def _outcome(error: psycopg.Error | None) -> str:
    if error is None:
        return "ran"
    return f"{error.sqlstate} {error.diag.message_primary}"


#: The one grant S1g adds to the run-as role.
DBLINK_GRANT = f"GRANT EXECUTE ON FUNCTION dblink_exec(text, text) TO {RUN_AS}"


def _clean(version: int | None, *, drop_dblink: bool = False) -> None:
    """Drop what this probe creates. dblink only where this run created it,
    so a server that already had the extension keeps it."""
    with _connect(version) as su:
        su.execute(sql.SQL("DROP DATABASE IF EXISTS {}").format(sql.Identifier(DB2)))
        su.execute(sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(sql.Identifier(SCHEMA)))
        if _one(su, "SELECT count(*) FROM pg_roles WHERE rolname = %s", (RUN_AS,)):
            su.execute(sql.SQL("DROP OWNED BY {}").format(sql.Identifier(RUN_AS)))
            su.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(RUN_AS)))
        if drop_dblink:
            su.execute("DROP EXTENSION IF EXISTS dblink")


def _setup(version: int | None) -> tuple[bool, bool]:
    """The fixture. Returns whether dblink can be used, and whether this run
    created it."""
    with _connect(version) as su:
        for statement in (
            f"CREATE ROLE {RUN_AS} LOGIN PASSWORD '{RUN_AS_PASSWORD}'",
            f"CREATE SCHEMA {SCHEMA} AUTHORIZATION {RUN_AS}",
            f"CREATE DATABASE {DB2}",
        ):
            su.execute(statement)
        created = False
        try:
            if not _one(su, "SELECT count(*) FROM pg_extension WHERE extname = 'dblink'"):
                su.execute("CREATE EXTENSION dblink")
                created = True
            su.execute(DBLINK_GRANT)
            dblink = True
        except psycopg.Error as error:
            print(f"  S1g  dblink: {_outcome(error)}")
            dblink = False
    with _connect(version, dbname=DB2) as su2:
        su2.execute("CREATE TABLE r (n int)")
        su2.execute(f"GRANT INSERT, SELECT ON r TO {RUN_AS}")
    with _run_as(version) as conn:
        for statement in (
            f"CREATE TABLE {SCHEMA}.t (id int PRIMARY KEY, v int)",
            f"INSERT INTO {SCHEMA}.t VALUES (1, 10), (2, 20), (3, 30)",
            f"CREATE SEQUENCE {SCHEMA}.s",
            f"CREATE FUNCTION {SCHEMA}.w() RETURNS int VOLATILE LANGUAGE plpgsql AS"
            f" $$BEGIN INSERT INTO {SCHEMA}.t VALUES (99, 0); RETURN 1; END$$",
            f"CREATE FUNCTION {SCHEMA}.ws() RETURNS int STABLE LANGUAGE plpgsql AS"
            f" $$BEGIN INSERT INTO {SCHEMA}.t VALUES (98, 0); RETURN 1; END$$",
            # A row whose deferred trigger sleeps at COMMIT, for S4.
            f"CREATE TABLE {SCHEMA}.d (n int)",
            f"CREATE FUNCTION {SCHEMA}.slow() RETURNS trigger LANGUAGE plpgsql AS"
            " $$BEGIN PERFORM pg_sleep(2); RETURN NULL; END$$",
            f"CREATE CONSTRAINT TRIGGER slow AFTER INSERT ON {SCHEMA}.d"
            f" DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION {SCHEMA}.slow()",
        ):
            conn.execute(statement)
    return dblink, created


def _read_only(conn: psycopg.Connection[Any], statement: str) -> str:
    """One statement in BEGIN READ ONLY, then a rollback. Autocommit is on, so
    the BEGIN and ROLLBACK are the server's, not psycopg's."""
    conn.execute("BEGIN READ ONLY")
    error = None
    try:
        cursor = conn.execute(statement)
        if cursor.description is not None:
            cursor.fetchall()
    except psycopg.Error as caught:
        error = caught
    finally:
        conn.execute("ROLLBACK")
    return _outcome(error)


def _s1(version: int | None, dblink: bool) -> None:
    t = f"{SCHEMA}.t"
    cases = {
        "CREATE TABLE": f"CREATE TABLE {SCHEMA}.x (n int)",
        # CREATE TABLE AS in a SELECT's shape: the keyword check reads a SELECT.
        "SELECT ... INTO": f"SELECT * INTO {SCHEMA}.t2 FROM {t}",
        "INSERT": f"INSERT INTO {t} VALUES (50, 0)",
        "UPDATE": f"UPDATE {t} SET v = v + 1",
        "DELETE": f"DELETE FROM {t} WHERE id = 1",
        "MERGE": f"MERGE INTO {t} USING (SELECT 1 AS id) s ON {t}.id = s.id"
        " WHEN MATCHED THEN UPDATE SET v = 0",
        "nextval": f"SELECT nextval('{SCHEMA}.s')",
        "FOR UPDATE": f"SELECT * FROM {t} WHERE id = 1 FOR UPDATE",
        "FOR SHARE": f"SELECT * FROM {t} WHERE id = 1 FOR SHARE",
        "data-modifying CTE": f"WITH x AS (DELETE FROM {t} WHERE id = 2 RETURNING *)"
        " SELECT count(*) FROM x",
        "VOLATILE function that writes": f"SELECT {SCHEMA}.w()",
        "STABLE function that writes": f"SELECT {SCHEMA}.ws()",
    }
    with _run_as(version) as conn:
        for name, statement in cases.items():
            print(f"  S1   {name}: {_read_only(conn, statement)}")
        rows = _one(conn, f"SELECT count(*) FROM {t}")
        last = _one(conn, f"SELECT last_value FROM {SCHEMA}.s")
        called = _one(conn, f"SELECT is_called FROM {SCHEMA}.s")
        print(
            f"  S1   after the rollbacks: t has {rows} rows; s last_value {last} is_called {called}"
        )
        # Temporary objects, made outside the read-only transaction.
        conn.execute("CREATE TEMP TABLE tmp (n int)")
        conn.execute("CREATE TEMP SEQUENCE tmps")
        insert = _read_only(conn, "INSERT INTO tmp VALUES (1)")
        print(f"  S1   INSERT into a temporary table: {insert}")
        nextval = _read_only(conn, "SELECT nextval('tmps')")
        print(f"  S1   nextval on a temporary sequence: {nextval}")
        if dblink:
            print(f"  S1g  the run-as role is given: {DBLINK_GRANT}")
            # The server's own address, not 127.0.0.1: the images trust a
            # loopback login, and dblink refuses a role that is not a
            # superuser a login that used no password (2F003).
            address = _one(conn, "SELECT host(inet_server_addr())")
            target = (
                f"host={address} port=5432 dbname={DB2} user={RUN_AS} password={RUN_AS_PASSWORD}"
            )
            outcome = _read_only(
                conn, f"SELECT dblink_exec('{target}', 'INSERT INTO r VALUES (1)')"
            )
            print(f"  S1g  dblink_exec INSERT on another database: {outcome}")
            with _connect(version, dbname=DB2) as su2:
                kept = _one(su2, "SELECT count(*) FROM r")
            print(f"  S1g  rows in {DB2}.r after the rollback: {kept}")


def _s2(version: int | None) -> None:
    two = {
        "SELECT 1; SELECT 2": "SELECT 1; SELECT 2",
        "UPDATE; DELETE": f"UPDATE {SCHEMA}.t SET v = v WHERE id = 1;"
        f" DELETE FROM {SCHEMA}.t WHERE id = 3",
    }
    with _run_as(version) as conn:
        for name, statement in two.items():
            for how, call in (
                ("execute(text)", lambda c, s: c.execute(s)),
                ("execute(text, ())", lambda c, s: c.execute(s, ())),
                ("execute(text, prepare=True)", lambda c, s: c.execute(s, prepare=True)),
            ):
                conn.execute("BEGIN")
                error = None
                with conn.cursor() as cursor:
                    try:
                        call(cursor, statement)
                        sets = 1
                        while cursor.nextset():
                            sets += 1
                        shape = f"ran, {sets} result sets, rowcount {cursor.rowcount}"
                    except psycopg.Error as caught:
                        error = caught
                        shape = _outcome(error)
                conn.execute("ROLLBACK")
                print(f"  S2   {how} with {name}: {shape}")
        # A % in the text, which psycopg reads as a placeholder once it is
        # given parameters.
        for how, call in (
            ("execute(text)", lambda c, s: c.execute(s)),
            ("execute(text, ())", lambda c, s: c.execute(s, ())),
            ("execute(text, prepare=True)", lambda c, s: c.execute(s, prepare=True)),
        ):
            with conn.cursor() as cursor:
                try:
                    call(cursor, "SELECT 'a%b' LIKE 'a%'")
                    shape = f"ran, {cursor.fetchone()}"
                except (psycopg.Error, TypeError, ValueError) as caught:
                    shape = f"{type(caught).__name__}: {caught}"
            print(f"  S2   {how} with a % in a literal: {shape}")


def _timed(conn: psycopg.Connection[Any], statement: str) -> tuple[str, float]:
    started = time.perf_counter()
    error = None
    try:
        conn.execute(statement)
    except psycopg.Error as caught:
        error = caught
    return _outcome(error), time.perf_counter() - started


def _after(conn: psycopg.Connection[Any]) -> str:
    """The transaction state after a failure, and whether the session goes on."""
    state = conn.info.transaction_status.name
    conn.execute("ROLLBACK")
    usable = _one(conn, "SELECT 1") == 1
    return f"then {state}; ROLLBACK and SELECT 1: {'ok' if usable else 'failed'}"


def _s3(version: int | None) -> None:
    t = f"{SCHEMA}.t"
    for run in range(1, REPEAT + 1):
        with _run_as(version) as conn:
            conn.execute("BEGIN")
            conn.execute(f"SET LOCAL statement_timeout = {TIMEOUT_MS}")
            outcome, took = _timed(conn, "SELECT pg_sleep(3)")
            print(
                f"  S3   run {run} statement_timeout on pg_sleep(3): {outcome} after"
                f" {took:.2f} s, {_after(conn)}"
            )
        for setting in ("lock_timeout", "statement_timeout"):
            with _run_as(version) as holder, _run_as(version) as conn:
                holder.execute("BEGIN")
                holder.execute(f"UPDATE {t} SET v = v WHERE id = 1")
                conn.execute("BEGIN")
                conn.execute(f"SET LOCAL {setting} = {TIMEOUT_MS}")
                outcome, took = _timed(conn, f"UPDATE {t} SET v = 0 WHERE id = 1")
                print(
                    f"  S3   run {run} {setting} on a locked row: {outcome} after"
                    f" {took:.2f} s, {_after(conn)}"
                )
                holder.execute("ROLLBACK")


def _s4(version: int | None) -> None:
    d = f"{SCHEMA}.d"
    # The bound, set inside the transaction or for the session.
    modes = {
        "with SET LOCAL statement_timeout": (None, f"SET LOCAL statement_timeout = {TIMEOUT_MS}"),
        "with a session's SET statement_timeout": (f"SET statement_timeout = {TIMEOUT_MS}", None),
    }
    for run in range(1, REPEAT + 1):
        for label, (session, local) in modes.items():
            with _run_as(version) as conn:
                conn.execute(f"TRUNCATE {d}")
                if session:
                    conn.execute(session)
                conn.execute("BEGIN")
                if local:
                    conn.execute(local)
                conn.execute(f"INSERT INTO {d} VALUES (1)")
                outcome, took = _timed(conn, "COMMIT")
                state = conn.info.transaction_status.name
                if state != "IDLE":
                    conn.execute("ROLLBACK")
                conn.execute("RESET statement_timeout")
                kept = _one(conn, f"SELECT count(*) FROM {d}")
                print(
                    f"  S4   run {run} COMMIT of a 2 s deferred trigger {label}: {outcome}"
                    f" after {took:.2f} s, then {state}; rows kept {kept}"
                )


def _s5(version: int | None) -> None:
    t = f"{SCHEMA}.t"
    cases = {
        "UPDATE of 3 rows to the values they hold": f"UPDATE {t} SET v = v",
        "UPDATE of 1 row": f"UPDATE {t} SET v = 11 WHERE id = 1",
        "INSERT ... ON CONFLICT DO NOTHING, 1 new and 1 conflict": (
            f"INSERT INTO {t} VALUES (1, 0), (60, 0) ON CONFLICT DO NOTHING"
        ),
        "MERGE of 2 matched and 1 not": f"MERGE INTO {t} USING (VALUES (1), (2), (70)) s(id)"
        f" ON {t}.id = s.id WHEN MATCHED THEN UPDATE SET v = 0"
        " WHEN NOT MATCHED THEN INSERT VALUES (s.id, 0)",
        "DELETE of 2 rows": f"DELETE FROM {t} WHERE id IN (2, 3)",
        "UPDATE ... RETURNING of 2 rows": f"UPDATE {t} SET v = 1 WHERE id IN (1, 2) RETURNING id",
        "UPDATE of 0 rows": f"UPDATE {t} SET v = 1 WHERE id = -1",
    }
    with _run_as(version) as conn:
        for name, statement in cases.items():
            conn.execute("BEGIN")
            with conn.cursor() as cursor:
                try:
                    cursor.execute(statement)
                    shape = f"rowcount {cursor.rowcount}"
                    if cursor.description is not None:
                        shape += f", {len(cursor.fetchall())} rows returned"
                except psycopg.Error as error:
                    shape = _outcome(error)
            conn.execute("ROLLBACK")
            print(f"  S5   {name}: {shape}")


def _s6(version: int | None) -> None:
    values = {
        "numeric 1.50": "1.50::numeric",
        "numeric 1e30": "1e30::numeric",
        "numeric NaN": "'NaN'::numeric",
        "float8 Infinity": "'Infinity'::float8",
        "bigint": "9007199254740993::bigint",
        "json": """'{"a": 1, "b": [1, 2]}'::json""",
        "jsonb": """'{"a": 1, "b": [1, 2]}'::jsonb""",
        "int[]": "ARRAY[1, 2, NULL]",
        "text[]": "ARRAY['a', 'b']",
        "uuid": "'a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11'::uuid",
        "inet": "'192.0.2.1'::inet",
        "cidr": "'192.0.2.0/24'::cidr",
        "interval day-second": "'1 day 2 hours 3.5 seconds'::interval",
        "interval year-month": "'1 year 2 months'::interval",
        "bytea": "'\\xdeadbeef'::bytea",
        "int4range": "int4range(1, 5)",
        "timestamptz": "'2026-11-25 12:00:00+00'::timestamptz",
        "timestamp": "'2026-11-25 12:00:00'::timestamp",
        "date": "'2026-11-25'::date",
        "time": "'12:00:00'::time",
        "money": "12.34::money",
        "boolean": "true",
        "oid": "'pg_class'::regclass::oid",
        "regclass": "'pg_class'::regclass",
        "xml": "'<a>1</a>'::xml",
        "char(3)": "'ab'::char(3)",
        "text of 5000 characters": "repeat('x', 5000)",
    }
    with _run_as(version) as conn:
        for name, expression in values.items():
            try:
                value = _one(conn, f"SELECT {expression}")
                shown = repr(value)
                if len(shown) > 60:
                    shown = shown[:57] + "..."
                print(f"  S6   {name}: {type(value).__module__}.{type(value).__qualname__} {shown}")
            except psycopg.Error as error:
                print(f"  S6   {name}: {_outcome(error)}")


def _s7(version: int | None) -> None:
    with _run_as(version) as conn:
        identity = conn.execute(
            "SELECT system_identifier::text, current_database()::text, session_user::text"
            " FROM pg_control_system()"
        ).fetchone()
    print(f"  S7   as {RUN_AS}: system_identifier, current_database(), session_user = {identity}")


def _s8(version: int | None) -> None:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))
    from sopuli.driver.postgres.errors import from_error
    from sopuli.driver.protocol import AuthenticationError

    for name, user, password in (
        ("wrong password", RUN_AS, "not-the-password"),
        ("role that does not exist", "sopuli_probe_none", "not-the-password"),
    ):
        try:
            _connect(version, user, password).close()
            print(f"  S8   {name}: logged in")
        except psycopg.OperationalError as error:
            raised = from_error(error, connecting=True).as_error()
            print(
                f"  S8   {name}: {type(error).__name__} sqlstate {error.sqlstate};"
                f" the driver raises {type(raised).__name__}"
                f" (AuthenticationError: {isinstance(raised, AuthenticationError)}),"
                f" code {raised.code}"
            )


def probe(version: int | None) -> None:
    with _connect(version) as su:
        release = _one(su, "SHOW server_version")
    print(f"PostgreSQL {release} (port {_port(version)})")
    _clean(version)
    created = False
    try:
        dblink, created = _setup(version)
        _s1(version, dblink)
        _s2(version)
        _s3(version)
        _s4(version)
        _s5(version)
        _s6(version)
        _s7(version)
        _s8(version)
    finally:
        # A cleanup that fails is printed, not raised, so it cannot hide the
        # failure of a step before it.
        try:
            _clean(version, drop_dblink=created)
        except Exception as error:  # noqa: BLE001 -- printed, the run goes on
            print(f"  cleanup failed: {type(error).__name__}: {error}")


def main() -> int:
    print(
        f"psycopg {psycopg.__version__}, libpq {psycopg.pq.version()},"
        f" Python {sys.version.split()[0]}"
    )
    tier1 = "--tier1" in sys.argv
    failed = 0
    for version in (None,) if tier1 else VERSIONS:
        try:
            probe(version)
        except Exception as error:  # noqa: BLE001 -- one release's failure; the rest still run
            failed += 1
            name = "tier-1" if version is None else f"PostgreSQL {version}"
            print(f"{name} (port {_port(version)}): FAILED: {type(error).__name__}: {error}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
