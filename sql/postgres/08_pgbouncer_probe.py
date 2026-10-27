"""sopuli-dba : a query budget, and a login, through PgBouncer

#1045. A PostgreSQL target sends its query budget as the startup parameter
`options=-c statement_timeout=<ms>` (src/sopuli/driver/postgres/connection.py).
This records what PgBouncer does with it, and with the other ways a budget
could reach the server, in session and in transaction pooling:

  PB1  a connection that sends `options`, to a PgBouncer that does not list it
       in ignore_startup_parameters, and to one that does. Where it gets in,
       `SHOW statement_timeout` and a `pg_sleep` longer than the budget
  PB2  `SET statement_timeout` after connecting, in autocommit, as the driver
       runs. What a second client of the same role then reads, what a third
       reads after both closed, and what one client reads after another sets
       it back
  PB3  `SET LOCAL statement_timeout` inside an explicit transaction: whether it
       holds there, and what is left after a COMMIT and after a rollback. Then
       `SET LOCAL` in autocommit, outside a transaction block
  PB4  a role whose password changes on the server while PgBouncer runs:
       which password PgBouncer then accepts, with auth_query, and whether a
       client that logged in before the change still answers
  PB5  one parametrised query run 8 times on one connection, past psycopg's
       prepare_threshold of 5, with a second client between each run
  PB6  what PgBouncer says when it refuses a login (#1105): a role the server
       does not have, a role with no password, and a wrong password, for a
       role that auth_query reads from the server and for one in auth_file
       (test/pgbouncer/userlist.txt). Then a role whose auth_file password is
       not the server's. Through the PgBouncer that refuses `options`
  PB7  with --server-down, run after the postgres service is stopped and
       PgBouncer left running: the right and a wrong password for the
       auth_query role and for the auth_file role, and a role the server does
       not have. Through the PgBouncer that refuses `options`

It MEASURES and decides nothing. The tool's own verbs through PgBouncer are run
by hand; the results are below.

STATUS: run twice against 16.15, the postgres service of test/compose.yaml,
behind PgBouncer 1.26.0 (profile pgbouncer), on 2026-10-27 (#1045), from
Windows 11 AMD64 with psycopg 3.3.6 and libpq 18.4. The two runs agree. PB6
and PB7 were added and run twice on the same day (#1105), from the same
client. PB6's two runs agree, and PB7's differ in one login, as below.

RESULTS

  PB1  PgBouncer refuses the connection, in both modes: 'FATAL: unsupported
       startup parameter in options: statement_timeout'. With options in
       ignore_startup_parameters it lets the connection in, and drops the
       budget without a message: SHOW statement_timeout reads 0, and a
       pg_sleep(2) completes
  PB2  session pooling: the setting holds for the client that set it, and no
       other client sees it, then or after it closes. Transaction pooling:
       the second client reads 1s and its pg_sleep(2) is cancelled, 57014. A
       third client, after both closed, still reads 1s: the server connection
       keeps it. When another client sets 0, the client that set 1s reads 0
  PB3  inside an explicit transaction, in both modes: SHOW reads 1s. After a
       COMMIT it reads 0, and another client reads 0. In a second transaction
       a pg_sleep(2) is cancelled, 57014, and after the rollback it reads 0.
       In autocommit, outside a transaction block, the server warns 25P01 'SET
       LOCAL can only be used in transaction blocks' and the setting reads 0
  PB4  in both modes, after each change PgBouncer accepts the new password and
       refuses the old one, and a client that logged in before the change
       still answers. A refused login reads 'FATAL: SASL authentication
       failed', with no SQLSTATE. The server's own message is 'password
       authentication failed for user', which the driver reads as 28P01
  PB5  every run answers, in both modes. Session pooling: the server holds
       psycopg's own prepared statement, _pg3_0. Transaction pooling: it holds
       PgBouncer's, PGBOUNCER_1 and PGBOUNCER_2. max_prepared_statements is
       left at PgBouncer's default
  PB6  each refusal is PgBouncer's own message, with no SQLSTATE, and both
       modes read the same. A role the server does not have: 'FATAL: no such
       user'. A role with no password, and a wrong password under auth_query
       and under auth_file: 'FATAL: SASL authentication failed'. The server
       sends neither message. A role whose auth_file password is not the
       server's: with the file's password PgBouncer passes on the server's own
       refusal, 'password authentication failed for user', which the driver
       reads as 28P01. With the server's password it reads 'SASL
       authentication failed'
  PB7  in compose, the stopped service's name no longer resolves. Under
       auth_file, a wrong password still reads 'SASL authentication failed':
       PgBouncer checks it against the file and does not reach the server.
       Every other login fails without that message. It either waits past the
       client's connect_timeout of 10 s, 'connection timeout expired', or,
       once a server login has failed, reads 'FATAL: server login has been
       failing, cached error: server DNS lookup failed (server_login_retry)'.
       In the first run, an auth_file login with the right password was let in
       on a server connection PgBouncer had kept from PB6; after a restart of
       PgBouncer it timed out

  The tool through PgBouncer, sopuli 0.80.0, run by hand on the same day,
  with the tool account and the two roles of docs/local-testing.md and a
  target at the database `transaction`, then at `session`. Both modes behaved
  the same:

  - doctor, and doctor --check-privileges at `transaction`: reachable, READ
    WRITE, scope cluster. ENCRYPTION reads none. It comes from pg_stat_ssl,
    which describes PgBouncer's connection to the server, not the tool's to
    PgBouncer, and require_encryption reads the same. With TLS on that hop
    only, it would read encrypted while the password crosses the tool's hop
    in clear. Not run with TLS on either hop
  - with db.query_timeout_s set, doctor reports the target unreachable, 08001,
    with PB1's message. Through the PgBouncer that ignores options, it is
    reachable and the budget is gone
  - creds check, roles in sync: IN_SYNC, verified by login with
    require_auth=scram-sha-256
  - creds check, a role whose password was changed on the server: ERROR,
    08001, 'SASL authentication failed', exit 1. Directly against the server
    the same role is DRIFT, 28P01, exit 3
  - creds apply with nothing to change: IN_SYNC, nothing changed
  - creds apply with a password to set, and creds rotate: ERROR for each role,
    08001, 'SASL authentication failed', and nothing changed. The verify
    before the change logs in with the new password and is refused, and the
    driver does not read PgBouncer's refusal as a wrong password. rotate
    leaves the password it drew in `pending` and promotes nothing

HOW TO RUN, against the profile (test/README.md), in the project's virtual
environment:

    docker compose --profile tier0 --profile pgbouncer up -d
    python sql/postgres/08_pgbouncer_probe.py

and for PB7, with the server stopped:

    docker compose --profile tier0 --profile pgbouncer stop postgres
    python sql/postgres/08_pgbouncer_probe.py --server-down
    docker compose --profile tier0 --profile pgbouncer start postgres

The probe connects to the server directly, as the superuser, to create
pgbouncer_auth, the function its auth_query calls, and the roles acme_pool_user,
acme_file_user, acme_stale_user and acme_nopw_user, and drops none of them. In
a second clone, set SOPULI_TEST_POSTGRES_PORT, SOPULI_TEST_PGBOUNCER_PORT and
SOPULI_TEST_PGBOUNCER_IGNORE_PORT as for compose.
The passwords are tier 0's public test password and the probe's own.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Callable
from typing import Any

import psycopg
from psycopg import pq, sql

HOST = "127.0.0.1"
SERVER_PORT = os.environ.get("SOPULI_TEST_POSTGRES_PORT", "5432")
#: pgbouncer refuses `options`; pgbouncer-ignore drops it.
BOUNCERS = {
    "strict": os.environ.get("SOPULI_TEST_PGBOUNCER_PORT", "6432"),
    "ignore": os.environ.get("SOPULI_TEST_PGBOUNCER_IGNORE_PORT", "6433"),
}
#: The databases of test/pgbouncer/pgbouncer.ini, one for each pool mode.
MODES = ("session", "transaction")
#: Tier 0's public test password, from test/compose.yaml.
SUPERUSER_PASSWORD = "sopuli-test"
ROLE = "acme_pool_user"
PASSWORD = "PoolProbe-first-1"
SECOND_PASSWORD = "PoolProbe-second-2"
#: PB6 and PB7. A role in auth_file, with the password userlist.txt holds for
#: it, and one whose server password is not the file's.
FILE_ROLE = "acme_file_user"
FILE_PASSWORD = "PoolProbe-file-3"
STALE_ROLE = "acme_stale_user"
STALE_SERVER_PASSWORD = "PoolProbe-other-4"
#: A role with no password, and one the server does not have.
NO_PASSWORD_ROLE = "acme_nopw_user"
MISSING_ROLE = "acme_missing_user"
WRONG_PASSWORD = "PoolProbe-wrong-5"
#: The budget the probe asks for, and a sleep that outlasts it.
BUDGET_MS = 1000
SLEEP_S = 2


def _setup() -> None:
    """The auth_query's role and function, and the role the probe logs in as."""
    with psycopg.connect(
        host=HOST,
        port=SERVER_PORT,
        dbname="sopuli",
        user="postgres",
        password=SUPERUSER_PASSWORD,
        autocommit=True,
    ) as conn:
        conn.execute("SET password_encryption = 'scram-sha-256'")
        for role, password in (
            ("pgbouncer_auth", SUPERUSER_PASSWORD),
            (ROLE, PASSWORD),
            (FILE_ROLE, FILE_PASSWORD),
            (STALE_ROLE, STALE_SERVER_PASSWORD),
            (NO_PASSWORD_ROLE, None),
        ):
            exists = conn.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (role,)).fetchone()
            verb = "ALTER" if exists else "CREATE"
            conn.execute(
                sql.SQL("{} ROLE {} LOGIN PASSWORD {}").format(
                    sql.SQL(verb), sql.Identifier(role), sql.Literal(password)
                )
            )
        # PgBouncer's default auth_query reads pg_authid, which only a superuser
        # may. This is the usual way round it.
        conn.execute(
            """
            CREATE OR REPLACE FUNCTION public.pgbouncer_lookup(p_user text)
            RETURNS TABLE (usename name, passwd text)
            LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog AS $$
              SELECT rolname, CASE WHEN rolvaliduntil < now() THEN NULL ELSE rolpassword END
                FROM pg_authid WHERE rolname = p_user AND rolcanlogin AND NOT rolsuper
            $$
            """
        )
        conn.execute("REVOKE ALL ON FUNCTION public.pgbouncer_lookup(text) FROM PUBLIC")
        conn.execute("GRANT EXECUTE ON FUNCTION public.pgbouncer_lookup(text) TO pgbouncer_auth")


def _connect(bouncer: str, mode: str, password: str = PASSWORD, **extra: Any) -> psycopg.Connection:
    return psycopg.connect(
        host=HOST,
        port=BOUNCERS[bouncer],
        dbname=mode,
        user=ROLE,
        password=password,
        connect_timeout=10,
        autocommit=True,
        **extra,
    )


def _outcome(action: Callable[..., object], *args: object) -> str:
    try:
        result = action(*args)
    except psycopg.Error as exc:
        return f"{type(exc).__name__} {exc.sqlstate or '-'}: {str(exc).strip()}"
    return str(result)


def _show(conn: psycopg.Connection) -> str:
    row = conn.execute("SHOW statement_timeout").fetchone()
    return row[0] if row else "?"


def _sleep(conn: psycopg.Connection) -> str:
    conn.execute(f"SELECT pg_sleep({SLEEP_S})")
    return f"pg_sleep({SLEEP_S}) completed"


def _login(mode: str, password: str) -> str:
    """Log in as the driver's verify_password does, asking for SCRAM."""
    _connect("strict", mode, password, require_auth="scram-sha-256").close()
    return "logged in"


def _role(conn: psycopg.Connection) -> str:
    row = conn.execute("SELECT rolname FROM pg_roles WHERE rolname = %s", (ROLE,)).fetchone()
    return row[0] if row else "?"


def pb1() -> None:
    print(f"PB1  options=-c statement_timeout={BUDGET_MS} at connect")
    for bouncer in BOUNCERS:
        for mode in MODES:
            label = f"  {bouncer:<6} {mode:<11}"
            try:
                conn = _connect(bouncer, mode, options=f"-c statement_timeout={BUDGET_MS}")
            except psycopg.Error as exc:
                print(f"{label} connect: {type(exc).__name__}: {str(exc).strip()}")
                continue
            with conn:
                print(f"{label} connect: ok; SHOW {_show(conn)}; {_outcome(_sleep, conn)}")


def pb2() -> None:
    print(f"PB2  SET statement_timeout = {BUDGET_MS} after connecting, in autocommit")
    for mode in MODES:
        with _connect("strict", mode) as first:
            first.execute(f"SET statement_timeout = {BUDGET_MS}")
            print(f"  {mode:<11} first, after SET: {_show(first)}")
            with _connect("strict", mode) as second:
                print(f"  {mode:<11} second client, while first is open: {_show(second)}")
                print(f"  {mode:<11} second: {_outcome(_sleep, second)}")
        # Nothing has set it back, so a third client reads what the server
        # connection was left with.
        with _connect("strict", mode) as third:
            print(f"  {mode:<11} a third client, after both closed: {_show(third)}")
            third.execute(f"SET statement_timeout = {BUDGET_MS}")
            with _connect("strict", mode) as fourth:
                fourth.execute("SET statement_timeout = 0")
                print(f"  {mode:<11} third sets it, fourth sets 0; third reads: {_show(third)}")


def pb3() -> None:
    print(f"PB3  SET LOCAL statement_timeout = {BUDGET_MS}")
    for mode in MODES:
        with _connect("strict", mode) as conn, _connect("strict", mode) as other:
            # A cancelled statement aborts its transaction, which then rolls
            # back, so the sleep has a transaction of its own. Nothing fails in
            # this one, so it ends with a real COMMIT.
            with conn.transaction():
                conn.execute(f"SET LOCAL statement_timeout = {BUDGET_MS}")
                print(f"  {mode:<11} inside a transaction: {_show(conn)}")
            print(f"  {mode:<11} after COMMIT: {_show(conn)}; other client: {_show(other)}")
            try:
                with conn.transaction():
                    conn.execute(f"SET LOCAL statement_timeout = {BUDGET_MS}")
                    print(f"  {mode:<11} a second transaction: {_outcome(_sleep, conn)}")
            except psycopg.Error as exc:
                print(f"  {mode:<11} the transaction ended with {exc.sqlstate}")
            print(f"  {mode:<11} after it rolled back: {_show(conn)}")
            notices: list[str] = []

            def keep(diag: psycopg.errors.Diagnostic, notices: list[str] = notices) -> None:
                notices.append(f"{diag.severity} {diag.sqlstate}: {diag.message_primary}")

            conn.add_notice_handler(keep)
            conn.execute(f"SET LOCAL statement_timeout = {BUDGET_MS}")
            print(f"  {mode:<11} in autocommit: notices {notices}; then reads {_show(conn)}")


def pb4() -> None:
    print("PB4  the password changes on the server while PgBouncer runs")
    for mode in MODES:
        # A client logged in with the first password, still open while the
        # password changes, as an application's would be.
        with (
            _connect("strict", mode) as warm,
            psycopg.connect(
                host=HOST,
                port=SERVER_PORT,
                dbname="sopuli",
                user="postgres",
                password=SUPERUSER_PASSWORD,
                autocommit=True,
            ) as admin,
        ):
            admin.execute("SET password_encryption = 'scram-sha-256'")
            for label, before, after in (
                ("first -> second", PASSWORD, SECOND_PASSWORD),
                ("second -> first", SECOND_PASSWORD, PASSWORD),
            ):
                admin.execute(
                    sql.SQL("ALTER ROLE {} PASSWORD {}").format(
                        sql.Identifier(ROLE), sql.Literal(after)
                    )
                )
                for name, password in (("old", before), ("new", after)):
                    result = _outcome(_login, mode, password)
                    print(f"  {mode:<11} {label}, {name} password: {result}")
                print(f"  {mode:<11} {label}, the open client: {_outcome(_role, warm)}")


def pb5() -> None:
    print("PB5  one parametrised query 8 times, prepare_threshold 5")
    for mode in MODES:
        with _connect("strict", mode) as conn, _connect("strict", mode) as other:
            results = []
            for _ in range(8):
                results.append(_outcome(_role, conn))
                other.execute("SELECT 1")
            # The statements prepared on the server connection the client holds
            # now, under the names PgBouncer gave them.
            prepared = [row[0] for row in conn.execute("SELECT name FROM pg_prepared_statements")]
            print(
                f"  {mode:<11} {', '.join(sorted(set(results)))} ({len(results)} runs); "
                f"prepared on the server: {prepared}"
            )


def _login_as(mode: str, role: str, password: str) -> str:
    """Log in as ``role``, asking for SCRAM as the driver does."""
    psycopg.connect(
        host=HOST,
        port=BOUNCERS["strict"],
        dbname=mode,
        user=role,
        password=password,
        connect_timeout=10,
        require_auth="scram-sha-256",
    ).close()
    return "logged in"


def _logins(cases: tuple[tuple[str, str, str], ...]) -> None:
    for mode in MODES:
        for label, role, password in cases:
            print(f"  {mode:<11} {label}: {_outcome(_login_as, mode, role, password)}")


def pb6() -> None:
    print("PB6  what PgBouncer says when it refuses a login")
    _logins(
        (
            ("a role the server does not have", MISSING_ROLE, WRONG_PASSWORD),
            ("a role with no password", NO_PASSWORD_ROLE, WRONG_PASSWORD),
            ("auth_query, a wrong password", ROLE, WRONG_PASSWORD),
            ("auth_file, a wrong password", FILE_ROLE, WRONG_PASSWORD),
            ("auth_file, the right password", FILE_ROLE, FILE_PASSWORD),
            ("auth_file not the server's, the file's password", STALE_ROLE, FILE_PASSWORD),
            ("auth_file not the server's, the server's", STALE_ROLE, STALE_SERVER_PASSWORD),
        )
    )


def pb7() -> None:
    print("PB7  the server is down, PgBouncer runs")
    _logins(
        (
            ("auth_query, the right password", ROLE, PASSWORD),
            ("auth_query, a wrong password", ROLE, WRONG_PASSWORD),
            ("a role the server does not have", MISSING_ROLE, WRONG_PASSWORD),
            ("auth_file, the right password", FILE_ROLE, FILE_PASSWORD),
            ("auth_file, a wrong password", FILE_ROLE, WRONG_PASSWORD),
        )
    )


def main() -> int:
    print(f"psycopg {psycopg.__version__}, libpq {pq.version()}")
    if "--server-down" in sys.argv[1:]:
        pb7()
        return 0
    _setup()
    with _connect("strict", "session") as conn:
        print(f"server {conn.execute('SHOW server_version').fetchone()[0]}")
        print(f"server default statement_timeout: {_show(conn)}")
    pb1()
    pb2()
    pb3()
    pb4()
    pb5()
    pb6()
    return 0


if __name__ == "__main__":
    sys.exit(main())
