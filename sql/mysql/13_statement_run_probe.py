"""sopuli-dba : what `sql run` (UC-3) relies on, on MySQL

#1714, part of #1712. `sql run` connects as a run-as account, runs a read in a
read-only transaction and rolls it back, and commits a write only when its row
guard passes (uc-03-run-statement.md §3 to §5). The maintainer decided #1713's
four questions on 2026-11-27, all A. This measures what the runner for MySQL
and MariaDB would rely on. The steps are the items of #1714. Each runs as the
run-as account sopuli_probe_runas, which holds ALL on the schema sopuli_probe
and FILE, unless a step says otherwise:

  T1   which statements START TRANSACTION READ ONLY refuses: INSERT, UPDATE
       and DELETE on an InnoDB and a MyISAM table, CREATE TABLE and TRUNCATE,
       CREATE TEMPORARY TABLE and an INSERT into a temporary table, WITH ...
       UPDATE and WITH ... DELETE, SELECT ... FOR UPDATE, FOR SHARE and LOCK
       IN SHARE MODE, a stored function that writes, called from a SELECT,
       with SQL SECURITY DEFINER and INVOKER, SELECT ... INTO OUTFILE and
       INTO DUMPFILE, SELECT ... INTO @v and GET_LOCK(). Each is rolled back.
       Then root reads each table, and whether the lock, the variable and the
       file are still there
  T2   PyMySQL's cursor.execute(text) with no parameters, on SELECT 1;
       SELECT 2 and on UPDATE ...; DELETE ..., and execute(text) and
       execute(text, ()) on a text with a % in a literal. Whether the
       session's client flags hold MULTI_STATEMENTS and FOUND_ROWS
  T3   executable comments: /*! ... */, /*!50700 ... */, /*!99999 ... */,
       /*M! ... */, /*M!100000 ... */ and SELECT 1 /*!, 2 */. Each inside a
       transaction that is rolled back: whether the content ran, by its rows
       and its row count
  T4   cursor.rowcount, without and with CLIENT.FOUND_ROWS: an UPDATE to the
       values the rows hold, an UPDATE that changes them, INSERT ... ON
       DUPLICATE KEY UPDATE for a new, a changed and an unchanged row, INSERT
       IGNORE, DELETE, a multi-table UPDATE and an UPDATE of no row
  T5   timeouts. The product's statement timer, at 500 ms, on SELECT SLEEP(2),
       a slow SELECT and UPDATE ... SET v = SLEEP(2). innodb_lock_wait_timeout
       on a row root holds locked, and lock_wait_timeout on a table root
       holds with LOCK TABLES WRITE: the error, the time, and whether the
       transaction's earlier write is still there. PyMySQL's read_timeout
       firing in a SELECT SLEEP(3) inside a transaction that holds a row
       lock: whether the connection is closed, and when root can lock the
       row and the thread is gone. Then a COMMIT that waits on root's FLUSH
       TABLES WITH READ LOCK, under the statement timer, lock_wait_timeout
       and read_timeout, and whether the row is kept
  T6   EXPLAIN of a multi-table UPDATE, a DELETE with a join, an INSERT ...
       SELECT, an UPDATE with a subquery, an UPDATE of a view over a MyISAM
       table, an UPDATE whose trigger writes a MyISAM table, and an UPDATE
       that calls a function that does: which tables each names. The engine
       of each table, as the run-as account reads it. Then a ROLLBACK after a
       MyISAM write, sent as a statement and with connection.rollback():
       the warnings PyMySQL reads, and what root reads afterwards
  T7   roles: what the account sopuli_probe_dba reads from
       information_schema.APPLICABLE_ROLES, SHOW GRANTS and CURRENT_ROLE()
       with no grant, granted the account sopuli_probe_svc as a role,
       inactive, active, as a default role, and through a role r1 that
       holds it. Whether it reads mysql.role_edges. Then root's GRANT PROXY
       ON sopuli_probe_svc TO sopuli_probe_dba, and its SHOW GRANTS
  T8   the Python type and value PyMySQL returns for each column type
  T9   CURRENT_USER(), USER(), DATABASE() and @@global.server_uuid, for an
       account with no grant and for the run-as account, with and without a
       database in the connection
  T10  what PyMySQL raises for a wrong password and for an account that does
       not exist, and what sopuli's driver (src/sopuli/driver/mysql/errors.py)
       makes of it

It MEASURES and decides nothing.

STATUS: run on 8.0.46, 8.4.13 and 9.7.4, the mysql:8.0, mysql:8.4 and
mysql:9 images of test/compose.yaml profile mysql-matrix, on 2026-11-27
(#1714). The client was PyMySQL 2.2.8, Python 3.13.12, on Windows 11 AMD64.
Twice, exit 0, the same result both times but for the timings, which are the
ranges below. Earlier runs, while the probe was written, are not counted.

RESULTS -- the same on every release, except where noted

  T1   START TRANSACTION READ ONLY refuses INSERT, UPDATE and DELETE on InnoDB
       and on MyISAM alike, 1792 "Cannot execute statement in a READ ONLY
       transaction.", and the table does not change. It refuses WITH ...
       UPDATE, WITH ... DELETE, SELECT ... FOR UPDATE, CREATE TEMPORARY
       TABLE, and each stored function that writes, DEFINER or INVOKER, to
       InnoDB or MyISAM, the same way. It does not refuse:
         CREATE TABLE and TRUNCATE TABLE. Each commits and runs: the table
           exists after the rollback, and TRUNCATE empties ti
         an INSERT into a temporary table made before the transaction. The
           rollback removes the row
         SELECT ... FOR SHARE and LOCK IN SHARE MODE. Each holds a shared
           lock on the row until the rollback: root's FOR UPDATE waits, 1205
         SELECT ... INTO OUTFILE and INTO DUMPFILE. The file is written, and
           is still there after the rollback
         SELECT ... INTO @v. @v keeps the value after the rollback
         GET_LOCK(). The session still holds the lock after the rollback
  T2   the session has neither MULTI_STATEMENTS nor FOUND_ROWS. execute() of
       SELECT 1; SELECT 2, and of UPDATE ...; DELETE ..., is refused, 1064,
       and no table changes. execute(text) with no parameters sends a % as
       written. execute(text, ()) formats the text in the client, and fails
       there: ProgrammingError "not enough arguments for format string"
  T3   /*! ... */ runs its content: SELECT 1 returns 1, and /*!50600,
       /*!50700 and /*!80000 DELETE delete the row. /*!99999 ... */ is a
       comment, and so are /*M! and /*M!100000: those DELETEs delete
       nothing. SELECT 1 /*!, 2 */ returns (1, 2), and /*! FOR UPDATE */ is
       part of the statement
  T4   without FOUND_ROWS, rowcount counts changed rows: an UPDATE to the
       values the rows hold counts 0. With FOUND_ROWS it counts matched rows:
       2. ON DUPLICATE KEY UPDATE counts 1 for a new row, 2 for a changed
       row, and 0, or 1 with FOUND_ROWS, for an unchanged one. INSERT IGNORE
       counts the rows inserted, 1 of 2, and DELETE the rows deleted, both
       ways. A multi-table UPDATE counts the rows of every table: 1 changed
       of 2 matched, and 0 of 4 when nothing changes. An UPDATE of no row
       counts 0 both ways
  T5   max_execution_time 500 interrupts a slow SELECT with 3024 after 0.50
       to 0.51 s. It cuts a SELECT SLEEP(2) short at 0.50 s too, but SLEEP
       returns 1 and there is no error. It does not bound an UPDATE: UPDATE
       ... SET v = SLEEP(2) runs for 2.00 s. innodb_lock_wait_timeout 1 ends
       a wait on root's row lock with 1205 after 1.00 s. With
       innodb_lock_wait_timeout 3 the timer does not cut the wait short:
       1205 after 3.00 s. lock_wait_timeout 1 ends a wait on root's LOCK
       TABLES WRITE with 1205 after 1.00 s. After each 1205 the transaction
       is still open, with its earlier write; innodb_rollback_on_timeout is
       0. The session runs the next statement after each. read_timeout 1 s
       raises 2013 after 1.00 to 1.02 s, and the connection is closed. The
       server goes on with the statement: root can lock the row, and the
       thread is gone, at 3.1 s, when the SLEEP ends. The write is rolled
       back. A COMMIT that waits on root's FLUSH TABLES WITH READ LOCK: the
       timer does not end it, and lock_wait_timeout 2 does, with 1205 after
       2.00 s; the row is not changed. With read_timeout 1 s the client
       gets 2013 after 1.00 to 1.01 s, but the COMMIT goes on waiting in the
       server, and it commits once root unlocks: the row reads 55
  T6   the run-as account reads each table's engine from
       information_schema.TABLES; a view's is NULL. EXPLAIN FORMAT=
       TRADITIONAL names both tables of a multi-table UPDATE, a DELETE with a
       join, an INSERT ... SELECT and the two UPDATEs with a subquery, and
       tm for the UPDATE of a view over it. It does not name a table that a
       trigger or a function writes: it gives only tt, and only ti. After a
       write to ti and tm, or to tm alone, a ROLLBACK gives warning 1196,
       sent as a statement or with connection.rollback(): SHOW WARNINGS
       reads it, and cursor.warning_count is 1 after a ROLLBACK sent as a
       statement. ti is rolled back and tm keeps its change.
       On 9.7.4, explain_format is TREE, which has no table column, so a
       plain EXPLAIN names no table. gtid_mode and enforce_gtid_consistency
       are ON there, and OFF on 8.0.46 and 8.4.13. So on 9.7.4 EXPLAIN of
       the UPDATE whose trigger writes tm, and of the one whose function
       does, is refused, 1785, and so is a write to tm after one to ti in a
       transaction; that ROLLBACK warns nothing, and tm keeps its value. A
       write to tm alone gives 1196, as on the others
  T7   activate_all_roles_on_login is 0. Root's GRANT of the account
       sopuli_probe_svc to sopuli_probe_dba, as a role, runs. sopuli_probe_
       dba, with no grant of its own, then reads the grant in
       information_schema.APPLICABLE_ROLES and SHOW GRANTS, whether the role
       is active or not. CURRENT_ROLE() is NONE until SET ROLE. The role's
       privileges are in SHOW GRANTS only while it is active. As the default
       role, IS_DEFAULT is YES, and it is active at login. Through the role
       r1, APPLICABLE_ROLES gives both edges, dba to r1 and r1 to svc, while
       r1 is inactive too; SHOW GRANTS gives only r1. mysql.role_edges is
       refused, 1142. Root at '%' is refused GRANT PROXY, 1698; root at
       localhost runs it, and SHOW GRANTS then gives "GRANT PROXY ON
       `sopuli_probe_svc`@`%` TO `sopuli_probe_dba`@`%`". APPLICABLE_ROLES
       does not show a proxy grant
  T8   DECIMAL is Decimal. BIGINT UNSIGNED, YEAR and TINYINT(1) are int, the
       largest BIGINT UNSIGNED whole. FLOAT and DOUBLE are float. JSON, ENUM,
       SET ('alpha,gamma'), TEXT, CHAR and VARCHAR are str; a TEXT of 5000
       characters comes back whole, and so does an emoji. BIT, BLOB, BINARY,
       VARBINARY and POINT are bytes: BINARY(4) padded with a zero byte, and
       POINT the server's own form, an SRID and WKB. DATE is date, DATETIME
       and TIMESTAMP datetime, and TIME timedelta: -12:34:56 is -1 day and
       41104 s, and 838:59:59 is 34 days and 82799 s. A zero date and a zero
       datetime are str, '0000-00-00' and '0000-00-00 00:00:00'. NULL is
       None
  T9   an account with no grant reads CURRENT_USER() as name@%, USER() as
       the name at the client's address, DATABASE() as NULL, and
       @@global.server_uuid. Its connection with a database is refused,
       1044. The run-as account reads DATABASE() as the database it
       connected with, or NULL
  T10  a wrong password and an account that does not exist both raise
       OperationalError 1045, "Access denied for user ... (using password:
       YES)". The driver makes AuthenticationError, code 1045, of both

  So START TRANSACTION READ ONLY stops every write to a table, MyISAM
  included, but not DDL, which commits first, and not a lock, a file, a user
  variable or GET_LOCK(), which outlive the rollback. EXPLAIN names the
  tables a statement reads and writes, but not those that its triggers and
  functions write. A timeout in the client does not stop the server: a
  COMMIT the client gave up on can still commit.

HOW TO RUN, against the matrix (test/README.md), from the repo root, with the
repo's virtual environment:

    .venv/Scripts/python sql/mysql/13_statement_run_probe.py

The ports follow SOPULI_TEST_MYSQL80_PORT, SOPULI_TEST_MYSQL84_PORT and
SOPULI_TEST_MYSQL9_PORT, so a second clone's servers are the ones it uses. T1
reads the OUTFILE through docker exec, in the container
{COMPOSE_PROJECT_NAME}-<service>-1. T10 imports sopuli from src/.
sql/mariadb/18_statement_run_probe.py runs the same steps on MariaDB.

THROWAWAY SERVERS ONLY. It creates the accounts sopuli_probe_runas,
sopuli_probe_nogrant, sopuli_probe_svc and sopuli_probe_dba, the role
sopuli_probe_r1 and the schema sopuli_probe, and drops them at the end. Before
it starts, it drops what an interrupted run left. A cleanup that fails is
printed, and the next release still runs.
"""

from __future__ import annotations

import contextlib
import os
import re
import subprocess
import sys
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

import pymysql
from pymysql.constants import CLIENT

PROJECT = os.environ.get("COMPOSE_PROJECT_NAME", "sopuli-test")
#: The matrix's public root password, from test/compose.yaml.
ROOT_PASSWORD = "sopuli-test"
SCHEMA = "sopuli_probe"
RUN_AS = "sopuli_probe_runas"
NOGRANT = "sopuli_probe_nogrant"
SVC = "sopuli_probe_svc"
DBA = "sopuli_probe_dba"
ROLE = "sopuli_probe_r1"
#: A test password, not a credential.
PASSWORD = "Acme-Runas-pw1"
LOCK_NAME = "sopuli_probe_lock"
#: The statement timer of T5, in milliseconds.
TIMER_MS = 500
#: The rows each table holds before each case.
BASELINE = ((1, 10), (2, 20), (3, 30))


@dataclass(frozen=True)
class Server:
    """One matrix server."""

    service: str
    port_variable: str
    default_port: int

    @property
    def port(self) -> int:
        return int(os.environ.get(self.port_variable, str(self.default_port)))

    @property
    def container(self) -> str:
        return f"{PROJECT}-{self.service}-1"


@dataclass(frozen=True)
class Product:
    """What differs between MySQL and MariaDB, for the steps below."""

    name: str
    servers: tuple[Server, ...]
    #: The tables T1 and T6 write that have no transactions.
    nontransactional: tuple[str, ...]
    #: Sets the statement timer to TIMER_MS for the session.
    timer: str
    #: The query that names the server.
    identity: str
    #: The driver module whose ``from_error`` T10 calls.
    errors_module: str
    #: The command-line client in the image.
    client: str = "mysql"
    #: How T6 asks for a plan with a ``table`` column. MySQL 9.7 defaults to
    #: the TREE format, which has none.
    explain: str = "EXPLAIN FORMAT=TRADITIONAL"
    #: The server settings T6 prints beside the plans.
    settings: str = "SELECT @@explain_format, @@global.gtid_mode, @@global.enforce_gtid_consistency"
    #: Extra column definitions and values for T8's table.
    extra_types: tuple[tuple[str, str, str], ...] = ()
    #: Extra T1 cases: (label, statement).
    extra_read_only: tuple[tuple[str, str], ...] = ()
    #: Extra T4 cases: (label, statement).
    extra_counts: tuple[tuple[str, str], ...] = ()
    mariadb: bool = False


MYSQL = Product(
    name="MySQL",
    servers=(
        Server("mysql-80", "SOPULI_TEST_MYSQL80_PORT", 3380),
        Server("mysql-84", "SOPULI_TEST_MYSQL84_PORT", 3384),
        Server("mysql-9", "SOPULI_TEST_MYSQL9_PORT", 3390),
    ),
    nontransactional=("tm",),
    timer=f"SET SESSION max_execution_time = {TIMER_MS}",
    identity="SELECT @@global.server_uuid",
    errors_module="sopuli.driver.mysql.errors",
)


def _outcome(error: BaseException) -> str:
    args = getattr(error, "args", ())
    if len(args) >= 2 and isinstance(args[0], int):
        return f"{args[0]} {str(args[1])[:110]}"
    return f"{type(error).__name__} {str(error)[:110]}"


@dataclass
class Ctx:
    """One server, as one release's run sees it."""

    product: Product
    server: Server
    release: str = ""
    #: The directory INTO OUTFILE writes to.
    file_dir: str = "/tmp/"
    notes: list[str] = field(default_factory=list)

    def connect(
        self,
        user: str = "root",
        password: str = ROOT_PASSWORD,
        *,
        database: str | None = None,
        autocommit: bool = True,
        client_flag: int = 0,
        read_timeout: float | None = None,
    ) -> pymysql.connections.Connection:  # type: ignore[type-arg]
        return pymysql.connect(
            host="127.0.0.1",
            port=self.server.port,
            user=user,
            password=password,
            database=database,
            autocommit=autocommit,
            client_flag=client_flag,
            read_timeout=read_timeout,
            connect_timeout=10,
        )

    def run_as(self, **kwargs: Any) -> pymysql.connections.Connection:  # type: ignore[type-arg]
        return self.connect(RUN_AS, PASSWORD, **kwargs)


def _one(conn: Any, statement: str) -> Any:
    with conn.cursor() as cur:
        cur.execute(statement)
        row = cur.fetchone()
    return None if row is None else row[0]


def _rows(conn: Any, statement: str) -> list[tuple[Any, ...]]:
    with conn.cursor() as cur:
        cur.execute(statement)
        return list(cur.fetchall())


def _exec(conn: Any, *statements: str) -> None:
    with conn.cursor() as cur:
        for statement in statements:
            cur.execute(statement)


def _try(conn: Any, statement: str) -> str:
    """``ran, rowcount N`` and any rows, or the error number and message."""
    try:
        with conn.cursor() as cur:
            cur.execute(statement)
            rows = cur.fetchall() if cur.description else ()
            shown = f", rows {list(rows)[:3]}" if rows else ""
            return f"ran, rowcount {cur.rowcount}{shown}"
    except pymysql.MySQLError as error:
        return _outcome(error)


def _warnings(conn: Any) -> str:
    shown = conn.show_warnings()
    return ", ".join(f"{level} {code}" for level, code, _ in shown) or "none"


TABLES = ("ti", "tm", "tj", "tt")


def _tables(ctx: Ctx) -> tuple[str, ...]:
    return TABLES + tuple(t for t in ctx.product.nontransactional if t not in TABLES)


def _reset(root: Any, ctx: Ctx) -> None:
    values = ", ".join(f"({i}, {v})" for i, v in BASELINE)
    for table in _tables(ctx):
        _exec(root, f"DELETE FROM {SCHEMA}.{table}")
        if table == "tj":
            _exec(root, f"INSERT INTO {SCHEMA}.tj VALUES (1, 100), (2, 200)")
        else:
            _exec(root, f"INSERT INTO {SCHEMA}.{table} VALUES {values}")


def _state(root: Any, ctx: Ctx) -> dict[str, str]:
    state = {}
    for table in _tables(ctx):
        state[table] = str(
            _one(
                root,
                f"SELECT GROUP_CONCAT(CONCAT(id, ':', {'w' if table == 'tj' else 'v'})"
                f" ORDER BY id SEPARATOR ',') FROM {SCHEMA}.{table}",
            )
        )
    return state


def _changed(before: dict[str, str], after: dict[str, str]) -> str:
    moved = [f"{t} {before[t]} -> {after[t]}" for t in before if before[t] != after[t]]
    return "; ".join(moved) or "no table changed"


def _docker(ctx: Ctx, *command: str) -> str:
    done = subprocess.run(
        ["docker", "exec", ctx.server.container, *command],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    return (done.stdout + done.stderr).strip() + f" (exit {done.returncode})"


# ---------------------------------------------------------------- fixture


def clean(ctx: Ctx) -> None:
    with ctx.connect() as root:
        _exec(root, f"DROP DATABASE IF EXISTS {SCHEMA}")
        for account in (RUN_AS, NOGRANT, SVC, DBA):
            _exec(root, f"DROP USER IF EXISTS '{account}'@'%'")
        if ctx.product.mariadb:
            _exec(root, f"DROP ROLE IF EXISTS {ROLE}")
        else:
            _exec(root, f"DROP ROLE IF EXISTS '{ROLE}'")


def setup(ctx: Ctx) -> None:
    with ctx.connect() as root:
        _exec(
            root,
            f"CREATE DATABASE {SCHEMA} CHARACTER SET utf8mb4",
            f"CREATE TABLE {SCHEMA}.ti (id INT PRIMARY KEY, v INT) ENGINE=InnoDB",
            f"CREATE TABLE {SCHEMA}.tm (id INT PRIMARY KEY, v INT) ENGINE=MyISAM",
            f"CREATE TABLE {SCHEMA}.tj (id INT PRIMARY KEY, w INT) ENGINE=InnoDB",
            f"CREATE TABLE {SCHEMA}.tt (id INT PRIMARY KEY, v INT) ENGINE=InnoDB",
            f"CREATE VIEW {SCHEMA}.vm AS SELECT id, v FROM {SCHEMA}.tm",
            f"CREATE TRIGGER {SCHEMA}.tt_au AFTER UPDATE ON {SCHEMA}.tt FOR EACH ROW"
            f" UPDATE {SCHEMA}.tm SET v = NEW.v WHERE id = NEW.id",
            f"CREATE TABLE {SCHEMA}.d (n INT PRIMARY KEY)",
            f"INSERT INTO {SCHEMA}.d VALUES (0),(1),(2),(3),(4),(5),(6),(7),(8),(9)",
            f"CREATE TABLE {SCHEMA}.big (n INT PRIMARY KEY)",
            f"INSERT INTO {SCHEMA}.big SELECT a.n * 100 + b.n * 10 + c.n + 1"
            f" FROM {SCHEMA}.d a, {SCHEMA}.d b, {SCHEMA}.d c",
        )
        if ctx.product.mariadb:
            _exec(
                root,
                f"CREATE TABLE {SCHEMA}.ta (id INT PRIMARY KEY, v INT) ENGINE=Aria",
                f"CREATE SEQUENCE {SCHEMA}.s NOCACHE",
            )
        # The functions are root's. DETERMINISTIC lets root create them with
        # the binary log on; nothing here relies on it being true.
        for name, security, table in (
            ("wd", "DEFINER", "ti"),
            ("wi", "INVOKER", "ti"),
            ("wdm", "DEFINER", "tm"),
        ):
            _exec(
                root,
                f"CREATE FUNCTION {SCHEMA}.{name}() RETURNS INT DETERMINISTIC MODIFIES SQL DATA"
                f" SQL SECURITY {security}"
                f" BEGIN UPDATE {SCHEMA}.{table} SET v = v + 1 WHERE id = 1; RETURN 1; END",
            )
        _exec(
            root,
            f"CREATE USER '{RUN_AS}'@'%' IDENTIFIED BY '{PASSWORD}'",
            f"GRANT ALL ON {SCHEMA}.* TO '{RUN_AS}'@'%'",
            f"GRANT FILE ON *.* TO '{RUN_AS}'@'%'",
            f"CREATE USER '{NOGRANT}'@'%' IDENTIFIED BY '{PASSWORD}'",
            f"CREATE USER '{SVC}'@'%' IDENTIFIED BY '{PASSWORD}'",
            f"GRANT SELECT ON {SCHEMA}.* TO '{SVC}'@'%'",
            f"CREATE USER '{DBA}'@'%' IDENTIFIED BY '{PASSWORD}'",
        )
        _reset(root, ctx)
        priv = _one(root, "SELECT @@secure_file_priv")
        ctx.file_dir = priv if priv else "/tmp/"


# ---------------------------------------------------------------- T1


def _t1_case(
    ctx: Ctx,
    label: str,
    statement: str,
    *,
    before: Iterable[str] = (),
    inside: Callable[[Any, Any], str] | None = None,
    after: Callable[[Any, Any], str] | None = None,
) -> None:
    with ctx.connect() as root:
        _reset(root, ctx)
        start = _state(root, ctx)
        with ctx.run_as() as conn:
            _exec(conn, *before)
            _exec(conn, "START TRANSACTION READ ONLY")
            outcome = _try(conn, statement)
            extra = f"; inside: {inside(conn, root)}" if inside else ""
            _exec(conn, "ROLLBACK")
            if after:
                extra += f"; after the rollback: {after(conn, root)}"
            end = _state(root, ctx)
    print(f"  T1   {label}: {outcome}; {_changed(start, end)}{extra}")


def _locked_by_other(_conn: Any, root: Any) -> str:
    """Whether root can lock row 1 of ti while the run-as transaction is open."""
    _exec(root, "SET SESSION innodb_lock_wait_timeout = 1")
    _exec(root, "START TRANSACTION")
    try:
        got = _try(root, f"SELECT v FROM {SCHEMA}.ti WHERE id = 1 FOR UPDATE")
    finally:
        _exec(root, "ROLLBACK")
    return f"root's FOR UPDATE of the row: {got}"


def _created(name: str) -> Callable[[Any, Any], str]:
    def check(_conn: Any, root: Any) -> str:
        found = _one(
            root,
            "SELECT COUNT(*) FROM information_schema.TABLES"
            f" WHERE TABLE_SCHEMA = '{SCHEMA}' AND TABLE_NAME = '{name}'",
        )
        if found:
            _exec(root, f"DROP TABLE {SCHEMA}.{name}")
        return f"table {name} exists: {bool(found)}"

    return check


def _temp_rows(conn: Any, _root: Any) -> str:
    return f"the temporary table holds {_rows(conn, 'SELECT n FROM tmp')}"


def _variable(conn: Any, _root: Any) -> str:
    return f"@v = {_one(conn, 'SELECT @v')}"


def _lock_held(conn: Any, root: Any) -> str:
    holder = _one(root, f"SELECT IS_USED_LOCK('{LOCK_NAME}')")
    mine = _one(conn, "SELECT CONNECTION_ID()")
    _exec(conn, f"DO RELEASE_LOCK('{LOCK_NAME}')")
    return f"the lock is held by the run-as session: {holder == mine}"


def _file(ctx: Ctx, path: str) -> Callable[[Any, Any], str]:
    def check(_conn: Any, _root: Any) -> str:
        there = _docker(ctx, "sh", "-c", f"test -f {path} && wc -c < {path}")
        _docker(ctx, "rm", "-f", path)
        return f"the file: {there}"

    return check


def _sequence(_conn: Any, root: Any) -> str:
    return f"next_not_cached_value {_one(root, f'SELECT next_not_cached_value FROM {SCHEMA}.s')}"


def t1(ctx: Ctx) -> None:
    s = SCHEMA
    for table in ("ti", *ctx.product.nontransactional):
        _t1_case(ctx, f"INSERT into {table}", f"INSERT INTO {s}.{table} VALUES (9, 90)")
        _t1_case(ctx, f"UPDATE of {table}", f"UPDATE {s}.{table} SET v = v + 1 WHERE id = 1")
        _t1_case(ctx, f"DELETE from {table}", f"DELETE FROM {s}.{table} WHERE id = 1")
    _t1_case(ctx, "CREATE TABLE", f"CREATE TABLE {s}.newt (n INT)", after=_created("newt"))
    _t1_case(ctx, "TRUNCATE ti", f"TRUNCATE TABLE {s}.ti")
    _t1_case(
        ctx,
        "CREATE TEMPORARY TABLE",
        f"CREATE TEMPORARY TABLE {s}.tmp2 (n INT)",
        after=lambda conn, _root: _try(conn, f"SELECT COUNT(*) FROM {s}.tmp2"),
    )
    _t1_case(
        ctx,
        "INSERT into a temporary table",
        "INSERT INTO tmp VALUES (1)",
        before=(f"USE {s}", "CREATE TEMPORARY TABLE tmp (n INT) ENGINE=InnoDB"),
        after=_temp_rows,
    )
    _t1_case(
        ctx,
        "WITH ... UPDATE",
        f"WITH x AS (SELECT 1 AS id) UPDATE {s}.ti, x SET ti.v = ti.v + 1 WHERE ti.id = x.id",
    )
    _t1_case(
        ctx,
        "WITH ... DELETE",
        f"WITH x AS (SELECT 2 AS id) DELETE {s}.ti FROM {s}.ti JOIN x ON ti.id = x.id",
    )
    for clause in ("FOR UPDATE", "FOR SHARE", "LOCK IN SHARE MODE"):
        _t1_case(
            ctx,
            f"SELECT ... {clause}",
            f"SELECT v FROM {s}.ti WHERE id = 1 {clause}",
            inside=_locked_by_other,
        )
    for name, label in (
        ("wd", "a DEFINER function that writes ti"),
        ("wi", "an INVOKER function that writes ti"),
        ("wdm", "a DEFINER function that writes tm"),
    ):
        _t1_case(ctx, f"SELECT {label}", f"SELECT {s}.{name}()")
    for kind in ("OUTFILE", "DUMPFILE"):
        path = f"{ctx.file_dir.rstrip('/')}/sopuli_probe_{kind.lower()}_{os.getpid()}"
        _t1_case(
            ctx,
            f"SELECT ... INTO {kind}",
            f"SELECT v FROM {s}.ti WHERE id = 1 INTO {kind} '{path}'",
            after=_file(ctx, path),
        )
    _t1_case(
        ctx, "SELECT ... INTO @v", f"SELECT v FROM {s}.ti WHERE id = 1 INTO @v", after=_variable
    )
    _t1_case(ctx, "GET_LOCK()", f"SELECT GET_LOCK('{LOCK_NAME}', 0)", after=_lock_held)
    for label, statement in ctx.product.extra_read_only:
        _t1_case(
            ctx,
            label,
            statement.format(s=s),
            after=_sequence if "NEXTVAL" in statement else None,
        )


# ---------------------------------------------------------------- T2


def t2(ctx: Ctx) -> None:
    with ctx.run_as() as conn:
        flags = conn.client_flag
        print(
            f"  T2   client flags: MULTI_STATEMENTS {bool(flags & CLIENT.MULTI_STATEMENTS)},"
            f" FOUND_ROWS {bool(flags & CLIENT.FOUND_ROWS)}"
        )
    with ctx.connect() as root:
        _reset(root, ctx)
        start = _state(root, ctx)
        with ctx.run_as() as conn:
            for text in (
                "SELECT 1; SELECT 2",
                f"UPDATE {SCHEMA}.ti SET v = 0 WHERE id = 1; DELETE FROM {SCHEMA}.ti WHERE id = 2",
            ):
                print(f"  T2   execute({text!r}): {_try(conn, text)}")
            for args in (None, ()):
                try:
                    with conn.cursor() as cur:
                        cur.execute("SELECT '100%' AS p, 'a%sb' AS q", args)
                        got = f"rows {cur.fetchall()}"
                except Exception as error:  # noqa: BLE001 -- printed
                    got = _outcome(error)
                print(f"  T2   execute(\"SELECT '100%', 'a%sb'\", {args!r}): {got}")
        print(f"  T2   afterwards: {_changed(start, _state(root, ctx))}")


# ---------------------------------------------------------------- T3


def t3(ctx: Ctx) -> None:
    ti = f"{SCHEMA}.ti"
    with ctx.connect() as root:
        _reset(root, ctx)
    with ctx.run_as() as conn:
        for text in (
            "/*! SELECT 1 */",
            f"/*!50600 DELETE FROM {ti} WHERE id = 3 */",
            f"/*!50700 DELETE FROM {ti} WHERE id = 3 */",
            f"/*!80000 DELETE FROM {ti} WHERE id = 3 */",
            f"/*!99999 DELETE FROM {ti} WHERE id = 3 */",
            f"/*M! DELETE FROM {ti} WHERE id = 3 */",
            f"/*M!100000 DELETE FROM {ti} WHERE id = 3 */",
            "SELECT 1 /*!, 2 */",
            f"SELECT v FROM {ti} WHERE id = 1 /*! FOR UPDATE */",
        ):
            _exec(conn, "START TRANSACTION")
            print(f"  T3   {text!r}: {_try(conn, text)}")
            _exec(conn, "ROLLBACK")


# ---------------------------------------------------------------- T4


def t4(ctx: Ctx) -> None:
    s = SCHEMA
    cases = [
        ("UPDATE to the same values", f"UPDATE {s}.ti SET v = v WHERE id IN (1, 2)"),
        ("UPDATE that changes one", f"UPDATE {s}.ti SET v = 11 WHERE id = 1"),
        (
            "ON DUPLICATE KEY UPDATE, a new row",
            f"INSERT INTO {s}.ti VALUES (4, 40) ON DUPLICATE KEY UPDATE v = 40",
        ),
        (
            "ON DUPLICATE KEY UPDATE, a changed row",
            f"INSERT INTO {s}.ti VALUES (1, 99) ON DUPLICATE KEY UPDATE v = 99",
        ),
        (
            "ON DUPLICATE KEY UPDATE, an unchanged row",
            f"INSERT INTO {s}.ti VALUES (1, 10) ON DUPLICATE KEY UPDATE v = 10",
        ),
        ("INSERT IGNORE, one new of two", f"INSERT IGNORE INTO {s}.ti VALUES (1, 5), (5, 50)"),
        ("DELETE of one row", f"DELETE FROM {s}.ti WHERE id = 2"),
        (
            "multi-table UPDATE, one changed and one not",
            f"UPDATE {s}.ti, {s}.tj SET ti.v = ti.v + 1, tj.w = tj.w"
            " WHERE ti.id = tj.id AND ti.id = 1",
        ),
        (
            "multi-table UPDATE, both unchanged",
            f"UPDATE {s}.ti, {s}.tj SET ti.v = ti.v, tj.w = tj.w WHERE ti.id = tj.id",
        ),
        ("UPDATE of no row", f"UPDATE {s}.ti SET v = 0 WHERE id = 99"),
        *ctx.product.extra_counts,
    ]
    with ctx.connect() as root:
        _reset(root, ctx)
    with ctx.run_as() as plain, ctx.run_as(client_flag=CLIENT.FOUND_ROWS) as found:
        for label, statement in cases:
            counts = []
            for conn in (plain, found):
                _exec(conn, "START TRANSACTION")
                with conn.cursor() as cur:
                    cur.execute(statement.format(s=s))
                    if cur.description:
                        cur.fetchall()
                    counts.append(cur.rowcount)
                _exec(conn, "ROLLBACK")
            print(f"  T4   {label}: rowcount {counts[0]}, with FOUND_ROWS {counts[1]}")


# ---------------------------------------------------------------- T5


def _timed(conn: Any, statement: str) -> str:
    started = time.monotonic()
    got = _try(conn, statement)
    return f"{got} after {time.monotonic() - started:.2f} s"


def _in_transaction(ctx: Ctx, conn: Any) -> str:
    """Whether the earlier write of the transaction is still there."""
    own = _one(conn, f"SELECT w FROM {SCHEMA}.tj WHERE id = 1")
    state = f"its earlier write is still there: {own == 101}"
    if ctx.product.mariadb:
        state += f", @@in_transaction {_one(conn, 'SELECT @@in_transaction')}"
    return state


def t5(ctx: Ctx) -> None:
    s = SCHEMA
    slow = f"SELECT COUNT(*) FROM {s}.big a, {s}.big b, {s}.big c WHERE a.n + b.n + c.n > 0"
    with ctx.connect() as root:
        _reset(root, ctx)
    with ctx.run_as() as conn:
        _exec(conn, ctx.product.timer)
        for label, statement in (
            ("SELECT SLEEP(2)", "SELECT SLEEP(2)"),
            ("a slow SELECT", slow),
            ("UPDATE ... SET v = SLEEP(2)", f"UPDATE {s}.ti SET v = SLEEP(2) WHERE id = 1"),
        ):
            _exec(conn, "START TRANSACTION")
            print(f"  T5   timer {TIMER_MS} ms, {label}: {_timed(conn, statement)}")
            _exec(conn, "ROLLBACK")
            print(f"  T5     then SELECT 1: {_try(conn, 'SELECT 1')}")

    # A row lock root holds, with innodb_lock_wait_timeout, and with the timer.
    for label, settings in (
        ("innodb_lock_wait_timeout 1", ("SET SESSION innodb_lock_wait_timeout = 1",)),
        (
            f"innodb_lock_wait_timeout 3 and the timer {TIMER_MS} ms",
            ("SET SESSION innodb_lock_wait_timeout = 3", ctx.product.timer),
        ),
    ):
        with ctx.connect() as root, ctx.run_as() as conn:
            _exec(conn, *settings)
            _exec(root, "START TRANSACTION", f"SELECT v FROM {s}.ti WHERE id = 1 FOR UPDATE")
            try:
                _exec(conn, "START TRANSACTION", f"UPDATE {s}.tj SET w = 101 WHERE id = 1")
                got = _timed(conn, f"UPDATE {s}.ti SET v = v + 1 WHERE id = 1")
                state = _in_transaction(ctx, conn)
                _exec(conn, "ROLLBACK")
            finally:
                _exec(root, "ROLLBACK")
            print(f"  T5   a row root holds, {label}: {got}; {state}")
        with ctx.connect() as root:
            _reset(root, ctx)
    with ctx.connect() as root:
        print(
            "  T5   innodb_rollback_on_timeout"
            f" {_one(root, 'SELECT @@global.innodb_rollback_on_timeout')}"
        )

    # A metadata lock root holds, with lock_wait_timeout.
    with ctx.connect() as root, ctx.run_as() as conn:
        _exec(conn, "SET SESSION lock_wait_timeout = 1")
        _exec(conn, "START TRANSACTION", f"UPDATE {s}.tj SET w = 101 WHERE id = 1")
        _exec(root, f"LOCK TABLES {s}.ti WRITE")
        try:
            got = _timed(conn, f"SELECT v FROM {s}.ti WHERE id = 1")
            state = _in_transaction(ctx, conn)
            _exec(conn, "ROLLBACK")
        finally:
            _exec(root, "UNLOCK TABLES")
        print(
            f"  T5   a table root holds with LOCK TABLES WRITE, lock_wait_timeout 1: {got}; {state}"
        )
    with ctx.connect() as root:
        _reset(root, ctx)

    _t5_read_timeout(ctx)
    _t5_commit(ctx)


def _t5_read_timeout(ctx: Ctx) -> None:
    s = SCHEMA
    with ctx.connect() as root:
        conn = ctx.run_as(read_timeout=1)
        thread = _one(conn, "SELECT CONNECTION_ID()")
        _exec(conn, "START TRANSACTION", f"UPDATE {s}.ti SET v = 77 WHERE id = 1")
        started = time.monotonic()
        try:
            got = _try(conn, "SELECT SLEEP(3)")
        except Exception as error:  # noqa: BLE001 -- printed
            got = _outcome(error)
        raised = time.monotonic() - started
        is_open = conn.open
        free_at = gone_at = None
        _exec(root, "SET SESSION innodb_lock_wait_timeout = 1")
        while time.monotonic() - started < 12 and (free_at is None or gone_at is None):
            if gone_at is None and not _one(
                root, f"SELECT COUNT(*) FROM information_schema.PROCESSLIST WHERE ID = {thread}"
            ):
                gone_at = time.monotonic() - started
            if free_at is None:
                _exec(root, "START TRANSACTION")
                try:
                    with root.cursor() as cur:
                        cur.execute(f"SELECT v FROM {s}.ti WHERE id = 1 FOR UPDATE NOWAIT")
                        value = cur.fetchone()
                    free_at = time.monotonic() - started
                    kept = value
                except pymysql.MySQLError:
                    pass
                finally:
                    _exec(root, "ROLLBACK")
            time.sleep(0.2)
        with contextlib.suppress(Exception):  # the connection may already be gone
            conn.close()

    def at(t: float | None) -> str:
        return "not within 12 s" if t is None else f"at {t:.1f} s"

    print(
        f"  T5   read_timeout 1 s, SELECT SLEEP(3) holding a row lock: {got} after {raised:.2f} s;"
        f" connection open {is_open}; root locks the row {at(free_at)}"
        f"{f' and reads v = {kept[0]}' if free_at is not None else ''};"
        f" the thread is gone {at(gone_at)}"
    )
    with ctx.connect() as root:
        _reset(root, ctx)


def _t5_commit(ctx: Ctx) -> None:
    s = SCHEMA
    for label, settings, read_timeout in (
        (
            f"the timer {TIMER_MS} ms and lock_wait_timeout 2",
            (ctx.product.timer, "SET SESSION lock_wait_timeout = 2"),
            None,
        ),
        ("read_timeout 1 s", (), 1),
    ):
        with ctx.connect() as root:
            _reset(root, ctx)
            conn = ctx.run_as(read_timeout=read_timeout)
            _exec(conn, *settings)
            _exec(conn, "START TRANSACTION", f"UPDATE {s}.ti SET v = 55 WHERE id = 3")
            _exec(root, "FLUSH TABLES WITH READ LOCK")
            try:
                started = time.monotonic()
                try:
                    conn.commit()
                    got = "committed"
                except Exception as error:  # noqa: BLE001 -- printed
                    got = _outcome(error)
                took = time.monotonic() - started
                time.sleep(1)
            finally:
                _exec(root, "UNLOCK TABLES")
            time.sleep(1)
            kept = _one(root, f"SELECT v FROM {s}.ti WHERE id = 3")
            with contextlib.suppress(Exception):  # the connection may already be gone
                conn.close()
        print(
            f"  T5   a COMMIT waiting on FLUSH TABLES WITH READ LOCK, {label}: {got}"
            f" after {took:.2f} s; after UNLOCK TABLES the row reads v = {kept}"
        )
    with ctx.connect() as root:
        _reset(root, ctx)


# ---------------------------------------------------------------- T6


def _explain_tables(conn: Any, explain: str, statement: str) -> str:
    try:
        with conn.cursor(pymysql.cursors.DictCursor) as cur:
            cur.execute(f"{explain} {statement}")
            tables = [str(row.get("table")) for row in cur.fetchall()]
        return ", ".join(tables)
    except pymysql.MySQLError as error:
        return _outcome(error)


def t6(ctx: Ctx) -> None:
    s = SCHEMA
    with ctx.run_as() as conn:
        engines = _rows(
            conn,
            "SELECT TABLE_NAME, COALESCE(ENGINE, 'NULL') FROM information_schema.TABLES"
            f" WHERE TABLE_SCHEMA = '{s}' ORDER BY TABLE_NAME",
        )
        print(f"  T6   engines, as the run-as account reads them: {engines}")
        print(f"  T6   settings: {_try(conn, ctx.product.settings)}")
        for label, statement in (
            ("multi-table UPDATE", f"UPDATE {s}.ti, {s}.tm SET ti.v = tm.v WHERE ti.id = tm.id"),
            (
                "DELETE with a join",
                f"DELETE {s}.ti FROM {s}.ti JOIN {s}.tm ON ti.id = tm.id",
            ),
            ("INSERT ... SELECT", f"INSERT INTO {s}.ti SELECT id + 10, v FROM {s}.tm"),
            (
                "UPDATE with a subquery",
                f"UPDATE {s}.ti SET v = (SELECT MAX(v) FROM {s}.tm) WHERE id = 1",
            ),
            (
                "UPDATE with IN (subquery)",
                f"UPDATE {s}.ti SET v = 1 WHERE id IN (SELECT id FROM {s}.tm)",
            ),
            ("UPDATE of a view over tm", f"UPDATE {s}.vm SET v = 1 WHERE id = 1"),
            ("UPDATE of tt, whose trigger writes tm", f"UPDATE {s}.tt SET v = 1 WHERE id = 1"),
            (
                "UPDATE of ti calling a function that writes tm",
                f"UPDATE {s}.ti SET v = {s}.wdm() WHERE id = 1",
            ),
        ):
            tables = _explain_tables(conn, ctx.product.explain, statement)
            print(f"  T6   {ctx.product.explain} {label}: tables {tables}")

    cases = [(f"ti and {t}", ("ti", t)) for t in ctx.product.nontransactional]
    cases += [(f"{t} alone", (t,)) for t in ctx.product.nontransactional]
    for label, tables in cases:
        table = tables[-1]
        for how in ("ROLLBACK as a statement", "connection.rollback()"):
            with ctx.connect() as root:
                _reset(root, ctx)
                with ctx.run_as() as conn:
                    _exec(conn, "START TRANSACTION")
                    writes = [_try(conn, f"UPDATE {s}.{t} SET v = 0 WHERE id = 1") for t in tables]
                    if how == "connection.rollback()":
                        conn.rollback()
                        count = "not read"
                    else:
                        with conn.cursor() as cur:
                            cur.execute("ROLLBACK")
                            count = str(getattr(cur, "warning_count", "no attribute"))
                    warned = _warnings(conn)
                ti_v = _one(root, f"SELECT v FROM {s}.ti WHERE id = 1")
                other_v = _one(root, f"SELECT v FROM {s}.{table} WHERE id = 1")
            print(
                f"  T6   a write to {label}: {' / '.join(writes)}; then {how}:"
                f" warning_count {count}, SHOW WARNINGS {warned};"
                f" root reads ti v = {ti_v}, {table} v = {other_v}"
            )
    with ctx.connect() as root:
        _reset(root, ctx)


# ---------------------------------------------------------------- T7


def _dba_reads(ctx: Ctx, label: str, before: Iterable[str] = ()) -> None:
    with ctx.connect(DBA, PASSWORD) as conn:
        _exec(conn, *before)
        roles = _rows(
            conn,
            "SELECT * FROM information_schema.APPLICABLE_ROLES",
        )
        # MariaDB's SHOW GRANTS holds the stored hash; it is never printed.
        grants = [
            re.sub(r"PASSWORD '[^']*'", "PASSWORD '<hash>'", row[0])
            for row in _rows(conn, "SHOW GRANTS")
        ]
        current = _try(conn, "SELECT CURRENT_ROLE()")
        edges = _try(conn, "SELECT COUNT(*) FROM mysql.role_edges")
    print(
        f"  T7   {label}: APPLICABLE_ROLES {roles}; SHOW GRANTS {grants};"
        f" CURRENT_ROLE() {current}; mysql.role_edges {edges}"
    )


def t7(ctx: Ctx) -> None:
    svc = f"'{SVC}'@'%'"
    dba = f"'{DBA}'@'%'"
    with ctx.connect() as root:
        print(
            "  T7   activate_all_roles_on_login"
            f" {_try(root, 'SELECT @@global.activate_all_roles_on_login')}"
        )
    _dba_reads(ctx, "no grant")
    with ctx.connect() as root:
        granted = _try(root, f"GRANT {svc} TO {dba}")
    print(f"  T7   root's GRANT {svc} TO {dba}: {granted}")
    if granted.startswith("ran"):
        _dba_reads(ctx, "granted, inactive")
        _dba_reads(ctx, "granted, after SET ROLE", (f"SET ROLE {svc}",))
        with ctx.connect() as root:
            _exec(root, f"SET DEFAULT ROLE {svc} TO {dba}")
        _dba_reads(ctx, "granted, as the default role")
        with ctx.connect() as root:
            _exec(root, f"SET DEFAULT ROLE NONE TO {dba}", f"REVOKE {svc} FROM {dba}")
            _exec(
                root,
                f"CREATE ROLE '{ROLE}'",
                f"GRANT {svc} TO '{ROLE}'",
                f"GRANT '{ROLE}' TO {dba}",
            )
        _dba_reads(ctx, f"through role {ROLE}, inactive")
        _dba_reads(ctx, f"through role {ROLE}, after SET ROLE ALL", ("SET ROLE ALL",))
        with ctx.connect() as root:
            _exec(root, f"REVOKE '{ROLE}' FROM {dba}")
    statement = f"GRANT PROXY ON {svc} TO {dba}"
    with ctx.connect() as root:
        proxy = _try(root, statement)
    print(f"  T7   root@'%''s {statement}: {proxy}")
    # Only root@localhost holds PROXY ON ''@'' WITH GRANT OPTION in the image.
    local = _docker(
        ctx, ctx.product.client, "-uroot", f"-p{ROOT_PASSWORD}", "-e", statement.replace("'", '"')
    )
    print(f"  T7   root@localhost's {statement}, in the container: {local}")
    _dba_reads(ctx, "after GRANT PROXY")


# ---------------------------------------------------------------- T8


TYPES: tuple[tuple[str, str, str], ...] = (
    ("c_decimal", "DECIMAL(20,6)", "12345.678900"),
    ("c_ubig", "BIGINT UNSIGNED", "18446744073709551615"),
    ("c_json", "JSON", "'{\"a\": [1, 2]}'"),
    ("c_bit", "BIT(10)", "b'1010101010'"),
    ("c_blob", "BLOB", "x'00FF10'"),
    ("c_binary", "BINARY(4)", "x'00FF10'"),
    ("c_varbinary", "VARBINARY(4)", "x'00FF'"),
    ("c_text", "TEXT", "REPEAT('x', 5000)"),
    ("c_date", "DATE", "'2026-11-27'"),
    ("c_datetime", "DATETIME(6)", "'2026-11-27 12:34:56.123456'"),
    ("c_timestamp", "TIMESTAMP NULL", "'2026-11-27 12:34:56'"),
    ("c_time_neg", "TIME", "'-12:34:56'"),
    ("c_time_big", "TIME", "'838:59:59'"),
    ("c_year", "YEAR", "2026"),
    ("c_enum", "ENUM('alpha','beta')", "'beta'"),
    ("c_set", "SET('alpha','beta','gamma')", "'alpha,gamma'"),
    ("c_point", "POINT", "ST_GeomFromText('POINT(1 2)')"),
    ("c_zero_date", "DATE", "'0000-00-00'"),
    ("c_zero_datetime", "DATETIME", "'0000-00-00 00:00:00'"),
    ("c_float", "FLOAT", "1.1"),
    ("c_double", "DOUBLE", "1.1"),
    ("c_tinyint1", "TINYINT(1)", "1"),
    ("c_char", "CHAR(5)", "'ab'"),
    ("c_utf8", "VARCHAR(10)", "'é€\U0001f600'"),
    ("c_null", "INT NULL", "NULL"),
)


def t8(ctx: Ctx) -> None:
    types = TYPES + ctx.product.extra_types
    columns = ", ".join(f"{name} {kind}" for name, kind, _ in types)
    values = ", ".join(value for _, _, value in types)
    with ctx.connect() as root:
        _exec(
            root,
            "SET SESSION sql_mode = ''",
            f"CREATE TABLE {SCHEMA}.tv ({columns}) CHARACTER SET utf8mb4",
            f"INSERT INTO {SCHEMA}.tv VALUES ({values})",
        )
    with ctx.run_as() as conn, conn.cursor() as cur:
        cur.execute(f"SELECT * FROM {SCHEMA}.tv")
        row = cur.fetchone()
        names = [d[0] for d in cur.description]
    for (name, kind, _), value in zip(types, row, strict=True):
        assert name in names
        shown = f"len {len(value)}" if name == "c_text" else repr(value)[:70]
        print(f"  T8   {kind}: {type(value).__name__} {shown}")


# ---------------------------------------------------------------- T9, T10


def t9(ctx: Ctx) -> None:
    query = f"SELECT CURRENT_USER(), USER(), DATABASE(), ({ctx.product.identity[7:]})"
    for user, database in ((NOGRANT, None), (NOGRANT, SCHEMA), (RUN_AS, None), (RUN_AS, SCHEMA)):
        try:
            with ctx.connect(user, PASSWORD, database=database) as conn:
                got = str(_rows(conn, query)[0])
        except pymysql.MySQLError as error:
            got = _outcome(error)
        print(f"  T9   {user}, database {database}: {got}")


def t10(ctx: Ctx) -> None:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))
    import importlib

    from sopuli.driver.protocol import AuthenticationError

    errors = importlib.import_module(ctx.product.errors_module)
    for label, user in (
        ("wrong password", RUN_AS),
        ("account that does not exist", "sopuli_probe_none"),
    ):
        try:
            ctx.connect(user, "not-the-password").close()
            print(f"  T10  {label}: logged in")
        except pymysql.MySQLError as error:
            raised = errors.from_error(error, connecting=True).as_error()
            print(
                f"  T10  {label}: {type(error).__name__} {_outcome(error)}; the driver raises"
                f" {type(raised).__name__} (AuthenticationError:"
                f" {isinstance(raised, AuthenticationError)}), code {raised.code}"
            )


# ---------------------------------------------------------------- main

STEPS = (t1, t2, t3, t4, t5, t6, t7, t8, t9, t10)


def probe(ctx: Ctx) -> None:
    with ctx.connect() as root:
        ctx.release = str(_one(root, "SELECT VERSION()"))
    print(f"{ctx.product.name} {ctx.release} ({ctx.server.service}, port {ctx.server.port})")
    clean(ctx)
    try:
        setup(ctx)
        for step in STEPS:
            step(ctx)
    finally:
        # A cleanup that fails is printed, not raised, so it cannot hide the
        # failure of a step before it.
        try:
            clean(ctx)
        except Exception as error:  # noqa: BLE001 -- printed, the run goes on
            print(f"  cleanup failed: {type(error).__name__}: {error}")


def main(product: Product = MYSQL) -> int:
    # T8 prints a value outside the Windows console's code page.
    sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[union-attr]
    print(f"PyMySQL {pymysql.__version__}, Python {sys.version.split()[0]}")
    only = sys.argv[1:]
    failed = 0
    for server in product.servers:
        if only and server.service not in only:
            continue
        ctx = Ctx(product, server)
        try:
            probe(ctx)
        except Exception as error:  # noqa: BLE001 -- one release's failure; the rest still run
            failed += 1
            print(f"{server.service} (port {server.port}): FAILED: {type(error).__name__}: {error}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
