"""sopuli-dba : what `sql run` on SQL Server relies on

#1729, for UC-3 on SQL Server (#1727) and the decisions in #1728. It
measures, through pyodbc and ODBC Driver 18, what the runner and its checks
will rely on:

  S1   the statement list: what row sets `SET SHOWPLAN_ALL ON` gives for each
       form, whether any of it runs, and which `SHOWPLAN` grants it needs
  S2   a transaction with `XACT_ABORT ON` that rolls back, as the read guard:
       what it undoes and what it does not, and a loopback linked server
  S3   one batch of two statements through pyodbc, `GO`, and a `?`
  S4   comments, literals and names, for the dialect
  S5   row counts as pyodbc reads them, triggers included, and `@@ROWCOUNT`
  S6   timeouts: `LOCK_TIMEOUT`, the query timeout, a deadlock and
       `cursor.cancel()`, and the transaction after each
  S7   stopping early in a large result
  S8   what pyodbc returns for each type
  S9   who and where: the login and database functions
  S10  `IMPERSONATE`: what `HAS_PERMS_BY_NAME` and a login's own catalogue
       show

Every case runs as a login with no server role, granted only what the case
says, unless it names `sysadmin`. The session's database is `master`, as
UC-3's will be (#1728, Q3), and every other object is named by its
three-part name. A refused statement shows the SQLSTATE and the server's
number that the ODBC driver puts in parentheses after its message.

It MEASURES and decides nothing.

STATUS: not yet run.

RESULTS -- not yet recorded.

HOW TO RUN, against the matrix (test/README.md), from the repo root:

    .venv/Scripts/python sql/mssql/17_statement_run_probe.py

It reaches each server on 127.0.0.1 at the port the matrix publishes,
SOPULI_TEST_MSSQL2019_PORT, SOPULI_TEST_MSSQL2022_PORT and
SOPULI_TEST_MSSQL2025_PORT, by default 14319, 14322 and 14325, as `sa`. A
service name as the argument limits the run to that server. With
SOPULI_MSSQL_SERVER set, as in .github/workflows/mssql-windows-probe.yml, it
reaches that one server instead, as the Windows account that runs it, which
needs SQL Server authentication turned on for the probe's logins.

THROWAWAY SERVERS ONLY. It creates the databases sopuli_probe,
sopuli_probe_other and sopuli_probe_qi, the logins sopuli_probe_runas,
sopuli_probe_plan, sopuli_probe_nogrant, sopuli_probe_svc, sopuli_probe_imp
and sopuli_probe_dba, and the linked server sopuli_probe_lnk, and drops them
at the end.
"""

from __future__ import annotations

import contextlib
import datetime
import os
import re
import struct
import sys
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Any

import pyodbc  # type: ignore[import-not-found]

DRIVER = "ODBC Driver 18 for SQL Server"
SA_PASSWORD = "Sopuli-test-1"
#: A test password, not a credential. It meets the complexity rule.
PASSWORD = "Acme-Runas-pw1"
PORTS = {
    "mssql-2019": ("SOPULI_TEST_MSSQL2019_PORT", "14319"),
    "mssql-2022": ("SOPULI_TEST_MSSQL2022_PORT", "14322"),
    "mssql-2025": ("SOPULI_TEST_MSSQL2025_PORT", "14325"),
}
#: The fixture database's schema, and the second database's.
P = "sopuli_probe.dbo"
Q = "sopuli_probe_other.dbo"
LINK = "sopuli_probe_lnk"
RUNAS = "sopuli_probe_runas"
PLAN = "sopuli_probe_plan"
NOGRANT = "sopuli_probe_nogrant"
SVC = "sopuli_probe_svc"
IMP = "sopuli_probe_imp"
DBA = "sopuli_probe_dba"
LOGINS = (RUNAS, PLAN, NOGRANT, SVC, IMP, DBA)
DATABASES = ("sopuli_probe", "sopuli_probe_other", "sopuli_probe_qi")
_NUMBER = re.compile(r"\((\d{2,6})\)")
_PREFIX = re.compile(r"(\[[^\]]*\])+")
_PROCESS = re.compile(r"Process ID \d+")
#: A SELECT that runs for minutes: no case lets it finish.
LONG_SELECT = (
    "SELECT COUNT_BIG(*) FROM sys.all_columns AS a CROSS JOIN sys.all_columns AS b "
    "CROSS JOIN sys.all_columns AS c"
)
MILLION = (
    "SELECT TOP (1000000) CAST(ROW_NUMBER() OVER (ORDER BY (SELECT NULL)) AS int) AS n, "
    "REPLICATE('x', 200) AS pad FROM sys.all_columns AS a CROSS JOIN sys.all_columns AS b"
)
TRAN = "SELECT @@TRANCOUNT, XACT_STATE()"

# A pooled connection keeps its session after close(), and a login with a
# session cannot be dropped.
pyodbc.pooling = False


@dataclass
class Server:
    """One server, and how the probe reaches it."""

    label: str
    address: str
    #: How the administrator logs in: sa's password, or Windows authentication.
    admin: str
    #: What the linked server reaches: the server itself.
    datasrc: str
    host: str = ""

    def connect(self, credentials: str, database: str = "master") -> Any:
        return pyodbc.connect(
            f"Driver={{{DRIVER}}};Server={self.address};Database={database};"
            f"{credentials}Encrypt=yes;TrustServerCertificate=yes;",
            autocommit=True,
            timeout=30,
        )

    def sa(self, database: str = "master") -> Any:
        return self.connect(self.admin, database)

    def login(self, name: str, database: str = "master") -> Any:
        return self.connect(f"Uid={name};Pwd={{{PASSWORD}}};", database)


def servers(only: list[str]) -> list[Server]:
    if os.environ.get("SOPULI_MSSQL_SERVER"):
        address = os.environ["SOPULI_MSSQL_SERVER"]
        return [Server("windows", address, "Trusted_Connection=yes;", address)]
    return [
        Server(
            service,
            f"127.0.0.1,{os.environ.get(variable, default)}",
            f"Uid=sa;Pwd={{{SA_PASSWORD}}};",
            "localhost",
        )
        for service, (variable, default) in PORTS.items()
        if not only or service in only
    ]


# ------------------------------------------------------------------ helpers


def err(exc: BaseException) -> str:
    """The SQLSTATE and the server's number, and the message, shortened."""
    args = getattr(exc, "args", ())
    state = args[0] if args and isinstance(args[0], str) else type(exc).__name__
    text = str(args[1]) if len(args) > 1 else str(exc)
    numbers = [n for n in _NUMBER.findall(text) if n != "0"]
    message = _NUMBER.sub("", _PREFIX.sub("", text.split("(SQL")[0])).strip()
    message = _PROCESS.sub("Process ID <n>", message)
    return " ".join(part for part in (state, numbers[0] if numbers else "", message[:100]) if part)


def run(conn: Any, sql: str) -> list[tuple[Any, ...]]:
    cursor = conn.cursor()
    cursor.execute(sql)
    rows: list[tuple[Any, ...]] = []
    while True:
        if cursor.description:
            rows.extend(tuple(row) for row in cursor.fetchall())
        if not cursor.nextset():
            break
    return rows


def one(conn: Any, sql: str) -> Any:
    rows = run(conn, sql)
    return rows[0][0] if rows else None


def attempt(conn: Any, sql: str) -> str:
    """`ran, rows ...` or the error."""
    try:
        rows = run(conn, sql)
    except pyodbc.Error as exc:
        return err(exc)
    return f"ran, rows {rows}" if rows else "ran"


def show(label: str, value: object) -> None:
    print(f"  {label}: {value}")


@contextlib.contextmanager
def closing(conn: Any) -> Iterator[Any]:
    try:
        yield conn
    finally:
        with contextlib.suppress(pyodbc.Error):
            conn.close()


def tran_state(conn: Any) -> str:
    try:
        return str(run(conn, TRAN)[0])
    except pyodbc.Error as exc:
        return f"connection unusable: {err(exc)}"


def rollback(conn: Any) -> None:
    with contextlib.suppress(pyodbc.Error):
        run(conn, "IF @@TRANCOUNT > 0 ROLLBACK TRANSACTION")


def as_sa(server: Server, sql: str, database: str = "master") -> list[tuple[Any, ...]]:
    with closing(server.sa(database)) as conn:
        return run(conn, sql)


# ------------------------------------------------------------------ fixture


def drop_all(server: Server) -> None:
    def quietly(sql: str) -> None:
        with contextlib.suppress(pyodbc.Error):
            as_sa(server, sql)

    for name in DATABASES:
        quietly(
            f"IF DB_ID('{name}') IS NOT NULL BEGIN ALTER DATABASE [{name}] "
            f"SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [{name}] END"
        )
    quietly(
        f"IF EXISTS (SELECT 1 FROM sys.servers WHERE name = '{LINK}') "
        f"EXEC sp_dropserver '{LINK}', 'droplogins'"
    )
    quietly("REVOKE VIEW DEFINITION ON SCHEMA::dbo TO guest")
    for name in LOGINS:
        quietly(f"IF USER_ID('{name}') IS NOT NULL DROP USER [{name}]")
        quietly(
            "DECLARE @k nvarchar(max) = N''; SELECT @k += N'KILL ' "
            "+ CAST(session_id AS nvarchar(10)) + N'; ' FROM sys.dm_exec_sessions "
            f"WHERE login_name = '{name}'; EXEC (@k)"
        )
        quietly(f"IF SUSER_ID('{name}') IS NOT NULL DROP LOGIN [{name}]")


FIXTURE = (
    "CREATE TABLE dbo.t (id int PRIMARY KEY, v int)",
    "INSERT INTO dbo.t VALUES (1, 10), (2, 20), (3, 30)",
    "CREATE TABLE dbo.u (id int PRIMARY KEY, v int)",
    "INSERT INTO dbo.u VALUES (1, 10), (2, 20), (3, 30)",
    "CREATE TABLE dbo.lg (id int PRIMARY KEY, v int)",
    "INSERT INTO dbo.lg VALUES (1, 0), (2, 0), (3, 0), (4, 0), (5, 0)",
    "CREATE TABLE dbo.tr_on (id int PRIMARY KEY, v int)",
    "INSERT INTO dbo.tr_on VALUES (1, 1)",
    "CREATE TABLE dbo.tr_off (id int PRIMARY KEY, v int)",
    "INSERT INTO dbo.tr_off VALUES (1, 1)",
    "CREATE TRIGGER dbo.tr_on_au ON dbo.tr_on AFTER UPDATE AS "
    "BEGIN SET NOCOUNT ON; UPDATE dbo.lg SET v = v + 1 END",
    "CREATE TRIGGER dbo.tr_off_au ON dbo.tr_off AFTER UPDATE AS "
    "BEGIN UPDATE dbo.lg SET v = v + 1 END",
    "CREATE VIEW dbo.vw AS SELECT id, v FROM dbo.t",
    "CREATE TRIGGER dbo.vw_iu ON dbo.vw INSTEAD OF UPDATE AS "
    "BEGIN UPDATE t SET v = i.v FROM dbo.t AS t JOIN inserted AS i ON t.id = i.id; "
    "UPDATE dbo.lg SET v = v + 1 END",
    "CREATE SEQUENCE dbo.s AS bigint START WITH 1",
    "CREATE TABLE dbo.ident (id int IDENTITY(1, 1) PRIMARY KEY, v int)",
    "CREATE TABLE dbo.rv (id int PRIMARY KEY, r rowversion)",
    "INSERT INTO dbo.rv (id) VALUES (1)",
    "CREATE FUNCTION dbo.f() RETURNS int AS BEGIN RETURN 1 END",
    "CREATE FUNCTION dbo.tvf() RETURNS TABLE AS RETURN SELECT id, v FROM dbo.t",
)

#: What each login is granted, by database. RUNAS is db_owner of
#: sopuli_probe, for the DDL of S2, and may grant VIEW DEFINITION on master's
#: dbo schema, for S2's GRANT. PLAN may run each of S1's statements there.
GRANTS = {
    "master": (
        f"CREATE USER {RUNAS} FOR LOGIN {RUNAS}",
        f"CREATE USER {PLAN} FOR LOGIN {PLAN}",
        f"CREATE USER {IMP} FOR LOGIN {IMP}",
        f"GRANT VIEW DEFINITION ON SCHEMA::dbo TO {RUNAS} WITH GRANT OPTION",
    ),
    "sopuli_probe": (
        f"CREATE USER {RUNAS} FOR LOGIN {RUNAS}",
        f"ALTER ROLE db_owner ADD MEMBER {RUNAS}",
        f"CREATE USER {PLAN} FOR LOGIN {PLAN}",
        f"GRANT SELECT, INSERT, UPDATE, DELETE, EXECUTE, ALTER ON SCHEMA::dbo TO {PLAN}",
        f"GRANT CREATE TABLE TO {PLAN}",
    ),
    "sopuli_probe_other": (
        "CREATE TABLE dbo.o (id int PRIMARY KEY, w int)",
        "INSERT INTO dbo.o VALUES (1, 100)",
        f"CREATE USER {PLAN} FOR LOGIN {PLAN}",
        f"CREATE USER {RUNAS} FOR LOGIN {RUNAS}",
        f"GRANT SELECT ON SCHEMA::dbo TO {PLAN}, {RUNAS}",
    ),
    "sopuli_probe_qi": (f"CREATE USER {RUNAS} FOR LOGIN {RUNAS}",),
}


def setup(server: Server) -> None:
    drop_all(server)
    with closing(server.sa()) as sa:
        server.host = str(one(sa, "SELECT CAST(SERVERPROPERTY('ServerName') AS nvarchar(256))"))
        for name in DATABASES:
            run(sa, f"CREATE DATABASE [{name}]")
        run(sa, "ALTER DATABASE sopuli_probe_qi SET QUOTED_IDENTIFIER OFF")
        for name in LOGINS:
            run(sa, f"CREATE LOGIN [{name}] WITH PASSWORD = N'{PASSWORD}', CHECK_POLICY = OFF")
        run(sa, f"ALTER SERVER ROLE sysadmin ADD MEMBER {DBA}")
        run(sa, f"GRANT IMPERSONATE ON LOGIN::{SVC} TO {IMP}")
        # The linked server is this server, and each login reaches it as
        # itself. It has no provider string where it can: with one, every
        # login but a sysadmin's is refused, 7416, mapping or not. Where the
        # provider refuses the server's own certificate without one (2025),
        # it has `Encrypt=Optional`.
        for provstr in ("", "Encrypt=Optional"):
            run(
                sa,
                f"EXEC sp_addlinkedserver @server = N'{LINK}', @srvproduct = N'', "
                f"@provider = N'MSOLEDBSQL', @datasrc = N'{server.datasrc}'"
                + (f", @provstr = N'{provstr}'" if provstr else ""),
            )
            reached = attempt(sa, f"SELECT a FROM OPENQUERY({LINK}, 'SELECT 1 AS a')")
            print(f"  the linked server, provider string '{provstr}': sa {reached}")
            if reached.startswith("ran") or provstr:
                break
            run(sa, f"EXEC sp_dropserver N'{LINK}'")
        for name in (RUNAS, PLAN):
            run(
                sa,
                f"EXEC sp_addlinkedsrvlogin @rmtsrvname = N'{LINK}', @useself = N'FALSE', "
                f"@locallogin = N'{name}', @rmtuser = N'{name}', @rmtpassword = N'{PASSWORD}'",
            )
    with closing(server.sa("sopuli_probe")) as db:
        for statement in FIXTURE:
            run(db, statement)
    for database, statements in GRANTS.items():
        with closing(server.sa(database)) as db:
            for statement in statements:
                run(db, statement)


def state(server: Server) -> tuple[Any, ...]:
    """What a statement that ran would have changed."""
    return as_sa(
        server,
        f"SELECT (SELECT CHECKSUM_AGG(CHECKSUM(id, v)) FROM {P}.t), "
        f"(SELECT CHECKSUM_AGG(CHECKSUM(id, v)) FROM {P}.u), (SELECT COUNT(*) FROM {P}.u), "
        f"OBJECT_ID('{P}.t2'), (SELECT CAST(current_value AS bigint) "
        "FROM sopuli_probe.sys.sequences WHERE name = 's'), "
        "(SELECT COUNT(*) FROM master.sys.database_permissions "
        "WHERE grantee_principal_id = DATABASE_PRINCIPAL_ID('guest') "
        "AND permission_name = 'VIEW DEFINITION')",
    )[0]


def reset(server: Server) -> None:
    for statement in (
        "UPDATE dbo.t SET v = id * 10",
        "DELETE FROM dbo.u WHERE id > 3",
        "UPDATE dbo.u SET v = id * 10",
        "IF OBJECT_ID('dbo.t2') IS NOT NULL DROP TABLE dbo.t2",
    ):
        as_sa(server, statement, "sopuli_probe")


# ------------------------------------------------------------------- S1

_W = f"UPDATE {P}.t SET v = v + 1 WHERE id = 1"
S1_STATEMENTS = (
    ("SELECT 1", "SELECT 1"),
    ("SELECT INTO a table", f"SELECT id, v INTO {P}.t2 FROM {P}.t"),
    ("SELECT INTO #t", f"SELECT id, v INTO #t FROM {P}.t"),
    ("UPDATE", _W),
    ("INSERT SELECT", f"INSERT INTO {P}.u (id, v) SELECT id + 100, v FROM {P}.t"),
    ("DELETE with a join",
     f"DELETE x FROM {P}.u AS x JOIN {P}.t AS y ON x.id = y.id WHERE y.id = 3"),
    ("MERGE",
     f"MERGE {P}.u AS d USING {P}.t AS s ON d.id = s.id WHEN MATCHED THEN UPDATE SET "
     "v = s.v + 1 WHEN NOT MATCHED THEN INSERT (id, v) VALUES (s.id, s.v);"),
    ("WITH SELECT", f"WITH c AS (SELECT id, v FROM {P}.t) SELECT id, v FROM c"),
    ("WITH UPDATE", f"WITH c AS (SELECT id, v FROM {P}.t WHERE id = 1) UPDATE c SET v = 99"),
    ("WITH DELETE", f"WITH c AS (SELECT id, v FROM {P}.u WHERE id = 1) DELETE FROM c"),
    ("WITH INSERT",
     f"WITH c AS (SELECT id, v FROM {P}.t) INSERT INTO {P}.u (id, v) SELECT id + 200, v FROM c"),
    ("UPDATE DELETE", f"{_W} DELETE FROM {P}.u WHERE id = 2"),
    ("SELECT SELECT", "SELECT 1 AS a SELECT 2 AS b"),
    ("UPDATE GRANT", f"{_W} GRANT VIEW DEFINITION ON SCHEMA::dbo TO guest"),
    ("UPDATE DECLARE", f"{_W} DECLARE @x int"),
    ("DECLARE UPDATE", f"DECLARE @x int {_W}"),
    ("UPDATE SET", f"{_W} SET XACT_ABORT OFF"),
    ("UPDATE EXEC", f"{_W} EXEC sp_who"),
    ("UPDATE EXECUTE AS", f"{_W} EXECUTE AS LOGIN = '{SVC}'"),
    ("UPDATE PRINT", f"{_W} PRINT 'x'"),
    ("no such table", f"SELECT id FROM {P}.nosuch"),
    ("no such database", "SELECT id FROM sopuli_probe_nosuch.dbo.t"),
    ("another database", f"SELECT o.w FROM {Q}.o AS o JOIN {P}.t AS t ON t.id = o.id"),
    ("scalar function", f"SELECT {P}.f() AS f"),
    ("table-valued function", f"SELECT id FROM {P}.tvf()"),
    ("NEXT VALUE FOR", f"SELECT NEXT VALUE FOR {P}.s AS n"),
    ("OPENQUERY SELECT", f"SELECT a FROM OPENQUERY({LINK}, 'SELECT 1 AS a')"),
    ("OPENQUERY UPDATE",
     f"SELECT v FROM OPENQUERY({LINK}, 'UPDATE {P}.t SET v = v + 1 OUTPUT inserted.v "
     "WHERE id = 1')"),
    ("four-part UPDATE", f"UPDATE {LINK}.sopuli_probe.dbo.t SET v = v + 1 WHERE id = 1"),
)  # fmt: skip


def short(text: object, width: int = 60) -> str:
    flat = " ".join(str(text).split())
    return flat if len(flat) <= width else flat[: width - 3] + "..."


def showplan(conn: Any, statement: str) -> str:
    """The row sets SHOWPLAN_ALL gives, and in each its statement rows (Type
    not PLAN_ROW): StmtId, Type and StmtText."""
    cursor = conn.cursor()
    cursor.execute("SET SHOWPLAN_ALL ON")
    sets: list[str] = []
    try:
        cursor.execute(statement)
        while True:
            if cursor.description:
                names = [d[0] for d in cursor.description]
                kind, sid = names.index("Type"), names.index("StmtId")
                rows = cursor.fetchall()
                found = [r for r in rows if r[kind] != "PLAN_ROW"]
                shown = [f"{r[sid]} {r[kind]} '{short(r[0], 40)}'" for r in found[:4]]
                if len(found) > 4:
                    shown.append(f"... {len(found)} statement rows")
                sets.append(f"[{len(rows)} rows: " + "; ".join(shown) + "]")
            if not cursor.nextset():
                break
    except pyodbc.Error as exc:
        sets.append(f"ERROR {err(exc)}")
    finally:
        with contextlib.suppress(pyodbc.Error):
            conn.cursor().execute("SET SHOWPLAN_ALL OFF")
    return f"{sum(s.startswith('[') for s in sets)} sets " + " ".join(sets)


def full_text(conn: Any, statement: str) -> list[str]:
    """Each statement row's whole StmtText."""
    cursor = conn.cursor()
    cursor.execute("SET SHOWPLAN_ALL ON")
    try:
        cursor.execute(statement)
        names = [d[0] for d in cursor.description]
        kind = names.index("Type")
        return [f"{r[kind]}: '{' '.join(str(r[0]).split())}'" for r in cursor.fetchall()
                if r[kind] != "PLAN_ROW"]  # fmt: skip
    finally:
        conn.cursor().execute("SET SHOWPLAN_ALL OFF")


def grant_showplan(server: Server, databases: tuple[str, ...]) -> None:
    for name in ("master", "sopuli_probe", "sopuli_probe_other"):
        verb = "GRANT" if name in databases else "REVOKE"
        as_sa(server, f"{verb} SHOWPLAN TO {PLAN}", name)


def s1(server: Server) -> None:
    print("S1 the statement list under SET SHOWPLAN_ALL ON")
    grant_showplan(server, ("master", "sopuli_probe", "sopuli_probe_other"))
    for who in (PLAN, DBA):
        print(f" as {who}" + (", sysadmin" if who == DBA else ""))
        before = state(server)
        with closing(server.login(who)) as conn:
            for label, statement in S1_STATEMENTS:
                show(label, showplan(conn, statement))
            show("after them, (@@TRANCOUNT, XACT_STATE())", tran_state(conn))
            show("after them, SUSER_SNAME()", one(conn, "SELECT SUSER_SNAME()"))
            show("after them, OBJECT_ID of #t", one(conn, "SELECT OBJECT_ID('tempdb..#t')"))
            if who == PLAN:
                for label in ("UPDATE DECLARE", "DECLARE UPDATE", "UPDATE SET", "UPDATE PRINT"):
                    show(f"whole StmtText, {label}", full_text(conn, dict(S1_STATEMENTS)[label]))
        after = state(server)
        show("nothing changed", before == after or f"{before} -> {after}")
        reset(server)
    print(f" the SHOWPLAN permission, as {PLAN}")
    statements = (
        ("SELECT 1", "SELECT 1"),
        ("SELECT from sopuli_probe", f"SELECT id FROM {P}.t"),
        ("UPDATE in sopuli_probe", f"UPDATE {P}.t SET v = v WHERE id = 1"),
        ("SELECT from both", f"SELECT o.w FROM {Q}.o AS o JOIN {P}.t AS t ON t.id = o.id"),
    )
    for databases in (
        (),
        ("master",),
        ("sopuli_probe",),
        ("master", "sopuli_probe"),
        ("master", "sopuli_probe", "sopuli_probe_other"),
    ):
        grant_showplan(server, databases)
        with closing(server.login(PLAN)) as conn:
            for what, statement in statements:
                where = ", ".join(databases) or "none"
                show(f"SHOWPLAN in {where}: {what}", showplan(conn, statement))


# ------------------------------------------------------------------- S2

_GUEST = (
    "SELECT COUNT(*) FROM master.sys.database_permissions WHERE grantee_principal_id = "
    "DATABASE_PRINCIPAL_ID('guest') AND permission_name = 'VIEW DEFINITION'"
)
_APPLOCK = (
    "DECLARE @r int; EXEC @r = sp_getapplock @Resource = N'sopuli_probe_lock', "
    "@LockMode = N'Exclusive'"
)
#: (label, the body, what is read after the rollback)
S2_CASES = (
    ("CREATE TABLE", f"CREATE TABLE {P}.ddl1 (a int); SELECT OBJECT_ID('{P}.ddl1')",
     f"SELECT OBJECT_ID('{P}.ddl1')"),
    ("ALTER TABLE",
     f"ALTER TABLE {P}.t ADD c int; SELECT COUNT(*) FROM sopuli_probe.sys.columns "
     f"WHERE object_id = OBJECT_ID('{P}.t')",
     f"SELECT COUNT(*) FROM sopuli_probe.sys.columns WHERE object_id = OBJECT_ID('{P}.t')"),
    ("GRANT", f"GRANT VIEW DEFINITION ON SCHEMA::dbo TO guest; {_GUEST}", _GUEST),
    ("ALTER DATABASE", "ALTER DATABASE sopuli_probe SET RECOVERY SIMPLE", ""),
    ("BACKUP DATABASE", "BACKUP DATABASE sopuli_probe TO DISK = N'sopuli_probe_never.bak'", ""),
    ("NEXT VALUE FOR", f"SELECT NEXT VALUE FOR {P}.s", f"SELECT NEXT VALUE FOR {P}.s"),
    ("INSERT into an identity column",
     f"INSERT INTO {P}.ident (v) VALUES (1), (2); SELECT IDENT_CURRENT('{P}.ident')",
     f"SELECT IDENT_CURRENT('{P}.ident')"),
    ("a temporary table made before it", "INSERT INTO #tt VALUES (1)", "SELECT COUNT(*) FROM #tt"),
    ("a temporary table made inside it", "CREATE TABLE #tin (a int)",
     "SELECT OBJECT_ID('tempdb..#tin')"),
    ("sp_getapplock, Session owner", f"{_APPLOCK}, @LockOwner = N'Session'; SELECT @r",
     "SELECT APPLOCK_MODE(N'public', N'sopuli_probe_lock', N'Session')"),
)  # fmt: skip
S2_LINKED = (
    ("OPENQUERY SELECT", f"SELECT a FROM OPENQUERY({LINK}, 'SELECT 1 AS a')"),
    ("OPENQUERY UPDATE",
     f"SELECT v FROM OPENQUERY({LINK}, 'UPDATE {P}.t SET v = v + 1 OUTPUT inserted.v "
     "WHERE id = 1')"),
    ("OPENQUERY UPDATE, then SELECT",
     f"SELECT a FROM OPENQUERY({LINK}, 'SET NOCOUNT ON; UPDATE {P}.t SET v = v + 1 "
     "WHERE id = 1; SELECT 1 AS a')"),
    ("four-part UPDATE", f"UPDATE {LINK}.sopuli_probe.dbo.t SET v = v + 1 WHERE id = 1"),
)  # fmt: skip


def in_transaction(conn: Any, body: str, after: str = "") -> str:
    """BEGIN TRANSACTION with XACT_ABORT ON, the body, ROLLBACK, and `after`."""
    run(conn, "SET XACT_ABORT ON")
    run(conn, "BEGIN TRANSACTION")
    try:
        got = attempt(conn, body)
        inside = tran_state(conn)
    finally:
        rollback(conn)
    text = f"{got}; then (@@TRANCOUNT, XACT_STATE()) {inside}"
    return text + (f"; after the rollback {attempt(conn, after)}" if after else "")


def s2_linked(server: Server, conn: Any) -> None:
    for label, body in S2_LINKED:
        show(f"linked server, outside a transaction, {label}", attempt(conn, body))
        show("  the row after", one(server.sa(), f"SELECT v FROM {P}.t WHERE id = 1"))
        reset(server)
        show(f"linked server, {label}", in_transaction(conn, body))
        show("  the row after", one(server.sa(), f"SELECT v FROM {P}.t WHERE id = 1"))
        reset(server)


def s2(server: Server) -> None:
    print(f"S2 BEGIN TRANSACTION with XACT_ABORT ON, then ROLLBACK, as {RUNAS}")
    with closing(server.login(RUNAS)) as conn:
        run(conn, "CREATE TABLE #tt (a int)")
        for label, body, after in S2_CASES:
            show(label, in_transaction(conn, body, after))
        with closing(server.sa()) as other:
            show(
                "  another session's sp_getapplock for it, @LockTimeout = 0",
                attempt(other, f"{_APPLOCK}, @LockOwner = N'Session', @LockTimeout = 0; SELECT @r"),
            )
        run(conn, "EXEC sp_releaseapplock N'sopuli_probe_lock', N'Session'")
        show(
            "a table variable",
            attempt(
                conn,
                "SET XACT_ABORT ON; DECLARE @tv TABLE (a int); BEGIN TRANSACTION; "
                "INSERT INTO @tv VALUES (1); ROLLBACK TRANSACTION; SELECT COUNT(*) FROM @tv",
            ),
        )
        s2_linked(server, conn)
    print(" as sa")
    with closing(server.sa()) as sa:
        for label, body, after in (
            ("CREATE DATABASE", "CREATE DATABASE sopuli_probe_never", ""),
            ("CREATE LOGIN",
             f"CREATE LOGIN sopuli_probe_never WITH PASSWORD = N'{PASSWORD}', CHECK_POLICY = OFF",
             "SELECT SUSER_ID('sopuli_probe_never')"),
            ("ALTER LOGIN", f"ALTER LOGIN {SVC} DISABLE",
             f"SELECT is_disabled FROM sys.server_principals WHERE name = '{SVC}'"),
        ):  # fmt: skip
            show(label, in_transaction(sa, body, after))
        s2_linked(server, sa)


# ------------------------------------------------------------------- S3


def counts(cursor: Any) -> list[int]:
    found = [cursor.rowcount]
    while cursor.nextset():
        found.append(cursor.rowcount)
    return found


def s3(server: Server) -> None:
    print(f"S3 one batch through pyodbc, as {RUNAS}")
    with closing(server.login(RUNAS)) as conn:
        run(conn, "BEGIN TRANSACTION")
        cursor = conn.cursor()
        cursor.execute(f"UPDATE {P}.t SET v = 11 WHERE id = 1 UPDATE {P}.u SET v = 22 WHERE id < 3")
        show("two UPDATEs: rowcount, then after each nextset()", counts(cursor))
        show(
            "  both ran: t's row 1, the sum of u's rows 1 and 2",
            run(
                conn,
                f"SELECT (SELECT v FROM {P}.t WHERE id = 1), "
                f"(SELECT SUM(v) FROM {P}.u WHERE id < 3)",
            )[0],  # fmt: skip
        )
        rollback(conn)
        cursor = conn.cursor()
        cursor.execute("SELECT 1 AS a SELECT 2 AS b")
        sets = [(cursor.rowcount, [tuple(r) for r in cursor.fetchall()])]
        while cursor.nextset():
            sets.append((cursor.rowcount, [tuple(r) for r in cursor.fetchall()]))
        show("two SELECTs: (rowcount, rows) per set", sets)
        run(conn, "BEGIN TRANSACTION")
        cursor = conn.cursor()
        cursor.execute(f"UPDATE {P}.t SET v = 11 WHERE id = 1 SELECT 2 AS b")
        first = (cursor.rowcount, cursor.description is not None)
        more = cursor.nextset()
        rest = (more, cursor.rowcount, [tuple(r) for r in cursor.fetchall()] if more else None)
        rollback(conn)
        show("UPDATE then SELECT: (rowcount, a result?), then (nextset(), rowcount, rows)",
             f"{first}, {rest}")  # fmt: skip
        show("GO on a line of its own", attempt(conn, "SELECT 1 AS a\nGO\nSELECT 2 AS b"))
        show("a ? in a literal, no parameters", attempt(conn, "SELECT '?' AS q"))
        show("a ? as a marker, no parameters", attempt(conn, "SELECT 1 AS a WHERE 1 = ?"))


# ------------------------------------------------------------------- S4

S4_CASES = (
    ("nested block comment", "SELECT 1 AS a /* /* */ , 2 AS b */"),
    ("/* in a -- comment", "SELECT 1 AS a --/*\n, 2 AS b"),
    ("-- with no space before it", "SELECT 5--3\nAS a"),
    ("-- inside a literal", "SELECT '--x' AS a"),
    ("/* inside a literal", "SELECT '/*' AS a, 2 AS b"),
    ("'' in a literal", "SELECT 'a''b' AS a"),
    ("a backslash before '", "SELECT 'a\\' AS a"),
    ("N'...'", "SELECT N'ä€' AS a"),
    ("[a]]b]", "SELECT 1 AS [a]]b]"),
    ("a ' inside [ ]", "SELECT 1 AS [it's]"),
)
QUOTED = ('"name" in a SELECT', 'SELECT "name" AS n FROM sys.databases WHERE database_id = 1')


def columns(conn: Any, sql: str) -> str:
    try:
        cursor = conn.cursor()
        cursor.execute(sql)
        names = [d[0] for d in cursor.description]
        return f"columns {names}, rows {[tuple(r) for r in cursor.fetchall()]}"
    except pyodbc.Error as exc:
        return err(exc)


def s4(server: Server) -> None:
    print(f"S4 comments, literals and names, as {RUNAS}")
    with closing(server.login(RUNAS)) as conn:
        for label, sql in S4_CASES:
            show(label, columns(conn, sql))
    for database in ("master", "sopuli_probe_qi"):
        with closing(server.login(RUNAS, database)) as conn:
            settings = run(
                conn,
                "SELECT CAST(SESSIONPROPERTY('QUOTED_IDENTIFIER') AS int), "
                "CAST(DATABASEPROPERTYEX(DB_NAME(), 'IsQuotedIdentifiersEnabled') AS int)",
            )[0]
            show(f"in {database}: QUOTED_IDENTIFIER (session, database default)", settings)
            show(f"in {database}: {QUOTED[0]}", columns(conn, QUOTED[1]))


# ------------------------------------------------------------------- S5

S5_CASES = (
    ("UPDATE to the same value, 2 rows", f"UPDATE {P}.t SET v = v WHERE id IN (1, 2)"),
    ("UPDATE matching none", f"UPDATE {P}.t SET v = v WHERE id = 99"),
    ("MERGE: 1 update, 1 insert, 2 deletes",
     f"MERGE {P}.u AS d USING (VALUES (1, 5), (4, 40)) AS s (id, v) ON d.id = s.id "
     "WHEN MATCHED THEN UPDATE SET v = s.v "
     "WHEN NOT MATCHED BY TARGET THEN INSERT (id, v) VALUES (s.id, s.v) "
     "WHEN NOT MATCHED BY SOURCE THEN DELETE;"),
    ("AFTER trigger with NOCOUNT ON: 1 row, the trigger's 5",
     f"UPDATE {P}.tr_on SET v = 2 WHERE id = 1"),
    ("AFTER trigger with NOCOUNT OFF: 1 row, the trigger's 5",
     f"UPDATE {P}.tr_off SET v = 2 WHERE id = 1"),
    ("INSTEAD OF trigger on a view: 1 row, the trigger's 1 and 5",
     f"UPDATE {P}.vw SET v = 7 WHERE id = 1"),
    ("INSERT of 3 rows", f"INSERT INTO {P}.u (id, v) VALUES (7, 1), (8, 1), (9, 1)"),
    ("DELETE with a join, 1 row",
     f"DELETE x FROM {P}.u AS x JOIN {P}.t AS y ON x.id = y.id WHERE y.id = 3"),
    ("SELECT of 3 rows", f"SELECT id FROM {P}.t"),
)  # fmt: skip


def counted(conn: Any, sql: str) -> str:
    """rowcount and after each nextset(), then @@ROWCOUNT, in a transaction
    that is rolled back."""
    run(conn, "BEGIN TRANSACTION")
    try:
        cursor = conn.cursor()
        cursor.execute(sql)
        found = counts(cursor)
        return f"rowcount {found}, then @@ROWCOUNT {one(conn, 'SELECT @@ROWCOUNT')}"
    except pyodbc.Error as exc:
        return err(exc)
    finally:
        rollback(conn)


def s5(server: Server) -> None:
    print(f"S5 row counts with SET NOCOUNT OFF, as {RUNAS}")
    with closing(server.login(RUNAS)) as conn:
        nocount = one(conn, "SELECT @@OPTIONS & 512")
        show("NOCOUNT as the driver leaves it (@@OPTIONS & 512)", nocount)
        run(conn, "SET NOCOUNT OFF")
        for label, sql in S5_CASES:
            show(label, counted(conn, sql))


# ------------------------------------------------------------------- S6

_HOLD = f"UPDATE {P}.t SET v = v + 1 WHERE id = 1"
_EARLIER = f"UPDATE {P}.u SET v = v + 1000 WHERE id = 1"
_WAITS = {
    "a long SELECT": LONG_SELECT,
    "a SELECT waiting on a row lock": f"SELECT v FROM {P}.t WHERE id = 1",
    "an UPDATE waiting on a row lock": f"UPDATE {P}.t SET v = v WHERE id = 1",
}


def key_locks(server: Server, spid: int) -> int:
    sql = (
        "SELECT COUNT(*) FROM sys.dm_tran_locks "
        f"WHERE request_session_id = {spid} AND resource_type = 'KEY'"
    )
    return int(as_sa(server, sql)[0][0])


def afterwards(server: Server, conn: Any, spid: int) -> str:
    try:
        earlier = one(conn, f"SELECT v FROM {P}.u WHERE id = 1")
    except pyodbc.Error as exc:
        return f"connection unusable: {err(exc)}"
    return (f"then (@@TRANCOUNT, XACT_STATE()) {tran_state(conn)}, the earlier write's row "
            f"{earlier}, KEY locks held {key_locks(server, spid)}")  # fmt: skip


def waited(server: Server, xact_abort: str, statement: str, prepare: Callable[[Any], None]) -> str:
    """sa holds a row lock on t's row 1; the run-as session writes u's row 1,
    then runs the statement."""
    with closing(server.sa()) as holder, closing(server.login(RUNAS)) as conn:
        run(holder, "BEGIN TRANSACTION")
        run(holder, _HOLD)
        spid = int(one(conn, "SELECT @@SPID"))
        run(conn, f"SET XACT_ABORT {xact_abort}")
        run(conn, "BEGIN TRANSACTION")
        run(conn, _EARLIER)
        prepare(conn)
        started = time.monotonic()
        got = attempt(conn, statement)
        took = time.monotonic() - started
        conn.timeout = 0
        after = afterwards(server, conn, spid)
        rollback(conn)
        rollback(holder)
    return f"{got}, after {took:.1f} s; {after}"


def s6(server: Server) -> None:
    print(f"S6 timeouts, as {RUNAS}; sa holds the row lock")
    for what in ("a SELECT waiting on a row lock", "an UPDATE waiting on a row lock"):
        for xact_abort in ("OFF", "ON"):
            show(f"SET LOCK_TIMEOUT 1000, XACT_ABORT {xact_abort}, {what}",
                 waited(server, xact_abort, _WAITS[what],
                        lambda conn: run(conn, "SET LOCK_TIMEOUT 1000")))  # fmt: skip
    for what, statement in _WAITS.items():
        for xact_abort in ("OFF", "ON"):

            def timeout(conn: Any) -> None:
                conn.timeout = 2

            show(f"connection.timeout = 2, XACT_ABORT {xact_abort}, {what}",
                 waited(server, xact_abort, statement, timeout))  # fmt: skip
    s6_deadlock(server)
    s6_cancel(server)


def s6_deadlock(server: Server) -> None:
    with closing(server.login(RUNAS)) as a, closing(server.login(RUNAS)) as b:
        for conn in (a, b):
            run(conn, "BEGIN TRANSACTION")
        run(a, f"UPDATE {P}.t SET v = v + 1 WHERE id = 2")
        run(b, f"UPDATE {P}.u SET v = v + 1 WHERE id = 2")
        results: dict[str, str] = {}

        def second() -> None:
            results["first to wait"] = attempt(a, f"UPDATE {P}.u SET v = v + 1 WHERE id = 2")

        thread = threading.Thread(target=second)
        thread.start()
        time.sleep(0.5)
        results["second to wait"] = attempt(b, f"UPDATE {P}.t SET v = v + 1 WHERE id = 2")
        thread.join()
        # The server chooses the victim, which differs between runs.
        sessions = sorted(
            ((results["first to wait"], a), (results["second to wait"], b)),
            key=lambda pair: pair[0] == "ran",
        )
        for name, (got, conn) in zip(("the victim", "the other"), sessions, strict=True):
            after = tran_state(conn)
            show(f"a deadlock, {name}", f"{got}; then (@@TRANCOUNT, XACT_STATE()) {after}")
            rollback(conn)


def s6_cancel(server: Server) -> None:
    for what in ("a long SELECT", "an UPDATE waiting on a row lock"):
        for xact_abort in ("OFF", "ON"):
            show(f"cursor.cancel() from another thread after 1 s, XACT_ABORT {xact_abort}, "
                 f"{what}", cancelled(server, xact_abort, _WAITS[what]))  # fmt: skip


def cancelled(server: Server, xact_abort: str, statement: str) -> str:
    with closing(server.sa()) as holder, closing(server.login(RUNAS)) as conn:
        run(holder, "BEGIN TRANSACTION")
        run(holder, _HOLD)
        spid = int(one(conn, "SELECT @@SPID"))
        run(conn, f"SET XACT_ABORT {xact_abort}")
        run(conn, "BEGIN TRANSACTION")
        run(conn, _EARLIER)
        cursor = conn.cursor()
        timer = threading.Timer(1.0, cursor.cancel)
        timer.start()
        started = time.monotonic()
        try:
            cursor.execute(statement)
            got = "ran"
        except pyodbc.Error as exc:
            got = err(exc)
        took = time.monotonic() - started
        timer.join()
        after = afterwards(server, conn, spid)
        rollback(conn)
        rollback(holder)
    return f"{got}, after {took:.1f} s; {after}"


# ------------------------------------------------------------------- S7


def s7(server: Server) -> None:
    print(f"S7 a SELECT of a million rows of 204 bytes, as {RUNAS}")
    with closing(server.login(RUNAS)) as conn:
        cursor = conn.cursor()
        started = time.monotonic()
        cursor.execute(MILLION)
        total = len(cursor.fetchall())
        show("read in full", f"{total} rows in {time.monotonic() - started:.1f} s")
    for label, steps in (
        ("fetchmany(100), cancel(), close()", ("cancel", "close")),
        ("fetchmany(100), close()", ("close",)),
        ("fetchmany(100), then a new execute on the same cursor", ()),
    ):
        with closing(server.login(RUNAS)) as conn:
            spid = int(one(conn, "SELECT @@SPID"))
            cursor = conn.cursor()
            cursor.execute(MILLION)
            cursor.fetchmany(100)
            started = time.monotonic()
            for step in steps:
                getattr(cursor, step)()
            stopped = time.monotonic() - started
            running = as_sa(server, f"SELECT COUNT(*) FROM sys.dm_exec_requests "
                                    f"WHERE session_id = {spid}")[0][0]  # fmt: skip
            target = conn.cursor() if steps else cursor
            started = time.monotonic()
            target.execute("SELECT 1")
            target.fetchall()
            show(label, f"returned in {stopped:.2f} s; requests of the session then {running}; "
                        f"the next SELECT 1 took {time.monotonic() - started:.2f} s")  # fmt: skip


# ------------------------------------------------------------------- S8

TYPES = (
    ("decimal(10,2)", "CAST(12.34 AS decimal(10,2))"),
    ("decimal(38,10)", "CAST('1234567890123456789012345678.0123456789' AS decimal(38,10))"),
    ("money", "CAST(12.34 AS money)"),
    ("bigint", "CAST(9007199254740993 AS bigint)"),
    ("bit", "CAST(1 AS bit)"),
    ("float", "CAST(0.1 AS float)"),
    ("real", "CAST(0.1 AS real)"),
    ("date", "CAST('2026-11-28' AS date)"),
    ("datetime", "CAST('2026-11-28T12:34:56.789' AS datetime)"),
    ("datetime2", "CAST('2026-11-28T12:34:56.1234567' AS datetime2)"),
    ("datetimeoffset", "CAST('2026-11-28T12:34:56.1234567+02:00' AS datetimeoffset)"),
    ("time", "CAST('12:34:56.1234567' AS time)"),
    ("uniqueidentifier", "CAST('6F9619FF-8B86-D011-B42D-00C04FC964FF' AS uniqueidentifier)"),
    ("binary(4)", "CAST(0x01020304 AS binary(4))"),
    ("varbinary(max), 10000 bytes",
     "CAST(REPLICATE(CAST('ab' AS varchar(max)), 5000) AS varbinary(max))"),
    ("nvarchar(max), 5000 characters", "REPLICATE(CAST(N'ä' AS nvarchar(max)), 5000)"),
    ("xml", "CAST('<a b=\"1\"/>' AS xml)"),
    ("sql_variant", "CAST(CAST(5 AS int) AS sql_variant)"),
    ("hierarchyid", "hierarchyid::Parse('/1/2/')"),
    ("geography", "geography::Point(60.17, 24.94, 4326)"),
    ("rowversion", f"(SELECT r FROM {P}.rv WHERE id = 1)"),
    ("NULL", "NULL"),
    ("int NULL", "CAST(NULL AS int)"),
)  # fmt: skip


def datetimeoffset(raw: bytes) -> datetime.datetime:
    """The SQL_SS_TIMESTAMPOFFSET struct the driver gives for type -155."""
    parts = struct.unpack("<6hI2h", raw)
    zone = datetime.timezone(datetime.timedelta(hours=parts[7], minutes=parts[8]))
    return datetime.datetime(*parts[:6], parts[6] // 1000, tzinfo=zone)


def describe(value: Any) -> str:
    text = repr(value)
    if len(text) > 70 and hasattr(value, "__len__"):
        text = f"{text[:40]}... length {len(value)}"
    return f"{type(value).__name__} {text}"


def s8(server: Server) -> None:
    print(f"S8 what pyodbc returns, as {RUNAS}")
    with closing(server.login(RUNAS)) as conn:
        for converter in (False, True):
            if converter:
                conn.add_output_converter(-155, datetimeoffset)
                print("  with an output converter for -155")
            for label, expression in TYPES if not converter else TYPES[10:11]:
                try:
                    cursor = conn.cursor()
                    cursor.execute(f"SELECT {expression} AS x")
                    code = cursor.description[0][1]
                    value = cursor.fetchone()[0]
                    got = f"{describe(value)}; description {getattr(code, '__name__', code)}"
                except pyodbc.Error as exc:
                    got = err(exc)
                show(label, got)


# ------------------------------------------------------------------- S9

WHO = (
    "SELECT ORIGINAL_LOGIN(), SUSER_SNAME(), USER_NAME(), DB_NAME(), "
    "CAST(SERVERPROPERTY('ServerName') AS nvarchar(256)), @@SERVERNAME"
)


def s9(server: Server) -> None:
    print("S9 ORIGINAL_LOGIN(), SUSER_SNAME(), USER_NAME(), DB_NAME(), ServerName, @@SERVERNAME")

    def who(conn: Any) -> list[object]:
        return [("<host>" if v == server.host else v) for v in run(conn, WHO)[0]]

    for name in (NOGRANT, DBA):
        with closing(server.login(name)) as conn:
            show(name + (", sysadmin" if name == DBA else ", no grant"), who(conn))
    for name, target in ((DBA, NOGRANT), (IMP, SVC)):
        with closing(server.login(name)) as conn:
            run(conn, f"EXECUTE AS LOGIN = '{target}'")
            show(f"{name}, inside EXECUTE AS LOGIN = '{target}'", who(conn))
            run(conn, "REVERT")
    with closing(server.login(NOGRANT)) as conn:
        show(f"{NOGRANT}: EXECUTE AS LOGIN = '{SVC}'", attempt(conn, f"EXECUTE AS LOGIN = '{SVC}'"))


# ------------------------------------------------------------------- S10


def s10(server: Server) -> None:
    print(f"S10 IMPERSONATE on {SVC}")
    reads = (
        ("HAS_PERMS_BY_NAME, IMPERSONATE",
         f"SELECT HAS_PERMS_BY_NAME('{SVC}', 'LOGIN', 'IMPERSONATE')"),
        ("HAS_PERMS_BY_NAME, VIEW SERVER STATE",
         "SELECT HAS_PERMS_BY_NAME(NULL, NULL, 'VIEW SERVER STATE')"),
        ("its own rows in sys.server_permissions",
         "SELECT permission_name, state_desc, class_desc, SUSER_NAME(major_id) "
         "FROM sys.server_permissions WHERE grantee_principal_id = SUSER_ID()"),
        (f"fn_my_permissions('{SVC}', 'LOGIN')",
         f"SELECT permission_name FROM fn_my_permissions('{SVC}', 'LOGIN')"),
        (f"{SVC} in sys.server_principals",
         f"SELECT name FROM sys.server_principals WHERE name = '{SVC}'"),
    )  # fmt: skip
    for name in (DBA, IMP, NOGRANT):
        with closing(server.login(name)) as conn:
            for label, sql in reads if name != DBA else reads[:1]:
                show(f"{name}: {label}", run(conn, sql))


# --------------------------------------------------------------------- main

STEPS: tuple[Callable[[Server], None], ...] = (s1, s2, s3, s4, s5, s6, s7, s8, s9, s10)


def probe(server: Server) -> None:
    with closing(server.sa()) as sa:
        version, edition = run(
            sa,
            "SELECT CAST(SERVERPROPERTY('ProductVersion') AS nvarchar(32)), "
            "CAST(SERVERPROPERTY('Edition') AS nvarchar(64))",
        )[0]
        driver = f"{sa.getinfo(pyodbc.SQL_DRIVER_NAME)} {sa.getinfo(pyodbc.SQL_DRIVER_VER)}"
    print(f"== {server.label}: {version}, {edition}, pyodbc {pyodbc.version}, {driver}")
    setup(server)
    try:
        for step in STEPS:
            try:
                step(server)
            except pyodbc.Error as exc:
                print(f"  STEP {step.__name__} FAILED: {err(exc)}")
            reset(server)
    finally:
        drop_all(server)


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    for server in servers(sys.argv[1:]):
        probe(server)
    return 0


if __name__ == "__main__":
    sys.exit(main())
