"""sopuli-dba : what an audit keeps of the hash-version check and the changes

#1569, mssql-hash-check-audit, and #1601. Once per session, before a change,
the driver learns whether the server takes a 0x0300 value. It sends `CREATE
LOGIN` for a random name with a 0x0300 value, inside a transaction that it
rolls back (#1564). The value is of a random password nobody holds. 2019
answers 15021, and 2022 and 2025 answer ok (11, HV6). No login is left, but an
auditor may see the statement. This measures what each place keeps of it, and
of the two statements that change a password:

  HC1  the check, sent by the driver itself as a tool login that holds only
       ALTER ANY LOGIN: `MssqlSession.hash_version()`, which sends
       `capabilities.check_statement()`. The probe records each statement the
       session sends, so it knows the login name and the value it chose
  HC2  UC-1's change: `statements.set_password_value()`, a value of the
       version HC1 read, sent by the tool login
  HC3  UC-2's seen reset: `password.MustChange`, sent by the tool login,
       for three passwords of 32 characters: with no `'`, with one, and with
       four. The literal doubles each `'`
  HC4  a control, which holds no password: a query the tool login sends with
       a marker in a comment, and xp_logevent with the marker, sent by sa. It
       shows that each place records a statement it can hold, so that "no
       row" there means the server kept none

Each is read back from:

  xevents      an Extended Events session, on probe 01's events:
               sql_batch_starting, sql_batch_completed, sql_statement_starting,
               sql_statement_completed and error_reported, to a ring buffer,
               for the tool login only. A lost event fails the step
  audit        a server audit to a file, with LOGIN_CHANGE_PASSWORD_GROUP,
               SERVER_PRINCIPAL_CHANGE_GROUP and BATCH_COMPLETED_GROUP, the
               tool login's records: action, succeeded, the object's name, and
               the statement
  trace        the default trace, the tool login's rows: the event, its
               success, and its text or, with none, the name it is about
  plan cache   sys.dm_exec_cached_plans with sys.dm_exec_sql_text
  error log    xp_readerrorlog, the current log

The event session and the audit start after the driver's session has read
what it reads on its first call (its scope), so each tool row in them is a
case's. Each row is shown with the check's login name as `<name>`. A value or
a password in a row is shown by what of it is there: `<check value>` for
the whole of HC1's value, `<change value: last 70 of 140 hex digits>` for its
end after `******`, and `<pw1: last 1 of 33 characters>` for the end of HC3's
second literal. Any other run of 4 or more of its characters adds `[PART OF
<what>]` to the row. The probe draws every password and value, and prints
none of them.

The probe checks each result against the one RESULTS below records. A
difference, or a step that fails, makes it exit 1.

It MEASURES and decides nothing.

STATUS: run on 15.0.4510.2, 16.0.4325.4 and 17.0.5065.9, the
mcr.microsoft.com/mssql/server 2019-latest, 2022-latest and 2025-latest images
of test/compose.yaml profile mssql-matrix, with Python 3.13.12, pyodbc 5.5.0
and ODBC Driver 18 on Windows 11 AMD64, on 2026-11-18 (#1569). Twice, exit 0,
and the same result every time.

RESULTS -- the same on every release, except where noted

  HC1  the session reads 0x0200 on 15.0.4510.2 and 0x0300 on 16.0.4325.4 and
       17.0.5065.9. It sends the check, and on 15.0.4510.2, which answers
       15021, also `IF @@TRANCOUNT > 0 ROLLBACK TRANSACTION`. No login is
       left
  xevents  the check's batch as `BEGIN TRANSACTION; --*CREATE LOGIN---
       ROLLBACK TRANSACTION`, with no name and no value, and statement events
       for `BEGIN TRANSACTION;`, `-- CREATE LOGIN` and `ROLLBACK
       TRANSACTION`. On 15.0.4510.2 also error_reported, "Invalid value given
       for parameter PASSWORD. Specify a valid parameter value.", which names
       no login, and the driver's `IF @@TRANCOUNT > 0`. HC2 and HC3 as
       `--*ALTER LOGIN---` and `-- ALTER LOGIN`. The control, HC4
  audit    **BATCH_COMPLETED_GROUP (BCM) keeps the end of a literal in
       clear.** It replaces as many characters as the value or the password
       has, and leaves the rest of the literal. A value's literal is 140 hex
       digits for 70 bytes, so BCM keeps its last 70 hex digits: the check's
       and the change's. A password's literal doubles each `'`, so BCM keeps
       as many of its last characters as the password has `'`: none, 1 and
       4. **The other records mask the value and the password whole:** CR,
       the check's `CREATE LOGIN`, with succeeded 1 also on 15.0.4510.2,
       which refuses it, and on the others, where it is rolled back; PWR and
       PWPL, the change; PWEX, PWMC and PWPL, the seen reset. CR names the
       check's login, and on 16.0.4325.4 and 17.0.5065.9 has it as its
       object. The control in BCM
  trace    the check as Audit Addlogin Event, success 1, with no text, naming
       the check's login. HC2 and HC3 as Audit Login Change Property Event,
       masked whole
  plan cache and error log
       only the control, HC4

  So whoever can read a server audit with BATCH_COMPLETED_GROUP reads the
  last 35 of a value's 64 digest bytes, but not its salt, and the last
  characters of a password sent in clear with `'` in it. Every other place
  measured masks both whole, or keeps no text.

HOW TO RUN, against the matrix (test/README.md), from the repo root, with
the package's src on the path and pyodbc with ODBC Driver 18 installed:

    PYTHONPATH=src .venv/Scripts/python sql/mssql/16_hash_check_audit_probe.py

It needs 02_client_hash_probe.py beside it. It reaches each server on
127.0.0.1 at the port the matrix publishes, SOPULI_TEST_MSSQL2019_PORT,
SOPULI_TEST_MSSQL2022_PORT and SOPULI_TEST_MSSQL2025_PORT, by default 14319,
14322 and 14325.

THROWAWAY SERVERS ONLY. It creates and drops the logins sopuli_probe_tool and
sopuli_probe_hash, the event session sopuli_probe_hc_xe, and the server audit
sopuli_probe_hc_audit and its specification. It deletes the audit's files,
which hold the ends of the test passwords, also when a drop fails. A run that
is stopped before its clean-up leaves them in /var/opt/mssql/data/; the next
run deletes them. The control's marker stays in the error log until it is
cycled.
"""

from __future__ import annotations

import importlib.util
import os
import re
import secrets
import string
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

from sopuli.config.model import ExpandedTarget, Target, TargetMssql
from sopuli.driver.mssql.password import MustChange, password_value
from sopuli.driver.mssql.session import MssqlDriver
from sopuli.driver.mssql.statements import set_password_value
from sopuli.driver.protocol import Credential
from sopuli.secrets import Secret

# 02's name starts with a digit, so it is loaded by its path.
_SPEC = importlib.util.spec_from_file_location(
    "mssql_client_hash_probe", Path(__file__).with_name("02_client_hash_probe.py")
)
assert _SPEC is not None
assert _SPEC.loader is not None
ch = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(ch)

SESSION = "sopuli_probe_hc_xe"
AUDIT = "sopuli_probe_hc_audit"
AUDIT_PATH = "/var/opt/mssql/data/sopuli_probe_hc_audit/"
GROUPS = ["LOGIN_CHANGE_PASSWORD_GROUP", "SERVER_PRINCIPAL_CHANGE_GROUP", "BATCH_COMPLETED_GROUP"]
EVENTS = (
    "sql_batch_starting",
    "sql_batch_completed",
    "sql_statement_starting",
    "sql_statement_completed",
    "error_reported",
)
#: The published port of each server, as test/compose.yaml sets it.
PORTS = {
    "mssql-2019": ("SOPULI_TEST_MSSQL2019_PORT", "14319"),
    "mssql-2022": ("SOPULI_TEST_MSSQL2022_PORT", "14322"),
    "mssql-2025": ("SOPULI_TEST_MSSQL2025_PORT", "14325"),
}
#: HC3's passwords: how many `'` each holds, and its length.
QUOTES = (0, 1, 4)
LENGTH = 32
#: No `'` here: HC3 places its own.
ALPHABET = string.ascii_letters + string.digits + "-_.!"


class Recording:
    """The driver session's connection, keeping the text of each statement."""

    def __init__(self, connection: Any) -> None:
        self._connection = connection
        self.statements: list[str] = []

    def cursor(self) -> Any:
        return _RecordingCursor(self._connection.cursor(), self.statements)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._connection, name)


class _RecordingCursor:
    def __init__(self, cursor: Any, statements: list[str]) -> None:
        self._cursor = cursor
        self._statements = statements

    def execute(self, sql: str, *params: Any) -> Any:
        self._statements.append(sql)
        self._cursor.execute(sql, *params)
        return self

    def __getattr__(self, name: str) -> Any:
        return getattr(self._cursor, name)


def draw(quotes: int) -> str:
    """A password of LENGTH characters, with `quotes` copies of `'` inside
    it, not at its end, that the Linux images' policy takes."""
    while True:
        chars = [secrets.choice(ALPHABET) for _ in range(LENGTH)]
        for i in range(quotes):
            chars[4 + 4 * i] = "'"
        password = "".join(chars)
        if (
            any(c.islower() for c in password)
            and any(c.isupper() for c in password)
            and any(c.isdigit() for c in password)
        ):
            return password


class Shown:
    """What the run sent, and how a row that holds it is shown."""

    def __init__(self) -> None:
        self.name = ""
        self.marker = "HashCheckControl" + secrets.token_hex(4)
        #: (label, literal, prefix, suffix): a value or a password, as the
        #: statement writes it, and the text around its masked form.
        self.literals: list[tuple[str, str, str, str]] = []

    def value(self, label: str, statement: str) -> None:
        found = re.search(r"PASSWORD = 0x([0-9A-Fa-f]+) HASHED", statement)
        if found is None:
            raise ch.StepError(f"{label}: no value in the statement")
        self.literals.append((label, found[1].lower(), "0x******", " hashed"))

    def password(self, label: str, password: str) -> None:
        self.literals.append((label, password.replace("'", "''"), "******", "' must_change"))

    def shown(self, text: str) -> str:
        flat = flattened(text)
        if self.name:
            flat = re.sub(re.escape(self.name), "<name>", flat, flags=re.IGNORECASE)
        flat = flat.replace(self.marker, "<marker>")
        parts = []
        for label, literal, prefix, suffix in self.literals:
            flat = re.sub(re.escape(literal), f"<{label}>", flat, flags=re.IGNORECASE)
            # The end of the literal after the mask, as the audit leaves it.
            lowered = flat.lower()
            for size in range(len(literal) - 1, 0, -1):
                tail = prefix + literal[-size:].lower() + suffix
                at = lowered.find(tail)
                if at >= 0:
                    start = at + len(prefix)
                    flat = (
                        flat[:start]
                        + f"<{label}: last {size} of {len(literal)}>"
                        + flat[start + size :]
                    )
                    break
            if leftover(literal, flat):
                parts.append(label)
        return flat + "".join(f" [PART OF {label}]" for label in parts)


def flattened(text: str) -> str:
    """`text` on one line. Extended Events writes a masked statement as
    dashes, as many as the statement is long; three stand for any number."""
    return re.sub(r"-{3,}", "---", " ".join(text.split()))


def leftover(literal: str, text: str) -> bool:
    """Whether `text` still holds a part of `literal`: its last 4 characters
    or more, or any 8 in a row. A shorter run could be other words by
    chance."""
    lowered, literal = text.lower(), literal.lower()
    return literal[-4:] in lowered or any(
        literal[i : i + 8] in lowered for i in range(len(literal) - 7)
    )


def port(service: str) -> int:
    variable, default = PORTS[service]
    return int(os.environ.get(variable, default))


def connect(service: str) -> Any:
    """The driver's session, as the tool login, with its statements recorded."""
    target = ExpandedTarget(
        target=Target(
            name=service,
            type="mssql",
            dsn=f"127.0.0.1:{port(service)}",
            mssql=TargetMssql(trust_server_certificate=True),
        )
    )
    session = MssqlDriver(correlation_id="probe-16").connect(
        target, Credential(username=ch.TOOL, secret=Secret(ch.TOOL_PASSWORD))
    )
    session.connection = Recording(session.connection)
    return session


def cleanup(service: str) -> None:
    """Drop the event session and the audit, and delete the audit's files,
    which hold the ends of the test passwords, even if a drop fails."""
    try:
        ch.sa(
            service,
            f"IF EXISTS (SELECT 1 FROM sys.server_event_sessions WHERE name = '{SESSION}') "
            f"DROP EVENT SESSION [{SESSION}] ON SERVER;\n"
            f"IF EXISTS (SELECT 1 FROM sys.server_audit_specifications WHERE name = '{AUDIT}') "
            f"BEGIN ALTER SERVER AUDIT SPECIFICATION [{AUDIT}] WITH (STATE = OFF); "
            f"DROP SERVER AUDIT SPECIFICATION [{AUDIT}] END;\n"
            f"IF EXISTS (SELECT 1 FROM sys.server_audits WHERE name = '{AUDIT}') "
            f"BEGIN ALTER SERVER AUDIT [{AUDIT}] WITH (STATE = OFF); "
            f"DROP SERVER AUDIT [{AUDIT}] END",
        )
    finally:
        removed = subprocess.run(
            ["docker", "exec", ch.container(service), "rm", "-rf", AUDIT_PATH],
            capture_output=True,
            check=False,
        )
        if removed.returncode != 0:
            raise ch.StepError(f"{service}: removing {AUDIT_PATH}: {removed.stderr[:200]!r}")


def prepare(service: str) -> None:
    """Start the event session, for the tool login only, and the audit."""
    events = ", ".join(
        f"ADD EVENT sqlserver.{name} (WHERE (sqlserver.server_principal_name = N'{ch.TOOL}'))"
        for name in EVENTS
    )
    ch.sa(service, f"EXEC xp_create_subdir N'{AUDIT_PATH}'")
    ch.sa(
        service,
        f"CREATE EVENT SESSION [{SESSION}] ON SERVER {events} "
        "ADD TARGET package0.ring_buffer (SET max_memory = 4096) "
        # error_reported cannot be in a session with NO_EVENT_LOSS, 25643.
        "WITH (EVENT_RETENTION_MODE = ALLOW_SINGLE_EVENT_LOSS, MAX_DISPATCH_LATENCY = 1 SECONDS);\n"
        f"ALTER EVENT SESSION [{SESSION}] ON SERVER STATE = START;\n"
        f"CREATE SERVER AUDIT [{AUDIT}] TO FILE (FILEPATH = N'{AUDIT_PATH}');\n"
        f"CREATE SERVER AUDIT SPECIFICATION [{AUDIT}] FOR SERVER AUDIT [{AUDIT}] "
        + ", ".join(f"ADD ({group})" for group in GROUPS)
        + " WITH (STATE = ON);\n"
        f"ALTER SERVER AUDIT [{AUDIT}] WITH (STATE = ON)",
    )


def rows(out: str) -> list[tuple[str, str, str]]:
    return [line.partition("|") for line in out.splitlines() if line.strip()]


def xevents(service: str, shown: Shown) -> list[str]:
    """Every event of the tool login. A lost event fails the step."""
    ch.sa(service, "WAITFOR DELAY '00:00:03'")
    target = (
        "(SELECT CAST(t.target_data AS xml) FROM sys.dm_xe_session_targets t "
        "JOIN sys.dm_xe_sessions s ON s.address = t.event_session_address "
        f"WHERE s.name = '{SESSION}' AND t.target_name = 'ring_buffer')"
    )
    lost = ch.sa(
        service,
        f"DECLARE @x xml = {target};\n"
        "SELECT CAST(s.dropped_event_count AS varchar(20)) + ',' "
        "+ CAST(s.dropped_buffer_count AS varchar(20)) + ',' "
        "+ ISNULL(@x.value('(/RingBufferTarget/@droppedCount)[1]', 'varchar(20)'), '?') + ',' "
        "+ CAST(@x.value('count(/RingBufferTarget/event)', 'int') AS varchar(20)) + ',' "
        "+ ISNULL(@x.value('(/RingBufferTarget/@eventCount)[1]', 'varchar(20)'), '?') "
        f"FROM sys.dm_xe_sessions s WHERE s.name = '{SESSION}'",
    )
    events, buffers, dropped, counted, total = lost.split(",")
    if (events, buffers, dropped) != ("0", "0", "0") or counted != total:
        raise ch.StepError(
            f"{service}: Extended Events lost events: session {events}, buffers {buffers}, "
            f"ring buffer {dropped}; {counted} of {total} events in its XML"
        )
    out = ch.sa(
        service,
        f"DECLARE @x xml = {target};\n"
        "SELECT e.value('@name', 'nvarchar(64)') + '.' + d.value('@name', 'nvarchar(64)') "
        "+ '|' + REPLACE(REPLACE(d.value('(value)[1]', 'nvarchar(max)'), CHAR(10), ' '), "
        "CHAR(13), ' ') "
        "FROM @x.nodes('/RingBufferTarget/event') AS events(e) "
        "CROSS APPLY e.nodes('data') AS fields(d) "
        "WHERE d.value('@name', 'nvarchar(64)') IN ('batch_text', 'statement', 'message')",
    )
    if shown.marker not in out:
        raise ch.StepError(f"{service}: the control is not in the event session")
    return sorted({f"{where}: {shown.shown(text)}" for where, _, text in rows(out)})


def audit(service: str, utc: str, shown: Shown) -> list[str]:
    """The tool login's audit records since `utc`, which is UTC."""
    ch.sa(service, f"ALTER SERVER AUDIT [{AUDIT}] WITH (STATE = OFF)")
    out = ch.sa(
        service,
        "SELECT action_id + ' succeeded=' + CAST(succeeded AS varchar(1)) "
        "+ ' object=' + ISNULL(NULLIF(object_name, ''), '-') + '|' "
        "+ REPLACE(REPLACE(ISNULL(statement, ''), CHAR(10), ' '), CHAR(13), ' ') "
        f"FROM sys.fn_get_audit_file(N'{AUDIT_PATH}*', DEFAULT, DEFAULT) "
        f"WHERE event_time >= CONVERT(datetime2, '{utc}') "
        f"AND server_principal_name = N'{ch.TOOL}'",
    )
    return sorted({f"{shown.shown(where)}: {shown.shown(text)}" for where, _, text in rows(out)})


def default_trace(service: str, local: str, shown: Shown) -> list[str]:
    """The tool login's default trace rows since `local`, the server's local time."""
    out = ch.sa(
        service,
        "DECLARE @path nvarchar(260) = (SELECT path FROM sys.traces WHERE is_default = 1);\n"
        "SELECT CAST(e.name AS nvarchar(128)) + ' success=' "
        "+ ISNULL(CAST(t.Success AS varchar(4)), '-') + '|' + "
        "REPLACE(REPLACE(COALESCE(CAST(t.TextData AS nvarchar(max)), "
        "N'(no text) ' + COALESCE(t.TargetLoginName, t.ObjectName, N'')), "
        "CHAR(10), ' '), CHAR(13), ' ') "
        "FROM sys.fn_trace_gettable(@path, DEFAULT) t "
        "JOIN sys.trace_events e ON e.trace_event_id = t.EventClass "
        f"WHERE t.StartTime >= CONVERT(datetime2, '{local}') AND t.LoginName = N'{ch.TOOL}'",
    )
    return sorted({f"{where}: {shown.shown(text)}" for where, _, text in rows(out)})


def ours(shown: Shown, text: str) -> bool:
    """Whether a server-wide row holds the name, the marker or a literal."""
    return shown.shown(text) != flattened(text)


def plan_cache(service: str, shown: Shown) -> list[str]:
    out = ch.sa(
        service,
        "SELECT '|' + REPLACE(REPLACE(t.text, CHAR(10), ' '), CHAR(13), ' ') "
        "FROM sys.dm_exec_cached_plans p CROSS APPLY sys.dm_exec_sql_text(p.plan_handle) t",
    )
    return sorted({shown.shown(text) for _, _, text in rows(out) if ours(shown, text)})


def error_log(service: str, local: str, shown: Shown) -> list[str]:
    out = ch.sa(service, f"EXEC xp_readerrorlog 0, 1, NULL, NULL, '{local}', NULL")
    # LogDate | ProcessInfo | Text
    texts = [line.split("|", 2)[-1] for line in out.splitlines()]
    return sorted({shown.shown(text) for text in texts if ours(shown, text)})


def send(service: str, session: Any, major: str, shown: Shown) -> None:
    """HC1 to HC4."""
    start = len(session.connection.statements)
    version = session.hash_version()
    sent = session.connection.statements[start:]
    check = [s for s in sent if "CREATE LOGIN" in s]
    if len(check) != 1:
        raise ch.StepError(f"{service}: expected one CREATE LOGIN from the driver, got {sent!r}")
    name = re.search(r"CREATE LOGIN \[([^\]]+)\]", check[0])
    if name is None:
        raise ch.StepError(f"{service}: the check names no login")
    shown.name = name[1]
    shown.value("check value", check[0])
    print(f"HC1 the driver sent {len(sent)} statement(s):")
    for statement in sent:
        print(f"    {shown.shown(statement)}")
    print(f"HC1 the session reads version 0x{version:04X}")
    ch.check("HC1 version", f"0x{version:04X}", VERSIONS.get(major))
    ch.check("HC1 sent", [shown.shown(s) for s in sent], SENT.get(major))
    left = ch.sa(service, f"SELECT CASE WHEN SUSER_ID(N'{shown.name}') IS NULL THEN 0 ELSE 1 END")
    print(f"HC1 the login exists afterwards: {left}")
    ch.check("HC1 left", left, "0")

    cursor = session.connection.cursor()
    change = set_password_value(
        ch.ACCOUNT, password_value(Secret(secrets.token_urlsafe(24)), version)
    )
    shown.value("change value", change)
    cursor.execute(change)
    print("HC2 the change: ok")

    for i, quotes in enumerate(QUOTES):
        password = draw(quotes)
        shown.password(f"pw{i}", password)
        MustChange(ch.ACCOUNT, Secret(password), unlock=False).send(session.connection.cursor())
        print(f"HC3 pw{i}, {LENGTH} characters with {quotes} of ': ok")

    cursor = session.connection.cursor()
    cursor.execute(f"SELECT /* {shown.marker} */ COUNT(*) FROM sys.objects WHERE object_id > 0")
    cursor.fetchall()
    ch.sa(service, f"EXEC xp_logevent 60000, N'{shown.marker}', informational")


def cases(service: str) -> None:
    major = ch.setup(service).split(".")[0]
    cleanup(service)
    shown = Shown()
    session = connect(service)
    try:
        # The session's first reads, before anything records.
        session.scope()
        prepare(service)
        print(f"audit groups: {GROUPS}")
        utc, local = ch.sa(
            service,
            "SELECT CONVERT(varchar(27), SYSUTCDATETIME(), 121) + '|' "
            # Milliseconds, as xp_readerrorlog takes no finer a time, 22004.
            "+ CONVERT(varchar(23), SYSDATETIME(), 121)",
        ).split("|")
        send(service, session, major, shown)
    finally:
        session.close()
    readers: tuple[tuple[str, Callable[[], list[str]]], ...] = (
        ("xevents", lambda: xevents(service, shown)),
        ("audit", lambda: audit(service, utc, shown)),
        ("trace", lambda: default_trace(service, local, shown)),
        ("plan cache", lambda: plan_cache(service, shown)),
        ("error log", lambda: error_log(service, local, shown)),
    )
    for place, read in readers:
        got = read()
        print(f"{place}:")
        for row in got:
            print(f"    {row}")
        ch.check(f"{place}", got, RECORDED[major][place] if major in RECORDED else None)


#: The version each major release reads.
VERSIONS = {"15": "0x0200", "16": "0x0300", "17": "0x0300"}
_CHECK = (
    "BEGIN TRANSACTION; CREATE LOGIN [<name>] WITH PASSWORD = 0x<check value> HASHED, "
    "CHECK_POLICY = OFF; ROLLBACK TRANSACTION"
)
#: The statements HC1 sends, by major release.
SENT = {
    "15": [_CHECK, "IF @@TRANCOUNT > 0 ROLLBACK TRANSACTION"],
    "16": [_CHECK],
    "17": [_CHECK],
}
_CONTROL = "SELECT /* <marker> */ COUNT(*) FROM sys.objects WHERE object_id > 0"
_ACCOUNT = "ALTER LOGIN [sopuli_probe_hash] WITH PASSWORD = "
_RESET = " MUST_CHANGE, CHECK_POLICY = ON, CHECK_EXPIRATION = ON"
_HASHED = _ACCOUNT + "0x****** HASHED, CHECK_POLICY = OFF"
_MASKED_RESET = _ACCOUNT + "N'******'" + _RESET
_BCM = "BCM succeeded=1 object=master: "
_PW = "PW{} succeeded=1 object=sopuli_probe_hash: "
_XE_TAKES = [
    "sql_batch_completed.batch_text: --*ALTER LOGIN---",
    "sql_batch_completed.batch_text: BEGIN TRANSACTION; --*CREATE LOGIN--- ROLLBACK TRANSACTION",
    f"sql_batch_completed.batch_text: {_CONTROL}",
    "sql_batch_starting.batch_text: --*ALTER LOGIN---",
    "sql_batch_starting.batch_text: BEGIN TRANSACTION; --*CREATE LOGIN--- ROLLBACK TRANSACTION",
    f"sql_batch_starting.batch_text: {_CONTROL}",
    "sql_statement_completed.statement: -- ALTER LOGIN",
    "sql_statement_completed.statement: -- CREATE LOGIN",
    "sql_statement_completed.statement: BEGIN TRANSACTION;",
    "sql_statement_completed.statement: ROLLBACK TRANSACTION",
    f"sql_statement_completed.statement: {_CONTROL}",
    "sql_statement_starting.statement: -- ALTER LOGIN",
    "sql_statement_starting.statement: -- CREATE LOGIN",
    "sql_statement_starting.statement: BEGIN TRANSACTION;",
    "sql_statement_starting.statement: ROLLBACK TRANSACTION",
    f"sql_statement_starting.statement: {_CONTROL}",
]
#: The 2019 events: the check is refused, so its statement has no completed
#: event, and the driver ends the transaction.
_XE_REFUSES = sorted(
    [
        "error_reported.message: Invalid value given for parameter PASSWORD. "
        "Specify a valid parameter value.",
        "sql_batch_completed.batch_text: IF @@TRANCOUNT > 0 ROLLBACK TRANSACTION",
        "sql_batch_starting.batch_text: IF @@TRANCOUNT > 0 ROLLBACK TRANSACTION",
        "sql_statement_completed.statement: IF @@TRANCOUNT > 0",
        "sql_statement_starting.statement: IF @@TRANCOUNT > 0",
        *(e for e in _XE_TAKES if e != "sql_statement_completed.statement: -- CREATE LOGIN"),
    ]
)


def _audit(check_object: str, refused: bool) -> list[str]:
    return sorted(
        [
            _BCM + _ACCOUNT + "0x******<change value: last 70 of 140> HASHED, CHECK_POLICY = OFF",
            _BCM + _MASKED_RESET,
            _BCM + _ACCOUNT + "N'******<pw1: last 1 of 33>'" + _RESET,
            _BCM + _ACCOUNT + "N'******<pw2: last 4 of 36>'" + _RESET,
            _BCM + "BEGIN TRANSACTION; CREATE LOGIN [<name>] WITH PASSWORD = "
            "0x******<check value: last 70 of 140> HASHED, CHECK_POLICY = OFF; "
            "ROLLBACK TRANSACTION",
            *([_BCM + "IF @@TRANCOUNT > 0 ROLLBACK TRANSACTION"] if refused else []),
            _BCM + _CONTROL,
            f"CR succeeded=1 object={check_object}: CREATE LOGIN [<name>] WITH PASSWORD = "
            "0x****** HASHED, CHECK_POLICY = OFF;",
            _PW.format("EX") + _MASKED_RESET,
            _PW.format("MC") + _MASKED_RESET,
            _PW.format("PL") + _HASHED,
            _PW.format("PL") + _MASKED_RESET,
            _PW.format("R") + _HASHED,
        ]
    )


_SAME = {
    "trace": [
        "Audit Addlogin Event success=1: (no text) <name>",
        f"Audit Login Change Property Event success=1: {_HASHED}",
        f"Audit Login Change Property Event success=1: {_MASKED_RESET}",
    ],
    "plan cache": [_CONTROL],
    "error log": ["<marker>"],
}
#: What each place keeps, by major release.
RECORDED = {
    "15": {"xevents": _XE_REFUSES, "audit": _audit("-", refused=True), **_SAME},
    "16": {"xevents": _XE_TAKES, "audit": _audit("<name>", refused=False), **_SAME},
    "17": {"xevents": _XE_TAKES, "audit": _audit("<name>", refused=False), **_SAME},
}


def probe(service: str) -> None:
    ch.cleaned(service, lambda: cases(service), lambda: cleanup(service))


def main() -> int:
    return ch.run(probe)


if __name__ == "__main__":
    sys.exit(main())
