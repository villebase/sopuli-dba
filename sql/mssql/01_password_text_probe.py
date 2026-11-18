"""sopuli-dba : what SQL Server keeps of the text of a password change

#1538, M1. Invariant 15 keeps the password from reaching PostgreSQL, MySQL and
MariaDB, because each keeps the statement's text somewhere. This measures where
each of these statements lands on SQL Server, and whether the password is in
it:

  PT0  CREATE LOGIN ... WITH PASSWORD = '<password>'
  PT1  ALTER LOGIN ... WITH PASSWORD = '<password>', which succeeds
  PT2  the same statement for a login that does not exist, which fails when
       it runs
  PT3  the same statement with a syntax error after the password, which fails
       when it is parsed
  PT4  the same statement with CHECK_POLICY = ON and a password the policy
       refuses
  PT5  ALTER LOGIN ... WITH PASSWORD = 0x... HASHED, the form a client that
       computes the hash itself would send (02)
  PT6  PT1's statement sent as dynamic SQL, EXEC (N'...'), for a second
       login, sopuli_probe_dyn, so that its rows can be told from PT1's
  PT7  a control, which holds no password: a query whose comment holds a
       marker, and xp_logevent with the marker. It shows that each place
       records a statement it can hold, so that "no case" there means the
       server kept none

Each case is its own batch, sent from a database with Query Store on, so that
Query Store can capture it. Each is read back from:

  xevents      an Extended Events session, on sql_batch_starting,
               sql_batch_completed, sql_statement_starting,
               sql_statement_completed and error_reported, to a ring buffer,
               for events in that database only. A lost event fails the step,
               so that an event the server left out is not one the buffer lost
  plan cache   sys.dm_exec_cached_plans with sys.dm_exec_sql_text, every
               statement cached, from this run or an earlier one
  query store  sys.query_store_query_text, in the database the run creates
  audit        a server audit to a file, with LOGIN_CHANGE_PASSWORD_GROUP,
               SERVER_PRINCIPAL_CHANGE_GROUP and BATCH_COMPLETED_GROUP, from
               the start of the cases
  trace        the default trace, from the start of the cases
  error log    xp_readerrorlog, the current log, from the start of the cases

Each row about a case is labelled with the case and with what it holds: `PT1
clear`, PT1's password; `PT5 hash`, PT5's value; `PT5 hash, last 70 of 140
hex digits`, the end of PT5's value, 4 hex digits or more right after
`0x******`, where the rest is replaced; `PT1 masked`, PT1's statement with
the password replaced; `PT2 message`, an error message that holds none.
A case with no marker is told by the rest of its text (SHAPES). Any other row
is labelled with its first characters, as SQL Server wrote it.

The probe checks each result against the one RESULTS below records. A
difference, or a step that fails, makes it exit 1.

It MEASURES and decides nothing.

STATUS: run on 15.0.4510.2, 16.0.4325.4 and 17.0.5065.9, the
mcr.microsoft.com/mssql/server 2019-latest, 2022-latest and 2025-latest images
of test/compose.yaml profile mssql-matrix, as pulled on 2026-11-15, with
Python 3.13.12 on Windows 11 AMD64, on 2026-11-15 (#1538). Twice, the first
time on servers just created, exit 0, and the same result every time. Run
again on the same three releases on 2026-11-18 (#1601), twice, exit 0, with
the label that finds the end of PT5's value; the runs of 2026-11-15 looked
only for the whole value.

RESULTS -- the same on every release

  answers  PT0, PT1, PT5, PT6 and PT7 succeed. PT2 fails, 15151, PT3 fails,
       102, and PT4 fails, 33064
  xevents  no event of PT0, PT1, PT2, PT4 or PT5 holds its statement: the
       server leaves them out. PT3 is in the batch events, password in clear.
       PT6 is in the batch and statement events, password in clear. PT2's
       error message names the login and holds no password. The control,
       PT7, is in the batch and statement events
  plan cache and query store
       only the control, PT7
  audit    PT0, PT1, PT2 and PT4 in BATCH_COMPLETED_GROUP (BCM), and in CR,
       PWR and PWPL, with the password replaced by `******`. **PT5 in BCM
       with its value's last 70 hex digits in clear**: BCM replaces 70
       characters, as many as the value has bytes, and the literal has 140.
       PT5 in PWR with the value replaced whole. PT3 and PT6 in BCM, password
       in clear. PT6 also in PWR, masked. The control in BCM
  trace    PT0 as Audit Addlogin Event, with no text. PT4 as Audit Login
       Change Property Event, password replaced by `******`. No other case.
       The default trace takes no statement of the probe's choosing, so it
       has no control; the Addlogin row shows that it records
  error log
       only the control, PT7

  So a password statement sent as a batch of its own, which parses, keeps
  its password out of each place measured: its events are left out, and the
  audit and the trace replace the password. The password is in clear, in
  Extended Events and in the audit's BATCH_COMPLETED_GROUP, in two cases: a
  statement that fails to parse, and a statement inside dynamic SQL, which
  parses. A HASHED value keeps half of its hex digits in clear in
  BATCH_COMPLETED_GROUP. 16_hash_check_audit_probe.py measures this for
  the driver's statements, and for a password that holds `'`.

HOW TO RUN, against the matrix (test/README.md), from the repo root:

    .venv/Scripts/python sql/mssql/01_password_text_probe.py

It needs 02_client_hash_probe.py beside it.

THROWAWAY SERVERS ONLY. It creates and drops the logins sopuli_probe_pw and
sopuli_probe_dyn, the database sopuli_probe_qs, the event session
sopuli_probe_xe, and the server audit sopuli_probe_audit and its
specification. It deletes the audit's files, which hold PT3's and PT6's test
passwords in clear, also when a drop fails. A run that is stopped before its
clean-up leaves those files in /var/opt/mssql/data/; the next run deletes
them. The control's marker stays in the error log until it is cycled.
"""

from __future__ import annotations

import importlib.util
import re
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

# 02's name starts with a digit, so it is loaded by its path.
_SPEC = importlib.util.spec_from_file_location(
    "mssql_client_hash_probe", Path(__file__).with_name("02_client_hash_probe.py")
)
assert _SPEC is not None
assert _SPEC.loader is not None
ch = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(ch)

LOGIN = "sopuli_probe_pw"
#: PT6's login, so that its masked rows can be told from PT1's: the statement
#: inside EXEC is PT1's but for the name.
LOGIN6 = "sopuli_probe_dyn"
DATABASE = "sopuli_probe_qs"
SESSION = "sopuli_probe_xe"
AUDIT = "sopuli_probe_audit"
AUDIT_PATH = "/var/opt/mssql/data/sopuli_probe_audit/"
#: The markers each case's password holds, so a row can be told apart. Test
#: passwords, not credentials. PT4's has one character class, so that the
#: policy refuses it.
MARKERS = {
    "PT0": "PwCreateMarker1a",
    "PT1": "PwPlainMarker4k",
    "PT2": "PwFailMarker9z",
    "PT3": "PwParseMarker5s",
    "PT4": "pwpolicymarker",
    "PT6": "PwDynamicMarker6t",
    "PT7": "ControlMarker8c",
}
#: PT5's value, of a password that no statement carries.
SEED_HASH = ch.password_hash("PwSeedMarker7q", bytes.fromhex("0a0b0c0d")).hex()
STATEMENTS = {
    "PT0": f"CREATE LOGIN [{LOGIN}] WITH PASSWORD = N'{MARKERS['PT0']}', CHECK_POLICY = OFF",
    "PT1": f"ALTER LOGIN [{LOGIN}] WITH PASSWORD = N'{MARKERS['PT1']}'",
    "PT2": f"ALTER LOGIN [sopuli_probe_missing] WITH PASSWORD = N'{MARKERS['PT2']}'",
    "PT3": f"ALTER LOGIN [{LOGIN}] WITH PASSWORD = N'{MARKERS['PT3']}' sopuli_bogus",
    "PT4": f"ALTER LOGIN [{LOGIN}] WITH PASSWORD = N'{MARKERS['PT4']}', CHECK_POLICY = ON",
    "PT5": f"ALTER LOGIN [{LOGIN}] WITH PASSWORD = 0x{SEED_HASH} HASHED",
    "PT6": f"EXEC (N'ALTER LOGIN [{LOGIN6}] WITH PASSWORD = N''{MARKERS['PT6']}''')",
    # The marker is in a comment, which parameterization leaves in the text,
    # and the query reads a table, so that it has a plan to cache. xp_logevent
    # writes the marker to the error log, and sends the client no message.
    "PT7": (
        f"SELECT /* {MARKERS['PT7']} */ COUNT(*) FROM sys.objects WHERE object_id > 0;\n"
        f"EXEC xp_logevent 60000, N'{MARKERS['PT7']}', informational"
    ),
}
#: The audit's action groups. Every release measured has each; a server
#: without one refuses the specification, and the step fails.
GROUPS = ["LOGIN_CHANGE_PASSWORD_GROUP", "SERVER_PRINCIPAL_CHANGE_GROUP", "BATCH_COMPLETED_GROUP"]
EVENTS = (
    "sql_batch_starting",
    "sql_batch_completed",
    "sql_statement_starting",
    "sql_statement_completed",
    "error_reported",
)


#: How a row with no marker is told to be a case, by the rest of its text, in
#: this order.
SHAPES = (
    ("sopuli_bogus", "PT3"),
    (LOGIN6, "PT6"),
    ("CREATE LOGIN", "PT0"),
    ("sopuli_probe_missing", "PT2"),
    ("CHECK_POLICY = ON", "PT4"),
    ("HASHED", "PT5"),
    (f"ALTER LOGIN [{LOGIN}] WITH PASSWORD", "PT1"),
)


def ours(text: str) -> bool:
    """Whether a row is about one of the cases.

    Not the statement DROP LOGIN runs to find jobs the login owns, by its name,
    which the plan cache keeps from a clean-up and which holds no password.
    """
    if "msdb.dbo.sysjobs" in text:
        return False
    return (
        LOGIN in text
        or LOGIN6 in text
        or "sopuli_probe_missing" in text
        or hash_tail(text) > 0
        or any(marker in text for marker in MARKERS.values())
    )


def hash_tail(text: str) -> int:
    """How many of the last hex digits of PT5's value `text` holds: all of
    them, or 4 or more right after the mask, `0x******`, where a server that
    masks only part of the value leaves its end; else 0. Four digits alone
    could be in any row by chance."""
    lowered = text.lower()
    if SEED_HASH.lower() in lowered:
        return len(SEED_HASH)
    start = lowered.find("0x******")
    while start >= 0:
        digits = re.match(r"[0-9a-f]*", lowered[start + 8 :])
        kept = digits[0] if digits else ""
        if len(kept) >= 4 and SEED_HASH.lower().endswith(kept):
            return len(kept)
        start = lowered.find("0x******", start + 8)
    return 0


def label(text: str) -> str:
    """Which case a row is, and whether it holds the password, the hash or neither.

    `PT1 clear` holds PT1's password. `PT5 hash` holds PT5's value. `PT1 masked`
    is PT1's statement with the password replaced, and `PT2 message` is an error
    message about PT2 that holds no password.
    """
    for case, marker in MARKERS.items():
        if marker in text:
            return f"{case} clear"
    tail = hash_tail(text)
    if tail == len(SEED_HASH):
        return "PT5 hash"
    if tail:
        return f"PT5 hash, last {tail} of {len(SEED_HASH)} hex digits"
    case = next((case for words, case in SHAPES if words in text), "other")
    if "******" in text:
        return f"{case} masked"
    if text.startswith(("Cannot alter the login", "Login failed")):
        return f"{case} message"
    if text.startswith("(no text)"):
        return "no text"
    return f"{case}: " + " ".join(text.split())[:70]


def cleanup(service: str) -> None:
    """Drop what the run made, and delete the audit's files, even if a drop fails."""
    try:
        drop(service)
    finally:
        # The audit's files hold PT3's and PT6's passwords in clear.
        removed = subprocess.run(
            ["docker", "exec", ch.container(service), "rm", "-rf", AUDIT_PATH],
            capture_output=True,
            check=False,
        )
        if removed.returncode != 0:
            raise ch.StepError(f"{service}: removing {AUDIT_PATH}: {removed.stderr[:200]!r}")


def drop(service: str) -> None:
    ch.sa(
        service,
        f"IF EXISTS (SELECT 1 FROM sys.server_event_sessions WHERE name = '{SESSION}') "
        f"DROP EVENT SESSION [{SESSION}] ON SERVER;\n"
        f"IF EXISTS (SELECT 1 FROM sys.server_audit_specifications WHERE name = '{AUDIT}') "
        f"BEGIN ALTER SERVER AUDIT SPECIFICATION [{AUDIT}] WITH (STATE = OFF); "
        f"DROP SERVER AUDIT SPECIFICATION [{AUDIT}] END;\n"
        f"IF EXISTS (SELECT 1 FROM sys.server_audits WHERE name = '{AUDIT}') "
        f"BEGIN ALTER SERVER AUDIT [{AUDIT}] WITH (STATE = OFF); DROP SERVER AUDIT [{AUDIT}] END;\n"
        f"IF DB_ID('{DATABASE}') IS NOT NULL BEGIN "
        f"ALTER DATABASE [{DATABASE}] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; "
        f"DROP DATABASE [{DATABASE}] END;\n" + ch.drop_login(LOGIN) + ";\n" + ch.drop_login(LOGIN6),
    )


def prepare(service: str) -> None:
    """Create PT6's login; start the event session, the audit and Query Store.

    The session records only events in the database the cases are sent from,
    so that other work on the server does not fill its buffer.
    """
    ch.sa(
        service,
        f"EXEC xp_create_subdir N'{AUDIT_PATH}';\n"
        f"CREATE LOGIN [{LOGIN6}] WITH PASSWORD = N'Acme-Probe-pw0', CHECK_POLICY = OFF",
    )
    events = ", ".join(
        f"ADD EVENT sqlserver.{name} (WHERE (sqlserver.database_name = N'{DATABASE}'))"
        for name in EVENTS
    )
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
        f"ALTER SERVER AUDIT [{AUDIT}] WITH (STATE = ON);\n"
        f"CREATE DATABASE [{DATABASE}];\n"
        f"ALTER DATABASE [{DATABASE}] SET QUERY_STORE = ON "
        "(OPERATION_MODE = READ_WRITE, QUERY_CAPTURE_MODE = ALL)",
    )
    # Query Store starts capturing once it is read in the database. Without
    # this read, a busy server left the control out of it.
    state = ch.sa(
        service, "SELECT actual_state_desc FROM sys.database_query_store_options", DATABASE
    )
    if state != "READ_WRITE":
        raise ch.StepError(f"{service}: Query Store is {state!r}, not READ_WRITE")


def send(service: str) -> dict[str, str]:
    """Send each case as its own batch; return what each answered."""
    answers = {}
    for case, statement in STATEMENTS.items():
        _, errors = ch.client(service, "sa", ch.SA_PASSWORD, statement, DATABASE)
        answers[case] = ch.code(errors)
    return answers


def xevents(service: str) -> list[str]:
    """The session's events. A lost event fails the step.

    The session may lose an event (error_reported needs that), and the ring
    buffer keeps only what fits, so an event that is not there may have been
    lost. The session's and the buffer's counts of lost events must be 0, or
    "the server leaves it out" could not be told from "it was lost".
    """
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
    events, buffers, dropped, shown, counted = lost.split(",")
    if (events, buffers, dropped) != ("0", "0", "0") or shown != counted:
        raise ch.StepError(
            f"{service}: Extended Events lost events: session {events}, buffers {buffers}, "
            f"ring buffer {dropped}; {shown} of {counted} events in its XML"
        )
    # The ring buffer's XML is longer than sqlcmd shows of a value, so the
    # server takes it apart: one row for each event's text.
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
    return labelled(out)


def labelled(out: str) -> list[str]:
    """`where | text` rows, each about a case, as `where: label`, once each."""
    rows = set()
    for line in out.splitlines():
        where, _, text = line.partition("|")
        if ours(text):
            rows.add(f"{where}: {label(text)}" if where else label(text))
    return sorted(rows)


def plan_cache(service: str) -> list[str]:
    """Every cached statement about a case, from this run or an earlier one."""
    out = ch.sa(
        service,
        "SELECT '|' + REPLACE(REPLACE(t.text, CHAR(10), ' '), CHAR(13), ' ') "
        "FROM sys.dm_exec_cached_plans p CROSS APPLY sys.dm_exec_sql_text(p.plan_handle) t",
    )
    return labelled(out)


def query_store(service: str) -> list[str]:
    """Every query text about a case, in the database this run created."""
    out = ch.sa(
        service,
        "EXEC sp_query_store_flush_db;\n"
        "SELECT '|' + REPLACE(REPLACE(query_sql_text, CHAR(10), ' '), CHAR(13), ' ') "
        "FROM sys.query_store_query_text",
        DATABASE,
    )
    return labelled(out)


def audit(service: str, utc: str) -> list[str]:
    """The audit's records since `utc`, which is UTC, as the audit records."""
    ch.sa(service, f"ALTER SERVER AUDIT [{AUDIT}] WITH (STATE = OFF)")
    out = ch.sa(
        service,
        "SELECT action_id + '|' + REPLACE(REPLACE(ISNULL(statement, ''), CHAR(10), ' '), "
        "CHAR(13), ' ') "
        f"FROM sys.fn_get_audit_file(N'{AUDIT_PATH}*', DEFAULT, DEFAULT) "
        f"WHERE event_time >= CONVERT(datetime2, '{utc}')",
    )
    return labelled(out)


def default_trace(service: str, local: str) -> list[str]:
    """The default trace's rows since `local`, the server's local time, as the trace records."""
    out = ch.sa(
        service,
        "DECLARE @path nvarchar(260) = (SELECT path FROM sys.traces WHERE is_default = 1);\n"
        "SELECT CAST(e.name AS nvarchar(128)) + '|' + "
        # A row with no text is shown by the names it has, so that one about a
        # case is kept; the event's name says which statement it is.
        "REPLACE(REPLACE(COALESCE(CAST(t.TextData AS nvarchar(max)), "
        "N'(no text) ' + COALESCE(t.TargetLoginName, t.ObjectName, N'')), "
        "CHAR(10), ' '), CHAR(13), ' ') "
        "FROM sys.fn_trace_gettable(@path, DEFAULT) t "
        "JOIN sys.trace_events e ON e.trace_event_id = t.EventClass "
        f"WHERE t.StartTime >= CONVERT(datetime2, '{local}')",
    )
    return labelled(out)


def error_log(service: str, local: str) -> list[str]:
    """The current error log's lines since `local`, the server's local time."""
    out = ch.sa(service, f"EXEC xp_readerrorlog 0, 1, NULL, NULL, '{local}', NULL")
    # LogDate | ProcessInfo | Text
    rows = set()
    for line in out.splitlines():
        text = line.split("|", 2)[-1]
        if ours(text):
            rows.add(label(text))
    return sorted(rows)


def cases(service: str) -> None:
    print(f"\n== {service}: {ch.release(service)}")
    cleanup(service)
    prepare(service)
    print(f"audit groups: {GROUPS}")
    utc, local = ch.sa(
        service,
        "SELECT CONVERT(varchar(27), SYSUTCDATETIME(), 121) + '|' "
        # Milliseconds, as xp_readerrorlog takes no finer a time, 22004.
        "+ CONVERT(varchar(23), SYSDATETIME(), 121)",
    ).split("|")
    answers = send(service)
    print(f"answers: {answers}")
    ch.check("answers", answers, ANSWERS)
    readers: tuple[tuple[str, Callable[[], list[str]]], ...] = (
        ("xevents", lambda: xevents(service)),
        ("plan cache", lambda: plan_cache(service)),
        ("query store", lambda: query_store(service)),
        ("audit", lambda: audit(service, utc)),
        ("trace", lambda: default_trace(service, local)),
        ("error log", lambda: error_log(service, local)),
    )
    for place, read in readers:
        rows = read()
        print(f"{place}:")
        for row in rows:
            print(f"    {row}")
        ch.check(place, rows, RECORDED[place])


ANSWERS = {
    "PT0": "ok",
    "PT1": "ok",
    "PT2": "15151",
    "PT3": "102",
    "PT4": "33064",
    "PT5": "ok",
    "PT6": "ok",
    "PT7": "ok",
}
#: Labels carry no count: two rows of one case in one place are one label.
RECORDED = {
    "xevents": [
        "error_reported.message: PT2 message",
        "sql_batch_completed.batch_text: PT3 clear",
        "sql_batch_completed.batch_text: PT6 clear",
        "sql_batch_completed.batch_text: PT7 clear",
        "sql_batch_starting.batch_text: PT3 clear",
        "sql_batch_starting.batch_text: PT6 clear",
        "sql_batch_starting.batch_text: PT7 clear",
        "sql_statement_completed.statement: PT6 clear",
        "sql_statement_completed.statement: PT7 clear",
        "sql_statement_starting.statement: PT6 clear",
        "sql_statement_starting.statement: PT7 clear",
    ],
    "plan cache": ["PT7 clear"],
    "query store": ["PT7 clear"],
    "audit": [
        "BCM: PT0 masked",
        "BCM: PT1 masked",
        "BCM: PT2 masked",
        "BCM: PT3 clear",
        "BCM: PT4 masked",
        "BCM: PT5 hash, last 70 of 140 hex digits",
        "BCM: PT6 clear",
        "BCM: PT7 clear",
        "CR: PT0 masked",
        "PWPL: PT4 masked",
        "PWR: PT1 masked",
        "PWR: PT4 masked",
        "PWR: PT5 masked",
        "PWR: PT6 masked",
    ],
    "trace": [
        "Audit Addlogin Event: no text",
        "Audit Login Change Property Event: PT4 masked",
    ],
    "error log": ["PT7 clear"],
}


def probe(service: str) -> None:
    ch.cleaned(service, lambda: cases(service), lambda: cleanup(service))


def main() -> int:
    return ch.run(probe)


if __name__ == "__main__":
    sys.exit(main())
