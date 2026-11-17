"""Invariant 15 on SQL Server: the password never reaches the server (#1551).

The driver sends the value it computed, with ``HASHED``. Two checks, because
neither is enough alone:

* **What the driver sends.** Every statement and bind the session sends is
  recorded at the client. None holds the password, and the change is an
  ``ALTER LOGIN … HASHED``. This is the check that catches a driver sending
  the password in clear: ``02-mssql-privileges.md`` §6.1 measured that a
  clear-text ``ALTER LOGIN`` that parses leaves no text in any place the
  server keeps (PT0 to PT2, PT4), so no server-side read can see it.
* **What the server keeps.** An Extended Events session records every
  statement, batch, call and error the tool login makes. The test then reads
  it, the plan cache, the default trace and the error log for the password.
  A control shows the reader finds a password where §6.1 says one is kept: a
  clear-text statement that does not parse (PT3).

The login made with the password in step 3 is a login, not a statement, and
carries it as every login does.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Iterator
from typing import Any

import pytest

pytest.importorskip("pyodbc")

from sopuli.config.model import ExpandedTarget, Target, TargetMssql  # noqa: E402
from sopuli.driver.mssql.password import password_value  # noqa: E402
from sopuli.driver.mssql.statements import set_password_value  # noqa: E402
from sopuli.driver.protocol import PASS, Credential  # noqa: E402
from sopuli.secrets import Secret  # noqa: E402

TOOL, TOOL_PASSWORD = "w1_np_tool", "W1-np-tool-pw-1"
LOGIN, OLD = "w1_np_acme_app", "W1-np-old-pw-1"


def xe_session(name: str) -> str:
    """Every statement, batch, call and error the tool login makes, with its
    text. The predicate keeps out the reader's own polling, which runs as
    `sa`, and every other connection to the instance."""
    where = f"WHERE (sqlserver.server_principal_name = N'{TOOL}')"
    events = ", ".join(
        f"ADD EVENT {event} (ACTION (sqlserver.sql_text, sqlserver.session_id) {where})"
        for event in (
            "sqlserver.sql_batch_starting",
            "sqlserver.sql_batch_completed",
            "sqlserver.sql_statement_completed",
            "sqlserver.rpc_completed",
            "sqlserver.error_reported",
        )
    )
    return (
        f"CREATE EVENT SESSION [{name}] ON SERVER {events} "
        "ADD TARGET package0.ring_buffer (SET max_memory = 8192) "
        # `NO_EVENT_LOSS` refuses `error_reported` (25643), so each test
        # waits for a marker sent after what it checks.
        "WITH (MAX_DISPATCH_LATENCY = 1 SECONDS)"
    )


class Recorder:
    """A running Extended Events session, and what else the server keeps."""

    def __init__(self, admin: Any, name: str) -> None:
        self.cursor = admin.cursor()
        self.name = name

    def start(self) -> None:
        self.cursor.execute(xe_session(self.name))
        self.cursor.execute(f"ALTER EVENT SESSION [{self.name}] ON SERVER STATE = START")

    def stop(self) -> None:
        self.cursor.execute(
            f"IF EXISTS (SELECT 1 FROM sys.server_event_sessions WHERE name = N'{self.name}') "
            f"DROP EVENT SESSION [{self.name}] ON SERVER"
        )

    def events(self) -> str:
        rows = self.cursor.execute(
            "SELECT CAST(t.target_data AS nvarchar(max)) FROM sys.dm_xe_session_targets t "
            "JOIN sys.dm_xe_sessions s ON s.address = t.event_session_address "
            "WHERE s.name = ? AND t.target_name = N'ring_buffer'",
            self.name,
        ).fetchall()
        return "".join(row[0] or "" for row in rows)

    def kept(self, marker: str) -> dict[str, str]:
        """The text of each place a statement could be kept, once the events
        hold ``marker``, which the caller sent after everything it checks.
        Stopping the session would empty its ring buffer, so this waits out
        the dispatch latency instead."""
        deadline = time.monotonic() + 15
        events = self.events()
        while marker not in events and time.monotonic() < deadline:
            time.sleep(0.5)
            events = self.events()
        assert marker in events, "the session recorded everything up to the marker"
        assert 'droppedCount="0"' in events, "the ring buffer dropped no event"
        cache = self.cursor.execute(
            "SELECT t.text FROM sys.dm_exec_cached_plans p "
            "CROSS APPLY sys.dm_exec_sql_text(p.plan_handle) t"
        ).fetchall()
        (default_traces,) = self.cursor.execute(
            "SELECT COUNT(*) FROM sys.traces WHERE is_default = 1"
        ).fetchone()
        assert default_traces == 1, "the default trace is on, so reading it checks something"
        trace = self.cursor.execute(
            "SELECT CAST(g.TextData AS nvarchar(max)) FROM sys.traces t "
            "CROSS APPLY sys.fn_trace_gettable(t.path, DEFAULT) g "
            "WHERE t.is_default = 1 AND g.TextData IS NOT NULL"
        ).fetchall()
        log = self.cursor.execute("EXEC sys.xp_readerrorlog 0, 1").fetchall()
        return {
            "extended events": events,
            "plan cache": "\n".join(row[0] or "" for row in cache),
            "default trace": "\n".join(row[0] or "" for row in trace),
            "error log": "\n".join(str(row[-1]) for row in log),
        }


class Sent:
    """The session's connection, recording each statement and its binds."""

    def __init__(self, connection: Any) -> None:
        self._connection = connection
        self.statements: list[str] = []

    def cursor(self) -> Any:
        return _SentCursor(self._connection.cursor(), self.statements)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._connection, name)


class _SentCursor:
    def __init__(self, cursor: Any, statements: list[str]) -> None:
        self._cursor = cursor
        self._statements = statements

    def execute(self, sql: str, *params: Any) -> Any:
        self._statements.append(f"{sql} {params!r}")
        self._cursor.execute(sql, *params)
        return self

    def __getattr__(self, name: str) -> Any:
        return getattr(self._cursor, name)


def mark(connection: Any) -> str:
    """A statement the tool login sends last, which the recorder waits for."""
    marker = f"sopuli_np_marker_{uuid.uuid4().hex[:12]}"
    connection.cursor().execute(f"SELECT N'{marker}'")
    return marker


@pytest.fixture
def recorded(live_mssql: Any) -> Iterator[tuple[Any, Recorder, Sent]]:
    """A tool session that may change ``LOGIN``, with its statements recorded,
    and a recorder started after the setup, so the setup's own passwords are
    not in what it records. Everything it makes is dropped, also when the
    setup fails part way."""
    from sopuli.driver.mssql.session import MssqlDriver

    admin = live_mssql.connect()
    cursor = admin.cursor()
    recorder = Recorder(admin, f"sopuli_test_no_password_{uuid.uuid4().hex[:8]}")
    opened = None
    try:
        for login in (TOOL, LOGIN):
            cursor.execute(f"IF SUSER_ID(N'{login}') IS NOT NULL DROP LOGIN [{login}]")
        cursor.execute(
            f"CREATE LOGIN [{TOOL}] WITH PASSWORD = N'{TOOL_PASSWORD}', CHECK_POLICY = ON"
        )
        cursor.execute(f"GRANT ALTER ANY LOGIN TO [{TOOL}]")
        cursor.execute(f"GRANT VIEW ANY DEFINITION TO [{TOOL}]")
        cursor.execute(f"CREATE LOGIN [{LOGIN}] WITH PASSWORD = N'{OLD}', CHECK_POLICY = ON")
        recorder.start()
        target = ExpandedTarget(
            target=Target(
                name="mssql-dev",
                type="mssql",
                dsn=live_mssql.dsn,
                mssql=TargetMssql(trust_server_certificate=True),
            )
        )
        opened = MssqlDriver(correlation_id="no-password").connect(
            target, Credential(username=TOOL, secret=Secret(TOOL_PASSWORD))
        )
        sent = Sent(opened.connection)
        opened.connection = sent
        yield opened, recorder, sent
    finally:
        if opened is not None:
            opened.close()
        recorder.stop()
        for login in (LOGIN, TOOL):
            cursor.execute(f"IF SUSER_ID(N'{login}') IS NOT NULL DROP LOGIN [{login}]")
        admin.close()


def test_a_change_sends_and_leaves_the_password_nowhere(
    recorded: tuple[Any, Recorder, Sent],
) -> None:
    session, recorder, sent = recorded
    password = f"Acme-np-{uuid.uuid4().hex[:12]}"
    flags = session.policy_flags(LOGIN)
    assert session.set_password(LOGIN, Secret(password)).changed
    assert session.verify_password(LOGIN, Secret(password)).result == PASS
    assert session.restore_policy(LOGIN, flags)

    # What the driver sent: the value with HASHED, and never the password.
    assert any("ALTER LOGIN" in line and " HASHED" in line for line in sent.statements)
    for line in sent.statements:
        assert password not in line, "the driver sent the password"

    # What the server kept.
    kept = recorder.kept(mark(session.connection))
    for place, text in kept.items():
        assert password not in text, f"the password is in the {place}"


def test_the_recorder_finds_a_password_sent_in_clear(
    recorded: tuple[Any, Recorder, Sent], live_mssql: Any
) -> None:
    """The control: a clear-text statement that does not parse is kept as sent
    (§6.1, PT3). If this fails, the server-side reads prove nothing."""
    import pyodbc

    _, recorder, _ = recorded
    password = f"Acme-np-{uuid.uuid4().hex[:12]}"
    connection = live_mssql.connect_as(TOOL, TOOL_PASSWORD)
    try:
        with pytest.raises(pyodbc.Error):
            connection.cursor().execute(
                f"ALTER LOGIN [{LOGIN}] WITH PASSWORD = N'{password}' NOT_A_KEYWORD"
            )
        marker = mark(connection)
    finally:
        connection.close()
    assert password in recorder.kept(marker)["extended events"]


def test_a_change_the_server_refuses_leaves_the_password_nowhere(
    recorded: tuple[Any, Recorder, Sent], live_mssql: Any
) -> None:
    """A statement that fails is kept as sent (§6.1, PT3), so what is sent
    must hold no password even when the server refuses it. The driver reads
    the login before it sends, so a refused change cannot be made through
    `set_password`: this sends the driver's own statement, for both value
    versions, for a login that does not exist, `15151`."""
    import pyodbc

    _, recorder, _ = recorded
    password = f"Acme-np-{uuid.uuid4().hex[:12]}"
    missing = f"w1_np_missing_{uuid.uuid4().hex[:6]}"
    connection = live_mssql.connect_as(TOOL, TOOL_PASSWORD)
    try:
        for version in (0x0200, 0x0300):
            statement = set_password_value(missing, password_value(Secret(password), version))
            with pytest.raises(pyodbc.Error) as refused:
                connection.cursor().execute(statement)
            assert "15151" in str(refused.value)
        marker = mark(connection)
    finally:
        connection.close()

    kept = recorder.kept(marker)
    assert missing in kept["extended events"], "the session recorded the refused statements"
    for place, text in kept.items():
        assert password not in text, f"the password is in the {place}"
