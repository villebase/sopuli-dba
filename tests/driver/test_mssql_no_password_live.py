"""Invariant 15 on SQL Server: the password never reaches the server (#1551).

The driver sends the value it computed, with ``HASHED``. This module changes
a password through the driver with an Extended Events session recording every
statement, batch and error, then looks for the password in that session, the
plan cache, the default trace and the error log. ``02-mssql-privileges.md``
§6.1 has the measurement this guards (``01_password_text_probe.py``): a
statement that does not parse keeps its text, so the guard is that no
statement ever holds the password, sent or failed.
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
    """Every statement, batch, call and error on the server, with its text."""
    events = ", ".join(
        f"ADD EVENT {event} (ACTION (sqlserver.sql_text, sqlserver.session_id))"
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
        # `NO_EVENT_LOSS` refuses `error_reported` (25643), so a lost event is
        # possible in principle; the test asserts the session saw the run.
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

    def kept(self, anchor: str) -> dict[str, str]:
        """The text of each place a statement could be kept, once the events
        name ``anchor``. Stopping the session would empty its ring buffer, so
        this waits out the dispatch latency instead."""
        deadline = time.monotonic() + 15
        events = self.events()
        while anchor not in events and time.monotonic() < deadline:
            time.sleep(0.5)
            events = self.events()
        cache = self.cursor.execute(
            "SELECT t.text FROM sys.dm_exec_cached_plans p "
            "CROSS APPLY sys.dm_exec_sql_text(p.plan_handle) t"
        ).fetchall()
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


@pytest.fixture
def recorded(live_mssql: Any) -> Iterator[tuple[Any, Recorder]]:
    """A tool session that may change ``LOGIN``, and a recorder started after
    the setup, so the setup's own passwords are not in what it records."""
    from sopuli.driver.mssql.session import MssqlDriver

    admin = live_mssql.connect()
    cursor = admin.cursor()
    for login in (TOOL, LOGIN):
        cursor.execute(f"IF SUSER_ID(N'{login}') IS NOT NULL DROP LOGIN [{login}]")
    cursor.execute(f"CREATE LOGIN [{TOOL}] WITH PASSWORD = N'{TOOL_PASSWORD}', CHECK_POLICY = ON")
    cursor.execute(f"GRANT ALTER ANY LOGIN TO [{TOOL}]")
    cursor.execute(f"GRANT VIEW ANY DEFINITION TO [{TOOL}]")
    cursor.execute(f"CREATE LOGIN [{LOGIN}] WITH PASSWORD = N'{OLD}', CHECK_POLICY = ON")
    recorder = Recorder(admin, f"sopuli_test_no_password_{uuid.uuid4().hex[:8]}")
    recorder.stop()
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
    try:
        yield opened, recorder
    finally:
        opened.close()
        recorder.stop()
        for login in (LOGIN, TOOL):
            cursor.execute(f"IF SUSER_ID(N'{login}') IS NOT NULL DROP LOGIN [{login}]")
        admin.close()


def test_a_change_leaves_the_password_nowhere(recorded: tuple[Any, Recorder]) -> None:
    session, recorder = recorded
    password = f"Acme-np-{uuid.uuid4().hex[:12]}"
    flags = session.policy_flags(LOGIN)
    assert session.set_password(LOGIN, Secret(password)).changed
    assert session.verify_password(LOGIN, Secret(password)).result == PASS
    assert session.restore_policy(LOGIN, flags)

    kept = recorder.kept(LOGIN)
    # The recorder saw the run: the flags read and the restore name the login.
    assert LOGIN in kept["extended events"], "the session recorded the run"
    for place, text in kept.items():
        assert password not in text, f"the password is in the {place}"


def test_the_recorder_finds_a_password_sent_in_clear(
    recorded: tuple[Any, Recorder], live_mssql: Any
) -> None:
    """The control: a clear-text statement that does not parse is kept as sent
    (§6.1, PT3). If this fails, the two tests beside it prove nothing."""
    import pyodbc

    _, recorder = recorded
    password = f"Acme-np-{uuid.uuid4().hex[:12]}"
    connection = live_mssql.connect_as(TOOL, TOOL_PASSWORD)
    try:
        with pytest.raises(pyodbc.Error):
            connection.cursor().execute(
                f"ALTER LOGIN [{LOGIN}] WITH PASSWORD = N'{password}' NOT_A_KEYWORD"
            )
    finally:
        connection.close()
    assert password in recorder.kept(password)["extended events"]


def test_a_change_the_server_refuses_leaves_the_password_nowhere(
    recorded: tuple[Any, Recorder], live_mssql: Any
) -> None:
    """A statement that fails is kept as sent (§6.1, PT3), so what is sent
    must hold no password even when the server refuses it. `15151`: there is
    no such login."""
    import pyodbc

    _, recorder = recorded
    password = f"Acme-np-{uuid.uuid4().hex[:12]}"
    missing = f"w1_np_missing_{uuid.uuid4().hex[:6]}"
    statement = set_password_value(missing, password_value(Secret(password), 0x0200))
    connection = live_mssql.connect_as(TOOL, TOOL_PASSWORD)
    try:
        with pytest.raises(pyodbc.Error) as refused:
            connection.cursor().execute(statement)
    finally:
        connection.close()
    assert "15151" in str(refused.value)

    kept = recorder.kept(missing)
    assert missing in kept["extended events"], "the session recorded the refused statement"
    for place, text in kept.items():
        assert password not in text, f"the password is in the {place}"
