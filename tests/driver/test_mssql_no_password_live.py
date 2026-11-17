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

UC-2's seen reset is the exception invariant 15 accepts (#1554): it sends
the password in clear, with ``MUST_CHANGE``. Its test checks that the
statement parses and so leaves the password in none of the same places.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Iterator
from contextlib import suppress
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
        assert 'truncated="0"' in events, "the ring buffer was read whole"
        cache = self.cursor.execute(
            "SELECT t.text FROM sys.dm_exec_cached_plans p "
            "CROSS APPLY sys.dm_exec_sql_text(p.plan_handle) t"
        ).fetchall()
        log = self.cursor.execute("EXEC sys.xp_readerrorlog 0, 1").fetchall()
        kept = {
            "extended events": events,
            "plan cache": "\n".join(row[0] or "" for row in cache),
            "error log": "\n".join(str(row[-1]) for row in log),
        }
        # Read only where it is on: an instance hardened with `default trace
        # enabled` = 0 has none, and reading nothing would check nothing.
        (default_traces,) = self.cursor.execute(
            "SELECT COUNT(*) FROM sys.traces WHERE is_default = 1"
        ).fetchone()
        if default_traces:
            trace = self.cursor.execute(
                "SELECT CAST(g.TextData AS nvarchar(max)) FROM sys.traces t "
                "CROSS APPLY sys.fn_trace_gettable(t.path, DEFAULT) g "
                "WHERE t.is_default = 1 AND g.TextData IS NOT NULL"
            ).fetchall()
            kept["default trace"] = "\n".join(row[0] or "" for row in trace)
        return kept


class Sent:
    """The session's connection, recording each statement and its binds."""

    def __init__(self, connection: Any) -> None:
        self._connection = connection
        self.statements: list[tuple[str, tuple[Any, ...]]] = []

    def cursor(self) -> Any:
        return _SentCursor(self._connection.cursor(), self.statements)

    def holds(self, password: str) -> list[str]:
        """Each statement that holds ``password`` in a form the server could
        read back: as text, as a bind, or as its UTF-16LE bytes, raw or in a
        hex literal, which is how SQL Server stores a password's text."""
        utf16 = password.encode("utf-16-le")
        forms = (password, utf16.hex().upper())
        found = []
        for sql, params in self.statements:
            texts = [sql.upper(), *(str(p).upper() for p in params if isinstance(p, str))]
            raw = [p for p in params if isinstance(p, (bytes, bytearray))]
            if (
                any(form.upper() in text for form in forms for text in texts)
                or any(password in text for text in [sql, *map(str, params)])
                or any(utf16 in value for value in raw)
            ):
                found.append(sql)
        return found

    def __getattr__(self, name: str) -> Any:
        return getattr(self._connection, name)


class _SentCursor:
    def __init__(self, cursor: Any, statements: list[tuple[str, tuple[Any, ...]]]) -> None:
        self._cursor = cursor
        self._statements = statements

    def execute(self, sql: str, *params: Any) -> Any:
        self._statements.append((sql, params))
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
        cursor.execute(
            f"CREATE LOGIN [{LOGIN}] WITH PASSWORD = N'{OLD}', CHECK_POLICY = ON, "
            "CHECK_EXPIRATION = ON"
        )
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
        # Each step on its own, so one that fails leaves the rest to run.
        steps = [
            *([opened.close] if opened is not None else []),
            recorder.stop,
            *(
                lambda login=login: cursor.execute(
                    f"IF SUSER_ID(N'{login}') IS NOT NULL DROP LOGIN [{login}]"
                )
                for login in (LOGIN, TOOL)
            ),
            admin.close,
        ]
        for step in steps:
            with suppress(Exception):
                step()


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
    assert any("ALTER LOGIN" in sql and " HASHED" in sql for sql, _ in sent.statements)
    assert sent.holds(password) == [], "the driver sent the password"

    # What the server kept.
    kept = recorder.kept(mark(session.connection))
    for place, text in kept.items():
        assert password not in text, f"the password is in the {place}"


@pytest.mark.parametrize("flags", ["on", "off"])
def test_the_seen_reset_leaves_its_password_nowhere_on_the_server(
    recorded: tuple[Any, Recorder, Sent], live_mssql: Any, flags: str
) -> None:
    """Invariant 15's SQL Server exception (#1554): the seen reset sends the
    password in clear, with ``MUST_CHANGE``, which has no value form. The
    statement always parses, so the server keeps it with the password left
    out or masked (§6.1, PT0 to PT2), and the owner's login then answers
    ``18488``, must change.

    Also from a login with both flags off, as ``CREATE LOGIN`` leaves
    ``CHECK_EXPIRATION`` and a stopped UC-1 change can leave ``CHECK_POLICY``:
    the one statement turns both on with ``MUST_CHANGE``.

    The password holds ODBC's escape characters, ``{`` ``}`` and ``?``, a
    ``'``, and a character outside the Basic Multilingual Plane, so the test
    shows the statement parses as sent with them in the literal."""
    import pyodbc

    session, recorder, sent = recorded
    if flags == "off":
        admin = live_mssql.connect()
        try:
            admin.cursor().execute(
                f"ALTER LOGIN [{LOGIN}] WITH CHECK_EXPIRATION = OFF, CHECK_POLICY = OFF"
            )
        finally:
            admin.close()
    secret_part = uuid.uuid4().hex[:12]
    password = f"Acme-np-{secret_part}'q{{fn x}}?{{call y}}\U0001f600"
    session.reset_password(LOGIN, Secret(password), expire=True)

    doubled = password.replace("'", "''")
    assert [sql for sql, _ in sent.statements if doubled in sql] == [
        f"ALTER LOGIN [{LOGIN}] WITH PASSWORD = N'{doubled}' MUST_CHANGE, "
        "CHECK_POLICY = ON, CHECK_EXPIRATION = ON"
    ], "the seen reset is the one statement with the password"

    with pytest.raises(pyodbc.Error) as answered:
        live_mssql.connect_as(LOGIN, password)
    assert "18488" in str(answered.value), "the login must change its password"

    admin = live_mssql.connect()
    try:
        policy, expiration = (
            admin.cursor()
            .execute(
                "SELECT is_policy_checked, is_expiration_checked FROM sys.sql_logins "
                "WHERE name = ?",
                LOGIN,
            )
            .fetchone()
        )
    finally:
        admin.close()
    assert (policy, expiration) == (True, True), "the reset leaves both flags on"

    kept = recorder.kept(mark(session.connection))
    for place, text in kept.items():
        # The random part alone, so a record cut at the quote is caught too.
        assert secret_part not in text, f"the password's random part is in the {place}"


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
    `set_password`: this sends the driver's own statement, with the value
    version the server takes, as the driver reads it, for a login that does
    not exist, `15151`."""
    import pyodbc

    session, recorder, _ = recorded
    password = f"Acme-np-{uuid.uuid4().hex[:12]}"
    missing = f"w1_np_missing_{uuid.uuid4().hex[:6]}"
    statement = set_password_value(
        missing, password_value(Secret(password), session.hash_version())
    )
    connection = live_mssql.connect_as(TOOL, TOOL_PASSWORD)
    try:
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
