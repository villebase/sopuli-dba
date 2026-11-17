"""The SQL Server capabilities of #1550, over fakes. Tier 0 where pyodbc is
installed: nothing here opens a socket.

The live answers, `ok` on 2022 and `15021` on 2019, are in
`test_mssql_capabilities_live.py` and in `11_hash_version_probe.py`, HV6.
"""

from __future__ import annotations

import re
from typing import Any

import pytest

from sopuli.config.model import ExpandedTarget, Target, TargetMssql
from sopuli.driver.mssql import capabilities
from sopuli.driver.mssql.password import PBKDF2_SHA512, SHA512, VALUE_LENGTH
from sopuli.driver.protocol import (
    PASSWORD_VALUE,
    DriverError,
    ReadOnlyTargetError,
    Scope,
    UnsupportedCapabilityError,
)
from sopuli.exit_codes import ExitCode

pyodbc = pytest.importorskip("pyodbc")
session = pytest.importorskip("sopuli.driver.mssql.session")


def _refused(number: int, text: str) -> Any:
    """A pyodbc error as ODBC Driver 18 words a server's refusal."""
    return pyodbc.ProgrammingError(
        "42000",
        f"[42000] [Microsoft][ODBC Driver 18 for SQL Server][SQL Server]{text} ({number}) "
        "(SQLExecDirectW)",
    )


#: 2019's answer to the check (HV6).
REFUSED_0300 = _refused(
    15021, "Invalid value given for parameter PASSWORD. Specify a valid parameter value."
)
#: 2022's answer where the name is taken (HV8).
NAME_TAKEN = _refused(15025, "The server principal 'x' already exists.")
#: A login without ALTER ANY LOGIN (measured on 16.0.4325.4).
NO_PERMISSION = _refused(15247, "User does not have permission to perform this action.")
#: A trigger's PRINT before 2019's refusal: an informational record first.
PRINTED_FIRST = pyodbc.ProgrammingError(
    "42000",
    "[01000] [Microsoft][ODBC Driver 18 for SQL Server][SQL Server]a trigger ran (0) "
    "(SQLExecDirectW); [42000] [Microsoft][ODBC Driver 18 for SQL Server][SQL Server]"
    "Invalid value given for parameter PASSWORD. Specify a valid parameter value. (15021) "
    "(SQLExecDirectW)",
)
#: A connection that broke: a client record only.
LOST = pyodbc.OperationalError(
    "08S01",
    "[08S01] [Microsoft][ODBC Driver 18 for SQL Server]TCP Provider: An existing connection "
    "was forcibly closed by the remote host. (10054) (SQLExecDirectW)",
)
#: The client's query timeout: the server keeps the transaction open.
TIMEOUT = pyodbc.OperationalError(
    "HYT00",
    "[HYT00] [Microsoft][ODBC Driver 18 for SQL Server]Query timeout expired (0) (SQLExecDirectW)",
)


class FakeCursor:
    def __init__(self, connection: FakeConnection) -> None:
        self.connection = connection

    def execute(self, statement: str, *params: Any) -> FakeCursor:
        self.connection.sent.append(statement)
        if statement.startswith("BEGIN TRANSACTION") and self.connection.raises is not None:
            raise self.connection.raises
        if statement == capabilities.END_TRANSACTION and self.connection.end_raises is not None:
            raise self.connection.end_raises
        return self

    def nextset(self) -> bool:
        return False

    def fetchone(self) -> Any:
        return (self.connection.platform,)

    def close(self) -> None:
        pass


class FakeConnection:
    timeout = 0

    def __init__(self, raises: Any = None, end_raises: Any = None) -> None:
        self.raises = raises
        self.end_raises = end_raises
        self.platform: str | None = "Linux"
        self.sent: list[str] = []

    def cursor(self) -> FakeCursor:
        return FakeCursor(self)

    def close(self) -> None:
        pass


def _session(raises: Any = None, *, read_write: bool = True, end_raises: Any = None) -> Any:
    opened = session.MssqlSession(
        connection=FakeConnection(raises, end_raises),
        target=ExpandedTarget(
            target=Target(name="mssql-dev", type="mssql", dsn="127.0.0.1:1433", mssql=TargetMssql())
        ),
    )
    # The scope is the session's own read; the fake has no answer for it.
    opened._scope = Scope(type="server", read_write=read_write)
    return opened


def test_ok_means_0x0300_and_15021_means_0x0200() -> None:
    assert capabilities.version_from("ok", target="t") == PBKDF2_SHA512
    assert capabilities.version_from("15021", target="t") == SHA512


@pytest.mark.parametrize("answer", ["15025", "102", "229"])
def test_any_other_answer_refuses_the_target(answer: str) -> None:
    """#1564: a clash, `15025`, says nothing about the value."""
    with pytest.raises(UnsupportedCapabilityError) as caught:
        capabilities.version_from(answer, target="mssql-dev")
    assert caught.value.capability == PASSWORD_VALUE
    assert caught.value.exit_code == ExitCode.UNSUPPORTED_CAPABILITY
    assert str(caught.value).startswith('target "mssql-dev" does not support password_value')
    assert caught.value.hint is not None
    assert f"answered {answer}" in caught.value.hint


def test_the_check_names_a_random_login() -> None:
    first, second = capabilities.check_name(), capabilities.check_name()
    assert first != second
    assert re.fullmatch(r"sopuli_hash_check_[0-9a-f]{16}", first)


def test_the_check_is_a_rolled_back_create_with_a_0x0300_value() -> None:
    statement = capabilities.check_statement("sopuli_hash_check_00")
    found = re.fullmatch(
        r"BEGIN TRANSACTION;\n"
        r"CREATE LOGIN \[sopuli_hash_check_00\] WITH PASSWORD = 0x([0-9A-F]+) HASHED, "
        r"CHECK_POLICY = OFF;\n"
        r"ROLLBACK TRANSACTION",
        statement,
    )
    assert found is not None
    value = bytes.fromhex(found[1])
    assert len(value) == VALUE_LENGTH
    assert value[:2] == b"\x03\x00"
    # A new random password each time.
    assert capabilities.check_statement("sopuli_hash_check_00") != statement


def test_the_session_reads_the_host_platform_once() -> None:
    opened = _session()
    assert opened.host_platform() == "Linux"
    assert opened.host_platform() == "Linux"
    assert opened.connection.sent == [capabilities.HOST_PLATFORM]


def test_a_server_that_takes_0x0300_is_asked_once() -> None:
    opened = _session()
    assert opened.hash_version() == PBKDF2_SHA512
    assert opened.hash_version() == PBKDF2_SHA512
    assert len(opened.connection.sent) == 1
    assert opened.connection.sent[0].startswith("BEGIN TRANSACTION;\nCREATE LOGIN [sopuli_hash")


def test_15021_means_0x0200_and_ends_the_transaction() -> None:
    opened = _session(REFUSED_0300)
    assert opened.hash_version() == SHA512
    assert opened.connection.sent[-1] == capabilities.END_TRANSACTION


def test_another_answer_refuses_and_is_asked_again() -> None:
    opened = _session(NAME_TAKEN)
    for _ in range(2):
        with pytest.raises(UnsupportedCapabilityError):
            opened.hash_version()
    checks = [s for s in opened.connection.sent if s.startswith("BEGIN TRANSACTION")]
    assert len(checks) == 2


@pytest.mark.parametrize("failure", [LOST, TIMEOUT], ids=["lost", "timeout"])
def test_a_client_failure_ends_the_transaction_and_is_the_connections_error(
    failure: Any,
) -> None:
    """A client timeout leaves the batch's transaction open on the server."""
    opened = _session(failure)
    with pytest.raises(DriverError) as caught:
        opened.hash_version()
    assert not isinstance(caught.value, UnsupportedCapabilityError)
    assert caught.value.category == "connectivity"
    assert opened.connection.sent[-1] == capabilities.END_TRANSACTION


def test_a_failure_to_end_the_transaction_leaves_the_first_error() -> None:
    """The server ends a broken session's transaction with it."""
    with pytest.raises(DriverError) as caught:
        _session(TIMEOUT, end_raises=LOST).hash_version()
    assert caught.value.category == "connectivity"


def test_a_missing_permission_is_the_tool_logins_not_the_targets() -> None:
    """15247: the tool login lacks ALTER ANY LOGIN; the hint names it."""
    with pytest.raises(DriverError) as caught:
        _session(NO_PERMISSION).hash_version()
    assert not isinstance(caught.value, UnsupportedCapabilityError)
    assert caught.value.category == "authorization"
    assert caught.value.code == "15247"
    assert "ALTER ANY LOGIN" in (caught.value.hint or "")


def test_an_informational_record_is_not_the_answer() -> None:
    """A trigger's PRINT comes first; the 15021 after it is the answer."""
    assert _session(PRINTED_FIRST).hash_version() == SHA512


def test_the_refusal_keeps_the_servers_words() -> None:
    with pytest.raises(UnsupportedCapabilityError) as caught:
        _session(NAME_TAKEN).hash_version()
    assert "answered 15025 (The server principal 'x' already exists.)" in (caught.value.hint or "")


@pytest.mark.parametrize("platform", [None, "", "  "])
def test_an_unnamed_platform_is_unknown_not_linux(platform: str | None) -> None:
    opened = _session()
    opened.connection.platform = platform
    assert opened.host_platform() is None
    assert opened.host_platform() is None
    assert opened.connection.sent == [capabilities.HOST_PLATFORM]


def test_a_read_only_master_is_not_checked() -> None:
    opened = _session(read_write=False)
    with pytest.raises(ReadOnlyTargetError):
        opened.hash_version()
    assert opened.connection.sent == []
