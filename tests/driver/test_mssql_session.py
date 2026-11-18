"""The SQL Server session and driver, with pyodbc's ``connect`` replaced. Tier 0
where pyodbc is installed: nothing here opens a socket (#1549)."""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

import pytest

from sopuli.config.model import ExpandedTarget, Target, TargetMssql
from sopuli.driver.protocol import (
    AuthenticationError,
    Credential,
    Timeouts,
    UnsupportedCapabilityError,
)
from sopuli.driver.registry import DRIVER_NOT_IMPLEMENTED, NotWrittenError
from sopuli.exit_codes import ExitCode
from sopuli.secrets import Secret

pyodbc = pytest.importorskip("pyodbc")
session = pytest.importorskip("sopuli.driver.mssql.session")

PASSWORD = "Never-in-a-log-1"

LOGIN_FAILED = (
    "28000",
    "[28000] [Microsoft][ODBC Driver 18 for SQL Server][SQL Server]Login failed for user "
    "'sopuli_admin'. (18456) (SQLDriverConnect)",
)


def target(**settings: Any) -> ExpandedTarget:
    return ExpandedTarget(
        target=Target(
            name="mssql-dev",
            type="mssql",
            dsn="127.0.0.1:1433",
            mssql=TargetMssql(**settings) if settings else None,
        )
    )


CREDENTIAL = Credential(username="sopuli_admin", secret=Secret(PASSWORD))


class FakeConnection:
    timeout = 0

    def close(self) -> None:
        pass


def test_pooling_is_off() -> None:
    assert pyodbc.pooling is False


def test_connect_passes_the_budgets_and_autocommit(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, Any] = {}

    def connect(text: str, **kwargs: Any) -> FakeConnection:
        seen.update(kwargs, text=text)
        return FakeConnection()

    monkeypatch.setattr(pyodbc, "connect", connect)
    driver = session.MssqlDriver(correlation_id="run-1", timeouts=Timeouts(connect_s=7, query_s=9))
    opened = driver.connect(target(), CREDENTIAL)
    assert (seen["autocommit"], seen["timeout"]) == (True, 7)
    assert opened.connection.timeout == 9
    assert f"PWD={{{PASSWORD}}}" in seen["text"]
    assert PASSWORD not in repr(opened)
    assert PASSWORD not in repr(driver)


class Collect(logging.Handler):
    def __init__(self) -> None:
        super().__init__(logging.DEBUG)
        self.lines: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.lines.append(record.getMessage())


def test_a_refused_login_logs_no_password(monkeypatch: pytest.MonkeyPatch) -> None:
    """The `sopuli` logger does not propagate, so the handler goes on it."""

    def connect(text: str, **kwargs: Any) -> FakeConnection:
        raise pyodbc.InterfaceError(*LOGIN_FAILED)

    monkeypatch.setattr(pyodbc, "connect", connect)
    collect = Collect()
    level = session.LOG.level
    session.LOG.addHandler(collect)
    # `setLevel`, not the attribute: it clears the logger's cached answer.
    session.LOG.setLevel(logging.DEBUG)
    try:
        with pytest.raises(AuthenticationError) as caught:
            session.MssqlDriver(correlation_id="run-1").connect(target(), CREDENTIAL)
    finally:
        session.LOG.setLevel(level)
        session.LOG.removeHandler(collect)
    text = "\n".join(collect.lines)
    assert caught.value.code == "18456"
    assert "connect to mssql-dev as sopuli_admin failed with 18456" in text
    assert PASSWORD not in text
    assert PASSWORD not in str(caught.value)


RESET = (
    "08001",
    "[08001] [Microsoft][ODBC Driver 18 for SQL Server]SSL Provider: An existing connection "
    "was forcibly closed by the remote host.\r\n (10054) (SQLDriverConnect)",
)


def test_a_reset_under_strict_refuses_the_capability(monkeypatch: pytest.MonkeyPatch) -> None:
    """Invariant 4: exit 5, naming the capability and the target (#1549)."""

    def connect(text: str, **kwargs: Any) -> FakeConnection:
        raise pyodbc.OperationalError(*RESET)

    monkeypatch.setattr(pyodbc, "connect", connect)
    with pytest.raises(UnsupportedCapabilityError) as caught:
        session.MssqlDriver(correlation_id="run-1").connect(target(encrypt="strict"), CREDENTIAL)
    assert caught.value.capability == "strict_encryption"
    assert caught.value.exit_code == ExitCode.UNSUPPORTED_CAPABILITY
    assert str(caught.value).startswith('target "mssql-dev" does not support strict_encryption')
    assert "encrypt: mandatory" in (caught.value.remedy or "")
    # The vendor code and the driver's own words are kept (CLAUDE.md, Style).
    assert caught.value.code == "08001"
    assert "forcibly closed by the remote host" in (caught.value.hint or "")


def test_every_other_method_is_not_written() -> None:
    """Refused without a round trip: the session has no connection here."""
    opened = session.MssqlSession(connection=None, target=target())
    calls: list[Callable[[], object]] = [
        lambda: opened.apply_attributes("acme_app"),
    ]
    for call in calls:
        with pytest.raises(NotWrittenError) as caught:
            call()
        assert caught.value.code == DRIVER_NOT_IMPLEMENTED
        assert "is a SQL Server instance, and this build cannot" in str(caught.value)


def test_a_role_the_tool_cannot_read_is_refused_as_role_lookup_missing() -> None:
    """Without VIEW ANY DEFINITION the catalog is not complete. So `report
    accounts` shows the role's members as undeclared and warns with
    `SOPULI-W075`, rather than failing the target (#1555), and the fix names
    the grant (#1554, Q6)."""
    from sopuli.driver.mssql.admin import MISSING_GRANT, Catalog

    opened = session.MssqlSession(connection=None, target=target())
    opened.scope = lambda: None
    opened._catalog = Catalog(unread=MISSING_GRANT)

    with pytest.raises(UnsupportedCapabilityError) as caught:
        opened.resolve_role("acme_ops")

    assert caught.value.capability == "role_lookup"
    assert "server role" in (caught.value.hint or "")
    # SOPULI-W075 words its fix from the remedy alone (#1587 review).
    assert "GRANT VIEW ANY DEFINITION" in (caught.value.remedy or "")


def test_client_report_names_pyodbc() -> None:
    lines = session.client_report(env={}, runtime=None)
    assert lines["pyodbc"] == pyodbc.version
    assert "odbc_driver" in lines
