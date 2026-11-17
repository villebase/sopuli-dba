"""Reading SQL Server logins as the tool login, against a live server.

Tier 1 (#1549). `sa` makes each login; the tool login, with only `ALTER ANY
LOGIN` (`02-mssql-privileges.md` §2.1), reads it. Every login this file makes
starts `w1_` and is dropped after.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest

pytest.importorskip("pyodbc")
session_module = pytest.importorskip("sopuli.driver.mssql.session")

from sopuli.config.model import ExpandedTarget, Target, TargetMssql  # noqa: E402
from sopuli.driver.mssql.accounts import (  # noqa: E402
    LOCKED,
    OPEN,
    NotAPasswordLoginError,
)
from sopuli.driver.mssql.admin import MISSING_GRANT  # noqa: E402
from sopuli.driver.protocol import Credential  # noqa: E402
from sopuli.secrets import Secret  # noqa: E402

LOGINS = ("w1_acme_app", "w1_acme_off", "w1_acme_cert")


def _sa(live_mssql: Any, *statements: str) -> None:
    connection = live_mssql.connect()
    try:
        cursor = connection.cursor()
        for statement in statements:
            cursor.execute(statement)
    finally:
        connection.close()


def _drop(live_mssql: Any) -> None:
    _sa(
        live_mssql,
        *(f"IF SUSER_ID(N'{name}') IS NOT NULL DROP LOGIN [{name}]" for name in LOGINS),
        "IF CERT_ID('w1_acme_cert_c') IS NOT NULL DROP CERTIFICATE [w1_acme_cert_c]",
    )


@pytest.fixture
def tool_session(live_mssql: Any) -> Iterator[Any]:
    """A session as the tool login, with the logins made, and dropped
    before and after."""
    _drop(live_mssql)
    try:
        _sa(
            live_mssql,
            "CREATE LOGIN [w1_acme_app] WITH PASSWORD = N'Acme-app-pw1', CHECK_POLICY = OFF",
            "CREATE LOGIN [w1_acme_off] WITH PASSWORD = N'Acme-off-pw1', CHECK_POLICY = OFF",
            "ALTER LOGIN [w1_acme_off] DISABLE",
            "CREATE CERTIFICATE [w1_acme_cert_c] ENCRYPTION BY PASSWORD = N'W1-cert-pw1' "
            "WITH SUBJECT = 'w1 probe'",
            "CREATE LOGIN [w1_acme_cert] FROM CERTIFICATE [w1_acme_cert_c]",
        )
        yield from _as_tool(live_mssql)
    finally:
        _drop(live_mssql)


def _as_tool(live_mssql: Any) -> Iterator[Any]:
    target = ExpandedTarget(
        target=Target(
            name="tier1-mssql",
            type="mssql",
            dsn=live_mssql.dsn,
            mssql=TargetMssql(trust_server_certificate=True),
        )
    )
    driver = session_module.MssqlDriver(correlation_id="tier1")
    opened = driver.connect(
        target, Credential(live_mssql.tool_user, Secret(live_mssql.tool_password))
    )
    try:
        yield opened
    finally:
        opened.close()


def test_a_sql_login_is_read_in_the_server_s_spelling(tool_session: Any) -> None:
    state = tool_session.describe_user("W1_ACME_APP")
    assert state is not None
    assert state.name == "w1_acme_app"
    assert state.status == OPEN
    assert state.password_changed_at is not None
    # The tool login holds ALTER ANY LOGIN alone, so guardrail 9 refuses
    # every login on the password verbs (#1567).
    assert state.admin_unread == MISSING_GRANT


def test_a_disabled_login_is_locked(tool_session: Any) -> None:
    state = tool_session.describe_user("w1_acme_off")
    assert state is not None
    assert state.status == LOCKED
    assert state.deliberately_locked


def test_a_certificate_login_is_refused(tool_session: Any) -> None:
    with pytest.raises(NotAPasswordLoginError, match="a login mapped to a certificate"):
        tool_session.describe_user("w1_acme_cert")


def test_no_login_is_none(tool_session: Any) -> None:
    assert tool_session.describe_user("w1_acme_absent") is None


def test_the_tool_login_is_its_own(tool_session: Any, live_mssql: Any) -> None:
    state = tool_session.describe_user(live_mssql.tool_user)
    assert state is not None
    assert state.session_account


def test_the_instance_is_named(tool_session: Any) -> None:
    name = tool_session.cluster_identity()
    assert name
