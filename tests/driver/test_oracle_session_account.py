"""Guardrail 7's input on Oracle: whether an account is the one the session is.

Tier 0, over a fake connection. The account read itself is stubbed, because
`test_accounts.py` covers it; what is checked here is the one thing
`OracleSession.describe_user` adds, and that it asks the database once.
"""

from __future__ import annotations

from typing import Any

import pytest

from sopuli.config.model import ExpandedTarget, Target
from sopuli.driver.protocol import Scope, UserState

TOOL_ACCOUNT = "C##SOPULI_SVC"


class _Cursor:
    """Answers the session-user query, and records what was asked."""

    def __init__(self) -> None:
        self.executed: list[str] = []

    def execute(self, sql: str, parameters: Any = None, /) -> None:
        self.executed.append(sql)

    def fetchone(self) -> Any:
        return (TOOL_ACCOUNT,)

    def __enter__(self) -> _Cursor:
        return self

    def __exit__(self, *_: object) -> None:
        return None


class _Connection:
    def __init__(self) -> None:
        self.opened = _Cursor()

    def cursor(self) -> _Cursor:
        return self.opened


@pytest.fixture
def session(session_module: Any, monkeypatch: pytest.MonkeyPatch) -> Any:
    def describe(cursor: Any, account: str, *, user_dollar: bool = False) -> UserState | None:
        if account == "missing":
            return None
        return UserState(name=account.upper(), status="OPEN")

    monkeypatch.setattr(session_module, "describe", describe)
    built = session_module.OracleSession(
        connection=_Connection(),
        target=ExpandedTarget(
            target=Target(name="orders", type="oracle", dsn="db.example.com:1521/orders"),
            index=0,
        ),
        correlation_id="00000000-0000-0000-0000-000000000000",
    )
    built._scope = Scope(type="pdb", open_mode="READ WRITE", read_write=True)
    return built


def test_the_account_the_session_logged_in_as_is_marked(session: Any) -> None:
    assert session.describe_user(TOOL_ACCOUNT).session_account is True


def test_any_other_account_is_not(session: Any) -> None:
    assert session.describe_user("acme_web_user").session_account is False


def test_the_session_user_is_read_once_per_session(session_module: Any, session: Any) -> None:
    session.describe_user("acme_web_user")
    session.describe_user(TOOL_ACCOUNT)

    asked = session.connection.opened.executed
    assert asked.count(session_module.SESSION_USER_QUERY) == 1


def test_a_proxy_logon_marks_the_proxy_account(session_module: Any) -> None:
    """Under `sopuli_svc[acme_web_user]` the session user is the client, which
    logged on with no password of its own; the proxy's password is the one the
    next connection needs, so the query prefers `PROXY_USER`."""
    query = session_module.SESSION_USER_QUERY
    assert query.index("PROXY_USER") < query.index("SESSION_USER")
    assert "nvl(" in query


def test_a_missing_account_asks_nothing_more(session_module: Any, session: Any) -> None:
    assert session.describe_user("missing") is None
    assert session_module.SESSION_USER_QUERY not in session.connection.opened.executed
