"""Reading one SQL Server login (:mod:`sopuli.driver.mssql.accounts`). Tier 0."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from sopuli.driver.mssql import accounts
from sopuli.driver.mssql.accounts import (
    EXPIRED,
    LOCKED,
    LOCKED_TIMED,
    OPEN,
    Login,
    NotAPasswordLoginError,
)
from sopuli.exit_codes import ExitCode

NOW = datetime(2026, 11, 17, 12, 0, tzinfo=UTC)
CHANGED = datetime(2026, 11, 1, 8, 30)


class FakeCursor:
    """Answers :data:`~sopuli.driver.mssql.accounts.LOGIN` with one row, or
    none, and keeps what it was sent."""

    def __init__(self, row: tuple[Any, ...] | None) -> None:
        self.row = row
        self.sent: list[tuple[str, Any]] = []

    def execute(self, statement: Any, parameters: Any = None, /) -> None:
        self.sent.append((statement, parameters))

    def fetchone(self) -> Any:
        return self.row

    def fetchall(self) -> Any:
        return [self.row] if self.row else []


def row(**changes: Any) -> tuple[Any, ...]:
    values: dict[str, Any] = {
        "name": "acme_app",
        "type": "S",
        "principal_id": 270,
        "disabled": False,
        "policy": True,
        "expiration": False,
        "locked_out": 0,
        "must_change": 0,
        "expired": 0,
        "days": None,
        "changed_at": CHANGED,
        "own": 0,
    }
    values.update(changes)
    return tuple(values.values())


def login(**changes: Any) -> Login:
    found = accounts.read_one(FakeCursor(row(**changes)), "acme_app", target="mssql-dev")
    assert found is not None
    return found


def test_the_name_is_a_parameter_and_the_server_spelling_is_kept() -> None:
    """The server compares the name under its collation (ID1), so the row's
    spelling is the one the state carries. The name goes as a parameter,
    never into the statement's text."""
    cursor = FakeCursor(row(name="Acme_App"))
    found = accounts.read_one(cursor, "ACME_APP", target="mssql-dev")
    assert found is not None
    assert found.name == "Acme_App"
    assert cursor.sent == [(accounts.LOGIN, ("ACME_APP",))]
    assert "ACME_APP" not in accounts.LOGIN


def test_no_principal_is_none() -> None:
    """A contained user is not a login, and the tool login does not see one."""
    assert accounts.read_one(FakeCursor(None), "acme_app", target="mssql-dev") is None


@pytest.mark.parametrize(
    ("kind", "words"),
    [
        ("U", "a Windows login"),
        ("G", "a Windows group"),
        ("E", "an Entra login"),
        ("X", "an Entra group"),
        ("C", "a login mapped to a certificate"),
        ("K", "a login mapped to an asymmetric key"),
        ("R", "a server role"),
        ("Q", "a server principal of type Q"),
    ],
)
def test_every_principal_but_a_sql_login_is_refused(kind: str, words: str) -> None:
    """Decision 1 of #1538: only a login with a password is managed."""
    with pytest.raises(NotAPasswordLoginError) as caught:
        accounts.read_one(FakeCursor(row(type=kind)), "acme_app", target="mssql-dev")
    assert str(caught.value).startswith(
        f'account "acme_app" on target "mssql-dev" is {words}, which has no password'
    )
    assert caught.value.exit_code == ExitCode.CONFIG_INVALID
    assert caught.value.category == "config"


def test_an_open_login() -> None:
    state = accounts.state_of(login(), now=NOW, admin_unread=None)
    assert state.status == OPEN
    assert (state.locked, state.deliberately_locked, state.expired) == (False, False, False)
    assert state.password_changed_at == CHANGED.replace(tzinfo=UTC)
    assert state.password_changed_unknown is None
    assert state.password_expires_at is None
    assert state.failed_logins is None
    assert not state.vendor_maintained
    assert not state.session_account


def test_a_disabled_login_is_locked_by_a_person() -> None:
    """``is_disabled`` is H4's plain lock, which a reset refuses (#1554)."""
    state = accounts.state_of(login(disabled=True, locked_out=1), now=NOW, admin_unread=None)
    assert state.status == LOCKED
    assert (state.locked, state.deliberately_locked) == (True, True)


def test_a_lockout_is_timed() -> None:
    """``IsLocked`` ends by itself under the host's policy (#1554)."""
    state = accounts.state_of(login(locked_out=1), now=NOW, admin_unread=None)
    assert state.status == LOCKED_TIMED
    assert (state.locked, state.deliberately_locked) == (True, False)


@pytest.mark.parametrize("flag", ["expired", "must_change"])
def test_an_expired_or_must_change_password_has_stopped_working(flag: str) -> None:
    state = accounts.state_of(login(**{flag: 1}), now=NOW, admin_unread=None)
    assert state.status == EXPIRED
    assert state.expired


def test_expired_and_locked_out() -> None:
    state = accounts.state_of(login(expired=1, locked_out=1), now=NOW, admin_unread=None)
    assert state.status == f"{EXPIRED} & {LOCKED_TIMED}"


def test_the_expiry_date_counts_whole_days_where_expiry_is_on() -> None:
    on = accounts.state_of(login(expiration=True, days=12), now=NOW, admin_unread=None)
    assert on.password_expires_at == NOW + timedelta(days=12)
    off = accounts.state_of(login(expiration=False, days=12), now=NOW, admin_unread=None)
    assert off.password_expires_at is None


def test_no_change_date_says_why() -> None:
    state = accounts.state_of(login(changed_at=None), now=NOW, admin_unread=None)
    assert state.password_changed_at is None
    assert state.password_changed_unknown == accounts.NO_CHANGE_DATE


def test_sa_is_the_server_s_own() -> None:
    state = accounts.state_of(login(name="sa", principal_id=1), now=NOW, admin_unread=None)
    assert state.vendor_maintained


def test_the_session_s_own_login() -> None:
    state = accounts.state_of(login(own=1), now=NOW, admin_unread=None)
    assert state.session_account


def test_guardrail_9_s_reason_is_carried() -> None:
    """Empty ``global_privileges`` means "read and found none", so a state
    whose paths were not read must say so, and check 9 then refuses it."""
    state = accounts.state_of(login(), now=NOW, admin_unread="not read")
    assert state.admin_unread == "not read"
    assert state.global_privileges == frozenset()
