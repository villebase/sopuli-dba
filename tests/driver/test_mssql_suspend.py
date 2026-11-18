"""UC-2's `account suspend`, and the refusals of `expire-password` and a
`profile:` or `role:` predicate, on SQL Server (#1554). Tier 0 where pyodbc
is installed: nothing here opens a socket."""

from __future__ import annotations

from typing import Any

import pytest

from sopuli.config.model import ExpandedTarget, Target
from sopuli.driver.protocol import (
    ACCOUNT_LOCK,
    DriverError,
    Scope,
    UnsupportedCapabilityError,
)
from sopuli.exit_codes import ExitCode

pyodbc = pytest.importorskip("pyodbc")
session = pytest.importorskip("sopuli.driver.mssql.session")

TARGET = ExpandedTarget(target=Target(name="mssql-dev", type="mssql", dsn="127.0.0.1:1433"))
SCOPE = Scope(type="server", open_mode="READ WRITE", read_write=True)


class FakeCursor:
    def __init__(self, sent: list[str]) -> None:
        self.sent = sent

    def execute(self, statement: str, *parameters: Any) -> None:
        self.sent.append(statement)

    def close(self) -> None:
        pass


class FakeConnection:
    def __init__(self) -> None:
        self.sent: list[str] = []

    def cursor(self) -> FakeCursor:
        return FakeCursor(self.sent)


def login(**changes: Any) -> Any:
    fields: dict[str, Any] = {
        "name": "acme_jdoe",
        "principal_id": 300,
        "disabled": False,
        "policy_checked": True,
        "expiration_checked": True,
        "locked_out": False,
        "must_change": False,
        "expired": False,
        "days_until_expiration": None,
        "changed_at": None,
        "session_login": False,
    }
    return session.accounts.Login(**{**fields, **changes})


def opened(monkeypatch: pytest.MonkeyPatch, *reads: Any, scope: Scope = SCOPE) -> Any:
    """A session whose login reads answer ``reads`` in turn."""
    one = session.MssqlSession(connection=FakeConnection(), target=TARGET)
    one.scope = lambda: scope
    answers = list(reads)
    monkeypatch.setattr(session.accounts, "read_one", lambda *a, **k: answers.pop(0))
    return one


def test_suspend_sends_disable_and_reads_it_back(monkeypatch: pytest.MonkeyPatch) -> None:
    one = opened(monkeypatch, login(), login(disabled=True))

    change = one.suspend_account("acme_jdoe")

    assert one.connection.sent == ["ALTER LOGIN [acme_jdoe] DISABLE"]
    assert (change.action, change.changed, change.status) == (ACCOUNT_LOCK, True, "OPEN")
    assert "sent ALTER LOGIN … DISABLE" in (change.detail or "")


def test_an_already_disabled_login_is_not_sent_again(monkeypatch: pytest.MonkeyPatch) -> None:
    """Invariant 9: the second run reports no change."""
    one = opened(monkeypatch, login(disabled=True))

    change = one.suspend_account("acme_jdoe")

    assert one.connection.sent == []
    assert change.changed is False
    assert change.status == "LOCKED"


def test_a_lockout_is_not_a_suspension(monkeypatch: pytest.MonkeyPatch) -> None:
    """`IsLocked` ends by itself; a suspension is somebody's decision (H4)."""
    one = opened(monkeypatch, login(locked_out=True), login(locked_out=True, disabled=True))

    change = one.suspend_account("acme_jdoe")

    assert change.changed is True
    assert change.status == "LOCKED(TIMED)"
    assert one.connection.sent == ["ALTER LOGIN [acme_jdoe] DISABLE"]


def test_a_disable_that_does_not_read_back_is_an_error(monkeypatch: pytest.MonkeyPatch) -> None:
    one = opened(monkeypatch, login(), login())

    with pytest.raises(DriverError, match="does not read is_disabled 1"):
        one.suspend_account("acme_jdoe")


def test_a_login_gone_on_the_read_back_says_disable_was_sent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The operator must be able to tell the statement went out (#1597
    review)."""
    one = opened(monkeypatch, login(), None)

    with pytest.raises(DriverError, match="was sent ALTER LOGIN … DISABLE.*has no row"):
        one.suspend_account("acme_jdoe")


def test_a_missing_login_is_refused_before_anything_is_sent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    one = opened(monkeypatch, None)

    with pytest.raises(DriverError, match='there is no login "acme_jdoe"'):
        one.suspend_account("acme_jdoe")
    assert one.connection.sent == []


def test_a_read_only_target_is_refused_before_anything_is_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    read_only = Scope(type="server", open_mode="READ ONLY", read_write=False)
    one = opened(monkeypatch, scope=read_only)

    with pytest.raises(DriverError):
        one.suspend_account("acme_jdoe")
    assert one.connection.sent == []


def test_expire_password_is_refused_by_capability(monkeypatch: pytest.MonkeyPatch) -> None:
    """MUST_CHANGE is taken only with a new password (#1538, decision 2)."""
    one = opened(monkeypatch)

    with pytest.raises(UnsupportedCapabilityError) as caught:
        one.expire_password("acme_jdoe")

    assert caught.value.capability == "expire_password"
    assert caught.value.exit_code == ExitCode.UNSUPPORTED_CAPABILITY


def test_a_profile_predicate_is_refused_by_capability(monkeypatch: pytest.MonkeyPatch) -> None:
    one = opened(monkeypatch)

    with pytest.raises(UnsupportedCapabilityError) as caught:
        one.accounts_matching(profile="STAFF")

    assert caught.value.capability == "profile_management"
    assert "no profiles" in (caught.value.hint or "")


def test_a_role_predicate_is_refused_where_the_roles_cannot_be_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Without VIEW ANY DEFINITION the catalog is not complete, so a role
    that matches nobody could not be told from one that does not exist
    (#1554, Q6)."""
    from sopuli.driver.mssql.admin import MISSING_GRANT, Catalog

    one = opened(monkeypatch)
    one._catalog = Catalog(unread=MISSING_GRANT)

    with pytest.raises(UnsupportedCapabilityError) as caught:
        one.accounts_matching(role="acme_staff")

    assert caught.value.capability == "role_lookup"
    assert "VIEW ANY DEFINITION" in (caught.value.remedy or "")
