"""UC-2's resets on SQL Server, seen and unseen, with pyodbc replaced. Tier 0
where pyodbc is installed: nothing here opens a socket (#1554).
``02-mssql-privileges.md`` §6.3 has the statements."""

from __future__ import annotations

from typing import Any

import pytest

from sopuli.driver.protocol import (
    ACCOUNT_UNLOCK,
    PASSWORD_SET,
    ROLLOVER_FINISH,
    DriverError,
    Scope,
    UnsupportedCapabilityError,
)
from sopuli.secrets import Secret

pyodbc = pytest.importorskip("pyodbc")
session = pytest.importorskip("sopuli.driver.mssql.session")
password = pytest.importorskip("sopuli.driver.mssql.password")

from sopuli.config.model import ExpandedTarget, Target  # noqa: E402

PASSWORD = "Acme-Vector-pw1"
TARGET = ExpandedTarget(target=Target(name="mssql-dev", type="mssql", dsn="127.0.0.1:1433"))


class FakeCursor:
    def __init__(self, sent: list[str], error: Exception | None) -> None:
        self.sent = sent
        self.error = error

    def execute(self, statement: str, *parameters: Any) -> None:
        self.sent.append(statement)
        if self.error is not None:
            raise self.error

    def close(self) -> None:
        pass


class FakeConnection:
    def __init__(self, error: Exception | None = None) -> None:
        self.sent: list[str] = []
        self.error = error

    def cursor(self) -> FakeCursor:
        return FakeCursor(self.sent, self.error)


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


def opened(monkeypatch: pytest.MonkeyPatch, row: Any, error: Exception | None = None) -> Any:
    monkeypatch.setattr(session.accounts, "read_one", lambda *a, **k: row)
    one = session.MssqlSession(connection=FakeConnection(error), target=TARGET)
    one.scope = lambda: Scope(type="server", open_mode="READ WRITE", read_write=True)
    return one


def test_the_seen_reset_sends_must_change_with_the_policy_on(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    one = opened(monkeypatch, login(name="acme_jdoe"))
    changes = one.reset_password("acme_jdoe", Secret(PASSWORD), expire=True)

    assert one.connection.sent == [
        f"ALTER LOGIN [acme_jdoe] WITH PASSWORD = N'{PASSWORD}' MUST_CHANGE, "
        "CHECK_POLICY = ON, CHECK_EXPIRATION = ON"
    ]
    assert [(c.action, c.changed) for c in changes] == [
        (ACCOUNT_UNLOCK, False),
        (PASSWORD_SET, True),
        (ROLLOVER_FINISH, False),
    ]


def test_a_lockout_is_ended_with_unlock(monkeypatch: pytest.MonkeyPatch) -> None:
    """Decision 3: a new password alone leaves a locked-out login locked."""
    one = opened(monkeypatch, login(name="acme_jdoe", locked_out=True))
    changes = one.reset_password("acme_jdoe", Secret(PASSWORD), expire=True)

    [statement] = one.connection.sent
    assert " MUST_CHANGE UNLOCK, CHECK_POLICY = ON" in statement
    assert changes[0].action == ACCOUNT_UNLOCK
    assert changes[0].changed


class Recorded:
    def __init__(self) -> None:
        self.sent: list[str] = []

    def execute(self, statement: str) -> None:
        self.sent.append(statement)


def test_a_quote_in_the_password_is_doubled() -> None:
    cursor = Recorded()
    password.MustChange("acme_jdoe", Secret("Ab1'x"), unlock=False).send(cursor)
    assert "PASSWORD = N'Ab1''x' MUST_CHANGE" in cursor.sent[0]


def test_the_statement_quotes_the_login_itself() -> None:
    """No caller can put an unquoted name into the one statement that
    carries a password (#1599 review)."""
    cursor = Recorded()
    password.MustChange("acme]jdoe", Secret(PASSWORD), unlock=False).send(cursor)
    assert cursor.sent[0].startswith("ALTER LOGIN [acme]]jdoe] WITH PASSWORD = N'")


def test_a_password_the_host_refuses_is_a_policy_error_with_a_hint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """33064, measured on the 2022 Linux image (#1599)."""
    refused = (
        "[42000] [Microsoft][ODBC Driver 18 for SQL Server][SQL Server]Password validation "
        "failed. The password does not meet SQL Server password policy requirements because "
        "it is not complex enough. (33064) (SQLExecDirectW)"
    )
    one = opened(monkeypatch, login(), pyodbc.ProgrammingError("42000", refused))
    with pytest.raises(DriverError) as caught:
        one.reset_password("acme_jdoe", Secret(PASSWORD), expire=True)
    assert caught.value.category == "policy"
    assert caught.value.hint is not None
    assert "policy" in caught.value.hint


def test_the_statement_never_renders_its_password() -> None:
    """Invariant 2: redaction is in the type, not at each call site."""
    statement = password.MustChange("acme_jdoe", Secret(PASSWORD), unlock=True)
    for shown in (str(statement), repr(statement), f"{statement}", statement.redacted):
        assert PASSWORD not in shown
        assert "N'***' MUST_CHANGE UNLOCK" in shown


def test_a_control_character_is_refused_before_a_statement_is_built() -> None:
    with pytest.raises(password.PasswordNotAdmissibleError, match="control characters"):
        password.MustChange("acme_jdoe", Secret("Ab1\nx"), unlock=False)


def test_a_pending_must_change_reads_as_expired(monkeypatch: pytest.MonkeyPatch) -> None:
    """As `describe_user` reads it (#1599 review)."""
    one = opened(monkeypatch, login(must_change=True))
    changes = one.reset_password("acme_jdoe", Secret(PASSWORD), expire=True)
    assert {change.status for change in changes} == {"EXPIRED"}


def test_the_state_says_must_change_is_pending() -> None:
    """`creds generate` and `apply` read it, not a status word (#1594)."""
    from datetime import UTC, datetime

    pending = session.accounts.state_of(
        login(must_change=True), now=datetime.now(UTC), admin_unread=None
    )
    plain = session.accounts.state_of(login(), now=datetime.now(UTC), admin_unread=None)

    assert pending.pending_must_change
    assert pending.expired
    assert not plain.pending_must_change


def test_keep_rollover_is_refused_by_capability(monkeypatch: pytest.MonkeyPatch) -> None:
    one = opened(monkeypatch, login())
    with pytest.raises(UnsupportedCapabilityError, match="password_rollover"):
        one.reset_password("acme_jdoe", Secret(PASSWORD), expire=True, keep_rollover=True)
    assert one.connection.sent == []


def test_a_disabled_login_is_refused_and_nothing_is_sent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """H4: `account suspend` set it, and a reset does not undo that."""
    one = opened(monkeypatch, login(name="acme_jdoe", disabled=True))
    with pytest.raises(DriverError, match="is disabled"):
        one.reset_password("acme_jdoe", Secret(PASSWORD), expire=True)
    assert one.connection.sent == []


def test_a_missing_login_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    one = opened(monkeypatch, None)
    with pytest.raises(DriverError, match='no login "acme_jdoe"'):
        one.reset_password("acme_jdoe", Secret(PASSWORD), expire=True)


def by_value(monkeypatch: pytest.MonkeyPatch, row: Any) -> Any:
    """:func:`opened`, on a server that takes ``0x0200``."""
    one = opened(monkeypatch, row)
    one.hash_version = lambda: 0x0200
    return one


@pytest.mark.parametrize("locked_out", [False, True])
def test_the_unseen_reset_sends_a_value_with_the_policy_off(
    monkeypatch: pytest.MonkeyPatch, locked_out: bool
) -> None:
    """§6.2's step 2, which ends a lockout too: no `UNLOCK` is sent, and the
    password never reaches the server (invariant 15). The command sets the
    flags back."""
    one = by_value(monkeypatch, login(name="acme_jdoe", locked_out=locked_out))
    changes = one.reset_password("acme_jdoe", Secret(PASSWORD), expire=False)

    [statement] = one.connection.sent
    assert statement.startswith("ALTER LOGIN [acme_jdoe] WITH PASSWORD = 0x0200")
    assert statement.endswith(" HASHED, CHECK_POLICY = OFF")
    assert PASSWORD not in statement
    assert [(c.action, c.changed) for c in changes] == [
        (ACCOUNT_UNLOCK, locked_out),
        (PASSWORD_SET, True),
        (ROLLOVER_FINISH, False),
    ]


def test_the_unseen_reset_refuses_a_pending_must_change_naming_the_seen_reset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The server refuses CHECK_POLICY = OFF then, `15128` (decision 2)."""
    one = by_value(monkeypatch, login(name="acme_jdoe", must_change=True))

    with pytest.raises(session.MustChangeError) as caught:
        one.reset_password("acme_jdoe", Secret(PASSWORD), expire=False)

    assert "delivery.method: manual" in str(caught.value.hint)
    assert one.connection.sent == []


def test_the_reset_reads_the_flags_and_refuses_must_change_before_anything(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Step 1 for the command, with the reset's hint."""
    one = by_value(monkeypatch, login(name="acme_jdoe", expiration_checked=False))
    flags = one.reset_policy_flags("acme_jdoe")
    assert (flags.check_policy, flags.check_expiration) == (True, False)

    pending = by_value(monkeypatch, login(name="acme_jdoe", must_change=True))
    with pytest.raises(session.MustChangeError) as caught:
        pending.reset_policy_flags("acme_jdoe")
    assert "delivery.method: manual" in str(caught.value.hint)
    assert pending.connection.sent == []


def test_a_refusal_keeps_no_password(monkeypatch: pytest.MonkeyPatch) -> None:
    """No answer measured echoes the statement; the scrub is the guard if one
    did (#786)."""
    echoed = (
        "[42000] [Microsoft][ODBC Driver 18 for SQL Server][SQL Server]Incorrect syntax "
        f"near 'N'{PASSWORD}' MUST_CHANGE'. (102) (SQLExecDirectW)"
    )
    one = opened(monkeypatch, login(name="acme_jdoe"), pyodbc.ProgrammingError("42000", echoed))
    with pytest.raises(DriverError) as caught:
        one.reset_password("acme_jdoe", Secret(PASSWORD), expire=True)
    assert PASSWORD not in str(caught.value)
    assert "N'***' MUST_CHANGE" in str(caught.value)
    assert caught.value.password_sent


def test_the_scrub_removes_the_doubled_form() -> None:
    statement = password.MustChange("acme_jdoe", Secret("Ab1'x"), unlock=False)
    assert statement.scrub("near 'Ab1''x' and Ab1'x") == "near '***' and ***"


def test_a_read_only_target_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    one = opened(monkeypatch, login(name="acme_jdoe"))
    one.scope = lambda: Scope(type="server", open_mode="READ ONLY", read_write=False)
    with pytest.raises(DriverError):
        one.reset_password("acme_jdoe", Secret(PASSWORD), expire=True)
    assert one.connection.sent == []
