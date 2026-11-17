"""SQL Server's password change, with pyodbc replaced. Tier 0
where pyodbc is installed: nothing here opens a socket (#1551).
``02-mssql-privileges.md`` §6.2 has the order these steps follow."""

from __future__ import annotations

from typing import Any

import pytest

from sopuli import cli
from sopuli.config.model import ExpandedTarget, Target
from sopuli.driver.protocol import (
    FAIL,
    OLD_RETAIN,
    PASS,
    UNAVAILABLE,
    DriverError,
    Scope,
    UnsupportedCapabilityError,
    UserState,
)
from sopuli.driver.registry import NotWrittenError
from sopuli.policy_flags import PolicyFlags
from sopuli.secrets import Secret

pyodbc = pytest.importorskip("pyodbc")
session = pytest.importorskip("sopuli.driver.mssql.session")

PASSWORD = "Acme-Vector-pw1"
TARGET = ExpandedTarget(target=Target(name="mssql-dev", type="mssql", dsn="127.0.0.1:1433"))
SCOPE = Scope(type="server", open_mode="READ WRITE", read_write=True)


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


def opened(*, platform: str | None = "Linux", error: Exception | None = None) -> Any:
    """A session on a Linux host that takes ``0x0200``, its reads replaced."""
    one = session.MssqlSession(connection=FakeConnection(error), target=TARGET)
    one.host_platform = lambda: platform
    one.hash_version = lambda: 0x0200
    one.scope = lambda: SCOPE
    return one


def test_the_value_goes_with_the_policy_off_and_never_the_password() -> None:
    one = opened()
    result = one.set_password("acme_app", Secret(PASSWORD))
    [statement] = one.connection.sent
    assert result.changed
    assert statement.startswith("ALTER LOGIN [acme_app] WITH PASSWORD = 0x0200")
    assert statement.endswith(" HASHED, CHECK_POLICY = OFF")
    assert PASSWORD not in statement


def test_a_message_that_quotes_the_statement_keeps_no_value() -> None:
    quoted = (
        "[42000] [Microsoft][ODBC Driver 18 for SQL Server][SQL Server]Incorrect syntax "
        "near 'ALTER LOGIN [acme_app] WITH PASSWORD = 0x0200A1B2C3D4E5F60718'. (102) "
        "(SQLExecDirectW)"
    )
    one = opened(error=pyodbc.ProgrammingError("42000", quoted))
    with pytest.raises(DriverError) as caught:
        one.set_password("acme_app", Secret(PASSWORD))
    assert "0x0200A1B2" not in str(caught.value)
    assert session.VALUE_REMOVED in str(caught.value)
    assert caught.value.password_sent


def test_scrub_value_leaves_short_hex_alone() -> None:
    assert session.scrub_value("state 0x01, value 0x0300ABCDEF01") == "state 0x01, value 0x…"


def test_a_window_is_refused_by_capability() -> None:
    with pytest.raises(UnsupportedCapabilityError) as caught:
        opened().set_password("acme_app", Secret(PASSWORD), old_password=OLD_RETAIN)
    assert caught.value.capability == "password_rollover"


@pytest.mark.parametrize(
    ("platform", "first"),
    [("Linux", True), ("Windows", False), (None, False)],
    ids=["linux", "windows", "unnamed"],
)
def test_only_a_linux_host_logs_in_before_a_change(platform: str | None, first: bool) -> None:
    """On Windows a wrong password counts toward a lockout (WP1), so `apply`
    sets only a `pending` there, as on MySQL. An unnamed host is Windows."""
    assert opened(platform=platform).verifies_before_change is first


def test_apply_makes_no_login_before_a_change_on_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    """The command reads the property, so it gets `None` and no login is made."""

    def connect(text: str, **kwargs: Any) -> None:
        raise AssertionError("no login is made")

    monkeypatch.setattr(pyodbc, "connect", connect)
    before: Any = cli._verify_before_change
    assert before(opened(platform="Windows"), "acme_app", Secret(PASSWORD), 2, attempts=2) is None


def test_the_skipped_row_does_not_send_the_operator_to_creds_check() -> None:
    """`creds check` cannot compare where `apply` skips: its login is refused."""
    skipped: Any = cli._skipped_without_login
    assert skipped(opened(platform="Windows")) == cli.NOT_CHECKED_WITHOUT_LOGIN_OR_CHECK
    assert "creds check" not in cli.NOT_CHECKED_WITHOUT_LOGIN_OR_CHECK
    # A driver that says nothing, such as MySQL's, keeps the advice.
    assert skipped(object()) == cli.NOT_CHECKED_WITHOUT_LOGIN


@pytest.mark.parametrize("platform", ["Windows", None], ids=["windows", "unnamed"])
def test_a_host_that_is_not_linux_takes_the_change(
    monkeypatch: pytest.MonkeyPatch, platform: str | None
) -> None:
    monkeypatch.setattr(session.accounts, "read_one", lambda *a, **k: login())
    one = opened(platform=platform)
    assert one.policy_flags("acme_app") == PolicyFlags(check_policy=True, check_expiration=False)
    assert one.set_password("acme_app", Secret(PASSWORD)).changed
    [statement] = one.connection.sent
    assert statement.endswith(" HASHED, CHECK_POLICY = OFF")


@pytest.mark.parametrize("platform", ["Windows", None], ids=["windows", "unnamed"])
def test_a_check_login_is_refused_on_a_host_that_is_not_linux(
    monkeypatch: pytest.MonkeyPatch, platform: str | None
) -> None:
    """Only a change's own login, with the policy off, is made there: any
    other caller, whatever it passes, is refused before a login."""

    def connect(text: str, **kwargs: Any) -> None:
        raise AssertionError("no login is made")

    monkeypatch.setattr(pyodbc, "connect", connect)
    one = opened(platform=platform)
    for for_check in (True, False):
        with pytest.raises(NotWrittenError, match="whose policy is on, on a Windows host"):
            one.verify_password("acme_app", Secret(PASSWORD), for_check=for_check)


def test_a_change_logs_in_on_windows_until_the_policy_is_back(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Step 3, made between step 2, which turns the policy off, and step 4."""

    class Opened:
        def close(self) -> None:
            pass

    monkeypatch.setattr(pyodbc, "connect", lambda text, **kwargs: Opened())
    one = opened(platform="Windows")
    one.describe_user = lambda account: state()
    one.set_password("acme_app", Secret(PASSWORD))
    assert one.verify_password("ACME_APP", Secret(PASSWORD)).result == PASS
    one.restore_policy("acme_app", PolicyFlags(check_policy=True, check_expiration=True))
    with pytest.raises(NotWrittenError, match="whose policy is on"):
        one.verify_password("acme_app", Secret(PASSWORD))


def login(**changes: Any) -> Any:
    fields: dict[str, Any] = {
        "name": "acme_app",
        "principal_id": 300,
        "disabled": False,
        "policy_checked": True,
        "expiration_checked": False,
        "locked_out": False,
        "must_change": False,
        "expired": False,
        "days_until_expiration": None,
        "changed_at": None,
        "session_login": False,
    }
    return session.accounts.Login(**{**fields, **changes})


def test_step_1_reads_both_flags(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(session.accounts, "read_one", lambda *a, **k: login())
    flags = opened().policy_flags("acme_app")
    assert flags == PolicyFlags(check_policy=True, check_expiration=False)


def test_a_pending_must_change_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(session.accounts, "read_one", lambda *a, **k: login(must_change=True))
    with pytest.raises(session.MustChangeError, match="must change its password"):
        opened().policy_flags("acme_app")


def test_step_4_sets_both_flags_back() -> None:
    one = opened()
    assert one.restore_policy("acme_app", PolicyFlags(check_policy=True, check_expiration=True))
    assert one.connection.sent == [
        "ALTER LOGIN [acme_app] WITH CHECK_POLICY = ON, CHECK_EXPIRATION = ON"
    ]


def test_step_4_sends_nothing_where_both_were_off() -> None:
    one = opened()
    assert not one.restore_policy("acme_app", PolicyFlags(False, False))
    assert one.connection.sent == []


def state(**changes: Any) -> UserState:
    return UserState(**{"name": "acme_app", "status": "OPEN", **changes})


@pytest.mark.parametrize(
    ("message", "result"),
    [
        ("Login failed for user 'acme_app'. (18456)", FAIL),
        ("Login failed for user 'acme_app'. Reason: The account is disabled. (18470)", UNAVAILABLE),
        (
            "Login failed for user 'acme_app'. Reason: The password must be changed. (18488)",
            UNAVAILABLE,
        ),
    ],
    ids=["wrong", "disabled", "must-change"],
)
def test_a_refused_login_says_what_it_shows(
    monkeypatch: pytest.MonkeyPatch, message: str, result: str
) -> None:
    def connect(text: str, **kwargs: Any) -> None:
        raise pyodbc.InterfaceError(
            "28000",
            f"[28000] [Microsoft][ODBC Driver 18 for SQL Server][SQL Server]{message} "
            "(SQLDriverConnect)",
        )

    monkeypatch.setattr(pyodbc, "connect", connect)
    one = opened()
    one.describe_user = lambda account: state()
    assert one.verify_password("acme_app", Secret(PASSWORD)).result == result


def test_a_login_that_logs_in_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, str] = {}

    class Opened:
        def close(self) -> None:
            pass

    def connect(text: str, **kwargs: Any) -> Opened:
        seen["text"] = text
        return Opened()

    monkeypatch.setattr(pyodbc, "connect", connect)
    one = opened()
    one.describe_user = lambda account: state()
    assert one.verify_password("acme_app", Secret(PASSWORD)).result == PASS
    assert "UID={acme_app}" in seen["text"]
    assert "Database=master" in seen["text"]


def test_a_locked_login_is_not_tried(monkeypatch: pytest.MonkeyPatch) -> None:
    """A locked login answers its right password 18456 (WP3)."""

    def connect(text: str, **kwargs: Any) -> None:
        raise AssertionError("no login is made")

    monkeypatch.setattr(pyodbc, "connect", connect)
    one = opened()
    one.describe_user = lambda account: state(locked=True, status="LOCKED(TIMED)")
    verified = one.verify_password("acme_app", Secret(PASSWORD))
    assert verified.result == UNAVAILABLE
    assert "no login was attempted" in (verified.detail or "")


def test_the_pre_flight_refuses_a_pending_must_change(monkeypatch: pytest.MonkeyPatch) -> None:
    """So `creds rotate`'s pre-flight refuses before it stages, exit 1."""
    monkeypatch.setattr(session.accounts, "read_one", lambda *a, **k: login(must_change=True))
    with pytest.raises(session.MustChangeError, match="must change its password"):
        opened().require_changeable("acme_app")


@pytest.mark.parametrize("found", [True, False], ids=["open", "missing"])
def test_the_pre_flight_passes_a_login_that_can_take_a_value(
    monkeypatch: pytest.MonkeyPatch, found: bool
) -> None:
    """A missing login is the pre-flight's own finding."""
    monkeypatch.setattr(session.accounts, "read_one", lambda *a, **k: login() if found else None)
    opened().require_changeable("acme_app")
