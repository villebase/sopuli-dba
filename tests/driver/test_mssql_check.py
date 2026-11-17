"""`creds check` on SQL Server: the login and its refusal on a Windows host
(#1552). Tier 0 where pyodbc is installed: nothing here opens a socket.
``02-mssql-privileges.md`` §7 has the rules."""

from __future__ import annotations

from typing import Any

import pytest

from sopuli.config.model import ExpandedTarget, Target
from sopuli.driver.protocol import (
    FAIL,
    UNAVAILABLE,
    UnsupportedCapabilityError,
    UserState,
)
from sopuli.exit_codes import ExitCode
from sopuli.secrets import Secret

pyodbc = pytest.importorskip("pyodbc")
session = pytest.importorskip("sopuli.driver.mssql.session")

PASSWORD = "Acme-Check-pw1"
TARGET = ExpandedTarget(target=Target(name="mssql-dev", type="mssql", dsn="127.0.0.1:1433"))

WRONG = "Login failed for user 'acme_app'. (18456)"
DISABLED = "Login failed for user 'acme_app'. Reason: The account is disabled. (18470)"
MUST = "Login failed for user 'acme_app'. Reason: The password must be changed. (18488)"


def opened(platform: str | None = "Linux") -> Any:
    one = session.MssqlSession(connection=None, target=TARGET)
    one.host_platform = lambda: platform
    one.describe_user = lambda account: UserState(name="acme_app", status="OPEN")
    return one


def refused_with(monkeypatch: pytest.MonkeyPatch, message: str) -> None:
    def connect(text: str, **kwargs: Any) -> None:
        raise pyodbc.InterfaceError(
            "28000",
            f"[28000] [Microsoft][ODBC Driver 18 for SQL Server][SQL Server]{message} "
            "(SQLDriverConnect)",
        )

    monkeypatch.setattr(pyodbc, "connect", connect)


@pytest.mark.parametrize(
    ("message", "code"), [(DISABLED, "18470"), (MUST, "18488")], ids=["disabled", "must-change"]
)
def test_for_check_18470_and_18488_say_the_password_is_right(
    monkeypatch: pytest.MonkeyPatch, message: str, code: str
) -> None:
    """Each is answered only to the right password; a wrong one is 18456
    (15_login_answers_probe.py, LA2 to LA4). Still never a pass: the login
    cannot use it, so the check must not call it in sync (#1592 review)."""
    refused_with(monkeypatch, message)

    verified = opened().verify_password("acme_app", Secret(PASSWORD), for_check=True)

    assert verified.result == UNAVAILABLE
    assert f"the password is right, but the login was refused ({code})" in (verified.detail or "")


@pytest.mark.parametrize("message", [DISABLED, MUST], ids=["disabled", "must-change"])
def test_after_a_change_they_never_verify_the_password(
    monkeypatch: pytest.MonkeyPatch, message: str
) -> None:
    """The login after a change (apply's and rotate's step 3) must not
    promote a password the login cannot use."""
    refused_with(monkeypatch, message)

    verified = opened().verify_password("acme_app", Secret(PASSWORD))

    assert verified.result == UNAVAILABLE
    assert "the login cannot use the password" in (verified.detail or "")


def test_a_wrong_password_fails_in_either_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    refused_with(monkeypatch, WRONG)

    assert opened().verify_password("acme_app", Secret(PASSWORD), for_check=True).result == FAIL
    assert opened().verify_password("acme_app", Secret(PASSWORD)).result == FAIL


def test_a_linux_host_may_check_by_login() -> None:
    opened("Linux").require_login_check()


@pytest.mark.parametrize("platform", ["Windows", None], ids=["windows", "unnamed"])
def test_another_host_is_refused_naming_the_capability(platform: str | None) -> None:
    """On Windows the lockout threshold cannot be read (WP1); a host that
    names no platform is treated as Windows (#1538, decision 3)."""
    with pytest.raises(UnsupportedCapabilityError) as caught:
        opened(platform).require_login_check()

    assert caught.value.capability == "lockout_threshold"
    assert caught.value.exit_code == ExitCode.UNSUPPORTED_CAPABILITY
    assert str(caught.value).startswith('target "mssql-dev" does not support lockout_threshold')
    assert "lockout threshold the tool login cannot read" in (caught.value.hint or "")
