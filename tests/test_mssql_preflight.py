"""The pre-flight's question to SQL Server before `creds rotate` stages a
password: can each login take one (#1551, ``02-mssql-privileges.md`` §6.2)?
Tier 0: the session is a fake, and the function is the command's own."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from sopuli import cli, preflight
from sopuli.config.model import ExpandedTarget, Target
from sopuli.driver.protocol import DriverError, Scope, UserState

survey: Any = cli._preflight_target

TARGET = ExpandedTarget(target=Target(name="mssql-dev", type="mssql", dsn="127.0.0.1:1433"))
CONFIG = SimpleNamespace(policies=[], defaults=SimpleNamespace(policy=None))


def binding(account: str) -> Any:
    return SimpleNamespace(account=account, target="mssql-dev", policy=None)


class AboutLoginError(DriverError):
    """A refusal about one login, as ``MustChangeError`` is."""

    about_account = True


class Session:
    """A SQL Server session whose ``acme_app`` cannot take a password."""

    def __init__(self, refusal: DriverError | None = None) -> None:
        self.asked: list[str] = []
        self.refusal = refusal or AboutLoginError(
            'login "acme_app" must change its password before it can take one',
            hint="clear MUST_CHANGE",
        )

    def scope(self) -> Scope:
        return Scope(type="server", open_mode="READ WRITE", read_write=True)

    def describe_user(self, account: str) -> UserState:
        return UserState(name=account, status="OPEN")

    def require_changeable(self, account: str) -> None:
        self.asked.append(account)
        if account == "acme_app":
            raise self.refusal

    def privileges(self, accounts: Any) -> Any:
        """What the pre-flight reads of the audit."""
        return SimpleNamespace(missing=(), hint=None)


def test_a_login_that_cannot_take_a_password_blocks_a_rotation() -> None:
    session = Session()
    bindings = [binding("acme_app"), binding("acme_rpt")]
    found = survey(session, TARGET, bindings, CONFIG, rotating=True)
    blocking = [finding for finding in found if finding.blocking]
    assert [(one.check, one.account) for one in blocking] == [(preflight.ACCOUNT, "acme_app")]
    assert "must change its password" in blocking[0].message
    # The other login is still asked: one refusal does not end the survey.
    assert session.asked == ["acme_app", "acme_rpt"]


def test_apply_does_not_ask() -> None:
    """`apply` reports such a login as one row and goes on to the others."""
    session = Session()
    found = survey(session, TARGET, [binding("acme_app")], CONFIG)
    assert session.asked == []
    assert not [finding for finding in found if finding.blocking]


def test_a_fault_in_the_session_is_not_a_finding_about_the_login() -> None:
    session = Session(DriverError("the connection was lost"))
    with pytest.raises(DriverError, match="connection was lost"):
        survey(session, TARGET, [binding("acme_app")], CONFIG, rotating=True)


def test_must_change_is_a_refusal_about_the_login() -> None:
    """The real error is the one the pre-flight files against the login."""
    mssql = pytest.importorskip("sopuli.driver.mssql.session")
    refusal = mssql.MustChangeError("acme_app", target="mssql-dev")
    found = survey(Session(refusal), TARGET, [binding("acme_app")], CONFIG, rotating=True)
    assert [(one.check, one.blocking) for one in found if one.account] == [
        (preflight.ACCOUNT, True)
    ]
