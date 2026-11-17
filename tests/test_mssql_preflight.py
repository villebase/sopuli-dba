"""The pre-flight's question to SQL Server before `creds rotate` stages a
password: can each login take one (#1551, ``02-mssql-privileges.md`` §6.2)?
Tier 0: the session is a fake, and the function is the command's own."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from sopuli import cli, preflight
from sopuli.config.model import ExpandedTarget, Target
from sopuli.driver.protocol import DriverError, Scope, UserState

survey: Any = cli._preflight_target

TARGET = ExpandedTarget(target=Target(name="mssql-dev", type="mssql", dsn="127.0.0.1:1433"))
CONFIG = SimpleNamespace(policies=[], defaults=SimpleNamespace(policy=None))


def binding(account: str) -> Any:
    return SimpleNamespace(account=account, target="mssql-dev", policy=None)


class Session:
    """A SQL Server session whose ``acme_app`` has a pending ``MUST_CHANGE``."""

    def __init__(self) -> None:
        self.asked: list[str] = []

    def scope(self) -> Scope:
        return Scope(type="server", open_mode="READ WRITE", read_write=True)

    def describe_user(self, account: str) -> UserState:
        return UserState(name=account, status="OPEN")

    def require_changeable(self, account: str) -> None:
        self.asked.append(account)
        if account == "acme_app":
            raise DriverError(
                f'login "{account}" must change its password before it can take one',
                hint="clear MUST_CHANGE",
            )

    def privileges(self, accounts: Any) -> Any:
        """What the pre-flight reads of the audit."""
        return SimpleNamespace(missing=(), hint=None)


def test_a_login_that_cannot_take_a_password_blocks_the_run() -> None:
    session = Session()
    found = survey(session, TARGET, [binding("acme_app"), binding("acme_rpt")], CONFIG)
    blocking = [finding for finding in found if finding.blocking]
    assert [(one.check, one.account) for one in blocking] == [(preflight.ACCOUNT, "acme_app")]
    assert "must change its password" in blocking[0].message
    # The other login is still asked: one refusal does not end the survey.
    assert session.asked == ["acme_app", "acme_rpt"]
