"""`sopuli account suspend` and `expire-password` on a MySQL target, on a fake
session (#1225). Tier 0.

What the commands add on MySQL: a `role:` rule that names a mandatory role is
refused at plan time, as `account list` and `reset-password` refuse it, and
names are compared as the server compares them. The driver's statements are
tested in `tests/driver/test_mysql_session.py`, and against a server in
`tests/driver/test_mysql_account_verbs_live.py`.
"""

from __future__ import annotations

import pytest
from click.testing import CliRunner, Result

from conftest import WriteConfig
from sopuli.cli import cli
from sopuli.driver.mysql.roles import MandatoryRoleError
from sopuli.driver.protocol import (
    ACCOUNT_LOCK,
    ENCRYPTION_TLS,
    EXPIRE_PASSWORD,
    PASSWORD_EXPIRE,
    ROLE_LOOKUP,
    ROLLOVER_FINISH,
    AccountChange,
    Encryption,
    Scope,
    UserState,
)
from sopuli.exit_codes import ExitCode

CONFIG = """version: 1
targets:
  - name: mysql-dev
    type: mysql
    environment: dev
    dsn: mysql-dev.example.com:3306
    admin: {{ username: "sopuli_svc@%", auth: {{ method: env }} }}
personal_accounts:
{rules}
"""

MANDATORY = "everyone@%"
#: A departed DBA with a global privilege.
ADMIN = "dba@%"


class FakeSession:
    """A server where `jdoe@%` and `JDOE@%`, two accounts, are open and hold
    `dev_role@%`. It records what the verbs asked of it."""

    def __init__(self, calls: list[str]) -> None:
        self.calls = calls

    def scope(self) -> Scope:
        return Scope(
            type="server",
            read_write=True,
            capabilities=frozenset({EXPIRE_PASSWORD, ROLE_LOOKUP}),
            encryption=Encryption(method=ENCRYPTION_TLS),
        )

    def resolve_role(self, role: str) -> str | None:
        if role == MANDATORY:
            raise MandatoryRoleError(role, through=role, target="mysql-dev")
        return role

    def describe_user(self, account: str) -> UserState | None:
        if account == ADMIN:
            return UserState(
                name=account, status="OPEN", global_privileges=frozenset({"ALL PRIVILEGES ON *.*"})
            )
        if account not in ("jdoe@%", "JDOE@%"):
            return None
        return UserState(name=account, status="OPEN", roles=frozenset({"dev_role@%"}))

    def suspend_account(self, account: str) -> AccountChange:
        self.calls.append(f"suspend {account}")
        return AccountChange(ACCOUNT_LOCK, changed=True, status="OPEN", detail="sent ACCOUNT LOCK")

    def expire_password(self, account: str) -> tuple[AccountChange, ...]:
        self.calls.append(f"expire {account}")
        return (
            AccountChange(ROLLOVER_FINISH, changed=True, status="OPEN", detail="discarded"),
            AccountChange(PASSWORD_EXPIRE, changed=True, status="OPEN", detail="expired"),
        )

    def close(self) -> None:
        return None


@pytest.fixture
def calls(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    found: list[str] = []
    monkeypatch.setattr("sopuli.cli._open_session", lambda target, run, config: FakeSession(found))
    return found


def run(write_config: WriteConfig, verb: str, rules: str, account: str) -> Result:
    config = write_config(CONFIG.format(rules=rules))
    return CliRunner().invoke(
        cli, ["--config", str(config), "account", verb, "--account", account, "--confirm"]
    )


VERBS = ["suspend", "expire-password"]


@pytest.mark.parametrize("verb", VERBS)
def test_a_rule_naming_a_mandatory_role_is_refused_at_plan_time(
    write_config: WriteConfig, calls: list[str], verb: str
) -> None:
    """Decision 5: exit 9, before anything is changed."""
    result = run(write_config, verb, f"  - role: {MANDATORY}", "jdoe@%")

    assert type(result.exception) is MandatoryRoleError, result.output
    assert result.exception.exit_code == ExitCode.CONFIG_INVALID
    assert calls == []


@pytest.mark.parametrize(("verb", "said"), [("suspend", "suspend"), ("expire-password", "expire")])
def test_a_declared_account_reaches_the_driver(
    write_config: WriteConfig, calls: list[str], verb: str, said: str
) -> None:
    result = run(write_config, verb, "  - role: dev_role@%", "jdoe@%")

    assert result.exit_code == ExitCode.SUCCESS, result.output
    assert calls == [f"{said} jdoe@%"]


@pytest.mark.parametrize("verb", VERBS)
def test_another_spelling_of_the_user_is_not_declared(
    write_config: WriteConfig, calls: list[str], verb: str
) -> None:
    """`JDOE@%` is another account than a declared `jdoe@%` on MySQL (#1225,
    item 1), so guardrail 1 refuses it."""
    result = run(write_config, verb, "  - accounts: [jdoe@%]", "JDOE@%")

    assert result.exit_code == ExitCode.SUCCESS, result.output
    assert "SKIPPED" in result.output
    assert calls == []


@pytest.mark.parametrize(("verb", "said"), [("suspend", "suspend"), ("expire-password", "expire")])
def test_an_account_with_a_global_privilege_reaches_the_driver_on_mysql(
    write_config: WriteConfig, calls: list[str], verb: str, said: str
) -> None:
    """Guardrail 9 does not run for these verbs on MySQL (#1222). The command
    passes the target's type, so this is not the refusal a missing type
    gets (#1272)."""
    result = run(write_config, verb, f"  - accounts: [{ADMIN}]", ADMIN)

    assert result.exit_code == ExitCode.SUCCESS, result.output
    assert calls == [f"{said} {ADMIN}"]


def test_suspend_needs_no_capability_on_mysql(write_config: WriteConfig, calls: list[str]) -> None:
    """As on PostgreSQL, suspend is not gated by `account_lock_state`, which a
    MySQL session does not report."""
    result = run(write_config, "suspend", "  - accounts: [jdoe@%]", "jdoe@%")

    assert result.exit_code == ExitCode.SUCCESS, result.output
    assert calls == ["suspend jdoe@%"]
