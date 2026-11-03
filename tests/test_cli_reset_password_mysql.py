"""`sopuli account reset-password` on a MySQL target, on a fake session
(#1225). Tier 0.

What the command adds on MySQL: `--keep-rollover` refused by capability, a
`role:` rule that names a mandatory role refused at plan time, and names
compared as the server compares them. The driver's statements are tested in
`tests/driver/test_mysql_session.py`, and against a server in
`tests/driver/test_mysql_account_verbs_live.py`.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from click.testing import CliRunner, Result

from conftest import WriteConfig
from sopuli.cli import cli
from sopuli.driver.mysql.roles import MandatoryRoleError
from sopuli.driver.protocol import (
    ENCRYPTION_TLS,
    EXPIRE_PASSWORD,
    KEEP_ROLLOVER,
    ROLE_LOOKUP,
    Encryption,
    Scope,
    UserState,
)
from sopuli.exit_codes import ExitCode
from sopuli.passwords import ByteLimit

CONFIG = """version: 1
targets:
  - name: mysql-dev
    type: mysql
    environment: dev
    dsn: mysql-dev.example.com:3306
    admin: {{ username: "sopuli_svc@%", auth: {{ method: env }} }}
policies:
  personal-standard:
    password: {{ length: 20, charset: alnum_safe }}
personal_accounts:
{rules}
    policy: personal-standard
delivery:
  method: manual
  manual:
    force_expire: true
"""

#: The role every account holds, in the fake server's `mandatory_roles`.
MANDATORY = "everyone@%"


class FakeSession:
    """A server where `jdoe@%` and `JDOE@%`, two accounts, are open and hold
    `dev_role@%`."""

    def __init__(self, opened: list[str]) -> None:
        self.opened = opened
        self.reset: list[str] = []

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
        if account not in ("jdoe@%", "JDOE@%"):
            return None
        return UserState(name=account, status="OPEN", roles=frozenset({"dev_role@%"}))

    def byte_limit(self) -> ByteLimit:
        return ByteLimit(max_bytes=256, encoding="utf-8")

    def reset_password(self, account: str, *_: Any, **__: Any) -> tuple[Any, ...]:
        self.reset.append(account)
        raise AssertionError("a preview or a refused run never resets")

    def close(self) -> None:
        return None


@pytest.fixture
def opened(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """The targets a session was opened to."""
    found: list[str] = []

    def open_session(target: Any, run: Any, config: Any) -> FakeSession:
        found.append(target.name)
        return FakeSession(found)

    monkeypatch.setattr("sopuli.cli._open_session", open_session)
    return found


def reset(write_config: WriteConfig, rules: str, *args: str) -> Result:
    config = write_config(CONFIG.format(rules=rules))
    return CliRunner().invoke(
        cli, ["--config", str(config), "account", "reset-password", "--dry-run", *args]
    )


def test_keep_rollover_is_refused_by_capability_before_connecting(
    write_config: WriteConfig, opened: list[str]
) -> None:
    """Decision 2: a kept window cannot be read on MySQL. Exit 5, naming the
    capability and the target, and refused under `--dry-run` too. On an
    unseen path: the seen path refuses the flag on every product first."""
    config = write_config(
        CONFIG.format(rules="  - accounts: [jdoe@%]").replace(
            "method: manual\n  manual:\n    force_expire: true",
            "method: vault_wrapped\n  vault_wrapped:\n    ttl: 15m",
        )
    )
    result = CliRunner().invoke(
        cli,
        [
            "--config", str(config), "account", "reset-password", "--dry-run",
            "--account", "jdoe@%", "--keep-rollover",
        ],
    )  # fmt: skip

    assert getattr(result.exception, "exit_code", None) == ExitCode.UNSUPPORTED_CAPABILITY
    assert getattr(result.exception, "capability", None) == KEEP_ROLLOVER
    assert 'target "mysql-dev"' in str(result.exception)
    assert opened == []


@pytest.mark.parametrize(
    "rules",
    [
        f"  - role: {MANDATORY}",
        f"  - accounts: [jdoe@%]\n    policy: personal-standard\n  - role: {MANDATORY}",
    ],
    ids=["only-rule", "beside-a-list"],
)
def test_a_rule_naming_a_mandatory_role_is_refused_at_plan_time(
    write_config: WriteConfig, opened: list[str], rules: str
) -> None:
    """Decision 5, in the verb as in `account list`: exit 9, before any
    password is drawn, whichever rule declares the account."""
    result = reset(write_config, rules, "--account", "jdoe@%")

    assert type(result.exception) is MandatoryRoleError, result.output
    assert result.exception.exit_code == ExitCode.CONFIG_INVALID
    assert "would reset" not in result.output


def test_a_declared_account_would_be_reset(write_config: WriteConfig, opened: list[str]) -> None:
    result = reset(write_config, "  - role: dev_role@%", "--account", "jdoe@%")

    assert result.exit_code == ExitCode.SUCCESS, result.output
    assert "would be reset" in result.output


def test_another_spelling_of_the_user_is_not_declared(
    write_config: WriteConfig, opened: list[str]
) -> None:
    """`JDOE@%` is another account than a declared `jdoe@%` on MySQL (#1225,
    item 1), so guardrail 1 refuses it, which `upper()` would have admitted."""
    result = reset(write_config, "  - accounts: [jdoe@%]", "--account", "JDOE@%")

    assert result.exit_code == ExitCode.SUCCESS, result.output
    assert "SKIPPED" in result.output
    assert "would be reset" not in result.output


def test_the_preview_lists_the_account_by_the_servers_identity(
    write_config: WriteConfig, opened: list[str]
) -> None:
    """The plan in the document names the account as typed, on the MySQL target."""
    config = write_config(CONFIG.format(rules="  - accounts: [jdoe@%]"))
    result = CliRunner().invoke(
        cli,
        [
            "--config", str(config), "--output", "json",
            "account", "reset-password", "--dry-run", "--account", "jdoe@%",
        ],
    )  # fmt: skip

    document = json.loads(result.output)
    assert [(row["account"], row["target"]) for row in document["results"]] == [
        ("jdoe@%", "mysql-dev")
    ]
