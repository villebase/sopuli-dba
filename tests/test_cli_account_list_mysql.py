"""`sopuli account list` on a MySQL target, on a fake session (#1225). Tier 0.

What the command adds on MySQL: names compared as the server compares them,
the user by case and the host without case; a bare `--account` refused; and
`SOPULI-W063`, because the block after failed logins cannot be read. The
driver's own reads are tested in `tests/driver/test_mysql_roles.py`, and
against a server in `tests/driver/test_mysql_predicate_live.py`.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

import click
import pytest
from click.testing import CliRunner, Result

from conftest import WriteConfig
from sopuli.cli import cli
from sopuli.diagnostics import ADMITTED_CROSS_DECLARED, FAILED_LOGIN_BLOCK_UNREAD
from sopuli.driver.mysql.accounts import OtherPluginError
from sopuli.driver.protocol import DriverError, UserState
from sopuli.exit_codes import ExitCode

CONFIG = """version: 1
targets:
  - name: mysql-dev
    type: mysql
    environment: dev
    dsn: mysql-dev.example.com:3306
    admin: {{ username: "sopuli_svc@%", auth: {{ method: env }} }}
  - name: mysql-test
    type: mysql
    environment: test
    dsn: mysql-test.example.com:3306
    admin: {{ username: "sopuli_svc@%", auth: {{ method: env }} }}
personal_accounts:
{rules}
"""


class FakeSession:
    """A server whose `role:` resolves to ``members``. An account whose user
    starts ``legacy`` is on another plugin, one that starts ``locked`` is
    locked, and the rest are open."""

    def __init__(self, members: Mapping[str, tuple[str, ...]]) -> None:
        self.members = members

    def resolve_role(self, role: str) -> str | None:
        return role if role in self.members else None

    def accounts_matching(self, *, role: str | None = None, **_: Any) -> tuple[str, ...]:
        assert role is not None
        return self.members[role]

    def describe_user(self, account: str) -> UserState:
        if account.startswith("legacy"):
            raise OtherPluginError(account, "mysql_native_password", target="mysql-dev")
        if account.startswith("broken"):
            raise DriverError('the session to target "mysql-dev" is closed')
        held = frozenset(role for role, names in self.members.items() if account in names)
        locked = account.startswith("locked")
        return UserState(
            name=account, status="LOCKED" if locked else "OPEN", locked=locked, roles=held
        )

    def close(self) -> None:
        return None


@pytest.fixture
def members(monkeypatch: pytest.MonkeyPatch) -> dict[str, tuple[str, ...]]:
    found: dict[str, tuple[str, ...]] = {}
    monkeypatch.setattr("sopuli.cli._open_session", lambda target, run, config: FakeSession(found))
    return found


def listed(write_config: WriteConfig, rules: str, *args: str) -> Result:
    config = write_config(CONFIG.format(rules=rules))
    return CliRunner().invoke(
        cli, ["--config", str(config), "--output", "json", "account", "list", *args]
    )


def accounts(result: Result) -> list[tuple[str, str]]:
    return [(row["account"], row["target"]) for row in json.loads(result.output)["results"]]


def test_two_spellings_of_a_user_are_two_rows(
    write_config: WriteConfig, members: dict[str, tuple[str, ...]]
) -> None:
    """`jdoe@%` and `JDOE@%` are two accounts on MySQL, and the listing must
    not fold them into one row, as `upper()` would (#1225)."""
    members["dev_role@%"] = ("JDOE@%", "jdoe@%")
    result = listed(write_config, "  - role: dev_role@%", "--target", "mysql-dev")

    assert result.exit_code == ExitCode.SUCCESS, result.output
    assert accounts(result) == [("JDOE@%", "mysql-dev"), ("jdoe@%", "mysql-dev")]


def test_one_account_from_two_rules_is_one_row(
    write_config: WriteConfig, members: dict[str, tuple[str, ...]]
) -> None:
    """The host compares without case, so `jdoe@LOCALHOST` listed and
    `jdoe@localhost` from the role are one account."""
    members["dev_role@%"] = ("jdoe@localhost",)
    rules = "  - accounts: [jdoe@LOCALHOST]\n  - role: dev_role@%"
    result = listed(write_config, rules, "--target", "mysql-dev")

    assert result.exit_code == ExitCode.SUCCESS, result.output
    assert accounts(result) == [("jdoe@LOCALHOST", "mysql-dev")]


def test_account_filters_by_the_servers_comparison(
    write_config: WriteConfig, members: dict[str, tuple[str, ...]]
) -> None:
    members["dev_role@%"] = ("JDOE@%", "jdoe@%")
    result = listed(
        write_config, "  - role: dev_role@%", "--target", "mysql-dev", "--account", "jdoe@%"
    )

    assert accounts(result) == [("jdoe@%", "mysql-dev")]


def test_a_bare_account_is_refused(
    write_config: WriteConfig, members: dict[str, tuple[str, ...]]
) -> None:
    """As a filter it would match nothing and look like an answer."""
    result = listed(write_config, "  - role: dev_role@%", "--account", "jdoe")

    assert getattr(result.exception, "exit_code", None) == ExitCode.CONFIG_INVALID
    assert "`jdoe@%`" in str(getattr(result.exception, "hint", ""))


def test_the_unread_block_is_said_once_per_mysql_target(
    write_config: WriteConfig, members: dict[str, tuple[str, ...]]
) -> None:
    """`SOPULI-W063` in the document, with `target`, and under the table."""
    members["dev_role@%"] = ("jdoe@%", "asmith@%")
    config = write_config(CONFIG.format(rules="  - role: dev_role@%"))
    runner = CliRunner()
    document = runner.invoke(cli, ["--config", str(config), "--output", "json", "account", "list"])
    text = runner.invoke(cli, ["--config", str(config), "account", "list"])

    found = [
        one
        for one in json.loads(document.output)["diagnostics"]
        if one.get("code") == FAILED_LOGIN_BLOCK_UNREAD
    ]
    assert [one["target"] for one in found] == ["mysql-dev", "mysql-test"]
    assert click.unstyle(text.output).count("error 3955") == 2


def test_no_account_says_nothing_about_blocks(
    write_config: WriteConfig, members: dict[str, tuple[str, ...]]
) -> None:
    members["dev_role@%"] = ()
    result = listed(write_config, "  - role: dev_role@%")

    codes = [one.get("code") for one in json.loads(result.output)["diagnostics"]]
    assert FAILED_LOGIN_BLOCK_UNREAD not in codes


@pytest.mark.parametrize(
    "names", [("locked_jdoe@%",), ("legacy@%",)], ids=["locked", "undescribed"]
)
def test_no_open_account_says_nothing_about_blocks(
    write_config: WriteConfig, members: dict[str, tuple[str, ...]], names: tuple[str, ...]
) -> None:
    """A locked account cannot log in anyway, and an account that could not
    be described has no state to doubt."""
    members["dev_role@%"] = names
    result = listed(write_config, "  - role: dev_role@%", "--target", "mysql-dev")

    codes = [one.get("code") for one in json.loads(result.output)["diagnostics"]]
    assert FAILED_LOGIN_BLOCK_UNREAD not in codes


def test_an_account_that_cannot_be_described_is_one_failed_row(
    write_config: WriteConfig, members: dict[str, tuple[str, ...]]
) -> None:
    """A role member on another plugin is one ERROR row with its error, the
    others are listed, and the run exits 4, partial, not with the member's
    refusal."""
    members["dev_role@%"] = ("jdoe@%", "legacy@%")
    config = write_config(CONFIG.format(rules="  - role: dev_role@%"))
    runner = CliRunner()
    args = ["--config", str(config), "account", "list", "--target", "mysql-dev"]
    document = runner.invoke(cli, ["--output", "json", *args])
    text = runner.invoke(cli, args)

    assert document.exit_code == ExitCode.PARTIAL, document.output
    rows = {row["account"]: row for row in json.loads(document.output)["results"]}
    assert rows["jdoe@%"]["state"] == "DECLARED"
    assert rows["legacy@%"]["state"] == "ERROR"
    assert "mysql_native_password" in rows["legacy@%"]["error"]["message"]
    assert "dev_role@%" in rows["legacy@%"]["declared_by"]
    assert "1 account could not be described" in click.unstyle(text.output)
    assert "could not be answered" not in click.unstyle(text.output)


def test_a_failure_of_the_target_is_not_caught_per_account(
    write_config: WriteConfig, members: dict[str, tuple[str, ...]]
) -> None:
    """Only the driver's refusal of one account, `config`, is a row. A
    session that fails is the target's failure and ends it, as before."""
    members["dev_role@%"] = ("jdoe@%", "broken@%")
    result = listed(write_config, "  - role: dev_role@%", "--target", "mysql-dev")

    assert type(result.exception) is DriverError, result.output


def test_two_spellings_of_a_user_are_counted_as_two_accounts(
    write_config: WriteConfig, members: dict[str, tuple[str, ...]]
) -> None:
    members["dev_role@%"] = ("JDOE@%", "jdoe@%")
    config = write_config(CONFIG.format(rules="  - role: dev_role@%"))
    text = CliRunner().invoke(
        cli, ["--config", str(config), "account", "list", "--target", "mysql-dev"]
    )

    assert "2 declared accounts, 2 on the selected targets" in click.unstyle(text.output)


def test_a_cross_declared_account_is_compared_as_the_server_does(
    write_config: WriteConfig, members: dict[str, tuple[str, ...]]
) -> None:
    """An application's `JDOE@%` is another account than `jdoe@%` (#1225,
    item 6), so only `JDOE@%` carries `SOPULI-W042`."""
    members["dev_role@%"] = ("JDOE@%", "jdoe@%")
    rules = (
        "  - role: dev_role@%\n"
        "vaults:\n"
        "  vault-dev: { type: hashicorp, addr: 'https://v.example.com' }\n"
        "applications:\n"
        "  - name: acme\n"
        "    targets: [mysql-dev]\n"
        "    vault: vault-dev\n"
        "    accounts: ['JDOE@%']\n"
        "    secret_template: 'apps/acme#DB/{user}'"
    )
    result = listed(write_config, rules, "--target", "mysql-dev")

    assert result.exit_code == ExitCode.SUCCESS, result.output
    warned = {
        row["account"]: [one.get("code") for one in row.get("warnings", [])]
        for row in json.loads(result.output)["results"]
    }
    assert ADMITTED_CROSS_DECLARED in warned["JDOE@%"]
    assert ADMITTED_CROSS_DECLARED not in warned["jdoe@%"]
