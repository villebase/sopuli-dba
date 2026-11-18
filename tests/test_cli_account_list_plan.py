"""`sopuli account list` refuses a rule a target cannot resolve, before
anything is listed (#1598). Tier 0, on fake sessions.

A `profile:` rule on a product with no profiles is refused from the target's
type, with no connection. Any other `profile:` or `role:` rule asks the
target. A target that cannot be opened, or whose read fails another way, is
passed over here and reported by the listing, per target.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from click.testing import CliRunner, Result

from conftest import WriteConfig
from sopuli.cli import cli
from sopuli.driver.protocol import (
    PROFILE_MANAGEMENT,
    ROLE_LOOKUP,
    DriverError,
    UnsupportedCapabilityError,
    UserState,
)
from sopuli.driver.registry import DRIVERS
from sopuli.exit_codes import ExitCode

CONFIG = """version: 1
targets:
  - name: dev-1
    type: {product}
    environment: dev
    dsn: {dsn}
    admin: {{ username: {admin}, auth: {{ method: env }} }}
  - name: dev-2
    type: {product}
    environment: dev
    dsn: {dsn}
    admin: {{ username: {admin}, auth: {{ method: env }} }}
personal_accounts:
{rules}
"""

#: Each product's target as the config spells it, and a role a rule can name.
PRODUCTS = {
    "oracle": ("db.example.com:1521/ACME", "sopuli_svc", "ACME_DEV_ROLE"),
    "postgresql": ("db.example.com:5432", "sopuli_svc", "acme_dev_role"),
    "mysql": ("db.example.com:3306", '"sopuli_svc@%"', "acme_dev_role@%"),
    "mariadb": ("db.example.com:3306", '"sopuli_svc@%"', "acme_dev_role"),
    "mssql": ("db.example.com:1433", "sopuli_svc", "acme_dev_role"),
}


class FakeSession:
    """A target whose role and profile reads answer as ``refuse`` says.

    ``refuse`` maps a method name to the error it raises. Every account the
    role or profile names is ``acme_jdoe``, and it is open.
    """

    def __init__(self, target: str, refuse: dict[str, Exception]) -> None:
        self.target = target
        self.refuse = refuse
        self.described: list[str] = []

    def _answer(self, method: str, name: str) -> str:
        if method in self.refuse:
            raise self.refuse[method]
        return name

    def resolve_role(self, role: str) -> str | None:
        return self._answer("resolve_role", role)

    def resolve_profile(self, profile: str) -> str | None:
        return self._answer("resolve_profile", profile)

    def accounts_matching(self, **_: Any) -> tuple[str, ...]:
        return ("acme_jdoe",)

    def describe_user(self, account: str) -> UserState:
        self.described.append(account)
        return UserState(name=account, status="OPEN", locked=False)

    def close(self) -> None:
        return None


@pytest.fixture
def sessions(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Per target name: a dict of errors its session raises, or an exception
    that opening it raises. Every session opened is kept under ``opened``."""
    plan: dict[str, Any] = {"opened": []}

    def open_session(target: Any, run: Any, config: Any) -> FakeSession:
        wanted = plan.get(target.name, {})
        if isinstance(wanted, Exception):
            raise wanted
        session = FakeSession(target.name, wanted)
        plan["opened"].append(session)
        return session

    monkeypatch.setattr("sopuli.cli._open_session", open_session)
    return plan


def listed(write_config: WriteConfig, product: str, rules: str) -> Result:
    dsn, admin, _ = PRODUCTS[product]
    config = write_config(CONFIG.format(product=product, dsn=dsn, admin=admin, rules=rules))
    return CliRunner().invoke(cli, ["--config", str(config), "--output", "json", "account", "list"])


def document(result: Result) -> dict[str, Any]:
    found: dict[str, Any] = json.loads(result.output)
    return found


@pytest.mark.parametrize(
    "product", sorted(name for name, entry in DRIVERS.items() if entry.no_profiles)
)
def test_a_profile_rule_on_a_product_with_no_profiles_is_refused_with_no_connection(
    write_config: WriteConfig, sessions: dict[str, Any], product: str
) -> None:
    result = listed(write_config, product, "  - profile: ACME_DEV")

    found = document(result)
    assert found["exit_code"] == ExitCode.UNSUPPORTED_CAPABILITY, result.output
    assert sessions["opened"] == [], "the product's type says it, with no connection"
    assert not found.get("results")
    error = found["error"]
    assert error["target_capability"] == PROFILE_MANAGEMENT
    assert "dev-1" in error["message"]
    assert error["hint"] == DRIVERS[product].no_profiles


def test_oracle_has_profiles_so_a_profile_rule_asks_the_target(
    write_config: WriteConfig, sessions: dict[str, Any]
) -> None:
    """Oracle has profiles, so only the target can say whether the tool may
    read them. The second target refuses, and nothing is listed: the first
    target's rows are not read and then lost."""
    sessions["dev-2"] = {
        "resolve_profile": UnsupportedCapabilityError(PROFILE_MANAGEMENT, target="dev-2")
    }
    result = listed(write_config, "oracle", "  - profile: ACME_DEV")

    found = document(result)
    assert found["exit_code"] == ExitCode.UNSUPPORTED_CAPABILITY, result.output
    assert found["error"]["target_capability"] == PROFILE_MANAGEMENT
    assert "dev-2" in found["error"]["message"]
    assert not found.get("results")
    assert [one.described for one in sessions["opened"]] == [[], []]


@pytest.mark.parametrize("product", sorted(PRODUCTS))
def test_a_role_rule_the_second_target_cannot_resolve_lists_nothing(
    write_config: WriteConfig, sessions: dict[str, Any], product: str
) -> None:
    """The refusal used to come from the listing, on the second target, after
    the first target's rows had been read, and they were lost."""
    sessions["dev-2"] = {
        "resolve_role": UnsupportedCapabilityError(
            ROLE_LOOKUP, target="dev-2", hint="grant the tool the read"
        )
    }
    result = listed(write_config, product, f"  - role: {PRODUCTS[product][2]}")

    found = document(result)
    assert found["exit_code"] == ExitCode.UNSUPPORTED_CAPABILITY, result.output
    assert found["error"]["target_capability"] == ROLE_LOOKUP
    assert "dev-2" in found["error"]["message"]
    assert found["error"]["hint"] == "grant the tool the read"
    assert not found.get("results")
    assert [one.described for one in sessions["opened"]] == [[], []]


def test_a_role_rule_every_target_resolves_is_listed(
    write_config: WriteConfig, sessions: dict[str, Any]
) -> None:
    """The plan-time check connects once more per target, and changes nothing
    in what is listed."""
    result = listed(write_config, "postgresql", "  - role: acme_dev_role")

    found = document(result)
    assert found["exit_code"] == ExitCode.SUCCESS, result.output
    assert [(row["account"], row["target"]) for row in found["results"]] == [
        ("acme_jdoe", "dev-1"),
        ("acme_jdoe", "dev-2"),
    ]
    assert len(sessions["opened"]) == 4


def test_an_enumerated_rule_makes_no_plan_time_connection(
    write_config: WriteConfig, sessions: dict[str, Any]
) -> None:
    result = listed(write_config, "postgresql", "  - accounts: [acme_jdoe]")

    assert document(result)["exit_code"] == ExitCode.SUCCESS, result.output
    assert len(sessions["opened"]) == 2, "one connection per target, for the listing"


@pytest.mark.parametrize(
    "failure",
    [
        pytest.param(DriverError("connection refused"), id="not-opened"),
        pytest.param(
            {"resolve_role": DriverError('the session to target "dev-1" is closed')},
            id="read-failed",
        ),
    ],
)
def test_a_target_that_fails_otherwise_is_passed_over_and_reported_per_target(
    write_config: WriteConfig, sessions: dict[str, Any], failure: Any
) -> None:
    """Not a capability, so not refused here: the listing reports the target as
    it always has. The plan-time check passes the first target over; the
    second target is still listed."""
    calls = {"dev-1": 0}
    real = sessions

    def first_fails_once(target: Any, run: Any, config: Any) -> FakeSession:
        if target.name == "dev-1":
            calls["dev-1"] += 1
            if calls["dev-1"] == 1:
                if isinstance(failure, Exception):
                    raise failure
                session = FakeSession("dev-1", failure)
                real["opened"].append(session)
                return session
            raise DriverError("connection refused")
        session = FakeSession(target.name, {})
        real["opened"].append(session)
        return session

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr("sopuli.cli._open_session", first_fails_once)
        result = listed(write_config, "postgresql", "  - role: acme_dev_role")

    found = document(result)
    assert found["exit_code"] == ExitCode.PARTIAL, result.output
    rows = {row["target"]: row for row in found["results"]}
    assert rows["dev-1"]["state"] == "ERROR"
    assert rows["dev-2"]["account"] == "acme_jdoe"
