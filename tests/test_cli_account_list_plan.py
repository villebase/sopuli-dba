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
from sopuli.driver.clusters import claim
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

    def __init__(self, target: str, refuse: dict[str, Exception | None]) -> None:
        self.target = target
        self.refuse = refuse
        self.described: list[str] = []

    def _answer(self, method: str, name: str) -> str | None:
        """``name``, or what ``refuse`` says: an error to raise, or ``None``
        for a role or profile the target does not have."""
        if method not in self.refuse:
            return name
        answer = self.refuse[method]
        if answer is None:
            return None
        raise answer

    def resolve_role(self, role: str) -> str | None:
        return self._answer("resolve_role", role)

    def resolve_profile(self, profile: str) -> str | None:
        return self._answer("resolve_profile", profile)

    def accounts_matching(self, **_: Any) -> tuple[str, ...]:
        self._answer("accounts_matching", "")
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


MIXED = """version: 1
targets:
  - name: ora-dev
    type: oracle
    environment: dev
    dsn: db.example.com:1521/ACME
    admin: { username: sopuli_svc, auth: { method: env } }
  - name: mysql-dev
    type: mysql
    environment: dev
    dsn: db.example.com:3306
    admin: { username: "sopuli_svc@%", auth: { method: env } }
personal_accounts:
  - profile: ACME_DEV
"""


def test_the_refusal_from_the_type_comes_before_any_target_is_opened(
    write_config: WriteConfig, sessions: dict[str, Any]
) -> None:
    """The Oracle target comes first and has profiles, but the MySQL target's
    refusal needs no connection, so neither is opened."""
    config = write_config(MIXED)
    result = CliRunner().invoke(
        cli, ["--config", str(config), "--output", "json", "account", "list"]
    )

    found = document(result)
    assert found["exit_code"] == ExitCode.UNSUPPORTED_CAPABILITY, result.output
    assert "mysql-dev" in found["error"]["message"]
    assert sessions["opened"] == []


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
    """The refusal comes before the first target's accounts are described, so
    no rows are read and then dropped."""
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


def test_a_target_that_cannot_be_opened_is_passed_over_and_reported_per_target(
    write_config: WriteConfig, sessions: dict[str, Any]
) -> None:
    """An unreachable target says nothing about whether it could resolve the
    rule, so it is not refused here: the listing reports it as it always has,
    and the other target is listed."""
    sessions["dev-1"] = DriverError("connection refused")
    result = listed(write_config, "postgresql", "  - role: acme_dev_role")

    found = document(result)
    assert found["exit_code"] == ExitCode.PARTIAL, result.output
    rows = {row["target"]: row for row in found["results"]}
    assert rows["dev-1"]["state"] == "ERROR"
    assert rows["dev-2"]["account"] == "acme_jdoe"


class LostError(DriverError):
    """A session lost while it is read."""

    category = "connectivity"


def test_a_session_lost_in_the_check_is_passed_over(
    write_config: WriteConfig, sessions: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """dev-1's session is lost while the check reads it. That says nothing
    about the rule, so the run goes on, and the listing reads dev-1 again."""
    opens = {"dev-1": 0}

    def open_session(target: Any, run: Any, config: Any) -> FakeSession:
        refuse: dict[str, Exception | None] = {}
        if target.name == "dev-1":
            opens["dev-1"] += 1
            if opens["dev-1"] == 1:
                refuse = {"resolve_role": LostError("the connection was lost")}
        session = FakeSession(target.name, refuse)
        sessions["opened"].append(session)
        return session

    monkeypatch.setattr("sopuli.cli._open_session", open_session)
    result = listed(write_config, "postgresql", "  - role: acme_dev_role")

    found = document(result)
    assert found["exit_code"] == ExitCode.SUCCESS, result.output
    assert [(row["account"], row["target"]) for row in found["results"]] == [
        ("acme_jdoe", "dev-1"),
        ("acme_jdoe", "dev-2"),
    ]


class MandatoryRoleError(DriverError):
    """As MySQL's ``MandatoryRoleError``: a refusal of the rule, ``config``."""

    category = "config"


@pytest.mark.parametrize(
    ("method", "error"),
    [
        pytest.param(
            "resolve_role", MandatoryRoleError("acme_dev_role@% is mandatory"), id="role-refused"
        ),
        pytest.param(
            "accounts_matching",
            DriverError("the server refused a read of mysql.role_edges"),
            id="read-refused",
        ),
    ],
)
def test_any_refusal_resolving_the_rule_comes_before_anything_is_listed(
    write_config: WriteConfig, sessions: dict[str, Any], method: str, error: DriverError
) -> None:
    """Not only a missing capability: the listing resolves a rule outside its
    per-target `try`, so any refusal it met there lost the earlier rows."""
    sessions["dev-2"] = {method: error}
    result = listed(write_config, "mysql", "  - role: acme_dev_role@%")

    assert type(result.exception) is type(error), result.output
    assert [one.described for one in sessions["opened"]] == [[], []]


def test_a_role_the_second_target_does_not_have_is_refused_before_anything_is_listed(
    write_config: WriteConfig, sessions: dict[str, Any]
) -> None:
    sessions["dev-2"] = {"resolve_role": None}
    result = listed(write_config, "postgresql", "  - role: acme_dev_role")

    assert "target 'dev-2' has no role 'acme_dev_role'" in result.output
    assert result.exit_code != ExitCode.SUCCESS
    assert [one.described for one in sessions["opened"]] == [[], []]


class OneServer(FakeSession):
    """A session that names its server, as PostgreSQL's names its cluster."""

    identity_caveat = None
    identity_kind = "PostgreSQL cluster"
    identity_key = "system_identifier"
    identity_hint = "declare the cluster once"

    def cluster_identity(self) -> str:
        return "7000000000000000001"


def test_the_check_does_not_change_which_of_two_targets_on_one_server_is_refused(
    write_config: WriteConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Only dev-2 has a predicate, so the check opens it first. Its claim is
    put back, and the listing, in target order, still refuses dev-2 and
    lists dev-1."""
    opened: list[str] = []

    def open_session(target: Any, run: Any, config: Any) -> FakeSession:
        session = OneServer(target.name, {})
        opened.append(target.name)
        claim(session, target.name, run.clusters)
        return session

    monkeypatch.setattr("sopuli.cli._open_session", open_session)
    rules = "  - accounts: [acme_jdoe]\n  - role: acme_dev_role\n    targets: [dev-2]"
    result = listed(write_config, "postgresql", rules)

    found = document(result)
    assert opened == ["dev-2", "dev-1", "dev-2"]
    rows = {row["target"]: row for row in found["results"]}
    assert rows["dev-1"]["account"] == "acme_jdoe"
    assert rows["dev-1"]["state"] != "ERROR"
    assert rows["dev-2"]["state"] == "ERROR"
