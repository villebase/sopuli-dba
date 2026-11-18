"""The `account` verbs that change an account refuse a `profile:` or `role:`
rule a target cannot resolve, at plan time, as `account list` does (#1603).
Tier 0, on the fake sessions of ``test_cli_account_list_plan``.

A verb admits an account by the profile and roles it holds. Without the
plan-time question, a rule that names nothing would only leave the account
undeclared, and the run would report it skipped rather than name the typo.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from click.testing import CliRunner, Result

from conftest import WriteConfig
from sopuli.cli import cli
from sopuli.driver.protocol import PROFILE_MANAGEMENT, DriverError
from sopuli.driver.registry import DRIVERS
from sopuli.exit_codes import ExitCode
from test_cli_account_list_plan import CONFIG, PRODUCTS, sessions

__all__ = ["sessions"]


def document(result: Result) -> dict[str, Any]:
    """The run document, from stdout alone: a refusal also prints to stderr."""
    found: dict[str, Any] = json.loads(result.stdout)
    return found


#: Each verb, with the arguments that reach the plan-time checks. A reset
#: needs a delivery method; `--dry-run` opens no store for it.
VERBS = {
    "suspend": ["account", "suspend", "--confirm"],
    "expire-password": ["account", "expire-password", "--confirm"],
    "reset-password": ["account", "reset-password", "--dry-run"],
}

DELIVERY = """delivery:
  method: vault_wrapped
  vault_wrapped: { vault: vault-dev, ttl: 15m }
vaults:
  vault-dev:
    type: hashicorp
    addr: https://vault.example.com:8200
    mount: secret
    kv_version: 2
    auth: { method: token }
"""


def run(write_config: WriteConfig, verb: str, product: str, rules: str) -> Result:
    dsn, admin, _ = PRODUCTS[product]
    text = CONFIG.format(product=product, dsn=dsn, admin=admin, rules=rules) + DELIVERY
    config = write_config(text)
    # MySQL and MariaDB name an account user@host.
    account = "acme_jdoe@%" if product in ("mysql", "mariadb") else "acme_jdoe"
    return CliRunner().invoke(
        cli, ["--config", str(config), "--output", "json", *VERBS[verb], "--account", account]
    )


def described(sessions: dict[str, Any]) -> list[str]:
    return [name for session in sessions["opened"] for name in session.described]


@pytest.mark.parametrize("verb", sorted(VERBS))
@pytest.mark.parametrize("product", sorted(PRODUCTS))
def test_a_role_the_second_target_does_not_have_is_refused_at_plan_time(
    write_config: WriteConfig, sessions: dict[str, Any], verb: str, product: str
) -> None:
    role = PRODUCTS[product][2]
    sessions["dev-2"] = {"resolve_role": None}

    result = run(write_config, verb, product, f"  - role: {role}")

    found = document(result)
    assert found["exit_code"] == ExitCode.FAILURE, result.output
    assert "dev-2" in found["error"]["message"]
    assert "has no role" in found["error"]["message"]
    assert described(sessions) == [], "no account is read before the refusal"
    assert not found.get("results")


@pytest.mark.parametrize("verb", sorted(VERBS))
def test_a_profile_oracle_does_not_have_is_refused_at_plan_time(
    write_config: WriteConfig, sessions: dict[str, Any], verb: str
) -> None:
    sessions["dev-1"] = {"resolve_profile": None}

    result = run(write_config, verb, "oracle", "  - profile: ACME_DEV")

    found = document(result)
    assert found["exit_code"] == ExitCode.FAILURE, result.output
    assert "has no profile" in found["error"]["message"]
    assert described(sessions) == []


@pytest.mark.parametrize("verb", sorted(VERBS))
@pytest.mark.parametrize(
    "product", sorted(name for name, entry in DRIVERS.items() if entry.no_profiles)
)
def test_a_profile_rule_on_a_product_with_no_profiles_is_refused_by_capability(
    write_config: WriteConfig, sessions: dict[str, Any], verb: str, product: str
) -> None:
    result = run(write_config, verb, product, "  - profile: ACME_DEV")

    found = document(result)
    assert found["exit_code"] == ExitCode.UNSUPPORTED_CAPABILITY, result.output
    assert found["error"]["target_capability"] == PROFILE_MANAGEMENT
    assert described(sessions) == [], "no account is read before the refusal"


@pytest.mark.parametrize("verb", sorted(VERBS))
def test_a_verb_reads_no_rule_members(
    write_config: WriteConfig, sessions: dict[str, Any], verb: str
) -> None:
    """A verb admits by what the account holds, so the plan-time check asks
    only whether the role exists: a member read that fails does not refuse."""
    failing = DriverError("the member read is refused", hint="")
    sessions["dev-1"] = {"accounts_matching": failing}
    sessions["dev-2"] = {"accounts_matching": failing}

    result = run(write_config, verb, "postgresql", "  - role: acme_dev_role")

    assert "member read" not in result.output
    assert "has no role" not in result.output
    assert "error" not in document(result), "the plan-time check passed the rule"
