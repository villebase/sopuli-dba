"""The `account` verbs apply a target's and a group's `safety:` block (#1670).

Tier 0, on the fake sessions of ``test_cli_account_list_plan``. The accounts
here are declared by `personal_accounts:` and no application binds the target,
which is the case the estate merge once skipped: a `readonly`, a `max_targets`
or a `confirm_environments` written on a target or a group applied to nothing.
A verb named on the command line reaches every target it selects.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from click.testing import CliRunner, Result

from conftest import WriteConfig
from sopuli.cli import cli
from sopuli.exit_codes import ExitCode
from test_cli_account_list_plan import CONFIG, PRODUCTS, sessions

__all__ = ["sessions"]

#: Each verb, with the arguments that reach the safety gates. A reset needs a
#: delivery method, and `--dry-run` opens no store for it.
VERBS = {
    "suspend": ["account", "suspend"],
    "expire-password": ["account", "expire-password"],
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

DSN, ADMIN, _ = PRODUCTS["oracle"]
BASE = CONFIG.format(product="oracle", dsn=DSN, admin=ADMIN, rules="  - accounts: [acme_jdoe]")
LABELLED = BASE.replace(
    "    environment: dev\n", "    environment: dev\n    labels: { fleet: acme }\n"
)


def run(write_config: WriteConfig, verb: str, text: str, *extra: str) -> Result:
    config = write_config(text + DELIVERY)
    return CliRunner().invoke(
        cli,
        [
            "--config",
            str(config),
            "--output",
            "json",
            *VERBS[verb],
            "--account",
            "acme_jdoe",
            *extra,
        ],
    )


def document(result: Result) -> dict[str, Any]:
    found: dict[str, Any] = json.loads(result.stdout)
    return found


@pytest.mark.parametrize("verb", sorted(VERBS))
def test_readonly_on_a_target_refuses_the_verb(
    write_config: WriteConfig, sessions: dict[str, Any], verb: str
) -> None:
    text = BASE.replace("  - name: dev-1\n", "  - name: dev-1\n    safety: { readonly: true }\n")

    result = run(write_config, verb, text)

    assert document(result)["exit_code"] == ExitCode.ABORTED, result.output
    assert "readonly" in document(result)["error"]["hint"]
    assert "sopuli account list" in document(result)["error"]["hint"]
    assert "creds check" not in document(result)["error"]["hint"]
    assert sessions["opened"] == []


@pytest.mark.parametrize("verb", sorted(VERBS))
def test_readonly_on_a_group_refuses_the_verb(
    write_config: WriteConfig, sessions: dict[str, Any], verb: str
) -> None:
    text = (
        LABELLED + "groups:\n  acme:\n    match: { fleet: acme }\n    safety: { readonly: true }\n"
    )

    result = run(write_config, verb, text)

    assert document(result)["exit_code"] == ExitCode.ABORTED, result.output
    assert "groups.acme.safety.readonly" in document(result)["error"]["hint"]
    assert sessions["opened"] == []


@pytest.mark.parametrize("verb", sorted(VERBS))
def test_max_targets_on_a_target_bounds_the_verb(
    write_config: WriteConfig, sessions: dict[str, Any], verb: str
) -> None:
    text = BASE.replace("  - name: dev-2\n", "  - name: dev-2\n    safety: { max_targets: 1 }\n")

    result = run(write_config, verb, text)

    assert document(result)["exit_code"] == ExitCode.ABORTED, result.output
    assert "max_targets" in document(result)["error"]["message"]
    assert sessions["opened"] == []


#: A dry run that gets past the gates reads the account. The fake session has no
#: reset-side reads, so a reset is covered by the refusals above only.
PREVIEWABLE = ["expire-password", "suspend"]


@pytest.mark.parametrize("verb", PREVIEWABLE)
def test_confirm_environments_on_a_group_makes_the_plan_ask(
    write_config: WriteConfig, sessions: dict[str, Any], verb: str
) -> None:
    text = (
        LABELLED
        + "groups:\n  acme:\n    match: { fleet: acme }\n"
        + "    safety: { confirm_environments: [dev] }\n"
    )

    result = run(write_config, verb, text, "--dry-run")

    assert result.exit_code == ExitCode.SUCCESS, result.output
    assert document(result)["plan"]["confirmation_required"] is True


@pytest.mark.parametrize("verb", PREVIEWABLE)
def test_confirm_environments_on_a_target_makes_the_plan_ask(
    write_config: WriteConfig, sessions: dict[str, Any], verb: str
) -> None:
    text = BASE.replace(
        "  - name: dev-1\n", "  - name: dev-1\n    safety: { confirm_environments: [dev] }\n"
    )

    result = run(write_config, verb, text, "--dry-run")

    assert result.exit_code == ExitCode.SUCCESS, result.output
    assert document(result)["plan"]["confirmation_required"] is True


@pytest.mark.parametrize("verb", PREVIEWABLE)
def test_no_safety_block_changes_nothing(
    write_config: WriteConfig, sessions: dict[str, Any], verb: str
) -> None:
    result = run(write_config, verb, BASE, "--dry-run")

    assert result.exit_code == ExitCode.SUCCESS, result.output
    assert document(result)["plan"]["confirmation_required"] is False


def test_allowed_methods_on_a_target_narrows_a_reset(
    write_config: WriteConfig, sessions: dict[str, Any]
) -> None:
    """A target that only `personal_accounts:` declares now joins the
    intersection `refuse_disallowed_method` checks (#1670)."""
    text = BASE.replace(
        "  - name: dev-1\n",
        "  - name: dev-1\n    safety: { delivery: { allowed_methods: [manual] } }\n",
    )

    result = run(write_config, "reset-password", text)

    found = document(result)
    assert found["exit_code"] == ExitCode.ABORTED, result.output
    assert "vault_wrapped" in found["error"]["message"]
    assert "targets[0].safety.delivery.allowed_methods" in found["error"]["hint"]
    assert sessions["opened"] == []


def test_allowed_methods_on_a_group_narrows_a_reset(
    write_config: WriteConfig, sessions: dict[str, Any]
) -> None:
    text = (
        LABELLED
        + "groups:\n  acme:\n    match: { fleet: acme }\n"
        + "    safety: { delivery: { allowed_methods: [manual] } }\n"
    )

    result = run(write_config, "reset-password", text)

    found = document(result)
    assert found["exit_code"] == ExitCode.ABORTED, result.output
    assert "groups.acme.safety.delivery.allowed_methods" in found["error"]["hint"]
    assert sessions["opened"] == []
