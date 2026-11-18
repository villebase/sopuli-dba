"""A seen reset on SQL Server whose policy can draw `'` is refused at plan
time (#1601, decision 1). Tier 0, from the config alone.

A server audit's `BATCH_COMPLETED_GROUP` keeps one of the password's last
characters in clear for each `'` (02-mssql-privileges.md §6.3), and the
seen reset sends the password in clear, so the policy must not be able to
draw one.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from click.testing import CliRunner

from conftest import WriteConfig
from sopuli.cli import cli
from sopuli.config.loading import build_config
from sopuli.config.model import Config, Delivery, ManualDelivery, WrappedDelivery
from sopuli.driver.protocol import SEEN_RESET_QUOTE, UnsupportedCapabilityError
from sopuli.driver.registry import DRIVERS
from sopuli.exit_codes import ExitCode
from sopuli.reset import refuse_unmasked_policy, refuse_unmasked_seen_password

SEEN = Delivery(method="manual", manual=ManualDelivery(force_expire=True))
UNSEEN = Delivery(method="vault_wrapped", vault_wrapped=WrappedDelivery(ttl="15m"))

MSSQL = {
    "type": "mssql",
    "name": "mssql-dev",
    "dsn": "db.example.com:1433",
    "environment": "dev",
    "admin": {"username": "sopuli_svc", "auth": {"method": "env"}},
}
ORACLE = {
    "type": "oracle",
    "name": "ora-dev",
    "dsn": "192.0.2.10:1521/ALPHA",
    "environment": "dev",
    "admin": {"username": "SOPULI_SVC", "auth": {"method": "env"}},
}

POLICIES = {
    "plain": {"password": {"length": 24}},
    "wide": {"password": {"length": 24, "charset": "printable_ascii"}},
    "custom-quote": {"password": {"length": 24, "charset": "custom", "allow": "abcdefgh'0123"}},
    "custom-plain": {"password": {"length": 24, "charset": "custom", "allow": "abcdefgh0123"}},
}


def config(rules: list[dict[str, Any]], *, default: str | None = None) -> Config:
    raw: dict[str, Any] = {
        "version": 1,
        "targets": [ORACLE, MSSQL],
        "policies": POLICIES,
        "personal_accounts": rules,
    }
    if default is not None:
        raw["defaults"] = {"policy": default}
    return build_config(raw)


def refused(found: Config, delivery: Delivery = SEEN, account: str = "acme_jdoe") -> None:
    refuse_unmasked_seen_password(delivery, found, account, found.expanded_targets)


@pytest.mark.parametrize("policy", ["wide", "custom-quote"])
def test_a_seen_reset_whose_policy_can_draw_a_quote_is_refused(policy: str) -> None:
    found = config([{"accounts": ["acme_jdoe"], "policy": policy}])

    with pytest.raises(UnsupportedCapabilityError) as caught:
        refused(found)

    assert caught.value.exit_code == ExitCode.UNSUPPORTED_CAPABILITY
    assert caught.value.capability == SEEN_RESET_QUOTE
    assert 'target "mssql-dev"' in str(caught.value)
    assert repr(policy) in str(caught.value.hint)
    assert "`'`" in str(caught.value.hint)


@pytest.mark.parametrize("policy", ["plain", "custom-plain"])
def test_a_policy_with_no_quote_passes(policy: str) -> None:
    refused(config([{"accounts": ["acme_jdoe"], "policy": policy}]))


def test_an_unseen_reset_is_not_refused() -> None:
    """The password goes to the owner's store, not into a statement in clear:
    the unseen reset sends a value (invariant 15)."""
    refused(config([{"accounts": ["acme_jdoe"], "policy": "wide"}]), delivery=UNSEEN)


def test_the_default_policy_is_the_one_a_rule_without_one_names() -> None:
    found = config([{"accounts": ["acme_jdoe"]}], default="wide")

    with pytest.raises(UnsupportedCapabilityError):
        refused(found)


def test_only_a_rule_that_could_admit_the_account_counts() -> None:
    """Another person's rule with a wide policy says nothing about this one."""
    found = config(
        [
            {"accounts": ["acme_jdoe"], "policy": "plain"},
            {"accounts": ["acme_asmith"], "policy": "wide"},
        ]
    )
    refused(found)


def test_a_rule_on_another_target_does_not_count() -> None:
    """A rule whose `targets:` leave out SQL Server is not drawn there, and
    Oracle keeps no part of the password in this way."""
    found = config(
        [
            {"accounts": ["acme_jdoe"], "policy": "plain"},
            {"role": "ACME_DEV_ROLE", "policy": "wide", "targets": ["ora-dev"]},
        ]
    )
    refused(found)


def test_a_rule_that_names_the_account_decides_over_a_predicate() -> None:
    """A role rule with a wide policy does not block a login a rule names with
    a safe one: a predicate that also admitted it with another policy would be
    refused as two rules, two policies, before any password is drawn."""
    found = config(
        [
            {"accounts": ["acme_jdoe"], "policy": "plain"},
            {"role": "acme_dev_role", "policy": "wide"},
        ]
    )
    refused(found)


@pytest.mark.parametrize(
    ("rules", "default"),
    [
        pytest.param(
            [{"role": "acme_dev_role", "policy": "wide"}, {"accounts": ["acme_jdoe"]}],
            "plain",
            id="predicate-first-with-its-own-policy",
        ),
        pytest.param(
            [{"role": "acme_dev_role"}, {"accounts": ["acme_jdoe"], "policy": "plain"}],
            "wide",
            id="predicate-first-with-the-default",
        ),
    ],
)
def test_a_predicate_before_the_naming_rule_counts(
    rules: list[dict[str, Any]], default: str
) -> None:
    """The run takes the first rule in file order that admits the account, so
    a predicate written before the naming rule may be the one, and its policy
    may be drawn: the explicit policies do not differ, so nothing refuses the
    pair."""
    with pytest.raises(UnsupportedCapabilityError) as caught:
        refused(config(rules, default=default))

    assert "'wide'" in str(caught.value.hint)


def test_a_predicate_after_the_naming_rule_does_not_count() -> None:
    """The naming rule admits the account for certain, so it is the first, and
    a later predicate's default policy is never drawn."""
    found = config(
        [{"accounts": ["acme_jdoe"], "policy": "plain"}, {"role": "acme_dev_role"}],
        default="wide",
    )
    refused(found)


def test_the_run_checks_the_policy_the_admitting_rule_names() -> None:
    """`refuse_unmasked_policy` is what the run asks of the one policy
    `_reset_policy` picked, before a password is drawn."""
    found = config([{"accounts": ["acme_jdoe"], "policy": "plain"}])
    mssql = next(one for one in found.expanded_targets if one.name == "mssql-dev")
    wide = next(policy.password for policy in found.policies if policy.name == "wide")
    oracle = next(one for one in found.expanded_targets if one.name == "ora-dev")

    with pytest.raises(UnsupportedCapabilityError):
        refuse_unmasked_policy(SEEN, "wide", wide, mssql)
    refuse_unmasked_policy(SEEN, "wide", wide, oracle)
    refuse_unmasked_policy(UNSEEN, "wide", wide, mssql)


def test_an_account_no_rule_names_counts_every_predicate_policy() -> None:
    """Which predicate admits the account only the database says, so a wide
    policy on any of them on the target refuses it."""
    found = config(
        [
            {"accounts": ["acme_asmith"], "policy": "plain"},
            {"role": "acme_dev_role", "policy": "plain"},
            {"role": "acme_ops_role", "policy": "wide"},
        ]
    )

    with pytest.raises(UnsupportedCapabilityError) as caught:
        refused(found)

    assert 'target "mssql-dev"' in str(caught.value)
    assert "'wide'" in str(caught.value.hint)


def test_only_sql_server_names_the_character() -> None:
    """The registry says which products keep part of a seen password in
    clear, and why: SQL Server alone, by measurement (#1601)."""
    assert {name for name, entry in DRIVERS.items() if entry.seen_reset_unmasked} == {"mssql"}
    assert DRIVERS["mssql"].seen_reset_unmasked == "'"
    for entry in DRIVERS.values():
        assert bool(entry.seen_reset_unmasked) == (entry.seen_reset_unmasked_why is not None)


CLI_CONFIG = """version: 1
targets:
  - name: mssql-dev
    type: mssql
    environment: dev
    dsn: db.example.com:1433
    admin: {{ username: sopuli_svc, auth: {{ method: env }} }}
policies:
  personal:
    password: {{ length: 24, charset: {charset} }}
delivery:
  method: manual
  manual: {{ force_expire: true }}
personal_accounts:
  - accounts: [acme_jdoe]
    policy: personal
"""


def test_account_reset_password_refuses_before_it_connects(
    write_config: WriteConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Through the command: a dry run, which skips the terminal guards, is
    refused with exit 5 and opens no connection."""

    def no_connection(*_: Any, **__: Any) -> None:
        raise AssertionError("the refusal needs no connection")

    monkeypatch.setattr("sopuli.cli._open_session", no_connection)
    monkeypatch.setattr("sopuli.cli._plan_scope", no_connection)
    path = write_config(CLI_CONFIG.format(charset="printable_ascii"))
    result = CliRunner().invoke(
        cli,
        [
            "--config",
            str(path),
            "--output",
            "json",
            "account",
            "reset-password",
            "--account",
            "acme_jdoe",
            "--dry-run",
        ],
    )

    found = json.loads(result.output)
    assert found["exit_code"] == ExitCode.UNSUPPORTED_CAPABILITY, result.output
    assert found["error"]["target_capability"] == SEEN_RESET_QUOTE
