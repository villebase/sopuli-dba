"""A seen reset on SQL Server whose policy can draw `'` is refused at plan
time (#1601, decision 1). Tier 0, from the config alone.

A server audit's `BATCH_COMPLETED_GROUP` keeps one of the password's last
characters in clear for each `'` (02-mssql-privileges.md §6.3), and the
seen reset sends the password in clear, so the policy must not be able to
draw one.
"""

from __future__ import annotations

from typing import Any

import pytest

from sopuli.config.loading import build_config
from sopuli.config.model import Config, Delivery, ManualDelivery, WrappedDelivery
from sopuli.driver.protocol import UnsupportedCapabilityError
from sopuli.driver.registry import DRIVERS
from sopuli.exit_codes import ExitCode
from sopuli.reset import SEEN_RESET_QUOTE, refuse_unmasked_seen_password

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


def test_a_predicate_rule_counts_because_only_the_database_says_whom_it_admits() -> None:
    """The role rule applies to both targets. Which rule admits the account is
    read from the database, so its policy counts on SQL Server, while Oracle,
    which keeps no part of the password, is not refused."""
    found = config(
        [
            {"accounts": ["acme_jdoe"], "policy": "plain"},
            {"role": "acme_dev_role", "policy": "wide"},
        ]
    )

    with pytest.raises(UnsupportedCapabilityError) as caught:
        refused(found)

    assert 'target "mssql-dev"' in str(caught.value)


def test_only_sql_server_names_the_character() -> None:
    """The registry says which products keep part of a seen password in
    clear: SQL Server alone, by measurement (#1601)."""
    assert {name for name, entry in DRIVERS.items() if entry.seen_reset_unmasked} == {"mssql"}
    assert DRIVERS["mssql"].seen_reset_unmasked == "'"
