"""The *not applicable* outcome of `report accounts` (#1458).

Tier 0, pure. A check the target's product has no concept of is
`not_applicable`, never `not_checked`: it is not a gap anybody can close, so it
never sets the exit code. The driver registry says which checks each product
lacks, from the target's `type:`, with no connection. Fictional names only.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

import sopuli.output.report_view as report_view
from sopuli.config.loading import build_config
from sopuli.config.model import Config
from sopuli.driver.registry import DRIVERS
from sopuli.driver.survey import SurveyedAccount
from sopuli.output.document import SCHEMA_VERSION
from sopuli.report_accounts import (
    CHECKS,
    NO_RULE,
    NOT_APPLICABLE_OUTCOME,
    OUTCOMES,
    REPORT_OK,
    REPORT_PROBLEM,
    AccountRow,
    evaluate,
    exit_code,
    missing_profiles,
    not_applicable_on,
)

SCHEMA = (
    Path(__file__).resolve().parents[1]
    / "docs"
    / "schemas"
    / f"sopuli-run-{SCHEMA_VERSION}.schema.json"
)

PG = "pg-dev"
MARIADB = "mariadb-dev"
ORACLE = "free-pdb"


def config(*rules: dict[str, Any]) -> Config:
    document: dict[str, Any] = {
        "version": 1,
        "targets": [
            {"name": ORACLE, "type": "oracle", "dsn": "localhost:1521/FREEPDB1"},
            {"name": PG, "type": "postgresql", "dsn": "pg-dev.example.com:5432"},
            {"name": MARIADB, "type": "mariadb", "dsn": "mariadb-dev.example.com:3306"},
        ],
    }
    if rules:
        document["reports"] = {"accounts": list(rules)}
    return build_config(document)


#: A rule for a schema owner nobody logs in as, with a lifetime PostgreSQL lacks.
OWNER_RULE = {"accounts": ["ACME_OWNER"], "login": "refused", "settings": {"password_lifetime": 90}}


def account(name: str, **fields: Any) -> SurveyedAccount:
    values: dict[str, Any] = {
        "name": name,
        "status": "OPEN",
        "locked": False,
        "profile": "",
        "common": False,
        "vendor_maintained": False,
        "password_lifetime": None,
        "failed_login_limit": None,
        "failed_logins": None,
        "unreadable": (),
    }
    values.update(fields)
    return SurveyedAccount(**values)


def row(cfg: Config, target: str, surveyed: SurveyedAccount) -> AccountRow:
    (only,) = evaluate(target, cfg, (surveyed,))
    return only


def outcome(found: AccountRow, check: str) -> tuple[str, str]:
    finding = next(f for f in found.findings if f.check == check)
    return finding.outcome, finding.detail


def test_each_products_set_names_only_checks_the_report_has() -> None:
    for name, driver in DRIVERS.items():
        assert driver.not_applicable <= set(CHECKS), name
        # The lock and an account's presence are checks every product has.
        assert not driver.not_applicable & {"lock", "present"}, name


def test_oracle_has_every_check() -> None:
    assert DRIVERS["oracle"].not_applicable == frozenset()
    assert not_applicable_on(config(), ORACLE) == frozenset()


@pytest.mark.parametrize(
    ("target", "expected"),
    [
        (PG, {"password_lifetime", "failed_login_limit", "profile"}),
        (MARIADB, {"failed_login_limit", "profile"}),
    ],
)
def test_the_registry_says_what_each_product_lacks(target: str, expected: set[str]) -> None:
    assert not_applicable_on(config(), target) == expected


def test_a_target_the_config_lacks_has_nothing_not_applicable() -> None:
    """A typo hides no check."""
    assert not_applicable_on(config(), "nosuch") == frozenset()


def test_a_stated_check_the_product_lacks_is_not_applicable() -> None:
    cfg = config(OWNER_RULE)
    found = row(cfg, PG, account("ACME_OWNER", locked=True, deliberately_locked=True))
    assert outcome(found, "password_lifetime") == (
        NOT_APPLICABLE_OUTCOME,
        "this product has no password_lifetime",
    )
    # The lock was stated and checked; the lifetime is not a gap.
    assert found.state == REPORT_OK


def test_not_applicable_never_hides_a_problem() -> None:
    cfg = config(OWNER_RULE)
    found = row(cfg, PG, account("ACME_OWNER", locked=False))
    assert found.state == REPORT_PROBLEM


def test_an_account_whose_every_stated_check_is_not_applicable_has_no_rule() -> None:
    """The file states nothing this product can compare, so it is `no rule`."""
    cfg = config({"accounts": ["ACME_SVC"], "settings": {"password_lifetime": 90}})
    found = row(cfg, PG, account("ACME_SVC"))
    assert found.state == NO_RULE
    # The finding stays, so the run document names the check (review of #1463).
    assert outcome(found, "password_lifetime") == (
        NOT_APPLICABLE_OUTCOME,
        "this product has no password_lifetime",
    )
    assert {f.check for f in found.findings} == {"lock", "password_lifetime"}


def test_a_lock_on_an_account_whose_checks_are_not_applicable_is_still_a_problem() -> None:
    cfg = config({"accounts": ["ACME_SVC"], "settings": {"password_lifetime": 90}})
    found = row(cfg, PG, account("ACME_SVC", locked=True, status="NOLOGIN"))
    assert found.state == REPORT_PROBLEM


def test_every_outcome_is_in_the_published_schema() -> None:
    """A tripwire: the run schema's outcome enum is the module's `OUTCOMES`."""
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    enum = _find_outcome_enum(schema)
    assert tuple(enum) == OUTCOMES


def _find_outcome_enum(node: Any) -> list[str]:
    """The `outcome` enum of a `report accounts` finding, wherever it sits."""
    if isinstance(node, dict):
        outcome_node = node.get("properties", {}).get("outcome")
        if isinstance(outcome_node, dict) and "no_rule" in outcome_node.get("enum", ()):
            return list(outcome_node["enum"])
        for value in node.values():
            found = _find_outcome_enum(value)
            if found:
                return found
    if isinstance(node, list):
        for value in node:
            found = _find_outcome_enum(value)
            if found:
                return found
    return []


def test_an_oracle_profile_on_another_product_is_not_applicable() -> None:
    """A product block that does not apply to the target reads as not applicable."""
    cfg = config({"accounts": ["ACME_SVC"], "login": "allowed", "oracle": {"profile": "TECH"}})
    found = row(cfg, MARIADB, account("ACME_SVC"))
    assert outcome(found, "profile")[0] == NOT_APPLICABLE_OUTCOME
    assert found.state == REPORT_OK


def test_mariadb_has_no_failed_login_limit() -> None:
    cfg = config(
        {"accounts": ["ACME_SVC"], "login": "allowed", "settings": {"failed_login_limit": 5}}
    )
    found = row(cfg, MARIADB, account("ACME_SVC"))
    assert outcome(found, "failed_login_limit")[0] == NOT_APPLICABLE_OUTCOME


def test_the_same_rule_on_oracle_is_checked() -> None:
    """Not applicable is the product's, not the rule's."""
    cfg = config({"accounts": ["ACME_SVC"], "settings": {"password_lifetime": 90}})
    found = row(cfg, ORACLE, account("ACME_SVC", password_lifetime=180))
    assert outcome(found, "password_lifetime")[0] == "problem"


def test_a_product_with_no_profiles_never_misses_one() -> None:
    cfg = config({"accounts": ["ACME_SVC"], "oracle": {"profile": "TECH"}})
    assert missing_profiles(PG, cfg, frozenset()) == ()
    assert [m.profile for m in missing_profiles(ORACLE, cfg, frozenset())] == ["TECH"]


def test_not_applicable_never_sets_the_exit_code() -> None:
    cfg = config(OWNER_RULE)
    found = row(cfg, PG, account("ACME_OWNER", locked=True, deliberately_locked=True))
    assert exit_code([found], unreachable=0) == 0


def test_the_head_line_counts_accounts_with_a_check_not_applicable() -> None:
    cfg = config(OWNER_RULE)
    found = row(cfg, PG, account("ACME_OWNER", locked=True, deliberately_locked=True))
    text = report_view.render(
        [report_view.TargetReport(target=PG, release="18.6", read=1, rows=(found,))],
        show_all=True,
    )
    assert "1 with a check not applicable" in text
    assert "password_lifetime: this product has no password_lifetime" in text
