"""UC-5's accounts report: what each surveyed account's state is, and the exit code.

Tier 0, pure. The config is built from a dict and the survey is a list of
:class:`SurveyedAccount` values, so nothing connects. Fictional names only.
"""

from __future__ import annotations

from typing import Any

from sopuli.config.loading import build_config
from sopuli.config.model import Config
from sopuli.driver.survey import SurveyedAccount
from sopuli.report_accounts import (
    ACCOUNT_MISSING,
    NO_RULE,
    NOT_CHECKED,
    REPORT_OK,
    REPORT_PROBLEM,
    UNDECLARED,
    AccountRow,
    evaluate,
    exit_code,
)

TARGET = "free-pdb"


def config(**extra: Any) -> Config:
    document: dict[str, Any] = {
        "version": 1,
        "targets": [
            {
                "name": TARGET,
                "type": "oracle",
                "dsn": "localhost:1521/FREEPDB1",
                "labels": {"env": "dev"},
            },
            {
                "name": "other-pdb",
                "type": "oracle",
                "dsn": "localhost:1521/OTHER",
                "labels": {"env": "prod"},
            },
        ],
    }
    document.update(extra)
    return build_config(document)


def account(name: str, **fields: Any) -> SurveyedAccount:
    values: dict[str, Any] = {
        "name": name,
        "status": "OPEN",
        "locked": False,
        "profile": "DEFAULT",
        "common": False,
        "vendor_maintained": False,
        "password_lifetime": 180,
        "failed_login_limit": 10,
        "failed_logins": 0,
        "unreadable": (),
    }
    values.update(fields)
    return SurveyedAccount(**values)


def rows(cfg: Config, *survey: SurveyedAccount) -> dict[str, AccountRow]:
    return {row.account: row for row in evaluate(TARGET, cfg, survey)}


def rule(**fields: Any) -> dict[str, Any]:
    return {"reports": {"accounts": [fields]}}


def test_a_technical_account_whose_password_expires_is_a_problem() -> None:
    cfg = config(**rule(accounts=["DBSNMP"], settings={"password_lifetime": "unlimited"}))
    row = rows(cfg, account("DBSNMP", vendor_maintained=True))["DBSNMP"]
    assert row.state == REPORT_PROBLEM
    assert row.kind == "technical"
    finding = next(f for f in row.findings if f.check == "password_lifetime")
    assert finding.outcome == "problem"
    assert finding.detail == "180 days, rule says unlimited"


def test_every_check_passing_is_ok() -> None:
    cfg = config(
        **rule(
            accounts=["DBSNMP"],
            profile="TECH_NOEXPIRE",
            settings={"password_lifetime": "unlimited"},
        )
    )
    row = rows(cfg, account("DBSNMP", profile="TECH_NOEXPIRE", password_lifetime="unlimited"))[
        "DBSNMP"
    ]
    assert row.state == REPORT_OK


def test_a_number_is_a_largest_value() -> None:
    cfg = config(
        **rule(accounts=["X"], settings={"password_lifetime": 90, "failed_login_limit": 5})
    )
    assert (
        rows(cfg, account("X", password_lifetime=60, failed_login_limit=5))["X"].state == REPORT_OK
    )
    over = rows(cfg, account("X", password_lifetime="unlimited", failed_login_limit=5))["X"]
    assert over.state == REPORT_PROBLEM
    assert any(f.detail == "unlimited, rule says at most 90 days" for f in over.findings)


def test_no_rule_is_its_own_state_not_ok() -> None:
    cfg = config(personal_accounts=[{"accounts": ["acme_dev_alice"]}])
    row = rows(cfg, account("ACME_DEV_ALICE"))["ACME_DEV_ALICE"]
    assert row.kind == "personal"
    assert row.state == NO_RULE


def test_a_common_account_lock_on_a_pdb_is_not_checked_never_ok() -> None:
    cfg = config(**rule(accounts=["C##ACME_ADM"], settings={"password_lifetime": "unlimited"}))
    surveyed = account(
        "C##ACME_ADM",
        common=True,
        locked=None,
        password_lifetime=None,
        failed_login_limit=None,
        failed_logins=None,
        unreadable=("lock", "PASSWORD_LIFE_TIME", "FAILED_LOGIN_ATTEMPTS", "failed logins"),
    )
    row = rows(cfg, surveyed)["C##ACME_ADM"]
    assert row.state == NOT_CHECKED
    lock = next(f for f in row.findings if f.check == "lock")
    assert lock.outcome == "not_checked"


def test_an_unreadable_limit_with_a_rule_is_not_checked() -> None:
    cfg = config(**rule(accounts=["X"], settings={"failed_login_limit": 5}))
    assert rows(cfg, account("X", failed_login_limit=None))["X"].state == NOT_CHECKED


def test_a_problem_outranks_not_checked() -> None:
    cfg = config(
        **rule(accounts=["X"], settings={"password_lifetime": 90, "failed_login_limit": 5})
    )
    row = rows(cfg, account("X", password_lifetime="unlimited", failed_login_limit=None))["X"]
    assert row.state == REPORT_PROBLEM


def test_a_locked_declared_account_is_a_problem() -> None:
    cfg = config(**rule(accounts=["X"], profile="DEFAULT"))
    row = rows(cfg, account("X", locked=True, status="LOCKED(TIMED)"))["X"]
    assert row.state == REPORT_PROBLEM
    assert any(f.check == "lock" and f.detail == "locked: LOCKED(TIMED)" for f in row.findings)


def test_a_declared_name_that_is_not_there_is_missing() -> None:
    cfg = config(**rule(accounts=["ACME_GONE_USER"], profile="P"))
    row = rows(cfg)["ACME_GONE_USER"]
    assert row.state == ACCOUNT_MISSING
    assert row.status is None


def test_a_pattern_that_matches_nothing_is_silent() -> None:
    cfg = config(**rule(accounts=["ORDS_*"], profile="P"))
    assert rows(cfg) == {}


def test_a_pattern_matches_by_upper_case_and_star_only() -> None:
    cfg = config(**rule(accounts=["ords_*"], profile="TECH"))
    found = rows(cfg, account("ORDS_PUBLIC_USER", profile="TECH"), account("ORDSX", profile="TECH"))
    assert found["ORDS_PUBLIC_USER"].state == REPORT_OK
    # `_` is a plain character, never a LIKE wildcard.
    assert found["ORDSX"].state == UNDECLARED


def test_an_undeclared_account_is_information() -> None:
    row = rows(config(), account("ACME_STRAY_USER", locked=True))["ACME_STRAY_USER"]
    assert row.state == UNDECLARED
    assert row.kind == "undeclared"
    assert exit_code([row], unreachable=0) == 0


def test_vendor_accounts_are_left_out_unless_a_rule_names_them() -> None:
    cfg = config(**rule(accounts=["DBSNMP", "APEX_*"], profile="P"))
    found = rows(
        cfg,
        account("SYSTEM", vendor_maintained=True),
        account("DBSNMP", vendor_maintained=True, profile="P"),
        account("APEX_240100", vendor_maintained=True, profile="P"),
    )
    assert "SYSTEM" not in found
    assert found["DBSNMP"].state == REPORT_OK
    assert found["APEX_240100"].state == REPORT_OK


def test_an_application_profile_comes_from_its_policy() -> None:
    cfg = config(
        policies={"app": {"account": {"profile": "ACME_APP_PROF"}}},
        applications=[
            {
                "name": "acme",
                "accounts": ["acme_app_user"],
                "policy": "app",
                "secret": "acme/app#password",
            }
        ],
        vaults={"vault-dev": {"type": "hashicorp", "addr": "http://127.0.0.1:8200"}},
        defaults={"vault": "vault-dev"},
    )
    row = rows(cfg, account("ACME_APP_USER", profile="DEFAULT"))["ACME_APP_USER"]
    assert row.kind == "application"
    assert row.state == REPORT_PROBLEM
    assert any(f.detail == "on DEFAULT, expected ACME_APP_PROF" for f in row.findings)


def test_a_db_profile_rule_states_settings_for_every_account_on_it() -> None:
    cfg = config(
        reports={
            "accounts": [{"accounts": ["X"], "profile": "TECH"}],
            "db_profiles": [{"name": "tech", "settings": {"password_lifetime": "unlimited"}}],
        }
    )
    row = rows(cfg, account("X", profile="TECH", password_lifetime=180))["X"]
    assert row.state == REPORT_PROBLEM


def test_two_patterns_that_disagree_are_not_checked() -> None:
    cfg = config(
        reports={
            "accounts": [
                {"accounts": ["ORDS_*"], "profile": "P"},
                {"accounts": ["ORDS_PUBLIC*"], "profile": "Q"},
            ]
        }
    )
    row = rows(cfg, account("ORDS_PUBLIC_USER", profile="P"))["ORDS_PUBLIC_USER"]
    assert row.state == NOT_CHECKED
    assert any(f.detail == "two rules expect different things" for f in row.findings)


def test_a_rule_applies_only_on_its_targets() -> None:
    cfg = config(**rule(accounts=["X"], targets={"match": {"env": "prod"}}, profile="P"))
    row = rows(cfg, account("X"))["X"]
    assert row.state == UNDECLARED


def test_problems_come_first_in_the_order_the_spec_gives() -> None:
    cfg = config(
        reports={
            "accounts": [
                {"accounts": ["A_OK"], "profile": "DEFAULT"},
                {"accounts": ["B_LOCKED"], "profile": "DEFAULT"},
                {"accounts": ["C_EXPIRES"], "settings": {"password_lifetime": "unlimited"}},
                {"accounts": ["D_GONE"], "profile": "DEFAULT"},
            ]
        }
    )
    order = [
        row.account
        for row in evaluate(
            TARGET,
            cfg,
            [
                account("A_OK"),
                account("B_LOCKED", locked=True),
                account("C_EXPIRES"),
                account("Z_STRAY"),
            ],
        )
    ]
    assert order == ["C_EXPIRES", "B_LOCKED", "D_GONE", "Z_STRAY", "A_OK"]


def test_exit_codes() -> None:
    def row(state: str) -> AccountRow:
        return AccountRow(TARGET, "X", "technical", None, None, (), state, None)

    assert exit_code([row(REPORT_PROBLEM)], unreachable=1) == 1
    assert exit_code([row(REPORT_PROBLEM)], unreachable=0) == 3
    assert exit_code([row(ACCOUNT_MISSING)], unreachable=0) == 3
    assert exit_code([row(REPORT_PROBLEM), row(NOT_CHECKED)], unreachable=0) == 3
    assert exit_code([row(NOT_CHECKED)], unreachable=0) == 4
    assert exit_code([row(NO_RULE), row(UNDECLARED), row(REPORT_OK)], unreachable=0) == 0


# ------------------------------------------------- from the review of #1385 ---


def test_two_rules_setting_different_fields_combine() -> None:
    """Only one field set two ways is a conflict; a profile from one rule and a
    setting from another apply together."""
    cfg = config(
        reports={
            "accounts": [
                {"accounts": ["ACME_*"], "profile": "P"},
                {"accounts": ["acme_batch_user"], "settings": {"password_lifetime": "unlimited"}},
            ]
        }
    )
    row = rows(cfg, account("ACME_BATCH_USER", profile="Q"))["ACME_BATCH_USER"]
    assert row.state == REPORT_PROBLEM
    details = {f.check: f.detail for f in row.findings}
    assert details["profile"] == "on Q, expected P"
    assert details["password_lifetime"] == "180 days, rule says unlimited"


def test_an_application_account_never_takes_a_rules_profile() -> None:
    """Its profile comes from its policy only, also when the policy names none."""
    cfg = config(
        applications=[
            {"name": "acme", "accounts": ["acme_app_user"], "secret": "acme/app#password"}
        ],
        vaults={"vault-dev": {"type": "hashicorp", "addr": "http://127.0.0.1:8200"}},
        defaults={"vault": "vault-dev"},
        reports={"accounts": [{"accounts": ["ACME_*"], "profile": "P"}]},
    )
    row = rows(cfg, account("ACME_APP_USER", profile="DEFAULT"))["ACME_APP_USER"]
    assert row.state == NO_RULE
    assert all(f.check != "profile" or f.outcome == "no_rule" for f in row.findings)


def test_a_profile_predicate_does_not_bring_in_oracles_own_accounts() -> None:
    cfg = config(personal_accounts=[{"profile": "DEFAULT"}])
    found = rows(
        cfg,
        account("SYSTEM", vendor_maintained=True, locked=True, status="LOCKED"),
        account("ACME_DEV_ALICE"),
    )
    assert "SYSTEM" not in found
    assert found["ACME_DEV_ALICE"].kind == "personal"


def test_a_not_checked_finding_says_the_surveys_reason() -> None:
    cfg = config(**rule(accounts=["C##ACME_ADM"], settings={"failed_login_limit": 5}))
    surveyed = account(
        "C##ACME_ADM",
        common=True,
        locked=None,
        password_lifetime=None,
        failed_login_limit=None,
        failed_logins=None,
        unreadable=(
            "the lock is kept in CDB$ROOT",
            "PASSWORD_LIFE_TIME is kept in CDB$ROOT",
            "FAILED_LOGIN_ATTEMPTS is kept in CDB$ROOT",
            "the count is kept in CDB$ROOT",
        ),
    )
    row = rows(cfg, surveyed)["C##ACME_ADM"]
    details = {f.check: f.detail for f in row.findings}
    assert details["lock"] == "the lock is kept in CDB$ROOT"
    assert details["failed_login_limit"] == "FAILED_LOGIN_ATTEMPTS is kept in CDB$ROOT"
    assert row.failed_logins_reason == "the count is kept in CDB$ROOT"


# ------------------------------------------ from the second review of #1385 ---


def test_a_rule_and_its_db_profile_that_disagree_are_not_checked() -> None:
    cfg = config(
        reports={
            "accounts": [{"accounts": ["X"], "settings": {"password_lifetime": "unlimited"}}],
            "db_profiles": [{"name": "APP_PROF", "settings": {"password_lifetime": 90}}],
        }
    )
    row = rows(cfg, account("X", profile="APP_PROF", password_lifetime="unlimited"))["X"]
    finding = next(f for f in row.findings if f.check == "password_lifetime")
    assert finding.outcome == "not_checked"
    assert row.state == NOT_CHECKED


def test_a_conflict_is_on_its_own_check_and_the_others_still_run() -> None:
    cfg = config(
        reports={
            "accounts": [
                {"accounts": ["ORDS_*"], "profile": "P", "settings": {"password_lifetime": 90}},
                {"accounts": ["ORDS_PUBLIC*"], "settings": {"password_lifetime": 30}},
            ]
        }
    )
    row = rows(cfg, account("ORDS_PUBLIC_USER", profile="Q"))["ORDS_PUBLIC_USER"]
    outcomes = {f.check: f.outcome for f in row.findings}
    assert outcomes["password_lifetime"] == "not_checked"
    assert outcomes["profile"] == "problem"
    assert row.state == REPORT_PROBLEM


def test_reasons_that_do_not_line_up_are_kept_not_dropped() -> None:
    cfg = config(**rule(accounts=["X"], settings={"failed_login_limit": 5}))
    surveyed = account("X", failed_login_limit=None, unreadable=("first reason", "an extra reason"))
    finding = next(f for f in rows(cfg, surveyed)["X"].findings if f.check == "failed_login_limit")
    assert finding.detail == "first reason; an extra reason"
