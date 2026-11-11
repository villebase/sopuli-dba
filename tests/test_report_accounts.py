"""UC-5's accounts report: what each surveyed account's state is, and the exit code.

Tier 0, pure. The config is built from a dict and the survey is a list of
:class:`SurveyedAccount` values, so nothing connects. Fictional names only.
"""

from __future__ import annotations

from typing import Any

import pytest

from sopuli.config.errors import ConfigError
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
    missing_profiles,
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
    """One `reports.accounts` rule. A ``profile`` goes in its `oracle:` block."""
    if "profile" in fields:
        fields["oracle"] = {"profile": fields.pop("profile")}
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


def lock_of(row: AccountRow) -> tuple[str, str]:
    """The lock finding's outcome and detail."""
    finding = next(f for f in row.findings if f.check == "lock")
    return finding.outcome, finding.detail


def test_login_refused_passes_on_a_lock_set_on_purpose() -> None:
    """An owner account locked on purpose is what `login: refused` is for (#1447)."""
    cfg = config(**rule(accounts=["ACME_OWNER"], login="refused"))
    surveyed = account("ACME_OWNER", locked=True, deliberately_locked=True, status="LOCKED")
    row = rows(cfg, surveyed)["ACME_OWNER"]
    assert lock_of(row) == ("ok", "locked on purpose: LOCKED")
    assert row.state == REPORT_OK
    assert row.kind == "technical"


def test_login_refused_passes_on_a_compound_status_with_a_lock_set_on_purpose() -> None:
    cfg = config(**rule(accounts=["ACME_OWNER"], login="refused"))
    surveyed = account(
        "ACME_OWNER", locked=True, deliberately_locked=True, status="EXPIRED & LOCKED"
    )
    assert rows(cfg, surveyed)["ACME_OWNER"].state == REPORT_OK


def test_login_refused_on_an_open_account_is_a_problem() -> None:
    """The case the rule exists to catch: an owner account that can log in."""
    cfg = config(**rule(accounts=["ACME_OWNER"], login="refused"))
    row = rows(cfg, account("ACME_OWNER", locked=False, status="OPEN"))["ACME_OWNER"]
    assert lock_of(row) == ("problem", "can log in: OPEN, rule says login refused")
    assert row.state == REPORT_PROBLEM


def test_login_refused_is_not_met_by_a_lockout_after_failed_logins() -> None:
    """`LOCKED(TIMED)` is a lockout: somebody tried, and it ends by itself."""
    cfg = config(**rule(accounts=["ACME_OWNER"], login="refused"))
    surveyed = account("ACME_OWNER", locked=True, deliberately_locked=False, status="LOCKED(TIMED)")
    row = rows(cfg, surveyed)["ACME_OWNER"]
    assert lock_of(row) == (
        "problem",
        "locked by failed logins: LOCKED(TIMED), rule says login refused",
    )
    assert row.state == REPORT_PROBLEM


def test_login_refused_where_the_purpose_cannot_be_read_is_not_checked() -> None:
    """Never OK without proof: a lock the target cannot classify is not checked."""
    cfg = config(**rule(accounts=["ACME_OWNER"], login="refused"))
    surveyed = account("ACME_OWNER", locked=True, deliberately_locked=None, status="LOCKED")
    row = rows(cfg, surveyed)["ACME_OWNER"]
    assert lock_of(row)[0] == "not_checked"
    assert row.state == NOT_CHECKED


def test_login_refused_where_the_lock_cannot_be_read_is_not_checked() -> None:
    cfg = config(**rule(accounts=["ACME_OWNER"], login="refused"))
    surveyed = account("ACME_OWNER", locked=None, status="OPEN", unreadable=("kept in CDB$ROOT",))
    row = rows(cfg, surveyed)["ACME_OWNER"]
    assert lock_of(row) == ("not_checked", "kept in CDB$ROOT")


def test_login_allowed_reads_any_lock_as_a_problem() -> None:
    cfg = config(**rule(accounts=["ACME_SVC"], login="allowed"))
    surveyed = account("ACME_SVC", locked=True, deliberately_locked=True, status="LOCKED")
    row = rows(cfg, surveyed)["ACME_SVC"]
    assert lock_of(row) == ("problem", "locked: LOCKED")


def test_login_allowed_alone_makes_an_open_account_ok() -> None:
    """A rule with only `login:` states something, so the account is not `no rule`."""
    cfg = config(**rule(accounts=["ACME_SVC"], login="allowed"))
    row = rows(cfg, account("ACME_SVC", locked=False, status="OPEN"))["ACME_SVC"]
    assert row.state == REPORT_OK


def test_two_rules_that_expect_two_logins_leave_the_lock_not_checked() -> None:
    cfg = config(
        reports={
            "accounts": [
                {"accounts": ["ACME_*"], "login": "refused"},
                {"accounts": ["ACME_OWNER*"], "login": "allowed"},
            ]
        }
    )
    row = rows(cfg, account("ACME_OWNER", locked=False, status="OPEN"))["ACME_OWNER"]
    assert lock_of(row) == ("not_checked", "two rules expect different things")
    assert row.state == NOT_CHECKED


def test_a_login_rule_beside_a_settings_rule_both_apply() -> None:
    """Rules combine field by field: one says the lock, another a setting."""
    cfg = config(
        reports={
            "accounts": [
                {"accounts": ["ACME_*"], "login": "refused"},
                {"accounts": ["ACME_OWNER"], "settings": {"password_lifetime": 90}},
            ]
        }
    )
    surveyed = account(
        "ACME_OWNER", locked=True, deliberately_locked=True, status="LOCKED", password_lifetime=60
    )
    row = rows(cfg, surveyed)["ACME_OWNER"]
    assert row.state == REPORT_OK
    assert {f.check for f in row.findings} == {"lock", "password_lifetime"}


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


def _common_in_pdb(name: str) -> SurveyedAccount:
    """A common account as the survey reads it in a PDB: nothing decidable."""
    return account(
        name,
        common=True,
        kept_in_root=True,
        locked=None,
        password_lifetime=None,
        failed_login_limit=None,
        failed_logins=None,
        unreadable=("lock in root", "lifetime in root", "limit in root", "count in root"),
    )


def test_a_common_account_in_a_pdb_is_left_out_unless_a_rule_names_it() -> None:
    """#1438: its checks belong to the CDB target, where they run."""
    cfg = config(**rule(accounts=["ACME_*_USER"], settings={"password_lifetime": "unlimited"}))
    found = rows(cfg, _common_in_pdb("C##ACME_MONITOR"), account("ACME_APP_USER"))
    assert "C##ACME_MONITOR" not in found
    assert found["ACME_APP_USER"].state == REPORT_PROBLEM


def test_the_privilege_report_keeps_a_common_account_in_a_pdb() -> None:
    """Its grants made in the PDB are read there, so it stays undeclared."""
    surveyed = _common_in_pdb("C##ACME_MONITOR")
    kept = {
        row.account: row for row in evaluate(TARGET, config(), [surveyed], keep_kept_in_root=True)
    }
    assert kept["C##ACME_MONITOR"].state == UNDECLARED


def test_a_rule_that_names_a_common_account_brings_it_back_in_a_pdb() -> None:
    by_name = config(**rule(accounts=["C##ACME_MONITOR"], profile="DEFAULT"))
    row = rows(by_name, _common_in_pdb("C##ACME_MONITOR"))["C##ACME_MONITOR"]
    assert row.state == NOT_CHECKED
    assert row.kind == "technical"
    by_pattern = config(**rule(accounts=["C##*"], profile="DEFAULT"))
    assert "C##ACME_MONITOR" in rows(by_pattern, _common_in_pdb("C##ACME_MONITOR"))


def test_a_personal_profile_predicate_does_not_bring_a_common_account_back() -> None:
    """As for Oracle's own accounts: a predicate over a profile names nobody."""
    cfg = config(personal_accounts=[{"profile": "DEFAULT"}])
    found = rows(cfg, _common_in_pdb("C##ACME_MONITOR"), account("ACME_DEV_ALICE"))
    assert "C##ACME_MONITOR" not in found
    assert found["ACME_DEV_ALICE"].kind == "personal"


def test_a_common_account_in_the_root_is_undeclared_where_nothing_names_it() -> None:
    """The CDB target keeps it, so an undeclared common account still shows."""
    row = rows(config(), account("C##ACME_MONITOR", common=True))["C##ACME_MONITOR"]
    assert row.state == UNDECLARED


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
            "accounts": [{"accounts": ["X"], "oracle": {"profile": "TECH"}}],
            "oracle": {
                "profiles": [{"name": "tech", "settings": {"password_lifetime": "unlimited"}}]
            },
        }
    )
    row = rows(cfg, account("X", profile="TECH", password_lifetime=180))["X"]
    assert row.state == REPORT_PROBLEM


def test_two_patterns_that_disagree_are_not_checked() -> None:
    cfg = config(
        reports={
            "accounts": [
                {"accounts": ["ORDS_*"], "oracle": {"profile": "P"}},
                {"accounts": ["ORDS_PUBLIC*"], "oracle": {"profile": "Q"}},
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
                {"accounts": ["A_OK"], "oracle": {"profile": "DEFAULT"}},
                {"accounts": ["B_LOCKED"], "oracle": {"profile": "DEFAULT"}},
                {"accounts": ["C_EXPIRES"], "settings": {"password_lifetime": "unlimited"}},
                {"accounts": ["D_GONE"], "oracle": {"profile": "DEFAULT"}},
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
                {"accounts": ["ACME_*"], "oracle": {"profile": "P"}},
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
        reports={"accounts": [{"accounts": ["ACME_*"], "oracle": {"profile": "P"}}]},
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
            "oracle": {"profiles": [{"name": "APP_PROF", "settings": {"password_lifetime": 90}}]},
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
                {
                    "accounts": ["ORDS_*"],
                    "oracle": {"profile": "P"},
                    "settings": {"password_lifetime": 90},
                },
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


# ------------------------------------------- a profile missing on a target ---
# #1390: one target-level problem for each profile the file expects there that
# the target does not have.

APPLICATION = {
    "policies": {"app": {"account": {"profile": "ACME_APP_PROF"}}},
    "applications": [
        {
            "name": "acme",
            "accounts": ["acme_app_user"],
            "policy": "app",
            "secret": "acme/app#password",
        }
    ],
    "vaults": {"vault-dev": {"type": "hashicorp", "addr": "http://127.0.0.1:8200"}},
    "defaults": {"vault": "vault-dev"},
}


def test_a_rules_profile_missing_on_the_target_is_one_problem() -> None:
    cfg = config(**rule(accounts=["DBSNMP", "ORDS_*"], profile="tech_noexp"))
    missing = missing_profiles(TARGET, cfg, {"DEFAULT", "APP_USERS"})
    assert [(m.target, m.profile, m.expected_by) for m in missing] == [
        (TARGET, "tech_noexp", ("reports.accounts",))
    ]


def test_a_profile_the_target_has_is_not_missing_compared_by_upper_case() -> None:
    cfg = config(**rule(accounts=["X"], profile="tech_noexp"))
    assert missing_profiles(TARGET, cfg, {"TECH_NOEXP"}) == ()


def test_an_application_policys_profile_missing_is_a_problem() -> None:
    cfg = config(**APPLICATION)
    missing = missing_profiles(TARGET, cfg, {"DEFAULT"})
    assert [(m.profile, m.expected_by) for m in missing] == [("ACME_APP_PROF", ("policies.app",))]


def test_one_finding_names_every_source_that_expects_the_profile() -> None:
    cfg = config(
        **APPLICATION,
        reports={
            "accounts": [
                {"accounts": ["X"], "oracle": {"profile": "ACME_APP_PROF"}},
                {"accounts": ["Y"], "oracle": {"profile": "acme_app_prof"}},
            ]
        },
    )
    missing = missing_profiles(TARGET, cfg, {"DEFAULT"})
    assert len(missing) == 1
    assert missing[0].expected_by == ("reports.accounts", "policies.app")


def test_a_rules_profile_never_names_an_application_account() -> None:
    """From the review of #1402. The config refuses a rule's `oracle.profile` on an
    application account named by name, so every rule profile that
    `missing_profiles` counts is one some non-application account may need."""
    with pytest.raises(ConfigError, match="its profile comes from its policy"):
        config(**APPLICATION, **rule(accounts=["ACME_APP_USER"], profile="OTHER_PROF"))


def test_a_rule_that_covers_the_target_expects_its_profile_with_no_account_matching() -> None:
    """The maintainer's decision for #1390, kept after the second review of
    #1402: the rule says what the target must have, whether or not an account
    there matches it. `targets:` is how a rule expects a profile only on some."""
    cfg = config(**APPLICATION, **rule(accounts=["ACME_*_USER"], profile="TECH"))
    missing = missing_profiles(TARGET, cfg, {"DEFAULT", "ACME_APP_PROF"})
    assert [(m.profile, m.expected_by) for m in missing] == [("TECH", ("reports.accounts",))]


def test_a_binding_without_a_policy_expects_no_profile() -> None:
    unbound = {
        "name": "acme",
        "accounts": ["acme_app_user"],
        "secret": "acme/app#password",
    }
    cfg = config(**{**APPLICATION, "applications": [unbound]})
    assert missing_profiles(TARGET, cfg, {"DEFAULT"}) == ()


def test_an_oracle_profiles_entry_alone_never_requires_the_profile() -> None:
    """The maintainer's narrowing of #1390: `reports.oracle.profiles` sets the
    limits where the profile is; it does not say the profile must be on every
    target."""
    cfg = config(
        reports={
            "oracle": {
                "profiles": [{"name": "TECH", "settings": {"password_lifetime": "unlimited"}}]
            }
        }
    )
    assert missing_profiles(TARGET, cfg, {"DEFAULT"}) == ()


def test_a_rule_for_other_targets_expects_nothing_here() -> None:
    cfg = config(**rule(accounts=["X"], targets={"match": {"env": "prod"}}, profile="P"))
    assert missing_profiles(TARGET, cfg, {"DEFAULT"}) == ()
    assert [m.profile for m in missing_profiles("other-pdb", cfg, {"DEFAULT"})] == ["P"]


def test_a_personal_predicate_over_a_profile_expects_nothing() -> None:
    """A personal rule's `profile:` selects accounts; it says nothing must exist."""
    cfg = config(personal_accounts=[{"profile": "DBA_PROF"}])
    assert missing_profiles(TARGET, cfg, {"DEFAULT"}) == ()


def test_a_missing_profile_makes_the_run_exit_3() -> None:
    cfg = config(**rule(accounts=["X"], profile="P"))
    missing = missing_profiles(TARGET, cfg, {"DEFAULT"})
    assert exit_code([], unreachable=0, missing=missing) == 3
    assert exit_code([], unreachable=1, missing=missing) == 1
    assert exit_code([], unreachable=0, missing=()) == 0
