"""`reports:` -- the rules UC-5's `report accounts` checks.

Tier 0, pure: everything builds from a dict, so there is no filesystem and no
I/O. Fixtures use the fictional vocabulary (`acme`, `acme_*_user`).

One accept and one reject per rule, and the rejects assert on the message.
"""

from __future__ import annotations

from typing import Any

import pytest

from sopuli.config.errors import ConfigError
from sopuli.config.loading import build_config
from sopuli.config.model import Reports, Settings, TargetSelector
from sopuli.config.reports import build_reports


def document(**section: Any) -> dict[str, Any]:
    return {"version": 1, "reports": section}


def on(profile: str) -> dict[str, Any]:
    """A rule's `oracle:` block that names a profile."""
    return {"profile": profile}


def test_an_absent_section_is_empty() -> None:
    assert build_reports({"version": 1}) == Reports()


def test_a_rule_with_names_patterns_and_settings() -> None:
    built = build_reports(
        document(
            accounts=[
                {
                    "accounts": ["DBSNMP", "ORDS_*"],
                    "oracle": on("TECH_NOEXPIRE"),
                    "settings": {"password_lifetime": "unlimited"},
                }
            ]
        )
    )
    rule = built.accounts[0]
    assert rule.accounts == ("DBSNMP", "ORDS_*")
    assert rule.profile == "TECH_NOEXPIRE"
    assert rule.settings == Settings(password_lifetime="unlimited")
    assert rule.targets == TargetSelector()


def test_a_rule_may_select_targets() -> None:
    built = build_reports(
        document(
            accounts=[{"accounts": ["DBSNMP"], "targets": {"group": "prod"}, "oracle": on("P")}]
        )
    )
    assert built.accounts[0].targets.group == "prod"


def test_a_db_profile() -> None:
    built = build_reports(
        document(
            oracle={"profiles": [{"name": "TECH_NOEXPIRE", "settings": {"failed_login_limit": 10}}]}
        )
    )
    assert built.oracle_profiles[0].name == "TECH_NOEXPIRE"
    assert built.oracle_profiles[0].settings == Settings(failed_login_limit=10)


def test_an_empty_section_is_refused() -> None:
    with pytest.raises(ConfigError) as caught:
        build_reports({"version": 1, "reports": {}})
    assert "must declare `accounts:` or `oracle:`" in str(caught.value)


def test_an_empty_list_is_refused() -> None:
    with pytest.raises(ConfigError) as caught:
        build_reports(document(accounts=[]))
    assert "at least one" in str(caught.value)


def test_an_unknown_key_is_refused() -> None:
    with pytest.raises(ConfigError) as caught:
        build_reports(
            document(accounts=[{"accounts": ["X"], "kind": "technical", "oracle": on("P")}])
        )
    assert "kind" in str(caught.value)


def test_an_unknown_setting_is_refused() -> None:
    with pytest.raises(ConfigError) as caught:
        build_reports(document(accounts=[{"accounts": ["X"], "settings": {"lifetime": 90}}]))
    assert "lifetime" in str(caught.value)


@pytest.mark.parametrize("value", [0, -1, "never", 1.5, True, None])
def test_a_setting_is_unlimited_or_a_positive_whole_number(value: Any) -> None:
    with pytest.raises(ConfigError) as caught:
        build_reports(
            document(accounts=[{"accounts": ["X"], "settings": {"password_lifetime": value}}])
        )
    assert "`password_lifetime` must be `unlimited` or a whole number above 0" in str(caught.value)


@pytest.mark.parametrize("value", ["unlimited", 1, 180])
def test_the_values_a_setting_accepts(value: Any) -> None:
    built = build_reports(
        document(accounts=[{"accounts": ["X"], "settings": {"failed_login_limit": value}}])
    )
    assert built.accounts[0].settings.failed_login_limit == value


def test_the_only_wildcard_is_a_star() -> None:
    with pytest.raises(ConfigError) as caught:
        build_reports(document(accounts=[{"accounts": ["ORDS_?"], "oracle": on("P")}]))
    assert "ORDS_?" in str(caught.value)


def test_a_rule_needs_a_profile_or_settings() -> None:
    with pytest.raises(ConfigError) as caught:
        build_reports(document(accounts=[{"accounts": ["X"]}]))
    assert "must declare `login:`, `settings:` or `oracle.profile`" in str(caught.value)


@pytest.mark.parametrize("login", ["refused", "allowed"])
def test_a_rule_may_state_only_login(login: str) -> None:
    """An owner account locked on purpose needs nothing but `login: refused` (#1447)."""
    built = build_reports(document(accounts=[{"accounts": ["ACME_OWNER"], "login": login}]))
    assert built.accounts[0].login == login


def test_a_rule_without_login_says_none() -> None:
    built = build_reports(document(accounts=[{"accounts": ["X"], "oracle": on("P")}]))
    assert built.accounts[0].login is None


@pytest.mark.parametrize("value", ["locked", "no", True, None])
def test_login_is_refused_or_allowed(value: Any) -> None:
    with pytest.raises(ConfigError) as caught:
        build_reports(document(accounts=[{"accounts": ["X"], "login": value}]))
    assert "reports.accounts[0].login" in str(caught.value)


def test_a_rule_needs_accounts() -> None:
    with pytest.raises(ConfigError) as caught:
        build_reports(document(accounts=[{"oracle": on("P")}]))
    assert "must declare `accounts:`" in str(caught.value)


def test_a_db_profile_needs_settings() -> None:
    with pytest.raises(ConfigError) as caught:
        build_reports(document(oracle={"profiles": [{"name": "P"}]}))
    assert "must declare `settings:`" in str(caught.value)


def test_empty_settings_are_refused_even_beside_a_profile() -> None:
    """The published schema refuses `settings: {}` too; builder and schema agree."""
    with pytest.raises(ConfigError) as caught:
        build_reports(document(accounts=[{"accounts": ["X"], "oracle": on("P"), "settings": {}}]))
    assert "must declare at least one setting" in str(caught.value)


def test_an_empty_oracle_block_on_a_rule_is_refused() -> None:
    """Present and empty means somebody meant to write a profile; the schema agrees."""
    with pytest.raises(ConfigError) as caught:
        build_reports(
            document(
                accounts=[{"accounts": ["X"], "oracle": {}, "settings": {"password_lifetime": 90}}]
            )
        )
    assert "reports.accounts[0].oracle" in str(caught.value)
    assert "must declare `profile:`" in str(caught.value)


def test_an_empty_oracle_block_on_the_section_is_refused() -> None:
    with pytest.raises(ConfigError) as caught:
        build_reports(document(oracle={}))
    assert "must declare `profiles:`" in str(caught.value)


def test_an_unknown_key_in_a_rule_oracle_block_is_refused() -> None:
    with pytest.raises(ConfigError) as caught:
        build_reports(document(accounts=[{"accounts": ["X"], "oracle": {"profiel": "P"}}]))
    assert "profiel" in str(caught.value)


def test_a_rule_profile_in_the_old_place_names_the_new_one() -> None:
    """Config schema 5.0 moved a rule's `profile:` into `oracle:` (#1447).

    A file written for 4.x is told where the key went, not that it has a typo,
    and the old place is not read as well. The hint shows the nested form,
    because a dotted path such as `oracle.profile` reads like one YAML key with
    a dot in its name (review of #1449).
    """
    with pytest.raises(ConfigError) as caught:
        build_reports(document(accounts=[{"accounts": ["X"], "profile": "P"}]))
    message = str(caught.value)
    assert "reports.accounts[0].profile" in message
    assert "`profile:` moved to the rule's `oracle:` block in config schema 5.0" in message
    assert caught.value.hint == "write `oracle: { profile: <name> }` on the rule"


def test_db_profiles_in_the_old_place_names_the_new_one() -> None:
    with pytest.raises(ConfigError) as caught:
        build_reports(document(db_profiles=[{"name": "P", "settings": {"password_lifetime": 90}}]))
    message = str(caught.value)
    assert "reports.db_profiles" in message
    assert "`db_profiles:` moved to `reports.oracle.profiles` in config schema 5.0" in message
    assert caught.value.hint == "write `oracle: { profiles: [...] }` under `reports:`"


def test_an_account_is_named_by_one_rule() -> None:
    with pytest.raises(ConfigError) as caught:
        build_reports(
            document(
                accounts=[
                    {"accounts": ["dbsnmp"], "oracle": on("P")},
                    {"accounts": ["DBSNMP"], "oracle": on("Q")},
                ]
            )
        )
    assert "'DBSNMP' is named by two rules" in str(caught.value)


def test_a_name_twice_in_one_rule_says_so() -> None:
    with pytest.raises(ConfigError) as caught:
        build_reports(document(accounts=[{"accounts": ["dbsnmp", "DBSNMP"], "oracle": on("P")}]))
    assert "'DBSNMP' is named twice in one rule" in str(caught.value)


def test_two_patterns_may_overlap() -> None:
    """Which accounts two patterns share is a fact about a database, not the file."""
    built = build_reports(
        document(
            accounts=[
                {"accounts": ["ORDS_*"], "oracle": on("P")},
                {"accounts": ["ORDS_PUBLIC*"], "oracle": on("Q")},
            ]
        )
    )
    assert len(built.accounts) == 2


def test_a_misspelt_group_in_a_rule_is_refused() -> None:
    with pytest.raises(ConfigError) as caught:
        build_config(
            {
                "version": 1,
                "groups": {"prod": {"match": {"env": "prod"}}},
                "targets": [
                    {
                        "name": "free-pdb",
                        "type": "oracle",
                        "dsn": "localhost:1521/FREEPDB1",
                        "labels": {"env": "prod"},
                    }
                ],
                "reports": {
                    "accounts": [
                        {"accounts": ["X"], "targets": {"group": "prdo"}, "oracle": on("P")}
                    ]
                },
            }
        )
    assert "prdo" in str(caught.value)


def test_an_unknown_target_in_a_rule_is_refused() -> None:
    with pytest.raises(ConfigError) as caught:
        build_config(
            {
                "version": 1,
                "targets": [
                    {"name": "free-pdb", "type": "oracle", "dsn": "localhost:1521/FREEPDB1"}
                ],
                "reports": {
                    "accounts": [{"accounts": ["X"], "targets": ["nosuch"], "oracle": on("P")}]
                },
            }
        )
    assert "nosuch" in str(caught.value)


def test_a_db_profile_name_appears_once() -> None:
    with pytest.raises(ConfigError) as caught:
        build_reports(
            document(
                oracle={
                    "profiles": [
                        {"name": "tech", "settings": {"password_lifetime": "unlimited"}},
                        {"name": "TECH", "settings": {"password_lifetime": 90}},
                    ]
                }
            )
        )
    assert "duplicate" in str(caught.value)
    assert "reports.oracle.profiles[1].name" in str(caught.value)


def test_a_rule_may_not_set_the_profile_of_an_application_account() -> None:
    """An application account's expected profile is its policy's, never a second source."""
    with pytest.raises(ConfigError) as caught:
        build_config(
            {
                "version": 1,
                "applications": [{"name": "acme", "accounts": ["ACME_APP_USER"]}],
                "reports": {"accounts": [{"accounts": ["acme_app_user"], "oracle": on("OTHER")}]},
            }
        )
    message = str(caught.value)
    assert "acme_app_user" in message
    assert "policy" in message
    assert "drop `oracle.profile` here" in message


def test_a_rule_may_give_settings_to_an_application_account() -> None:
    config = build_config(
        {
            "version": 1,
            "applications": [{"name": "acme", "accounts": ["ACME_APP_USER"]}],
            "reports": {
                "accounts": [{"accounts": ["acme_app_user"], "settings": {"password_lifetime": 90}}]
            },
        }
    )
    assert config.reports.accounts[0].settings.password_lifetime == 90


def test_a_rule_may_not_refuse_login_to_an_application_account() -> None:
    """An application logs in as its account, so `login: refused` could only
    report a problem (review of #1451)."""
    with pytest.raises(ConfigError) as caught:
        build_config(
            {
                "version": 1,
                "applications": [{"name": "acme", "accounts": ["ACME_APP_USER"]}],
                "reports": {"accounts": [{"accounts": ["acme_app_user"], "login": "refused"}]},
            }
        )
    message = str(caught.value)
    assert "reports.accounts[0].accounts[0]" in message
    assert "which logs in as it" in message
    assert "drop `login: refused`" in message


def test_a_rule_may_allow_login_to_an_application_account() -> None:
    config = build_config(
        {
            "version": 1,
            "applications": [{"name": "acme", "accounts": ["ACME_APP_USER"]}],
            "reports": {"accounts": [{"accounts": ["acme_app_user"], "login": "allowed"}]},
        }
    )
    assert config.reports.accounts[0].login == "allowed"


def test_a_pattern_with_login_refused_may_reach_an_application_account() -> None:
    """A pattern is matched against a database, so the config cannot refuse it."""
    config = build_config(
        {
            "version": 1,
            "applications": [{"name": "acme", "accounts": ["ACME_APP_USER"]}],
            "reports": {"accounts": [{"accounts": ["ACME_*"], "login": "refused"}]},
        }
    )
    assert config.reports.accounts[0].login == "refused"
