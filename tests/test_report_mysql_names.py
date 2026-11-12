"""How `report accounts` names a MySQL account (#1461). Tier 0, pure.

A rule names a MySQL account `user@host`, as UC-1 does: the user compared
exactly and the host without ASCII case, with `*` in the user part only. A
name without a host is a name for the rule's other targets, and reaches no
account on a MySQL target (decided on #1461). Fictional names only.
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
    REPORT_OK,
    TECHNICAL,
    UNDECLARED,
    AccountRow,
    evaluate,
)

MYSQL = "mysql-dev"
ORACLE = "free-pdb"
PG = "pg-dev"


def config(*rules: dict[str, Any], applications: list[dict[str, Any]] | None = None) -> Config:
    document: dict[str, Any] = {
        "version": 1,
        "targets": [
            {"name": ORACLE, "type": "oracle", "dsn": "localhost:1521/FREEPDB1"},
            {"name": MYSQL, "type": "mysql", "dsn": "mysql-dev.example.com:3306"},
            {"name": PG, "type": "postgresql", "dsn": "pg-dev.example.com:5432"},
        ],
    }
    if rules:
        document["reports"] = {"accounts": list(rules)}
    if applications:
        document["applications"] = applications
    return build_config(document)


def account(name: str, **fields: Any) -> SurveyedAccount:
    values: dict[str, Any] = {
        "name": name,
        "status": "OPEN",
        "locked": False,
        "profile": "",
        "common": False,
        "vendor_maintained": False,
        "password_lifetime": 90,
        "failed_login_limit": None,
        "failed_logins": None,
        "unreadable": ("no limit", "no count"),
    }
    values.update(fields)
    return SurveyedAccount(**values)


def rows(cfg: Config, *names: str) -> dict[str, AccountRow]:
    return {row.account: row for row in evaluate(MYSQL, cfg, [account(n) for n in names])}


LIFETIME = {"settings": {"password_lifetime": 90}}


def test_a_name_is_user_at_host() -> None:
    cfg = config({"accounts": ["acme_app@%"], **LIFETIME})
    found = rows(cfg, "acme_app@%", "acme_app@10.%")

    assert (found["acme_app@%"].kind, found["acme_app@%"].state) == (TECHNICAL, REPORT_OK)
    # The same user at another host is another account, which no rule names.
    assert found["acme_app@10.%"].state == UNDECLARED


def test_the_user_compares_by_case() -> None:
    """`JDOE@%` is not `jdoe@%`, so it does not stand in for a missing one."""
    cfg = config({"accounts": ["jdoe@%"], **LIFETIME})
    found = rows(cfg, "JDOE@%")

    assert found["JDOE@%"].state == UNDECLARED
    assert found["jdoe@%"].state == ACCOUNT_MISSING


def test_the_host_compares_without_case() -> None:
    cfg = config({"accounts": ["acme_app@App.Example.COM"], **LIFETIME})
    found = rows(cfg, "acme_app@app.example.com")

    assert found["acme_app@app.example.com"].state == REPORT_OK
    assert len(found) == 1


def test_a_missing_account_is_spelled_as_the_rule_writes_it() -> None:
    cfg = config({"accounts": ["acme_App@%"], **LIFETIME})
    (only,) = evaluate(MYSQL, cfg, [])
    assert (only.account, only.state) == ("acme_App@%", ACCOUNT_MISSING)


@pytest.mark.parametrize(("target", "shown"), [(PG, "acme_Gone"), (ORACLE, "ACME_GONE")])
def test_a_missing_account_keeps_the_files_spelling_except_on_oracle(
    target: str, shown: str
) -> None:
    """#1465, option B: Oracle keeps an unquoted name in upper case."""
    cfg = config({"accounts": ["acme_Gone"], **LIFETIME, "targets": [target]})
    (only,) = evaluate(target, cfg, [])
    assert (only.account, only.state) == (shown, ACCOUNT_MISSING)


def test_a_pattern_matches_the_user_by_case_and_the_host_as_a_name() -> None:
    cfg = config({"accounts": ["acme_*@10.%"], **LIFETIME})
    found = rows(cfg, "acme_app@10.%", "acme_api@10.%", "ACME_APP@10.%", "acme_app@%")

    assert found["acme_app@10.%"].state == REPORT_OK
    assert found["acme_api@10.%"].state == REPORT_OK
    assert found["ACME_APP@10.%"].state == UNDECLARED
    assert found["acme_app@%"].state == UNDECLARED


def test_a_name_without_a_host_reaches_no_mysql_account() -> None:
    """Decided on #1461: a rule written for Oracle covers every target."""
    cfg = config({"accounts": ["acme_app", "ACME_*"], **LIFETIME})
    found = rows(cfg, "acme_app@%")

    # Nothing matched, and nothing reported missing on the MySQL target.
    assert list(found) == ["acme_app@%"]
    assert found["acme_app@%"].state == UNDECLARED
    # On Oracle the same rule still names its accounts.
    (oracle,) = evaluate(ORACLE, cfg, [])
    assert (oracle.account, oracle.state) == ("ACME_APP", ACCOUNT_MISSING)


def test_an_application_account_compares_as_uc1_does() -> None:
    apps = [{"name": "acme", "targets": [MYSQL], "accounts": ["acme_app@%"]}]
    cfg = config(applications=apps)
    found = rows(cfg, "ACME_APP@%")

    assert found["ACME_APP@%"].state == UNDECLARED
    assert found["acme_app@%"].state == ACCOUNT_MISSING


def test_oracle_names_still_compare_by_upper() -> None:
    cfg = config({"accounts": ["acme_app"], **LIFETIME})
    (row,) = evaluate(ORACLE, cfg, [account("ACME_APP")])
    assert row.state == REPORT_OK


@pytest.mark.parametrize("name", ["acme_app@*", "acme_*@10.*"])
def test_a_wildcard_in_the_host_is_refused(name: str) -> None:
    with pytest.raises(ConfigError, match="with `\\*` in the host") as caught:
        config({"accounts": [name], **LIFETIME})
    assert "reports.accounts[0].accounts[0]" in str(caught.value)


def test_a_quoted_name_is_refused() -> None:
    with pytest.raises(ConfigError, match="starts or ends with a quote"):
        config({"accounts": ["'acme_app'@'%'"], **LIFETIME})


def test_a_rule_that_reaches_no_mysql_target_is_not_checked_for_hosts() -> None:
    config({"accounts": ["acme@*"], "targets": [ORACLE], **LIFETIME})
