"""`report accounts` on PostgreSQL (#1459).

Tier 0, pure. The survey's mapping of a ``pg_roles`` row, ``NOLOGIN`` judged
only against a rule's ``login:``, and ``VALID UNTIL`` against a rule's
``postgresql.valid_until``. Fictional names only.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from sopuli.config.errors import ConfigError
from sopuli.config.loading import build_config
from sopuli.config.model import Config
from sopuli.driver.postgres.survey import (
    NO_COUNT,
    SURVEY_QUERY,
    survey,
    surveyed_of,
)
from sopuli.driver.registry import DRIVERS
from sopuli.driver.survey import SurveyedAccount, ValidUntil
from sopuli.output.document import SCHEMA_VERSION
from sopuli.report_accounts import (
    CHECKS,
    NO_RULE,
    NOT_APPLICABLE_OUTCOME,
    NOT_CHECKED,
    REPORT_OK,
    REPORT_PROBLEM,
    UNDECLARED,
    AccountRow,
    evaluate,
)

SCHEMA = (
    Path(__file__).resolve().parents[1]
    / "docs"
    / "schemas"
    / f"sopuli-run-{SCHEMA_VERSION}.schema.json"
)

PG = "pg-dev"
ORACLE = "free-pdb"
FUTURE = "2099-01-01T00:00:00Z"
PAST = "2001-01-01T00:00:00Z"


def config(*rules: dict[str, Any]) -> Config:
    document: dict[str, Any] = {
        "version": 1,
        "targets": [
            {"name": ORACLE, "type": "oracle", "dsn": "localhost:1521/FREEPDB1"},
            {"name": PG, "type": "postgresql", "dsn": "pg-dev.example.com:5432"},
        ],
    }
    if rules:
        document["reports"] = {"accounts": list(rules)}
    return build_config(document)


def role(
    name: str,
    *,
    can_login: bool = True,
    built_in: bool = False,
    until: str | None = None,
    infinite: str | None = None,
    expired: bool = False,
) -> SurveyedAccount:
    """A surveyed role, made from the row the query returns."""
    return surveyed_of((name, can_login, built_in, until or infinite, expired))


def row(cfg: Config, surveyed: SurveyedAccount, target: str = PG) -> AccountRow:
    (only,) = evaluate(target, cfg, (surveyed,))
    return only


def outcome(found: AccountRow, check: str) -> tuple[str, str]:
    finding = next(f for f in found.findings if f.check == check)
    return finding.outcome, finding.detail


def checks(found: AccountRow) -> set[str]:
    return {f.check for f in found.findings}


# ------------------------------------------------------------- the survey ---


class FakeCursor:
    def __init__(self, rows: list[tuple[Any, ...]]) -> None:
        self.rows = rows
        self.executed: list[tuple[str, Any]] = []

    def execute(self, statement: str, parameters: Any = None) -> None:
        self.executed.append((statement, parameters))

    def fetchall(self) -> list[tuple[Any, ...]]:
        return self.rows

    def fetchone(self) -> tuple[Any, ...] | None:
        return self.rows[0] if self.rows else None


def test_the_survey_is_one_read_with_nothing_bound() -> None:
    cursor = FakeCursor([("acme_web_user", True, False, None, False)])
    (surveyed,) = survey(cursor)
    assert cursor.executed == [(SURVEY_QUERY, None)]
    assert surveyed.name == "acme_web_user"


def test_the_survey_reads_no_password_column() -> None:
    assert "rolpassword" not in SURVEY_QUERY
    assert "pg_authid" not in SURVEY_QUERY


def test_a_login_role_is_open_and_not_locked() -> None:
    surveyed = role("acme_web_user")
    assert (surveyed.status, surveyed.locked) == ("OPEN", False)
    assert surveyed.lock_is_login_attribute
    assert surveyed.valid_until == ValidUntil(text=None, expired=False)


def test_nologin_is_the_login_attribute_set_on_purpose() -> None:
    surveyed = role("acme_readers", can_login=False)
    assert (surveyed.status, surveyed.locked, surveyed.deliberately_locked) == (
        "NOLOGIN",
        True,
        True,
    )


def test_a_built_in_role_is_vendor_maintained() -> None:
    assert role("pg_monitor", can_login=False, built_in=True).vendor_maintained


def test_what_postgresql_lacks_is_none_with_a_reason() -> None:
    surveyed = role("acme_web_user")
    assert surveyed.password_lifetime is None
    assert surveyed.failed_login_limit is None
    assert surveyed.failed_logins is None
    assert surveyed.unreadable[-1] == NO_COUNT
    assert surveyed.profile == ""


def test_a_past_valid_until_is_expired() -> None:
    surveyed = role("acme_web_user", until=PAST, expired=True)
    assert surveyed.status == "EXPIRED"
    assert surveyed.valid_until is not None
    assert surveyed.valid_until.expired
    assert surveyed.valid_until.text == "2001-01-01T00:00:00Z"


def test_nologin_wins_over_expired_in_the_status() -> None:
    assert role("acme_readers", can_login=False, until=PAST, expired=True).status == "NOLOGIN"


@pytest.mark.parametrize(
    ("text", "never"),
    [(None, True), ("infinity", True), ("-infinity", False), ("2099-01-01", False)],
)
def test_infinity_counts_as_no_date(text: str | None, never: bool) -> None:
    assert ValidUntil(text=text, expired=False).never is never


# --------------------------------------------------------------- the lock ---


def test_registry_lists_the_report_for_postgresql() -> None:
    commands = DRIVERS["postgresql"].commands
    assert commands is not None
    assert "report.accounts" in commands


def test_nologin_without_a_login_rule_is_not_a_problem() -> None:
    """A group role is written NOLOGIN: never reported as locked."""
    cfg = config({"accounts": ["acme_*"], "postgresql": {"valid_until": "forbidden"}})
    found = row(cfg, role("acme_readers", can_login=False))
    assert outcome(found, "lock") == ("ok", "NOLOGIN, which only a rule's login: judges")
    assert found.state == REPORT_OK


def test_nologin_with_login_refused_passes() -> None:
    cfg = config({"accounts": ["acme_owner"], "login": "refused"})
    found = row(cfg, role("acme_owner", can_login=False))
    assert outcome(found, "lock") == ("ok", "cannot log in: NOLOGIN")
    assert found.state == REPORT_OK


def test_login_with_login_refused_is_a_problem() -> None:
    cfg = config({"accounts": ["acme_owner"], "login": "refused"})
    found = row(cfg, role("acme_owner"))
    assert outcome(found, "lock") == ("problem", "can log in: OPEN, rule says login refused")
    assert found.state == REPORT_PROBLEM


def test_nologin_with_login_allowed_is_a_problem() -> None:
    cfg = config({"accounts": ["acme_etl_user"], "login": "allowed"})
    found = row(cfg, role("acme_etl_user", can_login=False))
    assert outcome(found, "lock") == (
        "problem",
        "cannot log in: NOLOGIN, rule says login allowed",
    )


def test_an_expired_date_does_not_meet_login_refused() -> None:
    """#1468: VALID UNTIL limits password logins only, so pg_hba.conf's trust,
    peer and cert lines still let the role in. The message points to NOLOGIN,
    and the expiry stays a problem."""
    cfg = config({"accounts": ["acme_owner"], "login": "refused"})
    found = row(cfg, role("acme_owner", until=PAST, expired=True))

    assert outcome(found, "lock") == (
        "problem",
        "can log in: EXPIRED, rule says login refused; VALID UNTIL stops password "
        "logins only, and NOLOGIN refuses every login",
    )
    assert outcome(found, "valid_until")[0] == "problem"
    assert found.state == REPORT_PROBLEM


def test_an_expired_date_on_a_nologin_role_is_not_a_problem() -> None:
    """#1468: the role cannot log in, and the date only makes it safer."""
    cfg = config({"accounts": ["acme_owner"], "login": "refused"})
    found = row(cfg, role("acme_owner", can_login=False, until=PAST, expired=True))

    assert "valid_until" not in checks(found)
    assert found.state == REPORT_OK


def test_a_rule_still_judges_the_date_on_a_nologin_role() -> None:
    """`forbidden` wants no date, so a past one is still a problem there."""
    cfg = config({"accounts": ["acme_owner"], "postgresql": {"valid_until": "forbidden"}})
    found = row(cfg, role("acme_owner", can_login=False, until=PAST, expired=True))

    assert outcome(found, "valid_until") == (
        "problem",
        "VALID UNTIL 2001-01-01T00:00:00Z, rule says forbidden",
    )


def test_survey_reads_the_date_as_utc_text() -> None:
    """No `datetime` is built, so a date past the year 9999 cannot fail the read."""
    assert "to_char(r.rolvaliduntil at time zone 'UTC'" in SURVEY_QUERY
    assert role("acme_web_user", until="10000-01-01T00:00:00Z").valid_until == ValidUntil(
        text="10000-01-01T00:00:00Z", expired=False
    )


def application_config(*rules: dict[str, Any]) -> Config:
    """`acme_web_user` declared by an application on the PostgreSQL target."""
    document: dict[str, Any] = {
        "version": 1,
        "vaults": {
            "v": {
                "type": "hashicorp",
                "addr": "https://vault.example.com:8200",
                "mount": "kv",
                "kv_version": 2,
                "auth": {"method": "token"},
            }
        },
        "defaults": {"vault": "v"},
        "targets": [{"name": PG, "type": "postgresql", "dsn": "pg-dev.example.com:5432"}],
        "applications": [
            {
                "name": "acme",
                "accounts": ["acme_web_user"],
                "secret_template": "v:acme/{target}#DB_CREDENTIALS/{account}",
            }
        ],
    }
    if rules:
        document["reports"] = {"accounts": list(rules)}
    return build_config(document)


def test_an_application_role_that_cannot_log_in_is_a_problem() -> None:
    """The application logs in as it, with or without a rule (#1464 review)."""
    refused = {"accounts": ["acme_*"], "login": "refused"}
    for cfg in (application_config(), application_config(refused)):
        found = row(cfg, role("acme_web_user", can_login=False))
        assert outcome(found, "lock") == (
            "problem",
            "cannot log in: NOLOGIN, an application logs in as it",
        )
        assert found.state == REPORT_PROBLEM


def test_an_undeclared_role_is_information() -> None:
    found = row(config(), role("acme_leftover", can_login=False))
    assert found.state == UNDECLARED


def test_a_built_in_role_is_left_out_unless_named() -> None:
    assert evaluate(PG, config(), (role("pg_monitor", can_login=False, built_in=True),)) == ()


def test_a_role_no_rule_names_has_no_rule() -> None:
    """Declared by an application, with nothing stated: no rule, not OK."""
    cfg = build_config(
        {
            "version": 1,
            "vaults": {
                "v": {
                    "type": "hashicorp",
                    "addr": "https://vault.example.com:8200",
                    "mount": "kv",
                    "kv_version": 2,
                    "auth": {"method": "token"},
                }
            },
            "defaults": {"vault": "v"},
            "targets": [{"name": PG, "type": "postgresql", "dsn": "pg-dev.example.com:5432"}],
            "applications": [
                {
                    "name": "acme",
                    "accounts": ["acme_web_user"],
                    "secret_template": "v:acme/{target}#DB_CREDENTIALS/{account}",
                }
            ],
        }
    )
    found = row(cfg, role("acme_web_user"))
    assert found.state == NO_RULE
    assert found.failed_logins_reason == NO_COUNT


# ------------------------------------------------------------ valid until ---


def test_a_past_date_is_a_problem_without_the_key() -> None:
    cfg = config({"accounts": ["acme_web_user"], "login": "allowed"})
    found = row(cfg, role("acme_web_user", until=PAST, expired=True))
    assert outcome(found, "valid_until") == (
        "problem",
        "password expired: VALID UNTIL 2001-01-01T00:00:00Z",
    )
    assert found.state == REPORT_PROBLEM


def test_an_undeclared_roles_past_date_is_information() -> None:
    """Only a role the file declares is checked; an undeclared one never sets exit 3."""
    cfg = config({"accounts": ["acme_other_*"], "login": "allowed"})
    assert row(cfg, role("acme_web_user", until=PAST, expired=True)).state == UNDECLARED


def test_a_future_date_without_the_key_is_not_a_check() -> None:
    cfg = config({"accounts": ["acme_web_user"], "login": "allowed"})
    found = row(cfg, role("acme_web_user", until=FUTURE))
    assert "valid_until" not in checks(found)
    assert found.state == REPORT_OK


@pytest.mark.parametrize(
    ("wanted", "fields", "expected"),
    [
        ("required", {"until": FUTURE}, ("ok", "VALID UNTIL 2099-01-01T00:00:00Z")),
        ("required", {}, ("problem", "no VALID UNTIL, rule says required")),
        (
            "required",
            {"infinite": "infinity"},
            ("problem", "VALID UNTIL infinity, rule says required"),
        ),
        (
            "required",
            {"until": PAST, "expired": True},
            (
                "problem",
                "password expired: VALID UNTIL 2001-01-01T00:00:00Z, rule says required",
            ),
        ),
        ("forbidden", {}, ("ok", "no VALID UNTIL")),
        ("forbidden", {"infinite": "infinity"}, ("ok", "VALID UNTIL infinity")),
        (
            "forbidden",
            {"until": FUTURE},
            ("problem", "VALID UNTIL 2099-01-01T00:00:00Z, rule says forbidden"),
        ),
        (
            "forbidden",
            {"infinite": "-infinity", "expired": True},
            ("problem", "password expired: VALID UNTIL -infinity, rule says forbidden"),
        ),
    ],
)
def test_valid_until_against_the_rule(
    wanted: str, fields: dict[str, Any], expected: tuple[str, str]
) -> None:
    cfg = config({"accounts": ["acme_web_user"], "postgresql": {"valid_until": wanted}})
    found = row(cfg, role("acme_web_user", **fields))
    assert outcome(found, "valid_until") == expected


def test_two_rules_that_disagree_leave_valid_until_not_checked() -> None:
    cfg = config(
        {"accounts": ["acme_web_*"], "postgresql": {"valid_until": "required"}},
        {"accounts": ["acme_*_user"], "postgresql": {"valid_until": "forbidden"}},
    )
    found = row(cfg, role("acme_web_user", until=FUTURE))
    assert outcome(found, "valid_until") == ("not_checked", "two rules expect different things")
    assert found.state == NOT_CHECKED


def test_a_conflict_between_rules_never_hides_a_past_date() -> None:
    """A date in the past is a problem whatever the rules say (#1464 review)."""
    cfg = config(
        {"accounts": ["acme_web_*"], "postgresql": {"valid_until": "required"}},
        {"accounts": ["acme_*_user"], "postgresql": {"valid_until": "forbidden"}},
    )
    found = row(cfg, role("acme_web_user", until=PAST, expired=True))
    assert outcome(found, "valid_until") == (
        "problem",
        "password expired: VALID UNTIL 2001-01-01T00:00:00Z",
    )
    assert found.state == REPORT_PROBLEM


def test_valid_until_is_not_applicable_on_oracle() -> None:
    """A `postgresql:` block on a rule that covers an Oracle target."""
    cfg = config({"accounts": ["ACME_SVC"], "postgresql": {"valid_until": "required"}})
    oracle_account = SurveyedAccount(
        name="ACME_SVC",
        status="OPEN",
        locked=False,
        profile="DEFAULT",
        common=False,
        vendor_maintained=False,
        password_lifetime=180,
        failed_login_limit=10,
        failed_logins=0,
    )
    found = row(cfg, oracle_account, target=ORACLE)
    assert outcome(found, "valid_until")[0] == NOT_APPLICABLE_OUTCOME
    assert found.state == NO_RULE


def test_profile_and_lifetime_rules_are_not_applicable_on_postgresql() -> None:
    cfg = config(
        {
            "accounts": ["acme_web_user"],
            "settings": {"password_lifetime": 90, "failed_login_limit": 5},
            "oracle": {"profile": "TECH"},
            "postgresql": {"valid_until": "forbidden"},
        }
    )
    found = row(cfg, role("acme_web_user"))
    for check in ("password_lifetime", "failed_login_limit", "profile"):
        assert outcome(found, check)[0] == NOT_APPLICABLE_OUTCOME, check
    assert found.state == REPORT_OK


# ----------------------------------------------------------------- config ---


def test_a_rule_may_state_only_valid_until() -> None:
    cfg = config({"accounts": ["acme_web_user"], "postgresql": {"valid_until": "required"}})
    assert cfg.reports.accounts[0].valid_until == "required"


@pytest.mark.parametrize(
    ("block", "message"),
    [
        ({}, "must declare `valid_until:`"),
        ({"valid_until": "sometimes"}, "valid_until"),
        ({"profile": "TECH"}, "profile"),
    ],
)
def test_a_wrong_postgresql_block_is_refused(block: dict[str, Any], message: str) -> None:
    with pytest.raises(ConfigError, match=message):
        config({"accounts": ["acme_web_user"], "postgresql": block})


def test_valid_until_is_in_the_published_check_enum() -> None:
    """A tripwire: the run schema's check enum is the module's `CHECKS`."""
    text = SCHEMA.read_text(encoding="utf-8")
    schema = json.loads(text)
    enum = _find_check_enum(schema)
    assert set(enum) == set(CHECKS)


def _find_check_enum(node: Any) -> list[str]:
    if isinstance(node, dict):
        check = node.get("properties", {}).get("check")
        if isinstance(check, dict) and "present" in check.get("enum", ()):
            return list(check["enum"])
        for value in node.values():
            found = _find_check_enum(value)
            if found:
                return found
    if isinstance(node, list):
        for value in node:
            found = _find_check_enum(value)
            if found:
                return found
    return []
