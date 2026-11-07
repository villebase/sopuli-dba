"""`sopuli report accounts` on fake sessions (UC-5). Tier 0.

The survey and the rules are tested on their own in
`tests/driver/test_oracle_survey.py` and `tests/test_report_accounts.py`. Here:
the command's layout, its JSON, and its exit codes.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import click
import pytest
from click.testing import CliRunner, Result
from jsonschema import Draft202012Validator

from conftest import WriteConfig
from sopuli.cli import cli
from sopuli.driver.protocol import DriverError, Scope
from sopuli.driver.survey import SurveyedAccount
from sopuli.exit_codes import ExitCode
from sopuli.output.document import SCHEMA_VERSION

RUN_SCHEMA = json.loads(
    (
        Path(__file__).resolve().parents[1]
        / "docs"
        / "schemas"
        / f"sopuli-run-{SCHEMA_VERSION}.schema.json"
    ).read_text(encoding="utf-8")
)

CONFIG = """version: 1
targets:
  - name: prod-alpha
    type: oracle
    dsn: db-prod.example.com:1521/ALPHA
    admin: { username: C##SOPULI_SVC, auth: { method: env } }
  - name: qa-alpha
    type: oracle
    dsn: db-qa.example.com:1521/ALPHA
    admin: { username: C##SOPULI_SVC, auth: { method: env } }
reports:
  accounts:
    - accounts: [DBSNMP]
      settings: { password_lifetime: unlimited }
    - accounts: [ACME_BATCH_USER]
      profile: APP_USERS
    - accounts: ["ORDS_*"]
      profile: TECH_NOEXP
"""


def surveyed(name: str, **fields: Any) -> SurveyedAccount:
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
    }
    values.update(fields)
    return SurveyedAccount(**values)


#: What each target holds. qa-alpha has nothing wrong.
ESTATE: dict[str, tuple[SurveyedAccount, ...]] = {
    "prod-alpha": (
        surveyed("DBSNMP", vendor_maintained=True),
        surveyed("ACME_BATCH_USER", profile="APP_USERS"),
        surveyed(
            "ORDS_PUBLIC_USER", profile="TECH_NOEXP", failed_logins=None, failed_login_limit=None
        ),
        surveyed("ACME_STRAY_USER"),
        surveyed("SYSTEM", vendor_maintained=True),
    ),
    "qa-alpha": (
        surveyed("DBSNMP", vendor_maintained=True, password_lifetime="unlimited"),
        surveyed("ACME_BATCH_USER", profile="APP_USERS"),
    ),
}


class FakeSession:
    def __init__(self, target: str) -> None:
        self.target = target

    def scope(self) -> Scope:
        return Scope(type="pdb", db_version="23.26.3.0.0", capabilities=frozenset())

    def survey_accounts(self) -> tuple[SurveyedAccount, ...]:
        return ESTATE[self.target]

    def close(self) -> None:
        return None


Opener = Callable[[Any, Any, Any], Any]


@pytest.fixture
def sessions(monkeypatch: pytest.MonkeyPatch) -> dict[str, Opener]:
    """``_open_session`` per target name; a test may replace one."""
    openers: dict[str, Opener] = {}

    def open_session(target: Any, run: Any, config: Any) -> Any:
        opener = openers.get(target.name)
        return opener(target, run, config) if opener else FakeSession(target.name)

    monkeypatch.setattr("sopuli.cli._open_session", open_session)
    return openers


def report(write_config: WriteConfig, *args: str, json_out: bool = False) -> Result:
    config = write_config(CONFIG)
    output = ["--output", "json"] if json_out else []
    return CliRunner().invoke(cli, ["--config", str(config), *output, "report", "accounts", *args])


def test_problems_first_then_the_count(write_config: WriteConfig, sessions: Any) -> None:
    result = report(write_config, "--target", "prod-alpha")
    text = click.unstyle(result.output)

    assert result.exit_code == ExitCode.DRIFT, result.output
    lines = text.splitlines()
    assert lines[0] == (
        "prod-alpha  (23.26.3.0.0, 4 accounts read, 1 with a problem, 1 undeclared)"
    ) or lines[0].startswith("prod-alpha  (23.26.3.0.0, 5 accounts read, 1 with a problem")
    body = "\n".join(lines[1:])
    assert body.index("DBSNMP") < body.index("ACME_STRAY_USER")
    assert "password_lifetime: 180 days, rule says unlimited" in body
    assert "not in config" in body
    assert "SYSTEM" not in body
    assert "ACME_BATCH_USER" not in body
    assert "2 accounts OK" in text


def test_all_lists_every_account(write_config: WriteConfig, sessions: Any) -> None:
    text = click.unstyle(report(write_config, "--target", "prod-alpha", "--all").output)
    assert "ACME_BATCH_USER" in text
    assert "accounts OK" not in text


def test_an_unreadable_count_shows_unknown_never_zero(
    write_config: WriteConfig, sessions: Any
) -> None:
    text = click.unstyle(report(write_config, "--target", "prod-alpha", "--all").output)
    ords = next(line for line in text.splitlines() if "ORDS_PUBLIC_USER" in line)
    assert "unknown" in ords


def test_the_json_validates_against_the_current_schema(
    write_config: WriteConfig, sessions: Any
) -> None:
    result = report(write_config, json_out=True)
    document = json.loads(result.output)

    Draft202012Validator(RUN_SCHEMA).validate(document)
    assert document["command"] == "report.accounts"
    dbsnmp = next(
        row
        for row in document["results"]
        if row["account"] == "DBSNMP" and row["target"] == "prod-alpha"
    )
    assert dbsnmp["state"] == "REPORT_PROBLEM"
    assert dbsnmp["kind"] == "technical"
    assert {
        "check": "password_lifetime",
        "outcome": "problem",
        "detail": "180 days, rule says unlimited",
    } in dbsnmp["findings"]
    ords = next(row for row in document["results"] if row["account"] == "ORDS_PUBLIC_USER")
    assert ords["failed_logins"] is None


def test_an_unreachable_target_exits_1_and_the_others_are_reported(
    write_config: WriteConfig, sessions: dict[str, Opener]
) -> None:
    def refuse(target: Any, run: Any, config: Any) -> Any:
        raise DriverError("ORA-12541: Cannot connect. No listener")

    sessions["prod-alpha"] = refuse
    result = report(write_config, json_out=True)
    document = json.loads(result.output)

    assert result.exit_code == ExitCode.FAILURE, result.output
    Draft202012Validator(RUN_SCHEMA).validate(document)
    unreachable = [row for row in document["results"] if row["state"] == "ERROR"]
    assert [row["target"] for row in unreachable] == ["prod-alpha"]
    assert any(row["target"] == "qa-alpha" for row in document["results"])
    text = click.unstyle(report(write_config).output)
    assert "prod-alpha  could not connect: ORA-12541" in text


def test_a_clean_target_exits_0(write_config: WriteConfig, sessions: Any) -> None:
    result = report(write_config, "--target", "qa-alpha")
    assert result.exit_code == ExitCode.SUCCESS, result.output
    assert "2 accounts OK" in click.unstyle(result.output)


def test_only_not_checked_exits_4(
    write_config: WriteConfig, sessions: dict[str, Opener], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setitem(
        ESTATE,
        "qa-alpha",
        (
            surveyed("DBSNMP", vendor_maintained=True, password_lifetime=None),
            surveyed("ACME_BATCH_USER", profile="APP_USERS"),
        ),
    )
    result = report(write_config, "--target", "qa-alpha")
    assert result.exit_code == ExitCode.PARTIAL, result.output


def test_a_postgres_target_is_refused_before_connecting(write_config: WriteConfig) -> None:
    """The driver registry lists `report.accounts` for Oracle only."""
    config = write_config(
        "version: 1\n"
        "targets:\n"
        "  - name: pg-dev\n"
        "    type: postgresql\n"
        "    dsn: pg-dev.example.com:5432\n"
        "    postgres: { database: acme }\n"
        "    admin: { username: sopuli_svc, auth: { method: env } }\n"
    )
    result = CliRunner().invoke(
        cli, ["--config", str(config), "--output", "json", "report", "accounts"]
    )
    document = json.loads(result.output)
    row = document["results"][0]
    assert row["state"] == "ERROR"
    assert "SOPULI-20006" in json.dumps(row["error"])
    # No target can run the report: exit 5, UC-5 §3.
    assert result.exit_code == ExitCode.UNSUPPORTED_CAPABILITY
    text = click.unstyle(
        CliRunner().invoke(cli, ["--config", str(config), "report", "accounts"]).output
    )
    assert text.startswith("pg-dev  not supported: ")


def test_an_unsupported_target_beside_a_reached_one_is_not_checked(
    write_config: WriteConfig, sessions: dict[str, Opener]
) -> None:
    """One target of another product is that target not checked, exit 4 (UC-5 §3)."""
    from sopuli.driver.registry import NotWrittenError

    def unwritten(target: Any, run: Any, config: Any) -> Any:
        raise NotWrittenError(
            target.name, product="a MySQL server", what="report accounts", hint="none yet"
        )

    sessions["prod-alpha"] = unwritten
    result = report(write_config)
    assert result.exit_code == ExitCode.PARTIAL, result.output


# ------------------------------------------------------------------ tier 1 ---

LIVE = """version: 1
targets:
  - name: tier1-oracle
    type: oracle
    dsn: "{dsn}"
    admin: {{ username: {user}, auth: {{ method: env }} }}
reports:
  accounts:
    - accounts: [acme_rptt_user]
      settings: {{ password_lifetime: unlimited }}
    - accounts: [acme_rptt_gone]
      profile: ACME_RPTT_PROF
"""


def test_a_live_report_finds_the_expiring_password_and_the_missing_account(
    write_config: WriteConfig,
    live_oracle: Any,
    sysdba: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Against the tier-1 database: a profile with PASSWORD_LIFE_TIME 180 is a
    problem under a rule that says unlimited, and a declared name the database
    lacks is ACCOUNT_MISSING. Exit 3."""
    import os

    import oracle_harness
    from sopuli.config.targets import ADMIN_PASSWORD_ENV

    oracle_harness.execute(
        sysdba,
        "BEGIN EXECUTE IMMEDIATE 'DROP USER acme_rptt_user CASCADE'; "
        "EXCEPTION WHEN OTHERS THEN NULL; END;",
        "BEGIN EXECUTE IMMEDIATE 'DROP PROFILE acme_rptt_prof CASCADE'; "
        "EXCEPTION WHEN OTHERS THEN NULL; END;",
        "CREATE PROFILE acme_rptt_prof LIMIT PASSWORD_LIFE_TIME 180",
        'CREATE USER acme_rptt_user IDENTIFIED BY "Acme_Rptt_User_1" PROFILE acme_rptt_prof',
    )
    try:
        monkeypatch.setenv(
            ADMIN_PASSWORD_ENV, os.environ.get("SOPULI_TEST_ORACLE_PASSWORD", "sopuli-test")
        )
        user = os.environ.get("SOPULI_TEST_ORACLE_USER", "system")
        config = write_config(LIVE.format(dsn=live_oracle.dsn, user=user))
        result = CliRunner().invoke(
            cli, ["--config", str(config), "--output", "json", "report", "accounts"]
        )
        document = json.loads(result.output)
        Draft202012Validator(RUN_SCHEMA).validate(document)
        by_name = {row["account"]: row for row in document["results"]}

        assert result.exit_code == ExitCode.DRIFT, result.output
        assert by_name["ACME_RPTT_USER"]["state"] == "REPORT_PROBLEM"
        assert {
            "check": "password_lifetime",
            "outcome": "problem",
            "detail": "180 days, rule says unlimited",
        } in by_name["ACME_RPTT_USER"]["findings"]
        assert by_name["ACME_RPTT_GONE"]["state"] == "ACCOUNT_MISSING"
        assert "SYSTEM" not in by_name
    finally:
        oracle_harness.execute(
            sysdba,
            "BEGIN EXECUTE IMMEDIATE 'DROP USER acme_rptt_user CASCADE'; "
            "EXCEPTION WHEN OTHERS THEN NULL; END;",
            "BEGIN EXECUTE IMMEDIATE 'DROP PROFILE acme_rptt_prof CASCADE'; "
            "EXCEPTION WHEN OTHERS THEN NULL; END;",
        )
