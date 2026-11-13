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
from sopuli.cli import _personal_role_members, cli
from sopuli.config.loading import build_config
from sopuli.driver.protocol import ROLE_LOOKUP, DriverError, Scope, UnsupportedCapabilityError
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
      oracle: { profile: APP_USERS }
    - accounts: ["ORDS_*"]
      oracle: { profile: TECH_NOEXP }
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


#: Every target has the profiles the rules name.
PROFILES = frozenset({"DEFAULT", "APP_USERS", "TECH_NOEXP"})


class FakeSession:
    def __init__(self, target: str) -> None:
        self.target = target

    def scope(self) -> Scope:
        return Scope(
            type="pdb",
            db_version="23.0.0.0.0",
            db_release="23.26.3.0.0",
            capabilities=frozenset(),
        )

    def survey_accounts(self) -> tuple[SurveyedAccount, ...]:
        return ESTATE[self.target]

    def profiles(self) -> frozenset[str]:
        return PROFILES

    def survey_with_profiles(self) -> tuple[tuple[SurveyedAccount, ...], frozenset[str]]:
        # Through the two methods above, so a test can replace either one.
        return self.survey_accounts(), self.profiles()

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


class _RoleSession(FakeSession):
    """Answers `account list`'s two reads: whether a role exists, then its members."""

    roles: dict[str, tuple[str, ...]] = {"ACME_DEVELOPERS": ("ACME_STRAY_USER",)}

    def resolve_role(self, role: str) -> str | None:
        return role.upper() if role.upper() in self.roles else None

    def accounts_matching(
        self, *, profile: str | None = None, role: str | None = None
    ) -> tuple[str, ...]:
        assert role is not None
        return self.roles[role.upper()]


def role_report(write_config: WriteConfig, role: str) -> Result:
    config = write_config(f"{CONFIG}personal_accounts:\n  - role: {role}\n")
    return CliRunner().invoke(
        cli,
        [
            "--config",
            str(config),
            "--output",
            "json",
            "report",
            "accounts",
            "--target",
            "prod-alpha",
        ],
    )


def test_a_role_predicates_members_are_personal_accounts(
    write_config: WriteConfig, sessions: Any
) -> None:
    """#1469: resolved with `account list`'s reads, so both admit the same accounts."""
    sessions["prod-alpha"] = lambda *_: _RoleSession("prod-alpha")
    result = role_report(write_config, "acme_developers")

    by_name = {row["account"]: row for row in json.loads(result.output)["results"]}
    assert by_name["ACME_STRAY_USER"]["kind"] == "personal"


def test_a_role_that_does_not_exist_declares_nobody(
    write_config: WriteConfig, sessions: Any
) -> None:
    """As a personal rule's `profile:` naming no profile, it is not reported (#1390)."""
    sessions["prod-alpha"] = lambda *_: _RoleSession("prod-alpha")
    result = role_report(write_config, "acme_no_such_role")

    by_name = {row["account"]: row for row in json.loads(result.output)["results"]}
    assert by_name["ACME_STRAY_USER"]["state"] == "UNDECLARED"


#: A role as each product's config names it: a MySQL role is an account, and
#: a MariaDB role a name alone.
ROLES = {
    "oracle": "acme_developers",
    "postgresql": "acme_developers",
    "mysql": "acme_developers@%",
    "mariadb": "acme_developers",
}


def _quiet_run() -> Any:
    """A run whose document refuses a warning: these reads must raise none."""

    class _Document:
        def warn_in_text(self, diagnostic: Any) -> None:
            raise AssertionError(f"unexpected warning: {diagnostic}")

    class _Run:
        document = _Document()

    return _Run()


@pytest.mark.parametrize("product", sorted(ROLES))
def test_roles_are_resolved_on_every_product(product: str) -> None:
    """#1469 on Oracle and PostgreSQL, and #1495 on MySQL and MariaDB."""
    config = build_config(
        {
            "version": 1,
            "targets": [{"name": "t", "type": product, "dsn": "t.example.com:5432"}],
            "personal_accounts": [{"role": ROLES[product]}],
        }
    )
    session = _RoleSession("t")
    session.roles = {name.upper(): ("acme_dev_alice",) for name in ROLES.values()}
    members = _personal_role_members(session, config, config.expanded_targets[0], _quiet_run())

    assert members == ("acme_dev_alice",)


class _AskedRoles(_RoleSession):
    def __init__(self, target: str) -> None:
        super().__init__(target)
        self.asked: list[str] = []

    def resolve_role(self, role: str) -> str | None:
        self.asked.append(role)
        return role


@pytest.mark.parametrize(
    ("product", "asked"),
    [
        ("postgresql", ["acme_dev@Example.com"]),
        ("mysql", ["acme_Dev@example.com", "acme_dev@Example.com"]),
    ],
)
def test_roles_are_told_apart_as_the_config_tells_them(product: str, asked: list[str]) -> None:
    """By upper() on Oracle and PostgreSQL; on MySQL and MariaDB the name as
    written, where two spellings are two roles (#1465), and a MySQL host part
    without case, as the server compares it: three rules, two roles."""
    config = build_config(
        {
            "version": 1,
            "targets": [{"name": "t", "type": product, "dsn": "t.example.com:5432"}],
            "personal_accounts": [
                {"role": "acme_Dev@example.com"},
                {"role": "acme_dev@example.com"},
                {"role": "acme_dev@Example.com"},
            ],
        }
    )
    session = _AskedRoles("t")
    session.roles = {"ACME_DEV@EXAMPLE.COM": ()}
    _personal_role_members(session, config, config.expanded_targets[0], _quiet_run())

    assert session.asked == asked


def test_without_role_lookup_the_report_runs_and_the_role_is_not_resolved(
    write_config: WriteConfig, sessions: Any
) -> None:
    """On Oracle without `SELECT ON DBA_ROLES`: the report does not fail the
    target over a capability (invariant 4, #1376); the members show as
    undeclared, and `SOPULI-W075` names the role and the grant (#1478)."""

    class _NoLookup(_RoleSession):
        def resolve_role(self, role: str) -> str | None:
            raise UnsupportedCapabilityError(
                ROLE_LOOKUP, target=self.target, hint="GRANT SELECT ON SYS.DBA_ROLES to it"
            )

    sessions["prod-alpha"] = lambda *_: _NoLookup("prod-alpha")
    result = role_report(write_config, "acme_developers")

    assert result.exit_code == ExitCode.DRIFT, result.output
    document = json.loads(result.output)
    by_name = {row["account"]: row for row in document["results"]}
    assert by_name["ACME_STRAY_USER"]["state"] == "UNDECLARED"
    [warning] = [w for w in document["diagnostics"] if w["code"] == "SOPULI-W075"]
    assert warning["target"] == "prod-alpha"
    assert warning["message"] == (
        "prod-alpha: the role acme_developers of a personal_accounts: rule was not "
        "resolved, because the target does not support role_lookup, so its members "
        "show as undeclared: GRANT SELECT ON SYS.DBA_ROLES to it"
    )


def test_a_role_read_that_fails_is_a_read_failure_on_the_target(
    write_config: WriteConfig, sessions: Any
) -> None:
    class _Refused(_RoleSession):
        def accounts_matching(self, **_: Any) -> tuple[str, ...]:
            raise DriverError("ORA-01031: insufficient privileges")

    sessions["prod-alpha"] = lambda *_: _Refused("prod-alpha")
    result = role_report(write_config, "acme_developers")

    assert result.exit_code == ExitCode.FAILURE, result.output
    assert "insufficient privileges" in result.output


def test_a_role_every_account_holds_fails_the_target_with_its_own_reason(
    write_config: WriteConfig, sessions: Any
) -> None:
    """#1495: a MySQL mandatory role would make every account personal, so the
    target fails, as #1469 decided for a failed role read, and the finding is
    the refusal `account list` gives for the same rule."""
    from sopuli.driver.mysql.roles import MandatoryRoleError

    class _Mandatory(_RoleSession):
        def resolve_role(self, role: str) -> str | None:
            raise MandatoryRoleError(role, through=role, target=self.target)

    sessions["prod-alpha"] = lambda *_: _Mandatory("prod-alpha")
    result = role_report(write_config, "acme_developers")

    assert result.exit_code == ExitCode.FAILURE, result.output
    by_target = json.loads(result.output)["results"]
    assert by_target[0]["state"] == "ERROR"
    assert "every account" in by_target[0]["error"]["message"]


class _NoSurvey:
    """A session that connects but cannot survey its accounts (no `AccountSurvey`)."""

    def close(self) -> None:
        return None


def test_a_session_without_the_survey_is_not_supported_never_unreachable(
    write_config: WriteConfig, sessions: Any
) -> None:
    """From the review of #1463: the `AccountSurvey` check in `_report_target`."""
    sessions["prod-alpha"] = lambda *_: _NoSurvey()
    result = report(write_config, "--target", "prod-alpha")
    text = click.unstyle(result.output)
    assert "prod-alpha  not supported" in text
    assert "this driver cannot survey its accounts and profiles" in text
    assert "could not be reached" not in text
    # The only target cannot run the report, so nothing could run: exit 5.
    assert result.exit_code == ExitCode.UNSUPPORTED_CAPABILITY, result.output


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


def test_a_profile_missing_on_a_target_is_one_problem_exit_3(
    write_config: WriteConfig, sessions: dict[str, Opener]
) -> None:
    """#1390: qa-alpha lacks TECH_NOEXP, which the ORDS_* rule names. No
    account there is on it, so only the target-level finding says so."""

    class NoTechProfile(FakeSession):
        def profiles(self) -> frozenset[str]:
            return frozenset({"DEFAULT", "APP_USERS"})

    sessions["qa-alpha"] = lambda target, run, config: NoTechProfile(target.name)
    result = report(write_config, "--target", "qa-alpha")
    text = click.unstyle(result.output)
    assert result.exit_code == ExitCode.DRIFT, result.output
    assert "qa-alpha  (23.26.3.0.0, 2 accounts read, 1 profile missing)" in text
    assert (
        "  profile missing: TECH_NOEXP does not exist on this target; "
        "expected by a reports.accounts rule"
    ) in text

    document = json.loads(report(write_config, "--target", "qa-alpha", json_out=True).output)
    Draft202012Validator(RUN_SCHEMA).validate(document)
    [missing] = [row for row in document["results"] if row["state"] == "PROFILE_MISSING"]
    assert missing == {
        "account": "-",
        "target": "qa-alpha",
        "state": "PROFILE_MISSING",
        "changed": False,
        "missing_profile": "TECH_NOEXP",
        "expected_by": ["reports.accounts"],
        "findings": [
            {
                "check": "profile",
                "outcome": "problem",
                "detail": "TECH_NOEXP does not exist on this target; "
                "expected by a reports.accounts rule",
            }
        ],
    }
    assert document["summary"]["failed"] == 1
    assert document["summary"]["by_state"]["PROFILE_MISSING"] == 1


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


def test_a_target_whose_driver_lacks_the_report_is_refused_before_connecting(
    write_config: WriteConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Every product lists `report.accounts` in the driver registry now
    (#1462), so one entry is patched to lack it."""
    from dataclasses import replace

    from sopuli.driver.registry import DRIVERS

    entry = DRIVERS["mariadb"]
    assert entry.commands is not None
    monkeypatch.setitem(
        DRIVERS, "mariadb", replace(entry, commands=entry.commands - {"report.accounts"})
    )
    config = write_config(
        "version: 1\n"
        "targets:\n"
        "  - name: mariadb-dev\n"
        "    type: mariadb\n"
        "    dsn: mariadb-dev.example.com:3306\n"
        "    admin: { username: sopuli_svc, auth: { method: env } }\n"
    )
    result = CliRunner().invoke(
        cli, ["--config", str(config), "--output", "json", "report", "accounts"]
    )
    document = json.loads(result.output)
    row = document["results"][0]
    assert row["state"] == "NOT_CHECKED"
    assert "SOPULI-20006" in json.dumps(row["error"])
    # No target can run the report: exit 5, UC-5 §3.
    assert result.exit_code == ExitCode.UNSUPPORTED_CAPABILITY
    text = click.unstyle(
        CliRunner().invoke(cli, ["--config", str(config), "report", "accounts"]).output
    )
    assert text.startswith("mariadb-dev  not supported: ")


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

    document = json.loads(report(write_config, json_out=True).output)
    Draft202012Validator(RUN_SCHEMA).validate(document)
    refused = next(row for row in document["results"] if row["target"] == "prod-alpha")
    # Not checked, as the exit code says, and not counted as a failure.
    assert refused["state"] == "NOT_CHECKED"
    assert document["summary"]["failed"] == 0


def test_a_survey_that_fails_after_connecting_says_could_not_read(
    write_config: WriteConfig, sessions: dict[str, Opener]
) -> None:
    class Refusing(FakeSession):
        def survey_accounts(self) -> tuple[SurveyedAccount, ...]:
            raise DriverError("DBA_PROFILES could not be read (ORA-00942)")

    sessions["prod-alpha"] = lambda target, run, config: Refusing(target.name)
    result = report(write_config)
    assert result.exit_code == ExitCode.FAILURE, result.output
    assert "prod-alpha  could not read: DBA_PROFILES" in click.unstyle(result.output)


def test_a_session_without_a_survey_is_unsupported_not_unreachable(
    write_config: WriteConfig, sessions: dict[str, Opener]
) -> None:
    class NoSurvey:
        def close(self) -> None:
            return None

    sessions["prod-alpha"] = lambda target, run, config: NoSurvey()
    result = report(write_config)
    assert result.exit_code == ExitCode.PARTIAL, result.output
    assert "prod-alpha  not supported: " in click.unstyle(result.output)


def test_an_unreadable_count_says_why_once_per_target(
    write_config: WriteConfig, sessions: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setitem(
        ESTATE,
        "qa-alpha",
        (
            surveyed(
                "DBSNMP",
                vendor_maintained=True,
                password_lifetime="unlimited",
                failed_logins=None,
                unreadable=("SYS.USER$ is not readable: grant SELECT ON SYS.USER$",),
            ),
        ),
    )
    result = report(write_config, "--target", "qa-alpha")
    text = click.unstyle(result.output)
    assert text.count("SYS.USER$ is not readable") == 1
    document = json.loads(report(write_config, "--target", "qa-alpha", json_out=True).output)
    Draft202012Validator(RUN_SCHEMA).validate(document)
    dbsnmp = next(row for row in document["results"] if row["account"] == "DBSNMP")
    assert dbsnmp["failed_logins_reason"].startswith("SYS.USER$")


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
      oracle: {{ profile: ACME_RPTT_PROF }}
    - accounts: ["ACME_RPTT_NONE_*"]
      oracle: {{ profile: ACME_RPTT_NOPROF }}
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
        # A rule's profile the database lacks is one result for the target
        # (#1390); the profile the other rule names exists, so it is not one.
        missing = [row for row in document["results"] if row["state"] == "PROFILE_MISSING"]
        assert [(row["account"], row["missing_profile"]) for row in missing] == [
            ("-", "ACME_RPTT_NOPROF")
        ]
    finally:
        oracle_harness.execute(
            sysdba,
            "BEGIN EXECUTE IMMEDIATE 'DROP USER acme_rptt_user CASCADE'; "
            "EXCEPTION WHEN OTHERS THEN NULL; END;",
            "BEGIN EXECUTE IMMEDIATE 'DROP PROFILE acme_rptt_prof CASCADE'; "
            "EXCEPTION WHEN OTHERS THEN NULL; END;",
        )
