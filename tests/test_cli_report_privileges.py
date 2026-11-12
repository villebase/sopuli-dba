"""`sopuli report privileges` on fake sessions (UC-5 §5). Tier 0.

The collapsing and counting are tested in `tests/test_report_privileges.py`, and
the survey in work2's driver tests. Here: the command's text, JSON and exit codes.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import click
import pytest
from click.testing import CliRunner, Result
from jsonschema import Draft202012Validator

from conftest import WriteConfig
from sopuli.cli import cli
from sopuli.driver.grants import COLUMN, OBJECT, SCHEMA, SYSTEM, GrantRow, GrantSurvey, RoleGrant
from sopuli.driver.protocol import Scope
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
  - name: free-pdb
    type: oracle
    dsn: localhost:1521/FREEPDB1
    admin: { username: system, auth: { method: env } }
reports:
  accounts:
    - accounts: [ACME_RR_APP]
      oracle: { profile: DEFAULT }
"""

APP = "ACME_RR_APP"


def row(privilege: str, name: str | None = None, **fields: Any) -> GrantRow:
    values: dict[str, Any] = {
        "grantee": APP,
        "kind": OBJECT,
        "privilege": privilege,
        "owner": "ACME_RR_OWNER" if name else None,
        "name": name,
        "object_type": "TABLE" if name else None,
        "column": None,
        "path": (),
        "first_role_default": None,
        "grantable": False,
    }
    values.update(fields)
    return GrantRow(**values)


GRANTS = GrantSurvey(
    roles=(
        RoleGrant(APP, "ACME_RR_OUTER", False, True, "NONE"),
        RoleGrant(APP, "ACME_RR_EXTRA", False, False, "NONE"),
    ),
    system=(
        row("CREATE SESSION", kind=SYSTEM),
        row(
            "CREATE TABLE",
            kind=SYSTEM,
            path=("ACME_RR_OUTER", "ACME_RR_READ"),
            first_role_default=True,
        ),
    ),
    objects=(
        row("SELECT", "T1"),
        row("SELECT", "T3", path=("ACME_RR_OUTER", "ACME_RR_READ"), first_role_default=True),
        row("INSERT", "T1", path=("ACME_RR_EXTRA",), first_role_default=False),
    ),
    columns=(row("UPDATE", "T4", kind=COLUMN, column="N"),),
    schemas=(row("SELECT ANY TABLE", kind=SCHEMA, owner="ACME_SP_OWNER"),),
)


class FakeSession:
    def __init__(self, grants: GrantSurvey) -> None:
        self.grants = grants
        self.asked: tuple[Sequence[str], bool] | None = None

    def scope(self) -> Scope:
        return Scope(
            type="pdb",
            db_version="23.0.0.0.0",
            db_release="23.26.3.0.0",
            capabilities=frozenset(),
        )

    def survey_accounts(self) -> tuple[SurveyedAccount, ...]:
        return (SurveyedAccount(APP, "OPEN", False, "DEFAULT", False, False, 180, 10, 0),)

    def survey_with_profiles(self) -> tuple[tuple[SurveyedAccount, ...], frozenset[str]]:
        # The protocol the report asks for, as every product's session has it.
        return self.survey_accounts(), frozenset({"DEFAULT"})

    def survey_privileges(self, accounts: Sequence[str], *, public: bool) -> GrantSurvey:
        self.asked = (tuple(accounts), public)
        return self.grants

    def close(self) -> None:
        return None


@pytest.fixture
def session(monkeypatch: pytest.MonkeyPatch) -> dict[str, FakeSession]:
    holder = {"session": FakeSession(GRANTS)}
    monkeypatch.setattr("sopuli.cli._open_session", lambda target, run, config: holder["session"])
    return holder


def report(write_config: WriteConfig, *args: str) -> Result:
    config = write_config(CONFIG)
    return CliRunner().invoke(cli, ["--config", str(config), "report", "privileges", *args])


def test_the_summary(write_config: WriteConfig, session: Any) -> None:
    result = report(write_config)
    text = click.unstyle(result.output)

    assert result.exit_code == ExitCode.SUCCESS, result.output
    assert "ACME_RR_OUTER (default), ACME_RR_EXTRA (not default)" in text
    assert "CREATE TABLE (via ACME_RR_OUTER > ACME_RR_READ)" in text
    assert "SELECT on 2 tables (1 direct, 1 via roles)" in text
    assert (
        "INSERT on 1 table (0 direct, 1 via roles, 1 through a role that is not a default role)"
        in text
    )
    assert "UPDATE on 1 column (1 direct, 0 via roles)" in text
    assert "schemas: SELECT ANY TABLE on ACME_SP_OWNER (direct)" in text
    assert "not read yet" not in text
    assert session["session"].asked == ((APP,), False)


def test_account_names_one_the_target_lacks(write_config: WriteConfig, session: Any) -> None:
    result = report(write_config, "--account", "acme_nobody")
    assert "no account acme_nobody on this target" in click.unstyle(result.output)


def test_an_unread_roles_view_exits_4(
    write_config: WriteConfig, session: dict[str, FakeSession]
) -> None:
    session["session"] = FakeSession(
        GrantSurvey(
            roles=GRANTS.roles,
            system=GRANTS.system,
            objects=GRANTS.objects,
            columns=GRANTS.columns,
            schemas=GRANTS.schemas,
            unreadable=("DBA_ROLES could not be read",),
        )
    )
    assert report(write_config).exit_code == ExitCode.PARTIAL


def test_detail_lists_every_privilege_with_its_path(
    write_config: WriteConfig, session: Any
) -> None:
    text = click.unstyle(report(write_config, "--detail").output)
    assert "via ACME_RR_EXTRA, not a default role" in text
    assert "ACME_RR_OWNER.T4.N" in text
    schema_line = next(line for line in text.splitlines() if line.strip().startswith("schema "))
    assert schema_line.split()[:5] == ["schema", "SELECT", "ANY", "TABLE", "ACME_SP_OWNER"]
    assert "SCHEMA" in schema_line


def test_public_is_asked_for_only_with_the_flag(write_config: WriteConfig, session: Any) -> None:
    report(write_config, "--public")
    assert session["session"].asked == ((APP,), True)


def json_run(write_config: WriteConfig, *args: str) -> dict[str, Any]:
    config = write_config(CONFIG)
    result = CliRunner().invoke(
        cli, ["--config", str(config), "--output", "json", "report", "privileges", *args]
    )
    document: dict[str, Any] = json.loads(result.output)
    Draft202012Validator(RUN_SCHEMA).validate(document)
    return document


class _RoleSession(FakeSession):
    """A second account, which a personal rule's `role:` admits (#1469)."""

    def survey_accounts(self) -> tuple[SurveyedAccount, ...]:
        alice = SurveyedAccount(
            "ACME_DEV_ALICE", "OPEN", False, "DEFAULT", False, False, 180, 10, 0
        )
        return (*super().survey_accounts(), alice)

    def resolve_role(self, role: str) -> str | None:
        return role.upper()

    def accounts_matching(self, *, role: str | None = None, **_: Any) -> tuple[str, ...]:
        return ("ACME_DEV_ALICE",)


def test_a_role_predicates_member_is_personal_in_the_privilege_report(
    write_config: WriteConfig, session: dict[str, FakeSession]
) -> None:
    session["session"] = _RoleSession(GRANTS)
    config = write_config(f"{CONFIG}personal_accounts:\n  - role: acme_developers\n")
    result = CliRunner().invoke(
        cli, ["--config", str(config), "--output", "json", "report", "privileges"]
    )

    document = json.loads(result.output)
    kinds = {entry["account"]: entry["kind"] for entry in document["results"]}
    assert kinds["ACME_DEV_ALICE"] == "personal"


def test_public_json_validates_and_is_not_counted_as_an_account(
    write_config: WriteConfig, session: Any
) -> None:
    document = json_run(write_config, "--public")
    assert any(entry["kind"] == "public" for entry in document["results"])
    assert "(23.26.3.0.0, 1 account)" in click.unstyle(report(write_config, "--public").output)


def test_the_summary_agrees_with_the_results(
    write_config: WriteConfig, session: dict[str, FakeSession]
) -> None:
    session["session"] = FakeSession(
        GrantSurvey(
            roles=GRANTS.roles,
            system=GRANTS.system,
            objects=GRANTS.objects,
            columns=GRANTS.columns,
            schemas=GRANTS.schemas,
            unreadable=("DBA_ROLES could not be read",),
        )
    )
    document = json_run(write_config)
    assert document["summary"]["ok"] == 0
    assert document["summary"]["by_state"] == {"NOT_CHECKED": 1}


def test_a_missing_account_is_in_the_json(write_config: WriteConfig, session: Any) -> None:
    document = json_run(write_config, "--account", "acme_typo_user")
    assert document["results"] == [
        {
            "account": "acme_typo_user",
            "target": "free-pdb",
            "state": "ACCOUNT_MISSING",
            "changed": False,
        }
    ]


def test_an_unread_part_is_not_checked_exit_4(
    write_config: WriteConfig, session: dict[str, FakeSession]
) -> None:
    session["session"] = FakeSession(
        GrantSurvey(
            roles=GRANTS.roles,
            system=GRANTS.system,
            objects=None,
            columns=GRANTS.columns,
            schemas=GRANTS.schemas,
            unreadable=("DBA_TAB_PRIVS could not be read (ORA-00942)",),
        )
    )
    result = report(write_config)
    text = click.unstyle(result.output)
    assert result.exit_code == ExitCode.PARTIAL, result.output
    assert "objects: not checked" in text
    assert "not checked: DBA_TAB_PRIVS could not be read" in text


def test_a_level_is_shown_where_a_part_has_more_than_one(
    write_config: WriteConfig, session: dict[str, FakeSession]
) -> None:
    session["session"] = FakeSession(
        GrantSurvey(
            roles=(),
            system=(row("SYSTEM_VARIABLES_ADMIN", kind=SYSTEM, level="global dynamic"),),
            objects=(),
            columns=(),
            schemas=(),
        )
    )
    text = click.unstyle(report(write_config).output)
    assert "system: SYSTEM_VARIABLES_ADMIN (global dynamic, direct)" in text
    detail = click.unstyle(report(write_config, "--detail").output)
    line = next(one for one in detail.splitlines() if "SYSTEM_VARIABLES_ADMIN" in one)
    # The part first, so a reader can still tell the parts apart.
    assert line.split()[:4] == ["system", "(global", "dynamic)", "SYSTEM_VARIABLES_ADMIN"]
    (privilege,) = json_run(write_config)["results"][0]["privileges"]["system"]
    assert privilege["level"] == "global dynamic"


def test_a_path_not_checked_for_being_active_is_said_and_flagged(
    write_config: WriteConfig, session: dict[str, FakeSession]
) -> None:
    # MySQL, where the default roles could not be read (#1482).
    session["session"] = FakeSession(
        GrantSurvey(
            roles=(
                RoleGrant(APP, "acme_read@%", False, False, "NONE", default_role_checked=False),
            ),
            system=(),
            objects=(
                row("SELECT", "T1", path=("acme_read@%",), first_role_default=None),
                row("INSERT", "T1", path=("acme_read@%",), first_role_default=False),
            ),
            columns=(),
            schemas=(),
            unreadable=("whether a role is active without SET ROLE: no SELECT",),
        )
    )
    result = report(write_config)
    text = click.unstyle(result.output)
    assert result.exit_code == ExitCode.PARTIAL, result.output
    assert "1 through a role not checked for being active at login" in text
    assert "acme_read@% (default not checked)" in text
    (role,) = json_run(write_config)["results"][0]["privileges"]["roles"]
    assert (role["default_role"], role["default_role_checked"]) == (False, False)
    detail = click.unstyle(report(write_config, "--detail").output)
    assert "not checked whether active at login" in detail
    objects = json_run(write_config)["results"][0]["privileges"]["objects"]
    by_name = {one["privilege"]: one for one in objects}
    assert by_name["SELECT"]["active_at_login_checked"] is False
    assert by_name["SELECT"]["via_default_role"] is False
    # Absent where it was checked: an older entry is unchanged.
    assert "active_at_login_checked" not in by_name["INSERT"]


def test_a_driver_without_a_privilege_survey_is_not_supported(
    write_config: WriteConfig, session: dict[str, Any]
) -> None:
    class AccountsOnly:
        # A driver that serves `report accounts` and not this report.
        scope = FakeSession.scope
        survey_accounts = FakeSession.survey_accounts
        survey_with_profiles = FakeSession.survey_with_profiles

        def close(self) -> None:
            return None

    session["session"] = AccountsOnly()
    result = report(write_config)
    assert "not supported: " in click.unstyle(result.output)
    assert "cannot survey its privileges" in result.output


def test_the_oracle_session_is_a_privilege_survey() -> None:
    from sopuli.driver.grants import PrivilegeSurvey
    from sopuli.driver.oracle.session import OracleSession

    def typed(session: OracleSession) -> PrivilegeSurvey:
        # mypy checks the signature here; isinstance, at run time, only the name.
        # Each product's session gets the same line when it joins (#1481-#1483).
        return session

    assert typed is not None
    assert issubclass(OracleSession, PrivilegeSurvey)
    assert isinstance(FakeSession(GRANTS), PrivilegeSurvey)


def test_the_mysql_session_is_a_privilege_survey() -> None:
    pytest.importorskip("pymysql")
    from sopuli.driver.grants import PrivilegeSurvey
    from sopuli.driver.mysql.session import MysqlSession

    def typed(session: MysqlSession) -> PrivilegeSurvey:
        # mypy checks the signature here, as for Oracle's above.
        return session

    assert typed is not None
    assert issubclass(MysqlSession, PrivilegeSurvey)


def test_the_json_validates(write_config: WriteConfig, session: Any) -> None:
    config = write_config(CONFIG)
    result = CliRunner().invoke(
        cli, ["--config", str(config), "--output", "json", "report", "privileges"]
    )
    document = json.loads(result.output)
    Draft202012Validator(RUN_SCHEMA).validate(document)
    assert document["command"] == "report.privileges"
    entry = document["results"][0]
    assert entry["state"] == "REPORT_OK"
    insert = next(p for p in entry["privileges"]["objects"] if p["privilege"] == "INSERT")
    assert insert["paths"] == [["ACME_RR_EXTRA"]]
    # Oracle's parts each hold one level, so none is named.
    assert insert["level"] is None
    assert insert["via_default_role"] is False
    assert entry["privileges"]["schema_privileges_read"] is True
    (schema,) = entry["privileges"]["schemas"]
    assert (schema["privilege"], schema["owner"], schema["name"]) == (
        "SELECT ANY TABLE",
        "ACME_SP_OWNER",
        None,
    )


def test_unread_schema_privileges_are_not_checked_exit_4(
    write_config: WriteConfig, session: dict[str, FakeSession]
) -> None:
    reason = "DBA_SCHEMA_PRIVS could not be read (ORA-00942)"
    session["session"] = FakeSession(
        GrantSurvey(
            roles=GRANTS.roles,
            system=GRANTS.system,
            objects=GRANTS.objects,
            columns=GRANTS.columns,
            schemas=None,
            unreadable=(reason,),
        )
    )
    result = report(write_config)
    assert result.exit_code == ExitCode.PARTIAL, result.output
    assert "schemas: not checked" in click.unstyle(result.output)
    entry = json_run(write_config)["results"][0]
    assert entry["privileges"]["schemas"] is None
    assert entry["privileges"]["schema_privileges_read"] is False


def test_account_filter_may_name_an_undeclared_account(
    write_config: WriteConfig, session: Any
) -> None:
    result = report(write_config, "--account", "acme_rr_app")
    assert result.exit_code == ExitCode.SUCCESS, result.output
    assert session["session"].asked == ((APP,), False)


def test_a_common_account_in_a_pdb_keeps_its_privileges_read(
    write_config: WriteConfig, session: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#1438 leaves it out of the accounts report, but not out of this one:
    its grants made in the PDB are read there."""
    common = SurveyedAccount(
        "C##ACME_MONITOR", "OPEN", None, "DEFAULT", True, False, None, None, None,
        unreadable=("lock", "lifetime", "limit", "count"), kept_in_root=True,
    )  # fmt: skip
    plain = session["session"].survey_accounts()
    monkeypatch.setattr(session["session"], "survey_accounts", lambda: (common, *plain))
    result = report(write_config)
    assert result.exit_code == ExitCode.SUCCESS, result.output
    asked, _ = session["session"].asked
    assert "C##ACME_MONITOR" in asked
