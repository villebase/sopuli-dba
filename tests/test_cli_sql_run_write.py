"""`sopuli sql run --write`, on fake sessions, and once against a real server (UC-3).

The tier-0 tests pin the order of the gates and what a write reports: the
argv checks, `readonly`, `max_targets` and `confirm_environments`, the plan
fingerprint and `--plan`, and how a real write stops at the first target that
fails. The last test is tier 1: a dry run and a real run on two names for the
tier-1 PDB, with the rows read back from a second connection.
"""

from __future__ import annotations

import contextlib
import os
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import click
import pytest
from click.testing import CliRunner, Result

from conftest import WriteConfig
from oracle_harness import Environment
from sopuli.cli import cli
from sopuli.driver.protocol import DriverError, StatementResult
from sopuli.exit_codes import ExitCode
from sopuli.output import sql_view as sql_view_module
from sopuli.sql.fingerprint import PlannedTarget, fingerprint
from sopuli.sql.guard import RowGuard
from sopuli.sql.statement import Statement, classify
from test_cli_sql_run import (
    RUN_AS,
    FakeSession,
    document,
    exit_of,
    refused_login,
    terminal,  # noqa: F401 -- a fixture
)

UPDATE = "UPDATE acme_settings SET flag = 1 WHERE name = 'audit';\n"

#: Four targets, written out of order: a write runs them in sorted order.
FLEET = """targets:
  - name: d-delta
    type: oracle
    dsn: db-delta.example.com:1521/DELTA
    labels: { fleet: acme }
    admin: { username: C##SOPULI_SVC, auth: { method: env } }
  - name: b-beta
    type: oracle
    dsn: db-beta.example.com:1521/BETA
    labels: { fleet: acme }
    admin: { username: C##SOPULI_SVC, auth: { method: env } }
  - name: a-alpha
    type: oracle
    dsn: db-alpha.example.com:1521/ALPHA
    labels: { fleet: acme }
    admin: { username: C##SOPULI_SVC, auth: { method: env } }
  - name: c-gamma
    type: oracle
    dsn: db-gamma.example.com:1521/GAMMA
    labels: { fleet: acme }
    admin: { username: C##SOPULI_SVC, auth: { method: env } }
"""

CONFIG = f"version: 1\ndefaults:\n{RUN_AS}{FLEET}"
ORDER = ["a-alpha", "b-beta", "c-gamma", "d-delta"]
ALL = ("--select", "fleet=acme")


class WriteSession(FakeSession):
    """A session whose statement changes ``count`` rows."""

    def __init__(
        self,
        target: str,
        *,
        count: int = 1,
        identity: tuple[str, str] = ("FREE", "FREEPDB1"),
        error: Exception | None = None,
    ) -> None:
        super().__init__(target, error=error)
        self.count = count
        self.identity = identity
        self.closes = 0

    def database_identity(self) -> tuple[str, str]:
        self.identity_reads += 1
        return self.identity

    def run_statement(self, statement: Statement, **options: Any) -> StatementResult:
        self.calls.append({"statement": statement, **options})
        if self.error is not None:
            raise self.error
        guard = options["guard"]
        passed = guard.passes(self.count)
        committed = bool(options["commit"] and passed and self.count > 0)
        return StatementResult((), (), self.count, False, committed, passed)

    def close(self) -> None:
        self.closes += 1
        self.closed = True


@pytest.fixture
def fleet(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """``_open_sql_session`` per target name, as in `test_cli_sql_run.py`, with
    a :class:`WriteSession` where the test gave nothing."""
    given: dict[str, Any] = {}
    opened: list[WriteSession] = []

    def open_session(target: Any, run: Any, config: Any, as_user: str | None) -> Any:
        one = given.get(target.name)
        if isinstance(one, Exception):
            raise one
        session = one if one is not None else WriteSession(target.name)
        given[target.name] = session
        opened.append(session)
        return session

    monkeypatch.setattr("sopuli.cli._open_sql_session", open_session)
    monkeypatch.setenv("DBA_ALPHA_PW", "not-used-by-a-fake")
    given["opened"] = opened
    return given


def sql(
    write_config: WriteConfig,
    *args: str,
    statement: str | None = UPDATE,
    config: str = CONFIG,
    json_out: bool = False,
) -> Result:
    path = write_config(config)
    output = ["--output", "json"] if json_out else []
    return CliRunner().invoke(
        cli, ["--config", str(path), *output, "sql", "run", *args], input=statement
    )


def dry_hash(write_config: WriteConfig, fleet: dict[str, Any], *args: str, **kw: Any) -> str:
    """The fingerprint a dry run prints, with the sessions it opened forgotten."""
    loaded = document(sql(write_config, "--write", "--dry-run", *args, json_out=True, **kw))
    for session in fleet.values():
        if isinstance(session, WriteSession):
            session.calls.clear()
            session.closes = 0
            session.closed = False
    fleet["opened"].clear()
    found: str = loaded["statement"]["fingerprint"]
    return found


def states(loaded: dict[str, Any]) -> list[tuple[str, str]]:
    return [(entry["target"], entry["state"]) for entry in loaded["results"]]


# ------------------------------------------------------------- argv checks ---


def test_write_needs_a_guard(write_config: WriteConfig, fleet: dict[str, Any]) -> None:
    result = sql(write_config, "--write", "--dry-run", *ALL)

    assert result.exit_code == ExitCode.USAGE, result.output
    assert "--expect-rows" in result.output
    assert "--max-rows" in result.output
    assert fleet["opened"] == []


def test_both_guards_is_a_usage_error(write_config: WriteConfig, fleet: dict[str, Any]) -> None:
    result = sql(
        write_config, "--write", "--dry-run", *ALL, "--expect-rows", "1", "--max-rows", "2"
    )

    assert result.exit_code == ExitCode.USAGE, result.output
    assert fleet["opened"] == []


def test_write_needs_a_selector(write_config: WriteConfig, fleet: dict[str, Any]) -> None:
    result = sql(write_config, "--write", "--dry-run", "--expect-rows", "1")

    assert result.exit_code == ExitCode.USAGE, result.output
    assert "--target" in result.output
    assert fleet["opened"] == []


def test_real_run_without_plan_refused(write_config: WriteConfig, fleet: dict[str, Any]) -> None:
    result = sql(write_config, "--write", *ALL, "--expect-rows", "1")

    assert result.exit_code == ExitCode.USAGE, result.output
    assert "--plan" in result.output
    assert "--dry-run" in result.output
    assert fleet["opened"] == []


def test_a_guard_or_plan_without_write_is_a_usage_error(
    write_config: WriteConfig, fleet: dict[str, Any]
) -> None:
    for extra in (("--expect-rows", "1"), ("--max-rows", "1"), ("--plan", "0" * 12)):
        result = sql(write_config, *ALL, *extra, statement="SELECT 1 FROM dual")
        assert result.exit_code == ExitCode.USAGE, result.output
        assert "--write" in result.output
    assert fleet["opened"] == []


def test_read_statement_with_write_flag_refused(
    write_config: WriteConfig, fleet: dict[str, Any]
) -> None:
    result = sql(
        write_config,
        "--write",
        "--dry-run",
        *ALL,
        "--expect-rows",
        "1",
        statement="SELECT 1 FROM dual",
        json_out=True,
    )

    assert exit_of(result) == ExitCode.ABORTED, result.output
    error = document(result)["error"]
    assert error["code"] == "SOPULI-20009"
    assert "--write" in error["message"]
    assert fleet["opened"] == []


# ------------------------------------------------------------ safety settings ---

READONLY = CONFIG.replace("defaults:\n", "defaults:\n  safety: { readonly: true }\n")


def test_write_refused_when_readonly(write_config: WriteConfig, fleet: dict[str, Any]) -> None:
    result = sql(
        write_config, "--write", *ALL, "--expect-rows", "1", "--plan", "0" * 12, config=READONLY
    )

    assert exit_of(result) == ExitCode.ABORTED, result.output
    assert fleet["opened"] == []


def test_readonly_refuses_dry_run_write_too(
    write_config: WriteConfig, fleet: dict[str, Any]
) -> None:
    result = sql(write_config, "--write", "--dry-run", *ALL, "--expect-rows", "1", config=READONLY)

    assert exit_of(result) == ExitCode.ABORTED, result.output
    assert fleet["opened"] == []


def test_readonly_on_one_target_refuses_a_write_that_selects_it(
    write_config: WriteConfig, fleet: dict[str, Any]
) -> None:
    config = CONFIG.replace(
        "  - name: a-alpha\n", "  - name: a-alpha\n    safety: { readonly: true }\n"
    )

    refused = sql(write_config, "--write", "--dry-run", *ALL, "--expect-rows", "1", config=config)
    allowed = sql(
        write_config,
        "--write",
        "--dry-run",
        "--target",
        "b-beta",
        "--expect-rows",
        "1",
        config=config,
    )

    assert exit_of(refused) == ExitCode.ABORTED, refused.output
    assert "1 of the 4 targets it reaches" in str(refused.exception)
    assert allowed.exit_code == ExitCode.SUCCESS, allowed.output


def test_readonly_on_a_group_refuses_a_write_into_it(
    write_config: WriteConfig, fleet: dict[str, Any]
) -> None:
    config = (
        CONFIG + "groups:\n  acme:\n    match: { fleet: acme }\n    safety: { readonly: true }\n"
    )

    result = sql(write_config, "--write", "--dry-run", *ALL, "--expect-rows", "1", config=config)

    assert exit_of(result) == ExitCode.ABORTED, result.output
    assert "groups.acme.safety.readonly" in (getattr(result.exception, "hint", "") or "")
    assert fleet["opened"] == []


def test_max_targets_on_a_target_bounds_a_write(
    write_config: WriteConfig, fleet: dict[str, Any]
) -> None:
    config = CONFIG.replace(
        "  - name: c-gamma\n", "  - name: c-gamma\n    safety: { max_targets: 1 }\n"
    )

    result = sql(write_config, "--write", "--dry-run", *ALL, "--expect-rows", "1", config=config)

    assert exit_of(result) == ExitCode.ABORTED, result.output
    assert fleet["opened"] == []


def test_readonly_does_not_refuse_a_read(write_config: WriteConfig, fleet: dict[str, Any]) -> None:
    sessions = {name: FakeSession(name) for name in ORDER}
    fleet.update(sessions)

    result = sql(write_config, *ALL, statement="SELECT 1 FROM dual", config=READONLY)

    assert result.exit_code == ExitCode.SUCCESS, result.output


def test_write_over_max_targets_refused(write_config: WriteConfig, fleet: dict[str, Any]) -> None:
    config = CONFIG.replace("defaults:\n", "defaults:\n  safety: { max_targets: 2 }\n")

    result = sql(write_config, "--write", "--dry-run", *ALL, "--expect-rows", "1", config=config)

    assert exit_of(result) == ExitCode.ABORTED, result.output
    assert "max_targets" in str(result.exception)
    assert fleet["opened"] == []


PROD = CONFIG.replace("defaults:\n", "defaults:\n  safety: { confirm_environments: [prod] }\n")
PROD = PROD.replace(
    "    labels: { fleet: acme }\n", "    environment: prod\n    labels: { fleet: acme }\n"
)


def test_confirm_environments_refuses_with_nobody_to_ask(
    write_config: WriteConfig, fleet: dict[str, Any]
) -> None:
    """A real write into a listed environment, with no terminal, runs nothing."""
    plan = dry_hash(write_config, fleet, *ALL, "--expect-rows", "1", config=PROD)

    result = sql(write_config, "--write", *ALL, "--expect-rows", "1", "--plan", plan, config=PROD)

    assert exit_of(result) == ExitCode.ABORTED, result.output
    assert "confirm_environments" in str(result.exception)
    assert fleet["opened"] == []


def test_confirm_environments_asks_only_on_a_real_run(
    write_config: WriteConfig,
    fleet: dict[str, Any],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The dry run asks nothing. The real run asks once, after the fingerprint
    matched and before any statement runs; a "no" runs nothing."""
    statement = tmp_path / "update.sql"
    statement.write_text(UPDATE, encoding="utf-8")
    file_args = ("--file", str(statement))
    plan = dry_hash(write_config, fleet, *ALL, "--expect-rows", "1", *file_args, config=PROD)
    monkeypatch.setattr("sopuli.cli._can_prompt", lambda: True)
    args = ("--write", *ALL, "--expect-rows", "1", "--plan", plan, *file_args)

    declined = sql(write_config, *args, statement="n\n", config=PROD)
    assert exit_of(declined) == ExitCode.ABORTED, declined.output
    assert "[y/N]" in declined.output
    assert all(session.calls == [] for session in fleet["opened"])
    assert all(session.closed for session in fleet["opened"])

    accepted = sql(write_config, *args, statement="y\n", config=PROD)
    assert accepted.exit_code == ExitCode.SUCCESS, accepted.output
    assert all(fleet[name].calls[-1]["commit"] is True for name in ORDER)


def test_confirm_answers_the_question_in_advance(
    write_config: WriteConfig, fleet: dict[str, Any]
) -> None:
    plan = dry_hash(write_config, fleet, *ALL, "--expect-rows", "1", config=PROD)

    result = sql(
        write_config,
        "--write",
        *ALL,
        "--expect-rows",
        "1",
        "--plan",
        plan,
        "--confirm",
        config=PROD,
    )

    assert result.exit_code == ExitCode.SUCCESS, result.output


# ------------------------------------------------------- the dry run and plan ---


def test_dry_run_prints_plan_and_fingerprint_rolls_back(
    write_config: WriteConfig, fleet: dict[str, Any]
) -> None:
    result = sql(write_config, "--write", "--dry-run", *ALL, "--expect-rows", "1")
    text = click.unstyle(result.output)

    assert result.exit_code == ExitCode.SUCCESS, result.output
    expected = fingerprint(
        classify(UPDATE),
        RowGuard(expect=1),
        [
            PlannedTarget(name, dsn, "dba_alpha", "FREE", "FREEPDB1")
            for name, dsn in (
                ("a-alpha", "db-alpha.example.com:1521/ALPHA"),
                ("b-beta", "db-beta.example.com:1521/BETA"),
                ("c-gamma", "db-gamma.example.com:1521/GAMMA"),
                ("d-delta", "db-delta.example.com:1521/DELTA"),
            )
        ],
    )
    assert text.startswith("Plan: 1 account x 4 targets = 4 writes")
    assert f"--plan {expected}" in text
    assert "UPDATE acme_settings SET flag = 1 WHERE name = 'audit'" in text
    for session in fleet["opened"]:
        (call,) = session.calls
        assert call["commit"] is False
        assert call["guard"] == RowGuard(expect=1)
        assert session.closes == 1

    loaded = document(
        sql(write_config, "--write", "--dry-run", *ALL, "--expect-rows", "1", json_out=True)
    )
    assert loaded["statement"]["fingerprint"] == expected
    assert loaded["statement"]["kind"] == "write"
    assert {tuple(unit["intent"]) for unit in loaded["plan"]["units"]} == {("sql_write",)}
    assert states(loaded) == [(name, "ROLLED_BACK") for name in ORDER]
    assert all(entry["changed"] is False for entry in loaded["results"])
    assert all(entry["row_count"] == 1 for entry in loaded["results"])


def test_dry_run_does_not_stop_at_guard_failure(
    write_config: WriteConfig, fleet: dict[str, Any]
) -> None:
    fleet["a-alpha"] = WriteSession("a-alpha", count=3)
    fleet["c-gamma"] = WriteSession("c-gamma", error=DriverError("ORA-00942", code="ORA-00942"))

    loaded = document(
        sql(write_config, "--write", "--dry-run", *ALL, "--expect-rows", "1", json_out=True)
    )

    assert states(loaded) == [
        ("a-alpha", "GUARD_FAILED"),
        ("b-beta", "ROLLED_BACK"),
        ("c-gamma", "ERROR"),
        ("d-delta", "ROLLED_BACK"),
    ]
    assert loaded["results"][0]["row_count"] == 3
    assert "exactly 1 row" in loaded["results"][0]["error"]["message"]
    assert loaded["exit_code"] == ExitCode.PARTIAL


def test_plan_changes_when_config_adds_target(
    write_config: WriteConfig, fleet: dict[str, Any]
) -> None:
    before = dry_hash(write_config, fleet, *ALL, "--expect-rows", "1")
    grown = CONFIG + (
        "  - name: e-epsilon\n"
        "    type: oracle\n"
        "    dsn: db-epsilon.example.com:1521/EPSILON\n"
        "    labels: { fleet: acme }\n"
        "    admin: { username: C##SOPULI_SVC, auth: { method: env } }\n"
    )

    after = dry_hash(write_config, fleet, *ALL, "--expect-rows", "1", config=grown)
    refused = sql(
        write_config, "--write", *ALL, "--expect-rows", "1", "--plan", before, config=grown
    )

    assert before != after
    assert exit_of(refused) == ExitCode.ABORTED, refused.output
    assert all(session.calls == [] for session in fleet["opened"])


def test_plan_changes_when_the_guard_changes(
    write_config: WriteConfig, fleet: dict[str, Any]
) -> None:
    exactly = dry_hash(write_config, fleet, *ALL, "--expect-rows", "1")
    at_most = dry_hash(write_config, fleet, *ALL, "--max-rows", "1")

    assert exactly != at_most


def test_plan_changes_when_database_identity_changes(
    write_config: WriteConfig, fleet: dict[str, Any]
) -> None:
    """The same `dsn` now reaches another database, such as a TNS alias moved."""
    before = dry_hash(write_config, fleet, *ALL, "--expect-rows", "1")
    fleet["b-beta"] = WriteSession("b-beta", identity=("OTHER", "OTHERPDB"))

    result = sql(write_config, "--write", *ALL, "--expect-rows", "1", "--plan", before)

    assert exit_of(result) == ExitCode.ABORTED, result.output
    assert fleet["b-beta"].calls == []


def test_real_run_wrong_plan_refused_20011(
    write_config: WriteConfig, fleet: dict[str, Any]
) -> None:
    computed = dry_hash(write_config, fleet, *ALL, "--expect-rows", "1")

    result = sql(
        write_config, "--write", *ALL, "--expect-rows", "1", "--plan", "0" * 12, json_out=True
    )

    assert exit_of(result) == ExitCode.ABORTED, result.output
    loaded = document(result)
    error = loaded["error"]
    assert error["code"] == "SOPULI-20011"
    assert "0" * 12 in error["message"]
    assert computed in error["message"]
    assert "--dry-run" in error["hint"]
    assert loaded["statement"]["fingerprint"] == computed
    assert len(fleet["opened"]) == 4
    assert all(session.calls == [] for session in fleet["opened"])
    assert all(session.closes == 1 for session in fleet["opened"])


# ---------------------------------------------------------------- real writes ---


def real(write_config: WriteConfig, fleet: dict[str, Any], *guard: str) -> Result:
    plan = dry_hash(write_config, fleet, *ALL, *guard)
    return sql(write_config, "--write", *ALL, *guard, "--plan", plan, json_out=True)


def test_real_run_commits_each_target(write_config: WriteConfig, fleet: dict[str, Any]) -> None:
    result = real(write_config, fleet, "--expect-rows", "1")

    assert result.exit_code == ExitCode.SUCCESS, result.output
    loaded = document(result)
    assert states(loaded) == [(name, "COMMITTED") for name in ORDER]
    assert all(entry["changed"] is True for entry in loaded["results"])
    assert all(entry["row_count"] == 1 for entry in loaded["results"])
    assert [session.target for session in fleet["opened"]] == [
        "d-delta",
        "b-beta",
        "a-alpha",
        "c-gamma",
    ]
    assert all(session.calls[0]["commit"] is True for session in fleet["opened"])
    assert all(session.closes == 1 for session in fleet["opened"])
    assert loaded["summary"]["changed"] == 4
    assert loaded["summary"]["ok"] == 4


def test_a_committed_write_reports_in_text(
    write_config: WriteConfig, fleet: dict[str, Any]
) -> None:
    plan = dry_hash(write_config, fleet, "--target", "a-alpha", "--expect-rows", "1")

    result = sql(
        write_config, "--write", "--target", "a-alpha", "--expect-rows", "1", "--plan", plan
    )
    text = click.unstyle(result.output)

    assert result.exit_code == ExitCode.SUCCESS, result.output
    assert "a-alpha  COMMITTED  1 row" in text


def test_guard_fails_on_third_stops_rest_exit_4(
    write_config: WriteConfig, fleet: dict[str, Any]
) -> None:
    fleet["c-gamma"] = WriteSession("c-gamma", count=3)

    result = real(write_config, fleet, "--expect-rows", "1")

    loaded = document(result)
    assert states(loaded) == [
        ("a-alpha", "COMMITTED"),
        ("b-beta", "COMMITTED"),
        ("c-gamma", "GUARD_FAILED"),
        ("d-delta", "NOT_ATTEMPTED"),
    ]
    assert loaded["results"][2]["changed"] is False
    assert "c-gamma" in loaded["results"][3]["error"]["message"]
    assert fleet["d-delta"].calls == []
    assert fleet["d-delta"].closes == 1
    assert loaded["exit_code"] == ExitCode.PARTIAL
    assert exit_of(result) == ExitCode.PARTIAL


def test_first_target_fails_exit_1(write_config: WriteConfig, fleet: dict[str, Any]) -> None:
    fleet["a-alpha"] = WriteSession("a-alpha", count=2)

    result = real(write_config, fleet, "--expect-rows", "1")

    loaded = document(result)
    assert states(loaded) == [
        ("a-alpha", "GUARD_FAILED"),
        ("b-beta", "NOT_ATTEMPTED"),
        ("c-gamma", "NOT_ATTEMPTED"),
        ("d-delta", "NOT_ATTEMPTED"),
    ]
    assert loaded["exit_code"] == ExitCode.FAILURE


def test_a_statement_error_stops_a_real_run(
    write_config: WriteConfig, fleet: dict[str, Any]
) -> None:
    fleet["b-beta"] = WriteSession(
        "b-beta", error=DriverError("ORA-00942: table or view does not exist", code="ORA-00942")
    )

    loaded = document(real(write_config, fleet, "--expect-rows", "1"))

    assert states(loaded) == [
        ("a-alpha", "COMMITTED"),
        ("b-beta", "ERROR"),
        ("c-gamma", "NOT_ATTEMPTED"),
        ("d-delta", "NOT_ATTEMPTED"),
    ]
    assert loaded["results"][1]["error"]["code"] == "ORA-00942"
    assert loaded["exit_code"] == ExitCode.PARTIAL


def test_a_target_that_did_not_connect_refuses_a_real_run(
    write_config: WriteConfig, fleet: dict[str, Any]
) -> None:
    """The write cannot finish everywhere, and the tool knows it before it
    runs anything, so it commits nowhere."""
    fleet["b-beta"] = DriverError("ORA-12541: no listener", code="ORA-12541")

    result = real(write_config, fleet, "--expect-rows", "1")

    assert exit_of(result) == ExitCode.ABORTED, result.output
    error = document(result)["error"]
    assert error["category"] == "policy"
    assert "b-beta" in error["message"]
    assert "ORA-12541" in error["message"]
    assert "a-alpha" not in error["message"]
    assert all(session.calls == [] for session in fleet["opened"])
    assert all(session.closes == 1 for session in fleet["opened"])


def test_a_dry_run_reports_a_target_that_did_not_connect(
    write_config: WriteConfig, fleet: dict[str, Any]
) -> None:
    fleet["b-beta"] = DriverError("ORA-12541: no listener", code="ORA-12541")

    loaded = document(
        sql(write_config, "--write", "--dry-run", *ALL, "--expect-rows", "1", json_out=True)
    )

    assert states(loaded) == [
        ("a-alpha", "ROLLED_BACK"),
        ("b-beta", "ERROR"),
        ("c-gamma", "ROLLED_BACK"),
        ("d-delta", "ROLLED_BACK"),
    ]


@pytest.mark.usefixtures("terminal")
def test_a_refused_typed_password_refuses_a_real_run(
    write_config: WriteConfig, fleet: dict[str, Any], tmp_path: Path
) -> None:
    """A target the lockout guard left alone did not connect either."""
    config = CONFIG.replace(
        "  run_as: { username: dba_alpha, auth: { method: env, password_env: DBA_ALPHA_PW } }\n",
        "  run_as: { username: dba_alpha, auth: prompt }\n",
    )
    statement = tmp_path / "update.sql"
    statement.write_text(UPDATE, encoding="utf-8")
    fleet["d-delta"] = refused_login()

    result = sql(
        write_config,
        "--write",
        *ALL,
        "--expect-rows",
        "1",
        "--plan",
        "0" * 12,
        "--file",
        str(statement),
        "--confirm",
        statement=None,
        config=config,
        json_out=True,
    )

    assert exit_of(result) == ExitCode.ABORTED, result.output
    error = document(result)["error"]
    assert error.get("code") != "SOPULI-20011"
    assert "d-delta" in error["message"]
    assert "a-alpha" in error["message"]
    assert all(session.calls == [] for session in fleet["opened"])


def test_a_target_of_another_product_does_not_refuse_a_real_run(
    write_config: WriteConfig, fleet: dict[str, Any]
) -> None:
    config = CONFIG + (
        "  - name: e-pg\n"
        "    type: postgresql\n"
        "    dsn: pg.example.com:5432\n"
        "    postgres: { database: acme }\n"
        "    labels: { fleet: acme }\n"
        "    admin: { username: sopuli_svc, auth: { method: env } }\n"
    )
    plan = dry_hash(write_config, fleet, *ALL, "--expect-rows", "1", config=config)

    result = sql(
        write_config,
        "--write",
        *ALL,
        "--expect-rows",
        "1",
        "--plan",
        plan,
        config=config,
        json_out=True,
    )

    loaded = document(result)
    assert states(loaded)[-1] == ("e-pg", "SKIPPED")
    assert [state for _, state in states(loaded)[:4]] == ["COMMITTED"] * 4
    assert loaded["exit_code"] == ExitCode.SUCCESS


#: The fleet with a PostgreSQL target, which `sql run` skips.
WITH_PG = CONFIG + (
    "  - name: e-pg\n"
    "    type: postgresql\n"
    "    dsn: pg.example.com:5432\n"
    "    postgres: { database: acme }\n"
    "    labels: { fleet: acme }\n"
    "    admin: { username: sopuli_svc, auth: { method: env } }\n"
)


def test_zero_rows_and_a_skipped_target_exit_0(
    write_config: WriteConfig, fleet: dict[str, Any]
) -> None:
    """Nothing failed and nothing changed: a skipped target does not make it partial."""
    for name in ORDER:
        fleet[name] = WriteSession(name, count=0)
    plan = dry_hash(write_config, fleet, *ALL, "--max-rows", "5", config=WITH_PG)

    result = sql(write_config, "--write", *ALL, "--max-rows", "5", "--plan", plan, config=WITH_PG)

    assert result.exit_code == ExitCode.SUCCESS, result.output


def test_every_target_skipped_exits_5(write_config: WriteConfig, fleet: dict[str, Any]) -> None:
    result = sql(
        write_config,
        "--write",
        "--dry-run",
        "--target",
        "e-pg",
        "--expect-rows",
        "1",
        config=WITH_PG,
    )

    assert result.exit_code == ExitCode.UNSUPPORTED_CAPABILITY, result.output


def test_a_dry_run_with_a_failing_target_offers_no_plan(
    write_config: WriteConfig, fleet: dict[str, Any]
) -> None:
    """The hint to run it is shown only where a real run could finish."""
    fleet["b-beta"] = WriteSession("b-beta", count=3)
    fleet["d-delta"] = DriverError("ORA-12541: no listener", code="ORA-12541")

    result = sql(write_config, "--write", "--dry-run", *ALL, "--expect-rows", "1")
    text = click.unstyle(result.output)

    assert "to run it" not in text
    assert "a real run would stop at b-beta" in text
    assert "b-beta (GUARD_FAILED)" in text
    assert "d-delta (ERROR)" in text
    assert "plan fingerprint:" in text

    loaded = document(
        sql(write_config, "--write", "--dry-run", *ALL, "--expect-rows", "1", json_out=True)
    )
    assert len(loaded["statement"]["fingerprint"]) == 12


def test_a_dry_run_with_a_skipped_target_still_offers_the_plan(
    write_config: WriteConfig, fleet: dict[str, Any]
) -> None:
    result = sql(write_config, "--write", "--dry-run", *ALL, "--expect-rows", "1", config=WITH_PG)

    assert "to run it, drop --dry-run" in click.unstyle(result.output)


class InterruptedSession(WriteSession):
    """A session whose statement is stopped by Ctrl-C."""

    def run_statement(self, statement: Statement, **options: Any) -> StatementResult:
        self.calls.append({"statement": statement, **options})
        raise KeyboardInterrupt


def test_an_interrupt_keeps_the_record_and_closes_every_session(
    write_config: WriteConfig, fleet: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ctrl-C on the second of three targets: the first committed, the second
    is unknown, the third never ran, and the operator is told so."""
    config = CONFIG.replace("    labels: { fleet: acme }\n", "", 1)  # d-delta left out
    plan = dry_hash(write_config, fleet, *ALL, "--expect-rows", "1", config=config)
    fleet["b-beta"] = InterruptedSession("b-beta")
    said: list[str] = []
    monkeypatch.setattr("sopuli.cli._echo_err", lambda text, **_: said.append(text))
    recorded: list[Any] = []
    real_results = sql_view_module.build_results

    def build_results(outcomes: Any) -> Any:
        recorded.extend(outcomes)
        return real_results(outcomes)

    monkeypatch.setattr("sopuli.output.sql_view.build_results", build_results)

    result = CliRunner().invoke(
        cli,
        [
            "--config",
            str(write_config(config)),
            "sql",
            "run",
            "--write",
            *ALL,
            "--expect-rows",
            "1",
            "--plan",
            plan,
        ],
        input=UPDATE,
    )

    # click turns the interrupt into its own abort, as for every verb.
    assert result.exit_code == 1, result.output
    assert "Aborted!" in result.output
    assert [(one.target, one.state) for one in recorded] == [
        ("a-alpha", "COMMITTED"),
        ("b-beta", "ERROR"),
        ("c-gamma", "NOT_ATTEMPTED"),
    ]
    assert recorded[1].error is not None
    assert "whether it committed is unknown" in recorded[1].error.message
    assert fleet["c-gamma"].calls == []
    text = click.unstyle("\n".join(said))
    assert "a-alpha  COMMITTED" in text
    assert "whether it committed is unknown" in text
    assert all(session.closes == 1 for session in fleet["opened"])


def test_confirm_without_write_is_a_usage_error(
    write_config: WriteConfig, fleet: dict[str, Any]
) -> None:
    result = sql(write_config, *ALL, "--confirm", statement="SELECT 1 FROM dual")

    assert result.exit_code == ExitCode.USAGE, result.output
    assert "--confirm" in result.output
    assert fleet["opened"] == []


def commit_failed() -> DriverError:
    error = DriverError("ORA-03113: end-of-file on communication channel", code="ORA-03113")
    error.commit_failed = True
    return error


def test_a_failed_commit_is_unknown_and_stops_the_run(
    write_config: WriteConfig, fleet: dict[str, Any]
) -> None:
    """The commit itself failed, so the first target may have changed: exit 4."""
    fleet["a-alpha"] = WriteSession("a-alpha", error=commit_failed())

    result = real(write_config, fleet, "--expect-rows", "1")

    loaded = document(result)
    assert states(loaded) == [
        ("a-alpha", "ERROR"),
        ("b-beta", "NOT_ATTEMPTED"),
        ("c-gamma", "NOT_ATTEMPTED"),
        ("d-delta", "NOT_ATTEMPTED"),
    ]
    error = loaded["results"][0]["error"]
    assert "whether it took effect is unknown" in error["message"]
    assert "ORA-03113" in error["message"]
    assert error["code"] == "ORA-03113"
    assert loaded["exit_code"] == ExitCode.PARTIAL


def test_an_interrupt_right_after_a_commit_keeps_it(
    write_config: WriteConfig, fleet: dict[str, Any]
) -> None:
    """Ctrl-C between two targets: the commit that returned is kept, and the
    next target, which never started, is not attempted."""
    from sopuli import sql_run as sql_run_module
    from sopuli.config.loading import build_config
    from sopuli.output.document import Error

    config = build_config(
        {
            "version": 1,
            "defaults": {"run_as": {"username": "dba_alpha", "auth": {"method": "prompt"}}},
            "targets": [
                {"name": name, "type": "oracle", "dsn": f"{name}.example.com:1521/ALPHA"}
                for name in ("a-alpha", "b-beta", "c-gamma")
            ],
        }
    )
    sessions: dict[str, Any] = {
        name: WriteSession(name) for name in ("a-alpha", "b-beta", "c-gamma")
    }
    connections = sql_run_module.connect_all(
        config,
        None,
        open_session=lambda target, _: sessions[target.name],
        finding=lambda error: Error(category="database", message=str(error)),
        attended=True,
        need_identity=True,
    )

    class Interrupting(list[Any]):
        def append(self, item: Any) -> None:
            super().append(item)
            if len(self) == 1:
                raise KeyboardInterrupt

    into = Interrupting()
    with pytest.raises(KeyboardInterrupt):
        sql_run_module.run_write(
            connections,
            classify(UPDATE),
            RowGuard(expect=1),
            commit=True,
            timeout_ms=1000,
            finding=lambda error: Error(category="database", message=str(error)),
            into=into,
        )

    assert [(one.target, one.state) for one in into] == [
        ("a-alpha", "COMMITTED"),
        ("b-beta", "NOT_ATTEMPTED"),
        ("c-gamma", "NOT_ATTEMPTED"),
    ]
    assert sessions["b-beta"].calls == []


def test_a_skipped_target_is_not_in_the_plan(
    write_config: WriteConfig, fleet: dict[str, Any]
) -> None:
    """It never runs, so it counts for neither `max_targets` nor
    `confirm_environments`."""
    config = WITH_PG.replace(
        "defaults:\n",
        "defaults:\n  safety: { max_targets: 4, confirm_environments: [prod] }\n",
    ).replace("  - name: e-pg\n", "  - name: e-pg\n    environment: prod\n")

    loaded = document(
        sql(
            write_config,
            "--write",
            "--dry-run",
            *ALL,
            "--expect-rows",
            "1",
            config=config,
            json_out=True,
        )
    )

    assert [unit["target"] for unit in loaded["plan"]["units"]] == ORDER
    assert loaded["plan"]["confirmation_required"] is False
    assert states(loaded)[-1] == ("e-pg", "SKIPPED")


def test_readonly_on_a_write_names_the_read_instead(
    write_config: WriteConfig, fleet: dict[str, Any]
) -> None:
    config = CONFIG.replace(
        "  - name: a-alpha\n", "  - name: a-alpha\n    safety: { readonly: true }\n"
    )

    for refused in (
        sql(write_config, "--write", "--dry-run", *ALL, "--expect-rows", "1", config=config),
        sql(write_config, "--write", "--dry-run", *ALL, "--expect-rows", "1", config=READONLY),
    ):
        hint = getattr(refused.exception, "hint", "") or ""
        assert "without --write" in hint
        assert "creds check" not in hint
        assert "lock status" not in hint


def test_a_dry_run_where_every_target_is_skipped_says_nothing_would_run(
    write_config: WriteConfig, fleet: dict[str, Any]
) -> None:
    result = sql(
        write_config,
        "--write",
        "--dry-run",
        "--target",
        "e-pg",
        "--expect-rows",
        "1",
        config=WITH_PG,
    )
    text = click.unstyle(result.output)

    assert "nothing would run" in text
    assert "to run it" not in text


def test_a_dry_run_says_the_real_run_will_ask(
    write_config: WriteConfig, fleet: dict[str, Any]
) -> None:
    text = click.unstyle(
        sql(write_config, "--write", "--dry-run", *ALL, "--expect-rows", "1", config=PROD).output
    )

    assert "to run it, drop --dry-run" in text
    assert "the real run will ask before it runs" in text
    assert "--confirm" in text


def test_max_result_rows_with_write_is_a_usage_error(
    write_config: WriteConfig, fleet: dict[str, Any]
) -> None:
    result = sql(
        write_config, "--write", "--dry-run", *ALL, "--expect-rows", "1", "--max-result-rows", "5"
    )

    assert result.exit_code == ExitCode.USAGE, result.output
    assert "--max-result-rows" in result.output
    assert fleet["opened"] == []


@pytest.mark.parametrize(("given", "said"), [(None, "matches"), ("0" * 12, "does not match")])
def test_plan_on_a_dry_run_is_compared(
    write_config: WriteConfig, fleet: dict[str, Any], given: str | None, said: str
) -> None:
    plan = given or dry_hash(write_config, fleet, *ALL, "--expect-rows", "1")

    result = sql(write_config, "--write", "--dry-run", *ALL, "--expect-rows", "1", "--plan", plan)

    assert result.exit_code == ExitCode.SUCCESS, result.output
    assert f"--plan {plan} {said} this dry run's fingerprint" in click.unstyle(result.output)
    loaded = document(
        sql(
            write_config,
            "--write",
            "--dry-run",
            *ALL,
            "--expect-rows",
            "1",
            "--plan",
            plan,
            json_out=True,
        )
    )
    assert any(f"--plan {plan} {said}" in one["message"] for one in loaded.get("diagnostics", []))


def test_zero_rows_rolled_back_changed_false(
    write_config: WriteConfig, fleet: dict[str, Any]
) -> None:
    for name in ORDER:
        fleet[name] = WriteSession(name, count=0)

    result = real(write_config, fleet, "--max-rows", "5")

    assert result.exit_code == ExitCode.SUCCESS, result.output
    loaded = document(result)
    assert states(loaded) == [(name, "ROLLED_BACK") for name in ORDER]
    assert all(entry["changed"] is False for entry in loaded["results"])
    assert loaded["summary"]["changed"] == 0


def test_a_session_user_that_is_the_service_account_refuses_the_write(
    write_config: WriteConfig, fleet: dict[str, Any]
) -> None:
    fleet["c-gamma"] = WriteSession("c-gamma")
    fleet["c-gamma"].user = "C##SOPULI_SVC"

    result = sql(write_config, "--write", "--dry-run", *ALL, "--expect-rows", "1", json_out=True)

    assert exit_of(result) == ExitCode.ABORTED, result.output
    assert document(result)["error"]["code"] == "SOPULI-20010"
    assert all(session.calls == [] for session in fleet["opened"])
    assert all(session.closed for session in fleet["opened"])


# ------------------------------------------------------------------ tier 1 ---

USER = os.environ.get("SOPULI_TEST_ORACLE_USER", "system")
PASSWORD = os.environ.get("SOPULI_TEST_ORACLE_PASSWORD", "sopuli-test")


@pytest.fixture
def scratch_table(live_oracle: Environment) -> Iterator[str]:
    """A throwaway table in the test user's schema, with two rows, dropped afterwards."""
    oracledb = pytest.importorskip("oracledb")
    name = f"SOPULI_WRITE_{uuid.uuid4().hex[:8].upper()}"
    connection = oracledb.connect(user=USER, password=PASSWORD, dsn=live_oracle.dsn)
    try:
        with connection.cursor() as cursor:
            cursor.execute(f"CREATE TABLE {name} (name VARCHAR2(20), flag NUMBER)")
            cursor.execute(f"INSERT INTO {name} VALUES ('audit', 0)")
            cursor.execute(f"INSERT INTO {name} VALUES ('trace', 0)")
        connection.commit()
        yield name
    finally:
        with contextlib.suppress(Exception), connection.cursor() as cursor:
            cursor.execute(f"DROP TABLE {name} PURGE")
        connection.close()


def test_a_dry_run_then_a_real_write_on_two_names_for_one_pdb(
    write_config: WriteConfig,
    live_oracle: Environment,
    scratch_table: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Tier 1. The dry run counts and rolls back; the real run with its
    fingerprint commits on the first name, and its guard fails on the second,
    where the first name's commit already changed the row."""
    oracledb = pytest.importorskip("oracledb")
    monkeypatch.setenv("DBA_ALPHA_PW", PASSWORD)
    config = (
        "version: 1\ndefaults:\n"
        f"  run_as: {{ username: {USER}, auth: {{ method: env, password_env: DBA_ALPHA_PW }} }}\n"
        "targets:\n"
        f"  - name: pdb-one\n    type: oracle\n    dsn: {live_oracle.dsn}\n"
        "    admin: { username: C##SOPULI_SVC, auth: { method: env } }\n"
        f"  - name: pdb-two\n    type: oracle\n    dsn: {live_oracle.dsn}\n"
        "    admin: { username: C##SOPULI_SVC, auth: { method: env } }\n"
    )
    update = f"UPDATE {scratch_table} SET flag = 1 WHERE name = 'audit' AND flag = 0\n"
    args = ("--write", "--target", "pdb-one", "--target", "pdb-two", "--expect-rows", "1")

    dry = sql(write_config, *args, "--dry-run", statement=update, config=config, json_out=True)
    loaded = document(dry)
    assert dry.exit_code == ExitCode.SUCCESS, dry.output
    assert states(loaded) == [("pdb-one", "ROLLED_BACK"), ("pdb-two", "ROLLED_BACK")]
    plan = loaded["statement"]["fingerprint"]

    wrong = sql(write_config, *args, "--plan", "0" * 12, statement=update, config=config)
    assert exit_of(wrong) == ExitCode.ABORTED, wrong.output

    done = sql(write_config, *args, "--plan", plan, statement=update, config=config, json_out=True)
    loaded = document(done)
    assert states(loaded) == [("pdb-one", "COMMITTED"), ("pdb-two", "GUARD_FAILED")]
    assert loaded["exit_code"] == ExitCode.PARTIAL

    connection = oracledb.connect(user=USER, password=PASSWORD, dsn=live_oracle.dsn)
    try:
        with connection.cursor() as cursor:
            cursor.execute(f"SELECT name, flag FROM {scratch_table} ORDER BY name")
            assert cursor.fetchall() == [("audit", 1), ("trace", 0)]
    finally:
        connection.close()
