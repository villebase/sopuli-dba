"""`sopuli sql run` for reads, on fake sessions (UC-3). Tier 0.

The statement check, the runner and the run-as credential are tested on their
own in `tests/sql/`, `tests/driver/` and `tests/test_admin_run_as.py`. Here:
the command's text, its JSON and its exit codes.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import click
import pytest
from click.testing import CliRunner, Result
from jsonschema import Draft202012Validator

from conftest import WriteConfig
from sopuli import sql_run as sql_run_module
from sopuli.admin import PasswordPrompt
from sopuli.cli import cli
from sopuli.config.loading import build_config
from sopuli.driver.protocol import AuthenticationError, DriverError, StatementResult
from sopuli.exit_codes import ExitCode
from sopuli.output.document import SCHEMA_VERSION, Error
from sopuli.sql.statement import Statement

RUN_SCHEMA = json.loads(
    (
        Path(__file__).resolve().parents[1]
        / "docs"
        / "schemas"
        / f"sopuli-run-{SCHEMA_VERSION}.schema.json"
    ).read_text(encoding="utf-8")
)

RUN_AS = "  run_as: { username: dba_alpha, auth: { method: env, password_env: DBA_ALPHA_PW } }\n"

TARGETS = """targets:
  - name: prod-alpha
    type: oracle
    dsn: db-prod.example.com:1521/ALPHA
    admin: { username: C##SOPULI_SVC, auth: { method: env } }
  - name: qa-alpha
    type: oracle
    dsn: db-qa.example.com:1521/ALPHA
    admin: { username: C##SOPULI_SVC, auth: { method: env } }
"""

CONFIG = f"version: 1\ndefaults:\n{RUN_AS}{TARGETS}"

QUERY = "SELECT name, value FROM v$parameter WHERE name = 'open_cursors';\n"


def answer(
    columns: tuple[str, ...] = ("NAME", "VALUE"),
    rows: tuple[tuple[Any, ...], ...] = (("open_cursors", "300"),),
    *,
    truncated: bool = False,
) -> StatementResult:
    return StatementResult(columns, rows, len(rows), truncated, False, None)


class FakeSession:
    """A `StatementRunner` that answers from what the test gave it."""

    def __init__(
        self,
        target: str,
        *,
        result: StatementResult | None = None,
        error: Exception | None = None,
        user: str = "DBA_ALPHA",
        identity_error: Exception | None = None,
        user_error: Exception | None = None,
    ) -> None:
        self.target = target
        self.result = result or answer()
        self.error = error
        self.user = user
        self.identity_error = identity_error
        self.user_error = user_error
        self.calls: list[dict[str, Any]] = []
        self.closed = False
        #: The ``--as`` the opener was given, set by the fixture.
        self.as_user: str | None = None
        self.identity_reads = 0

    @property
    def connection_lost(self) -> bool:
        return False

    def session_user(self) -> str:
        if self.user_error is not None:
            raise self.user_error
        return self.user

    def database_identity(self) -> tuple[str, str]:
        self.identity_reads += 1
        if self.identity_error is not None:
            raise self.identity_error
        return "FREE", "FREEPDB1"

    def run_statement(self, statement: Statement, **options: Any) -> StatementResult:
        self.calls.append({"statement": statement, **options})
        if self.error is not None:
            raise self.error
        return self.result

    def close(self) -> None:
        self.closed = True


@pytest.fixture
def sessions(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """``_open_sql_session`` per target name. A value is a session, or an
    exception the opener raises. Every session opened is kept in ``opened``."""
    given: dict[str, Any] = {}
    opened: list[FakeSession] = []

    def open_session(target: Any, run: Any, config: Any, as_user: str | None) -> Any:
        one = given.get(target.name)
        if isinstance(one, Exception):
            raise one
        session = one if one is not None else FakeSession(target.name)
        session.as_user = as_user
        opened.append(session)
        return session

    monkeypatch.setattr("sopuli.cli._open_sql_session", open_session)
    monkeypatch.setenv("DBA_ALPHA_PW", "not-used-by-a-fake")
    given["opened"] = opened
    return given


class Asker:
    """A terminal that answers every question, and counts them."""

    def __init__(self) -> None:
        self.questions: list[str] = []

    def __call__(self, question: str) -> str:
        self.questions.append(question)
        return "typed-at-the-terminal"


@pytest.fixture
def terminal(monkeypatch: pytest.MonkeyPatch) -> Asker:
    """A run with somebody at the terminal, so `--as` may prompt."""
    asker = Asker()
    monkeypatch.setattr("sopuli.invocation.terminal_prompter", lambda _: PasswordPrompt(ask=asker))
    return asker


class FakeDriver:
    """Stands in for the Oracle driver, so `_open_sql_session` itself runs."""

    def __init__(self) -> None:
        self.credentials: list[Any] = []
        #: An exception to raise when a target of that name is connected.
        self.refuse: dict[str, Exception] = {}

    def connect(self, target: Any, credential: Any) -> FakeSession:
        self.credentials.append(credential)
        if target.name in self.refuse:
            raise self.refuse[target.name]
        return FakeSession(target.name)


@pytest.fixture
def driver(monkeypatch: pytest.MonkeyPatch) -> FakeDriver:
    fake = FakeDriver()
    monkeypatch.setattr("sopuli.cli.driver_for", lambda *_: fake)
    monkeypatch.setenv("DBA_ALPHA_PW", "from-the-environment")
    return fake


def sql_run(
    write_config: WriteConfig,
    *args: str,
    statement: str | None = QUERY,
    config: str = CONFIG,
    json_out: bool = False,
) -> Result:
    path = write_config(config)
    output = ["--output", "json"] if json_out else []
    return CliRunner().invoke(
        cli, ["--config", str(path), *output, "sql", "run", *args], input=statement
    )


def exit_of(result: Result) -> int | None:
    """The process's exit code. A refusal leaves the runner with the exception
    that `main` turns into it."""
    if result.exception is not None and not isinstance(result.exception, SystemExit):
        return getattr(result.exception, "exit_code", None)
    return result.exit_code


def document(result: Result) -> dict[str, Any]:
    loaded: dict[str, Any] = json.loads(result.output)
    Draft202012Validator(RUN_SCHEMA).validate(loaded)
    return loaded


def test_read_two_targets_same_columns_one_table(
    write_config: WriteConfig, sessions: dict[str, Any]
) -> None:
    result = sql_run(write_config)
    text = click.unstyle(result.output)

    assert result.exit_code == ExitCode.SUCCESS, result.output
    lines = text.splitlines()
    header = next(line for line in lines if line.startswith("TARGET"))
    assert header.split() == ["TARGET", "NAME", "VALUE"]
    assert any(line.split() == ["prod-alpha", "open_cursors", "300"] for line in lines)
    assert any(line.split() == ["qa-alpha", "open_cursors", "300"] for line in lines)
    assert "SELECT name, value FROM v$parameter WHERE name = 'open_cursors'" in text
    for session in sessions["opened"]:
        (call,) = session.calls
        assert call["commit"] is False
        assert call["guard"] is None
        assert call["max_rows"] == 100
        assert call["timeout_ms"] == 30_000
        assert session.closed


def test_read_different_columns_one_block_each(
    write_config: WriteConfig, sessions: dict[str, Any]
) -> None:
    sessions["qa-alpha"] = FakeSession("qa-alpha", result=answer(("N",), ((1,), (2,))))

    result = sql_run(write_config)
    text = click.unstyle(result.output)

    assert result.exit_code == ExitCode.SUCCESS, result.output
    assert "TARGET" not in text
    assert text.index("prod-alpha") < text.index("NAME") < text.index("qa-alpha")
    assert text.index("qa-alpha") < text.index("\n  N\n")
    assert "2 rows" in text


def test_one_target_down_others_shown_exit_4(
    write_config: WriteConfig, sessions: dict[str, Any]
) -> None:
    sessions["qa-alpha"] = DriverError(
        "ORA-12541: Cannot connect. No listener at host db-qa.example.com port 1521.",
        code="ORA-12541",
    )

    result = sql_run(write_config)
    text = click.unstyle(result.output)

    assert result.exit_code == ExitCode.PARTIAL, result.output
    assert "open_cursors" in text
    assert "qa-alpha" in text
    assert "ORA-12541" in text

    loaded = document(sql_run(write_config, json_out=True))
    by_target = {entry["target"]: entry for entry in loaded["results"]}
    assert by_target["prod-alpha"]["state"] == "READ"
    assert by_target["qa-alpha"]["state"] == "ERROR"
    assert by_target["qa-alpha"]["error"]["code"] == "ORA-12541"
    assert loaded["exit_code"] == ExitCode.PARTIAL


def test_a_statement_error_is_that_targets_error(
    write_config: WriteConfig, sessions: dict[str, Any]
) -> None:
    sessions["qa-alpha"] = FakeSession(
        "qa-alpha", error=DriverError("ORA-00942: table or view does not exist", code="ORA-00942")
    )

    result = sql_run(write_config)

    assert result.exit_code == ExitCode.PARTIAL, result.output
    assert "ORA-00942" in result.output
    assert all(session.closed for session in sessions["opened"])


def test_all_down_exit_1(write_config: WriteConfig, sessions: dict[str, Any]) -> None:
    for name in ("prod-alpha", "qa-alpha"):
        sessions[name] = DriverError(f"ORA-12541: no listener at {name}", code="ORA-12541")

    result = sql_run(write_config)

    assert result.exit_code == ExitCode.FAILURE, result.output


def test_non_oracle_target_refused_20006(
    write_config: WriteConfig, sessions: dict[str, Any]
) -> None:
    config = (
        f"version: 1\ndefaults:\n{RUN_AS}targets:\n"
        "  - name: pg-alpha\n"
        "    type: postgresql\n"
        "    dsn: pg.example.com:5432\n"
        "    postgres: { database: acme }\n"
        "    admin: { username: sopuli_svc, auth: { method: env } }\n"
    )

    result = sql_run(write_config, config=config, json_out=True)

    assert result.exit_code == ExitCode.UNSUPPORTED_CAPABILITY, result.output
    (entry,) = document(result)["results"]
    assert entry["state"] == "SKIPPED"
    assert entry["error"]["code"] == "SOPULI-20006"
    assert sessions["opened"] == []


def test_statement_from_stdin_and_file(
    write_config: WriteConfig, sessions: dict[str, Any], tmp_path: Path
) -> None:
    from_stdin = sql_run(write_config, "--target", "prod-alpha")
    assert from_stdin.exit_code == ExitCode.SUCCESS, from_stdin.output

    query = tmp_path / "query.sql"
    # With the byte order mark a Windows editor writes, which is not the statement's.
    query.write_text(
        "-- the open cursors\nselect value from v$parameter\n/\n", encoding="utf-8-sig"
    )
    from_file = sql_run(
        write_config, "--target", "prod-alpha", "--file", str(query), statement=None
    )
    assert from_file.exit_code == ExitCode.SUCCESS, from_file.output
    sent = sessions["opened"][-1].calls[0]["statement"]
    assert sent.text == "-- the open cursors\nselect value from v$parameter"


def test_empty_stdin_refused_exit_8(write_config: WriteConfig, sessions: dict[str, Any]) -> None:
    result = sql_run(write_config, statement="  \n", json_out=True)

    assert exit_of(result) == ExitCode.ABORTED, result.output
    assert document(result)["error"]["code"] == "SOPULI-20009"
    assert sessions["opened"] == []


def test_stdin_from_a_terminal_is_a_usage_error(
    write_config: WriteConfig, sessions: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("sopuli.cli.is_a_terminal", lambda _: True)

    result = sql_run(write_config)

    assert result.exit_code == ExitCode.USAGE, result.output
    assert "--file" in result.output


def test_write_keyword_without_write_flag_refused(
    write_config: WriteConfig, sessions: dict[str, Any]
) -> None:
    result = sql_run(write_config, statement="UPDATE acme_settings SET flag = 1", json_out=True)

    assert exit_of(result) == ExitCode.ABORTED, result.output
    error = document(result)["error"]
    assert error["code"] == "SOPULI-20009"
    assert "--write" in error["message"] + (error.get("hint") or "")
    assert sessions["opened"] == []


def test_no_run_as_and_no_as_exit_9(write_config: WriteConfig, sessions: dict[str, Any]) -> None:
    result = sql_run(write_config, config=f"version: 1\n{TARGETS}", json_out=True)

    assert exit_of(result) == ExitCode.CONFIG_INVALID, result.output
    assert "--as USER" in document(result)["error"]["hint"]
    assert sessions["opened"] == []


def test_run_as_equal_to_admin_refused_at_plan_time(
    write_config: WriteConfig, sessions: dict[str, Any], terminal: Asker
) -> None:
    result = sql_run(write_config, "--as", "c##sopuli_svc", json_out=True)

    assert exit_of(result) == ExitCode.ABORTED, result.output
    assert document(result)["error"]["code"] == "SOPULI-20010"
    assert sessions["opened"] == []


def test_session_user_is_service_account_refuses_all(
    write_config: WriteConfig, sessions: dict[str, Any]
) -> None:
    """A run-as name that logs in as the service account, such as through a
    proxy or a synonym-like alias, is caught from the session (UC-3 §2)."""
    sessions["qa-alpha"] = FakeSession("qa-alpha", user="C##SOPULI_SVC")

    result = sql_run(write_config, json_out=True)

    assert exit_of(result) == ExitCode.ABORTED, result.output
    assert document(result)["error"]["code"] == "SOPULI-20010"
    assert len(sessions["opened"]) == 2
    assert all(session.calls == [] for session in sessions["opened"])
    assert all(session.closed for session in sessions["opened"])


def test_json_validates_against_1_109(write_config: WriteConfig, sessions: dict[str, Any]) -> None:
    sessions["qa-alpha"] = FakeSession(
        "qa-alpha", result=answer(("N", "WHEN"), ((1, None), (2, "2026-11-24T10:00:00")))
    )

    loaded = document(sql_run(write_config, json_out=True))

    assert SCHEMA_VERSION == "1.109"
    assert loaded["command"] == "sql.run"
    assert loaded["statement"] == {
        "text": "SELECT name, value FROM v$parameter WHERE name = 'open_cursors'",
        "kind": "read",
    }
    by_target = {entry["target"]: entry for entry in loaded["results"]}
    qa = by_target["qa-alpha"]
    assert qa["account"] == "dba_alpha"
    assert qa["changed"] is False
    assert qa["columns"] == ["N", "WHEN"]
    assert qa["rows"] == [[1, None], [2, "2026-11-24T10:00:00"]]
    assert qa["row_count"] == 2
    assert qa["truncated"] is False
    assert loaded["summary"]["total"] == 2
    assert loaded["summary"]["ok"] == 2


def test_dry_run_reads_and_says_so(write_config: WriteConfig, sessions: dict[str, Any]) -> None:
    loaded = document(sql_run(write_config, "--dry-run", json_out=True))

    assert loaded["invocation"]["dry_run"] is True
    assert {entry["state"] for entry in loaded["results"]} == {"READ"}


def test_truncated_marked_in_text_and_json(
    write_config: WriteConfig, sessions: dict[str, Any]
) -> None:
    capped = answer(("N",), ((1,), (2,)), truncated=True)
    sessions["prod-alpha"] = FakeSession("prod-alpha", result=capped)

    result = sql_run(write_config, "--target", "prod-alpha", "--max-result-rows", "2")
    assert result.exit_code == ExitCode.SUCCESS, result.output
    assert "2 rows, truncated" in click.unstyle(result.output)
    assert sessions["opened"][-1].calls[0]["max_rows"] == 2

    sessions["prod-alpha"] = FakeSession("prod-alpha", result=capped)
    loaded = document(sql_run(write_config, "--target", "prod-alpha", json_out=True))
    (entry,) = loaded["results"]
    assert entry["truncated"] is True
    assert entry["row_count"] == 2


def test_timeout_is_given_in_milliseconds(
    write_config: WriteConfig, sessions: dict[str, Any]
) -> None:
    result = sql_run(write_config, "--target", "prod-alpha", "--timeout", "5")

    assert result.exit_code == ExitCode.SUCCESS, result.output
    assert sessions["opened"][-1].calls[0]["timeout_ms"] == 5000


def query_file(tmp_path: Path) -> str:
    path = tmp_path / "query.sql"
    path.write_text(QUERY, encoding="utf-8")
    return str(path)


def test_as_reaches_the_opener(
    write_config: WriteConfig, sessions: dict[str, Any], terminal: Asker, tmp_path: Path
) -> None:
    result = sql_run(
        write_config, "--as", "dba_beta", "--file", query_file(tmp_path), statement=None
    )

    assert result.exit_code == ExitCode.SUCCESS, result.output
    assert [session.as_user for session in sessions["opened"]] == ["dba_beta", "dba_beta"]


def test_as_with_the_statement_on_stdin_is_a_usage_error(
    write_config: WriteConfig, sessions: dict[str, Any]
) -> None:
    """`--as` asks at the terminal, and a piped statement leaves none (UC-3 §2)."""
    result = sql_run(write_config, "--as", "dba_beta")

    assert result.exit_code == ExitCode.USAGE, result.output
    assert "--file" in result.output
    assert sessions["opened"] == []


THREE_TARGETS = (
    f"{CONFIG}  - name: dev-alpha\n"
    "    type: oracle\n"
    "    dsn: db-dev.example.com:1521/ALPHA\n"
    "    admin: { username: C##SOPULI_SVC, auth: { method: env } }\n"
)


def test_as_asks_once_for_every_target(
    write_config: WriteConfig, driver: FakeDriver, terminal: Asker, tmp_path: Path
) -> None:
    result = sql_run(
        write_config,
        "--as",
        "dba_beta",
        "--file",
        query_file(tmp_path),
        statement=None,
        config=THREE_TARGETS,
    )

    assert result.exit_code == ExitCode.SUCCESS, result.output
    assert len(terminal.questions) == 1
    assert [credential.username for credential in driver.credentials] == ["dba_beta"] * 3


def test_an_env_run_as_is_flagged_low_assurance(
    write_config: WriteConfig, driver: FakeDriver
) -> None:
    loaded = document(sql_run(write_config, json_out=True))

    flagged = [one for one in loaded["diagnostics"] if one.get("code") == "SOPULI-W022"]
    assert [one["target"] for one in flagged] == ["prod-alpha", "qa-alpha"]
    assert (
        "the run-as credential came from the environment variable DBA_ALPHA_PW"
        in (flagged[0]["message"])
    )


def test_a_failed_session_read_is_that_targets_error(
    write_config: WriteConfig, sessions: dict[str, Any]
) -> None:
    broken = FakeSession(
        "qa-alpha", user_error=DriverError("ORA-03113: end-of-file", code="ORA-03113")
    )
    sessions["qa-alpha"] = broken

    loaded = document(sql_run(write_config, json_out=True))

    by_target = {entry["target"]: entry for entry in loaded["results"]}
    assert by_target["prod-alpha"]["state"] == "READ"
    assert by_target["qa-alpha"]["state"] == "ERROR"
    assert by_target["qa-alpha"]["error"]["code"] == "ORA-03113"
    assert broken.calls == []
    assert broken.closed
    assert loaded["exit_code"] == ExitCode.PARTIAL


def test_a_column_named_target_gets_a_block_per_target(
    write_config: WriteConfig, sessions: dict[str, Any]
) -> None:
    for name in ("prod-alpha", "qa-alpha"):
        sessions[name] = FakeSession(name, result=answer(("TARGET",), (("x",),)))

    text = click.unstyle(sql_run(write_config).output)

    assert text.count("TARGET") == 2
    assert "\nprod-alpha  1 row\n  TARGET\n  x\n" in text


def test_a_long_or_multiline_value_is_marked_in_text_and_whole_in_json(
    write_config: WriteConfig, sessions: dict[str, Any]
) -> None:
    long = "a" * 60
    rows = ((long,), ("first\nsecond",))
    sessions["prod-alpha"] = FakeSession("prod-alpha", result=answer(("V",), rows))

    text = click.unstyle(sql_run(write_config, "--target", "prod-alpha").output)
    assert "a" * 37 + "..." in text
    assert long not in text
    assert "first\\nsecond" in text

    sessions["prod-alpha"] = FakeSession("prod-alpha", result=answer(("V",), rows))
    loaded = document(sql_run(write_config, "--target", "prod-alpha", json_out=True))
    assert loaded["results"][0]["rows"] == [[long], ["first\nsecond"]]


def sent_text(sessions: dict[str, Any]) -> str:
    text: str = sessions["opened"][-1].calls[0]["statement"].text
    return text


def test_a_byte_order_mark_on_stdin_is_not_the_statement(
    write_config: WriteConfig, sessions: dict[str, Any]
) -> None:
    result = sql_run(write_config, "--target", "prod-alpha", statement="﻿SELECT 1 FROM dual")

    assert result.exit_code == ExitCode.SUCCESS, result.output
    assert sent_text(sessions) == "SELECT 1 FROM dual"


def test_a_non_ascii_literal_on_stdin_survives(
    write_config: WriteConfig, sessions: dict[str, Any]
) -> None:
    result = sql_run(
        write_config, "--target", "prod-alpha", statement="SELECT 'Räty ÅÖ' FROM dual\n"
    )

    assert result.exit_code == ExitCode.SUCCESS, result.output
    assert sent_text(sessions) == "SELECT 'Räty ÅÖ' FROM dual"


def test_stdin_that_is_not_utf8_is_a_usage_error(
    write_config: WriteConfig, sessions: dict[str, Any]
) -> None:
    path = write_config(CONFIG)
    result = CliRunner().invoke(
        cli, ["--config", str(path), "sql", "run"], input=b"SELECT '\xff' FROM dual"
    )

    assert result.exit_code == ExitCode.USAGE, result.output
    assert "not UTF-8" in result.output
    assert sessions["opened"] == []


def test_a_terminal_on_stdin_with_as_names_only_file(
    write_config: WriteConfig,
    sessions: dict[str, Any],
    terminal: Asker,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("sopuli.cli.is_a_terminal", lambda _: True)

    result = sql_run(write_config, "--as", "dba_beta")

    assert result.exit_code == ExitCode.USAGE, result.output
    assert "--file" in result.output
    assert "stdin" not in result.output


PROMPT_RUN_AS = (
    f"version: 1\ndefaults:\n  run_as: {{ username: dba_alpha, auth: prompt }}\n{TARGETS}"
)
KEYRING_RUN_AS = (
    "version: 1\ndefaults:\n"
    "  run_as: { username: dba_alpha, auth: { method: keyring, entry: dba-alpha } }\n"
    f"{TARGETS}"
)


def test_a_prompt_run_as_with_nobody_to_ask_is_refused_before_connecting(
    write_config: WriteConfig, sessions: dict[str, Any]
) -> None:
    result = sql_run(write_config, config=PROMPT_RUN_AS, json_out=True)

    assert exit_of(result) == ExitCode.ABORTED, result.output
    error = document(result)["error"]
    assert "keyring" in error["hint"]
    assert "SOPULI_DB_ADMIN_PASSWORD" not in error["hint"]
    assert sessions["opened"] == []


def test_a_keyring_run_as_without_the_extra_is_refused_before_connecting(
    write_config: WriteConfig, sessions: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("sopuli.safety.installed", lambda _: False)

    result = sql_run(write_config, config=KEYRING_RUN_AS, json_out=True)

    assert exit_of(result) == ExitCode.CONFIG_INVALID, result.output
    assert "keyring" in document(result)["error"]["message"]
    assert sessions["opened"] == []


def refused_login() -> AuthenticationError:
    return AuthenticationError(
        "ORA-01017: invalid credential or not authorized; logon denied", code="ORA-01017"
    )


def test_a_typed_password_refused_once_is_not_sent_to_other_targets(
    write_config: WriteConfig, driver: FakeDriver, terminal: Asker, tmp_path: Path
) -> None:
    """A mistyped `--as` password must not count against the account on every target."""
    driver.refuse["prod-alpha"] = refused_login()

    result = sql_run(
        write_config,
        "--as",
        "dba_beta",
        "--file",
        query_file(tmp_path),
        "--output",
        "json",
        statement=None,
        config=THREE_TARGETS,
    )

    loaded = document(result)
    states = {entry["target"]: entry["state"] for entry in loaded["results"]}
    assert states == {
        "prod-alpha": "ERROR",
        "qa-alpha": "NOT_ATTEMPTED",
        "dev-alpha": "NOT_ATTEMPTED",
    }
    assert len(driver.credentials) == 1
    reason = loaded["results"][1]["error"]["message"]
    assert "prod-alpha" in reason
    assert loaded["exit_code"] == ExitCode.FAILURE


def test_a_stored_password_refused_on_one_target_does_not_stop_the_others(
    write_config: WriteConfig, driver: FakeDriver
) -> None:
    driver.refuse["prod-alpha"] = refused_login()

    loaded = document(sql_run(write_config, json_out=True))

    states = [entry["state"] for entry in loaded["results"]]
    assert states == ["ERROR", "READ"]
    assert len(driver.credentials) == 2


def test_a_read_never_asks_for_the_database_identity(
    write_config: WriteConfig, sessions: dict[str, Any]
) -> None:
    result = sql_run(write_config)

    assert result.exit_code == ExitCode.SUCCESS, result.output
    assert [session.identity_reads for session in sessions["opened"]] == [0, 0]


def test_the_identity_is_read_where_it_is_needed() -> None:
    """A write's fingerprint needs it; a failed read is that target's error."""
    config = build_config(
        {
            "version": 1,
            "defaults": {"run_as": {"username": "dba_alpha", "auth": {"method": "prompt"}}},
            "targets": [
                {"name": name, "type": "oracle", "dsn": f"{name}.example.com:1521/ALPHA"}
                for name in ("prod-alpha", "qa-alpha")
            ],
        }
    )
    broken = FakeSession(
        "qa-alpha", identity_error=DriverError("ORA-03113: end-of-file", code="ORA-03113")
    )
    sessions: dict[str, Any] = {"prod-alpha": FakeSession("prod-alpha"), "qa-alpha": broken}

    connections = sql_run_module.connect_all(
        config,
        None,
        open_session=lambda target, _: sessions[target.name],
        finding=lambda error: Error(category="database", message=str(error)),
        attended=True,
        need_identity=True,
    )

    assert connections[0].identity == ("FREE", "FREEPDB1")
    assert connections[1].session is None
    assert connections[1].error is not None
    assert "ORA-03113" in connections[1].error.message
    assert broken.closed
    sql_run_module.close_all(connections)
