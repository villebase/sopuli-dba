"""A MySQL account name typed on the command line (#1225).

Tier 0. A `profile:` or `role:` rule admits a name the file never held, so
the config cannot refuse one without a host. Each mutating `account` verb
refuses it at plan time, with exit 9, before anything connects.
"""

from __future__ import annotations

import json

import pytest
from click.testing import CliRunner, Result

from conftest import WriteConfig
from sopuli.cli import cli
from sopuli.exit_codes import ExitCode

CONFIG = """version: 1
targets:
  - name: mysql-dev
    type: mysql
    environment: dev
    dsn: mysql-dev.example.com:3306
    admin: { username: "sopuli_svc@%", auth: { method: env } }
personal_accounts:
  - profile: DEVELOPER
delivery:
  method: manual
  manual:
    force_expire: true
"""


def exit_of(result: Result) -> int:
    """The process's exit code. `CliRunner` calls `cli` without `main()`'s
    boundary, so a refusal arrives as the exception that carries it."""
    code = getattr(result.exception, "exit_code", None)
    return int(code) if code is not None else result.exit_code


@pytest.mark.parametrize("verb", ["suspend", "expire-password", "reset-password"])
def test_a_bare_name_is_refused_on_a_mysql_target(write_config: WriteConfig, verb: str) -> None:
    result = CliRunner().invoke(
        cli,
        ["--config", str(write_config(CONFIG)), "account", verb, "--account", "jdoe"]
        + ["--dry-run", "--output", "json"],
    )

    assert exit_of(result) == ExitCode.CONFIG_INVALID, result.output
    error = json.loads(result.output)["error"]
    assert error["message"] == "account 'jdoe' is not user@host, and target 'mysql-dev' is MySQL"
    assert "jdoe@%" in error["hint"]
