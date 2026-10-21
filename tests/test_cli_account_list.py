"""`sopuli account list` through the CLI, against the tier-1 database.

The view's rendering is tested in `test_account_list.py`. This checks the
command's wiring: that what the command finds reaches the text output and the
run document both.

The listed account does not exist, so the test creates and drops nothing.
"""

from __future__ import annotations

import json
import os

import click
import pytest
from click.testing import CliRunner

from conftest import WriteConfig
from oracle_harness import Environment
from sopuli.cli import cli
from sopuli.config.targets import ADMIN_PASSWORD_ENV
from sopuli.diagnostics import NO_RESET_JOURNAL
from sopuli.exit_codes import ExitCode

#: No `reset_records:` block, so `SOPULI-W023` applies.
NO_JOURNAL = """version: 1

targets:
  - name: tier1-oracle
    type: oracle
    environment: dev
    dsn: "{dsn}"
    admin: {{ username: {user}, auth: {{ method: env }} }}

policies:
  personal-standard:
    password:
      length: 20

personal_accounts:
  - accounts: [acme_dev_nobody]
    policy: personal-standard
"""


@pytest.fixture
def no_journal(
    write_config: WriteConfig, live_oracle: Environment, monkeypatch: pytest.MonkeyPatch
) -> str:
    monkeypatch.setenv(
        ADMIN_PASSWORD_ENV, os.environ.get("SOPULI_TEST_ORACLE_PASSWORD", "sopuli-test")
    )
    user = os.environ.get("SOPULI_TEST_ORACLE_USER", "system")
    return str(write_config(NO_JOURNAL.format(dsn=live_oracle.dsn, user=user)))


def test_no_journal_is_said_in_the_text_and_in_the_document(no_journal: str) -> None:
    """`SOPULI-W023` reached `diagnostics[]` and never the text, so `RESET_AT`
    was `-` with nothing saying why (#921)."""
    runner = CliRunner()

    text = runner.invoke(cli, ["--config", no_journal, "account", "list"])
    document = runner.invoke(cli, ["--config", no_journal, "--output", "json", "account", "list"])

    assert text.exit_code == ExitCode.SUCCESS, text.output
    assert "no `reset_records:` block is declared" in click.unstyle(text.output)
    found = json.loads(document.output)
    assert NO_RESET_JOURNAL in [one["code"] for one in found["diagnostics"]]
