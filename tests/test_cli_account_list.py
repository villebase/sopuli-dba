"""`sopuli account list` through the CLI, against the tier-1 database.

The view's rendering is tested in `test_account_list.py`. This checks the
command's wiring: that what the command finds reaches the text output and the
run document both.

The listed account does not exist, so the tests create and drop nothing.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import click
import pytest
from click.testing import CliRunner

from conftest import WriteConfig
from oracle_harness import Environment
from sopuli.cli import cli
from sopuli.config.targets import ADMIN_PASSWORD_ENV
from sopuli.diagnostics import NO_RESET_JOURNAL, RESET_JOURNAL_UNREAD
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


def test_a_run_where_no_target_answered_prints_no_journal_note(
    write_config: WriteConfig, oracle_client: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With no target answering there is no `RESET_AT` to explain, and a note
    about the journal would point the reader away from the unreachable target.
    The document still says no journal is declared, because that is still true.

    Port 1 on loopback has nothing listening, so the refusal is immediate.
    """
    monkeypatch.setenv(ADMIN_PASSWORD_ENV, "unused")
    config = str(write_config(NO_JOURNAL.format(dsn="127.0.0.1:1/NOPE", user="system")))
    runner = CliRunner()

    text = runner.invoke(cli, ["--config", config, "account", "list"])
    document = runner.invoke(cli, ["--config", config, "--output", "json", "account", "list"])

    assert text.exit_code == ExitCode.PARTIAL, text.output
    assert "reset_records" not in text.output
    found = json.loads(document.output)
    assert NO_RESET_JOURNAL in [one["code"] for one in found["diagnostics"]]


#: A journal in the tier-1 Vault, on a mount of this module's own.
JOURNALLED = (
    NO_JOURNAL
    + """
vaults:
  vault-dev:
    type: hashicorp
    addr: {addr}
    mount: {mount}
    kv_version: 2
    auth:
      method: token

reset_records:
  vault: vault-dev
  prefix: sopuli/personal-resets
"""
)


@pytest.fixture
def journalled(
    write_config: WriteConfig,
    live_oracle: Environment,
    vault_stack: Any,
    private_mount: str,
    monkeypatch: pytest.MonkeyPatch,
) -> str:
    monkeypatch.setenv(
        ADMIN_PASSWORD_ENV, os.environ.get("SOPULI_TEST_ORACLE_PASSWORD", "sopuli-test")
    )
    monkeypatch.delenv("SOPULI_VAULT_TOKEN", raising=False)
    user = os.environ.get("SOPULI_TEST_ORACLE_USER", "system")
    written = JOURNALLED.format(
        dsn=live_oracle.dsn, user=user, addr=vault_stack.addr, mount=private_mount
    )
    return str(write_config(written))


def _codes(output: str) -> list[str]:
    return [one["code"] for one in json.loads(output)["diagnostics"]]


def test_a_journal_with_no_record_is_silent(
    journalled: str, vault_stack: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Nobody has reset the account through this tool, which is not a finding."""
    monkeypatch.setenv("VAULT_TOKEN", vault_stack.token)
    runner = CliRunner()

    text = runner.invoke(cli, ["--config", journalled, "account", "list"])
    document = runner.invoke(cli, ["--config", journalled, "--output", "json", "account", "list"])

    assert text.exit_code == ExitCode.SUCCESS, text.output
    assert "reset journal" not in text.output
    assert RESET_JOURNAL_UNREAD not in _codes(document.output)


def test_a_refused_token_is_said_with_the_stores_error(
    journalled: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A revoked token left RESET_AT `-` on every row with nothing saying why,
    which reads as "nobody was reset" (#929)."""
    monkeypatch.setenv("VAULT_TOKEN", "acme-revoked-token")
    runner = CliRunner()

    text = runner.invoke(cli, ["--config", journalled, "account", "list"])
    document = runner.invoke(cli, ["--config", journalled, "--output", "json", "account", "list"])

    assert text.exit_code == ExitCode.SUCCESS, text.output
    note = click.unstyle(text.output)
    assert "the reset journal in store 'vault-dev' could not be read for 1 account" in note
    assert "the store refused this token" in note
    found = json.loads(document.output)["diagnostics"]
    unread = [one for one in found if one["code"] == RESET_JOURNAL_UNREAD]
    assert len(unread) == 1
    assert "the store refused this token" in unread[0]["message"]


def test_a_journal_that_cannot_be_opened_does_not_fail_the_listing(
    journalled: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """With no token anywhere, the store cannot be opened. The listing used to
    fail with exit 9 over its history column (#929).

    The home directory is an empty one, so no `~/.vault-token` supplies a token.
    """
    monkeypatch.delenv("VAULT_TOKEN", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    runner = CliRunner()

    text = runner.invoke(cli, ["--config", journalled, "account", "list"])
    document = runner.invoke(cli, ["--config", journalled, "--output", "json", "account", "list"])

    assert text.exit_code == ExitCode.SUCCESS, text.output
    assert "no token" in click.unstyle(text.output)
    assert RESET_JOURNAL_UNREAD in _codes(document.output)
