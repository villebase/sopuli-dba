"""The config's warnings in the text output of every verb that loads it (#897).

Tier 0 (04-testing.md §4): in-process, no containers, no sockets. The warning
is SOPULI-W051, a ``VAULT_ADDR`` that names another server than the file's
``addr``: the case the warning exists for, and one an operator running a verb by
hand reads only in the text.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import pytest
from click.testing import CliRunner

from sopuli import cli as cli_module
from sopuli.cli import cli
from sopuli.exit_codes import ExitCode

CONFIG = """\
version: 1
vaults:
  vault-dev: { type: hashicorp, addr: "https://v.example.com" }
defaults:
  vault: vault-dev
  policy: app-standard
policies:
  app-standard:
    password:
      length: 24
      charset: alnum_safe
targets:
  - name: appdb-dev-alpha
    type: oracle
    dsn: db-dev.example.com:1521/alpha.pdb.example.com
    labels: { tenant: alpha }
"""


@pytest.fixture
def config(monkeypatch: pytest.MonkeyPatch, write_config: Callable[[str], Path]) -> Path:
    monkeypatch.setenv("VAULT_ADDR", "https://other.example.com")
    return write_config(CONFIG)


def test_a_verb_other_than_the_config_verbs_prints_the_warning(config: Path) -> None:
    result = CliRunner().invoke(cli, ["policy", "sample", "--config", str(config)])

    assert result.exit_code == ExitCode.SUCCESS, result.output
    assert "\n1 warning:\n" in result.stdout
    assert "https://other.example.com" in result.stdout


@pytest.mark.parametrize(
    "verb",
    [
        ["config", "show"],
        ["config", "show", "--resolved", "--select", "tenant=beta"],
        ["config", "validate"],
        ["target", "list"],
        ["target", "list", "--select", "tenant=beta"],
    ],
    ids=[
        "config-show",
        "config-show-nothing-matched",
        "config-validate",
        "target-list",
        "target-list-nothing-matched",
    ],
)
def test_the_config_verbs_print_it_once(config: Path, verb: list[str]) -> None:
    """They printed their own copy before the emitter printed one for every verb.

    Including where a selector matched nothing, which is when a warning about
    the file is worth reading."""
    result = CliRunner().invoke(cli, [*verb, "--config", str(config)])

    assert result.exit_code == ExitCode.SUCCESS, result.output
    assert result.stdout.count("1 warning:") == 1
    assert result.stdout.count("left over from other work") == 1


def test_config_validate_still_counts_the_warning_in_its_summary(config: Path) -> None:
    result = CliRunner().invoke(cli, ["config", "validate", "--config", str(config)])

    assert "ok: 1 target, 0 bindings, 1 warning" in result.stdout


def test_the_json_document_carries_it_and_the_text_does_not_leak_in(config: Path) -> None:
    result = CliRunner().invoke(
        cli, ["policy", "sample", "--output", "json", "--config", str(config)]
    )

    document = json.loads(result.stdout)
    assert [one["code"] for one in document["diagnostics"]] == ["SOPULI-W051"]
    assert "warnings_text" not in document


@pytest.mark.parametrize(
    "step",
    ["_policy_to_sample", "build_policy_section"],
    ids=["before-the-verb-reported", "after"],
)
def test_a_run_that_fails_prints_the_warning_on_stderr(
    config: Path, monkeypatch: pytest.MonkeyPatch, step: str
) -> None:
    """The run prints no text of its own, and the warning may be why it failed.

    Before the verb reported the warnings is the usual case: a verb reports them
    once its I/O is done, and a run that cannot reach the store stops first."""

    def broken(*args: object, **kwargs: object) -> None:
        raise RuntimeError("this step broke")

    monkeypatch.setattr(cli_module, step, broken)

    result = CliRunner().invoke(cli, ["policy", "sample", "--config", str(config)])

    assert result.exit_code != ExitCode.SUCCESS
    assert result.stdout == ""
    assert result.stderr.startswith("1 warning:\n")
    assert "https://other.example.com" in result.stderr
