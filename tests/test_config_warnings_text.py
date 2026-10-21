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
from sopuli.output.document import Diagnostic
from sopuli.store import StoreError

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


FAILING_STEPS = pytest.mark.parametrize(
    "step",
    ["_policy_to_sample", "build_policy_section"],
    ids=["first-step", "last-step"],
)


def _break(monkeypatch: pytest.MonkeyPatch, step: str) -> None:
    def broken(*args: object, **kwargs: object) -> None:
        raise RuntimeError("this step broke")

    monkeypatch.setattr(cli_module, step, broken)


@FAILING_STEPS
def test_a_run_that_fails_prints_the_warning_on_stderr(
    config: Path, monkeypatch: pytest.MonkeyPatch, step: str
) -> None:
    """The run prints no text of its own, and the warning may be why it failed."""
    _break(monkeypatch, step)

    result = CliRunner().invoke(cli, ["policy", "sample", "--config", str(config)])

    assert result.exit_code != ExitCode.SUCCESS
    assert result.stdout == ""
    assert result.stderr.startswith("1 warning:\n")
    assert "https://other.example.com" in result.stderr


@FAILING_STEPS
def test_a_run_that_fails_carries_the_warning_in_its_document_once(
    config: Path, monkeypatch: pytest.MonkeyPatch, step: str
) -> None:
    """#918: a scheduler reads only the document, and W051 may be why the run failed.

    The first step fails before the verb has done anything of its own."""
    _break(monkeypatch, step)

    result = CliRunner().invoke(
        cli, ["policy", "sample", "--output", "json", "--config", str(config)]
    )

    document = json.loads(result.stdout)
    assert document["exit_code"] == result.exit_code != ExitCode.SUCCESS
    assert [one["code"] for one in document["diagnostics"]] == ["SOPULI-W051"]


#: An application, so that `lock status` has a lock to survey and opens a store.
WITH_AN_APPLICATION = f"""{CONFIG}applications:
  - name: acme
    accounts: [acme_web_user]
    secret_template: "apps/acme/{{target}}#password"
"""


def test_a_run_that_cannot_reach_the_store_carries_the_warning(
    monkeypatch: pytest.MonkeyPatch, write_config: Callable[[str], Path]
) -> None:
    """#918's own case: VAULT_ADDR names a vault the run cannot reach."""
    monkeypatch.setenv("VAULT_ADDR", "https://other.example.com")

    def unreachable(*args: object, **kwargs: object) -> None:
        raise StoreError("could not reach the store: refused by the test")

    monkeypatch.setattr(cli_module, "connect", unreachable)

    result = CliRunner().invoke(
        cli,
        ["lock", "status", "--output", "json", "--config", str(write_config(WITH_AN_APPLICATION))],
    )

    document = json.loads(result.stdout)
    assert document["error"]["message"] == "could not reach the store: refused by the test"
    assert [one["code"] for one in document["diagnostics"]] == ["SOPULI-W051"]


#: `--profile ci` widens `max_targets`, which the ratchet refuses with W039.
RATCHETED = f"""{CONFIG}profiles:
  ci:
    safety:
      max_targets: 200
"""


@pytest.mark.usefixtures("config")
def test_the_warnings_follow_the_ratchet_notes_and_precede_the_verbs_own(
    monkeypatch: pytest.MonkeyPatch, write_config: Callable[[str], Path]
) -> None:
    """The order 03-json-output.md §diagnostics gives.

    `config validate`'s install warnings are its own, and come last."""
    own = Diagnostic(level="warning", message="the verb's own")
    monkeypatch.setattr(cli_module, "install_diagnostics", lambda *a, **k: [own])
    path = write_config(
        RATCHETED.replace("defaults:\n", "defaults:\n  safety: { max_targets: 1 }\n")
    )

    result = CliRunner().invoke(
        cli, ["config", "validate", "--profile", "ci", "--output", "json", "--config", str(path)]
    )

    diagnostics = json.loads(result.stdout)["diagnostics"]
    assert [one.get("code", one["message"]) for one in diagnostics] == [
        "SOPULI-W039",
        "SOPULI-W051",
        "the verb's own",
    ]


#: Two layers with no delivery method in common: the file loads, and resolving
#: its settings fails.
DISJOINT = f"""{CONFIG}profiles:
  ci:
    safety:
      delivery:
        allowed_methods: [manual]
""".replace(
    "defaults:\n", "defaults:\n  safety: { delivery: { allowed_methods: [vault_wrapped] } }\n"
)


@pytest.mark.usefixtures("config")
def test_a_run_whose_settings_do_not_resolve_carries_the_warning(
    write_config: Callable[[str], Path],
) -> None:
    """The handler adds them itself, because `refresh_document` never saw the file."""
    path = str(write_config(DISJOINT))

    as_json = CliRunner().invoke(
        cli, ["policy", "sample", "--profile", "ci", "--output", "json", "--config", path]
    )
    as_text = CliRunner().invoke(cli, ["policy", "sample", "--profile", "ci", "--config", path])

    document = json.loads(as_json.stdout)
    assert document["exit_code"] == ExitCode.CONFIG_INVALID
    assert "resolves to nothing" in document["error"]["message"]
    assert [one["code"] for one in document["diagnostics"]] == ["SOPULI-W051"]
    assert as_text.stderr.startswith("1 warning:\n")
    assert "https://other.example.com" in as_text.stderr
