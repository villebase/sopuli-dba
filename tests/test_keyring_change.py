"""`sopuli keyring set` and `keyring delete` (#1417, decision 3).

Tier 0, against a fake `keyring` library, as `tests/test_os_keyring.py` is.
"""

from __future__ import annotations

import io
import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import jsonschema
import pytest
from click.testing import CliRunner

from conftest import WriteConfig
from sopuli import invocation, os_keyring
from sopuli.cli import cli
from sopuli.config.discovery import CONFIG_ENV, discover
from sopuli.config.errors import ArgumentError
from sopuli.config.loading import build_config
from sopuli.config.model import Config
from sopuli.exit_codes import ExitCode
from sopuli.keyring_change import check_name, delete_entry, read_value, set_entry
from sopuli.keyring_survey import named_anywhere
from sopuli.output.document import SCHEMA_VERSION
from sopuli.safety import RefusedError
from sopuli.secrets import Secret

WINDOWS = "keyring.backends.Windows"
SCHEMA = (
    Path(__file__).parent.parent / "docs" / "schemas" / f"sopuli-run-{SCHEMA_VERSION}.schema.json"
)


class Backend:
    priority = 5

    def __init__(self, **entries: str) -> None:
        self.entries = dict(entries)
        self.writes = 0

    def get_password(self, service: str, user: str) -> str | None:
        assert service == "sopuli"
        return self.entries.get(user)

    def set_password(self, service: str, user: str, value: str) -> None:
        assert service == "sopuli"
        self.writes += 1
        self.entries[user] = value

    def delete_password(self, service: str, user: str) -> None:
        assert service == "sopuli"
        self.writes += 1
        del self.entries[user]


Backend.__module__ = WINDOWS


class Library:
    def __init__(self, found: Any) -> None:
        self.found = found

    def get_keyring(self) -> Any:
        return self.found


@pytest.fixture
def keyring(monkeypatch: pytest.MonkeyPatch) -> Backend:
    found = Backend()
    monkeypatch.setattr(os_keyring, "loader", lambda: Library(found))
    return found


VAULTS = {
    "vault-dev": {
        "type": "hashicorp",
        "addr": "https://vault-dev.example.com",
        "auth": {"method": "token", "token": {"keyring": "vault-dev"}},
    }
}


def config() -> Config:
    return build_config({"version": 1, "vaults": VAULTS})


# ------------------------------------------------------------------- set ---


def test_a_new_entry_is_added(keyring: Backend) -> None:
    change = set_entry("vault-dev", Secret("hvs.one"), config=None, replace=False, dry_run=False)

    assert keyring.entries == {"vault-dev": "hvs.one"}
    assert change.changed
    assert change.report.entries[0].action == "add"


def test_the_same_value_again_changes_nothing(keyring: Backend) -> None:
    """Invariant 9: the second run reports `unchanged` and does not write."""
    keyring.entries["vault-dev"] = "hvs.one"

    change = set_entry("vault-dev", Secret("hvs.one"), config=None, replace=False, dry_run=False)

    assert not change.changed
    assert keyring.writes == 0
    assert change.report.entries[0].action == "unchanged"


def test_a_different_value_needs_replace(keyring: Backend) -> None:
    keyring.entries["vault-dev"] = "hvs.old"

    with pytest.raises(RefusedError) as caught:
        set_entry("vault-dev", Secret("hvs.new"), config=None, replace=False, dry_run=False)

    assert "--replace" in str(caught.value)
    assert "hvs.old" not in str(caught.value)
    assert keyring.entries == {"vault-dev": "hvs.old"}


def test_replace_replaces(keyring: Backend) -> None:
    keyring.entries["vault-dev"] = "hvs.old"

    change = set_entry("vault-dev", Secret("hvs.new"), config=None, replace=True, dry_run=False)

    assert keyring.entries == {"vault-dev": "hvs.new"}
    assert change.report.entries[0].action == "replace"


def test_a_dry_run_writes_nothing_and_warns_about_replace(keyring: Backend) -> None:
    keyring.entries["vault-dev"] = "hvs.old"

    change = set_entry("vault-dev", Secret("hvs.new"), config=None, replace=False, dry_run=True)

    assert keyring.writes == 0
    assert not change.changed
    assert change.report.entries[0].applied is False
    assert [one.level for one in change.diagnostics] == ["warning"]


def test_an_entry_the_config_does_not_name_gets_a_note(keyring: Backend) -> None:
    named = set_entry("vault-dev", Secret("x"), config=config(), replace=False, dry_run=True)
    typo = set_entry("vault-dvo", Secret("x"), config=config(), replace=False, dry_run=True)

    assert named.diagnostics == ()
    assert named.report.entries[0].required_by == ("vaults.vault-dev.auth.token",)
    assert [one.level for one in typo.diagnostics] == ["info"]


def test_an_entry_named_only_in_a_delivery_block_counts_as_named() -> None:
    """Wider than `doctor`'s list: anything the config could read."""
    loaded = build_config(
        {
            "version": 1,
            "delivery": {
                "method": "vault_wrapped",
                "vault_wrapped": {"ttl": "15m"},
                "notify": {
                    "method": "webhook",
                    "webhook": {
                        "url": {"keyring": "ops-webhook"},
                        "template": "{account} on {target} has a new password waiting",
                    },
                },
            },
        }
    )

    assert named_anywhere(loaded, "ops-webhook")
    assert not named_anywhere(loaded, "other")


def test_a_target_admin_entry_counts_as_named() -> None:
    target = {
        "name": "cdb-root-dev",
        "type": "oracle",
        "dsn": "db-dev.example.com:1521/CDBDEV.pdb.example.com",
        "admin": {"username": "C##SOPULI_SVC", "auth": {"method": "keyring", "entry": "cdb"}},
    }

    assert named_anywhere(build_config({"version": 1, "targets": [target]}), "cdb")


# ---------------------------------------------------------------- delete ---


def test_delete_removes_and_a_second_delete_is_absent(keyring: Backend) -> None:
    keyring.entries["vault-dev"] = "hvs.one"

    first = delete_entry("vault-dev", config=None, dry_run=False)
    second = delete_entry("vault-dev", config=None, dry_run=False)

    assert keyring.entries == {}
    assert (first.changed, first.report.entries[0].action) == (True, "delete")
    assert (second.changed, second.report.entries[0].action) == (False, "absent")


def test_a_dry_run_delete_keeps_the_entry(keyring: Backend) -> None:
    keyring.entries["vault-dev"] = "hvs.one"

    change = delete_entry("vault-dev", config=None, dry_run=True)

    assert keyring.entries == {"vault-dev": "hvs.one"}
    assert change.report.entries[0].action == "delete"


# ----------------------------------------------------------- the value ---


def test_one_trailing_newline_is_removed_crlf_included() -> None:
    """PowerShell's pipe adds `\\r\\n`; a stored `\\r` would fail every login."""
    value = read_value("x", stdin=io.BytesIO(b"hvs.one\r\n"), terminal=False, ask=_never)

    assert value.reveal() == "hvs.one"


def test_an_empty_value_is_refused() -> None:
    with pytest.raises(ArgumentError):
        read_value("x", stdin=io.BytesIO(b"\n"), terminal=False, ask=_never)


def test_a_terminal_is_asked_twice() -> None:
    answers = iter(["hvs.one", "hvs.one"])

    value = read_value("x", stdin=io.BytesIO(), terminal=True, ask=lambda _: next(answers))

    assert value.reveal() == "hvs.one"


def test_two_different_answers_are_refused() -> None:
    answers = iter(["hvs.one", "hvs.two"])

    with pytest.raises(ArgumentError) as caught:
        read_value("x", stdin=io.BytesIO(), terminal=True, ask=lambda _: next(answers))

    assert "hvs" not in str(caught.value)


@pytest.mark.parametrize("name", ["", " vault-dev", "vault-dev "])
def test_a_name_no_config_could_write_is_refused(name: str) -> None:
    with pytest.raises(ArgumentError):
        check_name(name)


def _never(prompt: str) -> str:
    raise AssertionError(f"asked {prompt!r} with no terminal")


# ------------------------------------------------------------- the verbs ---


@pytest.fixture
def no_config(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """The search finds no file, as on a new machine.

    The real `discover`, searching an empty directory and home, so that a named
    file and `SOPULI_CONFIG` are still handled as a real run handles them.
    """
    monkeypatch.delenv("SOPULI_CONFIG", raising=False)
    monkeypatch.delenv("SOPULI_PROFILE", raising=False)

    def isolated(
        explicit: Sequence[Path] = (),
        *,
        env: Mapping[str, str] | None = None,
        optional: bool = False,
        **_: Any,
    ) -> tuple[Path, ...]:
        named = {key: value for key, value in (env or {}).items() if key == CONFIG_ENV}
        return discover(
            explicit,
            env=named,
            platform="linux",
            cwd=tmp_path,
            home=tmp_path / "home",
            optional=optional,
        )

    monkeypatch.setattr(invocation, "discover", isolated)


def test_set_runs_with_no_config_and_validates(keyring: Backend, no_config: None) -> None:
    result = CliRunner().invoke(
        cli, ["keyring", "set", "vault-dev", "--output", "json"], input="hvs.one\n"
    )

    assert result.exit_code == 0, result.output
    document = json.loads(result.output)
    jsonschema.validate(document, json.loads(SCHEMA.read_text(encoding="utf-8")))
    assert document["command"] == "keyring.set"
    assert document["summary"]["changed"] == 1
    assert "hvs.one" not in result.output
    assert keyring.entries == {"vault-dev": "hvs.one"}


def test_delete_runs_with_no_config_and_validates(keyring: Backend, no_config: None) -> None:
    result = CliRunner().invoke(cli, ["keyring", "delete", "vault-dev", "--output", "json"])

    assert result.exit_code == 0, result.output
    document = json.loads(result.output)
    jsonschema.validate(document, json.loads(SCHEMA.read_text(encoding="utf-8")))
    assert document["keyring"]["entries"][0]["action"] == "absent"
    assert document["summary"]["changed"] == 0


def test_the_refusal_without_replace_exits_8(keyring: Backend, no_config: None) -> None:
    keyring.entries["vault-dev"] = "hvs.old"

    result = CliRunner().invoke(cli, ["keyring", "set", "vault-dev"], input="hvs.new\n")

    assert getattr(result.exception, "exit_code", None) == ExitCode.ABORTED
    assert keyring.entries == {"vault-dev": "hvs.old"}


def test_a_named_config_must_still_exist(keyring: Backend, tmp_path: Path) -> None:
    """Asking for a file is not running without one."""
    missing = tmp_path / "nope.yaml"

    result = CliRunner().invoke(cli, ["keyring", "delete", "vault-dev", "--config", str(missing)])

    assert getattr(result.exception, "exit_code", None) == ExitCode.CONFIG_INVALID


def test_a_config_named_by_the_variable_must_still_exist(
    keyring: Backend, no_config: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(CONFIG_ENV, str(tmp_path / "nope.yaml"))

    result = CliRunner().invoke(cli, ["keyring", "delete", "vault-dev"])

    assert getattr(result.exception, "exit_code", None) == ExitCode.CONFIG_INVALID


@pytest.mark.parametrize("how", ["flag", "variable"])
def test_a_profile_asks_for_a_config(
    keyring: Backend, no_config: None, monkeypatch: pytest.MonkeyPatch, how: str
) -> None:
    """A profile lives in a config, so naming one is not running without one."""
    args = ["keyring", "delete", "vault-dev"]
    if how == "flag":
        args += ["--profile", "laptop"]
    else:
        monkeypatch.setenv("SOPULI_PROFILE", "laptop")

    result = CliRunner().invoke(cli, args)

    assert getattr(result.exception, "exit_code", None) == ExitCode.CONFIG_INVALID
    assert "no config file found" in str(result.exception)


def test_an_entry_with_an_empty_value_can_be_deleted(keyring: Backend) -> None:
    """A reader treats it as missing; delete must still remove it."""
    keyring.entries["vault-dev"] = ""

    change = delete_entry("vault-dev", config=None, dry_run=False)

    assert keyring.entries == {}
    assert change.report.entries[0].action == "delete"


def test_the_replace_warning_is_printed_with_the_warnings(
    keyring: Backend, no_config: None
) -> None:
    keyring.entries["vault-dev"] = "hvs.old"

    result = CliRunner().invoke(
        cli, ["keyring", "set", "vault-dev", "--dry-run", "--output", "json"], input="hvs.new\n"
    )

    document = json.loads(result.output)
    assert [one.get("code") for one in document["diagnostics"]] == ["SOPULI-W069"]
    assert keyring.entries == {"vault-dev": "hvs.old"}


def test_a_loaded_config_lists_who_needs_the_entry(
    keyring: Backend, write_config: WriteConfig
) -> None:
    path = write_config(
        "version: 1\n"
        "vaults:\n"
        "  vault-dev:\n"
        "    type: hashicorp\n"
        "    addr: https://vault-dev.example.com\n"
        "    auth: { method: token, token: { keyring: vault-dev } }\n"
    )

    result = CliRunner().invoke(
        cli,
        ["keyring", "set", "vault-dev", "--config", str(path), "--dry-run"],
        input="hvs.one\n",
    )

    assert result.exit_code == 0, result.output
    assert "would add" in result.output
    assert "vaults.vault-dev.auth.token" in result.output
    assert keyring.entries == {}


@pytest.mark.parametrize(
    "flag", [["--vault-addr", "https://vault.example.com"], ["--vault-token-file", "t"]]
)
def test_a_vault_option_is_refused(keyring: Backend, no_config: None, flag: list[str]) -> None:
    result = CliRunner().invoke(cli, ["keyring", "delete", "vault-dev", *flag])

    assert result.exit_code == 2
    assert "opens no vault" in result.output
