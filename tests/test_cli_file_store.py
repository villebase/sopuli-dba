"""A `file` store from the command line, `SOPULI-W070` (#1372, #1415) and
`SOPULI-W071` (#1430).

Real file stores with real age encryption, in a temporary directory; the
identity comes from a variable. The tests that open a store need the `file`
extra and skip without it; the rest do not.
"""

from __future__ import annotations

import json
import os
import secrets
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

import pytest
from click.testing import CliRunner

from sopuli import cli as cli_module
from sopuli.cli import cli
from sopuli.config import Config
from sopuli.config.model import MaterialRef, Vault
from sopuli.diagnostics import FILE_STORE_IN_USE, FILE_STORE_LEFTOVER, WARNINGS
from sopuli.exit_codes import ExitCode
from sopuli.invocation import Invocation
from sopuli.store.file._store import open_store

WriteConfig = Callable[[str], Path]

VARIABLE = "SOPULI_FILE_IDENTITY"

APPLICATION = """\
targets:
  - name: free-pdb
    type: oracle
    environment: dev
    dsn: "127.0.0.1:1521/FREEPDB1"
    admin: { username: SYSTEM, auth: { method: env } }
    oracle: { scope: pdb, container: FREEPDB1 }
policies:
  standard:
    password:
      length: 24
      charset: alnum_safe
      first_char: alpha
      require: { upper: 1, lower: 1, digit: 1, special: 1 }
accounts:
  - acme_app_user
secret_template: "acme-dev:acme/{env}/db#DB_CREDENTIALS/{account}"
policy: standard
"""


def file_store(name: str, directory: Path, *, locking: bool = True) -> str:
    return (
        f"  {name}:\n"
        "    type: file\n"
        f"    addr: {(directory / f'{name}.age').as_posix()}\n"
        f"    identity: {{ env: {VARIABLE} }}\n"
        + ("    locking: advisory-only\n" if locking else "")
    )


@pytest.fixture
def identity(monkeypatch: pytest.MonkeyPatch) -> str:
    pyrage = pytest.importorskip("pyrage", reason="the file extra is not installed")
    secret = str(pyrage.x25519.Identity.generate())
    monkeypatch.setenv(VARIABLE, secret)
    return secret


def run_json(config: Path, *args: str) -> tuple[int, dict[str, Any]]:
    result = CliRunner().invoke(cli, ["--config", str(config), "--output", "json", *args])
    return result.exit_code, cast(dict[str, Any], json.loads(result.stdout))


def warned(document: dict[str, Any]) -> list[str]:
    return [one["message"] for one in document["diagnostics"] if one["code"] == FILE_STORE_IN_USE]


def test_the_code_is_registered() -> None:
    assert FILE_STORE_IN_USE == "SOPULI-W070"
    assert "not for production" in WARNINGS[FILE_STORE_IN_USE]


def test_doctor_warns_once_for_each_file_store(
    write_config: WriteConfig, tmp_path: Path, identity: str
) -> None:
    config = write_config(
        "version: 1\nvaults:\n" + file_store("acme-dev", tmp_path) + file_store("acme-ci", tmp_path)
    )

    _, document = run_json(config, "doctor")

    assert sorted(warned(document)) == [
        'vault "acme-ci" is a file store, for local development and CI: it is not for production',
        'vault "acme-dev" is a file store, for local development and CI: it is not for production',
    ]
    assert [vault["status"] for vault in document["vaults"]] == ["ok", "ok"]


def test_doctor_prints_the_warning_in_the_text_view(
    write_config: WriteConfig, tmp_path: Path, identity: str
) -> None:
    config = write_config("version: 1\nvaults:\n" + file_store("acme-dev", tmp_path))

    result = CliRunner().invoke(cli, ["--config", str(config), "doctor"])

    assert 'vault "acme-dev" is a file store' in result.output


def _left_behind(directory: Path, *, minutes: int) -> Path:
    """A temporary file as a write names it, last written ``minutes`` ago."""
    path = directory / f".sopuli-{secrets.token_hex(8)}.tmp"
    path.write_bytes(b"ciphertext")
    stamp = time.time() - minutes * 60
    os.utime(path, (stamp, stamp))
    return path


def test_doctor_lists_a_temporary_file_a_stopped_run_left(
    write_config: WriteConfig, tmp_path: Path, identity: str
) -> None:
    """#1430: one SOPULI-W071 per file older than ten minutes, and nothing removed."""
    old = _left_behind(tmp_path, minutes=180)
    _left_behind(tmp_path, minutes=1)
    config = write_config("version: 1\nvaults:\n" + file_store("acme-dev", tmp_path))

    code, document = run_json(config, "doctor")

    found = [one for one in document["diagnostics"] if one["code"] == FILE_STORE_LEFTOVER]
    assert [one["message"] for one in found] == [
        f'vault "acme-dev": {old} is 3 hours old, a temporary file that a write of the '
        "store left behind: the run stopped before it finished, or could not remove the "
        "file. It is encrypted to the store's keys, and may hold a password version the "
        "store has pruned since. Remove it when no run is writing the store"
    ]
    assert found[0]["level"] == "warning"
    assert code == ExitCode.SUCCESS
    assert old.exists()


def test_doctor_prints_a_left_temporary_file_in_the_text_view(
    write_config: WriteConfig, tmp_path: Path, identity: str
) -> None:
    old = _left_behind(tmp_path, minutes=30)
    config = write_config("version: 1\nvaults:\n" + file_store("acme-dev", tmp_path))

    result = CliRunner().invoke(cli, ["--config", str(config), "doctor"])

    assert f"{old.name} is 30 minutes old" in result.output


def test_two_stores_in_one_directory_get_one_warning_per_file(
    write_config: WriteConfig, tmp_path: Path, identity: str
) -> None:
    """The file's name does not say which store wrote it, so it is reported
    once, naming both."""
    old = _left_behind(tmp_path, minutes=60)
    config = write_config(
        "version: 1\nvaults:\n" + file_store("acme-dev", tmp_path) + file_store("acme-ci", tmp_path)
    )

    _, document = run_json(config, "doctor")

    (message,) = [
        one["message"] for one in document["diagnostics"] if one["code"] == FILE_STORE_LEFTOVER
    ]
    assert message.startswith(f'vaults "acme-dev", "acme-ci": {old} is 60 minutes old')
    assert "encrypted to the keys of one of these stores" in message


def test_a_store_that_cannot_be_opened_is_looked_at_too(
    write_config: WriteConfig, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Listing the directory needs no key, so a store whose identity is not
    set still has its leftovers reported."""
    monkeypatch.delenv(VARIABLE, raising=False)
    old = _left_behind(tmp_path, minutes=60)
    config = write_config("version: 1\nvaults:\n" + file_store("acme-dev", tmp_path))

    _, document = run_json(config, "doctor")

    found = [one for one in document["diagnostics"] if one["code"] == FILE_STORE_LEFTOVER]
    assert [str(old) in one["message"] for one in found] == [True]


def test_the_leftover_code_is_registered() -> None:
    assert FILE_STORE_LEFTOVER == "SOPULI-W071"
    assert "Nothing removes it" in WARNINGS[FILE_STORE_LEFTOVER]


def test_creds_generate_stages_in_a_file_store(
    write_config: WriteConfig, tmp_path: Path, identity: str
) -> None:
    """UC-1 reaches the store: the pending password is staged as version 1 of
    the document, in a file that holds no password in clear."""
    config = write_config("version: 1\nvaults:\n" + file_store("acme-dev", tmp_path) + APPLICATION)

    code, document = run_json(config, "creds", "generate", "--offline")

    assert code == ExitCode.SUCCESS
    assert len(warned(document)) == 1
    raw = (tmp_path / "acme-dev.age").read_bytes()
    assert raw.startswith(b"age-encryption.org/v1")
    # Decrypted with the run's own identity: one version, holding a pending
    # password and no current one yet.
    store = open_store(_vault("acme-dev", tmp_path), env={VARIABLE: identity})
    # The document, and the advisory lock record the run took on it.
    assert store.list("") == ("acme/dev/db", "locks/acme/dev/db")
    stored = store.read("acme/dev/db")
    assert stored is not None
    assert stored.version == 1
    staged = json.dumps(stored.data)
    assert '"pending"' in staged
    assert '"current"' not in staged


def test_a_changing_command_needs_advisory_only_locking(
    write_config: WriteConfig,
    tmp_path: Path,
    identity: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The store has no compare-and-set, so the lock refuses it unless the
    store says `locking: advisory-only` (#1415, decision 4). Through `main`,
    which maps the refusal onto its exit code."""
    config = write_config(
        "version: 1\nvaults:\n" + file_store("acme-dev", tmp_path, locking=False) + APPLICATION
    )
    monkeypatch.setattr(
        sys, "argv", ["sopuli", "--config", str(config), "creds", "generate", "--offline"]
    )

    with pytest.raises(SystemExit) as exited:
        cli_module.main()

    assert exited.value.code == ExitCode.UNSUPPORTED_CAPABILITY
    assert "has no compare-and-set" in capsys.readouterr().err
    assert not (tmp_path / "acme-dev.age").exists()


def _vault(name: str, directory: Path, kind: str = "file") -> Vault:
    return Vault(
        name=name,
        type=kind,
        addr=str(directory / f"{name}.age"),
        identity=MaterialRef(kind="env", location=VARIABLE),
    )


def test_opening_stores_warns_once_per_file_store(tmp_path: Path, identity: str) -> None:
    """Each command opens its stores through `_stores_for`, often more than once
    in a run; the warning is added the first time a store is opened."""
    config = cast(Config, type("Config", (), {"vaults": [_vault("acme-dev", tmp_path)]})())
    run = Invocation()

    cli_module._stores_for({"acme-dev"}, config, run=run)
    cli_module._stores_for({"acme-dev"}, config, run=run)

    assert [one.code for one in run.document.diagnostics] == [FILE_STORE_IN_USE]


def test_another_store_type_does_not_warn(tmp_path: Path) -> None:
    run = Invocation()

    cli_module._warn_if_file_store(_vault("vault-x", tmp_path, kind="hashicorp"), run)

    assert run.document.diagnostics == []
