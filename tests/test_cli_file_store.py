"""`SOPULI-W069`: every run that opens a `file` store says it is not for production.

Decision #1415, item 5. Real file stores with real age encryption, in a
temporary directory; the identity comes from a variable.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

import pytest
from click.testing import CliRunner

pytest.importorskip("pyrage", reason="the file extra is not installed")

from pyrage import x25519  # noqa: E402

from sopuli import cli as cli_module  # noqa: E402
from sopuli.cli import cli  # noqa: E402
from sopuli.config import Config  # noqa: E402
from sopuli.config.model import MaterialRef, Vault  # noqa: E402
from sopuli.diagnostics import FILE_STORE_IN_USE, WARNINGS  # noqa: E402
from sopuli.invocation import Invocation  # noqa: E402

WriteConfig = Callable[[str], Path]

VARIABLE = "SOPULI_FILE_IDENTITY"


def file_store(name: str, directory: Path) -> str:
    return (
        f"  {name}:\n"
        "    type: file\n"
        f"    addr: {(directory / f'{name}.age').as_posix()}\n"
        f"    identity: {{ env: {VARIABLE} }}\n"
        "    locking: advisory-only\n"
    )


@pytest.fixture
def identity(monkeypatch: pytest.MonkeyPatch) -> str:
    secret = str(x25519.Identity.generate())
    monkeypatch.setenv(VARIABLE, secret)
    return secret


def doctor_json(config: Path) -> dict[str, Any]:
    result = CliRunner().invoke(cli, ["--config", str(config), "--output", "json", "doctor"])
    return cast(dict[str, Any], json.loads(result.stdout))


def test_the_code_is_registered() -> None:
    assert FILE_STORE_IN_USE == "SOPULI-W069"
    assert "not for production" in WARNINGS[FILE_STORE_IN_USE]


def test_doctor_warns_once_for_each_file_store(
    write_config: WriteConfig, tmp_path: Path, identity: str
) -> None:
    config = write_config(
        "version: 1\nvaults:\n" + file_store("acme-dev", tmp_path) + file_store("acme-ci", tmp_path)
    )

    document = doctor_json(config)

    found = [one for one in document["diagnostics"] if one["code"] == FILE_STORE_IN_USE]
    assert sorted(one["message"] for one in found) == [
        'vault "acme-ci" is a file store, for local development and CI: it is not for production',
        'vault "acme-dev" is a file store, for local development and CI: it is not for production',
    ]
    assert all(one["level"] == "warning" for one in found)
    assert [vault["status"] for vault in document["vaults"]] == ["ok", "ok"]


def test_doctor_prints_the_warning_in_the_text_view(
    write_config: WriteConfig, tmp_path: Path, identity: str
) -> None:
    config = write_config("version: 1\nvaults:\n" + file_store("acme-dev", tmp_path))

    result = CliRunner().invoke(cli, ["--config", str(config), "doctor"])

    assert 'vault "acme-dev" is a file store' in result.output


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

    codes = [one.code for one in run.document.diagnostics]
    assert codes == [FILE_STORE_IN_USE]


def test_another_store_type_does_not_warn(tmp_path: Path) -> None:
    run = Invocation()

    cli_module._warn_if_file_store(_vault("vault-x", tmp_path, kind="hashicorp"), run)

    assert run.document.diagnostics == []
