"""Ctrl-C part way through a run is an abort, as a declined question is (#1676).

Every verb: the run document is emitted with whatever the verb had recorded, the
process exits 8, and click's own "Aborted!" and exit 1 do not appear. Tier 0.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from click.testing import CliRunner

from conftest import WriteConfig
from sopuli.cli import cli
from sopuli.exit_codes import ExitCode
from test_cli_account_list_plan import CONFIG, PRODUCTS

DSN, ADMIN, _ = PRODUCTS["oracle"]
TEXT = CONFIG.format(product="oracle", dsn=DSN, admin=ADMIN, rules="  - accounts: [acme_jdoe]")


@pytest.fixture
def interrupted(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ctrl-C arrives as the first target is opened."""

    def open_session(*_: Any, **__: Any) -> Any:
        raise KeyboardInterrupt

    monkeypatch.setattr("sopuli.cli._open_session", open_session)


def suspend(write_config: WriteConfig, *output: str) -> Any:
    return CliRunner().invoke(
        cli,
        [
            "--config",
            str(write_config(TEXT)),
            *output,
            "account",
            "suspend",
            "--account",
            "acme_jdoe",
        ]
        + ["--confirm"],
    )


def test_ctrl_c_emits_the_run_document_and_exits_8(
    write_config: WriteConfig, interrupted: None
) -> None:
    result = suspend(write_config, "--output", "json")

    assert result.exit_code == ExitCode.ABORTED, result.output
    loaded = json.loads(result.stdout)
    assert loaded["command"] == "account.suspend"
    assert loaded["exit_code"] == ExitCode.ABORTED
    assert any("aborted before completion" in one["message"] for one in loaded["diagnostics"])
    assert loaded["plan"]["blast_radius"]["targets"] == 2
    assert "sopuli: aborted" in result.stderr


def test_ctrl_c_in_text_mode_exits_8_without_clicks_abort_line(
    write_config: WriteConfig, interrupted: None
) -> None:
    result = suspend(write_config)

    assert result.exit_code == ExitCode.ABORTED, result.output
    assert "sopuli: aborted" in result.stderr
    assert "Aborted!" not in result.output
    assert "Traceback" not in result.output
