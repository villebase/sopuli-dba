"""`sopuli doctor` and the SQL Server driver against a live server.

Tier 1 (#1549). The image's certificate is self-signed, so the target sets
`trust_server_certificate: true`, which encrypts and checks nothing about the
server, and warns. The tool login holds only `ALTER ANY LOGIN`
(`02-mssql-privileges.md` §2.1).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from sopuli.cli import cli

pytest.importorskip("pyodbc")
pytest.importorskip("sopuli.driver.mssql.session")

PASSWORD_ENV = "SOPULI_TEST_MSSQL_DOCTOR_PASSWORD"


def _config(path: Path, live_mssql: Any) -> Path:
    path.write_text(
        f"""version: 1
targets:
  - name: tier1-mssql
    type: mssql
    dsn: "{live_mssql.dsn}"
    environment: dev
    mssql: {{ trust_server_certificate: true }}
    admin:
      username: "{live_mssql.tool_user}"
      auth: {{ method: env, password_env: {PASSWORD_ENV} }}
""",
        encoding="utf-8",
    )
    # The permission check refuses a config others can read (Linux CI).
    if sys.platform != "win32":
        path.chmod(0o600)
    return path


def _doctor(config: Path, password: str) -> dict[str, Any]:
    result = CliRunner().invoke(
        cli, ["--config", str(config), "--output", "json", "doctor"], env={PASSWORD_ENV: password}
    )
    document: dict[str, Any] = json.loads(result.output)
    return document


def test_doctor_reports_the_instance(live_mssql: Any, tmp_path: Path) -> None:
    document = _doctor(_config(tmp_path / "c.yaml", live_mssql), live_mssql.tool_password)

    (target,) = document["targets"]
    assert target["reachable"] is True
    scope = target["scope"]
    assert scope["type"] == "server"
    assert scope["open_mode"] == "READ WRITE"
    assert scope["encryption"]["method"] == "tls"
    assert scope["db_release"].split(".")[0].isdigit()
    assert any(warning["code"] == "SOPULI-W058" for warning in document.get("diagnostics", [])), (
        document.get("diagnostics")
    )


def test_a_wrong_password_is_the_servers_18456(live_mssql: Any, tmp_path: Path) -> None:
    document = _doctor(_config(tmp_path / "c.yaml", live_mssql), "not-the-password")

    (target,) = document["targets"]
    assert target["reachable"] is False
    assert target["error"]["code"] == "18456"
    assert target["error"]["category"] == "authentication"
