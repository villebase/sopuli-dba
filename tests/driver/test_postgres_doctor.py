"""`sopuli doctor` and the PostgreSQL driver against the tier-1 `postgres` service.

Tier 1. The service has no TLS, so the targets here set `sslmode: disable`, and
the encryption the run reports is `none`.
"""

from __future__ import annotations

import json
import os
import sys
import uuid
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from sopuli.cli import cli
from sopuli.config.model import ExpandedTarget, Runtime, Target, TargetPostgres
from sopuli.driver.protocol import Credential, DriverContext
from sopuli.secrets import Secret

PASSWORD_ENV = "SOPULI_TEST_POSTGRES_DOCTOR_PASSWORD"


def _config(path: Path, dsn: str, user: str) -> Path:
    """No `vaults:` block, for `test_oracle_doctor.py`'s reason: `doctor` fails on
    a declared store it cannot reach, and these tests bind no account."""
    path.write_text(
        f"""
version: 1
targets:
  - name: tier1-postgres
    type: postgresql
    dsn: "{dsn}"
    environment: dev
    postgres: {{ sslmode: disable }}
    admin:
      username: {user}
      auth: {{ method: env, password_env: {PASSWORD_ENV} }}
""".lstrip(),
        encoding="utf-8",
    )
    if sys.platform != "win32":
        path.chmod(0o600)
    return path


@pytest.fixture
def runner(live_postgres: Any, monkeypatch: pytest.MonkeyPatch) -> CliRunner:
    """The admin password reaches the tool through the environment (invariant 1)."""
    monkeypatch.setenv(PASSWORD_ENV, live_postgres.password)
    return CliRunner()


def _doctor(runner: CliRunner, config: Path, *extra: str) -> Any:
    return runner.invoke(cli, ["--config", str(config), *extra, "doctor"])


def test_doctor_reaches_the_cluster_and_reports_what_it_is(
    runner: CliRunner, live_postgres: Any, tmp_path: Path
) -> None:
    config = _config(tmp_path / "doctor.yaml", live_postgres.dsn, live_postgres.user)

    result = _doctor(runner, config, "--output", "json")

    assert result.exit_code == 0, result.output
    (entry,) = json.loads(result.stdout)["targets"]
    assert entry["reachable"] is True
    scope = entry["scope"]
    assert scope["type"] == "cluster"
    assert scope["container"] is None
    assert scope["open_mode"] == "READ WRITE"
    assert scope["read_write"] is True
    assert scope["db_version"], "the version the server reported"
    assert scope["capabilities"] == []
    assert scope["encryption"]["method"] == "none"
    assert scope["encryption"]["protocol"] == "tcp"


def test_doctor_prints_the_postgresql_client_lines(
    runner: CliRunner, live_postgres: Any, tmp_path: Path
) -> None:
    config = _config(tmp_path / "doctor.yaml", live_postgres.dsn, live_postgres.user)

    result = _doctor(runner, config)

    assert result.exit_code == 0, result.output
    assert "  psycopg" in result.output
    assert "  libpq" in result.output
    assert "  require_auth" in result.output
    row = next(line for line in result.output.splitlines() if line.startswith("tier1-postgres "))
    assert row.split()[1:5] == ["yes", "cluster", "-", "READ"]


def test_a_wrong_admin_password_is_28p01_with_the_hint(
    runner: CliRunner, live_postgres: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(PASSWORD_ENV, "not-the-password")
    config = _config(tmp_path / "doctor.yaml", live_postgres.dsn, live_postgres.user)

    result = _doctor(runner, config, "--output", "json")

    assert result.exit_code == 1, result.output
    (entry,) = json.loads(result.stdout)["targets"]
    assert entry["reachable"] is False
    error = entry["error"]
    assert error["code"] == "28P01"
    assert error["category"] == "authentication"
    assert error["message"].startswith("28P01: ")
    assert "password authentication failed" in error["message"]
    assert "the password this run used" in error["hint"]


def test_the_session_carries_the_run_in_application_name(live_postgres: Any) -> None:
    """Seen from another session, as a DBA would see it in `pg_stat_activity`."""
    import psycopg

    from sopuli.driver.postgres.session import build_driver

    run = str(uuid.uuid4())
    driver = build_driver(DriverContext(env=os.environ, correlation_id=run, runtime=Runtime()))
    target = ExpandedTarget(
        target=Target(
            name="tier1-postgres",
            type="postgresql",
            dsn=live_postgres.dsn,
            postgres=TargetPostgres(sslmode="disable"),
        )
    )
    session = driver.connect(
        target,
        Credential(username=live_postgres.user, secret=Secret(live_postgres.password)),
    )
    try:
        with psycopg.connect(
            host=live_postgres.host,
            port=live_postgres.port,
            user=live_postgres.user,
            password=live_postgres.password,
            dbname="postgres",
            sslmode="disable",
        ) as observer:
            rows = observer.execute(
                "select count(*) from pg_stat_activity where application_name = %s",
                (f"sopuli {run}",),
            ).fetchone()
    finally:
        session.close()

    assert rows == (1,)
