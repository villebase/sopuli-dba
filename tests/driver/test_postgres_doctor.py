"""`sopuli doctor` and the PostgreSQL driver against the tier-1 `postgres` service.

Tier 1. The service has no TLS, so the targets here set `sslmode: disable`, and
the encryption the run reports is `none`.
"""

from __future__ import annotations

import json
import os
import sys
import uuid
from collections.abc import Iterator
from contextlib import suppress
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from sopuli.cli import cli
from sopuli.config.model import ExpandedTarget, Runtime, Target, TargetPostgres
from sopuli.driver.postgres.privileges import GRANT_OPTIONS_ROW
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


def test_check_privileges_reports_a_superuser_and_still_passes(
    runner: CliRunner, live_postgres: Any, tmp_path: Path
) -> None:
    """The stack's `postgres` is the bootstrap superuser. Over-granting warns
    and never fails (P5)."""
    config = _config(tmp_path / "doctor.yaml", live_postgres.dsn, live_postgres.user)

    result = runner.invoke(
        cli, ["--config", str(config), "--output", "json", "doctor", "--check-privileges"]
    )

    assert result.exit_code == 0, result.output
    (entry,) = json.loads(result.stdout)["targets"]
    assert entry["scope"]["type"] == "cluster"
    assert {"SUPERUSER", "REPLICATION", "BYPASSRLS"} <= set(entry["scope"]["over_granted"])
    assert entry["privileges"]["held"] == ["CREATEROLE"]


@pytest.fixture
def tool_account(live_postgres: Any) -> Iterator[tuple[str, str, str]]:
    """A `CREATEROLE` tool account that is not a superuser, and one role for it
    to manage: the setup of `02-postgres-privileges.md` §2, with no grant yet."""
    import psycopg
    from psycopg import sql

    suffix = uuid.uuid4().hex[:8]
    tool, managed, password = f"sopuli_tool_{suffix}", f"acme_{suffix}_user", uuid.uuid4().hex
    with _superuser(live_postgres) as admin:
        admin.execute(
            sql.SQL("create role {} login createrole password {}").format(
                sql.Identifier(tool), sql.Literal(password)
            )
        )
        admin.execute(f'create role "{managed}" login')
    try:
        yield tool, password, managed
    finally:
        with _superuser(live_postgres) as admin:
            for role in (managed, tool):
                with suppress(psycopg.Error):
                    admin.execute(f'drop role "{role}"')


@pytest.fixture
def grant_options(live_postgres: Any) -> None:
    """Skip unless grants carry INHERIT and SET options, the capability these
    tests' grants and findings depend on (``02-postgres-privileges.md`` §2.2)."""
    with _superuser(live_postgres) as admin:
        (present,) = admin.execute(GRANT_OPTIONS_ROW).fetchone()
    if not present:
        pytest.skip(
            "capability absent: grants with INHERIT and SET options (pg_auth_members.set_option)"
        )


def _superuser(live_postgres: Any) -> Any:
    import psycopg

    return psycopg.connect(
        host=live_postgres.host,
        port=live_postgres.port,
        user=live_postgres.user,
        password=live_postgres.password,
        dbname="postgres",
        sslmode="disable",
        autocommit=True,
    )


def _audit_as(live_postgres: Any, user: str, password: str, accounts: tuple[str, ...]) -> Any:
    from sopuli.driver.postgres.session import build_driver

    driver = build_driver(DriverContext(env=os.environ, correlation_id="audit", runtime=Runtime()))
    target = ExpandedTarget(
        target=Target(
            name="tier1-postgres",
            type="postgresql",
            dsn=live_postgres.dsn,
            postgres=TargetPostgres(sslmode="disable"),
        )
    )
    session = driver.connect(target, Credential(username=user, secret=Secret(password)))
    try:
        return session.privileges(accounts=accounts)
    finally:
        session.close()


@pytest.mark.usefixtures("grant_options")
def test_a_role_without_admin_option_is_missing_and_with_it_held(
    live_postgres: Any, tool_account: tuple[str, str, str]
) -> None:
    """A server whose grants carry options requires ADMIN OPTION (§2.2)."""
    tool, password, managed = tool_account

    before = _audit_as(live_postgres, tool, password, (managed,))
    with _superuser(live_postgres) as admin:
        admin.execute(f'grant "{managed}" to "{tool}" with admin option, inherit false, set false')
    after = _audit_as(live_postgres, tool, password, (managed,))

    assert before.missing == (f"ADMIN OPTION ON {managed}",)
    assert after.missing == ()
    assert after.held == (f"ADMIN OPTION ON {managed}", "CREATEROLE")
    assert after.over_granted == ()


@pytest.mark.usefixtures("grant_options")
def test_a_grant_that_inherits_and_a_built_in_role_are_over_granted(
    live_postgres: Any, tool_account: tuple[str, str, str]
) -> None:
    tool, password, managed = tool_account
    with _superuser(live_postgres) as admin:
        admin.execute(f'grant "{managed}" to "{tool}" with admin option')
        admin.execute(f'grant pg_monitor to "{tool}"')

    found = _audit_as(live_postgres, tool, password, (managed, "acme_absent_user"))

    assert found.over_granted == (
        f"INHERIT TRUE ON {managed}",
        f"SET TRUE ON {managed}",
        "pg_monitor",
        "pg_read_all_stats",
    )
    assert found.missing == ("ADMIN OPTION ON acme_absent_user",)
    assert found.remedies[0].startswith(f'GRANT "{managed}" TO "{tool}" WITH INHERIT FALSE')
    assert "acme_absent_user does not exist" in found.remedies[1]


@pytest.mark.usefixtures("grant_options")
def test_a_managed_role_reached_through_another_role_says_so(
    live_postgres: Any, tool_account: tuple[str, str, str]
) -> None:
    tool, password, managed = tool_account
    ops = f"{managed}_ops"
    with _superuser(live_postgres) as admin:
        admin.execute(f'grant "{managed}" to "{tool}" with admin option, inherit false, set false')
        admin.execute(f'create role "{ops}"')
        admin.execute(f'grant "{managed}" to "{ops}"')
        admin.execute(f'grant "{ops}" to "{tool}"')
    try:
        found = _audit_as(live_postgres, tool, password, (managed,))
    finally:
        with _superuser(live_postgres) as admin:
            admin.execute(f'drop role "{ops}"')

    assert found.over_granted == (f"INHERIT TRUE ON {managed}", f"SET TRUE ON {managed}")
    assert "through another role" in found.remedies[0]
    assert ops in found.roles


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
