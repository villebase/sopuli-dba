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


def _config(
    path: Path, dsn: str, user: str, *, names: tuple[str, ...] = ("tier1-postgres",)
) -> Path:
    """No `vaults:` block, for `test_oracle_doctor.py`'s reason: `doctor` fails on
    a declared store it cannot reach, and these tests bind no account. One
    target per name, all on ``dsn``."""
    targets = "".join(
        f"""
  - name: {name}
    type: postgresql
    dsn: "{dsn}"
    environment: dev
    postgres: {{ sslmode: disable }}
    admin:
      username: {user}
      auth: {{ method: env, password_env: {PASSWORD_ENV} }}"""
        for name in names
    )
    path.write_text(f"version: 1\ntargets:{targets}\n", encoding="utf-8")
    if sys.platform != "win32":
        path.chmod(0o600)
    return path


@pytest.fixture
def runner(tool_account: tuple[str, str, str], monkeypatch: pytest.MonkeyPatch) -> CliRunner:
    """The tool account's password reaches the tool through the environment
    (invariant 1)."""
    monkeypatch.setenv(PASSWORD_ENV, tool_account[1])
    return CliRunner()


def _doctor(runner: CliRunner, config: Path, *extra: str) -> Any:
    return runner.invoke(cli, ["--config", str(config), *extra, "doctor"])


def test_doctor_reaches_the_cluster_and_reports_what_it_is(
    runner: CliRunner, live_postgres: Any, tool_account: tuple[str, str, str], tmp_path: Path
) -> None:
    config = _config(tmp_path / "doctor.yaml", live_postgres.dsn, tool_account[0])

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


def test_a_superuser_is_refused(
    live_postgres: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The stack's `postgres` is the bootstrap superuser. Connecting works, and
    the run refuses it. `doctor` fails only for a target it cannot reach, so
    the refusal is the entry's error and the exit is 0."""
    monkeypatch.setenv(PASSWORD_ENV, live_postgres.password)
    config = _config(tmp_path / "doctor.yaml", live_postgres.dsn, live_postgres.user)

    result = _doctor(CliRunner(), config, "--output", "json")

    assert result.exit_code == 0, result.output
    (entry,) = json.loads(result.stdout)["targets"]
    assert entry["reachable"] is True
    assert entry["error"]["code"] == "SOPULI-20007"
    assert entry["error"]["category"] == "config"
    assert '"postgres", a superuser' in entry["error"]["message"]


def test_check_privileges_audits_the_tool_account(
    runner: CliRunner, live_postgres: Any, tool_account: tuple[str, str, str], tmp_path: Path
) -> None:
    config = _config(tmp_path / "doctor.yaml", live_postgres.dsn, tool_account[0])

    result = runner.invoke(
        cli, ["--config", str(config), "--output", "json", "doctor", "--check-privileges"]
    )

    assert result.exit_code == 0, result.output
    (entry,) = json.loads(result.stdout)["targets"]
    assert entry["scope"].get("over_granted", []) == []
    assert entry["privileges"]["held"] == ["CREATEROLE"]
    assert entry["privileges"]["missing"] == []


def test_two_targets_on_one_cluster_are_refused(
    runner: CliRunner, live_postgres: Any, tool_account: tuple[str, str, str], tmp_path: Path
) -> None:
    config = _config(
        tmp_path / "doctor.yaml",
        live_postgres.dsn,
        tool_account[0],
        names=("pg-primary", "pg-again"),
    )

    result = _doctor(runner, config, "--output", "json")

    assert result.exit_code == 0, result.output
    first, second = json.loads(result.stdout)["targets"]
    assert first.get("error") is None
    assert first["scope"]["type"] == "cluster"
    assert second["reachable"] is True
    assert second["error"]["category"] == "config"
    assert second["error"]["message"].startswith(
        'targets "pg-primary" and "pg-again" are one PostgreSQL cluster (system_identifier '
    )


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
    assert found.missing == ()
    assert found.remedies[0].startswith(f'GRANT "{managed}" TO "{tool}" WITH INHERIT FALSE')
    assert found.remedies[1].startswith("acme_absent_user does not exist")


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
    (remedy,) = found.remedies
    assert remedy.startswith(f"the tool account reaches {managed} through another role")
    assert ops in found.roles


@pytest.mark.usefixtures("grant_options")
def test_a_chain_of_one_inherit_and_one_set_grant_gives_nothing(
    live_postgres: Any, tool_account: tuple[str, str, str]
) -> None:
    """Privileges pass down INHERIT grants and SET ROLE down SET grants, so a
    chain of one of each gives the tool neither."""
    tool, password, _ = tool_account
    mid = f"{tool}_mid"
    with _superuser(live_postgres) as admin:
        admin.execute(f'create role "{mid}"')
        admin.execute(f'grant "{mid}" to "{tool}" with inherit true, set false')
        admin.execute(f'grant pg_read_server_files to "{mid}" with inherit false, set true')
    try:
        found = _audit_as(live_postgres, tool, password, ())
        with _superuser(live_postgres) as admin:
            (usable,) = admin.execute(
                "select pg_has_role(%s, 'pg_read_server_files', 'USAGE') "
                "or pg_has_role(%s, 'pg_read_server_files', 'SET')",
                (tool, tool),
            ).fetchone()
    finally:
        with _superuser(live_postgres) as admin:
            admin.execute(f'drop role "{mid}"')

    assert usable is False, "the server agrees the chain gives nothing"
    assert "pg_read_server_files" not in found.over_granted
    assert "pg_read_server_files" in found.roles


def test_doctor_prints_the_postgresql_client_lines(
    runner: CliRunner, live_postgres: Any, tool_account: tuple[str, str, str], tmp_path: Path
) -> None:
    config = _config(tmp_path / "doctor.yaml", live_postgres.dsn, tool_account[0])

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
