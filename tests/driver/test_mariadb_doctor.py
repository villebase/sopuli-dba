"""`sopuli doctor` and the MariaDB driver against the tier-1 `mariadb` service.

Tier 1 (#1268). The image starts with TLS on and a certificate it generates for
itself, so the target sets `ssl_mode: REQUIRED`, which encrypts and checks
nothing about the server. The tool account is the one the service's init
creates, with exactly `02-mariadb-privileges.md` §2.1's grants.
"""

from __future__ import annotations

import json
import sys
import uuid
from collections.abc import Iterator
from contextlib import suppress
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from sopuli.cli import cli

pymysql = pytest.importorskip("pymysql")
pytest.importorskip("sopuli.driver.mariadb.session")

PASSWORD_ENV = "SOPULI_TEST_MARIADB_DOCTOR_PASSWORD"


@pytest.fixture
def accounts(live_mariadb: Any) -> Iterator[str]:
    """A user name at two hosts, one on a plugin the tool does not change."""
    user = f"acme_{uuid.uuid4().hex[:8]}"
    with live_mariadb.connect() as admin, admin.cursor() as cursor:
        cursor.execute("create user %s@'%%' identified by %s", (user, uuid.uuid4().hex))
        cursor.execute("create user %s@'localhost' identified via unix_socket", (user,))
    try:
        yield user
    finally:
        with live_mariadb.connect() as admin, admin.cursor() as cursor, suppress(pymysql.Error):
            cursor.execute("drop user %s@'%%', %s@'localhost'", (user, user))


def _config(path: Path, live_mariadb: Any, declared: list[str]) -> Path:
    """No `vaults:` store is reached: `doctor --check-privileges` reports the
    store as unreachable and reads the target all the same."""
    accounts_yaml = ", ".join(f'"{name}"' for name in declared)
    applications = (
        f"""applications:
  - name: acme
    targets: [tier1-mariadb]
    accounts: [{accounts_yaml}]
    secret_template: "apps/acme/{{host}}#DB/{{user}}"
"""
        if declared
        else ""
    )
    path.write_text(
        f"""version: 1
vaults:
  vault-dev: {{ type: hashicorp, addr: "https://vault.example.com" }}
targets:
  - name: tier1-mariadb
    type: mariadb
    dsn: "{live_mariadb.dsn}"
    environment: dev
    vault: vault-dev
    mariadb: {{ ssl_mode: REQUIRED }}
    admin:
      username: "{live_mariadb.tool_user}"
      auth: {{ method: env, password_env: {PASSWORD_ENV} }}
{applications}""",
        encoding="utf-8",
    )
    # The permission check refuses a config others can read (Linux CI).
    if sys.platform != "win32":
        path.chmod(0o600)
    return path


def _doctor(config: Path, password: str) -> dict[str, Any]:
    result = CliRunner().invoke(
        cli,
        ["--config", str(config), "doctor", "--check-privileges", "--output", "json"],
        env={PASSWORD_ENV: password},
    )
    document: dict[str, Any] = json.loads(result.output)
    return document


def test_doctor_reports_the_server_and_audits_the_tool_account(
    live_mariadb: Any, accounts: str, tmp_path: Path
) -> None:
    config = _config(tmp_path / "c.yaml", live_mariadb, [f"{accounts}@%", "acme_none@%"])

    document = _doctor(config, live_mariadb.tool_password)

    (target,) = document["targets"]
    assert target["reachable"] is True
    scope = target["scope"]
    assert scope["type"] == "server"
    assert scope["open_mode"] == "READ WRITE"
    assert scope["encryption"]["method"] == "tls"
    assert "MariaDB" not in scope["db_version"]
    privileges = target["privileges"]
    assert privileges["missing"] == []
    # The run document carries over-grants in the scope, as on MySQL, and
    # leaves the key out where there are none. The tests below show it present.
    assert "over_granted" not in scope
    assert privileges["unaudited"] == [
        "privileges granted to PUBLIC, apart from reading stored values, which is tried "
        "directly; SHOW GRANTS FOR PUBLIC lists them"
    ]


def test_doctor_surveys_the_declared_accounts(
    live_mariadb: Any, accounts: str, tmp_path: Path
) -> None:
    config = _config(tmp_path / "c.yaml", live_mariadb, [f"{accounts}@%", f"{accounts}@localhost"])
    result = CliRunner().invoke(
        cli,
        ["--config", str(config), "doctor", "--check-privileges"],
        env={PASSWORD_ENV: live_mariadb.tool_password},
    )

    assert f"{accounts}@localhost uses unix_socket" in result.output
    # The gap in guardrail 9 that decision 4 accepts, said with declared
    # accounts (02-mariadb-privileges.md section 5).
    shown = " ".join(result.output.split())
    assert "check 9 cannot see BINLOG ADMIN," in shown
    assert "SET USER or SLAVE MONITOR: they set no column of the mysql.user view" in shown
    # The second login method the view does not show (section 4, #1301).
    assert "second login method, joined by OR" in shown


def test_without_declared_accounts_doctor_says_nothing_of_check_9(
    live_mariadb: Any, tmp_path: Path
) -> None:
    config = _config(tmp_path / "c.yaml", live_mariadb, [])
    result = CliRunner().invoke(
        cli,
        ["--config", str(config), "doctor", "--check-privileges"],
        env={PASSWORD_ENV: live_mariadb.tool_password},
    )

    # The audit ran: its always-present PUBLIC line is there.
    assert "privileges granted to PUBLIC" in " ".join(result.output.split())
    assert "check 9" not in result.output
    assert "second login method" not in result.output


def test_a_role_the_tool_account_holds_is_reported(live_mariadb: Any, tmp_path: Path) -> None:
    """`information_schema` shows only the account's own grants, so a role it
    holds, here one that reads every stored value, is named and left unaudited.
    Before #1287's review the role read matched nothing, and this passed clean."""
    role = f"sopuli_role_{uuid.uuid4().hex[:8]}"
    tool = f"'{live_mariadb.tool_user}'@'%'"
    with live_mariadb.connect() as admin, admin.cursor() as cursor:
        cursor.execute(f"create role {role}")
        cursor.execute(f"grant select on mysql.global_priv to {role}")
        cursor.execute(f"grant {role} to {tool}")
    try:
        document = _doctor(
            _config(tmp_path / "c.yaml", live_mariadb, ["acme_none@%"]),
            live_mariadb.tool_password,
        )
    finally:
        with live_mariadb.connect() as admin, admin.cursor() as cursor, suppress(pymysql.Error):
            cursor.execute(f"drop role {role}")

    target = document["targets"][0]
    assert target["privileges"]["roles"] == [role]
    assert "privileges the tool account gets through a role" in target["privileges"]["unaudited"]
    # The role is not a default role, so it is not active; the audit sets it,
    # tries the read, and finds that through it every stored value is readable.
    assert target["scope"]["over_granted"] == [f"SELECT ON mysql.global_priv (through role {role})"]


def test_a_grant_to_public_that_reads_stored_values_is_caught(
    live_mariadb: Any, tmp_path: Path
) -> None:
    """A grant to PUBLIC shows in no information_schema row the tool account
    reads; the direct read finds it (#1287)."""
    with live_mariadb.connect() as admin, admin.cursor() as cursor:
        cursor.execute("grant select on mysql.global_priv to public")
    try:
        document = _doctor(
            _config(tmp_path / "c.yaml", live_mariadb, ["acme_none@%"]),
            live_mariadb.tool_password,
        )
    finally:
        with live_mariadb.connect() as admin, admin.cursor() as cursor:
            cursor.execute("revoke select on mysql.global_priv from public")

    assert document["targets"][0]["scope"]["over_granted"] == ["SELECT ON mysql.global_priv"]


def test_a_wrong_password_is_an_authentication_failure(live_mariadb: Any, tmp_path: Path) -> None:
    config = _config(tmp_path / "c.yaml", live_mariadb, ["acme_none@%"])

    document = _doctor(config, "not-the-password")

    (target,) = document["targets"]
    assert target["reachable"] is False
    assert target["error"]["code"] == "1045"


def test_two_targets_on_one_server_are_refused(live_mariadb: Any, tmp_path: Path) -> None:
    """#1286: the second target that reaches the server is refused, naming
    both and the server's `@@server_uid`, and doctor exits 9."""
    target = """  - name: {name}
    type: mariadb
    dsn: "{dsn}"
    environment: dev
    mariadb: {{ ssl_mode: REQUIRED }}
    admin:
      username: "{user}"
      auth: {{ method: env, password_env: {env} }}
"""
    config = tmp_path / "c.yaml"
    config.write_text(
        "version: 1\ntargets:\n"
        + "".join(
            target.format(
                name=name, dsn=live_mariadb.dsn, user=live_mariadb.tool_user, env=PASSWORD_ENV
            )
            for name in ("tier1-mariadb", "tier1-again")
        ),
        encoding="utf-8",
    )
    # The permission check refuses a config others can read (Linux CI).
    if sys.platform != "win32":
        config.chmod(0o600)

    result = CliRunner().invoke(
        cli,
        ["--config", str(config), "doctor", "--output", "json"],
        env={PASSWORD_ENV: live_mariadb.tool_password},
    )

    assert result.exit_code == 9, result.output
    first, second = json.loads(result.stdout)["targets"]
    assert first.get("error") is None
    assert first["scope"]["type"] == "server"
    assert second["reachable"] is True
    assert second["error"]["code"] == "SOPULI-20008"
    assert second["error"]["category"] == "config"
    assert second["error"]["message"].startswith(
        'targets "tier1-mariadb" and "tier1-again" are one MariaDB server (server_uid '
    )
