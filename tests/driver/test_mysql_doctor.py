"""`sopuli doctor` and the MySQL driver against the tier-1 `mysql` service.

Tier 1. The image turns TLS on with a certificate it generates for itself, so
the targets here set `ssl_mode: REQUIRED`, which encrypts and checks nothing
about the server, and the encryption the run reports is `tls`. A test that asks
for `VERIFY_IDENTITY` meets a certificate it cannot verify.

The tool account is created per test with no privileges at all: connecting
and reading the scope need none.
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
from sopuli.config.model import ExpandedTarget, Target, TargetMysql
from sopuli.driver.protocol import AuthenticationError, Credential, DriverError
from sopuli.secrets import Secret

pymysql = pytest.importorskip("pymysql")
session_module = pytest.importorskip("sopuli.driver.mysql.session")

PASSWORD_ENV = "SOPULI_TEST_MYSQL_DOCTOR_PASSWORD"


@pytest.fixture
def tool_account(live_mysql: Any) -> Iterator[tuple[str, str]]:
    """An account with no privileges, and its password."""
    user, password = f"sopuli_tool_{uuid.uuid4().hex[:8]}", uuid.uuid4().hex
    with live_mysql.connect() as admin, admin.cursor() as cursor:
        cursor.execute("create user %s@'%%' identified by %s", (user, password))
    try:
        yield user, password
    finally:
        with live_mysql.connect() as admin, admin.cursor() as cursor, suppress(pymysql.Error):
            cursor.execute("drop user %s@'%%'", (user,))


def _config(path: Path, dsn: str, user: str, *, ssl_mode: str = "REQUIRED") -> Path:
    """No `vaults:` block: `doctor` fails on a declared store it cannot reach,
    and these tests bind no account."""
    path.write_text(
        f"""version: 1
targets:
  - name: tier1-mysql
    type: mysql
    dsn: "{dsn}"
    environment: dev
    mysql: {{ ssl_mode: {ssl_mode} }}
    admin:
      username: {user}
      auth: {{ method: env, password_env: {PASSWORD_ENV} }}
""",
        encoding="utf-8",
    )
    if sys.platform != "win32":
        path.chmod(0o600)
    return path


def _doctor(monkeypatch: pytest.MonkeyPatch, password: str, config: Path, *extra: str) -> Any:
    """The password reaches the tool through the environment (invariant 1)."""
    monkeypatch.setenv(PASSWORD_ENV, password)
    return CliRunner().invoke(cli, ["--config", str(config), *extra, "doctor"])


def test_doctor_reaches_the_server_and_reports_what_it_is(
    live_mysql: Any,
    tool_account: tuple[str, str],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user, password = tool_account
    config = _config(tmp_path / "doctor.yaml", live_mysql.dsn, user)

    result = _doctor(monkeypatch, password, config, "--output", "json")

    assert result.exit_code == 0, result.output
    document = json.loads(result.stdout)
    (entry,) = document["targets"]
    assert entry["reachable"] is True
    scope = entry["scope"]
    assert scope["type"] == "server"
    assert scope["container"] is None
    assert scope["open_mode"] == "READ WRITE"
    assert scope["read_write"] is True
    assert scope["db_version"], "the version the server reported"
    assert scope["capabilities"] == []
    assert scope["encryption"]["method"] == "tls"
    assert scope["encryption"]["protocol"] == "tcp"

    text = _doctor(monkeypatch, password, config)
    assert text.exit_code == 0, text.output
    assert "  pymysql" in text.output, "the client section names PyMySQL's release"


def test_verify_identity_meets_the_images_own_certificate(
    live_mysql: Any,
    tool_account: tuple[str, str],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The default mode checks the certificate, and the image's is self-signed."""
    user, password = tool_account
    config = _config(tmp_path / "doctor.yaml", live_mysql.dsn, user, ssl_mode="VERIFY_IDENTITY")

    result = _doctor(monkeypatch, password, config, "--output", "json")

    assert result.exit_code != 0
    (entry,) = json.loads(result.stdout)["targets"]
    assert entry["reachable"] is False
    assert entry["error"]["code"] == "2003"
    assert "mysql.ssl_ca" in entry["error"]["hint"]


def _target(dsn: str, mode: str = "REQUIRED") -> ExpandedTarget:
    return ExpandedTarget(
        target=Target(name="tier1-mysql", type="mysql", dsn=dsn, mysql=TargetMysql(ssl_mode=mode))
    )


def _connect(live_mysql: Any, user: str, password: str, mode: str = "REQUIRED") -> Any:
    driver = session_module.MysqlDriver(correlation_id="tier1")
    return driver.connect(
        _target(live_mysql.dsn, mode), Credential(username=user, secret=Secret(password))
    )


def test_a_wrong_password_is_1045(live_mysql: Any, tool_account: tuple[str, str]) -> None:
    with pytest.raises(AuthenticationError) as caught:
        _connect(live_mysql, tool_account[0], "not-the-password")

    assert caught.value.code == "1045"
    assert str(caught.value).startswith("1045 (28000): Access denied")


def test_an_expired_password_is_refused_at_login_with_1862(live_mysql: Any) -> None:
    """PyMySQL does not say it can handle an expired password, so the server
    refuses the login; the mysql client meets 1820 after it instead."""
    user, password = f"acme_expired_{uuid.uuid4().hex[:8]}", uuid.uuid4().hex
    with live_mysql.connect() as admin, admin.cursor() as cursor:
        cursor.execute("create user %s@'%%' identified by %s password expire", (user, password))
    try:
        with pytest.raises(AuthenticationError) as caught:
            _connect(live_mysql, user, password)
        assert caught.value.code == "1862"
    finally:
        with live_mysql.connect() as admin, admin.cursor() as cursor:
            cursor.execute("drop user %s@'%%'", (user,))


def test_a_plain_login_the_server_has_not_cached_fails_as_measured(
    live_mysql: Any, tool_account: tuple[str, str]
) -> None:
    """After FLUSH PRIVILEGES the server's caching_sha2_password cache is
    empty, and PyMySQL 1.2.3 cannot finish the full exchange without TLS."""
    with live_mysql.connect() as admin, admin.cursor() as cursor:
        cursor.execute("flush privileges")

    with pytest.raises(session_module.PlainLoginError):
        _connect(live_mysql, *tool_account, mode="DISABLED")


def test_a_plain_login_the_server_has_cached_reports_no_encryption(
    live_mysql: Any, tool_account: tuple[str, str]
) -> None:
    """A login over TLS fills the cache; a plain login then succeeds, and the
    scope says it is not encrypted."""
    _connect(live_mysql, *tool_account).close()

    session = _connect(live_mysql, *tool_account, mode="DISABLED")
    try:
        assert session.scope().encryption.method == "none"
    finally:
        session.close()


def test_a_query_timeout_loses_the_connection_with_2013(
    live_mysql: Any, tool_account: tuple[str, str]
) -> None:
    """A query budget is a socket timeout: the call fails with 2013, and the
    hint says a change in flight is unknown."""
    from sopuli.driver.mysql.errors import from_error
    from sopuli.driver.protocol import Timeouts

    driver = session_module.MysqlDriver(correlation_id="tier1", timeouts=Timeouts(query_s=1))
    session = driver.connect(
        _target(live_mysql.dsn),
        Credential(username=tool_account[0], secret=Secret(tool_account[1])),
    )
    try:
        with (
            pytest.raises(pymysql.err.OperationalError) as caught,
            session.connection.cursor() as cursor,
        ):
            cursor.execute("select sleep(3)")
        diagnosis = from_error(caught.value)
        assert diagnosis.code == "2013"
        assert "unknown until the account is checked" in str(diagnosis.hint)
    finally:
        with suppress(DriverError, pymysql.Error):
            session.close()
