"""The client-computed values, set on the tier-1 `mariadb` service (11.8.9).
Tier 1.

The tool account `sopuli_admin` holds the grants of
`02-mariadb-privileges.md` §2.1, as `test/mariadb-init/` creates it. It sets
each plugin's value for a new account with ``IDENTIFIED VIA … USING``, and the
password logs in. The port follows `SOPULI_TEST_MARIADB_PORT`, as the compose
file's does.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Iterator
from typing import Any

import pytest

from conftest import _missing_environment
from sopuli.secrets import Secret

pymysql = pytest.importorskip("pymysql")
# Before the module, which imports PyNaCl: it comes with the `mariadb` extra.
pytest.importorskip("nacl", reason="PyNaCl comes with the `mariadb` extra")

from sopuli.driver.mariadb.password import ED25519, NATIVE, VALUES, admit  # noqa: E402

PORT = int(os.environ.get("SOPULI_TEST_MARIADB_PORT", "3307"))


def connect(user: str, password: str | bytes) -> Any:
    """A session without TLS: neither plugin sends the password. The password
    goes to PyMySQL as UTF-8 bytes, because it encodes a str as latin-1
    (#1285)."""
    return pymysql.connect(
        host="127.0.0.1",
        port=PORT,
        user=user,
        password=password,
        ssl_disabled=True,
        charset="utf8mb4",
        autocommit=True,
        connect_timeout=5,
    )


@pytest.fixture
def account() -> Iterator[str]:
    """A new account at `%`, created and dropped as root."""
    name = f"acme_app_{uuid.uuid4().hex[:8]}"
    try:
        root = connect("root", "sopuli-test")
    except pymysql.err.MySQLError as error:
        _missing_environment(f"MariaDB not reachable at 127.0.0.1:{PORT}: {error}")
    with root, root.cursor() as cursor:
        cursor.execute("CREATE USER %s@'%%' IDENTIFIED BY %s", (name, uuid.uuid4().hex))
        try:
            yield name
        finally:
            cursor.execute("DROP USER IF EXISTS %s@'%%'", (name,))


@pytest.mark.parametrize("plugin", [NATIVE, ED25519])
@pytest.mark.parametrize("password", ["Acme-App-pw1", "pässwörd-€-" + "x" * 300])
def test_the_tool_account_sets_the_value_and_the_password_logs_in(
    account: str, plugin: str, password: str
) -> None:
    secret = Secret(password)
    admit(secret)
    value = VALUES[plugin](secret)

    with connect("sopuli_admin", "sopuli-test-admin") as tool, tool.cursor() as cursor:
        cursor.execute(
            f"ALTER USER %s@'%%' IDENTIFIED VIA {plugin} USING %s", (account, value.reveal())
        )

    with connect(account, password.encode("utf-8")) as session, session.cursor() as cursor:
        cursor.execute("SELECT CURRENT_USER()")
        assert cursor.fetchone()[0] == f"{account}@%"

    with pytest.raises(pymysql.err.OperationalError) as refused:
        connect(account, (password + "-wrong").encode("utf-8"))
    assert refused.value.args[0] == 1045
