"""The client-computed values, set on the tier-1 `mariadb` service (11.8.9).
Tier 1.

The tool account `sopuli_admin` holds the grants of
`02-mariadb-privileges.md` §2.1, as `test/mariadb-init/` creates it. It sets
each plugin's value for a new account with ``IDENTIFIED VIA … USING``, and the
password logs in.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from typing import Any

import pytest

from sopuli.secrets import Secret

pymysql = pytest.importorskip("pymysql")
# Before the module, which imports PyNaCl: it comes with the `mariadb` extra.
pytest.importorskip("nacl", reason="PyNaCl comes with the `mariadb` extra")

from sopuli.driver.mariadb.password import ED25519, NATIVE, VALUES, admit  # noqa: E402


@pytest.fixture
def account(live_mariadb: Any) -> Iterator[str]:
    """A new account at `%`, created and dropped as root."""
    name = f"acme_app_{uuid.uuid4().hex[:8]}"
    with live_mariadb.connect() as root, root.cursor() as cursor:
        cursor.execute("CREATE USER %s@'%%' IDENTIFIED BY %s", (name, uuid.uuid4().hex))
        try:
            yield name
        finally:
            cursor.execute("DROP USER IF EXISTS %s@'%%'", (name,))


@pytest.mark.parametrize("plugin", [NATIVE, ED25519])
@pytest.mark.parametrize("password", ["Acme-App-pw1", "pässwörd-€-" + "x" * 300])
def test_the_tool_account_sets_the_value_and_the_password_logs_in(
    live_mariadb: Any, account: str, plugin: str, password: str
) -> None:
    secret = Secret(password)
    admit(secret)
    value = VALUES[plugin](secret)

    with (
        live_mariadb.connect_as(live_mariadb.tool_user, live_mariadb.tool_password) as tool,
        tool.cursor() as cursor,
    ):
        cursor.execute(
            f"ALTER USER %s@'%%' IDENTIFIED VIA {plugin} USING %s", (account, value.reveal())
        )

    # Without TLS: neither plugin sends the password.
    with (
        live_mariadb.connect_as(account, password, tls=False) as session,
        session.cursor() as cursor,
    ):
        cursor.execute("SELECT CURRENT_USER()")
        assert cursor.fetchone()[0] == f"{account}@%"

    with pytest.raises(pymysql.err.OperationalError) as refused:
        live_mariadb.connect_as(account, password + "-wrong", tls=False).close()
    assert refused.value.args[0] == 1045
