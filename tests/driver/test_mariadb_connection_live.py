"""A MariaDB login through the shared connection arguments, with a password
that is not ASCII, on the tier-1 `mariadb` service (11.8.9). Tier 1.

The MariaDB driver connects with
:func:`~sopuli.driver.mysql_family.connection.connect_arguments`, as the MySQL
driver does. PyMySQL would encode a str password as latin-1; the server hashes
the password's UTF-8 bytes (#1285). The port follows
`SOPULI_TEST_MARIADB_PORT`, as the compose file's does.
"""

from __future__ import annotations

import os
import uuid

import pytest

from conftest import _missing_environment
from sopuli.config.model import ExpandedTarget, Target, TargetMysql
from sopuli.driver.mysql_family.connection import connect_arguments
from sopuli.driver.protocol import Credential, Timeouts
from sopuli.secrets import Secret

pymysql = pytest.importorskip("pymysql")

PORT = int(os.environ.get("SOPULI_TEST_MARIADB_PORT", "3307"))


@pytest.mark.parametrize("password", ["Acme-pässwörd-é", "Acme-pass-€-word"])
def test_a_password_that_is_not_ascii_logs_in(password: str) -> None:
    name = f"acme_app_{uuid.uuid4().hex[:8]}"
    try:
        root = pymysql.connect(
            host="127.0.0.1",
            port=PORT,
            user="root",
            password="sopuli-test",
            ssl_disabled=True,
            charset="utf8mb4",
            autocommit=True,
            connect_timeout=5,
        )
    except pymysql.err.MySQLError as error:
        _missing_environment(f"MariaDB not reachable at 127.0.0.1:{PORT}: {error}")
    target = ExpandedTarget(
        target=Target(
            name="tier1-mariadb",
            type="mariadb",
            dsn=f"127.0.0.1:{PORT}",
            mariadb=TargetMysql(ssl_mode="REQUIRED"),
        )
    )
    with root, root.cursor() as cursor:
        cursor.execute("CREATE USER %s@'%%' IDENTIFIED BY %s", (name, password))
        try:
            arguments = connect_arguments(
                target,
                Credential(username=name, secret=Secret(password)),
                correlation_id="tier1",
                timeouts=Timeouts(),
            )
            with pymysql.connect(**arguments) as session, session.cursor() as own:
                own.execute("SELECT CURRENT_USER()")
                assert own.fetchone()[0] == f"{name}@%"
        finally:
            cursor.execute("DROP USER IF EXISTS %s@'%%'", (name,))
