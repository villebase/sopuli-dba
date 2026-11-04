"""A MariaDB login through the shared connection arguments, with a password
that is not ASCII, on the tier-1 `mariadb` service (11.8.9). Tier 1.

:func:`~sopuli.driver.mysql_family.connection.connect_arguments` builds the
arguments for a MySQL or a MariaDB target, and the MariaDB driver (#1268) is
built on it. PyMySQL would encode a str password as latin-1; the server hashes
the password's UTF-8 bytes (#1285).
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest

from sopuli.config.model import ExpandedTarget, Target, TargetMysql
from sopuli.driver.mysql_family.connection import connect_arguments
from sopuli.driver.protocol import Credential, Timeouts
from sopuli.secrets import Secret

pymysql = pytest.importorskip("pymysql")


@pytest.mark.parametrize("password", ["Acme-pässwörd-é", "Acme-pass-€-word"])
def test_a_password_that_is_not_ascii_logs_in(live_mariadb: Any, password: str) -> None:
    name = f"acme_app_{uuid.uuid4().hex[:8]}"
    target = ExpandedTarget(
        target=Target(
            name="tier1-mariadb",
            type="mariadb",
            dsn=live_mariadb.dsn,
            mariadb=TargetMysql(ssl_mode="REQUIRED"),
        )
    )
    with live_mariadb.connect() as root, root.cursor() as cursor:
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
