"""The statements `account suspend` and `account expire-password` send on
MariaDB (#1272). Tier 0, and tier 1 on the `mariadb` service (11.8.9)."""

from __future__ import annotations

import uuid
from typing import Any

import pytest

from sopuli.driver.mariadb.account_statements import expire, lock


def test_each_statement_names_the_account_between_backquotes() -> None:
    assert lock("acme_dev", "10.%") == "ALTER USER `acme_dev`@`10.%` ACCOUNT LOCK"
    assert expire("acme`dev", "%") == "ALTER USER `acme``dev`@`%` PASSWORD EXPIRE"


def test_the_tool_account_locks_and_expires_an_account(live_mariadb: Any) -> None:
    """The tool account holds only §2.1's grants. A second lock is accepted
    (LK1), so a suspension can always be sent."""
    pymysql = pytest.importorskip("pymysql")
    name, password = f"acme_dev_{uuid.uuid4().hex[:8]}", "Acme-Dev-pw1"
    with live_mariadb.connect() as root, root.cursor() as cursor:
        cursor.execute("CREATE USER %s@'%%' IDENTIFIED BY %s", (name, password))
    try:
        tool = live_mariadb.connect_as(live_mariadb.tool_user, live_mariadb.tool_password)
        with tool, tool.cursor() as cursor:
            cursor.execute(expire(name, "%"))
            cursor.execute(
                "select password_expired from mysql.user where User = %s and Host = '%%'",
                (name,),
            )
            (expired,) = cursor.fetchone()
            cursor.execute(lock(name, "%"))
            cursor.execute(lock(name, "%"))

        assert expired == "Y"
        with pytest.raises(pymysql.err.OperationalError) as refused:
            live_mariadb.connect_as(name, password, tls=False).close()
        assert refused.value.args[0] == 4151
    finally:
        with live_mariadb.connect() as root, root.cursor() as cursor:
            cursor.execute("DROP USER IF EXISTS %s@'%%'", (name,))
