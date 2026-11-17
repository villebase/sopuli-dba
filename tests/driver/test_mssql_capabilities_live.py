"""The SQL Server capabilities of #1550 against a live server.

Tier 1. The tool login holds `ALTER ANY LOGIN` alone (`02-mssql-privileges.md`
§2.1), and reads both: the host's platform from `sys.dm_os_host_info` (WP0),
and the password value's version with the rolled-back check (#1564). The
service is 2022, which takes a `0x0300` value (`11_hash_version_probe.py`,
HV6). The check leaves no login and no open transaction.
"""

from __future__ import annotations

import uuid
from dataclasses import replace
from typing import Any

import pytest

from sopuli.config.model import ExpandedTarget, Target, TargetMssql
from sopuli.driver.mssql.capabilities import CHECK_PREFIX
from sopuli.driver.mssql.password import PBKDF2_SHA512
from sopuli.driver.protocol import Credential, DriverError
from sopuli.secrets import Secret

session_module = pytest.importorskip("sopuli.driver.mssql.session")


def _session(live_mssql: Any) -> Any:
    target = ExpandedTarget(
        target=Target(
            name="tier1-mssql",
            type="mssql",
            dsn=live_mssql.dsn,
            mssql=TargetMssql(trust_server_certificate=True),
        )
    )
    credential = Credential(username=live_mssql.tool_user, secret=Secret(live_mssql.tool_password))
    return session_module.MssqlDriver(correlation_id="t1-1550").connect(target, credential)


def test_a_login_without_alter_any_login_is_refused_for_the_grant(live_mssql: Any) -> None:
    """The check from a login with no grant: 15247, the tool login's fault,
    not the target's (measured on 16.0.4325.4)."""
    name = f"acme_t1_noperm_{uuid.uuid4().hex[:6]}"
    password = "Acme-Noperm-pw1"
    sa = live_mssql.connect()
    sa.cursor().execute(f"CREATE LOGIN [{name}] WITH PASSWORD = N'{password}', CHECK_POLICY = OFF")
    try:
        stack = replace(live_mssql, tool_user=name, tool_password=password)
        opened = _session(stack)
        try:
            with pytest.raises(DriverError) as caught:
                opened.hash_version()
        finally:
            opened.close()
    finally:
        sa.cursor().execute(f"DROP LOGIN [{name}]")
        sa.close()

    assert caught.value.category == "authorization"
    assert caught.value.code == "15247"


def test_the_tool_login_reads_the_host_platform(live_mssql: Any) -> None:
    opened = _session(live_mssql)
    try:
        assert opened.host_platform() == "Linux"
    finally:
        opened.close()


def test_the_check_reads_0x0300_and_leaves_nothing(live_mssql: Any) -> None:
    opened = _session(live_mssql)
    try:
        assert opened.hash_version() == PBKDF2_SHA512
        assert opened._read(lambda cursor: cursor.execute("SELECT @@TRANCOUNT").fetchone()[0]) == 0
    finally:
        opened.close()

    sa = live_mssql.connect()
    try:
        cursor = sa.cursor()
        cursor.execute(
            "SELECT COUNT(*) FROM sys.server_principals WHERE name LIKE ?",
            CHECK_PREFIX.replace("_", "[_]") + "%",
        )
        assert cursor.fetchone()[0] == 0
    finally:
        sa.close()
