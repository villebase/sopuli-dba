"""The Availability Group reads against a live SQL Server in no group.

Tier 1 (#1550). The tier-1 lane runs one instance, in no group, so this
checks what the driver reads there with `ALTER ANY LOGIN` alone: no replicas,
and the instance's own `master` (`14_availability_group_reads_probe.py`, AR6).
The reads in a real group, and the refusal in a contained group's `master`,
are the probe's and a hand run's: no group forms in the lane.
"""

from __future__ import annotations

from typing import Any

import pytest

from sopuli.config.model import ExpandedTarget, Target, TargetMssql
from sopuli.driver.protocol import Credential
from sopuli.secrets import Secret

session_module = pytest.importorskip("sopuli.driver.mssql.session")


def test_a_server_in_no_group_has_no_replicas_and_passes_the_scope(live_mssql: Any) -> None:
    target = ExpandedTarget(
        target=Target(
            name="tier1-mssql",
            type="mssql",
            dsn=live_mssql.dsn,
            mssql=TargetMssql(trust_server_certificate=True),
        )
    )
    credential = Credential(username=live_mssql.tool_user, secret=Secret(live_mssql.tool_password))
    opened = session_module.MssqlDriver(correlation_id="t1-1550").connect(target, credential)
    try:
        assert opened.availability_replicas() == ()
        # The scope passes: the session's database is the instance's master.
        assert opened.scope().read_write is True
    finally:
        opened.close()
