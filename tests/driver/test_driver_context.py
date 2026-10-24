"""What a driver is built from: the run's half of P1's split.

Tier 0. The protocol is imported on every run, including the ones that never
reach a database, so it must import no vendor client.
"""

from __future__ import annotations

import subprocess
import sys

from sopuli.config.model import Runtime
from sopuli.driver.protocol import DriverContext, Timeouts
from sopuli.settings.registry import DEFAULT_CONNECT_TIMEOUT_S, NO_QUERY_TIMEOUT


def test_a_context_built_with_no_settings_has_the_documented_budgets() -> None:
    context = DriverContext(env={}, correlation_id="run-id")

    assert context.timeouts == Timeouts(
        connect_s=DEFAULT_CONNECT_TIMEOUT_S, query_s=NO_QUERY_TIMEOUT
    )
    assert context.runtime == Runtime()


def test_the_protocol_imports_no_vendor_client() -> None:
    """In a fresh interpreter, because another test in this process may already
    have imported `oracledb` on a machine that has it."""
    probe = "import sys, sopuli.driver.protocol; sys.exit('oracledb' in sys.modules)"

    assert subprocess.run([sys.executable, "-c", probe], check=False).returncode == 0
