"""What a driver is built from: the run's half of P1's split.

Tier 0. That importing the protocol loads no vendor client is checked by
`tests/driver/test_driver_registry.py`'s probe, which imports the registry and
so the protocol, against a stub client that records being imported.
"""

from __future__ import annotations

import pytest

from sopuli.config.model import Runtime
from sopuli.driver.protocol import DriverContext, Timeouts
from sopuli.settings.registry import DEFAULT_CONNECT_TIMEOUT_S, NO_QUERY_TIMEOUT


def test_a_context_built_with_no_settings_has_the_documented_budgets() -> None:
    context = DriverContext(env={}, correlation_id="run-id", runtime=Runtime())

    assert context.timeouts == Timeouts(
        connect_s=DEFAULT_CONNECT_TIMEOUT_S, query_s=NO_QUERY_TIMEOUT
    )


def test_a_context_cannot_be_built_without_the_runtime_block() -> None:
    """`runtime` is where a driver finds its client on this machine. A default
    would let a new caller drop `runtime.oracle.client_lib_dir` and still
    type-check, and the run would then fail to load Instant Client with nothing
    in the config to say why."""
    with pytest.raises(TypeError):
        DriverContext(env={}, correlation_id="run-id")  # type: ignore[call-arg]
