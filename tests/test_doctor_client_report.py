"""`doctor`'s client lines come from each configured driver, not from the CLI.

Tier 0. The CLI asks the module the registry names for each ``type:`` the config
declares, so a second driver adds its own lines without a change to `cli.py`.
"""

from __future__ import annotations

import sys
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest

from sopuli import cli as cli_module
from sopuli.config.model import Runtime
from sopuli.driver.protocol import DriverError
from sopuli.driver.registry import DatabaseDriver


def _config(*types: str) -> Any:
    targets = [SimpleNamespace(target=SimpleNamespace(type=kind)) for kind in types]
    return SimpleNamespace(expanded_targets=targets, runtime=Runtime())


def _driver_module(monkeypatch: pytest.MonkeyPatch, name: str, report: dict[str, Any]) -> None:
    module = ModuleType(name)
    module.client_report = lambda *, env, runtime: dict(report)  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, name, module)


def test_each_configured_driver_writes_its_own_lines(monkeypatch: pytest.MonkeyPatch) -> None:
    _driver_module(monkeypatch, "fake_one", {"one_client": "1.0"})
    _driver_module(monkeypatch, "fake_two", {"two_client": "2.0"})
    monkeypatch.setattr(
        cli_module,
        "DRIVERS",
        {"one": DatabaseDriver(module="fake_one"), "two": DatabaseDriver(module="fake_two")},
    )

    assert cli_module._client_report(_config("two", "one", "two")) == {
        "one_client": "1.0",
        "two_client": "2.0",
    }


def test_a_driver_that_is_not_configured_is_not_asked(monkeypatch: pytest.MonkeyPatch) -> None:
    _driver_module(monkeypatch, "fake_one", {"one_client": "1.0"})
    monkeypatch.setattr(
        cli_module,
        "DRIVERS",
        {"one": DatabaseDriver(module="fake_one"), "two": DatabaseDriver(module="not_imported")},
    )

    assert cli_module._client_report(_config("one")) == {"one_client": "1.0"}


def test_a_driver_that_will_not_import_is_reported_not_raised(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The install section already names the missing extra; this line says the
    client report could not be written, and why."""
    monkeypatch.setattr(
        cli_module, "DRIVERS", {"one": DatabaseDriver(module="sopuli_no_such_module")}
    )

    report = cli_module._client_report(_config("one"))

    assert report == {"one": "not loaded", "detail": "No module named 'sopuli_no_such_module'"}


def test_a_failed_target_carries_the_drivers_reach_sentence() -> None:
    error = DriverError("refused", code="X-1")
    error.reach_warning = "the client is too new for this server"

    assert cli_module._reach_warning(error) == ("the client is too new for this server",)
    assert cli_module._reach_warning(DriverError("refused")) == ()
    assert cli_module._reach_warning(ValueError("not a driver error")) == ()
