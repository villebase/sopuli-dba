"""`doctor`'s client lines come from each configured driver, not from the CLI.

Tier 0. The CLI asks the module the registry names for each ``type:`` the config
declares, so a second driver adds its own lines without a change to `cli.py`.
"""

from __future__ import annotations

import sys
from pathlib import Path
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


def test_an_installed_driver_is_asked_with_no_target_of_its_type(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The client lines work with nothing else set up: before the first target
    is written, and when a selector leaves no target of the type."""
    _driver_module(monkeypatch, "fake_one", {"one_client": "1.0"})
    monkeypatch.setattr(
        cli_module,
        "DRIVERS",
        {"one": DatabaseDriver(module="fake_one", provides=frozenset({"json"}))},
    )

    assert cli_module._client_report(_config()) == {"one_client": "1.0"}


def test_a_driver_neither_installed_nor_configured_is_not_asked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _driver_module(monkeypatch, "fake_one", {"one_client": "1.0"})
    monkeypatch.setattr(
        cli_module,
        "DRIVERS",
        {
            "one": DatabaseDriver(module="fake_one"),
            "two": DatabaseDriver(
                module="not_imported", provides=frozenset({"sopuli_no_such_client"})
            ),
        },
    )

    assert cli_module._client_report(_config("one")) == {"one_client": "1.0"}


def test_a_driver_that_will_not_import_is_reported_not_raised(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The install section already names the missing extra; this line says the
    client report could not be written, and why. The detail is keyed by the
    driver, so a second driver's lines cannot overwrite it."""
    (tmp_path / "fake_needs_client.py").write_text("import sopuli_no_such_client\n")
    monkeypatch.syspath_prepend(str(tmp_path))
    monkeypatch.setattr(
        cli_module,
        "DRIVERS",
        {
            "one": DatabaseDriver(
                module="fake_needs_client",
                extra="one",
                provides=frozenset({"sopuli_no_such_client"}),
            )
        },
    )

    report = cli_module._client_report(_config("one"))

    assert report == {
        "one": "not loaded",
        "one_detail": "No module named 'sopuli_no_such_client'",
    }


def test_a_driver_this_build_has_no_module_for_writes_no_lines(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The install section reports it as `not_implemented` and the target's own
    row says so; a client line would only repeat it, naming a Python module."""
    monkeypatch.setattr(
        cli_module, "DRIVERS", {"one": DatabaseDriver(module="sopuli_no_such_module")}
    )

    assert cli_module._client_report(_config("one")) == {}


def test_a_client_report_that_raises_is_reported_not_raised(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`doctor` must survive a broken driver as it survives a broken client."""
    module = ModuleType("fake_broken")

    def broken(*, env: Any, runtime: Any) -> dict[str, Any]:
        raise OSError("the library would not open\nsecond line")

    module.client_report = broken  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "fake_broken", module)
    monkeypatch.setattr(cli_module, "DRIVERS", {"one": DatabaseDriver(module="fake_broken")})

    assert cli_module._client_report(_config("one")) == {
        "one": "no report",
        "one_detail": "the library would not open",
    }


def test_a_failed_target_carries_the_drivers_reach_sentence() -> None:
    error = DriverError("refused", code="X-1")
    error.reach_warning = "the client is too new for this server"

    assert cli_module._reach_warning(error) == ("the client is too new for this server",)
    assert cli_module._reach_warning(DriverError("refused")) == ()
    assert cli_module._reach_warning(ValueError("not a driver error")) == ()
