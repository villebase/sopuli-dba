"""The install lines in :mod:`sopuli.extras`, and which extras count as present.

Tier 0. :func:`~sopuli.extras.present_extras` reads package metadata, so these
tests replace the two :mod:`importlib.metadata` calls it makes. The answer must
not depend on what the machine running the tests has installed.
"""

from __future__ import annotations

import importlib.metadata
from collections.abc import Iterator

import pytest

from sopuli import extras

REQUIRES = [
    "click>=8.1",
    "pywin32>=306; sys_platform == 'win32'",
    "oracledb>=2.0; extra == 'oracle'",
    "httpx>=0.27; extra == 'hashicorp'",
    "httpx>=0.27; extra == 'notify'",
    "oci>=2.126; extra == 'oci'",
    "httpx>=0.27; extra == 'all'",
    "oracledb>=2.0; extra == 'all'",
    "pytest>=8.0; extra == 'dev'",
]


@pytest.fixture(autouse=True)
def _fresh_cache() -> Iterator[None]:
    extras.present_extras.cache_clear()
    yield
    extras.present_extras.cache_clear()


def _installed(monkeypatch: pytest.MonkeyPatch, *names: str) -> None:
    """Make the metadata say that exactly these distributions are installed."""

    def distribution(name: str) -> object:
        if name not in names:
            raise importlib.metadata.PackageNotFoundError(name)
        return object()

    monkeypatch.setattr(importlib.metadata, "requires", lambda _: REQUIRES)
    monkeypatch.setattr(importlib.metadata, "distribution", distribution)


def test_an_extra_is_present_when_every_dependency_is_installed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _installed(monkeypatch, "oracledb", "pytest")

    assert extras.present_extras() == frozenset({"oracle"})


def test_extras_that_share_a_dependency_are_both_present(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _installed(monkeypatch, "httpx")

    assert extras.present_extras() == frozenset({"hashicorp", "notify"})


def test_all_and_dev_are_never_named(monkeypatch: pytest.MonkeyPatch) -> None:
    """``all`` is the others together and ``dev`` is the test tools."""
    _installed(monkeypatch, "oracledb", "httpx", "oci", "pytest")

    assert extras.present_extras() == frozenset({"oracle", "hashicorp", "notify", "oci"})


def test_no_metadata_means_no_present_extras(monkeypatch: pytest.MonkeyPatch) -> None:
    def requires(name: str) -> list[str]:
        raise importlib.metadata.PackageNotFoundError(name)

    monkeypatch.setattr(importlib.metadata, "requires", requires)

    assert extras.present_extras() == frozenset()
    assert extras.pipx_install_command("oracle") == 'pipx install --force "sopuli-dba[oracle]"'


def test_the_pipx_line_keeps_the_extras_already_present(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``--force`` keeps only the extras it names, so a line without them removes them."""
    _installed(monkeypatch, "oracledb")

    assert extras.pipx_install_command("hashicorp") == (
        'pipx install --force "sopuli-dba[hashicorp,oracle]"'
    )


def test_the_hint_gives_the_pip_line_first_and_then_the_pipx_line(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _installed(monkeypatch, "oracledb")

    assert extras.install_hint("hashicorp") == (
        'pip install "sopuli-dba[hashicorp]", or after a pipx install:  '
        'pipx install --force "sopuli-dba[hashicorp,oracle]"'
    )
