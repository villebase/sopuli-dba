"""The install lines in :mod:`sopuli.extras`. Tier 0."""

from __future__ import annotations

from sopuli import extras


def test_the_pipx_line_runs_pip_inside_the_pipx_environment() -> None:
    """pip there finds the tool installed and adds only the extra's dependencies.

    That keeps the Python, the version, the source and every other extra, which
    ``pipx install --force`` does not (decision log #902).
    """
    assert extras.pipx_install_command("hashicorp") == (
        'pipx runpip sopuli-dba install "sopuli-dba[hashicorp]"'
    )


def test_the_hint_gives_the_pip_line_first_and_then_the_pipx_line() -> None:
    assert extras.install_hint("hashicorp") == (
        'pip install "sopuli-dba[hashicorp]", or after a pipx install:  '
        'pipx runpip sopuli-dba install "sopuli-dba[hashicorp]"'
    )
