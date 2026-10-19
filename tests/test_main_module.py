"""``python -m sopuli`` runs the tool.

Tier 0. It runs in a subprocess, because what it checks is how the interpreter
starts the package, and an in-process import would not do that.
"""

from __future__ import annotations

import subprocess
import sys

from sopuli.version import get_version


def test_python_dash_m_prints_the_version() -> None:
    finished = subprocess.run(
        [sys.executable, "-m", "sopuli", "--version"],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert finished.returncode == 0, finished.stderr
    assert finished.stdout.strip() == f"sopuli, version {get_version()}"
