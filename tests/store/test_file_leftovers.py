"""Which directories ``doctor`` scans for a file store's leftover temporary
files, read from the config (#1430).

Real files in a temporary directory. No key is needed, so these run on a base
install, without the ``file`` extra.
"""

from __future__ import annotations

import os
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from sopuli.config.model import MaterialRef, Vault
from sopuli.store.file import leftovers

NOW = datetime(2026, 11, 10, 12, 0, tzinfo=UTC)
IDENTITY = MaterialRef(kind="env", location="SOPULI_FILE_IDENTITY")


def vault(name: str, addr: str, *, kind: str = "file") -> Vault:
    return Vault(name=name, type=kind, addr=addr, identity=IDENTITY)


def left(directory: Path, *, hours: int = 1) -> Path:
    path = directory / f".sopuli-{'a' * 16}.tmp"
    path.write_bytes(b"ciphertext")
    stamp = (NOW - timedelta(hours=hours)).timestamp()
    os.utime(path, (stamp, stamp))
    return path


def test_one_directory_written_two_ways_is_listed_once(tmp_path: Path) -> None:
    """The second spelling goes through `sub/..`; both name one directory."""
    (tmp_path / "sub").mkdir()
    old = left(tmp_path)
    found = leftovers(
        [
            vault("acme-dev", str(tmp_path / "dev.age")),
            vault("acme-ci", str(tmp_path / "sub" / ".." / "ci.age")),
        ],
        now=NOW,
    )

    (one,) = found
    assert one.stores == ("acme-dev", "acme-ci")
    assert [file.path.name for file in one.files] == [old.name]


def test_two_directories_are_listed_apart(tmp_path: Path) -> None:
    dev, ci = tmp_path / "dev", tmp_path / "ci"
    dev.mkdir()
    ci.mkdir()
    left(dev)
    left(ci)

    found = leftovers(
        [vault("acme-dev", str(dev / "s.age")), vault("acme-ci", str(ci / "s.age"))], now=NOW
    )

    assert [one.stores for one in found] == [("acme-dev",), ("acme-ci",)]


def test_other_stores_and_unusable_addrs_are_skipped(tmp_path: Path) -> None:
    """Never raises: `open_store` and the store's health report a bad addr."""
    left(tmp_path)
    found = leftovers(
        [
            vault("vault-dev", str(tmp_path / "x.age"), kind="hashicorp"),
            vault("relative", "acme-dev.age"),
            vault("missing", str(tmp_path / "gone" / "s.age")),
            vault("nul", str(tmp_path / "bad\x00dir" / "s.age")),
        ],
        now=NOW,
    )

    assert found == ()


@pytest.mark.skipif(sys.platform == "win32", reason="`~user` expansion raises only on POSIX")
def test_a_home_of_a_user_that_does_not_exist_is_skipped() -> None:
    found = leftovers([vault("acme-dev", "~sopuli-no-such-user-1430/s.age")], now=NOW)

    assert found == ()
