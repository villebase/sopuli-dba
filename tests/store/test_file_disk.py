"""The ``file`` store's file on disk: P4's check, owner-only replace, the hash check.

Real files in a temporary directory, as ``tests/config/test_permissions.py``
uses: a mode or a DACL that was mocked would test the mock. Each
platform-specific test skips with a reason on the other platform.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from sopuli.config.errors import ConfigError
from sopuli.config.permissions import check_permissions
from sopuli.store.file import _disk
from sopuli.store.file._disk import ABSENT, digest_of, read, replace
from sopuli.store.protocol import CasConflictError, StoreError

posix_only = pytest.mark.skipif(
    sys.platform == "win32", reason="POSIX file modes; Windows has no st_mode worth reading"
)
windows_only = pytest.mark.skipif(
    sys.platform != "win32", reason="Windows ACLs; there is no DACL to walk on this platform"
)

#: Everyone, by SID, so the grant does not depend on Windows' language.
EVERYONE = "*S-1-1-0"


def _icacls(*args: str) -> None:
    result = subprocess.run(["icacls", *args], capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.fixture
def store_file(tmp_path: Path) -> Path:
    return tmp_path / "store.age"


def leftovers(directory: Path) -> list[str]:
    return sorted(one.name for one in directory.iterdir() if one.name.endswith(".tmp"))


# -------------------------------------------------------------------- read ---


def test_a_missing_file_reads_as_none_with_the_absent_digest(store_file: Path) -> None:
    found = read(store_file)

    assert found.data is None
    assert found.digest == ABSENT


def test_a_file_written_by_replace_reads_back(store_file: Path) -> None:
    replace(store_file, b"ciphertext", expected=ABSENT)

    found = read(store_file)

    assert found.data == b"ciphertext"
    assert found.digest == digest_of(b"ciphertext")


def test_a_directory_at_addr_is_refused(tmp_path: Path) -> None:
    with pytest.raises(StoreError, match="is a directory, not a file"):
        read(tmp_path)


@posix_only
@pytest.mark.parametrize("mode", [0o640, 0o604, 0o660])
def test_read_refuses_a_file_others_can_reach(store_file: Path, mode: int) -> None:
    store_file.write_bytes(b"ciphertext")
    store_file.chmod(mode)

    with pytest.raises(ConfigError, match="file store's file is accessible to others"):
        read(store_file)


@windows_only
def test_read_refuses_a_file_everyone_can_read(store_file: Path) -> None:
    replace(store_file, b"ciphertext", expected=ABSENT)
    _icacls(str(store_file), "/grant", f"{EVERYONE}:R")

    with pytest.raises(ConfigError, match="file store's file is accessible to"):
        read(store_file)


# ----------------------------------------------------------------- replace ---


@posix_only
def test_replace_creates_the_file_owner_only_whatever_the_umask(store_file: Path) -> None:
    previous = os.umask(0)
    try:
        replace(store_file, b"ciphertext", expected=ABSENT)
    finally:
        os.umask(previous)

    assert store_file.stat().st_mode & 0o777 == 0o600


@posix_only
def test_replace_leaves_a_wider_file_owner_only(store_file: Path) -> None:
    store_file.write_bytes(b"old")
    store_file.chmod(0o644)

    replace(store_file, b"new", expected=digest_of(b"old"))

    assert store_file.stat().st_mode & 0o777 == 0o600


@windows_only
def test_replace_inherits_nothing_from_a_directory_everyone_can_write(tmp_path: Path) -> None:
    """The directory grants Everyone write to every file made in it. A file
    written the ordinary way there is refused by P4's check; the store's own
    file is accepted."""
    shared = tmp_path / "shared"
    shared.mkdir()
    _icacls(str(shared), "/grant", f"{EVERYONE}:(OI)(CI)M")
    ordinary = shared / "ordinary"
    ordinary.write_bytes(b"x")
    with pytest.raises(ConfigError):
        check_permissions(ordinary)

    store_file = shared / "store.age"
    replace(store_file, b"ciphertext", expected=ABSENT)

    check_permissions(store_file, what=_disk.WHAT)
    assert read(store_file).data == b"ciphertext"


def test_replace_refuses_a_file_changed_since_the_read(store_file: Path) -> None:
    replace(store_file, b"first", expected=ABSENT)
    seen = read(store_file)
    replace(store_file, b"another run", expected=seen.digest)

    with pytest.raises(CasConflictError, match="changed after this run read it"):
        replace(store_file, b"this run", expected=seen.digest)

    assert read(store_file).data == b"another run"


def test_replace_refuses_a_file_that_appeared_since_the_read(store_file: Path) -> None:
    seen = read(store_file)
    replace(store_file, b"another run", expected=ABSENT)

    with pytest.raises(CasConflictError):
        replace(store_file, b"this run", expected=seen.digest)


def test_replace_refuses_a_file_removed_since_the_read(store_file: Path) -> None:
    replace(store_file, b"first", expected=ABSENT)
    seen = read(store_file)
    store_file.unlink()

    with pytest.raises(CasConflictError):
        replace(store_file, b"this run", expected=seen.digest)

    assert not store_file.exists()


def test_replace_does_not_create_the_directory(tmp_path: Path) -> None:
    missing = tmp_path / "missing" / "store.age"

    with pytest.raises(StoreError, match="does not exist"):
        replace(missing, b"ciphertext", expected=ABSENT)

    assert not missing.parent.exists()


def test_a_failed_replace_keeps_the_old_file_and_removes_the_temporary_one(
    store_file: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    replace(store_file, b"old", expected=ABSENT)

    def refuse(source: str, target: object) -> None:
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(os, "replace", refuse)

    with pytest.raises(OSError, match="No space left"):
        replace(store_file, b"new", expected=digest_of(b"old"))

    monkeypatch.undo()
    assert read(store_file).data == b"old"
    assert leftovers(store_file.parent) == []


def test_a_replace_leaves_no_temporary_file(store_file: Path) -> None:
    replace(store_file, b"one", expected=ABSENT)
    replace(store_file, b"two", expected=digest_of(b"one"))

    assert leftovers(store_file.parent) == []
