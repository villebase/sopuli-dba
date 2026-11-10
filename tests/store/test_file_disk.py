"""The ``file`` store's file on disk: P4's check, owner-only replace, the hash check.

Real files in a temporary directory, as ``tests/config/test_permissions.py``
uses: a mode or a DACL that was mocked would test the mock. Each
platform-specific test skips with a reason on the other platform.
"""

from __future__ import annotations

import os
import secrets
import subprocess
import sys
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from sopuli.config.errors import ConfigError
from sopuli.config.permissions import check_permissions
from sopuli.store.file import _disk
from sopuli.store.file._disk import ABSENT, FileChangedError, digest_of, read, replace
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


@pytest.mark.skipif(sys.platform == "win32", reason="named pipes are a POSIX file type")
def test_a_pipe_at_addr_is_refused_without_waiting(tmp_path: Path) -> None:
    """Opening a pipe would wait for a writer, and the run would hang."""
    pipe = tmp_path / "store.age"
    # By name: Windows has no mkfifo, and mypy runs there too.
    make_fifo = getattr(os, "mkfifo")  # noqa: B009
    make_fifo(pipe, 0o600)

    with pytest.raises(StoreError, match="is not a regular file"):
        read(pipe)


@pytest.mark.skipif(sys.platform == "win32", reason="named pipes are a POSIX file type")
def test_a_pipe_put_at_addr_before_the_replace_is_refused(tmp_path: Path) -> None:
    """The comparison opens the file as the read does, so it does not hang."""
    store_file = tmp_path / "store.age"
    replace(store_file, b"one", expected=ABSENT)
    seen = read(store_file)
    store_file.unlink()
    make_fifo = getattr(os, "mkfifo")  # noqa: B009
    make_fifo(store_file, 0o600)

    with pytest.raises(StoreError, match="is not a regular file"):
        replace(store_file, b"two", expected=seen.digest)


@posix_only
def test_a_link_loop_at_addr_is_a_store_error(tmp_path: Path) -> None:
    """A loop is RuntimeError before Python 3.13, and must not escape."""
    store_file = tmp_path / "store.age"
    store_file.symlink_to(store_file)

    with pytest.raises(StoreError):
        read(store_file)


def test_a_parent_that_is_a_file_is_named_as_such(tmp_path: Path) -> None:
    parent = tmp_path / "not-a-directory"
    parent.write_bytes(b"x")

    with pytest.raises(StoreError, match="could not reach the directory|is not a directory"):
        replace(parent / "store.age", b"ciphertext", expected=ABSENT)


def test_a_long_file_name_can_be_replaced(tmp_path: Path) -> None:
    """The temporary name has a fixed length, whatever the store's name."""
    store_file = tmp_path / ("s" * 240)

    replace(store_file, b"one", expected=ABSENT)
    replace(store_file, b"two", expected=digest_of(b"one"))

    assert read(store_file).data == b"two"


def test_a_temporary_name_that_exists_is_left_alone(
    store_file: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Created exclusively, and never removed when this run did not create it."""
    monkeypatch.setattr(secrets, "token_hex", lambda size: "0" * 16)
    someone_else = store_file.parent / f".sopuli-{'0' * 16}.tmp"
    someone_else.write_bytes(b"not this run's")

    with pytest.raises(StoreError, match="could not write the file store's file"):
        replace(store_file, b"ciphertext", expected=ABSENT)

    assert someone_else.read_bytes() == b"not this run's"
    assert not store_file.exists()


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
@pytest.mark.parametrize("umask", [0o000, 0o022, 0o277, 0o677])
def test_replace_creates_the_file_owner_only_whatever_the_umask(
    store_file: Path, umask: int
) -> None:
    """0600 outright: a strict umask must not leave a file the tool cannot
    read back, nor a lax one a file others can."""
    previous = os.umask(umask)
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

    with pytest.raises(FileChangedError, match="changed after this run read it") as caught:
        replace(store_file, b"this run", expected=seen.digest)

    # Not a path's version conflict, which the lock would read as a stolen lock.
    assert not isinstance(caught.value, CasConflictError)
    assert read(store_file).data == b"another run"


def test_replace_refuses_a_file_that_appeared_since_the_read(store_file: Path) -> None:
    seen = read(store_file)
    replace(store_file, b"another run", expected=ABSENT)

    with pytest.raises(FileChangedError):
        replace(store_file, b"this run", expected=seen.digest)


def test_replace_refuses_a_file_removed_since_the_read(store_file: Path) -> None:
    replace(store_file, b"first", expected=ABSENT)
    seen = read(store_file)
    store_file.unlink()

    with pytest.raises(FileChangedError):
        replace(store_file, b"this run", expected=seen.digest)

    assert not store_file.exists()
    assert leftovers(store_file.parent) == []


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

    with pytest.raises(StoreError, match="could not write the file store's file") as caught:
        replace(store_file, b"new", expected=digest_of(b"old"))

    monkeypatch.undo()
    assert "nothing was written" in (caught.value.hint or "")
    assert read(store_file).data == b"old"
    assert leftovers(store_file.parent) == []


def test_a_replace_leaves_no_temporary_file(store_file: Path) -> None:
    replace(store_file, b"one", expected=ABSENT)
    replace(store_file, b"two", expected=digest_of(b"one"))

    assert leftovers(store_file.parent) == []


def test_the_comparison_sees_a_write_made_while_this_one_was_flushed(
    store_file: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The comparison is made after the slow part, just before the replace."""
    replace(store_file, b"first", expected=ABSENT)
    seen = read(store_file)
    flush = os.fsync

    def another_run_writes(descriptor: int) -> None:
        flush(descriptor)
        monkeypatch.setattr(os, "fsync", flush)
        replace(store_file, b"another run", expected=seen.digest)

    monkeypatch.setattr(os, "fsync", another_run_writes)

    with pytest.raises(FileChangedError):
        replace(store_file, b"this run", expected=seen.digest)

    assert read(store_file).data == b"another run"
    assert leftovers(store_file.parent) == []


def test_a_directory_that_cannot_be_flushed_does_not_fail_a_write_that_landed(
    store_file: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def refuse(directory: Path) -> None:
        raise OSError(22, "Invalid argument")

    monkeypatch.setattr(_disk, "_sync_directory", refuse)

    replace(store_file, b"ciphertext", expected=ABSENT)

    assert read(store_file).data == b"ciphertext"


@posix_only
def test_a_link_at_addr_is_followed_and_kept(tmp_path: Path) -> None:
    target = tmp_path / "volume" / "store.age"
    target.parent.mkdir()
    replace(target, b"first", expected=ABSENT)
    link = tmp_path / "store.age"
    link.symlink_to(target)

    seen = read(link)
    replace(link, b"second", expected=seen.digest)

    assert link.is_symlink()
    assert target.read_bytes() == b"second"


@windows_only
def test_replace_waits_for_a_reader_to_close_the_file(store_file: Path) -> None:
    """Windows refuses to replace an open file; a run that is reading the
    store holds it open for a moment."""
    replace(store_file, b"one", expected=ABSENT)
    reader = store_file.open("rb")
    closer = threading.Timer(0.3, reader.close)
    closer.start()
    try:
        replace(store_file, b"two", expected=digest_of(b"one"))
    finally:
        closer.join()

    assert read(store_file).data == b"two"


@windows_only
def test_each_retry_compares_the_file_again(
    store_file: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A run that held the file open may replace it once it closes. The next
    attempt must see that, not overwrite it."""
    replace(store_file, b"one", expected=ABSENT)
    seen = read(store_file)
    real_replace = os.replace

    def held_then_replaced(source: object, target: object) -> None:
        monkeypatch.setattr(os, "replace", real_replace)
        replace(store_file, b"another run", expected=seen.digest)
        raise PermissionError(5, "Access is denied")

    monkeypatch.setattr(os, "replace", held_then_replaced)

    with pytest.raises(FileChangedError):
        replace(store_file, b"this run", expected=seen.digest)

    assert read(store_file).data == b"another run"
    assert leftovers(store_file.parent) == []


@windows_only
def test_replace_says_another_program_may_hold_the_file(
    store_file: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    replace(store_file, b"one", expected=ABSENT)
    monkeypatch.setattr(_disk, "REPLACE_WAIT", 0.2)

    with store_file.open("rb"), pytest.raises(StoreError) as caught:
        replace(store_file, b"two", expected=digest_of(b"one"))

    assert "another program may have the file open" in (caught.value.hint or "")
    assert read(store_file).data == b"one"
    assert leftovers(store_file.parent) == []


@windows_only
def test_the_new_file_is_owned_by_the_user_and_inherits_nothing(store_file: Path) -> None:
    """Owned by the user, not `Administrators` as under an elevated console,
    so P4's check accepts the one grant."""
    import win32api
    import win32security

    replace(store_file, b"ciphertext", expected=ABSENT)

    descriptor = win32security.GetNamedSecurityInfo(
        str(store_file),
        win32security.SE_FILE_OBJECT,
        win32security.OWNER_SECURITY_INFORMATION | win32security.DACL_SECURITY_INFORMATION,
    )
    token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32security.TOKEN_QUERY)
    user = win32security.GetTokenInformation(token, win32security.TokenUser)[0]
    dacl = descriptor.GetSecurityDescriptorDacl()
    assert descriptor.GetSecurityDescriptorOwner() == user
    assert dacl.GetAceCount() == 1
    assert dacl.GetAce(0)[2] == user


# --------------------------------------------------------------- leftovers ---


def _left(directory: Path, name: str, *, age: timedelta, now: datetime) -> Path:
    """A file named ``name`` in ``directory``, last written ``age`` before ``now``."""
    path = directory / name
    path.write_bytes(b"ciphertext")
    stamp = (now - age).timestamp()
    os.utime(path, (stamp, stamp))
    return path


NOW = datetime(2026, 11, 10, 12, 0, tzinfo=UTC)


def test_leftovers_lists_old_temporary_files_oldest_first(tmp_path: Path) -> None:
    """#1430: a run killed before the replace leaves its file behind."""
    older = _left(tmp_path, f".sopuli-{'a' * 16}.tmp", age=timedelta(hours=3), now=NOW)
    newer = _left(tmp_path, f".sopuli-{'b' * 16}.tmp", age=timedelta(minutes=11), now=NOW)

    found = _disk.leftovers(tmp_path / "store.age", now=NOW)

    assert [one.path for one in found] == [older, newer]
    assert found[0].age == timedelta(hours=3)


def test_leftovers_leaves_out_a_write_in_progress_and_other_names(tmp_path: Path) -> None:
    """A young file may be another run's write, and the store has no lock to
    tell the two apart, so it is not listed. Nor is a name the store never gives."""
    _left(tmp_path, f".sopuli-{'c' * 16}.tmp", age=timedelta(minutes=9), now=NOW)
    _left(tmp_path, ".sopuli-short.tmp", age=timedelta(days=1), now=NOW)
    _left(tmp_path, f".sopuli-{'D' * 16}.tmp", age=timedelta(days=1), now=NOW)
    _left(tmp_path, f"sopuli-{'e' * 16}.tmp", age=timedelta(days=1), now=NOW)
    (tmp_path / f".sopuli-{'f' * 16}.tmp").mkdir()

    assert _disk.leftovers(tmp_path / "store.age", now=NOW) == ()


def test_leftovers_removes_nothing(tmp_path: Path) -> None:
    left = _left(tmp_path, f".sopuli-{'a' * 16}.tmp", age=timedelta(days=2), now=NOW)

    _disk.leftovers(tmp_path / "store.age", now=NOW)

    assert left.exists()


def test_leftovers_of_a_missing_directory_is_nothing(tmp_path: Path) -> None:
    """The store's health reports the directory; this says nothing more."""
    assert _disk.leftovers(tmp_path / "gone" / "store.age", now=NOW) == ()


@posix_only
def test_leftovers_follows_a_link_at_addr(tmp_path: Path) -> None:
    """A write follows the link, so its file is left beside the link's target."""
    volume = tmp_path / "volume"
    volume.mkdir()
    left = _left(volume, f".sopuli-{'a' * 16}.tmp", age=timedelta(hours=1), now=NOW)
    link = tmp_path / "store.age"
    link.symlink_to(volume / "store.age")

    assert [one.path for one in _disk.leftovers(link, now=NOW)] == [left]


def test_replace_names_its_file_as_leftovers_looks_for_it(
    store_file: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The name a write gives is the name the report finds: a file kept by a
    write that failed at the replace is listed once it is old enough."""
    kept: list[str] = []

    def refuse(source: str, destination: str) -> None:
        kept.append(source)
        raise OSError(5, "refused")

    monkeypatch.setattr(os, "replace", refuse)
    monkeypatch.setattr(os, "unlink", lambda path: None)
    with pytest.raises(StoreError):
        replace(store_file, b"ciphertext", expected=ABSENT)

    (name,) = (Path(one).name for one in kept)
    later = datetime.now(UTC) + timedelta(minutes=11)
    assert [one.path.name for one in _disk.leftovers(store_file, now=later)] == [name]
