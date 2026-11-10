"""The ``file`` store's one file on disk: read it, and replace it whole (#1415).

No encryption here, and no document: this module moves bytes. The store
encrypts before :func:`replace` and decrypts after :func:`read`.

**P4's check on every read.** The tool creates this file and reads it on every
run, which is P4's reason for checking the config file, so the file gets the
config file's check, the owner included (#1415, decision 6). It is made on
the open file, so the file checked is the file read.

**Owner-only from the moment it exists.** The new file is written beside the
old one and then replaces it, so a write that fails part way leaves the old
file as it was. On POSIX the new file is created mode 0600. On Windows it is
created with a DACL that grants the current user alone, with that user as its
owner, and inherits nothing from the directory: the file never has another
user's grant, even for a moment, and P4's check accepts it under an elevated
console too, where a new file's owner would otherwise be ``Administrators``.

**A symbolic link at** ``addr`` **is followed**, for the write as for the read,
so the file the link names is the one replaced and the link stays.

**Not a lock.** :func:`replace` refuses with :class:`FileChangedError` when
the file's hash differs from the hash :func:`read` returned, so a write made
by another run since this one read is refused rather than lost. The
comparison is made just before the replace, after the new file is written
and flushed. Between the two there is no lock, so two runs that compare at
the same moment can both replace. The store reports no ``cas`` for that
reason (#1415, decision 4).
"""

from __future__ import annotations

import contextlib
import hashlib
import os
import secrets
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from sopuli.config.permissions import check_permissions
from sopuli.store.protocol import StoreError

#: What P4's messages call the file.
WHAT = "file store's file"

#: The digest of a file that is not there.
ABSENT = "absent"

#: What to do when the file cannot be read or written for a reason of the
#: file system's.
CHECK_ACCESS = (
    "check that the store's `addr` is right, and that the user running the tool can "
    "read and write the file and its directory"
)


class FileChangedError(StoreError):
    """The store's file changed after this run read it, so nothing was written.

    Not a :class:`~sopuli.store.protocol.CasConflictError`: that says one
    path's version moved, and a caller such as the lock reads it so. This is
    the whole file, changed by a write to any path, or by another program.
    """


@dataclass(frozen=True)
class Read:
    """The file's bytes, or ``None`` where there is no file, and their hash.

    ``digest`` is what :func:`replace` compares the file with. A missing file
    has a digest of its own, so a file created by another run after this one
    found none is refused too.
    """

    data: bytes | None
    digest: str


def digest_of(data: bytes) -> str:
    """The hash :func:`replace` compares, as hex."""
    return hashlib.sha256(data).hexdigest()


def read(path: Path) -> Read:
    """The file at ``path``, after P4's check, or ``data=None`` if there is none.

    Raises :class:`~sopuli.config.errors.ConfigError` when someone other than
    its owner can reach the file, or another user owns it, and
    :class:`StoreError` when it cannot be read for another reason.
    """
    path = _target(path)
    try:
        with path.open("rb") as handle:
            check_permissions(path, what=WHAT, owner=True, status=os.fstat(handle.fileno()))
            data = handle.read()
    except FileNotFoundError:
        return Read(data=None, digest=ABSENT)
    except OSError as error:
        # Windows answers a directory opened as a file with PermissionError.
        if path.is_dir():
            raise StoreError(
                f"the file store's addr {path} is a directory, not a file",
                hint="set `addr` to the path of the store's file",
            ) from None
        # A file this user cannot open may be one P4's check refuses, and its
        # refusal says what to fix. Nothing has been read. The config loader
        # does the same.
        with contextlib.suppress(OSError):
            check_permissions(path, what=WHAT, owner=True)
        raise StoreError(
            f"could not read the file store's file {path}: {error.strerror or error}",
            hint=CHECK_ACCESS,
        ) from None
    return Read(data=data, digest=digest_of(data))


def replace(path: Path, data: bytes, *, expected: str) -> None:
    """Write ``data`` as the file at ``path``, if the file is still what was read.

    ``expected`` is the :attr:`Read.digest` of the read this write was made
    from. A file that has changed since, appeared or gone is refused with
    :class:`FileChangedError`: another writer was here, and its write would
    be lost. The directory must exist; the tool does not create it.
    """
    path = _target(path)
    directory = path.parent
    if not directory.is_dir():
        raise StoreError(
            f"the directory of the file store's file {path} does not exist",
            hint="create the directory, readable only by the user that runs the tool",
        )
    temporary = directory / f".{path.name}.{secrets.token_hex(8)}.tmp"
    try:
        with _create_owner_only(temporary) as handle:
            # A file object's write writes everything, where os.write may
            # write part.
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        # As late as it can be: the slow part of the write is done.
        if _current_digest(path) != expected:
            raise FileChangedError(
                f"the file store's file {path} changed after this run read it",
                hint=(
                    "another run, or another program, wrote the store meanwhile; nothing "
                    "was written. Run the command again"
                ),
            )
        os.replace(temporary, path)
    except BaseException as error:
        with contextlib.suppress(OSError):
            os.unlink(temporary)
        if isinstance(error, OSError):
            raise StoreError(
                f"could not write the file store's file {path}: {error.strerror or error}",
                hint=f"nothing was written; {CHECK_ACCESS}",
            ) from None
        raise
    # The new file is in place. A directory that cannot be flushed, as on
    # some network file systems, does not make the write a failure.
    with contextlib.suppress(OSError):
        _sync_directory(directory)


def _target(path: Path) -> Path:
    """``path``, or what a symbolic link at ``path`` names, followed to the end."""
    try:
        return path.resolve() if path.is_symlink() else path
    except OSError as error:
        raise StoreError(
            f"could not follow the link at the file store's addr {path}: {error.strerror or error}",
            hint=CHECK_ACCESS,
        ) from None


def _current_digest(path: Path) -> str:
    """The digest of the file at ``path`` now, with no permission check.

    :func:`read` checked the file when it was read. This only compares, and
    an :class:`OSError` here is :func:`replace`'s to report.
    """
    try:
        return digest_of(path.read_bytes())
    except FileNotFoundError:
        return ABSENT


def _create_owner_only(path: Path) -> BinaryIO:
    """A new file at ``path``, open for writing, that only its owner can reach.

    Created exclusively, so the name cannot be a file put there first.
    """
    if sys.platform == "win32":
        return os.fdopen(_create_windows(path), "wb")
    return os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb")


def _sync_directory(directory: Path) -> None:
    """Flush the directory entry the replace changed, where the platform can.

    Windows cannot open a directory this way, and NTFS journals the rename.
    """
    if sys.platform == "win32":
        return
    descriptor = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _create_windows(path: Path) -> int:  # pragma: no cover - Windows only
    """Create ``path`` with a DACL that grants the current user alone, as its
    owner, inheriting nothing, and return a file descriptor open for writing.

    The security descriptor is given to ``CreateFile``, so the file has it
    from the moment it exists.
    """
    # Narrows the platform, so mypy on Linux skips what follows.
    assert sys.platform == "win32"
    import msvcrt

    import ntsecuritycon
    import win32api
    import win32con
    import win32file
    import win32security

    token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32security.TOKEN_QUERY)
    user = win32security.GetTokenInformation(token, win32security.TokenUser)[0]
    dacl = win32security.ACL()
    dacl.AddAccessAllowedAce(win32security.ACL_REVISION, ntsecuritycon.FILE_ALL_ACCESS, user)
    descriptor = win32security.SECURITY_DESCRIPTOR()
    descriptor.SetSecurityDescriptorOwner(user, False)
    descriptor.SetSecurityDescriptorDacl(True, dacl, False)
    descriptor.SetSecurityDescriptorControl(
        win32security.SE_DACL_PROTECTED, win32security.SE_DACL_PROTECTED
    )
    attributes = win32security.SECURITY_ATTRIBUTES()
    attributes.SECURITY_DESCRIPTOR = descriptor
    try:
        handle = win32file.CreateFile(
            str(path),
            win32con.GENERIC_WRITE,
            0,
            attributes,
            win32con.CREATE_NEW,
            win32con.FILE_ATTRIBUTE_NORMAL,
            None,
        )
    except win32file.error as error:
        raise OSError(error.winerror, error.strerror, str(path)) from None
    # Detach returns the handle's integer value, though the stubs say PyHANDLE.
    return msvcrt.open_osfhandle(int(handle.Detach()), os.O_WRONLY | os.O_BINARY)
