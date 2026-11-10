"""The ``file`` store's one file on disk: read it, and replace it whole (#1415).

No encryption here, and no document: this module moves bytes. The store
encrypts before :func:`replace` and decrypts after :func:`read`.

**P4's check on every read.** The tool creates this file and reads it on every
run, which is P4's reason for checking the config file, so the file gets the
same check (#1415, decision 6). It is made on the open file, so the file
checked is the file read.

**Owner-only on every write.** The new file is written beside the old one,
readable and writable by its owner only, and then replaces it. A write that
fails part way leaves the old file as it was, and a temporary file that is
removed. On POSIX the temporary file is mode 0600. On Windows it gets a DACL
that grants the current user alone and inherits nothing from the directory,
which is what :func:`sopuli.config.permissions.check_permissions` accepts.

**Not a lock.** :func:`replace` refuses when the file's hash differs from the
hash :func:`read` returned, so a write made by another run since this one read
is refused rather than lost. Between that comparison and the replace there is
no lock, so two runs that compare at the same moment can still both replace.
The store reports no ``cas`` for that reason (#1415, decision 4).
"""

from __future__ import annotations

import contextlib
import hashlib
import os
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from sopuli.config.permissions import check_permissions
from sopuli.store.protocol import CasConflictError, StoreError

#: What P4's messages call the file.
WHAT = "file store's file"


@dataclass(frozen=True)
class Read:
    """The file's bytes, or ``None`` where there is no file, and their hash.

    ``digest`` is what :func:`replace` compares the file with. A missing file
    has a digest of its own, so a file created by another run after this one
    found none is refused too.
    """

    data: bytes | None
    digest: str


#: The digest of a file that is not there.
ABSENT = "absent"


def digest_of(data: bytes) -> str:
    """The hash :func:`replace` compares, as hex."""
    return hashlib.sha256(data).hexdigest()


def read(path: Path) -> Read:
    """The file at ``path``, after P4's check, or ``data=None`` if there is none.

    Raises :class:`~sopuli.config.errors.ConfigError` when someone other than
    its owner can reach the file, and :class:`StoreError` when it cannot be
    read for another reason.
    """
    try:
        with path.open("rb") as handle:
            check_permissions(path, what=WHAT, status=os.fstat(handle.fileno()))
            data = handle.read()
    except FileNotFoundError:
        return Read(data=None, digest=ABSENT)
    except (IsADirectoryError, PermissionError) as error:
        # Windows answers a directory opened as a file with PermissionError.
        if not path.is_dir():
            raise StoreError(
                f"could not read the file store's file {path}: {error.strerror or error}",
                hint=(
                    "the store's file must be readable and writable by the user that runs the tool"
                ),
            ) from None
        raise StoreError(
            f"the file store's addr {path} is a directory, not a file",
            hint="set `addr` to the path of the store's file",
        ) from None
    except OSError as error:
        raise StoreError(
            f"could not read the file store's file {path}: {error.strerror or error}",
        ) from None
    return Read(data=data, digest=digest_of(data))


def replace(path: Path, data: bytes, *, expected: str) -> None:
    """Write ``data`` as the file at ``path``, if the file is still what was read.

    ``expected`` is the :attr:`Read.digest` of the read this write was made
    from. A file that has changed since, or appeared, is refused with
    :class:`CasConflictError`: another writer was here, and its write would be
    lost. The directory must exist; the tool does not create it.
    """
    now = _current_digest(path)
    if now != expected:
        raise CasConflictError(
            f"the file store's file {path} changed after this run read it",
            hint=(
                "another run, or another program, wrote the store meanwhile; nothing was "
                "written. Run the command again"
            ),
        )
    directory = path.parent
    if not directory.is_dir():
        raise StoreError(
            f"the directory of the file store's file {path} does not exist",
            hint="create the directory, readable only by the user that runs the tool",
        )
    # mkstemp creates the file with mode 0600 on POSIX, and opens it with
    # O_EXCL, so the name cannot be another file put there first.
    handle, temporary = tempfile.mkstemp(dir=directory, prefix=f".{path.name}.", suffix=".tmp")
    try:
        try:
            if sys.platform == "win32":
                _owner_only(temporary)
            os.write(handle, data)
            os.fsync(handle)
        finally:
            os.close(handle)
        os.replace(temporary, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(temporary)
        raise
    _sync_directory(directory)


def _current_digest(path: Path) -> str:
    """The digest of the file at ``path`` now, with no permission check.

    :func:`read` checked the file when it was read. This only compares.
    """
    try:
        return digest_of(path.read_bytes())
    except FileNotFoundError:
        return ABSENT
    except OSError as error:
        raise StoreError(
            f"could not read the file store's file {path}: {error.strerror or error}",
        ) from None


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


def _owner_only(path: str) -> None:  # pragma: no cover - Windows only
    """Give ``path`` a DACL that grants the current user alone, inheriting nothing.

    A file created in a directory inherits the directory's grants, and a
    directory such as ``C:\\source`` grants ``Authenticated Users`` write.
    """
    import ntsecuritycon
    import win32api
    import win32security

    token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32security.TOKEN_QUERY)
    user = win32security.GetTokenInformation(token, win32security.TokenUser)[0]
    dacl = win32security.ACL()
    dacl.AddAccessAllowedAce(win32security.ACL_REVISION, ntsecuritycon.FILE_ALL_ACCESS, user)
    win32security.SetNamedSecurityInfo(
        path,
        win32security.SE_FILE_OBJECT,
        win32security.DACL_SECURITY_INFORMATION | win32security.PROTECTED_DACL_SECURITY_INFORMATION,
        None,
        None,
        dacl,
        None,
    )
