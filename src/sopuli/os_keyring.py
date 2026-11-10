"""Reading the tool's own credentials from the OS keyring (#1417).

A ``{ keyring: NAME }`` MaterialRef and an admin credential's ``method:
keyring`` both read one entry here: service :data:`SERVICE`, user name
``NAME``. The entry holds a secret the tool *authenticates with*, such as a
vault token or a target's admin password. It is not a store of managed
passwords. That is the ``keyring`` store type, which this build does not have
(#1373).

**The service is fixed.** The config names only the entry, so the tool decides
how entries are named (decision 2 of #1417). An entry is written through the
same library, which on Windows stores a second entry of one service at the
address ``NAME@sopuli``; an entry written by hand in Credential Manager under
the address ``sopuli`` would replace the first.

**Only an OS keyring counts.** The ``keyring`` library picks a backend by
priority, and it can pick one that is not an OS keyring: ``fail`` and ``null``,
which hold nothing, or the plaintext files of ``keyrings.alt``. A plaintext file
is the ``file:`` source under another name, and a run that reads it while the
config says *keyring* has been told something untrue. So :func:`backend` takes
the highest-priority backend in :data:`OS_BACKENDS` and refuses when there is
none (decision 5). It never falls back to another source.

**Every failure is a** :class:`~sopuli.material.MaterialError`: ``config`` and
exit 9, the error an unset ``env:`` variable gives. The keyring has not refused a
credential; there was nothing to send, and the person reading the message fixes
it on this machine. The message names the entry and the backend.

The library is the ``keyring`` extra (ADR-006), imported on first use.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from sopuli.config.errors import ROOT, MaterialError
from sopuli.extras import install_hint
from sopuli.secrets import Secret

#: The service every entry is stored under. The config names only the user name.
SERVICE = "sopuli"

#: The install extra that carries the `keyring` package (ADR-006).
EXTRA = "keyring"

#: The top-level modules installing :data:`EXTRA` makes importable, for
#: :func:`sopuli.extras.installed`, which asks without importing them.
PROVIDES = frozenset({"keyring"})

#: The modules of the backends that are an OS keyring: Windows Credential
#: Manager, the macOS Keychain, and the Secret Service API (through D-Bus or
#: libsecret) or KWallet on Linux. Keyed on the module because the library
#: names its classes `Keyring` in more than one of them.
OS_BACKENDS = frozenset(
    {
        "keyring.backends.Windows",
        "keyring.backends.macOS",
        "keyring.backends.SecretService",
        "keyring.backends.libsecret",
        "keyring.backends.kwallet",
    }
)

#: The library's backend that wraps several others.
_CHAINER = "keyring.backends.chainer"


def describe(entry: str) -> str:
    """``the OS keyring entry sopuli/NAME``, for a message or a plan."""
    return f"the OS keyring entry {SERVICE}/{entry}"


def read(entry: str, *, where: str) -> Secret:
    """The value of ``entry``, or a :class:`~sopuli.material.MaterialError`.

    ``where`` names the position that asked, as :func:`sopuli.material.resolve`
    does. An empty value counts as missing, by §6's rule for an empty variable.
    """
    chosen = backend(where=where)
    try:
        value = chosen.get_password(SERVICE, entry)
    except Exception as error:  # noqa: BLE001 - see below
        # Any exception, not only `KeyringError` and `OSError`: a backend lets
        # its platform's own errors through. On Windows that is win32ctypes'
        # `pywintypes.error`, which is neither -- a scheduled task with no
        # logon session gets it from CredRead -- and on Linux it is a D-Bus
        # error. Each is "could not read", and a traceback would hide the entry.
        raise MaterialError(
            f"{where}: could not read {describe(entry)} from {name_of(chosen)}: "
            f"{type(error).__name__}: {error}",
            at=ROOT,
            hint=(
                "the keyring may be locked, or this session cannot reach it. Unlock it, "
                "or run as the user who wrote the entry. A Windows scheduled task set to "
                "run whether the user is logged on or not reads the entries only when "
                "it stores the user's password"
            ),
        ) from error
    if not value:
        raise MaterialError(
            f"{where}: {describe(entry)} is not in {name_of(chosen)}",
            at=ROOT,
            hint=(
                "the entry is read as the user this command runs as. A Windows "
                "scheduled task reads only the entries of the user it runs as"
            ),
        )
    return Secret(value)


def backend(*, where: str) -> Any:
    """The OS keyring backend, or a :class:`~sopuli.material.MaterialError`.

    **Chosen once per process.** Choosing reads each backend's priority, and on
    Linux the Secret Service and KWallet priorities each open a D-Bus
    connection. An estate whose targets each name an entry would otherwise
    choose again for every target. The cache is keyed on :data:`loader`, so a
    test that replaces it chooses again.
    """
    global _chosen
    if _chosen is not None and _chosen[0] is loader:
        return _chosen[1]
    library = _load(where=where)
    try:
        found = library.get_keyring()
        candidates = list(found.backends) if _module(found) == _CHAINER else [found]
    except Exception as error:  # noqa: BLE001 - the library sets itself up here
        # `get_keyring()` reads PYTHON_KEYRING_BACKEND and keyringrc and imports
        # what they name, and the chainer asks every backend whether it is
        # viable. Any of that can fail with an error of its own.
        raise MaterialError(
            f"{where}: the keyring library could not choose a backend: "
            f"{type(error).__name__}: {error}",
            at=ROOT,
            hint=_SETTING_HINT,
        ) from error
    chosen = choose(candidates)
    if chosen is None:
        raise _no_os_keyring(candidates, where=where)
    _chosen = (loader, chosen)
    return chosen


def choose(candidates: list[Any]) -> Any | None:
    """The first candidate that is an OS keyring, or ``None``.

    Pure, so the refusal of a plaintext or empty backend is testable without
    one. The library's chainer lists its backends highest priority first, so
    the first OS keyring in its order is the one it would have used; a single
    backend is a list of one.
    """
    for candidate in candidates:
        if _module(candidate) in OS_BACKENDS:
            return candidate
    return None


def name_of(chosen: Any) -> str:
    """``keyring.backends.Windows.WinVaultKeyring`` -- which backend, for a message."""
    return f"{_module(chosen)}.{type(chosen).__name__}"


def _module(candidate: Any) -> str:
    return type(candidate).__module__


#: The library's backends that hold nothing: no keyring was found.
_EMPTY = frozenset({"keyring.backends.fail", "keyring.backends.null"})

_SETTING_HINT = (
    "the environment variable PYTHON_KEYRING_BACKEND, or the keyring library's "
    "keyringrc.cfg, may name a backend; remove that setting to use the OS keyring"
)

#: Where no OS keyring is reachable: a Linux server, usually.
_SERVER_HINT = (
    "on Linux a keyring needs a desktop session (Secret Service), and a scheduled "
    "run on a server usually has none. Use `env:` or `file:` there instead"
)


def _no_os_keyring(candidates: list[Any], *, where: str) -> MaterialError:
    """The refusal, worded by what the library found.

    Only empty backends means there is no keyring here, which on Linux usually
    means no desktop session. Anything else is a backend that is not an OS
    keyring, offered either because a setting names it or because a package
    such as ``keyrings.alt`` is installed and nothing better was reachable. The
    message cannot tell those apart, so the hint names both.
    """
    seen = ", ".join(name_of(one) for one in candidates) or "none"
    if all(_module(one) in _EMPTY for one in candidates):
        return MaterialError(
            f"{where}: no OS keyring is available here (the keyring library found: {seen})",
            at=ROOT,
            hint=_SERVER_HINT,
        )
    return MaterialError(
        f"{where}: no OS keyring is available here; the keyring library offered only "
        f"{seen}, which is not one",
        at=ROOT,
        hint=(
            "a setting may name that backend (PYTHON_KEYRING_BACKEND, or the keyring "
            "library's keyringrc.cfg), or the package that provides it, such as "
            "keyrings.alt, is installed: remove the setting or the package. " + _SERVER_HINT
        ),
    )


#: Imports the library. A seam for tests, which replace it with a fake.
Loader = Callable[[], Any]

#: The loader and the backend :func:`backend` chose with it. Keyed on the
#: loader so that a test which replaces it chooses again.
_chosen: tuple[Loader, Any] | None = None


def _import() -> Any:
    import keyring

    return keyring


loader: Loader = _import


def _load(*, where: str) -> Any:
    try:
        return loader()
    except ImportError as error:
        # Only `import keyring` runs here, so any import failure is the
        # install's: the package itself missing, or a dependency of it, such as
        # one of its `jaraco` packages, left out by a partial install.
        missing = (
            "is not installed"
            if getattr(error, "name", None) == "keyring"
            else (f"could not be imported: {error}")
        )
        raise MaterialError(
            f"{where}: reading the OS keyring needs the keyring package, which {missing}",
            at=ROOT,
            hint=f"install it with:  {install_hint(EXTRA)}",
        ) from error
