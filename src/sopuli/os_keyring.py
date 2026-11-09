"""Reading the tool's own credentials from the OS keyring (#1417).

A ``{ keyring: NAME }`` MaterialRef and an admin credential's ``method:
keyring`` both read one entry here: service :data:`SERVICE`, user name
``NAME``. The entry holds a secret the tool *authenticates with*, such as a
vault token or a target's admin password. It is not a store of managed
passwords. That is the ``keyring`` store type, which this build does not have
(#1373).

**The service is fixed.** The config names only the entry, so the tool decides
how entries are named, and ``sopuli keyring set NAME`` writes the entry this
module reads (decision 2 of #1417).

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

from sopuli.config.errors import ROOT
from sopuli.extras import install_hint
from sopuli.material import MaterialError
from sopuli.secrets import Secret

#: The service every entry is stored under. The config names only the user name.
SERVICE = "sopuli"

#: The install extra that carries the `keyring` package (ADR-006).
EXTRA = "keyring"

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
    except _keyring_errors() as error:
        raise MaterialError(
            f"{where}: could not read {describe(entry)} from {name_of(chosen)}: {error}",
            at=ROOT,
            hint=_unlock_hint(),
        ) from error
    if not value:
        raise MaterialError(
            f"{where}: {describe(entry)} is not in {name_of(chosen)}",
            at=ROOT,
            hint=(
                f"write a generic entry with the service `{SERVICE}` and the user name "
                f"`{entry}`, as the user this command runs as. A Windows scheduled task "
                "reads only the entries of the user it runs as"
            ),
        )
    return Secret(value)


def backend(*, where: str) -> Any:
    """The OS keyring backend, or a :class:`~sopuli.material.MaterialError`."""
    library = _load(where=where)
    found = library.get_keyring()
    candidates = list(found.backends) if _module(found) == _CHAINER else [found]
    chosen = choose(candidates)
    if chosen is None:
        seen = ", ".join(name_of(one) for one in candidates) or "none"
        raise MaterialError(
            f"{where}: no OS keyring is available here (the keyring library found: {seen})",
            at=ROOT,
            hint=(
                "a keyring needs a desktop session on Linux (Secret Service), and a "
                "scheduled run on a server usually has none. Use `env:` or `file:` "
                "there instead"
            ),
        )
    return chosen


def choose(candidates: list[Any]) -> Any | None:
    """The highest-priority candidate that is an OS keyring, or ``None``.

    Pure, so the refusal of a plaintext or empty backend is testable without
    one. The library's chainer lists its backends highest priority first; a
    single backend is a list of one.
    """
    for candidate in sorted(candidates, key=_priority, reverse=True):
        if _module(candidate) in OS_BACKENDS:
            return candidate
    return None


def name_of(chosen: Any) -> str:
    """``keyring.backends.Windows.WinVaultKeyring`` -- which backend, for a message."""
    return f"{_module(chosen)}.{type(chosen).__name__}"


def _module(candidate: Any) -> str:
    return type(candidate).__module__


def _priority(candidate: Any) -> float:
    try:
        return float(candidate.priority)
    except Exception:  # noqa: BLE001 - a backend whose priority cannot be read ranks last
        return float("-inf")


#: Imports the library. A seam for tests, which replace it with a fake.
Loader = Callable[[], Any]


def _import() -> Any:
    import keyring

    return keyring


loader: Loader = _import


def _load(*, where: str) -> Any:
    try:
        return loader()
    except ModuleNotFoundError as error:
        if error.name != "keyring":
            raise
        raise MaterialError(
            f"{where}: reading the OS keyring needs the keyring package, which is not installed",
            at=ROOT,
            hint=f"install it with:  {install_hint(EXTRA)}",
        ) from error


def _keyring_errors() -> tuple[type[BaseException], ...]:
    """The library's own error, and the OS errors a backend lets through."""
    try:
        from keyring.errors import KeyringError
    except ModuleNotFoundError:  # a test's fake library has no errors module
        return (OSError,)
    return (KeyringError, OSError)


def _unlock_hint() -> str:
    return (
        "the keyring may be locked, or this session cannot reach it. Unlock it, or "
        "run as the user who wrote the entry"
    )
