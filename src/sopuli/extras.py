"""Asking whether an install extra is present, and reading an import failure.

ADR-006 makes every dependency that exists only to reach one vendor an install
extra, and rules 1 and 2 say what that means at run time: a vendor client is
imported inside its own module on first use, and a missing one is a diagnosable
condition rather than a traceback. Two registries implement that now -- stores
and drivers -- and this is what they share.

**What is shared is the mechanism, not the message.** The wording of a refusal
belongs to the thing being refused: a store is named by ``vaults:`` and a driver
by a target's ``type:``, and a message that tried to serve both would name
neither. So each registry keeps its own dataclass, its own error classes and its
own sentences, and takes from here the two pieces that are genuinely one piece:

* :func:`installed`, which answers *without importing*;
* :func:`missing_kind`, which is the three-way reading of a
  ``ModuleNotFoundError``.

The second is the reason this module exists at all. Three different failures
arrive as the same exception and only one of them is "install the extra" -- and
the expensive mistake, a bare ``except ImportError`` that sends somebody to `pip`
forever over a typo of ours, is exactly the kind of subtlety that rots when it is
written down twice. One copy, two callers, one place to be right.
"""

from __future__ import annotations

import functools
import importlib.metadata
import importlib.util
import re
from collections.abc import Collection

#: The extra's client is genuinely not installed. The operator runs `pip`.
MISSING_CLIENT = "client"

#: This build has no module for something the config may legitimately name.
#: Nothing the operator installs fixes it, so the message must not carry an
#: install line.
MISSING_MODULE = "module"


def install_command(extra: str) -> str:
    """The line an operator can paste.

    ``sopuli-dba``, not ``sopuli``. D1 splits the two -- the binary is ``sopuli``
    and the distribution is ``sopuli-dba`` -- and this is the one place the
    difference is load-bearing rather than cosmetic, because it is the half that
    goes into `pip`.
    """
    return f'pip install "sopuli-dba[{extra}]"'


def pipx_install_command(extra: str) -> str:
    """The line for an install that pipx made.

    The pip line is wrong there: it installs a second copy into the user's own
    Python, and the copy that ran still has no client. ``pipx install --force``
    replaces the install with exactly the extras it names, so the line names the
    extras already present as well as the missing one. Without them, the fix for
    one backend would remove another.
    """
    wanted = sorted({*present_extras(), extra})
    return f'pipx install --force "sopuli-dba[{",".join(wanted)}]"'


def install_hint(extra: str) -> str:
    """Both lines, for a message a person reads.

    The tool does not try to tell whether pipx made the install. pipx does not
    promise the layout that such a guess would read, and a wrong guess sends the
    reader to the wrong command. Decided in #902.
    """
    return f"{install_command(extra)}, or after a pipx install:  {pipx_install_command(extra)}"


#: Extras that do not name a vendor client. ``all`` is the others together, and
#: ``dev`` is the test tools. Neither belongs in an install line for an operator.
_NOT_A_CLIENT = frozenset({"all", "dev"})

_EXTRA_MARKER = re.compile(r"""extra\s*==\s*["']([^"']+)["']""")
_REQUIREMENT_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")


@functools.cache
def present_extras() -> frozenset[str]:
    """The extras whose every dependency is installed, read from package metadata.

    The extras and their dependencies come from the installed ``sopuli-dba``
    distribution, which ``pyproject.toml`` wrote, so this keeps no second copy of
    that list. A dependency counts as present when its distribution is installed.
    The version is not checked: the answer only decides which names go in an
    install line, and pipx checks versions when it runs that line.

    Two extras can share a dependency, as ``hashicorp`` and ``notify`` share
    ``httpx``. Both then count as present. Naming an extra whose dependencies
    are already installed costs nothing.

    Without the distribution's metadata, for example when running from a source
    tree that was never installed, the answer is empty, and the line names only
    the missing extra.
    """
    try:
        requires = importlib.metadata.requires("sopuli-dba") or []
    except importlib.metadata.PackageNotFoundError:
        return frozenset()

    by_extra: dict[str, list[str]] = {}
    for requirement in requires:
        marker = _EXTRA_MARKER.search(requirement)
        name = _REQUIREMENT_NAME.match(requirement)
        if marker is None or name is None:
            continue
        by_extra.setdefault(marker.group(1), []).append(name.group(0))

    return frozenset(
        extra
        for extra, names in by_extra.items()
        if extra not in _NOT_A_CLIENT and all(_distribution_installed(name) for name in names)
    )


def _distribution_installed(name: str) -> bool:
    try:
        importlib.metadata.distribution(name)
    except importlib.metadata.PackageNotFoundError:
        return False
    return True


def installed(provides: Collection[str]) -> bool:
    """Whether every module in ``provides`` is importable, **without importing**.

    :func:`importlib.util.find_spec` looks a module up on the path and stops
    there, which is what keeps this true to ADR-006 rule 3: asking the question
    must not run a vendor package's import side effects, which for an SDK can
    mean reading a config file or reaching a metadata service.

    An empty ``provides`` is vacuously installed -- there is no client to look
    for. That keeps ``config validate`` quiet about a backend with no extra
    rather than warning that something unnamed is missing.

    An unanswerable question returns ``True`` rather than ``False``: a
    namespace-package edge or a broken ``sys.path`` entry is not evidence of a
    missing install, and reporting one would send somebody to `pip` for a path
    problem. Resolution will produce the real error a moment later.
    """
    try:
        return all(importlib.util.find_spec(name) is not None for name in provides)
    except ImportError:
        return True


def missing_kind(
    exc: ModuleNotFoundError, *, module: str, provides: Collection[str], extra: str | None
) -> str | None:
    """Which of ADR-006's three failures this is, or ``None`` to re-raise.

    ============================================ ====================
    What actually happened                       Answer
    ============================================ ====================
    the extra's client is not installed          :data:`MISSING_CLIENT`
    this build has no module for that name       :data:`MISSING_MODULE`
    a bad import *inside* the vendor module      ``None``
    ============================================ ====================

    **Fails closed**, matching exactly what it can name and disclaiming the
    rest. The third row is the one a bare ``except ImportError`` gets wrong, and
    getting it wrong is expensive in both directions: the operator is sent to
    `pip` for something `pip` cannot fix, and the project loses the stack trace
    of its own bug. A module that exists and cannot import itself is ours to
    fix, so the caller re-raises it unchanged.
    """
    if extra is not None and exc.name in provides:
        return MISSING_CLIENT
    if exc.name == module:
        return MISSING_MODULE
    return None
