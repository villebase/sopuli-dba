"""Debug output: what happened inside a run, written to stderr.

``--debug`` attaches one handler to the ``sopuli`` logger for the length of a
run. Without the flag no handler writes anything, and a debug call costs one
level check. The #629 record in `docs/decisions/log.md` has the decision: one
level, stderr only, no log file, and no config key that turns it on.

Four rules hold it.

**The handler goes on the ``sopuli`` logger, never on the root logger.**
Libraries log through their own loggers, and some log values this tool treats as
secrets. httpx logs every request URL at INFO, and a webhook URL can hold a
token. A handler on the root logger would print those. ``propagate`` is off, so
a record from this tool never reaches a root handler that something else added.

**The formatter is an output serialiser** (invariant 2). A
:class:`~sopuli.secrets.Secret` renders as ``***`` here, as it does in the run
document. That holds for ``%s``, ``%r`` and an f-string, because ``Secret``
redacts itself in all three.

**Without ``--debug``, nothing is written.** The ``sopuli`` logger carries a
:class:`logging.NullHandler` from import, so a record at any level has a
handler and never falls through to :data:`logging.lastResort`, which would
print a warning to stderr.

**Debug output is not a contract.** Invariant 12 covers stdout. A debug line may
change in any release, and a script must not parse one.
"""

from __future__ import annotations

import logging
import sys
import time
import traceback
from collections.abc import Iterator
from contextlib import contextmanager
from types import TracebackType
from typing import TextIO

import click

#: The logger every part of the tool logs under.
ROOT = "sopuli"

#: What each debug line starts with, so it cannot be mistaken for a message.
PREFIX = "sopuli: debug:"

#: How a continuation line is indented: a traceback, or a server message that
#: spans lines.
INDENT = "    "

_root = logging.getLogger(ROOT)
_root.addHandler(logging.NullHandler())
_root.propagate = False


def logger(area: str) -> logging.Logger:
    """The logger for one part of the tool, such as ``"run"`` or ``"oracle"``."""
    return logging.getLogger(f"{ROOT}.{area}")


class DebugFormatter(logging.Formatter):
    """One debug record as text: the time since the run started, the area, the
    message.

    ``sopuli: debug:   0.012s run: command creds.check``

    The time is relative, because what a reader compares is how long one step
    took against another, and a run never crosses midnight in a way that
    matters.
    """

    def __init__(self, started: float) -> None:
        super().__init__()
        self._started = started

    def format(self, record: logging.LogRecord) -> str:
        message = record.getMessage()
        if record.exc_info:
            message = f"{message}\n{self.formatException(record.exc_info)}"
        # No colour, whatever `--color` says: a vendor message or a traceback
        # can arrive with escape sequences in it (`03-json-output.md` §*Colour*).
        message = click.unstyle(message)
        area = record.name.removeprefix(f"{ROOT}.")
        elapsed = record.created - self._started
        first, *rest = message.splitlines() or [""]
        lines = [f"{PREFIX} {elapsed:7.3f}s {area}: {first}"]
        lines.extend(f"{INDENT}{line}" for line in rest)
        return "\n".join(lines)

    def formatException(  # noqa: N802 - overrides `logging.Formatter`
        self,
        ei: tuple[type[BaseException], BaseException, TracebackType | None]
        | tuple[None, None, None],
    ) -> str:
        """The traceback of the exception itself, and its causes by type only.

        An exception the tool raises carries no secret in its message (P5). The
        exception it was raised *from* may: `sopuli.notify.webhook` leaves an
        httpx error's message out of its own, because that message holds the
        URL, and chains the error with ``from``. Python's default would print
        that message. So a cause is named by its type, and nothing more.
        """
        _, exc, tb = ei
        if exc is None:
            return ""
        lines = traceback.format_exception(type(exc), exc, tb, chain=False)
        cause = exc.__cause__ or exc.__context__
        while cause is not None:
            kind = type(cause)
            lines.append(f"caused by {kind.__module__}.{kind.__qualname__}\n")
            cause = cause.__cause__ or cause.__context__
        return "".join(lines).rstrip("\n")


@contextmanager
def debugging(enabled: bool, stream: TextIO | None = None) -> Iterator[None]:
    """Write the ``sopuli`` logger's records to ``stream`` while the block runs.

    ``stream`` defaults to the process's stderr, resolved when the block starts
    rather than at import, so a test runner that replaces ``sys.stderr`` gets the
    output.

    The handler is removed when the block ends, so a second run in the same
    process, as under ``CliRunner``, starts clean.
    """
    if not enabled:
        yield
        return
    handler = logging.StreamHandler(stream if stream is not None else sys.stderr)
    handler.setFormatter(DebugFormatter(time.time()))
    level = _root.level
    _root.addHandler(handler)
    _root.setLevel(logging.DEBUG)
    try:
        yield
    finally:
        _root.removeHandler(handler)
        _root.setLevel(level)
