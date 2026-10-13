"""Debug lines for what the Oracle driver sends (#782).

Every cursor the driver opens is a :class:`TracedCursor`, from
:func:`traced_cursor`. It writes one debug line for each statement: the time the
call took and the statement text. With ``--debug`` off, a line costs one level
check.

**A statement that carries a password is logged in its redacted form.**
:func:`TracedCursor.execute` takes a :class:`~sopuli.driver.oracle.statements.Statement`
as well as a string. It logs the statement's ``redacted`` text and sends the
revealed text, so the plaintext and the debug line never meet. This is why the
``reveal()`` that issues the DDL is here and not in the session: it is
invariant 2's driver call, and the line beside it is the only place that could
log it.

**A bind is logged by its name, never its value.** No password is ever bound
(invariant 14), so no value would hold one. The rule is kept anyway: a reader of
debug output needs to know which binds a query had, not what an account name
was.

**A failure is logged by its code.** The server's message reaches the operator
through the error the session raises, so it is not repeated here.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from sopuli.driver.oracle.errors import from_error
from sopuli.driver.oracle.statements import Statement
from sopuli.output.debug import logger

LOG = logger("oracle")


class TracedCursor:
    """A database cursor that writes a debug line for each call."""

    def __init__(self, cursor: Any) -> None:
        self._cursor = cursor

    def execute(self, statement: str | Statement, *parameters: Any) -> Any:
        """Execute ``statement``, and log its redacted text and the time it took.

        ``parameters`` are passed on as given, so that a caller's
        ``execute(sql)`` and ``execute(sql, None)`` reach the client unchanged.
        """
        if isinstance(statement, Statement):
            shown, sql = statement.redacted, statement.reveal()
        else:
            shown, sql = statement, statement
        started = time.monotonic()
        try:
            result = self._cursor.execute(sql, *parameters)
        except Exception as error:
            _log(started, f"failed with {_code(error)}: {_one_line(shown)}", parameters)
            raise
        _log(started, _one_line(shown), parameters)
        return result

    def callproc(self, name: str, parameters: Any = None) -> Any:
        """Call ``name``, and log its name and the time it took. Never its arguments."""
        started = time.monotonic()
        try:
            result = self._cursor.callproc(name, parameters)
        except Exception as error:
            _log(started, f"failed with {_code(error)}: call {name}", ())
            raise
        _log(started, f"call {name}", ())
        return result

    def fetchone(self) -> Any:
        return self._cursor.fetchone()

    def fetchall(self) -> Any:
        return self._cursor.fetchall()

    def __getattr__(self, name: str) -> Any:
        return getattr(self._cursor, name)


@contextmanager
def traced_cursor(connection: Any) -> Iterator[TracedCursor]:
    """A cursor on ``connection`` that logs each statement, closed when the block ends."""
    with connection.cursor() as cursor:
        yield TracedCursor(cursor)


def _log(started: float, text: str, parameters: tuple[Any, ...]) -> None:
    if not LOG.isEnabledFor(logging.DEBUG):
        return
    names = _bind_names(parameters)
    binds = f" (binds {names})" if names else ""
    LOG.debug("%s%s in %.3fs", text, binds, time.monotonic() - started)


def _bind_names(parameters: tuple[Any, ...]) -> str:
    """The names of the binds, or ``""``. Positional binds have no name to show."""
    if parameters and isinstance(parameters[0], dict):
        return ", ".join(f":{name}" for name in parameters[0])
    return ""


def _one_line(text: str) -> str:
    """The statement on one line. A dictionary query is written across several."""
    return " ".join(text.split())


def _code(error: Exception) -> str:
    return from_error(error).code or type(error).__name__
