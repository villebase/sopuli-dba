"""The error numbers MySQL and MariaDB both send, PyMySQL's own, and how a
PyMySQL exception is classified. Tier 0.

A number is here when ``sql/mariadb/`` measured MariaDB sending it as
``sql/mysql/`` measured MySQL sending it, or when PyMySQL raises it, whichever
server is behind it. Each row's hint holds on both servers. A driver adds its
own numbers, and may give a shared number a hint that names its own config
keys or plugin, as :mod:`sopuli.driver.mysql.errors` does.

PyMySQL raises a server error, and most failures of its own to reach the
server, as an exception whose ``args`` are ``(number, message)`` and whose
``sqlstate`` is the server's where the reply carried one (PyMySQL 1.2.3,
``err.raise_mysql_exception``). Numbers from 2000 to 2999 are the client's
own, such as 2003 for a server it could not reach; the server's run below 2000
and from 3000 up. Some of its own errors carry no number: a closed connection
is ``(0, "")``, and a broken handshake or packet stream is a message alone,
such as ``Packet sequence number wrong``. Each of those is a connection
failure (:func:`from_error`), as a PostgreSQL failure with no SQLSTATE is.

Nothing here raises; the caller decides.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from typing import Any

from sopuli.driver import errors
from sopuli.driver.protocol import AuthenticationError
from sopuli.exit_codes import ExitCode

#: ``ER_ACCESS_DENIED_ERROR``: a wrong password, or no account at this host.
ACCESS_DENIED = 1045
#: ``ER_MUST_CHANGE_PASSWORD``: an expired password, answered after login to
#: every statement but setting it.
MUST_CHANGE_PASSWORD = 1820
#: ``ER_DBACCESS_DENIED_ERROR``, ``ER_TABLEACCESS_DENIED_ERROR`` and
#: ``ER_COLUMNACCESS_DENIED_ERROR``.
DATABASE_ACCESS_DENIED = 1044
TABLE_ACCESS_DENIED = 1142
COLUMN_ACCESS_DENIED = 1143
#: ``ER_CANNOT_USER``: ``ALTER USER`` or ``DROP USER`` on an account that does
#: not exist, among others.
CANNOT_USER = 1396
#: The client's ``CR_AUTH_PLUGIN_CANNOT_LOAD`` and ``CR_AUTH_PLUGIN_ERR``: an
#: account on a plugin PyMySQL cannot speak.
AUTH_PLUGIN_CANNOT_LOAD = 2059
AUTH_PLUGIN_ERROR = 2061
#: The client's own: ``CR_UNKNOWN_ERROR``, ``CR_CONN_HOST_ERROR``,
#: ``CR_SERVER_GONE_ERROR``, ``CR_SERVER_LOST`` and ``CR_SSL_CONNECTION_ERROR``.
#: ``CR_UNKNOWN_ERROR`` is the number this module gives a PyMySQL error that
#: carries none.
UNKNOWN_CLIENT_ERROR = 2000
CANNOT_CONNECT = 2003
SERVER_GONE = 2006
SERVER_LOST = 2013
TLS_CONNECTION_ERROR = 2026

#: The numbers the client uses for its own errors.
_CLIENT_ERRORS = range(2000, 3000)


@dataclass(frozen=True)
class Rule:
    """What one number means: its category, exit code and hint."""

    category: str
    exit_code: ExitCode = ExitCode.FAILURE
    hint: str | None = None


AUTHENTICATION = AuthenticationError.category

#: What a connection lost mid-call leaves behind, for the rows that say so.
LOST = (
    "the connection to the server was lost. A statement in flight may have run: if it "
    "set a password, the change is unknown until the account is checked"
)

#: The same failures while the session was being opened, when nothing had run.
_FAILED_TO_CONNECT = (
    "the connection to the server failed while the session was being opened, before "
    "any statement ran"
)

#: The shared numbers. Each hint says what to do next; the message says what
#: happened.
RULES: dict[int, Rule] = {
    UNKNOWN_CLIENT_ERROR: Rule("connectivity", hint=LOST),
    SERVER_GONE: Rule("connectivity", hint=LOST),
    SERVER_LOST: Rule("connectivity", hint=LOST),
    ACCESS_DENIED: Rule(
        AUTHENTICATION,
        exit_code=ExitCode.AUTH_FAILURE,
        hint=(
            "the password this run used is not the one the server holds for this account, "
            "or no account matches this user name at the host the server sees: the server "
            "gives both the same message"
        ),
    ),
    MUST_CHANGE_PASSWORD: Rule(
        AUTHENTICATION,
        exit_code=ExitCode.AUTH_FAILURE,
        hint="the account's password has expired: it logs in, and must set a new one",
    ),
    DATABASE_ACCESS_DENIED: Rule(
        "authorization",
        hint="the tool account has no grant on the database the statement names",
    ),
    TABLE_ACCESS_DENIED: Rule(
        "authorization",
        hint=(
            "the tool account lacks the grant the statement needs on the table it names; "
            "the message says which command"
        ),
    ),
    COLUMN_ACCESS_DENIED: Rule(
        "authorization",
        hint="the tool account's column grant on the table does not cover this column",
    ),
    CANNOT_USER: Rule(
        "database", hint="the server refused the change: usually, the account does not exist"
    ),
    AUTH_PLUGIN_CANNOT_LOAD: Rule(
        AUTHENTICATION,
        exit_code=ExitCode.AUTH_FAILURE,
        hint="the account is on an authentication plugin PyMySQL cannot speak",
    ),
    AUTH_PLUGIN_ERROR: Rule(
        AUTHENTICATION,
        exit_code=ExitCode.AUTH_FAILURE,
        hint="the authentication plugin failed in the client; the message says why",
    ),
    TLS_CONNECTION_ERROR: Rule(
        "connectivity",
        hint=(
            "the target's `ssl_mode` requires TLS and the server offers none. Turn TLS on "
            "at the server; lowering the mode sends the password in clear"
        ),
    ),
}

#: Python's message when the server's certificate fails the check that
#: `VERIFY_CA` or `VERIFY_IDENTITY` asks for. PyMySQL reports it inside a 2003.
_CERTIFICATE = re.compile(r"CERTIFICATE_VERIFY_FAILED|certificate verify failed|Hostname mismatch")


@dataclass(frozen=True)
class Diagnosis(errors.Diagnosis):
    """One failure, classified. ``message`` is PyMySQL's, unchanged."""

    number: int
    category: str
    exit_code: ExitCode
    message: str
    sqlstate: str | None = None
    hint: str | None = None

    @property
    def code(self) -> str:  # type: ignore[override]
        """The vendor code: the error number, as the server sends it."""
        return str(self.number)

    @property
    def prefix(self) -> str:
        """The number and SQLSTATE, as the mysql client prints them in front
        of the message: ``1045 (28000): Access denied for user …``."""
        return self.code if self.sqlstate is None else f"{self.code} ({self.sqlstate})"


def classify(
    number: int, message: str, *, rules: Mapping[int, Rule], sqlstate: str | None = None
) -> Diagnosis:
    """What ``number`` means under a driver's ``rules``. A named row first;
    otherwise a client error (2000 to 2999) is a connection failure, and any
    other number is the database's."""
    rule = rules.get(number)
    if rule is None:
        rule = Rule("connectivity") if number in _CLIENT_ERRORS else Rule("database")
    return Diagnosis(
        number=number,
        category=rule.category,
        exit_code=rule.exit_code,
        message=message,
        sqlstate=sqlstate,
        hint=rule.hint,
    )


def unchanged(message: str) -> str:
    """The scrub that changes nothing, for a statement that carries no hash."""
    return message


def error_number(exc: BaseException) -> int | None:
    """The server's error number PyMySQL put first in ``exc.args``, or ``None``
    where there is none: no args, a message alone, or ``0``."""
    args = getattr(exc, "args", ())
    number = args[0] if args else None
    if isinstance(number, int) and not isinstance(number, bool) and number:
        return number
    return None


def from_error(
    exc: Any,
    *,
    rules: Mapping[int, Rule],
    certificate_hint: str,
    connecting: bool = False,
    scrub: Callable[[str], str] = unchanged,
) -> Diagnosis:
    """Classify a PyMySQL exception under a driver's ``rules``, without
    importing PyMySQL.

    The number is the first of ``args`` and the message the second. PyMySQL
    raises some of its own errors with no number: ``(0, "")`` for a connection
    already closed, and a message alone for a broken handshake or packet
    stream. Each of those is :data:`UNKNOWN_CLIENT_ERROR`, a connection
    failure, with the exception's own text as the message. A caller passes only
    PyMySQL's errors: anything else is a fault in this tool, and not mapped.

    A certificate that fails the check comes inside a :data:`CANNOT_CONNECT`,
    and gets ``certificate_hint``, which names the driver's config keys.

    ``connecting`` is true for a failure while the session is being opened. No
    statement has run then, so the hint about a change in flight is dropped.

    ``scrub`` is applied to the message before anything keeps it, as the Oracle
    driver's ``Statement.scrub`` is (#786). The server may quote the statement
    it refused, as a syntax error (1064) does, and the statement that changes a
    password carries its hash. The statement that failed is the caller's to
    know, so the caller supplies the scrub.
    """
    args = exc.args
    number = error_number(exc)
    if number is not None:
        message = str(args[1]) if len(args) > 1 else ""
    else:
        # A message alone is its args; `(0, "")` and no args at all say nothing.
        text = " ".join(str(arg) for arg in args if arg not in (0, "")).strip()
        number, message = UNKNOWN_CLIENT_ERROR, text or "the connection is closed"
    message = scrub(message)
    diagnosis = classify(number, message, rules=rules, sqlstate=getattr(exc, "sqlstate", None))
    if diagnosis.number == CANNOT_CONNECT and _CERTIFICATE.search(message):
        return replace(diagnosis, hint=certificate_hint)
    if connecting and diagnosis.hint == LOST:
        return replace(diagnosis, hint=_FAILED_TO_CONNECT)
    return diagnosis
