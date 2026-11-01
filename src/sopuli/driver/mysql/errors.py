"""What a MySQL error number means, and what to do about it. Tier 0.

The MySQL side of :mod:`sopuli.driver.postgres.errors`. An error carries the
server's error number where the Oracle driver puts the ``ORA-`` code, with a
category and a hint. The message is the server's, with the number and the
SQLSTATE put in front of it, as the mysql client prints them. Nothing here
raises; the caller decides.

PyMySQL raises a server error, and most failures of its own to reach the
server, as an exception whose ``args`` are ``(number, message)`` and whose
``sqlstate`` is the server's where the reply carried one (PyMySQL 1.2.3,
``err.raise_mysql_exception``). Numbers from 2000 to 2999 are the client's
own, such as 2003 for a server it could not reach; the server's run below 2000
and from 3000 up. Some of its own errors carry no number:
a closed connection is ``(0, "")``, and a broken handshake or packet stream is
a message alone, such as ``Packet sequence number wrong``. Each of those is a
connection failure (:func:`from_error`), as a PostgreSQL failure with no
SQLSTATE is.

Which rows were measured: `3118`, `1820`, `3955`, `1227`, `1142`, `1044`,
`1827` and `3894` on 8.0.46, 8.4.13 and 9.7.4 with the mysql client (#1202,
``docs/README.md`` §*MySQL*). The others are from MySQL's error reference.
The shapes here are read from PyMySQL 1.2.3's source, and PR 3 of #1221
measures them against a server. One difference is expected: PyMySQL does not
say it can handle an expired password, so it should meet `1862` at login
where the mysql client met `1820` after it.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Any

from sopuli.driver.protocol import AuthenticationError, DriverError
from sopuli.exit_codes import ExitCode

#: ``ER_ACCESS_DENIED_ERROR``: a wrong password, or no account at this host.
ACCESS_DENIED = 1045
#: ``ER_HOST_NOT_PRIVILEGED``: no account of any name allows the client's host.
HOST_NOT_PRIVILEGED = 1130
#: ``ER_HOST_IS_BLOCKED``: too many broken connections from the client's host
#: (``max_connect_errors``).
HOST_BLOCKED = 1129
#: ``ER_ACCESS_DENIED_NO_PASSWORD_ERROR``: an account on a plugin that takes no
#: password, such as ``auth_socket``.
ACCESS_DENIED_NO_PASSWORD = 1698
#: ``ER_ACCOUNT_HAS_BEEN_LOCKED``: ``ACCOUNT LOCK``.
ACCOUNT_LOCKED = 3118
#: ``ER_USER_ACCESS_DENIED_FOR_USER_ACCOUNT_BLOCKED_BY_PASSWORD_LOCK``: a block
#: from ``FAILED_LOGIN_ATTEMPTS``, answered to the right password too.
ACCOUNT_BLOCKED = 3955
#: ``ER_MUST_CHANGE_PASSWORD``: an expired password, answered after login to
#: every statement but setting it.
MUST_CHANGE_PASSWORD = 1820
#: ``ER_MUST_CHANGE_PASSWORD_LOGIN``: an expired password, refused at login to a
#: client that does not say it can handle one.
MUST_CHANGE_PASSWORD_LOGIN = 1862
#: ``ER_SPECIFIC_ACCESS_DENIED_ERROR``: a privilege missing, such as
#: ``SYSTEM_USER`` to change an account that holds it.
SPECIFIC_ACCESS_DENIED = 1227
#: ``ER_DBACCESS_DENIED_ERROR``, ``ER_TABLEACCESS_DENIED_ERROR`` and
#: ``ER_COLUMNACCESS_DENIED_ERROR``.
DATABASE_ACCESS_DENIED = 1044
TABLE_ACCESS_DENIED = 1142
COLUMN_ACCESS_DENIED = 1143
#: ``ER_CANNOT_USER``: ``ALTER USER`` or ``DROP USER`` on an account that does
#: not exist, among others.
CANNOT_USER = 1396
#: ``ER_PASSWORD_FORMAT``: a hash of the wrong form after ``AS``.
PASSWORD_FORMAT = 1827
#: ``ER_PLUGIN_IS_NOT_LOADED``: ``mysql_native_password`` on 8.4 and 9.
PLUGIN_NOT_LOADED = 1524
#: ``RETAIN CURRENT PASSWORD`` with a change of plugin.
RETAIN_WITH_PLUGIN_CHANGE = 3894
#: ``ER_OPTION_PREVENTS_STATEMENT``: ``read_only`` or ``super_read_only``.
READ_ONLY = 1290
#: ``ER_CON_COUNT_ERROR``: the server's ``max_connections``.
TOO_MANY_CONNECTIONS = 1040
#: ``ER_TOO_MANY_USER_CONNECTIONS``: the server's ``max_user_connections``,
#: which applies to every account.
TOO_MANY_USER_CONNECTIONS = 1203
#: ``ER_USER_LIMIT_REACHED``: one of the account's own limits, such as
#: ``MAX_USER_CONNECTIONS``.
USER_LIMIT_REACHED = 1226
#: The client's ``CR_AUTH_PLUGIN_CANNOT_LOAD`` and ``CR_AUTH_PLUGIN_ERR``: an
#: account on a plugin PyMySQL cannot speak.
AUTH_PLUGIN_CANNOT_LOAD = 2059
AUTH_PLUGIN_ERROR = 2061
#: ``ER_SECURE_TRANSPORT_REQUIRED``: the server requires TLS.
SECURE_TRANSPORT_REQUIRED = 3159
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
class _Rule:
    category: str
    exit_code: ExitCode = ExitCode.FAILURE
    hint: str | None = None


_AUTHENTICATION = AuthenticationError.category

#: What a connection lost mid-call leaves behind, for the rows that say so.
_LOST = (
    "the connection to the server was lost. A statement in flight may have run: if it "
    "set a password, the change is unknown until the account is checked"
)

#: The same failures while the session was being opened, when nothing had run.
_FAILED_TO_CONNECT = (
    "the connection to the server failed while the session was being opened, before "
    "any statement ran"
)

#: The named numbers. Each hint says what to do next; the message says what
#: happened.
RULES: dict[int, _Rule] = {
    HOST_NOT_PRIVILEGED: _Rule(
        _AUTHENTICATION,
        exit_code=ExitCode.AUTH_FAILURE,
        hint=(
            "no account allows a login from the host the server sees for this machine. "
            "Check the tool account's host part against the address the server sees"
        ),
    ),
    HOST_BLOCKED: _Rule(
        "connectivity",
        hint=(
            "the server blocked this machine's host after too many broken connections "
            "(max_connect_errors). FLUSH HOSTS, or TRUNCATE "
            "performance_schema.host_cache, ends it"
        ),
    ),
    ACCESS_DENIED_NO_PASSWORD: _Rule(
        _AUTHENTICATION,
        exit_code=ExitCode.AUTH_FAILURE,
        hint="the account's plugin takes no password, such as auth_socket",
    ),
    UNKNOWN_CLIENT_ERROR: _Rule("connectivity", hint=_LOST),
    SERVER_GONE: _Rule("connectivity", hint=_LOST),
    SERVER_LOST: _Rule("connectivity", hint=_LOST),
    ACCESS_DENIED: _Rule(
        _AUTHENTICATION,
        exit_code=ExitCode.AUTH_FAILURE,
        hint=(
            "the password this run used is not the one the server holds for this account, "
            "or no account matches this user name at the host the server sees: the server "
            "gives both the same message"
        ),
    ),
    ACCOUNT_LOCKED: _Rule(
        _AUTHENTICATION,
        exit_code=ExitCode.AUTH_FAILURE,
        hint="the account is locked (ACCOUNT LOCK); ACCOUNT UNLOCK ends it",
    ),
    ACCOUNT_BLOCKED: _Rule(
        _AUTHENTICATION,
        exit_code=ExitCode.AUTH_FAILURE,
        hint=(
            "too many failed logins blocked the account (FAILED_LOGIN_ATTEMPTS), and the "
            "server refuses the right password too until PASSWORD_LOCK_TIME passes or "
            "ACCOUNT UNLOCK ends it. Nothing in mysql.user shows the block"
        ),
    ),
    MUST_CHANGE_PASSWORD: _Rule(
        _AUTHENTICATION,
        exit_code=ExitCode.AUTH_FAILURE,
        hint="the account's password has expired: it logs in, and must set a new one",
    ),
    MUST_CHANGE_PASSWORD_LOGIN: _Rule(
        _AUTHENTICATION,
        exit_code=ExitCode.AUTH_FAILURE,
        hint="the account's password has expired, and the server refuses the login",
    ),
    SPECIFIC_ACCESS_DENIED: _Rule(
        "authorization",
        hint=(
            "the tool account lacks a privilege the statement needs. Changing an account "
            "that holds SYSTEM_USER needs SYSTEM_USER, which the tool account must not hold"
        ),
    ),
    DATABASE_ACCESS_DENIED: _Rule(
        "authorization",
        hint="the tool account has no grant on the database the statement names",
    ),
    TABLE_ACCESS_DENIED: _Rule(
        "authorization",
        hint=(
            "the tool account lacks the grant the statement needs on the table it names; "
            "the message says which command"
        ),
    ),
    COLUMN_ACCESS_DENIED: _Rule(
        "authorization",
        hint="the tool account's column grant on the table does not cover this column",
    ),
    CANNOT_USER: _Rule(
        "database", hint="the server refused the change: usually, the account does not exist"
    ),
    PASSWORD_FORMAT: _Rule(
        "database",
        hint="the server refused the hash's form. This is a fault in the tool: report it",
    ),
    PLUGIN_NOT_LOADED: _Rule(
        "database", hint="the server does not have the authentication plugin loaded"
    ),
    RETAIN_WITH_PLUGIN_CHANGE: _Rule(
        "database",
        hint=(
            "RETAIN CURRENT PASSWORD cannot change an account's authentication plugin. "
            "The account is on another plugin than caching_sha2_password"
        ),
    ),
    READ_ONLY: _Rule(
        "database",
        hint=(
            "the server is read-only (read_only or super_read_only): a replica, or a "
            "primary set read-only. Point the target at the writable primary"
        ),
    ),
    TOO_MANY_CONNECTIONS: _Rule(
        "database", hint="the server is at max_connections; raise it or end a session"
    ),
    TOO_MANY_USER_CONNECTIONS: _Rule(
        "database",
        hint=(
            "the account is at the server's max_user_connections, a setting for every "
            "account; raise it or end a session"
        ),
    ),
    USER_LIMIT_REACHED: _Rule(
        "database",
        hint=(
            "the account reached one of its own limits, such as MAX_USER_CONNECTIONS; "
            "ALTER USER raises it"
        ),
    ),
    AUTH_PLUGIN_CANNOT_LOAD: _Rule(
        _AUTHENTICATION,
        exit_code=ExitCode.AUTH_FAILURE,
        hint=(
            "the account is on an authentication plugin PyMySQL cannot speak. The tool "
            "logs in to caching_sha2_password accounts"
        ),
    ),
    AUTH_PLUGIN_ERROR: _Rule(
        _AUTHENTICATION,
        exit_code=ExitCode.AUTH_FAILURE,
        hint="the authentication plugin failed in the client; the message says why",
    ),
    SECURE_TRANSPORT_REQUIRED: _Rule(
        "connectivity",
        hint=(
            "the server requires TLS (require_secure_transport): set `mysql.ssl_mode` to "
            "`VERIFY_IDENTITY`"
        ),
    ),
    TLS_CONNECTION_ERROR: _Rule(
        "connectivity",
        hint=(
            "`mysql.ssl_mode` requires TLS and the server offers none. Turn TLS on at the "
            "server; lowering the mode sends the password in clear"
        ),
    ),
}

#: Python's message when the server's certificate fails the check that
#: `VERIFY_CA` or `VERIFY_IDENTITY` asks for. PyMySQL reports it inside a 2003.
_CERTIFICATE = re.compile(r"CERTIFICATE_VERIFY_FAILED|certificate verify failed|Hostname mismatch")
CERTIFICATE_HINT = (
    "the server certificate did not pass the check `mysql.ssl_mode` asks for: set "
    "`mysql.ssl_ca` to the CA file that issued it, and connect by the name it carries"
)


@dataclass(frozen=True)
class Diagnosis:
    """One failure, classified. ``message`` is PyMySQL's, unchanged."""

    number: int
    category: str
    exit_code: ExitCode
    message: str
    sqlstate: str | None = None
    hint: str | None = None

    @property
    def code(self) -> str:
        """The vendor code: the error number, as the server sends it."""
        return str(self.number)

    @property
    def coded_message(self) -> str:
        """The message with the number and SQLSTATE in front, as the mysql
        client prints them: ``1045 (28000): Access denied for user …``."""
        prefix = self.code if self.sqlstate is None else f"{self.code} ({self.sqlstate})"
        message = self.message.strip()
        return f"{prefix}: {message}" if message else prefix

    def as_error(self) -> DriverError:
        """This diagnosis as something to raise, with :attr:`coded_message` as
        its message. An authentication failure is an
        :class:`~sopuli.driver.protocol.AuthenticationError`, exit 6."""
        if self.category == AuthenticationError.category:
            return AuthenticationError(self.coded_message, hint=self.hint, code=self.code)
        return MappedError(self)


class MappedError(DriverError):
    """A :class:`Diagnosis` that a caller raised, with its own category and exit
    code on the instance, as :class:`sopuli.driver.postgres.errors.MappedError`."""

    def __init__(self, diagnosis: Diagnosis) -> None:
        super().__init__(diagnosis.coded_message, hint=diagnosis.hint, code=diagnosis.code)
        self.category = diagnosis.category
        self.exit_code = diagnosis.exit_code
        self.diagnosis = diagnosis


def classify(number: int, message: str, *, sqlstate: str | None = None) -> Diagnosis:
    """What ``number`` means. A named row first; otherwise a client error (2000
    to 2999) is a connection failure, and any other number is the database's."""
    rule = RULES.get(number)
    if rule is None:
        rule = _Rule("connectivity") if number in _CLIENT_ERRORS else _Rule("database")
    return Diagnosis(
        number=number,
        category=rule.category,
        exit_code=rule.exit_code,
        message=message,
        sqlstate=sqlstate,
        hint=rule.hint,
    )


def _unchanged(message: str) -> str:
    return message


def from_error(
    exc: Any, *, connecting: bool = False, scrub: Callable[[str], str] = _unchanged
) -> Diagnosis:
    """Classify a PyMySQL exception without importing PyMySQL.

    The number is the first of ``args`` and the message the second. PyMySQL
    raises some of its own errors with no number: ``(0, "")`` for a connection
    already closed, and a message alone for a broken handshake or packet
    stream. Each of those is :data:`UNKNOWN_CLIENT_ERROR`, a connection
    failure, with the exception's own text as the message. A caller passes only
    PyMySQL's errors: anything else is a fault in this tool, and not mapped.

    ``connecting`` is true for a failure while the session is being opened. No
    statement has run then, so the hint about a change in flight is dropped.

    ``scrub`` is applied to the message before anything keeps it, as the Oracle
    driver's ``Statement.scrub`` is (#786). The server may quote the statement
    it refused, as a syntax error (1064) does, and the statement that changes a
    password carries its hash. The statement that failed is the caller's to
    know, so the caller supplies the scrub.
    """
    args = exc.args
    number = args[0] if args else None
    if isinstance(number, int) and not isinstance(number, bool) and number:
        message = str(args[1]) if len(args) > 1 else ""
    else:
        # A message alone is its args; `(0, "")` and no args at all say nothing.
        text = " ".join(str(arg) for arg in args if arg not in (0, "")).strip()
        number, message = UNKNOWN_CLIENT_ERROR, text or "the connection is closed"
    message = scrub(message)
    diagnosis = classify(number, message, sqlstate=getattr(exc, "sqlstate", None))
    if diagnosis.number == CANNOT_CONNECT and _CERTIFICATE.search(message):
        return replace(diagnosis, hint=CERTIFICATE_HINT)
    if connecting and diagnosis.hint == _LOST:
        return replace(diagnosis, hint=_FAILED_TO_CONNECT)
    return diagnosis
