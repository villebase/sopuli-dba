"""What a MySQL error number means, and what to do about it. Tier 0.

The MySQL side of :mod:`sopuli.driver.postgres.errors`. An error carries the
server's error number where the Oracle driver puts the ``ORA-`` code, with a
category and a hint. The message is the server's, with the number and the
SQLSTATE put in front of it, as the mysql client prints them. Nothing here
raises; the caller decides.

PyMySQL raises every server error, and every failure of its own to reach the
server, as an exception whose ``args`` are ``(number, message)`` and whose
``sqlstate`` is the server's where the reply carried one (PyMySQL 1.2.3,
``err.raise_mysql_exception``). Numbers from 2000 are the client's own, such as
2003 for a server it could not reach.

Which rows were measured: `3118`, `1820`, `3955`, `1227`, `1142`, `1044`,
`1827` and `3894` on 8.0.46, 8.4.13 and 9.7.4 with the mysql client (#1202,
``docs/README.md`` §*MySQL*). The others are from MySQL's error reference, and
the PyMySQL shape of every row is measured with the driver (#1221).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, replace
from typing import Any

from sopuli.driver.protocol import AuthenticationError, DriverError
from sopuli.exit_codes import ExitCode

#: ``ER_ACCESS_DENIED_ERROR``: a wrong password, or no account at this host.
ACCESS_DENIED = 1045
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
#: ``ER_CON_COUNT_ERROR`` and ``ER_TOO_MANY_USER_CONNECTIONS``.
TOO_MANY_CONNECTIONS = 1040
TOO_MANY_USER_CONNECTIONS = 1203
#: ``ER_SECURE_TRANSPORT_REQUIRED``: the server requires TLS.
SECURE_TRANSPORT_REQUIRED = 3159
#: The client's own: ``CR_CONN_HOST_ERROR``, ``CR_SERVER_GONE_ERROR``,
#: ``CR_SERVER_LOST`` and ``CR_SSL_CONNECTION_ERROR``.
CANNOT_CONNECT = 2003
SERVER_GONE = 2006
SERVER_LOST = 2013
TLS_CONNECTION_ERROR = 2026

#: The first number the client uses for its own errors.
_CLIENT_ERRORS = 2000


@dataclass(frozen=True)
class _Rule:
    category: str
    exit_code: ExitCode = ExitCode.FAILURE
    hint: str | None = None
    retryable: bool | None = None


_AUTHENTICATION = "authentication"

#: The named numbers. Each hint says what to do next; the message says what
#: happened.
RULES: dict[int, _Rule] = {
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
        "authorization", hint="the tool account cannot read what the statement names"
    ),
    TABLE_ACCESS_DENIED: _Rule(
        "authorization", hint="the tool account cannot read the table the statement names"
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
        "database", hint="the server is at max_connections", retryable=True
    ),
    TOO_MANY_USER_CONNECTIONS: _Rule(
        "database",
        hint="the account is at its MAX_USER_CONNECTIONS; raise the limit or end a session",
        retryable=True,
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
    retryable: bool | None = None

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
            return AuthenticationError(
                self.coded_message, hint=self.hint, code=self.code, retryable=self.retryable
            )
        return MappedError(self)


class MappedError(DriverError):
    """A :class:`Diagnosis` that a caller raised, with its own category and exit
    code on the instance, as :class:`sopuli.driver.postgres.errors.MappedError`."""

    def __init__(self, diagnosis: Diagnosis) -> None:
        super().__init__(
            diagnosis.coded_message,
            hint=diagnosis.hint,
            code=diagnosis.code,
            retryable=diagnosis.retryable,
        )
        self.category = diagnosis.category
        self.exit_code = diagnosis.exit_code
        self.diagnosis = diagnosis


def classify(number: int, message: str, *, sqlstate: str | None = None) -> Diagnosis:
    """What ``number`` means. A named row first; otherwise a client error (from
    2000) is a connection failure, and any other number is the database's."""
    rule = RULES.get(number)
    if rule is None:
        rule = _Rule("connectivity") if number >= _CLIENT_ERRORS else _Rule("database")
    return Diagnosis(
        number=number,
        category=rule.category,
        exit_code=rule.exit_code,
        message=message,
        sqlstate=sqlstate,
        hint=rule.hint,
        retryable=rule.retryable,
    )


def from_error(exc: Any) -> Diagnosis:
    """Classify a PyMySQL exception without importing PyMySQL.

    The number is the first of ``args`` and the message the second. An
    exception without a number is not one the server or the connection raised,
    and is a fault in this tool, so it is not mapped: a caller passes only
    PyMySQL's errors.
    """
    number, message = exc.args[0], str(exc.args[1]) if len(exc.args) > 1 else ""
    diagnosis = classify(int(number), message, sqlstate=getattr(exc, "sqlstate", None))
    if diagnosis.number == CANNOT_CONNECT and _CERTIFICATE.search(message):
        return replace(diagnosis, hint=CERTIFICATE_HINT)
    return diagnosis
