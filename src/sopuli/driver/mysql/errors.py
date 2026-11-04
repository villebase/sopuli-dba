"""What a MySQL error number means, and what to do about it. Tier 0.

The MySQL side of :mod:`sopuli.driver.postgres.errors`. An error carries the
server's error number where the Oracle driver puts the ``ORA-`` code, with a
category and a hint. The message is the server's, with the number and the
SQLSTATE put in front of it, as the mysql client prints them. Nothing here
raises; the caller decides.

The numbers MariaDB sends too, PyMySQL's own, and the classification itself
are in :mod:`sopuli.driver.mysql_family.errors`. This module adds MySQL's own
numbers, and the hints that name MySQL's config keys or its plugin, and binds
:func:`classify` and :func:`from_error` to the whole set.

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
``docs/README.md`` §*MySQL*), and at login through PyMySQL 1.2.3 on 8.4.13:
`1045` for a wrong password, `3118` for a locked account's right one, and
`1862` for an expired account's right one, because PyMySQL does not say it can
handle an expired password (:mod:`sopuli.driver.mysql.verification`). The
others are from MySQL's error reference, and the exception shapes are read from
PyMySQL 1.2.3's source.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from sopuli.driver.errors import MappedError as MappedError
from sopuli.driver.mysql_family import errors as family
from sopuli.driver.mysql_family.errors import AUTHENTICATION, Diagnosis, Rule
from sopuli.exit_codes import ExitCode

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
#: ``ER_MUST_CHANGE_PASSWORD_LOGIN``: an expired password, refused at login to
#: a client that does not say it can handle one.
MUST_CHANGE_PASSWORD_LOGIN = 1862
#: ``ER_SPECIFIC_ACCESS_DENIED_ERROR``: a privilege missing, such as
#: ``SYSTEM_USER`` to change an account that holds it.
SPECIFIC_ACCESS_DENIED = 1227
#: ``ER_UNKNOWN_SYSTEM_VARIABLE``: a server without the variable read, such as
#: MariaDB 10.11.19 without ``super_read_only`` (#1202).
UNKNOWN_SYSTEM_VARIABLE = 1193
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
#: ``ER_SECURE_TRANSPORT_REQUIRED``: the server requires TLS.
SECURE_TRANSPORT_REQUIRED = 3159

#: MySQL's own numbers, and the shared numbers whose hint is MySQL's. Each
#: hint says what to do next; the message says what happened.
MYSQL_RULES: dict[int, Rule] = {
    HOST_NOT_PRIVILEGED: Rule(
        AUTHENTICATION,
        exit_code=ExitCode.AUTH_FAILURE,
        hint=(
            "no account allows a login from the host the server sees for this machine. "
            "Check the tool account's host part against the address the server sees"
        ),
    ),
    HOST_BLOCKED: Rule(
        "connectivity",
        hint=(
            "the server blocked this machine's host after too many broken connections "
            "(max_connect_errors). FLUSH HOSTS, or TRUNCATE "
            "performance_schema.host_cache, ends it"
        ),
    ),
    ACCESS_DENIED_NO_PASSWORD: Rule(
        AUTHENTICATION,
        exit_code=ExitCode.AUTH_FAILURE,
        hint="the account's plugin takes no password, such as auth_socket",
    ),
    ACCOUNT_LOCKED: Rule(
        AUTHENTICATION,
        exit_code=ExitCode.AUTH_FAILURE,
        hint="the account is locked (ACCOUNT LOCK); ACCOUNT UNLOCK ends it",
    ),
    ACCOUNT_BLOCKED: Rule(
        AUTHENTICATION,
        exit_code=ExitCode.AUTH_FAILURE,
        hint=(
            "too many failed logins blocked the account (FAILED_LOGIN_ATTEMPTS), and the "
            "server refuses the right password too until PASSWORD_LOCK_TIME passes or "
            "ACCOUNT UNLOCK ends it. Nothing in mysql.user shows the block"
        ),
    ),
    MUST_CHANGE_PASSWORD_LOGIN: Rule(
        AUTHENTICATION,
        exit_code=ExitCode.AUTH_FAILURE,
        hint="the account's password has expired, and the server refuses the login",
    ),
    SPECIFIC_ACCESS_DENIED: Rule(
        "authorization",
        hint=(
            "the tool account lacks a privilege the statement needs. Changing an account "
            "that holds SYSTEM_USER needs SYSTEM_USER, which the tool account must not hold"
        ),
    ),
    PASSWORD_FORMAT: Rule(
        "database",
        hint="the server refused the hash's form. This is a fault in the tool: report it",
    ),
    PLUGIN_NOT_LOADED: Rule(
        "database", hint="the server does not have the authentication plugin loaded"
    ),
    RETAIN_WITH_PLUGIN_CHANGE: Rule(
        "database",
        hint=(
            "RETAIN CURRENT PASSWORD cannot change an account's authentication plugin. "
            "The account is on another plugin than caching_sha2_password"
        ),
    ),
    READ_ONLY: Rule(
        "database",
        hint=(
            "the server is read-only (read_only or super_read_only): a replica, or a "
            "primary set read-only. Point the target at the writable primary"
        ),
    ),
    TOO_MANY_CONNECTIONS: Rule(
        "database", hint="the server is at max_connections; raise it or end a session"
    ),
    TOO_MANY_USER_CONNECTIONS: Rule(
        "database",
        hint=(
            "the account is at the server's max_user_connections, a setting for every "
            "account; raise it or end a session"
        ),
    ),
    USER_LIMIT_REACHED: Rule(
        "database",
        hint=(
            "the account reached one of its own limits, such as MAX_USER_CONNECTIONS; "
            "ALTER USER raises it"
        ),
    ),
    family.AUTH_PLUGIN_CANNOT_LOAD: Rule(
        AUTHENTICATION,
        exit_code=ExitCode.AUTH_FAILURE,
        hint=(
            "the account is on an authentication plugin PyMySQL cannot speak. The tool "
            "logs in to caching_sha2_password accounts"
        ),
    ),
    SECURE_TRANSPORT_REQUIRED: Rule(
        "connectivity",
        hint=(
            "the server requires TLS (require_secure_transport): set `mysql.ssl_mode` to "
            "`VERIFY_IDENTITY`"
        ),
    ),
    family.TLS_CONNECTION_ERROR: Rule(
        "connectivity",
        hint=(
            "`mysql.ssl_mode` requires TLS and the server offers none. Turn TLS on at the "
            "server; lowering the mode sends the password in clear"
        ),
    ),
}

#: Every number the MySQL driver names: the shared ones, then MySQL's.
RULES: dict[int, Rule] = {**family.RULES, **MYSQL_RULES}

CERTIFICATE_HINT = (
    "the server certificate did not pass the check `mysql.ssl_mode` asks for: set "
    "`mysql.ssl_ca` to the CA file that issued it, and connect by the name it carries"
)


def classify(number: int, message: str, *, sqlstate: str | None = None) -> Diagnosis:
    """What ``number`` means on MySQL: :func:`family.classify
    <sopuli.driver.mysql_family.errors.classify>` under :data:`RULES`."""
    return family.classify(number, message, rules=RULES, sqlstate=sqlstate)


def from_error(
    exc: Any, *, connecting: bool = False, scrub: Callable[[str], str] = family.unchanged
) -> Diagnosis:
    """Classify a PyMySQL exception from a MySQL server: :func:`family.from_error
    <sopuli.driver.mysql_family.errors.from_error>` under :data:`RULES`, with
    :data:`CERTIFICATE_HINT`. ``connecting`` and ``scrub`` are its own."""
    return family.from_error(
        exc, rules=RULES, certificate_hint=CERTIFICATE_HINT, connecting=connecting, scrub=scrub
    )
