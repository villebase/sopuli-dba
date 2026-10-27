"""What a SQLSTATE means, and what to do about it. Tier 0.

The PostgreSQL side of :mod:`sopuli.driver.oracle.errors`: an error carries the
SQLSTATE where the Oracle driver puts the ``ORA-`` code, with a category and a
hint. The message is the server's, with the code put in front of it. Nothing
here raises; the caller decides.

**A failed connection has no SQLSTATE.** The server sends one, but libpq reports
a connection failure as a message only, and psycopg's ``sqlstate`` is ``None``
there (measured with psycopg 3.3.6). The code is recovered from the server's
message, for the failures that have a row below. A failure with no server
message, such as a refused port or a timeout, is ``08001``, the code for a client
that could not establish a connection. A connection lost later is ``08006``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, replace
from typing import Any

from sopuli.driver.protocol import AuthenticationError, DriverError
from sopuli.exit_codes import ExitCode

WRONG_PASSWORD = "28P01"
LOGIN_REFUSED = "28000"
INSUFFICIENT_PRIVILEGE = "42501"
UNDEFINED_OBJECT = "42704"
READ_ONLY_TRANSACTION = "25006"
INVALID_CATALOG = "3D000"
#: ``too_many_connections``: the role is at its ``CONNECTION LIMIT``.
TOO_MANY_CONNECTIONS = "53300"
#: ``sqlclient_unable_to_establish_sqlconnection``.
UNABLE_TO_CONNECT = "08001"
#: ``connection_failure``.
CONNECTION_FAILURE = "08006"

#: Where an unnamed code is a lost or refused connection: class ``08``, and
#: ``57P``, the server shutting down or ending the session (``57P01`` for
#: ``pg_terminate_backend``). Not all of class ``57``: ``57014`` is a cancelled
#: statement, such as one that ran past ``statement_timeout``.
_CONNECTION_CLASSES = ("08", "57P")


@dataclass(frozen=True)
class _Rule:
    category: str
    exit_code: ExitCode = ExitCode.FAILURE
    hint: str | None = None
    retryable: bool | None = None


#: The named SQLSTATEs. Each hint says what to do next; the message says what
#: happened.
RULES: dict[str, _Rule] = {
    WRONG_PASSWORD: _Rule(
        "authentication",
        exit_code=ExitCode.AUTH_FAILURE,
        hint=(
            "the password this run used is not the one the cluster holds for this role, "
            "or the role does not exist: the server gives both the same message"
        ),
    ),
    LOGIN_REFUSED: _Rule(
        "authentication",
        exit_code=ExitCode.AUTH_FAILURE,
        hint=(
            "the server refused the login. One of these: the method pg_hba.conf names "
            "for this host, role and database failed, pg_hba.conf has no line for them, "
            "the role does not exist, or the role cannot log in (NOLOGIN)"
        ),
    ),
    INSUFFICIENT_PRIVILEGE: _Rule(
        "authorization",
        hint="the tool's role is missing a privilege the statement needs",
    ),
    UNDEFINED_OBJECT: _Rule(
        "database",
        hint="the role or object the statement names does not exist in this cluster",
    ),
    READ_ONLY_TRANSACTION: _Rule(
        "database",
        hint=(
            "the session is read-only: a standby, or default_transaction_read_only is on. "
            "Point the target at the primary"
        ),
    ),
    INVALID_CATALOG: _Rule(
        "config",
        exit_code=ExitCode.CONFIG_INVALID,
        hint="the database in `postgres.database` does not exist in this cluster",
    ),
    TOO_MANY_CONNECTIONS: _Rule(
        "database",
        hint="the role is at its CONNECTION LIMIT; raise the limit or end a session",
    ),
}

#: The start of the hint for a message only a connection pooler sends.
POOLER_HINT = (
    "the server never sends this message, so the target is a connection pooler such as "
    "PgBouncer. A pooler is not a supported target (#1045): point the target's `dsn` at "
    "the server"
)

#: The server's message for a failure libpq reports without a SQLSTATE, and the
#: SQLSTATE the server sent with it. English, which is the server's default
#: ``lc_messages``. A server that logs in another language reaches the
#: ``08001`` row, which keeps its message. Measured on 13 to 18
#: (``docs/README.md``, ``pg-connect-sqlstate``): ``password authentication
#: failed``, ``is not permitted to log in`` and ``database "…" does not
#: exist``. Under password authentication a role that does not exist reads as a
#: wrong password, so the server sends ``role "…" does not exist`` only where no
#: password is asked, such as ``trust`` or ``peer``. That message and the
#: ``pg_hba.conf`` ones are the server's text, not measured.
#:
#: A message can hold several attempts, one per address the host name resolves
#: to. The reason the first attempt failed with is the one reported.
#:
#: Only the password methods (``password``, ``md5``, ``scram-sha-256``) fail with
#: ``28P01``. Every other method, such as ``ldap``, ``pam``, ``cert`` or
#: ``peer``, fails with ``<method> authentication failed for user`` and
#: ``28000``: that is how the server's ``auth_failed()`` chooses the code. Not
#: measured: the stack has no LDAP or PAM.
#:
#: The last rows are PgBouncer's own refusals of a login, measured with
#: PgBouncer 1.26.0 (``08_pgbouncer_probe.py``, #1105). The server sends none
#: of them, so the target is a pooler. They stay ``08001``: a pooler is not a
#: supported target (#1045), and reading PgBouncer's refusal of a password as
#: ``28P01`` would make drift work through one.
#:
#: The third value is the hint, where the rule's own does not fit: no
#: statement ran, or the message is a pooler's.
_CONNECT_MESSAGES: tuple[tuple[re.Pattern[str], str, str | None], ...] = (
    (re.compile(r"password authentication failed for user"), WRONG_PASSWORD, None),
    (re.compile(r"authentication failed for user"), LOGIN_REFUSED, None),
    (
        re.compile(r"no pg_hba\.conf entry for|pg_hba\.conf rejects connection"),
        LOGIN_REFUSED,
        None,
    ),
    (
        re.compile(r'role ".*" is not permitted to log in|role ".*" does not exist'),
        LOGIN_REFUSED,
        None,
    ),
    (re.compile(r'database ".*" does not exist'), INVALID_CATALOG, None),
    # The server says these only after the password was accepted (measured on
    # 16.15, #1067): with a wrong password it answers 28P01 first.
    (
        re.compile(r'permission denied for database ".*"'),
        INSUFFICIENT_PRIVILEGE,
        "the role has no CONNECT on `postgres.database`: GRANT CONNECT ON DATABASE to it, "
        "or to PUBLIC",
    ),
    (re.compile(r'too many connections for (role|database) ".*"'), TOO_MANY_CONNECTIONS, None),
    (
        re.compile(r"FATAL:\s+SASL authentication failed"),
        UNABLE_TO_CONNECT,
        f"{POOLER_HINT}. PgBouncer sends it for a wrong password, for a role with no "
        "password, and for the server's own password where PgBouncer's auth_file holds "
        "another one",
    ),
    (
        re.compile(r"FATAL:\s+no such user"),
        UNABLE_TO_CONNECT,
        f"{POOLER_HINT}. PgBouncer sends it for a role the server does not have",
    ),
    (
        re.compile(r"FATAL:\s+server login has been failing"),
        UNABLE_TO_CONNECT,
        f"{POOLER_HINT}. PgBouncer sends it when it cannot log in to the server behind it",
    ),
)

#: libpq's own messages when it cannot verify the server certificate, which the
#: default `sslmode: verify-full` asks it to. No SQLSTATE: the server never saw a
#: login.
_CERTIFICATE = re.compile(
    r"root certificate file .* does not exist|certificate verify failed"
    r"|could not get home directory to locate root certificate file"
    r"|server certificate for .* does not match host name"
)
CERTIFICATE_HINT = (
    "libpq could not verify the server certificate: set `postgres.sslrootcert` to the "
    "CA file that issued it, and connect by the name the certificate carries"
)


@dataclass(frozen=True)
class Diagnosis:
    """One failure, classified. ``message`` is psycopg's, unchanged."""

    code: str
    category: str
    exit_code: ExitCode
    message: str
    hint: str | None = None
    retryable: bool | None = None

    @property
    def first_line(self) -> str:
        """The message's first line, with the code in front."""
        lines = self.message.strip().splitlines()
        first = lines[0].strip() if lines else ""
        return f"{self.code}: {first}" if first else self.code

    @property
    def coded_message(self) -> str:
        """The message with the code in front, as an ``ORA-`` message carries its
        own. A PostgreSQL message never contains its SQLSTATE, so every view
        that prints the message would otherwise print no code."""
        message = self.message.strip()
        return f"{self.code}: {message}" if message else self.code

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
    code on the instance, as :class:`sopuli.driver.oracle.errors.MappedError`."""

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


def classify(code: str, message: str) -> Diagnosis:
    """What ``code`` means. A named row first, then the class: the first two
    characters of a SQLSTATE. :data:`_CONNECTION_CLASSES` are a connection
    failure, and any other unnamed code is the database's."""
    rule = RULES.get(code)
    if rule is None:
        rule = _Rule("connectivity") if code.startswith(_CONNECTION_CLASSES) else _Rule("database")
    return Diagnosis(
        code=code,
        category=rule.category,
        exit_code=rule.exit_code,
        message=message,
        hint=rule.hint,
        retryable=rule.retryable,
    )


def _reasons(message: str) -> list[tuple[int, int, str]]:
    """Each row of :data:`_CONNECT_MESSAGES` the message holds: where, which
    row, and its code."""
    return [
        (match.start(), index, recovered)
        for index, (pattern, recovered, _) in enumerate(_CONNECT_MESSAGES)
        if (match := pattern.search(message))
    ]


def first_reason_at(message: str) -> int | None:
    """Where in a failed connection's message the first recognised reason
    starts, or ``None``. The reason there is the one :func:`from_error`
    reports."""
    found = _reasons(message)
    return min(found)[0] if found else None


def from_error(exc: Any, *, connecting: bool = False) -> Diagnosis:
    """Classify a psycopg exception without importing psycopg.

    ``sqlstate`` is read where the server's reply carried one. A failed
    connection has none, so its code comes from :data:`_CONNECT_MESSAGES`, or is
    ``08001``. On an open session, a failure with no SQLSTATE is read as the
    connection going away, ``08006``. So a caller passes only what the server
    or the connection raised: an error psycopg raises before it sends anything,
    such as a wrong number of parameters, is a fault in this tool, and is not
    mapped.
    """
    message = str(exc)
    code = getattr(exc, "sqlstate", None)
    if code:
        return classify(str(code), message)
    if not connecting:
        return classify(CONNECTION_FAILURE, message)
    found = _reasons(message)
    if found:
        # The earliest in the message, which is the first attempt; at one
        # place, the earlier row, so `password …` wins over `… authentication
        # failed` when both match.
        _, index, recovered_code = min(found)
        recovered = classify(recovered_code, message)
        hint = _CONNECT_MESSAGES[index][2]
        return recovered if hint is None else replace(recovered, hint=hint)
    diagnosis = classify(UNABLE_TO_CONNECT, message)
    if _CERTIFICATE.search(message):
        return replace(diagnosis, hint=CERTIFICATE_HINT)
    return diagnosis
