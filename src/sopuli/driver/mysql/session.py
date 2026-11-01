"""Connecting to a MySQL server, and reporting what it is.

The module :data:`sopuli.driver.registry.DRIVERS` imports for ``type: mysql``.
It imports ``pymysql`` at module scope, so a machine without the ``mysql``
extra gets ``SOPULI-20002`` from the registry rather than a traceback (ADR-006
rule 1). The modules beside it are tier 0.

**What this build does.** It connects, labels the session with the run's
correlation id, checks that a mode which requires TLS got it, and reports the
scope: ``server``, whether it takes writes, and its encryption. Only `doctor`
gets this far: the registry entry lists no command, so every other command
refuses the target with ``SOPULI-20006`` before it connects. The methods past
the scope are a second line behind that, and refuse with ``SOPULI-20006``
without a round trip. The driver sends nothing that changes the server.
"""

from __future__ import annotations

import importlib.metadata
import logging
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

import pymysql

from sopuli.config.model import ExpandedTarget, Runtime
from sopuli.driver.mysql.client import client_lines
from sopuli.driver.mysql.connection import connect_arguments
from sopuli.driver.mysql.errors import from_error
from sopuli.driver.mysql.scope import TLS_VERSION, encryption_of, observe
from sopuli.driver.protocol import (
    ENCRYPTION_TLS,
    PASSWORD_ROLLOVER,
    VERIFY_LOGIN,
    AccountAttributes,
    AccountChange,
    AttributeChange,
    AuditCoverage,
    ChangeResult,
    Credential,
    DriverContext,
    DriverError,
    PrivilegeAudit,
    Scope,
    Timeouts,
    UserState,
    VerifyResult,
    require_capability,
)
from sopuli.driver.registry import DRIVER_NOT_IMPLEMENTED
from sopuli.exit_codes import ExitCode
from sopuli.output.debug import logger
from sopuli.passwords import ByteLimit
from sopuli.secrets import Secret

LOG = logger("mysql")

#: The `ssl_mode` values under which a session without TLS is refused.
TLS_REQUIRED_MODES = ("REQUIRED", "VERIFY_CA", "VERIFY_IDENTITY")


class NotWrittenError(DriverError):
    """The MySQL driver connects, and cannot do this yet.

    ``SOPULI-20006``, ``config`` and exit 9, as for a driver with no module at
    all: nothing installed fixes it, and the configuration is right.
    """

    category = "config"
    exit_code = ExitCode.CONFIG_INVALID

    def __init__(self, target: str, what: str) -> None:
        super().__init__(
            f'target "{target}" is a MySQL server, and this build cannot {what} there yet',
            hint=(
                "this is not something to install: the MySQL driver connects and "
                "reports the server, and the rest of it is not written yet"
            ),
            code=DRIVER_NOT_IMPLEMENTED,
        )


class UnencryptedSessionError(DriverError):
    """A mode that requires TLS got a session without it. The session is
    closed before anything is sent over it. ``connectivity``, as a server that
    refuses TLS is."""

    category = "connectivity"


class PlainLoginError(DriverError):
    """PyMySQL 1.2.3 could not finish a ``caching_sha2_password`` login over a
    plain connection.

    Measured on 8.4.13: a login the server has not cached needs the full
    exchange, and PyMySQL 1.2.3 fails it over a plain connection with an
    ``AttributeError`` in ``_request_authentication``, not a MySQL error. The
    same login over TLS succeeds.
    """

    category = "connectivity"


@dataclass
class MysqlSession:
    """One open connection to a server. A
    :class:`~sopuli.driver.protocol.Session` by its methods."""

    connection: Any
    target: ExpandedTarget
    #: Invariant 3's cache, probed on first use as on Oracle.
    _scope: Scope | None = field(default=None, init=False, repr=False)

    def scope(self) -> Scope:
        """What this session is: a server, read-write or not, and its encryption.

        Probed on the first call and cached for the session (invariant 3).
        """
        if self._scope is None:
            if self.connection is None:
                raise DriverError(
                    f'the session to target "{self.target.name}" is closed',
                    hint="this is a fault in sopuli: a closed session was used again",
                )
            try:
                with self.connection.cursor() as cursor:
                    self._scope = observe(cursor, target=self.target.name)
            except pymysql.err.MySQLError as error:
                raise from_error(error).as_error() from error
            if LOG.isEnabledFor(logging.DEBUG):
                LOG.debug(
                    "%s is a server, %s %s, encryption %s",
                    self.target.name,
                    self._scope.db_version,
                    self._scope.open_mode,
                    self._scope.encryption.method,
                )
        return self._scope

    def _not_written(self, what: str) -> NotWrittenError:
        return NotWrittenError(self.target.name, what)

    def describe_user(self, account: str) -> UserState | None:
        raise self._not_written("read an account")

    def byte_limit(self) -> ByteLimit:
        raise self._not_written("size a password")

    def password_constraints(self, account: str) -> None:
        """Not on the protocol: ``creds generate`` asks it of a driver that
        has it, and would read a missing method as no answer."""
        raise self._not_written("read an account's password rules")

    def privileges(self, *, accounts: tuple[str, ...] = ()) -> PrivilegeAudit:
        raise self._not_written("audit the tool's privileges")

    def set_password(self, account: str, secret: Secret) -> ChangeResult:
        raise self._not_written("set a password")

    def suspend_account(self, account: str) -> AccountChange:
        raise self._not_written("suspend an account")

    def reset_password(
        self, account: str, secret: Secret, *, expire: bool, keep_rollover: bool = False
    ) -> tuple[AccountChange, ...]:
        raise self._not_written("reset a password")

    def expire_password(self, account: str) -> tuple[AccountChange, ...]:
        raise self._not_written("expire a password")

    def audit_coverage(self, account: str) -> AuditCoverage:
        """Never raises, as the protocol promises: the answer is unknown."""
        return AuditCoverage(
            audited=None, detail="the MySQL driver does not read audit settings yet"
        )

    def apply_attributes(
        self, account: str, attributes: AccountAttributes
    ) -> tuple[AttributeChange, ...]:
        raise self._not_written("enforce an account's attributes")

    def resolve_profile(self, profile: str) -> str | None:
        raise self._not_written("look up a profile")

    def resolve_role(self, role: str) -> str | None:
        raise self._not_written("look up a role")

    def accounts_matching(
        self, *, profile: str | None = None, role: str | None = None
    ) -> tuple[str, ...]:
        raise self._not_written("list the accounts a predicate admits")

    def verify_password(
        self,
        account: str,
        secret: Secret,
        *,
        method: str = VERIFY_LOGIN,
        lockout_margin: int = 2,
        attempts: int = 1,
    ) -> VerifyResult:
        raise self._not_written("verify a password")

    def require_verifier(self, account: str, secret: Secret) -> None:
        raise self._not_written("compare a stored hash")

    def require_rollover(self, account: str) -> None:
        """Refused by capability until the rollover is written (#1224): no
        capability is reported yet, so this always refuses (invariant 4)."""
        require_capability(self.scope(), PASSWORD_ROLLOVER, target=self.target.name)

    def finish_rollover(self, account: str) -> ChangeResult:
        raise self._not_written("end a rollover window")

    def close(self) -> None:
        """Let the connection go. Safe twice, also after a close that raised."""
        connection, self.connection = self.connection, None
        if connection is not None:
            connection.close()


def require_tls(connection: Any, target: ExpandedTarget) -> None:
    """Refuse a session without TLS where ``ssl_mode`` requires it.

    PyMySQL already refuses a server that offers no TLS when it is given a
    context (:mod:`sopuli.driver.mysql.connection`). This reads the answer from
    the session itself, so the rule does not rest on the client library alone.
    Nothing has been sent over the session but the login.
    """
    mode = target.target.mysql_settings.ssl_mode
    if mode not in TLS_REQUIRED_MODES:
        return
    with connection.cursor() as cursor:
        cursor.execute(TLS_VERSION)
        encryption = encryption_of(cursor.fetchone())
    if encryption.method == ENCRYPTION_TLS:
        return
    connection.close()
    raise UnencryptedSessionError(
        f'target "{target.name}" connected without TLS under `ssl_mode: {mode}`',
        hint="the server negotiated no TLS; give it a certificate, and keep the mode",
    )


@dataclass(frozen=True)
class MysqlDriver:
    """P1's :class:`~sopuli.driver.protocol.Driver`, for MySQL. The run's half
    of the inputs; :meth:`connect` takes the target's."""

    correlation_id: str
    timeouts: Timeouts = field(default_factory=Timeouts)

    def connect(self, target: ExpandedTarget, credential: Credential) -> MysqlSession:
        """Reach ``target`` as ``credential``.

        ``program_name`` carries the correlation id from the handshake, so the
        server's own record of the session names the run.

        A failure is classified by :mod:`sopuli.driver.mysql.errors` with
        ``connecting=True``, and the debug line names the code and never the
        arguments, which hold the password.
        """
        arguments = connect_arguments(
            target, credential, correlation_id=self.correlation_id, timeouts=self.timeouts
        )
        started = time.monotonic()
        try:
            connection = pymysql.connect(**arguments)
        except pymysql.err.MySQLError as error:
            failure = from_error(error, connecting=True)
            LOG.debug(
                "connect to %s as %s failed with %s in %.3fs",
                target.name,
                credential.username,
                failure.code,
                time.monotonic() - started,
            )
            raise failure.as_error() from error
        except AttributeError as error:
            # PyMySQL 1.2.3's own failure, measured (PlainLoginError). Only a
            # plain connection reaches it; under TLS the login succeeds.
            if "ssl" in arguments:
                raise
            raise PlainLoginError(
                f'target "{target.name}": PyMySQL could not finish the '
                f"caching_sha2_password login over a plain connection",
                hint=(
                    "a login the server has not cached needs the full exchange, which "
                    "PyMySQL 1.2.3 fails without TLS. Set `mysql.ssl_mode` to "
                    "VERIFY_IDENTITY, which sends the password over TLS anyway"
                ),
            ) from error
        LOG.debug(
            "connect to %s as %s in %.3fs",
            target.name,
            credential.username,
            time.monotonic() - started,
        )
        try:
            require_tls(connection, target)
        except pymysql.err.MySQLError as error:
            connection.close()
            raise from_error(error).as_error() from error
        return MysqlSession(connection=connection, target=target)


def build_driver(context: DriverContext) -> MysqlDriver:
    """The registry's way in: a :class:`MysqlDriver` for this run. PyMySQL
    needs nothing from ``runtime``: it is pure Python."""
    return MysqlDriver(correlation_id=context.correlation_id, timeouts=context.timeouts)


def client_report(*, env: Mapping[str, str], runtime: Runtime) -> dict[str, Any]:
    """`doctor`'s client line: PyMySQL's release, from its distribution's
    metadata. Neither argument is read."""
    return client_lines(pymysql_version=importlib.metadata.version("PyMySQL"))
