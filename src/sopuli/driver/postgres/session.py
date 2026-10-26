"""Connecting to a PostgreSQL cluster, and reporting what it is.

The module :data:`sopuli.driver.registry.DRIVERS` imports for
``type: postgresql``. It imports ``psycopg`` at module scope, so a machine
without the ``postgres`` extra gets ``SOPULI-20002`` from the registry rather than
a traceback (ADR-006 rule 1). The modules beside it are tier 0.

**What this build does.** It connects, labels the session with the run's
correlation id, and reports the scope: ``cluster``, whether it takes writes, and
its encryption, and audits the tool account's privileges for
`doctor --check-privileges`. Only `doctor` gets this far: the registry entry is
``scope_only``, so every other command refuses the target with ``SOPULI-20006``
before it connects. The methods past the scope are a second line behind that,
and refuse with ``SOPULI-20006`` without a round trip. A write that is written
later checks :func:`~sopuli.driver.postgres.scope.require_read_write` first.
The driver sends no DDL.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any

import psycopg

from sopuli.config.model import ExpandedTarget, Runtime
from sopuli.driver.postgres.client import client_lines
from sopuli.driver.postgres.connection import connect_arguments
from sopuli.driver.postgres.errors import INSUFFICIENT_PRIVILEGE, from_error
from sopuli.driver.postgres.privileges import audit
from sopuli.driver.postgres.scope import SYSTEM_IDENTIFIER, observe
from sopuli.driver.protocol import (
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

LOG = logger("postgres")


class NotWrittenError(DriverError):
    """The PostgreSQL driver connects, and cannot do this yet.

    ``SOPULI-20006``, ``config`` and exit 9, as for a driver with no module at
    all: nothing installed fixes it, and the configuration is right.
    """

    category = "config"
    exit_code = ExitCode.CONFIG_INVALID

    def __init__(self, target: str, what: str) -> None:
        super().__init__(
            f'target "{target}" is a PostgreSQL cluster, and this build cannot {what} there yet',
            hint=(
                "this is not something to install: the PostgreSQL driver connects and "
                "reports the cluster, and the rest of it is not written yet"
            ),
            code=DRIVER_NOT_IMPLEMENTED,
        )


@dataclass
class PostgresSession:
    """One open connection to a cluster. A
    :class:`~sopuli.driver.protocol.Session` by its methods."""

    connection: Any
    target: ExpandedTarget
    #: Invariant 3's cache, probed on first use as on Oracle.
    _scope: Scope | None = field(default=None, init=False, repr=False)
    #: Why :meth:`cluster_identity` found no answer, or ``None``.
    identity_caveat: str | None = field(default=None, init=False)

    def scope(self) -> Scope:
        """What this session is: a cluster, read-write or not, and its encryption.

        Probed on the first call and cached for the session (invariant 3). A
        superuser is refused here, with ``SOPULI-20007``.
        """
        if self._scope is None:
            with self._cursor() as cursor:
                self._scope = observe(cursor, target=self.target.name)
            if LOG.isEnabledFor(logging.DEBUG):
                LOG.debug(
                    "%s is a cluster, %s %s, encryption %s",
                    self.target.name,
                    self._scope.db_version,
                    self._scope.open_mode,
                    self._scope.encryption.method,
                )
        return self._scope

    def cluster_identity(self) -> str | None:
        """The cluster's ``system_identifier``, which the CLI uses to refuse two
        targets that are one cluster. A primary and its standbys share it.

        ``None`` where the session may not run ``pg_control_system()``, with the
        reason in :attr:`identity_caveat`. Any role can run it by default, so
        this is a site that revoked it. Not knowing is not a finding.
        """
        try:
            with self._cursor() as cursor:
                cursor.execute(SYSTEM_IDENTIFIER)
                return str(cursor.fetchone()[0])
        except DriverError as error:
            if error.code != INSUFFICIENT_PRIVILEGE:
                raise
            self.identity_caveat = (
                "cannot read system_identifier, so the tool cannot tell whether another "
                f"target is the same cluster: {error.message}"
            )
            return None

    @contextmanager
    def _cursor(self) -> Iterator[Any]:
        """A cursor on the open connection, with the server's errors mapped.

        An error psycopg raises before it sends anything has no SQLSTATE and is
        not an ``OperationalError``. That is a fault in this tool, so it is left
        unmapped rather than reported as a lost connection.
        """
        if self.connection is None:
            raise DriverError(
                f'the session to target "{self.target.name}" is closed',
                hint="this is a fault in sopuli: a closed session was used again",
            )
        try:
            with self.connection.cursor() as cursor:
                yield cursor
        except psycopg.Error as error:
            if error.sqlstate is None and not isinstance(error, psycopg.OperationalError):
                raise
            raise from_error(error).as_error() from error

    def _not_written(self, what: str) -> NotWrittenError:
        return NotWrittenError(self.target.name, what)

    def describe_user(self, account: str) -> UserState | None:
        raise self._not_written("read a role")

    def byte_limit(self) -> ByteLimit:
        raise self._not_written("size a password")

    def password_constraints(self, account: str) -> None:
        """Not on the protocol: ``creds generate`` asks it of a driver that
        has it, and would read a missing method as no answer."""
        raise self._not_written("read a role's password rules")

    def privileges(self, *, accounts: tuple[str, ...] = ()) -> PrivilegeAudit:
        """What the tool account holds, needs and should not hold, and its
        ``ADMIN OPTION`` on each of ``accounts``. Uncached: a run asks once."""
        with self._cursor() as cursor:
            return audit(cursor, accounts)

    def set_password(self, account: str, secret: Secret) -> ChangeResult:
        raise self._not_written("set a password")

    def suspend_account(self, account: str) -> AccountChange:
        raise self._not_written("suspend a role")

    def reset_password(
        self, account: str, secret: Secret, *, expire: bool, keep_rollover: bool = False
    ) -> tuple[AccountChange, ...]:
        raise self._not_written("reset a password")

    def expire_password(self, account: str) -> tuple[AccountChange, ...]:
        raise self._not_written("expire a password")

    def audit_coverage(self, account: str) -> AuditCoverage:
        """Never raises, as the protocol promises: the answer is unknown."""
        return AuditCoverage(
            audited=None, detail="the PostgreSQL driver does not read audit settings yet"
        )

    def require_no_rollover_window(self, account: str) -> None:
        raise self._not_written("check a role for a rollover window")

    def apply_attributes(
        self, account: str, attributes: AccountAttributes
    ) -> tuple[AttributeChange, ...]:
        raise self._not_written("enforce a role's attributes")

    def resolve_profile(self, profile: str) -> str | None:
        raise self._not_written("look up a profile")

    def resolve_role(self, role: str) -> str | None:
        raise self._not_written("look up a role")

    def accounts_matching(
        self, *, profile: str | None = None, role: str | None = None
    ) -> tuple[str, ...]:
        raise self._not_written("list the roles a predicate admits")

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
        raise self._not_written("compare a stored verifier")

    def require_rollover(self, account: str) -> None:
        """PostgreSQL has no password rollover, so this always refuses
        (invariant 4)."""
        require_capability(self.scope(), PASSWORD_ROLLOVER, target=self.target.name)

    def finish_rollover(self, account: str) -> ChangeResult:
        raise self._not_written("end a rollover window")

    def close(self) -> None:
        """Let the connection go. Safe twice, also after a close that raised."""
        connection, self.connection = self.connection, None
        if connection is not None:
            connection.close()


@dataclass(frozen=True)
class PostgresDriver:
    """P1's :class:`~sopuli.driver.protocol.Driver`, for PostgreSQL. The run's
    half of the inputs; :meth:`connect` takes the target's."""

    correlation_id: str
    timeouts: Timeouts = field(default_factory=Timeouts)

    def connect(self, target: ExpandedTarget, credential: Credential) -> PostgresSession:
        """Reach ``target`` as ``credential``.

        ``application_name`` carries the correlation id from the first packet,
        so no statement of this session is logged without it.

        Autocommit, so a session that only reads holds no transaction open. A
        failure is classified by :mod:`sopuli.driver.postgres.errors`, and the
        debug line names the code and never the arguments, which hold the
        password.
        """
        arguments = connect_arguments(
            target, credential, correlation_id=self.correlation_id, timeouts=self.timeouts
        )
        started = time.monotonic()
        try:
            connection = psycopg.connect(**arguments, autocommit=True)
        except psycopg.Error as error:
            failure = from_error(error, connecting=True)
            LOG.debug(
                "connect to %s as %s failed with %s in %.3fs",
                target.name,
                credential.username,
                failure.code,
                time.monotonic() - started,
            )
            raise failure.as_error() from error
        LOG.debug(
            "connect to %s as %s in %.3fs",
            target.name,
            credential.username,
            time.monotonic() - started,
        )
        return PostgresSession(connection=connection, target=target)


def build_driver(context: DriverContext) -> PostgresDriver:
    """The registry's way in: a :class:`PostgresDriver` for this run. psycopg
    needs nothing from ``runtime``, since its wheel brings libpq."""
    return PostgresDriver(correlation_id=context.correlation_id, timeouts=context.timeouts)


def client_report(*, env: Mapping[str, str], runtime: Runtime) -> dict[str, Any]:
    """`doctor`'s client lines: psycopg, the libpq it loaded, and whether that
    libpq accepts ``require_auth``. Neither argument is read."""
    return client_lines(psycopg_version=psycopg.__version__, libpq_version=psycopg.pq.version())
