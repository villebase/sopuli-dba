"""Connecting to a SQL Server instance, and reporting what it is.

The module :data:`sopuli.driver.registry.DRIVERS` imports for ``type: mssql``.
It imports ``pyodbc`` at module scope, so a machine without the ``mssql``
extra gets ``SOPULI-20002`` from the registry rather than a traceback (ADR-006
rule 1). The modules beside it are tier 0.

**What this build does** (#1549). It connects through ODBC Driver 18 with the
target's ``mssql:`` settings (:mod:`~sopuli.driver.mssql.connection`), labels
the session with the run's correlation id, and reports the scope: ``server``,
whether ``master`` takes writes, and its encryption. Every other method
refuses with ``SOPULI-20006``, and the registry lists no command but
`doctor`. Reading logins, the refusals of decision 1 and the server's
identity are #1549's next part; the capabilities are #1550.

**pyodbc's pooling is off for the process.** A pooled connection is kept open
after ``close()``, and the next ``connect()`` with the same string reuses it
without logging in again. A run that changes a password and then logs in to
check it must log in for real.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, NoReturn, TypeVar

import pyodbc

from sopuli.config.model import ExpandedTarget, Runtime
from sopuli.config.targets import MSSQL_STRICT
from sopuli.driver.mssql.admin import Assessment, Catalog, assess, read_catalog
from sopuli.driver.mssql.client import client_lines
from sopuli.driver.mssql.connection import connection_string
from sopuli.driver.mssql.errors import from_error
from sopuli.driver.mssql.scope import observe
from sopuli.driver.protocol import (
    ClosesConnection,
    Credential,
    DriverContext,
    DriverError,
    Scope,
    Timeouts,
)
from sopuli.driver.registry import NotWrittenError
from sopuli.output.debug import logger

LOG = logger("mssql")

pyodbc.pooling = False

T = TypeVar("T")


@dataclass
class MssqlSession(ClosesConnection):
    """One open connection to a SQL Server instance. Implements the
    :class:`~sopuli.driver.protocol.Session` methods `doctor` uses; every other
    one refuses with ``SOPULI-20006``."""

    connection: Any
    target: ExpandedTarget
    #: Invariant 3's cache, probed on first use.
    _scope: Scope | None = field(default=None, init=False, repr=False)
    #: Guardrail 9's catalog, read on first use (:meth:`admin_assessment`).
    _catalog: Catalog | None = field(default=None, init=False, repr=False)

    def scope(self) -> Scope:
        """What this session is: a server, read-write or not, and its
        encryption. Probed on the first call and cached (invariant 3)."""
        if self._scope is None:
            settings = self.target.target.mssql_settings
            self._scope = self._read(
                lambda cursor: observe(cursor, target=self.target.name, settings=settings)
            )
            if LOG.isEnabledFor(logging.DEBUG):
                LOG.debug(
                    "%s is a server, %s %s, encryption %s",
                    self.target.name,
                    self._scope.db_version,
                    self._scope.open_mode,
                    self._scope.encryption.method,
                )
        return self._scope

    def admin_assessment(self, principal_id: int) -> Assessment:
        """Guardrail 9's input for the login ``principal_id``
        (`02-mssql-privileges.md` §5): the grants it reaches, or why they
        could not be read. The catalog is read on the first call and cached
        for the session, so every managed login on the target is assessed
        against one read."""
        if self._catalog is None:
            self._catalog = self._read(read_catalog)
            LOG.debug(
                "%s guardrail catalog: %s",
                self.target.name,
                self._catalog.unread or "complete",
            )
        return assess(principal_id, self._catalog)

    def _not_written(self, what: str) -> NoReturn:
        raise NotWrittenError(
            self.target.name,
            product="a SQL Server instance",
            what=what,
            hint=(
                "the SQL Server driver connects and reports the instance for `doctor`, "
                "and the rest of it is not written yet (#1549 to #1555)"
            ),
        )

    def privileges(self, *args: Any, **kwargs: Any) -> NoReturn:
        self._not_written("audit the tool login's grants")

    def describe_user(self, account: str) -> NoReturn:
        self._not_written("describe a login")

    def byte_limit(self) -> NoReturn:
        self._not_written("say how long a password may be")

    def set_password(self, *args: Any, **kwargs: Any) -> NoReturn:
        self._not_written("set a password")

    def suspend_account(self, account: str) -> NoReturn:
        self._not_written("suspend a login")

    def reset_password(self, *args: Any, **kwargs: Any) -> NoReturn:
        self._not_written("reset a password")

    def expire_password(self, account: str) -> NoReturn:
        self._not_written("expire a password")

    def audit_coverage(self, account: str) -> NoReturn:
        self._not_written("read audit coverage")

    def apply_attributes(self, *args: Any, **kwargs: Any) -> NoReturn:
        self._not_written("apply login attributes")

    def resolve_profile(self, profile: str) -> NoReturn:
        self._not_written("resolve a profile")

    def resolve_role(self, role: str) -> NoReturn:
        self._not_written("resolve a role")

    def accounts_matching(self, *args: Any, **kwargs: Any) -> NoReturn:
        self._not_written("list logins")

    def verify_password(self, *args: Any, **kwargs: Any) -> NoReturn:
        self._not_written("verify a password")

    def require_verifier(self, *args: Any, **kwargs: Any) -> NoReturn:
        self._not_written("check a password by its stored value")

    def require_rollover(self, account: str) -> NoReturn:
        self._not_written("keep a rollover window")

    def finish_rollover(self, *args: Any, **kwargs: Any) -> NoReturn:
        self._not_written("finish a rollover")

    def _read(self, reader: Callable[[Any], T]) -> T:
        """Run ``reader`` on a cursor of this session. A closed session is a
        fault in sopuli, and a pyodbc error is classified by
        :mod:`~sopuli.driver.mssql.errors`."""
        if self.connection is None:
            raise DriverError(
                f'the session to target "{self.target.name}" is closed',
                hint="this is a fault in sopuli: a closed session was used again",
            )
        cursor = self.connection.cursor()
        try:
            return reader(cursor)
        except pyodbc.Error as error:
            raise from_error(error).as_error() from error
        finally:
            cursor.close()


@dataclass(frozen=True)
class MssqlDriver:
    """P1's :class:`~sopuli.driver.protocol.Driver`, for SQL Server."""

    correlation_id: str
    timeouts: Timeouts = field(default_factory=Timeouts)

    def connect(self, target: ExpandedTarget, credential: Credential) -> MssqlSession:
        """Reach ``target`` as ``credential``.

        Autocommit, so a session that only reads holds no transaction open.
        ``timeout`` is the login timeout, and the connection's ``timeout`` the
        query budget, where 0 sets none. A failure is classified with
        ``connecting=True``, and the debug line names the code and never the
        connection string, which holds the password.
        """
        text = connection_string(target, credential, correlation_id=self.correlation_id)
        strict = target.target.mssql_settings.encrypt == MSSQL_STRICT
        started = time.monotonic()
        try:
            connection = pyodbc.connect(text, autocommit=True, timeout=self.timeouts.connect_s)
        except pyodbc.Error as error:
            failure = from_error(error, connecting=True, strict=strict)
            LOG.debug(
                "connect to %s as %s failed with %s in %.3fs",
                target.name,
                credential.username,
                failure.code,
                time.monotonic() - started,
            )
            raise failure.as_error() from error
        connection.timeout = self.timeouts.query_s
        LOG.debug(
            "connect to %s as %s in %.3fs",
            target.name,
            credential.username,
            time.monotonic() - started,
        )
        return MssqlSession(connection=connection, target=target)


def build_driver(context: DriverContext) -> MssqlDriver:
    """The registry's way in: a :class:`MssqlDriver` for this run."""
    return MssqlDriver(correlation_id=context.correlation_id, timeouts=context.timeouts)


def client_report(*, env: Mapping[str, str], runtime: Runtime) -> dict[str, Any]:
    """`doctor`'s client lines: pyodbc's release, and whether the ODBC driver
    manager lists ODBC Driver 18. Neither argument is read."""
    return client_lines(pyodbc_version=pyodbc.version, drivers=pyodbc.drivers())
