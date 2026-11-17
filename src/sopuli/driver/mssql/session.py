"""Connecting to a SQL Server instance, and reporting what it is.

The module :data:`sopuli.driver.registry.DRIVERS` imports for ``type: mssql``.
It imports ``pyodbc`` at module scope, so a machine without the ``mssql``
extra gets ``SOPULI-20002`` from the registry rather than a traceback (ADR-006
rule 1). The modules beside it are tier 0.

**What this build does** (#1549). It connects through ODBC Driver 18 with the
target's ``mssql:`` settings (:mod:`~sopuli.driver.mssql.connection`), labels
the session with the run's correlation id, and reports the scope: ``server``,
whether ``master`` takes writes, and its encryption. It reads a declared
login (:meth:`MssqlSession.describe_user`), refusing every principal but a
SQL login, and names the instance by ``SERVERPROPERTY('ServerName')``
(:meth:`MssqlSession.cluster_identity`). Every other method refuses with
``SOPULI-20006``, and the registry lists no command but `doctor`: the first
verbs come with the password change (#1551) and the login check (#1552).
The capabilities are #1550.

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
from datetime import UTC, datetime
from typing import Any, NoReturn, TypeVar

import pyodbc

from sopuli.config.model import ExpandedTarget, Runtime
from sopuli.config.targets import MSSQL_STRICT
from sopuli.driver.mssql import accounts
from sopuli.driver.mssql.admin import Assessment, Catalog, assess, read_catalog
from sopuli.driver.mssql.client import client_lines
from sopuli.driver.mssql.connection import connection_string
from sopuli.driver.mssql.errors import (
    CAPABILITY,
    STRICT_ENCRYPTION,
    STRICT_REMEDY,
    from_error,
)
from sopuli.driver.mssql.scope import observe
from sopuli.driver.protocol import (
    ClosesConnection,
    Credential,
    Cursor,
    DriverContext,
    DriverError,
    Scope,
    Timeouts,
    UnsupportedCapabilityError,
    UserState,
)
from sopuli.driver.registry import NotWrittenError
from sopuli.output.debug import logger

LOG = logger("mssql")

pyodbc.pooling = False

T = TypeVar("T")


def _server_name(cursor: Cursor) -> str | None:
    """``SERVERPROPERTY('ServerName')``, or ``None`` where the server gives
    none."""
    cursor.execute("SELECT CAST(SERVERPROPERTY('ServerName') AS nvarchar(256))")
    row = cursor.fetchone()
    return str(row[0]) if row and row[0] is not None else None


@dataclass
class MssqlSession(ClosesConnection):
    """One open connection to a SQL Server instance. Implements the
    :class:`~sopuli.driver.protocol.Session` methods `doctor` uses and
    :meth:`describe_user`; every other one refuses with ``SOPULI-20006``."""

    connection: Any
    target: ExpandedTarget
    #: Invariant 3's cache, probed on first use.
    _scope: Scope | None = field(default=None, init=False, repr=False)
    #: :class:`~sopuli.driver.clusters.ClusterIdentity`'s: nothing is claimed
    #: less than it could be, so always ``None``.
    identity_caveat: str | None = field(default=None, init=False, repr=False)
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
                "and the rest of it is not written yet (#1550 to #1555)"
            ),
        )

    def privileges(self, *args: Any, **kwargs: Any) -> NoReturn:
        self._not_written("audit the tool login's grants")

    def describe_user(self, account: str) -> UserState | None:
        """The login's state, ``None`` where no login has the name
        (:mod:`~sopuli.driver.mssql.accounts`). Any principal but a SQL login
        is refused with
        :class:`~sopuli.driver.mssql.accounts.NotAPasswordLoginError`.

        A contained database user is not a login, and the tool login does not
        see one, so its name reads as ``None`` (``02-mssql-privileges.md``
        §4).
        """
        login = self._read(
            lambda cursor: accounts.read_one(cursor, account, target=self.target.name)
        )
        if login is None:
            return None
        assessment = self.admin_assessment(login.principal_id)
        return accounts.state_of(
            login,
            now=datetime.now(UTC),
            admin_unread=assessment.unread,
            global_privileges=assessment.grants,
        )

    #: The words for two targets that are one instance
    #: (:class:`~sopuli.driver.clusters.ClusterIdentity`). Not fields.
    identity_kind = "SQL Server instance"
    identity_key = "ServerName"
    identity_hint = (
        "declare each instance once: two targets on one instance would change its "
        "logins under two names"
    )

    def cluster_identity(self) -> str | None:
        """The instance's ``SERVERPROPERTY('ServerName')``, which the CLI uses
        to refuse two targets that are one instance. It is the host's name,
        with the instance's for a named instance. Nothing else measured tells
        two instances apart: ``master``'s ``service_broker_guid`` is all zeros,
        and ``msdb``'s comes with the image (``05_identity_probe.py``, ID2,
        ID5). So two instances on hosts of one name are refused as one.

        Not ``@@SERVERNAME``, which reads the same on the matrix (ID2): by
        Microsoft's documentation it keeps the name the instance was installed
        under until somebody resets it, so two hosts cloned from one image
        would read one name. ``ServerName`` follows the host's own name. That
        difference is not measured."""
        return self._read(_server_name)

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
            if failure.category == CAPABILITY:
                # Invariant 4: the server cannot be read over a connection it
                # resets, so the reset is the tool's only answer to whether it
                # takes TDS 8. A network fault reads the same; the hint says so,
                # after the driver's own words, and the code is kept.
                refused = UnsupportedCapabilityError(
                    STRICT_ENCRYPTION,
                    target=target.name,
                    hint=f"{failure.hint}. The ODBC driver said: {failure.message}",
                    remedy=STRICT_REMEDY,
                )
                refused.code = failure.code
                raise refused from error
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
