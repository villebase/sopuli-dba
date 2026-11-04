"""Connecting to a MariaDB server, and reporting what it is.

The module :data:`sopuli.driver.registry.DRIVERS` imports for ``type: mariadb``.
It imports ``pymysql`` at module scope, so a machine without the ``mariadb``
extra gets ``SOPULI-20002`` from the registry rather than a traceback (ADR-006
rule 1). The modules beside it are tier 0.

**What this build does** (#1268). It connects through
:mod:`sopuli.driver.mysql_family`, labels the session with the run's
correlation id, checks that a mode which requires TLS got it, and reports the
scope: ``server``, whether it takes writes, and its encryption. For ``doctor
--check-privileges`` it audits the tool account's grants
(:mod:`~sopuli.driver.mariadb.privileges`) and surveys the declared accounts
(:mod:`~sopuli.driver.mariadb.accounts`). It describes a declared account,
with the privileges guardrail 9 checks (#1270). Every other method refuses with
``SOPULI-20006``, and the registry lists no command but `doctor`: the rest of
UC-1 is #1270 and UC-2 #1272.

The session claims no server identity: MariaDB has no ``server_uuid``, and
11.8.9 shows no ``server_uid`` status either, so two targets on one server are
not caught here (#1286).
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, replace
from typing import Any, NoReturn, TypeVar

import pymysql

from sopuli.config.model import ExpandedTarget, Runtime
from sopuli.driver.mariadb import accounts as accounts_module
from sopuli.driver.mariadb.errors import from_error
from sopuli.driver.mariadb.privileges import audit as privilege_audit
from sopuli.driver.mariadb.scope import observe
from sopuli.driver.mysql_family.accounts import current_user
from sopuli.driver.mysql_family.client import client_lines
from sopuli.driver.mysql_family.connection import connect_arguments, require_tls
from sopuli.driver.mysql_family.encryption import read_encryption
from sopuli.driver.mysql_family.errors import COLUMN_ACCESS_DENIED, TABLE_ACCESS_DENIED
from sopuli.driver.protocol import (
    ClosesConnection,
    Credential,
    DriverContext,
    DriverError,
    Encryption,
    PrivilegeAudit,
    Scope,
    Timeouts,
    UserState,
)
from sopuli.driver.registry import NotWrittenError
from sopuli.output.debug import logger

LOG = logger("mariadb")

MISSING_GRANT_HINT = (
    "the tool account lacks a grant of 02-mariadb-privileges.md section 2.1, which it "
    "needs to read an account and the privileges guardrail 9 checks. "
    "`sopuli doctor --check-privileges` lists the missing ones, and the statements "
    "that grant them"
)

#: The server refused a read of a table (``1142``) or a column (``1143``).
REFUSED_READ = frozenset({str(TABLE_ACCESS_DENIED), str(COLUMN_ACCESS_DENIED)})

#: The privileges MariaDB split from ``SUPER`` that set no column of the
#: ``mysql.user`` view, as ``SHOW PRIVILEGES`` names them (SP1, SP2).
UNSEEN_PRIVILEGES = (
    "BINLOG ADMIN",
    "BINLOG REPLAY",
    "CONNECTION ADMIN",
    "FEDERATED ADMIN",
    "READ_ONLY ADMIN",
    "REPLICATION MASTER ADMIN",
    "REPLICATION SLAVE ADMIN",
    "SET USER",
    "SLAVE MONITOR",
)

#: The gap in guardrail 9 that ``02-mariadb-privileges.md`` §5 accepts
#: (#1267, decision 4): said wherever the config binds accounts to the
#: target, because check 9 cannot fully check any of them.
CHECK_9_GAP = (
    f"check 9 cannot see {', '.join(UNSEEN_PRIVILEGES[:-1])} or {UNSEEN_PRIVILEGES[-1]}: "
    "they set no column of the mysql.user view, so it does not refuse a declared account "
    "that holds one. Revoke them from accounts the tool manages "
    "(02-mariadb-privileges.md section 5)"
)

T = TypeVar("T")


@dataclass
class MariadbSession(ClosesConnection):
    """One open connection to a MariaDB server. Implements the
    :class:`~sopuli.driver.protocol.Session` methods `doctor` uses, and
    :meth:`describe_user`; every other one refuses with ``SOPULI-20006``."""

    connection: Any
    target: ExpandedTarget
    correlation_id: str
    timeouts: Timeouts
    #: The session's encryption, read at connect to hold a mode that requires
    #: TLS to it, so :meth:`scope` does not read it again.
    encryption: Encryption | None = None
    #: Invariant 3's cache, probed on first use.
    _scope: Scope | None = field(default=None, init=False, repr=False)
    #: ``CURRENT_USER()``, read on the first :meth:`describe_user`. It does
    #: not change for the life of a connection.
    _session_user: str | None = field(default=None, init=False, repr=False)

    def scope(self) -> Scope:
        """What this session is: a server, read-write or not, and its
        encryption. Probed on the first call and cached (invariant 3)."""
        if self._scope is None:
            self._scope = self._read(
                lambda cursor: observe(cursor, target=self.target.name, encryption=self.encryption)
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

    def privileges(self, *, accounts: tuple[str, ...] = ()) -> PrivilegeAudit:
        """What the tool account holds, needs and should not hold, and a line
        for each declared account that does not exist, uses a plugin the tool
        does not change, or shares its user name with an account at an
        undeclared host. Where the survey's read fails, the audit stands and a
        line says why, as on MySQL. With any declared account, a last line
        says what check 9 cannot see (:data:`CHECK_9_GAP`)."""
        audit = self._read(privilege_audit)
        if not accounts:
            return audit
        try:
            lines = self._read(lambda cursor: accounts_module.survey(cursor, accounts))
        except DriverError as error:
            # Only a refused read, the missing column grant: a config fault
            # or a fault in sopuli is not a missing privilege.
            if error.code not in REFUSED_READ:
                raise
            return replace(
                audit,
                unreadable=(*audit.unreadable, "mysql.user"),
                remedies=(
                    *audit.remedies,
                    f"the declared accounts were not read: {error}",
                    CHECK_9_GAP,
                ),
            )
        return replace(audit, remedies=(*audit.remedies, *lines, CHECK_9_GAP))

    def _not_written(self, what: str) -> NoReturn:
        raise NotWrittenError(
            self.target.name,
            product="a MariaDB server",
            what=what,
            hint=(
                "the MariaDB driver connects, reports the server for `doctor` and "
                "describes an account, and the rest of it is not written yet "
                "(#1270, #1272)"
            ),
        )

    def describe_user(self, account: str) -> UserState | None:
        """The account's state, ``None`` where it does not exist
        (:func:`~sopuli.driver.mariadb.accounts.describe`), with the
        privileges guardrail 9 checks. An account on another plugin is
        refused with :class:`~sopuli.driver.mariadb.accounts.OtherPluginError`.

        A tool account without §2.1's grants for the reads is refused with
        ``1142`` or ``1143``, and the hint then says where the grants are: the
        server's own hint names only the table.
        """
        return self._read_grants(lambda cursor: self._describe(cursor, account))

    def _describe(self, cursor: Any, account: str) -> UserState | None:
        if self._session_user is None:
            self._session_user = current_user(cursor)
        return accounts_module.describe(
            cursor, account, target=self.target.name, session_user=self._session_user
        )

    def _read_grants(self, reader: Callable[[Any], T]) -> T:
        """:meth:`_read`, with the hint about §2.1's grants on a refused read."""
        try:
            return self._read(reader)
        except DriverError as error:
            if error.code in REFUSED_READ:
                error.hint = MISSING_GRANT_HINT
            raise

    def byte_limit(self) -> NoReturn:
        self._not_written("say how long a password may be")

    def set_password(self, *args: Any, **kwargs: Any) -> NoReturn:
        self._not_written("set a password")

    def suspend_account(self, account: str) -> NoReturn:
        self._not_written("suspend an account")

    def reset_password(self, *args: Any, **kwargs: Any) -> NoReturn:
        self._not_written("reset a password")

    def expire_password(self, account: str) -> NoReturn:
        self._not_written("expire a password")

    def audit_coverage(self, account: str) -> NoReturn:
        self._not_written("read audit coverage")

    def apply_attributes(self, *args: Any, **kwargs: Any) -> NoReturn:
        self._not_written("apply account attributes")

    def resolve_profile(self, profile: str) -> NoReturn:
        self._not_written("resolve a profile")

    def resolve_role(self, role: str) -> NoReturn:
        self._not_written("resolve a role")

    def accounts_matching(self, *args: Any, **kwargs: Any) -> NoReturn:
        self._not_written("list accounts")

    def verify_password(self, *args: Any, **kwargs: Any) -> NoReturn:
        self._not_written("verify a password")

    def require_verifier(self, *args: Any, **kwargs: Any) -> NoReturn:
        self._not_written("check a password by its stored value")

    def require_rollover(self, account: str) -> NoReturn:
        self._not_written("keep a rollover window")

    def finish_rollover(self, account: str) -> NoReturn:
        self._not_written("finish a rollover")

    def _read(self, reader: Callable[[Any], T]) -> T:
        """Run ``reader`` on a cursor of this session. A closed session is a
        fault in sopuli, and a MariaDB error is classified by
        :mod:`~sopuli.driver.mariadb.errors`."""
        if self.connection is None:
            raise DriverError(
                f'the session to target "{self.target.name}" is closed',
                hint="this is a fault in sopuli: a closed session was used again",
            )
        try:
            with self.connection.cursor() as cursor:
                return reader(cursor)
        except pymysql.err.MySQLError as error:
            raise from_error(error).as_error() from error


@dataclass(frozen=True)
class MariadbDriver:
    """P1's :class:`~sopuli.driver.protocol.Driver`, for MariaDB."""

    correlation_id: str
    timeouts: Timeouts = field(default_factory=Timeouts)

    def connect(self, target: ExpandedTarget, credential: Credential) -> MariadbSession:
        """Reach ``target`` as ``credential``. A failure is classified with
        ``connecting=True``, and the debug line names the code and never the
        arguments, which hold the password."""
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
        LOG.debug(
            "connect to %s as %s in %.3fs",
            target.name,
            credential.username,
            time.monotonic() - started,
        )
        try:
            with connection.cursor() as cursor:
                encryption = read_encryption(cursor, block="mariadb")
            require_tls(encryption, target)
        except pymysql.err.MySQLError as error:
            connection.close()
            raise from_error(error).as_error() from error
        except BaseException:
            connection.close()
            raise
        return MariadbSession(
            connection=connection,
            target=target,
            correlation_id=self.correlation_id,
            timeouts=self.timeouts,
            encryption=encryption,
        )


def build_driver(context: DriverContext) -> MariadbDriver:
    """The registry's way in: a :class:`MariadbDriver` for this run."""
    return MariadbDriver(correlation_id=context.correlation_id, timeouts=context.timeouts)


def client_report(*, env: Mapping[str, str], runtime: Runtime) -> dict[str, Any]:
    """`doctor`'s client line: PyMySQL's release, as on MySQL."""
    return client_lines(pymysql_version=".".join(str(part) for part in pymysql.VERSION[:3]))
