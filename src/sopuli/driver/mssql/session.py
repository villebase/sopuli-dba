"""Connecting to a SQL Server instance, and reporting what it is.

The module :data:`sopuli.driver.registry.DRIVERS` imports for ``type: mssql``.
It imports ``pyodbc`` at module scope, so a machine without the ``mssql``
extra gets ``SOPULI-20002`` from the registry rather than a traceback (ADR-006
rule 1). The modules beside it are tier 0.

**What this build does** (#1549, #1550, #1551). It connects through ODBC
Driver 18 with the target's ``mssql:`` settings
(:mod:`~sopuli.driver.mssql.connection`), labels the session with the run's
correlation id, and reports the scope: ``server``, whether ``master`` takes
writes, and its encryption. It reads a declared login
(:meth:`MssqlSession.describe_user`), refusing every principal but a SQL
login, and names the instance by ``SERVERPROPERTY('ServerName')``
(:meth:`MssqlSession.cluster_identity`). It reads the host's platform and the
password value's version as capabilities
(:mod:`~sopuli.driver.mssql.capabilities`), and what it can of the
Availability Groups the instance is in (:mod:`~sopuli.driver.mssql.groups`):
the replicas' names, for `doctor`'s ``SOPULI-W076``, and whether its database
is a contained group's master, which the scope refuses.

On a Linux host it changes a password for `creds apply` and `creds rotate`,
in ``02-mssql-privileges.md`` §6.2's order: the command records the login's
flags (:meth:`MssqlSession.policy_flags`), :meth:`MssqlSession.set_password`
sends the value with the policy off, :meth:`MssqlSession.verify_password`
logs in as the login, and :meth:`MssqlSession.restore_policy` sets the flags
back. A Windows host is refused with ``SOPULI-20006`` before anything is sent
(#1551's next part), and so is every method not written yet.

**pyodbc's pooling is off for the process.** A pooled connection is kept open
after ``close()``, and the next ``connect()`` with the same string reuses it
without logging in again. A run that changes a password and then logs in to
check it must log in for real.
"""

from __future__ import annotations

import logging
import re
import time
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager, suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, NoReturn, TypeVar

import pyodbc

from sopuli.config.model import ExpandedTarget, Runtime
from sopuli.config.targets import MSSQL_STRICT
from sopuli.driver.mssql import accounts, capabilities, groups, statements, survey
from sopuli.driver.mssql import privileges as tool_login
from sopuli.driver.mssql.admin import Assessment, Catalog, assess, read_catalog
from sopuli.driver.mssql.client import client_lines
from sopuli.driver.mssql.connection import connection_string
from sopuli.driver.mssql.errors import (
    CAPABILITY,
    STRICT_ENCRYPTION,
    STRICT_REMEDY,
    from_error,
    raw_message,
    records,
    server_error,
)
from sopuli.driver.mssql.limits import LIMIT
from sopuli.driver.mssql.password import password_value
from sopuli.driver.mssql.scope import observe
from sopuli.driver.protocol import (
    FAIL,
    OFFLINE_VERIFY,
    OLD_DISCARD,
    PASS,
    PASSWORD_ROLLOVER,
    ROLE_LOOKUP,
    UNAVAILABLE,
    VERIFY_BOTH,
    VERIFY_HASH,
    VERIFY_LOGIN,
    AuditCoverage,
    ChangeResult,
    ClosesConnection,
    Credential,
    Cursor,
    DriverContext,
    DriverError,
    PrivilegeAudit,
    Scope,
    Timeouts,
    UnsupportedCapabilityError,
    UserState,
    VerifyResult,
    require_capability,
    require_read_write,
)
from sopuli.driver.registry import NotWrittenError
from sopuli.driver.survey import SurveyedAccount
from sopuli.output.debug import logger
from sopuli.passwords import ByteLimit
from sopuli.policy_flags import PolicyFlags
from sopuli.secrets import Secret

LOG = logger("mssql")

pyodbc.pooling = False

T = TypeVar("T")


#: A password value as a hex literal, or the start of one, in a message the
#: server quotes a statement in. The value allows an offline guessing attack,
#: so no message keeps one (``02-mssql-privileges.md`` §6.2).
_VALUE = re.compile(r"0x[0-9A-Fa-f]{8,}")

#: What replaces a value in a message.
VALUE_REMOVED = "0x…"


def scrub_value(message: str) -> str:
    """``message`` with every password value in it replaced by
    :data:`VALUE_REMOVED`, for a statement that carries one (#786)."""
    return _VALUE.sub(VALUE_REMOVED, message)


#: The server's answers to a login, by number (§7), and what each says about
#: the password. ``18470`` (disabled) and ``18488`` (must change) say nothing
#: until it is measured how such a login answers a wrong one (#1552).
WRONG_PASSWORD = "18456"
LOGIN_DISABLED = "18470"
MUST_CHANGE = "18488"

#: The host platform this build changes passwords on.
LINUX = "Linux"


class MustChangeError(DriverError):
    """A login whose ``MUST_CHANGE`` is pending: the server refuses to turn its
    policy off, ``15128``, so it cannot take a value (§6.2). Refused before
    anything is written or sent."""

    about_account = True

    def __init__(self, account: str, *, target: str) -> None:
        super().__init__(
            f'login "{account}" on target "{target}" must change its password at its next '
            "login, so it cannot take a value the tool computes",
            hint=(
                "the server refuses CHECK_POLICY = OFF while MUST_CHANGE is pending. Let "
                "the owner log in and change it, or clear it by hand, then run again"
            ),
        )


def _not_tried(detail: str) -> VerifyResult:
    """A login :meth:`MssqlSession.verify_password` settled without trying."""
    return VerifyResult(method=VERIFY_LOGIN, result=UNAVAILABLE, detail=detail)


def _ms(started: float) -> int:
    return int((time.monotonic() - started) * 1000)


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
    #: The run's, for the logins :meth:`verify_password` makes as a managed
    #: login, which carry the same ``APP`` and login timeout.
    correlation_id: str = ""
    timeouts: Timeouts = field(default_factory=Timeouts)
    #: Invariant 3's cache, probed on first use.
    _scope: Scope | None = field(default=None, init=False, repr=False)
    #: :class:`~sopuli.driver.clusters.ClusterIdentity`'s: nothing is claimed
    #: less than it could be, so always ``None``.
    identity_caveat: str | None = field(default=None, init=False, repr=False)
    #: Guardrail 9's catalog, read on first use (:meth:`admin_assessment`).
    _catalog: Catalog | None = field(default=None, init=False, repr=False)
    #: The Availability Group reads (:mod:`~sopuli.driver.mssql.groups`),
    #: read on first use.
    _replicas: tuple[str, ...] | None = field(default=None, init=False, repr=False)
    #: Why :meth:`scope` refused this session, kept so that it is raised
    #: again without another read.
    _scope_refusal: DriverError | None = field(default=None, init=False, repr=False)
    #: The capabilities of #1550, read on first use.
    _host_platform: str | None = field(default=None, init=False, repr=False)
    _host_read: bool = field(default=False, init=False, repr=False)
    _hash_version: int | None = field(default=None, init=False, repr=False)

    def scope(self) -> Scope:
        """What this session is: a server, read-write or not, and its
        encryption. Probed on the first call and cached (invariant 3).

        A session in a contained Availability Group's own ``master`` is
        refused here, before any login is read
        (:class:`~sopuli.driver.mssql.groups.ContainedGroupMasterError`). A
        refusal is kept as the scope is, and raised again on the next call
        without another read."""
        if self._scope_refusal is not None:
            raise self._scope_refusal
        if self._scope is None:
            settings = self.target.target.mssql_settings
            try:
                self._scope = self._read(
                    lambda cursor: observe(cursor, target=self.target.name, settings=settings)
                )
            except (groups.ContainedGroupMasterError, groups.MasterUnreadError) as refused:
                self._scope_refusal = refused
                raise
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
        against one read. The scope comes first, so a session in a contained
        group's master is refused before any login is read."""
        self.scope()
        if self._catalog is None:
            self._catalog = self._read(read_catalog)
            LOG.debug(
                "%s guardrail catalog: %s",
                self.target.name,
                self._catalog.unread or "complete",
            )
        return assess(principal_id, self._catalog)

    def host_platform(self) -> str | None:
        """``Linux`` or ``Windows``: the host's platform, read once and
        cached (:mod:`~sopuli.driver.mssql.capabilities`). ``None`` where the
        server named none, which a caller treats as Windows: the side whose
        lockout the tool cannot see."""
        if not self._host_read:
            self._host_platform = self._read(capabilities.host_platform)
            self._host_read = True
            LOG.debug("%s runs on %s", self.target.name, self._host_platform or "an unnamed host")
        return self._host_platform

    def hash_version(self) -> int:
        """The password value's version this server takes: ``0x0300`` or
        ``0x0200``, read once with the rolled-back check and cached (#1564).

        Only a session that will set a password calls it, the `--dry-run` of
        one included, so that the plan names the value it would send; the
        command never calls it for a target that is ``readonly``. A session
        that found ``master`` read-only refuses it, as it refuses a write.
        Any other answer refuses the target as lacking ``password_value``, with
        the server's own words, and is not cached: the next call asks again.
        A refusal the driver's error rules call ``authorization``, a missing
        permission, is raised as that instead: it names the grant to add.
        """
        if self._hash_version is None:
            require_read_write(
                self.scope(),
                target=self.target.name,
                hint="the check for the password value's version is a write, rolled back",
            )
            answer, message = self._check_answer(
                capabilities.check_statement(capabilities.check_name())
            )
            self._hash_version = capabilities.version_from(
                answer, target=self.target.name, message=message
            )
            LOG.debug(
                "%s takes a 0x%04X password value (check answered %s)",
                self.target.name,
                self._hash_version,
                answer,
            )
        return self._hash_version

    def _check_answer(self, statement: str) -> tuple[str, str | None]:
        """``ok``, or the number and text of the first server error, for the
        check's batch. An informational record, SQLSTATE ``01…``, such as a
        trigger's ``PRINT``, is not an answer.

        Whatever the failure, the transaction the batch opened is ended
        before anything is raised: a client timeout leaves it open on the
        server. A failure with no server error is the connection's, and a
        missing permission is the tool login's; each is raised as
        :meth:`_read` raises it."""
        with self._cursor() as cursor:
            try:
                cursor.execute(statement)
                # An error in a later statement of the batch is raised when
                # its result is reached.
                while cursor.nextset():
                    pass
            except pyodbc.Error as error:
                self._end_transaction(cursor)
                diagnosis = from_error(error)
                server = server_error(records(raw_message(error)))
                if server is None or diagnosis.category == "authorization":
                    raise diagnosis.as_error() from error
                return str(server.number), server.text
            return capabilities.TAKES_IT, None

    def _end_transaction(self, cursor: Any) -> None:
        """End the check's transaction if one is open. A connection that
        cannot take it has no transaction to keep: the server ends it with
        the session. So a failure here is left to the error being raised."""
        try:
            cursor.execute(capabilities.END_TRANSACTION)
        except pyodbc.Error as error:
            LOG.debug(
                "%s: ending the check's transaction failed: %s",
                self.target.name,
                from_error(error).code,
            )

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

    def privileges(self, *, accounts: tuple[str, ...] = ()) -> PrivilegeAudit:
        """What the tool login holds, needs and should not hold
        (:mod:`~sopuli.driver.mssql.privileges`). ``accounts`` is ignored:
        ``ALTER ANY LOGIN`` reaches every login. Uncached: a run asks once.

        The user in ``msdb`` is a read of its own: where ``msdb`` refuses the
        tool login, the audit stands and says so."""
        try:
            msdb_user: bool | None = self._read(tool_login.read_msdb_user)
        except DriverError as error:
            # Only a refusal, 916 or 229, says msdb is closed to the tool
            # login. A lost connection or a fault is raised as it is.
            if error.category != "authorization":
                raise
            LOG.debug("%s: msdb could not be read: %s", self.target.name, error.code)
            msdb_user = None
        return self._read(lambda cursor: tool_login.audit(cursor, msdb_user=msdb_user))

    def describe_user(self, account: str) -> UserState | None:
        """The login's state, ``None`` where no login has the name
        (:mod:`~sopuli.driver.mssql.accounts`). Any principal but a SQL login
        is refused with
        :class:`~sopuli.driver.mssql.accounts.NotAPasswordLoginError`.

        A contained database user is not a login, and the tool login does not
        see one, so its name reads as ``None`` (``02-mssql-privileges.md``
        §4).
        """
        # The scope refuses a contained group's master before a login is read.
        self.scope()
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

    def survey_with_profiles(self) -> tuple[tuple[SurveyedAccount, ...], frozenset[str]]:
        """Every login, and no profiles: SQL Server has none.

        :class:`~sopuli.driver.survey.AccountSurvey`, for `report accounts`
        (:mod:`~sopuli.driver.mssql.survey`). The registry makes the profile
        check *not applicable* here, so the empty set reports nothing missing.
        The scope comes first, so a contained group's master is refused before
        a login is read, as in :meth:`describe_user`."""
        self.scope()
        platform = self.host_platform()
        return self._read(lambda cursor: survey.survey(cursor, platform=platform)), frozenset()

    def availability_replicas(self) -> tuple[str, ...]:
        """The names of the replicas of every Availability Group the instance
        is in, itself among them, or none (:mod:`~sopuli.driver.mssql.groups`).
        Read once and cached."""
        if self._replicas is None:
            self._replicas = self._read(groups.replicas)
        return self._replicas

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

    def byte_limit(self) -> ByteLimit:
        """128 UTF-16 code units, whatever the server
        (:mod:`~sopuli.driver.mssql.limits`)."""
        return LIMIT

    def password_constraints(self, account: str) -> None:
        """Nothing beyond the length, read without a round trip: the server's
        policy does not apply to a value (§6.2). Not on the protocol: ``creds
        generate`` asks it of a driver that has it."""

    def require_host(self) -> None:
        """Refuse, when the command opens the session, a host this build
        changes no password on: every command but `doctor` asks, so a Windows
        host is refused before a pre-flight passes it or `creds rotate`
        stages a password there (invariant 4)."""
        self._require_linux("run this command")

    def _require_linux(self, what: str) -> None:
        """Refuse ``what`` on a host that is not Linux, before anything is
        sent. A Windows host locks a login, so `apply` there must not log in
        before a change, which is #1551's next part. A host that names no
        platform is treated as Windows."""
        if self.host_platform() != LINUX:
            self._not_written(f"{what} on a Windows host")

    #: The command records the flags :meth:`policy_flags` reads, before
    #: :meth:`set_password`, and calls :meth:`restore_policy` after the login
    #: (``02-mssql-privileges.md`` §6.2). Read by the command, as
    #: ``verifies_before_change`` is.
    keeps_policy_flags = True

    def policy_flags(self, account: str) -> PolicyFlags:
        """Step 1: the login's ``CHECK_POLICY`` and ``CHECK_EXPIRATION`` as
        they are now, which the command records in the vault before
        :meth:`set_password` turns the policy off.

        Refuses, before anything is written or sent, a Windows host, a login
        whose ``MUST_CHANGE`` is pending (:class:`MustChangeError`), and a
        server whose value version cannot be read (:meth:`hash_version`).
        """
        self._require_linux("set a password")
        login = self._read(
            lambda cursor: accounts.read_one(cursor, account, target=self.target.name)
        )
        if login is None:
            raise DriverError(
                f'there is no login "{account}" on target "{self.target.name}"',
                hint="create the login, or check the account's name in the config",
            )
        if login.must_change:
            raise MustChangeError(login.name, target=self.target.name)
        # The value's version, asked here so that a server that takes neither,
        # or a tool login the check refuses, stops the change before the
        # command writes the record (#1564).
        self.hash_version()
        return PolicyFlags(
            check_policy=login.policy_checked, check_expiration=login.expiration_checked
        )

    def set_password(
        self,
        account: str,
        secret: Secret,
        *,
        old_password: str = OLD_DISCARD,
        previous: Secret | None = None,
    ) -> ChangeResult:
        """Step 2: send the value at :meth:`hash_version`'s version, with the
        policy off in the same statement (``02-mssql-privileges.md`` §6.2).

        The password never reaches the server: the value is computed here. A
        message the server answers with keeps no value (:func:`scrub_value`).
        SQL Server keeps one password per login, so any ``old_password`` but
        :data:`~sopuli.driver.protocol.OLD_DISCARD` is refused by capability.
        """
        if old_password != OLD_DISCARD:
            self.require_rollover(account)
        self._require_linux("set a password")
        require_read_write(
            self.scope(), target=self.target.name, hint="a password change is a write to master"
        )
        statement = statements.set_password_value(
            account, password_value(secret, self.hash_version())
        )
        with self._cursor() as cursor:
            try:
                cursor.execute(statement)
            except pyodbc.Error as error:
                failure = from_error(error, scrub=scrub_value).as_error()
                failure.password_sent = True
                raise failure from None
        LOG.debug("%s: set the password value of %s", self.target.name, account)
        return ChangeResult(changed=True)

    def restore_policy(self, account: str, flags: PolicyFlags) -> bool:
        """Step 4: set ``CHECK_POLICY`` and ``CHECK_EXPIRATION`` back to
        ``flags``, and say whether a statement was sent. Where both were off,
        step 2 changed neither, and nothing is sent."""
        if not flags.check_policy and not flags.check_expiration:
            return False
        require_read_write(
            self.scope(),
            target=self.target.name,
            hint="setting the flags back is a write to master",
        )
        statement = statements.restore_policy(
            account, policy=flags.check_policy, expiration=flags.check_expiration
        )
        self._read(lambda cursor: cursor.execute(statement))
        LOG.debug("%s: set the policy flags of %s back", self.target.name, account)
        return True

    def suspend_account(self, account: str) -> NoReturn:
        self._not_written("suspend a login")

    def reset_password(self, *args: Any, **kwargs: Any) -> NoReturn:
        self._not_written("reset a password")

    def expire_password(self, account: str) -> NoReturn:
        self._not_written("expire a password")

    def audit_coverage(self, account: str) -> AuditCoverage:
        """Never raises, as the protocol promises: the answer is unknown."""
        return AuditCoverage(
            audited=None, detail="the SQL Server driver does not read audit settings yet"
        )

    def apply_attributes(self, *args: Any, **kwargs: Any) -> NoReturn:
        self._not_written("apply login attributes")

    def resolve_profile(self, profile: str) -> NoReturn:
        self._not_written("resolve a profile")

    def resolve_role(self, role: str) -> NoReturn:
        """Refused as ``role_lookup`` missing: a personal rule's `role:` is
        UC-2's, which is not written for SQL Server yet (#1554). `report
        accounts` then shows the role's members as undeclared and warns with
        `SOPULI-W075`, rather than failing the target (UC-5 §4)."""
        raise UnsupportedCapabilityError(
            ROLE_LOOKUP,
            target=self.target.name,
            hint=(
                "a personal_accounts: rule's role: is not resolved on SQL Server yet: UC-2 "
                "is not written for it (#1554)"
            ),
            # SOPULI-W075 words its fix from this, not from the hint.
            remedy=(
                "No grant gives it: UC-2, which resolves a role, is not written for SQL "
                "Server yet (#1554)."
            ),
        )

    def accounts_matching(self, *args: Any, **kwargs: Any) -> NoReturn:
        self._not_written("list logins")

    def verify_password(
        self,
        account: str,
        secret: Secret,
        *,
        method: str = VERIFY_LOGIN,
        lockout_margin: int = 2,
        attempts: int = 1,
        for_check: bool = False,
    ) -> VerifyResult:
        """Log in once as ``account`` with ``secret``, at ``master``, and say
        what that showed (``02-mssql-privileges.md`` §7).

        ``login`` only: the tool login reads no hash, so ``hash`` and ``both``
        are refused by capability. On Linux no login locks (LK2), so
        ``lockout_margin`` and ``attempts`` have nothing to guard; a Windows
        host is refused before any login. The login's state is read first: a
        login that is missing, disabled or locked out (``IsLocked``) is
        :data:`~sopuli.driver.protocol.UNAVAILABLE` with no login, because a
        locked login answers its right password as a wrong one (WP3).
        """
        if method in (VERIFY_HASH, VERIFY_BOTH):
            self.require_verifier(account, secret)
        if method != VERIFY_LOGIN:
            raise UnsupportedCapabilityError(
                f"verification method {method!r}",
                target=self.target.name,
                hint="this driver verifies by `login` only",
            )
        self._require_linux("log in as a login")
        login = self.describe_user(account)
        if login is None:
            return _not_tried(f'there is no login "{account}" on this target')
        if login.locked:
            return _not_tried(f"the login is {login.status}; no login was attempted")
        text = connection_string(
            self.target,
            Credential(username=login.name, secret=secret),
            correlation_id=self.correlation_id,
        )
        started = time.monotonic()
        try:
            connection = pyodbc.connect(text, autocommit=True, timeout=self.timeouts.connect_s)
        except pyodbc.Error as error:
            failure = from_error(error, connecting=True)
            LOG.debug("login as %s failed with %s", login.name, failure.code)
            if failure.code == WRONG_PASSWORD:
                return VerifyResult(
                    method=VERIFY_LOGIN,
                    result=FAIL,
                    latency_ms=_ms(started),
                    detail="the server refused the password (18456)",
                )
            if failure.code in (LOGIN_DISABLED, MUST_CHANGE):
                return VerifyResult(
                    method=VERIFY_LOGIN,
                    result=UNAVAILABLE,
                    latency_ms=_ms(started),
                    detail=f"{failure.message}: this says nothing about the password",
                )
            raise failure.as_error() from None
        latency = _ms(started)
        # The login has answered. A socket that drops as it closes does not
        # change the answer.
        with suppress(pyodbc.Error):
            connection.close()
        LOG.debug("login as %s: pass", login.name)
        return VerifyResult(method=VERIFY_LOGIN, result=PASS, latency_ms=latency)

    def require_verifier(self, account: str, secret: Secret) -> None:
        """Refuse ``hash`` and ``both`` at plan time (invariant 4): the tool
        login reads ``NULL`` for every hash (§2.1)."""
        require_capability(
            self.scope(),
            OFFLINE_VERIFY,
            target=self.target.name,
            hint="the tool login reads no password hash; use --method login, the default",
        )

    def require_rollover(self, account: str) -> None:
        """SQL Server keeps one password per login, so this always refuses
        (invariant 4)."""
        require_capability(
            self.scope(),
            PASSWORD_ROLLOVER,
            target=self.target.name,
            hint=(
                "SQL Server keeps one password per login, so there is no window to open: "
                "use --strategy staged, or leave --strategy out"
            ),
        )

    def finish_rollover(self, account: str, *, current: Secret | None = None) -> ChangeResult:
        """A login never has a window, so there is none to end (invariant 4)."""
        self.require_rollover(account)
        raise UnsupportedCapabilityError(PASSWORD_ROLLOVER, target=self.target.name)

    def _read(self, reader: Callable[[Any], T]) -> T:
        """Run ``reader`` on a cursor of this session. A closed session is a
        fault in sopuli, and a pyodbc error is classified by
        :mod:`~sopuli.driver.mssql.errors`."""
        with self._cursor() as cursor:
            try:
                return reader(cursor)
            except pyodbc.Error as error:
                raise from_error(error).as_error() from error

    @contextmanager
    def _cursor(self) -> Iterator[Any]:
        """A cursor of this session, closed after. A closed session is a
        fault in sopuli."""
        if self.connection is None:
            raise DriverError(
                f'the session to target "{self.target.name}" is closed',
                hint="this is a fault in sopuli: a closed session was used again",
            )
        cursor = self.connection.cursor()
        try:
            yield cursor
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
        return MssqlSession(
            connection=connection,
            target=target,
            correlation_id=self.correlation_id,
            timeouts=self.timeouts,
        )


def build_driver(context: DriverContext) -> MssqlDriver:
    """The registry's way in: a :class:`MssqlDriver` for this run."""
    return MssqlDriver(correlation_id=context.correlation_id, timeouts=context.timeouts)


def client_report(*, env: Mapping[str, str], runtime: Runtime) -> dict[str, Any]:
    """`doctor`'s client lines: pyodbc's release, and whether the ODBC driver
    manager lists ODBC Driver 18. Neither argument is read."""
    return client_lines(pyodbc_version=pyodbc.version, drivers=pyodbc.drivers())
