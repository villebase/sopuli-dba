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

It changes a password for `creds apply` and `creds rotate`, in
``02-mssql-privileges.md`` §6.2's order: the command records the login's
flags (:meth:`MssqlSession.policy_flags`), :meth:`MssqlSession.set_password`
sends the value with the policy off, :meth:`MssqlSession.verify_password`
logs in as the login, and :meth:`MssqlSession.restore_policy` sets the flags
back. On Linux `apply` logs in before a change; on Windows, and on a host
that names no platform, it does not
(:attr:`MssqlSession.verifies_before_change`). Every method not written yet
refuses with ``SOPULI-20006``.

**pyodbc's pooling is off for the process.** A pooled connection is kept open
after ``close()``, and the next ``connect()`` with the same string reuses it
without logging in again. A run that changes a password and then logs in to
check it must log in for real.
"""

from __future__ import annotations

import logging
import re
import time
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager, suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime
from functools import partial
from typing import Any, ClassVar, NoReturn, TypeVar

import pyodbc

from sopuli.config.model import ExpandedTarget, Runtime
from sopuli.config.targets import MSSQL_STRICT
from sopuli.driver.grants import COLUMN, OBJECT, SCHEMA, GrantRow, GrantSurvey, RoleGrant
from sopuli.driver.mssql import (
    accounts,
    capabilities,
    db_grants,
    groups,
    server_grants,
    statements,
    survey,
)
from sopuli.driver.mssql import errors as server_errors
from sopuli.driver.mssql import privileges as tool_login
from sopuli.driver.mssql.admin import (
    MISSING_GRANT,
    PUBLIC,
    Assessment,
    Catalog,
    Principal,
    assess,
    read_catalog,
)
from sopuli.driver.mssql.client import client_lines
from sopuli.driver.mssql.connection import connection_string
from sopuli.driver.mssql.errors import (
    CAPABILITY,
    DATABASE_DENIED,
    STRICT_ENCRYPTION,
    STRICT_REMEDY,
    from_error,
    raw_message,
    records,
    server_error,
)
from sopuli.driver.mssql.limits import LIMIT
from sopuli.driver.mssql.password import MustChange, password_value
from sopuli.driver.mssql.scope import observe
from sopuli.driver.protocol import (
    ACCOUNT_LOCK,
    ACCOUNT_UNLOCK,
    EXPIRE_PASSWORD,
    FAIL,
    MUST_CHANGE_PENDING,
    OFFLINE_VERIFY,
    OLD_DISCARD,
    PASS,
    PASSWORD_ROLLOVER,
    PASSWORD_SET,
    PROFILE_MANAGEMENT,
    ROLE_LOOKUP,
    ROLLOVER_FINISH,
    UNAVAILABLE,
    VERIFY_BOTH,
    VERIFY_HASH,
    VERIFY_LOGIN,
    AccountChange,
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
from sopuli.driver.registry import NotWrittenError, no_profiles_hint
from sopuli.driver.survey import SurveyedAccount
from sopuli.exit_codes import ExitCode
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


#: The server's answers to a login, by number (§7). ``18470`` (disabled) and
#: ``18488`` (must change) are answered only to the right password: a wrong
#: one is ``18456`` either way (``15_login_answers_probe.py``, LA2 to LA4).
#: As :class:`~sopuli.driver.mssql.errors.Diagnosis` codes, which are text,
#: from the error module's numbers, so the two cannot drift apart.
WRONG_PASSWORD = str(server_errors.LOGIN_FAILED)
LOGIN_DISABLED = str(server_errors.LOGIN_DISABLED)
MUST_CHANGE = str(server_errors.MUST_CHANGE)

#: The capability a `creds check` login needs on the host: a lockout
#: threshold the tool can read, or no lockout at all. Linux has no lockout
#: (LK2); on Windows ``LOGINPROPERTY`` gives no threshold (WP1), so the check
#: is refused there at plan time (#1538, decision 3; #1552).
LOCKOUT_THRESHOLD = "lockout_threshold"

#: Why `account expire-password` is refused on SQL Server, pointing to
#: `account suspend` (#1554).
NO_EXPIRY = (
    "SQL Server takes MUST_CHANGE only with a new password, so it cannot expire the "
    "password a login has; end the account with `account suspend`"
)

#: Why a `profile:` predicate is refused on SQL Server, which has no
#: profiles (#1554): the registry's, so `account list`'s refusal with no
#: connection says the same (#1598).
NO_PROFILES = no_profiles_hint("mssql")

#: How a SQL Server target gets ``role_lookup``: the grant that lets the tool
#: login see user-defined server roles and nested membership (PA2), which
#: `SOPULI-W075` words its fix from (#1554, Q6).
ROLE_LOOKUP_REMEDY = (
    "GRANT VIEW ANY DEFINITION to the tool login, and revoke any DENY of "
    "VIEW ANY SECURITY DEFINITION or VIEW DEFINITION (02-mssql-privileges.md §2.2)"
)


class PublicServerRoleError(DriverError):
    """A `role:` rule names ``public``, which every login holds (#1554, Q6).

    ``config`` and exit 9, as MySQL's mandatory role is: the fix is in the
    config, and running again changes nothing."""

    category = "config"
    exit_code = ExitCode.CONFIG_INVALID

    def __init__(self, *, target: str) -> None:
        super().__init__(
            f'target "{target}": every login holds the server role public, so a `role:` '
            "rule naming it would admit every login",
            hint=(
                "name a role that only the people the rule is for hold, or list the logins "
                "under `accounts:`"
            ),
        )


#: The host platform this build changes passwords on.
LINUX = "Linux"


class MustChangeError(DriverError):
    """A login whose ``MUST_CHANGE`` is pending: the server refuses to turn its
    policy off, ``15128``, so it cannot take a value (§6.2). Refused before
    anything is written or sent."""

    about_account = True

    def __init__(self, account: str, *, target: str, hint: str | None = None) -> None:
        super().__init__(
            f'login "{account}" on target "{target}" must change its password at its next '
            "login, so it cannot take a value the tool computes",
            # The one text `creds generate` and `apply` give for it too (#1594).
            hint=hint or MUST_CHANGE_PENDING,
        )


#: Why an unseen reset refuses a login whose ``MUST_CHANGE`` is pending, and
#: what works instead (#1554, decision 2).
UNSEEN_MUST_CHANGE = (
    "the server refuses CHECK_POLICY = OFF while MUST_CHANGE is pending, so the unseen "
    "reset cannot send its value. The seen reset, `delivery.method: manual`, keeps the "
    "policy on and works on such a login (02-mssql-privileges.md section 6.3)"
)


def _not_tried(detail: str) -> VerifyResult:
    """A login :meth:`MssqlSession.verify_password` settled without trying."""
    return VerifyResult(method=VERIFY_LOGIN, result=UNAVAILABLE, detail=detail)


def _ms(started: float) -> int:
    return int((time.monotonic() - started) * 1000)


def _grant_survey(
    server: server_grants.ServerGrants,
    roles: Sequence[RoleGrant],
    rows: Sequence[GrantRow],
    unreadable: Sequence[str],
    *,
    read: int,
    group_users: bool,
) -> GrantSurvey:
    """The server level and the databases' rows as one survey. A part is
    ``None`` where its rows could not be read at all: *system* and the
    server's *objects* without a complete server read, and *schemas*,
    *columns* and the databases' *objects* where no database was ``read``,
    never an empty list in their place. ``group_users`` is whether a database
    read has a Windows or Entra group user."""
    databases_read = read > 0
    objects: tuple[GrantRow, ...] | None = None
    if server.objects is not None and databases_read:
        objects = (*server.objects, *(row for row in rows if row.kind == OBJECT))
    return GrantSurvey(
        roles=tuple(roles),
        system=server.system,
        objects=objects,
        columns=tuple(row for row in rows if row.kind == COLUMN) if databases_read else None,
        schemas=tuple(row for row in rows if row.kind == SCHEMA) if databases_read else None,
        unreadable=tuple(unreadable),
        # A Windows or Entra login on a server with a group login, or a
        # database with a group user: that login alone is not checked
        # (#1555, Q5).
        account_unreadable=server.gaps(database_groups=group_users),
    )


def _no_login(account: str, *, target: str) -> DriverError:
    """The refusal of a verb that changes a login the name finds no row for,
    made before anything is sent. The command decides on a missing account
    before it calls, so this is the guard if it did not."""
    return DriverError(
        f'there is no login "{account}" on target "{target}"',
        hint="create the login, or check the account's name in the config",
    )


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
    #: The logins, upper-cased, that :meth:`set_password` sent a value to
    #: with the policy off, until :meth:`restore_policy` sets it back: the
    #: only ones :meth:`verify_password` logs in as on a host that is not
    #: Linux. A login whose flags were both off stays here, because the
    #: command has nothing to set back: its policy stays off, and a login as
    #: it counts toward no lockout.
    _policy_off: set[str] = field(default_factory=set, init=False, repr=False)

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
        return assess(principal_id, self._server_catalog())

    def _server_catalog(self) -> Catalog:
        """The server's principals and memberships as the tool login reads
        them, read once per session (:func:`~.admin.read_catalog`). Guardrail
        9 and a `role:` rule read the same one."""
        self.scope()
        if self._catalog is None:
            self._catalog = self._read(read_catalog)
            LOG.debug(
                "%s guardrail catalog: %s",
                self.target.name,
                self._catalog.unread or "complete",
            )
        return self._catalog

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
                "the SQL Server driver serves `doctor`, the `creds` commands, the reports, "
                "`account list` and `account suspend`; this is not written yet (#1554)"
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
        catalog = self._server_catalog()
        assessment = assess(login.principal_id, catalog)
        return accounts.state_of(
            login,
            now=datetime.now(UTC),
            admin_unread=assessment.unread,
            global_privileges=assessment.grants,
            # The server roles it holds, through nesting, which a `role:`
            # rule is compared with (#1554, Q6). None where the read is not
            # complete: a verb's plan-time question about each `role:` rule
            # has already refused it then, as `role_lookup` missing
            # (`cli._refuse_mandatory_roles`).
            roles=catalog.roles_of(login.principal_id) if catalog.complete else frozenset(),
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

    def survey_privileges(self, accounts: Sequence[str], *, public: bool) -> GrantSurvey:
        """Every privilege ``accounts`` hold, one row per path, for `report
        privileges` (:class:`~sopuli.driver.grants.PrivilegeSurvey`).

        The server level first (:mod:`~sopuli.driver.mssql.server_grants`).
        Where it was not read completely, no database is read, because no
        login's user can be followed. Otherwise each online database is read
        on its own (:mod:`~sopuli.driver.mssql.db_grants`). One that refuses
        the tool login, ``916``, is named as not checked with the grants that
        open it; one that answers another refusal, ``229``, or one of
        :data:`~sopuli.driver.mssql.db_grants.UNREADABLE_DATABASE`, with the
        server's message; one whose read names a principal it has no row
        for, with :data:`~sopuli.driver.mssql.db_grants.PARTIAL`. Any other
        failure fails the target."""
        self.scope()
        server = self._read(lambda cursor: server_grants.read(cursor, accounts, public=public))
        unreadable = [server.unread] if server.unread else []
        roles = list(server.roles)
        rows: list[GrantRow] = []
        if server.unread is not None:
            unreadable.append(db_grants.SERVER_NOT_READ)
            return _grant_survey(server, roles, rows, unreadable, read=0, group_users=False)
        logins = dict(server.login_sids)
        # The surveyed logins' SIDs: a database with no user for one is read
        # for its principals alone, unless --public asks for its grants.
        sids = frozenset(logins[name] for name in accounts if name in logins)
        refused: list[str] = []
        offline: list[str] = []
        read = 0
        group_users = False
        for database in self._read(db_grants.read_databases):
            if database.state != db_grants.ONLINE:
                offline.append(database.name)
                continue
            try:
                catalog = self._read(
                    partial(
                        db_grants.read_catalog, database=database.name, sids=sids, public=public
                    )
                )
            except DriverError as error:
                if error.code == str(DATABASE_DENIED):
                    refused.append(database.name)
                elif (
                    error.category == "authorization" or error.code in db_grants.UNREADABLE_DATABASE
                ):
                    unreadable.append(db_grants.unreadable_reason(database.name, error.message))
                else:
                    raise
                LOG.debug("%s: %s was not read: %s", self.target.name, database.name, error.code)
                continue
            if not catalog.complete:
                unreadable.append(db_grants.unreadable_reason(database.name, db_grants.PARTIAL))
                continue
            read += 1
            group_users = group_users or catalog.group_users
            found = db_grants.survey(database, catalog, logins, accounts, public=public)
            roles.extend(found.roles)
            rows.extend(found.rows)
        if refused:
            unreadable.append(db_grants.not_read_reason(refused, db_grants.REFUSED))
        if offline:
            unreadable.append(db_grants.not_read_reason(offline, db_grants.NOT_ONLINE))
        return _grant_survey(server, roles, rows, unreadable, read=read, group_users=group_users)

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
        generate`` asks it of a driver that has it. UC-2's seen reset sends the
        password in clear with ``CHECK_POLICY`` on, so the host's policy does
        apply to it, and a password it refuses fails that account during the
        run (§6.3)."""

    @property
    def verifies_before_change(self) -> bool:
        """Whether `creds apply` logs in before a change to see whether one is
        needed (``02-mssql-privileges.md`` §6.2, #1551). On Linux, where no
        login locks (LK2), it does. On Windows a wrong password counts toward
        a threshold the tool cannot read (WP1), so it does not, as on MySQL
        and MariaDB: a password is set only from `pending`, or for a rollback.
        A host that names no platform is treated as Windows."""
        return self.host_platform() == LINUX

    @property
    def change_ends_lockout(self) -> bool:
        """Whether a change goes ahead on a login locked out after failed
        logins, and ends the lockout (§6.2, #1551). On a host that is not
        Linux it does: step 2 sends the value with ``CHECK_POLICY = OFF``,
        which unlocks the login and sets its count to 0, and step 4 turning
        the policy on again keeps it unlocked (WP4). A login a person
        disabled is not locked out, and is not changed. On Linux no login
        locks (LK2)."""
        return not self.verifies_before_change

    #: Whether `creds check` can compare the vault with a login where
    #: `apply` makes none before a change. Read by the command for the
    #: ``SKIPPED`` row's advice. Only a non-Linux host skips, and there a
    #: check's login is refused (:meth:`verify_password`).
    check_compares: ClassVar[bool] = False

    def require_changeable(self, account: str) -> None:
        """Refuse, in the pre-flight, a login whose ``MUST_CHANGE`` is pending
        (:class:`MustChangeError`), before `creds rotate` stages a password
        for it (§6.2). A missing login is the pre-flight's own
        finding, so it passes here."""
        self._changeable_login(account)

    def _changeable_login(
        self, account: str, *, must_change_hint: str | None = None
    ) -> accounts.Login | None:
        """The login's row, or ``None`` where there is none. Raises
        :class:`MustChangeError` where its ``MUST_CHANGE`` is pending, with
        ``must_change_hint`` where the caller has a better one."""
        login = self._read(
            lambda cursor: accounts.read_one(cursor, account, target=self.target.name)
        )
        if login is not None and login.must_change:
            raise MustChangeError(login.name, target=self.target.name, hint=must_change_hint)
        return login

    #: The command records the flags :meth:`policy_flags` reads, before
    #: :meth:`set_password`, and calls :meth:`restore_policy` after the login
    #: (``02-mssql-privileges.md`` §6.2). Read by the command, as
    #: ``verifies_before_change`` is.
    keeps_policy_flags = True

    def policy_flags(self, account: str) -> PolicyFlags:
        """Step 1: the login's ``CHECK_POLICY`` and ``CHECK_EXPIRATION`` as
        they are now, which the command records in the vault before
        :meth:`set_password` turns the policy off.

        Refuses, before anything is written or sent, a login whose
        ``MUST_CHANGE`` is pending (:class:`MustChangeError`), and a server
        whose value version cannot be read (:meth:`hash_version`).
        """
        return self._flags_before_change(account)

    def reset_policy_flags(self, account: str) -> PolicyFlags:
        """:meth:`policy_flags` for UC-2's unseen reset, which the command
        records in the reset record (§6.3). A login whose ``MUST_CHANGE`` is
        pending is refused naming the seen reset, which works on it (#1554,
        decision 2)."""
        return self._flags_before_change(account, must_change_hint=UNSEEN_MUST_CHANGE)

    def _flags_before_change(
        self, account: str, *, must_change_hint: str | None = None
    ) -> PolicyFlags:
        login = self._changeable_login(account, must_change_hint=must_change_hint)
        if login is None:
            raise _no_login(account, target=self.target.name)
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
        self._policy_off.add(account.upper())
        return ChangeResult(changed=True)

    def restore_policy(self, account: str, flags: PolicyFlags) -> bool:
        """Step 4: set ``CHECK_POLICY`` and ``CHECK_EXPIRATION`` back to
        ``flags``, and say whether a statement was sent. Where both were off,
        step 2 changed neither, and nothing is sent."""
        self._policy_off.discard(account.upper())
        if not flags.need_restoring:
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

    def _login_to_change(self, account: str) -> tuple[accounts.Login, str]:
        """The login a verb changes, and its status, read before anything is
        sent. A name with no login is refused (:func:`_no_login`)."""
        login = self._read(
            lambda cursor: accounts.read_one(cursor, account, target=self.target.name)
        )
        if login is None:
            raise _no_login(account, target=self.target.name)
        return login, accounts.login_status(login)

    def suspend_account(self, account: str) -> AccountChange:
        """``ALTER LOGIN … DISABLE``, or report that the login is already
        disabled (#1554, ``02-mssql-privileges.md`` §6.3).

        ``is_disabled`` is the lock a person sets, which a reset refuses (H4).
        A lockout after failed logins (``IsLocked``) is not a suspension, and
        does not count. **The state is read first** (invariant 9), and read
        back after: a login whose ``is_disabled`` does not then read 1 is an
        error, never a suspension reported on trust."""
        require_read_write(
            self.scope(), target=self.target.name, hint="a suspension is a write to master"
        )
        login, status = self._login_to_change(account)
        if login.disabled:
            return AccountChange(
                ACCOUNT_LOCK,
                changed=False,
                status=status,
                detail="the login is already disabled (ALTER LOGIN … DISABLE)",
            )
        self._read(lambda cursor: cursor.execute(statements.disable(login.name)))
        LOG.debug("DISABLE for %s on %s", login.name, self.target.name)
        after = self._read(
            lambda cursor: accounts.read_one(cursor, account, target=self.target.name)
        )
        if after is None or not after.disabled:
            seen = "has no row" if after is None else "does not read is_disabled 1"
            raise DriverError(
                f'login "{login.name}" on target "{self.target.name}" was sent ALTER LOGIN … '
                f"DISABLE, and on the read back it {seen}",
                hint="check the login by hand; nothing else was changed",
            )
        return AccountChange(
            ACCOUNT_LOCK,
            changed=True,
            status=status,
            detail=f"login was {status.lower()}; sent ALTER LOGIN … DISABLE",
        )

    def reset_password(
        self, account: str, secret: Secret, *, expire: bool, keep_rollover: bool = False
    ) -> tuple[AccountChange, ...]:
        """UC-2's reset on SQL Server (``02-mssql-privileges.md`` §6.3; #1554).

        **The seen path** (``expire``) sends one statement, with
        ``MUST_CHANGE``, and ``UNLOCK`` where a lockout is in place (decision
        3). The password goes in clear, the exception to invariant 15 that
        #1538's decision 2 accepts (:class:`~.password.MustChange`).

        **The unseen path** sends the value with the policy off, §6.2's step
        2 (:meth:`set_password`), which also ends a lockout. The command has
        recorded the login's flags (:meth:`policy_flags`) before it calls
        this, and sets them back after (:meth:`restore_policy`). A login whose
        ``MUST_CHANGE`` is pending cannot take a value, and is refused before
        anything is sent, naming the seen reset (decision 2). It makes no
        login with the new password (H4).

        On both paths a disabled login is refused before anything is sent:
        `account suspend` set it, and a reset does not undo that (H4). The
        tool's own login is refused by the guardrails, from
        :meth:`describe_user`, as on every driver. The registry does not list
        `account reset-password` for SQL Server yet, so the command does not
        reach this. SQL Server has no rollover window: ``keep_rollover`` is
        refused by capability, and the third row never sends anything.
        """
        if keep_rollover:
            self.require_rollover(account)
        require_read_write(
            self.scope(), target=self.target.name, hint="a password reset is a write to master"
        )
        login, status = self._login_to_change(account)
        if login.disabled:
            raise DriverError(
                f'login "{login.name}" on target "{self.target.name}" is disabled, and a reset '
                "does not change that",
                hint=(
                    "a disabled login is somebody's decision -- `account suspend`, usually -- "
                    "and handing it a working password would undo it silently. Run ALTER "
                    "LOGIN … ENABLE first if that is what you mean (H4)"
                ),
            )
        if not expire:
            return self._reset_by_value(login, secret, status)
        statement = MustChange(login.name, secret, unlock=login.locked_out)
        with self._cursor() as cursor:
            try:
                statement.send(cursor)
            except pyodbc.Error as error:
                failure = from_error(error, scrub=statement.scrub).as_error()
                failure.password_sent = True
                raise failure from None
        LOG.debug("%s: reset the password of %s, MUST_CHANGE", self.target.name, login.name)
        return (
            AccountChange(
                ACCOUNT_UNLOCK,
                changed=login.locked_out,
                status=status,
                detail=(
                    "the login was locked out after failed logins; sent UNLOCK with the password"
                    if login.locked_out
                    else "the login was not locked out"
                ),
            ),
            AccountChange(
                PASSWORD_SET,
                changed=True,
                status=status,
                detail="password set, MUST_CHANGE, with CHECK_POLICY and CHECK_EXPIRATION on",
            ),
            AccountChange(
                ROLLOVER_FINISH,
                changed=False,
                status=status,
                detail="SQL Server has no rollover window",
            ),
        )

    def _reset_by_value(
        self, login: accounts.Login, secret: Secret, status: str
    ) -> tuple[AccountChange, ...]:
        """The unseen path's change: the value, with the policy off, which
        ends a lockout too (WP4). The command sets the flags back.

        The pending ``MUST_CHANGE`` is refused here as well as in
        :meth:`reset_policy_flags`: this is reached through the protocol's
        :meth:`reset_password`, and a caller that did not read the flags
        first must still not send a value the server refuses, ``15128``."""
        if login.must_change:
            raise MustChangeError(login.name, target=self.target.name, hint=UNSEEN_MUST_CHANGE)
        self.set_password(login.name, secret)
        return (
            AccountChange(
                ACCOUNT_UNLOCK,
                changed=login.locked_out,
                status=status,
                detail=(
                    "the login was locked out after failed logins; turning the policy off ended it"
                    if login.locked_out
                    else "the login was not locked out"
                ),
            ),
            AccountChange(
                PASSWORD_SET,
                changed=True,
                status=status,
                detail="password value set, with CHECK_POLICY = OFF in its statement",
            ),
            AccountChange(
                ROLLOVER_FINISH,
                changed=False,
                status=status,
                detail="SQL Server has no rollover window",
            ),
        )

    def expire_password(self, account: str) -> NoReturn:
        """Refused by capability (#1538, decision 2): ``MUST_CHANGE`` is taken
        only with a new password, so the server cannot expire a password and
        keep it. The command refuses at plan time, because the scope does not
        report ``expire_password``; this is the guard for a caller that did not
        ask."""
        require_capability(self.scope(), EXPIRE_PASSWORD, target=self.target.name, hint=NO_EXPIRY)
        raise AssertionError("unreachable: the scope never reports expire_password")

    def audit_coverage(self, account: str) -> AuditCoverage:
        """Never raises, as the protocol promises: the answer is unknown."""
        return AuditCoverage(
            audited=None, detail="the SQL Server driver does not read audit settings yet"
        )

    def apply_attributes(self, *args: Any, **kwargs: Any) -> NoReturn:
        self._not_written("apply login attributes")

    def resolve_profile(self, profile: str) -> NoReturn:
        """Refused by capability: SQL Server has no profiles, so a `profile:`
        predicate names nothing on an instance, as on PostgreSQL."""
        require_capability(
            self.scope(), PROFILE_MANAGEMENT, target=self.target.name, hint=NO_PROFILES
        )
        raise AssertionError("unreachable: the scope never reports profile_management")

    def resolve_role(self, role: str) -> str | None:
        """The server role ``role`` as the server spells it, or ``None`` where
        there is none (#1554, Q6: a `role:` names a server role).

        Read from the catalog guardrail 9 reads. Without ``VIEW ANY
        DEFINITION`` the tool login cannot see a user-defined server role or
        one role's membership of another (PA2), so a role that matches nobody
        could not be told from one that does not exist: the read is not
        complete, and this is refused as ``role_lookup`` missing, naming the
        grant. `report accounts` then shows the role's members as undeclared
        and warns with `SOPULI-W075` (UC-5 §4)."""
        found = self._one_role(self._role_catalog(), role)
        if found is None:
            return None
        self._refuse_public(found.name)
        return found.name

    def accounts_matching(
        self, *, profile: str | None = None, role: str | None = None
    ) -> tuple[str, ...]:
        """Every login that holds the server role ``role``, through any chain
        of nested server roles, by name (#1554, Q6). A role the server has no
        row for holds nobody. ``profile`` is refused, as
        :meth:`resolve_profile` refuses it: SQL Server has no profiles."""
        if (profile is None) == (role is None):
            raise ValueError("accounts_matching takes exactly one of `profile` and `role`")
        if profile is not None:
            self.resolve_profile(profile)
        catalog = self._role_catalog()
        found = self._one_role(catalog, role or "")
        if found is None:
            return ()
        self._refuse_public(found.name)
        return tuple(member.name for member in catalog.members(found.principal_id))

    def _one_role(self, catalog: Catalog, role: str) -> Principal | None:
        """The one server role ``role`` names by ``upper()``, or ``None``.
        Two in two cases, on a case-sensitive server, are refused: a verb
        compares by ``upper()``, so it would admit the members of both, and
        the listing must admit the same logins."""
        found = catalog.server_roles(role)
        if len(found) > 1:
            raise DriverError(
                f'target "{self.target.name}" has {len(found)} server roles named '
                f"{role!r} in different cases: " + ", ".join(sorted(p.name for p in found)),
                hint="rename one of them, or list the logins under `accounts:`",
            )
        return found[0] if found else None

    def _refuse_public(self, role: str) -> None:
        """Every login holds ``public``, with no membership rows to read, so a
        rule naming it would admit every login: refused, as MySQL refuses a
        mandatory role."""
        if role == PUBLIC:
            raise PublicServerRoleError(target=self.target.name)

    def _role_catalog(self) -> Catalog:
        """:meth:`_server_catalog`, refused as ``role_lookup`` missing where the
        read is not complete."""
        catalog = self._server_catalog()
        if not catalog.complete:
            raise UnsupportedCapabilityError(
                ROLE_LOOKUP,
                target=self.target.name,
                hint=(
                    "a personal_accounts: rule's role: names a server role, and the tool "
                    "login cannot see every server role and which roles each role holds, so "
                    "a role that admits nobody could not be told from one that does not exist"
                ),
                # SOPULI-W075 words its fix from this, not from the hint: the
                # grant where it is missing, else the read's own reason,
                # which says what to do (a DENY to revoke, a read to run again).
                remedy=ROLE_LOOKUP_REMEDY if catalog.unread == MISSING_GRANT else catalog.unread,
            )
        return catalog

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
        ``lockout_margin`` and ``attempts`` have nothing to guard. On Windows,
        and on a host that names no platform, only a login whose policy this
        session turned off in :meth:`set_password` is tried: a change's step
        3, which counts toward no lockout. Every other login there is refused
        before it is made, `creds check`'s among them. The login's state is
        read first: a
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
        platform = self.host_platform()
        if platform != LINUX and account.upper() not in self._policy_off:
            # On Windows a wrong password counts toward a lockout (WP1). Only
            # a login whose policy this session turned off may be tried: a
            # change's step 3 (§6.2). Every other login is refused, so a new
            # caller fails closed. A guard, not unwritten work.
            host = "a Windows host" if platform else "a host that names no platform"
            raise DriverError(
                f'the tool does not log in as "{account}" on target "{self.target.name}", '
                f"{host}, while the login's password policy is on",
                hint=(
                    "there a wrong password counts toward a lockout threshold the tool "
                    "cannot read (02-mssql-privileges.md §6.2); only a change logs in, "
                    "with the policy off"
                ),
            )
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
                # Never a pass: the login cannot use the password, so after a
                # change it must not be promoted, and a check must not call
                # the login in sync. `creds check` reads the state first, so
                # it meets these only where the login was disabled or made to
                # change its password since; they are answered only to the
                # right password (LA2 to LA4), which its detail says.
                # The error module keeps the server's words without their
                # number, so the number is given once here.
                detail = (
                    f"the password is right, but the login was refused ({failure.code}): "
                    f"{failure.message}"
                    if for_check
                    else f"{failure.message}: the login cannot use the password"
                )
                return VerifyResult(
                    method=VERIFY_LOGIN,
                    result=UNAVAILABLE,
                    latency_ms=_ms(started),
                    detail=detail,
                )
            raise failure.as_error() from None
        latency = _ms(started)
        # The login has answered. A socket that drops as it closes does not
        # change the answer.
        with suppress(pyodbc.Error):
            connection.close()
        LOG.debug("login as %s: pass", login.name)
        return VerifyResult(method=VERIFY_LOGIN, result=PASS, latency_ms=latency)

    def require_login_check(self) -> None:
        """Refuse `creds check`'s login at plan time on a host whose lockout
        the tool cannot read (#1538, decision 3; #1552). On Linux no login
        locks (LK2). On Windows a wrong password counts toward a threshold
        ``LOGINPROPERTY`` does not give (WP1), so a check could lock the
        login. A host that names no platform is treated as Windows. The
        command asks before any account is checked (invariant 4)."""
        platform = self.host_platform()
        if platform == LINUX:
            return
        raise UnsupportedCapabilityError(
            LOCKOUT_THRESHOLD,
            target=self.target.name,
            hint=(
                f"the host runs {platform or 'a platform it does not name'}, where a wrong "
                "password counts toward a lockout threshold the tool login cannot read, "
                "so a login check could lock the login (02-mssql-privileges.md §7)"
            ),
        )

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
