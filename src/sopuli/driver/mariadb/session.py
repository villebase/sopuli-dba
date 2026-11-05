"""Connecting to a MariaDB server, and reporting what it is.

The module :data:`sopuli.driver.registry.DRIVERS` imports for ``type: mariadb``.
It imports ``pymysql`` at module scope, so a machine without the ``mariadb``
extra gets ``SOPULI-20002`` from the registry rather than a traceback (ADR-006
rule 1). The modules beside it are tier 0.

**What this build does** (#1268). It connects through
:mod:`sopuli.driver.mysql_family`, labels the session with the run's
correlation id, checks that a mode which requires TLS got it, and reports the
scope: ``server``, whether it takes writes, its encryption, and
``role_lookup``. For ``doctor
--check-privileges`` it audits the tool account's grants
(:mod:`~sopuli.driver.mariadb.privileges`) and surveys the declared accounts
(:mod:`~sopuli.driver.mariadb.accounts`). It describes a declared account,
with the privileges guardrail 9 checks and the roles it holds, sets its password
by the value its plugin stores and verifies it by login (#1270). It resolves a
role and lists its members, suspends an account, resets its password and
expires it (#1272). Every other method
refuses with
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
from sopuli.driver.mariadb import password as password_module
from sopuli.driver.mariadb import roles, verification
from sopuli.driver.mariadb.errors import from_error
from sopuli.driver.mariadb.limits import LIMIT
from sopuli.driver.mariadb.privileges import audit as privilege_audit
from sopuli.driver.mariadb.scope import observe, require_read_write
from sopuli.driver.mysql_family import account_statements
from sopuli.driver.mysql_family.accounts import Principal, current_user, split
from sopuli.driver.mysql_family.client import client_lines
from sopuli.driver.mysql_family.connection import connect_arguments, require_tls
from sopuli.driver.mysql_family.encryption import read_encryption
from sopuli.driver.mysql_family.errors import COLUMN_ACCESS_DENIED, TABLE_ACCESS_DENIED
from sopuli.driver.protocol import (
    ACCOUNT_LOCK,
    EXPIRE_PASSWORD,
    KEEP_ROLLOVER,
    KEPT_WINDOW_UNREADABLE_MARIADB,
    OFFLINE_VERIFY,
    OLD_DISCARD,
    OLD_PASSWORD_MODES,
    PASSWORD_EXPIRE,
    PASSWORD_SET,
    PROFILE_MANAGEMENT,
    ROLE_LOOKUP,
    UNAVAILABLE,
    VERIFY_BOTH,
    VERIFY_HASH,
    VERIFY_LOGIN,
    AccountChange,
    ChangeResult,
    ClosesConnection,
    Credential,
    DriverContext,
    DriverError,
    Encryption,
    PrivilegeAudit,
    Scope,
    Timeouts,
    UnsupportedCapabilityError,
    UserState,
    VerifyResult,
    require_capability,
)
from sopuli.driver.registry import NotWrittenError
from sopuli.output.debug import logger
from sopuli.passwords import ByteLimit
from sopuli.secrets import Secret

LOG = logger("mariadb")

#: The hint for a `profile:` rule on a MariaDB server.
NO_PROFILES = (
    "MariaDB has no profiles; declare these accounts by name with `accounts:`, "
    "or by a role they hold with `role:`"
)

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
    :class:`~sopuli.driver.protocol.Session` methods `doctor` uses, and those
    the module docstring names; every other one refuses with
    ``SOPULI-20006``."""

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
            observed = self._read(
                lambda cursor: observe(cursor, target=self.target.name, encryption=self.encryption)
            )
            # `role_lookup` always: a role is a row of the view, and its grants
            # are in mysql.roles_mapping, and §2.1 grants the tool account both.
            # `expire_password` always: an account with only CREATE USER
            # expires another on every supported release (10.11.19 to 12.3.3,
            # `04_lock_expiry_probe.py`, LK3), and a new value sent alone ends
            # an expiry (`11_rollover_expiry_probe.py`). The capability also
            # tells `creds apply` it may set a password on an expired account,
            # as on MySQL (`apply.py`, `expiry_cleared`).
            self._scope = replace(
                observed, capabilities=observed.capabilities | {ROLE_LOOKUP, EXPIRE_PASSWORD}
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
                "the MariaDB driver connects, reports the server for `doctor`, "
                "describes an account, sets its password and verifies it by login, "
                "resolves a role, and suspends, resets and expires an account; the rest "
                "of it is not written yet (#1270, #1271)"
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
        state = accounts_module.describe(
            cursor, account, target=self.target.name, session_user=self._session_user
        )
        if state is None:
            return None
        # A `role:` rule admits by these (`sopuli.personal.admits`), and
        # `accounts_matching` lists by the same grants the other way.
        user, host = split(state.name)
        return replace(state, roles=frozenset(roles.granted(cursor, Principal(user, host))))

    def _read_grants(self, reader: Callable[[Any], T]) -> T:
        """:meth:`_read`, with the hint about §2.1's grants on a refused read."""
        try:
            return self._read(reader)
        except DriverError as error:
            if error.code in REFUSED_READ:
                error.hint = MISSING_GRANT_HINT
            raise

    def byte_limit(self) -> ByteLimit:
        """1024 bytes of UTF-8, whatever the server: the server sees only the
        value, and the limit is for the application's client
        (:mod:`~sopuli.driver.mariadb.limits`)."""
        return LIMIT

    def password_constraints(self, account: str) -> None:
        """Nothing beyond the length, read without a round trip. Not on the
        protocol: ``creds generate`` asks it of a driver that has it.

        MariaDB has no profiles, and an account's reuse history is not read.
        Whether a password check plugin refuses the value the driver sends is
        not measured yet (#1310)."""

    def set_password(
        self, account: str, secret: Secret, *, old_password: str = OLD_DISCARD
    ) -> ChangeResult:
        """``ALTER USER … IDENTIFIED VIA <plugin> USING '<value>'``, with the
        value for the account's own plugin computed here (invariant 15,
        :mod:`~sopuli.driver.mariadb.password`).

        Only ``discard``: the statement names one method, which replaces every
        method the account had (``03_dual_password_probe.py``, DP3). That ends
        a second password a rollover kept, so only the vault's password logs
        in. It also ends a second method of another kind, such as
        ``unix_socket``, which the view does not show. That gap is open, and
        no verb that calls this is registered. TODO(#1301): register them once
        the gap is decided. ``retain`` and ``keep`` are a rollover, which is
        #1271.

        As on the other drivers, ``changed`` is ``True`` whenever the statement
        succeeded: the command decides first whether the account already had
        this password.

        Refused before anything is sent, with ``password_sent`` left ``False``:
        a password the target cannot take, a read-only session, an account that
        does not exist, and one on another plugin. Once the statement is handed
        to the server, a failure has ``password_sent`` set. What crossed is the
        value, which still allows an offline guess.
        """
        if old_password not in OLD_PASSWORD_MODES:
            raise ValueError(f"not an old-password mode: {old_password!r}")
        if old_password != OLD_DISCARD:
            self._not_written("keep a rollover window")
        password_module.admit(secret)
        require_read_write(self.scope(), target=self.target.name)
        found = self._existing(
            account,
            hint=(
                "the tool does not create accounts (Q8); `creds check` reports this "
                "as ACCOUNT_MISSING rather than failing"
            ),
        )
        statement = password_module.alter_user(found.user, found.host, found.plugin, secret)
        try:
            # The read above found the session open, so a failure here is the
            # server's answer to the statement.
            self._read(lambda cursor: cursor.execute(statement), scrub=password_module.scrub)
        except DriverError as failure:
            failure.password_sent = True
            raise
        LOG.debug("password set for %s on %s", found.name, self.target.name)
        return ChangeResult(changed=True, detail="password set", discarded=True)

    def suspend_account(self, account: str) -> AccountChange:
        """``ALTER USER … ACCOUNT LOCK``, sent every time (#1267, decision 2).

        The lock is only in ``mysql.global_priv``, which the tool account does
        not read, so whether the account is already locked cannot be read. A
        second ``ACCOUNT LOCK`` is accepted (``04_lock_expiry_probe.py``, LK1),
        so the statement is sent and the change reported as ``changed: true``
        on every run: an exception to invariant 9, as CLAUDE.md records.
        ``CREATE USER`` is enough. Refused before anything is sent where the
        account does not exist or uses another plugin.
        """
        require_read_write(self.scope(), target=self.target.name)
        found = self._existing(account, what="suspended")
        status = accounts_module.state_of(found).status
        self._read(lambda cursor: cursor.execute(account_statements.lock(found.user, found.host)))
        LOG.debug("ACCOUNT LOCK for %s on %s", found.name, self.target.name)
        return AccountChange(
            ACCOUNT_LOCK,
            changed=True,
            status=status,
            detail=(
                "sent ACCOUNT LOCK; whether the account was already locked cannot be read "
                "on MariaDB"
            ),
        )

    def _existing(
        self, account: str, *, what: str = "changed", hint: str | None = None
    ) -> accounts_module.Account:
        """The account's row in the view, refused before anything is sent where
        it does not exist or uses another plugin. ``what`` is the verb's
        participle for the hint, and ``hint`` replaces the hint whole."""
        found = self._read_grants(
            lambda cursor: accounts_module.read_one(cursor, account, target=self.target.name)
        )
        if found is None:
            raise DriverError(
                f'account "{account}" does not exist on target "{self.target.name}"',
                hint=hint
                or (
                    f"the tool does not create accounts (Q8); nothing is {what}, and the "
                    "account name is worth checking against the server"
                ),
            )
        return found

    def reset_password(
        self, account: str, secret: Secret, *, expire: bool, keep_rollover: bool = False
    ) -> tuple[AccountChange, ...]:
        """UC-2 §4.1 on a MariaDB server: one statement, the value for the
        account's own plugin with ``PASSWORD EXPIRE`` where ``expire``
        (invariant 15, :func:`~sopuli.driver.mariadb.password.alter_user`).

        The value names one method, which replaces every method the account
        had (``03_dual_password_probe.py``, DP3), and ends an expiry
        (``11_rollover_expiry_probe.py``). So no second password logs in
        afterwards, whether a rollover's or one added by hand with ``OR``. A
        second method the view does not show, such as ``unix_socket``, stops
        working too: that gap is accepted (``02-mariadb-privileges.md`` §4,
        #1301), and ``doctor --check-privileges`` says so.

        **The lock is left as it is** (#1272, decision 1). It is not read, so
        the reset cannot tell a suspension from a block after failed logins,
        and an ``ACCOUNT UNLOCK`` could end a suspension (H4). A locked or
        blocked account keeps its new password and stays locked; the row says
        so.

        **Refused before anything is sent:** ``keep_rollover``, by capability,
        a password the server cannot take, a read-only session, an account
        that does not exist, and one on another plugin. A failure of the
        statement has ``password_sent`` set: what crossed is the value, which
        still allows an offline guess.
        """
        if keep_rollover:
            # The command refuses it at plan time; this is the driver's own line.
            raise UnsupportedCapabilityError(
                KEEP_ROLLOVER, target=self.target.name, hint=KEPT_WINDOW_UNREADABLE_MARIADB
            )
        password_module.admit(secret)
        require_read_write(self.scope(), target=self.target.name)
        found = self._existing(account, what="reset")
        status = accounts_module.state_of(found).status
        statement = password_module.alter_user(
            found.user, found.host, found.plugin, secret, expire=expire
        )
        try:
            self._read(lambda cursor: cursor.execute(statement), scrub=password_module.scrub)
        except DriverError as failure:
            failure.password_sent = True
            raise
        LOG.debug("password reset for %s on %s", found.name, self.target.name)
        return (
            AccountChange(
                PASSWORD_SET,
                changed=True,
                status=status,
                detail=(
                    f"{'password set, expired' if expire else 'password set'}, as the only "
                    "login method. Whether the account is locked cannot be read on MariaDB, "
                    "and a reset does not unlock it"
                ),
            ),
        )

    def expire_password(self, account: str) -> tuple[AccountChange, ...]:
        """``PASSWORD EXPIRE`` alone, where ``password_expired`` is ``N``;
        nothing where it is ``Y`` (#1272).

        **Keyed on the view's ``password_expired``** (invariant 9). Only
        ``PASSWORD EXPIRE`` sets it (``04_lock_expiry_probe.py``, LK3), so a
        second run reports ``changed: false``.

        **No vault value is read.** ``PASSWORD EXPIRE`` does not end a second
        method joined by ``OR``: both passwords keep logging in, expired
        (``11_rollover_expiry_probe.py``). The tool makes no rollover on a
        personal account, because a name cannot be declared twice, so only an
        ``OR`` added by hand survives this, with both its passwords expired
        (UC-2, decided on #1272). ``CREATE USER`` is enough (LK1 to LK3).
        """
        require_read_write(self.scope(), target=self.target.name)
        found = self._existing(account, what="expired")
        status = accounts_module.state_of(found).status
        if found.expired:
            return (
                AccountChange(
                    PASSWORD_EXPIRE,
                    changed=False,
                    status=status,
                    detail="the password is already expired",
                ),
            )
        statement = account_statements.expire(found.user, found.host)
        self._read(lambda cursor: cursor.execute(statement))
        LOG.debug("PASSWORD EXPIRE for %s on %s", found.name, self.target.name)
        return (
            AccountChange(
                PASSWORD_EXPIRE,
                changed=True,
                status=status,
                detail="password expired",
            ),
        )

    def audit_coverage(self, account: str) -> NoReturn:
        self._not_written("read audit coverage")

    def apply_attributes(self, *args: Any, **kwargs: Any) -> NoReturn:
        self._not_written("apply account attributes")

    def resolve_profile(self, profile: str) -> str | None:
        """Refused by capability: MariaDB has no profiles, so a `profile:` rule
        names nothing on a server."""
        require_capability(
            self.scope(), PROFILE_MANAGEMENT, target=self.target.name, hint=NO_PROFILES
        )
        return None  # pragma: no cover -- the capability is never reported

    def resolve_role(self, role: str) -> str | None:
        """The role as the view spells it, or ``None``
        (:func:`~sopuli.driver.mariadb.roles.resolve`). A role ``PUBLIC``
        reaches is refused with exit 9."""
        require_capability(self.scope(), ROLE_LOOKUP, target=self.target.name)
        return self._read_grants(
            lambda cursor: roles.resolve(cursor, role, target=self.target.name)
        )

    def accounts_matching(
        self, *, profile: str | None = None, role: str | None = None
    ) -> tuple[str, ...]:
        """Every account that holds ``role``, through any chain of grants
        (:func:`~sopuli.driver.mariadb.roles.members_of`). The account that
        created the role holds it too. A ``profile`` is refused as
        :meth:`resolve_profile` refuses it."""
        if (profile is None) == (role is None):
            raise ValueError("accounts_matching takes exactly one of `profile` and `role`")
        if profile is not None:
            self.resolve_profile(profile)
            return ()  # pragma: no cover -- resolve_profile always raises
        assert role is not None
        spelled = self.resolve_role(role)
        if spelled is None:
            return ()
        return self._read_grants(lambda cursor: roles.members_of(cursor, spelled))

    def verify_password(
        self,
        account: str,
        secret: Secret,
        *,
        method: str = VERIFY_LOGIN,
        lockout_margin: int = 2,
        attempts: int = 1,
    ) -> VerifyResult:
        """Log in once as ``account`` with ``secret``, and say what that showed
        (:mod:`~sopuli.driver.mariadb.verification`).

        ``login`` only: ``hash`` and ``both`` need ``offline_verify``, which
        this driver never reports, because the value is in
        ``mysql.global_priv``, which the tool account does not read.
        :meth:`require_verifier` refuses them at plan time, and this refuses
        them again.

        A login passes only where ``CURRENT_USER()`` is the declared account
        (#1267, decision 8). An answer that comes before it can be read counts
        only where no other account can answer the login
        (:func:`~sopuli.driver.mariadb.verification.competitor`). An account
        that does not exist is :data:`~sopuli.driver.protocol.UNAVAILABLE`
        without a login. The tool cannot read MariaDB's count of failed logins,
        so ``lockout_margin`` and ``attempts`` have nothing to guard, and the
        detail says so.
        """
        if method in (VERIFY_HASH, VERIFY_BOTH):
            self.require_verifier(account, secret)
        if method != VERIFY_LOGIN:
            raise UnsupportedCapabilityError(
                f"verification method {method!r}",
                target=self.target.name,
                hint="this driver verifies by `login` only",
            )
        user, host = split(account)
        # One read: the user's accounts at every host, and the anonymous ones,
        # which compete for the same login.
        found = self._read_grants(lambda cursor: accounts_module.read(cursor, [user, ""]))
        declared = accounts_module.find(found[user], host)
        if declared is None:
            return VerifyResult(
                method=VERIFY_LOGIN,
                result=UNAVAILABLE,
                detail=f'there is no account "{account}" on this target',
            )
        if declared.plugin not in accounts_module.SUPPORTED_PLUGINS:
            # As `describe_user` refuses it: the tool manages no other plugin.
            raise accounts_module.OtherPluginError(
                declared.name, declared.plugin, target=self.target.name
            )
        return verification.login(
            self.target,
            declared,
            secret,
            competing=verification.competitor(declared, found[user], found[""]),
            correlation_id=self.correlation_id,
            timeouts=self.timeouts,
        )

    def require_verifier(self, account: str, secret: Secret) -> None:
        """Refuse ``hash`` and ``both`` at plan time (invariant 4): this driver
        never reports ``offline_verify``."""
        require_capability(
            self.scope(),
            OFFLINE_VERIFY,
            target=self.target.name,
            hint=(
                "the value is in mysql.global_priv, which the tool account does not read; "
                "use --method login, the default"
            ),
        )

    def require_rollover(self, account: str) -> NoReturn:
        self._not_written("keep a rollover window")

    def finish_rollover(self, account: str) -> NoReturn:
        self._not_written("finish a rollover")

    def _read(self, reader: Callable[[Any], T], *, scrub: Callable[[str], str] | None = None) -> T:
        """Run ``reader`` on a cursor of this session. A closed session is a
        fault in sopuli, and a MariaDB error is classified by
        :mod:`~sopuli.driver.mariadb.errors`.

        With ``scrub``, the message passes through it, and the error is raised
        without PyMySQL's as its cause: that one keeps the message as the
        server sent it, and a traceback or a log with ``exc_info`` would print
        it."""
        if self.connection is None:
            raise DriverError(
                f'the session to target "{self.target.name}" is closed',
                hint="this is a fault in sopuli: a closed session was used again",
            )
        try:
            with self.connection.cursor() as cursor:
                return reader(cursor)
        except pymysql.err.MySQLError as error:
            if scrub is None:
                raise from_error(error).as_error() from error
            raise from_error(error, scrub=scrub).as_error() from None


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
