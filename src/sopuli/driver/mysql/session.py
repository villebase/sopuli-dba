"""Connecting to a MySQL server, and reporting what it is.

The module :data:`sopuli.driver.registry.DRIVERS` imports for ``type: mysql``.
It imports ``pymysql`` at module scope, so a machine without the ``mysql``
extra gets ``SOPULI-20002`` from the registry rather than a traceback (ADR-006
rule 1). The modules beside it are tier 0.

**What this build does.** It connects, labels the session with the run's
correlation id, checks that a mode which requires TLS got it, and reports the
scope: ``server``, whether it takes writes, and its encryption. It refuses a
tool account that can use ``SYSTEM_USER``, audits the tool account's grants
and the declared accounts for ``doctor --check-privileges``, and describes an
account. For UC-1 it sets a password from a hash computed on the client,
keeps the old one working for `rotate --strategy rollover` until `creds
finish-rollover` discards it, verifies one by login where only the declared
account can answer, and names the server by its ``server_uuid``. For UC-2 it
resolves a `role:` rule (:mod:`~sopuli.driver.mysql.roles`), resets a
password, suspends an account and expires a password. The registry lists
`doctor`, the `creds` commands and every `account` command.
:meth:`MysqlSession.apply_attributes`, which a policy's `account:` block needs,
refuses with ``SOPULI-20006`` without a round trip.
"""

from __future__ import annotations

import logging
import re
import time
from collections.abc import Callable, Mapping
from contextlib import suppress
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from typing import Any, ClassVar, TypeVar

import pymysql

from sopuli.config.model import ExpandedTarget, Runtime
from sopuli.config.products import same_mysql_account
from sopuli.driver.mysql import accounts as accounts_module
from sopuli.driver.mysql import password as password_module
from sopuli.driver.mysql import roles, verification
from sopuli.driver.mysql.errors import UNKNOWN_SYSTEM_VARIABLE, from_error
from sopuli.driver.mysql.limits import LIMIT
from sopuli.driver.mysql.privileges import audit as privilege_audit
from sopuli.driver.mysql.scope import observe, read_encryption, require_read_write
from sopuli.driver.mysql_family.accounts import Principal, split
from sopuli.driver.mysql_family.client import client_lines
from sopuli.driver.mysql_family.connection import TLS_REQUIRED_MODES, connect_arguments
from sopuli.driver.mysql_family.errors import (
    COLUMN_ACCESS_DENIED,
    TABLE_ACCESS_DENIED,
    TLS_CONNECTION_ERROR,
    UNKNOWN_CLIENT_ERROR,
)
from sopuli.driver.protocol import (
    ACCOUNT_LOCK,
    ACCOUNT_UNLOCK,
    ENCRYPTION_TLS,
    EXPIRE_PASSWORD,
    EXPIRY_UNAVAILABLE,
    KEEP_ROLLOVER,
    KEPT_WINDOW_UNREADABLE,
    OFFLINE_VERIFY,
    OLD_DISCARD,
    OLD_PASSWORD_MODES,
    OLD_RETAIN,
    PASS,
    PASSWORD_EXPIRE,
    PASSWORD_ROLLOVER,
    PASSWORD_SET,
    PROFILE_MANAGEMENT,
    ROLE_LOOKUP,
    ROLLOVER_FINISH,
    STORED,
    UNAVAILABLE,
    UNKNOWN,
    VERIFY_BOTH,
    VERIFY_HASH,
    VERIFY_LOGIN,
    VERIFY_NONE,
    AccountAttributes,
    AccountChange,
    AttributeChange,
    AuditCoverage,
    ChangeResult,
    ClosesConnection,
    Credential,
    DriverContext,
    DriverError,
    Encryption,
    PartialAccountChangeError,
    PrivilegeAudit,
    Scope,
    Timeouts,
    UnsupportedCapabilityError,
    UserState,
    VerifyResult,
    require_capability,
)
from sopuli.driver.registry import NotWrittenError as NotWrittenError
from sopuli.output.debug import logger
from sopuli.passwords import ByteLimit
from sopuli.secrets import Secret

LOG = logger("mysql")

#: The server refused a read of a table (``1142``) or a column (``1143``).
REFUSED_READ = frozenset({str(TABLE_ACCESS_DENIED), str(COLUMN_ACCESS_DENIED)})

MISSING_GRANT_HINT = (
    "the tool account lacks a grant of 02-mysql-privileges.md section 2.1, which it "
    "needs to read an account and the privileges guardrail 9 checks. "
    "`sopuli doctor --check-privileges` lists the missing ones, and the statements "
    "that grant them"
)

#: The hint for a `profile:` rule on a MySQL server.
NO_PROFILES = (
    "MySQL has no profiles; declare these accounts by name with `accounts:`, "
    "or by a role they hold with `role:`"
)

T = TypeVar("T")


class UnencryptedSessionError(DriverError):
    """A mode that requires TLS got a session it could not confirm as TLS. The
    session is closed before anything is sent over it. ``connectivity``, with
    the client's ``CR_SSL_CONNECTION_ERROR`` number, which is what PyMySQL
    raises for a server that offers no TLS: the same refusal, read from the
    session."""

    category = "connectivity"


class PlainLoginError(DriverError):
    """PyMySQL 1.2.3 could not finish a ``caching_sha2_password`` login over a
    plain connection.

    Measured on 8.4.13: a login the server has not cached needs the full
    exchange, and PyMySQL 1.2.3 fails it over a plain connection with
    ``AttributeError: 'NoneType' object has no attribute
    'is_auth_switch_request'``, not a MySQL error: its
    ``caching_sha2_password_auth`` returns nothing after the RSA round trip.
    The same login over TLS succeeds. ``connectivity``, with ``2000``
    (``CR_UNKNOWN_ERROR``), the number :mod:`~sopuli.driver.mysql_family.errors` gives
    every client failure that carries none, in the same category. When PyMySQL
    is fixed, the tier-1 test that pins this fails, and this goes.
    """

    category = "connectivity"


#: The text of PyMySQL 1.2.3's failure that :class:`PlainLoginError` reports.
#: Matched exactly, so no other ``AttributeError`` is taken for it.
PLAIN_LOGIN_FAILURE = "'NoneType' object has no attribute 'is_auth_switch_request'"


@dataclass
class MysqlSession(ClosesConnection):
    """One open connection to a server. A
    :class:`~sopuli.driver.protocol.Session` by its methods."""

    #: ``creds apply`` and ``creds rotate`` do not log in before a change
    #: (#1223). During a rotation that login always fails once, and on an
    #: account with ``FAILED_LOGIN_ATTEMPTS 1`` one failure blocks it for
    #: ``PASSWORD_LOCK_TIME`` days, a block a new password does not clear
    #: (probe 04, LE5). The tool cannot read the setting, which is in
    #: ``User_attributes``. Not on the protocol: a driver without it logs in.
    verifies_before_change: ClassVar[bool] = False

    connection: Any
    target: ExpandedTarget
    #: The run's, for the login :meth:`verify_password` makes as a managed
    #: account, which carries the same ``program_name`` and timeouts. No
    #: defaults, so a session cannot be built that loses the run's id or its
    #: budgets, as on PostgreSQL.
    correlation_id: str
    timeouts: Timeouts
    #: The session's encryption, where connect already read it to hold a mode
    #: that requires TLS to it, so :meth:`scope` does not read it again.
    encryption: Encryption | None = None
    #: Invariant 3's cache, probed on first use as on Oracle.
    _scope: Scope | None = field(default=None, init=False, repr=False)
    #: ``caching_sha2_password_digest_rounds``, read with the scope, or ``None``
    #: where the server has no such variable.
    _rounds: int | None = field(default=None, init=False, repr=False)
    #: ``CURRENT_USER()``, ``user@host``, read on the first
    #: :meth:`describe_user`. It does not change for the life of a connection,
    #: as the Oracle session's ``_session_user`` does not.
    _session_user: str | None = field(default=None, init=False, repr=False)
    #: The server's clock just before :meth:`set_password` sent its statement,
    #: per account, for :meth:`confirm_change`.
    _changed_since: dict[str, datetime] = field(default_factory=dict, init=False, repr=False)
    #: The words for two targets that are one server
    #: (:class:`~sopuli.driver.clusters.ClusterIdentity`). Not fields.
    #: ``identity_caveat`` is always ``None``: any account reads ``server_uuid``
    #: (probe 02, CH5).
    identity_caveat = None
    identity_kind = "MySQL server"
    identity_key = "server_uuid"
    identity_hint = (
        "declare each server once: two targets on one server would change its "
        "accounts under two names. A server whose data directory was copied "
        "from another keeps that server's server_uuid until its auto.cnf is "
        "removed and it restarts"
    )

    def cluster_identity(self) -> str | None:
        """The server's ``server_uuid``, which the CLI uses to refuse two
        targets that are one server. Any account reads it. A replica has its
        own, so a source and its replica are not caught here."""
        return self._read(_server_uuid)

    def scope(self) -> Scope:
        """What this session is: a server, read-write or not, and its encryption.

        Probed on the first call and cached for the session (invariant 3). Not
        at connect: a server that answers and is not MySQL, or a read that
        fails on a session that opened, is about a target that was reached, and
        `doctor` keeps the two apart.
        """
        if self._scope is None:
            observed = self._read(
                lambda cursor: observe(cursor, target=self.target.name, encryption=self.encryption)
            )
            self._scope = replace(observed, capabilities=self._capabilities())
            if LOG.isEnabledFor(logging.DEBUG):
                LOG.debug(
                    "%s is a server, %s %s, encryption %s",
                    self.target.name,
                    self._scope.db_version,
                    self._scope.open_mode,
                    self._scope.encryption.method,
                )
        return self._scope

    def _capabilities(self) -> frozenset[str]:
        """``role_lookup`` always, and ``password_rollover`` and
        ``expire_password`` where the server has
        ``caching_sha2_password_digest_rounds``.

        ``role_lookup``: a role is a row in ``mysql.user`` and its grants are in
        ``mysql.role_edges``, and §2.1 grants the tool account both reads.

        The tool needs that variable to set any password, and ``RETAIN CURRENT
        PASSWORD`` and ``DISCARD OLD PASSWORD`` are older than it (MySQL 8.0.14
        and 8.0.24), so a server that has it keeps a second password on request
        and discards it (``03_dual_password_probe.py``, measured on 8.0.46,
        8.4.13 and 9.7.4). A server without it answers ``1193``. Any account
        reads the variable (CH5).

        ``expire_password``: an account with only ``CREATE USER`` sends
        ``PASSWORD EXPIRE`` (LE3) and ``DISCARD OLD PASSWORD`` (DP7), and a
        new password ends an expiry (LE7, LE8), so `creds apply` sets one on an
        expired account and the change confirms. It comes with the variable,
        because the expiry sends ``DISCARD OLD PASSWORD`` first: a server too
        old to know the statement is refused at plan time, exit 5, rather than
        with a syntax error in the run (invariant 4).
        """
        try:
            self._rounds = self._read(_digest_rounds)
        except DriverError as error:
            if error.code != str(UNKNOWN_SYSTEM_VARIABLE):
                raise
            return frozenset({ROLE_LOOKUP})
        return frozenset({EXPIRE_PASSWORD, PASSWORD_ROLLOVER, ROLE_LOOKUP})

    def _not_written(self, what: str) -> NotWrittenError:
        return NotWrittenError(
            self.target.name,
            product="a MySQL server",
            what=what,
            hint=(
                "the MySQL driver connects, reports the server and reads accounts, and "
                "the rest of it is not written yet"
            ),
        )

    def describe_user(self, account: str) -> UserState | None:
        """The account's state, ``None`` where it does not exist
        (:mod:`~sopuli.driver.mysql.accounts`). An account on another plugin
        is refused with
        :class:`~sopuli.driver.mysql.accounts.OtherPluginError`.

        It reads the grant tables of guardrail 9 too. A tool account installed
        without §2.1's grants for them is refused there with ``1142`` or
        ``1143``, and the hint then says which grants and where to find them:
        the server's own hint names only the table.
        """
        return self._read_grants(lambda cursor: self._describe(cursor, account))

    def _describe(self, cursor: Any, account: str) -> UserState | None:
        if self._session_user is None:
            self._session_user = accounts_module.current_user(cursor)
        state = accounts_module.describe(
            cursor, account, target=self.target.name, session_user=self._session_user
        )
        if state is None:
            return None
        # A `role:` rule admits by these (`sopuli.personal.admits`), and
        # `accounts_matching` lists by the same grants the other way.
        user, host = split(state.name)
        return replace(state, roles=frozenset(roles.granted(cursor, Principal(user, host))))

    def byte_limit(self) -> ByteLimit:
        """256 bytes of UTF-8, whatever the server: a longer password is stored
        and then refused at login (:mod:`~sopuli.driver.mysql.limits`)."""
        return LIMIT

    def password_constraints(self, account: str) -> None:
        """Nothing beyond the length, read without a round trip. Not on the
        protocol: ``creds generate`` asks it of a driver that has it.

        The server's own rules never see a password the tool sets: neither an
        account's ``PASSWORD HISTORY`` or ``PASSWORD REUSE INTERVAL`` nor the
        ``validate_password`` component checks a hash sent with ``AS``
        (``08_password_rules_probe.py``). So there is nothing for the server
        to refuse, and nothing to report."""

    def privileges(self, *, accounts: tuple[str, ...] = ()) -> PrivilegeAudit:
        """What the tool account holds, needs and should not hold
        (:mod:`~sopuli.driver.mysql.privileges`). Uncached: a run asks once.

        ``accounts`` are the accounts the config declares on this target. Each
        one that does not exist, uses another plugin, or shares its user name
        with an account at an undeclared host gets a line in ``remedies``
        (:func:`~sopuli.driver.mysql.accounts.survey`). Where that read fails,
        as it does with ``1142`` or ``1143`` when §2.1's column grant is
        missing, ``mysql.user`` is unreadable, a line says why, and the audit
        of the tool account's grants is kept.
        """
        audit = self._read(privilege_audit)
        if not accounts:
            return audit
        try:
            lines = self._read(lambda cursor: accounts_module.survey(cursor, accounts))
        except DriverError as error:
            # The tool account's audit above stands: a pre-flight still sees a
            # missing grant, and `doctor` still reports the rest.
            return replace(
                audit,
                unreadable=(*audit.unreadable, "mysql.user"),
                remedies=(*audit.remedies, f"the declared accounts were not read: {error}"),
            )
        return replace(audit, remedies=(*audit.remedies, *lines))

    def _read(self, reader: Callable[[Any], T], *, scrub: Callable[[str], str] | None = None) -> T:
        """Run ``reader`` on a cursor of this session. A closed session is a
        fault in sopuli, and a MySQL error is classified by
        :mod:`~sopuli.driver.mysql.errors`.

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

    def set_password(
        self, account: str, secret: Secret, *, old_password: str = OLD_DISCARD
    ) -> ChangeResult:
        """``ALTER USER … IDENTIFIED WITH caching_sha2_password AS 0x…``, with
        the hash computed here (invariant 15, :mod:`~sopuli.driver.mysql.password`).

        ``old_password`` says what happens to the password the account had
        (#1224, ``03_dual_password_probe.py``):

        * ``discard``: ``DISCARD OLD PASSWORD`` follows, so only the vault's
          password logs in. It also ends a password someone retained by hand,
          which survives a change without it (DP4).
        * ``retain``: the statement ends with ``RETAIN CURRENT PASSWORD``, and
          the old password keeps working until ``creds finish-rollover``.
        * ``keep``: neither. A password already retained stays retained (DP4).
          A second ``RETAIN`` would replace it with the current one (DP3), so a
          staged password set again is set this way.

        As on the other drivers, ``changed`` is ``True`` whenever the statement
        succeeded: whether the account already had this password is not a
        question the server can answer, so the command decides it first.

        Refused before anything is sent, with ``password_sent`` left ``False``:
        a password the target cannot take, a read-only session, an account that
        does not exist, and one on another plugin. Once the statement is handed
        to the server, a failure has ``password_sent`` set. What crossed is a
        hash, which still allows an offline guessing attack. A timeout (``2013``)
        leaves the outcome unknown, and the error's hint says so.
        """
        if old_password not in OLD_PASSWORD_MODES:
            raise ValueError(f"not an old-password mode: {old_password!r}")
        password_module.admit(secret)
        require_read_write(self.scope(), target=self.target.name)
        if old_password == OLD_RETAIN:
            require_capability(self.scope(), PASSWORD_ROLLOVER, target=self.target.name)
        state = self.describe_user(account)
        if state is None:
            raise DriverError(
                f'account "{account}" does not exist on target "{self.target.name}"',
                hint=(
                    "the tool does not create accounts (Q8); `creds check` reports this "
                    "as ACCOUNT_MISSING rather than failing"
                ),
            )
        user, host = split(state.name)
        statement = self._password_statement(user, host, secret, retain=old_password == OLD_RETAIN)
        # The server's clock before the statement: confirm_change compares
        # password_last_changed with it. The session's time zone is UTC.
        since = self._read(_server_now)
        try:
            # The read above found the session open, so a failure here is the
            # server's answer to the statement.
            self._read(lambda cursor: cursor.execute(statement), scrub=_scrub_hash)
        except DriverError as failure:
            failure.password_sent = True
            raise
        self._changed_since[state.name] = since
        if old_password != OLD_DISCARD:
            LOG.debug(
                "password set for %s on %s, old password %s",
                state.name,
                self.target.name,
                "retained" if old_password == OLD_RETAIN else "left as it was",
            )
            return ChangeResult(
                changed=True, detail="password set", retained=old_password == OLD_RETAIN
            )
        try:
            self._read(lambda cursor: cursor.execute(password_module.discard_old(user, host)))
        except DriverError as failure:
            # The new password is set; an old one someone retained may still
            # work. The run reports the account failed, with the change made.
            failure.password_sent = True
            failure.message = (
                f"the password was set, but discarding a retained old password failed: "
                f"{failure.message}"
            )
            raise
        LOG.debug("password set for %s on %s", state.name, self.target.name)
        return ChangeResult(changed=True, detail="password set", discarded=True)

    def _password_statement(
        self, user: str, host: str, secret: Secret, *, retain: bool = False, expire: bool = False
    ) -> str:
        """The ``ALTER USER`` that sets ``secret`` by its hash, with the
        server's own rounds. Built before the first statement of a change, so
        a refusal here changes nothing."""
        try:
            # Read with the scope, and set only at server start, so the value
            # cannot change within the session.
            rounds = self._rounds if self._rounds is not None else self._read(_digest_rounds)
        except DriverError as error:
            if error.code != str(UNKNOWN_SYSTEM_VARIABLE):
                raise
            raise DriverError(
                f'target "{self.target.name}" has no caching_sha2_password_digest_rounds',
                code=error.code,
                hint=(
                    "the tool sets a password with the server's own rounds, and does not "
                    "guess them; a server without the variable is not supported for this"
                ),
            ) from error
        if rounds % 1000:
            raise DriverError(
                f"caching_sha2_password_digest_rounds is {rounds} on target "
                f'"{self.target.name}", which is not a multiple of 1000',
                hint=(
                    "the stored hash writes the rounds in thousands, so the tool does not "
                    "know what the server would store; set the variable to a multiple of 1000"
                ),
            )
        return password_module.alter_user(
            user,
            host,
            password_module.caching_sha2_hash(secret, rounds),
            retain=retain,
            expire=expire,
        )

    def suspend_account(self, account: str) -> AccountChange:
        """``ALTER USER … ACCOUNT LOCK``, or report that the account is already
        locked (#1225).

        The password then answers ``3118`` (LE2). ``account_locked`` is set only
        by ``ACCOUNT LOCK``, so a ``Y`` is already a suspension; a block after
        failed logins is not in ``mysql.user`` and does not count, as Oracle's
        ``LOCKED(TIMED)`` does not. A reset refuses a locked account (H4), so a
        suspended account stays suspended until somebody runs ``ALTER USER …
        ACCOUNT UNLOCK``.

        **The state is read first** (invariant 9): a second ``ACCOUNT LOCK`` is
        accepted silently (LE2). ``CREATE USER`` is enough.

        Not gated by ``account_lock_state``, which a MySQL session does not
        report: that capability is also what lets UC-1's ``unlock_if_locked``
        clear a lock, which this driver does not do yet. PostgreSQL's
        ``NOLOGIN`` is not gated for the same reason.
        """
        require_read_write(self.scope(), target=self.target.name)
        found, status = self._row(account, what="suspended")
        if found.locked:
            return AccountChange(
                ACCOUNT_LOCK,
                changed=False,
                status=status,
                detail="the account is already locked (ACCOUNT LOCK)",
            )
        self._read(lambda cursor: cursor.execute(password_module.lock(found.user, found.host)))
        LOG.debug("ACCOUNT LOCK for %s on %s", found.name, self.target.name)
        return AccountChange(
            ACCOUNT_LOCK,
            changed=True,
            status=status,
            detail=f"account was {status.lower()}; sent ACCOUNT LOCK",
        )

    def _row(self, account: str, *, what: str) -> tuple[accounts_module.Account, str]:
        """The account's ``mysql.user`` row and its status, for a verb that
        needs no more: no roles and no grant tables, which the command already
        read. Refuses an account that does not exist, before anything is sent;
        ``what`` is the verb's participle for the hint."""

        def read(cursor: Any) -> tuple[accounts_module.Account | None, str]:
            found = accounts_module.read_one(cursor, account, target=self.target.name)
            if found is None:
                return None, ""
            return found, accounts_module.state_now(cursor, found).status

        found, status = self._read(read)
        if found is None:
            raise DriverError(
                f'account "{account}" does not exist on target "{self.target.name}"',
                hint=(
                    f"the tool does not create accounts (Q8); nothing is {what}, and the "
                    "account name is worth checking against the server"
                ),
            )
        return found, status

    def reset_password(
        self, account: str, secret: Secret, *, expire: bool, keep_rollover: bool = False
    ) -> tuple[AccountChange, ...]:
        """UC-2 §4.1 on a MySQL server: three statements, one per row the
        protocol names (#1225).

        1. ``ACCOUNT UNLOCK``, on every reset. A block after failed logins is
           not in ``mysql.user``, and a new password does not end it (LE5), so
           the reset cannot tell whether one is in place and ends it anyway
           (decision 1). The row says it was sent, and that its effect cannot
           be read.
        2. The password by its hash, with ``PASSWORD EXPIRE`` where
           ``expire``. The owner then logs in only to set a password of their
           own (LE6).
        3. ``DISCARD OLD PASSWORD``. A password someone retained survives the
           change, and the expiry with it (LE7), so this is sent on every
           reset. The tool cannot read whether one was retained.

        **Refused before anything is sent:** ``keep_rollover``, by capability
        (decision 2), a read-only session, a password the server cannot take,
        an account that does not exist, and one locked with ``ACCOUNT LOCK``.
        That lock is always somebody's decision (H4): a block after failed
        logins never sets ``account_locked``.

        A failure after the unlock committed raises
        :class:`~sopuli.driver.protocol.PartialAccountChangeError` with the
        rows that ran, as on Oracle.
        """
        if keep_rollover:
            # The command refuses it at plan time; this is the driver's own line.
            raise UnsupportedCapabilityError(
                KEEP_ROLLOVER, target=self.target.name, hint=KEPT_WINDOW_UNREADABLE
            )
        password_module.admit(secret)
        require_read_write(self.scope(), target=self.target.name)
        found, status = self._row(account, what="reset")
        if found.locked:
            raise DriverError(
                f'account "{found.name}" is locked, and a reset does not unlock it',
                hint=(
                    "ACCOUNT LOCK is somebody's decision -- `account suspend`, usually -- and "
                    "handing the account a working password would undo it silently. Run "
                    "ALTER USER … ACCOUNT UNLOCK first if that is what you mean (H4)"
                ),
            )
        user, host = found.user, found.host
        # Built before the first statement, so a refusal of the rounds cannot
        # come after the unlock.
        statement = self._password_statement(user, host, secret, expire=expire)
        discard = password_module.discard_old(user, host)

        self._read(lambda cursor: cursor.execute(password_module.unlock(user, host)))
        done: tuple[AccountChange, ...] = (
            AccountChange(
                ACCOUNT_UNLOCK,
                changed=True,
                status=status,
                detail=(
                    "sent ACCOUNT UNLOCK, which ends a block after failed logins; "
                    "whether one was in place cannot be read"
                ),
            ),
        )
        try:
            self._read(lambda cursor: cursor.execute(statement), scrub=_scrub_hash)
        except DriverError as failure:
            failure.password_sent = True
            raise PartialAccountChangeError(failure, completed=done) from failure
        done = (
            *done,
            AccountChange(
                PASSWORD_SET,
                changed=True,
                status=status,
                detail="password set, expired" if expire else "password set",
            ),
        )
        try:
            self._read(lambda cursor: cursor.execute(discard))
        except DriverError as failure:
            raise PartialAccountChangeError(
                failure,
                completed=done,
                hint=f"assume a retained old password still works. Discard it by hand: {discard}",
            ) from failure
        LOG.debug("password reset for %s on %s", found.name, self.target.name)
        return (
            *done,
            AccountChange(
                ROLLOVER_FINISH,
                changed=True,
                status=status,
                detail="sent DISCARD OLD PASSWORD, so no retained password logs in",
            ),
        )

    def expire_password(self, account: str) -> tuple[AccountChange, ...]:
        """``DISCARD OLD PASSWORD``, then ``PASSWORD EXPIRE``, where
        ``password_expired`` is ``N``; nothing where it is ``Y`` (#1225,
        decision 3).

        **The discard comes first, on every expiry this sends.** A password someone
        kept with ``RETAIN CURRENT PASSWORD`` survives ``PASSWORD EXPIRE`` and
        still logs in, expired, until the discard (LE9). The tool cannot read
        whether one is kept. Discard first so that a failed expiry leaves the
        old password dead, as Oracle's close comes first (#525).

        **Keyed on ``password_expired``, not on the reported state** (invariant
        9). Only ``PASSWORD EXPIRE`` sets the column, so ``Y`` is the state this
        verb converges on, and a second run reports ``changed: false``. A
        password past its lifetime reads as expired and still has ``N``: the
        verb expires it, which a new lifetime would not undo. An account someone
        else expired keeps a retained password; the tool cannot see one.

        A lock is left alone, as on Oracle. ``CREATE USER`` is enough (LE3, DP7).
        Refused by capability where the server does not report
        ``expire_password`` (:meth:`_capabilities`): the command refuses it at
        plan time, and this is the driver's own line for a target whose scope
        plan time could not read.
        """
        require_read_write(self.scope(), target=self.target.name)
        require_capability(
            self.scope(), EXPIRE_PASSWORD, target=self.target.name, hint=EXPIRY_UNAVAILABLE
        )
        found, status = self._row(account, what="expired")
        if found.expired:
            return (
                AccountChange(
                    ROLLOVER_FINISH,
                    changed=False,
                    status=status,
                    detail="nothing sent: the password is already expired",
                ),
                AccountChange(
                    PASSWORD_EXPIRE,
                    changed=False,
                    status=status,
                    detail="the password is already expired",
                ),
            )
        before = status
        self._read(
            lambda cursor: cursor.execute(password_module.discard_old(found.user, found.host))
        )
        discarded = AccountChange(
            ROLLOVER_FINISH,
            changed=True,
            status=before,
            detail="sent DISCARD OLD PASSWORD, so no retained password logs in",
        )
        try:
            statement = password_module.expire(found.user, found.host)
            self._read(lambda cursor: cursor.execute(statement))
        except DriverError as failure:
            raise PartialAccountChangeError(
                failure,
                completed=(discarded,),
                hint=(
                    "no retained password works now, and the current one is not expired. "
                    f"Run the command again, or expire it by hand: {statement}"
                ),
            ) from failure
        LOG.debug("PASSWORD EXPIRE for %s on %s", found.name, self.target.name)
        return (
            discarded,
            AccountChange(PASSWORD_EXPIRE, changed=True, status=before, detail="password expired"),
        )

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
        """Refused by capability: MySQL has no profiles, so a `profile:` rule
        names nothing on a server."""
        require_capability(
            self.scope(), PROFILE_MANAGEMENT, target=self.target.name, hint=NO_PROFILES
        )
        return None  # pragma: no cover -- the capability is never reported

    def resolve_role(self, role: str) -> str | None:
        """The role as ``mysql.user`` spells it, or ``None``
        (:func:`~sopuli.driver.mysql.roles.resolve`). A mandatory role, or one a
        mandatory role holds, is refused with exit 9. The tool account reads
        ``mysql.user`` and ``mysql.role_edges`` by §2.1's grants, so
        :data:`ROLE_LOOKUP` is always reported."""
        require_capability(self.scope(), ROLE_LOOKUP, target=self.target.name)
        return self._read_grants(
            lambda cursor: roles.resolve(cursor, role, target=self.target.name)
        )

    def accounts_matching(
        self, *, profile: str | None = None, role: str | None = None
    ) -> tuple[str, ...]:
        """Every account that holds ``role``, through any chain of grants
        (:func:`~sopuli.driver.mysql.roles.members_of`). A ``profile`` is
        refused as :meth:`resolve_profile` refuses it."""
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

    def _read_grants(self, reader: Callable[[Any], T]) -> T:
        """:meth:`_read`, with the hint about §2.1's grants on a refused read."""
        try:
            return self._read(reader)
        except DriverError as error:
            if error.code in REFUSED_READ:
                error.hint = MISSING_GRANT_HINT
            raise

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
        (:mod:`sopuli.driver.mysql.verification`).

        ``login`` only: ``hash`` and ``both`` need ``offline_verify``, which this
        driver never reports, because the hash is in ``authentication_string``,
        which the tool account does not read. :meth:`require_verifier` refuses
        them at plan time, and this refuses them again.

        The tool logs in only where nothing but the declared account can answer:
        a ``user@%`` account that is the user's only one, with no anonymous
        account at a named host. Any other is
        :data:`~sopuli.driver.protocol.UNAVAILABLE` without a login, as is an
        account that does not exist or is locked. MySQL gives the tool no
        lockout counter to read, so ``lockout_margin`` and ``attempts`` have
        nothing to guard, and the detail says so.
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
        # which compete for the same login (`verification.not_tried_reason`).
        try:
            found = self._read(lambda cursor: accounts_module.read(cursor, [user, ""]))
        except DriverError as error:
            if error.code in REFUSED_READ:
                error.hint = MISSING_GRANT_HINT
            raise
        declared = accounts_module.find(found[user], host)
        if declared is None:
            return _not_tried(f'there is no account "{account}" on this target')
        if declared.plugin != accounts_module.SUPPORTED_PLUGIN:
            # As `describe_user` refuses it: the tool manages no other plugin.
            raise accounts_module.OtherPluginError(
                declared.name, declared.plugin, target=self.target.name
            )
        reason = verification.not_tried_reason(declared, found[user], found[""])
        if reason is not None:
            return _not_tried(reason)
        if declared.locked:
            return _not_tried("the account is locked; no login was attempted")
        return self._login(declared, secret)

    def confirm_change(self, account: str) -> VerifyResult | None:
        """After :meth:`set_password`, for an account no login can reach: a
        :data:`~sopuli.driver.protocol.STORED` result where the server's
        ``password_last_changed`` for it is no earlier than the server's clock
        read just before the statement (#1223). ``None`` otherwise: for an
        account a login can reach, for one this session did not change, and
        where the time did not move. Not on the protocol: ``creds apply`` asks
        it of a driver that has it, after a login that was unavailable.

        Weaker than a login: it shows a password change at or after the
        statement, almost always the tool's, not that a client logs in with
        the password.
        """
        since = self._changed_since.get(account)
        if since is None:
            return None
        user, host = split(account)
        # The read verify_password makes, so the two agree on which accounts a
        # login can reach.
        found = self._read(lambda cursor: accounts_module.read(cursor, [user, ""]))
        declared = accounts_module.find(found[user], host)
        if declared is None or declared.changed_at is None:
            return None
        reason = verification.not_tried_reason(declared, found[user], found[""])
        if reason is None or declared.changed_at < since:
            return None
        changed = declared.changed_at.strftime("%Y-%m-%d %H:%M:%S")
        return VerifyResult(
            method=VERIFY_NONE,
            result=STORED,
            detail=(
                f"not verified by login: {reason}. The server records the password as "
                f"changed at {changed} UTC, no earlier than its clock just before this "
                f"run's statement"
            ),
        )

    def _login(self, declared: accounts_module.Account, secret: Secret) -> VerifyResult:
        arguments = connect_arguments(
            self.target,
            Credential(username=declared.user, secret=secret),
            correlation_id=self.correlation_id,
            timeouts=self.timeouts,
        )
        started = time.monotonic()
        try:
            connection = pymysql.connect(**arguments)
        except pymysql.err.MySQLError as error:
            latency = _ms(started)
            failure = from_error(error, connecting=True)
            LOG.debug(
                "login as %s failed with %s in %.3fs", declared.name, failure.code, latency / 1000
            )
            outcome = verification.login_outcome(failure)
            if outcome is None:
                raise failure.as_error() from error
            result, detail = outcome
            return VerifyResult(
                method=VERIFY_LOGIN, result=result, latency_ms=latency, detail=detail
            )
        except AttributeError as error:
            # PyMySQL 1.2.3's failure over a plain connection, as
            # `MysqlDriver.connect` meets it. The password was not tried.
            if str(error) != PLAIN_LOGIN_FAILURE:
                raise
            return VerifyResult(
                method=VERIFY_LOGIN,
                result=UNAVAILABLE,
                latency_ms=_ms(started),
                detail=(
                    "PyMySQL could not finish the caching_sha2_password login over a plain "
                    "connection, so the password was not tried: set `mysql.ssl_mode` to "
                    "VERIFY_IDENTITY"
                ),
            )
        latency = _ms(started)
        try:
            with connection.cursor() as cursor:
                # The same TLS rule as the tool's own session (`require_tls`),
                # before anything else is read over this one.
                require_tls(read_encryption(cursor), self.target)
                answered = accounts_module.current_user(cursor)
        except pymysql.err.MySQLError as error:
            # The password was accepted, and which account accepted it is
            # unknown. A result, not an exception: a scheduled check must not
            # look broken for a socket that dropped after the answer.
            failure = from_error(error)
            return VerifyResult(
                method=VERIFY_LOGIN,
                result=UNAVAILABLE,
                latency_ms=latency,
                detail=(
                    f"the login succeeded, and reading which account it reached failed "
                    f"({failure.code}), so it says nothing certain about {declared.name}"
                ),
            )
        finally:
            # The login has answered. A socket that drops as it closes does
            # not change the answer.
            with suppress(pymysql.err.MySQLError):
                connection.close()
        if not same_mysql_account(answered, declared.name):
            # Unreachable for a user's sole `%` account, and checked anyway:
            # a pass on another account's password would be a false pass. A
            # login was made, so its latency is kept.
            return VerifyResult(
                method=VERIFY_LOGIN,
                result=UNAVAILABLE,
                latency_ms=latency,
                detail=(
                    f"the login reached {answered}, not {declared.name}, so it says nothing "
                    "about the declared account's password"
                ),
            )
        LOG.debug("login as %s: pass in %.3fs", declared.name, latency / 1000)
        return VerifyResult(
            method=VERIFY_LOGIN, result=PASS, latency_ms=latency, detail=verification.UNGUARDED
        )

    def require_verifier(self, account: str, secret: Secret) -> None:
        """Refuse ``hash`` and ``both`` at plan time (invariant 4): this driver
        never reports ``offline_verify``."""
        require_capability(
            self.scope(),
            OFFLINE_VERIFY,
            target=self.target.name,
            hint=(
                "the hash is in mysql.user.authentication_string, which the tool account "
                "does not read; use --method login, the default"
            ),
        )

    def require_rollover(self, account: str) -> None:
        """Refuse ``--strategy rollover`` where the server has no dual
        passwords (invariant 4), then where the account does not exist.

        No profile decides it: the tool opens the window itself, with ``RETAIN
        CURRENT PASSWORD`` (#1224). An account on another plugin is refused by
        :meth:`describe_user`, and ``RETAIN`` with a plugin change would be
        refused by the server too (``3894``, DP9).
        """
        require_capability(
            self.scope(),
            PASSWORD_ROLLOVER,
            target=self.target.name,
            hint=(
                "the server has no caching_sha2_password_digest_rounds, which the tool "
                "needs to set any password here; every server that has it keeps a "
                "second password on request"
            ),
        )
        if self.describe_user(account) is None:
            raise DriverError(f'account "{account}" does not exist on target "{self.target.name}"')

    def finish_rollover(self, account: str) -> ChangeResult:
        """``ALTER USER … DISCARD OLD PASSWORD``, always, and ``changed: True``.

        The tool cannot read whether a password is retained: it is in
        ``mysql.user.User_attributes``, which the tool account never reads
        (decision 6 of #1202). The server accepts the statement with nothing
        retained (``03_dual_password_probe.py``, DP1), so it is sent every
        time, and every run reports a change. That is the one exception to
        invariant 9 this verb has (#1224).
        """
        require_read_write(self.scope(), target=self.target.name)
        state = self.describe_user(account)
        if state is None:
            raise DriverError(f'account "{account}" does not exist on target "{self.target.name}"')
        user, host = split(state.name)
        self._read(lambda cursor: cursor.execute(password_module.discard_old(user, host)))
        LOG.debug("old password discarded for %s on %s", state.name, self.target.name)
        return ChangeResult(changed=True, detail="any retained password discarded")


def _ms(started: float) -> int:
    """Milliseconds since ``started``, a :func:`time.monotonic` reading."""
    return round((time.monotonic() - started) * 1000)


def _not_tried(detail: str) -> VerifyResult:
    """A login :meth:`MysqlSession.verify_password` settled without trying."""
    return VerifyResult(method=VERIFY_LOGIN, result=UNAVAILABLE, detail=detail)


#: Which server this is, for two targets that are one (probe 02, CH5).
SERVER_UUID = "select @@global.server_uuid"


def _server_uuid(cursor: Any) -> str:
    cursor.execute(SERVER_UUID)
    return str(cursor.fetchone()[0])


#: The server's clock, in the session's time zone, which is UTC
#: (:data:`~sopuli.driver.mysql_family.connection.UTC_SESSION`).
SERVER_NOW = "select now()"


def _server_now(cursor: Any) -> datetime:
    cursor.execute(SERVER_NOW)
    (now,) = cursor.fetchone()
    found: datetime = now.replace(tzinfo=UTC)
    return found


def _digest_rounds(cursor: Any) -> int:
    """The server's ``caching_sha2_password_digest_rounds`` (CH5)."""
    cursor.execute(password_module.DIGEST_ROUNDS)
    row = cursor.fetchone()
    return int(row[0])


#: A hex literal, such as the hash in the statement that sets a password, or a
#: run of 16 or more hex digits: a message that quotes the statement from the
#: middle of the literal starts without the ``0x``.
_HEX = re.compile(r"0x[0-9a-fA-F]+|[0-9a-fA-F]{16,}")

#: The hash as text, ``$A$`` and the rounds, then the salt and the digest.
_STORED = re.compile(r"\$A\$[0-9A-Fa-f]{3}\$\S*")


def _scrub_hash(message: str) -> str:
    """The server's message about the statement that sets a password, with any
    hex literal written as ``0x***``, any other long run of hex digits as
    ``***``, and the hash as text as ``$A$***``. The server may quote part of
    the statement, and the hash is worth an offline guessing attack."""
    message = _STORED.sub("$A$***", message)
    return _HEX.sub(lambda found: "0x***" if found[0].startswith("0x") else "***", message)


def require_tls(encryption: Encryption, target: ExpandedTarget) -> None:
    """Refuse a session not known to be TLS where ``ssl_mode`` requires it.

    PyMySQL already refuses a server that offers no TLS when it is given a
    context (:mod:`sopuli.driver.mysql_family.connection`). This reads the
    answer from the session itself, so the rule does not rest on the client
    library alone.
    ``unknown`` is refused too, with its own words: a mode that requires TLS
    needs it confirmed.
    """
    mode = target.target.mysql_settings.ssl_mode
    if mode not in TLS_REQUIRED_MODES or encryption.method == ENCRYPTION_TLS:
        return
    if encryption.method == UNKNOWN:
        raise UnencryptedSessionError(
            f'target "{target.name}" could not confirm TLS under `ssl_mode: {mode}`',
            hint=encryption.hint or "the server did not say whether the session is TLS",
            code=str(TLS_CONNECTION_ERROR),
        )
    raise UnencryptedSessionError(
        f'target "{target.name}" connected without TLS under `ssl_mode: {mode}`',
        hint="the server negotiated no TLS; give it a certificate, and keep the mode",
        code=str(TLS_CONNECTION_ERROR),
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
            # PyMySQL 1.2.3's own failure, measured (PlainLoginError), matched
            # by its exact text. Anything else is a fault, and surfaces.
            if str(error) != PLAIN_LOGIN_FAILURE:
                raise
            raise PlainLoginError(
                f'target "{target.name}": PyMySQL could not finish the '
                f"caching_sha2_password login over a plain connection",
                hint=(
                    "a login the server has not cached needs the full exchange, which "
                    "PyMySQL 1.2.3 fails without TLS. Set `mysql.ssl_mode` to "
                    "VERIFY_IDENTITY, with `mysql.ssl_ca` naming the CA that issued the "
                    "server's certificate"
                ),
                code=str(UNKNOWN_CLIENT_ERROR),
            ) from error
        LOG.debug(
            "connect to %s as %s in %.3fs",
            target.name,
            credential.username,
            time.monotonic() - started,
        )
        try:
            # Only the encryption here, which the TLS rule needs before anything
            # is sent. The session keeps it, so the scope does not read it again.
            with connection.cursor() as cursor:
                encryption = read_encryption(cursor)
            require_tls(encryption, target)
        except pymysql.err.MySQLError as error:
            connection.close()
            raise from_error(error).as_error() from error
        except BaseException:
            connection.close()
            raise
        return MysqlSession(
            connection=connection,
            target=target,
            correlation_id=self.correlation_id,
            timeouts=self.timeouts,
            encryption=encryption,
        )


def build_driver(context: DriverContext) -> MysqlDriver:
    """The registry's way in: a :class:`MysqlDriver` for this run. PyMySQL
    needs nothing from ``runtime``: it is pure Python."""
    return MysqlDriver(correlation_id=context.correlation_id, timeouts=context.timeouts)


def client_report(*, env: Mapping[str, str], runtime: Runtime) -> dict[str, Any]:
    """`doctor`'s client line: PyMySQL's release, from ``pymysql.VERSION``,
    ``(1, 2, 3, 'final')`` on 1.2.3. Not ``pymysql.__version__``, a
    MySQLdb-compatible string (``2.2.8`` there), and not the distribution's
    metadata, which an unusual install may lack. Neither argument is read."""
    return client_lines(pymysql_version=".".join(str(part) for part in pymysql.VERSION[:3]))
