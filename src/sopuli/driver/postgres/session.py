"""Connecting to a PostgreSQL cluster, and reporting what it is.

The module :data:`sopuli.driver.registry.DRIVERS` imports for
``type: postgresql``. It imports ``psycopg`` at module scope, so a machine
without the ``postgres`` extra gets ``SOPULI-20002`` from the registry rather than
a traceback (ADR-006 rule 1). Which of the modules beside it import ``psycopg``
is in the package docstring.

**What this build does.** It connects, labels the session with the run's
correlation id, and reports the scope: ``cluster``, whether it takes writes, and
its encryption, audits the tool account's privileges for
`doctor --check-privileges`, describes a role for the guardrails
(:meth:`PostgresSession.describe_user`), verifies a role's password by logging
in as the role (:meth:`PostgresSession.verify_password`), and sets a role's
password with a verifier computed on the client
(:meth:`PostgresSession.set_password`, invariant 15), and suspends a role with
``ALTER ROLE … NOLOGIN`` (:meth:`PostgresSession.suspend_account`). Those two
``ALTER ROLE`` statements are the only ones the driver sends that change
anything, and each checks
:func:`~sopuli.driver.postgres.scope.require_read_write` first. It also resolves
a `role:` predicate for `account list` (:meth:`PostgresSession.accounts_matching`).
The registry entry lists the commands it is written for: UC-1's, and UC-2's
`account list`, `reset-password`, `suspend` and `expire-password`. What
PostgreSQL has no counterpart for, such as a rollover window, a profile, or an
expired password a role must change at login, is refused by capability, exit 5.
:meth:`PostgresSession.apply_attributes` is not written, and is never reached:
the attributes it enforces are refused by capability at plan time.
"""

from __future__ import annotations

import logging
import re
import time
from collections.abc import Iterator, Mapping
from contextlib import contextmanager, suppress
from dataclasses import dataclass, field
from typing import Any

import psycopg
from psycopg import pq, sql

from sopuli.config.model import ExpandedTarget, Runtime
from sopuli.driver.postgres import roles
from sopuli.driver.postgres.client import REQUIRE_AUTH_FROM, client_lines, libpq_release
from sopuli.driver.postgres.connection import connect_arguments
from sopuli.driver.postgres.errors import INSUFFICIENT_PRIVILEGE, from_error
from sopuli.driver.postgres.limits import LIMIT
from sopuli.driver.postgres.password import (
    SCRAM_FROM,
    SCRAM_VERIFIER,
    admit,
    alter_role,
    verifier,
)
from sopuli.driver.postgres.privileges import audit
from sopuli.driver.postgres.roles import describe, members_of
from sopuli.driver.postgres.scope import SYSTEM_IDENTIFIER, observe, require_read_write
from sopuli.driver.postgres.verification import REQUIRED_METHOD, login_outcome
from sopuli.driver.protocol import (
    ACCOUNT_LOCK,
    ACCOUNT_UNLOCK,
    EXPIRE_PASSWORD,
    EXPIRY_UNAVAILABLE,
    OFFLINE_VERIFY,
    PASS,
    PASSWORD_ROLLOVER,
    PASSWORD_SET,
    PROFILE_MANAGEMENT,
    ROLE_LOOKUP,
    ROLLOVER_FINISH,
    SEEN_NEEDS_EXPIRY,
    UNAVAILABLE,
    VERIFY_BOTH,
    VERIFY_HASH,
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
    UnsupportedCapabilityError,
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

#: The hint for a `profile:` predicate on a cluster.
NO_PROFILES = (
    "PostgreSQL has no profiles; declare these accounts by name with `accounts:`, "
    "or by a role they hold with `role:`"
)


def _ms(started: float) -> int:
    """Milliseconds since ``started``, a :func:`time.monotonic` reading,
    truncated as the CLI's ``duration_ms`` is."""
    return int((time.monotonic() - started) * 1000)


def _not_tried(detail: str) -> VerifyResult:
    """A login :meth:`PostgresSession.verify_password` settled without trying."""
    return VerifyResult(method=VERIFY_LOGIN, result=UNAVAILABLE, detail=detail)


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
                f"this is not something to install: the PostgreSQL driver reads roles, "
                f"checks and sets their passwords, and cannot {what} yet"
            ),
            code=DRIVER_NOT_IMPLEMENTED,
        )


@dataclass
class PostgresSession:
    """One open connection to a cluster. A
    :class:`~sopuli.driver.protocol.Session` by its methods."""

    connection: Any
    target: ExpandedTarget
    #: The run's, for the logins :meth:`verify_password` makes as a managed
    #: role, which carry the same ``application_name`` and timeouts. No
    #: defaults, so a session cannot be built that loses the run's id or its
    #: budgets.
    correlation_id: str
    timeouts: Timeouts
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
        """The role from ``pg_roles``, or ``None`` if there is none
        (:mod:`sopuli.driver.postgres.roles`)."""
        with self._cursor() as cursor:
            return describe(cursor, account, target=self.target.name)

    def byte_limit(self) -> ByteLimit:
        """1024 bytes of UTF-8, whatever the server: the limit is libpq 13's, on
        the application's side (:mod:`sopuli.driver.postgres.password`)."""
        return LIMIT

    def password_constraints(self, account: str) -> None:
        """Nothing beyond the length, read without a round trip: a plain server
        has no verify function and no reuse history (``password_reuse_policy``
        is absent), so ``creds generate`` reports none for a role.

        A server module that checks passwords, such as ``passwordcheck``, is
        not read. It sees only the verifier the tool sends, not the password,
        so it can refuse little; whatever it refuses is the server's error on
        that row. Not on the protocol: ``generate`` asks it of a driver that
        has it."""

    def privileges(self, *, accounts: tuple[str, ...] = ()) -> PrivilegeAudit:
        """What the tool account holds, needs and should not hold, and its
        ``ADMIN OPTION`` on each of ``accounts``. Uncached: a run asks once."""
        with self._cursor() as cursor:
            return audit(cursor, accounts)

    def set_password(self, account: str, secret: Secret) -> ChangeResult:
        """``ALTER ROLE … PASSWORD`` with a verifier computed here (invariant 15).

        As on Oracle, the driver does not regenerate and ``changed`` is ``True``
        whenever the statement succeeded: whether the role already had this
        password is not a question a server can answer, so the command decides it
        from the vault before calling this.

        Refused before anything is sent, with ``password_sent`` left ``False``:
        a read-only target; a server older than PostgreSQL 10, which would store
        the verifier's text as a plaintext password; a role that does not exist;
        a password :func:`~sopuli.driver.postgres.password.admit` refuses; and a
        verifier libpq could not compute. Once the statement is handed to the
        server, a failure has ``password_sent`` set: what crossed is a verifier,
        which still allows an offline guessing attack, so the warnings about an
        unencrypted connection apply to it as they would to a password.
        """
        admit(secret)
        state = self._role_to_set(account)
        self._send_password(state.name, secret)
        return ChangeResult(changed=True, detail="password set")

    def _role_to_set(self, account: str) -> UserState:
        """The role whose password is about to be set, after the refusals that
        come before anything is sent: a read-only target, a server that cannot
        store a SCRAM verifier, and a role that does not exist."""
        scope = self.scope()
        require_read_write(scope, target=self.target.name)
        major = _major(scope.db_version)
        if major is None or major < SCRAM_FROM:
            raise UnsupportedCapabilityError(
                SCRAM_VERIFIER,
                target=self.target.name,
                hint=(
                    f"PostgreSQL {scope.db_version} cannot store a SCRAM verifier, so the "
                    f"tool cannot set a password there without sending it; this needs "
                    f"PostgreSQL {SCRAM_FROM} or later, and the driver is tested on 13 to 18"
                ),
            )
        state = self.describe_user(account)
        if state is None:
            raise DriverError(
                f'role "{account}" does not exist on target "{self.target.name}"',
                hint=(
                    "the tool does not create roles (Q8); `creds check` reports this as "
                    "ACCOUNT_MISSING rather than failing"
                ),
            )
        return state

    def _send_password(self, role: str, secret: Secret, *, clear_valid_until: bool = False) -> None:
        """Compute the verifier and send the one ``ALTER ROLE``. A failure once
        the statement is handed over has ``password_sent`` set."""
        computed = verifier(self.connection.pgconn, role, secret)
        try:
            with self._cursor() as cursor:
                cursor.execute(alter_role(role, computed, clear_valid_until=clear_valid_until))
        except DriverError as error:
            error.password_sent = True
            raise
        LOG.debug(
            "ALTER ROLE %s PASSWORD <SCRAM-SHA-256 verifier>%s on %s",
            role,
            " VALID UNTIL 'infinity'" if clear_valid_until else "",
            self.target.name,
        )

    def suspend_account(self, account: str) -> AccountChange:
        """``ALTER ROLE … NOLOGIN``, or report that the role is already
        ``NOLOGIN`` (#1201).

        ``NOLOGIN`` blocks every authentication method, where a past ``VALID
        UNTIL`` stops only a password. A reset refuses a ``NOLOGIN`` role (H4),
        so a suspended role stays suspended until somebody runs ``ALTER ROLE …
        LOGIN``.

        **The state is read first** (invariant 9): measured on 13.23 to 18.6, a
        second ``NOLOGIN`` is accepted silently
        (``03_createrole_password_probe.sql``, CR8). From 16 the tool account
        needs ``ADMIN OPTION`` on the role, as for a password (CR7); without it
        the server answers 42501.

        Not gated by ``account_lock_state``, which a cluster does not report:
        that capability is also what lets UC-1's ``unlock_if_locked`` clear a
        lock, and every ``NOLOGIN`` here is somebody's decision.
        """
        require_read_write(self.scope(), target=self.target.name)
        state = self.describe_user(account)
        if state is None:
            raise DriverError(
                f'role "{account}" does not exist on target "{self.target.name}"',
                hint=(
                    "the tool does not create roles (Q8); nothing is suspended, and "
                    "the role name is worth checking against the estate"
                ),
            )
        if state.deliberately_locked:
            return AccountChange(
                ACCOUNT_LOCK,
                changed=False,
                status=state.status,
                detail="the role is already NOLOGIN",
            )
        with self._cursor() as cursor:
            cursor.execute(sql.SQL("ALTER ROLE {} NOLOGIN").format(sql.Identifier(state.name)))
        LOG.debug("ALTER ROLE %s NOLOGIN on %s", state.name, self.target.name)
        return AccountChange(
            ACCOUNT_LOCK,
            changed=True,
            status=state.status,
            detail=f"role was {state.status.lower()}; set NOLOGIN",
        )

    def reset_password(
        self, account: str, secret: Secret, *, expire: bool, keep_rollover: bool = False
    ) -> tuple[AccountChange, ...]:
        """UC-2 §4.1 on a cluster: one statement, reported as the three rows
        the protocol names (#1201).

        **Refusals come before anything is sent**, as on Oracle: a seen reset
        (``expire``), because PostgreSQL cannot make a role change its password
        at its next login, and that expiry is what ends the DBA's exposure; then
        :meth:`_role_to_set`'s; then a ``NOLOGIN`` role, which a person
        suspended (H4). PostgreSQL has no lock that a failed-login limit sets,
        so every ``NOLOGIN`` is deliberate.

        **A ``VALID UNTIL`` that has passed is cleared to ``infinity``** in the
        same ``ALTER ROLE`` as the password, so the two change together or not
        at all. A role past its date cannot log in with any password, and a
        reset exists to end that state, as Oracle's reset clears a timed lock. A
        date still to come is left alone. The first row reports it, in the
        place of Oracle's unlock.

        PostgreSQL has no rollover window, so the third row never issues
        anything, whatever ``keep_rollover`` says.
        """
        if expire:
            require_capability(
                self.scope(), EXPIRE_PASSWORD, target=self.target.name, hint=SEEN_NEEDS_EXPIRY
            )
        admit(secret)
        state = self._role_to_set(account)
        if state.deliberately_locked:
            raise DriverError(
                f'role "{state.name}" cannot log in (NOLOGIN), and a reset does not change that',
                hint=(
                    "NOLOGIN is somebody's decision -- `account suspend`, usually -- and "
                    "handing the role a working password would undo it silently. Run "
                    "ALTER ROLE … LOGIN first if that is what you mean (H4)"
                ),
            )
        self._send_password(state.name, secret, clear_valid_until=state.expired)
        if state.expired:
            cleared = AccountChange(
                ACCOUNT_UNLOCK,
                changed=True,
                status=state.status,
                detail="VALID UNTIL had passed; set to infinity with the password",
            )
        else:
            cleared = AccountChange(
                ACCOUNT_UNLOCK,
                changed=False,
                status=state.status,
                detail="the role can log in; VALID UNTIL has not passed",
            )
        return (
            cleared,
            AccountChange(PASSWORD_SET, changed=True, status=state.status, detail="password set"),
            AccountChange(
                ROLLOVER_FINISH,
                changed=False,
                status=state.status,
                detail="PostgreSQL has no rollover window",
            ),
        )

    def expire_password(self, account: str) -> tuple[AccountChange, ...]:
        """Refused by capability: PostgreSQL cannot make a role change its
        password at its next login (#1201). The command refuses at plan time;
        this is the refusal for a target whose scope plan time could not read."""
        require_capability(
            self.scope(), EXPIRE_PASSWORD, target=self.target.name, hint=EXPIRY_UNAVAILABLE
        )
        return ()  # pragma: no cover -- the capability is never reported

    def audit_coverage(self, account: str) -> AuditCoverage:
        """Never raises, as the protocol promises: the answer is unknown."""
        return AuditCoverage(
            audited=None, detail="the PostgreSQL driver does not read audit settings yet"
        )

    def apply_attributes(
        self, account: str, attributes: AccountAttributes
    ) -> tuple[AttributeChange, ...]:
        raise self._not_written("enforce a role's attributes")

    def resolve_profile(self, profile: str) -> str | None:
        """Refused by capability: PostgreSQL has no profiles, so a `profile:`
        predicate names nothing on a cluster."""
        require_capability(
            self.scope(), PROFILE_MANAGEMENT, target=self.target.name, hint=NO_PROFILES
        )
        return None  # pragma: no cover -- the capability is never reported

    def resolve_role(self, role: str) -> str | None:
        """The role as ``pg_roles`` spells it, or ``None``
        (:func:`~sopuli.driver.postgres.roles.resolve_role`). ``pg_roles`` is
        open to every role, so :data:`ROLE_LOOKUP` is always reported."""
        require_capability(self.scope(), ROLE_LOOKUP, target=self.target.name)
        with self._cursor() as cursor:
            return roles.resolve_role(cursor, role, target=self.target.name)

    def accounts_matching(
        self, *, profile: str | None = None, role: str | None = None
    ) -> tuple[str, ...]:
        """Every role that is a member of ``role`` by grants with ``INHERIT`` or
        ``SET`` (:func:`~sopuli.driver.postgres.roles.members_of`). A
        ``profile`` is refused as :meth:`resolve_profile` refuses it."""
        if (profile is None) == (role is None):
            raise ValueError("accounts_matching takes exactly one of `profile` and `role`")
        if profile is not None:
            self.resolve_profile(profile)
            return ()  # pragma: no cover -- resolve_profile always raises
        assert role is not None
        spelled = self.resolve_role(role)
        if spelled is None:
            return ()
        with self._cursor() as cursor:
            return members_of(cursor, spelled)

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
        (:mod:`sopuli.driver.postgres.verification`).

        ``login`` only. ``hash`` and ``both`` need ``offline_verify``, which
        this driver never reports: the verifiers are in ``pg_authid``, which
        only a superuser reads. :meth:`require_verifier` refuses them at plan
        time, and this refuses them again, and any other method, rather than
        log in in their place.

        A role that does not exist is :data:`~sopuli.driver.protocol.UNAVAILABLE`
        before any login, as on Oracle: the server would answer its login as a
        wrong password. PostgreSQL has no failed-login lockout, so
        ``lockout_margin`` and ``attempts`` have nothing to guard, and the
        result carries no counter. The login uses the target's ``sslmode``,
        timeouts and ``application_name``, as :meth:`PostgresDriver.connect`
        does, and asks for SCRAM. A libpq older than 16 cannot ask, so the
        login is refused before anything is sent.
        """
        if method in (VERIFY_HASH, VERIFY_BOTH):
            self.require_verifier(account, secret)
        if method != VERIFY_LOGIN:
            raise UnsupportedCapabilityError(
                f"verification method {method!r}",
                target=self.target.name,
                hint="this driver verifies by `login` only",
            )
        major, minor = libpq_release(pq.version())
        if major < REQUIRE_AUTH_FROM:
            raise DriverError(
                f"libpq {major}.{minor} cannot require SCRAM, so the tool will not log in "
                f'as "{account}" on target "{self.target.name}" with its password',
                hint=f"install a psycopg wheel that bundles libpq {REQUIRE_AUTH_FROM} or later",
            )
        role = self.describe_user(account)
        # The server would answer each of these as a wrong password, or as a
        # refusal no different from a missing pg_hba.conf line, so none is tried.
        if role is None:
            return _not_tried(f'there is no role "{account}" on this target')
        if role.locked:
            return _not_tried(f"the role cannot log in ({role.status}); no login was attempted")
        if role.expired:
            return _not_tried("the role's VALID UNTIL has passed; no login was attempted")
        account = role.name
        arguments = connect_arguments(
            self.target,
            Credential(username=account, secret=secret),
            correlation_id=self.correlation_id,
            timeouts=self.timeouts,
        )
        arguments["require_auth"] = REQUIRED_METHOD
        started = time.monotonic()
        try:
            connection = psycopg.connect(**arguments)
        except psycopg.Error as error:
            latency = _ms(started)
            failure = from_error(error, connecting=True)
            LOG.debug("login as %s failed with %s in %.3fs", account, failure.code, latency / 1000)
            outcome = login_outcome(failure)
            if outcome is None:
                raise failure.as_error() from error
            result, detail = outcome
            return VerifyResult(
                method=VERIFY_LOGIN, result=result, latency_ms=latency, detail=detail
            )
        latency = _ms(started)
        # The login has answered. A socket that drops as it closes does not
        # change the answer.
        with suppress(psycopg.Error):
            connection.close()
        LOG.debug("login as %s: pass in %.3fs", account, latency / 1000)
        return VerifyResult(method=VERIFY_LOGIN, result=PASS, latency_ms=latency)

    def require_verifier(self, account: str, secret: Secret) -> None:
        """Refuse ``hash`` and ``both`` at plan time (invariant 4): this driver
        never reports ``offline_verify``."""
        require_capability(
            self.scope(),
            OFFLINE_VERIFY,
            target=self.target.name,
            hint=(
                "the verifiers are in pg_authid, which only a superuser reads; "
                "use --method login, the default"
            ),
        )

    def require_rollover(self, account: str) -> None:
        """PostgreSQL has no password rollover, so this always refuses
        (invariant 4)."""
        require_capability(
            self.scope(),
            PASSWORD_ROLLOVER,
            target=self.target.name,
            hint=(
                "PostgreSQL keeps one password per role, so there is no window to open: "
                "use --strategy staged, or leave --strategy out"
            ),
        )

    def finish_rollover(self, account: str) -> ChangeResult:
        """A role never has a window, so there is none to end (invariant 4).
        `creds finish-rollover` settles every role before it gets here; this
        refuses by capability for any other caller."""
        self.require_rollover(account)
        raise UnsupportedCapabilityError(PASSWORD_ROLLOVER, target=self.target.name)

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
        return PostgresSession(
            connection=connection,
            target=target,
            correlation_id=self.correlation_id,
            timeouts=self.timeouts,
        )


def _major(version: str | None) -> int | None:
    """The major release from ``server_version``'s first word: 16 from
    ``16.15``, 9 from ``9.6.24``, 18 from ``18beta1`` and 17 from ``17devel``.
    ``None`` where it does not start with a number, which refuses rather than
    guesses."""
    found = re.match(r"\d+", version or "")
    return int(found.group()) if found else None


def build_driver(context: DriverContext) -> PostgresDriver:
    """The registry's way in: a :class:`PostgresDriver` for this run. psycopg
    needs nothing from ``runtime``, since its wheel brings libpq."""
    return PostgresDriver(correlation_id=context.correlation_id, timeouts=context.timeouts)


def client_report(*, env: Mapping[str, str], runtime: Runtime) -> dict[str, Any]:
    """`doctor`'s client lines: psycopg, the libpq it loaded, and whether that
    libpq accepts ``require_auth``. Neither argument is read."""
    return client_lines(psycopg_version=psycopg.__version__, libpq_version=psycopg.pq.version())
