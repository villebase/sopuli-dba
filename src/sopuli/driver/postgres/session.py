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
``ALTER ROLE … NOLOGIN`` (:meth:`PostgresSession.suspend_account`). A reset
(:meth:`PostgresSession.reset_password`) sends the same password statement,
with a passed ``VALID UNTIL`` cleared to ``infinity`` in it. Those two
``ALTER ROLE`` statements are the only ones the driver sends that change
anything, and each checks
:func:`~sopuli.driver.postgres.scope.require_read_write` first. It also resolves
a `role:` predicate for `account list` (:meth:`PostgresSession.accounts_matching`).
It runs one operator's statement for `sql run` in a guarded transaction
(:meth:`PostgresSession.run_statement`, UC-3).
The registry entry lists the commands it is written for: UC-1's, UC-2's
`account list`, `reset-password`, `suspend` and `expire-password`, and UC-5's
`report accounts`, `report history` and `report privileges`, and UC-3's
`sql run`. What
PostgreSQL has no counterpart for, such as a rollover window, a profile, or an
expired password a role must change at login, is refused by capability, exit 5.
:meth:`PostgresSession.apply_attributes` is never reached, because a
capability check refuses the attributes it enforces first. If it is, it
raises :class:`~sopuli.driver.protocol.InternalFaultError`.
"""

from __future__ import annotations

import json
import logging
import re
import time
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager, suppress
from dataclasses import dataclass, field
from typing import Any, NoReturn

import psycopg
from psycopg import pq, sql
from psycopg.types.datetime import DateLoader, TimestampLoader, TimestamptzLoader
from psycopg.types.string import TextLoader

from sopuli.config.model import ExpandedTarget, Runtime
from sopuli.driver.grants import GrantSurvey
from sopuli.driver.postgres import roles
from sopuli.driver.postgres.client import REQUIRE_AUTH_FROM, client_lines, libpq_release
from sopuli.driver.postgres.connection import connect_arguments
from sopuli.driver.postgres.errors import (
    CONNECTION_FAILURE,
    INSUFFICIENT_PRIVILEGE,
    for_statement,
    from_error,
)
from sopuli.driver.postgres.grants import survey_grants
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
from sopuli.driver.postgres.survey import survey
from sopuli.driver.postgres.verification import REQUIRED_METHOD, login_outcome
from sopuli.driver.protocol import (
    ACCOUNT_LOCK,
    ACCOUNT_UNLOCK,
    EXPIRE_ON_RESET,
    EXPIRE_PASSWORD,
    EXPIRY_UNAVAILABLE,
    OFFLINE_VERIFY,
    OLD_DISCARD,
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
    ClosesConnection,
    Credential,
    DriverContext,
    DriverError,
    InternalFaultError,
    PrivilegeAudit,
    Scope,
    StatementResult,
    Timeouts,
    UnsupportedCapabilityError,
    UserState,
    VerifyResult,
    require_capability,
)
from sopuli.driver.registry import no_profiles_hint
from sopuli.driver.survey import SurveyedAccount
from sopuli.output.debug import logger
from sopuli.passwords import ByteLimit
from sopuli.secrets import Secret
from sopuli.sql.guard import RowGuard
from sopuli.sql.statement import Statement as RunStatement
from sopuli.sql.statement import StatementKind
from sopuli.sql.values import JsonValue, to_json

LOG = logger("postgres")

#: The hint for a `profile:` predicate on a cluster, the registry's, so
#: `account list`'s refusal with no connection says the same (#1598).
NO_PROFILES = no_profiles_hint("postgresql")


def _ms(started: float) -> int:
    """Milliseconds since ``started``, a :func:`time.monotonic` reading,
    truncated as the CLI's ``duration_ms`` is."""
    return int((time.monotonic() - started) * 1000)


def _not_tried(detail: str) -> VerifyResult:
    """A login :meth:`PostgresSession.verify_password` settled without trying."""
    return VerifyResult(method=VERIFY_LOGIN, result=UNAVAILABLE, detail=detail)


@dataclass
class PostgresSession(ClosesConnection):
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
    #: `sql run`'s: the role the login became, read once.
    _session_user: str | None = field(default=None, init=False, repr=False)
    #: `sql run`'s: a statement left the connection closed.
    _connection_lost: bool = field(default=False, init=False, repr=False)
    #: The words for two targets that are one cluster
    #: (:class:`~sopuli.driver.clusters.ClusterIdentity`). Not fields.
    identity_kind = "PostgreSQL cluster"
    identity_key = "system_identifier"
    identity_hint = (
        "declare each cluster once. A primary and its standbys share their "
        "roles, so one target covers them all. If one is a pg_basebackup copy "
        "or a promoted standby, a separate server, give each its own secret and "
        "run one of them per run with --target"
    )

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
            raise InternalFaultError.closed_session(self.target.name)
        try:
            with self.connection.cursor() as cursor:
                yield cursor
        except psycopg.Error as error:
            if error.sqlstate is None and not isinstance(error, psycopg.OperationalError):
                raise
            raise from_error(error).as_error() from error

    def _fault(self, what: str) -> NoReturn:
        raise InternalFaultError.unreachable_call(
            self.target.name,
            product="a PostgreSQL cluster",
            what=what,
            hint=(
                "PostgreSQL has no profiles, and the PostgreSQL driver cannot unlock or "
                "expire a role, so a capability check should have refused each of these "
                "before the call"
            ),
        )

    def describe_user(self, account: str) -> UserState | None:
        """The role from ``pg_roles``, or ``None`` if there is none
        (:mod:`sopuli.driver.postgres.roles`)."""
        with self._cursor() as cursor:
            return describe(cursor, account, target=self.target.name)

    def survey_with_profiles(self) -> tuple[tuple[SurveyedAccount, ...], frozenset[str]]:
        """Every role on the cluster, and no profiles: a cluster has none.

        :class:`~sopuli.driver.survey.AccountSurvey`, for `report accounts`
        (:mod:`sopuli.driver.postgres.survey`). The registry makes the profile
        check *not applicable* here, so the empty set reports nothing missing.
        """
        with self._cursor() as cursor:
            return survey(cursor), frozenset()

    def survey_privileges(self, accounts: Sequence[str], *, public: bool) -> GrantSurvey:
        """Every privilege ``accounts`` hold, with each path, for `report privileges`.

        :class:`~sopuli.driver.grants.PrivilegeSurvey`
        (:mod:`sopuli.driver.postgres.grants`). The catalogs it reads are open
        to every role, so it needs no grant and no capability. The cluster's
        other databases are named in ``unreadable`` and ``other_databases``.
        """
        with self._cursor() as cursor:
            return survey_grants(cursor, accounts, public=public)

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

    def set_password(
        self,
        account: str,
        secret: Secret,
        *,
        old_password: str = OLD_DISCARD,
        previous: Secret | None = None,
    ) -> ChangeResult:
        """``ALTER ROLE … PASSWORD`` with a verifier computed here (invariant 15).

        ``old_password`` is ignored: a role has one password.

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
                self.scope(), EXPIRE_ON_RESET, target=self.target.name, hint=SEEN_NEEDS_EXPIRY
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
        # Never reached, as a cluster never reports the capability. If one did,
        # a refusal is the safe answer: an empty tuple would read as "already
        # expired" with nothing issued.
        self._fault("expire a password")

    def audit_coverage(self, account: str) -> AuditCoverage:
        """Never raises, as the protocol promises: the answer is unknown."""
        return AuditCoverage(
            audited=None, detail="the PostgreSQL driver does not read audit settings yet"
        )

    def apply_attributes(
        self, account: str, attributes: AccountAttributes
    ) -> tuple[AttributeChange, ...]:
        self._fault("enforce a role's attributes")

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
        for_check: bool = False,
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

    def finish_rollover(self, account: str, *, current: Secret | None = None) -> ChangeResult:
        """A role never has a window, so there is none to end (invariant 4).
        `creds finish-rollover` settles every role before it gets here; this
        refuses by capability for any other caller."""
        self.require_rollover(account)
        raise UnsupportedCapabilityError(PASSWORD_ROLLOVER, target=self.target.name)

    # ------------------------------------------------------------ sql run ---

    @property
    def connection_lost(self) -> bool:
        """A statement left the connection closed. A timeout does not: the
        server cancels the statement and the session stays usable."""
        return self._connection_lost

    def session_user(self) -> str:
        """The role this session logged in as, read once and cached."""
        if self._session_user is None:
            with self._cursor() as cursor:
                cursor.execute("select session_user")
                self._session_user = str(cursor.fetchone()[0])
        return self._session_user

    def current_user(self) -> str:
        """The role statements run as. It differs from :meth:`session_user`
        where the login role has a default ``role`` (``ALTER ROLE … SET
        role``)."""
        with self._cursor() as cursor:
            cursor.execute("select current_user")
            return str(cursor.fetchone()[0])

    def member_of(self, account: str) -> bool:
        """Whether the login role, or the role its statements run as, is a
        member of ``account``, directly or through other roles, by ``upper()``
        (decision A of #1690). Every membership counts, whatever its
        ``INHERIT`` or ``SET`` option: a member without ``INHERIT`` can still
        take the role with ``set_config('role', …)``. A superuser is not
        counted, because it gains nothing from ``account``. But a superuser
        login whose default role is a member is refused, because its
        statements run as that member. ``pg_auth_members`` is readable by
        every role."""
        with self._cursor() as cursor:
            cursor.execute(MEMBERSHIP, (account,))
            return bool(cursor.fetchone()[0])

    def database_identity(self) -> tuple[str, str]:
        """``(system_identifier, current_database())``: the cluster and the
        database this session reached. Any role can read both by default
        (``12_statement_run_probe.py``). A site that revoked
        ``pg_control_system()`` is refused with a hint that names it: the plan
        fingerprint needs the cluster's identity, and nothing else names it."""
        try:
            with self._cursor() as cursor:
                cursor.execute(STATEMENT_IDENTITY)
                row = cursor.fetchone()
        except DriverError as error:
            if error.code == INSUFFICIENT_PRIVILEGE:
                error.hint = (
                    "the run-as account may not run pg_control_system(), which every "
                    "role may by default. The plan fingerprint reads the cluster's "
                    "system_identifier from it. Grant EXECUTE on it to the run-as account"
                )
            raise
        return str(row[0]), str(row[1])

    def check_write(self, statement: RunStatement, *, timeout_ms: int) -> None:
        """Nothing to refuse: every PostgreSQL table is transactional, so a
        rollback undoes the statement's change (UC-3 §3 names what it does
        not undo, such as ``dblink_exec()``)."""

    def run_statement(
        self,
        statement: RunStatement,
        *,
        guard: RowGuard | None,
        commit: bool,
        max_rows: int,
        timeout_ms: int,
    ) -> StatementResult:
        """Run one statement in a transaction that ends the way UC-3 says.

        A read runs in ``BEGIN READ ONLY``, so the server refuses a write that
        got past the keyword check, and is rolled back. A write is committed
        only when ``commit`` is true, the guard passes and a row matched; any
        other outcome rolls back. ``dblink_exec()`` and the like write through
        another connection, which neither covers (UC-3 §3).

        The statement is sent as written, with no bind, so that the server
        refuses a text that holds two statements with ``42601``. psycopg's
        plain ``execute`` would run them all (``12_statement_run_probe.py``).
        A read goes through a server-side cursor, so only the rows up to
        ``max_rows`` cross the network, and ``DECLARE`` takes one query. A
        write is a prepared statement.

        ``statement_timeout`` is ``timeout_ms`` for this transaction only, or
        the one the role or the session already has where that is lower; ``0``
        means no bound. It covers a lock wait too, so a write that waits on an
        application's row lock is cancelled with ``57014``, and the session
        stays usable. No timeout bounds the ``COMMIT``.

        A ``COMMIT`` the server refused with a SQLSTATE was rolled back. Only
        one whose connection was lost has ``commit_failed`` set, because it
        may still have taken effect. A transaction an earlier caller left open
        is rolled back first, so the read-only transaction is a new one.
        ``json`` and ``jsonb`` are read as the server's text, so a number in
        one is not rounded to a float.
        """
        if commit and guard is None:
            raise ValueError("run_statement commits only with a row guard")
        self._refuse_if_lost()
        read = statement.kind is StatementKind.READ
        begun = committed = committing = False
        try:
            if self.connection.info.transaction_status != pq.TransactionStatus.IDLE:
                self.connection.execute("rollback")
            with self.connection.cursor() as control:
                control.execute("begin read only" if read else "begin")
                begun = True
                bound = _bound(timeout_ms, _session_timeout_ms(control))
                control.execute(f"set local statement_timeout = {bound}")
                if not read:
                    control.execute(statement.text, prepare=True)
                    count = control.rowcount
                    passed = None if guard is None else guard.passes(count)
                    if commit and passed is not False and count > 0:
                        committing = True
                        control.execute("commit")
                        committed = True
                    return StatementResult((), (), count, False, committed, passed)
            with self.connection.cursor(name="sopuli_sql_run") as rows:
                for name, loader in _READ_LOADERS:
                    rows.adapters.register_loader(name, loader)
                rows.execute(statement.text)
                return _read_result(rows, max_rows)
        except psycopg.Error as error:
            self._connection_lost = bool(self.connection.closed)
            unanswered = error.sqlstate is None
            if unanswered and not committing and not isinstance(error, psycopg.OperationalError):
                raise
            raised = for_statement(from_error(error), read=read).as_error()
            # A COMMIT the server answered with a SQLSTATE was rolled back. One
            # it did not answer, or whose connection was lost, may have taken effect.
            raised.commit_failed = committing and (unanswered or self._connection_lost)
            raise raised from error
        finally:
            if begun and not committed and not self.connection.closed:
                with suppress(psycopg.Error):
                    self.connection.execute("rollback")

    def _refuse_if_lost(self) -> None:
        """Refuse to send on a connection a statement left closed, or on one
        where psycopg would not prepare a write. With ``prepare_threshold``
        ``None``, psycopg ignores ``prepare=True`` and sends the text with the
        simple protocol, which runs every statement in it."""
        if self.connection is None:
            raise InternalFaultError.closed_session(self.target.name)
        if self.connection.prepare_threshold is None:
            raise InternalFaultError(
                f'the session to target "{self.target.name}" has prepared statements turned '
                "off, so the server would run every statement in a write's text",
                hint="this is a fault in sopuli: `sql run` needs psycopg to prepare a write",
            )
        if self._connection_lost or self.connection.closed:
            raise DriverError(
                f"{CONNECTION_FAILURE}: the connection was closed under an earlier statement",
                hint="close this session and open another",
                code=CONNECTION_FAILURE,
            )


#: Whether the login role or the current role, where it is not a superuser,
#: is a member of the role named by the parameter, through any chain of
#: memberships (#1690). The name is a role name from the config, never a
#: password, so it is bound.
MEMBERSHIP = """
with recursive granted(start, roleid) as (
    select r.rolname, m.roleid
      from pg_auth_members m
      join pg_roles r on r.oid = m.member
     where r.rolname in (session_user, current_user)
    union
    select g.start, m.roleid
      from pg_auth_members m
      join granted g on m.member = g.roleid
)
select exists (select 1
                 from granted g
                 join pg_roles s on s.rolname = g.start
                 join pg_roles r on r.oid = g.roleid
                where not s.rolsuper
                  and upper(r.rolname) = upper(%s))
"""

#: What `sql run` reads to tell one database from another (UC-3 §4).
STATEMENT_IDENTITY = "select system_identifier::text, current_database() from pg_control_system()"


def _session_timeout_ms(cursor: Any) -> int:
    """The ``statement_timeout`` in force before `sql run` sets one, in
    milliseconds: the role's, the database's or the session's. ``0`` is none."""
    cursor.execute("select setting::bigint from pg_settings where name = 'statement_timeout'")
    return int(cursor.fetchone()[0])


def _bound(requested_ms: int, existing_ms: int) -> int:
    """The lower of two timeouts, where ``0`` means no bound."""
    if requested_ms == 0 or existing_ms == 0:
        return max(requested_ms, existing_ms)
    return min(requested_ms, existing_ms)


#: The longest text or ``bytea`` value `sql run` returns, in characters or
#: bytes, as Oracle's LOB limit. A longer one is cut.
VALUE_LIMIT = 4000


def _plain(value: Any) -> Any:
    """A JSON value or array, with every scalar in it in JSON form."""
    if isinstance(value, dict):
        return {str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, list | tuple):
        return [_plain(item) for item in value]
    return to_json(value)


def _cell(value: Any) -> tuple[JsonValue, bool]:
    """One fetched value in JSON form, and whether it was cut to get there.

    An array and a record come back as JSON text; ``json`` and ``jsonb``
    arrive as text already. Any other type is
    :func:`~sopuli.sql.values.to_json`'s: ``uuid``, ``inet`` and a range
    become their text form. A ``bytea`` longer than :data:`VALUE_LIMIT` bytes
    is cut before it becomes hex, as Oracle's ``RAW`` LOB is, and any text
    form longer than :data:`VALUE_LIMIT` characters is cut.
    """
    if isinstance(value, dict | list | tuple):
        value = json.dumps(_plain(value), ensure_ascii=False)
    if isinstance(value, bytes) and len(value) > VALUE_LIMIT:
        return to_json(value[:VALUE_LIMIT]), True
    converted = to_json(value)
    if isinstance(converted, str) and len(converted) > VALUE_LIMIT:
        return converted[:VALUE_LIMIT], True
    return converted, False


class _DateOrText(DateLoader):
    """A ``date``, or the server's text where no Python date holds it:
    ``infinity``, ``-infinity``, a BC date or a year past 9999. psycopg
    raises a ``DataError`` with no SQLSTATE for those."""

    def load(self, data: Any) -> Any:
        try:
            return super().load(data)
        except psycopg.DataError:
            return bytes(data).decode()


class _TimestampOrText(TimestampLoader):
    """A ``timestamp``, or the server's text, as :class:`_DateOrText`."""

    def load(self, data: Any) -> Any:
        try:
            return super().load(data)
        except psycopg.DataError:
            return bytes(data).decode()


class _TimestamptzOrText(TimestamptzLoader):
    """A ``timestamptz``, or the server's text, as :class:`_DateOrText`. A
    role's ``VALID UNTIL 'infinity'``, which `account reset-password` sets, is
    one."""

    def load(self, data: Any) -> Any:
        try:
            return super().load(data)
        except psycopg.DataError:
            return bytes(data).decode()


#: The loaders a read's cursor uses in place of psycopg's: JSON as the
#: server's text, so a number in it is not rounded to a float, and dates
#: and times that fall back to the server's text where Python has no value.
_READ_LOADERS: tuple[tuple[str, type], ...] = (
    ("json", TextLoader),
    ("jsonb", TextLoader),
    ("date", _DateOrText),
    ("timestamp", _TimestampOrText),
    ("timestamptz", _TimestamptzOrText),
)


def _read_result(cursor: Any, max_rows: int) -> StatementResult:
    """The rows of a query, at most ``max_rows`` of them."""
    columns = tuple(column.name for column in cursor.description)
    fetched = cursor.fetchmany(max_rows + 1)
    truncated = len(fetched) > max_rows
    rows: list[tuple[JsonValue, ...]] = []
    for row in fetched[:max_rows]:
        cells = [_cell(value) for value in row]
        truncated = truncated or any(cut for _, cut in cells)
        rows.append(tuple(value for value, _ in cells))
    return StatementResult(columns, tuple(rows), len(rows), truncated, False, None)


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
