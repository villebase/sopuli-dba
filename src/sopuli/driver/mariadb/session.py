"""Connecting to a MariaDB server, and reporting what it is.

The module :data:`sopuli.driver.registry.DRIVERS` imports for ``type: mariadb``.
It imports ``pymysql`` at module scope, so a machine without the ``mariadb``
extra gets ``SOPULI-20002`` from the registry rather than a traceback (ADR-006
rule 1). The modules beside it are tier 0.

**What this build does** (#1268). It connects through
:mod:`sopuli.driver.mysql_family`, labels the session with the run's
correlation id, checks that a mode which requires TLS got it, and reports the
scope: ``server``, whether it takes writes, its encryption, and
:data:`CAPABILITIES`. For ``doctor --check-privileges`` it audits the tool
account's grants (:mod:`~sopuli.driver.mariadb.privileges`) and surveys the
declared accounts (:mod:`~sopuli.driver.mariadb.accounts`). It describes a
declared account, with the privileges guardrail 9 checks and the roles it
holds, sets its password by the value its plugin stores and verifies it by
login (#1270). It resolves a role and lists its members, suspends an account,
resets its password and expires it (#1272). It opens a rollover by sending
the new and the old value joined by ``OR``, and finishes it by sending the
current value alone (#1271). The registry lists `doctor`, UC-1's `creds
generate`, `apply`, `check`, `rotate` and `status`, and UC-2's four verbs.
Every other method refuses with ``SOPULI-20006``.

The session names its server by ``@@server_uid``, so the CLI refuses two
targets that are one server, as on MySQL (#1286). MariaDB has no
``server_uuid``, and ``@@server_uid`` changes at each restart: it identifies a
server only within one run.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, replace
from typing import Any, ClassVar, NoReturn, TypeVar

import pymysql

from sopuli.config.model import ExpandedTarget, Runtime
from sopuli.driver.clusters import Identity
from sopuli.driver.mariadb import accounts as accounts_module
from sopuli.driver.mariadb import password as password_module
from sopuli.driver.mariadb import roles, verification
from sopuli.driver.mariadb.errors import from_error
from sopuli.driver.mariadb.limits import LIMIT
from sopuli.driver.mariadb.privileges import audit as privilege_audit
from sopuli.driver.mariadb.scope import observe, read_password_checks, require_read_write
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
    OLD_RETAIN,
    PASSWORD_EXPIRE,
    PASSWORD_ROLLOVER,
    PASSWORD_SET,
    PASSWORD_VALUE,
    PROFILE_MANAGEMENT,
    ROLE_LOOKUP,
    UNAVAILABLE,
    VERIFY_BOTH,
    VERIFY_HASH,
    VERIFY_LOGIN,
    AccountChange,
    AuditCoverage,
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
    password_value_hint,
    require_capability,
)
from sopuli.driver.registry import NotWrittenError
from sopuli.output.debug import logger
from sopuli.passwords import ByteLimit
from sopuli.secrets import Secret

LOG = logger("mariadb")

#: What a rollover does not do on an ``ed25519`` account: PyMySQL uses only the
#: first method of an ``ed25519`` ``OR``, which is the new password
#: (``11_rollover_expiry_probe.py``, RE5). Other clients, and PyMySQL on
#: ``mysql_native_password``, use both (#1271, decision 4).
ED25519_ROLLOVER = (
    "the account uses ed25519, so a PyMySQL client cannot log in with the old "
    "password while the rollover is open; other clients can"
)


def _rollover_caveat(plugin: str) -> str | None:
    """:data:`ED25519_ROLLOVER` for an ``ed25519`` account, else ``None``."""
    return ED25519_ROLLOVER if plugin == password_module.ED25519 else None


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

#: The capabilities every MariaDB session reports, with no query behind them
#: because each holds on every supported release:
#:
#: - ``role_lookup``: a role is a row of the view, its grants are in
#:   ``mysql.roles_mapping``, and §2.1 grants the tool account both;
#: - ``expire_password``: an account with only ``CREATE USER`` expires another
#:   on 10.11.19 to 12.3.3 (``04_lock_expiry_probe.py``, LK3), and a new value
#:   sent alone ends an expiry (``11_rollover_expiry_probe.py``). It also tells
#:   `creds apply` it may set a password on an expired account, as on MySQL
#:   (:func:`sopuli.apply.settled_before_acting`'s ``expiry_cleared``);
#: - ``password_rollover``: two methods joined by ``OR`` both log in, on
#:   10.11.19 to 12.3.3 (``03_dual_password_probe.py``, DP2). The tool opens
#:   the window itself (#1271), and cannot read whether one is open.
CAPABILITIES = frozenset({ROLE_LOOKUP, EXPIRE_PASSWORD, PASSWORD_ROLLOVER})

#: The server refused a read of a table (``1142``) or a column (``1143``).
REFUSED_READ = frozenset({str(TABLE_ACCESS_DENIED), str(COLUMN_ACCESS_DENIED)})

#: The answers to the password checks read (#1310) that leave
#: ``password_value`` out rather than fail the session: a refused read, and
#: an unknown system variable (``1193``) on a server without it.
CHECKS_UNREADABLE = REFUSED_READ | {"1193"}

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

#: The gap in what the tool reads that ``02-mariadb-privileges.md`` §4
#: accepts (decisions/log.md #1301): said with :data:`CHECK_9_GAP`, for the same
#: reason. The view shows one method of an account that has two.
OR_GAP = (
    "a declared account with a second login method, joined by OR, shows one of them: "
    "the mysql.user view does not show the other. A password change sends one method "
    "and ends the other, so a login by unix_socket, for example, stops working. "
    "Check SHOW CREATE USER for accounts the tool manages (02-mariadb-privileges.md "
    "section 4)"
)

#: What ``doctor --check-privileges`` says last for a target with declared
#: accounts, whether or not the survey's read succeeded.
ACCOUNT_GAPS = (CHECK_9_GAP, OR_GAP)

T = TypeVar("T")


def _nothing(what: str) -> str:
    """The hint for an account a UC-2 verb found missing; ``what`` is the
    verb's participle."""
    return (
        f"the tool does not create accounts (Q8); nothing is {what}, and the account "
        "name is worth checking against the server"
    )


#: The server's identity for the one-server check (#1286). Not the status
#: variable: ``SHOW STATUS LIKE 'server_uid'`` returns no row (probe 13, SI1).
SERVER_UID = "select @@global.server_uid"


def _server_uid(cursor: Any) -> str:
    cursor.execute(SERVER_UID)
    return str(cursor.fetchone()[0])


#: A Galera node's cluster, for the same check (#1346). Each node has its own
#: ``@@server_uid``, and ``wsrep_cluster_state_uuid`` is the value one cluster's
#: nodes share; an account with only ``CREATE USER`` reads it, and a server
#: without Galera answers it empty (probe 14, GI1 to GI6).
WSREP_STATE = (
    "show global status where variable_name in "
    "('wsrep_cluster_state_uuid', 'wsrep_local_state_comment')"
)


def _wsrep_state(cursor: Any) -> tuple[str, str]:
    """The cluster's UUID and the node's state, each ``""`` where the server
    has no such row, as a MariaDB built without Galera has none, or answers
    NULL. A value that comes as bytes is decoded, so it is never read as its
    ``b'...'`` text."""
    cursor.execute(WSREP_STATE)
    found = {_text(name).lower(): _text(value) for name, value in cursor.fetchall()}
    return found.get("wsrep_cluster_state_uuid", ""), found.get("wsrep_local_state_comment", "")


def _text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes | bytearray):
        return value.decode("utf-8", errors="replace")
    return str(value)


#: The words for two targets on nodes of one Galera cluster (#1346).
GALERA_KIND = "Galera cluster"
GALERA_KEY = "wsrep_cluster_state_uuid"
GALERA_HINT = (
    "declare each cluster once: its nodes share their accounts, so one target "
    "covers them all. If they are two clusters, one started from a copy of the "
    "other's data, they can share the UUID: give each its own secret and run one "
    "of them per run with --target"
)


@dataclass
class MariadbSession(ClosesConnection):
    """One open connection to a MariaDB server. Implements the
    :class:`~sopuli.driver.protocol.Session` methods `doctor` uses, and those
    the module docstring names; every other one refuses with
    ``SOPULI-20006``."""

    #: ``creds apply`` and ``creds rotate`` do not log in before a change, as
    #: on MySQL (#1270, decision 4). During a rotation that login fails once,
    #: and a failure counts toward ``max_password_errors``, which the tool
    #: cannot read. Whether a new password clears the block it sets (``4150``)
    #: is not measured. So the login after a change is the only one a change
    #: makes. Not on the protocol: a driver without it logs in.
    verifies_before_change: ClassVar[bool] = False

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
    #: The password validation plugins that refuse the driver's value, read
    #: with the scope (#1310); ``None`` where that read failed.
    _password_checks: tuple[str, ...] | None = field(default=None, init=False, repr=False)
    #: Why that read failed, for the refusal's hint.
    _checks_unread: str | None = field(default=None, init=False, repr=False)
    #: Why :meth:`shared_identity` found no cluster on a Galera node, or
    #: ``None``. An account with only ``CREATE USER`` reads ``@@server_uid``
    #: and the wsrep status (probe 13, SI1; probe 14, GI1).
    identity_caveat: str | None = field(default=None, init=False, repr=False)
    #: The words for two targets that are one server
    #: (:class:`~sopuli.driver.clusters.ClusterIdentity`), as on MySQL. Not
    #: fields.
    identity_kind = "MariaDB server"
    identity_key = "server_uid"
    identity_hint = (
        "declare each server once: two targets on one server would change its "
        "accounts under two names"
    )

    def cluster_identity(self) -> str | None:
        """The server's ``@@server_uid``, which the CLI uses to refuse two
        targets that are one server (#1286). Any account reads it. It differed
        on every server measured, a replica and its primary included, even
        one with the primary's hostname (probe 13, SI3 to SI5).

        It changes when the server restarts (SI2). The CLI compares identities
        only within one run, so a restart during a run can miss two targets
        on one server."""
        return self._read(_server_uid)

    def shared_identity(self) -> Identity | None:
        """On a Galera node, the cluster's ``wsrep_cluster_state_uuid``,
        claimed beside :meth:`cluster_identity` (#1346). A cluster's nodes
        share their accounts, and each has its own ``@@server_uid``.

        The UUID was shared by every node, differed between two clusters
        started from empty data, and survived a node's restart and the whole
        cluster's (probe 14, GI2 to GI5). A cluster started from a copy of
        another's data was not measured, and would be expected to keep the
        UUID: that refuses two targets, and never lets two through.

        Only a node that is ``Synced`` was measured, so a node in another
        state, such as one joining or serving a state transfer, gives no
        cluster, and :attr:`identity_caveat` says so. Its server is still
        claimed, so two targets on that one node are still refused."""
        cluster, state = self._read(_wsrep_state)
        if not cluster:
            return None
        if state != "Synced":
            self.identity_caveat = (
                f"this Galera node is {state or 'in an unknown state'}, not Synced, so "
                "it is known by its server alone: another target on a node of its "
                "cluster is not refused"
            )
            return None
        return Identity(cluster, GALERA_KIND, GALERA_KEY, GALERA_HINT)

    def scope(self) -> Scope:
        """What this session is: a server, read-write or not, and its
        encryption. Probed on the first call and cached (invariant 3).

        ``password_value`` is added where :func:`read_password_checks` finds
        no plugin that would refuse the value. That read is apart from the
        rest: where it fails, the capability is absent, so only the verbs that
        send a password are refused, and the others run (#1310)."""
        if self._scope is None:
            observed = self._read(
                lambda cursor: observe(cursor, target=self.target.name, encryption=self.encryption)
            )
            try:
                self._password_checks = self._read(read_password_checks)
            except DriverError as error:
                # Only a refused read, or a variable this server lacks: a
                # lost connection or a timeout is the run's fault to report.
                if error.code not in CHECKS_UNREADABLE:
                    raise
                self._checks_unread = str(error)
            takes_value = self._password_checks == ()
            capabilities = observed.capabilities | CAPABILITIES
            if takes_value:
                capabilities |= {PASSWORD_VALUE}
            self._scope = replace(observed, capabilities=capabilities)
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
        line says why, as on MySQL. With any declared account, the last lines
        say what check 9 cannot see (:data:`CHECK_9_GAP`) and that a second
        login method is not seen (:data:`OR_GAP`). Where the scope lacks
        ``password_value``, a line says why, with or without declared accounts
        (#1310)."""
        audit = self._read(privilege_audit)
        refused = self._password_value_line()
        if refused is not None:
            audit = replace(audit, remedies=(*audit.remedies, refused))
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
                    *ACCOUNT_GAPS,
                ),
            )
        return replace(audit, remedies=(*audit.remedies, *lines, *ACCOUNT_GAPS))

    def _not_written(self, what: str, *, hint: str | None = None) -> NoReturn:
        raise NotWrittenError(
            self.target.name,
            product="a MariaDB server",
            what=what,
            hint=hint
            or (
                "the MariaDB driver runs `doctor`, the `creds` commands and the `account` "
                "commands, and applies no account attributes"
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
        A password validation plugin does not shape the draw either: it sees no
        password, only the value, and under strict validation it refuses the
        value whatever the password, which the scope reports as a missing
        ``password_value`` (#1310)."""

    def set_password(
        self,
        account: str,
        secret: Secret,
        *,
        old_password: str = OLD_DISCARD,
        previous: Secret | None = None,
    ) -> ChangeResult:
        """``ALTER USER … IDENTIFIED VIA <plugin> USING '<value>'``, with the
        value for the account's own plugin computed here (invariant 15,
        :mod:`~sopuli.driver.mariadb.password`).

        ``old_password`` says what happens to the password the account had.
        MariaDB keeps no second password beside a change: the statement
        names its methods, and they replace every method the account had
        (``03_dual_password_probe.py``, DP3). So the tool sends the old
        password's value again where it is to keep working (#1271).
        ``previous`` is that password, the one the vault's document says the
        account had.

        * ``discard``: the new value alone, so only the vault's password logs
          in. It ends a second password a rollover kept, and also a second
          method of another kind, such as ``unix_socket``, which the view does
          not show. That gap is accepted (``02-mariadb-privileges.md`` §4,
          #1301), and ``doctor`` says so (:data:`OR_GAP`).
        * ``retain``: the new value ``OR`` ``previous``'s, new first
          (:func:`~sopuli.driver.mariadb.password.alter_user_rollover`). Both
          log in until :meth:`finish_rollover`.
        * ``keep``: the same statement. A rollover's ``pending`` that `creds
          apply` sets again while its promotion is held must keep the window
          open, and nothing else keeps it.

        Either way, on an ``ed25519`` account the result carries
        :data:`ED25519_ROLLOVER` as its ``caveat``.

        As on the other drivers, ``changed`` is ``True`` whenever the statement
        succeeded: the command decides first whether the account already had
        this password.

        Refused before anything is sent, with ``password_sent`` left ``False``:
        ``retain`` or ``keep`` without ``previous``, a password the target
        cannot take, a read-only session, an account that does not exist, and
        one on another plugin. Once the statement is handed to the server, a
        failure has ``password_sent`` set. What crossed is the value, which
        still allows an offline guess.
        """
        if old_password not in OLD_PASSWORD_MODES:
            raise ValueError(f"not an old-password mode: {old_password!r}")
        keeps_old = old_password != OLD_DISCARD
        if keeps_old and previous is None:
            raise self._not_passed("previous", account)
        password_module.admit(secret)
        if keeps_old and previous is not None:
            password_module.admit(previous)
        require_read_write(self.scope(), target=self.target.name)
        self._require_password_value()
        found = self._existing(
            account,
            hint=(
                "the tool does not create accounts (Q8); `creds check` reports this "
                "as ACCOUNT_MISSING rather than failing"
            ),
        )
        if keeps_old and previous is not None:
            statement = password_module.alter_user_rollover(
                found.user, found.host, found.plugin, secret, previous
            )
        else:
            statement = password_module.alter_user(found.user, found.host, found.plugin, secret)
        try:
            # The read above found the session open, so a failure here is the
            # server's answer to the statement.
            self._read(lambda cursor: cursor.execute(statement), scrub=password_module.scrub)
        except DriverError as failure:
            failure.password_sent = True
            raise
        if keeps_old:
            LOG.debug("password set for %s on %s, old password kept", found.name, self.target.name)
            return ChangeResult(
                changed=True,
                detail="password set; the old password logs in too",
                retained=old_password == OLD_RETAIN,
                caveat=_rollover_caveat(found.plugin),
            )
        LOG.debug("password set for %s on %s", found.name, self.target.name)
        return ChangeResult(changed=True, detail="password set", discarded=True)

    def _password_value_line(self) -> str | None:
        """`doctor`'s line for a scope without ``password_value``, or ``None``
        where the server takes the value (#1310)."""
        if self.scope().supports(PASSWORD_VALUE):
            return None
        if self._password_checks is None:
            return (
                "strict_password_validation and the password validation plugins could not "
                f"be read ({self._checks_unread}), so the verbs that set a password refuse "
                "this target"
            )
        return (
            f"{', '.join(self._password_checks)} refuses every password value the tool "
            "sends while strict_password_validation is ON, so the verbs that set a "
            "password refuse this target; set strict_password_validation=OFF to manage "
            "passwords here (02-mariadb-privileges.md section 6)"
        )

    def _require_password_value(self) -> None:
        """Refuse before a value is sent where a password validation plugin
        would refuse it (#1310). The command refuses the target at plan time;
        this is the driver's own line, on the connection that sends."""
        scope = self.scope()
        if scope.supports(PASSWORD_VALUE):
            return
        hint = (
            password_value_hint(self._password_checks)
            if self._password_checks is not None
            else (
                "strict_password_validation and the password validation plugins could not "
                f"be read ({self._checks_unread}), so nothing says the server takes the "
                "value the tool computes"
            )
        )
        require_capability(scope, PASSWORD_VALUE, target=self.target.name, hint=hint)

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
        found = self._existing(account, hint=_nothing("suspended"))
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

    def _existing(self, account: str, *, hint: str) -> accounts_module.Account:
        """The account's row in the view, refused before anything is sent where
        it does not exist, with ``hint``, or uses another plugin."""
        found = self._read_grants(
            lambda cursor: accounts_module.read_one(cursor, account, target=self.target.name)
        )
        if found is None:
            raise DriverError(
                f'account "{account}" does not exist on target "{self.target.name}"', hint=hint
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
        working too: that gap is accepted for personal accounts as for
        application ones (``02-mariadb-privileges.md`` §4, #1301, #1317). The
        tool cannot see whether an account has one, so the command warns at
        plan time (`SOPULI-W065`) and the row says that any other method stops
        working.

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
        self._require_password_value()
        found = self._existing(account, hint=_nothing("reset"))
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
                    "login method. Any other method, such as unix_socket, stops working; the "
                    "tool cannot see one. Whether the account is locked cannot be read on "
                    "MariaDB, and a reset does not unlock it"
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
        # Always reported (CAPABILITIES); the driver's own line all the same.
        require_capability(self.scope(), EXPIRE_PASSWORD, target=self.target.name)
        found = self._existing(account, hint=_nothing("expired"))
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

    def audit_coverage(self, account: str) -> AuditCoverage:
        """Never raises, as the protocol promises: the answer is unknown, as
        on MySQL. An unseen reset asks it."""
        return AuditCoverage(
            audited=None, detail="the MariaDB driver does not read audit settings yet"
        )

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

        The tool logs in only where no other account can answer the login
        (:func:`~sopuli.driver.mariadb.verification.competitor`), as on MySQL.
        Any other account is :data:`~sopuli.driver.protocol.UNAVAILABLE`
        without a login, as is one that does not exist: a failed login counts
        toward ``max_password_errors`` on the account it reaches, and `creds
        check` and `creds apply` repeat (#1270, decision 3). Such a result has
        ``attempted`` unset, which is what lets `creds apply` make the one
        reaching login of :meth:`verify_reaching` instead.

        The tool cannot read MariaDB's count of failed logins, so
        ``lockout_margin`` and ``attempts`` have nothing to guard, and the
        detail of every login says so.
        """
        if method in (VERIFY_HASH, VERIFY_BOTH):
            self.require_verifier(account, secret)
        if method != VERIFY_LOGIN:
            raise UnsupportedCapabilityError(
                f"verification method {method!r}",
                target=self.target.name,
                hint="this driver verifies by `login` only",
            )
        return self._verify(account, secret, reach=False)

    def verify_reaching(self, account: str, secret: Secret) -> VerifyResult:
        """The one login after a change from a staged ``pending`` that may
        reach further (#1270, decision 5): where :meth:`verify_password` did
        not log in because another account could answer, it logs in wherever
        the login reaches, and passes only where ``CURRENT_USER()`` is the
        declared account (#1267, decision 8). A refusal then says nothing,
        because another account may have sent it.

        Not on the protocol. `creds apply` asks it of a driver that has it,
        in place of a login and never after one, and only once it has written
        the vault mark that spends this ``pending``'s reach on this target
        (#1316). It may reach an account the config does not declare, the one
        exception to invariant 5, which CLAUDE.md records.
        """
        return self._verify(account, secret, reach=True)

    def _verify(self, account: str, secret: Secret, *, reach: bool) -> VerifyResult:
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
        competing = verification.competitor(declared, found[user], found[""])
        if competing is not None and not reach:
            return VerifyResult(
                method=VERIFY_LOGIN,
                result=UNAVAILABLE,
                detail=f"no login was attempted, because {competing}",
                attempted=False,
            )
        return verification.login(
            self.target,
            declared,
            secret,
            # `verification` judges what comes back by it: an answer that comes
            # before `CURRENT_USER()` can be read says nothing where another
            # account could have sent it.
            competing=competing,
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

    def require_rollover(self, account: str) -> str | None:
        """Refuse ``--strategy rollover`` where the account does not exist or
        uses another plugin, before anything is sent.

        Every supported release joins two methods with ``OR``
        (``03_dual_password_probe.py``, DP2), so :data:`CAPABILITIES` reports
        ``password_rollover``, and no profile decides it: the tool opens the
        window itself (#1271). An ``ed25519`` account is allowed, with
        :data:`ED25519_ROLLOVER` as the caveat (#1271, decision 4)."""
        require_capability(self.scope(), PASSWORD_ROLLOVER, target=self.target.name)
        found = self._existing(account, hint=_nothing("rolled over"))
        return _rollover_caveat(found.plugin)

    def finish_rollover(self, account: str, *, current: Secret | None = None) -> ChangeResult:
        """The ``current`` password's value alone, always, and ``changed:
        True`` (#1271).

        The statement names one method, so it ends the old password a
        rollover kept, and an expiry with it (``11_rollover_expiry_probe.py``,
        RE4). ``PASSWORD EXPIRE`` would not end it (RE2), and MariaDB has no
        ``DISCARD OLD PASSWORD``. Whether a second method is there is in
        ``mysql.global_priv``, which the tool account does not read (#1267,
        decision 3), so the value is sent on every run and every run reports a
        change: the exception to invariant 9 this verb has on MariaDB.

        Refused before anything is sent, with ``password_sent`` left ``False``:
        no ``current``, one the target cannot take, a read-only session, an
        account that does not exist, and one on another plugin. A failure of
        the statement has ``password_sent`` set.
        """
        if current is None:
            raise self._not_passed("current", account)
        password_module.admit(current)
        require_read_write(self.scope(), target=self.target.name)
        self._require_password_value()
        found = self._existing(account, hint=_nothing("changed"))
        statement = password_module.alter_user(found.user, found.host, found.plugin, current)
        try:
            self._read(lambda cursor: cursor.execute(statement), scrub=password_module.scrub)
        except DriverError as failure:
            failure.password_sent = True
            raise
        LOG.debug("rollover finished for %s on %s", found.name, self.target.name)
        return ChangeResult(
            changed=True,
            detail="any second password ended; the current password was sent alone",
        )

    def _not_passed(self, which: str, account: str) -> DriverError:
        """The refusal for a password the command must pass and did not:
        ``previous`` for :meth:`set_password` to keep, or ``current`` for
        :meth:`finish_rollover`. MariaDB keeps or ends a rollover only by being
        sent the value (#1271)."""
        return DriverError(
            f'no {which} password was passed for "{account}" on target '
            f'"{self.target.name}"; nothing was sent',
            hint=(
                f"this is a fault in sopuli: MariaDB keeps or ends a rollover only by being "
                f"sent the {which} password's value, so the command must pass it"
            ),
        )

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
