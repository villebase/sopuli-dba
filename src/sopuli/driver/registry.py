"""Which module serves a ``targets.*.type``, imported on first use.

ADR-006 rules 1 and 2, applied to drivers exactly as they are applied to
stores. A vendor client is imported inside its own module when something
actually connects, and a target declaring a driver this machine has not
installed is a structured error naming the extra that supplies it. It exits 9,
and its hint gives the pip line and the pipx line from :mod:`sopuli.extras`.
``01-configuration.md`` §3a shows the same error for a store.

**Why a driver is an extra at all** (D9, E1): ``python-oracledb`` exists only to
reach Oracle. Binding stores and not drivers would read as arbitrary, and D3
already makes reaching Oracle a per-site runtime condition, since Instant Client
has to be installed either way.

**Three registries, one mechanism.** :mod:`sopuli.extras` holds what this
shares with :mod:`sopuli.store.registry` and :mod:`sopuli.notify.registry` --
looking a module up without importing it, and the three-way reading of a
``ModuleNotFoundError``. What stays here is the noun and the wording: a store is
named by ``vaults:``, a driver by a target's ``type:`` and a channel by
``notify.method``, and a message that tried to serve all three would name none
of them. The subtlety is shared because it is subtle; the sentences are not
shared because they are not the same sentence.

**Not a plugin system** (D6). The mapping below is a literal, in-tree dict.
Extras control which dependencies are installed, not which modules exist, so
installing a package cannot register a driver.

Declaring a driver is config and reaching one is not. A file naming a target
loads, validates and prints with nothing installed; only connecting needs the
client.
"""

from __future__ import annotations

import importlib
from collections.abc import Iterable
from dataclasses import dataclass
from types import ModuleType

from sopuli.config.errors import ConfigError
from sopuli.config.model import Target

# The limits modules import no vendor client, so naming them here keeps the
# registry importable on a machine with no driver installed.
from sopuli.driver.mariadb.limits import LIMIT as MARIADB_LIMIT
from sopuli.driver.mssql.limits import LIMIT as MSSQL_LIMIT
from sopuli.driver.mysql.limits import LIMIT as MYSQL_LIMIT
from sopuli.driver.postgres.limits import LIMIT as POSTGRES_LIMIT
from sopuli.driver.protocol import Driver, DriverContext
from sopuli.extras import (
    MISSING_CLIENT,
    MISSING_MODULE,
    install_command,
    install_hint,
    missing_kind,
    pipx_install_command,
)
from sopuli.extras import installed as extras_installed
from sopuli.passwords import BYTE_LENGTH, CONTROL, ENCODING, FORBIDDEN, ByteLimit

#: ``error.code`` for a configured driver whose client is not installed
#: (``03-json-output.md`` §3), so a consumer can branch on this case without
#: parsing the message.
#:
#: The next number after ``SOPULI-20001``, its store equivalent (J3).
DRIVER_NOT_INSTALLED = "SOPULI-20002"

#: ``error.code`` for a driver type this build has no module for: the driver
#: equivalent of ``SOPULI-20005``. A separate code because a store and a
#: database are different outages, which is also why ``SOPULI-20001`` and this
#: module's ``SOPULI-20002`` are two.
DRIVER_NOT_IMPLEMENTED = "SOPULI-20006"

#: Every command that connects to a target, by the run document's command name,
#: and so every command :func:`require_command` gates. A driver that lists its
#: commands lists these, so a new command reaches every driver at once; a mode
#: a product lacks is refused by capability at plan time (#1636). A command is
#: added here only when every driver that uses this set runs it or refuses it
#: by capability; a driver that cannot, such as a new product's, lists a set of
#: its own. `doctor` is not one: it is never refused.
CONNECTING_COMMANDS = frozenset(
    {
        "creds.check",
        "creds.apply",
        "creds.rotate",
        "creds.generate",
        "creds.status",
        "creds.finish-rollover",
        "account.list",
        "account.reset-password",
        "account.suspend",
        "account.expire-password",
        "report.accounts",
        "report.history",
        "report.privileges",
    }
)


@dataclass(frozen=True)
class DatabaseDriver:
    """What is behind one ``targets.*.type``.

    ``provides`` is the field that makes the difference between "the operator
    has not installed this" and "we have a typo in our own import", since both
    arrive as ``ModuleNotFoundError``.

    Named ``DatabaseDriver`` rather than ``Driver`` because
    :class:`sopuli.driver.protocol.Driver` already means the connecting thing.
    This is the registry entry that finds it -- a fact about packaging, not
    about databases.
    """

    #: Dotted path of the module implementing the driver.
    module: str
    #: The extra that installs its client.
    extra: str | None = None
    #: Top-level module names ``pip install "sopuli-dba[<extra>]"`` makes
    #: importable.
    provides: frozenset[str] = frozenset()
    #: The product's password byte limit in words, for `policy sample
    #: --max-bytes`'s help. Read from :attr:`fixed_limit` where the product has
    #: one, and a literal on Oracle, because the help is built when the CLI is
    #: imported and must not import a driver; a tier-0 test pins it to the
    #: driver's own rule.
    password_limit: str | None = None
    #: The :func:`sopuli.passwords.check` rules whose violation this driver
    #: refuses when it sets a password, so `creds generate --no-policy-check`
    #: cannot waive them (#1327, #1335). A literal for the reason
    #: ``password_limit`` is one; a tier-0 test pins it to what the driver's own
    #: admission check refuses. An empty password is refused before any rule.
    refuses: frozenset[str] = frozenset()
    #: The password limit when it is a fact about the product rather than about
    #: one database, so a check needs no connection to know it. ``None`` where
    #: only the target can say, as on Oracle, whose limit depends on the release
    #: and the character set.
    fixed_limit: ByteLimit | None = None
    #: The commands this driver is written for, by the run document's command
    #: name (``creds.apply``, never ``creds apply``), or ``None`` for every
    #: command. `doctor` is never listed and never refused: it asks only what the
    #: target is, which every driver can answer. :func:`require_command` refuses
    #: any other command not listed. A driver is built one command at a time, and
    #: this says how far it has got.
    #:
    #: **A command is listed only when every mode of it either works or is
    #: refused at plan time.** A mode the driver cannot do is refused through a
    #: capability, before any connection (invariant 4), as ``check --method
    #: hash`` is where ``offline_verify`` is absent. A mode that would reach a
    #: method not written yet keeps the command off this list.
    commands: frozenset[str] | None = None
    #: The `report accounts` checks this product has no concept of, by check
    #: name. Each is *not applicable* on its targets, never *not checked*: a
    #: setting the product lacks is not a gap anybody can close (UC-5 §3,
    #: #1458). It is a fact about the product, so it needs no connection.
    not_applicable: frozenset[str] = frozenset()
    #: Whether `creds check` asks each of this product's targets, once and
    #: before any account is checked, whether it may log in as an account
    #: (``require_login_check``), at the cost of one more connection per
    #: target. SQL Server's: on a Windows host a login can lock at a
    #: threshold the tool cannot read, so the check is refused there at plan
    #: time (invariant 4, #1552). A flag rather than a method found by
    #: ``getattr``, because the command must know before it connects which
    #: products need that extra connection; every other product makes none.
    login_check_preflight: bool = False
    #: Whether this product's unseen reset turns the login's policy off and
    #: keeps its flags in the reset record (SQL Server, #1554). With no
    #: `reset_records:` block, `account reset-password` then asks each such
    #: target at plan time whether the login's policy is on, and refuses it
    #: (Q7). A flag rather than a method, as ``login_check_preflight`` is:
    #: the command must know before it connects which targets need asking.
    reset_keeps_policy_flags: bool = False
    #: Where the product has no profiles, the hint that refuses a
    #: `personal_accounts:` rule's `profile:` on it, by ``profile_management``.
    #: ``None`` where the product has profiles and only the target can say
    #: whether it may read them, as on Oracle. A fact about the product, so
    #: `account list` refuses such a rule with no connection (#1598), and the
    #: driver's own ``resolve_profile`` gives the same hint.
    no_profiles: str | None = None
    #: The characters a seen reset's password may not be drawn with on this
    #: product, because the server keeps part of such a password in clear,
    #: and why, for the refusal's hint; ``None`` where there are none. SQL
    #: Server's ``'``: the password goes as a literal with each ``'``
    #: doubled, and an audit's ``BATCH_COMPLETED_GROUP`` masks only as many
    #: characters as the password has, so it keeps one of the password's last
    #: characters for each ``'`` (#1601). A fact about the product, so
    #: `account reset-password` refuses the policy at plan time, with no
    #: connection.
    seen_reset_unmasked: tuple[str, str] | None = None
    #: The system package the client loads when it is imported, where it has
    #: one, as a hint: pyodbc loads unixODBC's ``libodbc`` on Linux and macOS.
    #: Without it the import fails with an ``ImportError`` that is not a
    #: missing module, and :func:`resolve` reports it as not installed.
    system_library: str | None = None

    @property
    def install_command(self) -> str:
        """The line an operator can paste."""
        assert self.extra is not None
        return install_command(self.extra)

    @property
    def pipx_install_command(self) -> str:
        """The line for an install that pipx made. See :mod:`sopuli.extras`."""
        assert self.extra is not None
        return pipx_install_command(self.extra)

    @property
    def install_hint(self) -> str:
        """Both lines, for the message a person reads."""
        assert self.extra is not None
        return install_hint(self.extra)


#: Every ``type:`` :data:`~sopuli.config.targets.TARGET_TYPES` allows, and what
#: serves it. ``tests/driver/test_driver_registry.py`` checks the two against
#: each other: a type the config layer accepts and this one has never heard of
#: would fail at connect time with a ``KeyError``, which is precisely the
#: traceback rule 2 exists to prevent.
#:
#: D6 keeps drivers in the tree. A type joins this dict in the PR that lets the
#: config declare it, which may come before its module: until the module exists
#: the type resolves to :class:`DriverNotImplementedError`, and `doctor` reports
#: it as ``not_implemented``, as it does a store backend with no module.
DRIVERS: dict[str, DatabaseDriver] = {
    "oracle": DatabaseDriver(
        # The module that *connects*, not the package above it. The whole
        # value of resolving through here is that a missing client arrives as
        # `DriverNotInstalledError` rather than a traceback, and that only works
        # if the import being caught is the one that pulls the client in. The
        # package deliberately does not: `statements.py` and `client.py` are
        # tier 0 and must stay importable on a machine with no Oracle client at
        # all, which is every tier-0 CI job.
        module="sopuli.driver.oracle.session",
        extra="oracle",
        # `oracledb`, not `python-oracledb`. Oracle calls the driver
        # python-oracledb everywhere it is written about, but the distribution
        # on PyPI and the module you import are both `oracledb`, and the other
        # name resolves to nothing at all.
        provides=frozenset({"oracledb"}),
        password_limit="30 below 23, 128 from 23",
        # `"` too: a quoted identifier has no escape for it (invariant 11).
        refuses=frozenset({CONTROL, FORBIDDEN, ENCODING, BYTE_LENGTH}),
        # A rule's `postgresql.valid_until` (#1459).
        not_applicable=frozenset({"valid_until"}),
    ),
    # The module that imports psycopg, for the reason the Oracle entry names
    # `session`. `psycopg` is the module the `postgres` extra installs.
    "postgresql": DatabaseDriver(
        module="sopuli.driver.postgres.session",
        extra="postgres",
        provides=frozenset({"psycopg"}),
        password_limit=str(POSTGRES_LIMIT.max_bytes),
        refuses=frozenset({CONTROL, ENCODING, BYTE_LENGTH}),
        fixed_limit=POSTGRES_LIMIT,
        # A role has a `VALID UNTIL` date, not a lifetime; no failed-login
        # limit; and no profile (#1443, #1411).
        not_applicable=frozenset({"password_lifetime", "failed_login_limit", "profile"}),
        no_profiles=(
            "PostgreSQL has no profiles; declare these accounts by name with `accounts:`, "
            "or by a role they hold with `role:`"
        ),
        # UC-1: `creds check`, by login (#1067); `creds apply`, which sets a
        # password with a verifier computed on the client (#1060); and `creds
        # rotate`, `generate`, `status` and `finish-rollover`, whose modes
        # PostgreSQL lacks are refused at plan time by capability (#1072). A
        # role never has a rollover window, so `finish-rollover` finds none.
        # UC-2: `account list`, where a `profile:` predicate is refused by
        # capability, because a cluster has no profiles; `account
        # reset-password`, whose seen path is refused by capability, because a
        # role cannot be made to change its password at login; `account
        # suspend`, which sets NOLOGIN; and `account expire-password`, which is
        # refused by the same capability at plan time (#1201). UC-5: `report
        # accounts`, from `pg_roles` (#1459); `report history`, from the store,
        # with no database date, because PostgreSQL keeps none (#1460); `report
        # privileges`, from the catalogs' ACLs of the database the target
        # connects to, with the cluster's other databases not checked (#1481)
        # unless another declared target connects to them (#1501). UC-3: `sql
        # run`, a read declared as a cursor in a read-only transaction and a
        # write as a prepared statement (#1693), as a run-as role that is not
        # the service role or a member of it (#1700).
        commands=CONNECTING_COMMANDS | {"sql.run"},
    ),
    # The module that imports PyMySQL, for the reason the Oracle entry names
    # `session`. `pymysql` is the module the `mysql` extra installs (#1202,
    # decision 8). UC-1 (#1223): `creds check`, by login where only the
    # declared account can answer (#1246); `creds apply` and `rotate`, which set
    # a password from a hash computed on the client and never log in first, so
    # with only `current` an account is skipped; `creds generate` and `status`.
    # `finish-rollover` sends `DISCARD OLD PASSWORD` (#1224, decision 6 of
    # #1202). UC-2: `account list`, where a `role:` rule names its host and a
    # `profile:` rule is refused by capability, because MySQL has no profiles
    # (#1225); `account reset-password`, which refuses `--keep-rollover` by
    # capability; `account suspend`, by `ACCOUNT LOCK`; and `account
    # expire-password`, which discards a retained password first. UC-5: `report
    # accounts`, one row per `user@host` (#1461); `report history`, from the
    # store, with `mysql.user.password_last_changed` as the database's date
    # (#1460); `report privileges`, one row per path, each with its level.
    # Under `partial_revokes` the revokes come from the optional view
    # `sopuli.account_state`, and global privileges are not checked without it
    # (#1482, #1502). UC-3: `sql run`, a read in a read-only transaction and a
    # write that commits only past its guard (#1716), as a run-as account that
    # is not the service account or granted it as a role (#1722), refusing a
    # write that names a table without transactions (#1723).
    "mysql": DatabaseDriver(
        module="sopuli.driver.mysql.session",
        extra="mysql",
        provides=frozenset({"pymysql"}),
        password_limit=str(MYSQL_LIMIT.max_bytes),
        refuses=frozenset({CONTROL, ENCODING, BYTE_LENGTH}),
        fixed_limit=MYSQL_LIMIT,
        # MySQL has a lifetime and a failed-login limit per account, but no
        # profile (#1448), and no `VALID UNTIL` (#1459).
        not_applicable=frozenset({"profile", "valid_until"}),
        no_profiles=(
            "MySQL has no profiles; declare these accounts by name with `accounts:`, "
            "or by a role they hold with `role:`"
        ),
        commands=CONNECTING_COMMANDS | {"sql.run"},
    ),
    # PyMySQL reaches MariaDB too, and its `ed25519` extra brings PyNaCl for that
    # plugin (#1267, decisions 1 and 5), so the extra provides `nacl` as well as
    # `pymysql`: with only the `mysql` extra installed, `mariadb` is not. The
    # session connects and serves `doctor` (#1268). UC-1 (#1270): `creds check`,
    # by login only where no other account can answer; `creds apply` and
    # `rotate`, which set the value the account's plugin stores, computed on the
    # client, and never log in first, so with only `current` an account is
    # skipped; `creds generate` and `status`. A rollover sends the new and the
    # old value joined by `OR`, and `finish-rollover` sends the current value
    # alone on every run, because the tool cannot read whether one is open
    # (#1271). UC-2 (#1272): `account
    # list`, where a `role:` rule names a role alone and one `PUBLIC` reaches is
    # refused; `account reset-password`, which sets the value with `PASSWORD
    # EXPIRE` in one statement, never unlocks, and refuses `--keep-rollover` by
    # capability; `account suspend`, by `ACCOUNT LOCK` on every run; and
    # `account expire-password`, by `PASSWORD EXPIRE` alone. Guardrail 9
    # refuses an administrator in all three that change an account, except a
    # reset of the tool's own account, which guardrail 7 refuses unless
    # `--force`; `account list` says which (`guardrails.every_verb`). UC-5:
    # `report accounts`, one row per `user@host` (#1462), and `report
    # history`, from the store (#1460): the lock, the lifetime and the
    # database's date come from the optional view `sopuli.account_state`, and
    # are not checked without it (#1491). `report privileges`, one row per
    # path: an account's global level comes from the optional view
    # `sopuli.global_privileges`, and is not checked without it, or for a role
    # or `PUBLIC` (#1483, decisions A and C). UC-3: `sql run`, as on MySQL
    # (#1716, #1723), where a role is never an account, so no role check.
    "mariadb": DatabaseDriver(
        module="sopuli.driver.mariadb.session",
        extra="mariadb",
        provides=frozenset({"pymysql", "nacl"}),
        password_limit=str(MARIADB_LIMIT.max_bytes),
        refuses=frozenset({CONTROL, ENCODING, BYTE_LENGTH}),
        fixed_limit=MARIADB_LIMIT,
        # No failed-login limit per account, only the server's
        # `max_password_errors` (#1411, R1), no profile (#1448), and no `VALID
        # UNTIL` (#1459).
        not_applicable=frozenset({"failed_login_limit", "profile", "valid_until"}),
        no_profiles=(
            "MariaDB has no profiles; declare these accounts by name with `accounts:`, "
            "or by a role they hold with `role:`"
        ),
        commands=CONNECTING_COMMANDS | {"sql.run"},
    ),
    # The session connects and reports the instance for `doctor` (#1549),
    # changes a password for UC-1 (#1551), reads a login for `creds status`
    # (#1631), serves UC-2's commands (#1554) and UC-5's three reports (#1555).
    # SQL Server has no profile and no `VALID UNTIL`. The client is pyodbc with
    # Microsoft ODBC Driver 18, a system package like Oracle's Instant Client
    # (#1538, decision 6).
    "mssql": DatabaseDriver(
        module="sopuli.driver.mssql.session",
        extra="mssql",
        provides=frozenset({"pyodbc"}),
        # Bytes of UTF-16, which is how the server counts: 128 characters. The
        # help says so, because `--encoding` defaults to UTF-8.
        password_limit=f"{MSSQL_LIMIT.max_bytes} as UTF-16",
        refuses=frozenset({CONTROL, ENCODING, BYTE_LENGTH}),
        fixed_limit=MSSQL_LIMIT,
        # UC-1's change (#1551), `creds check` by login on a Linux host
        # (#1552), `creds status` (#1631), UC-5's reports (#1555), and UC-2's
        # commands (#1554):
        # `account list`, `suspend`, `reset-password` on both paths, and
        # `expire-password`, refused at plan time by capability. And `sql run`
        # (UC-3, #1727). Each driver names `sql.run` itself rather than the
        # shared set holding it, so a driver added later runs it only once it
        # has a runner and a dialect.
        commands=CONNECTING_COMMANDS | {"sql.run"},
        not_applicable=frozenset({"profile", "valid_until"}),
        no_profiles="SQL Server has no profiles; declare these logins by name with `accounts:`",
        seen_reset_unmasked=(
            "'",
            "a seen reset sends the password in clear, and a server audit's batch-completed "
            "record keeps one character of the password's end for each `'` "
            "(02-mssql-privileges.md section 6.3)",
        ),
        login_check_preflight=True,
        reset_keeps_policy_flags=True,
        system_library=(
            "install unixODBC (`unixodbc` on Debian and Ubuntu) and Microsoft ODBC Driver 18 "
            "for SQL Server, which are system packages: pyodbc loads unixODBC's libodbc when "
            "it is imported"
        ),
    ),
}


class DriverNotInstalledError(ConfigError):
    """A configured driver's client is not installed on this machine.

    ``config`` and exit 9, not ``capability`` (ADR-006 E5). ``capability`` names
    something a *target* cannot do -- a property of the database at the far end
    that no local action changes. This is the opposite: it is fixed on this
    machine, by the person reading the message, with the command in the message.
    """

    code = DRIVER_NOT_INSTALLED


class DriverNotImplementedError(ConfigError):
    """This build has no module for a driver type the config named.

    A separate class from :class:`DriverNotInstalledError` because the two are
    the same ``ModuleNotFoundError`` and completely different problems. Nothing
    the operator installs fixes this one, so it must never carry an install
    line.

    It has a code because the configuration is right and there is nothing to
    install, so a consumer must tell it from the ``config`` errors that a change
    to either fixes (J3).
    """

    code = DRIVER_NOT_IMPLEMENTED


def refused_password_rules(products: Iterable[str]) -> frozenset[str]:
    """Every :func:`sopuli.passwords.check` rule a driver of ``products``
    refuses, read from :attr:`DatabaseDriver.refuses`. No driver is imported.

    No products is read as every product, the strictest answer: a caller that
    named none still gets nothing waived that some driver refuses.
    """
    found: frozenset[str] = frozenset()
    for product in products or DRIVERS:
        found = found | DRIVERS[product].refuses
    return found


def no_profiles_hint(product: str) -> str:
    """:attr:`DatabaseDriver.no_profiles` for a product that has no profiles,
    for its driver's refusal of a `profile:` rule. Raises for a product that
    has them, so a driver module that names the wrong product fails on import
    rather than refusing with no hint."""
    hint = DRIVERS[product].no_profiles
    if hint is None:
        raise ValueError(f"{product} has profiles; it has no no_profiles hint")
    return hint


def installed(driver: DatabaseDriver) -> bool:
    """Whether ``driver``'s client is importable, **without importing it**.

    Safe to call from an offline command, which is the only kind that calls it:
    looking a module up does not run a vendor package's import side effects.
    """
    return extras_installed(driver.provides)


def resolve(target: Target) -> ModuleType:
    """Import the module serving ``target``'s ``type:``, or say why it cannot.

    Returns the module, which exports ``build_driver(context)`` and
    ``client_report(env=, runtime=)``, `doctor`'s lines about this machine's
    client. A caller that wants a driver uses :func:`driver_for`.
    """
    driver = DRIVERS[target.type]
    try:
        return importlib.import_module(driver.module)
    except ModuleNotFoundError as exc:
        kind = missing_kind(exc, module=driver.module, provides=driver.provides, extra=driver.extra)
        if kind == MISSING_CLIENT:
            raise DriverNotInstalledError(
                f'target "{target.name}" declares type "{target.type}", '
                f"but that driver is not installed",
                hint=f"install it with:  {driver.install_hint}",
            ) from exc
        if kind == MISSING_MODULE:
            raise DriverNotImplementedError(
                f'target "{target.name}" declares type "{target.type}", '
                f"but this build has no {target.type} driver yet",
                hint="this is not something to install -- the driver is not written yet",
            ) from exc
        raise
    except ImportError as exc:
        # The client is there and a library it loads is not, such as
        # unixODBC's libodbc for pyodbc on Linux: the import of the client's own
        # module fails, and the message names the library. Any other import
        # fault, in this tool's modules among them, stays a traceback.
        if driver.system_library is None or exc.name not in driver.provides:
            raise
        raise DriverNotInstalledError(
            f'target "{target.name}" declares type "{target.type}", but its client '
            f"cannot load a system library: {exc}",
            hint=driver.system_library,
        ) from exc


def require_command(target: Target, command: str) -> None:
    """Refuse ``command`` on a driver not written for it, with ``SOPULI-20006``.

    ``command`` is the run document's name for it, such as ``creds.apply``
    (:attr:`DatabaseDriver.commands`). Every command but `doctor` calls this
    before it resolves a credential or opens a socket, so a command over
    several targets reports that target's error and carries on. `doctor` only
    asks what the target is, and skips it.
    """
    supported = DRIVERS[target.type].commands
    if supported is None or command == "doctor" or command in supported:
        return
    names = ", ".join(f"`{name.replace('.', ' ')}`" for name in ("doctor", *sorted(supported)))
    raise DriverNotImplementedError(
        f'target "{target.name}" declares type "{target.type}", and this build '
        f"can run only {names} there yet",
        hint=(
            "this is not something to install -- the driver is written one command at "
            f"a time, and `{command.replace('.', ' ')}` is not written for it yet"
        ),
    )


def driver_for(target: Target, context: DriverContext) -> Driver:
    """The driver for ``target``'s ``type:``, built for this run.

    The one way a command gets a driver, so a command never names a vendor's
    driver class (P1). Every error :func:`resolve` raises reaches the caller
    unchanged.
    """
    driver: Driver = resolve(target).build_driver(context)
    return driver
