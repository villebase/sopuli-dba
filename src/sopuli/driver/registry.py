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
from sopuli.driver.mysql.limits import LIMIT as MYSQL_LIMIT
from sopuli.driver.postgres.limits import LIMIT as POSTGRES_LIMIT
from sopuli.driver.protocol import Driver, DriverContext, DriverError
from sopuli.exit_codes import ExitCode
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
        # accounts`, from `pg_roles` (#1459).
        commands=frozenset(
            {
                "account.list",
                "account.reset-password",
                "account.suspend",
                "account.expire-password",
                "creds.check",
                "creds.apply",
                "creds.rotate",
                "creds.generate",
                "creds.status",
                "creds.finish-rollover",
                "report.accounts",
            }
        ),
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
    # expire-password`, which discards a retained password first. UC-5 (#1461):
    # `report accounts`, one row per `user@host`. `report privileges` and
    # `report history` are not written for it yet.
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
        commands=frozenset(
            {
                "report.accounts",
                "account.list",
                "account.reset-password",
                "account.suspend",
                "account.expire-password",
                "creds.check",
                "creds.apply",
                "creds.rotate",
                "creds.generate",
                "creds.status",
                "creds.finish-rollover",
            }
        ),
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
    # `--force`; `account list` says which (`guardrails.every_verb`).
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
        commands=frozenset(
            {
                "account.list",
                "account.reset-password",
                "account.suspend",
                "account.expire-password",
                "creds.check",
                "creds.apply",
                "creds.rotate",
                "creds.generate",
                "creds.status",
                "creds.finish-rollover",
            }
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


class NotWrittenError(DriverError):
    """A driver connects, and cannot do this yet.

    ``SOPULI-20006``, ``config`` and exit 9, as for a driver with no module at
    all: nothing installed fixes it, and the configuration is right. A session
    raises it, so it is a :class:`~sopuli.driver.protocol.DriverError` and
    reaches the caller as that target's error. ``product`` is how the message
    names what the target is, such as "a MySQL server", and ``hint`` says what
    the driver can do instead.
    """

    category = "config"
    exit_code = ExitCode.CONFIG_INVALID

    def __init__(self, target: str, *, product: str, what: str, hint: str) -> None:
        super().__init__(
            f'target "{target}" is {product}, and this build cannot {what} there yet',
            hint=f"this is not something to install: {hint}",
            code=DRIVER_NOT_IMPLEMENTED,
        )


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
