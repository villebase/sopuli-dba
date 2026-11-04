"""The accounts a MariaDB config declares, as the server has them. Tier 0.

Read from the ``mysql.user`` view through §2.1's column grant
(``02-mariadb-privileges.md``): the user, the host, the plugin, whether the
password is expired and whether the row is a role. Never the stored value, the
lock or the rollover state, which are only in ``mysql.global_priv`` beside it
(#1267, decisions 2 and 3).

The driver changes passwords on ``mysql_native_password`` and ``ed25519``
accounts only (#1267, decision 1). ``parsec`` is out: PyMySQL has no client for
it (``sql/mariadb/06_pymysql_login_probe.py``), so the change could not be
checked by a login. The tool never changes an account's plugin.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, replace
from typing import Any

from sopuli.config.products import same_mysql_account
from sopuli.driver.mariadb import admin
from sopuli.driver.mysql_family.accounts import (
    Principal,
    current_user,
    same_host,
    split,
    text,
)
from sopuli.driver.protocol import Cursor, DriverError, UserState
from sopuli.exit_codes import ExitCode

#: The plugins whose stored value the tool computes and whose login PyMySQL
#: makes (#1267, decision 1).
SUPPORTED_PLUGINS = ("mysql_native_password", "ed25519")

#: Every row for the given user names, at any host, one ``%s`` per name. A role
#: is a row too, with ``is_role = 'Y'`` and an empty host (TG7), and is left out.
ROWS_FOR_USERS = (
    "select User, Host, plugin, password_expired from mysql.user "
    "where is_role = 'N' and User in ({names})"
)

#: The account a new server creates to own the ``mysql.user`` view and the
#: other system views. 10.11.19, 11.8.9 and 12.3.3 all create it, on
#: ``mysql_native_password``, so the plugin check does not refuse it.
#: ``root`` is the site's own account, not one of these.
SYSTEM_ACCOUNTS = frozenset({"mariadb.sys@localhost"})

#: ``UserState.status``, in the words Oracle and MySQL use.
OPEN = "OPEN"
EXPIRED = "EXPIRED"

#: ``UserState.password_changed_unknown``: MariaDB keeps the time of a change
#: only in ``mysql.global_priv``, beside the stored value (#1275, RD1).
NO_CHANGE_DATE = (
    "MariaDB keeps the time of a password change beside the stored value, which the "
    "tool does not read"
)

OTHER_PLUGIN_HINT = (
    "the tool changes passwords only on mysql_native_password and ed25519 accounts, "
    "and never changes an account's plugin. Move the account with ALTER USER … "
    "IDENTIFIED VIA, or remove it from the config"
)


@dataclass(frozen=True)
class Account:
    """One row of the view, as :data:`ROWS_FOR_USERS` reads it."""

    user: str
    host: str
    plugin: str
    expired: bool = False

    @property
    def name(self) -> str:
        """``user@host``, in the server's spelling."""
        return f"{self.user}@{self.host}"


def account_of(row: Sequence[Any]) -> Account:
    user, host, plugin, expired = row
    return Account(
        user=text(user), host=text(host), plugin=text(plugin), expired=text(expired) == "Y"
    )


class OtherPluginError(DriverError):
    """A declared account authenticates with a plugin the tool does not set
    passwords for (#1267, decision 1). ``config``, exit 9, before anything is
    changed (invariant 4)."""

    category = "config"
    exit_code = ExitCode.CONFIG_INVALID

    def __init__(self, account: str, plugin: str, *, target: str) -> None:
        super().__init__(
            f'account "{account}" on target "{target}" uses {plugin}, and sopuli changes '
            f"only {' and '.join(SUPPORTED_PLUGINS)} accounts",
            hint=OTHER_PLUGIN_HINT,
        )


def read_one(cursor: Cursor, account: str, *, target: str) -> Account | None:
    """The declared account's row, ``None`` where it does not exist. Raises
    :class:`OtherPluginError` for an account on another plugin."""
    user, host = split(account)
    found = find(read(cursor, [user])[user], host)
    if found is not None and found.plugin not in SUPPORTED_PLUGINS:
        raise OtherPluginError(found.name, found.plugin, target=target)
    return found


def state_of(account: Account) -> UserState:
    """One account as a :class:`~sopuli.driver.protocol.UserState`.

    The expiry is the view's ``password_expired``, which ``PASSWORD EXPIRE``
    sets (``04_lock_expiry_probe.py``, LK3). A lifetime that has run out is not
    seen: the time of the last change is beside the stored value. The lock is
    never read (#1267, decision 2), so an account reads as not locked; a login
    to a locked one answers ``4151``. :data:`SYSTEM_ACCOUNTS` are vendor
    maintained, so guardrail 2 refuses them.
    """
    return UserState(
        name=account.name,
        status=EXPIRED if account.expired else OPEN,
        expired=account.expired,
        vendor_maintained=account.name in SYSTEM_ACCOUNTS,
        password_changed_unknown=NO_CHANGE_DATE,
        password_file_member=False,
    )


def read(cursor: Cursor, users: Sequence[str]) -> dict[str, list[Account]]:
    """Every account with one of these user names, at any host, by user name."""
    found: dict[str, list[Account]] = {user: [] for user in users}
    if not users:
        return found
    cursor.execute(ROWS_FOR_USERS.format(names=", ".join(["%s"] * len(users))), tuple(users))
    for row in cursor.fetchall():
        account = account_of(row)
        found.setdefault(account.user, []).append(account)
    return found


def find(accounts: Sequence[Account], host: str) -> Account | None:
    """The account at ``host``, compared as the server compares hosts."""
    return next((account for account in accounts if same_host(account.host, host)), None)


def describe(
    cursor: Cursor, account: str, *, target: str, session_user: str | None = None
) -> UserState | None:
    """The declared account's state, ``None`` where it does not exist.

    Raises :class:`OtherPluginError` for an account on another plugin. Reads
    the privileges guardrail 9 checks (:func:`~sopuli.driver.mariadb.admin.
    global_privileges`, ``02-mariadb-privileges.md`` §5), so every command that
    describes an account before it changes it has them. ``session_user`` is
    :func:`current_user` where the session already read it.
    """
    found = read_one(cursor, account, target=target)
    if found is None:
        return None
    held = admin.global_privileges(cursor, Principal(found.user, found.host))
    own = same_mysql_account(found.name, session_user or current_user(cursor))
    return replace(state_of(found), global_privileges=held, session_account=own)


def survey(cursor: Cursor, declared: Sequence[str]) -> tuple[str, ...]:
    """What `doctor --check-privileges` says about the declared accounts.

    One line for each declared account that does not exist or uses a plugin the
    tool does not change, and one for each account whose user name the config
    declares at another host. That other account logs in with a password of its
    own. On MySQL a locked one is left out; on MariaDB the lock cannot be read
    (#1267, decision 2), so every such account is named, and the line says so.
    """
    lines: list[str] = []
    hosts: dict[str, list[str]] = {}
    for account in declared:
        user, host = split(account)
        hosts.setdefault(user, []).append(host)
    rows = read(cursor, list(hosts))
    for user, wanted in hosts.items():
        for host in wanted:
            found = find(rows[user], host)
            if found is None:
                lines.append(
                    f"{user}@{host} does not exist on this server: create it, or remove "
                    "it from the config. The tool does not create accounts"
                )
            elif found.plugin not in SUPPORTED_PLUGINS:
                lines.append(f"{found.name} uses {found.plugin}: {OTHER_PLUGIN_HINT}")
        for row in rows[user]:
            if any(same_host(row.host, host) for host in wanted):
                continue
            lines.append(
                f"{row.name} exists and the config does not declare it: unless it is "
                f"locked, which the tool cannot read on MariaDB, it logs in as {user} with "
                "a password of its own, which the tool does not change. Declare it, or "
                "lock or drop it"
            )
    return tuple(lines)
