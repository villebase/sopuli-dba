"""The accounts a MariaDB config declares, as the server has them. Tier 0.

Read from the ``mysql.user`` view through §2.1's column grant
(``02-mariadb-privileges.md``): the user, the host, the plugin and whether the
row is a role. Never the stored value, the lock or the rollover state, which
are only in ``mysql.global_priv`` beside it (#1267, decisions 2 and 3).

The driver changes passwords on ``mysql_native_password`` and ``ed25519``
accounts only (#1267, decision 1). ``parsec`` is out: PyMySQL has no client for
it (``sql/mariadb/06_pymysql_login_probe.py``), so the change could not be
checked by a login. The tool never changes an account's plugin.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from sopuli.driver.mysql_family.accounts import same_host, split
from sopuli.driver.protocol import Cursor

#: The plugins whose stored value the tool computes and whose login PyMySQL
#: makes (#1267, decision 1).
SUPPORTED_PLUGINS = ("mysql_native_password", "ed25519")

#: Every row for the given user names, at any host, one ``%s`` per name. A role
#: is a row too, with ``is_role = 'Y'`` and an empty host (TG7), and is left out.
ROWS_FOR_USERS = (
    "select User, Host, plugin from mysql.user where is_role = 'N' and User in ({names})"
)

OTHER_PLUGIN_HINT = (
    "the tool changes passwords only on mysql_native_password and ed25519 accounts, "
    "and never changes an account's plugin. Move the account with ALTER USER … "
    "IDENTIFIED VIA, or remove it from the config"
)


def text(value: object) -> str:
    """PyMySQL returns some ``mysql`` columns as bytes."""
    return value.decode("utf-8") if isinstance(value, bytes) else str(value)


@dataclass(frozen=True)
class Account:
    """One row of the view, as :data:`ROWS_FOR_USERS` reads it."""

    user: str
    host: str
    plugin: str

    @property
    def name(self) -> str:
        """``user@host``, in the server's spelling."""
        return f"{self.user}@{self.host}"


def account_of(row: Sequence[Any]) -> Account:
    user, host, plugin = row
    return Account(user=text(user), host=text(host), plugin=text(plugin))


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
