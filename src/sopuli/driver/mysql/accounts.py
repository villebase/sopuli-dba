"""Reading a MySQL account, and what the config declares about it. Tier 0.

A MySQL account is a user name and a host pattern, and the config names it as
``user@host`` (#1202, decision 4). One user name can exist at several hosts,
each its own account with its own password (``05_identity_grants_probe.py``,
ID1). The server compares the user name by case and the host without case
(ID3), and so does this module (decision 3). That model is MariaDB's too, so
it is in :mod:`sopuli.driver.mysql_family.accounts`.

**What it reads.** The columns of ``mysql.user`` that
``02-mysql-privileges.md`` §2.1 grants: the user, the host, the plugin, the
lock, the expiry and the password's age, and the server's
``default_password_lifetime``, which any account can read. Never
``authentication_string`` or ``User_attributes``: the tool account is not
granted them, and the server refuses them with ``1143`` (TG5). The user names
are sent as bind values; they are not secrets, and invariant 14 is about
passwords.

**Only ``caching_sha2_password`` is supported** (decision 5). An account on
another plugin is refused when it is described, which every command does
before it changes anything, so the refusal comes at plan time. The tool does
not move an account to another plugin.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from typing import Any

from sopuli.config.products import same_mysql_account
from sopuli.driver.mysql import admin
from sopuli.driver.mysql_family.accounts import (
    Principal,
    current_user,
    same_host,
    split,
    text,
)
from sopuli.driver.protocol import Cursor, DriverError, UserState
from sopuli.exit_codes import ExitCode

#: The plugin the tool sets passwords for (decision 5).
SUPPORTED_PLUGIN = "caching_sha2_password"

#: Every row for the given user names, at any host, one ``%s`` per name.
#: ``User`` is ``char(32)`` with a binary collation: case counts, and trailing
#: spaces do not. The server returns it without them, and refuses
#: ``CREATE USER 'acme_app '`` beside ``'acme_app'`` with ``1396``, so the two
#: are one account (measured on 8.4.13).
ROWS_FOR_USERS = (
    "select User, Host, plugin, account_locked, password_expired, "
    "password_last_changed, password_lifetime from mysql.user where User in ({names})"
)

#: The lifetime, in days, of a password whose account's ``password_lifetime``
#: is ``NULL``. ``0`` is no limit.
DEFAULT_LIFETIME = "select @@global.default_password_lifetime"

#: ``UserState.status``, in the words Oracle uses for the same states.
OPEN = "OPEN"
LOCKED = "LOCKED"
EXPIRED = "EXPIRED"
EXPIRED_AND_LOCKED = "EXPIRED & LOCKED"

#: The system accounts a new server creates, by name (TG2). Each holds
#: ``SYSTEM_USER``, so the tool account cannot change them anyway (TG1). A
#: site's own account whose name starts ``mysql.`` is not one of them.
SYSTEM_ACCOUNTS = frozenset(
    {"mysql.infoschema@localhost", "mysql.session@localhost", "mysql.sys@localhost"}
)

#: ``UserState.password_changed_unknown`` where the column is empty.
NO_CHANGE_DATE = "mysql.user.password_last_changed is empty for this account"


class OtherPluginError(DriverError):
    """A declared account authenticates with a plugin the tool does not set
    passwords for (decision 5). ``config``, exit 9: the fix is to move the
    account to ``caching_sha2_password`` outside the tool, or to remove it
    from the config."""

    category = "config"
    exit_code = ExitCode.CONFIG_INVALID
    about_account = True

    def __init__(self, account: str, plugin: str, *, target: str) -> None:
        super().__init__(
            f'account "{account}" on target "{target}" {other_plugin(plugin)}',
            hint=OTHER_PLUGIN_HINT,
        )


#: What to do about an account on another plugin: the refusal's hint, and the
#: end of `doctor`'s line about it.
OTHER_PLUGIN_HINT = (
    f"move the account to {SUPPORTED_PLUGIN} with ALTER USER … IDENTIFIED WITH, or "
    "remove it from the config. The tool does not change an account's plugin"
)


def other_plugin(plugin: str) -> str:
    """The words for an account on another plugin, shared by the refusal and
    `doctor`'s line, so the two say the same."""
    return f"uses {plugin}, and sopuli changes only {SUPPORTED_PLUGIN} accounts"


@dataclass(frozen=True)
class Account:
    """One ``mysql.user`` row, as :data:`ROWS_FOR_USERS` reads it."""

    user: str
    host: str
    plugin: str
    locked: bool
    expired: bool
    changed_at: datetime | None
    lifetime_days: int | None

    @property
    def name(self) -> str:
        """``user@host``, in the server's spelling."""
        return f"{self.user}@{self.host}"


def account_of(row: Sequence[Any]) -> Account:
    user, host, plugin, locked, expired, changed_at, lifetime = row
    return Account(
        user=text(user),
        host=text(host),
        plugin=text(plugin),
        locked=text(locked) == "Y",
        expired=text(expired) == "Y",
        # The session's time zone is UTC (connection.UTC_SESSION).
        changed_at=changed_at.replace(tzinfo=UTC) if isinstance(changed_at, datetime) else None,
        lifetime_days=None if lifetime is None else int(lifetime),
    )


def read(cursor: Cursor, users: Sequence[str]) -> dict[str, list[Account]]:
    """Every account with one of these user names, at any host, by user name.
    One read for all of them."""
    found: dict[str, list[Account]] = {user: [] for user in users}
    if not users:
        return found
    names = ", ".join("%s" for _ in users)
    cursor.execute(ROWS_FOR_USERS.format(names=names), tuple(users))
    for account in map(account_of, cursor.fetchall()):
        found.setdefault(account.user, []).append(account)
    return found


def default_lifetime(cursor: Cursor) -> int:
    """The server's ``default_password_lifetime``, in days; ``0`` is none."""
    cursor.execute(DEFAULT_LIFETIME)
    row = cursor.fetchone()
    return int(row[0]) if row and row[0] is not None else 0


def find(accounts: Iterable[Account], host: str) -> Account | None:
    """The account at ``host``, compared without case."""
    for account in accounts:
        if same_host(account.host, host):
            return account
    return None


def state_of(account: Account, *, now: datetime, default_days: int = 0) -> UserState:
    """One account as a :class:`~sopuli.driver.protocol.UserState`.

    A lock is always a person's: ``account_locked`` is set by ``ACCOUNT
    LOCK``. The temporary lock after failed logins is not in ``mysql.user``
    (``04_lock_expiry_probe.py``), so ``failed_logins`` is unknown.

    The password expires ``password_lifetime`` days after it changed. A
    lifetime of ``NULL`` follows ``default_days``, the server's
    ``default_password_lifetime``; ``0`` is no limit. The password has expired
    where ``password_expired`` says so, which only ``PASSWORD EXPIRE`` sets, or
    where its lifetime has run out at ``now``.
    """
    days = default_days if account.lifetime_days is None else account.lifetime_days
    expires_at = None
    if account.changed_at is not None and days:
        expires_at = account.changed_at + timedelta(days=days)
    expired = account.expired or (expires_at is not None and expires_at <= now)
    return UserState(
        name=account.name,
        status=_status(locked=account.locked, expired=expired),
        locked=account.locked,
        deliberately_locked=account.locked,
        expired=expired,
        password_changed_at=account.changed_at,
        password_changed_unknown=None if account.changed_at else NO_CHANGE_DATE,
        password_expires_at=expires_at,
        vendor_maintained=account.name in SYSTEM_ACCOUNTS,
        password_file_member=False,
    )


def _status(*, locked: bool, expired: bool) -> str:
    if locked and expired:
        return EXPIRED_AND_LOCKED
    if locked:
        return LOCKED
    if expired:
        return EXPIRED
    return OPEN


def read_one(cursor: Cursor, account: str, *, target: str) -> Account | None:
    """The declared account's row, ``None`` where it does not exist. Raises
    :class:`OtherPluginError` for an account on another plugin. What
    :func:`describe` and the verbs that need only the row read."""
    user, host = split(account)
    found = find(read(cursor, [user])[user], host)
    if found is not None and found.plugin != SUPPORTED_PLUGIN:
        raise OtherPluginError(found.name, found.plugin, target=target)
    return found


def state_now(cursor: Cursor, found: Account, *, now: datetime | None = None) -> UserState:
    """:func:`state_of` with the server's ``default_password_lifetime``, so a
    password past its lifetime reads as expired."""
    return state_of(found, now=now or datetime.now(UTC), default_days=default_lifetime(cursor))


def describe(
    cursor: Cursor,
    account: str,
    *,
    target: str,
    now: datetime | None = None,
    session_user: str | None = None,
) -> UserState | None:
    """The declared account's state, ``None`` where it does not exist.

    Raises :class:`OtherPluginError` for an account on another plugin.
    ``session_user`` is :func:`current_user` where the session already read it;
    without it, this reads it.
    """
    found = read_one(cursor, account, target=target)
    if found is None:
        return None
    state = state_now(cursor, found, now=now)
    # Guardrail 9 reads it (`02-mysql-privileges.md` §5). Read here, so every
    # command that describes the account before it changes it has it.
    held = admin.global_privileges(cursor, Principal(found.user, found.host))
    own = is_session_account(found, session_user or current_user(cursor))
    return replace(state, global_privileges=held, session_account=own)


def is_session_account(account: Account, session_user: str) -> bool:
    """Whether ``account`` is the one this session is connected as: the tool's
    own. Guardrail 7 refuses it unless ``--force`` waives that, and guardrail 9
    lets it through (#1225). Compared by
    :func:`~sopuli.config.products.same_mysql_account`, the one copy of the
    rule: the user exactly, the host without ASCII case."""
    return same_mysql_account(account.name, session_user)


def survey(cursor: Cursor, declared: Sequence[str]) -> tuple[str, ...]:
    """What `doctor --check-privileges` says about the declared accounts.

    One line for each declared account that does not exist, that uses another
    plugin, or whose user name also exists, unlocked, at a host the config
    does not declare. That other account logs in with a password of its own,
    which the tool does not manage. A locked one cannot log in, and a role is
    a locked account, so neither is reported.
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
            elif found.plugin != SUPPORTED_PLUGIN:
                lines.append(f"{found.name} {other_plugin(found.plugin)}: {OTHER_PLUGIN_HINT}")
        for row in rows[user]:
            if row.locked or any(same_host(row.host, host) for host in wanted):
                continue
            lines.append(
                f"{row.name} exists and the config does not declare it: it logs in as "
                f"{user} with a password of its own, which the tool does not change. "
                "Declare it, or lock or drop it"
            )
    return tuple(lines)
