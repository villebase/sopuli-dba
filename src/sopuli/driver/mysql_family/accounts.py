"""An account as MySQL and MariaDB name it: a user name and a host. Tier 0.

The config names an account ``user@host`` (#1202, decision 4). One user name
can exist at several hosts, each its own account with its own password
(``sql/mysql/05_identity_grants_probe.py``, ID1). The server compares the user
name by case and the host without case (ID3), and so does this module
(decision 3). MariaDB names and compares accounts the same way
(``sql/mariadb/05_identity_grants_probe.py``).

The config's own matcher is :func:`sopuli.config.products.same_mysql_host`,
which the config layer keeps because it does no I/O; :func:`same_host` here
calls it, so the two cannot drift apart.
"""

from __future__ import annotations

from dataclasses import dataclass

from sopuli.config.products import same_mysql_host
from sopuli.driver.protocol import Cursor, DriverError
from sopuli.exit_codes import ExitCode

#: The account the session authenticated as: ``user@host``, with the host as
#: the account's own pattern (``%``), not the client's address.
CURRENT_USER = "select current_user()"

#: ``UserState.status`` and ``SurveyedAccount.status`` on MySQL and MariaDB,
#: in the words Oracle uses for the same states.
OPEN = "OPEN"
LOCKED = "LOCKED"
EXPIRED = "EXPIRED"
EXPIRED_AND_LOCKED = "EXPIRED & LOCKED"


class BareAccountError(DriverError):
    """A MySQL or MariaDB account named without its host. The config refuses
    one first; this is the driver's own second line. ``config``, exit 9."""

    category = "config"
    exit_code = ExitCode.CONFIG_INVALID

    def __init__(self, account: str) -> None:
        super().__init__(
            f'account "{account}" has no host',
            hint=f"name it with its host, such as {account}@10.%",
        )


def text(value: object) -> str:
    """A column as text: PyMySQL returns some ``mysql`` columns as bytes."""
    return value.decode("utf-8") if isinstance(value, bytes) else str(value)


def current_user(cursor: Cursor) -> str:
    """The account this session is connected as, ``user@host``. It is the
    account the server matched at login, so a tool connected as
    ``sopuli_svc@%`` is that account, whichever address it came from. It does
    not change for the life of a connection, so a session reads it once."""
    cursor.execute(CURRENT_USER)
    (value,) = cursor.fetchone()
    return text(value)


def split(account: str) -> tuple[str, str]:
    """``user@host`` as its two parts, split at the last ``@``. A user name
    may hold ``@``; a host pattern may not. Trailing spaces in the user name
    are dropped, as the server drops them."""
    user, at, host = account.rpartition("@")
    user = user.rstrip(" ")
    if not at or not user or not host:
        raise BareAccountError(account)
    return user, host


def same_host(left: str, right: str) -> bool:
    """Hosts compare without case, as the server compares them (ID3). The rule
    is :func:`sopuli.config.products.same_mysql_host`'s, so the config's
    matcher and the driver's reads cannot drift apart."""
    return same_mysql_host(left, right)


@dataclass(frozen=True, order=True)
class Principal:
    """An account or a role: both are a user name and a host."""

    user: str
    host: str

    def __str__(self) -> str:
        return f"{self.user}@{self.host}"

    def key(self) -> tuple[str, str]:
        """The server's identity of it: the host without case (ID3), folding
        only ASCII letters, as ``ascii_general_ci`` does."""
        return (self.user, self.host.translate(_ASCII_LOWER))

    def sql(self) -> str:
        """The account as a statement names it, each part between backquotes.
        A backquoted name escapes only a doubled backquote, so it names the
        same account under every ``sql_mode``. A string literal does not:
        ``NO_BACKSLASH_ESCAPES`` changes what a backslash in it means, and
        ``ANSI_QUOTES`` makes a double-quoted one an identifier."""
        return f"{_backquote(self.user)}@{_backquote(self.host)}"


def _backquote(name: str) -> str:
    return "`" + name.replace("`", "``") + "`"


_ASCII_LOWER = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")
