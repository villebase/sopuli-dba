"""Which accounts a login meant for one account may reach. Tier 0.

On MySQL and on MariaDB the server picks the account a login reaches from the
client's host, so a login as ``acme_app`` may reach an account other than the
declared one. Only a ``user@%`` account that is the user's only account, with
no anonymous account at a named host, is reached by every login as its user.
Both drivers log in to verify a password only there (#1223, #1270). The
MariaDB driver makes one exception: once per staged ``pending``, the login
after a change may reach another account, and it passes only when
``CURRENT_USER()`` is the declared one (CLAUDE.md invariant 5). Each driver
says why in its own words.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol

from sopuli.driver.mysql_family.accounts import same_host

#: The host of the one kind of account only its own login can reach.
ANY_HOST = "%"


class Named(Protocol):
    """An account as either driver reads it."""

    @property
    def host(self) -> str: ...

    @property
    def name(self) -> str: ...


@dataclass(frozen=True)
class Competition:
    """What else may answer a login meant for one account."""

    #: The declared account's host is not ``%``, so a login from the tool's
    #: host may match another account, or none.
    named_host: bool
    #: The user's other accounts, ``user@host``, sorted.
    others: tuple[str, ...]
    #: The anonymous accounts at a named host, ``''@host``, sorted. The server
    #: matches the host first, so one wins over ``acme_app@%`` for a client
    #: from that host. One at ``%`` does not: at one host, a named user wins.
    named_anonymous: tuple[str, ...]

    @property
    def none(self) -> bool:
        """Only the declared account can answer."""
        return not (self.named_host or self.others or self.named_anonymous)


def competition(
    declared: Named, same_user: Sequence[Named], anonymous: Sequence[Named] = ()
) -> Competition:
    """``same_user`` is every account with the declared user name, at any
    host, ``declared`` included; ``anonymous`` every account with the empty
    user name."""
    return Competition(
        named_host=not same_host(declared.host, ANY_HOST),
        others=tuple(sorted(a.name for a in same_user if not same_host(a.host, declared.host))),
        named_anonymous=tuple(
            sorted(f"''@{a.host}" for a in anonymous if not same_host(a.host, ANY_HOST))
        ),
    )
