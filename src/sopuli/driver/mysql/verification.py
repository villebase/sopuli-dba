"""What a login as a managed MySQL account shows about its password (#1223).

`creds check` verifies a password by logging in as the account. On MySQL the
server picks the account a login reaches from the **client's host**: a login
as `acme_app` from the tool's host reaches `acme_app@%`, or a more specific
account, or none. Measured on 8.4.13: with `acme_app@%` and `acme_app@10.%`,
a login from the tool's host reached `acme_app@%`, and `acme_app@10.%`'s own
password was refused with `1045`. A refusal names the client's host, not the
account that refused, so it cannot be told apart from a wrong password.

So the tool logs in only where nothing else can answer: the declared account
is `user@%`, and no other account has that user name (decided on #1223,
2026-11-02). Any other declared account is reported
:data:`~sopuli.driver.protocol.UNAVAILABLE` without a login, saying why. After
a login, ``CURRENT_USER()`` confirms which account answered.

What a login answers, measured on 8.4.13 with PyMySQL 1.2.3:

| Account | Right password | Wrong password |
|---|---|---|
| open | logs in | `1045` |
| expired | `1862` at connect | `1045` |
| locked | `3118` | `1045` |

`1862` and `3118` therefore say the password is right. PyMySQL does not say
it can handle an expired password, so the server refuses at connect with
`1862`, and the mysql client's `1820` after login does not arise. A block
after failed logins (`3955`) answers the right password too, so it says
nothing about it.

**There is no lockout guard.** `FAILED_LOGIN_ATTEMPTS` and its counter are in
`mysql.user.User_attributes`, which the tool account cannot read (#1202,
decision 6). A login therefore goes ahead, as on Oracle without the
`SYS.USER$` grant, and the result says the guard is unavailable.
"""

from __future__ import annotations

from collections.abc import Sequence

from sopuli.driver.mysql.accounts import Account, same_host
from sopuli.driver.mysql.errors import (
    ACCESS_DENIED,
    ACCOUNT_BLOCKED,
    ACCOUNT_LOCKED,
    MUST_CHANGE_PASSWORD,
    MUST_CHANGE_PASSWORD_LOGIN,
    Diagnosis,
)
from sopuli.driver.protocol import FAIL, PASS, UNAVAILABLE

#: The host of the one kind of account a login can only reach: any host.
ANY_HOST = "%"

#: Said on every login, because MySQL gives the tool nothing to guard it with.
UNGUARDED = (
    "the lockout guard is unavailable: MySQL keeps FAILED_LOGIN_ATTEMPTS and its "
    "counter in mysql.user.User_attributes, which the tool account does not read"
)


def not_tried_reason(
    declared: Account, same_user: Sequence[Account], anonymous: Sequence[Account] = ()
) -> str | None:
    """Why the tool does not log in as ``declared``, or ``None`` to log in.

    ``same_user`` is every account with the declared user name, at any host,
    ``declared`` included. ``anonymous`` is every account with the empty user
    name. A login can reach only ``declared`` when its host is ``%``, it is the
    user's only account, and no anonymous account sits at a named host.

    **An anonymous account competes.** The server matches the host first, so
    ``''@localhost`` wins over ``acme_app@%`` for a client on ``localhost``,
    and the right password would then be refused with ``1045``. An anonymous
    account at ``%`` does not: at one host, a named user wins.
    """
    others = sorted(
        account.name for account in same_user if not same_host(account.host, declared.host)
    )
    named_anonymous = sorted(
        f"''@{account.host}" for account in anonymous if not same_host(account.host, ANY_HOST)
    )
    if not same_host(declared.host, ANY_HOST):
        return (
            f"a login reaches the account the server matches from the tool's host, which "
            f"may not be {declared.name}, so its password is checked by login only where "
            f"its host is `%` and it is the user's only account; no login was attempted"
        )
    if others:
        return (
            f"the user also exists as {', '.join(others)}, and a login from the tool's "
            f"host may reach one of those instead of {declared.name}; no login was attempted"
        )
    if named_anonymous:
        return (
            f"the server has the anonymous account {', '.join(named_anonymous)}, and a "
            f"login from a host it matches reaches it instead of {declared.name}; no login "
            f"was attempted"
        )
    return None


def login_outcome(diagnosis: Diagnosis) -> tuple[str, str] | None:
    """The result and detail for a login that failed with ``diagnosis``, or
    ``None`` where the failure says nothing about the password, and the caller
    raises it."""
    if diagnosis.number == ACCESS_DENIED:
        return FAIL, f"the server refused the password ({ACCESS_DENIED}); {UNGUARDED}"
    if diagnosis.number in (MUST_CHANGE_PASSWORD_LOGIN, MUST_CHANGE_PASSWORD):
        return PASS, (
            f"the server accepted the password, and then refused the session because "
            f"the password has expired ({diagnosis.number}); {UNGUARDED}"
        )
    if diagnosis.number == ACCOUNT_LOCKED:
        return PASS, (
            f"the server accepted the password, and then refused the session because "
            f"the account is locked ({ACCOUNT_LOCKED}); {UNGUARDED}"
        )
    if diagnosis.number == ACCOUNT_BLOCKED:
        return UNAVAILABLE, (
            f"the account is blocked after failed logins ({ACCOUNT_BLOCKED}), which the "
            f"server answers to any password, so this says nothing about it"
        )
    return None
