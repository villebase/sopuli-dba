"""What a login as a managed MariaDB account shows about its password (#1270).

`creds check`, and the check after a change, log in as the account with the
password. The server picks the account a login reaches from the **client's
host** (``05_identity_grants_probe.py``, ID1): a login as ``acme_app`` from the
tool's host reaches ``acme_app@%`` even where ``acme_app@localhost`` is the one
declared. So the result counts only when the login is known to have reached
the declared account (#1267, decision 8):

- a session that reads ``CURRENT_USER()`` as the declared account passes;
- a session that reads another account says nothing about the declared one;
- an answer that comes before ``CURRENT_USER()`` can be read says something
  only where no other account can answer: the declared account is
  ``user@%``, it is the user's only account, and no anonymous account sits at
  a named host (:func:`competitor`). The same rule decides where the MySQL
  driver logs in at all (:mod:`sopuli.driver.mysql.verification`).

What the server answers at a login, measured on 11.8.9 with PyMySQL 1.2.3 and
the password as UTF-8 bytes:

| Account | Right password | Wrong password |
|---|---|---|
| open | logs in | ``1045`` |
| expired | logs in, then ``1820`` to ``SELECT CURRENT_USER()`` | ``1045`` |
| locked | ``4151`` | ``1045`` |
| blocked after failed logins | ``4150`` | ``4150`` |

``1820`` and ``4151`` say the password is right, for the account the login
reached. ``4150`` answers any password, so it says nothing. The lock cannot be
read on MariaDB (#1267, decision 2), so a locked account is logged in to, and
answers ``4151``.

**There is no lockout guard.** MariaDB counts failed logins against
``max_password_errors`` in ``mysql.global_priv``, beside the stored value, which
the tool account does not read. A failed login counts on the account it
reaches; that is an accepted cost of decision 8 (``02-mariadb-privileges.md``
§7).
"""

from __future__ import annotations

import time
from collections.abc import Sequence
from contextlib import suppress
from typing import Any

from sopuli.config.model import ExpandedTarget
from sopuli.config.products import same_mysql_account
from sopuli.driver.mariadb.accounts import Account
from sopuli.driver.mariadb.errors import ACCOUNT_BLOCKED, ACCOUNT_LOCKED, from_error
from sopuli.driver.mysql_family.accounts import same_host, text
from sopuli.driver.mysql_family.connection import connect_arguments, require_tls
from sopuli.driver.mysql_family.encryption import read_encryption
from sopuli.driver.mysql_family.errors import ACCESS_DENIED, MUST_CHANGE_PASSWORD
from sopuli.driver.protocol import (
    FAIL,
    PASS,
    UNAVAILABLE,
    VERIFY_LOGIN,
    Credential,
    Timeouts,
    VerifyResult,
)
from sopuli.output.debug import logger
from sopuli.secrets import Secret

LOG = logger("mariadb")

#: The host of the one kind of account only its own login can reach.
ANY_HOST = "%"

#: The account a session is connected as: ``user@host``, the account's own
#: host pattern, not the client's address.
CURRENT_USER = "select current_user()"

#: Said on every login, because MariaDB gives the tool nothing to guard it with.
UNGUARDED = (
    "the lockout guard is unavailable: MariaDB counts failed logins against "
    "max_password_errors in mysql.global_priv, which the tool account does not read"
)


def competitor(
    declared: Account, same_user: Sequence[Account], anonymous: Sequence[Account] = ()
) -> str | None:
    """Why a login meant for ``declared`` may reach another account, or
    ``None`` where only ``declared`` can answer it.

    ``same_user`` is every account with the declared user name, at any host,
    ``declared`` included. ``anonymous`` is every account with the empty user
    name. **An anonymous account at a named host competes**: the server
    matches the host first, so ``''@localhost`` wins over ``acme_app@%`` for a
    client on ``localhost``. One at ``%`` does not: at one host, a named user
    wins.
    """
    if not same_host(declared.host, ANY_HOST):
        return (
            f"the login reaches the account the server matches from the tool's host, "
            f"which need not be {declared.name}"
        )
    others = sorted(
        account.name for account in same_user if not same_host(account.host, declared.host)
    )
    if others:
        return (
            f"the user also exists as {', '.join(others)}, which a login from the tool's "
            f"host may reach instead of {declared.name}"
        )
    named_anonymous = sorted(
        f"''@{account.host}" for account in anonymous if not same_host(account.host, ANY_HOST)
    )
    if named_anonymous:
        return (
            f"the server has the anonymous account {', '.join(named_anonymous)}, which a "
            f"login from a host it matches reaches instead of {declared.name}"
        )
    return None


def _accepted(declared: Account, competing: str | None, why: str, number: int) -> tuple[str, str]:
    """A refusal the server sends only to the right password: a pass where
    only ``declared`` can answer, and nothing certain otherwise."""
    if competing is None:
        return PASS, (
            f"the server accepted the password, and then refused the session because {why} "
            f"({number}); {UNGUARDED}"
        )
    return UNAVAILABLE, (
        f"the server accepted the password and refused the session because {why} "
        f"({number}), but {competing}, so it says nothing certain about {declared.name}"
    )


def outcome(declared: Account, number: int, competing: str | None) -> tuple[str, str] | None:
    """The result and detail for a login that ended with ``number``, or
    ``None`` where the number says nothing about the password and the caller
    raises it. ``competing`` is :func:`competitor`'s answer."""
    if number == ACCESS_DENIED:
        if competing is None:
            return FAIL, f"the server refused the password ({ACCESS_DENIED}); {UNGUARDED}"
        return UNAVAILABLE, (
            f"the server refused the password ({ACCESS_DENIED}), but {competing}, and a "
            f"refusal does not say which account refused, so it says nothing certain "
            f"about {declared.name}"
        )
    if number == MUST_CHANGE_PASSWORD:
        return _accepted(declared, competing, "the password has expired", number)
    if number == ACCOUNT_LOCKED:
        return _accepted(declared, competing, "the account is locked", number)
    if number == ACCOUNT_BLOCKED:
        return UNAVAILABLE, (
            f"the account is blocked after failed logins ({ACCOUNT_BLOCKED}), which the "
            f"server answers to any password, so this says nothing about it"
        )
    return None


def login(
    target: ExpandedTarget,
    declared: Account,
    secret: Secret,
    *,
    competing: str | None,
    correlation_id: str,
    timeouts: Timeouts,
) -> VerifyResult:
    """Log in once as ``declared`` with ``secret``, over the target's own TLS
    settings, timeouts and ``program_name``, and say what that showed.

    ``competing`` is :func:`competitor`'s answer for ``declared``. A failure
    that says nothing about the password is raised as the driver's error."""
    # Imported here: only the session module may import a vendor client at
    # module scope (tests/store/test_install_shape.py), and it has already
    # imported PyMySQL by the time a login is made.
    import pymysql

    arguments = connect_arguments(
        target,
        Credential(username=declared.user, secret=secret),
        correlation_id=correlation_id,
        timeouts=timeouts,
    )
    started = time.monotonic()
    try:
        connection = pymysql.connect(**arguments)
    except pymysql.err.MySQLError as error:
        return _ended(declared, error, competing, started, connecting=True)
    latency = _ms(started)
    try:
        with connection.cursor() as cursor:
            # The tool's own session's TLS rule, before anything else is read.
            require_tls(read_encryption(cursor), target)
            cursor.execute(CURRENT_USER)
            (answered,) = cursor.fetchone()
    except pymysql.err.MySQLError as error:
        return _ended(declared, error, competing, started, connecting=False, latency=latency)
    finally:
        # The login has answered. A socket that drops as it closes does not
        # change the answer.
        with suppress(pymysql.err.MySQLError):
            connection.close()
    reached = text(answered)
    if not same_mysql_account(reached, declared.name):
        return VerifyResult(
            method=VERIFY_LOGIN,
            result=UNAVAILABLE,
            latency_ms=latency,
            detail=(
                f"the login reached {reached}, not {declared.name}, so it says nothing "
                "about the declared account's password"
            ),
        )
    LOG.debug("login as %s: pass in %.3fs", declared.name, latency / 1000)
    return VerifyResult(method=VERIFY_LOGIN, result=PASS, latency_ms=latency, detail=UNGUARDED)


def _ended(
    declared: Account,
    error: Any,
    competing: str | None,
    started: float,
    *,
    connecting: bool,
    latency: int | None = None,
) -> VerifyResult:
    """The result for a login that ended in ``error``, at connect or after."""
    latency = _ms(started) if latency is None else latency
    failure = from_error(error, connecting=connecting)
    LOG.debug("login as %s ended with %s in %.3fs", declared.name, failure.code, latency / 1000)
    result = outcome(declared, failure.number, competing) if failure.number else None
    if result is not None:
        return VerifyResult(
            method=VERIFY_LOGIN, result=result[0], latency_ms=latency, detail=result[1]
        )
    if not connecting:
        # The password was accepted, and which account accepted it is
        # unknown. A result, not an exception: a scheduled check must not look
        # broken for a socket that dropped after the answer.
        return VerifyResult(
            method=VERIFY_LOGIN,
            result=UNAVAILABLE,
            latency_ms=latency,
            detail=(
                f"the login succeeded, and reading which account it reached failed "
                f"({failure.code}), so it says nothing certain about {declared.name}"
            ),
        )
    raise failure.as_error() from error


def _ms(started: float) -> int:
    """Milliseconds since ``started``, a :func:`time.monotonic` reading."""
    return round((time.monotonic() - started) * 1000)
