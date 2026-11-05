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
  a named host (:func:`competitor`). The MySQL driver logs in only there; the
  rule is :func:`~sopuli.driver.mysql_family.verification.competition`.

What the server answers at a login, measured on 11.8.9 with PyMySQL 1.2.3 and
the password as UTF-8 bytes:

| Account | Right password | Wrong password |
|---|---|---|
| open | logs in | ``1045`` |
| expired | logs in, then ``1820`` to the first statement | ``1045`` |
| expired, ``disconnect_on_expired_password = ON`` | ``1862`` | ``1045`` |
| locked | ``4151`` | ``1045`` |
| blocked after failed logins | ``4150`` | ``4150`` |
| ``REQUIRE SSL``, over a session without TLS | ``1045`` | ``1045`` |
| ``ed25519`` ``OR``, the second method (a rollover) | PyMySQL's own error | PyMySQL's own error |

The last row is PyMySQL's: the server asks for a second authentication, and
PyMySQL 1.2.3 takes only one. The first method of the ``OR`` logs in as the
open row does (``11_rollover_expiry_probe.py``, on 10.11.19 to 12.3.3).

``1820``, ``1862`` and ``4151`` say the password is right, for the account the
login reached. ``4150`` answers any password, so it says nothing. ``1045``
says the password is wrong only over TLS: an account that requires TLS
answers its right password with it too. So ``1045`` is a fail only where the
target's ``ssl_mode`` requires TLS. The lock cannot be read on MariaDB (#1267,
decision 2), so a locked account is logged in to, and answers ``4151``.

On an expired session the first statement is the TLS read, and it gets
``1820``. The session's TLS is then not confirmed. Neither plugin sends the
password, and under a mode that requires TLS PyMySQL refused a session
without it at connect.

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
from sopuli.driver.mysql.errors import MUST_CHANGE_PASSWORD_LOGIN
from sopuli.driver.mysql_family.accounts import current_user
from sopuli.driver.mysql_family.connection import (
    TLS_REQUIRED_MODES,
    connect_arguments,
    require_tls,
    settings_of,
)
from sopuli.driver.mysql_family.encryption import read_encryption
from sopuli.driver.mysql_family.errors import ACCESS_DENIED, MUST_CHANGE_PASSWORD
from sopuli.driver.mysql_family.verification import competition
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

    The arguments are :func:`~sopuli.driver.mysql_family.verification.competition`'s.
    """
    found = competition(declared, same_user, anonymous)
    if found.named_host:
        return (
            f"the login reaches the account the server matches from the tool's host, "
            f"which need not be {declared.name}"
        )
    if found.others:
        return (
            f"the user also exists as {', '.join(found.others)}, which a login from the "
            f"tool's host may reach instead of {declared.name}"
        )
    if found.named_anonymous:
        return (
            f"the server has the anonymous account {', '.join(found.named_anonymous)}, "
            f"which a login from a host it matches reaches instead of {declared.name}"
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


#: PyMySQL 1.2.3's own error, with no number, when the server asks for a
#: second authentication: for the second method of an ``ed25519`` ``OR``, which
#: a rollover sets, and for a wrong password on such an account. Measured on
#: 10.11.19, 11.4.13, 11.8.9 and 12.3.3 by ``11_rollover_expiry_probe.py``, RE1,
#: RE2 and RE5 (#1271, PR #1304). Matched as text anywhere in the error's
#: arguments, so a release that adds a number still matches.
MULTIPLE_SWITCHES = "received multiple auth switch requests"

#: What a login that met :data:`MULTIPLE_SWITCHES` says.
SECOND_METHOD = (
    "PyMySQL cannot finish a login the server asks to authenticate twice, which it does "
    "for the second method of an ed25519 `OR` (a rollover in progress) and for a wrong "
    "password on such an account, so this says nothing about the password"
)

#: Why a refusal over a session that need not be TLS says nothing.
NOT_OVER_TLS = (
    "the target's `mariadb.ssl_mode` does not require TLS, and an account that "
    "requires TLS answers its right password with the same refusal over a session "
    "without it"
)


def outcome(
    declared: Account, number: int, competing: str | None, *, tls: bool
) -> tuple[str, str] | None:
    """The result and detail for a login that ended with ``number``, or
    ``None`` where the number says nothing about the password and the caller
    raises it. ``competing`` is :func:`competitor`'s answer; ``tls`` whether
    the target's ``ssl_mode`` requires TLS."""
    if number == ACCESS_DENIED:
        if competing is None and tls:
            return FAIL, f"the server refused the password ({ACCESS_DENIED}); {UNGUARDED}"
        why = competing if competing is not None else NOT_OVER_TLS
        return UNAVAILABLE, (
            f"the server refused the password ({ACCESS_DENIED}), but {why}, so it says "
            f"nothing certain about {declared.name}"
        )
    if number in (MUST_CHANGE_PASSWORD, MUST_CHANGE_PASSWORD_LOGIN):
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
    tls = settings_of(target).ssl_mode in TLS_REQUIRED_MODES
    started = time.monotonic()
    try:
        connection = pymysql.connect(**arguments)
    except pymysql.err.MySQLError as error:
        return _ended(declared, error, competing, started, tls=tls, connecting=True)
    latency = _ms(started)
    try:
        with connection.cursor() as cursor:
            # The tool's own session's TLS rule, before anything else is read.
            require_tls(read_encryption(cursor), target)
            reached = current_user(cursor)
    except pymysql.err.MySQLError as error:
        return _ended(
            declared, error, competing, started, tls=tls, connecting=False, latency=latency
        )
    finally:
        # The login has answered. A socket that drops as it closes does not
        # change the answer.
        with suppress(pymysql.err.MySQLError):
            connection.close()
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
    tls: bool,
    connecting: bool,
    latency: int | None = None,
) -> VerifyResult:
    """The result for a login that ended in ``error``, at connect or after."""
    latency = _ms(started) if latency is None else latency
    if connecting and any(MULTIPLE_SWITCHES in str(arg) for arg in getattr(error, "args", ())):
        # Unavailable wherever no other account can answer too: a wrong
        # password and a right second method fail the same way here.
        LOG.debug("login as %s: PyMySQL met a second auth switch", declared.name)
        return VerifyResult(
            method=VERIFY_LOGIN, result=UNAVAILABLE, latency_ms=latency, detail=SECOND_METHOD
        )
    failure = from_error(error, connecting=connecting)
    LOG.debug("login as %s ended with %s in %.3fs", declared.name, failure.code, latency / 1000)
    result = outcome(declared, failure.number, competing, tls=tls) if failure.number else None
    if result is not None:
        return VerifyResult(
            method=VERIFY_LOGIN, result=result[0], latency_ms=latency, detail=result[1]
        )
    if not connecting:
        # The password was accepted. Where only the declared account can
        # answer, that settles it; elsewhere which account accepted it is
        # unknown. A result, not an exception: a scheduled check must not look
        # broken for a socket that dropped after the answer.
        if competing is None:
            return VerifyResult(
                method=VERIFY_LOGIN,
                result=PASS,
                latency_ms=latency,
                detail=(
                    f"the server accepted the password, and reading the session afterwards "
                    f"failed ({failure.code}); only {declared.name} can answer this login. "
                    f"{UNGUARDED}"
                ),
            )
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
