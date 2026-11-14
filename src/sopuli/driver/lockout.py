"""The lockout guard's rule, shared by the drivers that have a guard (UC-1 §7
mitigation 2).

Oracle reads the count from ``SYS.USER$.LCOUNT`` and the limit from the
profile; MySQL reads both from ``performance_schema.temporary_account_locks``
(#1515). Each driver reads its own; this module decides from the two numbers,
and words a refusal, the same way for each. Pure: no I/O.
"""

from __future__ import annotations

from sopuli.driver.protocol import DEFAULT_MARGIN

#: What ``FAILED_LOGIN_ATTEMPTS`` says when there is no lockout to guard against.
UNLIMITED = "UNLIMITED"


def margin_reason(
    failed_logins: int | None,
    failed_login_limit: str | None,
    *,
    margin: int = DEFAULT_MARGIN,
    attempts: int = 1,
) -> str | None:
    """Why this run must not attempt a login, or ``None`` to go ahead.

    ``attempts`` is how many logins **this run intends against this account**,
    and it is a parameter rather than an assumed 1 because of what
    ``--include-previous`` does. Mitigation 1 sets a fixed budget per account per
    run; a flag that checks the previous password too makes it two, and restating
    the rule per *value checked* rather than per account would quietly double
    the spend on the counter the guard is protecting. Asking for the budget up
    front is what keeps the flag honest.

    Returns a sentence rather than a bool because it is reported: "we chose not
    to try" is a result (:data:`~sopuli.driver.protocol.SKIPPED`), and a result
    with no reason attached is indistinguishable at 03:00 from a run that did
    nothing.

    Two ways to have no guard, and they are not the same:

    * **``UNLIMITED``, or no limit** -- there is no lockout, so there is
      nothing to protect and the attempt goes ahead.
    * **``failed_logins is None``** -- the driver could not read the count: on
      Oracle, the optional grant on ``SYS.USER$`` was never made (decision P2),
      or the account is a common account whose count is in another container
      (#1122); on MySQL, the optional grant on ``temporary_account_locks`` was
      not made, or the server has no such table. The guard is *unavailable*.
      The attempt still goes ahead, because `check` runs without a
      site-specific grant -- but the caller is expected to say so plainly
      rather than let an absent guard look like a satisfied one.
    """
    if failed_login_limit is None or failed_login_limit.upper() == UNLIMITED:
        return None
    if failed_logins is None:
        return None

    try:
        limit = int(failed_login_limit)
    except ValueError:
        # A limit that is neither a number nor UNLIMITED is one this code does
        # not understand, and guessing at a lockout threshold is the wrong thing
        # to guess at. Refuse the attempt rather than spend an unknown budget.
        return (
            f"the profile's FAILED_LOGIN_ATTEMPTS is {failed_login_limit!r}, "
            "which is neither a count nor UNLIMITED"
        )

    remaining = limit - failed_logins
    if remaining - attempts < margin:
        return (
            f"{failed_logins} of {limit} failed logins are already recorded, "
            f"and {attempts} more would leave less than the {margin}-attempt margin"
        )
    return None


def skipped_detail(reason: str) -> str:
    """What a skipped verification says about itself."""
    return f"no login attempted: {reason}"


__all__ = ["UNLIMITED", "margin_reason", "skipped_detail"]
