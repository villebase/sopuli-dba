"""Which MySQL logins the tool attempts, and what each answer means (#1223).

Tier 0. The answers are the ones measured on 8.4.13 with PyMySQL 1.2.3 and
written in :mod:`sopuli.driver.mysql.verification`'s docstring.
"""

from __future__ import annotations

from datetime import datetime

import pytest

from sopuli.driver.mysql.accounts import Account
from sopuli.driver.mysql.errors import classify
from sopuli.driver.mysql.verification import (
    NO_GRANT,
    NO_TABLE,
    NOT_OVER_TLS,
    Lockout,
    lockout_from_row,
    login_outcome,
    not_tried_reason,
    unguarded_reason,
)
from sopuli.driver.protocol import FAIL, PASS, UNAVAILABLE

UNGUARDED = NO_GRANT


def account(host: str, user: str = "acme_app") -> Account:
    return Account(
        user=user,
        host=host,
        plugin="caching_sha2_password",
        locked=False,
        expired=False,
        changed_at=datetime(2026, 10, 1),
        lifetime_days=None,
    )


def test_a_user_s_only_account_at_any_host_is_logged_in_as() -> None:
    declared = account("%")

    assert not_tried_reason(declared, [declared]) is None


def test_an_account_at_a_named_host_is_not_logged_in_as() -> None:
    """The login reaches whichever account the server matches from the tool's
    host, which may not be this one."""
    declared = account("10.%")

    reason = not_tried_reason(declared, [declared])

    assert reason is not None
    assert "its host is `%` and it is the user's only account" in reason
    assert reason.endswith("no login was attempted")


def test_a_user_at_another_host_too_is_not_logged_in_as() -> None:
    """Measured: with `acme@%` and `acme@10.%`, a login from the tool's host
    reached `acme@%`, so a refusal could be the other account's."""
    declared = account("%")

    reason = not_tried_reason(declared, [declared, account("10.%"), account("localhost")])

    assert reason is not None
    assert "acme_app@10.%, acme_app@localhost" in reason


def test_an_anonymous_account_at_a_named_host_competes() -> None:
    """The server matches the host first, so `''@localhost` wins over
    `acme_app@%` for a client on localhost."""
    declared = account("%")

    reason = not_tried_reason(declared, [declared], [account("localhost", user="")])

    assert reason is not None
    assert "anonymous account ''@localhost" in reason


def test_an_anonymous_account_at_any_host_does_not_compete() -> None:
    """At one host a named user wins, so `''@%` never takes `acme_app@%`'s login."""
    declared = account("%")

    assert not_tried_reason(declared, [declared], [account("%", user="")]) is None


@pytest.mark.parametrize(
    ("number", "result"),
    [
        (1045, FAIL),
        (1862, PASS),
        (1820, PASS),
        (3118, PASS),
        (3955, UNAVAILABLE),
    ],
)
def test_each_answer_at_login_over_tls_says_what_it_shows(number: int, result: str) -> None:
    outcome = login_outcome(classify(number, "refused"), tls=True, unguarded=None)

    assert outcome is not None
    assert outcome[0] == result


def test_a_pass_or_fail_says_when_the_lockout_guard_is_unavailable() -> None:
    for number in (1045, 1862, 3118):
        outcome = login_outcome(classify(number, "refused"), tls=True, unguarded=UNGUARDED)
        assert outcome is not None
        assert outcome[1].endswith(f"; {UNGUARDED}")


def test_a_guarded_login_says_nothing_of_the_guard() -> None:
    for number in (1045, 1862, 3118):
        outcome = login_outcome(classify(number, "refused"), tls=True, unguarded=None)
        assert outcome is not None
        assert "lockout guard" not in outcome[1]


def test_a_refusal_where_tls_is_not_required_says_nothing() -> None:
    """Measured on 8.4.13: an account created REQUIRE SSL answers its right
    password with 1045 over a plain connection (#1410)."""
    outcome = login_outcome(classify(1045, "refused"), tls=False, unguarded=UNGUARDED)

    assert outcome is not None
    assert outcome[0] == UNAVAILABLE
    assert NOT_OVER_TLS in outcome[1]
    assert outcome[1].endswith(UNGUARDED), "a login was made, with no lockout guard"


@pytest.mark.parametrize(("number", "result"), [(1862, PASS), (3118, PASS), (3955, UNAVAILABLE)])
def test_the_other_answers_mean_the_same_without_tls(number: int, result: str) -> None:
    outcome = login_outcome(classify(number, "refused"), tls=False, unguarded=None)

    assert outcome is not None
    assert outcome[0] == result


def test_a_failure_that_says_nothing_about_the_password_is_raised() -> None:
    """A server that cannot be reached is the caller's to raise."""
    assert login_outcome(classify(2003, "Can't connect"), tls=True, unguarded=None) is None


# ------------------------------------------------------- the lockout guard ---


def test_a_row_gives_the_count_and_the_limit() -> None:
    """Measured on 9.7.4: after two wrong passwords of three, the row reads
    `NO, 3, 1` (#1515). The query reads the limit, the attempts left and
    `LOCKED`, in that order."""
    assert lockout_from_row((3, 1, "NO")) == Lockout(failed=2, limit=3, blocked=False)


def test_a_blocked_row_says_so() -> None:
    assert lockout_from_row((3, 0, b"YES")) == Lockout(failed=3, limit=3, blocked=True)


def test_no_row_is_nothing_to_guard() -> None:
    """An account with no limit, or a limit and no lock time, has no row, and
    the server never blocks it."""
    assert lockout_from_row(None) == Lockout()


def test_the_two_refusals_name_why_the_guard_is_unavailable() -> None:
    """`1142` without the grant, or on a server without the table; `1146` on
    a server without the table, under a broader grant. Anything else is
    raised by the caller."""
    assert unguarded_reason(1142) == NO_GRANT
    assert unguarded_reason(1146) == NO_TABLE
    assert unguarded_reason(2013) is None
