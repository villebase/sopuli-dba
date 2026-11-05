"""What a login as a managed MariaDB account shows (#1270). Tier 0: the
rule that decides when an answer counts, by the numbers 11.8.9 sent."""

from __future__ import annotations

import pytest

from sopuli.driver.mariadb.accounts import Account
from sopuli.driver.mariadb.errors import ACCOUNT_BLOCKED, ACCOUNT_LOCKED, RULES
from sopuli.driver.mariadb.verification import UNGUARDED, competitor, outcome
from sopuli.driver.mysql.errors import MUST_CHANGE_PASSWORD_LOGIN
from sopuli.driver.mysql_family.errors import ACCESS_DENIED, MUST_CHANGE_PASSWORD
from sopuli.driver.protocol import FAIL, PASS, UNAVAILABLE

ANY = Account(user="acme_app", host="%", plugin="ed25519")
LOCAL = Account(user="acme_app", host="localhost", plugin="ed25519")


def _anonymous(host: str) -> Account:
    return Account(user="", host=host, plugin="mysql_native_password")


def test_only_the_users_sole_account_at_any_host_has_no_competitor() -> None:
    assert competitor(ANY, [ANY]) is None
    # An anonymous account at `%` loses to a named user at one host.
    assert competitor(ANY, [ANY], [_anonymous("%")]) is None


@pytest.mark.parametrize(
    ("declared", "same_user", "anonymous", "words"),
    [
        (LOCAL, [LOCAL], [], "which need not be acme_app@localhost"),
        (ANY, [ANY, LOCAL], [], "also exists as acme_app@localhost"),
        (ANY, [ANY], [_anonymous("localhost")], "anonymous account ''@localhost"),
    ],
)
def test_another_account_that_may_answer_is_named(
    declared: Account, same_user: list[Account], anonymous: list[Account], words: str
) -> None:
    reason = competitor(declared, same_user, anonymous)

    assert reason is not None
    assert words in reason


def test_a_refusal_fails_only_over_tls_where_nothing_else_answers() -> None:
    assert outcome(ANY, ACCESS_DENIED, None, tls=True) == (
        FAIL,
        f"the server refused the password ({ACCESS_DENIED}); {UNGUARDED}",
    )
    result, detail = outcome(LOCAL, ACCESS_DENIED, "another account may answer", tls=True) or (
        "",
        "",
    )
    assert result == UNAVAILABLE
    assert "nothing certain about acme_app@localhost" in detail


def test_a_refusal_without_tls_says_nothing() -> None:
    """`REQUIRE SSL` answers its right password with `1045` over a session
    without TLS (measured on 11.8.9)."""
    result, detail = outcome(ANY, ACCESS_DENIED, None, tls=False) or ("", "")

    assert result == UNAVAILABLE
    assert "does not require TLS" in detail


@pytest.mark.parametrize(
    ("number", "why"),
    [
        (MUST_CHANGE_PASSWORD, "has expired"),
        # `disconnect_on_expired_password = ON` (11.8.9).
        (MUST_CHANGE_PASSWORD_LOGIN, "has expired"),
        (ACCOUNT_LOCKED, "is locked"),
    ],
)
def test_an_answer_only_the_right_password_gets_passes_where_nothing_else_answers(
    number: int, why: str
) -> None:
    result, detail = outcome(ANY, number, None, tls=False) or ("", "")
    assert result == PASS
    assert why in detail
    assert f"({number})" in detail

    result, detail = outcome(LOCAL, number, "another account may answer", tls=True) or ("", "")
    assert result == UNAVAILABLE


def test_a_block_answers_any_password_and_says_nothing() -> None:
    result, detail = outcome(ANY, ACCOUNT_BLOCKED, None, tls=True) or ("", "")

    assert result == UNAVAILABLE
    assert f"({ACCOUNT_BLOCKED})" in detail


def test_any_other_number_is_left_to_the_caller() -> None:
    assert outcome(ANY, 2003, None, tls=True) is None


@pytest.mark.parametrize("number", [ACCOUNT_LOCKED, ACCOUNT_BLOCKED])
def test_mariadbs_own_numbers_are_authentication_failures(number: int) -> None:
    assert RULES[number].category == "authentication"
