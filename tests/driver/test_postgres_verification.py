"""What a login as a managed role says about its password. Tier 0, pure.

The messages are libpq's and the server's, in the shape #1032 and #1040
measured: a failed login reaches the client with no SQLSTATE, so the code is
recovered from the text.
"""

from __future__ import annotations

import pytest

from sopuli.driver.postgres.errors import from_error
from sopuli.driver.postgres.verification import HBA_HINT, WRONG_PASSWORD_DETAIL, login_outcome
from sopuli.driver.protocol import FAIL, PASS, UNAVAILABLE


class _FailedLoginError(Exception):
    """A failed connection as psycopg raises it: a message, no SQLSTATE."""

    sqlstate = None


def outcome(message: str) -> tuple[str, str | None] | None:
    return login_outcome(from_error(_FailedLoginError(message), connecting=True))


def test_a_wrong_password_is_a_fail_that_names_the_md5_case() -> None:
    """The server answers an md5 verifier behind a scram-sha-256 line the same way."""
    assert outcome(
        'connection failed: connection to server at "127.0.0.1", port 5432 failed: '
        'FATAL:  password authentication failed for user "acme_app_user"'
    ) == (FAIL, WRONG_PASSWORD_DETAIL)


def test_the_first_attempts_reason_is_the_one_that_counts() -> None:
    """A host with two addresses: the password was tried at the first, and
    refused, so it is a fail, whatever the second attempt said."""
    result = outcome(
        'connection to server at "192.0.2.10", port 5432 failed: FATAL:  password '
        'authentication failed for user "acme_app_user"\n'
        'connection to server at "192.0.2.11", port 5432 failed: authentication method '
        'requirement "scram-sha-256" failed: server requested a cleartext password'
    )

    assert result is not None
    assert result[0] == FAIL


@pytest.mark.parametrize(
    "server",
    [
        'FATAL:  no pg_hba.conf entry for host "192.0.2.10", user "acme_app_user", '
        'database "postgres", no encryption',
        'FATAL:  pg_hba.conf rejects connection for host "192.0.2.10", user "acme_app_user"',
        'FATAL:  role "acme_app_user" is not permitted to log in',
    ],
    ids=["no line", "a reject line", "nologin"],
)
def test_a_login_refused_for_another_reason_is_unavailable(server: str) -> None:
    result = outcome(f'connection to server at "127.0.0.1", port 5432 failed: {server}')

    assert result is not None
    assert result[0] == UNAVAILABLE
    assert result[1] is not None
    assert result[1].startswith("28000: ")
    assert "says nothing about it" in result[1]
    assert result[1].endswith(HBA_HINT)


@pytest.mark.parametrize(
    "asked",
    [
        "server requested a cleartext password",
        "server requested a hashed password",
        "server did not complete authentication",
    ],
    ids=["password line", "md5 verifier", "trust line"],
)
def test_a_server_that_does_not_use_scram_is_unavailable(asked: str) -> None:
    """libpq refuses before it sends the password. A trust line would otherwise
    let any password in, and read as a match."""
    result = outcome(
        'connection to server at "127.0.0.1", port 5432 failed: '
        f'authentication method requirement "scram-sha-256" failed: {asked}'
    )

    assert result is not None
    assert result[0] == UNAVAILABLE
    assert f"({asked})" in str(result[1])
    assert "the password was not tried" in str(result[1])


@pytest.mark.parametrize(
    ("server", "code"),
    [
        (
            'FATAL:  permission denied for database "postgres"\n'
            "DETAIL:  User does not have CONNECT privilege.",
            "42501",
        ),
        ('FATAL:  too many connections for role "acme_app_user"', "53300"),
    ],
    ids=["no connect", "connection limit"],
)
def test_a_refusal_after_the_password_is_a_pass(server: str, code: str) -> None:
    """The server says these only once the password was accepted (16.15)."""
    result = outcome(f'connection to server at "127.0.0.1", port 5432 failed: {server}')

    assert result is not None
    assert result[0] == PASS
    assert f"refused the session: {code}: " in str(result[1])


@pytest.mark.parametrize(
    "message",
    [
        'connection to server at "127.0.0.1", port 5432 failed: Connection refused',
        "connection timeout expired",
        'FATAL:  database "nosuch" does not exist',
    ],
    ids=["refused port", "timeout", "no database"],
)
def test_any_other_failure_is_not_an_answer_about_the_password(message: str) -> None:
    assert outcome(message) is None
