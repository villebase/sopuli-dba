"""What a MySQL error number means. Tier 0 (#1221).

The exceptions are written in the shape PyMySQL 1.2.3 raises,
``(number, message)`` in ``args`` and ``sqlstate`` on the instance, read from
its source. PR 3 of #1221 measures them against a server.
"""

from __future__ import annotations

from typing import Any

import pytest

from sopuli.driver.mysql.errors import (
    ACCESS_DENIED,
    ACCOUNT_BLOCKED,
    CANNOT_CONNECT,
    CERTIFICATE_HINT,
    TLS_CONNECTION_ERROR,
    MappedError,
    classify,
    from_error,
)
from sopuli.driver.protocol import AuthenticationError
from sopuli.exit_codes import ExitCode


class FakeMysqlError(Exception):
    """PyMySQL's error shape: ``args`` and an optional ``sqlstate``."""

    def __init__(self, number: int, message: str, sqlstate: str | None = None) -> None:
        super().__init__(number, message)
        self.sqlstate = sqlstate


def test_a_wrong_password_is_an_authentication_failure_with_the_mysql_clients_prefix() -> None:
    diagnosis = from_error(
        FakeMysqlError(1045, "Access denied for user 'sopuli_svc'@'192.0.2.1'", "28000")
    )

    assert diagnosis.number == ACCESS_DENIED
    assert diagnosis.code == "1045"
    assert diagnosis.category == "authentication"
    assert diagnosis.exit_code == ExitCode.AUTH_FAILURE
    assert diagnosis.coded_message == (
        "1045 (28000): Access denied for user 'sopuli_svc'@'192.0.2.1'"
    )
    error = diagnosis.as_error()
    assert isinstance(error, AuthenticationError)
    assert error.code == "1045"


@pytest.mark.parametrize(("number", "word"), [(3118, "ACCOUNT LOCK"), (3955, "FAILED_LOGIN")])
def test_a_lock_and_a_block_say_which_they_are(number: int, word: str) -> None:
    diagnosis = classify(number, "Access denied")

    assert diagnosis.category == "authentication"
    assert word in str(diagnosis.hint)


def test_a_block_says_the_right_password_is_refused_too() -> None:
    """Measured on #1202: `3955` answers the right password as well."""
    assert "right password too" in str(classify(ACCOUNT_BLOCKED, "").hint)


@pytest.mark.parametrize(
    ("number", "category"),
    [
        (1227, "authorization"),
        (1142, "authorization"),
        (1143, "authorization"),
        (1044, "authorization"),
        (1396, "database"),
        (1290, "database"),
        (3894, "database"),
    ],
)
def test_the_named_numbers_have_their_category(number: int, category: str) -> None:
    diagnosis = classify(number, "message")

    assert diagnosis.category == category
    assert diagnosis.hint
    assert isinstance(diagnosis.as_error(), MappedError)


def test_an_unnamed_server_number_is_the_databases() -> None:
    assert classify(1064, "You have an error in your SQL syntax").category == "database"


def test_an_unnamed_client_number_is_a_connection_failure() -> None:
    assert classify(2005, "Unknown MySQL server host").category == "connectivity"


def test_a_server_that_offers_no_tls_under_a_mode_that_requires_it() -> None:
    diagnosis = from_error(
        FakeMysqlError(TLS_CONNECTION_ERROR, "SSL is required but the server doesn't support it")
    )

    assert diagnosis.category == "connectivity"
    assert "lowering the mode sends the password in clear" in str(diagnosis.hint)


def test_a_certificate_that_fails_its_check_names_the_ca_setting() -> None:
    """PyMySQL wraps the ssl module's error in a 2003."""
    diagnosis = from_error(
        FakeMysqlError(
            CANNOT_CONNECT,
            "Can't connect to MySQL server on 'mysql-dev.example.com' ([SSL: "
            "CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer "
            "certificate (_ssl.c:1018))",
        )
    )

    assert diagnosis.hint == CERTIFICATE_HINT


def test_an_unreachable_server_is_a_connection_failure_with_no_certificate_hint() -> None:
    diagnosis = from_error(
        FakeMysqlError(CANNOT_CONNECT, "Can't connect to MySQL server on '192.0.2.20' (timed out)")
    )

    assert diagnosis.category == "connectivity"
    assert diagnosis.hint is None
    assert diagnosis.coded_message.startswith("2003: ")


def test_a_message_with_no_sqlstate_has_only_the_number_in_front() -> None:
    exc: Any = FakeMysqlError(2013, "Lost connection to MySQL server during query")

    assert from_error(exc).coded_message == "2013: Lost connection to MySQL server during query"
