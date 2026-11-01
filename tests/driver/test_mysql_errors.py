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


def test_a_closed_connection_with_no_number_is_a_connection_failure() -> None:
    """PyMySQL's ``InterfaceError(0, "")`` once the socket is closed."""
    diagnosis = from_error(FakeMysqlError(0, ""))

    assert diagnosis.category == "connectivity"
    assert diagnosis.coded_message == "2000: the connection is closed"
    assert "may have run" in str(diagnosis.hint)


class MessageOnlyError(Exception):
    """PyMySQL's errors that carry a message and no number."""


@pytest.mark.parametrize(
    "exc",
    [
        MessageOnlyError("Packet sequence number wrong - got 3 expected 1"),
        MessageOnlyError("Received extra packet for auth method %r", "caching_sha2_password"),
        MessageOnlyError(),
    ],
)
def test_an_error_with_no_number_is_classified_not_raised(exc: Exception) -> None:
    diagnosis = from_error(exc)

    assert diagnosis.code == "2000"
    assert diagnosis.category == "connectivity"
    assert diagnosis.message


@pytest.mark.parametrize("number", [2006, 2013])
def test_a_lost_connection_says_a_change_in_flight_is_unknown(number: int) -> None:
    assert "unknown until the account is checked" in str(classify(number, "").hint)


@pytest.mark.parametrize(
    ("number", "category"),
    [(1130, "authentication"), (1698, "authentication"), (1129, "connectivity")],
)
def test_a_login_refused_for_the_host_has_a_row(number: int, category: str) -> None:
    diagnosis = classify(number, "Host '192.0.2.1' is not allowed to connect")

    assert diagnosis.category == category
    assert diagnosis.hint


@pytest.mark.parametrize(
    ("number", "setting"),
    [(1203, "max_user_connections, a setting for every account"), (1226, "its own limits")],
)
def test_the_servers_limit_and_the_accounts_own_are_told_apart(number: int, setting: str) -> None:
    """1203 is the global `max_user_connections`; an account's own
    `MAX_USER_CONNECTIONS` answers 1226."""
    assert setting in str(classify(number, "").hint)


@pytest.mark.parametrize("number", [3024, 3572, 3819, 4031])
def test_a_server_number_from_3000_up_is_the_databases(number: int) -> None:
    """The client's own numbers stop at 2999."""
    assert classify(number, "").category == "database"


@pytest.mark.parametrize("number", [2059, 2061])
def test_a_plugin_pymysql_cannot_speak_is_an_authentication_failure(number: int) -> None:
    diagnosis = classify(number, "Authentication plugin 'auth_pam' not configured")

    assert diagnosis.category == "authentication"
    assert "plugin" in str(diagnosis.hint)


def test_a_failure_while_connecting_says_nothing_ran() -> None:
    """The handshake's own errors carry no number; no statement had been sent."""
    diagnosis = from_error(
        MessageOnlyError("unexpected packet during authentication"), connecting=True
    )

    assert diagnosis.category == "connectivity"
    assert "before any statement ran" in str(diagnosis.hint)
    assert "may have run" not in str(diagnosis.hint)


def test_the_message_is_scrubbed_before_anything_keeps_it() -> None:
    """A syntax error quotes the statement, and the statement carries a hash."""
    verifier = "0x2441243030352433"
    exc = FakeMysqlError(1064, f"You have an error in your SQL syntax near 'AS {verifier}'")

    diagnosis = from_error(exc, scrub=lambda text: text.replace(verifier, "***"))

    assert verifier not in diagnosis.coded_message
    assert verifier not in str(diagnosis.as_error())
    assert "AS ***" in diagnosis.message


def test_a_message_with_no_sqlstate_has_only_the_number_in_front() -> None:
    exc: Any = FakeMysqlError(2013, "Lost connection to MySQL server during query")

    assert from_error(exc).coded_message == "2013: Lost connection to MySQL server during query"
