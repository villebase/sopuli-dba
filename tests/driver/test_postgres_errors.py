"""The SQLSTATE mapping. Tier 0: an exception is read by its attributes.

The connection messages are psycopg 3.3.6's, from the tier-1 `postgres`
service (16).
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from sopuli.driver.postgres.errors import classify, from_error
from sopuli.driver.protocol import AuthenticationError
from sopuli.exit_codes import ExitCode

WRONG_PASSWORD = (
    'connection failed: connection to server at "127.0.0.1", port 5432 failed: '
    'FATAL:  password authentication failed for user "postgres"'
)
NO_HBA_LINE = (
    'connection failed: connection to server at "127.0.0.1", port 5432 failed: '
    'FATAL:  no pg_hba.conf entry for host "192.0.2.7", user "acme_app_user", '
    'database "postgres", no encryption'
)


class _PsycopgError(Exception):
    """A psycopg error's shape: a message and a ``sqlstate``."""

    def __init__(self, message: str, sqlstate: str | None = None) -> None:
        super().__init__(message)
        self.sqlstate = sqlstate


@pytest.mark.parametrize(
    ("code", "category", "exit_code"),
    [
        ("28P01", "authentication", ExitCode.AUTH_FAILURE),
        ("28000", "authentication", ExitCode.AUTH_FAILURE),
        ("42501", "authorization", ExitCode.FAILURE),
        ("42704", "database", ExitCode.FAILURE),
        ("25006", "database", ExitCode.FAILURE),
        ("3D000", "config", ExitCode.CONFIG_INVALID),
        ("08006", "connectivity", ExitCode.FAILURE),
        ("08P01", "connectivity", ExitCode.FAILURE),
        ("XX000", "database", ExitCode.FAILURE),
    ],
)
def test_each_sqlstate_has_its_category(code: str, category: str, exit_code: ExitCode) -> None:
    diagnosis = classify(code, "the server's own message")

    assert (diagnosis.code, diagnosis.category, diagnosis.exit_code) == (code, category, exit_code)
    assert diagnosis.message == "the server's own message"


@pytest.mark.parametrize("code", ["28P01", "28000", "42501", "42704", "25006", "3D000"])
def test_every_named_sqlstate_has_a_hint(code: str) -> None:
    assert classify(code, "").hint


def test_a_server_error_keeps_its_sqlstate() -> None:
    raised = _PsycopgError("cannot execute CREATE TABLE in a read-only transaction", "25006")

    diagnosis = from_error(raised)

    assert diagnosis.code == "25006"
    assert diagnosis.message == "cannot execute CREATE TABLE in a read-only transaction"
    assert "standby" in str(diagnosis.hint)


def test_a_wrong_password_is_recovered_from_the_message() -> None:
    """libpq reports a failed connection with no SQLSTATE."""
    error = from_error(_PsycopgError(WRONG_PASSWORD), connecting=True).as_error()

    assert isinstance(error, AuthenticationError)
    assert error.code == "28P01"
    assert error.exit_code == ExitCode.AUTH_FAILURE
    assert error.message == WRONG_PASSWORD
    assert error.hint == "the password this run used is not the one the cluster holds for this role"


def test_a_missing_hba_line_is_recovered_from_the_message() -> None:
    diagnosis = from_error(_PsycopgError(NO_HBA_LINE), connecting=True)

    assert diagnosis.code == "28000"
    assert "pg_hba.conf" in str(diagnosis.hint)


@pytest.mark.parametrize(
    "message",
    [
        'FATAL:  role "acme_app_user" is not permitted to log in',
        'FATAL:  role "acme_app_user" does not exist',
    ],
)
def test_a_refused_login_is_recovered_from_the_message(message: str) -> None:
    assert from_error(_PsycopgError(message), connecting=True).code == "28000"


def test_a_missing_database_is_recovered_from_the_message() -> None:
    message = 'FATAL:  database "acme" does not exist'

    assert from_error(_PsycopgError(message), connecting=True).code == "3D000"


def test_a_failed_connection_with_no_server_message_is_08001() -> None:
    diagnosis = from_error(SimpleNamespace(sqlstate=None), connecting=True)

    assert diagnosis.code == "08001"
    assert diagnosis.category == "connectivity"


def test_an_unverified_server_certificate_names_sslrootcert() -> None:
    """The default `verify-full` with no CA file, as libpq on Windows reports it."""
    message = (
        'connection failed: connection to server at "127.0.0.1", port 5633 failed: root '
        'certificate file "C:\\Users\\dba\\AppData\\Roaming/postgresql/root.crt" does not exist'
    )

    diagnosis = from_error(_PsycopgError(message), connecting=True)

    assert diagnosis.code == "08001"
    assert "postgres.sslrootcert" in str(diagnosis.hint)


def test_a_lost_connection_with_no_sqlstate_is_08006() -> None:
    """On an open session. A message that matches a login failure is not read
    as one there."""
    diagnosis = from_error(_PsycopgError(WRONG_PASSWORD))

    assert diagnosis.code == "08006"
    assert diagnosis.category == "connectivity"


def test_the_first_line_leads_with_the_code() -> None:
    assert classify("28P01", WRONG_PASSWORD).first_line == f"28P01: {WRONG_PASSWORD}"
