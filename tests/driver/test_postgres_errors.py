"""The SQLSTATE mapping. Tier 0: an exception is read by its attributes.

`WRONG_PASSWORD` and the root-certificate message are psycopg 3.3.6's, from
real runs against PostgreSQL 16. The others are the server's and libpq's text,
written in the shape psycopg gives a failed connection, and not measured.
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
        ("57P01", "connectivity", ExitCode.FAILURE),
        ("57014", "database", ExitCode.FAILURE),
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
    assert error.message == f"28P01: {WRONG_PASSWORD}"
    assert "the password this run used" in str(error.hint)
    assert "the role does not exist" in str(error.hint)


@pytest.mark.parametrize("code", ["28P01", "3D000", "08001"])
def test_a_raised_error_leads_with_its_code(code: str) -> None:
    """A PostgreSQL message never contains its SQLSTATE, so every view that
    prints the message would otherwise print no code."""
    error = classify(code, "the server's message").as_error()

    assert error.message == f"{code}: the server's message"


@pytest.mark.parametrize(
    "method", ["LDAP", "PAM", "RADIUS", "certificate", "Peer", "Ident", "GSSAPI"]
)
def test_another_methods_failed_login_is_28000(method: str) -> None:
    """Only the password methods fail with 28P01; the server sends 28000 for
    the rest. Each is still an authentication failure, exit 6."""
    message = f'FATAL:  {method} authentication failed for user "acme_app_user"'

    diagnosis = from_error(_PsycopgError(message), connecting=True)

    assert (diagnosis.code, diagnosis.exit_code) == ("28000", ExitCode.AUTH_FAILURE)


def test_the_first_attempts_reason_is_the_one_reported() -> None:
    """A name that resolves to two addresses gives one message per attempt."""
    message = (
        "connection failed: Multiple connection attempts failed. All failures were:\n"
        '- host: "localhost", port: 5432, hostaddr: "::1": connection failed: '
        'FATAL:  no pg_hba.conf entry for host "::1", user "acme_app_user", '
        'database "postgres", no encryption\n'
        '- host: "localhost", port: 5432, hostaddr: "127.0.0.1": connection failed: '
        'FATAL:  password authentication failed for user "acme_app_user"'
    )

    assert from_error(_PsycopgError(message), connecting=True).code == "28000"


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


@pytest.mark.parametrize(
    "message",
    [
        # The default `verify-full` with no CA file, as libpq on Windows reports it.
        'connection failed: connection to server at "127.0.0.1", port 5633 failed: root '
        'certificate file "C:\\Users\\dba\\AppData\\Roaming/postgresql/root.crt" does not exist',
        # The same, for an account with no home directory, such as a service.
        "connection failed: could not get home directory to locate root certificate file",
    ],
)
def test_an_unverified_server_certificate_names_sslrootcert(message: str) -> None:
    diagnosis = from_error(_PsycopgError(message), connecting=True)

    assert diagnosis.code == "08001"
    assert "postgres.sslrootcert" in str(diagnosis.hint)


#: PgBouncer 1.26.0's refusals, as psycopg 3.3.6 reported them (probe 08, PB6
#: and PB7, #1105).
_PGBOUNCER = 'connection failed: connection to server at "127.0.0.1", port 6432 failed: FATAL:  '


@pytest.mark.parametrize(
    ("refusal", "meaning"),
    [
        ("SASL authentication failed", "a wrong password, and for a role with no password"),
        ("no such user", "a role the server does not have"),
        (
            "server login has been failing, cached error: server DNS lookup failed "
            "(server_login_retry)",
            "cannot log in to the server behind it",
        ),
    ],
)
def test_a_pgbouncer_refusal_names_the_pooler(refusal: str, meaning: str) -> None:
    """It stays a connection failure: a pooler is not a supported target
    (#1045), so a refused password is not read as 28P01."""
    error = from_error(_PsycopgError(_PGBOUNCER + refusal), connecting=True).as_error()

    assert not isinstance(error, AuthenticationError)
    assert (error.code, error.category, error.exit_code) == (
        "08001",
        "connectivity",
        ExitCode.FAILURE,
    )
    assert "connection pooler" in str(error.hint)
    assert "#1045" in str(error.hint)
    assert meaning in str(error.hint)


def test_the_servers_refusal_through_pgbouncer_keeps_its_code() -> None:
    """Where auth_file holds another password than the server, PgBouncer passes
    on the server's own refusal (PB6)."""
    message = _PGBOUNCER + 'password authentication failed for user "acme_stale_user"'

    assert from_error(_PsycopgError(message), connecting=True).code == "28P01"


def test_a_pgbouncer_refusal_on_the_first_attempt_is_the_one_reported() -> None:
    message = (
        "connection failed: Multiple connection attempts failed. All failures were:\n"
        '- host: "localhost", port: 6432, hostaddr: "::1": connection failed: '
        "FATAL:  SASL authentication failed\n"
        '- host: "localhost", port: 6432, hostaddr: "127.0.0.1": connection failed: '
        'FATAL:  password authentication failed for user "acme_app_user"'
    )

    diagnosis = from_error(_PsycopgError(message), connecting=True)

    assert diagnosis.code == "08001"
    assert "connection pooler" in str(diagnosis.hint)


def test_a_lost_connection_with_no_sqlstate_is_08006() -> None:
    """On an open session. A message that matches a login failure is not read
    as one there."""
    diagnosis = from_error(_PsycopgError(WRONG_PASSWORD))

    assert diagnosis.code == "08006"
    assert diagnosis.category == "connectivity"


def test_the_first_line_leads_with_the_code() -> None:
    assert classify("28P01", WRONG_PASSWORD).first_line == f"28P01: {WRONG_PASSWORD}"


def test_no_connect_on_the_database_has_a_connect_hint() -> None:
    """No statement ran, so the rule's own hint about a statement does not fit."""
    diagnosis = from_error(
        _PsycopgError(
            'connection to server at "127.0.0.1", port 5432 failed: FATAL:  permission denied '
            'for database "postgres"\nDETAIL:  User does not have CONNECT privilege.'
        ),
        connecting=True,
    )

    assert diagnosis.code == "42501"
    assert "GRANT CONNECT ON DATABASE" in str(diagnosis.hint)
    assert "statement" not in str(diagnosis.hint)
