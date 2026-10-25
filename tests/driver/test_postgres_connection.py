"""The PostgreSQL connection arguments, built from a target. Tier 0."""

from __future__ import annotations

import pytest

from sopuli.config.model import ExpandedTarget, Target, TargetPostgres
from sopuli.driver.postgres.connection import (
    application_name,
    connect_arguments,
    host_and_port,
)
from sopuli.driver.protocol import Credential, Timeouts
from sopuli.secrets import Secret

PASSWORD = "Tr0ub4dor-and-3"
RUN = "5b0d3f5e-2c0a-4c43-9d6c-0e6f1d2a7b11"


def _target(
    dsn: str = "pg-dev.example.com:5432", block: TargetPostgres | None = None
) -> ExpandedTarget:
    return ExpandedTarget(target=Target(name="pg-dev", type="postgresql", dsn=dsn, postgres=block))


def _arguments(target: ExpandedTarget, timeouts: Timeouts | None = None) -> dict[str, object]:
    return connect_arguments(
        target,
        Credential(username="sopuli_admin", secret=Secret(PASSWORD)),
        correlation_id=RUN,
        timeouts=timeouts or Timeouts(),
    )


def test_a_target_with_no_block_connects_with_the_defaults() -> None:
    arguments = _arguments(_target())

    assert arguments == {
        "host": "pg-dev.example.com",
        "port": 5432,
        "dbname": "postgres",
        "user": "sopuli_admin",
        "sslmode": "verify-full",
        "application_name": f"sopuli {RUN}",
        "connect_timeout": Timeouts().connect_s,
        "password": PASSWORD,
    }


def test_the_block_sets_the_database_and_tls() -> None:
    block = TargetPostgres(database="acme", sslmode="require", sslrootcert="/etc/sopuli/ca.pem")

    arguments = _arguments(_target(block=block))

    assert arguments["dbname"] == "acme"
    assert arguments["sslmode"] == "require"
    assert arguments["sslrootcert"] == "/etc/sopuli/ca.pem"


def test_the_password_is_only_in_its_own_argument() -> None:
    """Never in a string that a log line or an error could repeat."""
    arguments = _arguments(_target())

    others = [value for key, value in arguments.items() if key != "password"]
    assert not any(PASSWORD in str(value) for value in others)


@pytest.mark.parametrize(
    ("dsn", "expected"),
    [
        ("pg-dev.example.com:5432", ("pg-dev.example.com", 5432)),
        ("192.0.2.10:6432", ("192.0.2.10", 6432)),
        ("[2001:db8::10]:5432", ("2001:db8::10", 5432)),
    ],
)
def test_the_dsn_splits_into_host_and_port(dsn: str, expected: tuple[str, int]) -> None:
    """libpq takes an IPv6 address without its brackets."""
    assert host_and_port(dsn) == expected


def test_a_query_budget_becomes_a_statement_timeout() -> None:
    arguments = _arguments(_target(), Timeouts(connect_s=5, query_s=30))

    assert arguments["connect_timeout"] == 5
    assert arguments["options"] == "-c statement_timeout=30000"


def test_no_query_budget_sends_no_statement_timeout() -> None:
    assert "options" not in _arguments(_target())


def test_the_application_name_fits_what_the_server_keeps() -> None:
    """The server keeps 63 bytes of `application_name`, and cuts the rest."""
    assert len(application_name(RUN).encode()) <= 63
    assert RUN in application_name(RUN)
