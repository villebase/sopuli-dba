"""`doctor`'s PostgreSQL client lines. Tier 0: the versions are arguments."""

from __future__ import annotations

import pytest

from sopuli.driver.postgres.client import client_lines, libpq_release


@pytest.mark.parametrize(
    ("number", "release"),
    [(180004, (18, 4)), (160000, (16, 0)), (150000, (15, 0)), (90624, (9, 6))],
)
def test_libpq_numbers_read_as_a_release(number: int, release: tuple[int, int]) -> None:
    assert libpq_release(number) == release


def test_libpq_15_does_not_accept_require_auth() -> None:
    """psycopg 3.1.4's wheel, measured in #1032."""
    assert client_lines(psycopg_version="3.1.4", libpq_version=150000) == {
        "psycopg": "3.1.4",
        "libpq": "15.0",
        "require_auth": "not accepted: libpq 15 is older than 16",
    }


@pytest.mark.parametrize("number", [160000, 180004])
def test_libpq_16_and_later_accept_require_auth(number: int) -> None:
    assert client_lines(psycopg_version="3.3.6", libpq_version=number)["require_auth"] == "accepted"
