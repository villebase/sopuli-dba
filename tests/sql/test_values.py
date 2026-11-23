"""Converting a fetched value to JSON for `sql run`. Tier 0, pure."""

from __future__ import annotations

from datetime import date, datetime, timedelta
from decimal import Decimal

import pytest

from sopuli.sql.values import to_json


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, None),
        (True, True),
        (7, 7),
        ("Y", "Y"),
        (Decimal("1.10"), "1.10"),
        (Decimal("12345678901234567890"), "12345678901234567890"),
        (Decimal("42"), 42),
        (Decimal(2**53), 2**53),
        (Decimal(2**53 + 1), str(2**53 + 1)),
        (datetime(2026, 11, 23, 10, 0, 0), "2026-11-23T10:00:00"),
        (date(2026, 11, 23), "2026-11-23"),
        (b"\x01\xab", "01ab"),
    ],
)
def test_to_json(value: object, expected: object) -> None:
    result = to_json(value)
    assert result == expected
    assert type(result) is type(expected)


def test_float_kept() -> None:
    assert to_json(1.5) == 1.5


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (float("nan"), "nan"),
        (float("inf"), "inf"),
        (float("-inf"), "-inf"),
        (2**53, 2**53),
        (-(2**53), -(2**53)),
        (2**53 + 1, str(2**53 + 1)),
        (-(2**53) - 1, str(-(2**53) - 1)),
    ],
)
def test_non_finite_floats_and_large_ints_are_strings(value: object, expected: object) -> None:
    assert to_json(value) == expected
    assert type(to_json(value)) is type(expected)


def test_unknown_type_is_its_str() -> None:
    assert to_json(1 + 2j) == "(1+2j)"


class _IntervalYM:
    """Stands in for `oracledb.IntervalYM`, which has integer years and months."""

    def __init__(self, years: int, months: int) -> None:
        self.years = years
        self.months = months


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (timedelta(days=1, hours=2), "P1DT2H0M0S"),
        (timedelta(0), "P0DT0H0M0S"),
        (timedelta(days=3, minutes=4, seconds=5, microseconds=500000), "P3DT0H4M5.5S"),
        (timedelta(microseconds=1), "P0DT0H0M0.000001S"),
        (-timedelta(days=1, hours=2), "-P1DT2H0M0S"),
        (-timedelta(seconds=1, microseconds=250000), "-P0DT0H0M1.25S"),
        (_IntervalYM(1, 2), "P1Y2M"),
        (_IntervalYM(-1, -2), "-P1Y2M"),
        (_IntervalYM(0, 0), "P0Y0M"),
    ],
)
def test_intervals_are_iso_durations(value: object, expected: str) -> None:
    assert to_json(value) == expected


def test_an_object_with_non_integer_years_is_its_str() -> None:
    class Odd:
        years = "x"
        months = 1

        def __str__(self) -> str:
            return "odd"

    assert to_json(Odd()) == "odd"
