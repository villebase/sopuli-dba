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
    assert to_json(timedelta(hours=1)) == "1:00:00"
