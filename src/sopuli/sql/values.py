"""Turn a fetched value into JSON for `sql run` (UC-3). It does no I/O."""

from __future__ import annotations

import math
from datetime import date, datetime, timedelta
from decimal import Decimal

#: What a JSON document can hold, as a result cell.
JsonValue = None | bool | int | float | str

#: The largest whole number a JSON reader holding doubles keeps exactly.
_EXACT = 2**53


def to_json(value: object) -> JsonValue:
    """The JSON form of one cell.

    A whole ``Decimal`` within plus or minus 2**53 is an ``int``. Any other
    ``Decimal`` is its ``str``, so nothing is rounded. An ``int`` outside that
    range is its ``str`` too. A float that is not finite is its ``str``, because
    JSON has no ``NaN`` or ``Infinity``. Bytes are hex. A
    ``timedelta`` (``INTERVAL DAY TO SECOND``) is an ISO 8601 duration, and so
    is an object with integer ``years`` and ``months`` (``INTERVAL YEAR TO
    MONTH``, as ``oracledb.IntervalYM``). A type this does not know is its
    ``str``. The driver reads a LOB before this runs.
    """
    if value is None or isinstance(value, bool | str):
        return value
    if isinstance(value, int):
        return value if abs(value) <= _EXACT else str(value)
    if isinstance(value, float):
        return value if math.isfinite(value) else str(value)
    if isinstance(value, Decimal):
        if value.is_finite() and value == value.to_integral_value() and abs(value) <= _EXACT:
            return int(value)
        return str(value)
    if isinstance(value, datetime | date):
        return value.isoformat()
    if isinstance(value, bytes | bytearray):
        return bytes(value).hex()
    if isinstance(value, timedelta):
        return _day_second(value)
    years, months = getattr(value, "years", None), getattr(value, "months", None)
    if isinstance(years, int) and isinstance(months, int):
        return _year_month(years, months)
    return str(value)


def _day_second(value: timedelta) -> str:
    """An ISO 8601 duration such as ``P1DT2H0M0S``. A negative one starts with ``-``."""
    sign = "-" if value < timedelta(0) else ""
    total = abs(value)
    hours, rest = divmod(total.seconds, 3600)
    minutes, seconds = divmod(rest, 60)
    fraction = f".{total.microseconds:06d}".rstrip("0") if total.microseconds else ""
    return f"{sign}P{total.days}DT{hours}H{minutes}M{seconds}{fraction}S"


def _year_month(years: int, months: int) -> str:
    """An ISO 8601 duration such as ``P1Y2M``. A negative one starts with ``-``."""
    sign = "-" if years < 0 or months < 0 else ""
    return f"{sign}P{abs(years)}Y{abs(months)}M"
