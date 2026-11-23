"""Turn a fetched value into JSON for `sql run` (UC-3). It does no I/O."""

from __future__ import annotations

from datetime import date, datetime
from decimal import Decimal

#: What a JSON document can hold, as a result cell.
JsonValue = None | bool | int | float | str

#: The largest whole number a JSON reader holding doubles keeps exactly.
_EXACT = 2**53


def to_json(value: object) -> JsonValue:
    """The JSON form of one cell.

    A whole ``Decimal`` within plus or minus 2**53 is an ``int``. Any other
    ``Decimal`` is its ``str``, so nothing is rounded. Bytes are hex. A type
    this does not know is its ``str``. The driver reads a LOB before this runs.
    """
    if value is None or isinstance(value, bool | int | float | str):
        return value
    if isinstance(value, Decimal):
        if value.is_finite() and value == value.to_integral_value() and abs(value) <= _EXACT:
            return int(value)
        return str(value)
    if isinstance(value, datetime | date):
        return value.isoformat()
    if isinstance(value, bytes | bytearray):
        return bytes(value).hex()
    return str(value)
