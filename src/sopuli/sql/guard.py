"""The row guard of `sql run` (UC-3).

A guard says how many rows a statement may touch or return. It does no I/O.
"""

from __future__ import annotations

from dataclasses import dataclass

import click


@dataclass(frozen=True)
class RowGuard:
    """Exactly ``expect`` rows, or at most ``maximum`` rows. One of them is set."""

    expect: int | None = None
    maximum: int | None = None

    def __post_init__(self) -> None:
        if (self.expect is None) == (self.maximum is None):
            raise ValueError("a RowGuard sets exactly one of expect and maximum")
        if (self.expect or 0) < 0 or (self.maximum or 0) < 0:
            raise ValueError("a RowGuard count cannot be negative")

    def passes(self, count: int) -> bool:
        if self.expect is not None:
            return count == self.expect
        if self.maximum is not None:
            return count <= self.maximum
        return True

    def describe(self) -> str:
        if self.expect is not None:
            return f"exactly {_rows(self.expect)}"
        if self.maximum is not None:
            return f"at most {_rows(self.maximum)}"
        return "any number of rows"


def _rows(count: int) -> str:
    return f"{count} row" if count == 1 else f"{count} rows"


def row_guard(expect_rows: int | None, max_rows: int | None) -> RowGuard | None:
    """The guard for the two options, or ``None`` when neither is given.

    Giving both, or a negative number, is a usage error (exit 2).
    """
    if expect_rows is not None and max_rows is not None:
        raise click.UsageError("give --expect-rows or --max-rows, not both")
    for name, value in (("--expect-rows", expect_rows), ("--max-rows", max_rows)):
        if value is not None and value < 0:
            raise click.UsageError(f"{name} cannot be negative")
    if expect_rows is None and max_rows is None:
        return None
    return RowGuard(expect=expect_rows, maximum=max_rows)
