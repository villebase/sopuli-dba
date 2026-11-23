"""The row guard for `sql run`. Tier 0, pure."""

from __future__ import annotations

import click
import pytest

from sopuli.sql.guard import RowGuard, row_guard


@pytest.mark.parametrize(
    ("expect", "maximum"),
    [(None, None), (1, 1), (-1, None), (None, -1)],
)
def test_a_row_guard_built_by_hand_is_checked(expect: int | None, maximum: int | None) -> None:
    with pytest.raises(ValueError, match="RowGuard"):
        RowGuard(expect=expect, maximum=maximum)


def test_expect_rows_passes_only_exact() -> None:
    guard = row_guard(1, None)
    assert guard is not None
    assert guard.passes(1)
    assert not guard.passes(0)
    assert not guard.passes(2)
    assert guard.describe() == "exactly 1 row"


def test_max_rows_passes_up_to() -> None:
    guard = row_guard(None, 5)
    assert guard is not None
    assert guard.passes(0)
    assert guard.passes(5)
    assert not guard.passes(6)
    assert guard.describe() == "at most 5 rows"


def test_describe_uses_the_plural() -> None:
    guard = row_guard(3, None)
    assert guard is not None
    assert guard.describe() == "exactly 3 rows"


def test_zero_is_a_guard() -> None:
    guard = row_guard(0, None)
    assert guard is not None
    assert guard.passes(0)
    assert not guard.passes(1)


def test_no_guard_is_none() -> None:
    assert row_guard(None, None) is None


def test_both_refused() -> None:
    with pytest.raises(click.UsageError):
        row_guard(1, 5)


@pytest.mark.parametrize(("expect", "maximum"), [(-1, None), (None, -1)])
def test_negative_refused(expect: int | None, maximum: int | None) -> None:
    with pytest.raises(click.UsageError):
        row_guard(expect, maximum)
