"""Merging what the estate said into one limit (#317). Tier 0.

Pure arithmetic over readings the caller collected, so none of this needs a
database -- which is the point of the split: `cli._constraints_for` opens the
connections and this decides what they meant.
"""

from __future__ import annotations

import pytest

from sopuli.constraints import POLICY, TARGETS, UNREAD, Constraints, strictest
from sopuli.passwords import ByteLimit

MODERN = ByteLimit(max_bytes=128, encoding="ascii", charset="US7ASCII")
LEGACY = ByteLimit(max_bytes=30, encoding="ascii", charset="US7ASCII")
UNICODE = ByteLimit(max_bytes=128, encoding="utf-8", charset="AL32UTF8")
WESTERN = ByteLimit(max_bytes=128, encoding="cp1252", charset="WE8MSWIN1252")


def test_nothing_asked_is_not_nothing_answered() -> None:
    """``--offline`` and an estate that is down are different runs.

    The same rule ``driver/oracle/privileges.py`` states about a view it cannot
    read: "I looked and found nothing" and "I could not look" are answers a
    report must never merge. Here there is a third -- "I did not look" -- and
    collapsing it into the fallback would report a warning about an estate
    nobody tried to reach.
    """
    assert strictest([]).source == UNREAD
    assert strictest([], unreachable=("appdb-alpha",)).source == POLICY


def test_no_limit_is_carried_when_nothing_answered() -> None:
    """``None`` is what `candidate_for` already means by "no target limit", so
    the fallback is a default rather than a branch somebody has to remember."""
    assert strictest([], unreachable=("appdb-alpha",)).limit is None


def test_the_smallest_limit_wins() -> None:
    found = strictest([("modern", MODERN), ("legacy", LEGACY)])

    assert found.limit == LEGACY
    assert found.source == TARGETS
    assert found.strictest_target == "legacy"


def test_the_strictest_limit_is_not_the_smallest_number() -> None:
    """The reason a `ByteLimit` is a pair and not an int.

    Both are 128 bytes. One is counted in ``cp1252``, where a character is always
    one byte, and one in ``utf-8``, where a character can be four -- so the second
    is guaranteed to hold 32 characters and the first 128. Comparing the counts
    alone would call them equal and pick whichever came first.
    """
    found = strictest([("western", WESTERN), ("unicode", UNICODE)])

    assert found.limit == UNICODE
    assert found.strictest_target == "unicode"


def test_a_narrow_encoding_can_still_lose_to_a_small_count() -> None:
    """The other half of the same comparison, so it is not just encoding-first.

    30 ASCII bytes hold 30 characters; 128 UTF-8 bytes are guaranteed 32. The
    legacy target is stricter and the encoding-aware rule has to agree.
    """
    assert strictest([("unicode", UNICODE), ("legacy", LEGACY)]).limit == LEGACY


def test_a_tie_keeps_the_first_reading() -> None:
    """Nothing depends on which of two identical limits is named, and a run that
    named a different one each time would be reporting noise as a fact."""
    first = ByteLimit(max_bytes=128, encoding="ascii", charset="US7ASCII")
    second = ByteLimit(max_bytes=128, encoding="ascii", charset="WE8ISO8859P1")

    assert strictest([("alpha", first), ("beta", second)]).limit.charset == "US7ASCII"  # type: ignore[union-attr]


def test_one_reading_names_no_strictest_target() -> None:
    """There was nothing to be strictest *than*, and reporting a winner of a
    one-horse race invites a reader to think an estate was surveyed."""
    assert strictest([("only", MODERN)]).strictest_target is None


def test_every_target_that_answered_is_named() -> None:
    found = strictest([("alpha", MODERN), ("beta", LEGACY)], unreachable=("gamma",))

    assert found.read == ("alpha", "beta")
    assert found.unreachable == ("gamma",)


@pytest.mark.parametrize(
    ("readings", "unreachable", "expected"),
    [
        ([("alpha", MODERN)], (), False),
        ([("alpha", MODERN)], ("beta",), True),
        ([], ("beta",), False),
    ],
)
def test_partial_means_some_answered_and_some_did_not(
    readings: list[tuple[str, ByteLimit]], unreachable: tuple[str, ...], expected: bool
) -> None:
    """The case a reader is most likely to get wrong: the limit is real, it came
    from a database, and it is still not necessarily the estate's strictest."""
    assert strictest(readings, unreachable=unreachable).partial is expected


def test_the_default_constraints_claim_nothing() -> None:
    assert Constraints().limit is None
    assert Constraints().source == UNREAD
    assert Constraints().partial is False
