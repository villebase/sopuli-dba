"""A store's waits are shown only inside a verb (decision 8, #1133)."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from sopuli.store.waiting import showing, waiting


def test_waiting_does_nothing_by_default() -> None:
    with waiting("Waiting for something"):
        pass


def test_showing_reaches_a_wait_and_resets_after_the_block() -> None:
    shown: list[str] = []

    @contextmanager
    def notice(message: str) -> Iterator[None]:
        shown.append(message)
        yield

    with showing(notice), waiting("inside"):
        pass
    with waiting("outside"):
        pass

    assert shown == ["inside"]


def test_showing_puts_back_an_outer_notice() -> None:
    shown: list[str] = []

    @contextmanager
    def outer(message: str) -> Iterator[None]:
        shown.append(f"outer {message}")
        yield

    @contextmanager
    def inner(message: str) -> Iterator[None]:
        shown.append(f"inner {message}")
        yield

    with showing(outer):
        with showing(inner), waiting("a"):
            pass
        with waiting("b"):
            pass

    assert shown == ["inner a", "outer b"]
