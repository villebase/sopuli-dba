"""The hints for ``results[].error``, under a verb's text output.

Tier 0. A verb's table carries an error's message, if it shows the error at
all; the hint that says what to do next is added once per run, by the emitter,
so no verb can leave it out.
"""

from __future__ import annotations

import io
from typing import Any, TextIO, cast

import click

from sopuli.output.color import ColorChoice
from sopuli.output.document import RunDocument
from sopuli.output.emit import Emitter, OutputMode
from sopuli.output.notices import render_hints

REFUSED = {
    "category": "config",
    "message": "ORA-28009: connection as SYS should be as SYSDBA or SYSOPER",
    "code": "ORA-28009",
    "hint": "point the target's admin at the service account",
}


def _result(account: str, error: dict[str, Any] | None = None) -> dict[str, Any]:
    entry: dict[str, Any] = {"account": account, "target": "free-pdb", "state": "ERROR"}
    if error is not None:
        entry["error"] = error
    return entry


def _plain(lines: list[str]) -> list[str]:
    """Without the heading's colour, which the emitter's gate removes when it is off."""
    return [click.unstyle(line) for line in lines]


def test_a_hint_is_printed_once_with_its_code() -> None:
    lines = _plain(
        render_hints([_result("acme_app_user", REFUSED), _result("acme_batch_user", REFUSED)])
    )

    assert lines == ["", "1 hint:", "  ORA-28009: point the target's admin at the service account"]


def test_distinct_hints_keep_the_order_they_were_raised_in() -> None:
    unset = {"category": "config", "message": "not set", "hint": "set the variable"}
    results = [_result("a", REFUSED), _result("b", unset), _result("c", REFUSED)]
    lines = _plain(render_hints(results))

    assert lines[1] == "2 hints:"
    assert lines[2:] == [
        "  ORA-28009: point the target's admin at the service account",
        "  set the variable",
    ]


def test_two_codes_that_share_a_hint_are_both_named() -> None:
    """A rollback refusal gives ORA-28007 and ORA-28003 one hint; naming only the
    first would say only that one happened."""
    shared = "the previous password is refused; rotate instead"
    reused = {"category": "policy", "message": "reused", "code": "ORA-28007", "hint": shared}
    rejected = {"category": "policy", "message": "rejected", "code": "ORA-28003", "hint": shared}

    lines = _plain(render_hints([_result("a", reused), _result("b", rejected)]))

    assert lines[1:] == ["1 hint:", f"  ORA-28007, ORA-28003: {shared}"]


def test_every_line_of_a_hint_is_indented() -> None:
    long = {"category": "config", "message": "m", "code": "X-1", "hint": "first\nsecond"}

    assert _plain(render_hints([_result("a", long)]))[2:] == ["  X-1: first", "  second"]


def test_a_run_with_no_hint_adds_nothing() -> None:
    without = {"category": "database", "message": "ORA-00942: table or view does not exist"}

    assert render_hints([_result("a"), _result("b", without)]) == []
    assert render_hints(None) == []


def _emitted(document: RunDocument, text: str) -> str:
    written = io.StringIO()
    emitter = Emitter(
        mode=OutputMode.TEXT, stream=cast("TextIO", written), color_choice=ColorChoice.NEVER
    )
    emitter.emit(document, text)
    return written.getvalue()


def test_the_emitter_adds_the_hints_under_the_verbs_text() -> None:
    """Under the text rather than inside it: no verb has to remember them."""
    document = RunDocument.start("creds.apply")
    document.results = [_result("acme_app_user", REFUSED)]

    output = _emitted(document, "nothing changed, 1 not confirmed")

    assert output.splitlines() == [
        "nothing changed, 1 not confirmed",
        "",
        "1 hint:",
        "  ORA-28009: point the target's admin at the service account",
    ]


def test_the_emitter_leaves_the_text_alone_where_there_is_no_hint() -> None:
    document = RunDocument.start("creds.apply")
    document.results = [_result("acme_app_user")]

    assert _emitted(document, "nothing changed").splitlines() == ["nothing changed"]
