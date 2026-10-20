"""The hints for ``results[].error``, under a verb's text output (#912).

Tier 0. A verb's ``DETAIL`` cell carries an error's message; the hint that says
what to do next is added once per run, by the emitter, so no verb can leave it
out.
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
