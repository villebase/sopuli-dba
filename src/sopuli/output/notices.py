"""Blocks of findings rendered under a verb's text output.

Two blocks share one shape: a counted heading, then an indented line per entry.

* **Notes** are things that belong to one account but do not fit in a column --
  a grace period and the date it ends, so far. In ``--output json`` they are
  ``results[].warnings[]``. `check` and `creds status` print them, and
  `config validate` prints its warnings the same way under its summary.
* **Hints** say what to do about the errors in ``results[]``. A verb's table
  carries an error's message, if it shows the error at all, and the hint was in
  the JSON only. The emitter prints them for every verb.

A warning a terminal user cannot see is not surfaced: UC-1 §4 says so for the
constraint caveats, and ``03-json-output.md`` §3 says it per diagnostic code.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from sopuli.output.palette import Role, paint

__all__ = ["render_hints", "render_notices"]


def render_hints(results: Sequence[Mapping[str, Any]] | None) -> list[str]:
    """What to do about the errors in ``results[]``, each hint once.

    A table cannot hold a second sentence, so the hints go under the run, as
    the notes do. Each distinct hint is printed once, after every code that
    raised it and the targets it was raised on: twenty accounts on one target
    refused for one reason need one hint, not twenty. Two codes can share a
    hint, so the line names both rather than suggesting only the first one
    happened. The targets are named because some tables show a state and not
    the error, and a reader has to be able to tell which rows a hint is for.

    A hint's later lines are indented further than its first, so a hint of
    several lines does not read as several hints.

    Empty where no result carries a hint, so a run with nothing to fix prints
    nothing more.
    """
    found: dict[str, tuple[list[str], list[str]]] = {}
    for result in results or ():
        error = result.get("error") or {}
        hint = error.get("hint")
        if not hint:
            continue
        codes, targets = found.setdefault(hint, ([], []))
        code = error.get("code")
        if code and code not in codes:
            codes.append(code)
        target = result.get("target")
        if target and target not in targets:
            targets.append(target)
    if not found:
        return []
    body: list[str] = []
    for hint, (codes, targets) in found.items():
        first, *rest = hint.splitlines()
        where = ", ".join(codes)
        if targets:
            where = f"{where} on {', '.join(targets)}" if where else ", ".join(targets)
        body.append(f"  {where}: {first}" if where else f"  {first}")
        body.extend(f"    {line}" for line in rest)
    count = "1 hint" if len(found) == 1 else f"{len(found)} hints"
    return ["", paint(f"{count}:", Role.NOTABLE), *body]


def render_notices(notices: Sequence[str]) -> list[str]:
    """Findings that belong to a row but do not fit in it.

    A table column cannot hold a sentence with a date in it. A warning nobody
    can see in the default output is not surfaced, and `results[].warnings[]`
    alone does not show one to a person reading a terminal.

    The same block `config validate` prints under its summary, and deliberately
    the same words: an operator who has read one of these has read all of them.
    Empty for the ordinary run, so nothing is added to the output that says
    nothing.
    """
    if not notices:
        return []
    body = [f"  {line}" for notice in notices for line in notice.splitlines()]
    count = "1 note" if len(notices) == 1 else f"{len(notices)} notes"
    return ["", paint(f"{count}:", Role.NOTABLE), *body]
