"""`sql run`'s text and its ``results[]`` entries (UC-3 §7).

The text starts with the statement as sent. When every target that answered
returned the same columns, the rows are one table with a ``TARGET`` column;
otherwise, or when the statement returns a column named ``TARGET``, each target
has a block of its own. The shared table cuts a value longer than 40
characters with ``...`` and shows a line break as ``\\n``; the JSON keeps the
whole value. A line per target then gives its
row count, ``truncated`` where the rows were cut, or why it gave no answer.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from sopuli.apply import SKIPPED
from sopuli.output.document import Summary
from sopuli.output.palette import Role, paint, role_for_state
from sopuli.output.table import Cell, Column, render_table
from sopuli.sql.statement import Statement
from sopuli.sql.values import JsonValue
from sopuli.sql_run import READ, TargetOutcome

#: The widest a value is shown. The whole value is in the JSON.
_VALUE = 40
_TARGET_HEADING = "TARGET"


def statement_section(statement: Statement, fingerprint: str | None = None) -> dict[str, Any]:
    """The run document's ``statement``: what was sent, and a write's fingerprint."""
    section: dict[str, Any] = {"text": statement.text, "kind": str(statement.kind)}
    if fingerprint is not None:
        section["fingerprint"] = fingerprint
    return section


def build_results(outcomes: Sequence[TargetOutcome]) -> list[dict[str, Any]]:
    """One ``results[]`` entry per target."""
    results: list[dict[str, Any]] = []
    for outcome in outcomes:
        entry: dict[str, Any] = {
            "account": outcome.run_as,
            "target": outcome.target,
            "state": outcome.state,
            "changed": bool(outcome.result is not None and outcome.result.committed),
        }
        if outcome.result is not None:
            entry["columns"] = list(outcome.result.columns)
            entry["rows"] = [list(row) for row in outcome.result.rows]
            entry["row_count"] = outcome.result.row_count
            entry["truncated"] = outcome.result.truncated
        if outcome.error is not None:
            entry["error"] = outcome.error.to_dict()
        results.append(entry)
    return results


def summarise(outcomes: Sequence[TargetOutcome]) -> Summary:
    """The run's counts, one per target. ``failed`` counts the targets with an error
    that is not a product `sql run` is not written for."""
    counts: dict[str, int] = {}
    for outcome in outcomes:
        counts[outcome.state] = counts.get(outcome.state, 0) + 1
    answered = counts.get(READ, 0)
    skipped = counts.get(SKIPPED, 0)
    return Summary(
        total=len(outcomes),
        ok=answered,
        changed=0,
        failed=len(outcomes) - answered - skipped,
        skipped=skipped or None,
        by_state=counts,
    )


def render_text(statement: Statement, outcomes: Sequence[TargetOutcome]) -> str:
    """The whole text view."""
    lines = [paint(f"{statement.kind} statement:", Role.HEADING)]
    lines.extend(f"  {line}" for line in statement.text.splitlines())
    lines.append("")
    if not outcomes:
        lines.append("no targets selected")
        return "\n".join(lines)
    answered = [outcome for outcome in outcomes if outcome.result is not None]
    shapes = {outcome.result.columns for outcome in answered if outcome.result is not None}
    # A result column of that name would read as the target's own column.
    shared = len(shapes) == 1 and not any(
        column.upper() == _TARGET_HEADING for shape in shapes for column in shape
    )
    if shared:
        lines.extend(_one_table(answered))
        if any(outcome.result is not None and outcome.result.rows for outcome in answered):
            lines.append("")
        width = max(len(outcome.target) for outcome in outcomes)
        lines.extend(_status(outcome, width) for outcome in outcomes)
    else:
        for outcome in outcomes:
            lines.append(_status(outcome))
            lines.extend(f"  {line}" for line in _block(outcome))
    return "\n".join(lines).rstrip("\n")


def _one_table(answered: Sequence[TargetOutcome]) -> list[str]:
    """Every answering target's rows under one heading, with the target first."""
    first = answered[0].result
    assert first is not None
    # The target column is never cut: two long names that differ only at the
    # end would otherwise read as one target.
    columns = [Column(_TARGET_HEADING), *(Column(name, _VALUE) for name in first.columns)]
    rows: list[list[Cell | str]] = [
        [outcome.target, *(_text(value) for value in row)]
        for outcome in answered
        if outcome.result is not None
        for row in outcome.result.rows
    ]
    return render_table(columns, rows)


def _block(outcome: TargetOutcome) -> list[str]:
    """One target's own rows, under its own columns."""
    if outcome.result is None:
        return []
    columns = [Column(name, _VALUE) for name in outcome.result.columns]
    return render_table(columns, [[_text(value) for value in row] for row in outcome.result.rows])


def _status(outcome: TargetOutcome, width: int = 0) -> str:
    """One target's line: its row count, or why it gave no answer. The name is
    padded to ``width``, so the lines under one table line up."""
    name = paint(outcome.target, Role.HEADING) + " " * (width - len(outcome.target))
    if outcome.result is not None:
        count = outcome.result.row_count
        said = f"{count} row" if count == 1 else f"{count} rows"
        if outcome.result.truncated:
            said += ", " + paint("truncated", Role.ATTENTION)
        return f"{name}  {said}"
    reason = outcome.error.message if outcome.error is not None else ""
    return f"{name}  {paint(outcome.state, role_for_state(outcome.state))}: {reason}"


def _text(value: JsonValue) -> str:
    """A cell as text. A null is blank, as SQL*Plus shows it."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "TRUE" if value else "FALSE"
    return str(value)
