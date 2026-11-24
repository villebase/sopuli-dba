"""`sql run`'s text and its ``results[]`` entries (UC-3 §7).

The text starts with the statement as sent. When every target that answered
returned the same columns, the rows are one table with a ``TARGET`` column;
otherwise, or when the statement returns a column named ``TARGET``, each target
has a block of its own. The shared table cuts a value longer than 40
characters with ``...`` and shows a line break as ``\\n``; the JSON keeps the
whole value. A line per target then gives its
row count, ``truncated`` where the rows were cut, or why it gave no answer.

A write's text has no rows: a line per target with its state and its count,
then the plan fingerprint.
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
from sopuli.sql_run import COMMITTED, GUARD_FAILED, READ, ROLLED_BACK, TargetOutcome

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


def summarise_write(outcomes: Sequence[TargetOutcome]) -> Summary:
    """A write's counts. ``ok`` counts the targets that committed or rolled
    back with their guard passed, and ``changed`` the ones that committed."""
    counts: dict[str, int] = {}
    for outcome in outcomes:
        counts[outcome.state] = counts.get(outcome.state, 0) + 1
    ok = counts.get(COMMITTED, 0) + counts.get(ROLLED_BACK, 0)
    skipped = counts.get(SKIPPED, 0)
    return Summary(
        total=len(outcomes),
        ok=ok,
        changed=counts.get(COMMITTED, 0),
        failed=len(outcomes) - ok - skipped,
        skipped=skipped or None,
        by_state=counts,
    )


def render_write(
    statement: Statement,
    outcomes: Sequence[TargetOutcome],
    plan: str,
    *,
    dry_run: bool,
    note: str | None = None,
    asks: bool = False,
    unconnected: Sequence[str] = (),
) -> str:
    """A write's text: the statement, a line per target, and the plan fingerprint.

    A dry run ends with what to do next (:func:`_next_step`), and ``note``
    says whether a `--plan` it was given matches. ``asks`` is whether the real
    run will ask for a confirmation. ``unconnected`` names the targets that
    did not connect.
    """
    lines = [paint(f"{statement.kind} statement:", Role.HEADING)]
    lines.extend(f"  {line}" for line in statement.text.splitlines())
    lines.append("")
    if not outcomes:
        lines.append("no targets selected")
    width = max((len(outcome.target) for outcome in outcomes), default=0)
    states = max((len(outcome.state) for outcome in outcomes), default=0)
    for outcome in outcomes:
        name = paint(outcome.target, Role.HEADING) + " " * (width - len(outcome.target))
        state = paint(outcome.state, role_for_state(outcome.state))
        state += " " * (states - len(outcome.state))
        lines.append(f"{name}  {state}  {_write_detail(outcome, dry_run=dry_run)}")
    lines.extend(["", f"plan fingerprint: {plan}"])
    if dry_run:
        lines.extend(_next_step(outcomes, plan, asks=asks, unconnected=unconnected))
    if note is not None:
        lines.append(note)
    return "\n".join(lines)


def _next_step(
    outcomes: Sequence[TargetOutcome],
    plan: str,
    *,
    asks: bool,
    unconnected: Sequence[str] = (),
) -> list[str]:
    """After a dry run: the `--plan` to run it with, where a real run could
    finish on every target, and whether it will ask first (``asks``);
    otherwise why it would not. A real run is refused before it starts where
    a target did not connect (``unconnected``), and stops where a statement
    failed or a guard did not pass. Nothing is offered where every target is
    of a product `sql run` does not run on."""
    if all(outcome.state == SKIPPED for outcome in outcomes):
        return ["nothing would run: no selected target is of a product `sql run` runs on"]
    failing = [outcome for outcome in outcomes if outcome.state not in (ROLLED_BACK, SKIPPED)]
    if not failing:
        lines = [f"to run it, drop --dry-run and add:  --plan {plan}"]
        if asks:
            lines.append(
                "`safety.confirm_environments` covers these targets, so the real run will "
                "ask before it runs; where nobody can answer, add --confirm"
            )
        return lines
    lines = []
    if unconnected:
        lines.append(
            "a real run would be refused: these targets did not connect: " + ", ".join(unconnected)
        )
    rest = [outcome for outcome in failing if outcome.target not in unconnected]
    if rest:
        named = ", ".join(f"{outcome.target} ({outcome.state})" for outcome in rest)
        lines.append(
            f"a real run would stop at {rest[0].target}. These targets did not pass: {named}"
        )
    lines.append("fix them, or leave them out with a selector, and dry-run again")
    return lines


def _write_detail(outcome: TargetOutcome, *, dry_run: bool) -> str:
    if outcome.state == GUARD_FAILED and outcome.error is not None:
        return outcome.error.message
    if outcome.result is None:
        return outcome.error.message if outcome.error is not None else ""
    count = outcome.result.row_count
    said = f"{count} row" if count == 1 else f"{count} rows"
    if outcome.state == ROLLED_BACK:
        if dry_run and count:
            return f"{said}, rolled back (dry run)"
        return f"{said}, rolled back: no row changed"
    return said


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
