"""The run document's ``keyring`` section, and what ``doctor`` prints (#1417).

Absent when the configuration names no keyring entry, for ``wallet``'s reason:
a keyring source is a configuration option most files never use, and a section
about it in every document would be noise.

**Not coloured**, for ``wallet``'s reason (decision #395): a key-value block,
with no column a reader scans.
"""

from __future__ import annotations

from typing import Any

from sopuli.keyring_survey import EntryReport, KeyringReport
from sopuli.os_keyring import SERVICE


def build(report: KeyringReport) -> dict[str, Any]:
    """The ``keyring`` section, as the run schema describes it.

    ``backend`` and ``problem`` are nulled rather than omitted, as ``wallet``'s
    ``directory`` is: both are always part of the answer, and "no backend" must
    read differently from "not reported".
    """
    return {
        "service": SERVICE,
        "backend": report.backend,
        "problem": report.problem,
        "entries": [_entry(one) for one in report.entries],
    }


def _entry(entry: EntryReport) -> dict[str, Any]:
    return {
        "entry": entry.entry,
        "required_by": list(entry.required_by),
        "present": entry.present,
        "problem": entry.problem,
    }


def render(report: KeyringReport) -> list[str]:
    """The text form: the backend, then one line per entry."""
    lines = ["keyring", f"  {'backend':<18}{report.backend or '(none)'}"]
    if report.problem is not None:
        lines.append(f"  {report.problem}")
    names = [f"{SERVICE}/{entry.entry}" for entry in report.entries]
    width = max(18, *(len(name) + 2 for name in names))
    for name, entry in zip(names, report.entries, strict=True):
        named = ", ".join(entry.required_by)
        lines.append(f"  {name:<{width}}{_state(entry):<9}{named}")
        if entry.problem is not None:
            lines.append(f"    {entry.problem}")
    lines.append("")
    return lines


def _state(entry: EntryReport) -> str:
    if entry.present is None:
        return "unread"
    return "present" if entry.present else "missing"
