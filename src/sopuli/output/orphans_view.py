"""The run document's ``orphans`` section, and ``vault orphans`` in text (#999).

:mod:`sopuli.orphans` finds the records. This module says what they are, in the
shape the run schema pins and in the table a person reads.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import Any

from sopuli.lock.record import RELEASED
from sopuli.orphans import LOCK, Orphan, Survey
from sopuli.output.palette import Role, paint
from sopuli.output.table import Cell, Column, render_table


def build_section(survey: Survey, commands: Sequence[str | None]) -> dict[str, Any]:
    """The ``orphans`` section.

    Emitted even when ``found`` is empty, as ``lock status`` emits its own:
    an empty array is the finding. ``listed`` names the stores whose paths
    were read, so an empty ``found`` says what it covers (#1015), and
    ``prefix`` the secret path the survey was limited to, or ``null`` (#1016).
    """
    return {
        "listed": list(survey.listed),
        "prefix": survey.prefix,
        "found": [
            _entry(orphan, command)
            for orphan, command in zip(survey.orphans, commands, strict=True)
        ],
    }


def _entry(orphan: Orphan, command: str | None) -> dict[str, Any]:
    lock = orphan.lock
    record = lock.record if lock is not None else None
    return {
        "vault": orphan.store,
        "path": orphan.path,
        "kind": orphan.kind,
        "version": orphan.version if lock is None else lock.version,
        "lock": None
        if lock is None
        else {
            "state": record.state if record is not None else None,
            "held": lock.is_held,
            "expired": lock.expired,
        },
        "delete_command": command,
    }


def render(
    paths: Sequence[Path],
    survey: Survey,
    commands: Sequence[str | None],
    *,
    warnings: Sequence[str] = (),
) -> str:
    """``vault orphans`` in text.

    The table, a count, and then the delete commands, each on a line of its own
    so it can be pasted. A path a live lock stands on gets a line saying why it
    has no command instead. The count names the stores that were listed, and
    the prefix where there was one; a store that could not be listed is in a
    warning.
    """
    lines = [f"config: {paths[0]}"]
    lines.extend(f"        {path} (layered)" for path in paths[1:])
    vaults = survey.listed
    where = f"{len(vaults)} vault{'' if len(vaults) == 1 else 's'} ({', '.join(vaults)})"
    if survey.prefix is not None:
        where = f"{where} under {survey.prefix}/"
    if not vaults and not survey.unlistable and not survey.unread:
        lines.extend(["", "no vault in `vaults:`"])
    elif not vaults:
        lines.extend(["", "no vault could be listed"])
    elif survey.prefix is not None and not survey.seen:
        # Not "no orphans": nothing was there to look at, which a mistyped
        # prefix would also give.
        lines.extend(["", f"nothing is stored in {where}"])
    elif not survey.orphans:
        lines.extend(["", f"no orphans in {where}"])
    else:
        lines.extend(["", *_table(survey.orphans)])
        count = len(survey.orphans)
        lead = (
            "To delete them:"
            if any(command is not None for command in commands)
            else "No delete command is printed:"
        )
        lines.extend(
            [
                "",
                f"{count} orphan{'' if count == 1 else 's'} in {where}: records that look "
                f"like this tool's, at paths no binding in this config declares",
                "",
                "They may be another config's. Check each one before you delete it "
                f'(getting-started.md, "Moving a secret path"). {lead}',
                "",
            ]
        )
        held = survey.held()
        for orphan, command in zip(survey.orphans, commands, strict=True):
            if command is not None:
                lines.append(f"  {command}")
            elif orphan.key in held:
                lines.append(
                    f"  (none for {orphan.store}:{orphan.path}: a live lock stands on "
                    f"{orphan.key.path}; see `sopuli lock status`)"
                )
            else:
                lines.append(
                    f"  (none for {orphan.store}:{orphan.path}: no command for this store)"
                )
    if warnings:
        heading = "1 warning" if len(warnings) == 1 else f"{len(warnings)} warnings"
        lines.extend(["", paint(f"{heading}:", Role.NOTABLE)])
        lines.extend(f"  {line}" for message in warnings for line in message.splitlines())
    return "\n".join(lines)


def _table(orphans: Sequence[Orphan]) -> list[str]:
    return list(
        render_table(
            [Column("VAULT"), Column("PATH"), Column("KIND"), Column("LOCK")],
            [[orphan.store, orphan.path, orphan.kind, _lock(orphan)] for orphan in orphans],
        )
    )


def _lock(orphan: Orphan) -> Cell | str:
    """A lock record's state in one word, and ``-`` for a secret."""
    if orphan.kind != LOCK or orphan.lock is None:
        return "-"
    record = orphan.lock.record
    if record is None:
        return Cell("empty", Role.MUTED)
    if not record.is_held:
        return Cell(RELEASED, Role.MUTED)
    if orphan.lock.expired:
        return Cell("expired", Role.NOTABLE)
    return Cell(record.state, Role.NOTABLE)
