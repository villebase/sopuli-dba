"""The plan fingerprint of `sql run` (UC-3).

The plan prints it, and the run must be given it back. If the statement, the
guard or any target changed in between, the fingerprint differs and the run
refuses. It does no I/O.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from dataclasses import dataclass

from sopuli.sql.guard import RowGuard
from sopuli.sql.statement import Statement


@dataclass(frozen=True)
class PlannedTarget:
    """One target as the plan saw it."""

    name: str
    dsn: str
    #: The database user the tool logs in as, or ``"external"``.
    run_as: str
    #: The database's identity, read when the tool connects: on Oracle
    #: ``DB_UNIQUE_NAME``, and on PostgreSQL the cluster's ``system_identifier``.
    system: str
    #: On Oracle ``CON_NAME``, and on PostgreSQL ``current_database()``.
    database: str


def fingerprint(
    statement: Statement, guard: RowGuard | None, targets: Sequence[PlannedTarget]
) -> str:
    """Twelve lower-case hex characters that name this statement, guard and target set."""
    if guard is None:
        guard_part = None
    elif guard.expect is not None:
        guard_part = ["expect", guard.expect]
    else:
        guard_part = ["max", guard.maximum]
    document = {
        "statement": statement.text,
        "guard": guard_part,
        "targets": sorted([t.name, t.dsn, t.run_as, t.system, t.database] for t in targets),
    }
    text = json.dumps(document, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]
