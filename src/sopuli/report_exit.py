"""UC-5 §3's exit code, the one place every `report` command takes it from.

Each report decides what counts as a problem and what as not checked; this
module only orders them, so the reports cannot exit differently for the same
fleet.
"""

from __future__ import annotations

from sopuli.exit_codes import ExitCode

__all__ = ["exit_code_for"]


def exit_code_for(
    *,
    unreachable: int,
    unsupported: int,
    targets: int,
    problem: bool = False,
    incomplete: bool = False,
    refused: int = 0,
) -> int:
    """5 when every target is of a product the report is not written for; 1 when
    a target gave no answer; 3 for a problem; 4 for anything not checked, an
    unsupported target included; else 0.

    ``refused`` counts the targets that refused the connection for a
    capability they lack, such as SQL Server's ``strict_encryption``. Each is
    *not checked*, so 4, also where every target is one: the report is written
    for the product, and a target of it did answer (#1555, decision 1).

    A report that judges nothing passes no ``problem``, so it never exits 3.
    """
    if targets and unsupported == targets:
        return int(ExitCode.UNSUPPORTED_CAPABILITY)
    if unreachable:
        return int(ExitCode.FAILURE)
    if problem:
        return int(ExitCode.DRIFT)
    if incomplete or unsupported or refused:
        return int(ExitCode.PARTIAL)
    return int(ExitCode.SUCCESS)
