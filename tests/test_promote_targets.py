"""`targets` after `creds generate --promote --overwrite-current` (#975).

A rotation records in `targets` the databases that confirmed `current`.
`generate --promote --overwrite-current` replaces `current` with a password no
database has, so the same write clears `targets`. Otherwise the document says a
database confirmed a password it has not seen.

This needs only the tier-1 services, Oracle Free and Vault, and skips without
them.
"""

from __future__ import annotations

from typing import Any

from fault_harness import ACCOUNT, SECRET, Estate
from sopuli.exit_codes import ExitCode


def test_overwriting_current_clears_the_targets_a_rotation_wrote(
    fault_estate: Estate, vault_stack: Any
) -> None:
    config = fault_estate.config(vault_stack.addr)
    rotated = fault_estate.sopuli(config, "creds", "rotate", "--confirm")
    assert rotated.returncode == ExitCode.SUCCESS, rotated.stderr
    before, _ = fault_estate.read(SECRET)
    assert before["targets"][ACCOUNT] == ["free-pdb"]

    promoted = fault_estate.sopuli(
        config, "creds", "generate", "--promote", "--overwrite-current", "--confirm"
    )

    assert promoted.returncode == ExitCode.SUCCESS, promoted.stderr
    after, _ = fault_estate.read(SECRET)
    assert after["DB_CREDENTIALS"][ACCOUNT] != before["DB_CREDENTIALS"][ACCOUNT]
    assert after["previous"][ACCOUNT] == before["DB_CREDENTIALS"][ACCOUNT]
    assert ACCOUNT not in after.get("targets", {})
    assert not fault_estate.login(after["DB_CREDENTIALS"][ACCOUNT])
