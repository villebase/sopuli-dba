"""Fault injection: two runs contend for one lock (`04-testing.md` §5).

Two rows of §5's table, through ``sopuli creds rotate`` against a real
database:

* two rotations of one account at once. One loses the lock and exits 7, having
  changed nothing, and the other finishes. The vault and the database agree
  afterwards;
* a lock taken over mid-run. The first run's lock expires, a second run takes
  it over, and the first run's next fence check finds it. The first run stops
  before its ``ALTER USER``, exits 4 with ``SOPULI-W011``, and promotes
  nothing.

``tests/store/test_lock_concurrency.py`` makes the same claims about the lock
manager alone. These make them about the command: its exit codes, its
diagnostic, and what the database and the vault hold afterwards.

The first run is held inside its lock by :class:`fault_harness.VaultGate`,
which pauses its staging write. Step 4 checks the fence before that write, so
the next check is the one before step 5's ``ALTER USER``.

These need only the tier-1 services, Oracle Free and Vault, and skip without
them.
"""

from __future__ import annotations

import json
import subprocess
import time
from collections.abc import Iterator
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any

import pytest

from fault_harness import (
    ACCOUNT,
    LOCK,
    OLD,
    SECRET,
    TIMEOUT,
    Estate,
    Fault,
    HarnessError,
    VaultGate,
)
from sopuli.diagnostics import LOCK_LOST
from sopuli.exit_codes import ExitCode

#: ``rotate``'s first write to the secret's path stages ``pending``.
STAGING = 1


@dataclass
class Paused:
    """A rotation that holds its lock, paused at its staging write."""

    gate: VaultGate
    run: Future[subprocess.CompletedProcess[str]]
    #: The run's own pid, from its lock record. See ``fault_harness`` for why
    #: ``Popen.pid`` is not always it.
    pid: int

    def finish(self) -> subprocess.CompletedProcess[str]:
        """Let the staging write through, and wait for the run to end."""
        self.gate.release()
        return self.run.result(timeout=TIMEOUT)


@pytest.fixture
def paused(fault_estate: Estate, vault_stack: Any) -> Iterator[Paused]:
    """Start ``creds rotate`` through a gate, and return once it holds the lock."""
    gate = VaultGate(
        vault_stack.addr,
        f"/v1/{fault_estate.mount}/data/{SECRET}",
        Fault.PAUSE_WRITE,
        writes=STAGING,
    )
    with ThreadPoolExecutor(max_workers=1) as pool:
        run = pool.submit(
            fault_estate.sopuli, fault_estate.config(gate.addr), "creds", "rotate", "--confirm"
        )
        # Closed inside the pool, so a run still paused at the gate is let go
        # before the pool waits for it.
        try:
            deadline = time.monotonic() + TIMEOUT
            while not gate.tripped.wait(0.5):
                if run.done() or time.monotonic() > deadline:
                    ended = run.result(timeout=TIMEOUT) if run.done() else None
                    raise HarnessError(
                        f"the run never staged; the gate saw {gate.seen}"
                        + (
                            f"; exit {ended.returncode}, stderr: {ended.stderr}"
                            if ended is not None
                            else ""
                        )
                    )
            record, _ = fault_estate.read(LOCK)
            if record["state"] != "held":
                raise HarnessError(f"the paused run does not hold its lock: {record}")
            yield Paused(gate=gate, run=run, pid=record["holder"]["pid"])
        finally:
            gate.close()


def _codes(result: subprocess.CompletedProcess[str]) -> list[str]:
    document = json.loads(result.stdout)
    return [diagnostic.get("code") for diagnostic in document.get("diagnostics", [])]


def test_two_rotations_at_once_one_exits_7_and_the_other_finishes(
    fault_estate: Estate, vault_stack: Any, paused: Paused
) -> None:
    """The second run is refused at its acquire, before it reads or writes anything.

    The first run then rotates as if the second had never started: the vault
    promotes the password the database has, and stages nothing more.
    """
    second = fault_estate.sopuli(
        fault_estate.config(vault_stack.addr), "creds", "rotate", "--confirm"
    )

    assert second.returncode == ExitCode.LOCK_HELD, second.stderr
    assert f"pid {paused.pid}" in second.stderr
    assert fault_estate.login(OLD), "the refused run changed the password"

    first = paused.finish()

    assert first.returncode == ExitCode.SUCCESS, first.stderr
    document, _ = fault_estate.read(SECRET)
    new = document["DB_CREDENTIALS"][ACCOUNT]
    assert new != OLD
    assert ACCOUNT not in document.get("pending", {})
    assert fault_estate.login(new), "the vault promoted a password the database does not have"
    record, _ = fault_estate.read(LOCK)
    assert record["state"] == "released"
    assert record["holder"]["pid"] == paused.pid


@pytest.fixture
def rotated(fault_estate: Estate, vault_stack: Any) -> str:
    """Rotate once to the end, so the vault has a ``current`` the database accepts.

    Returns that password. Runs before :func:`paused`, because the test asks
    for it first.
    """
    result = fault_estate.sopuli(
        fault_estate.config(vault_stack.addr), "creds", "rotate", "--confirm"
    )
    assert result.returncode == ExitCode.SUCCESS, result.stderr
    document, _ = fault_estate.read(SECRET)
    return str(document["DB_CREDENTIALS"][ACCOUNT])


def test_a_run_whose_lock_is_taken_over_stops_before_its_alter_user(
    fault_estate: Estate, vault_stack: Any, rotated: str, paused: Paused
) -> None:
    """The fence: a stalled run's plan is no longer true, so it applies none of it.

    The first run stalls inside its lock until the lock expires. A second run
    under ``locking.break_expired`` takes the lock over and finishes. It writes
    no secret document: the estate is converged, so ``apply`` has nothing to do.
    The first run then stages its ``pending``, and its fence check before
    ``ALTER USER`` finds the takeover. It stops there.

    A staged document is a change, so the run exits 4 and not 7. ``SOPULI-W011``
    says why, which the exit code cannot: a run whose targets failed also exits
    4, and that one is repaired by running ``apply`` again.
    """
    fault_estate.expire_lock()
    takeover = fault_estate.sopuli(
        fault_estate.config(vault_stack.addr, break_expired=True), "creds", "apply", "--confirm"
    )
    assert takeover.returncode == ExitCode.SUCCESS, takeover.stderr
    record, _ = fault_estate.read(LOCK)
    taker = record["holder"]["pid"]
    assert taker != paused.pid, "the second run did not take the lock over"

    first = paused.finish()

    assert first.returncode == ExitCode.PARTIAL, first.stderr
    assert LOCK_LOST in _codes(first), first.stdout
    assert f"pid {taker}" in first.stdout, "the message does not name the run that took over"
    document, _ = fault_estate.read(SECRET)
    staged = document["pending"][ACCOUNT]
    assert document["DB_CREDENTIALS"][ACCOUNT] == rotated, "promoted after a takeover"
    assert fault_estate.login(rotated)
    assert not fault_estate.login(staged), "the run reached ALTER USER after its lock was taken"
    # The fenced-out run gave back nothing it no longer held.
    record, _ = fault_estate.read(LOCK)
    assert record["holder"]["pid"] == taker
