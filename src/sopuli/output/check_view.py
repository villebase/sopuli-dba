"""`creds check` as a document and as a table (#248).

The `results[]` array and the text UC-1 §7 shows. Same arrangement as
:mod:`sopuli.output.doctor_view`: the shape lives here, the decision lives in
:mod:`sopuli.check`, and :class:`~sopuli.output.document.RunDocument` only knows
the section is optional.

**`results[]` is per (account, target), and `targets[]` is not.** `doctor` reports
on a target and manages no credential; this reports on a credential in a target.
The two arrays coexist for that reason and #182 added the second rather than
widening the first.

**The detail column is the point of the text view.** A state on its own is a word
an operator has to interpret -- `UNVERIFIABLE` says nothing about whether to act
-- and §7's worked output puts the reason beside every row for that reason. It is
the same sentence the JSON carries in ``actions[].detail``, so the two views
cannot drift.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from sopuli.check import DRIFT, IN_SYNC, Outcome, counts, is_inconclusive
from sopuli.config.model import Binding
from sopuli.driver.protocol import VerifyResult
from sopuli.output.document import Error, Summary
from sopuli.output.palette import Role, paint
from sopuli.output.table import Cell, Column, render_table

__all__ = ["build_result", "render_check", "summarise"]

#: Column caps, matching the widths the estate is already printed at elsewhere.
_ACCOUNT = 24
_TARGET = 28
_STATE = 16


def build_result(
    binding: Binding,
    outcome: Outcome,
    *,
    version: int | None = None,
    stage: str | None = None,
    age_days: float | None = None,
    duration_ms: int | None = None,
    previous_accepted: bool | None = None,
    error: Error | None = None,
    warnings: Sequence[str] = (),
) -> dict[str, Any]:
    """One ``results[]`` entry.

    ``changed`` is always ``False`` and is required by the schema anyway, which
    is worth saying rather than hiding: `check` is a read-only verb, and
    ``changed`` answers *did this run do anything* rather than *is anything
    wrong*. A consumer diffing the two arrays gets a run of ``false`` from this
    command by construction, and that is invariant 9's shape rather than an
    omission.
    """
    entry: dict[str, Any] = {
        "account": binding.account,
        "target": binding.target,
        "state": outcome.state,
        "changed": False,
    }
    secret = _secret(binding, version=version, stage=stage)
    if secret is not None:
        entry["secret"] = secret
    entry["actions"] = [
        {
            "kind": "verify",
            # `applied` is whether the action happened, not whether it passed.
            # A declined login is an action that did not happen and a failed one
            # is an action that did -- collapsing them would lose exactly the
            # distinction UC-1 §7's mitigation 1 exists to make visible.
            "applied": outcome.verification is not None,
            "detail": outcome.detail,
        }
    ]
    if outcome.verification is not None:
        entry["verification"] = _verification(
            outcome.verification, previous_accepted=previous_accepted
        )
    if age_days is not None:
        entry["password_age_days"] = age_days
    if duration_ms is not None:
        entry["duration_ms"] = duration_ms
    if error is not None:
        entry["error"] = error.to_dict()
    if warnings:
        entry["warnings"] = [
            {"level": "warning", "message": text, "target": binding.target} for text in warnings
        ]
    return entry


def _secret(binding: Binding, *, version: int | None, stage: str | None) -> dict[str, Any] | None:
    """The document this credential was read from, as ``secret_ref``.

    Carries the version the store actually served, which is the one thing this
    knows that `plan.units[].secret` deliberately cannot: a plan is a function of
    the config, and an observed version is a fact about the store at a moment.
    That is the whole reason both sections exist.

    ``None`` when the binding has no ref, or no store even after
    :func:`sopuli.config.binding_stores.complete` -- the schema requires ``vault``
    as a string, so there is no shape for half an address.
    """
    ref = binding.secret
    if ref is None or binding.vault is None:
        return None
    item: dict[str, Any] = {"vault": binding.vault, "path": ref.path}
    if ref.field is not None:
        item["field"] = ref.field
    if ref.pointer is not None:
        item["pointer"] = ref.pointer
    if version is not None:
        item["version"] = version
    if stage is not None:
        item["stage"] = stage
    return item


def _verification(result: VerifyResult, *, previous_accepted: bool | None = None) -> dict[str, Any]:
    """The ``verification`` object.

    ``lcount`` and ``failed_login_attempts_limit`` are emitted as ``null`` rather
    than omitted when the grant is absent, because null here is a real answer:
    #86 made ``SELECT ON SYS.USER$`` optional, so "the guard was unavailable" is
    a thing a scheduled check must be able to report. Omitting the keys would
    make an ungranted estate indistinguishable from one where nothing looked.
    """
    return {
        "method": result.method,
        "result": result.result,
        "latency_ms": result.latency_ms,
        "lcount": result.failed_logins,
        "failed_login_attempts_limit": result.failed_login_limit,
        "lockout_margin_hit": result.lockout_margin_hit,
        # Populated only with `--include-previous`, per the schema. Null covers
        # both "we did not ask" and "there was no previous password to ask
        # about" -- the second is the ordinary state of a credential that has
        # never been rotated, and neither is a `false`.
        "previous_password_accepted": previous_accepted,
    }


def summarise(states: Sequence[str]) -> Summary:
    """The whole ``summary`` object, in the vocabulary UC-1 §7's last line uses.

    Returns the object rather than a mapping to splat into it: `Summary` is
    frozen, and building it here means the optional counters this command has --
    and the ones it deliberately does not -- are decided in one place.

    ``ok`` is ``IN_SYNC`` and ``ROLLOVER_ACTIVE`` is **not** counted in it. The
    window is a healthy state and an operator should still know it is open --
    folding it into `ok` would make "4 ok" mean two different situations, one of
    which has a deadline attached.

    ``changed`` is zero and ``unchanged`` is everything, which is invariant 9's
    shape for a read-only verb rather than an oversight: nothing here mutates, so
    a second run reports exactly what the first did.
    """
    return Summary(
        total=len(states),
        ok=sum(1 for state in states if state == IN_SYNC),
        changed=0,
        failed=0,
        unchanged=len(states),
        drift=sum(1 for state in states if state == DRIFT),
        unverifiable=sum(1 for state in states if is_inconclusive(state)),
        by_state=counts(states),
    )


def render_check(rows: Sequence[tuple[Binding, Outcome]]) -> str:
    """The table, and the one-line verdict UC-1 §7 ends with.

    The verdict counts only what is worth acting on. A run where everything is
    in sync says so in one line rather than repeating the table's own arithmetic
    -- and a run with findings names them in the order somebody would deal with
    them: drift first, because it is the thing that is actually wrong.
    """
    table = render_table(
        [
            Column("ACCOUNT", _ACCOUNT),
            Column("TARGET", _TARGET),
            Column("STATE", _STATE),
            Column("DETAIL"),
        ],
        [
            [binding.account, binding.target, _state(outcome.state), outcome.detail]
            for binding, outcome in rows
        ],
    )
    return "\n".join([*table, "", _verdict([outcome.state for _, outcome in rows])])


def _state(state: str) -> Cell | str:
    """The state cell, with drift picked out.

    Only ``DRIFT`` takes colour. It is the state with an exit code of its own,
    and painting the inconclusive ones as well would make four of the eight
    states shout -- at which point the colour has stopped saying anything. The
    word is on the line either way, so `NO_COLOR` loses nothing.
    """
    return Cell(state, Role.NOTABLE) if state == DRIFT else state


def _verdict(states: Sequence[str]) -> str:
    drift = sum(1 for state in states if state == DRIFT)
    unverifiable = sum(1 for state in states if is_inconclusive(state))
    if not drift and not unverifiable:
        return paint(f"all {len(states)} in sync", Role.HEADING)
    findings = []
    if drift:
        findings.append(f"{drift} drift")
    if unverifiable:
        findings.append(f"{unverifiable} unverifiable")
    return ", ".join(findings)
