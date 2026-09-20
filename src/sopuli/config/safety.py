"""Building a ``safety:`` block.

§9 allows one under ``defaults``, a target, a group or a profile, and says they
are the one thing in the file that does *not* follow last-one-wins: the resolved
value is the safest of all layers -- the lowest ``max_targets``, the union of
``confirm_environments``, the *intersection* of ``delivery.allowed_methods``,
``readonly`` if any layer sets it (P3, invariant 10).

That resolution is the precedence work and is not here. This reads one block, and
its only real job is to keep "unset" distinct from "set to the default" so the
resolver has something to be safest *of*.
"""

from __future__ import annotations

from typing import Any

from sopuli.config.delivery import DELIVERY_METHODS
from sopuli.config.errors import ConfigError, KeyPath
from sopuli.config.fields import (
    choice,
    mapping,
    optional_bool,
    optional_int,
    reject_unknown_keys,
    string_list,
)
from sopuli.config.model import Safety, SafetyDelivery

SAFETY_KEYS = ("max_targets", "confirm_environments", "readonly", "delivery")

#: The keys a ``safety.delivery:`` block takes. One today, and a block rather
#: than a flat ``delivery_allowed_methods`` key because UC-2 §6's other safety
#: axes -- were any to arrive -- belong beside it rather than beside
#: ``max_targets``.
SAFETY_DELIVERY_KEYS = ("allowed_methods",)


def build_safety(raw: Any, *, at: KeyPath) -> Safety | None:
    """Read a ``safety:`` block, or ``None`` where there is none."""
    if raw is None:
        return None
    block = mapping(raw, at=at)
    reject_unknown_keys(block, allowed=SAFETY_KEYS, at=at)

    max_targets = optional_int(block, "max_targets", at=at)
    if max_targets is not None and max_targets < 1:
        # Zero would be a way of saying "touch nothing", but `readonly: true` is
        # that, and it says so. A max_targets of 0 or -1 is much more likely to
        # be a slip in a file that then blocks every run for a reason nobody can
        # find.
        raise ConfigError(
            f"max_targets must be at least 1, not {max_targets}",
            at=at.key("max_targets"),
            hint="use `readonly: true` to block changes entirely",
        )

    confirm = block.get("confirm_environments")
    return Safety(
        max_targets=max_targets,
        confirm_environments=(
            () if confirm is None else string_list(confirm, at=at.key("confirm_environments"))
        ),
        readonly=optional_bool(block, "readonly", at=at),
        delivery=_build_delivery(block.get("delivery"), at=at.key("delivery")),
    )


def _build_delivery(raw: Any, *, at: KeyPath) -> SafetyDelivery | None:
    """Read ``safety.delivery:``, or ``None`` where the sub-block is absent.

    **Which methods, not which method.** ``delivery.method`` names the one an
    estate uses and lives in its own top-level block (#440); this says which ones
    it *may* use, and it is a safety axis rather than a delivery key -- a reader
    who looked for it beside ``method:`` would be looking in the layer that gets
    overridden rather than in the one that ratchets.

    **An empty list is refused rather than stored.** Under the intersection
    (:class:`~sopuli.settings.registry.ListMerge`) an empty set is unsatisfiable:
    it can only narrow further, so no later layer could ever restore a method and
    no run could deliver anything. Saying so here is better than letting it
    resolve, because the file is where the slip is and a resolved refusal would
    name a merge the operator did not know was happening. An estate that means
    "never hand a password over" configures no ``delivery:`` block at all.

    **Each entry is checked against the method enum**, so an allow-list naming a
    method that does not exist is refused instead of silently permitting one
    fewer than it reads as permitting -- which under an intersection is the
    difference between a typo and an estate that cannot deliver.
    """
    if raw is None:
        return None
    block = mapping(raw, at=at)
    reject_unknown_keys(block, allowed=SAFETY_DELIVERY_KEYS, at=at)

    written = block.get("allowed_methods")
    if written is None:
        return SafetyDelivery()
    where = at.key("allowed_methods")
    names = string_list(written, at=where)
    if not names:
        raise ConfigError(
            "allowed_methods is empty, so no delivery method would be permitted",
            at=where,
            hint=(
                "the set only ever narrows, so nothing could widen it again -- name the "
                "methods this estate permits, or leave the key out, which imposes no "
                "constraint at all"
            ),
        )
    return SafetyDelivery(
        allowed_methods=tuple(
            choice(name, allowed=DELIVERY_METHODS, at=where.index(index), noun="delivery method")
            for index, name in enumerate(names)
        )
    )
