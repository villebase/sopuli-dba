"""A SQL Server login's policy flags, kept in the vault while its policy is off (#1551).

SQL Server takes a ``HASHED`` value only with ``CHECK_POLICY = OFF`` in the same
statement, and turning the policy off also turns ``CHECK_EXPIRATION`` off
(``mssql-policy-off``). So a change reads both flags first, records them in
the vault, and sets them back once the login has passed
(``02-mssql-privileges.md`` §6.2). A run that stops in between leaves the
policy off, and the next run sets the recorded flags back.

The record is :data:`~sopuli.payload.POLICY_FLAGS`, beside ``pending`` by the
mirror rule: ``{"mssql-dev": {"check_policy": true, "check_expiration":
false}}``, per account in a shared document. This module reads it and builds
the merge patches that write it. It does no I/O, and nothing here writes it
yet: SQL Server's change does (#1551).

**A record that cannot be read is never written over.** A merge patch replaces
whatever is not a mapping, so a write over a record of the wrong shape would
drop flags that may be the only copy of the login's settings. :func:`recorded`
raises :class:`PolicyFlagsUnreadableError` instead, and a caller reads before
it writes: the change on that target is refused, and the record stays for a
person to look at. Refusing costs one target's change; guessing would cost a
login's password policy or its expiry, for good and unseen.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from sopuli.payload import POLICY_FLAGS, REMOVE, StageLayout
from sopuli.store.protocol import StoreError

#: The two flags' keys in the record: the server's own option names, in lower
#: case, so a DBA reading the vault knows what each one means.
CHECK_POLICY = "check_policy"
CHECK_EXPIRATION = "check_expiration"

__all__ = [
    "CHECK_EXPIRATION",
    "CHECK_POLICY",
    "PolicyFlags",
    "PolicyFlagsUnreadableError",
    "record_patch",
    "recorded",
    "remove_patch",
]


@dataclass(frozen=True)
class PolicyFlags:
    """One login's ``CHECK_POLICY`` and ``CHECK_EXPIRATION``, as read from
    ``sys.sql_logins`` before the policy was turned off."""

    check_policy: bool
    check_expiration: bool

    def to_record(self) -> dict[str, bool]:
        return {CHECK_POLICY: self.check_policy, CHECK_EXPIRATION: self.check_expiration}

    @property
    def need_restoring(self) -> bool:
        """Whether turning the policy off changes anything to set back: not
        where both were off already."""
        return self.check_policy or self.check_expiration

    @classmethod
    def from_record(cls, node: Any) -> PolicyFlags | None:
        """The flags a record's entry holds, or ``None`` where it is not a pair
        of JSON booleans the server can have: ``CHECK_EXPIRATION`` is on only
        with ``CHECK_POLICY`` on, so a pair with expiration alone could never
        be set back (``statements.restore_policy`` refuses it). A string
        ``"true"`` is refused too: nothing here guesses what a value written
        some other way meant."""
        if (
            not isinstance(node, Mapping)
            or set(node) != {CHECK_POLICY, CHECK_EXPIRATION}
            or not all(isinstance(value, bool) for value in node.values())
        ):
            return None
        flags = cls(check_policy=node[CHECK_POLICY], check_expiration=node[CHECK_EXPIRATION])
        if flags.check_expiration and not flags.check_policy:
            return None
        return flags


class PolicyFlagsUnreadableError(StoreError):
    """The vault holds a policy-flags record the tool cannot read.

    Exit 1, as :class:`~sopuli.store.credentials.SecretShapeError` is: the
    config is fine, and the document needs a person.
    """

    def __init__(self, target: str, path: tuple[str, ...]) -> None:
        super().__init__(
            f"the vault's record of the policy flags for target {target!r} "
            f"(at {'/'.join(path)}) is not a pair of true/false values",
            hint=(
                "the tool does not change this login until the record can be read, "
                "because it may be the only copy of the login's CHECK_POLICY and "
                "CHECK_EXPIRATION. Set them on the server by hand if they are known, "
                "then fix or remove the record"
            ),
        )
        self.target = target


def recorded(document: Any, layout: StageLayout, target: str) -> PolicyFlags | None:
    """The flags ``document`` records for ``target``, or ``None`` where it
    records none.

    Raises :class:`PolicyFlagsUnreadableError` where anything on the way is
    of the wrong shape: the record root, the account's entry in a shared
    document, the target's entry, or a flag that is not a JSON boolean. A
    string ``"true"`` is refused too: nothing here guesses what a value
    written some other way meant.
    """
    path = (*layout.location(POLICY_FLAGS), target)
    node: Any = document
    for segment in path:
        if node is None:
            return None
        if not isinstance(node, Mapping):
            raise PolicyFlagsUnreadableError(target, path)
        if segment not in node:
            return None
        node = node[segment]
    if node is None:
        return None
    flags = PolicyFlags.from_record(node)
    if flags is None:
        raise PolicyFlagsUnreadableError(target, path)
    return flags


def record_patch(layout: StageLayout, target: str, flags: PolicyFlags) -> dict[str, Any]:
    """A merge patch recording ``flags`` for ``target``, touching no other
    target's entry. Send it only where :func:`recorded` answered ``None``:
    flags already recorded are the ones from before the policy went off, and a
    second read would record the policy off (§6.2, step 1)."""
    return layout.patch(POLICY_FLAGS, {target: flags.to_record()})


def remove_patch(document: Any, layout: StageLayout, target: str) -> dict[str, Any]:
    """A merge patch removing ``target``'s entry from ``document``, once its
    flags are set back on the server (§6.2, step 4). The other targets'
    entries stay.

    A node the removal would leave empty goes with it: the account's entry
    in a shared document, and the record's root where nothing else is in it.
    So no store keeps an empty ``policy_flags: {}`` behind, whether it takes
    merge patches or stages natively. Read ``document`` with :func:`recorded`
    first, which refuses one of the wrong shape.
    """
    path = (*layout.location(POLICY_FLAGS), target)
    # The shallowest node along the path whose only content is the next step.
    cut = len(path) - 1
    node: Any = document
    nodes: list[Any] = []
    for segment in path[:-1]:
        node = node.get(segment) if isinstance(node, Mapping) else None
        nodes.append(node)
    for depth in range(len(path) - 2, -1, -1):
        held = nodes[depth]
        if isinstance(held, Mapping) and set(held) <= {path[depth + 1]}:
            cut = depth
        else:
            break
    patch: Any = REMOVE
    for segment in reversed(path[: cut + 1]):
        patch = {segment: patch}
    return dict(patch)
