"""What the estate says a password may be, before one is drawn (#317, UC-1 §4 step 2).

`creds generate` draws against the *policy*. The policy is written by a human who
may never have seen the databases it will be applied to, so a run can stage a
password no target can hold -- and nobody finds out until `apply` connects, by
which time the vault has a `pending` that cannot be applied anywhere.

**This is not #268's problem and must not be described as its answer.** A verify
function is arbitrary PL/SQL that cannot be consulted (invariants 13 and 14) and
a reuse history is hashed, so `ORA-28003` and `ORA-28007` cannot be predicted
before the statement is issued; #312 handles those by redrawing. What is
predictable is the *deterministic* pair -- a password longer than the target's
maximum, counted in bytes in the target's own character set, and characters the
target will not accept. Those hit every account in the selection identically and
one policy fix ends them, which is exactly why they were the wrong answer to #268
and are worth fixing on their own.

**Strictest wins, and the strictest is not the smallest number.** A
:class:`~sopuli.passwords.ByteLimit` is a count *and* the encoding it is counted
in, and the two cannot be compared apart: 30 bytes of ``cp1252`` holds 30
characters and 30 bytes of ``utf-8`` holds as few as 7. So the comparison is on
what a limit will actually accept, and the tie-break is the encoding rather than
the count.

**Not reaching a target is not a failure.** §4 says so, and it is the difference
between this being useful and being a new way for `generate` to fail: staging a
password for an estate that is down is a thing operators do, and the policy's
declared limits are the documented fallback. What the run must not do is stay
quiet about which of the two happened, so :class:`Constraints` carries its own
provenance rather than leaving the caller to remember.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from sopuli.passwords import ByteLimit

__all__ = [
    "Constraints",
    "POLICY",
    "TARGETS",
    "UNREAD",
    "strictest",
]

#: The limit came from at least one target that answered.
TARGETS = "targets"

#: No target answered, so the policy's declared length governs. §4's fallback,
#: and the reason :attr:`Constraints.limit` may be ``None``.
POLICY = "policy"

#: Nothing was asked. ``--offline``, and a distinct value from :data:`POLICY`
#: because "we could not find out" and "we did not look" are answers a report
#: must never merge -- the same rule ``driver/oracle/privileges.py`` states about
#: an unreadable view, applied one layer up.
UNREAD = "unread"


@dataclass(frozen=True)
class Constraints:
    """What was learned about the estate, and from where.

    ``limit`` is ``None`` in exactly the two cases where nothing was learned:
    nothing was asked (:data:`UNREAD`) or nothing answered (:data:`POLICY`).
    Passing that ``None`` on to :func:`sopuli.generate.candidate_for` is not a
    degradation -- it is the argument that function already accepts for "no target
    limit", and the policy's own length then governs, which is §4's fallback
    written as a default rather than as a branch.

    ``unreachable`` names the targets that did not answer, in the order they were
    tried. It is not an error list: a run that reached three of four targets used
    the three, and the fourth is a caveat on how strict the answer is rather than
    a reason to stop.
    """

    limit: ByteLimit | None = None
    source: str = UNREAD
    read: tuple[str, ...] = ()
    unreachable: tuple[str, ...] = ()
    #: Where two targets disagreed, the one whose limit won. Empty where only one
    #: target answered, because there was nothing to be strictest *than*.
    strictest_target: str | None = None

    @property
    def partial(self) -> bool:
        """Some targets answered and some did not.

        Worth its own name because it is the case a reader is most likely to get
        wrong: the limit is real, it came from a database, and it is still not
        necessarily the strictest one in the estate.
        """
        return bool(self.read) and bool(self.unreachable)


#: Characters probed to find how wide an encoding's widest one is. Chosen to
#: separate the encodings ``driver/oracle/limits.py`` actually maps rather than to
#: be exhaustive: ASCII, a Latin-1 letter, a symbol outside it, and a character
#: above the Basic Multilingual Plane. Under ``ascii`` and ``cp1252`` only some
#: encode and each is one byte; under ``utf-8`` all four do and the last is four.
_WIDTH_PROBES = ("z", "é", "€", "𝄞")


def _widest(encoding: str) -> int:
    """The most bytes one character can take in ``encoding``.

    Measured rather than tabulated, for the reason ``limits.py`` gives about its
    codec table: a second list of facts about encodings is a second thing to keep
    true, and this one can be asked of the codec directly.
    """
    widths = []
    for probe in _WIDTH_PROBES:
        try:
            widths.append(len(probe.encode(encoding)))
        except UnicodeEncodeError:
            continue
    return max(widths, default=1)


def _accepts(limit: ByteLimit) -> int:
    """How many characters this limit is *guaranteed* to hold.

    The comparable quantity, and deliberately the worst case: a limit accepts
    fewer characters the wider its encoding, so comparing byte counts alone would
    call 128 bytes of ``utf-8`` looser than 30 bytes of ``ascii`` and be right,
    and would call it looser than 30 bytes of ``utf-8`` and be wrong about what
    either will hold.

    **For a generated password the two coincide**, because §8's alphabets are
    ASCII and one ASCII character is one byte in every encoding
    ``driver/oracle/limits.py`` maps. The distinction earns its keep on the
    ``--from-stdin`` path, where the password is whatever an external system
    dictated and may be nothing of the kind.
    """
    return limit.max_bytes // _widest(limit.encoding)


def strictest(
    readings: Iterable[tuple[str, ByteLimit]],
    *,
    unreachable: Sequence[str] = (),
) -> Constraints:
    """The tightest of what the estate reported, with where it came from.

    ``readings`` is one pair per target that answered -- **one connection per
    target, never one per account**, which is what §4's "one representative"
    means for a command whose unit of work is an account and whose selection
    routinely puts several of them on one database.

    Ties keep the first reading, so the order targets were tried in decides an
    otherwise arbitrary choice rather than the iteration order of a set. Nothing
    depends on which of two identical limits is reported, but a run that named a
    different target on each invocation would be reporting noise as a fact.
    """
    seen = list(readings)
    unreached = tuple(unreachable)

    if not seen:
        return Constraints(source=POLICY if unreached else UNREAD, unreachable=unreached)

    name, limit = min(seen, key=lambda pair: _accepts(pair[1]))
    return Constraints(
        limit=limit,
        source=TARGETS,
        read=tuple(target for target, _ in seen),
        unreachable=unreached,
        strictest_target=name if len(seen) > 1 else None,
    )
