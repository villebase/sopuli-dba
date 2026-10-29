"""The tool's paths, as OCI secret names, and the reserved metadata keys.

A ref on an OCI store is the secret's name exactly (#1137), so a path with no
``/`` is used as it is. The only other path UC-1 has is a lock's,
``locks/<name>``, and the lock secret is ``sopuli-locks.<name>``. The config
layer refuses a ref under that prefix, so the two cannot collide. Any other
path with a ``/`` is refused: a new kind of record must choose its mapping on
purpose.
"""

from __future__ import annotations

from sopuli.config.vaults import OCI_RESERVED_PREFIX
from sopuli.store.protocol import StoreError

#: The prefix of a lock's path, as the lock manager writes it.
LOCKS = "locks/"

#: The secret's write counter, the compare-and-set token (#1128 builder's
#: calls). OCI's own version number does not move on a promotion or a
#: metadata-only update, so it cannot be the token. Underscores, because the
#: probe measured keys with them (#1136) and not keys with dots.
CAS_KEY = "sopuli_cas"

#: A lock record, as a JSON string, in the lock secret's metadata (decision 5).
RECORD_KEY = "sopuli_record"

#: Metadata keys the store keeps for itself, left out of ``Stored.attributes``.
RESERVED_KEYS = frozenset({CAS_KEY, RECORD_KEY})


def to_oci(path: str) -> str:
    """The OCI secret name for one of the tool's paths."""
    if path.startswith(LOCKS):
        return OCI_RESERVED_PREFIX + path[len(LOCKS) :]
    if "/" in path:
        raise StoreError(
            f"{path!r} is not an OCI secret name: an OCI secret name has no '/'",
            hint="name the secret exactly, as OCI does",
        )
    return path


def from_oci(name: str) -> str:
    """The tool's path for an OCI secret name: the inverse of :func:`to_oci`."""
    if name.startswith(OCI_RESERVED_PREFIX):
        return LOCKS + name[len(OCI_RESERVED_PREFIX) :]
    return name


def is_lock(path: str) -> bool:
    return path.startswith(LOCKS)
