"""An estate whose store keeps UC-1's stages as its own versions (#1134).

The CLI tests for the UC-1 verbs run over ``MemoryStore`` in payload fields.
These helpers give them the other mechanism: an OCI-typed vault, so the config
chooses native staging, and a ``MemoryStore`` with ``staging_labels`` standing
in for it, seeded and read through the adapter the verbs use.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sopuli.payload import StageLayout
from sopuli.store import MemoryStore
from sopuli.store.native_view import NativeStagedStore
from sopuli.store.protocol import CAS, LIST, STAGING, VERSIONING

#: A ``vaults:`` entry of a type that stages natively. The OCIDs are the
#: documentation's placeholders; nothing connects to them.
OCI_VAULT = """\
vaults:
  vault-oci:
    type: oci
    vault_id: ocid1.vault.oc1..exampleuniqueid
    compartment_id: ocid1.compartment.oc1..exampleuniqueid
    key_id: ocid1.key.oc1..exampleuniqueid
"""

#: The field each one-account secret keeps its password in.
FIELD = "password"

NOW = datetime(2026, 10, 29, 12, 0, tzinfo=UTC)


def staging_store() -> MemoryStore:
    """A store with OCI's capabilities: no merge patch, stages as versions."""
    return MemoryStore(capabilities=frozenset({CAS, LIST, VERSIONING, STAGING}))


def adapter(store: MemoryStore, path: str, *, field: str = FIELD) -> NativeStagedStore:
    """``store`` as the verbs see it, with ``path`` native in ``field``."""
    return NativeStagedStore(
        store,
        native=lambda one: StageLayout(field) if one == path else None,
        by="svc_sopuli@ci-runner-3",
        now=lambda: NOW,
    )


def seed(store: MemoryStore, path: str, *documents: dict[str, Any], field: str = FIELD) -> None:
    """Write ``documents`` in turn, each in the emulated layout, as native
    versions: a rotated secret is a first document, then one whose
    ``previous`` is the first one's password."""
    view = adapter(store, path, field=field)
    for document in documents:
        found = view.read(path)
        view.write(path, document, cas=0 if found is None else found.version)


def view(store: MemoryStore, path: str) -> dict[str, Any]:
    """The document the verbs read at ``path``: ``password``, ``pending``,
    ``previous`` and the stamps, assembled from the versions."""
    found = adapter(store, path).read(path)
    assert found is not None
    return dict(found.data)
