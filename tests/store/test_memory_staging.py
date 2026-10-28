"""The in-memory store with native staging (#1131).

Tier 0. The semantics are the ones measured against OCI Vault (#1129, the
``oci-*`` entries in ``docs/README.md``), so that UC-1 can be built and tested on
native staging without a tenancy.
"""

from __future__ import annotations

import pytest

from sopuli.store import MemoryStore
from sopuli.store.protocol import (
    CAS,
    LIST,
    STAGING,
    VERSIONING,
    CasConflictError,
    NativeStaging,
    StoreError,
)

PATH = "acme-db"


@pytest.fixture
def store() -> MemoryStore:
    return MemoryStore(capabilities=frozenset({CAS, LIST, VERSIONING, STAGING}))


def generations(store: MemoryStore) -> dict[str, int | None]:
    """Which generation holds each stage."""
    found = {}
    for stage in ("current", "pending", "previous"):
        stored = store.read_stage(PATH, stage)
        found[stage] = None if stored is None else stored.generation
    return found


def test_it_offers_native_staging(store: MemoryStore) -> None:
    assert isinstance(store, NativeStaging)
    assert STAGING in store.supports()


def test_a_write_is_current_and_generation_one(store: MemoryStore) -> None:
    store.write(PATH, {"password": "a"}, cas=0)

    stored = store.read(PATH)
    assert stored is not None
    assert (stored.stage, stored.generation, stored.data) == ("current", 1, {"password": "a"})


def test_a_staged_version_is_not_what_read_returns(store: MemoryStore) -> None:
    """Measured: `oci-pending-stage`. A reader sees PENDING only by asking."""
    token = store.write(PATH, {"password": "a"}, cas=0)
    store.stage(PATH, {"password": "b"}, attributes={}, cas=token)

    current = store.read(PATH)
    pending = store.read_stage(PATH, "pending")
    assert current is not None
    assert current.generation == 1
    assert pending is not None
    assert (pending.generation, pending.data) == (2, {"password": "b"})


def test_promote_moves_current_to_previous(store: MemoryStore) -> None:
    """Measured: `oci-promote-metadata`."""
    token = store.write(PATH, {"password": "a"}, cas=0)
    token = store.stage(PATH, {"password": "b"}, attributes={}, cas=token)
    store.promote(PATH, 2, attributes={}, cas=token)

    assert generations(store) == {"current": 2, "pending": None, "previous": 1}


def test_promote_replaces_the_attributes_whole(store: MemoryStore) -> None:
    """Measured: OCI replaces the metadata map whole."""
    token = store.write(PATH, {"password": "a"}, cas=0)
    token = store.stage(PATH, {"password": "b"}, attributes={"rotated_by": "x"}, cas=token)
    store.promote(PATH, 2, attributes={"targets": ["appdb-alpha"]}, cas=token)

    stored = store.read(PATH)
    assert stored is not None
    assert dict(stored.attributes) == {"targets": ["appdb-alpha"]}


def test_every_mutation_moves_the_cas_token(store: MemoryStore) -> None:
    """The lock fences on the token, so an attributes-only promotion moves it too."""
    tokens = [store.write(PATH, {"password": "a"}, cas=0)]
    tokens.append(store.stage(PATH, {"password": "b"}, attributes={}, cas=tokens[-1]))
    tokens.append(store.promote(PATH, 2, attributes={}, cas=tokens[-1]))
    tokens.append(store.promote(PATH, 2, attributes={"n": 1}, cas=tokens[-1]))

    assert tokens == sorted(set(tokens))
    stored = store.read(PATH)
    assert stored is not None
    assert stored.version == tokens[-1]


def test_a_stale_cas_is_refused_on_stage_and_promote(store: MemoryStore) -> None:
    token = store.write(PATH, {"password": "a"}, cas=0)
    store.stage(PATH, {"password": "b"}, attributes={}, cas=token)

    with pytest.raises(CasConflictError):
        store.stage(PATH, {"password": "c"}, attributes={}, cas=token)
    with pytest.raises(CasConflictError):
        store.promote(PATH, 2, attributes={}, cas=token)


def test_staging_over_a_pending_drops_the_old_pending(store: MemoryStore) -> None:
    """Measured: `oci-pending-replace`. The old one is deprecated."""
    token = store.write(PATH, {"password": "a"}, cas=0)
    token = store.stage(PATH, {"password": "b"}, attributes={"n": 1}, cas=token)
    store.stage(PATH, {"password": "c"}, attributes={"n": 2}, cas=token)

    assert generations(store) == {"current": 1, "pending": 3, "previous": None}
    stored = store.read(PATH)
    assert stored is not None
    assert dict(stored.attributes) == {"n": 2}


def test_a_current_write_leaves_a_pending_alone(store: MemoryStore) -> None:
    """Measured: `oci-pending-replace`."""
    token = store.write(PATH, {"password": "a"}, cas=0)
    token = store.stage(PATH, {"password": "b"}, attributes={}, cas=token)
    store.write(PATH, {"password": "c"}, cas=token)

    assert generations(store) == {"current": 3, "pending": 2, "previous": 1}


def test_promoting_an_unknown_generation_is_refused(store: MemoryStore) -> None:
    token = store.write(PATH, {"password": "a"}, cas=0)

    with pytest.raises(StoreError, match="cannot be promoted"):
        store.promote(PATH, 99, attributes={}, cas=token)


def test_promoting_a_deprecated_generation_is_refused(store: MemoryStore) -> None:
    """Measured: OCI would promote it. The store refuses."""
    token = store.write(PATH, {"password": "a"}, cas=0)
    token = store.write(PATH, {"password": "b"}, cas=token)
    token = store.write(PATH, {"password": "c"}, cas=token)

    with pytest.raises(StoreError, match="cannot be promoted"):
        store.promote(PATH, 1, attributes={}, cas=token)


def test_rollback_promotes_previous(store: MemoryStore) -> None:
    """One generation back (Q3): PREVIOUS and CURRENT swap."""
    token = store.write(PATH, {"password": "a"}, cas=0)
    token = store.write(PATH, {"password": "b"}, cas=token)
    store.promote(PATH, 1, attributes={}, cas=token)

    assert generations(store) == {"current": 1, "pending": None, "previous": 2}


def test_a_pinned_read_is_a_generation(store: MemoryStore) -> None:
    token = store.write(PATH, {"password": "a"}, cas=0)
    store.write(PATH, {"password": "b"}, cas=token)

    stored = store.read(PATH, version=1)
    assert stored is not None
    assert (stored.generation, stored.stage, stored.data) == (1, "previous", {"password": "a"})


def test_nothing_staged_reads_as_nothing(store: MemoryStore) -> None:
    assert store.read(PATH) is None
    assert store.read_stage(PATH, "pending") is None


def test_an_unknown_stage_is_refused(store: MemoryStore) -> None:
    with pytest.raises(StoreError, match="not a stage"):
        store.read_stage(PATH, "latest")


def test_without_staging_the_store_refuses_native_calls() -> None:
    store = MemoryStore()

    with pytest.raises(StoreError, match="native staging"):
        store.stage(PATH, {"password": "a"}, attributes={}, cas=0)
    with pytest.raises(StoreError, match="native staging"):
        store.promote(PATH, 1, attributes={}, cas=0)
    with pytest.raises(StoreError, match="native staging"):
        store.read_stage(PATH, "current")
