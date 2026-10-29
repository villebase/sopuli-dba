"""The OCI store stages, promotes, and makes room at the version limit (#1153).

Tier 0, against ``tests/store/oci_fake.py``.

The staging semantics are the ones ``MemoryStore`` was built to, from the same
measurements, so its tests run here too against :class:`OciStore`: they are
imported below, and pytest runs them with this module's ``store`` fixture. The
tests after them are about what only OCI has: the version limit, the reserved
metadata keys, and what reaches the SDK.
"""

from __future__ import annotations

import pytest
from oci_fake import COMPARTMENT_ID, KEY_ID, VAULT_ID, FakeOci, FakeSecret
from test_memory_staging import (  # noqa: F401 -- collected and run with `store` below
    test_a_current_write_leaves_a_pending_alone,
    test_a_pinned_read_is_a_generation,
    test_a_staged_version_is_not_what_read_returns,
    test_a_stale_cas_is_refused_on_stage_and_promote,
    test_a_write_is_current_and_generation_one,
    test_an_unknown_stage_is_refused,
    test_every_mutation_moves_the_cas_token,
    test_nothing_staged_reads_as_nothing,
    test_promote_moves_current_to_previous,
    test_promote_replaces_the_attributes_whole,
    test_promoting_a_deprecated_generation_is_refused,
    test_promoting_an_unknown_generation_is_refused,
    test_rollback_promotes_previous,
    test_staging_onto_a_path_with_no_current_is_refused,
    test_staging_over_a_pending_drops_the_old_pending,
)

from sopuli.config.model import Vault
from sopuli.store.oci import OciStore
from sopuli.store.oci._names import CAS_KEY, RECORD_KEY
from sopuli.store.oci.store import VERSION_LIMIT, Pruned, Room
from sopuli.store.protocol import CAS, LIST, STAGING, VERSIONING, CasConflictError, StoreError


@pytest.fixture
def fake() -> FakeOci:
    return FakeOci()


@pytest.fixture
def store(fake: FakeOci) -> OciStore:
    entry = Vault(
        name="vault-oci",
        type="oci",
        vault_id=VAULT_ID,
        compartment_id=COMPARTMENT_ID,
        key_id=KEY_ID,
    )
    # The clock never moves, so no wait for ACTIVE times out.
    return OciStore(
        entry, vaults=fake, secrets=fake, kms=fake, sleep=lambda _: None, monotonic=lambda: 0.0
    )


def full(fake: FakeOci, stages: list[set[str]] | None = None) -> FakeSecret:
    """A secret at the limit. By default versions 1 to 27 are DEPRECATED, and
    PREVIOUS, CURRENT and PENDING are 28 to 30."""
    if stages is None:
        stages = [{"DEPRECATED"}] * (VERSION_LIMIT - 3) + [{"PREVIOUS"}, {"CURRENT"}, {"PENDING"}]
    contents = [{"password": f"p{n}"} for n in range(1, VERSION_LIMIT + 1)]
    return fake.put("acme-db", *contents, stages=[set(one) for one in stages])


def test_it_declares_native_staging(store: OciStore) -> None:
    assert store.supports() == frozenset({CAS, LIST, STAGING, VERSIONING})


def test_a_stage_sends_pending_content_and_the_attributes_whole(
    store: OciStore, fake: FakeOci
) -> None:
    token = store.write("acme-db", {"password": "a"}, cas=0)

    store.stage("acme-db", {"password": "b"}, attributes={"pending_version": 2}, cas=token)

    _, details, _ = fake.updates[-1]
    assert details.secret_content.stage == "PENDING"
    assert details.metadata == {"pending_version": 2, CAS_KEY: "2"}


def test_a_promotion_is_one_call_with_the_attributes(store: OciStore, fake: FakeOci) -> None:
    """`oci-promote-metadata`: the stage and the metadata move together."""
    token = store.write("acme-db", {"password": "a"}, cas=0)
    token = store.stage("acme-db", {"password": "b"}, attributes={}, cas=token)

    store.promote("acme-db", 2, attributes={"targets": ["appdb-alpha"]}, cas=token)

    _, details, _ = fake.updates[-1]
    assert (details.current_version_number, details.secret_content) == (2, None)
    assert details.metadata == {"targets": ["appdb-alpha"], CAS_KEY: "3"}


def test_a_deprecated_generation_is_refused_before_oci_is_asked(
    store: OciStore, fake: FakeOci
) -> None:
    """OCI would promote it (#1136, M5)."""
    fake.put("acme-db", {"password": "a"}, {"password": "b"}, {"password": "c"})

    with pytest.raises(StoreError, match="cannot be promoted"):
        store.promote("acme-db", 1, attributes={}, cas=1)

    assert fake.updates == []


@pytest.mark.parametrize("key", [CAS_KEY, RECORD_KEY])
def test_attributes_may_not_use_a_reserved_key(store: OciStore, fake: FakeOci, key: str) -> None:
    fake.put("acme-db", {"password": "a"})

    with pytest.raises(StoreError, match="keeps for itself"):
        store.stage("acme-db", {"password": "b"}, attributes={key: "9"}, cas=1)
    with pytest.raises(StoreError, match="keeps for itself"):
        store.promote("acme-db", 1, attributes={key: "9"}, cas=1)

    assert fake.updates == []


def test_a_lock_is_never_staged(store: OciStore) -> None:
    with pytest.raises(StoreError, match="never staged or promoted"):
        store.stage("locks/acme-db", {"state": "held"}, attributes={}, cas=1)


# ---------------------------------------------------------- the limit ---


def test_room_counts_versions_not_scheduled_for_deletion(store: OciStore, fake: FakeOci) -> None:
    """#1136, M7c: a version scheduled for deletion stops counting at once."""
    secret = fake.put("acme-db", {"p": 1}, {"p": 2}, {"p": 3}, {"p": 4})
    secret.versions[0].time_of_deletion = "2026-10-30T12:00:00Z"

    assert store.room("acme-db") == Room(versions=3, oldest_deprecated=2)
    assert store.room("acme-nothing") is None


def test_a_write_to_a_full_secret_deletes_its_oldest_deprecated_version_first(
    store: OciStore, fake: FakeOci
) -> None:
    secret = full(fake)

    assert store.write("acme-db", {"password": "new"}, cas=1) == 2

    assert secret.versions[0].time_of_deletion is not None
    assert all(one.time_of_deletion is None for one in secret.versions[1:])
    assert store.pruned == [Pruned(path="acme-db", generation=1)]
    assert len(secret.versions) == VERSION_LIMIT + 1


def test_a_stage_to_a_full_secret_makes_room_too(store: OciStore, fake: FakeOci) -> None:
    full(fake)

    store.stage("acme-db", {"password": "new"}, attributes={}, cas=1)

    assert store.pruned == [Pruned(path="acme-db", generation=1)]


def test_current_pending_and_previous_are_never_deleted(store: OciStore, fake: FakeOci) -> None:
    """After a rollback the low numbers can hold the stages that matter."""
    secret = full(
        fake, [{"CURRENT"}, {"PREVIOUS"}, {"PENDING"}] + [{"DEPRECATED"}] * (VERSION_LIMIT - 3)
    )

    store.write("acme-db", {"password": "new"}, cas=1)

    assert store.pruned == [Pruned(path="acme-db", generation=4)]
    assert all(one.time_of_deletion is None for one in secret.versions[:3])


def test_a_full_secret_with_nothing_deprecated_is_refused(store: OciStore, fake: FakeOci) -> None:
    """Versions 1 to 27 are already scheduled for deletion and do not count;
    the rest is full only in this test's arithmetic, so it is built directly."""
    stages = [{"PREVIOUS"}, {"CURRENT"}, {"PENDING"}] + [set()] * (VERSION_LIMIT - 3)
    full(fake, stages)

    with pytest.raises(StoreError, match="none of them is DEPRECATED"):
        store.write("acme-db", {"password": "new"}, cas=1)

    assert fake.updates == []


def test_a_lock_write_never_counts_versions(store: OciStore, fake: FakeOci) -> None:
    store.write("locks/acme-db", {"state": "held"}, cas=0)
    store.write("locks/acme-db", {"state": "released"}, cas=1)

    assert "list_secret_versions" not in fake.calls


def test_a_write_while_room_was_made_conflicts(store: OciStore, fake: FakeOci) -> None:
    """The counter is checked again after the deletion's wait."""
    secret = full(fake)

    def other_writer(secret_id: str, number: int, details: object) -> None:
        secret.metadata[CAS_KEY] = "2"

    real = fake.schedule_secret_version_deletion

    def schedule(secret_id: str, number: int, details: object) -> object:
        result = real(secret_id, number, details)
        other_writer(secret_id, number, details)
        return result

    fake.schedule_secret_version_deletion = schedule  # type: ignore[method-assign]

    with pytest.raises(CasConflictError, match="while this run made room"):
        store.write("acme-db", {"password": "new"}, cas=1)
