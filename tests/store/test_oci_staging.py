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
from sopuli.exit_codes import ExitCode
from sopuli.store.oci import OciStore
from sopuli.store.oci._errors import OciUnavailableError
from sopuli.store.oci._names import CAS_KEY, RECORD_KEY
from sopuli.store.oci.store import THROTTLE_WAITS, VERSION_LIMIT
from sopuli.store.protocol import (
    CAS,
    LIST,
    STAGING,
    VERSIONING,
    CasConflictError,
    PinnedVersionError,
    Pruned,
    Room,
    StoreError,
)


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

    assert store.room("acme-db") == Room(
        versions=3, deprecated=(2,), limit=VERSION_LIMIT, previous=3, current=4
    )
    assert store.room("acme-nothing") is None


def test_room_says_which_versions_each_write_would_delete() -> None:
    """A rotation in payload fields writes twice, so a secret one short of
    full still loses a version, and a full one loses two (#1159). Each such
    write demotes the old PREVIOUS to DEPRECATED, so the second can delete
    what the first demoted; a native stage demotes nothing."""
    room = Room(versions=29, deprecated=(3, 4, 5), limit=30, previous=29, current=30)

    assert room.making_room_for(0, demoting=True) == ()
    assert room.making_room_for(1, demoting=True) == ()
    assert room.making_room_for(2, demoting=True) == (3,)

    full = Room(versions=30, deprecated=(3,), limit=30, previous=29, current=30)
    assert full.making_room_for(2, demoting=True) == (3, 29)
    assert full.making_room_for(1, demoting=False) == (3,)
    assert full.making_room_for(2, demoting=False) is None
    nothing = Room(versions=30, deprecated=(), limit=30, previous=29, current=30)
    assert nothing.making_room_for(1, demoting=True) is None
    # With no PREVIOUS, the first write makes CURRENT PREVIOUS, not DEPRECATED.
    no_previous = Room(versions=30, deprecated=(5,), limit=30, previous=None, current=30)
    assert no_previous.making_room_for(2, demoting=True) is None


def test_a_name_held_only_by_a_deleting_secret_is_held(store: OciStore, fake: FakeOci) -> None:
    """``oci-create-taken``: a name a secret scheduled for deletion holds
    cannot be created, though reads report nothing there (#1159)."""
    fake.put("acme-gone", {"p": 1}, lifecycle_state="PENDING_DELETION")
    fake.put("acme-live", {"p": 1})
    fake.put("acme-deleted", {"p": 1}, lifecycle_state="DELETED")

    assert store.name_held("acme-gone") is True
    assert store.name_held("acme-live") is False
    assert store.name_held("acme-nothing") is False
    assert store.name_held("acme-deleted") is False


def test_a_lock_name_held_by_a_deleting_secret_is_held(store: OciStore, fake: FakeOci) -> None:
    """The lock at ``locks/<name>`` is the secret ``sopuli-locks.<name>``,
    and a deleting one holds that name as a secret's does (#1188). A live
    lock record holds nothing: taking the lock then creates nothing."""
    fake.put("sopuli-locks.acme-gone", {}, lifecycle_state="PENDING_DELETION")
    fake.put("sopuli-locks.acme-live", {})

    assert store.name_held("locks/acme-gone") is True
    assert store.name_held("acme-gone") is False
    assert store.name_held("locks/acme-live") is False


def test_a_write_to_a_full_secret_deletes_its_oldest_deprecated_version_first(
    store: OciStore, fake: FakeOci
) -> None:
    secret = full(fake)

    assert store.write("acme-db", {"password": "new"}, cas=1) == 2

    assert secret.versions[0].time_of_deletion is not None
    assert all(one.time_of_deletion is None for one in secret.versions[1:])
    assert store.pruned == [Pruned(path="acme-db", generation=1)]
    assert len(secret.versions) == VERSION_LIMIT + 1


def test_making_room_never_deletes_a_pinned_version(store: OciStore, fake: FakeOci) -> None:
    """The guarantee is the store's, at the deletion, whatever the plan saw
    (#1159): a ref pinning the oldest DEPRECATED version refuses the write."""
    secret = full(fake)
    store.protect("acme-db", [1])

    with pytest.raises(PinnedVersionError, match="`@version=1`") as raised:
        store.write("acme-db", {"password": "new"}, cas=1)

    assert raised.value.exit_code == ExitCode.CONFIG_INVALID
    assert all(one.time_of_deletion is None for one in secret.versions)
    assert store.pruned == []


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
    """The measurements never showed OCI leaving a counted version with no
    stage, so this state is built by hand. Whatever leads to it, the store
    deletes nothing it cannot prove unreachable, and refuses."""
    stages = [{"PREVIOUS"}, {"CURRENT"}, {"PENDING"}] + [set()] * (VERSION_LIMIT - 3)
    secret = full(fake, stages)

    with pytest.raises(StoreError, match="none of them is DEPRECATED"):
        store.write("acme-db", {"password": "new"}, cas=1)

    assert len(secret.versions) == VERSION_LIMIT
    assert all(one.time_of_deletion is None for one in secret.versions)


def test_a_write_to_a_secret_with_room_lists_no_versions(store: OciStore, fake: FakeOci) -> None:
    """Room is made only when OCI says the secret is full."""
    fake.put("acme-db", {"password": "a"})

    store.write("acme-db", {"password": "b"}, cas=1)

    assert "list_secret_versions" not in fake.calls


def test_a_write_that_fails_otherwise_deletes_nothing(store: OciStore, fake: FakeOci) -> None:
    """A full secret whose write is refused on its size never reaches OCI's
    limit answer, so no version is scheduled for deletion."""
    secret = full(fake)
    secret.metadata["terraform_note"] = "x" * 5100

    with pytest.raises(StoreError, match="metadata would be"):
        store.write("acme-db", {"password": "new"}, cas=1)

    assert all(one.time_of_deletion is None for one in secret.versions)
    assert store.pruned == []


def test_an_unguarded_write_after_making_room_builds_on_the_new_state(
    store: OciStore, fake: FakeOci, monkeypatch: pytest.MonkeyPatch
) -> None:
    """While room is made, another writer moves the counter. A guarded write
    refuses; an unguarded one moves the counter past it."""
    secret = full(fake)
    real = fake.schedule_secret_version_deletion

    def schedule_then_another_writer(secret_id: str, number: int, details: object) -> object:
        result = real(secret_id, number, details)
        secret.metadata[CAS_KEY] = "5"
        return result

    monkeypatch.setattr(fake, "schedule_secret_version_deletion", schedule_then_another_writer)

    assert store.write("acme-db", {"password": "new"}, cas=None) == 6


def test_an_unguarded_promotion_still_sends_the_etag(store: OciStore, fake: FakeOci) -> None:
    """The stage check is only good for the read it was made on."""
    token = store.write("acme-db", {"password": "a"}, cas=0)
    store.stage("acme-db", {"password": "b"}, attributes={}, cas=token)

    store.promote("acme-db", 2, attributes={}, cas=None)

    assert fake.updates[-1][2] is not None


def test_a_lock_write_never_counts_versions(store: OciStore, fake: FakeOci) -> None:
    store.write("locks/acme-db", {"state": "held"}, cas=0)
    store.write("locks/acme-db", {"state": "released"}, cas=1)

    assert "list_secret_versions" not in fake.calls


def test_a_write_while_room_was_made_conflicts(
    store: OciStore, fake: FakeOci, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The counter is checked again after the deletion's wait."""
    secret = full(fake)
    real = fake.schedule_secret_version_deletion

    def schedule_then_another_writer(secret_id: str, number: int, details: object) -> object:
        result = real(secret_id, number, details)
        secret.metadata[CAS_KEY] = "2"
        return result

    monkeypatch.setattr(fake, "schedule_secret_version_deletion", schedule_then_another_writer)

    with pytest.raises(CasConflictError, match="while this run made room"):
        store.write("acme-db", {"password": "new"}, cas=1)


def test_making_room_is_always_followed_by_a_resend(store: OciStore, fake: FakeOci) -> None:
    """Busy three times, then full: the room made is used, not wasted."""
    secret = full(fake)
    busy: list[int] = []

    def other_writers(target: FakeSecret) -> None:
        if len(busy) < 3:
            busy.append(1)
            target.lifecycle_state = "UPDATING"
            target.busy = 1

    fake.before_update = other_writers

    assert store.write("acme-db", {"password": "new"}, cas=1) == 2
    assert store.pruned == [Pruned(path="acme-db", generation=1)]
    assert len(secret.versions) == VERSION_LIMIT + 1


def test_a_guarded_write_checks_the_counter_before_deleting(store: OciStore, fake: FakeOci) -> None:
    """Another writer moved the counter, and OCI answers the limit before the
    ETag: nothing may be deleted for a write that has already lost."""
    secret = full(fake)
    once: list[bool] = []

    def other_writer(target: FakeSecret) -> None:
        if not once:
            once.append(True)
            target.metadata[CAS_KEY] = "5"

    fake.before_update = other_writer

    with pytest.raises(CasConflictError, match="since this run read it"):
        store.write("acme-db", {"password": "new"}, cas=1)

    assert all(one.time_of_deletion is None for one in secret.versions)


def test_a_failed_wait_after_making_room_says_a_deletion_was_scheduled(
    store: OciStore, fake: FakeOci, monkeypatch: pytest.MonkeyPatch
) -> None:
    full(fake)
    real = fake.schedule_secret_version_deletion

    def schedule_then_fail(secret_id: str, number: int, details: object) -> object:
        result = real(secret_id, number, details)
        fake.final_state = "FAILED"
        return result

    monkeypatch.setattr(fake, "schedule_secret_version_deletion", schedule_then_fail)

    with pytest.raises(StoreError, match="version 1 was scheduled for deletion to make room"):
        store.write("acme-db", {"password": "new"}, cas=1)


# ---------------------------------------------------------- throttling ---


def throttled_store(fake: FakeOci, sleeps: list[float]) -> OciStore:
    entry = Vault(
        name="vault-oci",
        type="oci",
        vault_id=VAULT_ID,
        compartment_id=COMPARTMENT_ID,
        key_id=KEY_ID,
    )
    return OciStore(
        entry, vaults=fake, secrets=fake, kms=fake, sleep=sleeps.append, monotonic=lambda: 0.0
    )


def test_a_throttled_read_is_tried_again(fake: FakeOci) -> None:
    """A real run met `429` on ListSecretVersions while counting versions."""
    fake.put("acme-db", {"p": 1}, {"p": 2})
    fake.throttle["list_secret_versions"] = 2
    sleeps: list[float] = []

    assert throttled_store(fake, sleeps).room("acme-db") == Room(
        versions=2, deprecated=(), limit=VERSION_LIMIT, previous=1, current=2
    )
    assert sleeps == list(THROTTLE_WAITS[:2])


def test_a_read_throttled_every_time_gives_up(fake: FakeOci) -> None:
    fake.put("acme-db", {"p": 1})
    fake.throttle["get_secret_bundle_by_name"] = 99
    sleeps: list[float] = []

    with pytest.raises(OciUnavailableError, match="429 TooManyRequests"):
        throttled_store(fake, sleeps).read("acme-db")

    assert sleeps == list(THROTTLE_WAITS)
    assert fake.calls.count("get_secret_bundle_by_name") == len(THROTTLE_WAITS) + 1
