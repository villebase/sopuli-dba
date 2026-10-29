"""The OCI store holds lock records in metadata (#1152, decision 5).

Tier 0, against ``tests/store/oci_fake.py``.
"""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime

import pytest
from oci_fake import COMPARTMENT_ID, KEY_ID, VAULT_ID, FakeOci

from sopuli.config.model import Vault
from sopuli.lock import Holder, LockableStore, LockKey, LockManager, lock_path
from sopuli.store.oci import OciStore
from sopuli.store.oci._errors import OciAuthError
from sopuli.store.oci._names import CAS_KEY, RECORD_KEY
from sopuli.store.protocol import CasConflictError, MetadataNotPermittedError, StoreError

RECORD = {"state": "held", "correlation_id": "01JACME", "command": "creds rotate"}


@pytest.fixture
def fake() -> FakeOci:
    return FakeOci()


def store(fake: FakeOci) -> OciStore:
    entry = Vault(
        name="vault-oci",
        type="oci",
        vault_id=VAULT_ID,
        compartment_id=COMPARTMENT_ID,
        key_id=KEY_ID,
    )
    # The clock never moves, so the wait for ACTIVE never times out.
    return OciStore(
        entry, vaults=fake, secrets=fake, kms=fake, sleep=lambda _: None, monotonic=lambda: 0.0
    )


def test_a_first_lock_creates_the_lock_secret(fake: FakeOci) -> None:
    assert store(fake).write("locks/acme-db", RECORD, cas=0) == 1

    details = fake.created[0]
    assert details.secret_name == "sopuli-locks.acme-db"
    assert json.loads(base64.b64decode(details.secret_content.content)) == {}
    assert details.metadata[CAS_KEY] == "1"
    assert json.loads(details.metadata[RECORD_KEY]) == RECORD


def test_a_lock_record_adds_no_version(fake: FakeOci) -> None:
    """#1136, M7b: a metadata-only update adds no version."""
    oci_store = store(fake)
    oci_store.write("locks/acme-db", RECORD, cas=0)
    oci_store.write("locks/acme-db", {**RECORD, "state": "released"}, cas=1)
    oci_store.write("locks/acme-db", RECORD, cas=2)

    assert len(fake.secrets["sopuli-locks.acme-db"].versions) == 1
    _, details, _ = fake.updates[-1]
    assert details.secret_content is None


def test_a_lock_record_reads_back_at_its_token(fake: FakeOci) -> None:
    oci_store = store(fake)
    oci_store.write("locks/acme-db", RECORD, cas=0)
    oci_store.write("locks/acme-db", {**RECORD, "state": "released"}, cas=1)

    stored = oci_store.read("locks/acme-db")

    assert stored is not None
    assert (stored.data["state"], stored.version) == ("released", 2)


def test_a_stale_lock_token_conflicts(fake: FakeOci) -> None:
    oci_store = store(fake)
    oci_store.write("locks/acme-db", RECORD, cas=0)

    with pytest.raises(CasConflictError):
        oci_store.write("locks/acme-db", RECORD, cas=0)


@pytest.mark.parametrize(
    "metadata",
    [{CAS_KEY: "3"}, {CAS_KEY: "3", RECORD_KEY: "not json"}, {CAS_KEY: "3", RECORD_KEY: "[1]"}],
    ids=["no record", "not JSON", "not an object"],
)
def test_a_lock_secret_without_a_readable_record_is_still_a_lock(
    fake: FakeOci, metadata: dict[str, str]
) -> None:
    """Read as nothing, every later `cas: 0` acquisition would fail for good.
    At its token, `LockRecord.from_dict` makes a held record of it."""
    fake.put("sopuli-locks.acme-db", {}, metadata=metadata)

    stored = store(fake).read("locks/acme-db")

    assert stored is not None
    assert (stored.data, stored.version) == (None, 3)


def test_a_lock_being_created_is_waited_for_not_refused(fake: FakeOci) -> None:
    """`oci-read-while-creating`: a second run reads the lock a first run has
    just created, and OCI answers 404 until it is ACTIVE."""
    secret = fake.put(
        "sopuli-locks.acme-db",
        {},
        metadata={CAS_KEY: "1", RECORD_KEY: json.dumps(RECORD)},
        lifecycle_state="CREATING",
    )
    secret.busy = 2

    stored = store(fake).read("locks/acme-db")

    assert stored is not None
    assert stored.data == RECORD


def test_a_read_that_lags_behind_the_creation_is_tried_once_more(fake: FakeOci) -> None:
    secret = fake.put(
        "sopuli-locks.acme-db",
        {},
        metadata={CAS_KEY: "1", RECORD_KEY: json.dumps(RECORD)},
        lifecycle_state="CREATING",
    )
    secret.busy = 1
    fake.lagging_reads = 1

    stored = store(fake).read("locks/acme-db")

    assert stored is not None
    assert stored.data == RECORD


def test_a_created_secret_that_stays_unreadable_is_refused_after_three_reads(
    fake: FakeOci,
) -> None:
    """Bounded: no loop of ListSecrets and reads against a throttling OCI."""
    secret = fake.put("sopuli-locks.acme-db", {}, lifecycle_state="CREATING")
    secret.busy = 1
    fake.unreadable.add("sopuli-locks.acme-db")

    with pytest.raises(OciAuthError, match="may not read its content"):
        store(fake).read("locks/acme-db")

    assert fake.calls.count("get_secret_bundle_by_name") == 3


def test_a_character_outside_the_bmp_counts_twice(fake: FakeOci) -> None:
    """Only ASCII and two-byte text were measured; count on the safe side."""
    oci_store = store(fake)

    with pytest.raises(StoreError, match="metadata would be"):
        oci_store.write("locks/acme-db", {"note": "\U0001f512" * 2600}, cas=0)


def test_the_record_is_counted_as_it_is_not_escaped_again(fake: FakeOci) -> None:
    """A record full of quotes is no bigger to OCI for being JSON inside JSON:
    escaped once, in the record itself, it is about 4,800 characters; escaped
    again, as the whole map's JSON, it would be about 9,600, over the limit."""
    oci_store = store(fake)

    assert oci_store.write("locks/acme-db", {"note": '"' * 2400}, cas=0) == 1


def test_require_cas_refuses_and_says_only_iam_guards_the_lock(fake: FakeOci) -> None:
    """OCI has no `cas_required`. The tool does not claim a guarantee it
    cannot check (P2), so the pre-flight records `SOPULI-W019` every run."""
    oci_store = store(fake)

    assert oci_store.metadata("locks/acme-db") is None
    with pytest.raises(MetadataNotPermittedError, match="only IAM keeps other writers off"):
        oci_store.require_cas("locks/acme-db")

    assert fake.calls == []


def test_the_lock_manager_takes_and_releases_a_lock_on_an_oci_store(fake: FakeOci) -> None:
    oci_store = store(fake)
    key = LockKey(store="vault-oci", path="acme-db")
    manager = LockManager(
        stores={"vault-oci": LockableStore(store=oci_store)},
        correlation_id="01JACME",
        command="creds rotate",
        holder=Holder(host="ci-runner-3", pid=8821, os_user="svc_sopuli"),
        now=lambda: datetime(2026, 10, 29, 12, 0, tzinfo=UTC),
    )

    with manager.holding([key]):
        held = oci_store.read(lock_path(key))
        assert held is not None
        assert held.data["state"] == "held"

    released = oci_store.read(lock_path(key))
    assert released is not None
    assert released.data["state"] == "released"
    # The lock held, and the run says the path is not guarded against others.
    assert [one.key for one in manager.unguarded] == [key]
    assert "only IAM keeps other writers off" in manager.unguarded[0].reason
    assert len(fake.secrets["sopuli-locks.acme-db"].versions) == 1
