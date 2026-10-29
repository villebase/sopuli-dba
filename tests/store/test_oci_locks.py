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
from sopuli.store.oci._names import CAS_KEY, RECORD_KEY

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
    from sopuli.store.protocol import CasConflictError

    oci_store = store(fake)
    oci_store.write("locks/acme-db", RECORD, cas=0)

    with pytest.raises(CasConflictError):
        oci_store.write("locks/acme-db", RECORD, cas=0)


def test_metadata_is_unknown_and_require_cas_sends_nothing(fake: FakeOci) -> None:
    """OCI has no `cas_required`; IAM keeps other writers out."""
    oci_store = store(fake)

    assert oci_store.metadata("locks/acme-db") is None
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
    assert manager.unguarded == []
    assert len(fake.secrets["sopuli-locks.acme-db"].versions) == 1
