"""The OCI store reads and lists (#1144).

Tier 0, against ``tests/store/oci_fake.py``, whose answers were measured in
#1136.
"""

from __future__ import annotations

from typing import Any

import oci
import pytest
from oci_fake import COMPARTMENT_ID, VAULT_ID, FakeOci

from sopuli.config.model import Vault
from sopuli.exit_codes import ExitCode
from sopuli.store.oci import OciStore
from sopuli.store.oci._errors import raise_for
from sopuli.store.oci._names import CAS_KEY, RECORD_KEY, from_oci, to_oci
from sopuli.store.protocol import LIST, VERSIONING, CasConflictError, StoreError


@pytest.fixture
def fake() -> FakeOci:
    return FakeOci()


def store(fake: FakeOci, *, vault_id: str = VAULT_ID) -> OciStore:
    entry = Vault(name="vault-oci", type="oci", vault_id=vault_id, compartment_id=COMPARTMENT_ID)
    return OciStore(entry, vaults=fake, secrets=fake, kms=fake)


# ------------------------------------------------------------------ names ---


def test_a_lock_path_is_a_reserved_secret_name() -> None:
    assert to_oci("locks/acme-db") == "sopuli-locks.acme-db"
    assert from_oci("sopuli-locks.acme-db") == "locks/acme-db"


def test_a_ref_name_is_used_as_it_is() -> None:
    assert to_oci("acme-prod.db_creds") == "acme-prod.db_creds"
    assert from_oci("acme-prod.db_creds") == "acme-prod.db_creds"


def test_any_other_path_with_a_separator_is_refused() -> None:
    with pytest.raises(StoreError, match="has no '/'"):
        to_oci("sopuli/personal-resets/acme")


# ------------------------------------------------------------------ reads ---


def test_it_declares_list_and_versioning_only() -> None:
    """`cas` and `staging_labels` arrive with the writes (#1133)."""
    assert store(FakeOci()).supports() == frozenset({LIST, VERSIONING})


def test_a_read_returns_current_with_its_stamps(fake: FakeOci) -> None:
    fake.put(
        "acme-db",
        {"password": "a"},
        {"password": "b"},
        metadata={CAS_KEY: "4", "targets": ["appdb-alpha"]},
    )

    stored = store(fake).read("acme-db")

    assert stored is not None
    assert stored.data == {"password": "b"}
    assert (stored.version, stored.stage, stored.generation) == (4, "current", 2)
    assert dict(stored.attributes) == {"targets": ["appdb-alpha"]}


def test_a_secret_the_tool_never_wrote_reads_at_token_one(fake: FakeOci) -> None:
    """Decision 6: adopted. 0 would mean "nothing here" to a `cas: 0` write."""
    fake.put("acme-db", {"password": "a"})

    stored = store(fake).read("acme-db")

    assert stored is not None
    assert stored.version == 1


def test_a_missing_secret_reads_as_nothing(fake: FakeOci) -> None:
    assert store(fake).read("acme-db") is None


def test_the_vault_is_checked_once(fake: FakeOci) -> None:
    oci_store = store(fake)

    oci_store.read("acme-db")
    oci_store.read("acme-dw")

    assert fake.calls.count("get_vault") == 1


def test_a_wrong_vault_id_is_a_config_error_not_an_empty_vault(fake: FakeOci) -> None:
    """Otherwise every secret reads as absent, and a run plans to create them."""
    fake.put("acme-db", {"password": "a"})

    with pytest.raises(StoreError, match="vault_id was not found") as error:
        store(fake, vault_id="ocid1.vault.oc1..wrongone").read("acme-db")

    assert error.value.exit_code == ExitCode.CONFIG_INVALID


def test_a_pinned_read_of_current_carries_the_token(fake: FakeOci) -> None:
    fake.put("acme-db", {"password": "a"}, {"password": "b"}, metadata={CAS_KEY: "7"})

    stored = store(fake).read("acme-db", version=2)

    assert stored is not None
    assert (stored.version, stored.generation) == (7, 2)


def test_a_pinned_read_of_an_old_version_gets_token_zero(fake: FakeOci) -> None:
    """As MemoryStore: content derived from it must not replace CURRENT."""
    fake.put("acme-db", {"password": "a"}, {"password": "b"}, metadata={CAS_KEY: "7"})

    stored = store(fake).read("acme-db", version=1)

    assert stored is not None
    assert (stored.data, stored.version, stored.stage) == ({"password": "a"}, 0, "previous")


def test_a_version_that_is_gone_reads_as_nothing(fake: FakeOci) -> None:
    fake.put("acme-db", {"password": "a"})

    assert store(fake).read("acme-db", version=9) is None


def test_a_deprecated_version_has_no_stage(fake: FakeOci) -> None:
    fake.put("acme-db", {"password": "a"}, {"password": "b"}, {"password": "c"})

    stored = store(fake).read("acme-db", version=1)

    assert stored is not None
    assert stored.stage is None


def test_read_stage_returns_pending_only_when_asked(fake: FakeOci) -> None:
    """Measured: `oci-pending-stage`."""
    fake.put(
        "acme-db",
        {"password": "a"},
        {"password": "b"},
        stages=[{"CURRENT"}, {"PENDING", "LATEST"}],
        metadata={CAS_KEY: "3"},
    )
    oci_store = store(fake)

    current = oci_store.read("acme-db")
    pending = oci_store.read_stage("acme-db", "pending")

    assert current is not None
    assert current.data == {"password": "a"}
    assert pending is not None
    assert (pending.data, pending.stage, pending.generation, pending.version) == (
        {"password": "b"},
        "pending",
        2,
        3,
    )


def test_no_version_in_the_stage_reads_as_nothing(fake: FakeOci) -> None:
    fake.put("acme-db", {"password": "a"})

    assert store(fake).read_stage("acme-db", "pending") is None


def test_an_unknown_stage_is_refused(fake: FakeOci) -> None:
    with pytest.raises(StoreError, match="not a stage"):
        store(fake).read_stage("acme-db", "latest")


@pytest.mark.parametrize("content", ["hunter2", '["a", "b"]', "null"])
def test_content_that_is_not_a_json_object_is_refused(fake: FakeOci, content: str) -> None:
    """Decision 6, naming the secret."""
    fake.put("acme-db", content)

    with pytest.raises(StoreError, match='secret "acme-db" .* does not hold a JSON object'):
        store(fake).read("acme-db")


def test_a_lock_record_is_read_from_the_metadata(fake: FakeOci) -> None:
    """Decision 5: the content is a placeholder, and the record is metadata."""
    fake.put(
        "sopuli-locks.acme-db",
        {},
        metadata={CAS_KEY: "5", RECORD_KEY: '{"state": "held", "holder": "run-1"}'},
    )

    stored = store(fake).read("locks/acme-db")

    assert stored is not None
    assert stored.data == {"state": "held", "holder": "run-1"}
    assert stored.version == 5
    assert dict(stored.attributes) == {}


def test_a_lock_secret_with_no_record_reads_as_nothing(fake: FakeOci) -> None:
    fake.put("sopuli-locks.acme-db", {})

    assert store(fake).read("locks/acme-db") is None


def test_a_write_counter_the_tool_did_not_write_is_refused(fake: FakeOci) -> None:
    fake.put("acme-db", {"password": "a"}, metadata={CAS_KEY: "soon"})

    with pytest.raises(StoreError, match="write counter"):
        store(fake).read("acme-db")


def test_writes_are_refused_until_they_are_built(fake: FakeOci) -> None:
    with pytest.raises(StoreError, match="not built"):
        store(fake).write("acme-db", {"password": "a"}, cas=0)


# ---------------------------------------------------------------- listing ---


def test_listing_pages_maps_locks_and_sorts(fake: FakeOci) -> None:
    for name in ("sopuli-locks.acme-db", "acme-dw", "acme-db", "zeta-db", "sopuli-locks.acme-dw"):
        fake.put(name, {})

    assert store(fake).list("") == (
        "acme-db",
        "acme-dw",
        "locks/acme-db",
        "locks/acme-dw",
        "zeta-db",
    )
    assert fake.calls.count("list_secrets") == 3


def test_listing_under_locks_returns_lock_paths_only(fake: FakeOci) -> None:
    for name in ("sopuli-locks.acme-db", "acme-db", "locksmith-db"):
        fake.put(name, {})

    assert store(fake).list("locks") == ("locks/acme-db",)


def test_listing_skips_secrets_being_deleted(fake: FakeOci) -> None:
    fake.put("acme-db", {})
    fake.put("acme-old", {}, lifecycle_state="PENDING_DELETION")

    assert store(fake).list("") == ("acme-db",)


def test_an_empty_vault_lists_as_empty(fake: FakeOci) -> None:
    assert store(fake).list("") == ()


# ----------------------------------------------------------------- errors ---


def service_error(status: int, code: str, *, request_id: str | None = "req-1") -> Any:
    headers = {"opc-request-id": request_id} if request_id else {}
    return oci.exceptions.ServiceError(status, code, headers, "refused")


@pytest.mark.parametrize(
    ("status", "code", "kind", "exit_code"),
    [
        (401, "NotAuthenticated", StoreError, ExitCode.AUTH_FAILURE),
        (404, "NotAuthorizedOrNotFound", StoreError, ExitCode.FAILURE),
        (409, "Conflict", CasConflictError, ExitCode.FAILURE),
        (409, "IncorrectState", StoreError, ExitCode.FAILURE),
        (429, "TooManyRequests", StoreError, ExitCode.FAILURE),
        (500, "InternalServerError", StoreError, ExitCode.FAILURE),
    ],
)
def test_every_service_error_keeps_the_request_id(
    status: int, code: str, kind: type[StoreError], exit_code: ExitCode
) -> None:
    with pytest.raises(kind) as error:
        raise_for(service_error(status, code), what='secret "acme-db"')

    assert f"OCI {status} {code}, opc-request-id req-1" in error.value.message
    assert error.value.exit_code == exit_code


def test_only_a_conflict_is_a_lost_compare_and_set() -> None:
    """409 IncorrectState is a secret still UPDATING, measured in #1136."""
    with pytest.raises(StoreError) as error:
        raise_for(service_error(409, "IncorrectState"), what='secret "acme-db"')

    assert not isinstance(error.value, CasConflictError)


def test_an_error_with_no_request_id_did_not_come_from_oci() -> None:
    with pytest.raises(StoreError, match="did not come from OCI") as error:
        raise_for(service_error(502, "Unknown", request_id=None), what='secret "acme-db"')

    assert error.value.category == "connectivity"


def test_a_read_that_gets_no_answer_is_a_connectivity_error(
    fake: FakeOci, monkeypatch: pytest.MonkeyPatch
) -> None:
    def no_answer(**kwargs: Any) -> None:
        raise oci.exceptions.RequestException("connection refused")

    monkeypatch.setattr(fake, "get_secret_bundle_by_name", no_answer)

    with pytest.raises(StoreError, match="connection refused") as error:
        store(fake).read("acme-db")

    assert error.value.category == "connectivity"
