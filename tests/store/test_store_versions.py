"""``SecretStore.versions``, per backend, for UC-5's history report.

`test_store_conformance.py` holds the memory store and KV v2 to the same
answers. This module covers what only one backend has: KV v2's answer shapes,
pruning by ``max_versions`` on a real Vault, KV v1's ``None``, the memory
store's native staging, OCI's version list, and the native-staging adapter.

The KV v2 shapes are the ones Vault 2.0.4 answered when this was written:
``oldest_version`` reads 0 until a version is pruned, a deleted version has a
``deletion_time``, and a destroyed one has ``destroyed: true``.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from oci_fake import COMPARTMENT_ID, FIRST_CREATED, KEY_ID, VAULT_ID, FakeOci

from sopuli.config.model import Vault
from sopuli.secrets import Secret
from sopuli.store import MemoryStore
from sopuli.store.hashicorp._transport import Response
from sopuli.store.hashicorp.kv1 import Kv1Store
from sopuli.store.hashicorp.kv2 import Kv2Store
from sopuli.store.native_view import LayoutUnknownError, NativeStagedStore
from sopuli.store.oci import OciStore
from sopuli.store.protocol import (
    CAS,
    LIST,
    MERGE_PATCH,
    STAGING,
    VERSIONING,
    StoreError,
    VersionHistory,
    VersionInfo,
)


class _Transport:
    """Answers one request with one response, and records what was asked."""

    def __init__(self, response: Response) -> None:
        self.response = response
        self.asked: list[tuple[str, str]] = []

    def request(self, method: str, path: str, **_: Any) -> Response:
        self.asked.append((method, path))
        return self.response


def _version(created: str, *, deleted: str = "", destroyed: bool = False) -> dict[str, Any]:
    return {
        "created_by": {"actor": "token", "operation": "update"},
        "created_time": created,
        "deleted_by": None,
        "deletion_time": deleted,
        "destroyed": destroyed,
    }


# ---------------------------------------------------------------- KV v2 ---


def test_kv2_reads_the_metadata_endpoint_and_lists_oldest_first() -> None:
    body = {
        "data": {
            "current_version": 4,
            "oldest_version": 3,
            "max_versions": 2,
            "versions": {
                "4": _version(
                    "2026-11-07T22:17:44.859488832Z", deleted="2026-11-07T22:17:45.062272888Z"
                ),
                "3": _version("2026-11-07T22:17:44.606133686Z", destroyed=True),
            },
        }
    }
    transport = _Transport(Response(status=200, body=body))

    history = Kv2Store(transport=transport, mount="kv").versions("acme/dev/acme")  # type: ignore[arg-type]

    assert transport.asked == [("GET", "kv/metadata/acme/dev/acme")]
    assert history == VersionHistory(
        current=4,
        oldest_kept=3,
        versions=(
            VersionInfo(
                version=3,
                created_at=datetime(2026, 11, 7, 22, 17, 44, 606133, tzinfo=UTC),
                deleted=False,
                destroyed=True,
            ),
            VersionInfo(
                version=4,
                created_at=datetime(2026, 11, 7, 22, 17, 44, 859488, tzinfo=UTC),
                deleted=True,
                destroyed=False,
            ),
        ),
    )


def test_kv2_takes_the_oldest_kept_from_the_list_not_oldest_version() -> None:
    """Vault reports `oldest_version: 0` until it prunes, with version 1 there."""
    body = {
        "data": {
            "current_version": 2,
            "oldest_version": 0,
            "versions": {
                "1": _version("2026-11-07T22:17:44.469128085Z"),
                "2": _version("2026-11-07T22:17:44.541278794Z"),
            },
        }
    }
    history = Kv2Store(transport=_Transport(Response(200, body)), mount="kv").versions("p")  # type: ignore[arg-type]

    assert history is not None
    assert history.oldest_kept == 1


def test_kv2_a_path_with_no_metadata_is_none() -> None:
    transport = _Transport(Response(status=404, body={"errors": []}))
    assert Kv2Store(transport=transport, mount="kv").versions("p") is None  # type: ignore[arg-type]


def test_kv2_a_deletion_time_still_ahead_is_not_a_deletion() -> None:
    """`delete_version_after`, which `vault_path` delivery sets, gives every
    live version a deletion time in the future."""
    body = {
        "data": {
            "current_version": 1,
            "versions": {"1": _version("2026-11-07T22:17:44Z", deleted="2999-01-01T00:00:00Z")},
        }
    }
    history = Kv2Store(transport=_Transport(Response(200, body)), mount="kv").versions("p")  # type: ignore[arg-type]

    assert history is not None
    assert history.versions[0].deleted is False


@pytest.mark.parametrize(
    "versions",
    [
        {"one": _version("2026-11-07T22:17:44Z")},
        {"1": _version("2026-11-07T22:17:44Z", deleted="yesterday")},
    ],
    ids=["key-not-a-number", "deletion-time-not-a-time"],
)
def test_kv2_an_answer_it_cannot_read_raises(versions: dict[str, Any]) -> None:
    body = {"data": {"current_version": 1, "versions": versions}}
    with pytest.raises(StoreError, match="cannot be read"):
        Kv2Store(transport=_Transport(Response(200, body)), mount="kv").versions("p")  # type: ignore[arg-type]


def test_kv2_an_unreadable_time_is_none_not_a_failure() -> None:
    body = {"data": {"current_version": 1, "versions": {"1": _version("not a time")}}}
    history = Kv2Store(transport=_Transport(Response(200, body)), mount="kv").versions("p")  # type: ignore[arg-type]

    assert history is not None
    assert history.versions[0].created_at is None


def test_kv2_a_refused_read_raises() -> None:
    transport = _Transport(Response(status=403, body={"errors": ["permission denied"]}))
    with pytest.raises(StoreError):
        Kv2Store(transport=transport, mount="kv").versions("p")  # type: ignore[arg-type]


# ---------------------------------------------------------------- KV v1 ---


def test_kv1_keeps_no_versions_and_asks_nothing() -> None:
    transport = _Transport(Response(status=500, body=None))
    store = Kv1Store(transport=transport, mount="kv1")  # type: ignore[arg-type]

    assert store.versions("acme/dev/acme") is None
    assert transport.asked == []
    assert VERSIONING not in store.supports()


# --------------------------------------------------------------- memory ---


def test_memory_without_versioning_is_none() -> None:
    store = MemoryStore(capabilities=frozenset({CAS, LIST, MERGE_PATCH}))
    store.write("p", {"n": 1}, cas=0)
    assert store.versions("p") is None


def test_memory_stamps_each_version_with_its_own_clock() -> None:
    times = iter(datetime(2026, 11, 1, 3, minute, tzinfo=UTC) for minute in range(10))
    store = MemoryStore(clock=lambda: next(times))
    store.write("p", {"n": 1}, cas=0)
    store.write("p", {"n": 2}, cas=1)

    history = store.versions("p")

    assert history is not None
    assert [info.created_at for info in history.versions] == [
        datetime(2026, 11, 1, 3, 0, tzinfo=UTC),
        datetime(2026, 11, 1, 3, 1, tzinfo=UTC),
    ]


def test_memory_native_staging_lists_generations_not_tokens() -> None:
    """A promotion moves the compare-and-set token and makes no generation."""
    store = MemoryStore(capabilities=frozenset({CAS, LIST, VERSIONING, STAGING}))
    token = store.write("p", {"password": "a"}, cas=0)
    token = store.stage("p", {"password": "b"}, attributes={}, cas=token)
    store.promote("p", 2, attributes={}, cas=token)

    history = store.versions("p")

    assert history is not None
    assert history.current == 2
    assert [info.version for info in history.versions] == [1, 2]


# ------------------------------------------------------------------ OCI ---


@pytest.fixture
def fake() -> FakeOci:
    return FakeOci()


@pytest.fixture
def oci_store(fake: FakeOci) -> OciStore:
    entry = Vault(
        name="vault-oci",
        type="oci",
        vault_id=VAULT_ID,
        compartment_id=COMPARTMENT_ID,
        key_id=KEY_ID,
    )
    return OciStore(
        entry, vaults=fake, secrets=fake, kms=fake, sleep=lambda _: None, monotonic=lambda: 0.0
    )


def test_oci_lists_every_version_with_its_time(oci_store: OciStore, fake: FakeOci) -> None:
    """Version 1's deletion time has passed; version 2's, as the tool schedules
    one two days ahead, has not, so version 2 is still there."""
    secret = fake.put("acme-db", {"password": "a"}, {"password": "b"}, {"password": "c"})
    secret.versions[0].time_of_deletion = datetime(2020, 1, 1, tzinfo=UTC)
    secret.versions[1].time_of_deletion = datetime(2999, 1, 1, tzinfo=UTC)

    history = oci_store.versions("acme-db")

    assert history == VersionHistory(
        current=3,
        oldest_kept=1,
        versions=tuple(
            VersionInfo(
                version=number,
                created_at=FIRST_CREATED + timedelta(minutes=number - 1),
                deleted=number == 1,
                destroyed=False,
            )
            for number in (1, 2, 3)
        ),
    )


def test_oci_pages_through_the_version_list(oci_store: OciStore, fake: FakeOci) -> None:
    fake.page_size = 2
    fake.put("acme-db", *({"password": str(n)} for n in range(5)))

    history = oci_store.versions("acme-db")

    assert history is not None
    assert [info.version for info in history.versions] == [1, 2, 3, 4, 5]


def test_oci_current_is_the_latest_version_even_when_it_is_pending(
    oci_store: OciStore, fake: FakeOci
) -> None:
    token = oci_store.write("acme-db", {"password": "a"}, cas=0)
    oci_store.stage("acme-db", {"password": "b"}, attributes={}, cas=token)

    history = oci_store.versions("acme-db")

    assert history is not None
    assert history.current == 2


def test_oci_a_missing_secret_is_none(oci_store: OciStore) -> None:
    assert oci_store.versions("acme-none") is None


def test_oci_a_secret_being_deleted_is_none(oci_store: OciStore, fake: FakeOci) -> None:
    fake.put("acme-db", {"password": "a"}, lifecycle_state="PENDING_DELETION")
    assert oci_store.versions("acme-db") is None


def test_oci_a_busy_secret_is_listed_without_waiting(oci_store: OciStore, fake: FakeOci) -> None:
    """A write waits for ACTIVE and needs the ETag; a listing needs neither."""
    fake.put("acme-db", {"password": "a"}, lifecycle_state="UPDATING")
    fake.calls.clear()

    history = oci_store.versions("acme-db")

    assert history is not None
    assert "get_secret" not in fake.calls


def test_oci_an_unreadable_deletion_time_raises(oci_store: OciStore, fake: FakeOci) -> None:
    secret = fake.put("acme-db", {"password": "a"})
    secret.versions[0].time_of_deletion = "soon"
    with pytest.raises(StoreError, match="not one"):
        oci_store.versions("acme-db")


# ------------------------------------------------------- native staging ---


def test_the_native_staging_adapter_passes_versions_through() -> None:
    inner = MemoryStore(capabilities=frozenset({CAS, LIST, VERSIONING, STAGING}))
    inner.write("p", {"password": "a"}, cas=0)
    view = NativeStagedStore(
        inner, native=lambda path: None, by="test", now=lambda: datetime(2026, 11, 1, tzinfo=UTC)
    )

    assert view.versions("p") == inner.versions("p")


def test_the_native_staging_adapter_refuses_a_path_whose_layout_is_unsure() -> None:
    inner = MemoryStore(capabilities=frozenset({CAS, LIST, VERSIONING, STAGING}))
    inner.write("p", {"password": "a"}, cas=0)
    view = NativeStagedStore(
        inner,
        native=lambda path: None,
        by="test",
        now=lambda: datetime(2026, 11, 1, tzinfo=UTC),
        unsure=lambda path: True,
    )

    with pytest.raises(LayoutUnknownError):
        view.versions("p")


def test_memory_native_staging_after_a_delete_is_none() -> None:
    """OCI answers nothing for a secret being deleted, and the fake agrees."""
    store = MemoryStore(capabilities=frozenset({CAS, LIST, VERSIONING, STAGING}))
    store.write("p", {"password": "a"}, cas=0)
    store.delete("p")

    assert store.versions("p") is None


# ------------------------------------------------------- Vault, tier 1 ---


@pytest.fixture
def kv2(vault_stack: Any) -> Iterator[tuple[Any, Any]]:
    """A KV v2 store on the stack's Vault, with its scratch path wiped."""
    from sopuli.store.hashicorp import open_store

    path = f"{vault_stack.kv2_mount}/metadata/{vault_stack.scratch}"
    vault_stack.client.delete(f"/v1/{path}")
    store = open_store(
        Vault(
            name="vault-dev",
            type="hashicorp",
            addr=vault_stack.addr,
            mount=vault_stack.kv2_mount,
            kv_version=2,
        ),
        token=Secret(vault_stack.token),
    )
    yield store, vault_stack
    vault_stack.client.delete(f"/v1/{path}")


def test_vault_pruning_moves_the_oldest_kept_version(kv2: tuple[Any, Any]) -> None:
    """Three versions, then `max_versions: 2` and a fourth write: versions 1
    and 2 are gone, `current` stays the counter, and `oldest_kept` is 3."""
    store, stack = kv2
    for n in (1, 2, 3):
        store.write(stack.scratch, {"n": n}, cas=n - 1)
    before = store.versions(stack.scratch)
    stack.client.post(
        f"/v1/{stack.kv2_mount}/metadata/{stack.scratch}", json={"max_versions": 2}
    ).raise_for_status()
    store.write(stack.scratch, {"n": 4}, cas=3)

    after = store.versions(stack.scratch)

    assert before is not None
    assert (before.current, before.oldest_kept) == (3, 1)
    assert after is not None
    assert (after.current, after.oldest_kept) == (4, 3)
    assert [info.version for info in after.versions] == [3, 4]


def test_vault_a_destroyed_version_is_marked(kv2: tuple[Any, Any]) -> None:
    store, stack = kv2
    store.write(stack.scratch, {"n": 1}, cas=0)
    store.write(stack.scratch, {"n": 2}, cas=1)
    stack.client.post(
        f"/v1/{stack.kv2_mount}/destroy/{stack.scratch}", json={"versions": [1]}
    ).raise_for_status()

    history = store.versions(stack.scratch)

    assert history is not None
    assert [(info.version, info.destroyed) for info in history.versions] == [(1, True), (2, False)]
