"""``merge_patch: false`` on a store entry (#904).

A proxy or WAF in front of Vault can block the PATCH method and answer 401
itself. The adapter cannot tell that 401 from Vault refusing the token, so the
operator turns the merge patch off in the config, and every write takes
read-modify-write under compare-and-set.

The first tests are tier 0: they build the store and ask what it supports,
which sends nothing. The last one is tier 1 and skips without the container.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest

from sopuli.config.errors import ConfigError
from sopuli.config.model import Vault
from sopuli.config.secret_refs import parse_secret_ref
from sopuli.config.vaults import build_vaults
from sopuli.secrets import Secret
from sopuli.store.credentials import READ_MODIFY_WRITE, apply_patch, staged_patch
from sopuli.store.hashicorp._errors import StoreAuthError
from sopuli.store.protocol import (
    CAS,
    LIST,
    MERGE_PATCH,
    VERSIONING,
    PatchNotPermittedError,
    SecretStore,
    StoreError,
)

#: An address nothing listens on. Building a store opens no connection, so the
#: tier-0 tests never reach it.
NOWHERE = "http://127.0.0.1:9"


def _open(*, merge_patch: bool | None) -> SecretStore:
    # Imported here: it pulls in `httpx`, and a base install must reach the skip.
    pytest.importorskip("httpx")
    from sopuli.store.hashicorp import open_store

    vault = Vault(
        name="vault-dev", type="hashicorp", addr=NOWHERE, kv_version=2, merge_patch=merge_patch
    )
    return open_store(vault, token=Secret("not-sent"))


def test_kv2_offers_the_merge_patch_by_default() -> None:
    assert MERGE_PATCH in _open(merge_patch=None).supports()


def test_merge_patch_false_drops_only_the_merge_patch() -> None:
    assert _open(merge_patch=False).supports() == frozenset({CAS, LIST, VERSIONING})


def test_merge_patch_true_is_the_same_as_absent() -> None:
    assert _open(merge_patch=True).supports() == _open(merge_patch=None).supports()


def test_patch_refuses_without_sending_when_the_merge_patch_is_off() -> None:
    """The protocol's rule for a store without the capability. The address is one
    nothing listens on, so a request that was sent would fail differently."""
    store = _open(merge_patch=False)

    with pytest.raises(StoreError, match="cannot apply a merge patch"):
        store.patch("acme/dev/acme", {"pending": {}}, cas=1)


def _answering(status: int, body: Any) -> SecretStore:
    """A KV v2 store whose every request gets this answer, as from a proxy."""
    httpx = pytest.importorskip("httpx")
    from sopuli.store.hashicorp._transport import Transport
    from sopuli.store.hashicorp.kv2 import Kv2Store

    client = httpx.Client(
        base_url="https://vault.example.com/v1/",
        transport=httpx.MockTransport(lambda _: httpx.Response(status, json=body)),
    )
    return Kv2Store(transport=Transport(client), mount="kv")


def test_a_patch_401_not_in_vaults_format_names_merge_patch_false() -> None:
    """#905: what the WAF in #904 answered. Only here is the setting the remedy."""
    store = _answering(401, {"code": "401", "message": "Unauthorized"})

    with pytest.raises(StoreAuthError) as caught:
        store.patch("acme/dev/acme", {"pending": {}}, cas=1)

    assert "the answer was not in Vault's format" in str(caught.value)
    assert "merge_patch: false" in str(caught.value.hint)


def test_a_patch_403_falls_back_whatever_its_body() -> None:
    """Vault's own 403 on PATCH can be a policy without `patch`, so a 403 is a
    patch refusal and the caller falls back (01-configuration.md §7)."""
    store = _answering(403, {"message": "Forbidden"})

    with pytest.raises(PatchNotPermittedError):
        store.patch("acme/dev/acme", {"pending": {}}, cas=1)


def test_vaults_own_refusals_are_in_vaults_format(vault_stack: Any) -> None:
    """Tier 1. The 'not in Vault's format' message rests on this: if a Vault
    release stops sending `errors` on a refusal, this fails before operators are
    sent to look for a proxy that is not there."""
    from sopuli.store.hashicorp._errors import from_vault

    for token in ("not-a-token", ""):
        response = vault_stack.client.get(
            f"/v1/{vault_stack.kv2_mount}/data/{vault_stack.scratch}",
            headers={"X-Vault-Token": token},
        )
        assert response.status_code == 403, token
        assert from_vault(response.json()), response.text


def test_the_key_is_read_from_a_vaults_entry() -> None:
    (vault,) = build_vaults(
        {"vaults": {"vault-dev": {"type": "hashicorp", "kv_version": 2, "merge_patch": False}}}
    )

    assert vault.merge_patch is False


def test_a_value_that_is_not_a_boolean_is_refused() -> None:
    with pytest.raises(ConfigError, match="merge_patch"):
        build_vaults({"vaults": {"vault-dev": {"type": "hashicorp", "merge_patch": "no"}}})


@pytest.fixture
def blocked_store(vault_stack: Any) -> Iterator[tuple[SecretStore, str]]:
    """A real KV v2 store with the merge patch turned off, and a scratch path."""
    from sopuli.store.hashicorp import open_store

    store = open_store(
        Vault(
            name="vault-dev",
            type="hashicorp",
            addr=vault_stack.addr,
            mount=vault_stack.kv2_mount,
            kv_version=2,
            merge_patch=False,
        ),
        token=Secret(vault_stack.token),
    )
    path = f"{vault_stack.scratch}/merge-patch-off"
    yield store, path
    vault_stack.client.delete(f"/v1/{vault_stack.kv2_mount}/metadata/{path}")


def test_a_write_takes_read_modify_write_and_keeps_the_siblings(
    blocked_store: tuple[SecretStore, str],
) -> None:
    """The run reports the mechanism, and a sibling account stays as it was."""
    store, path = blocked_store
    version = store.write(
        path,
        {"DB_CREDENTIALS": {"acme_web_user": "current-one", "acme_api_user": "current-two"}},
        cas=0,
    )

    ref = parse_secret_ref(f"vault-dev:{path}#DB_CREDENTIALS/acme_web_user")
    written = apply_patch(store, path, staged_patch(ref, Secret("x")), cas=version)

    assert written.mechanism == READ_MODIFY_WRITE
    stored = store.read(path)
    assert stored is not None
    assert stored.data["DB_CREDENTIALS"]["acme_api_user"] == "current-two"
