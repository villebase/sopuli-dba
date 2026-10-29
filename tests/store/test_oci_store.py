"""The OCI store's health check and error mapping (#1132).

Tier 0, against a fake KMS vault client. What OCI sends was measured in #1136.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import oci
import pytest

from sopuli.config.model import Vault
from sopuli.store.oci import OciStore
from sopuli.store.protocol import DEGRADED, OK, UNREACHABLE, SecretStore, StoreError

VAULT_ID = "ocid1.vault.oc1..exampleuniqueid"
DATE = "Thu, 29 Oct 2026 10:15:30 GMT"


def service_error(status: int, code: str, message: str | None = "refused") -> Any:
    return oci.exceptions.ServiceError(status, code, {"opc-request-id": "req-1"}, message)


class FakeKms:
    """``KmsVaultClient.get_vault``: answers with ``reply``, or raises it."""

    def __init__(self, reply: Any) -> None:
        self.reply = reply
        self.asked: list[str] = []

    def get_vault(self, vault_id: str) -> Any:
        self.asked.append(vault_id)
        if isinstance(self.reply, Exception):
            raise self.reply
        return self.reply


def vault_reply(state: str = "ACTIVE", headers: dict[str, str] | None = None) -> Any:
    return SimpleNamespace(
        data=SimpleNamespace(lifecycle_state=state),
        headers={"date": DATE} if headers is None else headers,
    )


def ticking() -> Iterator[datetime]:
    moment = datetime(2026, 10, 29, 10, 15, 30, tzinfo=UTC)
    while True:
        yield moment
        moment += timedelta(milliseconds=200)


def store(reply: Any) -> tuple[OciStore, FakeKms]:
    kms = FakeKms(reply)
    clock = ticking()
    entry = Vault(
        name="vault-oci",
        type="oci",
        vault_id=VAULT_ID,
        compartment_id="ocid1.compartment.oc1..exampleuniqueid",
    )
    return OciStore(entry, vaults=None, secrets=None, kms=kms, now=lambda: next(clock)), kms


def test_it_is_a_secret_store() -> None:
    oci_store, _ = store(vault_reply())
    assert isinstance(oci_store, SecretStore)


def test_an_active_vault_is_ok_with_the_servers_clock() -> None:
    oci_store, kms = store(vault_reply())

    health = oci_store.health()

    assert kms.asked == [VAULT_ID]
    assert (health.status, health.detail, health.authenticated) == (OK, None, True)
    assert health.server_time == datetime(2026, 10, 29, 10, 15, 30, tzinfo=UTC)
    assert health.time_resolution == timedelta(seconds=1)
    assert health.round_trip == timedelta(milliseconds=200)
    assert health.measured_at == datetime(2026, 10, 29, 10, 15, 30, 100000, tzinfo=UTC)


def test_a_vault_that_is_not_active_is_degraded() -> None:
    oci_store, _ = store(vault_reply("PENDING_DELETION"))

    health = oci_store.health()

    assert (health.status, health.detail) == (DEGRADED, "the vault is PENDING_DELETION")


def test_no_date_header_is_no_server_time() -> None:
    """Never this host's clock in its place (`StoreHealth`)."""
    oci_store, _ = store(vault_reply(headers={}))

    assert oci_store.health().server_time is None


def test_a_refused_signature_is_degraded_and_unauthenticated() -> None:
    oci_store, _ = store(service_error(401, "NotAuthenticated"))

    health = oci_store.health()

    assert (health.status, health.authenticated) == (DEGRADED, False)
    assert health.detail is not None
    assert "OCI 401 NotAuthenticated, opc-request-id req-1" in health.detail


def test_a_wrong_vault_id_is_degraded_never_ok() -> None:
    """OCI cannot say whether the vault is missing or hidden, so neither can we."""
    oci_store, _ = store(service_error(404, "NotAuthorizedOrNotFound"))

    health = oci_store.health()

    assert (health.status, health.authenticated) == (DEGRADED, None)
    assert health.detail is not None
    assert "404 NotAuthorizedOrNotFound" in health.detail


def test_no_answer_is_unreachable() -> None:
    oci_store, _ = store(oci.exceptions.RequestException("connection refused"))

    health = oci_store.health()

    assert health.status == UNREACHABLE
    assert health.detail is not None
    assert "connection refused" in health.detail


def test_metadata_is_refused_until_it_is_built() -> None:
    """Never an empty answer, which the lock would read as an untouched path."""
    oci_store, _ = store(vault_reply())

    with pytest.raises(StoreError, match="not built"):
        oci_store.metadata("locks/acme-db")


def test_a_reply_without_a_request_id_did_not_come_from_oci() -> None:
    """A proxy's 502: no evidence about the store, so unreachable, not degraded."""
    oci_store, _ = store(oci.exceptions.ServiceError(502, None, {}, None))

    health = oci_store.health()

    assert (health.status, health.detail) == (
        UNREACHABLE,
        "answered HTTP 502, which did not come from OCI",
    )


def test_an_error_with_no_message_still_reads() -> None:
    oci_store, _ = store(service_error(403, "Forbidden", message=None))

    assert oci_store.health().detail == "refused (OCI 403 Forbidden, opc-request-id req-1)"


def test_a_date_in_unknown_zone_is_utc() -> None:
    """`-0000` parses as naive; it must not be read as this host's local time."""
    oci_store, _ = store(vault_reply(headers={"date": "Thu, 29 Oct 2026 10:15:30 -0000"}))

    assert oci_store.health().server_time == datetime(2026, 10, 29, 10, 15, 30, tzinfo=UTC)
