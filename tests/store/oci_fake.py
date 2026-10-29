"""A fake of the OCI SDK's secrets, vaults and KMS clients, for tier 0.

Its answers are the ones measured against OCI Vault in #1136 (the ``oci-*``
entries in ``docs/README.md``):

* a read with no stage returns CURRENT, and PENDING only when asked for;
* a missing secret, version or vault is ``404 NotAuthorizedOrNotFound``;
* every answer carries an ``opc-request-id``;
* ``ListSecrets`` pages, and lists secrets that are being deleted.

It holds secrets as an operator would leave them: :meth:`FakeOci.put` seeds
one. Writing through the store comes with #1133.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any

import oci

VAULT_ID = "ocid1.vault.oc1..exampleuniqueid"
COMPARTMENT_ID = "ocid1.compartment.oc1..exampleuniqueid"


def _raw(content: Any) -> bytes:
    if isinstance(content, bytes):
        return content
    text = content if isinstance(content, str) else json.dumps(content)
    return text.encode("utf-8")


def not_found(message: str) -> Any:
    return oci.exceptions.ServiceError(
        404, "NotAuthorizedOrNotFound", {"opc-request-id": "req-404"}, message
    )


@dataclass
class FakeVersion:
    number: int
    content: bytes
    stages: set[str]


@dataclass
class FakeSecret:
    name: str
    versions: list[FakeVersion] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    lifecycle_state: str = "ACTIVE"


class FakeOci:
    """The three clients at once: pass it as ``vaults``, ``secrets`` and ``kms``."""

    def __init__(self, *, page_size: int = 2) -> None:
        self.secrets: dict[str, FakeSecret] = {}
        self.page_size = page_size
        self.vault_id = VAULT_ID
        self.calls: list[str] = []
        #: Secrets this principal may list and not read: OCI answers their
        #: content reads with the same 404 as a missing secret.
        self.unreadable: set[str] = set()

    def put(
        self,
        name: str,
        *contents: Any,
        stages: list[set[str]] | None = None,
        metadata: dict[str, Any] | None = None,
        lifecycle_state: str = "ACTIVE",
    ) -> FakeSecret:
        """Seed a secret. Each content is a version: bytes as they are, a
        string as UTF-8, and anything else as JSON.

        Without ``stages``, the last version is CURRENT, the one before it
        PREVIOUS, and the rest DEPRECATED, as OCI leaves them after updates.
        """
        count = len(contents)
        if stages is None:
            stages = [
                {"CURRENT", "LATEST"}
                if number == count
                else {"PREVIOUS"}
                if number == count - 1
                else {"DEPRECATED"}
                for number in range(1, count + 1)
            ]
        secret = FakeSecret(
            name=name,
            versions=[
                FakeVersion(
                    number=number,
                    content=_raw(one),
                    stages=set(stage),
                )
                for number, (one, stage) in enumerate(zip(contents, stages, strict=True), 1)
            ],
            metadata=dict(metadata or {}),
            lifecycle_state=lifecycle_state,
        )
        self.secrets[name] = secret
        return secret

    # -- SecretsClient ------------------------------------------------------

    def get_secret_bundle_by_name(
        self,
        secret_name: str,
        vault_id: str,
        stage: str | None = None,
        version_number: int | None = None,
    ) -> Any:
        self.calls.append("get_secret_bundle_by_name")
        secret = self.secrets.get(secret_name)
        if vault_id != self.vault_id or secret is None or secret_name in self.unreadable:
            raise not_found(f"secret {secret_name} not found")
        if version_number is not None:
            found = [one for one in secret.versions if one.number == version_number]
        else:
            wanted = stage or "CURRENT"
            found = [one for one in secret.versions if wanted in one.stages]
        if not found:
            raise not_found(f"no such version of {secret_name}")
        version = found[0]
        return SimpleNamespace(
            data=SimpleNamespace(
                secret_bundle_content=SimpleNamespace(
                    content_type="BASE64",
                    content=base64.b64encode(version.content).decode("ascii"),
                ),
                stages=sorted(version.stages),
                version_number=version.number,
                metadata=dict(secret.metadata) or None,
            )
        )

    # -- VaultsClient -------------------------------------------------------

    def list_secrets(
        self,
        compartment_id: str,
        vault_id: str | None = None,
        page: str | None = None,
        name: str | None = None,
    ) -> Any:
        self.calls.append("list_secrets")
        everything = (
            sorted(self.secrets.values(), key=lambda one: one.name)
            if compartment_id == COMPARTMENT_ID and vault_id == self.vault_id
            else []
        )
        if name is not None:
            everything = [one for one in everything if one.name == name]
        start = int(page or 0)
        chunk = everything[start : start + self.page_size]
        more = start + self.page_size < len(everything)
        return SimpleNamespace(
            data=[
                SimpleNamespace(secret_name=one.name, lifecycle_state=one.lifecycle_state)
                for one in chunk
            ],
            next_page=str(start + self.page_size) if more else None,
        )

    # -- KmsVaultClient -----------------------------------------------------

    def get_vault(self, vault_id: str) -> Any:
        self.calls.append("get_vault")
        if vault_id != VAULT_ID:
            raise not_found(f"vault {vault_id} not found")
        return SimpleNamespace(data=SimpleNamespace(lifecycle_state="ACTIVE"), headers={})
