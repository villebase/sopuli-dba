"""A fake of the OCI SDK's secrets, vaults and KMS clients, for tier 0.

Its answers are the ones measured against OCI Vault in #1136 and #1151 (the
``oci-*`` entries in ``docs/README.md``):

* a read with no stage returns CURRENT, and PENDING only when asked for;
* a missing secret, version or vault is ``404 NotAuthorizedOrNotFound``;
* every answer carries an ``opc-request-id``;
* ``ListSecrets`` pages, and lists secrets that are being deleted;
* a write leaves the secret ``CREATING`` or ``UPDATING`` for a while, and a
  write meanwhile is ``409 IncorrectState``;
* a stale ``if_match`` is ``409 Conflict``, and a taken name is
  ``400 InvalidParameter``;
* the metadata an update sends replaces the whole map.

:meth:`FakeOci.put` seeds a secret as an operator would leave it. "A while" is
:attr:`FakeOci.settle_polls` reads of ``GetSecret``, so a test needs no clock.
"""

from __future__ import annotations

import base64
import json
from collections.abc import Callable
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any

import oci

VAULT_ID = "ocid1.vault.oc1..exampleuniqueid"
COMPARTMENT_ID = "ocid1.compartment.oc1..exampleuniqueid"
KEY_ID = "ocid1.key.oc1..exampleuniqueid"


def _raw(content: Any) -> bytes:
    if isinstance(content, bytes):
        return content
    text = content if isinstance(content, str) else json.dumps(content)
    return text.encode("utf-8")


def not_found(message: str) -> Any:
    return oci.exceptions.ServiceError(
        404, "NotAuthorizedOrNotFound", {"opc-request-id": "req-404"}, message
    )


def refused(status: int, code: str, message: str) -> Any:
    return oci.exceptions.ServiceError(status, code, {"opc-request-id": f"req-{status}"}, message)


#: How many versions a secret holds, not counting those scheduled for
#: deletion (#1136, M7 and M7c).
VERSION_LIMIT = 30


@dataclass
class FakeVersion:
    number: int
    content: bytes
    stages: set[str]
    time_of_deletion: Any = None


@dataclass
class FakeSecret:
    name: str
    versions: list[FakeVersion] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    lifecycle_state: str = "ACTIVE"
    #: Reads of ``GetSecret`` that still find the secret busy.
    busy: int = 0
    etag: int = 1

    @property
    def id(self) -> str:
        return f"ocid1.vaultsecret.oc1..{self.name}"

    def version(self, number: int) -> FakeVersion:
        for one in self.versions:
            if one.number == number:
                return one
        raise not_found(f"version {number} of {self.name} not found")

    def counted(self) -> int:
        return sum(1 for one in self.versions if one.time_of_deletion is None)

    def add(self, content: bytes, *, stage: str) -> None:
        """A new version. A new PENDING deprecates the old one (M6). A 31st
        counted version is refused (M7)."""
        if self.counted() >= VERSION_LIMIT:
            raise refused(400, "LimitExceeded", "The limit for this tenancy has been exceeded.")
        for one in self.versions:
            one.stages.discard("LATEST")
            if stage == "PENDING" and "PENDING" in one.stages:
                one.stages = {"DEPRECATED"}
        number = len(self.versions) + 1
        self.versions.append(FakeVersion(number=number, content=content, stages={"LATEST"}))
        if stage == "PENDING":
            self.versions[-1].stages.add("PENDING")
        else:
            self.promote(number)

    def promote(self, number: int) -> None:
        """Make ``number`` CURRENT: the old CURRENT becomes PREVIOUS, and the
        old PREVIOUS DEPRECATED (M5)."""
        chosen = self.version(number)
        if "CURRENT" in chosen.stages:
            return
        for one in self.versions:
            if "PREVIOUS" in one.stages and one is not chosen:
                one.stages = (one.stages - {"PREVIOUS"}) | {"DEPRECATED"}
        for one in self.versions:
            if "CURRENT" in one.stages:
                one.stages = (one.stages - {"CURRENT"}) | {"PREVIOUS"}
        chosen.stages = (chosen.stages & {"LATEST"}) | {"CURRENT"}


class FakeOci:
    """The three clients at once: pass it as ``vaults``, ``secrets`` and ``kms``."""

    def __init__(self, *, page_size: int = 2, settle_polls: int = 2) -> None:
        self.secrets: dict[str, FakeSecret] = {}
        self.page_size = page_size
        self.vault_id = VAULT_ID
        self.calls: list[str] = []
        #: Secrets this principal may list and not read: OCI answers their
        #: content reads with the same 404 as a missing secret.
        self.unreadable: set[str] = set()
        #: How many ``GetSecret`` reads find a secret busy after a write, and
        #: the state it settles in.
        self.settle_polls = settle_polls
        self.final_state = "ACTIVE"
        #: Every ``CreateSecret`` and ``UpdateSecret`` sent, refused or not.
        self.created: list[Any] = []
        self.updates: list[tuple[str, Any, str | None]] = []
        #: Called before each write is applied, so a test can play another
        #: writer: with the secret for an update, with the name for a create.
        self.before_update: Callable[[FakeSecret], object] | None = None
        self.before_create: Callable[[str], object] | None = None
        #: Called before each ``GetSecret``, so a test can make one fail.
        self.before_get: Callable[[FakeSecret], object] | None = None

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

    def _by_id(self, secret_id: str) -> FakeSecret:
        for secret in self.secrets.values():
            if secret.id == secret_id:
                return secret
        raise not_found(f"secret {secret_id} not found")

    def _busy(self, secret: FakeSecret, state: str) -> None:
        secret.busy = self.settle_polls
        secret.lifecycle_state = state if secret.busy else "ACTIVE"

    @staticmethod
    def _data(secret: FakeSecret) -> Any:
        return SimpleNamespace(
            id=secret.id,
            secret_name=secret.name,
            lifecycle_state=secret.lifecycle_state,
            metadata=dict(secret.metadata) or None,
            current_version_number=next(
                (one.number for one in secret.versions if "CURRENT" in one.stages), None
            ),
        )

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
                secret_id=secret.id,
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
                SimpleNamespace(
                    id=one.id, secret_name=one.name, lifecycle_state=one.lifecycle_state
                )
                for one in chunk
            ],
            next_page=str(start + self.page_size) if more else None,
        )

    def get_secret(self, secret_id: str) -> Any:
        """The secret, with its ETag. Each read of a busy secret counts down."""
        self.calls.append("get_secret")
        secret = self._by_id(secret_id)
        if self.before_get is not None:
            self.before_get(secret)
        data = self._data(secret)
        if secret.busy:
            secret.busy -= 1
            if not secret.busy:
                secret.lifecycle_state = self.final_state
        return SimpleNamespace(data=data, headers={"etag": str(secret.etag)})

    def create_secret(self, create_secret_details: Any) -> Any:
        details = create_secret_details
        self.calls.append("create_secret")
        self.created.append(details)
        if self.before_create is not None:
            self.before_create(details.secret_name)
        if details.vault_id != self.vault_id:
            raise not_found(f"vault {details.vault_id} not found")
        if details.secret_name in self.secrets:
            raise refused(400, "InvalidParameter", "name already exists")
        content = details.secret_content
        if (content.stage or "CURRENT") != "CURRENT":
            raise refused(400, "InvalidParameter", "stage must be one of CURRENT.")
        secret = FakeSecret(name=details.secret_name, metadata=dict(details.metadata or {}))
        secret.add(base64.b64decode(content.content), stage="CURRENT")
        self._busy(secret, "CREATING")
        self.secrets[secret.name] = secret
        return SimpleNamespace(data=self._data(secret), headers={"etag": str(secret.etag)})

    def update_secret(
        self, secret_id: str, update_secret_details: Any, if_match: str | None = None
    ) -> Any:
        details = update_secret_details
        self.calls.append("update_secret")
        self.updates.append((secret_id, details, if_match))
        secret = self._by_id(secret_id)
        if self.before_update is not None:
            self.before_update(secret)
        if secret.lifecycle_state != "ACTIVE":
            raise refused(
                409,
                "IncorrectState",
                f"The existing Secret has a conflicting state of {secret.lifecycle_state}.",
            )
        if if_match is not None and if_match != str(secret.etag):
            raise refused(409, "Conflict", "The resource has been modified")
        if details.secret_content is not None:
            content = details.secret_content
            secret.add(base64.b64decode(content.content), stage=content.stage or "CURRENT")
        if details.current_version_number is not None:
            secret.promote(details.current_version_number)
        if details.metadata is not None:
            secret.metadata = dict(details.metadata)
        secret.etag += 1
        self._busy(secret, "UPDATING")
        return SimpleNamespace(data=self._data(secret), headers={"etag": str(secret.etag)})

    def get_secret_version(self, secret_id: str, secret_version_number: int) -> Any:
        self.calls.append("get_secret_version")
        version = self._by_id(secret_id).version(secret_version_number)
        return SimpleNamespace(
            data=SimpleNamespace(
                version_number=version.number,
                stages=sorted(version.stages),
                time_of_deletion=version.time_of_deletion,
            )
        )

    def list_secret_versions(self, secret_id: str, page: str | None = None) -> Any:
        self.calls.append("list_secret_versions")
        everything = self._by_id(secret_id).versions
        start = int(page or 0)
        chunk = everything[start : start + self.page_size]
        more = start + self.page_size < len(everything)
        return SimpleNamespace(
            data=[
                SimpleNamespace(
                    version_number=one.number,
                    stages=sorted(one.stages),
                    time_of_deletion=one.time_of_deletion,
                )
                for one in chunk
            ],
            next_page=str(start + self.page_size) if more else None,
        )

    def schedule_secret_version_deletion(
        self,
        secret_id: str,
        secret_version_number: int,
        schedule_secret_version_deletion_details: Any,
    ) -> Any:
        """Only a DEPRECATED version may go (M6), and the secret is then busy
        for a while (M11)."""
        self.calls.append("schedule_secret_version_deletion")
        secret = self._by_id(secret_id)
        version = secret.version(secret_version_number)
        if secret.lifecycle_state != "ACTIVE" or version.stages - {"LATEST"} != {"DEPRECATED"}:
            raise refused(409, "IncorrectState", "The version is in a conflicting state.")
        version.time_of_deletion = schedule_secret_version_deletion_details.time_of_deletion
        secret.etag += 1
        self._busy(secret, "UPDATING")
        return SimpleNamespace(data=None, headers={})

    # -- KmsVaultClient -----------------------------------------------------

    def get_vault(self, vault_id: str) -> Any:
        self.calls.append("get_vault")
        if vault_id != VAULT_ID:
            raise not_found(f"vault {vault_id} not found")
        return SimpleNamespace(data=SimpleNamespace(lifecycle_state="ACTIVE"), headers={})
