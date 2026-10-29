"""P2's store interface over one OCI vault.

This build connects, answers :meth:`OciStore.health`, reads and lists.
Writing comes in #1133, and until then each write refuses with a
:class:`StoreError`.

Content is read with ``GetSecretBundleByName``, the call External Secrets
Operator makes, so the tool reads exactly what an application would. One call
returns the content, the version's stages and number, and the secret's
metadata, which holds the write counter (:data:`._names.CAS_KEY`).
"""

from __future__ import annotations

import base64
import binascii
import json
from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime
from types import MappingProxyType
from typing import Any, NoReturn

import oci

from sopuli.clock import utc_now
from sopuli.config.model import Vault
from sopuli.exit_codes import ExitCode
from sopuli.store.oci import _errors, _names
from sopuli.store.protocol import (
    DEGRADED,
    LIST,
    OK,
    STAGES,
    UNREACHABLE,
    VERSIONING,
    PathMetadata,
    Stored,
    StoreError,
    StoreHealth,
    bounded_prefix,
)

#: The stage a read with no stage returns, in OCI's spelling.
CURRENT = "CURRENT"

#: Lifecycle states of a secret on its way out. OCI keeps a deleted secret for
#: up to 30 days, and none of these can be read or written.
GONE = frozenset({"DELETING", "DELETED", "SCHEDULING_DELETION", "PENDING_DELETION"})

#: OCI's ``Date`` header has whole seconds, so a finer skew would be noise.
RESOLUTION = timedelta(seconds=1)

#: A vault that can serve requests.
ACTIVE = "ACTIVE"

#: The errors a request raises when no answer came back at all.
NO_ANSWER = (oci.exceptions.RequestException, oci.exceptions.ConnectTimeout)


class OciStore:
    """One ``vaults:`` entry of ``type: oci``.

    ``vaults``, ``secrets`` and ``kms`` are the SDK clients
    (:class:`sopuli.store.oci._auth.Clients`). They are passed in, so tier 0
    can pass fakes.
    """

    def __init__(
        self,
        vault: Vault,
        *,
        vaults: Any,
        secrets: Any,
        kms: Any,
        now: Callable[[], datetime] = utc_now,
    ) -> None:
        if vault.vault_id is None or vault.compartment_id is None:
            # Unreachable through a config file, which requires both keys.
            raise StoreError(f'vault "{vault.name}" needs a vault_id and a compartment_id')
        self._name = vault.name
        self._vault_id = vault.vault_id
        self._compartment_id = vault.compartment_id
        self._vault_seen = False
        self._vaults = vaults
        self._secrets = secrets
        self._kms = kms
        self._now = now

    def supports(self) -> frozenset[str]:
        """What works in this build. Each capability arrives with its methods:
        ``cas`` and ``staging_labels`` with the writes (#1133)."""
        return frozenset({LIST, VERSIONING})

    def health(self) -> StoreHealth:
        """One read-only ``GetVault``, which proves the auth, region and vault id.

        It never raises: a store that cannot be reached is the answer.
        """
        sent = self._now()
        try:
            response = self._kms.get_vault(self._vault_id)
        except oci.exceptions.ServiceError as exc:
            if not exc.request_id:
                # OCI sends an opc-request-id with every answer. A reply without
                # one came from something in between, such as a proxy's 502, and
                # is not evidence about the store: fail closed, as
                # `UNREACHABLE` says.
                return StoreHealth(
                    status=UNREACHABLE,
                    detail=f"answered HTTP {exc.status}, which did not come from OCI",
                )
            return StoreHealth(
                status=DEGRADED,
                detail=f"{exc.message or 'refused'} ({_errors.describe(exc)})",
                authenticated=False if exc.status == 401 else None,
            )
        except NO_ANSWER as exc:
            return StoreHealth(status=UNREACHABLE, detail=f"OCI did not answer: {exc}")
        received = self._now()

        state = response.data.lifecycle_state
        return StoreHealth(
            status=OK if state == ACTIVE else DEGRADED,
            detail=None if state == ACTIVE else f"the vault is {state}",
            server_time=_server_time(response.headers),
            time_resolution=RESOLUTION,
            measured_at=sent + (received - sent) / 2,
            round_trip=received - sent,
            authenticated=True,
        )

    def read(self, path: str, *, version: int | None = None) -> Stored | None:
        """The CURRENT version, or the version numbered ``version``.

        ``version`` is OCI's own version number, C14's ``@version=N``. A pinned
        read of a version that is not CURRENT carries the token 0, as
        :class:`~sopuli.store.memory.MemoryStore` does: content derived from an
        old version must not replace CURRENT.
        """
        if version is None:
            return self._bundle(path, stage=CURRENT)
        return self._bundle(path, version_number=version)

    def read_stage(self, path: str, stage: str) -> Stored | None:
        """The version in ``stage``, one of :data:`STAGES`, or ``None``."""
        if stage not in STAGES:
            raise StoreError(f"{stage!r} is not a stage; the stages are {', '.join(STAGES)}")
        return self._bundle(path, stage=stage.upper())

    def list(self, prefix: str) -> tuple[str, ...]:
        """Every secret in the store's compartment and vault below ``prefix``.

        OCI names are flat, so the only paths with a ``/`` are the locks'
        (:mod:`._names`). Secrets being deleted are left out: OCI keeps them
        for up to 30 days, and none of them can be read or written.
        """
        bounded = bounded_prefix(prefix)
        found: list[str] = []
        page = None
        while True:
            try:
                response = self._vaults.list_secrets(
                    self._compartment_id, vault_id=self._vault_id, page=page
                )
            except oci.exceptions.ServiceError as exc:
                _errors.raise_for(exc, what=f'the secrets of vault "{self._name}"')
            except NO_ANSWER as exc:
                raise _errors.unreachable(exc, what=f'vault "{self._name}"') from exc
            for summary in response.data:
                if summary.lifecycle_state in GONE:
                    continue
                path = _names.from_oci(summary.secret_name)
                if path.startswith(bounded):
                    found.append(path)
            page = response.next_page
            if not page:
                return tuple(sorted(found))

    def write(self, path: str, data: Any, *, cas: int | None) -> int:
        self._not_built("writing")

    def patch(self, path: str, changes: Any, *, cas: int | None) -> int:
        self._not_built("writing")

    def metadata(self, path: str) -> PathMetadata | None:
        self._not_built("reading")

    def require_cas(self, path: str) -> None:
        self._not_built("writing")

    def stage(self, path: str, data: Any, *, attributes: Mapping[str, Any], cas: int | None) -> int:
        self._not_built("writing")

    def promote(
        self, path: str, generation: int, *, attributes: Mapping[str, Any], cas: int | None
    ) -> int:
        self._not_built("writing")

    def _not_built(self, doing: str) -> NoReturn:
        raise StoreError(
            f'vault "{self._name}": {doing} an OCI store is not built in this version',
            hint="this version can check, read and list an OCI store only",
        )

    def _bundle(self, path: str, **which: Any) -> Stored | None:
        """One ``GetSecretBundleByName``, as a :class:`Stored`, or ``None``."""
        name = _names.to_oci(path)
        what = f'secret "{name}" in vault "{self._name}"'
        try:
            bundle = self._secrets.get_secret_bundle_by_name(
                secret_name=name, vault_id=self._vault_id, **which
            ).data
        except oci.exceptions.ServiceError as exc:
            if exc.status == 404 and exc.request_id:
                self._check_vault()
                return None
            _errors.raise_for(exc, what=what)
        except NO_ANSWER as exc:
            raise _errors.unreachable(exc, what=what) from exc

        metadata = dict(bundle.metadata or {})
        if _names.is_lock(path):
            # Decision 5: the record is in the metadata, so updating it adds no
            # version. A lock secret with no record holds nothing to read.
            if _names.RECORD_KEY not in metadata:
                return None
            data = _json_object(metadata[_names.RECORD_KEY], what=what)
        else:
            data = _json_object(_content(bundle, what=what), what=what)
        stages = set(bundle.stages or ())
        pinned_old = "version_number" in which and CURRENT not in stages
        return Stored(
            data=data,
            version=0 if pinned_old else _token(metadata, what=what),
            stage=next((one for one in STAGES if one.upper() in stages), None),
            generation=bundle.version_number,
            attributes=MappingProxyType(
                {key: value for key, value in metadata.items() if key not in _names.RESERVED_KEYS}
            ),
        )

    def _check_vault(self) -> None:
        """Tell a missing secret from a missing vault, once per store.

        OCI answers 404 for both. A wrong ``vault_id`` would otherwise make
        every secret read as absent, and a run would plan to create them.
        """
        if self._vault_seen:
            return
        try:
            self._kms.get_vault(self._vault_id)
        except oci.exceptions.ServiceError as exc:
            if exc.status == 404:
                raise OciVaultError(
                    f'vault "{self._name}": its vault_id was not found, or this principal '
                    f"may not see it ({_errors.describe(exc)})",
                    hint="check vault_id, the region, and the IAM policy for this principal",
                ) from exc
            _errors.raise_for(exc, what=f'vault "{self._name}"')
        except NO_ANSWER as exc:
            raise _errors.unreachable(exc, what=f'vault "{self._name}"') from exc
        self._vault_seen = True


class OciVaultError(StoreError):
    """The store's vault is not there, or not visible: the config is wrong."""

    category = "config"
    exit_code = ExitCode.CONFIG_INVALID


def _content(bundle: Any, *, what: str) -> str:
    """A version's content, decoded. OCI keeps it base64-encoded."""
    content = bundle.secret_bundle_content
    if getattr(content, "content_type", None) != "BASE64" or content.content is None:
        raise StoreError(f"{what} has content this build cannot read")
    try:
        return base64.b64decode(content.content, validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError) as exc:
        raise StoreError(f"{what} has content that is not UTF-8 text: {exc}") from exc


def _json_object(text: str, *, what: str) -> dict[str, Any]:
    """Decision 6: a secret is used when its content is a JSON object."""
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        value = None
    if not isinstance(value, dict):
        raise StoreError(
            f"{what} does not hold a JSON object, so this tool cannot use it",
            hint="the tool keeps fields in a JSON object; store one, or name another secret",
        )
    return value


def _token(metadata: Mapping[str, Any], *, what: str) -> int:
    """The write counter. A secret the tool never wrote has none, and reads as 1."""
    value = metadata.get(_names.CAS_KEY, 1)
    try:
        token = int(value)
    except (TypeError, ValueError):
        token = 0
    if token < 1:
        raise StoreError(f"{what} has a write counter this tool did not write: {value!r}")
    return token


def _server_time(headers: Mapping[str, str] | None) -> datetime | None:
    """The ``Date`` header as an aware UTC time, or ``None`` if there is none."""
    value = headers.get("date") if headers is not None else None
    if not value:
        return None
    try:
        parsed = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        # `-0000` parses as naive: RFC 5322's "UTC, source unknown".
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)
