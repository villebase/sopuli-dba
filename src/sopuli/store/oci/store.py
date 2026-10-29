"""P2's store interface over one OCI vault.

This build connects, authenticates and answers :meth:`OciStore.health`.
Reading, listing and writing come in the next pull requests of #1128, and
until then each of those methods refuses with a :class:`StoreError` rather
than answering as if the store were empty.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime
from typing import Any, NoReturn

import oci

from sopuli.clock import utc_now
from sopuli.config.model import Vault
from sopuli.store.oci import _errors
from sopuli.store.protocol import (
    DEGRADED,
    OK,
    UNREACHABLE,
    PathMetadata,
    Stored,
    StoreError,
    StoreHealth,
)

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
        if vault.vault_id is None:
            # Unreachable through a config file, which requires the key.
            raise StoreError(f'vault "{vault.name}" has no vault_id')
        self._name = vault.name
        self._vault_id = vault.vault_id
        self._vaults = vaults
        self._secrets = secrets
        self._kms = kms
        self._now = now

    def supports(self) -> frozenset[str]:
        """Nothing yet. Each capability arrives with the methods it needs."""
        return frozenset()

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
        self._not_built("reading")

    def write(self, path: str, data: Any, *, cas: int | None) -> int:
        self._not_built("writing")

    def patch(self, path: str, changes: Any, *, cas: int | None) -> int:
        self._not_built("writing")

    def metadata(self, path: str) -> PathMetadata | None:
        self._not_built("reading")

    def require_cas(self, path: str) -> None:
        self._not_built("writing")

    def list(self, prefix: str) -> tuple[str, ...]:
        self._not_built("listing")

    def read_stage(self, path: str, stage: str) -> Stored | None:
        self._not_built("reading")

    def stage(self, path: str, data: Any, *, attributes: Mapping[str, Any], cas: int | None) -> int:
        self._not_built("writing")

    def promote(
        self, path: str, generation: int, *, attributes: Mapping[str, Any], cas: int | None
    ) -> int:
        self._not_built("writing")

    def _not_built(self, doing: str) -> NoReturn:
        raise StoreError(
            f'vault "{self._name}": {doing} an OCI store is not built in this version',
            hint="this version can check an OCI store with `sopuli doctor` only",
        )


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
