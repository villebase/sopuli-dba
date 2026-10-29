"""P2's store interface over one OCI vault.

This build connects, answers :meth:`OciStore.health`, reads, lists, writes,
and holds lock records in metadata. Staging comes with #1153, and until then
it refuses with a :class:`StoreError`.

Content is read with ``GetSecretBundleByName``, the call External Secrets
Operator makes, so the tool reads exactly what an application would. One call
returns the content, the version's stages and number, and the secret's
metadata, which holds the write counter (:data:`._names.CAS_KEY`).

A write is a compare-and-set in two halves. ``GetSecret`` gives the counter
and the ETag; the counter is compared with ``cas``, and the ETag goes back as
``if_match``, so OCI refuses the update if anybody wrote in between. The
counter is the token, not OCI's version number, because a promotion and a
metadata-only update move no version.

After every write the secret is busy for about 20 seconds, and a read meanwhile
returns the old content (``oci-read-while-updating``). So each write waits
until the secret is ``ACTIVE`` again before it returns (decision 8), under the
spinner (:mod:`sopuli.store.waiting`).
"""

from __future__ import annotations

import base64
import binascii
import json
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
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
    CAS,
    DEGRADED,
    LIST,
    OK,
    STAGES,
    UNREACHABLE,
    VERSIONING,
    CasConflictError,
    PathMetadata,
    Stored,
    StoreError,
    StoreHealth,
    bounded_prefix,
)
from sopuli.store.waiting import waiting

#: The stage a read with no stage returns, in OCI's spelling.
CURRENT = "CURRENT"

#: Lifecycle states of a secret on its way out. OCI keeps a deleted secret for
#: up to 30 days, and none of these can be read or written.
GONE = frozenset({"DELETING", "DELETED", "SCHEDULING_DELETION", "PENDING_DELETION"})

#: OCI's ``Date`` header has whole seconds, so a finer skew would be noise.
RESOLUTION = timedelta(seconds=1)

#: A vault, or a secret, that can serve requests.
ACTIVE = "ACTIVE"

#: The states a secret is in for about 20 seconds after a write
#: (``oci-create-state``, ``oci-updating-state``).
BUSY = frozenset({"CREATING", "UPDATING"})

#: How long a write waits for its secret to be ACTIVE when the store sets no
#: ``timeout_s`` (decision 8). The measured window is about 20 seconds.
SETTLE_TIMEOUT_S = 120

#: Seconds between two reads of a busy secret.
POLL_S = 2.0

#: The largest metadata map the store sends, in characters of keys and values
#: (:func:`_check_size`). A little under the 5,113 measured to be accepted
#: (``oci-metadata-limits``).
METADATA_MAX = 5100

#: OCI's answer to a write the secret's state does not allow: it is busy.
INCORRECT_STATE = "IncorrectState"

#: OCI's ETag moves once more a few seconds after a secret turns ACTIVE, with
#: no field changing (``oci-etag-settle``). So a ``409 Conflict`` is retried
#: with the fresh ETag when a read straight afterwards shows that nothing
#: changed: still ACTIVE, the same metadata, the same current version. Every
#: accepted write leaves a secret busy for about 20 seconds, so an ACTIVE
#: secret read within :data:`CHURN_WINDOW_S` of the first read has had no
#: write accepted in between.
CHURN_WINDOW_S = 15.0

#: How many times a write is retried for that reason before it gives up.
CHURN_RETRIES = 3

#: The errors a request raises when no answer came back at all.
NO_ANSWER = (oci.exceptions.RequestException, oci.exceptions.ConnectTimeout)


@dataclass(frozen=True)
class _Live:
    """A secret as ``GetSecret`` answered, once it was ACTIVE, and when."""

    id: str
    name: str
    etag: str
    metadata: dict[str, Any]
    version: int | None
    read_at: float


class OciStore:
    """One ``vaults:`` entry of ``type: oci``.

    ``vaults``, ``secrets`` and ``kms`` are the SDK clients
    (:class:`sopuli.store.oci._auth.Clients`). They are passed in, so tier 0
    can pass fakes, and so are the clock and ``sleep`` the wait for ACTIVE uses.
    """

    def __init__(
        self,
        vault: Vault,
        *,
        vaults: Any,
        secrets: Any,
        kms: Any,
        now: Callable[[], datetime] = utc_now,
        sleep: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        if vault.vault_id is None or vault.compartment_id is None:
            # Unreachable through a config file, which requires both keys.
            raise StoreError(f'vault "{vault.name}" needs a vault_id and a compartment_id')
        self._name = vault.name
        self._vault_id = vault.vault_id
        self._compartment_id = vault.compartment_id
        self._key_id = vault.key_id
        self._settle_s = vault.timeout_s or SETTLE_TIMEOUT_S
        self._vault_seen = False
        #: Secret ids by name, from this run's reads and creates (:meth:`_live`).
        self._ids: dict[str, str] = {}
        self._vaults = vaults
        self._secrets = secrets
        self._kms = kms
        self._now = now
        self._sleep = sleep
        self._monotonic = monotonic

    def supports(self) -> frozenset[str]:
        """What works in this build. ``staging_labels`` arrives with staging
        (#1153). There is no ``merge_patch``: OCI has none."""
        return frozenset({CAS, LIST, VERSIONING})

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

        ``ListSecrets`` takes a compartment, so a secret in this vault and
        another compartment can be read by name and is not listed. The tool
        creates its secrets in the store's compartment.

        OCI names are flat, so the only paths with a ``/`` are the locks'
        (:mod:`._names`). Secrets being deleted are left out: OCI keeps them
        for up to 30 days.
        """
        self._check_vault()
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
        """Write ``data`` as the new CURRENT version, and return the new token.

        A secret that does not exist is created, with the store's KMS key, at
        token 1. ``cas`` is compared with the write counter before anything is
        sent, and the ETag guards the update itself. The call returns once the
        secret is ACTIVE again, so a read straight afterwards sees ``data``.

        ``cas=None`` is the protocol's unguarded write: the update carries no
        ETag, and a create that loses a race becomes an update.

        A lock record is the exception (decision 5): it goes in the lock
        secret's metadata under :data:`._names.RECORD_KEY`, and the content is
        left alone, so updating a lock adds no version (#1136, M7b). The
        first lock on a path creates its secret with ``{}`` as the content,
        because OCI will not create a secret without one.
        """
        name = _names.to_oci(path)
        return self._write(name, path, data, cas=cas, what=self._what(name), raced=False)

    def _write(
        self, name: str, path: str, data: Any, *, cas: int | None, what: str, raced: bool
    ) -> int:
        lock = _names.is_lock(path)
        record = {_names.RECORD_KEY: _compact(data)} if lock else {}
        live = self._live(name, what=what)
        if live is None:
            if cas not in (0, None):
                raise CasConflictError(
                    f"compare-and-set failed at {path!r}: expected version {cas}, found nothing"
                )
            try:
                self._create(
                    name, {} if lock else data, metadata={_names.CAS_KEY: "1", **record}, what=what
                )
            except CasConflictError:
                # An unguarded write overwrites whoever created it first, once.
                if cas is not None or raced:
                    raise
                return self._write(name, path, data, cas=None, what=what, raced=True)
            return 1
        token = _token(live.metadata, what=what)
        # `cas: 0` asserts that nothing is there, and a token is never below 1.
        if cas is not None and cas != token:
            raise CasConflictError(
                f"compare-and-set failed at {path!r}: expected version {cas}, found {token}"
            )
        return self._update(
            live,
            what=what,
            guarded=cas is not None,
            content={} if lock else {"secret_content": _encode(data)},
            metadata=lambda now: {
                **now.metadata,
                _names.CAS_KEY: str(_token(now.metadata, what=what) + 1),
                **record,
            },
        )

    def patch(self, path: str, changes: Any, *, cas: int | None) -> int:
        """OCI has no merge patch, so the store does not declare ``merge_patch``,
        and :func:`~sopuli.store.credentials.apply_patch` never asks."""
        raise StoreError(f'vault "{self._name}": an OCI store has no merge patch')

    def metadata(self, path: str) -> PathMetadata | None:
        """Nothing: OCI has no setting that makes a secret refuse an update
        without ``if_match``, so there is no ``cas_required`` to report.

        Who may write a secret is IAM's to say. The tool's own writes always
        carry the counter and the ETag; keeping other writers out is the IAM
        policy's job, which ``01-configuration.md`` §7 describes.
        """
        return None

    def require_cas(self, path: str) -> None:
        """Nothing to arrange, for the reason :meth:`metadata` gives. The lock's
        pre-flight calls this for a path it found no metadata for, which on
        OCI is every path; it sends nothing."""

    def stage(self, path: str, data: Any, *, attributes: Mapping[str, Any], cas: int | None) -> int:
        self._not_built("writing")

    def promote(
        self, path: str, generation: int, *, attributes: Mapping[str, Any], cas: int | None
    ) -> int:
        self._not_built("writing")

    def _not_built(self, doing: str) -> NoReturn:
        raise StoreError(
            f'vault "{self._name}": {doing} an OCI store is not built in this version',
            hint="this version can check, read, list and write an OCI store's secrets",
        )

    def _what(self, name: str) -> str:
        return f'secret "{name}" in vault "{self._name}"'

    # ------------------------------------------------------------- writes ---

    def _live(self, name: str, *, what: str) -> _Live | None:
        """The secret called ``name`` as ``GetSecret`` sees it once ACTIVE, or
        ``None`` if there is none that is not being deleted.

        A secret read or created earlier in the run is asked for by the id
        remembered then, which saves a ``ListSecrets`` per write: OCI throttles
        (``429``), and a write usually follows a read of the same secret.
        """
        response = None
        secret_id = self._ids.get(name)
        if secret_id is not None:
            response = self._get(secret_id, what=what, missing_ok=True)
            if response is None or response.data.lifecycle_state in GONE:
                response = None
                del self._ids[name]
        if response is None:
            summary = next(
                (one for one in self._summaries(name) if one.lifecycle_state not in GONE), None
            )
            if summary is None:
                self._check_vault()
                return None
            secret_id = summary.id
            response = self._get(secret_id, what=what)
            self._ids[name] = secret_id
        assert secret_id is not None
        if response.data.lifecycle_state != ACTIVE:
            response = self._settle(secret_id, name=name, written=False, what=what, first=response)
        return self._as_live(secret_id, name, response, what=what)

    def _as_live(self, secret_id: str, name: str, response: Any, *, what: str) -> _Live:
        etag = (response.headers or {}).get("etag")
        if not etag:
            # Without an ETag the update could not be a compare-and-set.
            raise StoreError(f"{what}: OCI sent no ETag, so it cannot be written safely")
        return _Live(
            id=secret_id,
            name=name,
            etag=etag,
            metadata=dict(response.data.metadata or {}),
            version=response.data.current_version_number,
            read_at=self._monotonic(),
        )

    def _create(self, name: str, data: Any, *, metadata: dict[str, Any], what: str) -> None:
        """``CreateSecret`` with ``data`` as the first version, and the wait for ACTIVE."""
        if self._key_id is None:
            # Unreachable through a config file, which requires the key.
            raise StoreError(f'vault "{self._name}" needs a key_id to create {what}')
        _check_size(metadata, what=what)
        details = oci.vault.models.CreateSecretDetails(
            compartment_id=self._compartment_id,
            vault_id=self._vault_id,
            key_id=self._key_id,
            secret_name=name,
            secret_content=_encode(data),
            metadata=metadata,
        )
        try:
            created = self._vaults.create_secret(details).data
        except oci.exceptions.ServiceError as exc:
            if _name_taken(exc):
                self._taken(name, exc, what=what)
            _errors.raise_for(exc, what=what)
        except NO_ANSWER as exc:
            raise _errors.unreachable(exc, what=what, maybe_written=True) from exc
        self._ids[name] = created.id
        self._settle(created.id, name=name, written=True, what=what)

    def _taken(self, name: str, exc: Any, *, what: str) -> NoReturn:
        """Say why OCI refused a create for a name that is held.

        OCI answers ``400 InvalidParameter: name already exists`` whether the
        name belongs to a live secret or to one scheduled for deletion
        (``oci-create-taken``). The first is another writer that created it
        after this run looked; the second keeps the name for days, and needs
        somebody to act.
        """
        held = [one.lifecycle_state for one in self._summaries(name)]
        if any(state not in GONE for state in held):
            raise CasConflictError(
                f"{what} was created by another writer after this run looked "
                f"({_errors.describe(exc)})"
            ) from exc
        if held:
            raise StoreError(
                f"{what} cannot be created: a secret of that name is scheduled for deletion, "
                f"and OCI keeps the name until it is deleted ({_errors.describe(exc)})",
                hint="cancel the deletion in OCI to use that secret again, or name another one",
            ) from exc
        # Names are unique in a vault, and the listing covers one compartment.
        raise StoreError(
            f"{what} cannot be created: OCI says the name is taken, and no secret of that "
            f"name is in the store's compartment ({_errors.describe(exc)})",
            hint=(
                "a secret in another compartment of this vault may hold the name, or one was "
                "created a moment ago; check the vault, then run again"
            ),
        ) from exc

    def _update(
        self,
        live: _Live,
        *,
        what: str,
        guarded: bool,
        content: Mapping[str, Any],
        metadata: Callable[[_Live], dict[str, Any]],
    ) -> int:
        """``UpdateSecret`` under ``live``'s ETag, the wait for ACTIVE, and the
        new token.

        ``metadata`` builds the whole map to send from the secret as last
        read, the counter moved. ``guarded=False`` sends no ETag: the
        protocol's unguarded write.

        A ``409 IncorrectState`` means another writer made the secret busy
        after :meth:`_live` saw it ACTIVE, and the store waits that out. A
        guarded write then sends the same ETag again: if the other writer
        changed the secret, OCI answers ``409 Conflict``, a lost
        compare-and-set. An unguarded write builds its metadata again from the
        secret as it now is, so the counter still moves forward.

        A ``409 Conflict`` is a lost compare-and-set unless a read straight
        afterwards shows that nothing changed (:data:`CHURN_WINDOW_S`). Then
        only OCI's ETag moved, and the update is sent again with the new one.
        """
        current = live
        last = ""
        for _ in range(CHURN_RETRIES + 1):
            sent = metadata(current)
            _check_size(sent, what=what)
            update = oci.vault.models.UpdateSecretDetails(metadata=sent, **content)
            try:
                self._send_update(current, update, guarded=guarded, what=what)
                break
            except oci.exceptions.ServiceError as exc:
                if exc.status != 409 or not exc.request_id:
                    _errors.raise_for(exc, what=what)
                last = exc.code
                if exc.code == INCORRECT_STATE:
                    response = self._settle(current.id, name=current.name, written=False, what=what)
                    if guarded:
                        # Somebody else wrote: no later Conflict is only churn.
                        current = replace(current, read_at=float("-inf"))
                    else:
                        current = self._as_live(current.id, current.name, response, what=what)
                    continue
                churned = None
                if exc.code == _errors.CONFLICT:
                    churned = self._churned(current, what=what)
                if churned is None:
                    _errors.raise_for(exc, what=what)
                current = churned
        else:
            if last == INCORRECT_STATE:
                raise _errors.OciUnavailableError(
                    f"{what}: the secret was busy with other writes {CHURN_RETRIES + 1} times, "
                    f"so nothing was written",
                    hint="run again once the other writers have finished",
                )
            raise CasConflictError(
                f"{what}: OCI refused the update {CHURN_RETRIES + 1} times with a changing ETag, "
                f"and the secret did not change in between",
                hint="run again; if it keeps happening, the OCI request ids in a debug run help",
            )
        self._settle(live.id, name=live.name, written=True, what=what)
        return int(sent[_names.CAS_KEY])

    def _churned(self, live: _Live, *, what: str) -> _Live | None:
        """The secret with a fresh ETag, if only its ETag has moved since ``live``.

        ``None`` if anything else may have: the secret is not ACTIVE, its
        metadata or current version changed, or too long has passed since
        ``live`` was read for an ACTIVE state to prove that no write was
        accepted in between (``oci-etag-settle``, ``oci-updating-state``).
        """
        response = self._get(live.id, what=what)
        if self._monotonic() - live.read_at > CHURN_WINDOW_S:
            return None
        data = response.data
        if (
            data.lifecycle_state != ACTIVE
            or dict(data.metadata or {}) != live.metadata
            or data.current_version_number != live.version
        ):
            return None
        fresh = self._as_live(live.id, live.name, response, what=what)
        return None if fresh.etag == live.etag else fresh

    def _send_update(self, live: _Live, update: Any, *, guarded: bool, what: str) -> None:
        try:
            if guarded:
                self._vaults.update_secret(live.id, update, if_match=live.etag)
            else:
                self._vaults.update_secret(live.id, update)
        except NO_ANSWER as exc:
            raise _errors.unreachable(exc, what=what, maybe_written=True) from exc

    def _settle(
        self, secret_id: str, *, name: str, written: bool, what: str, first: Any = None
    ) -> Any:
        """Wait until the secret is ACTIVE, and return that ``GetSecret`` answer.

        ``first`` is a ``GetSecret`` answer already in hand, used as the first
        poll. Each wait is bounded by the store's ``timeout_s``, or
        :data:`SETTLE_TIMEOUT_S`. ``written`` says whether this run's write was
        already accepted, which every error here must say: the write is made
        either way.

        A poll OCI throttles (``429``, seen in a real run straight after a
        write) is one more reason to wait, not a failure: the wait goes on,
        polling half as often.
        """
        made = "the write was made, and " if written else ""
        start = self._monotonic()
        response = first
        state = "busy"
        with waiting(f"Waiting for OCI secret `{name}` to finish updating"):
            while True:
                if response is None:
                    response = self._get(secret_id, what=what, made=made, throttled_ok=True)
                if response is not None:
                    state = response.data.lifecycle_state
                    if state == ACTIVE:
                        return response
                    if state not in BUSY:
                        raise StoreError(
                            f"{what}: {made}the secret is {state}"
                            + ("" if written else ", so it cannot be written")
                        )
                waited = self._monotonic() - start
                if waited >= self._settle_s:
                    raise _errors.OciUnavailableError(
                        f"{what}: {made}the secret is still {state} after {waited:.0f} s",
                        hint=(
                            f"OCI keeps a secret busy for about 20 seconds after a write; "
                            f'`timeout_s` on vault "{self._name}" bounds this wait'
                        ),
                    )
                self._sleep(POLL_S if response is not None else 2 * POLL_S)
                response = None

    def _get(
        self,
        secret_id: str,
        *,
        what: str,
        made: str = "",
        throttled_ok: bool = False,
        missing_ok: bool = False,
    ) -> Any:
        """One ``GetSecret``.

        ``None`` for a throttled answer (``429``) when ``throttled_ok``, and
        for a 404 when ``missing_ok``. Any other failure raises, saying first
        that the write was made when ``made`` says so.
        """
        try:
            return self._vaults.get_secret(secret_id)
        except oci.exceptions.ServiceError as exc:
            if exc.request_id and (
                (throttled_ok and exc.status == 429) or (missing_ok and exc.status == 404)
            ):
                return None
            try:
                _errors.raise_for(exc, what=what)
            except StoreError as failed:
                raise _restated(failed, what, made) from exc
        except NO_ANSWER as exc:
            raise _restated(_errors.unreachable(exc, what=what), what, made) from exc

    def _bundle(self, path: str, **which: Any) -> Stored | None:
        """One ``GetSecretBundleByName``, as a :class:`Stored`, or ``None``."""
        name = _names.to_oci(path)
        what = self._what(name)
        try:
            bundle = self._secrets.get_secret_bundle_by_name(
                secret_name=name, vault_id=self._vault_id, **which
            ).data
        except oci.exceptions.ServiceError as exc:
            if exc.status == 404 and exc.request_id:
                if self._absent_or_refused(name, which, exc, what=what):
                    return self._bundle(path, **which)
                return None
            _errors.raise_for(exc, what=what)
        except NO_ANSWER as exc:
            raise _errors.unreachable(exc, what=what) from exc

        if getattr(bundle, "secret_id", None):
            self._ids[name] = bundle.secret_id
        metadata = dict(bundle.metadata or {})
        if _names.is_lock(path):
            # Decision 5: the record is in the metadata, so updating it adds no
            # version. A lock secret with no readable record is still a lock,
            # at its token: `LockRecord.from_dict` makes a held, expired record
            # of it, which `lock break` can clear. Read as nothing, every later
            # `cas: 0` acquisition would fail for good.
            data = _record(metadata.get(_names.RECORD_KEY))
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

    def _absent_or_refused(
        self, name: str, which: Mapping[str, Any], exc: Any, *, what: str
    ) -> bool:
        """After a 404 on a content read: ``False`` if it means "nothing there",
        ``True`` if the caller should read again; raise if it means neither.

        OCI answers 404 ``NotAuthorizedOrNotFound`` for a missing secret, a
        missing version or stage, a missing vault, **and** a secret this
        principal may list but not read. Reading the last as absent would make
        a run plan to create a secret that exists, so the cases are told apart:

        * the secret is not listed: it is absent, once the vault is known;
        * it is listed and still ``CREATING``: OCI answers a read by name with
          404 until it is ACTIVE (``oci-read-while-creating``), as when a
          second run reads the lock a first run has just created. The store
          waits, and the caller reads again;
        * it is listed and CURRENT was asked for: the principal may not read it;
        * it is listed and a stage or a version was asked for: a CURRENT read
          says which. If that is refused too, the principal may not read it;
          otherwise the stage or version is just not there.
        """
        live = [one for one in self._summaries(name) if one.lifecycle_state not in GONE]
        if not live:
            self._check_vault()
            return False
        if live[0].lifecycle_state == "CREATING":
            self._settle(live[0].id, name=name, written=False, what=what)
            return True
        if which.get("stage") != CURRENT:
            try:
                self._secrets.get_secret_bundle_by_name(
                    secret_name=name, vault_id=self._vault_id, stage=CURRENT
                )
                return False
            except oci.exceptions.ServiceError as again:
                if again.status != 404:
                    _errors.raise_for(again, what=what)
        raise _errors.OciAuthError(
            f"{what} exists, and this principal may not read its content ({_errors.describe(exc)})",
            hint="the IAM policy must allow reading secret bundles in this vault",
        )

    def _summaries(self, name: str) -> tuple[Any, ...]:
        """Every secret called ``name`` in the store's compartment, deleting ones
        included. Names are unique in a vault, so there is one at most, unless
        an old one is still on its way out."""
        try:
            response = self._vaults.list_secrets(
                self._compartment_id, vault_id=self._vault_id, name=name
            )
        except oci.exceptions.ServiceError as exc:
            _errors.raise_for(exc, what=self._what(name))
        except NO_ANSWER as exc:
            raise _errors.unreachable(exc, what=f'vault "{self._name}"') from exc
        return tuple(response.data)

    def _check_vault(self) -> None:
        """Tell an empty answer from a missing vault, once per store.

        OCI answers 404 for a missing vault, and ``ListSecrets`` answers an
        empty list. A wrong ``vault_id`` would otherwise make every secret read
        as absent, and a run would plan to create them.
        """
        if self._vault_seen:
            return
        what = f'the vault_id of vault "{self._name}"'
        try:
            self._kms.get_vault(self._vault_id)
        except oci.exceptions.ServiceError as exc:
            _errors.raise_for(exc, what=what, missing=OciVaultError)
        except NO_ANSWER as exc:
            raise _errors.unreachable(exc, what=what) from exc
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
    except (binascii.Error, UnicodeDecodeError):
        # Not `from exc`, and not its text: a UnicodeDecodeError quotes a byte
        # of the content, and the content is a secret.
        raise StoreError(f"{what} has content that is not UTF-8 text") from None


def _compact(data: Any) -> str:
    return json.dumps(data, separators=(",", ":"), ensure_ascii=False)


def _restated(error: StoreError, what: str, made: str) -> StoreError:
    """``error``, saying first that the write was made, when it was.

    The original message follows whole: it may or may not start with
    ``what``, and cutting it apart would garble the one that does not.
    """
    if not made:
        return error
    return type(error)(f"{what}: {made}waiting for it failed. {error.message}", hint=error.hint)


def _name_taken(exc: Any) -> bool:
    """OCI's answer to a create whose name is held (``oci-create-taken``).

    A 400 with OCI's request id, code and message: a 400 from a proxy, or one
    OCI words differently, goes to :func:`._errors.raise_for` as it is.
    """
    return (
        exc.status == 400
        and exc.code == "InvalidParameter"
        and bool(exc.request_id)
        and "already exists" in (exc.message or "")
    )


def _encode(data: Any) -> Any:
    """``data`` as a CURRENT version's content: JSON, UTF-8, base64.

    The one place a password leaves the process on an OCI store (invariant 2).
    """
    return oci.vault.models.Base64SecretContentDetails(
        content_type="BASE64",
        content=base64.b64encode(_compact(data).encode("utf-8")).decode("ascii"),
        stage=CURRENT,
    )


def _check_size(metadata: Mapping[str, Any], *, what: str) -> None:
    """Refuse a metadata map OCI would refuse, before it is sent.

    OCI limits the whole map (``oci-metadata-limits``), in characters rather
    than bytes: a 12-character key with a 5,101-character value was accepted,
    5,113 in all, and with 5,159, refused. So the size is counted as OCI was
    measured, keys and string values as they are, and a list or an object as
    compact JSON. The lock record is a string already, and is not escaped
    again. The lock record and the promotion stamps share the map, and a
    secret the tool did not create may bring keys of its own.
    """
    size = sum(
        len(key) + len(value if isinstance(value, str) else _compact(value))
        for key, value in metadata.items()
    )
    if size > METADATA_MAX:
        raise StoreError(
            f"{what}: its metadata would be {size} characters, and OCI allows about {METADATA_MAX}",
            hint="remove metadata keys this tool does not use from the secret",
        )


def _record(value: Any) -> Any:
    """A lock record from the metadata: the object, or ``None`` if there is no
    readable one. Never a refusal, for the reason ``LockRecord.from_dict``
    gives: a lock nobody can read must still be a lock somebody can break."""
    if not isinstance(value, str):
        return None
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


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
    value = metadata.get(_names.CAS_KEY, "1")
    # The tool writes the counter as a string of digits. Anything else, a
    # bool or a float included, was written by something else.
    if not isinstance(value, str) or not value.isascii() or not value.isdigit():
        raise StoreError(f"{what} has a write counter this tool did not write: {value!r}")
    token = int(value)
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
