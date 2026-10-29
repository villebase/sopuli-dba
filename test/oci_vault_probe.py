"""Probe: what does OCI Vault actually do with the calls the OCI store will make?

Written for #1129, the first part of #1128 (OCI Vault as the second secret
store). The design leans on OCI behaviour that Oracle's documentation does not
state, or states too loosely to build on: how long a secret name can be, what a
PENDING version looks like to a reader, whether an ETag guards an update, and
how many versions a secret keeps. Each check below answers one of those, and
the results decide how PRs 3 to 6 are built.

Not a pytest test. A spike, run by hand against a real tenancy, as
``test/vault_cas_probe.py`` is run against Vault. It needs the ``[oci]`` extra
and an OCI config file. Set these variables first:

    OCI_PROBE_VAULT_ID         the vault's OCID
    OCI_PROBE_COMPARTMENT_ID   the compartment the vault is in
    OCI_PROBE_KEY_ID           a KMS key in that vault
    OCI_PROBE_PROFILE          the config-file profile (default: DEFAULT)

    python test/oci_vault_probe.py            # every check
    python test/oci_vault_probe.py m9 m12     # only the checks named

Every secret it creates is named ``acme-probe-<UTC timestamp>-<n>`` and is
scheduled for deletion at the end, after the shortest wait OCI allows. OCI
keeps the name until then, so each run uses new names. Content is placeholder
JSON such as ``{"password": "probe-3"}``. It is never a real credential.

Results, 2026-10-28, region eu-frankfurt-1, a DEFAULT (virtual) vault, a
software-protected AES key, ``oci`` SDK 2.189.0. Two runs, with the same
results:

- **M1** A name may be up to 255 characters. At 256, ``400 InvalidParameter:
  secretName size must be between 0 and 255``. Names are case-sensitive:
  ``acme-…`` and ``ACME-…`` can both exist in one vault.
- **M1b** (two runs of the check alone, the same day) Letters, digits, ``-``,
  ``_`` and ``.`` are accepted in any position: leading, trailing and doubled
  (``-acme…``, ``.acme…``, ``_acme…``, ``…-``, ``….``, ``acme..probe…``). ``/``,
  ``@``, a space and ``~`` are refused with ``400 InvalidParameter: secretName
  contains one or more invalid characters``.
- **M2** After an update with ``stage = PENDING``, version 2 is ``PENDING`` and
  ``LATEST``, and version 1 stays ``CURRENT``. A read by name with no stage
  returns version 1, and so does ``stage=CURRENT``. Only ``stage=PENDING``
  returns version 2.
- **M3** The ETag is the same across two reads. An update with the current
  ETag as ``if_match`` succeeds. The same, now stale, ETag is refused with
  ``409 Conflict``, not 412. A content update, a PENDING update, a promotion
  and a metadata-only update each change the ETag.
- **M4** Straight after an update the secret is ``UPDATING``, and a second
  update is refused with ``409 IncorrectState``. It was ``ACTIVE`` again 19.9
  and 21.7 seconds after the refused update. The timer starts after that
  refusal and polls once a second, so the window is a little longer than that.
- **M5** ``current_version_number=2`` with ``metadata`` in the same call makes
  version 2 ``CURRENT``, version 1 ``PREVIOUS``, and changes the metadata.
  Promoting the version that is already ``CURRENT`` succeeds and changes only
  the metadata. The metadata sent **replaces the whole map**:
  ``{"targets": […], "n": 1}`` followed by ``{"n": 2}`` leaves ``{"n": 2}``.
  Promoting version 99 is ``404 NotAuthorizedOrNotFound``. Promoting a
  ``DEPRECATED`` version **succeeds**: OCI does not refuse it.
- **M6** A second PENDING makes the first ``DEPRECATED``. A ``CURRENT`` update
  over a PENDING leaves the PENDING in place. Scheduling the deletion of a
  PENDING version is refused with ``409 IncorrectState``. Of the calls tried,
  only a promotion or a newer PENDING takes the stage off a version.
- **M7** A secret holds 30 versions. The create makes version 1, and content
  updates 1 to 29 make versions 2 to 30. Content update 30, which would make
  version 31, is refused with ``400 LimitExceeded: The limit for this tenancy
  has been exceeded.`` (Run 1 and run 2 printed this as "refused at update 31",
  the version number. A third run of M7 alone, after the label was corrected,
  printed "content update 30, which would make version 31, refused".) OCI
  removes no version by itself.
- **M7b** A metadata-only update adds no version.
- **M7c** Scheduling the deletion of the oldest ``DEPRECATED`` version
  succeeds. The secret still lists 30 versions, and the next content update
  succeeds: a version scheduled for deletion does not count against the limit.

M9 to M13 were added for #1151, before the store's writes (#1133). Results,
2026-10-29, the same vault, key, region and SDK. Two runs, with the same
results:

- **M9** A create with ``stage = PENDING`` is refused with ``400
  InvalidParameter: stage must be one of CURRENT.`` A secret's first version is
  always CURRENT.
- **M10** A create with the name of an ACTIVE secret is refused with ``400
  InvalidParameter: name already exists``, not a 409. A secret scheduled for
  deletion is ``SCHEDULING_DELETION`` straight afterwards, and a create with
  its name gets the same answer.
- **M11** A create answers ``CREATING``, and the secret is still ``CREATING``
  when read straight afterwards. An update then is refused with ``409
  IncorrectState``. It was ``ACTIVE`` 18.1 and 20.2 seconds later. Scheduling a
  version's deletion makes the secret ``UPDATING``, for 20.5 and 19.5 seconds.
  The version listing then shows a ``time_of_deletion`` on that version only.
- **M12** Metadata values of 1,000 and 4,000 characters are accepted and read
  back unchanged. 16,000 is refused with ``400 InvalidParameter: metadata
  exceeds max allowed size``. A list, a nested object and an integer are
  accepted and read back as they were sent. A read by name carries the
  metadata.
- **M13** A read by name while the secret is ``UPDATING`` after a content
  update returns the **old** version. Once ``ACTIVE``, it returns the new one.
"""

from __future__ import annotations

import base64
import json
import os
import sys
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import oci

VAULT_ID = os.environ.get("OCI_PROBE_VAULT_ID", "")
COMPARTMENT_ID = os.environ.get("OCI_PROBE_COMPARTMENT_ID", "")
KEY_ID = os.environ.get("OCI_PROBE_KEY_ID", "")
PROFILE = os.environ.get("OCI_PROBE_PROFILE", "DEFAULT")

RUN = datetime.now(UTC).strftime("%Y%m%d%H%M%S")

#: How long to wait for a secret to leave UPDATING before giving up.
SETTLE_S = 120

created: list[str] = []


def report(check: str, question: str, observed: object) -> None:
    print(f"{check} {question}: {observed}")


def content(value: str) -> oci.vault.models.Base64SecretContentDetails:
    raw = json.dumps({"password": value}).encode("utf-8")
    return oci.vault.models.Base64SecretContentDetails(
        content_type="BASE64", content=base64.b64encode(raw).decode("ascii")
    )


def staged(value: str, stage: str) -> oci.vault.models.Base64SecretContentDetails:
    details = content(value)
    details.stage = stage
    return details


def error(exc: oci.exceptions.ServiceError) -> str:
    return f"{exc.status} {exc.code}: {exc.message}"


class Probe:
    def __init__(self) -> None:
        config = oci.config.from_file(profile_name=PROFILE)
        self.vaults = oci.vault.VaultsClient(config)
        self.secrets = oci.secrets.SecretsClient(config)
        self.counter = 0

    # -------------------------------------------------------------- helpers ---

    def name(self, suffix: str = "") -> str:
        self.counter += 1
        return f"acme-probe-{RUN}-{self.counter}{suffix}"

    def create(self, name: str, value: str = "probe-1") -> Any:
        secret = self.vaults.create_secret(
            oci.vault.models.CreateSecretDetails(
                compartment_id=COMPARTMENT_ID,
                vault_id=VAULT_ID,
                key_id=KEY_ID,
                secret_name=name,
                secret_content=content(value),
            )
        ).data
        created.append(secret.id)
        self.settle(secret.id)
        return secret

    def settle(self, secret_id: str) -> float:
        """Wait until the secret is ACTIVE, and return how long that took."""
        start = time.monotonic()
        while True:
            state = self.vaults.get_secret(secret_id).data.lifecycle_state
            if state == "ACTIVE":
                return time.monotonic() - start
            if time.monotonic() - start > SETTLE_S:
                raise RuntimeError(f"secret {secret_id} still {state} after {SETTLE_S}s")
            time.sleep(1)

    def state(self, secret_id: str) -> str:
        return str(self.vaults.get_secret(secret_id).data.lifecycle_state)

    def get(self, secret_id: str) -> tuple[Any, str]:
        response = self.vaults.get_secret(secret_id)
        return response.data, response.headers.get("etag", "")

    def update(self, secret_id: str, **details: Any) -> Any:
        if_match = details.pop("if_match", None)
        kwargs = {} if if_match is None else {"if_match": if_match}
        response = self.vaults.update_secret(
            secret_id, oci.vault.models.UpdateSecretDetails(**details), **kwargs
        )
        self.settle(secret_id)
        return response

    def stages(self, secret_id: str) -> dict[int, list[str]]:
        versions = oci.pagination.list_call_get_all_results(
            self.vaults.list_secret_versions, secret_id
        ).data
        return {v.version_number: sorted(v.stages or []) for v in versions}

    def bundle(self, name: str, **kwargs: Any) -> str:
        try:
            data = self.secrets.get_secret_bundle_by_name(name, VAULT_ID, **kwargs).data
        except oci.exceptions.ServiceError as exc:
            return f"error {error(exc)}"
        return f"version {data.version_number} stages {sorted(data.stages or [])}"

    # --------------------------------------------------------------- checks ---

    def m1_names(self) -> None:
        stem = f"acme-probe-{RUN}-len-"
        for length in (100, 255, 256, 1000):
            name = (stem + "x" * length)[:length]
            try:
                self.create(name)
                outcome = "accepted"
            except oci.exceptions.ServiceError as exc:
                outcome = f"refused ({error(exc)})"
            report("M1", f"name of {length} characters", outcome)

        lower = self.name("-case")
        self.create(lower)
        try:
            self.create(lower.upper())
            outcome = "accepted: names are case-sensitive"
        except oci.exceptions.ServiceError as exc:
            outcome = f"refused: names are case-insensitive ({error(exc)})"
        report("M1", "same name in upper case", outcome)

    def m1b_characters(self) -> None:
        """Which characters, and which placements, a name may have."""
        stem = f"{RUN}-{self.counter}"
        for name in (
            f"acme_probe.{stem}",
            f"-acme-probe-{stem}",
            f".acme-probe-{stem}",
            f"_acme-probe-{stem}",
            f"acme-probe-{stem}-",
            f"acme-probe-{stem}.",
            f"acme..probe-{stem}",
            f"acme/probe-{stem}",
            f"acme@probe-{stem}",
            f"acme probe-{stem}",
            f"acme~probe-{stem}",
        ):
            try:
                self.create(name)
                outcome = "accepted"
            except oci.exceptions.ServiceError as exc:
                outcome = f"refused ({error(exc)})"
            report("M1b", repr(name.replace(stem, "<n>")), outcome)

    def m2_pending(self) -> None:
        name = self.name()
        secret = self.create(name)
        self.update(secret.id, secret_content=staged("probe-2", "PENDING"))
        report("M2", "version stages after a PENDING update", self.stages(secret.id))
        report("M2", "read with no stage", self.bundle(name))
        report("M2", "read with stage=PENDING", self.bundle(name, stage="PENDING"))
        report("M2", "read with stage=CURRENT", self.bundle(name, stage="CURRENT"))

    def m3_etag(self) -> None:
        secret = self.create(self.name())
        _, etag = self.get(secret.id)
        _, again = self.get(secret.id)
        report("M3", "ETag stable across two reads", etag == again)

        self.update(secret.id, secret_content=content("probe-2"), if_match=etag)
        _, after_content = self.get(secret.id)
        report("M3", "update with the current ETag", "accepted")
        report("M3", "content update changes the ETag", after_content != etag)

        try:
            self.update(secret.id, secret_content=content("probe-3"), if_match=etag)
            outcome = "accepted (no compare-and-set)"
        except oci.exceptions.ServiceError as exc:
            outcome = f"refused ({error(exc)})"
        report("M3", "update with a stale ETag", outcome)

        _, before = self.get(secret.id)
        self.update(secret.id, secret_content=staged("probe-4", "PENDING"))
        _, after_stage = self.get(secret.id)
        report("M3", "PENDING update changes the ETag", after_stage != before)

        pending = max(self.stages(secret.id))
        self.update(secret.id, current_version_number=pending)
        _, after_promote = self.get(secret.id)
        report("M3", "promotion changes the ETag", after_promote != after_stage)

        self.update(secret.id, metadata={"sopuli_probe": "1"})
        _, after_metadata = self.get(secret.id)
        report("M3", "metadata-only update changes the ETag", after_metadata != after_promote)

    def m4_updating(self) -> None:
        secret = self.create(self.name())
        self.vaults.update_secret(
            secret.id, oci.vault.models.UpdateSecretDetails(secret_content=content("probe-2"))
        )
        state = self.vaults.get_secret(secret.id).data.lifecycle_state
        report("M4", "state straight after an update", state)
        try:
            self.vaults.update_secret(
                secret.id, oci.vault.models.UpdateSecretDetails(secret_content=content("probe-3"))
            )
            outcome = "accepted"
        except oci.exceptions.ServiceError as exc:
            outcome = f"refused ({error(exc)})"
        report("M4", "second update straight after the first", outcome)
        report("M4", "seconds until ACTIVE", round(self.settle(secret.id), 1))

    def m5_promote(self) -> None:
        secret = self.create(self.name())
        self.update(secret.id, secret_content=staged("probe-2", "PENDING"))
        self.update(
            secret.id, current_version_number=2, metadata={"targets": ["appdb-alpha"], "n": 1}
        )
        data, _ = self.get(secret.id)
        report("M5", "stages after promoting 2 with metadata", self.stages(secret.id))
        report("M5", "current_version_number", data.current_version_number)
        report("M5", "metadata after the same call", data.metadata)

        try:
            self.update(secret.id, current_version_number=2, metadata={"n": 2})
            data, _ = self.get(secret.id)
            outcome = f"accepted; metadata {data.metadata}"
        except oci.exceptions.ServiceError as exc:
            outcome = f"refused ({error(exc)})"
        report("M5", "promoting the version that is already CURRENT", outcome)

        try:
            self.update(secret.id, current_version_number=99)
            outcome = "accepted"
        except oci.exceptions.ServiceError as exc:
            outcome = f"refused ({error(exc)})"
        report("M5", "promoting a version that does not exist", outcome)

        self.update(secret.id, secret_content=staged("probe-3", "PENDING"))
        self.update(secret.id, current_version_number=3)
        report("M5", "stages after a second promotion", self.stages(secret.id))
        try:
            self.update(secret.id, current_version_number=1)
            outcome = f"accepted; stages {self.stages(secret.id)}"
        except oci.exceptions.ServiceError as exc:
            outcome = f"refused ({error(exc)})"
        report("M5", "promoting a DEPRECATED version", outcome)

    def m6_replace_pending(self) -> None:
        secret = self.create(self.name())
        self.update(secret.id, secret_content=staged("probe-2", "PENDING"))
        self.update(secret.id, secret_content=staged("probe-3", "PENDING"))
        report("M6", "stages after a second PENDING", self.stages(secret.id))

        self.update(secret.id, secret_content=content("probe-4"))
        report("M6", "stages after a CURRENT update over a PENDING", self.stages(secret.id))

        pending = [n for n, s in self.stages(secret.id).items() if "PENDING" in s]
        if not pending:
            report("M6", "remove PENDING without promoting", "no PENDING left to remove")
            return
        when = datetime.now(UTC) + timedelta(days=1, hours=1)
        try:
            self.vaults.schedule_secret_version_deletion(
                secret.id,
                pending[0],
                oci.vault.models.ScheduleSecretVersionDeletionDetails(time_of_deletion=when),
            )
            self.settle(secret.id)
            outcome = f"scheduled; stages {self.stages(secret.id)}"
        except oci.exceptions.ServiceError as exc:
            outcome = f"refused ({error(exc)})"
        report("M6", "schedule deletion of the PENDING version", outcome)

    def m7_versions(self) -> None:
        secret = self.create(self.name())
        before = len(self.stages(secret.id))
        self.update(secret.id, metadata={"sopuli_probe": "1"})
        report("M7b", "metadata-only update adds a version", len(self.stages(secret.id)) > before)

        # The create made version 1, so content update `done` makes version
        # `done + 1`. Only `LimitExceeded` is the limit; anything else stops
        # the check and is reported as itself.
        outcome = "no limit reached after 40 content updates"
        for done in range(1, 41):
            try:
                self.update(secret.id, secret_content=content(f"probe-{done + 1}"))
            except oci.exceptions.ServiceError as exc:
                if exc.code != "LimitExceeded":
                    report("M7", f"content update {done} stopped the check", error(exc))
                    return
                outcome = (
                    f"content update {done}, which would make version {done + 1}, "
                    f"refused ({error(exc)})"
                )
                break
        versions = self.stages(secret.id)
        report("M7", "limit", outcome)
        report("M7", "versions listed", len(versions))
        report("M7", "lowest and highest version listed", (min(versions), max(versions)))
        report("M7", "stages of the lowest version", versions[min(versions)])

        when = datetime.now(UTC) + timedelta(days=1, hours=1)
        deprecated = [n for n, s in versions.items() if s == ["DEPRECATED"]]
        if not deprecated:
            report("M7c", "schedule deletion of the oldest DEPRECATED version", "none to delete")
            return
        oldest = min(deprecated)
        try:
            self.vaults.schedule_secret_version_deletion(
                secret.id,
                oldest,
                oci.vault.models.ScheduleSecretVersionDeletionDetails(time_of_deletion=when),
            )
            self.settle(secret.id)
            outcome = "scheduled"
        except oci.exceptions.ServiceError as exc:
            report("M7c", "schedule deletion of the oldest DEPRECATED version", error(exc))
            return
        report("M7c", "schedule deletion of the oldest DEPRECATED version", outcome)
        report("M7c", "versions listed after it", len(self.stages(secret.id)))
        try:
            self.update(secret.id, secret_content=content("probe-after-delete"))
            outcome = "accepted: a version pending deletion does not count"
        except oci.exceptions.ServiceError as exc:
            outcome = f"refused: it still counts ({error(exc)})"
        report("M7c", "content update after it", outcome)

    def m9_create_pending(self) -> None:
        """Can a secret be created with its only version in PENDING?"""
        name = self.name()
        try:
            secret = self.vaults.create_secret(
                oci.vault.models.CreateSecretDetails(
                    compartment_id=COMPARTMENT_ID,
                    vault_id=VAULT_ID,
                    key_id=KEY_ID,
                    secret_name=name,
                    secret_content=staged("probe-1", "PENDING"),
                )
            ).data
        except oci.exceptions.ServiceError as exc:
            report("M9", "create with stage PENDING", f"refused ({error(exc)})")
            return
        created.append(secret.id)
        self.settle(secret.id)
        report("M9", "create with stage PENDING", "accepted")
        report("M9", "version stages", self.stages(secret.id))
        report("M9", "read with no stage", self.bundle(name))
        report("M9", "read with stage=PENDING", self.bundle(name, stage="PENDING"))

    def m10_create_taken(self) -> None:
        """What a create answers for a name that is already held."""
        name = self.name()
        self.create(name)
        try:
            self.create(name)
            outcome = "accepted"
        except oci.exceptions.ServiceError as exc:
            outcome = f"refused ({error(exc)})"
        report("M10", "create over an ACTIVE secret's name", outcome)

        name = self.name()
        secret = self.create(name)
        self.vaults.schedule_secret_deletion(
            secret.id,
            oci.vault.models.ScheduleSecretDeletionDetails(
                time_of_deletion=datetime.now(UTC) + timedelta(days=1, hours=1)
            ),
        )
        created.remove(secret.id)
        report("M10", "state after scheduling deletion", self.state(secret.id))
        try:
            self.create(name)
            outcome = "accepted"
        except oci.exceptions.ServiceError as exc:
            outcome = f"refused ({error(exc)})"
        report("M10", "create over the name of a secret scheduled for deletion", outcome)

    def m11_states(self) -> None:
        """The state after a create and after scheduling a version's deletion."""
        secret = self.vaults.create_secret(
            oci.vault.models.CreateSecretDetails(
                compartment_id=COMPARTMENT_ID,
                vault_id=VAULT_ID,
                key_id=KEY_ID,
                secret_name=self.name(),
                secret_content=content("probe-1"),
            )
        ).data
        created.append(secret.id)
        report("M11", "state in the create's answer", secret.lifecycle_state)
        report("M11", "state read straight after the create", self.state(secret.id))
        try:
            self.vaults.update_secret(
                secret.id, oci.vault.models.UpdateSecretDetails(metadata={"sopuli_probe": "1"})
            )
            outcome = "accepted"
        except oci.exceptions.ServiceError as exc:
            outcome = f"refused ({error(exc)})"
        report("M11", "update straight after the create", outcome)
        report("M11", "seconds until ACTIVE", round(self.settle(secret.id), 1))

        self.update(secret.id, secret_content=content("probe-2"))
        self.update(secret.id, secret_content=content("probe-3"))
        when = datetime.now(UTC) + timedelta(days=1, hours=1)
        self.vaults.schedule_secret_version_deletion(
            secret.id,
            1,
            oci.vault.models.ScheduleSecretVersionDeletionDetails(time_of_deletion=when),
        )
        report("M11", "state straight after scheduling a version's deletion", self.state(secret.id))
        report("M11", "seconds until ACTIVE", round(self.settle(secret.id), 1))
        versions = oci.pagination.list_call_get_all_results(
            self.vaults.list_secret_versions, secret.id
        ).data
        report(
            "M11",
            "time_of_deletion per version",
            {v.version_number: v.time_of_deletion is not None for v in versions},
        )

    def m12_metadata(self) -> None:
        """Which metadata values OCI accepts, and what comes back."""
        secret = self.create(self.name())
        values: list[tuple[str, object]] = [
            ("string of 1,000 characters", "x" * 1000),
            ("string of 4,000 characters", "x" * 4000),
            ("string of 16,000 characters", "x" * 16000),
            ("list", ["appdb-alpha", "appdb-beta"]),
            ("nested object", {"host": "app01.example.com", "pid": 4242}),
            ("integer", 7),
        ]
        for label, value in values:
            try:
                self.update(secret.id, metadata={"sopuli_probe": value})
            except oci.exceptions.ServiceError as exc:
                report("M12", label, f"refused ({error(exc)})")
                continue
            data, _ = self.get(secret.id)
            back = (data.metadata or {}).get("sopuli_probe")
            same = "the same" if back == value else f"changed to {type(back).__name__}"
            report("M12", label, f"accepted; read back {same}")
        bundle = self.secrets.get_secret_bundle_by_name(secret.secret_name, VAULT_ID).data
        report("M12", "bundle read carries the metadata", bundle.metadata is not None)

    def m13_read_while_updating(self) -> None:
        """Does a read during UPDATING see the old version or the new one?"""
        name = self.name()
        secret = self.create(name)
        self.vaults.update_secret(
            secret.id, oci.vault.models.UpdateSecretDetails(secret_content=content("probe-2"))
        )
        report("M13", "state", self.state(secret.id))
        report("M13", "read with no stage while updating", self.bundle(name))
        self.settle(secret.id)
        report("M13", "read with no stage once ACTIVE", self.bundle(name))

    # -------------------------------------------------------------- cleanup ---

    def cleanup(self) -> None:
        when = datetime.now(UTC) + timedelta(days=1, hours=1)
        scheduled = 0
        for secret_id in created:
            try:
                self.settle(secret_id)
                self.vaults.schedule_secret_deletion(
                    secret_id,
                    oci.vault.models.ScheduleSecretDeletionDetails(time_of_deletion=when),
                )
                scheduled += 1
            except (oci.exceptions.ServiceError, RuntimeError) as exc:
                print(f"cleanup: could not schedule deletion of {secret_id}: {exc}")
        print(f"cleanup: scheduled deletion of {scheduled} of {len(created)} secrets")


def main() -> int:
    missing = [
        name
        for name, value in (
            ("OCI_PROBE_VAULT_ID", VAULT_ID),
            ("OCI_PROBE_COMPARTMENT_ID", COMPARTMENT_ID),
            ("OCI_PROBE_KEY_ID", KEY_ID),
        )
        if not value
    ]
    if missing:
        print(f"set {', '.join(missing)} first", file=sys.stderr)
        return 2

    probe = Probe()
    print(f"run {RUN}, oci SDK {oci.__version__}, profile {PROFILE}")
    checks: list[Callable[[], None]] = [
        probe.m1_names,
        probe.m1b_characters,
        probe.m2_pending,
        probe.m3_etag,
        probe.m4_updating,
        probe.m5_promote,
        probe.m6_replace_pending,
        probe.m7_versions,
        probe.m9_create_pending,
        probe.m10_create_taken,
        probe.m11_states,
        probe.m12_metadata,
        probe.m13_read_while_updating,
    ]
    wanted = {one.lower() for one in sys.argv[1:]}
    if wanted:
        checks = [check for check in checks if check.__name__.split("_")[0] in wanted]
    try:
        for check in checks:
            try:
                check()
            except (oci.exceptions.ServiceError, RuntimeError) as exc:
                print(f"{check.__name__} stopped: {exc}")
    finally:
        probe.cleanup()
    return 0


if __name__ == "__main__":
    sys.exit(main())
