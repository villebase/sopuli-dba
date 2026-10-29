"""The OCI store writes an application secret (#1133).

Tier 0, against ``tests/store/oci_fake.py``, whose answers were measured in
#1136 and #1151.
"""

from __future__ import annotations

import base64
import json
from contextlib import contextmanager
from typing import Any

import oci
import pytest
from oci_fake import COMPARTMENT_ID, KEY_ID, VAULT_ID, FakeOci, FakeSecret, refused

from sopuli.config.model import Vault
from sopuli.store.oci import OciStore
from sopuli.store.oci._errors import OciUnavailableError
from sopuli.store.oci._names import CAS_KEY
from sopuli.store.oci.store import POLL_S
from sopuli.store.protocol import CasConflictError, StoreError
from sopuli.store.waiting import showing


class Clock:
    """``monotonic`` and ``sleep`` for the store: sleeping moves the clock."""

    def __init__(self) -> None:
        self.now = 0.0
        self.sleeps: list[float] = []

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


@pytest.fixture
def fake() -> FakeOci:
    return FakeOci()


@pytest.fixture
def clock() -> Clock:
    return Clock()


def store(fake: FakeOci, clock: Clock, *, timeout_s: int | None = None) -> OciStore:
    entry = Vault(
        name="vault-oci",
        type="oci",
        vault_id=VAULT_ID,
        compartment_id=COMPARTMENT_ID,
        key_id=KEY_ID,
        timeout_s=timeout_s,
    )
    return OciStore(
        entry, vaults=fake, secrets=fake, kms=fake, sleep=clock.sleep, monotonic=clock.monotonic
    )


def decoded(details: Any) -> Any:
    return json.loads(base64.b64decode(details.secret_content.content))


# ----------------------------------------------------------------- create ---


def test_a_write_creates_an_absent_secret_at_token_one(fake: FakeOci, clock: Clock) -> None:
    oci_store = store(fake, clock)

    assert oci_store.write("acme-db", {"password": "a"}, cas=0) == 1

    details = fake.created[0]
    assert (details.compartment_id, details.vault_id, details.key_id) == (
        COMPARTMENT_ID,
        VAULT_ID,
        KEY_ID,
    )
    assert details.secret_name == "acme-db"
    assert details.metadata == {CAS_KEY: "1"}
    assert decoded(details) == {"password": "a"}
    stored = oci_store.read("acme-db")
    assert stored is not None
    assert (stored.data, stored.version) == ({"password": "a"}, 1)


def test_a_nonzero_cas_on_an_absent_secret_conflicts(fake: FakeOci, clock: Clock) -> None:
    with pytest.raises(CasConflictError, match="found nothing"):
        store(fake, clock).write("acme-db", {"password": "a"}, cas=3)

    assert fake.created == []


def test_a_create_race_is_a_cas_conflict(fake: FakeOci, clock: Clock) -> None:
    """OCI answers 400, not 409, for a taken name (`oci-create-taken`)."""
    fake.before_create = lambda name: fake.put(name, {"password": "theirs"})

    with pytest.raises(CasConflictError, match="another writer"):
        store(fake, clock).write("acme-db", {"password": "a"}, cas=0)


def test_a_name_held_by_a_secret_being_deleted_is_refused_with_that_reason(
    fake: FakeOci, clock: Clock
) -> None:
    fake.put("acme-db", {"password": "old"}, lifecycle_state="PENDING_DELETION")

    with pytest.raises(StoreError, match="scheduled for deletion") as caught:
        store(fake, clock).write("acme-db", {"password": "a"}, cas=0)

    assert not isinstance(caught.value, CasConflictError)


# ----------------------------------------------------------------- update ---


def test_a_write_updates_under_the_etag_and_moves_the_token(fake: FakeOci, clock: Clock) -> None:
    fake.put("acme-db", {"password": "a"}, metadata={CAS_KEY: "4", "targets": ["appdb-alpha"]})
    etag = str(fake.secrets["acme-db"].etag)

    assert store(fake, clock).write("acme-db", {"password": "b"}, cas=4) == 5

    _, details, if_match = fake.updates[0]
    assert if_match == etag
    assert details.metadata == {CAS_KEY: "5", "targets": ["appdb-alpha"]}
    assert decoded(details) == {"password": "b"}


def test_the_new_version_is_current_and_the_old_one_previous(fake: FakeOci, clock: Clock) -> None:
    fake.put("acme-db", {"password": "a"})
    oci_store = store(fake, clock)

    oci_store.write("acme-db", {"password": "b"}, cas=1)

    stored = oci_store.read("acme-db")
    assert stored is not None
    assert (stored.data, stored.generation, stored.version) == ({"password": "b"}, 2, 2)
    previous = oci_store.read_stage("acme-db", "previous")
    assert previous is not None
    assert previous.data == {"password": "a"}


def test_a_stale_token_conflicts_before_anything_is_sent(fake: FakeOci, clock: Clock) -> None:
    fake.put("acme-db", {"password": "a"}, metadata={CAS_KEY: "4"})

    with pytest.raises(CasConflictError, match="expected version 3, found 4"):
        store(fake, clock).write("acme-db", {"password": "b"}, cas=3)

    assert fake.updates == []


def test_cas_zero_on_an_existing_secret_conflicts(fake: FakeOci, clock: Clock) -> None:
    fake.put("acme-db", {"password": "a"})

    with pytest.raises(CasConflictError):
        store(fake, clock).write("acme-db", {"password": "b"}, cas=0)


def test_a_foreign_secret_is_written_from_token_one(fake: FakeOci, clock: Clock) -> None:
    """Decision 6: a secret the tool did not create has no counter, and reads at 1."""
    fake.put("acme-db", {"password": "a"})

    assert store(fake, clock).write("acme-db", {"password": "b"}, cas=1) == 2


def test_a_stale_etag_is_a_cas_conflict(fake: FakeOci, clock: Clock) -> None:
    """Another writer between this run's GetSecret and its UpdateSecret: it
    moved the counter, and the secret is busy with its write."""
    fake.put("acme-db", {"password": "a"})

    def other_writer(secret: FakeSecret) -> None:
        secret.etag += 1
        secret.metadata[CAS_KEY] = "2"

    fake.before_update = other_writer

    with pytest.raises(CasConflictError):
        store(fake, clock).write("acme-db", {"password": "b"}, cas=1)


def test_an_etag_that_moved_with_nothing_else_is_retried(fake: FakeOci, clock: Clock) -> None:
    """`oci-etag-settle`: OCI moves the ETag a few seconds after ACTIVE, with
    no field changing. Still ACTIVE and unchanged means no write landed."""
    fake.put("acme-db", {"password": "a"})
    once: list[bool] = []

    def churn(secret: FakeSecret) -> None:
        if not once:
            once.append(True)
            secret.etag += 1

    fake.before_update = churn

    assert store(fake, clock).write("acme-db", {"password": "b"}, cas=1) == 2
    assert [if_match for _, _, if_match in fake.updates] == ["1", "2"]


def test_an_etag_that_keeps_moving_gives_up(fake: FakeOci, clock: Clock) -> None:
    fake.put("acme-db", {"password": "a"})

    def churn(secret: FakeSecret) -> None:
        secret.etag += 1

    fake.before_update = churn

    with pytest.raises(CasConflictError, match="changing ETag"):
        store(fake, clock).write("acme-db", {"password": "b"}, cas=1)

    assert len(fake.updates) == 4


def test_a_moved_etag_on_a_busy_secret_is_a_conflict(fake: FakeOci, clock: Clock) -> None:
    """Busy means a write was accepted since the first read, whatever it changed:
    the same ETag is sent again once it settles, and its Conflict is final."""
    fake.put("acme-db", {"password": "a"})
    once: list[bool] = []

    def other_writer(secret: FakeSecret) -> None:
        if not once:
            once.append(True)
            secret.etag += 1
            secret.lifecycle_state = "UPDATING"
            secret.busy = 2

    fake.before_update = other_writer

    with pytest.raises(CasConflictError):
        store(fake, clock).write("acme-db", {"password": "b"}, cas=1)


def test_a_moved_etag_found_too_late_is_a_conflict(fake: FakeOci, clock: Clock) -> None:
    """Past the window, an ACTIVE secret no longer proves that nothing was written."""
    fake.put("acme-db", {"password": "a"})

    def slow(secret: FakeSecret) -> None:
        secret.etag += 1
        clock.now += 20

    fake.before_update = slow

    with pytest.raises(CasConflictError):
        store(fake, clock).write("acme-db", {"password": "b"}, cas=1)


def test_a_409_that_is_neither_conflict_nor_busy_is_not_retried(
    fake: FakeOci, clock: Clock
) -> None:
    fake.put("acme-db", {"password": "a"})

    def other(secret: FakeSecret) -> None:
        secret.etag += 1
        raise refused(409, "NotAllowed", "Not allowed")

    fake.before_update = other

    with pytest.raises(StoreError, match="409 NotAllowed"):
        store(fake, clock).write("acme-db", {"password": "b"}, cas=1)

    assert len(fake.updates) == 1


def test_a_secret_busy_every_time_says_so(fake: FakeOci, clock: Clock) -> None:
    fake.put("acme-db", {"password": "a"})

    def busy(secret: FakeSecret) -> None:
        secret.lifecycle_state = "UPDATING"
        secret.busy = 1

    fake.before_update = busy

    with pytest.raises(OciUnavailableError, match="busy with other writes"):
        store(fake, clock).write("acme-db", {"password": "b"}, cas=1)


def test_an_unguarded_write_after_another_writer_moves_the_counter_on(
    fake: FakeOci, clock: Clock
) -> None:
    """Built from the old read, the counter would repeat the other writer's."""
    fake.put("acme-db", {"password": "a"}, metadata={CAS_KEY: "1"})
    once: list[bool] = []

    def other_writer(secret: FakeSecret) -> None:
        if not once:
            once.append(True)
            secret.metadata = {CAS_KEY: "2", "theirs": "kept"}
            secret.lifecycle_state = "UPDATING"
            secret.busy = 1

    fake.before_update = other_writer

    assert store(fake, clock).write("acme-db", {"password": "b"}, cas=None) == 3
    assert fake.secrets["acme-db"].metadata == {CAS_KEY: "3", "theirs": "kept"}


def test_a_write_after_a_read_does_not_list_the_secrets_again(fake: FakeOci, clock: Clock) -> None:
    """OCI throttles; the read already gave the secret's id."""
    fake.put("acme-db", {"password": "a"})
    oci_store = store(fake, clock)
    oci_store.read("acme-db")
    fake.calls.clear()

    oci_store.write("acme-db", {"password": "b"}, cas=1)

    assert "list_secrets" not in fake.calls


def test_a_remembered_secret_being_deleted_is_looked_up_again(fake: FakeOci, clock: Clock) -> None:
    secret = fake.put("acme-db", {"password": "a"})
    oci_store = store(fake, clock)
    oci_store.read("acme-db")
    secret.lifecycle_state = "PENDING_DELETION"

    with pytest.raises(StoreError, match="scheduled for deletion"):
        oci_store.write("acme-db", {"password": "b"}, cas=0)


def test_an_unguarded_write_sends_no_etag(fake: FakeOci, clock: Clock) -> None:
    fake.put("acme-db", {"password": "a"})

    assert store(fake, clock).write("acme-db", {"password": "b"}, cas=None) == 2
    assert fake.updates[0][2] is None


def test_an_unguarded_create_that_loses_the_race_updates(fake: FakeOci, clock: Clock) -> None:
    fake.before_create = lambda name: fake.put(name, {"password": "theirs"})

    assert store(fake, clock).write("acme-db", {"password": "mine"}, cas=None) == 2
    assert store(fake, clock).read("acme-db").data == {"password": "mine"}  # type: ignore[union-attr]


def test_a_name_taken_outside_the_compartment_says_so(fake: FakeOci, clock: Clock) -> None:
    def elsewhere(name: str) -> None:
        raise refused(400, "InvalidParameter", "name already exists")

    fake.before_create = elsewhere

    with pytest.raises(StoreError, match="no secret of that name is in the store's compartment"):
        store(fake, clock).write("acme-db", {"password": "a"}, cas=0)


def test_a_400_that_did_not_come_from_oci_is_not_read_as_a_taken_name(
    fake: FakeOci, clock: Clock
) -> None:
    def proxy(name: str) -> None:
        raise oci.exceptions.ServiceError(400, "InvalidParameter", {}, "name already exists")

    fake.before_create = proxy

    with pytest.raises(OciUnavailableError, match="did not come from OCI"):
        store(fake, clock).write("acme-db", {"password": "a"}, cas=0)


def test_an_update_with_no_answer_may_have_been_made(fake: FakeOci, clock: Clock) -> None:
    fake.put("acme-db", {"password": "a"})

    def timeout(secret: FakeSecret) -> None:
        raise oci.exceptions.RequestException("read timed out")

    fake.before_update = timeout

    with pytest.raises(OciUnavailableError, match="the write may have been made"):
        store(fake, clock).write("acme-db", {"password": "b"}, cas=1)


def test_a_refused_write_does_not_quote_the_content(fake: FakeOci, clock: Clock) -> None:
    fake.put("acme-db", {"password": "a"})

    def refuse(secret: FakeSecret) -> None:
        raise refused(400, "InvalidParameter", "secretContent is not valid")

    fake.before_update = refuse

    with pytest.raises(StoreError) as caught:
        store(fake, clock).write("acme-db", {"password": "s3cret-value"}, cas=1)

    chain: list[BaseException] = []
    exc: BaseException | None = caught.value
    while exc is not None:
        chain.append(exc)
        exc = exc.__cause__ or exc.__context__
    assert "400 InvalidParameter" in str(caught.value)
    assert not any("s3cret-value" in f"{one!s} {one!r}" for one in chain)


def test_patch_is_refused(fake: FakeOci, clock: Clock) -> None:
    with pytest.raises(StoreError, match="no merge patch"):
        store(fake, clock).patch("acme-db", {"password": "b"}, cas=1)


def test_metadata_over_oci_s_limit_is_refused_before_it_is_sent(
    fake: FakeOci, clock: Clock
) -> None:
    """`oci-metadata-limits`: about 5,100 characters for the whole map."""
    fake.put("acme-db", {"password": "a"}, metadata={"terraform_note": "x" * 5100})

    with pytest.raises(StoreError, match="metadata would be"):
        store(fake, clock).write("acme-db", {"password": "b"}, cas=1)

    assert fake.updates == []


# ------------------------------------------------------------------- wait ---


def test_the_write_waits_for_active_after_writing(fake: FakeOci, clock: Clock) -> None:
    """A read while UPDATING returns the old content (`oci-read-while-updating`)."""
    fake.settle_polls = 3
    fake.put("acme-db", {"password": "a"})

    store(fake, clock).write("acme-db", {"password": "b"}, cas=1)

    assert fake.secrets["acme-db"].lifecycle_state == "ACTIVE"
    assert clock.sleeps == [POLL_S] * 3


def test_a_create_waits_for_active(fake: FakeOci, clock: Clock) -> None:
    store(fake, clock).write("acme-db", {"password": "a"}, cas=0)

    assert fake.secrets["acme-db"].lifecycle_state == "ACTIVE"
    assert clock.sleeps == [POLL_S] * 2


def test_a_secret_already_updating_is_waited_for_before_the_write(
    fake: FakeOci, clock: Clock
) -> None:
    secret = fake.put("acme-db", {"password": "a"}, lifecycle_state="UPDATING")
    secret.busy = 2

    assert store(fake, clock).write("acme-db", {"password": "b"}, cas=1) == 2
    assert len(fake.updates) == 1
    # Three reads before the update and three after: the first answer that
    # found it busy is the wait's first poll, not read again.
    assert fake.calls.count("get_secret") == 6


def test_incorrect_state_at_the_update_waits_and_retries_once(fake: FakeOci, clock: Clock) -> None:
    fake.put("acme-db", {"password": "a"})
    once: list[bool] = []

    def other_writer_starts(secret: FakeSecret) -> None:
        if not once:
            once.append(True)
            secret.lifecycle_state = "UPDATING"
            secret.busy = 1

    fake.before_update = other_writer_starts

    assert store(fake, clock).write("acme-db", {"password": "b"}, cas=1) == 2
    assert len(fake.updates) == 2


def test_the_wait_gives_up_after_timeout_s_and_says_the_write_was_made(
    fake: FakeOci, clock: Clock
) -> None:
    fake.settle_polls = 1000
    fake.put("acme-db", {"password": "a"})

    with pytest.raises(OciUnavailableError, match="the write was made") as caught:
        store(fake, clock, timeout_s=10).write("acme-db", {"password": "b"}, cas=1)

    assert "acme-db" in str(caught.value)
    assert caught.value.hint is not None
    assert "timeout_s" in caught.value.hint
    assert clock.now == 10


def test_a_secret_that_failed_is_not_waited_for(fake: FakeOci, clock: Clock) -> None:
    fake.put("acme-db", {"password": "a"}, lifecycle_state="FAILED")

    with pytest.raises(StoreError, match="is FAILED, so it cannot be written"):
        store(fake, clock).write("acme-db", {"password": "b"}, cas=1)

    assert clock.sleeps == []


def test_a_throttled_poll_is_waited_out(fake: FakeOci, clock: Clock) -> None:
    """A real run met `429 TooManyRequests` on the first poll after a write."""
    fake.put("acme-db", {"password": "a"})
    throttled: list[bool] = []

    def throttle(secret: FakeSecret) -> None:
        if secret.busy and not throttled:
            throttled.append(True)
            raise refused(429, "TooManyRequests", "User-rate limit exceeded.")

    fake.before_get = throttle

    assert store(fake, clock).write("acme-db", {"password": "b"}, cas=1) == 2
    assert clock.sleeps[0] == 2 * POLL_S


def test_an_error_while_waiting_after_a_write_says_the_write_was_made(
    fake: FakeOci, clock: Clock
) -> None:
    fake.put("acme-db", {"password": "a"})

    def fail(secret: FakeSecret) -> None:
        if secret.busy:
            raise refused(500, "InternalServerError", "Internal error")

    fake.before_get = fail

    with pytest.raises(OciUnavailableError, match="the write was made, and waiting for it failed"):
        store(fake, clock).write("acme-db", {"password": "b"}, cas=1)


def test_a_secret_gone_while_waiting_after_a_write_reads_whole(fake: FakeOci, clock: Clock) -> None:
    """A 404 message has no ': ' after the subject, and must not be cut apart."""
    fake.put("acme-db", {"password": "a"})

    def gone(secret: FakeSecret) -> None:
        if secret.busy:
            raise refused(404, "NotAuthorizedOrNotFound", "not found")

    fake.before_get = gone

    with pytest.raises(StoreError) as caught:
        store(fake, clock).write("acme-db", {"password": "b"}, cas=1)

    assert caught.value.message.startswith(
        'secret "acme-db" in vault "vault-oci": the write was made, and waiting for it failed. '
        'secret "acme-db" in vault "vault-oci" was not found'
    )


def test_a_secret_that_fails_after_the_write_says_the_write_was_made(
    fake: FakeOci, clock: Clock
) -> None:
    fake.put("acme-db", {"password": "a"})
    fake.final_state = "FAILED"

    with pytest.raises(StoreError, match="the write was made, and the secret is FAILED$"):
        store(fake, clock).write("acme-db", {"password": "b"}, cas=1)


def test_the_wait_shows_a_notice_naming_the_secret(fake: FakeOci, clock: Clock) -> None:
    fake.put("acme-db", {"password": "a"})
    shown: list[str] = []

    @contextmanager
    def notice(message: str) -> Any:
        shown.append(message)
        yield

    with showing(notice):
        store(fake, clock).write("acme-db", {"password": "b"}, cas=1)
    store(fake, clock).write("acme-db", {"password": "c"}, cas=2)

    assert len(shown) == 1
    assert "acme-db" in shown[0]
