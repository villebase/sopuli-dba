"""UC-1's documents over a native-staging store (#1158).

Tier 0, against ``MemoryStore`` with ``staging_labels``, which models OCI's
measured stage moves. Writes go through ``credentials.apply_patch``, the path
the verbs use, with the patches the verbs build: a ``pending`` and an
``origin`` to stage, and the promotion patch's fields to promote.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from sopuli.config.secret_refs import parse_secret_ref
from sopuli.payload import CURRENT, ORIGIN, PENDING, PREVIOUS, REMOVE, StageLayout, merge
from sopuli.store import MemoryStore
from sopuli.store.credentials import READ_MODIFY_WRITE, apply_patch, resolve
from sopuli.store.native_view import (
    NATIVE,
    PENDING_VERSION,
    LayoutChangedError,
    NativeStagedStore,
)
from sopuli.store.protocol import CAS, LIST, STAGING, VERSIONING, CasConflictError

PATH = "acme-db"
LAYOUT = StageLayout("password")
NOW = datetime(2026, 10, 29, 12, 0, tzinfo=UTC)


@pytest.fixture
def inner() -> MemoryStore:
    return MemoryStore(capabilities=frozenset({CAS, LIST, VERSIONING, STAGING}))


@pytest.fixture
def view(inner: MemoryStore) -> NativeStagedStore:
    return NativeStagedStore(
        inner,
        native=lambda path: LAYOUT if path == PATH else None,
        by="svc_sopuli@ci-runner-3",
        now=lambda: NOW,
    )


def stages(inner: MemoryStore) -> dict[str, int | None]:
    found = {}
    for stage in ("current", "pending", "previous"):
        stored = inner.read_stage(PATH, stage)
        found[stage] = None if stored is None else stored.generation
    return found


def token(view: NativeStagedStore) -> int:
    stored = view.read(PATH)
    assert stored is not None
    return stored.version


def stage_patch(value: str) -> dict[str, Any]:
    """What `DocumentWrite.patch(stage=PENDING)` sends."""
    return merge(LAYOUT.patch(PENDING, value), LAYOUT.patch(ORIGIN, "generated"))


def promotion(value: str, replaces: str | None, **stamps: Any) -> dict[str, Any]:
    """What `apply.promotion_patch` sends for one account."""
    patches = [
        LAYOUT.patch(CURRENT, value),
        LAYOUT.patch(PENDING, REMOVE),
        LAYOUT.patch(ORIGIN, REMOVE),
        *(LAYOUT.patch(key, stamp) for key, stamp in stamps.items()),
    ]
    if replaces is not None:
        patches.append(LAYOUT.patch(PREVIOUS, replaces))
    return merge(*patches)


def seeded(view: NativeStagedStore) -> None:
    """A secret with a current password, as `creds generate --promote` leaves it."""
    apply_patch(view, PATH, LAYOUT.patch(CURRENT, "a"), cas=0)


# ------------------------------------------------------------------ reading ---


def test_a_native_read_shows_current_in_the_field(
    view: NativeStagedStore, inner: MemoryStore
) -> None:
    seeded(view)

    stored = view.read(PATH)

    assert stored is not None
    assert stored.data == {"password": "a"}
    assert stored.generation == 1
    current = inner.read_stage(PATH, "current")
    assert current is not None
    assert current.data["generated_by"] == "svc_sopuli@ci-runner-3"


def test_a_live_pending_is_shown_with_its_origin(
    view: NativeStagedStore, inner: MemoryStore
) -> None:
    seeded(view)
    inner.stage(
        PATH,
        {"password": "b", "origin": "generated"},
        attributes={PENDING_VERSION: 2},
        cas=token(view),
    )

    stored = view.read(PATH)

    assert stored is not None
    assert stored.data == {"password": "a", "pending": "b", "origin": "generated"}


def test_a_pending_that_is_not_the_recorded_one_is_not_a_pending(
    view: NativeStagedStore, inner: MemoryStore
) -> None:
    seeded(view)
    inner.stage(PATH, {"password": "b"}, attributes={PENDING_VERSION: 7}, cas=token(view))

    stored = view.read(PATH)

    assert stored is not None
    assert stored.data == {"password": "a"}


def test_a_pinned_old_generation_reads_at_token_zero(view: NativeStagedStore) -> None:
    seeded(view)
    apply_patch(view, PATH, stage_patch("b"), cas=token(view))
    apply_patch(view, PATH, promotion("b", "a"), cas=token(view))

    stored = view.read(PATH, version=1)

    assert stored is not None
    assert (stored.data, stored.version) == ({"password": "a"}, 0)


def test_a_path_that_is_not_native_passes_through(
    view: NativeStagedStore, inner: MemoryStore
) -> None:
    view.write("locks/acme-db", {"state": "held"}, cas=0)
    view.write("acme-dw", {"password": "x", "pending": "y"}, cas=0)

    lock = inner.read("locks/acme-db")
    other = view.read("acme-dw")
    assert lock is not None
    assert lock.data == {"state": "held"}
    assert other is not None
    assert other.data == {"password": "x", "pending": "y"}


def test_resolve_reads_every_stage_through_the_view(view: NativeStagedStore) -> None:
    """The readers need no change: `@stage=` resolves against the assembled document."""
    seeded(view)
    apply_patch(view, PATH, stage_patch("b"), cas=token(view))
    apply_patch(view, PATH, promotion("b", "a"), cas=token(view))
    apply_patch(view, PATH, stage_patch("c"), cas=token(view))
    stored = view.read(PATH)
    assert stored is not None

    def at(stage: str) -> str:
        found = resolve(stored.data, parse_secret_ref(f"acme-db#password@stage={stage}"))
        assert found is not None
        return found.reveal()

    assert (at("current"), at("pending"), at("previous")) == ("b", "c", "a")


# ------------------------------------------------------------------ writing ---


def test_the_first_write_creates_the_secret(view: NativeStagedStore, inner: MemoryStore) -> None:
    written = apply_patch(view, PATH, LAYOUT.patch(CURRENT, "a"), cas=0)

    assert written.mechanism == NATIVE
    assert stages(inner) == {"current": 1, "pending": None, "previous": None}


def test_staging_into_a_new_secret_starts_from_an_empty_current(
    view: NativeStagedStore, inner: MemoryStore
) -> None:
    """OCI cannot hold a PENDING-only secret; an empty CURRENT reads as none."""
    apply_patch(view, PATH, stage_patch("a"), cas=0)

    assert stages(inner) == {"current": 1, "pending": 2, "previous": None}
    stored = view.read(PATH)
    assert stored is not None
    assert stored.data == {"pending": "a", "origin": "generated"}


def test_staging_a_pending_is_a_native_stage(view: NativeStagedStore, inner: MemoryStore) -> None:
    seeded(view)

    apply_patch(view, PATH, stage_patch("b"), cas=token(view))

    assert stages(inner) == {"current": 1, "pending": 2, "previous": None}
    current = inner.read(PATH)
    assert current is not None
    assert current.data["password"] == "a"
    assert current.attributes[PENDING_VERSION] == 2


def test_promoting_the_pending_is_a_native_promotion(
    view: NativeStagedStore, inner: MemoryStore
) -> None:
    seeded(view)
    apply_patch(view, PATH, stage_patch("b"), cas=token(view))

    apply_patch(
        view,
        PATH,
        promotion(
            "b", "a", rotated_at="2026-10-29T12:00:00Z", rotated_by="x", targets=["appdb-alpha"]
        ),
        cas=token(view),
    )

    assert stages(inner) == {"current": 2, "pending": None, "previous": 1}
    current = inner.read(PATH)
    assert current is not None
    assert dict(current.attributes) == {
        "rotated_at": "2026-10-29T12:00:00Z",
        "rotated_by": "x",
        "targets": ["appdb-alpha"],
    }


def test_a_rollback_promotes_previous_by_number(
    view: NativeStagedStore, inner: MemoryStore
) -> None:
    seeded(view)
    apply_patch(view, PATH, stage_patch("b"), cas=token(view))
    apply_patch(view, PATH, promotion("b", "a"), cas=token(view))

    apply_patch(view, PATH, promotion("a", "b", rotated_by="y"), cas=token(view))

    assert stages(inner) == {"current": 1, "pending": None, "previous": 2}
    assert len(inner.paths[PATH].generations) == 2


def test_a_new_current_over_a_pending_clears_it(
    view: NativeStagedStore, inner: MemoryStore
) -> None:
    """`creds generate --promote` over a live pending."""
    seeded(view)
    apply_patch(view, PATH, stage_patch("b"), cas=token(view))

    apply_patch(view, PATH, promotion("c", "a"), cas=token(view))

    stored = view.read(PATH)
    assert stored is not None
    assert stored.data == {"password": "c", "previous": "a"}
    current = inner.read(PATH)
    assert current is not None
    assert PENDING_VERSION not in current.attributes


def test_stamps_alone_are_an_attributes_only_promotion(
    view: NativeStagedStore, inner: MemoryStore
) -> None:
    seeded(view)

    apply_patch(view, PATH, LAYOUT.patch("targets", ["appdb-beta"]), cas=token(view))

    assert stages(inner) == {"current": 1, "pending": None, "previous": None}
    current = inner.read(PATH)
    assert current is not None
    assert current.attributes["targets"] == ["appdb-beta"]


def test_a_stale_token_still_conflicts(view: NativeStagedStore) -> None:
    seeded(view)
    stale = token(view)
    apply_patch(view, PATH, stage_patch("b"), cas=stale)

    with pytest.raises(CasConflictError):
        apply_patch(view, PATH, stage_patch("c"), cas=stale)


def test_payload_stages_in_a_native_secret_are_a_layout_change(
    view: NativeStagedStore, inner: MemoryStore
) -> None:
    """A secret staged in payload fields by an older build, now used natively."""
    inner.write(PATH, {"password": "a", "pending": "b", "origin": "generated"}, cas=0)

    with pytest.raises(LayoutChangedError, match="finish or discard"):
        view.read(PATH)
    with pytest.raises(LayoutChangedError):
        view.write(PATH, {"password": "a"}, cas=1)


def test_a_write_outside_the_view_is_read_modify_write(view: NativeStagedStore) -> None:
    written = apply_patch(view, "acme-dw", {"password": "x"}, cas=0)

    assert written.mechanism == READ_MODIFY_WRITE
