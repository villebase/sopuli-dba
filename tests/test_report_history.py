"""One account's rotation history, from a store's versions (UC-5 §6). Tier 0.

The property worth the most here is the anti-goal: a history must never look
complete when it is not. A version the store lists and nobody could read is a
gap, and the oldest version kept is never presented as the first rotation.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sopuli import report_history as history
from sopuli.config.model import Binding
from sopuli.config.secret_refs import parse_secret_ref
from sopuli.driver.protocol import UserState
from sopuli.secrets import Secret
from sopuli.store.protocol import VersionHistory, VersionInfo

TARGET = "appdb-dev-alpha"
REF = "apps/acme/db#DB_CREDENTIALS/{account}"


def at(day: int, hour: int = 3) -> datetime:
    return datetime(2026, 11, day, hour, 0, tzinfo=UTC)


def stamp(day: int, hour: int = 3) -> str:
    return at(day, hour).isoformat().replace("+00:00", "Z")


def binding(account: str = "acme_web_user", ref: str = REF) -> Binding:
    return Binding(
        account=account,
        target=TARGET,
        secret=parse_secret_ref(ref.replace("{account}", account)),
        vault="vault-dev",
    )


def listed(
    *numbers: int, deleted: tuple[int, ...] = (), destroyed: tuple[int, ...] = ()
) -> VersionHistory:
    return VersionHistory(
        current=max(numbers) if numbers else 0,
        oldest_kept=min(numbers) if numbers else None,
        versions=tuple(
            VersionInfo(n, at(n, 1), n in deleted, n in destroyed) for n in sorted(numbers)
        ),
    )


def shared(rotated: dict[str, str] | None, by: dict[str, str] | None = None) -> dict[str, Any]:
    document: dict[str, Any] = {
        "DB_CREDENTIALS": {"acme_web_user": Secret("live"), "acme_batch_user": Secret("other")}
    }
    if rotated is not None:
        document["rotated_at"] = rotated
    if by is not None:
        document["rotated_by"] = by
    return document


def app(target: str, bound: Binding, *args: Any, **kwargs: Any) -> history.AccountHistory:
    """`application` on a store that keeps versions, unless a test says not."""
    kwargs.setdefault("versioning", True)
    return history.application(target, bound, *args, **kwargs)


def pers(target: str, account: str, *args: Any, **kwargs: Any) -> history.AccountHistory:
    kwargs.setdefault("versioning", True)
    return history.personal(target, account, *args, **kwargs)


# --------------------------------------------------------- application ---


def test_each_change_of_the_accounts_own_stamp_is_a_rotation_newest_first() -> None:
    documents = {
        1: shared({"acme_web_user": stamp(1)}, {"acme_web_user": "ville"}),
        # `pending` staged: the stamp does not move, so no rotation.
        2: shared({"acme_web_user": stamp(1)}, {"acme_web_user": "ville"}),
        3: shared({"acme_web_user": stamp(3)}, {"acme_web_user": "jdoe"}),
    }

    found = app(TARGET, binding(), listed(1, 2, 3), documents)

    assert [(e.at, e.by, e.version) for e in found.events] == [
        (at(3), "jdoe", 3),
        (at(1), "ville", 1),
    ]
    assert all(e.kind == history.ROTATION for e in found.events)
    assert found.complete


def test_another_accounts_rotation_in_a_shared_document_is_not_this_ones() -> None:
    documents = {
        1: shared({"acme_web_user": stamp(1), "acme_batch_user": stamp(1)}),
        2: shared({"acme_web_user": stamp(1), "acme_batch_user": stamp(2)}),
    }

    found = app(TARGET, binding(), listed(1, 2), documents)

    assert [e.version for e in found.events] == [1]


def test_a_single_account_document_reads_the_root_stamp() -> None:
    documents = {
        1: {"password": Secret("a"), "rotated_at": stamp(1), "rotated_by": "ville"},
        2: {"password": Secret("b"), "rotated_at": stamp(2), "rotated_by": "ville"},
    }

    found = app(TARGET, binding(ref="apps/acme/web#password"), listed(1, 2), documents)

    assert [e.at for e in found.events] == [at(2), at(1)]


def test_where_the_history_starts_is_said_and_counts_what_is_gone() -> None:
    documents = {
        4: shared({"acme_web_user": stamp(3)}),
        5: shared({"acme_web_user": stamp(5)}),
    }

    found = app(TARGET, binding(), listed(4, 5), documents)

    assert found.start == history.Start(version=4, at=at(4, 1), gone=3)
    # The stamp the oldest kept version carries is listed: it is a real
    # rotation, even if the version that first wrote it is gone.
    assert [e.at for e in found.events] == [at(5), at(3)]
    assert found.complete


def test_a_deleted_or_destroyed_version_is_a_gap_and_not_checked() -> None:
    documents = {
        1: shared({"acme_web_user": stamp(1)}),
        3: shared({"acme_web_user": stamp(3)}),
    }

    found = app(TARGET, binding(), listed(1, 2, 3, destroyed=(2,)), documents)

    assert found.unread == (2,)
    assert not found.complete
    assert "version 2" in found.reasons[0]


def test_a_listed_version_with_no_document_is_a_gap() -> None:
    documents = {1: shared({"acme_web_user": stamp(1)})}

    found = app(TARGET, binding(), listed(1, 2), documents)

    assert found.unread == (2,)
    assert not found.complete


def test_a_malformed_stamp_is_a_gap_not_a_crash() -> None:
    documents = {
        1: shared({"acme_web_user": stamp(1)}),
        2: shared({"acme_web_user": "not a date"}),
        3: shared({"acme_web_user": stamp(3)}),
    }

    found = app(TARGET, binding(), listed(1, 2, 3), documents)

    assert [e.version for e in found.events] == [3, 1]
    assert found.unread == (2,)
    assert not found.complete
    # The rotation may have been written by version 2, which was not read.
    assert not found.events[0].exact


def test_a_stamp_that_disappears_is_a_gap() -> None:
    documents = {1: shared({"acme_web_user": stamp(1)}), 2: shared(None)}

    found = app(TARGET, binding(), listed(1, 2), documents)

    assert found.unread == (2,)
    assert not found.complete


def test_a_version_number_the_store_does_not_list_is_a_gap() -> None:
    """OCI drops a deleted version from its list once its deletion time passes."""
    documents = {5: shared({"acme_web_user": stamp(5)}), 7: shared({"acme_web_user": stamp(7)})}

    found = app(TARGET, binding(), listed(5, 7), documents)

    assert found.unread == (6,)
    assert not found.complete


def test_versions_up_to_the_current_one_must_be_listed() -> None:
    documents = {1: shared({"acme_web_user": stamp(1)})}
    known = VersionHistory(current=3, oldest_kept=1, versions=listed(1).versions)

    found = app(TARGET, binding(), known, documents)

    assert found.unread == (2, 3)


def test_deleted_versions_before_the_oldest_readable_one_are_gone_not_gaps() -> None:
    """OCI deletes the oldest version itself when a secret is full."""
    documents = {2: shared({"acme_web_user": stamp(2)}), 3: shared({"acme_web_user": stamp(3)})}

    found = app(TARGET, binding(), listed(1, 2, 3, deleted=(1,)), documents)

    assert found.start == history.Start(version=2, at=at(2, 1), gone=1)
    assert found.complete


def test_a_rotation_first_seen_after_pruning_is_not_exact() -> None:
    documents = {4: shared({"acme_web_user": stamp(3)})}

    found = app(TARGET, binding(), listed(4), documents)

    assert [(e.version, e.exact) for e in found.events] == [(4, False)]


def test_a_rotation_written_by_the_version_is_exact() -> None:
    documents = {1: shared(None), 2: shared({"acme_web_user": stamp(2)})}

    found = app(TARGET, binding(), listed(1, 2), documents)

    assert [(e.version, e.exact) for e in found.events] == [(2, True)]


def test_an_unknown_path_on_a_versioned_store_is_an_empty_true_history() -> None:
    found = app(TARGET, binding(), None, {})

    assert found.events == ()
    assert found.note == history.NOTHING_STORED
    assert found.complete


def test_a_held_secret_with_no_versions_listed_is_not_checked() -> None:
    """OCI lists no versions of a secret pending deletion."""
    latest = shared({"acme_web_user": stamp(7)})

    found = app(TARGET, binding(), None, {}, latest=latest)

    assert [e.at for e in found.events] == [at(7)]
    assert found.not_checked == (history.NO_VERSIONS_LISTED,)
    assert not found.complete


def test_a_live_version_below_the_first_readable_one_is_a_gap_not_gone() -> None:
    documents = {2: shared({"acme_web_user": stamp(2)})}

    found = app(TARGET, binding(), listed(1, 2), documents)

    assert found.start == history.Start(version=1, at=at(1, 1), gone=0)
    assert found.unread == (1,)
    assert not found.complete


def test_no_listed_versions_of_a_written_path_is_not_checked() -> None:
    nothing = VersionHistory(current=3, oldest_kept=None, versions=())

    found = app(TARGET, binding(), nothing, {})

    assert found.start is None
    assert not found.complete
    assert "none of the 3 versions" in found.reasons[0]


def test_only_destroyed_versions_is_not_checked() -> None:
    found = app(TARGET, binding(), listed(1, destroyed=(1,)), {})

    assert not found.complete


def test_a_seeded_secret_with_no_stamp_has_no_rotation() -> None:
    found = app(TARGET, binding(), listed(1), {1: shared(None)})

    assert found.events == ()
    assert found.complete


def test_no_versioning_shows_the_latest_stamp_and_is_not_checked() -> None:
    latest = shared({"acme_web_user": stamp(7)}, {"acme_web_user": "ville"})

    found = app(TARGET, binding(), None, {}, versioning=False, latest=latest)

    assert [(e.at, e.version) for e in found.events] == [(at(7), None)]
    assert found.start is None
    assert not found.complete
    assert "versioning" in found.reasons[0]


def test_the_history_holds_no_password() -> None:
    documents = {1: shared({"acme_web_user": stamp(1)}, {"acme_web_user": "ville"})}

    found = app(TARGET, binding(), listed(1), documents)

    assert "live" not in repr(found)
    assert "other" not in repr(found)


# --------------------------------------------------------- native staging ---


def test_native_staging_lists_versions_by_generation_and_says_why() -> None:
    raw = {
        1: {"password": Secret("a"), "generated_at": stamp(1), "generated_by": "ville"},
        2: {"password": Secret("b"), "generated_at": stamp(2), "generated_by": "jdoe"},
    }
    attributes = {"rotated_at": stamp(2, 5), "rotated_by": "jdoe"}

    found = history.native(
        TARGET, binding(ref="apps/acme/web#password"), listed(1, 2), raw, attributes
    )

    assert [(e.kind, e.at, e.version) for e in found.events] == [
        (history.ROTATION, at(2, 5), None),
        (history.GENERATED, at(2), 2),
        (history.GENERATED, at(1), 1),
    ]
    assert found.note == history.NATIVE_NOTE
    assert found.complete


def test_a_malformed_native_promotion_stamp_is_not_checked() -> None:
    raw = {1: {"password": Secret("a"), "generated_at": stamp(1)}}

    found = history.native(
        TARGET, binding(ref="apps/acme/web#password"), listed(1), raw, {"rotated_at": "2026-13-40"}
    )

    assert found.not_checked == (history.MALFORMED_PROMOTION,)
    assert not found.complete


# ---------------------------------------------------------- personal ---


def record(day: int, *, seen: bool = False, user: str = "ville") -> dict[str, Any]:
    return {
        "account": "JDOE",
        "target": TARGET,
        "reset_at": stamp(day),
        "seen": seen,
        "expired": True,
        "delivery": {"method": "vault_wrapped"},
        "by": {"host": "laptop", "pid": 42, "os_user": user},
    }


def test_each_reset_record_version_is_a_reset() -> None:
    documents = {1: record(1, seen=True), 2: record(4, user="jdba")}

    found = pers(TARGET, "JDOE", listed(1, 2), documents)

    assert [(e.kind, e.at, e.by, e.seen) for e in found.events] == [
        (history.RESET, at(4), "jdba@laptop", False),
        (history.RESET, at(1), "ville@laptop", True),
    ]
    assert found.kind == history.PERSONAL
    assert found.complete


def test_a_record_version_that_repeats_a_reset_is_one_reset() -> None:
    documents = {1: record(1), 2: record(1)}

    found = pers(TARGET, "JDOE", listed(1, 2), documents)

    assert [e.version for e in found.events] == [1]


def test_a_personal_account_with_no_versioning_shows_the_last_reset() -> None:
    found = pers(TARGET, "JDOE", None, {}, versioning=False, latest=record(9))

    assert [e.at for e in found.events] == [at(9)]
    assert not found.complete


# ---------------------------------------------------------- the database ---


def test_the_database_date_is_shown_beside_it() -> None:
    found = history.with_database(
        app(TARGET, binding(), listed(1), {1: shared(None)}),
        UserState(name="ACME_WEB_USER", status="OPEN", password_changed_at=at(2)),
    )

    assert found.db_changed_at == at(2)
    assert found.db_unknown is None
    # Information only: an unknown or later date never makes it incomplete.
    assert found.complete


def test_an_unknown_database_date_says_why() -> None:
    found = history.with_database(
        app(TARGET, binding(), listed(1), {1: shared(None)}),
        UserState(name="X", status="OPEN", password_changed_unknown="needs SELECT ON SYS.USER$"),
    )

    assert found.db_changed_at is None
    assert found.db_unknown == "needs SELECT ON SYS.USER$"


def test_no_account_on_the_target_is_said() -> None:
    found = history.with_database(app(TARGET, binding(), listed(1), {1: shared(None)}), None)

    assert found.db_unknown == history.NO_ACCOUNT


# ---------------------------------------------------------- exit codes ---


def complete() -> history.AccountHistory:
    return app(TARGET, binding(), listed(1), {1: shared(None)})


def gap() -> history.AccountHistory:
    return app(TARGET, binding(), listed(1), {})


def test_exit_codes() -> None:
    assert history.exit_code([complete()], unreachable=0, unsupported=0, targets=1) == 0
    assert history.exit_code([gap()], unreachable=0, unsupported=0, targets=1) == 4
    assert history.exit_code([complete()], unreachable=1, unsupported=0, targets=2) == 1
    assert history.exit_code([complete()], unreachable=0, unsupported=1, targets=2) == 4
    assert history.exit_code([], unreachable=0, unsupported=2, targets=2) == 5
    # A store that gave no answer is a hole, as an unreachable target is.
    assert (
        history.exit_code([complete()], unreachable=0, unsupported=0, targets=1, unanswered=1) == 1
    )
