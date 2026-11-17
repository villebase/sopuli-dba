"""A SQL Server login's policy flags in the vault record (#1551).

Tier 0. The record is read and patched by :mod:`sopuli.policy_flags`, and it
must outlive every write that stages or promotes a ``pending``: it describes
the login, whose policy stays off until the flags are set back
(``02-mssql-privileges.md`` §6.2).
"""

from __future__ import annotations

from typing import Any

import pytest

from sopuli.payload import (
    CURRENT,
    ORIGIN,
    PENDING,
    POLICY_FLAGS,
    PREVIOUS,
    REMOVE,
    RESERVED,
    StageLayout,
    merge,
)
from sopuli.policy_flags import (
    PolicyFlags,
    PolicyFlagsUnreadableError,
    record_patch,
    recorded,
    remove_patch,
)
from sopuli.secrets import Secret
from sopuli.store import MemoryStore
from sopuli.store.credentials import apply_patch

ONE = StageLayout("password")
SHARED = StageLayout("DB_CREDENTIALS", ("acme_app_user",))
ON = PolicyFlags(check_policy=True, check_expiration=True)
POLICY_ONLY = PolicyFlags(check_policy=True, check_expiration=False)


def test_the_name_is_reserved() -> None:
    assert POLICY_FLAGS in RESERVED


@pytest.mark.parametrize("layout", [ONE, SHARED], ids=["one account", "shared"])
def test_a_recorded_target_reads_back_and_the_others_are_none(layout: StageLayout) -> None:
    document = merge(
        record_patch(layout, "mssql-dev", ON), record_patch(layout, "mssql-test", POLICY_ONLY)
    )
    assert recorded(document, layout, "mssql-dev") == ON
    assert recorded(document, layout, "mssql-test") == POLICY_ONLY
    assert recorded(document, layout, "mssql-prod") is None
    assert recorded(None, layout, "mssql-dev") is None
    assert recorded({}, layout, "mssql-dev") is None


def test_the_record_is_the_decided_shape() -> None:
    assert record_patch(ONE, "mssql-dev", POLICY_ONLY) == {
        POLICY_FLAGS: {"mssql-dev": {"check_policy": True, "check_expiration": False}}
    }
    assert record_patch(SHARED, "mssql-dev", ON) == {
        POLICY_FLAGS: {
            "acme_app_user": {"mssql-dev": {"check_policy": True, "check_expiration": True}}
        }
    }


def test_removing_one_target_keeps_the_others() -> None:
    document = merge(record_patch(SHARED, "mssql-dev", ON), record_patch(SHARED, "mssql-test", ON))
    after = merge(document, remove_patch(SHARED, "mssql-dev"))
    assert recorded(after, SHARED, "mssql-dev") is None
    assert recorded(after, SHARED, "mssql-test") == ON


@pytest.mark.parametrize(
    "entry",
    [
        "on",
        {"check_policy": "true", "check_expiration": True},
        {"check_policy": 1, "check_expiration": 0},
        {"check_policy": True},
        {"check_policy": True, "check_expiration": True, "extra": True},
    ],
    ids=["a string", "a string flag", "integers", "one flag", "an extra key"],
)
def test_an_entry_it_cannot_read_is_refused_not_guessed(entry: Any) -> None:
    """The record may be the only copy of the login's settings, so nothing
    reads a value written some other way as on or off."""
    document = {POLICY_FLAGS: {"mssql-dev": entry}}
    with pytest.raises(PolicyFlagsUnreadableError, match="mssql-dev") as caught:
        recorded(document, ONE, "mssql-dev")
    assert caught.value.target == "mssql-dev"


@pytest.mark.parametrize("root", ["off", ["mssql-dev"], {"acme_app_user": "off"}])
def test_a_root_of_the_wrong_shape_is_refused_for_every_target(root: Any) -> None:
    """A merge patch would replace a root that is not a mapping, dropping
    whatever it held. A caller reads before it writes, and this refuses."""
    with pytest.raises(PolicyFlagsUnreadableError):
        recorded({POLICY_FLAGS: root}, SHARED, "mssql-dev")


def test_the_record_outlives_a_new_pending_and_a_promotion() -> None:
    """§6.2: the record stays until the flags are set back, also when a new
    `pending` replaces the one whose change turned the policy off. The patches
    are the shapes `creds generate` and `apply.promotion_patch` send: neither
    names the record, so a merge keeps it."""
    store = MemoryStore()
    apply_patch(store, "apps/acme", ONE.patch(CURRENT, Secret("a")), cas=0)
    staged = merge(ONE.patch(PENDING, Secret("b")), ONE.patch(ORIGIN, "generated"))
    apply_patch(store, "apps/acme", staged, cas=_version(store))
    apply_patch(store, "apps/acme", record_patch(ONE, "mssql-dev", ON), cas=_version(store))

    restaged = merge(ONE.patch(PENDING, Secret("c")), ONE.patch(ORIGIN, "generated"))
    apply_patch(store, "apps/acme", restaged, cas=_version(store))
    assert recorded(_data(store), ONE, "mssql-dev") == ON

    promoted = merge(
        ONE.patch(CURRENT, Secret("c")),
        ONE.patch(PREVIOUS, Secret("a")),
        ONE.patch(PENDING, REMOVE),
        ONE.patch(ORIGIN, REMOVE),
    )
    apply_patch(store, "apps/acme", promoted, cas=_version(store))
    assert recorded(_data(store), ONE, "mssql-dev") == ON

    apply_patch(store, "apps/acme", remove_patch(ONE, "mssql-dev"), cas=_version(store))
    assert recorded(_data(store), ONE, "mssql-dev") is None


def _version(store: MemoryStore) -> int:
    stored = store.read("apps/acme")
    assert stored is not None
    return stored.version


def _data(store: MemoryStore) -> Any:
    stored = store.read("apps/acme")
    assert stored is not None
    return stored.data
