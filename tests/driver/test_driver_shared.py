"""The read-only refusal and the not-written refusal the drivers share. Tier 0 (#1232).

Each driver supplies its own hint; the class and the rule are
:mod:`sopuli.driver.protocol`'s and :mod:`sopuli.driver.registry`'s, so code
that catches one driver's refusal catches every driver's.
"""

from __future__ import annotations

from collections.abc import Callable

import pytest

import sopuli.driver.mysql.scope as mysql
import sopuli.driver.oracle.capabilities as oracle
import sopuli.driver.postgres.scope as postgres
from sopuli.driver.protocol import ReadOnlyTargetError, Scope
from sopuli.driver.registry import NotWrittenError

RequireReadWrite = Callable[..., None]

DRIVERS: list[tuple[str, RequireReadWrite, str]] = [
    ("oracle", oracle.require_read_write, "physical standby"),
    ("postgres", postgres.require_read_write, "default_transaction_read_only"),
    ("mysql", mysql.require_read_write, "super_read_only"),
]


def test_every_driver_names_the_shared_read_only_error() -> None:
    assert oracle.ReadOnlyTargetError is ReadOnlyTargetError
    assert postgres.ReadOnlyTargetError is ReadOnlyTargetError
    assert mysql.ReadOnlyTargetError is ReadOnlyTargetError


@pytest.mark.parametrize(
    "module", ["sopuli.driver.postgres.session", "sopuli.driver.mysql.session"]
)
def test_every_driver_session_names_the_shared_not_written_error(module: str) -> None:
    """The session imports its vendor's client, so it is skipped without one."""
    assert pytest.importorskip(module).NotWrittenError is NotWrittenError


@pytest.mark.parametrize(("driver", "require", "hint"), DRIVERS, ids=[d[0] for d in DRIVERS])
def test_a_read_only_session_is_refused_with_the_driver_s_hint(
    driver: str, require: RequireReadWrite, hint: str
) -> None:
    scope = Scope(type="server", open_mode="READ ONLY", read_write=False)

    with pytest.raises(ReadOnlyTargetError) as raised:
        require(scope, target="acme-dr")

    assert raised.value.message == 'target "acme-dr" is READ ONLY and cannot be written to'
    assert hint in str(raised.value.hint)
    assert raised.value.category == "database"


@pytest.mark.parametrize(("driver", "require", "hint"), DRIVERS, ids=[d[0] for d in DRIVERS])
def test_an_unknown_open_mode_is_not_refused(
    driver: str, require: RequireReadWrite, hint: str
) -> None:
    require(Scope(type="server"), target="acme-dr")


def test_a_postgres_standby_gets_the_standby_hint() -> None:
    scope = Scope(type="cluster", open_mode=postgres.IN_RECOVERY, read_write=False)

    with pytest.raises(ReadOnlyTargetError) as raised:
        postgres.require_read_write(scope, target="acme-dr")

    assert raised.value.hint == "this cluster is a standby; point the target at the primary"
