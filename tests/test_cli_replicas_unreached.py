"""`SOPULI-W076`: `doctor` warns when a SQL Server target is a replica of an
Availability Group with a replica no target of the run reached (#1538,
decision 4; #1550).

Tier 0, over the run's maps: the identities :func:`~sopuli.driver.clusters.claim`
kept, and what :func:`~sopuli.cli._read_replicas` read. The live run is a
hand run against a 2025 group (`14_availability_group_reads_probe.py`); no
group forms in the tier-1 lane.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from sopuli.cli import _read_replicas, _replicas_unreached
from sopuli.config.model import ExpandedTarget, Target
from sopuli.diagnostics import REPLICAS_UNREACHED, replicas_unreached
from sopuli.driver.clusters import AvailabilityReplicas
from sopuli.driver.protocol import DriverError


def _run(clusters: dict[str, str] | None = None) -> Any:
    return SimpleNamespace(clusters=dict(clusters or {}), replicas={}, instance_names={})


class Replicas:
    def __init__(self, names: tuple[str, ...] = (), error: DriverError | None = None) -> None:
        self.names = names
        self.error = error

    def availability_replicas(self) -> tuple[str, ...]:
        if self.error is not None:
            raise self.error
        return self.names


def _read(run: Any, target: str, names: tuple[str, ...]) -> tuple[str, ...]:
    return _read_replicas(Replicas(names), target, run)


def test_the_sql_server_session_names_its_replicas() -> None:
    """A tripwire: `doctor` asks for the replicas by this protocol."""
    session = pytest.importorskip("sopuli.driver.mssql.session")
    opened = session.MssqlSession(
        connection=None,
        target=ExpandedTarget(target=Target(name="mssql-dev", type="mssql", dsn="h:1433")),
    )
    assert isinstance(opened, AvailabilityReplicas)


def test_both_replicas_reached_warn_nothing() -> None:
    run = _run({"SQLAG1": "mssql-ag1", "SQLAG2": "mssql-ag2"})
    assert _read(run, "mssql-ag1", ("SQLAG1", "SQLAG2")) == ()
    assert _read(run, "mssql-ag2", ("SQLAG1", "SQLAG2")) == ()
    assert _replicas_unreached(run) == []


def test_a_replica_no_target_reached_is_named() -> None:
    run = _run({"SQLAG1": "mssql-ag1"})
    _read(run, "mssql-ag1", ("SQLAG1", "SQLAG2"))
    (warning,) = _replicas_unreached(run)
    assert warning.code == REPLICAS_UNREACHED
    assert warning.target == "mssql-ag1"
    assert "reached no target on its replica SQLAG2." in warning.message


def test_names_are_compared_by_upper() -> None:
    """Invariant 5's fold; SQL Server compares server names without case."""
    run = _run({"sqlag1": "mssql-ag1", "SqlAg2": "mssql-ag2"})
    _read(run, "mssql-ag1", ("SQLAG1", "SQLAG2"))
    _read(run, "mssql-ag2", ("SQLAG1", "SQLAG2"))
    assert _replicas_unreached(run) == []


def test_another_products_identity_is_not_a_server_name() -> None:
    """A MySQL server_uuid that happened to match is not a reached replica."""
    run = _run({"SQLAG1": "mssql-ag1", "SQLAG2": "mysql-dev"})
    _read(run, "mssql-ag1", ("SQLAG1", "SQLAG2"))
    (warning,) = _replicas_unreached(run)
    assert "SQLAG2" in warning.message


def test_a_target_in_no_group_warns_nothing() -> None:
    run = _run({"SQL1": "mssql-dev"})
    assert _read(run, "mssql-dev", ()) == ()
    assert _replicas_unreached(run) == []


def test_several_replicas_are_named_once_in_the_plural() -> None:
    run = _run({"SQLAG1": "mssql-ag1"})
    _read(run, "mssql-ag1", ("SQLAG1", "SQLAG2", "SQLAG3"))
    (warning,) = _replicas_unreached(run)
    assert "reached no target on its replicas SQLAG2, SQLAG3." in warning.message


def test_a_target_whose_name_is_not_among_its_replicas_is_not_compared() -> None:
    """A server renamed after its group was made would count itself as
    missing: nothing is compared, and the note says so."""
    run = _run({"NEWNAME": "mssql-ag1"})
    (note,) = _read(run, "mssql-ag1", ("OLDNAME", "SQLAG2"))
    assert "its ServerName is not among its Availability Group's replicas" in note
    assert _replicas_unreached(run) == []


def test_a_target_whose_name_was_not_read_is_not_compared() -> None:
    run = _run()
    (note,) = _read(run, "mssql-ag1", ("SQLAG1", "SQLAG2"))
    assert "SOPULI-W076 was not checked" in note
    assert _replicas_unreached(run) == []


def test_a_failed_read_is_a_note_not_the_targets_failure() -> None:
    run = _run({"SQLAG1": "mssql-ag1"})
    failed = Replicas(error=DriverError("refused", hint=None))
    (note,) = _read_replicas(failed, "mssql-ag1", run)
    assert note.startswith("mssql-ag1: its Availability Group replicas could not be read")
    assert run.replicas == {}


def test_a_peer_whose_read_failed_still_counts_as_reached() -> None:
    """The second review of #1583: B was reached, so A must not call it
    unreached because B's own read failed."""
    run = _run({"SQLAG1": "mssql-ag1", "SQLAG2": "mssql-ag2"})
    _read(run, "mssql-ag1", ("SQLAG1", "SQLAG2"))
    (note,) = _read_replicas(Replicas(error=DriverError("lost", hint=None)), "mssql-ag2", run)
    assert "could not be read" in note
    assert _replicas_unreached(run) == []


def test_a_peer_whose_name_did_not_match_still_counts_as_reached() -> None:
    run = _run({"SQLAG1": "mssql-ag1", "SQLAG2": "mssql-ag2"})
    _read(run, "mssql-ag1", ("SQLAG1", "SQLAG2"))
    (note,) = _read(run, "mssql-ag2", ("OLDNAME", "SQLAG1"))
    assert "not among" in note
    assert _replicas_unreached(run) == []


def test_a_failed_reads_note_carries_no_server_text() -> None:
    run = _run({"SQLAG1": "mssql-ag1"})
    failed = Replicas(error=DriverError("the server said something long", hint=None))
    (note,) = _read_replicas(failed, "mssql-ag1", run)
    assert "the server said" not in note
    assert note.endswith("SOPULI-W076 was not checked: DriverError")


def test_the_message_asks_for_every_replica_reached() -> None:
    """A declared target that was down, or left out by --select, is named
    too, so the message asks for both."""
    message = replicas_unreached("mssql-ag1", ["SQLAG2"]).message
    assert message.startswith("mssql-ag1: this instance is a replica of an Availability Group")
    assert "this run reached no target on its replica SQLAG2" in message
    assert "--select" in message
    assert "02-mssql-privileges.md §4" in message
