"""`SOPULI-W076`: `doctor` warns when a SQL Server target is a replica of an
Availability Group with a replica no target of the run reached (#1538,
decision 4; #1550).

Tier 0, over the run's two maps: the replicas each target read, and the
identities :func:`~sopuli.driver.clusters.claim` kept. The live run is a hand
run against a 2025 group (`14_availability_group_reads_probe.py`); no group
forms in the tier-1 lane.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from sopuli.cli import _replicas_undeclared
from sopuli.diagnostics import REPLICAS_UNDECLARED, replicas_undeclared


def _run(clusters: dict[str, str], replicas: dict[str, tuple[str, ...]]) -> Any:
    return SimpleNamespace(clusters=clusters, replicas=replicas)


def test_both_replicas_declared_and_reached_warn_nothing() -> None:
    run = _run(
        {"SQLAG1": "mssql-ag1", "SQLAG2": "mssql-ag2"},
        {"mssql-ag1": ("SQLAG1", "SQLAG2"), "mssql-ag2": ("SQLAG1", "SQLAG2")},
    )
    assert _replicas_undeclared(run) == []


def test_a_replica_no_target_reached_is_named() -> None:
    run = _run({"SQLAG1": "mssql-ag1"}, {"mssql-ag1": ("SQLAG1", "SQLAG2")})
    (warning,) = _replicas_undeclared(run)
    assert warning.code == REPLICAS_UNDECLARED
    assert warning.target == "mssql-ag1"
    assert "its replica SQLAG2." in warning.message
    assert "SQLAG1" not in warning.message.split("replica ", 2)[-1]


def test_names_are_compared_without_case() -> None:
    """SQL Server compares server names without case."""
    run = _run({"sqlag1": "mssql-ag1", "SqlAg2": "mssql-ag2"}, {"mssql-ag1": ("SQLAG1", "SQLAG2")})
    assert _replicas_undeclared(run) == []


def test_a_target_in_no_group_warns_nothing() -> None:
    assert _replicas_undeclared(_run({"SQL1": "mssql-dev"}, {"mssql-dev": ()})) == []


def test_each_target_warns_once_naming_every_replica_not_reached() -> None:
    run = _run(
        {"SQLAG1": "mssql-ag1"},
        {"mssql-ag1": ("SQLAG1", "SQLAG2", "SQLAG3")},
    )
    (warning,) = _replicas_undeclared(run)
    assert "its replica SQLAG2, SQLAG3." in warning.message


def test_the_message_says_the_run_did_not_reach_it() -> None:
    """A declared target the run could not reach has no name the run read,
    so the message does not claim the config lacks it."""
    message = replicas_undeclared("mssql-ag1", ["SQLAG2"]).message
    assert message.startswith("mssql-ag1: this instance is a replica of an Availability Group")
    assert "no target this run reached" in message
    assert "02-mssql-privileges.md §4" in message
