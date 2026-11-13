"""Which databases another declared target covers, for `report privileges`
(#1501). Tier 0: the config alone, no connection."""

from __future__ import annotations

from typing import Any

from sopuli.config.loading import build_config
from sopuli.driver.clusters import covered_databases

ADMIN = {"username": "sopuli_svc", "auth": {"method": "env"}}


def target(name: str, dsn: str, database: str | None = None, kind: str = "postgresql") -> Any:
    entry: dict[str, Any] = {"name": name, "type": kind, "dsn": dsn, "admin": ADMIN}
    if database is not None:
        entry["postgres"] = {"database": database}
    return entry


def covered(*targets: dict[str, Any]) -> frozenset[str]:
    config = build_config({"version": 1, "targets": list(targets)})
    first, *_ = config.expanded_targets
    return covered_databases(first, config.expanded_targets)


def test_the_same_host_and_port_covers_the_other_database() -> None:
    assert covered(
        target("pg-acme", "db-dev.example.com:5432", "acme"),
        # The default database, written by no `postgres:` block; the host in
        # another case is the same host.
        target("pg-postgres", "DB-DEV.example.com:5432"),
    ) == frozenset({"postgres"})


def test_another_port_or_host_does_not_cover() -> None:
    assert (
        covered(
            target("pg-acme", "db-dev.example.com:5432", "acme"),
            target("pg-batch", "db-dev.example.com:5433", "acme_batch"),
            target("pg-other", "192.0.2.10:5432", "acme_other"),
        )
        == frozenset()
    )


def test_only_postgresql_targets_cover_or_are_covered() -> None:
    assert (
        covered(
            target("pg-acme", "db-dev.example.com:5432", "acme"),
            target("my-acme", "db-dev.example.com:5432", kind="mysql"),
        )
        == frozenset()
    )
    assert (
        covered(
            target("my-acme", "db-dev.example.com:5432", kind="mysql"),
            target("pg-acme", "db-dev.example.com:5432", "acme"),
        )
        == frozenset()
    )
