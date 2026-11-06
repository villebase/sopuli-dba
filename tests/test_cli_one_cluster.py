"""Two targets that are one cluster are refused. Tier 0, with fake sessions."""

from __future__ import annotations

from typing import Any

import pytest

from sopuli.driver.clusters import ONE_CLUSTER, ClusterIdentity, OneClusterError, claim
from sopuli.exit_codes import ExitCode


class _Session:
    identity_kind = "PostgreSQL cluster"
    identity_key = "system_identifier"
    identity_hint = "declare each cluster once"

    def __init__(self, identity: str | None) -> None:
        self.identity = identity
        self.identity_caveat: str | None = None

    def cluster_identity(self) -> str | None:
        return self.identity


class _NoIdentity:
    """A driver whose session has no identity to give, as Oracle's."""


def test_a_second_target_on_the_same_cluster_is_refused() -> None:
    clusters: dict[str, str] = {}
    claim(_Session("742"), "pg-primary", clusters)

    with pytest.raises(OneClusterError) as refused:
        claim(_Session("742"), "pg-standby", clusters)

    assert refused.value.message == (
        'targets "pg-primary" and "pg-standby" are one PostgreSQL cluster (system_identifier 742)'
    )
    assert refused.value.code == ONE_CLUSTER
    assert refused.value.exit_code == ExitCode.CONFIG_INVALID
    assert "declare each cluster once" in str(refused.value.hint)


def test_the_same_target_reached_again_is_not_a_second_cluster() -> None:
    """A run opens one target more than once: a pre-flight, then the run."""
    clusters: dict[str, str] = {}

    claim(_Session("742"), "pg-dev", clusters)
    claim(_Session("742"), "pg-dev", clusters)

    assert clusters == {"742": "pg-dev"}


def test_two_clusters_are_two_targets() -> None:
    clusters: dict[str, str] = {}

    claim(_Session("742"), "pg-alpha", clusters)
    claim(_Session("913"), "pg-beta", clusters)

    assert clusters == {"742": "pg-alpha", "913": "pg-beta"}


@pytest.mark.parametrize("session", [_Session(None), _NoIdentity()])
def test_a_session_with_no_identity_claims_nothing(session: object) -> None:
    clusters: dict[str, str] = {}

    claim(session, "pg-dev", clusters)

    assert clusters == {}


def test_the_postgresql_session_still_names_its_cluster() -> None:
    """The check finds the method and attribute by name, so a rename would turn
    the refusal off without a type error. This is what catches it."""
    session_module = pytest.importorskip("sopuli.driver.postgres.session")
    from sopuli.config.model import ExpandedTarget, Target
    from sopuli.driver.protocol import Timeouts

    target = ExpandedTarget(target=Target(name="pg-dev", type="postgresql", dsn="h:5432"))
    session = session_module.PostgresSession(
        connection=None, target=target, correlation_id="run", timeouts=Timeouts()
    )

    assert isinstance(session, ClusterIdentity)


def test_the_mysql_session_names_its_server() -> None:
    """For the same reason, on MySQL (#1223)."""
    session_module = pytest.importorskip("sopuli.driver.mysql.session")
    from sopuli.config.model import ExpandedTarget, Target
    from sopuli.driver.protocol import Timeouts

    target = ExpandedTarget(target=Target(name="mysql-dev", type="mysql", dsn="h:3306"))
    session = session_module.MysqlSession(
        connection=None, target=target, correlation_id="run", timeouts=Timeouts()
    )

    assert isinstance(session, ClusterIdentity)
    assert (session.identity_kind, session.identity_key) == ("MySQL server", "server_uuid")


def test_the_mariadb_session_names_its_server() -> None:
    """For the same reason, on MariaDB, by ``@@server_uid`` (#1286)."""
    session_module = pytest.importorskip("sopuli.driver.mariadb.session")
    from sopuli.config.model import ExpandedTarget, Target
    from sopuli.driver.protocol import Timeouts

    target = ExpandedTarget(target=Target(name="mariadb-dev", type="mariadb", dsn="h:3306"))
    session = session_module.MariadbSession(
        connection=None, target=target, correlation_id="run", timeouts=Timeouts()
    )

    assert isinstance(session, ClusterIdentity)
    assert (session.identity_kind, session.identity_key) == ("MariaDB server", "server_uid")
    assert session.identity_caveat is None


GALERA_UUID = "ed105c80-da14-11f1-8404-db003b3a7fb6"
SERVER_UID = "vmGAk3HDOBZm5rKnJnCGDtplUwQ="


SYNCED = {"Wsrep_cluster_state_uuid": GALERA_UUID, "Wsrep_local_state_comment": "Synced"}
DONOR = {"wsrep_cluster_state_uuid": GALERA_UUID, "wsrep_local_state_comment": "Donor/Desynced"}


def _mariadb(wsrep: dict[str, str], server_uid: str = SERVER_UID) -> tuple[Any, list[str]]:
    """A MariaDB session over a fake connection, and the statements it ran.
    ``fetchone`` answers ``@@server_uid``, ``fetchall`` the wsrep rows."""
    session_module = pytest.importorskip("sopuli.driver.mariadb.session")
    from sopuli.config.model import ExpandedTarget, Target
    from sopuli.driver.protocol import Timeouts

    executed: list[str] = []

    class _Cursor:
        def __enter__(self) -> _Cursor:
            return self

        def __exit__(self, *_: object) -> None:
            pass

        def execute(self, statement: str) -> None:
            executed.append(statement)

        def fetchone(self) -> tuple[str]:
            return (server_uid,)

        def fetchall(self) -> list[tuple[str, str]]:
            return list(wsrep.items())

    class _Connection:
        def cursor(self) -> _Cursor:
            return _Cursor()

    target = ExpandedTarget(target=Target(name="mariadb-dev", type="mariadb", dsn="h:3306"))
    session = session_module.MariadbSession(
        connection=_Connection(), target=target, correlation_id="run", timeouts=Timeouts()
    )
    return session, executed


def test_the_mariadb_session_reads_the_server_uid() -> None:
    """The statement and the reader, without a server: the isinstance check
    above sees only that the names exist."""
    session, executed = _mariadb({})

    assert session.cluster_identity() == SERVER_UID
    assert executed == ["select @@global.server_uid"]


@pytest.mark.parametrize(
    ("wsrep", "shared", "caveat"),
    [
        # Without Galera the UUID is empty (probe 14, GI6).
        ({"wsrep_cluster_state_uuid": ""}, None, False),
        # A server built without Galera has no rows at all.
        ({}, None, False),
        (SYNCED, GALERA_UUID, False),
        # Only `Synced` was measured, so another state gives no cluster.
        (DONOR, None, True),
    ],
    ids=["no-galera", "no-rows", "synced-node", "donor-node"],
)
def test_the_mariadb_session_reads_its_cluster(
    wsrep: dict[str, str], shared: str | None, caveat: bool
) -> None:
    """#1346: a Galera node that is `Synced` gives its cluster's UUID. A node
    in another state gives none, and says why."""
    from sopuli.driver.clusters import SharedIdentity

    session, executed = _mariadb(wsrep)
    found = session.shared_identity()

    # A name of its own, so the check does not narrow `session` for mypy.
    checked: object = session
    assert isinstance(checked, SharedIdentity)
    assert executed == [pytest.importorskip("sopuli.driver.mariadb.session").WSREP_STATE]
    assert (found and found.value) == shared
    if found is not None:
        assert (found.kind, found.key) == ("Galera cluster", "wsrep_cluster_state_uuid")
    assert (session.identity_caveat is not None) == caveat
    if caveat:
        assert "Donor/Desynced, not Synced" in session.identity_caveat
    # The server's own words are never replaced.
    assert (session.identity_kind, session.identity_key) == ("MariaDB server", "server_uid")


def test_two_targets_on_nodes_of_one_galera_cluster_are_refused() -> None:
    """#1346, end to end through `claim`: two nodes have their own
    `@@server_uid` and share the cluster's UUID."""
    clusters: dict[str, str] = {}
    first, _ = _mariadb(SYNCED, server_uid="node-1")
    claim(first, "galera-g1", clusters)
    second, _ = _mariadb(SYNCED, server_uid="node-2")

    with pytest.raises(OneClusterError) as refused:
        claim(second, "galera-g2", clusters)

    assert refused.value.message == (
        'targets "galera-g1" and "galera-g2" are one Galera cluster '
        f"(wsrep_cluster_state_uuid {GALERA_UUID})"
    )
    assert "declare each cluster once" in str(refused.value.hint)
    # The refused target claimed nothing.
    assert clusters == {"node-1": "galera-g1", GALERA_UUID: "galera-g1"}


def test_two_targets_on_one_galera_node_are_refused_whatever_its_state() -> None:
    """The server is always claimed, so a node that left `Synced` between two
    targets' reads is still one server, as before #1346."""
    clusters: dict[str, str] = {}
    synced, _ = _mariadb(SYNCED, server_uid="node-1")
    claim(synced, "galera-a", clusters)
    donor, _ = _mariadb(DONOR, server_uid="node-1")

    with pytest.raises(OneClusterError) as refused:
        claim(donor, "galera-b", clusters)

    assert "are one MariaDB server (server_uid node-1)" in refused.value.message


def test_two_targets_on_one_mysql_server_are_refused_by_name() -> None:
    class _Mysql(_Session):
        identity_kind = "MySQL server"
        identity_key = "server_uuid"

    clusters: dict[str, str] = {}
    claim(_Mysql("8747dbf7"), "mysql-a", clusters)

    with pytest.raises(OneClusterError) as refused:
        claim(_Mysql("8747dbf7"), "mysql-b", clusters)

    assert refused.value.message == (
        'targets "mysql-a" and "mysql-b" are one MySQL server (server_uuid 8747dbf7)'
    )
