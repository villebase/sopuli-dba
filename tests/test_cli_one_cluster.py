"""Two targets that are one cluster are refused. Tier 0, with fake sessions."""

from __future__ import annotations

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


@pytest.mark.parametrize(
    ("wsrep", "identity", "kind", "key"),
    [
        # Without Galera the UUID is empty (probe 14, GI6).
        ({"wsrep_cluster_state_uuid": ""}, SERVER_UID, "MariaDB server", "server_uid"),
        (
            {"Wsrep_cluster_state_uuid": GALERA_UUID, "Wsrep_local_state_comment": "Synced"},
            GALERA_UUID,
            "Galera cluster",
            "wsrep_cluster_state_uuid",
        ),
        # A node still joining was not measured, so it is known by its server.
        (
            {"wsrep_cluster_state_uuid": GALERA_UUID, "wsrep_local_state_comment": "Joining"},
            SERVER_UID,
            "MariaDB server",
            "server_uid",
        ),
    ],
    ids=["no-galera", "synced-node", "joining-node"],
)
def test_the_mariadb_session_reads_its_identity(
    wsrep: dict[str, str], identity: str, kind: str, key: str
) -> None:
    """The statements and the reader, without a server: the isinstance check
    above sees only that the names exist. A Galera node that is `Synced` is
    known by its cluster (#1346), any other server by `@@server_uid`
    (#1286)."""
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
            return (SERVER_UID,)

        def fetchall(self) -> list[tuple[str, str]]:
            return list(wsrep.items())

    class _Connection:
        def cursor(self) -> _Cursor:
            return _Cursor()

    target = ExpandedTarget(target=Target(name="mariadb-dev", type="mariadb", dsn="h:3306"))
    session = session_module.MariadbSession(
        connection=_Connection(), target=target, correlation_id="run", timeouts=Timeouts()
    )

    assert session.cluster_identity() == identity
    assert (session.identity_kind, session.identity_key) == (kind, key)
    assert executed[0] == session_module.WSREP_STATE
    assert executed[1:] == ([] if identity == GALERA_UUID else ["select @@global.server_uid"])


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
