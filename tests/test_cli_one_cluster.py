"""Two targets that are one cluster are refused. Tier 0, with fake sessions."""

from __future__ import annotations

import pytest

from sopuli.driver.clusters import ONE_CLUSTER, ClusterIdentity, OneClusterError, claim
from sopuli.exit_codes import ExitCode


class _Session:
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
