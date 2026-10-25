"""Two targets that are one cluster are refused. Tier 0, with fake sessions."""

from __future__ import annotations

import pytest

from sopuli.cli import OneClusterError, _claim_cluster
from sopuli.exit_codes import ExitCode
from sopuli.invocation import Invocation


class _Session:
    def __init__(self, identity: str | None) -> None:
        self.identity = identity

    def cluster_identity(self) -> str | None:
        return self.identity


class _NoIdentity:
    """A driver whose session has no identity to give, as Oracle's."""


def test_a_second_target_on_the_same_cluster_is_refused() -> None:
    run = Invocation()
    _claim_cluster(_Session("742"), "pg-primary", run)  # type: ignore[arg-type]

    with pytest.raises(OneClusterError) as refused:
        _claim_cluster(_Session("742"), "pg-standby", run)  # type: ignore[arg-type]

    assert refused.value.message == (
        'targets "pg-primary" and "pg-standby" are one PostgreSQL cluster (system_identifier 742)'
    )
    assert refused.value.exit_code == ExitCode.CONFIG_INVALID
    assert "declare each cluster once" in str(refused.value.hint)


def test_the_same_target_reached_again_is_not_a_second_cluster() -> None:
    """A run opens one target more than once: a pre-flight, then the run."""
    run = Invocation()

    _claim_cluster(_Session("742"), "pg-dev", run)  # type: ignore[arg-type]
    _claim_cluster(_Session("742"), "pg-dev", run)  # type: ignore[arg-type]

    assert run.clusters == {"742": "pg-dev"}


def test_two_clusters_are_two_targets() -> None:
    run = Invocation()

    _claim_cluster(_Session("742"), "pg-alpha", run)  # type: ignore[arg-type]
    _claim_cluster(_Session("913"), "pg-beta", run)  # type: ignore[arg-type]

    assert run.clusters == {"742": "pg-alpha", "913": "pg-beta"}


@pytest.mark.parametrize("session", [_Session(None), _NoIdentity()])
def test_a_session_with_no_identity_claims_nothing(session: object) -> None:
    run = Invocation()

    _claim_cluster(session, "pg-dev", run)  # type: ignore[arg-type]

    assert run.clusters == {}
