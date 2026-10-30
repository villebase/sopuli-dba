"""Two targets that are one cluster are refused. Tier 0.

A PostgreSQL target is a cluster, and a primary and its standbys share one set
of roles. Two targets that reach one cluster would change those roles under two
names, so the second is refused, as a name declared twice is
(``01-configuration.md`` §*``postgres:`` on a target*).

A session that can say which cluster it reached has ``cluster_identity()``
and ``identity_caveat`` (:class:`ClusterIdentity`). Only the PostgreSQL
session does, so the check asks for them by name rather than through
:class:`~sopuli.driver.protocol.Session`, which every driver and test fake
implements. ``tests/test_cli_one_cluster.py`` checks that the PostgreSQL
session still has both.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from sopuli.config.errors import ConfigError
from sopuli.driver.protocol import Scope, Session

#: ``error.code`` for a second target on a cluster another target reached.
ONE_CLUSTER = "SOPULI-20008"


@runtime_checkable
class ClusterIdentity(Protocol):
    """A session that can name the cluster it reached."""

    #: Why :meth:`cluster_identity` found no answer, or ``None``.
    identity_caveat: str | None

    def cluster_identity(self) -> str | None: ...


class OneClusterError(ConfigError):
    """Two targets are one cluster. Refused as a name declared twice is, and
    for its reason: one set of roles would be changed under two names."""

    code = ONE_CLUSTER


def scope_and_claim(
    session: Session, target: str, clusters: dict[str, str]
) -> tuple[Scope, tuple[str, ...]]:
    """Read the session's scope, then claim its cluster: the one order both
    `doctor` and the other commands use.

    The scope comes first, so a PostgreSQL superuser is refused before the
    cluster is read. Returns the scope and the caveat, if the session could not
    read its identity.
    """
    scope = session.scope()
    claim(session, target, clusters)
    caveat = session.identity_caveat if isinstance(session, ClusterIdentity) else None
    return scope, (caveat,) if caveat else ()


def claim(session: object, target: str, clusters: dict[str, str]) -> None:
    """Record which target reached this session's cluster, and refuse a second.

    ``clusters`` maps each identity to the first target that reached it, for
    the run. A session with no identity to give, or one that cannot read it,
    claims nothing: not knowing is not a finding, and the session says why.
    """
    if not isinstance(session, ClusterIdentity):
        return
    identity = session.cluster_identity()
    if identity is None:
        return
    first = clusters.setdefault(identity, target)
    if first != target:
        raise OneClusterError(
            f'targets "{first}" and "{target}" are one PostgreSQL cluster '
            f"(system_identifier {identity})",
            hint=(
                "declare each cluster once. A primary and its standbys share their "
                "roles, so one target covers them all. If one is a pg_basebackup copy "
                "or a promoted standby, a separate server, give each its own secret and "
                "run one of them per run with --target"
            ),
        )
