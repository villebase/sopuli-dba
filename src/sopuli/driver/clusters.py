"""Two targets that are one cluster are refused. Tier 0.

A PostgreSQL target is a cluster, and a primary and its standbys share one set
of roles. Two targets that reach one cluster would change those roles under two
names, so the second is refused, as a name declared twice is
(``01-configuration.md`` §*``postgres:`` on a target*).

A MySQL server is one set of accounts too, known by its ``server_uuid``, and
so is a MariaDB server, known by its ``@@server_uid`` (#1286), and a Galera
cluster, known by its ``wsrep_cluster_state_uuid`` (#1346).

A session that can say which cluster it reached has ``cluster_identity()``,
``identity_caveat`` and the words for its refusal (:class:`ClusterIdentity`).
The PostgreSQL, MySQL and MariaDB sessions do, so the check asks for them by
name rather than through :class:`~sopuli.driver.protocol.Session`, which every
driver and test fake implements. ``tests/test_cli_one_cluster.py`` checks
that the three sessions still have them. The MariaDB session also has
``shared_identity()`` (:class:`SharedIdentity`), for a Galera node's cluster,
which is claimed beside its server.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from sopuli.config.errors import ConfigError
from sopuli.config.model import ExpandedTarget
from sopuli.config.targets import POSTGRESQL
from sopuli.driver.address import host_and_port
from sopuli.driver.protocol import Scope, Session

#: ``error.code`` for a second target on a cluster another target reached.
ONE_CLUSTER = "SOPULI-20008"


@runtime_checkable
class ClusterIdentity(Protocol):
    """A session that can name the cluster it reached."""

    #: Why the session claims less than it could, or ``None``: on PostgreSQL,
    #: why :meth:`cluster_identity` found no answer; on MariaDB, why a Galera
    #: node gave no cluster (:class:`SharedIdentity`).
    identity_caveat: str | None
    #: What one identity names, and what the identity is, for the refusal:
    #: ``PostgreSQL cluster`` and ``system_identifier``.
    identity_kind: str
    identity_key: str
    #: What to do about two targets that are one, for the refusal's hint.
    identity_hint: str

    def cluster_identity(self) -> str | None: ...


@dataclass(frozen=True)
class Identity:
    """One identity a session claims, with the words for its refusal."""

    value: str
    kind: str
    key: str
    hint: str


@runtime_checkable
class SharedIdentity(Protocol):
    """A session whose server can belong to a group that shares its accounts,
    such as a Galera cluster (#1346). The group's identity is claimed beside
    the server's own, never instead of it, so it only adds refusals: two
    targets on one server are refused whatever the group's state."""

    def shared_identity(self) -> Identity | None: ...


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
    cluster is read. Returns the scope and the caveat, if the session claims
    less than it could: it could not read its identity, or a Galera node is
    not `Synced`.
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
    found: list[Identity] = []
    own = session.cluster_identity()
    if own is not None:
        found.append(
            Identity(own, session.identity_kind, session.identity_key, session.identity_hint)
        )
    if isinstance(session, SharedIdentity):
        shared = session.shared_identity()
        if shared is not None:
            found.append(shared)
    # Every identity is checked before any is recorded, so a refused target
    # claims nothing.
    for one in found:
        first = clusters.get(one.value, target)
        if first != target:
            raise OneClusterError(
                f'targets "{first}" and "{target}" are one {one.kind} ({one.key} {one.value})',
                hint=one.hint,
            )
    for one in found:
        clusters.setdefault(one.value, target)


def covered_databases(target: ExpandedTarget, declared: Sequence[ExpandedTarget]) -> frozenset[str]:
    """The databases other PostgreSQL targets in ``declared`` connect to at
    ``target``'s host and port, for `report privileges` (#1501).

    ``declared`` is every target the file declares, selected in the run or
    not. Each one's own report reads its database's schemas and objects, so
    ``target``'s report does not name that database as not checked. "Same
    cluster" is the same host, in any case, and the same port in ``dsn:``,
    compared without reading anything: :func:`claim` refuses a second target
    on one cluster in a run, and a target the selectors left out is never
    connected to, so neither's ``system_identifier`` can be read. A cluster
    reached under another name, such as an alias or a standby's address, does
    not match, and its database stays not checked. Nothing here says whether
    the other target's own run was made or succeeded: each target's run
    reports its own database.
    """
    if target.target.type != POSTGRESQL:
        return frozenset()
    host, port = host_and_port(target.target.dsn)
    here = (host.lower(), port)
    covered: set[str] = set()
    for other in declared:
        if other.name == target.name or other.target.type != POSTGRESQL:
            continue
        other_host, other_port = host_and_port(other.target.dsn)
        if (other_host.lower(), other_port) == here:
            covered.add(other.target.postgres_settings.database)
    return frozenset(covered)
