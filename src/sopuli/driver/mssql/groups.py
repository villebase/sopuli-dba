"""What a SQL Server session reads of the Availability Group it is in. Tier 0.

Decision 4 of #1538: each replica of a group is a target of its own, and a
login in a contained group's own ``master`` is refused, because the group
copies it to every replica, so two declared replicas would be one account
(``02-mssql-privileges.md`` §4). Both reads here are made with ``ALTER ANY
LOGIN`` alone (``14_availability_group_reads_probe.py``):

- **the replicas' names**, from ``sys.availability_replicas`` (AR1). The
  group's own row in ``sys.availability_groups`` needs ``VIEW ANY
  DEFINITION``, and the replica's role ``VIEW SERVER STATE``, which shows
  every session (AR2), so neither is read;
- **whether the session is in a contained group's own master**, from the
  ``physical_database_name`` of its database in ``sys.databases`` (AR6).
  There ``DB_NAME()`` is ``master`` too (AR5), and the physical name is the
  group's master, ``<group>_master``. On a server in no group, and in the
  instance's own ``master``, it is ``master``, on 2019, 2022 and 2025.
"""

from __future__ import annotations

from sopuli.driver.protocol import Cursor, DriverError
from sopuli.exit_codes import ExitCode

#: The names of the replicas of every group the instance is in (AR1), each
#: once: an instance in two groups lists itself in each.
REPLICAS = (
    "SELECT DISTINCT replica_server_name FROM sys.availability_replicas "
    "ORDER BY replica_server_name"
)

#: The physical name of the session's database (AR6), as a subquery: the
#: scope reads it in its own round trip (:data:`~sopuli.driver.mssql.scope.SCOPE`).
PHYSICAL_NAME = "(SELECT physical_database_name FROM sys.databases WHERE database_id = DB_ID())"

#: The physical name of the instance's own ``master``.
MASTER = "master"

CONTAINED_HINT = (
    "a contained Availability Group copies the logins of its own master to every "
    "replica, so two targets on its replicas would change one login under two names. "
    "Point the target at the instance itself, not at the group's listener, and manage "
    "the group's logins outside the tool (02-mssql-privileges.md §4)"
)


UNREAD_HINT = (
    "the tool login reads its database's physical_database_name in sys.databases "
    "with ALTER ANY LOGIN alone on every release measured; without it the tool cannot "
    "tell the instance's master from a contained Availability Group's, whose logins "
    "the group copies to every replica (02-mssql-privileges.md §4)"
)


class ContainedGroupMasterError(DriverError):
    """The session's database is not the instance's own ``master``: as in a
    contained Availability Group's own ``master``, whose logins the group
    copies to every replica (#1538, decision 4). The whole target is refused,
    at its scope, before any login is read: ``config``, exit 9, before
    anything is changed (invariant 4)."""

    category = "config"
    exit_code = ExitCode.CONFIG_INVALID


class MasterUnreadError(DriverError):
    """The session's database gave no physical name, so the tool cannot tell
    the instance's ``master`` from a contained group's. Refused, as an
    unknown is (invariant 4), but nothing in the config is at fault:
    ``database``, exit 1."""

    category = "database"
    exit_code = ExitCode.FAILURE


def replicas(cursor: Cursor) -> tuple[str, ...]:
    """The replicas' names, or none where the instance is in no group."""
    cursor.execute(REPLICAS)
    return tuple(str(row[0]) for row in cursor.fetchall() if row[0] is not None)


def require_instance_master(physical_name: object, *, target: str) -> None:
    """Refuse a session whose database is not the instance's own ``master``,
    by the ``physical_database_name`` the scope read.

    Only a contained group's ``master`` was measured to give another name
    (AR6), so another name is refused as one, and the message says what was
    read rather than claiming more. A name that cannot be read is refused
    too: a read that cannot say where the session is never lets it through.
    """
    name = None if physical_name is None else str(physical_name).strip()
    if name and name.lower() == MASTER:
        return
    if not name:
        raise MasterUnreadError(
            f'target "{target}" did not say which database its session is in',
            hint=UNREAD_HINT,
        )
    raise ContainedGroupMasterError(
        f'target "{target}" connects to a database whose physical name is {name}, '
        "not the instance's master, as a contained Availability Group's own master does",
        hint=CONTAINED_HINT,
    )
