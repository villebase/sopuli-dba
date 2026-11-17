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

#: The physical name of the session's database (AR6).
PHYSICAL_NAME = "SELECT physical_database_name FROM sys.databases WHERE database_id = DB_ID()"

#: The physical name of the instance's own ``master``.
MASTER = "master"

CONTAINED_HINT = (
    "a contained Availability Group copies the logins of its own master to every "
    "replica, so two targets on its replicas would change one login under two names. "
    "Point the target at the instance itself, not at the group's listener, and manage "
    "the group's logins outside the tool (02-mssql-privileges.md §4)"
)


class ContainedGroupLoginError(DriverError):
    """The session is in a contained Availability Group's own ``master``, so
    every login it reads is the group's (#1538, decision 4). ``config``,
    exit 9, before anything is changed (invariant 4)."""

    category = "config"
    exit_code = ExitCode.CONFIG_INVALID
    about_account = True

    def __init__(self, account: str, master: str, *, target: str) -> None:
        super().__init__(
            f'account "{account}" on target "{target}" is a login of a contained '
            f"Availability Group, in its master {master}",
            hint=CONTAINED_HINT,
        )


def replicas(cursor: Cursor) -> tuple[str, ...]:
    """The replicas' names, or none where the instance is in no group."""
    cursor.execute(REPLICAS)
    return tuple(str(row[0]) for row in cursor.fetchall() if row[0] is not None)


def contained_master(cursor: Cursor) -> str | None:
    """The physical name of the contained group's master the session is in,
    or ``None`` where it is in the instance's own ``master``.

    A name that is not ``master``, or no name at all, counts as a contained
    group's: a read that cannot say where the session is never lets a login
    through as the instance's."""
    cursor.execute(PHYSICAL_NAME)
    row = cursor.fetchone()
    name = None if row is None or row[0] is None else str(row[0])
    if name is not None and name.lower() == MASTER:
        return None
    return name or "(unnamed)"
