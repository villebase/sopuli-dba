"""What a SQL Server session finds when it looks at itself. Tier 0.

A login with only ``ALTER ANY LOGIN`` makes every read here: the release, the
engine edition and whether ``master`` takes writes (measured on 16.0.4325.4,
#1549). Nothing branches on the release (invariant 3); it is read to report
it.

**The session's encryption is not read from the server.**
``sys.dm_exec_connections.encrypt_option`` needs ``VIEW SERVER STATE``, which
the tool login does not hold: the read is refused, ``300``.
``CONNECTIONPROPERTY`` names no encryption. So the answer comes from the
client: under ``Encrypt=yes`` and ``strict``, ODBC Driver 18 refuses to
connect without TLS, and the session reads ``encrypt_option`` ``TRUE``
(``06_client_library_probe.py``, CL1; ``10_client_tls_probe.py``). Under
``optional`` the connection is encrypted only where the server forces it, and
the answer is unknown.
"""

from __future__ import annotations

from sopuli.config.model import TargetMssql
from sopuli.config.targets import MSSQL_OPTIONAL
from sopuli.driver.mssql import groups
from sopuli.driver.protocol import (
    ENCRYPTION_TLS,
    EXPIRE_ON_RESET,
    SERVER,
    UNKNOWN,
    Cursor,
    DriverError,
    Encryption,
    Scope,
)
from sopuli.exit_codes import ExitCode

#: ``scope.open_mode``, in the words P1 uses for an Oracle database.
READ_WRITE = "READ WRITE"
READ_ONLY = "READ ONLY"

#: The release, the engine edition, ``master``'s updateability, and the
#: physical name of the session's database
#: (:func:`~sopuli.driver.mssql.groups.require_instance_master`), in one round
#: trip.
SCOPE = (
    "SELECT CAST(SERVERPROPERTY('ProductVersion') AS nvarchar(128)), "
    "CAST(SERVERPROPERTY('EngineEdition') AS int), "
    "CAST(DATABASEPROPERTYEX('master', 'Updateability') AS nvarchar(60)), "
    f"{groups.PHYSICAL_NAME}"
)

#: ``SERVERPROPERTY('EngineEdition')`` of the Azure services that are a
#: logical server rather than an instance, by Microsoft's documentation: Azure
#: SQL Database, and Azure Synapse's dedicated and serverless pools. Not
#: measured: no image of any exists.
LOGICAL_SERVERS = {5: "Azure SQL Database", 6: "Azure Synapse", 11: "Azure Synapse serverless"}

UNENCRYPTED_HINT = (
    "`mssql.encrypt: optional` lets the connection go unencrypted, and the tool login "
    "cannot read whether it is: sys.dm_exec_connections needs VIEW SERVER STATE. Set "
    "`encrypt: mandatory`"
)


class NotAnInstanceError(DriverError):
    """A ``type: mssql`` target reached Azure SQL Database or Azure Synapse.

    Neither is an instance whose ``master`` holds logins the tool can manage
    (#1538, decision 1). ``config``, exit 9: nothing in the run fixes it.
    """

    category = "config"
    exit_code = ExitCode.CONFIG_INVALID


def encryption(settings: TargetMssql) -> Encryption:
    """The session's encryption, from what the client enforced."""
    if settings.encrypt == MSSQL_OPTIONAL:
        return Encryption(method=UNKNOWN, protocol="tcp", hint=UNENCRYPTED_HINT)
    return Encryption(method=ENCRYPTION_TLS, protocol="tcp")


def observe(cursor: Cursor, *, target: str, settings: TargetMssql) -> Scope:
    """This session's scope: a server, whether ``master`` takes writes, and
    its encryption. A logical server, such as Azure SQL Database, is refused
    before anything else is reported (:class:`NotAnInstanceError`), and then a
    session whose database is not the instance's ``master``, as in a contained
    Availability Group's (:func:`~sopuli.driver.mssql.groups.require_instance_master`)."""
    cursor.execute(SCOPE)
    version, edition, updateability, physical_name = cursor.fetchone()
    if edition in LOGICAL_SERVERS:
        raise NotAnInstanceError(
            f'target "{target}" is {LOGICAL_SERVERS[edition]}, which the SQL Server driver '
            "does not manage",
            hint=(
                "it keeps its logins in a logical server's master, which the tool cannot "
                "manage. Declare a SQL Server instance or an Azure SQL Managed Instance"
            ),
        )
    groups.require_instance_master(physical_name, target=target)
    can_write = str(updateability).upper() == "READ_WRITE"
    return Scope(
        type=SERVER,
        db_version=str(version),
        db_release=str(version),
        open_mode=READ_WRITE if can_write else READ_ONLY,
        read_write=can_write,
        # `MUST_CHANGE` with a new password, which UC-2's seen reset sends;
        # never `expire_password`, because it comes only with a new
        # password (#1554, Q8).
        capabilities=frozenset({EXPIRE_ON_RESET}),
        encryption=encryption(settings),
    )
