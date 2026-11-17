"""sopuli-dba : what the tool login reads of an Availability Group

#1550. `02-mssql-privileges.md` §4 has `doctor` warn when a target is in a
group whose other replicas the config does not declare, and refuse a login in
a contained group's own master. 08 read the group as sa. This measures what
the tool login reads, on a group of two replicas made as 08 makes it, on each
replica, as a login made there with ALTER ANY LOGIN:

  AR1  with ALTER ANY LOGIN alone: the rows of sys.availability_groups and
       sys.availability_replicas, and the local row of
       sys.dm_hadr_availability_replica_states (its role), or the refusal
  AR2  the same with VIEW SERVER STATE as well
  AR3  2022 and later: the same with VIEW SERVER PERFORMANCE STATE alone,
       and with VIEW SERVER SECURITY STATE alone; and with each, whether the
       tool login sees another login's session in sys.dm_exec_sessions,
       which is why §3 refuses VIEW SERVER STATE
  AR4  with ALTER ANY LOGIN alone, two reads that name the role without the
       DMV: sys.fn_hadr_is_primary_replica of the group's database, and
       DATABASEPROPERTYEX(database, 'Updateability')
  AR5  2022 and later, in a contained group: as the tool login made in the
       group's own master, on the primary, what DB_NAME() names, and the
       rows of sys.availability_groups it reads, with is_contained, with
       ALTER ANY LOGIN alone and with VIEW ANY DEFINITION
  AR6  with ALTER ANY LOGIN alone, what a session reads of where it is:
       DB_ID(), ORIGINAL_DB_NAME(), its database's name and
       physical_database_name in sys.databases, and how many databases it
       lists; in the contained group's master and the instance's, and on the
       matrix's own server, in no group, on every release

Each answer is the value read, `-` for none, or the error numbers.
16.0.4325.4 forms no group (08, AG0), so only AR6 on a server in no group is
measured there.

THROWAWAY SERVERS ONLY. It starts and removes two containers per server as 08
does, makes the login sopuli_probe_agtool on each replica, and in the contained
group's master on the primary, and grants it what each case names.

STATUS: run on 15.0.4510.2, 16.0.4325.4 and 17.0.5065.9, the
mcr.microsoft.com/mssql/server 2019-latest, 2022-latest and 2025-latest images
of test/compose.yaml profile mssql-matrix, as pulled on 2026-11-15, in Docker
Desktop on WSL 2, with Python 3.13.12 on Windows 11 AMD64, on 2026-11-17
(#1550). Four times while the probe was written, once of them stopped by a
replica that did not start in two minutes, and twice more against this
header, exit 0. Every run of a case gave the same result.

RESULTS -- the same on 15.0.4510.2 and 17.0.5065.9, on both replicas

  AR1  **with ALTER ANY LOGIN alone the tool login reads the replicas and
       not the group**: sys.availability_replicas gives both, with their
       names, and sys.availability_groups no row. The local row of
       sys.dm_hadr_availability_replica_states is refused, 262 and 297
  AR2  VIEW SERVER STATE reads the role, PRIMARY or SECONDARY, and every
       session, sa's among them; still no group row. VIEW ANY DEFINITION
       reads the group's row (is_contained 0), and not the role
  AR3  on 17.0.5065.9, VIEW SERVER PERFORMANCE STATE reads the role and
       every session, as VIEW SERVER STATE does. VIEW SERVER SECURITY STATE
       reads neither
  AR4  sys.fn_hadr_is_primary_replica is refused, 297.
       DATABASEPROPERTYEX's Updateability reads READ_WRITE on the primary
       and READ_ONLY on the secondary, which a database outside any group
       can read too
  AR5  on 17.0.5065.9, **in the contained group's master DB_NAME() is
       master**. With ALTER ANY LOGIN alone the tool login reads no group
       there or in the instance's master. With VIEW ANY DEFINITION it reads
       both groups in both, the contained one with is_contained 1
  AR6  **physical_database_name tells the contained group's master**: there
       it is sopuli_probe_cag_master, which ORIGINAL_DB_NAME() also gives
       for a connection that named it, and the session lists 4 databases;
       in the instance's master both are master, and 8 are listed. On a
       server in no group, on every release, 16.0.4325.4 included, the
       session reads 1|master|master|4|master

HOW TO RUN, against the matrix (test/README.md), from the repo root:

    .venv/Scripts/python sql/mssql/14_availability_group_reads_probe.py

It needs 02_client_hash_probe.py and 08_availability_group_probe.py beside it,
and the matrix running.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def _load(name: str, file: str) -> object:
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(file))
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# 02's and 08's names start with a digit, so they are loaded by their paths.
ag: object = _load("mssql_availability_group_probe", "08_availability_group_probe.py")
ch = ag.ch  # type: ignore[attr-defined]

TOOL = "sopuli_probe_agtool"
#: A test password, not a credential.
TOOL_PASSWORD = "Acme-AGtool-pw1"

GROUP_VIEWS = (
    "SELECT CAST((SELECT COUNT(*) FROM sys.availability_groups) AS varchar(5)) + ',' "
    "+ CAST((SELECT COUNT(*) FROM sys.availability_replicas) AS varchar(5))"
)
ROLE = "SELECT role_desc FROM sys.dm_hadr_availability_replica_states WHERE is_local = 1"
#: `yes` where the tool login sees a session of sa's, the probe's own; how
#: many differs between runs.
SESSIONS = (
    "SELECT CASE WHEN EXISTS (SELECT 1 FROM sys.dm_exec_sessions "
    "WHERE login_name = 'sa' AND session_id <> @@SPID) THEN 'yes' ELSE 'no' END"
)
#: The groups read, `name:is_contained`, or `-`.
GROUPS = (
    "SELECT ISNULL(STRING_AGG(name + ':' + CAST(is_contained AS varchar(1)), ' ') "
    "WITHIN GROUP (ORDER BY name), '-') FROM sys.availability_groups"
)


def read(side: str, statement: str, database: str = "master") -> str:
    """The tool login's answer: the value, `-` for no row, or the error numbers."""
    out, errors = ch.client(side, TOOL, TOOL_PASSWORD, statement, database)
    if errors:
        return ch.code(errors)
    return out or "-"


def make_tool(side: str, database: str = "master") -> None:
    ch.sa(
        side,
        f"IF SUSER_ID('{TOOL}') IS NULL CREATE LOGIN [{TOOL}] "
        f"WITH PASSWORD = {ch.quote(TOOL_PASSWORD)}, CHECK_POLICY = OFF;\n"
        f"GRANT ALTER ANY LOGIN TO [{TOOL}]",
        database,
    )


def with_grant(side: str, grant: str, body: object) -> object:
    ch.sa(side, f"GRANT {grant} TO [{TOOL}]")
    try:
        return body()  # type: ignore[operator]
    finally:
        ch.sa(side, f"REVOKE {grant} FROM [{TOOL}]")


def views(side: str) -> str:
    """`groups,replicas|role`, as the tool login reads them."""
    return f"{read(side, GROUP_VIEWS)}|{read(side, ROLE)}"


#: The replicas' names, as the tool login reads them.
REPLICA_NAMES = (
    "SELECT ISNULL(STRING_AGG(replica_server_name, ' ') "
    "WITHIN GROUP (ORDER BY replica_server_name), '-') FROM sys.availability_replicas"
)

#: AR6: what a session reads of where it is, with ALTER ANY LOGIN alone:
#: DB_ID(), ORIGINAL_DB_NAME(), its database's row in sys.databases, and the
#: count of databases it lists.
WHERE_AM_I = (
    "SELECT CAST(DB_ID() AS varchar(5)) + '|' + ISNULL(ORIGINAL_DB_NAME(), '-') + '|' "
    "+ ISNULL((SELECT name FROM sys.databases WHERE database_id = DB_ID()), '-') + '|' "
    "+ CAST((SELECT COUNT(*) FROM sys.databases) AS varchar(5)) + '|' "
    "+ ISNULL((SELECT physical_database_name FROM sys.databases WHERE database_id = DB_ID()), "
    "'-')"
)


def cases(service: str) -> None:
    found = ch.release(service)
    major = found.split(".")[0]
    print(f"\n== {service}: {found}")
    results: dict[str, str] = {}
    # AR6 on the matrix's own server, in no group: the read the driver makes.
    make_tool(service)
    try:
        results["AR6 a server in no group"] = read(service, WHERE_AM_I)
    finally:
        ch.sa(service, ch.drop_login(TOOL))
    if major == "16":
        results["AR group"] = "not measured: no group forms (08, AG0)"
    else:
        ag.start(service)  # type: ignore[attr-defined]
        ag.endpoints(service)  # type: ignore[attr-defined]
        ag.group(service, ag.GROUP, ag.DATABASE, contained=False)  # type: ignore[attr-defined]
        measure(service, major, results)
    for label, value in results.items():
        print(f"{label}: {value}")
        recorded = RECORDED.get((major, label), RECORDED.get(label))
        ch.check(f"{service} {label}", value, recorded)


def measure(service: str, major: str, results: dict[str, str]) -> None:
    sides = (("primary", ag.replica(service, 1)), ("secondary", ag.replica(service, 2)))  # type: ignore[attr-defined]
    database = ag.DATABASE  # type: ignore[attr-defined]
    for _, side in sides:
        make_tool(side)
    for label, side in sides:
        results[f"AR1 {label}"] = views(side)
        results[f"AR1 {label}, replica names"] = read(side, REPLICA_NAMES)
        results[f"AR2 {label}, VIEW SERVER STATE"] = str(
            with_grant(side, "VIEW SERVER STATE", lambda s=side: f"{views(s)}|{read(s, SESSIONS)}")
        )
        results[f"AR2 {label}, VIEW ANY DEFINITION"] = str(
            with_grant(side, "VIEW ANY DEFINITION", lambda s=side: f"{views(s)}|{read(s, GROUPS)}")
        )
        if major != "15":
            for grant in ("VIEW SERVER PERFORMANCE STATE", "VIEW SERVER SECURITY STATE"):
                results[f"AR3 {label}, {grant}"] = str(
                    with_grant(side, grant, lambda s=side: f"{views(s)}|{read(s, SESSIONS)}")
                )
        results[f"AR4 {label}"] = (
            read(side, f"SELECT CAST(sys.fn_hadr_is_primary_replica(N'{database}') AS varchar(2))")
            + "|"
            + read(
                side,
                f"SELECT CAST(DATABASEPROPERTYEX(N'{database}', 'Updateability') AS varchar(20))",
            )
        )
    if major != "15":
        one = ag.replica(service, 1)  # type: ignore[attr-defined]
        ag.group(service, ag.CONTAINED, ag.CONTAINED_DATABASE, contained=True)  # type: ignore[attr-defined]
        master = f"{ag.CONTAINED}_master"  # type: ignore[attr-defined]
        ag.synchronized(service, master)  # type: ignore[attr-defined]
        make_tool(one, master)
        results["AR5 DB_NAME() in the group's master"] = read(one, "SELECT DB_NAME()", master)
        results["AR5 groups read there"] = read(one, GROUPS, master)
        results["AR5 groups read in the instance's master"] = read(one, GROUPS)
        ch.sa(one, f"GRANT VIEW ANY DEFINITION TO [{TOOL}]", master)
        ch.sa(one, f"GRANT VIEW ANY DEFINITION TO [{TOOL}]")
        try:
            results["AR5 groups read there, VIEW ANY DEFINITION"] = read(one, GROUPS, master)
            results["AR5 groups read in the instance's master, VIEW ANY DEFINITION"] = read(
                one, GROUPS
            )
        finally:
            ch.sa(one, f"REVOKE VIEW ANY DEFINITION FROM [{TOOL}]", master)
            ch.sa(one, f"REVOKE VIEW ANY DEFINITION FROM [{TOOL}]")
        for where, database in (
            ("the group's master", master),
            ("the instance's master", "master"),
        ):
            results[f"AR6 {where}"] = read(one, WHERE_AM_I, database)


def probe(service: str) -> None:
    ch.cleaned(service, lambda: cases(service), lambda: ag.remove(service))  # type: ignore[attr-defined]


#: What every release answered, by label; by (major release, label) where one differs.
RECORDED: dict[object, str] = {
    "AR6 a server in no group": "1|master|master|4|master",
    "AR1 primary": "0,2|262,297",
    "AR1 secondary": "0,2|262,297",
    ("15", "AR1 primary, replica names"): "sopuli2019ag1 sopuli2019ag2",
    ("15", "AR1 secondary, replica names"): "sopuli2019ag1 sopuli2019ag2",
    ("17", "AR1 primary, replica names"): "sopuli2025ag1 sopuli2025ag2",
    ("17", "AR1 secondary, replica names"): "sopuli2025ag1 sopuli2025ag2",
    "AR2 primary, VIEW SERVER STATE": "0,2|PRIMARY|yes",
    "AR2 secondary, VIEW SERVER STATE": "0,2|SECONDARY|yes",
    "AR2 primary, VIEW ANY DEFINITION": "1,2|262,297|sopuli_probe_ag:0",
    "AR2 secondary, VIEW ANY DEFINITION": "1,2|262,297|sopuli_probe_ag:0",
    "AR3 primary, VIEW SERVER PERFORMANCE STATE": "0,2|PRIMARY|yes",
    "AR3 secondary, VIEW SERVER PERFORMANCE STATE": "0,2|SECONDARY|yes",
    "AR3 primary, VIEW SERVER SECURITY STATE": "0,2|262,297|no",
    "AR3 secondary, VIEW SERVER SECURITY STATE": "0,2|262,297|no",
    "AR4 primary": "297|READ_WRITE",
    "AR4 secondary": "297|READ_ONLY",
    "AR5 DB_NAME() in the group's master": "master",
    "AR5 groups read there": "-",
    "AR5 groups read in the instance's master": "-",
    "AR5 groups read there, VIEW ANY DEFINITION": "sopuli_probe_ag:0 sopuli_probe_cag:1",
    "AR5 groups read in the instance's master, VIEW ANY DEFINITION": (
        "sopuli_probe_ag:0 sopuli_probe_cag:1"
    ),
    "AR6 the group's master": "1|sopuli_probe_cag_master|master|4|sopuli_probe_cag_master",
    "AR6 the instance's master": "1|master|master|8|master",
    ("16", "AR group"): "not measured: no group forms (08, AG0)",
}


def main() -> int:
    return int(ch.run(probe))


if __name__ == "__main__":
    sys.exit(main())
