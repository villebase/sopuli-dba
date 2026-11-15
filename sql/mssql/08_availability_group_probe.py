"""sopuli-dba : logins and passwords in a SQL Server Availability Group

#1538, M7. An Availability Group copies databases from a primary replica to
secondaries. Logins live in each instance's master, which no group copies,
unless the group is contained (2022 and later), which has a master of its
own. This measures, on a group of two replicas with CLUSTER_TYPE = NONE:

  AG1  a login made on the primary: whether it exists on the secondary;
       and, for a login made on both with one SID, whether a password set on
       the primary reaches the secondary: which password then logs in on
       each replica
  AG2  a user made in the group's database on the primary: whether the
       secondary has it, and whether the secondary's login of the same SID
       reaches the database through it
  AG3  what each replica reports: sys.availability_groups' name and
       group_id, its own role in sys.dm_hadr_availability_replica_states,
       and the replicas sys.availability_replicas lists. Whether the two
       give the same group_id
  AG4  on the secondary, which allows every connection: whether sa there
       can read the group's database and write to it, and whether ALTER
       LOGIN works there

AG1's reads wait until a table made on the primary after the change is in
the secondary's copy of the database: what could reach the secondary has.
  AG5  a contained group, where the release has it: a login made in the
       group's master on the primary, whether the secondary's group master
       has it, and whether a password set there on the primary logs in on
       the secondary

  AG0  whether the group forms at all: the secondary's JOIN

STATUS: run on 15.0.4510.2, 16.0.4325.4 and 17.0.5065.9, the
mcr.microsoft.com/mssql/server 2019-latest, 2022-latest and 2025-latest images
of test/compose.yaml profile mssql-matrix, as pulled on 2026-11-15, in Docker
Desktop on WSL 2 (kernel 6.6.87.2), with Python 3.13.12 on Windows 11 AMD64,
on 2026-11-15 (#1538). Twice, exit 0, and the same result every time.

RESULTS -- the same on 15.0.4510.2 and 17.0.5065.9, except AG5

  AG0  on 16.0.4325.4 **the group does not form**: the secondary's JOIN
       either fails, 47106 "Download configuration timeout", and 41158, or
       gives no answer in 300 seconds; both were seen. In the runs watched,
       the secondary's sqlservr used a full CPU from the moment the primary
       connected and stopped answering logins; with endpoint encryption off
       it failed the same way. Nothing below was measured
       on 16.0.4325.4 (unverified: mssql-ag-2022)
  AG1  **a login and its password are each replica's own**. A login made on
       the primary does not exist on the secondary (0). For a login made on
       both with one SID, a password set on the primary logs in there and is
       refused on the secondary, 18456, where the old one still logs in
  AG2  the database's users reach the secondary (2), one of them with no
       login there. The secondary's login of the same SID reaches the
       database through its user
  AG3  each replica names the group and its own role (PRIMARY, SECONDARY),
       lists both replicas, and gives the same group_id. So a tool can tell
       that two targets are replicas of one group
  AG4  on the secondary, the database reads, a write is refused, 3906 (the
       database is read-only), and ALTER LOGIN works: master is the
       secondary's own
  AG5  on 17.0.5065.9, **a contained group copies its logins**: a login
       made in the group's master on the primary is in the secondary's group
       master (1) and not in its own master (0), and a password set there on
       the primary logs in on the secondary, where the old one is refused,
       18456. 15.0.4510.2 has no contained group

HOW TO RUN, against the matrix (test/README.md), from the repo root:

    .venv/Scripts/python sql/mssql/08_availability_group_probe.py

It needs 02_client_hash_probe.py beside it, and the matrix running: for each
server, it starts two containers of the server's image,
<project>-<service>-ag1-1 and -ag2-1, with HADR on and the matrix's sa
password, on the matrix's network, and removes them at the end. It measures
nothing on the matrix's servers; 02's shared runner drops 02's logins there
if they exist.
"""

from __future__ import annotations

import importlib.util
import os
import re
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable
from pathlib import Path

# 02's name starts with a digit, so it is loaded by its path.
_SPEC = importlib.util.spec_from_file_location(
    "mssql_client_hash_probe", Path(__file__).with_name("02_client_hash_probe.py")
)
assert _SPEC is not None
assert _SPEC.loader is not None
ch = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(ch)

GROUP = "sopuli_probe_ag"
CONTAINED = "sopuli_probe_cag"
DATABASE = "sopuli_probe_agdb"
CONTAINED_DATABASE = "sopuli_probe_cagdb"
ONE_SIDE = "sopuli_probe_ag_one"
BOTH = "sopuli_probe_ag_both"
IN_GROUP = "sopuli_probe_ag_cl"
SID = "0x5A0B0C0D0E0F10111213141516171819"
#: Test passwords, not credentials.
FIRST = "Acme-AG-pw1"
SECOND = "Acme-AG-pw2"
KEY = "Acme-AG-key-1"
DATA = "/var/opt/mssql/data"


def replica(service: str, n: int) -> str:
    """The `service` name ch's helpers take for replica n: its container is
    <project>-<service>-agN-1."""
    return f"{service}-ag{n}"


def host(service: str, n: int) -> str:
    """Replica n's hostname, which is its replica name: @@SERVERNAME, which
    must be the replica's name, keeps 15 characters at most."""
    return f"sopuli{service.removeprefix('mssql-')}ag{n}"


def docker(*args: str, check: bool = True) -> str:
    try:
        done = subprocess.run(
            ["docker", *args], capture_output=True, check=False, timeout=300,
            env={**os.environ, "MSYS_NO_PATHCONV": "1", "MSSQL_SA_PASSWORD": ch.SA_PASSWORD},
        )  # fmt: skip
    except subprocess.TimeoutExpired as exc:
        raise ch.StepError(f"docker {args[0]}: no answer in 300 seconds") from exc
    if check and done.returncode != 0:
        raise ch.StepError(f"docker {args[0]}: {done.stderr.decode()[-300:]}")
    return done.stdout.decode().strip()


def start(service: str) -> None:
    """Start the two replicas from the server's image, and wait for each."""
    image = docker("inspect", "-f", "{{.Image}}", ch.container(service))
    for n in (1, 2):
        name = ch.container(replica(service, n))
        docker("rm", "-f", name, check=False)
        docker(
            "run", "-d", "--name", name, "--hostname", host(service, n),
            "--network", f"{ch.PROJECT}_default", "--network-alias", host(service, n),
            "-e", "ACCEPT_EULA=Y", "-e", "MSSQL_PID=Developer", "-e", "MSSQL_SA_PASSWORD",
            "-e", "MSSQL_ENABLE_HADR=1", image,
        )  # fmt: skip
    for n in (1, 2):
        for _ in range(60):
            try:
                if ch.sa(replica(service, n), "SELECT 1") == "1":
                    break
            except ch.StepError:
                pass
            time.sleep(2)
        else:
            raise ch.StepError(f"{replica(service, n)} never answered")


def remove(service: str) -> None:
    for n in (1, 2):
        docker("rm", "-f", ch.container(replica(service, n)), check=False)


def endpoints(service: str) -> None:
    """A certificate on the primary, copied to the secondary, and an endpoint
    on each that authenticates by it."""
    one, two = replica(service, 1), replica(service, 2)
    # The certificate's owner is the login the other replica's connection
    # maps to, which needs CONNECT on the endpoint.
    key = (
        f"CREATE MASTER KEY ENCRYPTION BY PASSWORD = {ch.quote(KEY)};\n"
        f"CREATE LOGIN sopuli_dbm WITH PASSWORD = {ch.quote(KEY)};\n"
        "CREATE USER sopuli_dbm FOR LOGIN sopuli_dbm"
    )
    ch.sa(
        one,
        f"{key};\nCREATE CERTIFICATE sopuli_ag_cert AUTHORIZATION sopuli_dbm "
        "WITH SUBJECT = 'sopuli probe';\n"
        f"BACKUP CERTIFICATE sopuli_ag_cert TO FILE = '{DATA}/sopuli_ag.cer' "
        f"WITH PRIVATE KEY (FILE = '{DATA}/sopuli_ag.pvk', "
        f"ENCRYPTION BY PASSWORD = {ch.quote(KEY)})",
    )
    with tempfile.TemporaryDirectory() as here:
        for suffix in ("cer", "pvk"):
            local = str(Path(here) / f"sopuli_ag.{suffix}")
            docker("cp", f"{ch.container(one)}:{DATA}/sopuli_ag.{suffix}", local)
            docker("cp", local, f"{ch.container(two)}:{DATA}/sopuli_ag.{suffix}")
    docker("exec", "-u", "0", ch.container(two), "chown", "mssql", f"{DATA}/sopuli_ag.cer",
           f"{DATA}/sopuli_ag.pvk")  # fmt: skip
    ch.sa(
        two,
        f"{key};\nCREATE CERTIFICATE sopuli_ag_cert AUTHORIZATION sopuli_dbm "
        f"FROM FILE = '{DATA}/sopuli_ag.cer' "
        f"WITH PRIVATE KEY (FILE = '{DATA}/sopuli_ag.pvk', "
        f"DECRYPTION BY PASSWORD = {ch.quote(KEY)})",
    )
    for side in (one, two):
        ch.sa(
            side,
            "CREATE ENDPOINT sopuli_hadr STATE = STARTED AS TCP (LISTENER_PORT = 5022) "
            "FOR DATABASE_MIRRORING (ROLE = ALL, AUTHENTICATION = CERTIFICATE "
            "sopuli_ag_cert, ENCRYPTION = REQUIRED ALGORITHM AES);\n"
            "GRANT CONNECT ON ENDPOINT::sopuli_hadr TO sopuli_dbm",
        )


def group(service: str, name: str, database: str, contained: bool) -> None:
    """Create the group on replica 1, join replica 2, and seed `database`."""
    one, two = replica(service, 1), replica(service, 2)
    spec = ",\n".join(
        f"N'{host(service, n)}' WITH (ENDPOINT_URL = N'tcp://{host(service, n)}:5022', "
        "AVAILABILITY_MODE = SYNCHRONOUS_COMMIT, FAILOVER_MODE = MANUAL, "
        "SEEDING_MODE = AUTOMATIC, SECONDARY_ROLE (ALLOW_CONNECTIONS = ALL))"
        for n in (1, 2)
    )
    options = "CLUSTER_TYPE = NONE" + (", CONTAINED" if contained else "")
    ch.sa(
        one,
        f"CREATE DATABASE [{database}];\nALTER DATABASE [{database}] SET RECOVERY FULL;\n"
        f"BACKUP DATABASE [{database}] TO DISK = N'{DATA}/{database}.bak';\n"
        f"CREATE AVAILABILITY GROUP [{name}] WITH ({options}) FOR DATABASE [{database}] "
        f"REPLICA ON {spec};\n"
        f"ALTER AVAILABILITY GROUP [{name}] GRANT CREATE ANY DATABASE",
    )
    ch.sa(
        two,
        f"ALTER AVAILABILITY GROUP [{name}] JOIN WITH (CLUSTER_TYPE = NONE);\n"
        f"ALTER AVAILABILITY GROUP [{name}] GRANT CREATE ANY DATABASE",
    )
    for _ in range(60):
        state = ch.sa(
            two,
            "SELECT ISNULL((SELECT synchronization_state_desc FROM "
            "sys.dm_hadr_database_replica_states s JOIN sys.databases d "
            f"ON d.database_id = s.database_id WHERE d.name = '{database}' "
            "AND s.is_local = 1), 'absent')",
        )
        if state == "SYNCHRONIZED":
            return
        time.sleep(2)
    raise ch.StepError(f"{service}: {database} never synchronized on the secondary: {state}")


def logs_in(side: str, user: str, password: str, database: str = "master") -> str:
    out, errors = ch.client(side, user, password, "SELECT SUSER_SNAME()", database)
    if errors:
        return ch.code(errors)
    return "logs in" if out == user else f"logs in as {out}"


def until(read: Callable[[], str], wanted: str) -> str:
    """`read()`, retried for up to 20 seconds while it is not `wanted` or
    fails: a change on the primary reaches the secondary a moment later."""
    got = ""
    for attempt in range(11):
        if attempt:
            time.sleep(2)
        try:
            got = read()
        except ch.StepError as exc:
            got = f"failed: {exc}"[:200]
            continue
        if got == wanted:
            break
    return got


def caught_up(service: str, mark: str) -> None:
    """Wait until a table made on the primary is in the secondary's copy of
    the database, so that what the primary did before it has had its chance
    to reach the secondary."""
    one, two = replica(service, 1), replica(service, 2)
    ch.sa(one, f"CREATE TABLE dbo.[{mark}] (i int)", DATABASE)
    seen = until(lambda: count(two, "sys.tables", mark, DATABASE), "1")
    if seen != "1":
        raise ch.StepError(f"{service}: {mark} never reached the secondary: {seen}")


def count(side: str, view: str, name: str, database: str = "master") -> str:
    return ch.sa(
        side, f"SELECT CAST(COUNT(*) AS varchar(5)) FROM {view} WHERE name = '{name}'", database
    )


def as_sa(side: str, statement: str, database: str = "master") -> str:
    """`ok`, or the error numbers, for a statement sa sends."""
    _, errors = ch.client(side, "sa", ch.SA_PASSWORD, statement, database)
    return ch.code(errors)


def formed(service: str) -> str:
    """`yes`, or the error numbers of the step that failed."""
    try:
        group(service, GROUP, DATABASE, contained=False)
    except ch.StepError as exc:
        # The JOIN fails with error numbers, as ch.client lists them,
        # "(47106, 'Cannot join ...')", or does not answer at all. Either
        # is `no`; which one is printed, as it differs from run to run.
        numbers = re.findall(r"\((\d+), ['\"]", str(exc))
        if numbers:
            print(f"AG0 the JOIN failed: {','.join(numbers)}")
        elif "no answer in" in str(exc):
            print(f"AG0 the JOIN did not answer: {exc}")
        else:
            raise
        return "no"
    return "yes"


def cases(service: str) -> None:
    found = ch.release(service)
    major = found.split(".")[0]
    print(f"\n== {service}: {found}")
    start(service)
    endpoints(service)
    results = {"AG0 the group forms": formed(service)}
    if results["AG0 the group forms"] == "yes":
        measure(service, major, results)
    for label, value in results.items():
        print(f"{label}: {value}")
        recorded = RECORDED.get((major, label), RECORDED.get(label))
        ch.check(f"{service} {label}", value, recorded)


def measure(service: str, major: str, results: dict[str, str]) -> None:
    one, two = replica(service, 1), replica(service, 2)
    # AG1
    ch.sa(one, f"CREATE LOGIN [{ONE_SIDE}] WITH PASSWORD = {ch.quote(FIRST)}, CHECK_POLICY = OFF")
    caught_up(service, "sopuli_probe_mark1")
    results["AG1 a login made on the primary, on the secondary"] = count(
        two, "sys.server_principals", ONE_SIDE
    )
    for side in (one, two):
        ch.sa(
            side,
            f"CREATE LOGIN [{BOTH}] WITH PASSWORD = {ch.quote(FIRST)}, SID = {SID}, "
            "CHECK_POLICY = OFF",
        )
    ch.sa(one, f"ALTER LOGIN [{BOTH}] WITH PASSWORD = {ch.quote(SECOND)}")
    caught_up(service, "sopuli_probe_mark2")
    for label, side in (("primary", one), ("secondary", two)):
        for which, password in (("first", FIRST), ("second", SECOND)):
            results[f"AG1 {label}, the {which} password"] = logs_in(side, BOTH, password)

    # AG2
    ch.sa(
        one,
        f"CREATE USER [{BOTH}] FOR LOGIN [{BOTH}]; CREATE USER [{ONE_SIDE}] FOR LOGIN [{ONE_SIDE}]",
        DATABASE,
    )
    users = (
        "SELECT CAST(COUNT(*) AS varchar(5)) FROM sys.database_principals "
        f"WHERE name IN ('{BOTH}', '{ONE_SIDE}')"
    )
    results["AG2 the users, on the secondary"] = until(lambda: ch.sa(two, users, DATABASE), "2")
    results["AG2 the shared-SID login, into the database on the secondary"] = logs_in(
        two, BOTH, FIRST, DATABASE
    )

    # AG3
    for label, side in (("primary", one), ("secondary", two)):
        results[f"AG3 {label}: group and role"] = ch.sa(
            side,
            "SELECT g.name + ',' + r.role_desc FROM sys.availability_groups g "
            "JOIN sys.dm_hadr_availability_replica_states r ON r.group_id = g.group_id "
            "AND r.is_local = 1",
        )
        results[f"AG3 {label}: replicas listed"] = ch.sa(
            side, "SELECT CAST(COUNT(*) AS varchar(5)) FROM sys.availability_replicas"
        )
    group_id = "SELECT CAST(group_id AS varchar(36)) FROM sys.availability_groups"
    ids = [ch.sa(side, group_id) for side in (one, two)]
    results["AG3 group_id"] = "the same on both" if ids[0] == ids[1] else f"differs: {ids}"

    # AG4
    results["AG4 read the database on the secondary"] = as_sa(
        two, "SELECT COUNT(*) FROM sys.tables", DATABASE
    )
    results["AG4 write the database on the secondary"] = as_sa(
        two, "CREATE TABLE dbo.sopuli_probe_w (i int)", DATABASE
    )
    results["AG4 ALTER LOGIN on the secondary"] = as_sa(
        two, f"ALTER LOGIN [{BOTH}] WITH PASSWORD = {ch.quote(SECOND)}"
    )

    # AG5
    if major == "15":
        results["AG5 contained group"] = "not on this release"
    else:
        group(service, CONTAINED, CONTAINED_DATABASE, contained=True)
        master = f"{CONTAINED}_master"
        ch.sa(
            one,
            f"CREATE LOGIN [{IN_GROUP}] WITH PASSWORD = {ch.quote(FIRST)}, CHECK_POLICY = OFF",
            master,
        )
        in_group = (
            "SELECT CAST(COUNT(*) AS varchar(5)) FROM sys.server_principals "
            f"WHERE name = '{IN_GROUP}'"
        )
        results["AG5 the login, in the secondary's group master"] = until(
            lambda: ch.sa(two, in_group, master), "1"
        )
        results["AG5 the login, in the secondary's own master"] = ch.sa(two, in_group)
        ch.sa(one, f"ALTER LOGIN [{IN_GROUP}] WITH PASSWORD = {ch.quote(SECOND)}", master)
        results["AG5 the second password, on the secondary's group master"] = until(
            lambda: logs_in(two, IN_GROUP, SECOND, master), "logs in"
        )
        results["AG5 the first password, on the secondary's group master"] = logs_in(
            two, IN_GROUP, FIRST, master
        )


def probe(service: str) -> None:
    ch.cleaned(service, lambda: cases(service), lambda: remove(service))


#: What every release answered, by label; by (major release, label) where one differs.
RECORDED: dict[object, str] = {
    "AG0 the group forms": "yes",
    ("16", "AG0 the group forms"): "no",
    "AG1 a login made on the primary, on the secondary": "0",
    "AG1 primary, the first password": "18456",
    "AG1 primary, the second password": "logs in",
    "AG1 secondary, the first password": "logs in",
    "AG1 secondary, the second password": "18456",
    "AG2 the users, on the secondary": "2",
    "AG2 the shared-SID login, into the database on the secondary": "logs in",
    "AG3 primary: group and role": f"{GROUP},PRIMARY",
    "AG3 primary: replicas listed": "2",
    "AG3 secondary: group and role": f"{GROUP},SECONDARY",
    "AG3 secondary: replicas listed": "2",
    "AG3 group_id": "the same on both",
    "AG4 read the database on the secondary": "ok",
    "AG4 write the database on the secondary": "3906",
    "AG4 ALTER LOGIN on the secondary": "ok",
    ("15", "AG5 contained group"): "not on this release",
    "AG5 the login, in the secondary's group master": "1",
    "AG5 the login, in the secondary's own master": "0",
    "AG5 the second password, on the secondary's group master": "logs in",
    "AG5 the first password, on the secondary's group master": "18456",
}


def main() -> int:
    return ch.run(probe)


if __name__ == "__main__":
    sys.exit(main())
