"""sopuli-dba : which value tells one MariaDB server from another

#1286. On MySQL the tool refuses two targets that reach one server by
`server_uuid` (SOPULI-20008). MariaDB has no `server_uuid`. This measures, on
each server, which candidate value a tool account that holds only CREATE USER
can read, whether it survives a restart, and whether it differs between the
four servers:

  SI1  as the tool account: @@server_id, @@hostname, @@port, @@datadir,
       @@gtid_domain_id and @@server_uid, and the status variable
       server_uid. Each answers its value, or its refusal's number. A value
       that differs per server (hostname, server_uid) is checked as `read`
  SI2  the server is restarted (docker restart), and SI1 is read again. A
       value answers `same` or `changed`
  SI3  across the four servers, once all four are read: for each value,
       whether all four differ
  SI4  a replica of each server: a new container of the same image on the
       server's network, started with --server-id=2, which replication
       needs, and replicating from the server's current binary log
       position. The tool account is then created again on the server, so
       the replica holds it only through replication. SI1 is read as that
       account on both, and each value answers `same` or `differ`

The probe checks each result against the one RESULTS below records. A
difference, or a step that fails, makes it exit 1.

It MEASURES and decides nothing.

STATUS: run on 10.11.19, 11.4.13, 11.8.9 and 12.3.3, the mariadb:10.11,
mariadb:11.4, mariadb:11.8 and mariadb:12.3 images of test/compose.yaml profile
mariadb-matrix, on 2026-11-06 (#1286), with Python 3.13.12 on Windows 11
AMD64. Twice, exit 0, and the same result both times.

RESULTS -- the same on every release; RECORDED below holds each value

  SI1  the tool account reads every variable. server_id is 1, port 3306,
       datadir /var/lib/mysql/ and gtid_domain_id 0, each the default.
       hostname is the container's name. @@server_uid exists and reads a
       base64 value, such as `vmGAk3HDOBZm5rKnJnCGDtplUwQ=`. SHOW GLOBAL
       STATUS LIKE 'server_uid' returns no row
  SI2  after a restart every value is the same **but @@server_uid, which
       changes**
  SI3  hostname and @@server_uid differ between the four servers; the others
       are shared
  SI4  @@server_uid and hostname differ between a server and its replica.
       server_id differs only because the replica had to be given another.
       port, datadir and gtid_domain_id are the same

  So no value is both stable across a restart and set per server by the
  server itself. @@server_uid changes at each start. hostname differs here
  only because each container has its own; two servers on one host share
  it, and differ by port or datadir instead. Within one run, while no
  server restarts, @@server_uid tells every server apart, a replica from
  its primary included.

HOW TO RUN, against the matrix (test/README.md), from the repo root:

    .venv/Scripts/python sql/mariadb/13_server_identity_probe.py

It needs the docker CLI, and 02 beside it, with MySQL's 02, whose helpers it
uses.

THROWAWAY SERVERS ONLY. It restarts each server, creates the accounts
sopuli_probe_hash, sopuli_probe_tool and sopuli_probe_repl, and drops them at
the end, also after a failed step. It starts one replica container per server,
named after the server's container with `-replica`, and removes it after SI4.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
import time
from collections.abc import Callable
from pathlib import Path

# 02's name starts with a digit, so it is loaded by its path.
_SPEC = importlib.util.spec_from_file_location(
    "mariadb_client_hash_probe", Path(__file__).with_name("02_client_hash_probe.py")
)
assert _SPEC is not None
assert _SPEC.loader is not None
ch = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(ch)

VARIABLES = (
    "server_id",
    "hostname",
    "port",
    "datadir",
    "gtid_domain_id",
    "server_uid",
)
STATUS = "server_uid"

#: Each server's values, by name, before and after its restart.
SEEN: dict[str, dict[str, str]] = {}


def read(service: str, name: str) -> str:
    """One variable as the tool account: its value, or its refusal's number."""
    ok, out = ch.mysql(service, ch.TOOL, ch.base.TOOL_PASSWORD, f"SELECT @@global.{name}")
    return str(out) if ok else str(ch.code(out))


def status(service: str) -> str:
    ok, out = ch.mysql(
        service, ch.TOOL, ch.base.TOOL_PASSWORD, f"SHOW GLOBAL STATUS LIKE '{STATUS}'"
    )
    if not ok:
        return str(ch.code(out))
    return str(out).split("\t")[-1] if out else "no row"


def values(service: str) -> dict[str, str]:
    found = {name: read(service, name) for name in VARIABLES}
    found[f"status {STATUS}"] = status(service)
    return found


def restart(service: str) -> None:
    """docker restart, by the container name 02 uses, which honours the
    stack's project name, then wait for the server to answer."""
    subprocess.run(
        ["docker", "restart", ch.base.container(service)], check=True, capture_output=True
    )
    for _ in range(60):
        ok, _out = ch.mysql(service, "root", ch.ROOT_PASSWORD, "SELECT 1")
        if ok:
            return
        time.sleep(1)
    raise ch.StepError(f"{service}: did not come back after a restart")


#: The values that differ per server, checked in SI1 only as read.
PER_SERVER = frozenset({"hostname", "server_uid"})


def shape(found: dict[str, str]) -> dict[str, str]:
    """SI1 as RECORDED holds it: a per-server value as `read`, unless the
    read was refused, which shows as its number."""
    return {
        name: "read" if name in PER_SERVER and not value[:4].isdigit() else value
        for name, value in found.items()
    }


def cases(service: str) -> None:
    ch.base.setup(service, "Acme-Ident-pw0")
    before = values(service)
    print(f"SI1 {service}: {before}")
    ch.check(f"SI1 {service}", shape(before), RECORDED.get("SI1"))
    restart(service)
    after = values(service)
    stable = {name: "same" if after[name] == before[name] else "changed" for name in before}
    print(f"SI2 {service}: {stable}")
    ch.check(f"SI2 {service}", stable, RECORDED.get("SI2"))
    SEEN[service] = after
    if len(SEEN) == len(ch.base.SERVICES):
        compare()
    replica = f"{service}-replica"
    try:
        start_replica(service, replica)
        primary_values, replica_values = values(service), values(replica)
    finally:
        remove_replica(service, replica)
    print(f"SI4 {service}: primary {primary_values}")
    print(f"SI4 {service}: replica {replica_values}")
    apart = {
        name: "same" if replica_values[name] == primary_values[name] else "differ"
        for name in primary_values
    }
    print(f"SI4 {service}: {apart}")
    ch.check(f"SI4 {service}", apart, RECORDED.get("SI4"))


REPLICATION_USER = "sopuli_probe_repl"
REPLICATION_PASSWORD = "Acme-Repl-pw0"


def docker(*args: str) -> str:
    done = subprocess.run(["docker", *args], check=False, capture_output=True, text=True)
    if done.returncode != 0:
        raise ch.StepError(f"docker {args[0]}: {done.stderr.strip()}")
    return done.stdout.strip()


def wait_for(what: str, ready: Callable[[], bool], seconds: int = 120) -> None:
    for _ in range(seconds):
        if ready():
            return
        time.sleep(1)
    raise ch.StepError(f"{what}: not ready after {seconds} s")


def start_replica(service: str, replica: str) -> None:
    """SI4: a new server of the same image on the primary's network,
    replicating from the primary's current binary log position. The tool
    account is then created again on the primary, so the replica holds it
    only through replication, which shows that replication runs."""
    primary = ch.base.container(service)
    image = docker("inspect", "--format", "{{.Config.Image}}", primary)
    network = docker(
        "inspect", "--format", "{{range $name, $_ := .NetworkSettings.Networks}}{{$name}}{{end}}",
        primary,
    )  # fmt: skip
    ch.root(
        service,
        f"DROP USER IF EXISTS '{REPLICATION_USER}'@'%';"
        f"CREATE USER '{REPLICATION_USER}'@'%' IDENTIFIED BY '{REPLICATION_PASSWORD}';"
        f"GRANT REPLICATION SLAVE ON *.* TO '{REPLICATION_USER}'@'%'",
    )
    log_file, log_pos = ch.root(service, "SHOW MASTER STATUS").split("\t")[:2]
    docker(
        "run", "-d", "--name", ch.base.container(replica), "--network", network,
        "-e", f"MARIADB_ROOT_PASSWORD={ch.ROOT_PASSWORD}", image, "--server-id=2",
    )  # fmt: skip
    wait_for(replica, lambda: ch.mysql(replica, "root", ch.ROOT_PASSWORD, "SELECT 1")[0])
    ch.root(
        replica,
        f"CHANGE MASTER TO MASTER_HOST='{primary}', MASTER_PORT=3306,"
        f" MASTER_USER='{REPLICATION_USER}', MASTER_PASSWORD='{REPLICATION_PASSWORD}',"
        f" MASTER_LOG_FILE='{log_file}', MASTER_LOG_POS={log_pos};"
        "START SLAVE",
    )
    tool = ch.TOOL
    ch.root(
        service,
        f"DROP USER IF EXISTS '{tool}'@'%';"
        f"CREATE USER '{tool}'@'%' IDENTIFIED BY '{ch.base.TOOL_PASSWORD}';"
        f"GRANT CREATE USER ON *.* TO '{tool}'@'%'",
    )
    wait_for(
        f"{replica} replicating",
        lambda: ch.root(replica, f"SELECT COUNT(*) FROM mysql.user WHERE user = '{tool}'") == "1",
        seconds=60,
    )


def remove_replica(service: str, replica: str) -> None:
    subprocess.run(
        ["docker", "rm", "-f", ch.base.container(replica)], check=False, capture_output=True
    )
    ch.root(service, f"DROP USER IF EXISTS '{REPLICATION_USER}'@'%'")


def compare() -> None:
    """SI3, once every server was read, so the verdict that follows includes
    it. A server that failed leaves SI3 unrun, and the run fails anyway."""
    names = next(iter(SEEN.values())).keys()
    unique = {
        name: "all differ" if len({one[name] for one in SEEN.values()}) == len(SEEN) else "shared"
        for name in names
    }
    print(f"SI3: {unique}")
    ch.check("SI3", unique, RECORDED.get("SI3"))


#: Each case's results, the same on every release.
RECORDED: dict[str, dict[str, str]] = {
    "SI1": {
        "server_id": "1",
        "hostname": "read",
        "port": "3306",
        "datadir": "/var/lib/mysql/",
        "gtid_domain_id": "0",
        "server_uid": "read",
        "status server_uid": "no row",
    },
    "SI2": {
        "server_id": "same",
        "hostname": "same",
        "port": "same",
        "datadir": "same",
        "gtid_domain_id": "same",
        "server_uid": "changed",
        "status server_uid": "same",
    },
    "SI3": {
        "server_id": "shared",
        "hostname": "all differ",
        "port": "shared",
        "datadir": "shared",
        "gtid_domain_id": "shared",
        "server_uid": "all differ",
        "status server_uid": "shared",
    },
    "SI4": {
        "server_id": "differ",
        "hostname": "differ",
        "port": "same",
        "datadir": "same",
        "gtid_domain_id": "same",
        "server_uid": "differ",
        "status server_uid": "same",
    },
}


def main() -> int:
    # 02's run tears each server down after its cases, also after a failure.
    result: int = ch.run(cases)
    return result


if __name__ == "__main__":
    sys.exit(main())
