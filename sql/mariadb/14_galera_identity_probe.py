"""sopuli-dba : which value tells one Galera cluster from another

#1346. The tool refuses two MariaDB targets that reach one server by
@@server_uid (SOPULI-20008, #1286). The nodes of one Galera cluster share
their accounts, because CREATE USER and ALTER USER replicate, but each node is
a server of its own. This measures which value a tool account that holds only
CREATE USER reads the same on every node of one cluster and differently on
another cluster, and whether it survives restarts. The tool account's other
grants in 02-mariadb-privileges.md section 2.1 are table reads, and none of them
reaches a variable.

For each image it starts, on a docker network of its own, cluster A of three
nodes (a1, which bootstraps it, a2 and a3), cluster B of one node (b1), and a
server without Galera (p1). Both clusters keep the default cluster name.
Joining nodes copy the data by rsync. The candidates are @@server_uid,
@@wsrep_cluster_name and @@wsrep_on, the status variables
wsrep_cluster_state_uuid, wsrep_local_state_uuid and wsrep_gcomm_uuid, and the
column mysql.wsrep_cluster.cluster_uuid:

  GI1  as the tool account on a1: each candidate answers its value, or its
       refusal's number. A value that differs per node or per cluster is
       checked as `read`
  GI2  within cluster A: for each candidate, whether the three nodes share it
       or all differ
  GI3  between a1 and b1: `same` or `differ`
  GI4  a2 is restarted (docker restart), and rejoins. Each candidate on a2
       answers `same` or `changed`
  GI5  the whole of A is stopped, a3, then a2, then a1, and started again in
       the other order: a1 bootstraps, as the last node to stop. Each
       candidate on a1 answers `same` or `changed`
  GI6  as the tool account on p1, which has no Galera: each candidate's
       answer
  GI7  a password set on a1 by ALTER USER, then a login with it on a2 and on
       a3, from inside the node, at once. Twenty times, each with a new
       password. Answers how many logins failed on each node

The probe checks each result against the one RECORDED below holds. A
difference, or a step that fails, makes it exit 1.

It MEASURES and decides nothing.

STATUS: run on 10.11.19, 11.4.13, 11.8.9 and 12.3.3, the mariadb:10.11,
mariadb:11.4, mariadb:11.8 and mariadb:12.3 images of test/compose.yaml profile
mariadb-matrix, on 2026-11-06 (#1346), with Python 3.13.12 on Windows 11
AMD64. Twice, exit 0, and the same result both times.

RESULTS -- the same on every release; RECORDED below holds each value

  GI1  the tool account reads every variable and status variable.
       wsrep_cluster_state_uuid and wsrep_local_state_uuid are one UUID, such
       as `ed105c80-da14-11f1-8404-db003b3a7fb6`. wsrep_cluster_name is
       `my_wsrep_cluster`, the default. mysql.wsrep_cluster is refused,
       1142
  GI2  within cluster A, server_uid and wsrep_gcomm_uuid differ on every
       node. wsrep_cluster_state_uuid and wsrep_local_state_uuid are shared
  GI3  between A and B, wsrep_cluster_state_uuid differs. wsrep_cluster_name
       is the same, because both keep the default
  GI4  after a2 restarts and rejoins, wsrep_cluster_state_uuid is the same.
       server_uid and wsrep_gcomm_uuid change
  GI5  after the whole cluster stops and starts again, wsrep_cluster_state_uuid
       is the same on a1
  GI6  without Galera, wsrep_on is 0, wsrep_cluster_state_uuid is an empty
       value, and wsrep_local_state_uuid and wsrep_gcomm_uuid have no row.
       wsrep_cluster_name is the same default as on a cluster
  GI7  no login failed: a password set on a1 logged in on a2 and on a3 at
       once, 20 times out of 20 on each node

  So wsrep_cluster_state_uuid is the value one cluster shares and another
  does not, and it survives a node's restart and the cluster's. An account
  with only CREATE USER reads it, and a server without Galera answers it
  empty, which tells the two apart. wsrep_cluster_name tells nothing apart
  where it is left at its default. A cluster bootstrapped again from new data
  was not measured; it would be expected to get a new UUID.

HOW TO RUN, from the repo root, with the images of test/compose.yaml profile
mariadb-matrix pulled:

    .venv/Scripts/python sql/mariadb/14_galera_identity_probe.py [image ...]

With no image it runs mariadb:10.11, mariadb:11.4, mariadb:11.8 and
mariadb:12.3, one after another. It needs the docker CLI, and no stack: it
starts its own containers.

THROWAWAY CONTAINERS ONLY. It starts five containers per image, named
sopuli-galera-<release>-<node>, such as sopuli-galera-118-a1, on the network
sopuli-galera-<release>, and removes them with their volumes, and the network,
after the image's cases, also after a failed step, and before it starts them
in case an interrupted run left them. The root password goes to each container
by the environment, not argv.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import time
from collections.abc import Callable, Sequence
from functools import partial

IMAGES = ("mariadb:10.11", "mariadb:11.4", "mariadb:11.8", "mariadb:12.3")
ROOT_PASSWORD = "Acme-Galera-root0"
TOOL = "sopuli_probe_tool"
TOOL_PASSWORD = "Acme-Galera-tool0"
APP = "sopuli_probe_app"
TRIES = 20

VARIABLES = ("server_uid", "wsrep_cluster_name", "wsrep_on")
STATUS = ("wsrep_cluster_state_uuid", "wsrep_local_state_uuid", "wsrep_gcomm_uuid")
TABLE = "mysql.wsrep_cluster.cluster_uuid"

#: The candidates whose value differs per node or per cluster, checked in GI1
#: only as `read`.
PER_NODE = frozenset({"server_uid", *STATUS, TABLE})

CLUSTER_A = ("a1", "a2", "a3")
GALERA = (
    "--wsrep_on=ON",
    "--wsrep_provider=/usr/lib/galera/libgalera_smm.so",
    "--binlog_format=ROW",
    "--innodb_autoinc_lock_mode=2",
    "--wsrep_sst_method=rsync",
)


class StepError(Exception):
    """A step that could not be made, as against a result that differs."""


FAILURES: list[str] = []


def docker(*args: str, env: dict[str, str] | None = None, check: bool = True) -> str:
    done = subprocess.run(
        ["docker", *args],
        check=False,
        capture_output=True,
        text=True,
        env=None if env is None else {**os.environ, **env},
    )
    if check and done.returncode != 0:
        raise StepError(f"docker {' '.join(args[:2])}: {done.stderr.strip()}")
    return done.stdout.strip()


class Release:
    """One image's containers, by node name."""

    def __init__(self, image: str) -> None:
        self.image = image
        self.tag = image.split(":")[1].replace(".", "")
        self.network = f"sopuli-galera-{self.tag}"

    def name(self, node: str) -> str:
        return f"sopuli-galera-{self.tag}-{node}"

    def sql(self, node: str, user: str, password: str, statement: str) -> tuple[bool, str]:
        """One statement inside the node's container, by its socket. The
        password goes by the environment of `docker exec`, not argv."""
        done = subprocess.run(
            [
                "docker", "exec", "-e", "MYSQL_PWD", self.name(node),
                "mariadb", f"-u{user}", "-N", "-B", "-e", statement,
            ],
            check=False,
            capture_output=True,
            text=True,
            env={**os.environ, "MYSQL_PWD": password},
        )  # fmt: skip
        if done.returncode != 0:
            return False, done.stderr.strip()
        return True, done.stdout.strip()

    def root(self, node: str, statement: str) -> str:
        ok, out = self.sql(node, "root", ROOT_PASSWORD, statement)
        if not ok:
            raise StepError(f"{node}: {statement[:60]}: {out}")
        return out

    def start(self, node: str, *options: str) -> None:
        docker(
            "run", "-d", "--name", self.name(node), "--hostname", node,
            "--network", self.network, "-e", "MARIADB_ROOT_PASSWORD", self.image, *options,
            env={"MARIADB_ROOT_PASSWORD": ROOT_PASSWORD},
        )  # fmt: skip

    def remove(self) -> None:
        """Every container and its volume, then the network. It never raises,
        so in a `finally` it keeps the error that came before it."""
        for node in (*CLUSTER_A, "b1", "p1"):
            docker("rm", "-f", "-v", self.name(node), check=False)
        docker("network", "rm", self.network, check=False)


def wait_for(what: str, ready: Callable[[], bool], seconds: int = 180) -> None:
    """Ask `ready` once a second. A step that fails while a server starts
    counts as not ready yet."""
    for _ in range(seconds):
        try:
            if ready():
                return
        except StepError:
            pass
        time.sleep(1)
    raise StepError(f"{what}: not ready after {seconds} s")


def status(release: Release, node: str, name: str) -> str:
    ok, out = release.sql(node, "root", ROOT_PASSWORD, f"SHOW GLOBAL STATUS LIKE '{name}'")
    return out.split("\t")[-1] if ok and out else ""


def synced(release: Release, node: str, size: int) -> bool:
    return status(release, node, "wsrep_local_state_comment") == "Synced" and status(
        release, node, "wsrep_cluster_size"
    ) == str(size)


def answers(release: Release, node: str) -> bool:
    ok, _out = release.sql(node, "root", ROOT_PASSWORD, "SELECT 1")
    return ok


def bring_up(release: Release) -> None:
    release.remove()
    docker("network", "create", release.network)
    address = "--wsrep_cluster_address=gcomm://" + ",".join(CLUSTER_A)
    # a1 always bootstraps: GI4 restarts a2, never a1, and GI5 stops a1 last,
    # which makes it the node safe to bootstrap from.
    release.start("a1", *GALERA, address, "--wsrep-new-cluster")
    wait_for("a1", lambda: synced(release, "a1", 1))
    for count, node in enumerate(("a2", "a3"), start=2):
        release.start(node, *GALERA, address)
        wait_for(node, partial(synced, release, node, count))
    release.start("b1", *GALERA, "--wsrep_cluster_address=gcomm://b1", "--wsrep-new-cluster")
    release.start("p1")
    wait_for("b1", lambda: synced(release, "b1", 1))
    wait_for("p1", lambda: answers(release, "p1"))
    # Created on a1 and b1, so A's other nodes hold it only by replication.
    for node in ("a1", "b1", "p1"):
        release.root(
            node,
            f"DROP USER IF EXISTS '{TOOL}'@'%';"
            f"CREATE USER '{TOOL}'@'%' IDENTIFIED BY '{TOOL_PASSWORD}';"
            f"GRANT CREATE USER ON *.* TO '{TOOL}'@'%'",
        )
    for node in ("a2", "a3"):
        wait_for(f"{node} replicating", partial(holds_tool, release, node), seconds=30)


def holds_tool(release: Release, node: str) -> bool:
    count = release.root(node, f"SELECT COUNT(*) FROM mysql.user WHERE user = '{TOOL}'")
    return count == "1"


REFUSAL = re.compile(r"ERROR (\d+) \((\w+)\)")


def refusal(out: str) -> str:
    found = REFUSAL.search(out)
    return f"{found.group(1)} ({found.group(2)})" if found else f"error: {out[:80]}"


def values(release: Release, node: str) -> dict[str, str]:
    """Each candidate as the tool account: its value, `no row`, `empty`, or
    its refusal's number."""
    found: dict[str, str] = {}
    for name in VARIABLES:
        ok, out = release.sql(node, TOOL, TOOL_PASSWORD, f"SELECT @@global.{name}")
        found[name] = (out or "empty") if ok else refusal(out)
    for name in STATUS:
        ok, out = release.sql(node, TOOL, TOOL_PASSWORD, f"SHOW GLOBAL STATUS LIKE '{name}'")
        if not ok:
            found[name] = refusal(out)
        elif not out:
            found[name] = "no row"
        else:
            found[name] = out.split("\t", 1)[1] if "\t" in out else "empty"
            found[name] = found[name] or "empty"
    ok, out = release.sql(node, TOOL, TOOL_PASSWORD, "SELECT cluster_uuid FROM mysql.wsrep_cluster")
    found[TABLE] = (out or "no row") if ok else refusal(out)
    return found


def shape(found: dict[str, str]) -> dict[str, str]:
    """GI1 as RECORDED holds it: a per-node value as `read`, unless it was
    refused or absent."""
    return {
        name: "read" if name in PER_NODE and not unread(value) else value
        for name, value in found.items()
    }


def unread(value: str) -> bool:
    """Absent, or refused, which shows as its number and SQLSTATE."""
    return (
        value in ("no row", "empty")
        or value.startswith("error")
        or re.fullmatch(r"\d+ \(\w+\)", value) is not None
    )


def check(case: str, image: str, got: object) -> None:
    expected = RECORDED.get(case)
    if expected is None:
        FAILURES.append(f"{case} {image}: not recorded")
        print(f"  {case}: UNRECORDED {got}")
    elif got != expected:
        FAILURES.append(f"{case} {image}: {got} != {expected}")
        print(f"  {case}: DIFFERS {got}")
    else:
        print(f"  {case}: as recorded")


def compare(found: Sequence[dict[str, str]]) -> dict[str, str]:
    out = {}
    for name in found[0]:
        seen = len({one[name] for one in found})
        out[name] = "shared" if seen == 1 else "all differ" if seen == len(found) else "some differ"
    return out


def side_by_side(
    before: dict[str, str], after: dict[str, str], same: str, other: str
) -> dict[str, str]:
    return {name: same if after[name] == before[name] else other for name in before}


def full_restart(release: Release) -> None:
    for node in ("a3", "a2", "a1"):
        docker("stop", "-t", "60", release.name(node))
    docker("start", release.name("a1"))
    wait_for("a1 after the cluster stopped", lambda: synced(release, "a1", 1))
    for count, node in enumerate(("a2", "a3"), start=2):
        docker("start", release.name(node))
        wait_for(f"{node} after the cluster stopped", partial(synced, release, node, count))


def propagation(release: Release) -> dict[str, int]:
    """GI7: ALTER USER on a1, then a login on the other node at once, both
    from inside that node's container, so no `docker exec` start lies between
    them. The root and new passwords go by the environment."""
    release.root(
        "a1",
        f"DROP USER IF EXISTS '{APP}'@'%';CREATE USER '{APP}'@'%' IDENTIFIED BY 'Acme-App-pw0'",
    )
    script = (
        'MYSQL_PWD="$ROOT_PW" mariadb -h a1 -uroot -e "ALTER USER \'' + APP + "'@'%' "
        'IDENTIFIED BY \'$NEW_PW\'" && MYSQL_PWD="$NEW_PW" mariadb -u' + APP + ' -N -e "SELECT 1"'
    )
    failed: dict[str, int] = {}
    for node in ("a2", "a3"):
        failed[node] = 0
        for attempt in range(TRIES):
            new = f"Acme-App-{node}-{attempt}x"
            done = subprocess.run(
                [
                    "docker", "exec", "-e", "ROOT_PW", "-e", "NEW_PW", release.name(node),
                    "sh", "-c", script,
                ],
                check=False,
                capture_output=True,
                text=True,
                env={**os.environ, "ROOT_PW": ROOT_PASSWORD, "NEW_PW": new},
            )  # fmt: skip
            if done.returncode != 0:
                if "1045" not in done.stderr:
                    raise StepError(f"GI7 {node}: {done.stderr.strip()}")
                failed[node] += 1
    return failed


def cases(image: str) -> None:
    release = Release(image)
    print(f"{image}:")
    try:
        bring_up(release)
        version = release.root("a1", "SELECT VERSION()")
        print(f"  version {version}")
        a = {node: values(release, node) for node in CLUSTER_A}
        print(f"  GI1 a1 {a['a1']}")
        check("GI1", image, shape(a["a1"]))
        for node in ("a2", "a3"):
            print(f"  GI1 {node} {a[node]}")
        check("GI2", image, compare(list(a.values())))
        b = values(release, "b1")
        print(f"  GI3 b1 {b}")
        check("GI3", image, side_by_side(a["a1"], b, "same", "differ"))

        docker("restart", "-t", "60", release.name("a2"))
        wait_for("a2 after a restart", lambda: synced(release, "a2", 3))
        again = values(release, "a2")
        print(f"  GI4 a2 {again}")
        check("GI4", image, side_by_side(a["a2"], again, "same", "changed"))

        before = values(release, "a1")
        full_restart(release)
        after = values(release, "a1")
        print(f"  GI5 a1 {after}")
        check("GI5", image, side_by_side(before, after, "same", "changed"))

        plain = values(release, "p1")
        print(f"  GI6 p1 {plain}")
        check("GI6", image, shape(plain))

        failed = propagation(release)
        print(f"  GI7 failed logins out of {TRIES}: {failed}")
        check("GI7", image, failed)
    except StepError as error:
        FAILURES.append(f"{image}: step failed: {error}")
        print(f"  STEP FAILED: {error}")
    finally:
        release.remove()


#: Each case's results, the same on every release.
RECORDED: dict[str, object] = {
    "GI1": {
        "server_uid": "read",
        "wsrep_cluster_name": "my_wsrep_cluster",
        "wsrep_on": "1",
        "wsrep_cluster_state_uuid": "read",
        "wsrep_local_state_uuid": "read",
        "wsrep_gcomm_uuid": "read",
        TABLE: "1142 (42000)",
    },
    "GI2": {
        "server_uid": "all differ",
        "wsrep_cluster_name": "shared",
        "wsrep_on": "shared",
        "wsrep_cluster_state_uuid": "shared",
        "wsrep_local_state_uuid": "shared",
        "wsrep_gcomm_uuid": "all differ",
        TABLE: "shared",
    },
    "GI3": {
        "server_uid": "differ",
        "wsrep_cluster_name": "same",
        "wsrep_on": "same",
        "wsrep_cluster_state_uuid": "differ",
        "wsrep_local_state_uuid": "differ",
        "wsrep_gcomm_uuid": "differ",
        TABLE: "same",
    },
    "GI4": {
        "server_uid": "changed",
        "wsrep_cluster_name": "same",
        "wsrep_on": "same",
        "wsrep_cluster_state_uuid": "same",
        "wsrep_local_state_uuid": "same",
        "wsrep_gcomm_uuid": "changed",
        TABLE: "same",
    },
    "GI5": {
        "server_uid": "changed",
        "wsrep_cluster_name": "same",
        "wsrep_on": "same",
        "wsrep_cluster_state_uuid": "same",
        "wsrep_local_state_uuid": "same",
        "wsrep_gcomm_uuid": "changed",
        TABLE: "same",
    },
    "GI6": {
        "server_uid": "read",
        "wsrep_cluster_name": "my_wsrep_cluster",
        "wsrep_on": "0",
        "wsrep_cluster_state_uuid": "empty",
        "wsrep_local_state_uuid": "no row",
        "wsrep_gcomm_uuid": "no row",
        TABLE: "1142 (42000)",
    },
    "GI7": {"a2": 0, "a3": 0},
}


def main(argv: Sequence[str]) -> int:
    for image in argv or IMAGES:
        cases(image)
    if FAILURES:
        print("\nFAILED:")
        for one in FAILURES:
            print(f"  {one}")
        return 1
    print("\nevery case as recorded")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
