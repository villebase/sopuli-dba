"""sopuli-dba : which value tells one MariaDB server from another

#1286. On MySQL the tool refuses two targets that reach one server by
`server_uuid` (SOPULI-20008). MariaDB has no `server_uuid`. This measures, on
each server, which candidate value a tool account that holds only CREATE USER
can read, whether it survives a restart, and whether it differs between the
four servers:

  SI1  as the tool account: @@server_id, @@hostname, @@port, @@datadir,
       @@gtid_domain_id, @@server_uid where the server has the variable, and
       the status variable server_uid. Each answers its value, or its
       refusal's number
  SI2  the server is restarted (docker restart), and SI1 is read again. A
       value answers `same` or `changed`
  SI3  across the four servers: for each value, whether all four differ

A replica of one of these servers was not measured: whether a value differs
between a primary and its replica, as `server_uuid` does, stays open.

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

  So no value is both stable across a restart and set per server by the
  server itself. @@server_uid changes at each start. hostname differs here
  only because each container has its own; two servers on one host share
  it, and differ by port or datadir instead.

HOW TO RUN, against the matrix (test/README.md), from the repo root:

    .venv/Scripts/python sql/mariadb/13_server_identity_probe.py

It needs the docker CLI, and 02 beside it, with MySQL's 02, whose helpers it
uses.

THROWAWAY SERVERS ONLY. It restarts each server, creates the accounts
sopuli_probe_hash and sopuli_probe_tool, and drops them at the end, also
after a failed step.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
import time
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
    container = f"sopuli-test-{service}-1"
    subprocess.run(["docker", "restart", container], check=True, capture_output=True)
    for _ in range(60):
        ok, _out = ch.mysql(service, "root", ch.ROOT_PASSWORD, "SELECT 1")
        if ok:
            return
        time.sleep(1)
    raise ch.StepError(f"{service}: did not come back after a restart")


def probe(service: str) -> None:
    ch.cleaned(service, lambda: cases(service), lambda: ch.base.teardown(service))


def cases(service: str) -> None:
    ch.base.setup(service, "Acme-Ident-pw0")
    before = values(service)
    print(f"SI1 {service}: {before}")
    restart(service)
    after = values(service)
    stable = {name: "same" if after[name] == before[name] else "changed" for name in before}
    print(f"SI2 {service}: {stable}")
    ch.check(f"SI2 {service}", stable, RECORDED.get("SI2"))
    SEEN[service] = after


def compare() -> None:
    names = next(iter(SEEN.values())).keys() if SEEN else ()
    unique = {
        name: "all differ" if len({one[name] for one in SEEN.values()}) == len(SEEN) else "shared"
        for name in names
    }
    print(f"SI3: {unique}")
    ch.check("SI3", unique, RECORDED.get("SI3"))


#: Each case's results, the same on every release.
RECORDED: dict[str, dict[str, str]] = {
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
}


def main() -> int:
    result: int = ch.run(probe)
    compare()
    if ch.base.DIFFERENCES and result == 0:
        for difference in ch.base.DIFFERENCES:
            print(f"DIFFERS: {difference}")
        return 1
    return result


if __name__ == "__main__":
    sys.exit(main())
