"""sopuli-dba : MySQL's dual passwords, RETAIN CURRENT PASSWORD

#1202. UC-1's rollover window keeps the old password working while every
reader moves to the new one. MySQL documents a second, retained password for
that. This measures, on each server, each case from the same start: the
account has password A and no retained password. A tool account that holds
only CREATE USER sends every statement:

  DP1  DISCARD OLD PASSWORD, with no retained password
  DP2  IDENTIFIED BY 'B' RETAIN CURRENT PASSWORD. Then A, B and a wrong
       password log in, and root reads mysql.user's User_attributes
  DP3  DP2, then IDENTIFIED BY 'C' RETAIN CURRENT PASSWORD
  DP4  DP2, then IDENTIFIED BY 'C' with no RETAIN
  DP5  IDENTIFIED WITH caching_sha2_password BY 'B' RETAIN CURRENT PASSWORD,
       naming the plugin the account already has
  DP6  IDENTIFIED WITH caching_sha2_password AS 0x<hash of B> RETAIN CURRENT
       PASSWORD, with the hash computed by 02_client_hash_probe.py's code
  DP7  DP2, then DISCARD OLD PASSWORD, and User_attributes again
  DP8  with a password retained, the tool account reads User_attributes, and
       SHOW CREATE USER for the account. Root runs SHOW CREATE USER too
  DP9  IDENTIFIED WITH sha256_password BY 'B' RETAIN CURRENT PASSWORD, which
       changes the account's plugin

A login is "ok", or the error number and SQLSTATE of the refusal. Logins use
the server's own mysql client, as in 02_client_hash_probe.py.

A wrong password that logs in makes the probe exit 1.

It MEASURES and decides nothing.

STATUS: run on 8.0.46, 8.4.13 and 9.7.4, the mysql:8.0, mysql:8.4 and mysql:9
images of test/compose.yaml profile mysql-matrix, on 2026-11-01 (#1202), with
Python 3.13.12 on Windows 11 AMD64. Twice, exit 0, and the same result both
times.

RESULTS -- the same on all three releases

  DP1  accepted. User_attributes is NULL
  DP2  accepted. A and B log in, and a wrong password is refused, 1045
       (28000). User_attributes has the key additional_password
  DP3  accepted. B and C log in, and A is refused: a second RETAIN replaces
       the retained password with the current one
  DP4  accepted. A and C log in, and B is refused: a change without RETAIN
       keeps the retained password
  DP5  accepted. A and B log in
  DP6  accepted. A and B log in
  DP7  accepted. B logs in, A is refused, and User_attributes is NULL again
  DP8  the tool account cannot read User_attributes, 1142 (42000), "SELECT
       command denied ... for table 'user'", nor run SHOW CREATE USER, 1044
       (42000), "Access denied ... to database 'mysql'". Root's SHOW CREATE
       USER shows one hash, the current password's, and not the retained one
  DP9  refused, 3894 (HY000), "Current password can not be retained for user
       ... because authentication plugin is being changed". A still logs in

  So a rollover window maps onto RETAIN and DISCARD, with a hash the client
  computes as well as with IDENTIFIED BY, as long as the plugin stays the
  same. A change without RETAIN leaves a retained password working. Only an
  account that can read mysql.user sees whether a password is retained.

HOW TO RUN, against the matrix (test/README.md), from the repo root:

    .venv/Scripts/python sql/mysql/03_dual_password_probe.py

It needs only the standard library and the docker CLI, and
02_client_hash_probe.py beside it. The container names follow
COMPOSE_PROJECT_NAME, so a second clone's matrix is the one it uses.

THROWAWAY SERVERS ONLY. On each server it creates the accounts
sopuli_probe_hash and sopuli_probe_tool and drops them at the end, and before
it starts it drops ones an interrupted run left.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

# 02's name starts with a digit, so it is loaded by its path.
_SPEC = importlib.util.spec_from_file_location(
    "client_hash_probe", Path(__file__).with_name("02_client_hash_probe.py")
)
assert _SPEC is not None
assert _SPEC.loader is not None
ch = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(ch)

ACCOUNT = ch.ACCOUNT
TOOL = ch.TOOL
TOOL_PASSWORD = "Acme-Tool-pw1"
A, B, C = "Acme-Probe-pwA", "Acme-Probe-pwB", "Acme-Probe-pwC"
WRONG = "Acme-Wrong-pw9"


def tool(service: str, statement: str) -> str:
    ok, out = ch.mysql(service, TOOL, TOOL_PASSWORD, statement)
    return "ok" if ok else out


def alter(service: str, clause: str) -> str:
    return tool(service, f"ALTER USER '{ACCOUNT}'@'%' {clause}")


def reset(service: str) -> None:
    """Password A, and no retained password."""
    ch.root(service, f"ALTER USER '{ACCOUNT}'@'%' IDENTIFIED BY '{A}'")
    ch.root(service, f"ALTER USER '{ACCOUNT}'@'%' DISCARD OLD PASSWORD")


def logins(service: str, *passwords: str) -> str:
    return ", ".join(f"{p[-1]}: {ch.login(service, p)}" for p in passwords)


def attributes(service: str) -> str:
    """The keys of User_attributes, which hold a retained password if there is one."""
    return ch.root(
        service,
        f"SELECT IFNULL(JSON_KEYS(User_attributes), 'NULL') FROM mysql.user "
        f"WHERE user = '{ACCOUNT}' AND host = '%'",
    )


def probe(service: str) -> bool:
    held = True
    print(f"\n== {service}: {ch.root(service, 'SELECT VERSION()')}")
    ch.root(service, f"DROP USER IF EXISTS '{ACCOUNT}'@'%', '{TOOL}'@'%'")
    ch.root(service, f"CREATE USER '{TOOL}'@'%' IDENTIFIED BY '{TOOL_PASSWORD}'")
    ch.root(service, f"GRANT CREATE USER ON *.* TO '{TOOL}'@'%'")
    ch.root(service, f"CREATE USER '{ACCOUNT}'@'%' IDENTIFIED BY '{A}'")

    reset(service)
    print(f"DP1 {alter(service, 'DISCARD OLD PASSWORD')}; attributes: {attributes(service)}")

    retain_b = f"IDENTIFIED BY '{B}' RETAIN CURRENT PASSWORD"
    reset(service)
    answer = alter(service, retain_b)
    wrong = ch.login(service, WRONG)
    held &= wrong != "ok"
    keys = attributes(service)
    print(f"DP2 {answer}; {logins(service, A, B)}, wrong: {wrong}; attributes: {keys}")

    reset(service)
    alter(service, retain_b)
    answer = alter(service, f"IDENTIFIED BY '{C}' RETAIN CURRENT PASSWORD")
    print(f"DP3 {answer}; {logins(service, A, B, C)}")

    reset(service)
    alter(service, retain_b)
    answer = alter(service, f"IDENTIFIED BY '{C}'")
    print(f"DP4 {answer}; {logins(service, A, B, C)}")

    reset(service)
    answer = alter(
        service, f"IDENTIFIED WITH caching_sha2_password BY '{B}' RETAIN CURRENT PASSWORD"
    )
    print(f"DP5 {answer}; {logins(service, A, B)}")

    reset(service)
    value = ch.caching_sha2_hash(B, ch.draw_salt(), 5000)
    answer = alter(
        service, f"IDENTIFIED WITH caching_sha2_password AS 0x{value.hex()} RETAIN CURRENT PASSWORD"
    )
    print(f"DP6 {answer}; {logins(service, A, B)}")

    reset(service)
    alter(service, retain_b)
    answer = alter(service, "DISCARD OLD PASSWORD")
    print(f"DP7 {answer}; {logins(service, A, B)}; attributes: {attributes(service)}")

    reset(service)
    alter(service, retain_b)
    read = tool(
        service,
        f"SELECT User_attributes FROM mysql.user WHERE user = '{ACCOUNT}' AND host = '%'",
    )
    show = tool(service, f"SHOW CREATE USER '{ACCOUNT}'@'%'")
    created = ch.root(service, f"SHOW CREATE USER '{ACCOUNT}'@'%'")
    print(f"DP8 tool reads User_attributes: {read}")
    print(f"DP8 tool SHOW CREATE USER: {show}")
    # Each caching_sha2_password hash starts `$A$`. Two would mean the retained
    # password is shown too.
    print(f"DP8 root SHOW CREATE USER, hashes shown: {created.count('$A$')}")

    reset(service)
    answer = alter(service, f"IDENTIFIED WITH sha256_password BY '{B}' RETAIN CURRENT PASSWORD")
    print(f"DP9 {answer}; {logins(service, A, B)}")

    ch.root(service, f"DROP USER '{ACCOUNT}'@'%', '{TOOL}'@'%'")
    return held


def main() -> int:
    held = True
    for service in ch.SERVICES:
        held &= probe(service)
    print("\nall held" if held else "\nA WRONG PASSWORD LOGGED IN")
    return 0 if held else 1


if __name__ == "__main__":
    sys.exit(main())
