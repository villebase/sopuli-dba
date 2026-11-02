"""sopuli-dba : the server's password rules, for a password sent as a hash

#1223. The MySQL driver sets a password with `ALTER USER ... IDENTIFIED WITH
caching_sha2_password AS 0x<hash>`, the hash computed on the client
(02_client_hash_probe.py). A server can refuse a password by two rules: an
account's reuse limits (PASSWORD HISTORY and PASSWORD REUSE INTERVAL), and
the validate_password component. This measures, on each server, whether
either rule sees a password that arrives as a hash:

  PR1  an account with PASSWORD HISTORY 2 and the password A, set by root with
       IDENTIFIED BY. The tool account, with only CREATE USER, sets A again
       with AS and a fresh salt; then the same with IDENTIFIED BY. The rows
       mysql.password_history holds for the account after each, and whether
       A then logs in
  PR2  as PR1, with PASSWORD REUSE INTERVAL 1 DAY and no history count
  PR3  the validate_password component installed by root, at its default
       policy. The tool account sets the password "acme" with AS, then with
       IDENTIFIED BY; whether "acme" then logs in. The component is
       uninstalled afterwards

The hash is computed as 02_client_hash_probe.py computes it, with the
server's own rounds.

The probe checks each result against the one RESULTS below records, and
prints each that differs. A difference, or a step that fails, makes it exit 1.

It MEASURES and decides nothing.

STATUS: run on 8.0.46, 8.4.13 and 9.7.4, the mysql:8.0, mysql:8.4 and mysql:9
images of test/compose.yaml profile mysql-matrix, on 2026-11-02 (#1223), with
Python 3.13.12 on Windows 11 AMD64. Three times, the last two exit 0 (the first
filled in RESULTS), and the same result each time.

RESULTS -- the same on all three releases

  PR1  root's IDENTIFIED BY leaves 1 row in mysql.password_history. The tool
       sets A again by hash: accepted, and a second row is added. The tool
       sets A again as text: refused, 3638 (HY000), "Cannot use these
       credentials for 'sopuli_probe_hash@%' because they contradict the
       password history policy", and no row is added. A logs in
  PR2  the same as PR1, with the reuse interval in place of the count
  PR3  the policy is MEDIUM. "acme" by hash is accepted, and logs in. As text
       it is refused, 1819 (HY000), "Your password does not satisfy the
       current policy requirements"

  So neither rule sees a password that arrives as a hash: the server cannot
  compare a hash with the history, or measure its length and characters. A
  password set by hash is still added to the history, so a later IDENTIFIED BY
  of the same password is refused.

HOW TO RUN, against the matrix (test/README.md), from the repo root:

    .venv/Scripts/python sql/mysql/08_password_rules_probe.py

It needs only the standard library and the docker CLI, and
02_client_hash_probe.py beside it. The container names follow
COMPOSE_PROJECT_NAME, so a second clone's matrix is the one it uses.

THROWAWAY SERVERS ONLY. On each server it creates the accounts
sopuli_probe_hash and sopuli_probe_tool and drops them at the end, and before
it starts it drops ones an interrupted run left. PR3 installs the
validate_password component, server-wide, and uninstalls it at the end, also
when a step fails.
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
#: Test passwords, not credentials. WEAK fails validate_password's default
#: policy: it is short, and has no capital, digit or special character.
A = "Acme-Probe-pwA"
WEAK = "acme"
COMPONENT = "file://component_validate_password"


def rounds(service: str) -> int:
    return int(ch.root(service, "SELECT @@global.caching_sha2_password_digest_rounds"))


def by_hash(service: str, password: str) -> str:
    """`ok`, or the refusal's code, for the tool setting `password` as a hash."""
    stored = ch.caching_sha2_hash(password, ch.draw_salt(), rounds(service))
    answer = ch.as_tool(
        service,
        f"ALTER USER '{ACCOUNT}'@'%' IDENTIFIED WITH caching_sha2_password AS 0x{stored.hex()}",
    )
    return ch.code(answer)


def by_text(service: str, password: str) -> str:
    """`ok`, or the refusal's code, for the tool setting `password` as text."""
    answer = ch.as_tool(service, f"ALTER USER '{ACCOUNT}'@'%' IDENTIFIED BY {ch.quote(password)}")
    return ch.code(answer)


def history(service: str) -> int:
    return int(
        ch.root(
            service,
            f"SELECT COUNT(*) FROM mysql.password_history WHERE user = '{ACCOUNT}' AND host = '%'",
        )
    )


def reuse(service: str, clause: str) -> tuple[object, ...]:
    """PR1 and PR2: set A, then A again by hash, then by text."""
    ch.root(service, f"ALTER USER '{ACCOUNT}'@'%' {clause}")
    ch.root(service, f"ALTER USER '{ACCOUNT}'@'%' IDENTIFIED BY {ch.quote(A)}")
    first = history(service)
    hashed = by_hash(service, A)
    after_hash = history(service)
    text = by_text(service, A)
    after_text = history(service)
    return (first, hashed, after_hash, text, after_text, ch.login(service, A))


def validation(service: str) -> tuple[object, ...]:
    """PR3, with the component installed for the length of it."""
    ch.root(service, f"INSTALL COMPONENT '{COMPONENT}'")
    try:
        policy = ch.root(service, "SELECT @@global.validate_password.policy")
        hashed = by_hash(service, WEAK)
        login = ch.login(service, WEAK)
        text = by_text(service, WEAK)
    finally:
        ch.root(service, f"UNINSTALL COMPONENT '{COMPONENT}'")
    return (policy, hashed, login, text)


#: What each step recorded, the same on every release: the history rows after
#: root set A, the hash's answer, the rows after it, the text's answer, the
#: rows after that, and A's login.
PR1 = (1, "ok", 2, "3638 (HY000)", 2, "ok")
PR2 = PR1
#: The policy, the hash's answer, the weak password's login, the text's answer.
PR3 = ("MEDIUM", "ok", "ok", "1819 (HY000)")


def probe(service: str) -> None:
    ch.setup(service, A)
    pr1 = reuse(service, "PASSWORD HISTORY 2")
    print(f"PR1  history rows, by hash, rows, by text, rows, login: {pr1}")
    ch.check(f"{service} PR1", pr1, PR1)

    ch.root(service, f"DROP USER '{ACCOUNT}'@'%'")
    ch.root(service, f"CREATE USER '{ACCOUNT}'@'%' IDENTIFIED BY {ch.quote(A)}")
    pr2 = reuse(service, "PASSWORD REUSE INTERVAL 1 DAY")
    print(f"PR2  history rows, by hash, rows, by text, rows, login: {pr2}")
    ch.check(f"{service} PR2", pr2, PR2)

    pr3 = validation(service)
    print(f"PR3  policy, by hash, login, by text: {pr3}")
    ch.check(f"{service} PR3", pr3, PR3)


def main() -> int:
    return ch.run(probe)


if __name__ == "__main__":
    sys.exit(main())
