"""sopuli-dba : MySQL's account lock, password expiry and timed lock

#1202. UC-1 and UC-2 read whether an account is locked or expired, lock it,
and expire its password. This measures, on each server, as a tool account
that holds only CREATE USER, and reads each state back as root from
mysql.user's account_locked, password_expired and User_attributes:

  LE1  a new account
  LE2  ACCOUNT LOCK. Then a login with the password and with a wrong one.
       Then ACCOUNT LOCK again
  LE3  ACCOUNT UNLOCK and PASSWORD EXPIRE. Then a login with the password,
       first as the mysql client does by default, then with
       --connect-expired-password, which runs SELECT 1, sets a new password
       with ALTER USER USER(), and runs SELECT again. Then the new password
       and the old one log in
  LE4  FAILED_LOGIN_ATTEMPTS 2 PASSWORD_LOCK_TIME 1. Two wrong passwords, then
       the right one. Then whether any column of the account's row in
       mysql.user changed. Then ACCOUNT UNLOCK, and
       the right one again

A login is "ok", or the error number and SQLSTATE of the refusal. Logins use
the server's own mysql client, as in 02_client_hash_probe.py.

The probe checks each result against the one RESULTS below records, as 02
does. A difference, or a step that fails, makes it exit 1.

It MEASURES and decides nothing.

STATUS: run on 8.0.46, 8.4.13 and 9.7.4, the mysql:8.0, mysql:8.4 and mysql:9
images of test/compose.yaml profile mysql-matrix, on 2026-11-01 (#1202), with
Python 3.13.12 on Windows 11 AMD64. Twice, exit 0, and the same result both
times.

RESULTS -- the same on all three releases

  LE1  account_locked N, password_expired N, User_attributes NULL
  LE2  accepted, and account_locked reads Y. The password is refused with
       3118 (HY000), "Account is locked", and a wrong one with 1045 (28000).
       A second ACCOUNT LOCK is accepted without an error
  LE3  accepted, and password_expired reads Y. By default the mysql client
       logs in and then refuses to run a statement itself: "Please use
       --connect-expired-password option or invoke mysql in interactive
       mode". With the option, SELECT 1 answers 1820 (HY000), "You must reset
       your password using ALTER USER statement", ALTER USER USER() is
       accepted, and the next SELECT runs. password_expired then reads N, the
       new password logs in and the old one is refused
  LE4  accepted, and User_attributes holds Password_locking with
       failed_login_attempts 2 and password_lock_time_days 1. The first wrong
       password answers 1045 (28000), the second 3955 (HY000), "Account is
       blocked for 1 day(s) (1 day(s) remaining) due to 2 consecutive failed
       logins", and the right password then 3955 too. Every column of the
       account's row in mysql.user is the same as before the wrong passwords.
       ACCOUNT UNLOCK is accepted, and the right password logs in

  So a lock and an expiry read back from mysql.user, and a timed block does
  not: nothing in mysql.user shows it. ACCOUNT UNLOCK ends both kinds.

HOW TO RUN, against the matrix (test/README.md), from the repo root:

    .venv/Scripts/python sql/mysql/04_lock_expiry_probe.py

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
A, B = "Acme-Probe-pwA", "Acme-Probe-pwB"
OK, REFUSED = "ok", "1045 (28000)"
LOCKED = "3118 (HY000)"
BLOCKED = "3955 (HY000)"
#: What the mysql client prints, and exits 1, when it will not run a statement
#: on a session whose password has expired.
CLIENT_REFUSES = "Please use --connect-expired-password option or invoke mysql in interactive mode."


def alter(service: str, clause: str) -> str:
    return ch.code(ch.as_tool(service, f"ALTER USER '{ACCOUNT}'@'%' {clause}"))


def state(service: str) -> str:
    return ch.root(
        service,
        "SELECT CONCAT('locked=', account_locked, ' expired=', password_expired, "
        "' attributes=', IFNULL(User_attributes, 'NULL')) FROM mysql.user "
        f"WHERE user = '{ACCOUNT}' AND host = '%'",
    )


def row(service: str) -> str:
    """The account's whole row of mysql.user, every column, as root reads it."""
    return ch.root(service, f"SELECT * FROM mysql.user WHERE user = '{ACCOUNT}' AND host = '%'")


def client(service: str, password: str, statements: str, *flags: str) -> list[str]:
    """Run the account's mysql client, and return what it printed, line by line.

    For the cases where the client itself refuses, which 02's mysql() treats as
    a failed step.
    """
    _, out, err = ch.client(service, ACCOUNT, password, statements, "-h127.0.0.1", "-f", *flags)
    return [line for line in (out + "\n" + err).splitlines() if line]


def answers(lines: list[str]) -> list[str]:
    """Each line, with a server error shortened to its number and SQLSTATE."""
    return [line.split(" at line ")[0].removeprefix("ERROR ") for line in lines]


def probe(service: str) -> None:
    ch.setup(service, A)
    new = state(service)
    print(f"LE1 {new}")
    ch.check("LE1", new, "locked=N expired=N attributes=NULL")

    answer = alter(service, "ACCOUNT LOCK")
    locked = state(service)
    right, wrong = ch.login(service, A), ch.login(service, ch.WRONG)
    again = alter(service, "ACCOUNT LOCK")
    print(f"LE2 {answer}; {locked}; password: {right}; wrong: {wrong}; again: {again}")
    ch.check(
        "LE2",
        (answer, locked, right, wrong, again, state(service)),
        (OK, "locked=Y expired=N attributes=NULL", LOCKED, REFUSED, OK, locked),
    )

    answer = alter(service, "ACCOUNT UNLOCK PASSWORD EXPIRE")
    expired = state(service)
    default = client(service, A, "SELECT 1;\n")
    session = answers(
        client(
            service, A,
            f"SELECT 1;\nALTER USER USER() IDENTIFIED BY '{B}';\nSELECT 'after';\n",
            "--connect-expired-password",
        )
    )  # fmt: skip
    changed = state(service)
    new_login, old_login = ch.login(service, B), ch.login(service, A)
    print(f"LE3 {answer}; {expired}; by default: {default}")
    print(f"LE3 --connect-expired-password: {session}")
    print(f"LE3 then: {changed}; new password: {new_login}; old: {old_login}")
    # The client's output comes before its errors, so the order is not compared:
    # SELECT 1 answers 1820, the ALTER prints nothing, and the last SELECT runs.
    ch.check(
        "LE3",
        (answer, expired, default, sorted(session), changed, new_login, old_login),
        (
            OK, "locked=N expired=Y attributes=NULL", [CLIENT_REFUSES],
            ["1820 (HY000)", "after"], "locked=N expired=N attributes=NULL", OK, REFUSED,
        ),
    )  # fmt: skip

    answer = alter(service, "FAILED_LOGIN_ATTEMPTS 2 PASSWORD_LOCK_TIME 1")
    before = state(service)
    before_row = row(service)
    first, second = ch.login(service, ch.WRONG), ch.login(service, ch.WRONG)
    right = ch.login(service, B)
    unchanged = row(service) == before_row
    unlock = alter(service, "ACCOUNT UNLOCK")
    after_unlock = ch.login(service, B)
    print(f"LE4 {answer}; {before}")
    print(f"LE4 wrong: {first}; wrong: {second}; password: {right}; mysql.user same: {unchanged}")
    print(f"LE4 ACCOUNT UNLOCK: {unlock}; password: {after_unlock}")
    attributes = (
        'locked=N expired=N attributes={"Password_locking": '
        '{"failed_login_attempts": 2, "password_lock_time_days": 1}}'
    )
    ch.check(
        "LE4",
        (answer, before, first, second, right, unchanged, unlock, after_unlock),
        (OK, attributes, REFUSED, BLOCKED, BLOCKED, True, OK, OK),
    )


def main() -> int:
    return ch.run(probe)


if __name__ == "__main__":
    sys.exit(main())
