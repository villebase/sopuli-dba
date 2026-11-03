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
  LE5  FAILED_LOGIN_ATTEMPTS 1 PASSWORD_LOCK_TIME 1. A login with a new
       password the account does not have yet, as a rotation's login before
       the change would make, then the current password. Then the tool sets
       the new password by hash, as the driver does, and logs in with it. Then
       ACCOUNT UNLOCK, and the new password again (#1223)
  LE6  A wrong password and the right one, which blocks the account. Then a
       seen reset as the driver sends it: ACCOUNT UNLOCK, the new password by
       hash with PASSWORD EXPIRE, and DISCARD OLD PASSWORD. Then the new
       password, as the mysql client does by default and with
       --connect-expired-password (#1225)
  LE7  No failed-login limit, and a password retained with RETAIN CURRENT
       PASSWORD. Then the new password by hash with PASSWORD EXPIRE, and the
       retained and previous passwords. Then DISCARD OLD PASSWORD, the
       retained password and the new one. Then a password by hash without
       PASSWORD EXPIRE, and whether the expiry is still set (#1225)
  LE8  PASSWORD EXPIRE, then a password by hash with RETAIN CURRENT PASSWORD,
       as `creds rotate --strategy rollover` sends it. Then the new and the
       retained passwords (#1225)
  LE9  PASSWORD EXPIRE alone, with that password retained. Then the current
       and the retained passwords. Then DISCARD OLD PASSWORD, and both again
       (#1225)

A login is "ok", or the error number and SQLSTATE of the refusal. Logins use
the server's own mysql client, as in 02_client_hash_probe.py.

The probe checks each result against the one RESULTS below records, as 02
does. A difference, or a step that fails, makes it exit 1.

It MEASURES and decides nothing.

STATUS: run on 8.0.46, 8.4.13 and 9.7.4, the mysql:8.0, mysql:8.4 and mysql:9
images of test/compose.yaml profile mysql-matrix, on 2026-11-01 (#1202), with
Python 3.13.12 on Windows 11 AMD64. Twice, exit 0, and the same result both
times. LE5 was added and the whole probe run again on 2026-11-02 (#1223),
twice, exit 0, with the same result. LE6 to LE9 were added and the whole
probe run again on 2026-11-03 (#1225), twice, exit 0, with the same result.

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
  LE5  accepted. The new password, which the account does not have yet,
       answers 3955 (HY000) at once, and the current password 3955 too. The
       tool's ALTER USER ... AS with the new password's hash is accepted, and
       the new password still answers 3955. ACCOUNT UNLOCK is accepted, and
       the new password then logs in
  LE6  both answer 3955 (HY000). The three statements are accepted, and
       password_expired reads Y. The new password logs in: the mysql client
       refuses to run a statement by default, and with the option SELECT 1
       answers 1820 (HY000)
  LE7  both log in. The new password with PASSWORD EXPIRE is accepted, the
       retained password still logs in, expired as the new one is, and the
       previous one answers 1045 (28000). DISCARD OLD PASSWORD is accepted,
       password_expired still reads Y, the retained password answers 1045
       (28000), and the new one logs in, expired. A password by hash without
       PASSWORD EXPIRE is accepted, password_expired reads N, and it logs in
  LE8  both accepted, and password_expired reads N. The new password and the
       retained one both log in
  LE9  accepted, and password_expired reads Y. The current password and the
       retained one both log in, expired. DISCARD OLD PASSWORD is accepted,
       password_expired still reads Y, the current password logs in, expired,
       and the retained one answers 1045 (28000)

  So a lock and an expiry read back from mysql.user, and a timed block does
  not: nothing in mysql.user shows it. ACCOUNT UNLOCK ends both kinds. A
  password change does not end a timed block, so with FAILED_LOGIN_ATTEMPTS 1
  one wrong login, such as one before a rotation's change, blocks the account
  for PASSWORD_LOCK_TIME days. A password change ends an expiry, with RETAIN
  CURRENT PASSWORD or without, and one with
  PASSWORD EXPIRE expires the retained password too, which keeps working
  until DISCARD OLD PASSWORD. So does PASSWORD EXPIRE alone.

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
A, B, C, D = "Acme-Probe-pwA", "Acme-Probe-pwB", "Acme-Probe-pwC", "Acme-Probe-pwD"
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

    # LE5: a rotation's login before the change uses the new password, C, which
    # the server does not have yet. Then the tool sets C by hash.
    answer = alter(service, "FAILED_LOGIN_ATTEMPTS 1 PASSWORD_LOCK_TIME 1")
    wrong = ch.login(service, C)
    old = ch.login(service, B)
    rounds = int(ch.root(service, "SELECT @@global.caching_sha2_password_digest_rounds"))
    stored = ch.caching_sha2_hash(C, ch.draw_salt(), rounds)
    set_c = alter(service, f"IDENTIFIED WITH caching_sha2_password AS 0x{stored.hex()}")
    new = ch.login(service, C)
    unlock = alter(service, "ACCOUNT UNLOCK")
    after_unlock = ch.login(service, C)
    print(f"LE5 {answer}; the new password first: {wrong}; the old one: {old}")
    print(f"LE5 set by hash: {set_c}; the new password: {new}")
    print(f"LE5 ACCOUNT UNLOCK: {unlock}; the new password: {after_unlock}")
    ch.check(
        "LE5",
        (answer, wrong, old, set_c, new, unlock, after_unlock),
        (OK, BLOCKED, BLOCKED, OK, BLOCKED, OK, OK),
    )

    # LE6: a reset of a blocked account, in the driver's order (#1225).
    wrong, right = ch.login(service, ch.WRONG), ch.login(service, C)
    unlock, set_d, discard = reset(service, D, rounds)
    after = state(service)
    default = login(service, D)
    session = answers(client(service, D, "SELECT 1;\n", "--connect-expired-password"))
    print(f"LE6 wrong: {wrong}; password: {right}")
    print(f"LE6 ACCOUNT UNLOCK: {unlock}; set by hash with PASSWORD EXPIRE: {set_d}; "
          f"DISCARD OLD PASSWORD: {discard}")  # fmt: skip
    print(f"LE6 then: {after}; new password by default: {default}; with the option: {session}")
    ch.check(
        "LE6",
        (wrong, right, unlock, set_d, discard, after, default, session),
        (BLOCKED, BLOCKED, OK, OK, OK, attributes_one(expired="Y"), CLIENT_REFUSES,
         ["1820 (HY000)"]),
    )  # fmt: skip

    # LE7: a reset of an account with a retained password, with no failed-login
    # limit, so a refused login blocks nothing.
    ch.root(service, f"ALTER USER '{ACCOUNT}'@'%' FAILED_LOGIN_ATTEMPTS 0 PASSWORD_LOCK_TIME 0")
    ch.root(service, f"ALTER USER '{ACCOUNT}'@'%' IDENTIFIED BY '{A}'")
    ch.root(service, f"ALTER USER '{ACCOUNT}'@'%' IDENTIFIED BY '{B}' RETAIN CURRENT PASSWORD")
    retained, current = ch.login(service, A), ch.login(service, B)
    set_c = alter(service, by_hash(C, rounds) + " PASSWORD EXPIRE")
    kept, previous = login(service, A), login(service, B)
    discard = alter(service, "DISCARD OLD PASSWORD")
    after = state(service)
    kept_after, new = login(service, A), login(service, C)
    set_d = alter(service, by_hash(D, rounds))
    cleared, new_d = state(service), ch.login(service, D)
    print(f"LE7 retained: {retained}; current: {current}")
    print(f"LE7 set by hash with PASSWORD EXPIRE: {set_c}; retained: {kept}; previous: {previous}")
    print(f"LE7 DISCARD OLD PASSWORD: {discard}; {after}; retained: {kept_after}; new: {new}")
    print(f"LE7 set by hash without it: {set_d}; {cleared}; new: {new_d}")
    ch.check(
        "LE7",
        (retained, current, set_c, kept, previous, discard, after, kept_after, new, set_d,
         cleared, new_d),
        (OK, OK, OK, CLIENT_REFUSES, REFUSED, OK, "locked=N expired=Y attributes=NULL", REFUSED,
         CLIENT_REFUSES, OK, "locked=N expired=N attributes=NULL", OK),
    )  # fmt: skip

    # LE8: a rotation's rollover set on an expired account.
    expire = alter(service, "PASSWORD EXPIRE")
    set_a = alter(service, by_hash(A, rounds) + " RETAIN CURRENT PASSWORD")
    # The attributes now hold the retained hash, whose salt differs per run.
    after = state(service).split(" attributes=")[0]
    new, kept = login(service, A), login(service, D)
    print(f"LE8 PASSWORD EXPIRE: {expire}; set by hash with RETAIN CURRENT PASSWORD: {set_a}")
    print(f"LE8 then: {after}; new: {new}; retained: {kept}")
    ch.check(
        "LE8",
        (expire, set_a, after, new, kept),
        (OK, OK, "locked=N expired=N", OK, OK),
    )

    # LE9: a bare PASSWORD EXPIRE with a retained password (D), then DISCARD.
    expire = alter(service, "PASSWORD EXPIRE")
    after = state(service).split(" attributes=")[0]
    current, kept = login(service, A), login(service, D)
    discard = alter(service, "DISCARD OLD PASSWORD")
    discarded = state(service)
    current_after, kept_after = login(service, A), login(service, D)
    print(f"LE9 PASSWORD EXPIRE: {expire}; {after}; current: {current}; retained: {kept}")
    print(f"LE9 DISCARD OLD PASSWORD: {discard}; {discarded}; current: {current_after}; "
          f"retained: {kept_after}")  # fmt: skip
    ch.check(
        "LE9",
        (expire, after, current, kept, discard, discarded, current_after, kept_after),
        (OK, "locked=N expired=Y", CLIENT_REFUSES, CLIENT_REFUSES, OK,
         "locked=N expired=Y attributes=NULL", CLIENT_REFUSES, REFUSED),
    )  # fmt: skip


def reset(service: str, password: str, rounds: int) -> tuple[str, str, str]:
    """The three statements of the MySQL driver's seen reset, as the tool account."""
    return (
        alter(service, "ACCOUNT UNLOCK"),
        alter(service, by_hash(password, rounds) + " PASSWORD EXPIRE"),
        alter(service, "DISCARD OLD PASSWORD"),
    )


def login(service: str, password: str) -> str:
    """:func:`ch.login`, which also reports the client's own refusal of an
    expired password, :data:`CLIENT_REFUSES`: the server took the password."""
    lines = client(service, password, "SELECT CURRENT_USER();\n")
    if CLIENT_REFUSES in lines:
        return CLIENT_REFUSES
    for line in lines:
        if line.startswith("ERROR "):
            return ch.code(line.removeprefix("ERROR ").split(" at line ")[0])
    return OK


def by_hash(password: str, rounds: int) -> str:
    """The clause that sets ``password`` by its hash, as the driver sends it."""
    stored = ch.caching_sha2_hash(password, ch.draw_salt(), rounds)
    return f"IDENTIFIED WITH caching_sha2_password AS 0x{stored.hex()}"


def attributes_one(*, expired: str) -> str:
    """The state LE5 left the attributes in: one failed login, a day's block."""
    return (
        f'locked=N expired={expired} attributes={{"Password_locking": '
        '{"failed_login_attempts": 1, "password_lock_time_days": 1}}'
    )


def main() -> int:
    return ch.run(probe)


if __name__ == "__main__":
    sys.exit(main())
