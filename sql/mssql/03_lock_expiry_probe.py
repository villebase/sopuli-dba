"""sopuli-dba : lock, disable, expiry and failed logins on SQL Server

#1538, M4. What a tool login with only ALTER ANY LOGIN can do to another
login's state, what it can read back, and what a login answers in each state:

  LK1  ALTER LOGIN ... DISABLE and ENABLE: what is_disabled reads, and what
       the login answers
  LK2  CHECK_POLICY = ON and up to 30 wrong passwords, one at a time: what
       each login answers, what IsLocked and BadPasswordCount read after
       each, whether and when the login locks, and what the right password
       then answers
  LK3  after two wrong passwords, what each statement a driver might send
       does to BadPasswordCount, one change at a time: none; CHECK_POLICY =
       ON on its own; CHECK_POLICY = OFF on its own, then ON; a HASHED value
       with CHECK_POLICY = OFF, left off, then CHECK_POLICY = ON, as a
       driver that sends values would (02); the same password in clear; a
       new password in clear, as a rotation sends; and a new password with
       UNLOCK
  LK4  whether a login with the right password resets BadPasswordCount
  LK5  MUST_CHANGE: what IsMustChange reads, and what the login answers
  LK6  CHECK_EXPIRATION = ON: what IsExpired and DaysUntilExpiration read

Each read is the tool login's, through LOGINPROPERTY and sys.sql_logins. A
refused login's number is found by its message's text, as 02 says.

STATUS: run on 15.0.4510.2, 16.0.4325.4 and 17.0.5065.9, the
mcr.microsoft.com/mssql/server 2019-latest, 2022-latest and 2025-latest images
of test/compose.yaml profile mssql-matrix, as pulled on 2026-11-15, with
Python 3.13.12 on Windows 11 AMD64, on 2026-11-15 (#1538). Twice, exit 0, and
the same result every time.

RESULTS -- the same on every release

  LK1  the tool disables and enables the login. is_disabled reads 1, then
       0. A disabled login is refused, 18470, "The account is disabled". A
       second DISABLE is accepted
  LK2  **No lock.** With CHECK_POLICY = ON, 30 wrong passwords in a row do
       not lock the login: each is refused 18456, IsLocked reads 0 after
       each, and the right password then logs in. BadPasswordCount reads 1
       after the first and after every later one: it does not count past 1.
       These are the Linux images, where no Windows account policy applies
  LK3  BadPasswordCount, 1 after the two wrong passwords, stays 1 with
       nothing sent, after CHECK_POLICY = ON on its own, after the same
       password in clear, and after a new password in clear. It reads 0
       after CHECK_POLICY = OFF, and after a new password with UNLOCK. A
       HASHED value can only be sent with CHECK_POLICY = OFF (02), and the
       count reads 0 after it too, so whether HASHED alone would reset it
       cannot be told. Turning the policy on again leaves it 0
  LK4  the right password resets BadPasswordCount from 1 to 0
  LK5  the tool sets a password with MUST_CHANGE, which needs CHECK_POLICY
       and CHECK_EXPIRATION on. IsMustChange reads 1, DaysUntilExpiration 0,
       and the login is refused, 18488, "The password of the account must be
       changed". A new password without MUST_CHANGE clears it
  LK6  with CHECK_EXPIRATION = ON, a new password reads IsExpired 0 and
       DaysUntilExpiration 90; with it off, DaysUntilExpiration reads NULL.
       The 90 days are the Linux image's. What sets the age on Windows is
       not measured here

HOW TO RUN, against the matrix (test/README.md), from the repo root:

    .venv/Scripts/python sql/mssql/03_lock_expiry_probe.py

It needs 02_client_hash_probe.py beside it.

THROWAWAY SERVERS ONLY. It creates the logins sopuli_probe_hash and
sopuli_probe_tool, as 02 does, and drops them at the end.
"""

from __future__ import annotations

import importlib.util
import sys
from collections import Counter
from pathlib import Path

# 02's name starts with a digit, so it is loaded by its path.
_SPEC = importlib.util.spec_from_file_location(
    "mssql_client_hash_probe", Path(__file__).with_name("02_client_hash_probe.py")
)
assert _SPEC is not None
assert _SPEC.loader is not None
ch = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(ch)

ACCOUNT = ch.ACCOUNT
#: Test passwords, not credentials.
RIGHT = ch.PASSWORDS[0]
#: A second password, for a change to a different one, as a rotation sends.
NEW = "Acme-Probe-pw7"
#: How many wrong passwords LK2 sends at most before it gives up on a lock.
MOST = 30
PROPERTIES = ("IsLocked", "BadPasswordCount", "IsMustChange", "IsExpired", "DaysUntilExpiration")


def state(service: str) -> dict[str, str]:
    """What the tool login reads of the probe login's state."""
    columns = ", ".join(
        f"ISNULL(CAST(LOGINPROPERTY('{ACCOUNT}', '{name}') AS varchar(20)), 'NULL')"
        for name in PROPERTIES
    )
    out, errors = ch.client(
        service,
        ch.TOOL,
        ch.TOOL_PASSWORD,
        f"SELECT {columns}, CAST(l.is_disabled AS varchar(1)), "
        "CAST(l.is_policy_checked AS varchar(1)), CAST(l.is_expiration_checked AS varchar(1)) "
        f"FROM sys.sql_logins l WHERE l.name = '{ACCOUNT}'",
    )
    if errors:
        raise ch.StepError(f"{service}: the tool's read: {errors}")
    names = (*PROPERTIES, "is_disabled", "is_policy_checked", "is_expiration_checked")
    return dict(zip((KEYS.get(name, name) for name in names), out.split("|"), strict=True))


#: The key a property is kept under, where it is not its own name. CodeQL
#: reads a key that holds "password" as a password, so the count of failed
#: logins, which holds none, is kept as `failures` and printed under its name.
KEYS = {"BadPasswordCount": "failures"}
LABELS = {key: name for name, key in KEYS.items()}


def short(found: dict[str, str], *names: str) -> str:
    return ", ".join(f"{LABELS.get(name, name)} {found[name]}" for name in names or found)


#: Each result line, as the probe prints it.
SEEN: list[str] = []


def report(line: str) -> None:
    print(line)
    SEEN.append(line)


def lock(service: str) -> tuple[str, set[str]]:
    """Send up to MOST wrong passwords, and stop at the first sign of a lock.

    A sign is a login refused with 18486, or IsLocked reading 1. Returns when
    the first sign came, as `after N`, or `not locked`, and each
    answer:BadPasswordCount/IsLocked triple seen on the way, once each.
    """
    seen = set()
    for sent in range(1, MOST + 1):
        answer = ch.login(service, ch.WRONG)
        found = state(service)
        seen.add(f"{answer}:{found['failures']}/{found['IsLocked']}")
        if answer == "18486" or found["IsLocked"] == "1":
            return f"after {sent}", seen
    return "not locked", seen


def probe(service: str) -> None:
    SEEN.clear()
    ch.setup(service)
    cases(service)
    # By content, not position, so that one line missing or added is named
    # alone and does not shift every later line; and counted, so that a line
    # printed twice is named too.
    printed, recorded = Counter(SEEN), Counter(RECORDED)
    for line in sorted((recorded - printed).elements()):
        ch.DIFFERENCES.append(f"recorded, not printed: {line}")
    for line in sorted((printed - recorded).elements()):
        ch.DIFFERENCES.append(f"printed, not recorded: {line}")


def two_wrong(service: str) -> None:
    """Set the right password with the policy on, then send two wrong ones."""
    ch.reset(service, RIGHT, policy="ON")
    ch.login(service, ch.WRONG)
    ch.login(service, ch.WRONG)


def cases(service: str) -> None:
    tool = ch.as_tool

    ch.reset(service, RIGHT)
    off = tool(service, f"ALTER LOGIN [{ACCOUNT}] DISABLE")
    disabled = state(service)["is_disabled"]
    answer = ch.login(service, RIGHT)
    again = tool(service, f"ALTER LOGIN [{ACCOUNT}] DISABLE")
    on = tool(service, f"ALTER LOGIN [{ACCOUNT}] ENABLE")
    report(
        f"LK1 DISABLE {off}, is_disabled {disabled}, login {answer}, DISABLE again {again}; "
        f"ENABLE {on}, is_disabled {state(service)['is_disabled']}, "
        f"login {ch.login(service, RIGHT)}"
    )

    ch.reset(service, RIGHT, policy="ON")
    report(f"LK2 before: {short(state(service))}")
    when, seen = lock(service)
    report(
        f"LK2 up to {MOST} wrong passwords: {when}; "
        f"answer:BadPasswordCount/IsLocked seen: {sorted(seen)}; "
        f"right password: {ch.login(service, RIGHT)}"
    )

    value = ch.password_hash(RIGHT, ch.draw_salt())
    policy_on = f"ALTER LOGIN [{ACCOUNT}] WITH CHECK_POLICY = ON"
    for label, statements in (
        ("nothing", []),
        ("CHECK_POLICY = ON alone", [policy_on]),
        (
            "CHECK_POLICY = OFF, then ON",
            [f"ALTER LOGIN [{ACCOUNT}] WITH CHECK_POLICY = OFF", policy_on],
        ),
        (
            "HASHED with CHECK_POLICY = OFF, then ON",
            [ch.hashed(ACCOUNT, value, ", CHECK_POLICY = OFF"), policy_on],
        ),
        (
            "the same password in clear",
            [f"ALTER LOGIN [{ACCOUNT}] WITH PASSWORD = {ch.quote(RIGHT)}"],
        ),
        (
            "a new password in clear",
            [f"ALTER LOGIN [{ACCOUNT}] WITH PASSWORD = {ch.quote(NEW)}"],
        ),
        (
            "a new password with UNLOCK",
            [f"ALTER LOGIN [{ACCOUNT}] WITH PASSWORD = {ch.quote(NEW)} UNLOCK"],
        ),
    ):
        two_wrong(service)
        steps = [f"count {state(service)['failures']}"]
        # The count after each statement, so that a reset is laid to the one
        # statement that made it.
        for statement in statements:
            answer = tool(service, statement)
            steps.append(f"{answer}, count {state(service)['failures']}")
        found = state(service)
        current = NEW if "new password" in label else RIGHT
        report(
            f"LK3 two wrong passwords, then {label}: {'; '.join(steps)}; "
            f"{short(found, 'IsLocked', 'is_policy_checked')}; "
            f"right password: {ch.login(service, current)}"
        )

    two_wrong(service)
    before = state(service)["failures"]
    good = ch.login(service, RIGHT)
    after = state(service)["failures"]
    report(f"LK4 two wrong: count {before}; right {good}; count {after}")

    ch.reset(service, RIGHT)
    must = tool(
        service,
        f"ALTER LOGIN [{ACCOUNT}] WITH PASSWORD = {ch.quote(RIGHT)} MUST_CHANGE, "
        "CHECK_POLICY = ON, CHECK_EXPIRATION = ON",
    )
    report(f"LK5 MUST_CHANGE {must}: {short(state(service))}; login {ch.login(service, RIGHT)}")
    # A new password without MUST_CHANGE clears it, which reset() needs:
    # while MUST_CHANGE is on, neither CHECK_POLICY nor CHECK_EXPIRATION can
    # be turned off, 15128.
    cleared = tool(service, f"ALTER LOGIN [{ACCOUNT}] WITH PASSWORD = {ch.quote(RIGHT + 'x')}")
    report(f"LK5 a new password: {cleared}; IsMustChange {state(service)['IsMustChange']}")

    ch.reset(service, RIGHT, policy="ON", expiration="ON")
    report(f"LK6 CHECK_EXPIRATION = ON: {short(state(service))}")


#: The lines every release measured prints.
RECORDED = [
    "LK1 DISABLE ok, is_disabled 1, login 18470, DISABLE again ok; "
    "ENABLE ok, is_disabled 0, login ok",
    "LK2 before: IsLocked 0, BadPasswordCount 0, IsMustChange 0, IsExpired 0, "
    "DaysUntilExpiration NULL, is_disabled 0, is_policy_checked 1, is_expiration_checked 0",
    f"LK2 up to {MOST} wrong passwords: not locked; "
    "answer:BadPasswordCount/IsLocked seen: ['18456:1/0']; right password: ok",
    "LK3 two wrong passwords, then nothing: count 1; "
    "IsLocked 0, is_policy_checked 1; right password: ok",
    "LK3 two wrong passwords, then CHECK_POLICY = ON alone: count 1; ok, count 1; "
    "IsLocked 0, is_policy_checked 1; right password: ok",
    "LK3 two wrong passwords, then CHECK_POLICY = OFF, then ON: count 1; ok, count 0; "
    "ok, count 0; IsLocked 0, is_policy_checked 1; right password: ok",
    "LK3 two wrong passwords, then HASHED with CHECK_POLICY = OFF, then ON: count 1; "
    "ok, count 0; ok, count 0; IsLocked 0, is_policy_checked 1; right password: ok",
    "LK3 two wrong passwords, then the same password in clear: count 1; ok, count 1; "
    "IsLocked 0, is_policy_checked 1; right password: ok",
    "LK3 two wrong passwords, then a new password in clear: count 1; ok, count 1; "
    "IsLocked 0, is_policy_checked 1; right password: ok",
    "LK3 two wrong passwords, then a new password with UNLOCK: count 1; ok, count 0; "
    "IsLocked 0, is_policy_checked 1; right password: ok",
    "LK4 two wrong: count 1; right ok; count 0",
    "LK5 MUST_CHANGE ok: IsLocked 0, BadPasswordCount 0, IsMustChange 1, IsExpired 0, "
    "DaysUntilExpiration 0, is_disabled 0, is_policy_checked 1, is_expiration_checked 1; "
    "login 18488",
    "LK5 a new password: ok; IsMustChange 0",
    "LK6 CHECK_EXPIRATION = ON: IsLocked 0, BadPasswordCount 0, IsMustChange 0, IsExpired 0, "
    "DaysUntilExpiration 90, is_disabled 0, is_policy_checked 1, is_expiration_checked 1",
]


def main() -> int:
    return ch.run(probe)


if __name__ == "__main__":
    sys.exit(main())
