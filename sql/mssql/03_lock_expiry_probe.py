"""sopuli-dba : lock, disable, expiry and failed logins on SQL Server

#1538, M4. What a tool login with only ALTER ANY LOGIN can do to another
login's state, what it can read back, and what a login answers in each state:

  LK1  ALTER LOGIN ... DISABLE and ENABLE: what is_disabled reads, and what
       the login answers
  LK2  CHECK_POLICY = ON and wrong passwords, one at a time, until the login
       locks: after how many, what LOGINPROPERTY reads after each, and what
       the right password answers once it is locked
  LK3  after two wrong passwords, what each statement a driver might send
       does to BadPasswordCount: none; CHECK_POLICY = ON on its own;
       CHECK_POLICY = OFF then ON; a HASHED value with CHECK_POLICY = OFF,
       then CHECK_POLICY = ON, as a driver that sends values would (02); and
       a password in clear with UNLOCK. LK3 was meant to measure each way to
       end a lock, but LK2 finds no lock to end
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
       not lock the login: IsLocked reads 0 after each, BadPasswordCount
       reads 1 after each, and the right password then logs in. These are
       the Linux images, where no Windows account policy applies; on Windows
       the lockout comes from that policy, which is not measured here
  LK3  BadPasswordCount stays 1 with nothing sent and after CHECK_POLICY =
       ON on its own. It reads 0 after CHECK_POLICY = OFF then ON, after a
       HASHED value with CHECK_POLICY = OFF then CHECK_POLICY = ON, and after
       a password in clear with UNLOCK
  LK4  the right password resets BadPasswordCount from 1 to 0
  LK5  the tool sets a password with MUST_CHANGE, which needs CHECK_POLICY
       and CHECK_EXPIRATION on. IsMustChange reads 1, DaysUntilExpiration 0,
       and the login is refused, 18488, "The password of the account must be
       changed". A new password without MUST_CHANGE clears it
  LK6  with CHECK_EXPIRATION = ON, a new password reads IsExpired 0 and
       DaysUntilExpiration 90; with it off, DaysUntilExpiration reads NULL

HOW TO RUN, against the matrix (test/README.md), from the repo root:

    .venv/Scripts/python sql/mssql/03_lock_expiry_probe.py

It needs 02_client_hash_probe.py beside it.

THROWAWAY SERVERS ONLY. It creates the logins sopuli_probe_hash and
sopuli_probe_tool, as 02 does, and drops them at the end.
"""

from __future__ import annotations

import importlib.util
import sys
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
RIGHT = "Acme-Probe-pw1"
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
    return dict(zip(names, out.split("|"), strict=True))


def short(found: dict[str, str], *names: str) -> str:
    return ", ".join(f"{name} {found[name]}" for name in names or found)


#: Each result line, as the probe prints it.
SEEN: list[str] = []


def report(line: str) -> None:
    print(line)
    SEEN.append(line)


def lock(service: str) -> tuple[int, set[str]]:
    """Send wrong passwords until the login locks or MOST are sent.

    How many it took, 0 when none locked it, and each BadPasswordCount/IsLocked
    pair read on the way, once each.
    """
    counts = set()
    for sent in range(1, MOST + 1):
        ch.login(service, ch.WRONG)
        found = state(service)
        counts.add(f"{found['BadPasswordCount']}/{found['IsLocked']}")
        if found["IsLocked"] == "1":
            return sent, counts
    return 0, counts


def probe(service: str) -> None:
    SEEN.clear()
    ch.setup(service)
    cases(service)
    for got, recorded in zip(SEEN, RECORDED, strict=False):
        ch.check(got.split(":")[0], got, recorded)
    ch.check("lines", len(SEEN), len(RECORDED))


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
    sent, counts = lock(service)
    report(
        f"LK2 {MOST} wrong passwords: locked after {sent}; "
        f"BadPasswordCount/IsLocked read: {sorted(counts)}; "
        f"right password: {ch.login(service, RIGHT)}"
    )

    value = ch.password_hash(RIGHT, ch.draw_salt())
    for label, statements in (
        ("nothing", []),
        ("CHECK_POLICY = ON alone", [f"ALTER LOGIN [{ACCOUNT}] WITH CHECK_POLICY = ON"]),
        (
            "CHECK_POLICY = OFF, then ON",
            [
                f"ALTER LOGIN [{ACCOUNT}] WITH CHECK_POLICY = OFF",
                f"ALTER LOGIN [{ACCOUNT}] WITH CHECK_POLICY = ON",
            ],
        ),
        (
            "HASHED with CHECK_POLICY = OFF, then ON",
            [
                ch.hashed(ACCOUNT, value, ", CHECK_POLICY = OFF"),
                f"ALTER LOGIN [{ACCOUNT}] WITH CHECK_POLICY = ON",
            ],
        ),
        (
            "a password in clear with UNLOCK",
            [f"ALTER LOGIN [{ACCOUNT}] WITH PASSWORD = {ch.quote(RIGHT)} UNLOCK"],
        ),
    ):
        ch.reset(service, RIGHT, policy="ON")
        ch.login(service, ch.WRONG)
        ch.login(service, ch.WRONG)
        before = state(service)["BadPasswordCount"]
        answers = [tool(service, statement) for statement in statements]
        found = state(service)
        report(
            f"LK3 two wrong passwords, then {label}: count {before}; {answers}; "
            f"{short(found, 'BadPasswordCount', 'IsLocked', 'is_policy_checked')}; "
            f"right password: {ch.login(service, RIGHT)}"
        )

    ch.reset(service, RIGHT, policy="ON")
    ch.login(service, ch.WRONG)
    ch.login(service, ch.WRONG)
    before = state(service)["BadPasswordCount"]
    good = ch.login(service, RIGHT)
    after = state(service)["BadPasswordCount"]
    report(f"LK4 two wrong: count {before}; right {good}; count {after}")

    ch.reset(service, RIGHT)
    must = tool(
        service,
        f"ALTER LOGIN [{ACCOUNT}] WITH PASSWORD = {ch.quote(RIGHT)} MUST_CHANGE, "
        "CHECK_POLICY = ON, CHECK_EXPIRATION = ON",
    )
    report(f"LK5 MUST_CHANGE {must}: {short(state(service))}; login {ch.login(service, RIGHT)}")
    # A new password without MUST_CHANGE clears it, which reset() needs:
    # CHECK_POLICY cannot be turned off while it is on, 15128.
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
    f"LK2 {MOST} wrong passwords: locked after 0; BadPasswordCount/IsLocked read: ['1/0']; "
    "right password: ok",
    "LK3 two wrong passwords, then nothing: count 1; []; "
    "BadPasswordCount 1, IsLocked 0, is_policy_checked 1; right password: ok",
    "LK3 two wrong passwords, then CHECK_POLICY = ON alone: count 1; ['ok']; "
    "BadPasswordCount 1, IsLocked 0, is_policy_checked 1; right password: ok",
    "LK3 two wrong passwords, then CHECK_POLICY = OFF, then ON: count 1; ['ok', 'ok']; "
    "BadPasswordCount 0, IsLocked 0, is_policy_checked 1; right password: ok",
    "LK3 two wrong passwords, then HASHED with CHECK_POLICY = OFF, then ON: count 1; "
    "['ok', 'ok']; BadPasswordCount 0, IsLocked 0, is_policy_checked 1; right password: ok",
    "LK3 two wrong passwords, then a password in clear with UNLOCK: count 1; ['ok']; "
    "BadPasswordCount 0, IsLocked 0, is_policy_checked 1; right password: ok",
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
