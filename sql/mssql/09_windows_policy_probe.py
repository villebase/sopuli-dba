"""sopuli-dba : SQL Server's password policy on Windows

#1557. Probes 01 to 08 ran on the Linux images, which apply no Windows account
policy: no login locks there (03, LK2). On Windows, CHECK_POLICY applies the
host's or the domain's account policy. This measures it on a host whose local
policy the run sets with `net accounts`, for a login with CHECK_POLICY = ON:

  WP0  the conditions, printed and not compared: the release, the edition,
       the Windows version and the policy `net accounts` reports. Compared:
       whether the tool login reads sys.dm_os_host_info, the host-platform
       capability a driver would read
  WP1  what LOGINPROPERTY reads for the login, and whether any of it is the
       lockout threshold
  WP2  wrong passwords one at a time, to one past the threshold: each
       answer, and BadPasswordCount, IsLocked and LockoutTime after each
  WP3  what a locked login answers to its right password, and what it
       answers once the lockout duration has passed
  WP4  on a locked login, what each statement does to the lock, and which
       password then logs in: CHECK_POLICY = OFF alone, and then ON again;
       a HASHED value with CHECK_POLICY = OFF; a new password with UNLOCK; a
       new password with MUST_CHANGE and UNLOCK together; a new password
       alone
  WP5  the order a driver uses (#1538, decision 2): two wrong passwords,
       then a HASHED value with CHECK_POLICY = OFF, then wrong passwords to
       past the threshold while the policy is off, then CHECK_POLICY = ON:
       whether the failures counted, and whether the login is locked
  WP6  password history: whether a reused password is refused, what
       HistoryLength reads, and whether turning the policy off and on again
       clears the history
  WP7  expiry: DaysUntilExpiration under the policy's maximum age, and
       whether turning the policy off turns CHECK_EXPIRATION off, and on
       again leaves it off

The administrator's steps use Windows authentication. Every other step is
the tool login's, which holds only ALTER ANY LOGIN, as in 02 to 05. A refused
login's or statement's number is the one the ODBC driver puts in parentheses
after the server's message.

The probe checks each result against the one RESULTS below records. A
difference, or a step that fails, makes it exit 1.

It MEASURES and decides nothing.

STATUS: not yet run.

RESULTS -- not yet measured

HOW TO RUN: .github/workflows/mssql-windows-probe.yml runs it on a
windows-latest runner, after it installs SQL Server Express and sets the
local policy:

    python -I sql/mssql/09_windows_policy_probe.py --prepare
    (restart the SQL Server service)
    python -I sql/mssql/09_windows_policy_probe.py

`--prepare` turns on SQL Server authentication, which takes effect at the
service's next start. SOPULI_MSSQL_SERVER names the server (default
`.\\SQLEXPRESS`), SOPULI_PROBE_LOCKOUT_THRESHOLD the threshold the run set
(default 5) and SOPULI_PROBE_LOCKOUT_MINUTES the lockout duration (default 1).

THROWAWAY SERVERS ONLY. It creates the logins sopuli_probe_win and
sopuli_probe_tool, and drops them at the end. It locks sopuli_probe_win on
purpose.
"""

from __future__ import annotations

import hashlib
import os
import re
import secrets
import subprocess
import sys
import time
from collections.abc import Callable

SERVER = os.environ.get("SOPULI_MSSQL_SERVER", r".\SQLEXPRESS")
THRESHOLD = int(os.environ.get("SOPULI_PROBE_LOCKOUT_THRESHOLD", "5"))
MINUTES = int(os.environ.get("SOPULI_PROBE_LOCKOUT_MINUTES", "1"))
DRIVER = "ODBC Driver 18 for SQL Server"

ACCOUNT = "sopuli_probe_win"
TOOL = "sopuli_probe_tool"
#: Test passwords, not credentials. Each meets Windows' complexity rule.
GOOD = "Acme-Win-Good1"
NEW = "Acme-Win-New2"
WRONG = "Acme-Win-Wrong3"
HISTORY = ("Acme-Win-HistA4", "Acme-Win-HistB5")
#: A fresh password for the tool login each run.
TOOL_PASSWORD = "Tool-" + secrets.token_urlsafe(18) + "a1!"

PROPERTIES = (
    "BadPasswordCount", "BadPasswordTime", "DaysUntilExpiration", "HistoryLength",
    "IsExpired", "IsLocked", "IsMustChange", "LockoutTime", "PasswordLastSetTime",
)  # fmt: skip
_NUMBER = re.compile(r"\((\d{3,6})\)\s*\(SQL\w+\)")


class StepError(Exception):
    """A step that failed, as opposed to a result that differs."""


def _connect(credentials: str) -> object:
    import pyodbc  # type: ignore[import-not-found]

    return pyodbc.connect(
        f"Driver={{{DRIVER}}};Server={SERVER};Database=master;{credentials}Encrypt=no;",
        autocommit=True,
        timeout=30,
    )


def braced(value: str) -> str:
    """An ODBC connection-string value in braces, a closing brace doubled."""
    return "{" + value.replace("}", "}}") + "}"


def number(exc: BaseException) -> str:
    found = _NUMBER.findall(str(exc))
    return found[0] if found else f"none: {str(exc)[:120]}"


def admin(sql: str) -> list[tuple[object, ...]]:
    conn = _connect("Trusted_Connection=yes;")
    try:
        cursor = conn.cursor()  # type: ignore[attr-defined]
        cursor.execute(sql)
        return [tuple(row) for row in cursor.fetchall()] if cursor.description else []
    finally:
        conn.close()  # type: ignore[attr-defined]


def as_login(user: str, password: str, sql: str) -> list[tuple[object, ...]]:
    conn = _connect(f"Uid={braced(user)};Pwd={braced(password)};")
    try:
        cursor = conn.cursor()  # type: ignore[attr-defined]
        cursor.execute(sql)
        return [tuple(row) for row in cursor.fetchall()] if cursor.description else []
    finally:
        conn.close()  # type: ignore[attr-defined]


def tool(sql: str) -> str:
    """Run a statement as the tool login: `ok`, or `refused, <number>`."""
    try:
        as_login(TOOL, TOOL_PASSWORD, sql)
        return "ok"
    except Exception as exc:  # noqa: BLE001 - the result is the failure
        return f"refused, {number(exc)}"


def login(password: str) -> str:
    """Log in as the account: `logged in`, or the server's number."""
    try:
        as_login(ACCOUNT, password, "SELECT 1")
        return "logged in"
    except Exception as exc:  # noqa: BLE001 - the result is the failure
        return number(exc)


def props() -> dict[str, str]:
    """The account's LOGINPROPERTY values and policy flags, as the tool reads them."""
    columns = ", ".join(f"LOGINPROPERTY(N'{ACCOUNT}', '{name}')" for name in PROPERTIES)
    rows = as_login(
        TOOL, TOOL_PASSWORD,
        f"SELECT {columns}, is_policy_checked, is_expiration_checked "
        f"FROM sys.sql_logins WHERE name = N'{ACCOUNT}'",
    )  # fmt: skip
    if not rows:
        raise StepError(f"the tool login reads no row for {ACCOUNT}")
    values = [*PROPERTIES, "is_policy_checked", "is_expiration_checked"]
    return {name: shape(name, value) for name, value in zip(values, rows[0], strict=True)}


def shape(name: str, value: object) -> str:
    """A value that does not change between runs: a date reads as set or default."""
    if value is None:
        return "NULL"
    if name.endswith("Time"):
        return "default" if str(value).startswith("1900-01-01") else "set"
    return str(value)


def lock_state() -> str:
    p = props()
    return (
        f"BadPasswordCount {p['BadPasswordCount']}, IsLocked {p['IsLocked']}, "
        f"LockoutTime {p['LockoutTime']}"
    )


def quote(password: str) -> str:
    return "N'" + password.replace("'", "''") + "'"


def hashed(password: str) -> str:
    """A 0x0200 value: version, a 4-byte salt, SHA-512 of UTF-16LE password and salt."""
    salt = secrets.token_bytes(4)
    digest = hashlib.sha512(password.encode("utf-16-le") + salt).digest()
    return "0x" + (b"\x02\x00" + salt + digest).hex().upper()


def fresh(expiration: bool = False) -> None:
    """The account, recreated with GOOD, the policy on, and no failed logins."""
    admin(drop(ACCOUNT))
    admin(
        f"CREATE LOGIN [{ACCOUNT}] WITH PASSWORD = {quote(GOOD)}, CHECK_POLICY = ON, "
        f"CHECK_EXPIRATION = {'ON' if expiration else 'OFF'}"
    )


def drop(name: str) -> str:
    return f"IF SUSER_ID(N'{name}') IS NOT NULL DROP LOGIN [{name}]"


def lock() -> str:
    """Wrong passwords until the account locks; the lock state, or why it did not."""
    for _ in range(THRESHOLD * 2):
        login(WRONG)
        if props()["IsLocked"] == "1":
            return "locked"
    return f"not locked after {THRESHOLD * 2}: {lock_state()}"


# ----------------------------------------------------------------- cases --


def wp0(results: dict[str, str]) -> None:
    version = admin(
        "SELECT CAST(SERVERPROPERTY('ProductVersion') AS nvarchar(64)), "
        "CAST(SERVERPROPERTY('Edition') AS nvarchar(128)), "
        "(SELECT host_distribution FROM sys.dm_os_host_info)"
    )[0]
    print(f"WP0 release {version[0]}, {version[1]}, on {version[2]}")
    policy = subprocess.run(["net", "accounts"], capture_output=True, check=False)
    for line in policy.stdout.decode("utf-8", "replace").splitlines():
        if line.strip() and not line.startswith("The command"):
            print(f"WP0 policy {' '.join(line.split())}")
    try:
        host = as_login(TOOL, TOOL_PASSWORD, "SELECT host_platform FROM sys.dm_os_host_info")
        results["WP0 tool reads sys.dm_os_host_info"] = f"yes, {host[0][0]}"
    except Exception as exc:  # noqa: BLE001 - the result is the failure
        results["WP0 tool reads sys.dm_os_host_info"] = f"refused, {number(exc)}"


def wp1(results: dict[str, str]) -> None:
    fresh()
    p = props()
    results["WP1 properties"] = ", ".join(f"{name} {p[name]}" for name in PROPERTIES)


def wp2_wp3(results: dict[str, str]) -> None:
    fresh()
    for attempt in range(1, THRESHOLD + 2):
        answer = login(WRONG)
        results[f"WP2 wrong password {attempt}"] = f"{answer}; {lock_state()}"
    results["WP3 right password while locked"] = f"{login(GOOD)}; {lock_state()}"
    time.sleep(MINUTES * 60 + 15)
    results["WP3 right password after the duration"] = f"{login(GOOD)}; {lock_state()}"


def wp4(results: dict[str, str]) -> None:
    cases: dict[str, tuple[str, str]] = {
        "CHECK_POLICY = OFF": ("CHECK_POLICY = OFF", GOOD),
        "HASHED, CHECK_POLICY = OFF": (f"PASSWORD = {hashed(NEW)} HASHED, CHECK_POLICY = OFF", NEW),
        "UNLOCK": (f"PASSWORD = {quote(NEW)} UNLOCK", NEW),
        "MUST_CHANGE UNLOCK": (
            f"PASSWORD = {quote(NEW)} MUST_CHANGE UNLOCK, CHECK_POLICY = ON, CHECK_EXPIRATION = ON",
            NEW,
        ),
        "a new password alone": (f"PASSWORD = {quote(NEW)}", NEW),
    }
    for case, (options, password) in cases.items():
        fresh()
        locked = lock()
        sent = tool(f"ALTER LOGIN [{ACCOUNT}] WITH {options}")
        results[f"WP4 {case}"] = f"{locked}; {sent}; {lock_state()}; login {login(password)}"
        if case == "CHECK_POLICY = OFF":
            again = tool(f"ALTER LOGIN [{ACCOUNT}] WITH CHECK_POLICY = ON")
            results["WP4 then CHECK_POLICY = ON"] = f"{again}; {lock_state()}; login {login(GOOD)}"


def wp5(results: dict[str, str]) -> None:
    fresh()
    login(WRONG)
    login(WRONG)
    results["WP5 two wrong passwords"] = lock_state()
    sent = tool(f"ALTER LOGIN [{ACCOUNT}] WITH PASSWORD = {hashed(NEW)} HASHED, CHECK_POLICY = OFF")
    results["WP5 HASHED, CHECK_POLICY = OFF"] = f"{sent}; {lock_state()}"
    answers = [login(WRONG) for _ in range(THRESHOLD + 2)]
    results["WP5 wrong passwords while off"] = f"{', '.join(answers)}; {lock_state()}"
    again = tool(f"ALTER LOGIN [{ACCOUNT}] WITH CHECK_POLICY = ON")
    results["WP5 CHECK_POLICY = ON"] = f"{again}; {lock_state()}; login {login(NEW)}"


def wp6(results: dict[str, str]) -> None:
    fresh()
    first, second = HISTORY
    steps = [
        ("set A", f"PASSWORD = {quote(first)}"),
        ("set B", f"PASSWORD = {quote(second)}"),
        ("set A again", f"PASSWORD = {quote(first)}"),
        ("CHECK_POLICY = OFF", "CHECK_POLICY = OFF"),
        ("CHECK_POLICY = ON", "CHECK_POLICY = ON"),
        ("set A after off and on", f"PASSWORD = {quote(first)}"),
    ]
    for label, options in steps:
        sent = tool(f"ALTER LOGIN [{ACCOUNT}] WITH {options}")
        results[f"WP6 {label}"] = f"{sent}; HistoryLength {props()['HistoryLength']}"


def wp7(results: dict[str, str]) -> None:
    fresh(expiration=True)
    sent = tool(f"ALTER LOGIN [{ACCOUNT}] WITH PASSWORD = {quote(NEW)}")
    p = props()
    results["WP7 a new password"] = (
        f"{sent}; DaysUntilExpiration {p['DaysUntilExpiration']}, "
        f"is_expiration_checked {p['is_expiration_checked']}"
    )
    for options in ("CHECK_POLICY = OFF", "CHECK_POLICY = ON"):
        sent = tool(f"ALTER LOGIN [{ACCOUNT}] WITH {options}")
        p = props()
        results[f"WP7 {options}"] = (
            f"{sent}; is_policy_checked {p['is_policy_checked']}, "
            f"is_expiration_checked {p['is_expiration_checked']}"
        )


CASES: tuple[Callable[[dict[str, str]], None], ...] = (wp0, wp1, wp2_wp3, wp4, wp5, wp6, wp7)

#: What the server answered. Empty until the first run measures it.
RECORDED: dict[str, str] = {}


def setup() -> None:
    teardown()
    admin(
        f"CREATE LOGIN [{TOOL}] WITH PASSWORD = {quote(TOOL_PASSWORD)}, CHECK_POLICY = OFF; "
        f"GRANT ALTER ANY LOGIN TO [{TOOL}]"
    )


def teardown() -> None:
    admin(f"{drop(ACCOUNT)}; {drop(TOOL)}")


def prepare() -> int:
    """Turn on SQL Server authentication; it takes effect at the next start."""
    admin(
        "EXEC xp_instance_regwrite N'HKEY_LOCAL_MACHINE', "
        "N'Software\\Microsoft\\MSSQLServer\\MSSQLServer', N'LoginMode', REG_DWORD, 2"
    )
    print("LoginMode set to 2; restart the service")
    return 0


def main() -> int:
    if sys.argv[1:2] == ["--prepare"]:
        return prepare()
    results: dict[str, str] = {}
    try:
        setup()
        for case in CASES:
            case(results)
    except StepError as exc:
        print(f"STEP FAILED: {exc}")
        return 1
    finally:
        teardown()
    differences = 0
    for label in [*RECORDED, *(label for label in results if label not in RECORDED)]:
        got = results.get(label)
        print(f"{label}: {got}")
        if got != RECORDED.get(label):
            differences += 1
            print(f"  DIFFERS from RESULTS: {RECORDED.get(label)}")
    print(f"{differences} differences")
    return 1 if differences else 0


if __name__ == "__main__":
    sys.exit(main())
