"""sopuli-dba : a SQL Server password hash computed by the client

#1538, M2. If SQL Server keeps the password of `ALTER LOGIN ... WITH PASSWORD`
anywhere (01), a SQL Server driver would compute the stored value itself and
send `ALTER LOGIN ... WITH PASSWORD = 0x... HASHED`, as the PostgreSQL driver
sends a SCRAM verifier. This measures, on each server:

  CH1  whether the probe's value, computed with the salt of the server's own
       hash, agrees with it, for passwords that sa sets
  CH2  whether a tool login that holds only ALTER ANY LOGIN sets a value the
       probe computed with a salt of its own, and whether the password then
       logs in, and a wrong password and the former one are refused
  CH3  what a malformed value answers, and whether the former password still
       logs in
  CH4  whether a value is accepted for a password that CHECK_POLICY would
       refuse, on a login with CHECK_POLICY = ON
  CH5  whether HASHED is accepted with MUST_CHANGE, and with UNLOCK
  CH6  the longest password sa can set, and whether a value for a longer one
       is accepted and logs in
  CH7  what the tool login reads of another login's hash

A stored value is a version of 2 bytes, a salt of 4 bytes, and a digest of 64
bytes. Version 0x0200 is SHA-512 over the password in UTF-16LE followed by the
salt. Version 0x0300 is PBKDF2-HMAC-SHA512 of the password in UTF-16LE and the
salt, 100,000 rounds. CH1 checks both against the server's own, and CH2 sets
both.

Statements and logins use the server's own sqlcmd, in its container. A password
reaches it through the environment of `docker exec`, as SQLCMDPASSWORD, never
through argv. The statements reach it on stdin.

The probe checks each result against the one RESULTS below records. The helpers
the other probes in this folder use are here. A difference, or a step that
fails, makes it exit 1.

It MEASURES and decides nothing.

STATUS: run on 15.0.4510.2, 16.0.4325.4 and 17.0.5065.9, the
mcr.microsoft.com/mssql/server 2019-latest, 2022-latest and 2025-latest images
of test/compose.yaml profile mssql-matrix, as pulled on 2026-11-15, with
Python 3.13.12 on Windows 11 AMD64, on 2026-11-15 (#1538). Twice, the first
time on servers just created, exit 0, and the same result every time.

RESULTS -- the same on every release, except where noted

  CH1  the server stores version 0x0200 on 15.0.4510.2 and 16.0.4325.4, and
       0x0300 on 17.0.5065.9. The probe's value agrees with the server's
       each time, also for the password that is not ASCII
  CH2  the tool login, with only ALTER ANY LOGIN, sets a 0x0200 value, and on
       16.0.4325.4 and 17.0.5065.9 a 0x0300 value. It is stored as sent, the
       password logs in, and a wrong password and the former one are refused,
       18456. 15.0.4510.2 refuses 0x0300, 15021
  CH3  a string, and a 0x0200 value of 6, 69 or 71 bytes, are refused, 15021,
       and the former password still logs in. **A 0x0100 value of 26 bytes,
       and a 0x0300 value of 70 bytes of zeros, are accepted, and the former
       password stops logging in.** 15.0.4510.2 refuses the 0x0300 one,
       15021. So the server checks a value's length and version, not that any
       password matches it
  CH4  on a login with CHECK_POLICY = ON, 'a' in clear is refused, 33062,
       and a value alone is refused, 33020, "A HASHED password cannot be set
       for a login that has CHECK_POLICY turned on". The value with
       `, CHECK_POLICY = OFF` in the same statement is accepted, for the
       password 'a', which then logs in. CHECK_POLICY = ON is then accepted
       on its own, reads back as is_policy_checked 1, and 'a' still logs in
  CH5  HASHED MUST_CHANGE is refused: 15099, "The MUST_CHANGE option cannot
       be used when CHECK_EXPIRATION is OFF", on a login with the policy off,
       and also when the statement turns CHECK_POLICY off; 33020 on a login
       with the policy and expiration on. HASHED UNLOCK is accepted on a
       login with the policy off, and the password logs in
  CH6  sa sets a password of 128 characters in clear, and is refused one of
       129, 15156. The tool sets a value for either. The 128-character
       password logs in. The 129-character one is not tried: sqlcmd takes at
       most 128 characters from SQLCMDPASSWORD
  CH7  the tool login reads NULL for another login's hash, from LOGINPROPERTY
       and from sys.sql_logins.password_hash, and sees sa's row in
       sys.sql_logins

HOW TO RUN, against the matrix (test/README.md), from the repo root:

    .venv/Scripts/python sql/mssql/02_client_hash_probe.py

It needs only the standard library and the docker CLI. The container names
follow COMPOSE_PROJECT_NAME, so a second clone's matrix is the one it uses.

THROWAWAY SERVERS ONLY. It creates the logins sopuli_probe_hash and
sopuli_probe_tool, and drops them at the end. Before it starts, it drops logins
an interrupted run left.
"""

from __future__ import annotations

import functools
import hashlib
import os
import re
import secrets
import subprocess
import sys
from collections.abc import Callable

PROJECT = os.environ.get("COMPOSE_PROJECT_NAME", "sopuli-test")
SERVICES = ("mssql-2019", "mssql-2022", "mssql-2025")
#: The matrix's public sa password, from test/compose.yaml.
SA_PASSWORD = "Sopuli-test-1"
ACCOUNT = "sopuli_probe_hash"
TOOL = "sopuli_probe_tool"
#: Test passwords, not credentials.
TOOL_PASSWORD = "Acme-Tool-pw1"
WRONG = "Acme-Wrong-pw9"
#: Test passwords, not credentials. One is not ASCII: e with acute, written as
#: a code point so the source stays ASCII.
PASSWORDS = ("Acme-Probe-pw1", "Acme probe " + chr(0xE9) + " pw2", "A" * 100)


class StepError(Exception):
    """A step that is not a result failed."""


# ---------------------------------------------------------------- the hash --


#: PBKDF2's rounds in a version 0x0300 value.
ROUNDS = 100_000


def password_hash(password: str, salt: bytes, version: int = 2) -> bytes:
    """A stored value: its version, the salt, and the digest.

    Version 0x0200 is SHA-512 over the UTF-16LE password and the salt. Version
    0x0300 is PBKDF2-HMAC-SHA512 of the UTF-16LE password and the salt, ROUNDS
    rounds, 64 bytes.
    """
    encoded = password.encode("utf-16-le")
    if version == 3:
        return b"\x03\x00" + salt + hashlib.pbkdf2_hmac("sha512", encoded, salt, ROUNDS)
    return b"\x02\x00" + salt + hashlib.sha512(encoded + salt).digest()


def draw_salt() -> bytes:
    return secrets.token_bytes(4)


# ------------------------------------------------------------------ sqlcmd --


def container(service: str) -> str:
    return f"{PROJECT}-{service}-1"


@functools.cache
def sqlcmd_path(service: str) -> tuple[str, ...]:
    """sqlcmd in the container, with -C where it is mssql-tools18's."""
    newer = "/opt/mssql-tools18/bin/sqlcmd"
    found = subprocess.run(
        ["docker", "exec", container(service), "test", "-x", newer],
        capture_output=True,
        check=False,
    )
    if found.returncode == 0:
        return (newer, "-C")
    return ("/opt/mssql-tools/bin/sqlcmd",)


#: "Msg 15151, Level 16, State 1, Server x, Line 1" and the message after it.
_MESSAGE = re.compile(r"^Msg (\d+), Level (\d+), State (\d+)[^\n]*\n(.*)$", re.MULTILINE)
#: "Sqlcmd: Error: Microsoft ODBC Driver 18 for SQL Server : Login failed ...".
_ODBC = re.compile(r"^Sqlcmd: Error: Microsoft ODBC Driver \d+ for SQL Server : (.*)$", re.M)
#: A refused login's message, which the ODBC driver prints without its number,
#: and the number sys.messages gives that text. Most specific first.
LOGIN_MESSAGES = (
    ("because the account is currently locked out", 18486),
    ("The password of the account has expired", 18487),
    ("The password of the account must be changed", 18488),
    ("Login failed for user", 18456),
)


def client(
    service: str, user: str, password: str, script: str, database: str = "master"
) -> tuple[str, list[tuple[int, str]]]:
    """Run `script` with sqlcmd as `user`: the output, and each error's number and text.

    The script is one batch. Output has no headers, `|` between columns, and
    UTF-8 in both directions. sqlcmd shows up to 8000 characters of a value
    (-y), and pads each column to its width, so each cell is stripped here; -W,
    which would not pad, cannot be used with -y. -I turns QUOTED_IDENTIFIER on,
    as a driver's session has it, which sqlcmd leaves off.
    """
    done = subprocess.run(
        [
            "docker", "exec", "-i", "-e", "SQLCMDPASSWORD", container(service),
            *sqlcmd_path(service), "-S", "localhost", "-U", user, "-d", database,
            "-h", "-1", "-y", "8000", "-s", "|", "-f", "65001", "-r", "1", "-I",
        ],
        input=("SET NOCOUNT ON;\n" + script + "\nGO\n").encode("utf-8"),
        env={**os.environ, "SQLCMDPASSWORD": password},
        capture_output=True,
        check=False,
    )  # fmt: skip
    out = "\n".join(
        "|".join(cell.strip() for cell in line.split("|"))
        for line in done.stdout.decode("utf-8", "replace").splitlines()
    ).strip()
    err = done.stderr.decode("utf-8", "replace").strip()
    errors = [(int(m[1]), m[4].strip()) for m in _MESSAGE.finditer(err)]
    # A refused login reaches sqlcmd through the ODBC driver, which prints the
    # server's message without its number. The number is found by the text,
    # and 0 stands for a text not in LOGIN_MESSAGES.
    for found in _ODBC.finditer(err):
        text = found[1].strip()
        number = next((n for words, n in LOGIN_MESSAGES if words in text), 0)
        errors.append((number, text))
    if err and not errors:
        # Not the server's answer: docker, or sqlcmd itself.
        raise StepError(f"{service}: {user}: {err[:200]}")
    return out, errors


def code(errors: list[tuple[int, str]]) -> str:
    """`ok`, or the error numbers, such as `15151`.

    An error with no number is its message, up to its first full stop, in
    quotes, such as `"Login failed for user 'x'"`.
    """
    parts = [str(number) if number else '"' + text.split(".")[0] + '"' for number, text in errors]
    return ",".join(parts) or "ok"


def sa(service: str, script: str, database: str = "master") -> str:
    out, errors = client(service, "sa", SA_PASSWORD, script, database)
    if errors:
        raise StepError(f"{service}: {script[:60]}: {errors}")
    return out


def as_tool(service: str, script: str) -> str:
    """`ok`, or the error numbers, for a batch the tool login sends."""
    _, errors = client(service, TOOL, TOOL_PASSWORD, script)
    return code(errors)


def login(service: str, password: str, account: str = ACCOUNT) -> str:
    """`ok`, or the error number of the refusal."""
    out, errors = client(service, account, password, "SELECT SUSER_SNAME()")
    if errors:
        return code(errors)
    return "ok" if out == account else f"other: {out[:40]}"


def quote(text: str) -> str:
    """An N'...' literal."""
    return "N'" + text.replace("'", "''") + "'"


#: Each result that differs from the one this header records.
DIFFERENCES: list[str] = []


def check(label: str, got: object, recorded: object) -> None:
    if got != recorded:
        DIFFERENCES.append(f"{label}: got {got!r}, recorded {recorded!r}")


def release(service: str) -> str:
    return sa(service, "SELECT CAST(SERVERPROPERTY('ProductVersion') AS nvarchar(32))")


def drop_login(name: str) -> str:
    """A batch that ends the login's sessions and drops it, if it exists.

    The variable is named after the login, so that two of these fit in one batch.
    """
    kills = f"@kill_{name}"
    return (
        f"IF SUSER_ID('{name}') IS NOT NULL BEGIN "
        f"DECLARE {kills} nvarchar(max) = N''; "
        f"SELECT {kills} += N'KILL ' + CAST(session_id AS nvarchar(10)) + N';' "
        f"FROM sys.dm_exec_sessions WHERE login_name = '{name}'; "
        f"EXEC ({kills}); DROP LOGIN [{name}] END"
    )


def setup(service: str) -> str:
    """Create the tool login and the probe's login; return the release."""
    found = release(service)
    print(f"\n== {service}: {found}")
    teardown(service)
    sa(
        service,
        f"CREATE LOGIN [{TOOL}] WITH PASSWORD = {quote(TOOL_PASSWORD)}, CHECK_POLICY = OFF;\n"
        f"GRANT ALTER ANY LOGIN TO [{TOOL}];\n"
        f"CREATE LOGIN [{ACCOUNT}] WITH PASSWORD = N'Acme-Probe-pw0', CHECK_POLICY = OFF",
    )
    return found


def teardown(service: str) -> None:
    sa(service, drop_login(ACCOUNT) + ";\n" + drop_login(TOOL))


def stored(service: str, account: str = ACCOUNT) -> bytes:
    hexed = sa(
        service,
        "SELECT CONVERT(varchar(max), "
        f"CAST(LOGINPROPERTY('{account}', 'PasswordHash') AS varbinary(256)), 2)",
    )
    return bytes.fromhex(hexed)


def reset(service: str, password: str, policy: str = "OFF", expiration: str = "OFF") -> None:
    """As sa, set the probe login's password in clear, and its policy settings."""
    sa(
        service,
        f"ALTER LOGIN [{ACCOUNT}] WITH CHECK_EXPIRATION = OFF, CHECK_POLICY = OFF;\n"
        f"ALTER LOGIN [{ACCOUNT}] WITH PASSWORD = {quote(password)} UNLOCK;\n"
        f"ALTER LOGIN [{ACCOUNT}] WITH CHECK_POLICY = {policy}, CHECK_EXPIRATION = {expiration}",
    )


def hashed(account: str, value: bytes, extra: str = "") -> str:
    return f"ALTER LOGIN [{account}] WITH PASSWORD = 0x{value.hex()} HASHED{extra}"


def cleaned(service: str, body: Callable[[], None], *cleanups: Callable[[], None]) -> None:
    """Run `body`, then each clean-up, even when `body` fails."""
    try:
        body()
    finally:
        for cleanup in cleanups:
            cleanup()


def run(probe: Callable[[str], None]) -> int:
    """Run `probe` on each server. Exit 1 on a difference or a failed step."""
    failed = False
    for service in SERVICES:
        try:
            probe(service)
        except (StepError, ValueError) as exc:
            print(f"STEP FAILED: {service}: {type(exc).__name__}: {exc}")
            failed = True
        finally:
            try:
                teardown(service)
            except StepError as exc:
                print(f"CLEAN-UP FAILED: {exc}")
                failed = True
    for difference in DIFFERENCES:
        print(f"DIFFERS: {difference}")
    if failed or DIFFERENCES:
        print("\nA RESULT DIFFERS FROM THE HEADER, OR A STEP FAILED")
        return 1
    print("\nevery result as recorded")
    return 0


# ------------------------------------------------------------------ probes --


#: CH2's refusals, by release and version. Every other pair is accepted.
CH2_REFUSED = {("15.0.4510.2", 3): "15021"}


def probe(service: str) -> None:
    """Run CH1 to CH7 on one server, print each result, and check it."""
    setup(service)

    found = release(service)
    native = "0300" if found.startswith("17.") else "0200"
    for password in PASSWORDS:
        sa(service, f"ALTER LOGIN [{ACCOUNT}] WITH PASSWORD = {quote(password)}")
        value = stored(service)
        version = value[0]
        agrees = len(value) == 70 and password_hash(password, value[2:6], version) == value
        print(f"CH1 {len(password)} characters: version 0x{value[:2].hex()}, agrees={agrees}")
        check(f"CH1 {len(password)}", (value[:2].hex(), agrees), (native, True))

    before = PASSWORDS[0]
    sa(service, f"ALTER LOGIN [{ACCOUNT}] WITH PASSWORD = {quote(before)}")
    for version in (2, 3):
        password = f"Acme-Probe-hashed{version}"
        value = password_hash(password, draw_salt(), version)
        answer = as_tool(service, hashed(ACCOUNT, value))
        if answer != "ok":
            print(f"CH2 version 0x0{version}00, set by the tool: {answer}")
            check(f"CH2 0x0{version}00", answer, CH2_REFUSED.get((found, version), "ok"))
            continue
        as_sent = stored(service) == value
        good, wrong = login(service, password), login(service, WRONG)
        former = login(service, before)
        print(
            f"CH2 version 0x0{version}00, set by the tool: {answer}; stored as sent={as_sent}; "
            f"password: {good}; wrong: {wrong}; former: {former}"
        )
        check(
            f"CH2 0x0{version}00",
            (answer, as_sent, good, wrong, former),
            (CH2_REFUSED.get((found, version), "ok"), True, "ok", "18456", "18456"),
        )
        before = password

    for label, literal, recorded in (
        ("a string", "N'not-a-hash'", ("15021", 70, "ok")),
        ("6 bytes", "0x0200aabbccdd", ("15021", 70, "ok")),
        ("69 bytes", "0x0200" + "00" * 67, ("15021", 70, "ok")),
        ("71 bytes", "0x0200" + "00" * 69, ("15021", 70, "ok")),
        ("version 0x0100, 26 bytes", "0x0100" + "00" * 24, ("ok", 26, "18456")),
        (
            "version 0x0300, 70 bytes",
            "0x0300" + "00" * 68,
            ("15021", 70, "ok") if found == "15.0.4510.2" else ("ok", 70, "18456"),
        ),
    ):
        reset(service, before)
        answer = as_tool(service, f"ALTER LOGIN [{ACCOUNT}] WITH PASSWORD = {literal} HASHED")
        kept = len(stored(service))
        former = login(service, before)
        print(f"CH3 {label}: {answer}; stored bytes {kept}; former: {former}")
        check(f"CH3 {label}", (answer, kept, former), recorded)

    weak = "a"
    reset(service, before, policy="ON")
    plain = as_tool(service, f"ALTER LOGIN [{ACCOUNT}] WITH PASSWORD = {quote(weak)}")
    alone = as_tool(service, hashed(ACCOUNT, password_hash(weak, draw_salt())))
    turned_off = ", CHECK_POLICY = OFF"
    both = as_tool(service, hashed(ACCOUNT, password_hash(weak, draw_salt()), turned_off))
    weak_login = login(service, weak)
    back_on = as_tool(service, f"ALTER LOGIN [{ACCOUNT}] WITH CHECK_POLICY = ON")
    policy = sa(service, f"SELECT is_policy_checked FROM sys.sql_logins WHERE name = '{ACCOUNT}'")
    last_login = login(service, weak)
    print(
        f"CH4 CHECK_POLICY = ON: 'a' in clear {plain}; as a value {alone}; "
        f"as a value with CHECK_POLICY = OFF {both}, login {weak_login}; "
        f"CHECK_POLICY = ON again {back_on}, is_policy_checked {policy}, login {last_login}"
    )
    check(
        "CH4",
        (plain, alone, both, weak_login, back_on, policy, last_login),
        ("33062", "33020", "ok", "ok", "ok", "1", "ok"),
    )

    password = "Acme-Probe-hashed2"
    value = password_hash(password, draw_salt())
    reset(service, before)
    off = as_tool(service, hashed(ACCOUNT, value, " MUST_CHANGE"))
    reset(service, before, policy="ON", expiration="ON")
    on = as_tool(service, hashed(ACCOUNT, value, " MUST_CHANGE"))
    turned = as_tool(service, hashed(ACCOUNT, value, " MUST_CHANGE" + turned_off))
    print(
        f"CH5 HASHED MUST_CHANGE: policy off {off}; policy and expiration on {on}; "
        f"with CHECK_POLICY = OFF {turned}"
    )
    check("CH5 MUST_CHANGE", (off, on, turned), ("15099", "33020", "15099"))
    reset(service, before)
    unlock = as_tool(service, hashed(ACCOUNT, value, " UNLOCK"))
    unlocked = login(service, password)
    print(f"CH5 HASHED UNLOCK, policy off: {unlock}; login: {unlocked}")
    check("CH5 UNLOCK", (unlock, unlocked), ("ok", "ok"))

    lengths = []
    for size in (128, 129):
        text = ("Ab3" * 60)[:size]
        reset(service, before)
        _, errors = client(
            service, "sa", SA_PASSWORD, f"ALTER LOGIN [{ACCOUNT}] WITH PASSWORD = {quote(text)}"
        )
        lengths.append(f"{size} in clear: {code(errors)}")
        answer = as_tool(service, hashed(ACCOUNT, password_hash(text, draw_salt())))
        # sqlcmd takes a password of at most 128 characters from SQLCMDPASSWORD.
        logged = login(service, text) if size <= 128 else "not tried"
        lengths.append(f"{size} as a value: {answer}, login {logged}")
    print(f"CH6 {lengths}")
    check(
        "CH6",
        lengths,
        [
            "128 in clear: ok",
            "128 as a value: ok, login ok",
            "129 in clear: 15156",
            "129 as a value: ok, login not tried",
        ],
    )

    out, errors = client(
        service,
        TOOL,
        TOOL_PASSWORD,
        "SELECT CONVERT(varchar(max), "
        f"CAST(LOGINPROPERTY('{ACCOUNT}', 'PasswordHash') AS varbinary(256)), 2);\n"
        "SELECT ISNULL(CONVERT(varchar(max), password_hash, 2), 'NULL') "
        f"FROM sys.sql_logins WHERE name = '{ACCOUNT}';\n"
        f"SELECT COUNT(*) FROM sys.sql_logins WHERE name = 'sa'",
    )
    read = (*out.splitlines(), code(errors))
    print(f"CH7 the tool reads: LOGINPROPERTY, password_hash, sa's row count, answer: {read}")
    check("CH7", read, ("NULL", "NULL", "1", "ok"))


def main() -> int:
    return run(probe)


if __name__ == "__main__":
    sys.exit(main())
