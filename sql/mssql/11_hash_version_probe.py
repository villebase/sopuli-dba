"""sopuli-dba : how the tool can tell whether a server takes a 0x0300 value

#1550, mssql-hash-version. 2019 refuses a 0x0300 value, 15021, and 2022 and
2025 take it (02, CH2). The tool login reads NULL for every login's hash (02,
CH7), so it cannot copy the version a server stores. This measures, as a tool
login that holds only ALTER ANY LOGIN:

  HV1  what the tool reads of SERVERPROPERTY: ProductVersion,
       ProductMajorVersion, EngineEdition and Edition
  HV2  a 0x0300 value sent to a login that does not exist: the answer, so
       whether the server checks the value's version before it looks for the
       login. A statement that changes nothing, because there is no login to
       change
  HV3  a 0x0300 value sent to an existing login with CHECK_POLICY and
       CHECK_EXPIRATION on, in the statement the driver sends (with
       `, CHECK_POLICY = OFF`): the answer, and afterwards the login's two
       flags, whether its stored value changed, and whether its password
       still logs in. On a server that refuses 0x0300, whether the refusal
       changes nothing
  HV4  the same statement inside BEGIN TRANSACTION ... ROLLBACK
  HV5  CREATE LOGIN with a 0x0300 value, for a login the tool creates and
       drops: the answer, and whether the login is left behind
  HV6  the same CREATE LOGIN inside BEGIN TRANSACTION ... ROLLBACK, with a
       0x0300 value and with a 0x0200 one: the answer, and whether the login
       exists afterwards. A check that touches no managed login
  HV7  HV6 with a malformed 0x0300 value: one byte short, and all zeros. So
       whether 15021 says only that the server refuses the version
  HV8  HV6 with the name of a login that exists, with each version. So what
       the check answers when its name is taken

STATUS: run on 15.0.4510.2, 16.0.4325.4 and 17.0.5065.9, the
mcr.microsoft.com/mssql/server 2019-latest, 2022-latest and 2025-latest images
of test/compose.yaml profile mssql-matrix, as pulled on 2026-11-15, with
Python 3.13.12 on Windows 11 AMD64, on 2026-11-16 (#1550). Six times; HV7 and
HV8 three times. The last two runs exit 0 against this header, and every run
gave the same result.

RESULTS -- the same on every release, except where noted

  HV1  the tool reads SERVERPROPERTY: ProductMajorVersion 15, 16 and 17,
       EngineEdition 3, and the edition, Developer on 2019 and 2022 and
       Enterprise Developer on 2025
  HV2  a value of either version, sent to a login that does not exist, is
       refused 15151, "Cannot alter the login ..., because it does not exist
       or you do not have permission". The server looks for the login first,
       so this does not tell the versions apart
  HV3  on 15.0.4510.2 the statement is refused, 15021, "Invalid value given
       for parameter PASSWORD", and **changes nothing**: both flags stay on,
       the stored value is the same, the former password logs in and the new
       one is refused, 18456. On 16.0.4325.4 and 17.0.5065.9 it is accepted:
       both flags are off, and the new password logs in
  HV4  inside a transaction that is rolled back, the same statement answers
       as in HV3. On 16.0.4325.4 and 17.0.5065.9, where it is accepted, it is
       then rolled back: both flags on, the stored value the same, the former
       password logs in. On 15.0.4510.2 it is refused, so nothing is rolled
       back
  HV5  CREATE LOGIN with a 0x0300 value is refused on 15.0.4510.2, 15021, and
       no login is left. It is accepted on 16.0.4325.4 and 17.0.5065.9
  HV6  **a check that touches no managed login:** CREATE LOGIN with a 0x0300
       value inside a transaction that is rolled back answers 15021 on
       15.0.4510.2 and ok on 16.0.4325.4 and 17.0.5065.9, and leaves no
       login on any release. With a 0x0200 value it answers ok on every
       release, and leaves no login
  HV7  **15021 is not only the version's refusal.** A 0x0300 value one byte
       short is refused 15021 on every release. One of zeros is accepted on
       16.0.4325.4 and 17.0.5065.9, and refused 15021 on 15.0.4510.2. So
       HV6's answer means what it says only for a value of the right length
  HV8  with the name of a login that exists: on 15.0.4510.2 a 0x0300 value
       answers 15021, and a 0x0200 one 15025, "The server principal ...
       already exists". On 16.0.4325.4 and 17.0.5065.9 both answer 15025.
       2019 checks the value's version before the name; the others check
       the name first

HOW TO RUN, against the matrix (test/README.md), from the repo root:

    .venv/Scripts/python sql/mssql/11_hash_version_probe.py

It needs 02_client_hash_probe.py beside it.

THROWAWAY SERVERS ONLY. It creates the logins sopuli_probe_tool,
sopuli_probe_hash and sopuli_probe_created, and drops them at the end. Before
it starts, it drops logins an interrupted run left, and it makes sure
sopuli_probe_absent does not exist.
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

ABSENT = "sopuli_probe_absent"
CREATED = "sopuli_probe_created"
#: Test passwords, not credentials.
BEFORE = "Acme-Version-pw0"
NEW = "Acme-Version-pw1"

#: What a release that takes 0x0300 answers.
_TAKES: dict[str, object] = {
    "HV2 0x0300": "15151",
    "HV2 0x0200": "15151",
    "HV3": ("ok", "0,0", False, "18456", "ok"),
    "HV4": ("ok", "1,1", True, "ok", "18456"),
    "HV5": ("ok", "1"),
    "HV6 0x0300": ("ok", "0"),
    "HV6 0x0200": ("ok", "0"),
    "HV7 0x0300 of 69 bytes": ("15021", "0"),
    "HV7 0x0300 of zeros": ("ok", "0"),
    "HV8 0x0300, an existing name": ("15025", "0"),
    "HV8 0x0200, an existing name": ("15025", "0"),
}

#: Each recorded result, by the server's major release.
RECORDED: dict[str, dict[str, object]] = {
    "15": {
        "HV1": ["15", "3"],
        "HV2 0x0300": "15151",
        "HV2 0x0200": "15151",
        "HV3": ("15021", "1,1", True, "ok", "18456"),
        "HV4": ("15021", "1,1", True, "ok", "18456"),
        "HV5": ("15021", "0"),
        "HV6 0x0300": ("15021", "0"),
        "HV6 0x0200": ("ok", "0"),
        "HV7 0x0300 of 69 bytes": ("15021", "0"),
        "HV7 0x0300 of zeros": ("15021", "0"),
        "HV8 0x0300, an existing name": ("15021", "0"),
        "HV8 0x0200, an existing name": ("15025", "0"),
    },
    "16": {"HV1": ["16", "3"], **_TAKES},
    "17": {"HV1": ["17", "3"], **_TAKES},
}


def tool(service: str, script: str) -> str:
    """The tool's output, `ok` for a statement with none, or the refusal."""
    out, errors = ch.client(service, ch.TOOL, ch.TOOL_PASSWORD, script)
    return ch.code(errors) if errors else (out or "ok")


def answer(service: str, script: str) -> tuple[str, str]:
    """One run of `script` as the tool: the code that is checked, as
    `ch.code` gives it, and the server's text, which is printed."""
    _, errors = ch.client(service, ch.TOOL, ch.TOOL_PASSWORD, script)
    text = "; ".join(f"{number}: {message}" for number, message in errors) or "ok"
    return ch.code(errors), text


def flags(service: str) -> str:
    return ch.sa(
        service,
        "SELECT CAST(is_policy_checked AS varchar(1)) + ',' "
        "+ CAST(is_expiration_checked AS varchar(1)) "
        f"FROM sys.sql_logins WHERE name = {ch.quote(ch.ACCOUNT)}",
    )


def exists(service: str, name: str) -> str:
    return ch.sa(service, f"SELECT CASE WHEN SUSER_ID({ch.quote(name)}) IS NULL THEN 0 ELSE 1 END")


def rolled_back_create(name: str, value: bytes) -> str:
    return (
        "BEGIN TRANSACTION;\n"
        f"CREATE LOGIN [{name}] WITH PASSWORD = 0x{value.hex()} HASHED, CHECK_POLICY = OFF;\n"
        "ROLLBACK TRANSACTION"
    )


def drop_extra(service: str) -> None:
    ch.sa(service, ch.drop_login(CREATED) + ";\n" + ch.drop_login(ABSENT))


def probe(service: str) -> None:
    ch.cleaned(service, lambda: cases(service), lambda: drop_extra(service))


def cases(service: str) -> None:
    major = ch.setup(service).split(".")[0]
    drop_extra(service)
    recorded = RECORDED.get(major, {})

    props = tool(
        service,
        "SELECT CAST(SERVERPROPERTY('ProductVersion') AS nvarchar(32)) + ',' "
        "+ CAST(SERVERPROPERTY('ProductMajorVersion') AS nvarchar(8)) + ',' "
        "+ CAST(SERVERPROPERTY('EngineEdition') AS nvarchar(8)) + ',' "
        "+ CAST(SERVERPROPERTY('Edition') AS nvarchar(64))",
    )
    print(f"HV1 ProductVersion, ProductMajorVersion, EngineEdition, Edition: {props}")
    ch.check("HV1", props.split(",")[1:3], recorded.get("HV1"))

    value3 = ch.password_hash(NEW, ch.draw_salt(), 3)
    value2 = ch.password_hash(NEW, ch.draw_salt(), 2)
    for label, value in (("0x0300", value3), ("0x0200", value2)):
        code, text = answer(service, ch.hashed(ABSENT, value, ", CHECK_POLICY = OFF"))
        print(f"HV2 {label} to a login that does not exist: {text}")
        ch.check(f"HV2 {label}", code, recorded.get(f"HV2 {label}"))

    for label, wrap in (
        ("HV3", lambda s: s),
        ("HV4", lambda s: f"BEGIN TRANSACTION;\n{s};\nROLLBACK TRANSACTION"),
    ):
        ch.reset(service, BEFORE, policy="ON", expiration="ON")
        stored = ch.stored(service)
        statement = wrap(ch.hashed(ch.ACCOUNT, ch.password_hash(NEW, ch.draw_salt(), 3),
                                   ", CHECK_POLICY = OFF"))  # fmt: skip
        code, text = answer(service, statement)
        after = (
            flags(service),
            ch.stored(service) == stored,
            ch.login(service, BEFORE),
            ch.login(service, NEW),
        )
        print(
            f"{label} 0x0300 with CHECK_POLICY = OFF to a login with the policy and expiration "
            f"on: {text}; then flags {after[0]}, stored value unchanged {after[1]}, "
            f"former password {after[2]}, new password {after[3]}"
        )
        ch.check(label, (code, *after), recorded.get(label))

    create = f"CREATE LOGIN [{CREATED}] WITH PASSWORD = 0x{value3.hex()} HASHED, CHECK_POLICY = OFF"
    code, text = answer(service, create)
    left = exists(service, CREATED)
    print(f"HV5 CREATE LOGIN with a 0x0300 value: {text}; the login exists afterwards: {left}")
    ch.check("HV5", (code, left), recorded.get("HV5"))

    drop_extra(service)
    for label, name, value in (
        ("HV6 0x0300", CREATED, value3),
        ("HV6 0x0200", CREATED, value2),
        # A malformed 0x0300 value: one byte short, and all zeros (02, CH3).
        ("HV7 0x0300 of 69 bytes", CREATED, value3[:-1]),
        ("HV7 0x0300 of zeros", CREATED, b"\x03\x00" + bytes(68)),
        # The name of a login that exists.
        ("HV8 0x0300, an existing name", ch.ACCOUNT, value3),
        ("HV8 0x0200, an existing name", ch.ACCOUNT, value2),
    ):
        code, text = answer(service, rolled_back_create(name, value))
        left = exists(service, CREATED)
        print(f"{label}: CREATE LOGIN, rolled back: {text}; {CREATED} exists afterwards: {left}")
        ch.check(label, (code, left), recorded.get(label))
        drop_extra(service)


def main() -> int:
    return ch.run(probe)


if __name__ == "__main__":
    sys.exit(main())
