"""sopuli-dba : what each fixed server role gives, and what the catalog shows of it

#1553. Guardrail 9 (`02-mssql-privileges.md` §5) refuses a managed login
that holds CONTROL SERVER, ALTER ANY LOGIN, IMPERSONATE ANY LOGIN or ALTER ANY
SERVER ROLE through a server role, and reads the grants from
sys.server_permissions. A fixed server role's permissions may have no row
there. For each fixed server role the server lists (is_fixed_role = 1), the
login sopuli_probe_f is made its only new member, and then:

  FR1  how many rows of sys.server_permissions name the role as grantee,
       read by sa
  FR2  logged in as the member, what it holds: sysadmin membership, and
       HAS_PERMS_BY_NAME of CONTROL SERVER, ALTER ANY LOGIN, IMPERSONATE ANY
       LOGIN and ALTER ANY SERVER ROLE (`s,c,a,i,r`, 1 for held)
  FR3  whether the tool login, with only ALTER ANY LOGIN, sets the member's
       password, or is refused, 15151, as GR1 recorded for sysadmin
  FR4  whether the tool login reads the member's row in
       sys.server_role_members with the role's name (`name`), with its id
       only (`#id`), or not at all (`-`)

THROWAWAY SERVERS ONLY. It creates the logins sopuli_probe_tool,
sopuli_probe_hash (02's setup makes them) and sopuli_probe_f, adds
sopuli_probe_f to each fixed server role in turn and drops it from the role
again, and drops the logins at the end.

STATUS: run on 15.0.4510.2, 16.0.4325.4 and 17.0.5065.9, the
mcr.microsoft.com/mssql/server 2019-latest, 2022-latest and 2025-latest images
of test/compose.yaml profile mssql-matrix, as pulled on 2026-11-15, with
Python 3.13.12 on Windows 11 AMD64, on 2026-11-17 (#1553). Once while the
probe was written, and twice more against this header, exit 0. Every run of
a case gave the same result.

RESULTS -- the same on every release unless named

  FR1  **no fixed server role has a row in sys.server_permissions**: what
       each gives is implicit. 15.0.4510.2 lists 8 fixed roles, sysadmin to
       bulkadmin; 16.0.4325.4 and 17.0.5065.9 list those and 10 more, from
       ##MS_ServerStateReader## to ##MS_ServerPerformanceStateReader##
  FR2  three give a permission of the list: sysadmin gives all four, and
       securityadmin and ##MS_LoginManager## give ALTER ANY LOGIN and none
       of the others (`0,0,1,0,0`). Every other fixed role gives none
  FR3  the tool is refused the password of a member of each of those three,
       15151, and sets the password of a member of every other
  FR4  the tool reads each fixed role's membership row with the role's name
  On 15.0.4510.2 sa cannot add a member to bulkadmin, 16202: "not supported
  on the 'Linux' platform". 16.0.4325.4 and 17.0.5065.9 add one.

HOW TO RUN, against the matrix (test/README.md), from the repo root:

    .venv/Scripts/python sql/mssql/13_fixed_roles_probe.py

It needs 02_client_hash_probe.py beside it.
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

MEMBER = "sopuli_probe_f"
#: Test passwords, not credentials.
MEMBER_PASSWORD = "Acme-Member-pw1"
TOOL_SET = "Acme-Member-pw2"

#: What a login holds: sysadmin membership, then the four server permissions
#: of guardrail 9's list.
POWER = (
    "SELECT CAST(IS_SRVROLEMEMBER('sysadmin') AS varchar(2)) + ',' "
    "+ CAST(HAS_PERMS_BY_NAME(NULL, NULL, 'CONTROL SERVER') AS varchar(2)) + ',' "
    "+ CAST(HAS_PERMS_BY_NAME(NULL, NULL, 'ALTER ANY LOGIN') AS varchar(2)) + ',' "
    "+ CAST(HAS_PERMS_BY_NAME(NULL, NULL, 'IMPERSONATE ANY LOGIN') AS varchar(2)) + ',' "
    "+ CAST(HAS_PERMS_BY_NAME(NULL, NULL, 'ALTER ANY SERVER ROLE') AS varchar(2))"
)

#: The fixed server roles of 2019, in principal_id order.
LEGACY = (
    "sysadmin", "securityadmin", "serveradmin", "setupadmin", "processadmin",
    "diskadmin", "dbcreator", "bulkadmin",
)  # fmt: skip
#: The ones 2022 added.
ADDED_2022 = (
    "##MS_ServerStateReader##", "##MS_ServerStateManager##", "##MS_DefinitionReader##",
    "##MS_DatabaseConnector##", "##MS_DatabaseManager##", "##MS_LoginManager##",
    "##MS_SecurityDefinitionReader##", "##MS_PerformanceDefinitionReader##",
    "##MS_ServerSecurityStateReader##", "##MS_ServerPerformanceStateReader##",
)  # fmt: skip
#: The fixed server roles each major release lists.
ROLES_BY = {"15": LEGACY, "16": LEGACY + ADDED_2022, "17": LEGACY + ADDED_2022}

#: A role that gives none of the listed permissions: FR1, FR2, FR3 and FR4.
NOTHING = ("0", "0,0,0,0,0", "ok", "name")
#: Each fixed role's result where it is not NOTHING. The same on every
#: release that has the role, unless RECORDED_BY says.
RECORDED: dict[str, tuple[str, str, str, str]] = {
    "sysadmin": ("0", "1,1,1,1,1", "15151", "name"),
    "securityadmin": ("0", "0,0,1,0,0", "15151", "name"),
    "##MS_LoginManager##": ("0", "0,0,1,0,0", "15151", "name"),
}
RECORDED_BY: dict[str, dict[str, tuple[str, str, str, str]]] = {
    "15": {"bulkadmin": ("not added: 16202", "-", "-", "-")},
}


def as_login(service: str, name: str, password: str, script: str) -> str:
    out, errors = ch.client(service, name, password, script)
    return ch.code(errors) if errors else (out or "ok")


def fixed_roles(service: str) -> list[str]:
    out = ch.sa(
        service,
        "SELECT name FROM sys.server_principals WHERE type = 'R' AND is_fixed_role = 1 "
        "ORDER BY principal_id",
    )
    return [line for line in out.splitlines() if line]


def bracketed(name: str) -> str:
    return "[" + name.replace("]", "]]") + "]"


def once(service: str, role: str) -> tuple[str, str, str, str]:
    """FR1 to FR4 for one role, with the member added, and dropped after.

    A role the server does not let sa add a member to, such as bulkadmin on
    Linux before 2022, 16202, is recorded as `not added: <number>`.
    """
    ch.sa(service, f"ALTER LOGIN [{MEMBER}] WITH PASSWORD = {ch.quote(MEMBER_PASSWORD)}")
    _, errors = ch.client(
        service, "sa", ch.SA_PASSWORD, f"ALTER SERVER ROLE {bracketed(role)} ADD MEMBER [{MEMBER}]"
    )
    if errors:
        return ("not added: " + ch.code(errors), "-", "-", "-")
    try:
        rows = ch.sa(
            service,
            "SELECT CAST(COUNT(*) AS varchar(6)) FROM sys.server_permissions "
            f"WHERE grantee_principal_id = SUSER_ID({ch.quote(role)})",
        )
        sets = ch.as_tool(service, f"ALTER LOGIN [{MEMBER}] WITH PASSWORD = {ch.quote(TOOL_SET)}")
        if sets != "ok":
            ch.sa(service, f"ALTER LOGIN [{MEMBER}] WITH PASSWORD = {ch.quote(TOOL_SET)}")
        power = as_login(service, MEMBER, TOOL_SET, POWER)
        seen = as_login(
            service,
            ch.TOOL,
            ch.TOOL_PASSWORD,
            "SELECT ISNULL(MAX(CASE WHEN r.name IS NULL THEN '#id' ELSE 'name' END), '-') "
            "FROM sys.server_role_members AS m "
            "LEFT JOIN sys.server_principals AS r ON r.principal_id = m.role_principal_id "
            f"WHERE m.member_principal_id = SUSER_ID({ch.quote(MEMBER)}) "
            f"AND m.role_principal_id = SUSER_ID({ch.quote(role)})",
        )
    finally:
        ch.sa(service, f"ALTER SERVER ROLE {bracketed(role)} DROP MEMBER [{MEMBER}]")
    return rows, power, sets, seen


def probe(service: str) -> None:
    ch.cleaned(service, lambda: cases(service), lambda: ch.sa(service, ch.drop_login(MEMBER)))


def cases(service: str) -> None:
    major = ch.setup(service).split(".")[0]
    ch.sa(service, ch.drop_login(MEMBER))
    ch.sa(
        service,
        f"CREATE LOGIN [{MEMBER}] WITH PASSWORD = {ch.quote(MEMBER_PASSWORD)}, CHECK_POLICY = OFF",
    )
    roles = fixed_roles(service)
    ch.check(f"{major} fixed roles", tuple(roles), ROLES_BY.get(major))
    for role in roles:
        result = once(service, role)
        rows, power, sets, seen = result
        print(
            f"{role}: FR1 permission rows {rows}; FR2 member holds {power}; "
            f"FR3 tool sets the password {sets}; FR4 tool reads the membership {seen}"
        )
        recorded = RECORDED_BY.get(major, {}).get(role, RECORDED.get(role, NOTHING))
        ch.check(role, result, recorded)


def main() -> int:
    return ch.run(probe)


if __name__ == "__main__":
    sys.exit(main())
