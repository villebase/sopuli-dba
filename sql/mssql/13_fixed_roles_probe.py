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

Then, with VIEW ANY DEFINITION granted to the tool login, and a server role
sopuli_probe_fr that holds CONTROL SERVER:

  FR5  what the tool login reads under no denial, under DENY VIEW
       DEFINITION ON SERVER ROLE:: the role, and under DENY VIEW ANY
       SECURITY DEFINITION, each revoked before the next: HAS_PERMS_BY_NAME
       of VIEW ANY DEFINITION and of VIEW ANY SECURITY DEFINITION (`null`
       where the server answers NULL), the role's row in
       sys.server_principals, and its grant rows in sys.server_permissions,
       as `v,s|row|grants`

THROWAWAY SERVERS ONLY. It creates the logins sopuli_probe_tool,
sopuli_probe_hash (02's setup makes them) and sopuli_probe_f, adds
sopuli_probe_f to each fixed server role in turn and drops it from the role
again, makes and drops the role sopuli_probe_fr, grants the tool login VIEW
ANY DEFINITION and denies it what FR5 names, and drops the logins at the end.

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
  FR5  **HAS_PERMS_BY_NAME answers 1 for VIEW ANY DEFINITION under either
       denial, and the denial still hides rows**. DENY VIEW DEFINITION on
       the role hides its row and not its grant (`1,1|0|1`). DENY VIEW ANY
       SECURITY DEFINITION hides the row and the grant, and HAS_PERMS_BY_NAME
       of that permission answers 0 (`1,0|0|0`). With no denial the tool
       reads both (`1,1|1|1`). 15.0.4510.2 answers NULL for VIEW ANY
       SECURITY DEFINITION, as for a permission it does not have, and the
       DENY of it is a syntax error, 102; the denial on the role is as on
       the others (`1,null|0|1`)

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


#: FR5's role, which holds CONTROL SERVER.
HIDDEN = "sopuli_probe_fr"

#: What the tool login reads, as `v,s | r | g`: HAS_PERMS_BY_NAME of VIEW ANY
#: DEFINITION and VIEW ANY SECURITY DEFINITION, the role's rows in
#: sys.server_principals, and its grant rows in sys.server_permissions.
HIDDEN_VIEW = (
    "SELECT ISNULL(CAST(HAS_PERMS_BY_NAME(NULL, NULL, 'VIEW ANY DEFINITION') AS varchar(4)), "
    "'null') + ',' + ISNULL(CAST(HAS_PERMS_BY_NAME(NULL, NULL, "
    "'VIEW ANY SECURITY DEFINITION') AS varchar(4)), 'null') + ' | ' "
    f"+ (SELECT CAST(COUNT(*) AS varchar(4)) FROM sys.server_principals WHERE name = '{HIDDEN}') "
    "+ ' | ' + (SELECT CAST(COUNT(*) AS varchar(4)) FROM sys.server_permissions "
    f"WHERE grantee_principal_id = SUSER_ID('{HIDDEN}'))"
)

#: FR5's denials, each made and revoked in turn.
DENIALS = {
    "none": "",
    "deny on the role": f"VIEW DEFINITION ON SERVER ROLE::[{HIDDEN}]",
    "deny security definition": "VIEW ANY SECURITY DEFINITION",
}

#: FR5's results: what the tool reads under each denial.
#: sqlcmd's column separator is `|`, and each cell is stripped.
RECORDED_FR5: dict[str, str] = {
    "none": "1,1|1|1",
    "deny on the role": "1,1|0|1",
    "deny security definition": "1,0|0|0",
}
RECORDED_FR5_BY: dict[str, dict[str, str]] = {
    "15": {
        "none": "1,null|1|1",
        "deny on the role": "1,null|0|1",
        "deny security definition": "not denied: 102",
    },
}


def hidden(service: str, major: str) -> None:
    """FR5: what a DENY hides from a tool login that holds VIEW ANY DEFINITION."""
    ch.sa(service, f"GRANT VIEW ANY DEFINITION TO [{ch.TOOL}]")
    ch.sa(service, f"CREATE SERVER ROLE [{HIDDEN}]; GRANT CONTROL SERVER TO [{HIDDEN}]")
    for label, what in DENIALS.items():
        if what:
            _, errors = ch.client(service, "sa", ch.SA_PASSWORD, f"DENY {what} TO [{ch.TOOL}]")
            if errors:
                seen = "not denied: " + ch.code(errors)
            else:
                seen = as_login(service, ch.TOOL, ch.TOOL_PASSWORD, HIDDEN_VIEW)
                ch.sa(service, f"REVOKE {what} FROM [{ch.TOOL}]")
        else:
            seen = as_login(service, ch.TOOL, ch.TOOL_PASSWORD, HIDDEN_VIEW)
        print(f"FR5 {label}: tool reads {seen}")
        recorded = RECORDED_FR5_BY.get(major, {}).get(label, RECORDED_FR5.get(label))
        ch.check(f"FR5 {label}", seen, recorded)


def drop_hidden(service: str) -> None:
    ch.sa(service, f"IF SUSER_ID('{HIDDEN}') IS NOT NULL DROP SERVER ROLE [{HIDDEN}]")


def probe(service: str) -> None:
    ch.cleaned(
        service,
        lambda: cases(service),
        lambda: ch.sa(service, ch.drop_login(MEMBER)),
        lambda: drop_hidden(service),
    )


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
    drop_hidden(service)
    hidden(service, major)


def main() -> int:
    return ch.run(probe)


if __name__ == "__main__":
    sys.exit(main())
