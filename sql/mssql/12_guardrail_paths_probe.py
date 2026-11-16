"""sopuli-dba : the grant paths of guardrail 9 that 04 did not measure

#1553. `02-mssql-privileges.md` §5 refuses a managed login that holds, itself
or through a server role, a grant on one login or one server role, or that
owns such a role; and it reads `public`'s grants as every login's. 04
measured only ALTER ANY SERVER ROLE's path (GR4). This measures the others.
For each path a holder login is made, and then:

  PA1  whether the tool login, with only ALTER ANY LOGIN, sets the holder's
       password, or is refused, 15151, as GR1 recorded for the server's own
       protected logins
  PA2  what the tool login reads of the holder: its rows in
       sys.server_permissions (permission, class, and the object's name),
       its rows in sys.server_role_members, and, for a role, the owner
       sys.server_principals.owning_principal_id names
  PA3  logged in as the holder, whether the path reaches CONTROL SERVER or
       ALTER ANY LOGIN: what the holder then holds, as sysadmin membership,
       CONTROL SERVER and ALTER ANY LOGIN (`s,c,a`, 1 for held)

The paths, each held by its own login sopuli_probe_h_<path>:

  on one login, the tool login (`tool`) and a member of sysadmin (`admin`):
       CONTROL, ALTER, IMPERSONATE and TAKE OWNERSHIP. The holder tries
       EXECUTE AS LOGIN, and ALTER LOGIN ... WITH PASSWORD, setting the
       password the login already has
  on a server role that holds CONTROL SERVER: CONTROL, ALTER and TAKE
       OWNERSHIP. The holder tries ALTER SERVER ROLE ... ADD MEMBER itself,
       and, if that is refused, ALTER AUTHORIZATION ON SERVER ROLE to itself
       and then ADD MEMBER
  owner: a role that holds CONTROL SERVER, created with AUTHORIZATION the
       holder. The holder tries ADD MEMBER itself
  nested: the holder is a member of a role that is a member of the role
       that holds CONTROL SERVER. The holder tries nothing
  public: ALTER ANY SERVER ROLE granted to public, and a holder with no
       grant of its own, which tries ADD MEMBER itself. The tool's read of
       public's row (grantee principal_id 2) is part of PA2. The grant is
       revoked at once

  PA4  for the role paths, what a second reader reads, one that holds VIEW
       ANY DEFINITION besides ALTER ANY LOGIN

STATUS: run on 15.0.4510.2, 16.0.4325.4 and 17.0.5065.9, the
mcr.microsoft.com/mssql/server 2019-latest, 2022-latest and 2025-latest images
of test/compose.yaml profile mssql-matrix, as pulled on 2026-11-15, with
Python 3.13.12 on Windows 11 AMD64, on 2026-11-17 (#1553). Six times while the
probe was written, and twice more against this header, exit 0. Every run gave
the same result.

RESULTS -- the same on every release

  PA1  the tool sets the password of every holder but one: the member of a
       role nested in the role that holds CONTROL SERVER, which it is refused,
       15151, as GR1 recorded for a direct member
  PA3  **CONTROL or IMPERSONATE on one login reaches that login's power**:
       EXECUTE AS the tool login holds ALTER ANY LOGIN, and EXECUTE AS the
       sysadmin member holds sysadmin. Neither sets the login's password,
       15151. ALTER on one login reaches no power: EXECUTE AS is refused,
       15406, the password is refused, 15151, and DEFAULT_DATABASE is set.
       CONTROL sets DEFAULT_DATABASE too, and IMPERSONATE does not, 15151.
       **TAKE OWNERSHIP on a login cannot be granted**: the GRANT is a syntax
       error
       **Every role path reaches CONTROL SERVER**: CONTROL or ALTER on the
       role that holds it lets the holder add itself; TAKE OWNERSHIP does not,
       15151, but ALTER AUTHORIZATION to itself does, and then it adds
       itself; the owner of such a role adds itself. ALTER ANY SERVER ROLE
       granted to public lets a login with no grant of its own add itself.
       The nested member holds CONTROL SERVER without trying anything
  PA2  **the tool, with ALTER ANY LOGIN alone, does not see a user-defined
       server role's row**: its name, and the owner owning_principal_id
       names, are not read. It reads a holder's grant on a role and its
       membership of a role with the role's id only, and that role's own
       grants by the id. **It does not see a membership row whose member is
       a role**, so it cannot follow a role nested in another. It reads a
       grant on a login with the login's name, and public's grants
       (grantee principal_id 2), ALTER ANY SERVER ROLE among them
  PA4  with VIEW ANY DEFINITION as well, the reader sees each role's name and
       owner, and the nested role's membership of the role that holds
       CONTROL SERVER

HOW TO RUN, against the matrix (test/README.md), from the repo root:

    .venv/Scripts/python sql/mssql/12_guardrail_paths_probe.py

It needs 02_client_hash_probe.py beside it.

THROWAWAY SERVERS ONLY. It creates the logins sopuli_probe_tool,
sopuli_probe_hash (02's setup makes it), sopuli_probe_admin and
sopuli_probe_h_*, and the server roles sopuli_probe_ctl, sopuli_probe_nest
and sopuli_probe_owned, and drops them at the end. It grants ALTER ANY SERVER
ROLE to public and revokes it in the same step, and again at the end. It
sets the tool's and the admin's passwords to the ones they already have.
"""

from __future__ import annotations

import importlib.util
import re
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

ADMIN = "sopuli_probe_admin"
#: A second reader: ALTER ANY LOGIN, as the tool, and VIEW ANY DEFINITION.
VIEWER = "sopuli_probe_viewer"
VIEWER_PASSWORD = "Acme-Viewer-pw1"
CONTROL_ROLE = "sopuli_probe_ctl"
NESTED = "sopuli_probe_nest"
OWNED = "sopuli_probe_owned"
ROLES = (CONTROL_ROLE, NESTED, OWNED)
#: Test passwords, not credentials.
ADMIN_PASSWORD = "Acme-Admin-pw1"
HOLDER_PASSWORD = "Acme-Holder-pw1"
TOOL_SET = "Acme-Holder-pw2"

#: What a login holds: sysadmin membership, CONTROL SERVER, ALTER ANY LOGIN.
POWER = (
    "SELECT CAST(IS_SRVROLEMEMBER('sysadmin') AS varchar(2)) + ',' "
    "+ CAST(HAS_PERMS_BY_NAME(NULL, NULL, 'CONTROL SERVER') AS varchar(2)) + ',' "
    "+ CAST(HAS_PERMS_BY_NAME(NULL, NULL, 'ALTER ANY LOGIN') AS varchar(2))"
)

#: Each login a holder may hold a grant on, and the password it has.
LOGIN_TARGETS = {"tool": (ch.TOOL, ch.TOOL_PASSWORD), "admin": (ADMIN, ADMIN_PASSWORD)}
LOGIN_GRANTS = ("CONTROL", "ALTER", "IMPERSONATE", "TAKE OWNERSHIP")
ROLE_GRANTS = ("CONTROL", "ALTER", "TAKE OWNERSHIP")


def holder(path: str) -> str:
    return "sopuli_probe_h_" + path


def short(grant: str) -> str:
    return grant.lower().replace("take ownership", "take")


def paths() -> list[str]:
    login = [f"{short(g)}_{t}" for t in LOGIN_TARGETS for g in LOGIN_GRANTS]
    return [*login, *(f"{short(g)}_role" for g in ROLE_GRANTS), "owner", "nested", "public"]


def drop_role(name: str) -> str:
    """A batch that drops the role's members, then the role, if it exists."""
    var = f"@members_{name}"
    return (
        f"IF SUSER_ID('{name}') IS NOT NULL BEGIN "
        f"DECLARE {var} nvarchar(max) = N''; "
        f"SELECT {var} += N'ALTER SERVER ROLE [{name}] DROP MEMBER ' + QUOTENAME(p.name) + N';' "
        "FROM sys.server_role_members AS m JOIN sys.server_principals AS p "
        "ON p.principal_id = m.member_principal_id "
        f"WHERE m.role_principal_id = SUSER_ID('{name}'); "
        f"EXEC ({var}); DROP SERVER ROLE [{name}] END"
    )


def drop_all(service: str) -> None:
    ch.sa(service, "REVOKE ALTER ANY SERVER ROLE FROM public")
    for role in ROLES:
        ch.sa(service, drop_role(role))
    for name in (*map(holder, paths()), ADMIN, VIEWER):
        ch.sa(service, ch.drop_login(name))


def as_login(service: str, name: str, password: str, script: str) -> str:
    out, errors = ch.client(service, name, password, script)
    return ch.code(errors) if errors else (out or "ok")


#: A reader: a login and its password.
Reader = tuple[str, str]
TOOL_READER: Reader = (ch.TOOL, ch.TOOL_PASSWORD)
VIEWER_READER: Reader = (VIEWER, VIEWER_PASSWORD)


def tool_view(service: str, name: str, reader: Reader = TOOL_READER) -> str:
    """What `reader` reads of `name`: its permissions, beside CONNECT SQL,
    as `permission/class/object`, and the roles it is a member of."""
    out = as_login(
        service,
        *reader,
        # The catalog's columns differ in collation, which STRING_AGG refuses,
        # 4191, without one named.
        # An object whose principal row the tool does not see is `#<id>`.
        "SELECT ISNULL(STRING_AGG((p.permission_name + '/' + p.class_desc + '/' "
        "+ CASE WHEN p.class <> 101 THEN '-' "
        "ELSE ISNULL(o.name, '#' + CAST(p.major_id AS varchar(12))) END) "
        "COLLATE DATABASE_DEFAULT, ' ') WITHIN GROUP (ORDER BY p.permission_name), '-') "
        "FROM sys.server_permissions AS p LEFT JOIN sys.server_principals AS o "
        "ON p.class = 101 AND o.principal_id = p.major_id "
        f"WHERE p.grantee_principal_id = SUSER_ID({ch.quote(name)}) "
        "AND p.permission_name <> 'CONNECT SQL';\n"
        "SELECT ISNULL(STRING_AGG(ISNULL(r.name, '#' + CAST(m.role_principal_id AS varchar(12))) "
        "COLLATE DATABASE_DEFAULT, ' '), '-') FROM sys.server_role_members AS m "
        "LEFT JOIN sys.server_principals AS r ON r.principal_id = m.role_principal_id "
        f"WHERE m.member_principal_id = SUSER_ID({ch.quote(name)})",
    )
    return out.replace("\n", " | ")


def role_row(service: str, role: str, reader: Reader = TOOL_READER) -> str:
    """What `reader` reads of a role's own row, found by the id sa reads:
    the owner's name or `#<id>`, or `no row` where it does not see it."""
    role_id = int(ch.sa(service, f"SELECT CAST(SUSER_ID({ch.quote(role)}) AS varchar(12))"))
    out = as_login(
        service,
        *reader,
        "SELECT ISNULL(o.name, '#' + CAST(r.owning_principal_id AS varchar(12))) "
        "FROM sys.server_principals AS r "
        "LEFT JOIN sys.server_principals AS o ON o.principal_id = r.owning_principal_id "
        f"WHERE r.principal_id = {role_id}",
    )
    row = "no row" if out == "ok" else f"owned by {out}"
    # The role's own grants and memberships, by its id, which the tool reads
    # from a member's row even where it does not see the role's.
    grants = as_login(
        service,
        *reader,
        "SELECT ISNULL(STRING_AGG(permission_name COLLATE DATABASE_DEFAULT, ' '), '-') "
        f"FROM sys.server_permissions WHERE grantee_principal_id = {role_id};\n"
        "SELECT CAST(COUNT(*) AS varchar(4)) FROM sys.server_role_members "
        f"WHERE member_principal_id = {role_id} OR role_principal_id = {role_id}",
    ).replace("\n", ", membership rows ")
    return f"{row}, grants {grants}"


def setup(service: str) -> str:
    found = ch.setup(service)
    drop_all(service)
    ch.sa(
        service,
        f"CREATE LOGIN [{ADMIN}] WITH PASSWORD = {ch.quote(ADMIN_PASSWORD)}, CHECK_POLICY = OFF;\n"
        f"ALTER SERVER ROLE [sysadmin] ADD MEMBER [{ADMIN}];\n"
        f"CREATE LOGIN [{VIEWER}] WITH PASSWORD = {ch.quote(VIEWER_PASSWORD)}, "
        "CHECK_POLICY = OFF;\n"
        f"GRANT ALTER ANY LOGIN TO [{VIEWER}];\nGRANT VIEW ANY DEFINITION TO [{VIEWER}];\n"
        f"CREATE SERVER ROLE [{CONTROL_ROLE}];\nGRANT CONTROL SERVER TO [{CONTROL_ROLE}];\n"
        f"CREATE SERVER ROLE [{NESTED}];\n"
        f"ALTER SERVER ROLE [{CONTROL_ROLE}] ADD MEMBER [{NESTED}]",
    )
    for path in paths():
        ch.sa(
            service,
            f"CREATE LOGIN [{holder(path)}] WITH PASSWORD = {ch.quote(HOLDER_PASSWORD)}, "
            "CHECK_POLICY = OFF",
        )
    return found


def grant(service: str, path: str) -> str:
    """Give the holder its path, as sa: `ok`, or the refusal."""
    name = holder(path)
    if path == "owner":
        script = (
            f"CREATE SERVER ROLE [{OWNED}] AUTHORIZATION [{name}];\n"
            f"GRANT CONTROL SERVER TO [{OWNED}]"
        )
    elif path == "nested":
        script = f"ALTER SERVER ROLE [{NESTED}] ADD MEMBER [{name}]"
    elif path == "public":
        script = "GRANT ALTER ANY SERVER ROLE TO public"
    else:
        kind, on = path.rsplit("_", 1)
        permission = {"take": "TAKE OWNERSHIP"}.get(kind, kind.upper())
        if on == "role":
            script = f"GRANT {permission} ON SERVER ROLE::[{CONTROL_ROLE}] TO [{name}]"
        else:
            script = f"GRANT {permission} ON LOGIN::[{LOGIN_TARGETS[on][0]}] TO [{name}]"
    try:
        _, errors = ch.client(service, "sa", ch.SA_PASSWORD, script)
    except ch.StepError as exc:
        # sqlcmd prints a syntax error without the "Msg" line ch.client reads.
        if "Incorrect syntax" in str(exc):
            return "syntax error"
        raise
    return ch.code(errors)


def attempt(service: str, path: str) -> str:
    """As the holder, try the path; return each step's answer."""
    name = holder(path)
    if path == "nested":
        return "nothing tried"
    if path in ("owner", "public") or path.endswith("_role"):
        role = OWNED if path == "owner" else CONTROL_ROLE
        add = f"ALTER SERVER ROLE [{role}] ADD MEMBER [{name}]"
        first = as_login(service, name, TOOL_SET, add)
        if first == "ok" or path in ("owner", "public"):
            return f"add member {first}"
        take = as_login(
            service, name, TOOL_SET, f"ALTER AUTHORIZATION ON SERVER ROLE::[{role}] TO [{name}]"
        )
        then = as_login(service, name, TOOL_SET, add) if take == "ok" else "not tried"
        return f"add member {first}; take ownership {take}; add member {then}"
    target, password = LOGIN_TARGETS[path.rsplit("_", 1)[1]]
    impersonated = as_login(
        service, name, TOOL_SET, f"EXECUTE AS LOGIN = {ch.quote(target)};\n{POWER};\nREVERT"
    )
    reset = as_login(
        service, name, TOOL_SET, f"ALTER LOGIN [{target}] WITH PASSWORD = {ch.quote(password)}"
    )
    # A setting the login already has: whether the grant reaches the login
    # at all, with a statement that changes nothing.
    setting = as_login(
        service, name, TOOL_SET, f"ALTER LOGIN [{target}] WITH DEFAULT_DATABASE = [master]"
    )
    return f"execute as {impersonated}; set password {reset}; set default database {setting}"


_LOGIN_SET = "set password 15151; set default database"

#: Each path's result: the grant, PA1, PA2, PA3's attempt, what the holder
#: then holds, and PA4. The same on every release unless RECORDED_BY says.
RECORDED: dict[str, object] = {
    "control_tool": (
        "ok", "ok", "CONTROL/SERVER_PRINCIPAL/sopuli_probe_tool | -",
        f"execute as 0,0,1; {_LOGIN_SET} ok", "0,0,0", "",
    ),
    "alter_tool": (
        "ok", "ok", "ALTER/SERVER_PRINCIPAL/sopuli_probe_tool | -",
        f"execute as 15406; {_LOGIN_SET} ok", "0,0,0", "",
    ),
    "impersonate_tool": (
        "ok", "ok", "IMPERSONATE/SERVER_PRINCIPAL/sopuli_probe_tool | -",
        f"execute as 0,0,1; {_LOGIN_SET} 15151", "0,0,0", "",
    ),
    "take_tool": ("syntax error", "ok", "- | -", "not granted", "0,0,0", ""),
    "control_admin": (
        "ok", "ok", "CONTROL/SERVER_PRINCIPAL/sopuli_probe_admin | -",
        f"execute as 1,1,1; {_LOGIN_SET} ok", "0,0,0", "",
    ),
    "alter_admin": (
        "ok", "ok", "ALTER/SERVER_PRINCIPAL/sopuli_probe_admin | -",
        f"execute as 15406; {_LOGIN_SET} ok", "0,0,0", "",
    ),
    "impersonate_admin": (
        "ok", "ok", "IMPERSONATE/SERVER_PRINCIPAL/sopuli_probe_admin | -",
        f"execute as 1,1,1; {_LOGIN_SET} 15151", "0,0,0", "",
    ),
    "take_admin": ("syntax error", "ok", "- | -", "not granted", "0,0,0", ""),
    "control_role": (
        "ok", "ok",
        "CONTROL/SERVER_PRINCIPAL/#id | - | sopuli_probe_ctl no row, grants CONTROL SERVER, "
        "membership rows 0",
        "add member ok", "0,1,1",
        "CONTROL/SERVER_PRINCIPAL/sopuli_probe_ctl | - | sopuli_probe_ctl owned by sa, "
        "grants CONTROL SERVER, membership rows 1",
    ),
    "alter_role": (
        "ok", "ok", "ALTER/SERVER_PRINCIPAL/#id | -", "add member ok", "0,1,1", "",
    ),
    "take_role": (
        "ok", "ok", "TAKE OWNERSHIP/SERVER_PRINCIPAL/#id | -",
        "add member 15151; take ownership ok; add member ok", "0,1,1", "",
    ),
    "owner": (
        "ok", "ok", "- | - | owner no row, grants CONTROL SERVER, membership rows 0",
        "add member ok", "0,1,1",
        "- | - | sopuli_probe_owned owned by sopuli_probe_h_owner, grants CONTROL SERVER, "
        "membership rows 0",
    ),
    "nested": (
        "ok", "15151",
        "- | #id | sopuli_probe_ctl no row, grants CONTROL SERVER, membership rows 3 "
        "| sopuli_probe_nest no row, grants -, membership rows 1",
        "nothing tried", "0,1,1",
        # take_role, before it, made its holder the owner of sopuli_probe_ctl.
        "- | sopuli_probe_nest | sopuli_probe_ctl owned by sopuli_probe_h_take_role, "
        "grants CONTROL SERVER, membership rows 4 "
        "| sopuli_probe_nest owned by sa, grants -, membership rows 2",
    ),
    "public": (
        "ok", "ok",
        "- | - | public ALTER ANY SERVER ROLE/SERVER/- CONNECT/ENDPOINT/- CONNECT/ENDPOINT/- "
        "CONNECT/ENDPOINT/- CONNECT/ENDPOINT/- VIEW ANY DATABASE/SERVER/- | -",
        "add member ok", "0,1,1", "",
    ),
}  # fmt: skip
RECORDED_BY: dict[str, dict[str, object]] = {}


def probe(service: str) -> None:
    ch.cleaned(service, lambda: cases(service), lambda: drop_all(service))


def cases(service: str) -> None:
    major = setup(service).split(".")[0]
    for path in paths():
        name = holder(path)
        granted = grant(service, path)
        sets = ch.as_tool(service, f"ALTER LOGIN [{name}] WITH PASSWORD = {ch.quote(TOOL_SET)}")
        view = tool_view(service, name)
        extra = ""
        if path == "owner":
            extra = " | owner " + role_row(service, OWNED)
        if path in ("nested", "control_role"):
            extra = f" | {CONTROL_ROLE} " + role_row(service, CONTROL_ROLE)
        if path == "nested":
            extra += f" | {NESTED} " + role_row(service, NESTED)
        if path == "public":
            extra = " | public " + tool_view(service, "public")
        viewer = ""
        if path in ("owner", "control_role", "nested"):
            role = OWNED if path == "owner" else CONTROL_ROLE
            viewer = f"{tool_view(service, name, VIEWER_READER)} | {role} " + role_row(
                service, role, VIEWER_READER
            )
            if path == "nested":
                viewer += f" | {NESTED} " + role_row(service, NESTED, VIEWER_READER)
        if sets != "ok":
            # The tool could not set it; sa does, so that the holder can try.
            ch.sa(service, f"ALTER LOGIN [{name}] WITH PASSWORD = {ch.quote(TOOL_SET)}")
        tried = attempt(service, path) if granted == "ok" else "not granted"
        power = as_login(service, name, TOOL_SET, POWER)
        if path == "public":
            ch.sa(service, "REVOKE ALTER ANY SERVER ROLE FROM public")
        # A principal_id differs between runs; the probe records that the
        # reader saw an id and no name.
        view, extra = re.sub(r"#\d+", "#id", view), re.sub(r"#\d+", "#id", extra)
        result = (granted, sets, view + extra, tried, power, viewer)
        print(
            f"{path}: grant {granted}; PA1 tool sets the password {sets}; "
            f"PA2 tool reads {view}{extra}; PA3 {tried}; then holds {power}"
            + (f"; PA4 with VIEW ANY DEFINITION reads {viewer}" if viewer else "")
        )
        recorded = RECORDED_BY.get(major, {}).get(path, RECORDED.get(path))
        ch.check(path, result, recorded)


def main() -> int:
    return ch.run(probe)


if __name__ == "__main__":
    sys.exit(main())
