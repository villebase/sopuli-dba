"""sopuli-dba : a SECURITY DEFINER function that says whether a role has a password

#1511, gap 6. The tool account, LOGIN CREATEROLE and nothing else
(02-postgres-privileges.md §2.1), reads rolpassword in pg_roles as the mask
******** for every role, and is refused pg_authid (10_report_read_probe.py,
#1443). So the report cannot tell whether a role has a password. This
measures a function a DBA could create to answer that alone, as #1457 lets
MySQL and MariaDB read a view. The superuser creates it:

    CREATE FUNCTION sopuli_probe.role_password_set()
      RETURNS TABLE (rolname name, password_set boolean)
      LANGUAGE sql STABLE SECURITY DEFINER
      SET search_path = pg_catalog, pg_temp
      AS $$ SELECT a.rolname, a.rolpassword IS NOT NULL
              FROM pg_catalog.pg_authid a $$

and grants EXECUTE on it, and USAGE on the schema, to the tool account
alone, after REVOKE ALL ... FROM PUBLIC. The probe runs as the tool account
unless a step says otherwise:

  PS1  what the tool account reads through it, for each fixture role, and how
       many rows against pg_roles. Then a second function of the same shape
       that returns the kind of password instead of a boolean: scram, md5 or
       NULL
  PS2  the shape check and the capability probe: to_regprocedure(), the
       result type from pg_get_function_result(), prosecdef, proconfig, the
       owner's rolsuper, has_function_privilege() and the body in prosrc. Then
       what a call and to_regprocedure() give for a function absent from the
       schema, for an absent schema, without EXECUTE, and without USAGE on the
       schema
  PS3  an owner that is not a superuser: sopuli_probe_ps_owner, NOLOGIN, owns
       a copy of the function. A call when it holds nothing on pg_authid,
       then after the superuser's GRANT SELECT ON pg_authid to it, and after a
       column grant on rolname and rolpassword in place of that. Then, with
       the column grant in place, what the tool account can do to that owner:
       GRANT it to itself, ALTER ROLE ... LOGIN PASSWORD on it, and, where the
       GRANT succeeded, SET ROLE to it and count the rows of pg_authid it
       reads with a value that begins SCRAM-SHA-256$. Then the same three on
       the superuser postgres, and whether the tool account may CREATE OR
       REPLACE, ALTER or DROP the superuser's function
  PS4  search_path: three copies owned by the superuser, beside the function
       above: an unqualified pg_authid without the SET clause, a qualified
       pg_catalog.pg_authid without it, and an unqualified pg_authid with it.
       The tool account creates a temporary table pg_authid with one row,
       and calls the four

The fixture, which the superuser creates on each server:

  sopuli_probe_admin       LOGIN CREATEROLE, the tool account
  sopuli_probe_ps_scram    LOGIN, a password under scram-sha-256
  sopuli_probe_ps_md5      LOGIN, a password under password_encryption md5
  sopuli_probe_ps_none     LOGIN, created without a password
  sopuli_probe_ps_null     LOGIN, a password, then ALTER ROLE ... PASSWORD NULL
  sopuli_probe_ps_empty    LOGIN, PASSWORD ''
  sopuli_probe_ps_nologin  NOLOGIN, a password
  sopuli_probe_ps_expired  LOGIN, a password, VALID UNTIL 2000-01-01
  sopuli_probe_ps_owner    NOLOGIN, PS3's owner
  schema sopuli_probe, owned by the superuser, with the functions

It MEASURES and decides nothing. It prints no stored value. The superuser
reads each fixture role's rolpassword, and the probe looks for each one, and
for "SCRAM-SHA-256$" and an md5 value, in everything the tool account read,
rows and refusals: it prints only whether one was found. PS3's count of
pg_authid's values is made on the server, and only the count comes back.

It prints each result and checks none against RESULTS below: compare a new
run with RESULTS by eye. It exits 1 only when a step fails, or when a stored
value is found in what the tool account read.

STATUS: run on 13.23, 14.24, 15.19, 16.15, 17.11 and 18.6, the postgres:13 to
postgres:18 images of test/compose.yaml profile postgres-matrix, on 2026-11-14
(#1511). The client was psycopg 3.3.6 with libpq 18.4, on Windows 11 AMD64.
Twice, exit 0, the same result both times. Five earlier runs are not counted:
PS4 had only the first and the last of its four functions, so it did not
show which of the two safeguards stops the spoof. They gave the same results
as below for PS1 to PS3.

RESULTS -- the same on every release, except where noted

  PS1  password_set is true for the roles with a scram or an md5 password,
       the NOLOGIN one and the expired one, and false for the role created
       without one, the one set to PASSWORD NULL, and the one given
       PASSWORD '', which the server stores as no password. The function has
       one row per row of pg_roles, and no name differs. password_kind reads
       scram, md5 or NULL as the fixture set them. On 13.23 a role created
       without a SET reads md5, because the image's password_encryption is
       md5 there
  PS2  to_regprocedure() finds the function. pg_get_function_result() reads
       "TABLE(rolname name, password_set boolean)", prosecdef true, proconfig
       ['search_path=pg_catalog, pg_temp'], the owner's rolsuper true,
       has_function_privilege() true, and prosrc the body. For an absent
       function and an absent schema, to_regprocedure() is NULL, and a call
       gets 42883 "function sopuli_probe.no_such_function() does not exist"
       and 3F000 "schema "sopuli_probe_no_schema" does not exist". Without
       EXECUTE, to_regprocedure() finds it, has_function_privilege() is false,
       and a call gets 42501 "permission denied for function
       role_password_set". Without USAGE on the schema, to_regprocedure()
       itself gets 42501 "permission denied for schema sopuli_probe", as the
       call does
  PS3  owned by sopuli_probe_ps_owner with nothing on pg_authid, a call gets
       42501 "permission denied for table pg_authid". The superuser's GRANT
       SELECT ON pg_authid, and a column grant on rolname and rolpassword,
       are both accepted, and the call then reads. With the column grant in
       place:
         13.23, 14.24, 15.19: the tool account's GRANT of the owner to itself
         is accepted, SET ROLE to it works, and as the owner it reads every
         value in pg_authid that begins SCRAM-SHA-256$: 1 on 13.23, and 5 on
         14.24 and 15.19, the superuser's among them. Its ALTER ROLE ...
         LOGIN PASSWORD on the owner is accepted too
         16.15, 17.11, 18.6: the GRANT gets 42501 "permission denied to grant
         role "sopuli_probe_ps_owner"", and the ALTER ROLE 42501 "permission
         denied to alter role"
       The same on postgres, the superuser, gets 42501 on every release: "must
       be superuser to alter superusers" or "... to alter superuser roles or
       change superuser attribute" on 13.23 to 15.19, and the two messages of
       16.15 above from 16.15. The tool account's CREATE OR REPLACE of the
       superuser's function gets 42501 "permission denied for schema
       sopuli_probe", and its ALTER FUNCTION and DROP FUNCTION get 42501
       "must be owner of function sopuli_probe.role_password_set"
  PS4  the tool account may create a temporary table pg_authid. The copy
       with an unqualified pg_authid and no SET search_path then reads that
       table: one row, the spoofed one. Each of the other three reads the
       catalog, one row per role and no spoofed row: the qualified name
       without the SET clause, the unqualified name with it, and both
  leak check: nothing the tool account read held a stored value, 29 outputs
       on 13.23 to 15.19 and 27 from 16.15, against 5 values each

  So the function answers the question with the tool account's grants of
  02-postgres-privileges.md §2.1 and EXECUTE, and shows no stored value. Its
  owner must be a superuser: on 13 to 15 the tool account can make itself a
  member of any other owner, and then read every verifier. Its body must
  name pg_catalog.pg_authid, or the function must SET search_path =
  pg_catalog, pg_temp: with neither, a temporary table decides its answer.

HOW TO RUN, against the matrix (test/README.md), from the repo root, with the
repo's virtual environment:

    .venv/Scripts/python sql/postgres/11_password_set_function_probe.py

The ports follow SOPULI_TEST_POSTGRES13_PORT to SOPULI_TEST_POSTGRES18_PORT,
so a second clone's matrix is the one it uses.

THROWAWAY SERVERS ONLY. It creates the roles above and the schema
sopuli_probe, and drops them at the end. Before it starts, it drops what an
interrupted run left.
"""

from __future__ import annotations

import os
import re
import sys
from typing import Any

import psycopg
from psycopg import sql

VERSIONS = (13, 14, 15, 16, 17, 18)
#: Tier 0's public test password, from test/compose.yaml.
SUPERUSER_PASSWORD = "sopuli-test"
#: The tool account's password, and the fixture's. Markers on a throwaway server.
ADMIN_PASSWORD = "sopuli-probe-admin"
FIXTURE_PASSWORD = "sopuli-probe-ps-1"
ADMIN = "sopuli_probe_admin"
OWNER = "sopuli_probe_ps_owner"
SCHEMA = "sopuli_probe"
FIXTURE = (
    "sopuli_probe_ps_scram",
    "sopuli_probe_ps_md5",
    "sopuli_probe_ps_none",
    "sopuli_probe_ps_null",
    "sopuli_probe_ps_empty",
    "sopuli_probe_ps_nologin",
    "sopuli_probe_ps_expired",
)
ROLES = (ADMIN, OWNER, *FIXTURE)

FUNCTION = "role_password_set"
KIND_FUNCTION = "role_password_kind"
OWNED_COPY = "role_password_set_owned"
UNSET_COPY = "role_password_set_no_path"
QUALIFIED_UNSET_COPY = "role_password_set_qualified_no_path"
UNQUALIFIED_SET_COPY = "role_password_set_unqualified_path"

BODY = "SELECT a.rolname, a.rolpassword IS NOT NULL FROM pg_catalog.pg_authid a"
KIND_BODY = (
    "SELECT a.rolname, CASE WHEN a.rolpassword LIKE 'SCRAM-SHA-256$%' THEN 'scram'"
    " WHEN a.rolpassword LIKE 'md5%' THEN 'md5' END FROM pg_catalog.pg_authid a"
)
UNQUALIFIED_BODY = "SELECT a.rolname, a.rolpassword IS NOT NULL FROM pg_authid a"

MD5_VALUE = re.compile(r"md5[0-9a-f]{32}")


class Seen:
    """Everything the tool account read, rows and refusals, for the leak check."""

    def __init__(self) -> None:
        self.texts: list[str] = []

    def add(self, value: Any) -> Any:
        self.texts.append(repr(value))
        return value


def _port(version: int) -> str:
    return os.environ.get(f"SOPULI_TEST_POSTGRES{version}_PORT", f"54{version}")


def _connect(
    version: int, user: str = "postgres", password: str = SUPERUSER_PASSWORD
) -> psycopg.Connection[Any]:
    """The superuser by default, or the tool account."""
    return psycopg.connect(
        host="127.0.0.1",
        port=_port(version),
        user=user,
        password=password,
        dbname="postgres",
        autocommit=True,
        connect_timeout=10,
    )


def _one(conn: psycopg.Connection[Any], query: Any, params: Any = None) -> Any:
    """The first column of the one row a query returns."""
    row = conn.execute(query, params).fetchone()
    if row is None:
        raise RuntimeError(f"no row from: {query}")
    return row[0]


def _try(conn: psycopg.Connection[Any], seen: Seen, query: Any, params: Any = None) -> str:
    """Run a statement as the tool account, and say what it got: its rows, or
    the SQLSTATE and message of its refusal."""
    try:
        cursor = conn.execute(query, params)
        rows = cursor.fetchall() if cursor.description else []
        seen.add(rows)
        return f"ok {rows}" if rows else "ok"
    except psycopg.Error as error:
        message = f"{error.sqlstate} {error.diag.message_primary}"
        seen.add(message)
        return message


def _clean(version: int) -> None:
    """Drop what this probe creates, whatever an earlier run left."""
    with _connect(version) as su:
        su.execute(sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(sql.Identifier(SCHEMA)))
        found = [
            row[0]
            for row in su.execute(
                "SELECT rolname::text FROM pg_roles WHERE rolname = ANY(%s)", (list(ROLES),)
            ).fetchall()
        ]
        if found:
            su.execute("REVOKE ALL ON pg_catalog.pg_authid FROM " + ", ".join(found))
            names = sql.SQL(", ").join(sql.Identifier(role) for role in found)
            su.execute(sql.SQL("DROP OWNED BY {}").format(names))
            su.execute(sql.SQL("DROP ROLE {}").format(names))


def _create_function(
    su: psycopg.Connection[Any], name: str, result: str, body: str, path: bool = True
) -> None:
    setting = "SET search_path = pg_catalog, pg_temp" if path else ""
    su.execute(
        f"CREATE FUNCTION {SCHEMA}.{name}() RETURNS TABLE (rolname name, {result})"
        f" LANGUAGE sql STABLE SECURITY DEFINER {setting} AS $${body}$$"
    )
    su.execute(f"REVOKE ALL ON FUNCTION {SCHEMA}.{name}() FROM PUBLIC")
    su.execute(f"GRANT EXECUTE ON FUNCTION {SCHEMA}.{name}() TO {ADMIN}")


def _setup(version: int) -> list[str]:
    """The fixture. Returns every stored value of the fixture's roles, for the
    leak check."""
    with _connect(version) as su:
        statements = [
            f"CREATE ROLE {ADMIN} LOGIN CREATEROLE PASSWORD '{ADMIN_PASSWORD}'",
            f"CREATE ROLE {OWNER} NOLOGIN",
            "SET password_encryption = 'scram-sha-256'",
            f"CREATE ROLE sopuli_probe_ps_scram LOGIN PASSWORD '{FIXTURE_PASSWORD}'",
            "SET password_encryption = 'md5'",
            f"CREATE ROLE sopuli_probe_ps_md5 LOGIN PASSWORD '{FIXTURE_PASSWORD}'",
            "RESET password_encryption",
            "CREATE ROLE sopuli_probe_ps_none LOGIN",
            f"CREATE ROLE sopuli_probe_ps_null LOGIN PASSWORD '{FIXTURE_PASSWORD}'",
            "ALTER ROLE sopuli_probe_ps_null PASSWORD NULL",
            "CREATE ROLE sopuli_probe_ps_empty LOGIN PASSWORD ''",
            f"CREATE ROLE sopuli_probe_ps_nologin NOLOGIN PASSWORD '{FIXTURE_PASSWORD}'",
            f"CREATE ROLE sopuli_probe_ps_expired LOGIN PASSWORD '{FIXTURE_PASSWORD}'"
            " VALID UNTIL '2000-01-01'",
            f"CREATE SCHEMA {SCHEMA}",
            f"REVOKE ALL ON SCHEMA {SCHEMA} FROM PUBLIC",
            f"GRANT USAGE ON SCHEMA {SCHEMA} TO {ADMIN}",
        ]
        for statement in statements:
            su.execute(statement)
        _create_function(su, FUNCTION, "password_set boolean", BODY)
        _create_function(su, KIND_FUNCTION, "password_kind text", KIND_BODY)
        _create_function(su, OWNED_COPY, "password_set boolean", BODY)
        su.execute(f"ALTER FUNCTION {SCHEMA}.{OWNED_COPY}() OWNER TO {OWNER}")
        _create_function(su, UNSET_COPY, "password_set boolean", UNQUALIFIED_BODY, path=False)
        _create_function(su, QUALIFIED_UNSET_COPY, "password_set boolean", BODY, path=False)
        _create_function(su, UNQUALIFIED_SET_COPY, "password_set boolean", UNQUALIFIED_BODY)
        return [
            row[0]
            for row in su.execute(
                "SELECT rolpassword FROM pg_authid WHERE rolname = ANY(%s)"
                " AND rolpassword IS NOT NULL",
                (list(ROLES),),
            ).fetchall()
        ]


def _ps1(conn: psycopg.Connection[Any], seen: Seen) -> None:
    rows = seen.add(
        conn.execute(
            f"SELECT rolname::text, password_set FROM {SCHEMA}.{FUNCTION}()"
            " WHERE rolname = ANY(%s) ORDER BY rolname",
            (list(ROLES),),
        ).fetchall()
    )
    print(f"  PS1  {FUNCTION}(): {rows}")
    counts = seen.add(
        conn.execute(
            f"SELECT (SELECT count(*) FROM {SCHEMA}.{FUNCTION}()),"
            " (SELECT count(*) FROM pg_roles),"
            f" (SELECT count(*) FROM {SCHEMA}.{FUNCTION}() f"
            "   WHERE NOT EXISTS (SELECT 1 FROM pg_roles r WHERE r.rolname = f.rolname))"
        ).fetchone()
    )
    print(f"  PS1  rows: function {counts[0]}, pg_roles {counts[1]}, not in pg_roles {counts[2]}")
    kinds = seen.add(
        conn.execute(
            f"SELECT rolname::text, password_kind FROM {SCHEMA}.{KIND_FUNCTION}()"
            " WHERE rolname = ANY(%s) ORDER BY rolname",
            (list(ROLES),),
        ).fetchall()
    )
    print(f"  PS1  {KIND_FUNCTION}(): {kinds}")


def _ps2(conn: psycopg.Connection[Any], su: psycopg.Connection[Any], seen: Seen) -> None:
    shape = seen.add(
        conn.execute(
            "SELECT p.oid IS NOT NULL, pg_get_function_result(p.oid), p.prosecdef,"
            " p.proconfig, o.rolsuper, has_function_privilege(p.oid, 'EXECUTE'), p.prosrc"
            " FROM pg_proc p JOIN pg_roles o ON o.oid = p.proowner"
            " WHERE p.oid = to_regprocedure(%s)",
            (f"{SCHEMA}.{FUNCTION}()",),
        ).fetchone()
    )
    print(
        f"  PS2  found {shape[0]}; result {shape[1]!r}; prosecdef {shape[2]}; proconfig"
        f" {shape[3]}; owner rolsuper {shape[4]}; EXECUTE {shape[5]}; prosrc {shape[6]!r}"
    )
    cases = {
        "absent function": f"{SCHEMA}.no_such_function()",
        "absent schema": "sopuli_probe_no_schema.role_password_set()",
    }
    for label, name in cases.items():
        regproc = _try(conn, seen, "SELECT to_regprocedure(%s)", (name,))
        call = _try(conn, seen, f"SELECT count(*) FROM {name}")
        print(f"  PS2  {label}: to_regprocedure {regproc}; call {call}")
    su.execute(f"REVOKE EXECUTE ON FUNCTION {SCHEMA}.{FUNCTION}() FROM {ADMIN}")
    regproc = _try(
        conn,
        seen,
        "SELECT to_regprocedure(%s) IS NOT NULL,"
        " has_function_privilege(to_regprocedure(%s), 'EXECUTE')",
        (f"{SCHEMA}.{FUNCTION}()", f"{SCHEMA}.{FUNCTION}()"),
    )
    call = _try(conn, seen, f"SELECT count(*) FROM {SCHEMA}.{FUNCTION}()")
    print(f"  PS2  without EXECUTE: found, EXECUTE {regproc}; call {call}")
    su.execute(f"GRANT EXECUTE ON FUNCTION {SCHEMA}.{FUNCTION}() TO {ADMIN}")
    su.execute(f"REVOKE USAGE ON SCHEMA {SCHEMA} FROM {ADMIN}")
    regproc = _try(conn, seen, "SELECT to_regprocedure(%s)", (f"{SCHEMA}.{FUNCTION}()",))
    call = _try(conn, seen, f"SELECT count(*) FROM {SCHEMA}.{FUNCTION}()")
    print(f"  PS2  without USAGE on the schema: to_regprocedure {regproc}; call {call}")
    su.execute(f"GRANT USAGE ON SCHEMA {SCHEMA} TO {ADMIN}")


def _ps3(conn: psycopg.Connection[Any], su: psycopg.Connection[Any], seen: Seen) -> None:
    call = f"SELECT count(*) FILTER (WHERE password_set) FROM {SCHEMA}.{OWNED_COPY}()"
    print(f"  PS3  owner holds nothing on pg_authid: {_try(conn, seen, call)}")
    granted = _try(su, Seen(), f"GRANT SELECT ON pg_catalog.pg_authid TO {OWNER}")
    print(f"  PS3  superuser GRANT SELECT ON pg_authid: {granted}; call {_try(conn, seen, call)}")
    su.execute(f"REVOKE SELECT ON pg_catalog.pg_authid FROM {OWNER}")
    granted = _try(
        su, Seen(), f"GRANT SELECT (rolname, rolpassword) ON pg_catalog.pg_authid TO {OWNER}"
    )
    print(f"  PS3  superuser column grant: {granted}; call {_try(conn, seen, call)}")

    count = (
        "SELECT count(*) FILTER (WHERE rolpassword LIKE 'SCRAM-SHA-256$%')"
        " FROM pg_catalog.pg_authid"
    )
    for target in (OWNER, "postgres"):
        grant = _try(conn, seen, f"GRANT {target} TO {ADMIN}")
        print(f"  PS3  tool account: GRANT {target} TO itself: {grant}")
        if grant.startswith("ok"):
            set_role = _try(conn, seen, f"SET ROLE {target}")
            print(f"  PS3  tool account: SET ROLE {target}: {set_role}")
            values = _try(conn, seen, count)
            print(f"  PS3  tool account as {target}: values that begin SCRAM-SHA-256$: {values}")
            conn.execute("RESET ROLE")
            su.execute(f"REVOKE {target} FROM {ADMIN}")
        alter = _try(conn, seen, f"ALTER ROLE {target} LOGIN PASSWORD 'sopuli-probe-taken'")
        print(f"  PS3  tool account: ALTER ROLE {target} LOGIN PASSWORD: {alter}")
        if alter.startswith("ok") and target == OWNER:
            su.execute(f"ALTER ROLE {OWNER} NOLOGIN PASSWORD NULL")

    replace = _try(
        conn,
        seen,
        f"CREATE OR REPLACE FUNCTION {SCHEMA}.{FUNCTION}()"
        " RETURNS TABLE (rolname name, password_set boolean)"
        " LANGUAGE sql STABLE SECURITY DEFINER AS $$SELECT NULL::name, NULL::boolean$$",
    )
    print(f"  PS3  tool account: CREATE OR REPLACE the superuser's function: {replace}")
    alter = _try(conn, seen, f"ALTER FUNCTION {SCHEMA}.{FUNCTION}() RESET search_path")
    print(f"  PS3  tool account: ALTER FUNCTION ... RESET search_path: {alter}")
    drop = _try(conn, seen, f"DROP FUNCTION {SCHEMA}.{FUNCTION}()")
    print(f"  PS3  tool account: DROP FUNCTION: {drop}")


def _ps4(conn: psycopg.Connection[Any], seen: Seen) -> None:
    made = _try(
        conn,
        seen,
        "CREATE TEMPORARY TABLE pg_authid (rolname name, rolpassword text)",
    )
    print(f"  PS4  tool account: CREATE TEMPORARY TABLE pg_authid: {made}")
    if made.startswith("ok"):
        conn.execute("INSERT INTO pg_temp.pg_authid VALUES ('sopuli_probe_spoof', 'x')")
    for name in (UNSET_COPY, QUALIFIED_UNSET_COPY, UNQUALIFIED_SET_COPY, FUNCTION):
        rows = _try(
            conn,
            seen,
            f"SELECT count(*), count(*) FILTER (WHERE rolname = 'sopuli_probe_spoof')"
            f" FROM {SCHEMA}.{name}()",
        )
        print(f"  PS4  {name}(): rows, spoofed rows: {rows}")


def _leaks(seen: Seen, values: list[str]) -> bool:
    text = "\n".join(seen.texts)
    found = any(value in text for value in values)
    found = found or "SCRAM-SHA-256$" in text or bool(MD5_VALUE.search(text))
    print(
        f"  leak check: {len(seen.texts)} outputs against {len(values)} values:"
        f" {'FOUND A STORED VALUE' if found else 'none found'}"
    )
    return found


def probe(version: int) -> bool:
    with _connect(version) as su:
        release = _one(su, "SHOW server_version")
    print(f"PostgreSQL {release} (port {_port(version)})")
    _clean(version)
    seen = Seen()
    try:
        values = _setup(version)
        with _connect(version) as su, _connect(version, ADMIN, ADMIN_PASSWORD) as conn:
            _ps1(conn, seen)
            _ps2(conn, su, seen)
            _ps3(conn, su, seen)
            _ps4(conn, seen)
        return _leaks(seen, values)
    finally:
        _clean(version)


def main() -> int:
    failed = 0
    for version in VERSIONS:
        try:
            if probe(version):
                failed += 1
        except (psycopg.Error, RuntimeError) as error:
            failed += 1
            print(f"PostgreSQL {version}: FAILED: {error}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
