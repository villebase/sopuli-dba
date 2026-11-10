"""sopuli-dba : what the UC-5 report commands can read on PostgreSQL

#1443. The `report` commands read every role on a target (UC-5 §2). The tool
account is LOGIN CREATEROLE and nothing else (02-postgres-privileges.md §2.1).
This measures, on each server, as that account unless a step says otherwise:

  PR0  which of pg_roles's columns it reads, every one the catalog lists,
       whether rolpassword reads as the mask ******** there for a role with a
       password and for one without, and whether pg_authid refuses it
  PR1  which pg_catalog columns could hold an account's lock, expiry, last
       password change, last login or failed logins: a column of a role
       catalog whose name contains passw, login, fail, valid, lock, expir,
       time or date, and a column of any pg_catalog relation whose name
       contains passw, login, auth or session. It prints the names, never a
       value
  PR2  pg_auth_members's columns, and whether a recursive query over it gives
       each fixture role's roles with the path, as pg_has_role() does: MEMBER
       for every membership, and USAGE where at least one path is inherited.
       Inheritance is pg_auth_members.inherit_option where the column
       exists, and the member's rolinherit where it does not. The setup also
       says whether the server accepted GRANT ... WITH INHERIT FALSE
  PR3  the ACLs of pg_database, pg_namespace, pg_class, pg_proc and
       pg_default_acl through aclexplode(), which fixture grants each shows,
       and whether a grant made in a second database can be seen from the
       first, by ACL or by has_table_privilege(). Then has_table_privilege()
       on a table the tool account has no USAGE on its schema for, by name
       and by oid, for an inheriting, a NOINHERIT and an INHERIT FALSE member.
       Then a function left with its default ACL: what aclexplode() gives for
       its NULL proacl, and what it gives for acldefault('f', owner), with
       PUBLIC, grantee 0, which has no pg_roles row. Then the other catalogs
       that carry an ACL: pg_attribute, pg_language, pg_type,
       pg_largeobject_metadata, pg_foreign_data_wrapper, pg_foreign_server,
       pg_tablespace and pg_parameter_acl, with a column grant and a language
       grant in the fixture
  PR5  the time of PR2's query over every role, and of has_table_privilege()
       over every role and table, after the superuser adds 500 roles in
       chains of five and 1000 tables, each granted to one role. Each query
       runs once untimed, then three times timed

PR4, the date of a role's last password change for `report history`, is
PR1's answer: a column for it would be one PR1 lists.

The fixture, which the superuser creates on each server:

  sopuli_probe_admin  LOGIN CREATEROLE, the tool account
  sopuli_probe_app    LOGIN VALID UNTIL 2100-01-01, a member of
                      sopuli_probe_mid
  sopuli_probe_old    LOGIN VALID UNTIL 2000-01-01
  sopuli_probe_off    NOLOGIN
  sopuli_probe_mid    NOLOGIN, a member of sopuli_probe_top and of
                      pg_read_all_settings
  sopuli_probe_top    NOLOGIN, granted SELECT on sopuli_probe.t
  sopuli_probe_noinh  LOGIN NOINHERIT, a member of sopuli_probe_top
  sopuli_probe_set    LOGIN, a member of sopuli_probe_top, granted WITH
                      INHERIT FALSE; where the server refuses the clause, the
                      probe says so and grants without it
  sopuli_probe_two    LOGIN, a member of sopuli_probe_mid, and of
                      sopuli_probe_top directly as sopuli_probe_set is: two
                      paths to sopuli_probe_top
  schema sopuli_probe, table t, function f() granted to sopuli_probe_app
  alone, function g() left with its default ACL, and default privileges for
  sopuli_probe_top on the schema's tables. SELECT on column t.n and USAGE on
  language sql, granted to sopuli_probe_app
  database sopuli_probe_db2, with a table t2 granted to sopuli_probe_app

It MEASURES and decides nothing. It selects no verifier: rolpassword is
compared to the mask on the server, and only true or false comes back.

STATUS: run on 13.23, 14.24, 15.19, 16.15, 17.11 and 18.6, the postgres:13 to
postgres:18 images of test/compose.yaml profile postgres-matrix, on 2026-11-10
(#1443). The client was psycopg 3.3.6 with libpq 18.4, on Windows 11 AMD64.
Twice, exit 0, the same result both times but for the timings, which are the
ranges below. Earlier versions of the probe are not counted: they did not
send WITH INHERIT FALSE to 13 to 15, had no two-path member, no g(), no role
without a password and no other ACL catalogs, and timed each query once,
cold.

RESULTS

  PR0  pg_roles has 13 columns, and the tool account reads all 13: rolname,
       the attributes, rolconnlimit, rolpassword, rolvaliduntil, rolconfig
       and oid. rolpassword reads as the mask ******** for a role with a
       password and for one without, so it says nothing about whether a role
       has one. pg_authid refuses it: 42501, "permission denied for table
       pg_authid". rolcanlogin and rolvaliduntil read as each fixture role
       was created
  PR1  no column holds an account's last password change, last login or
       failed logins, on any release. The role catalogs have rolcanlogin,
       rolvaliduntil and the password column alone. pg_stat_database counts
       sessions, sessions_fatal and the like from 14, per database and not
       per role. 17 adds pg_database.dathasloginevt, which says only that a
       login event trigger exists
  PR2  13 to 15 refuse GRANT ... WITH INHERIT FALSE: 42601, "syntax error at
       or near "INHERIT"". 16 to 18 accept it. pg_auth_members has roleid,
       member, grantor and admin_option on 13 to 15, and 16 adds oid,
       inherit_option and set_option. The recursive query gives 11 paths and
       10 role pairs for the fixture roles. On 16 to 18 the WITH INHERIT FALSE
       grants are not inherited; on 13 to 15 they were made without the
       clause, and are. Each pair agrees with pg_has_role(): MEMBER for every
       pair, and USAGE where one of its paths is inherited. sopuli_probe_two
       reaches sopuli_probe_top by an inherited path through sopuli_probe_mid
       and, on 16 to 18, a direct path that is not, and pg_has_role USAGE is
       true. pg_has_role knows no membership the query misses. A NOINHERIT
       member is a MEMBER without USAGE on every release
  PR3  the tool account reads every ACL of the five catalogs: USAGE on the
       schema, SELECT on t, EXECUTE on f() and the default SELECT on tables
       for sopuli_probe_top. pg_database shows no fixture grant, as none was
       made. Nothing of sopuli_probe_db2 is visible from postgres: no
       pg_class row, and has_table_privilege() on its table is refused,
       0A000, "cross-database references are not implemented".
       has_table_privilege() on sopuli_probe.t by name is refused, 42501,
       "permission denied for schema sopuli_probe", because the name is
       resolved with the tool account's own rights. By oid it answers: true
       for the inheriting member, false for the NOINHERIT one, and for
       sopuli_probe_set false on 16 to 18 and true on 13 to 15. g()'s proacl
       is NULL, and aclexplode() of it gives no row.
       aclexplode(acldefault('f', owner)) gives PUBLIC EXECUTE and the
       owner's EXECUTE. PUBLIC is grantee 0, and pg_roles has no row for it.
       The tool account reads the ACLs of pg_attribute, with the column grant
       on t.n, pg_language, with the grant on sql, pg_type,
       pg_largeobject_metadata, pg_foreign_data_wrapper, pg_foreign_server
       and pg_tablespace. pg_parameter_acl exists from 15, and it reads it;
       13 and 14 have none: 42P01, "relation "pg_parameter_acl" does not
       exist"
  PR5  about 520 roles, 1014 membership paths: the recursive query takes
       0.01 s. has_table_privilege() over every role and the 1001 tables of
       the schema takes 0.16 to 0.42 s, and 1.73 to 1.96 s on 13.23, in
       both runs, after the untimed run. 9006 pairs are true, and 10007 on
       14 and 15: the bulk tables take the fixture's default SELECT for
       sopuli_probe_top, so pg_read_all_data
       holds 1001 of them from 14, and sopuli_probe_set holds 1001 where its
       grant is inherited, on 13 to 15

  So a target, which is one database, can read every role, its login and
  expiry, and its memberships with the path, as the tool account holds them
  today. It can read the ACLs of the thirteen catalogs above, but only in the
  database it connects to, and an object with its default privileges has a
  NULL ACL, which only acldefault() expands. It can read no last password
  change, last login or failed logins, and not whether a role has a password.

HOW TO RUN, against the matrix (test/README.md), from the repo root, with the
repo's virtual environment:

    .venv/Scripts/python sql/postgres/10_report_read_probe.py

The ports follow SOPULI_TEST_POSTGRES13_PORT to SOPULI_TEST_POSTGRES18_PORT,
so a second clone's matrix is the one it uses.

THROWAWAY SERVERS ONLY. It creates the roles above, sopuli_probe_r0 to
sopuli_probe_r499, the schema sopuli_probe with 1000 tables, and the database
sopuli_probe_db2, and drops them at the end. Before it starts, it drops what an
interrupted run left.
"""

from __future__ import annotations

import os
import sys
import time
from typing import Any

import psycopg
from psycopg import sql

VERSIONS = (13, 14, 15, 16, 17, 18)
#: Tier 0's public test password, from test/compose.yaml.
SUPERUSER_PASSWORD = "sopuli-test"
#: The tool account's password. A marker on a throwaway server.
ADMIN_PASSWORD = "sopuli-probe-admin"
ADMIN = "sopuli_probe_admin"
FIXTURE = (
    "sopuli_probe_app",
    "sopuli_probe_old",
    "sopuli_probe_off",
    "sopuli_probe_mid",
    "sopuli_probe_top",
    "sopuli_probe_noinh",
    "sopuli_probe_set",
    "sopuli_probe_two",
)
SCHEMA = "sopuli_probe"
DB2 = "sopuli_probe_db2"
BULK_ROLES = 500
BULK_TABLES = 1000
CHAIN = 5

#: PR2. Every role a role is a member of, directly or through others, with
#: the path and whether every step of it is inherited. `{inherit}` is the
#: expression that says whether one membership row is inherited.
MEMBERSHIP_QUERY = """
WITH RECURSIVE m(member, roleid, path, inherited) AS (
    SELECT a.member, a.roleid,
           ARRAY[r.rolname::text, g.rolname::text],
           {inherit}
      FROM pg_auth_members a
      JOIN pg_roles r ON r.oid = a.member
      JOIN pg_roles g ON g.oid = a.roleid
    UNION ALL
    SELECT m.member, a.roleid,
           m.path || g.rolname::text,
           m.inherited AND {inherit}
      FROM m
      JOIN pg_auth_members a ON a.member = m.roleid
      JOIN pg_roles r ON r.oid = a.member
      JOIN pg_roles g ON g.oid = a.roleid
     WHERE NOT g.rolname::text = ANY (m.path)
)
SELECT r.rolname::text, g.rolname::text, m.path, m.inherited
  FROM m
  JOIN pg_roles r ON r.oid = m.member
  JOIN pg_roles g ON g.oid = m.roleid
"""
INHERIT_BY_OPTION = "a.inherit_option"
INHERIT_BY_MEMBER = "r.rolinherit"


def _port(version: int) -> str:
    return os.environ.get(f"SOPULI_TEST_POSTGRES{version}_PORT", f"54{version}")


def _connect(
    version: int,
    user: str = "postgres",
    password: str = SUPERUSER_PASSWORD,
    dbname: str = "postgres",
) -> psycopg.Connection[Any]:
    """The superuser by default, or the tool account."""
    return psycopg.connect(
        host="127.0.0.1",
        port=_port(version),
        user=user,
        password=password,
        dbname=dbname,
        autocommit=True,
        connect_timeout=10,
    )


def _one(conn: psycopg.Connection[Any], query: Any, params: Any = None) -> Any:
    """The first column of the one row a query returns."""
    row = conn.execute(query, params).fetchone()
    if row is None:
        raise RuntimeError(f"no row from: {query}")
    return row[0]


def _has_column(conn: psycopg.Connection[Any], relation: str, column: str) -> bool:
    return bool(
        _one(
            conn,
            "SELECT count(*) FROM pg_attribute WHERE attrelid = %s::regclass AND attname = %s"
            " AND NOT attisdropped",
            (relation, column),
        )
    )


def _inherit(conn: psycopg.Connection[Any]) -> str:
    """Where a membership's inheritance is read: the grant's option, where the
    catalog has one, or the member's attribute."""
    return (
        INHERIT_BY_OPTION
        if _has_column(conn, "pg_auth_members", "inherit_option")
        else INHERIT_BY_MEMBER
    )


def _all_roles() -> list[str]:
    return [ADMIN, *FIXTURE, *(f"sopuli_probe_r{n}" for n in range(BULK_ROLES))]


def _clean(version: int) -> None:
    """Drop what this probe creates, whatever an earlier run left."""
    with _connect(version) as su:
        su.execute(sql.SQL("DROP DATABASE IF EXISTS {}").format(sql.Identifier(DB2)))
        su.execute(sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(sql.Identifier(SCHEMA)))
        found = [
            row[0]
            for row in su.execute(
                "SELECT rolname::text FROM pg_roles WHERE rolname = ANY(%s)", (_all_roles(),)
            ).fetchall()
        ]
        if found:
            names = sql.SQL(", ").join(sql.Identifier(role) for role in found)
            su.execute(sql.SQL("DROP OWNED BY {}").format(names))
            su.execute(sql.SQL("DROP ROLE {}").format(names))


def _grant_without_inherit(su: psycopg.Connection[Any], member: str) -> None:
    """GRANT sopuli_probe_top WITH INHERIT FALSE, or without the clause where
    the server refuses it, and say which."""
    try:
        su.execute(f"GRANT sopuli_probe_top TO {member} WITH INHERIT FALSE")
        print(f"  PR2  GRANT ... TO {member} WITH INHERIT FALSE: accepted")
    except psycopg.Error as error:
        print(
            f"  PR2  GRANT ... TO {member} WITH INHERIT FALSE:"
            f" {error.sqlstate} {error.diag.message_primary}; granted without it"
        )
        su.execute(f"GRANT sopuli_probe_top TO {member}")


def _setup(version: int) -> None:
    with _connect(version) as su:
        statements = [
            f"CREATE ROLE {ADMIN} LOGIN CREATEROLE PASSWORD '{ADMIN_PASSWORD}'",
            "CREATE ROLE sopuli_probe_top NOLOGIN",
            "CREATE ROLE sopuli_probe_mid NOLOGIN",
            "CREATE ROLE sopuli_probe_app LOGIN VALID UNTIL '2100-01-01'",
            "CREATE ROLE sopuli_probe_old LOGIN VALID UNTIL '2000-01-01'",
            "CREATE ROLE sopuli_probe_off NOLOGIN",
            "CREATE ROLE sopuli_probe_noinh LOGIN NOINHERIT",
            "CREATE ROLE sopuli_probe_set LOGIN",
            "CREATE ROLE sopuli_probe_two LOGIN",
            "GRANT sopuli_probe_top TO sopuli_probe_mid",
            "GRANT pg_read_all_settings TO sopuli_probe_mid",
            "GRANT sopuli_probe_mid TO sopuli_probe_app",
            "GRANT sopuli_probe_mid TO sopuli_probe_two",
            "GRANT sopuli_probe_top TO sopuli_probe_noinh",
            f"CREATE SCHEMA {SCHEMA}",
            f"CREATE TABLE {SCHEMA}.t (n int)",
            f"GRANT USAGE ON SCHEMA {SCHEMA} TO sopuli_probe_top",
            f"GRANT SELECT ON {SCHEMA}.t TO sopuli_probe_top",
            f"CREATE FUNCTION {SCHEMA}.f() RETURNS int LANGUAGE sql AS 'SELECT 1'",
            f"REVOKE EXECUTE ON FUNCTION {SCHEMA}.f() FROM PUBLIC",
            f"GRANT EXECUTE ON FUNCTION {SCHEMA}.f() TO sopuli_probe_app",
            f"GRANT SELECT (n) ON {SCHEMA}.t TO sopuli_probe_app",
            "GRANT USAGE ON LANGUAGE sql TO sopuli_probe_app",
            f"CREATE FUNCTION {SCHEMA}.g() RETURNS int LANGUAGE sql AS 'SELECT 1'",
            f"ALTER DEFAULT PRIVILEGES IN SCHEMA {SCHEMA} GRANT SELECT ON TABLES"
            " TO sopuli_probe_top",
            f"CREATE DATABASE {DB2}",
        ]
        for statement in statements:
            su.execute(statement)
        _grant_without_inherit(su, "sopuli_probe_set")
        _grant_without_inherit(su, "sopuli_probe_two")
    with _connect(version, dbname=DB2) as su2:
        su2.execute("CREATE TABLE t2 (n int)")
        su2.execute("GRANT SELECT ON t2 TO sopuli_probe_app")


def _bulk(version: int) -> None:
    """PR5's estate: chains of five roles, and tables each granted to one."""
    with _connect(version) as su, su.transaction():
        for n in range(BULK_ROLES):
            su.execute(sql.SQL("CREATE ROLE {} NOLOGIN").format(_bulk_role(n)))
            if n % CHAIN:
                su.execute(sql.SQL("GRANT {} TO {}").format(_bulk_role(n), _bulk_role(n - 1)))
        for n in range(BULK_TABLES):
            table = sql.Identifier(SCHEMA, f"b{n}")
            su.execute(sql.SQL("CREATE TABLE {} (n int)").format(table))
            su.execute(
                sql.SQL("GRANT SELECT ON {} TO {}").format(table, _bulk_role(n % BULK_ROLES))
            )


def _bulk_role(n: int) -> sql.Identifier:
    return sql.Identifier(f"sopuli_probe_r{n}")


def _pr0(conn: psycopg.Connection[Any]) -> None:
    columns = [
        row[0]
        for row in conn.execute(
            "SELECT attname::text FROM pg_attribute WHERE attrelid = 'pg_roles'::regclass"
            " AND attnum > 0 AND NOT attisdropped ORDER BY attnum"
        ).fetchall()
    ]
    refused = []
    for column in columns:
        try:
            conn.execute(sql.SQL("SELECT {} FROM pg_roles LIMIT 1").format(sql.Identifier(column)))
        except psycopg.Error as error:
            refused.append(column)
            print(f"  PR0  pg_roles.{column}: {error.sqlstate} {error.diag.message_primary}")
    print(
        f"  PR0  pg_roles columns: {len(columns)}, read {len(columns) - len(refused)}:"
        f" {', '.join(columns)}"
    )
    # The tool account has a password; sopuli_probe_off was created without one.
    for role in (ADMIN, "sopuli_probe_off"):
        masked = _one(
            conn, "SELECT rolpassword = '********' FROM pg_roles WHERE rolname = %s", (role,)
        )
        print(f"  PR0  pg_roles.rolpassword is the mask for {role}: {masked}")
    try:
        conn.execute("SELECT rolname FROM pg_authid LIMIT 1")
        print("  PR0  pg_authid: READ")
    except psycopg.Error as error:
        print(f"  PR0  pg_authid: {error.sqlstate} {error.diag.message_primary}")
    rows = conn.execute(
        "SELECT rolname, rolcanlogin, rolvaliduntil::text FROM pg_roles"
        " WHERE rolname = ANY(%s) ORDER BY rolname",
        (list(FIXTURE[:3]),),
    ).fetchall()
    for name, can_login, valid_until in rows:
        print(f"  PR0  {name}: rolcanlogin={can_login} rolvaliduntil={valid_until}")


def _pr1(conn: psycopg.Connection[Any]) -> None:
    rows = conn.execute(
        """
        SELECT c.relname::text || '.' || a.attname::text
          FROM pg_attribute a
          JOIN pg_class c ON c.oid = a.attrelid
          JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = 'pg_catalog'
           AND c.relkind IN ('r', 'v')
           AND a.attnum > 0 AND NOT a.attisdropped
           AND (
                (c.relname IN ('pg_authid', 'pg_roles', 'pg_shadow', 'pg_user',
                               'pg_auth_members', 'pg_db_role_setting')
                 AND a.attname ~ '(passw|login|fail|valid|lock|expir|time|date)')
                OR a.attname ~ '(passw|login|auth|session)'
           )
         ORDER BY 1
        """
    ).fetchall()
    print(f"  PR1  pg_catalog columns: {', '.join(row[0] for row in rows)}")


def _pr2(conn: psycopg.Connection[Any]) -> None:
    columns = conn.execute(
        "SELECT attname::text FROM pg_attribute WHERE attrelid = 'pg_auth_members'::regclass"
        " AND attnum > 0 AND NOT attisdropped ORDER BY attnum"
    ).fetchall()
    print(f"  PR2  pg_auth_members columns: {', '.join(row[0] for row in columns)}")
    inherit = _inherit(conn)
    print(f"  PR2  inheritance read from: {inherit}")
    rows = conn.execute(
        MEMBERSHIP_QUERY.format(inherit=inherit) + " WHERE r.rolname = ANY(%s) ORDER BY 1, 2, 3",
        (list(FIXTURE),),
    ).fetchall()
    # pg_has_role() answers per role pair. A pair is inherited when any one
    # of its paths is.
    pairs: dict[tuple[str, str], bool] = {}
    for member, role, path, inherited in rows:
        pairs[(member, role)] = pairs.get((member, role), False) or inherited
        print(f"  PR2  {' -> '.join(path)}: inherited={inherited}")
    disagree = []
    for (member, role), inherited in sorted(pairs.items()):
        usage, is_member = conn.execute(
            "SELECT pg_has_role(%s, %s, 'USAGE'), pg_has_role(%s, %s, 'MEMBER')",
            (member, role, member, role),
        ).fetchone() or (None, None)
        if not (is_member and usage == inherited):
            disagree.append((member, role))
        print(
            f"  PR2  pair {member} in {role}: inherited={inherited}"
            f" pg_has_role USAGE={usage} MEMBER={is_member}"
        )
    # The other direction: a membership pg_has_role knows and the query does not.
    known = conn.execute(
        "SELECT r.rolname::text, g.rolname::text FROM pg_roles r CROSS JOIN pg_roles g"
        " WHERE r.rolname = ANY(%s) AND r.oid <> g.oid AND pg_has_role(r.oid, g.oid, 'MEMBER')",
        (list(FIXTURE),),
    ).fetchall()
    missing = [pair for pair in known if pair not in pairs]
    print(
        f"  PR2  {len(rows)} paths, {len(pairs)} pairs, {len(disagree)} disagree with"
        f" pg_has_role {disagree}, {len(missing)} memberships missing {missing}"
    )


def _pr3(conn: psycopg.Connection[Any]) -> None:
    sources = {
        "pg_database": "SELECT datname::text, datacl FROM pg_database",
        "pg_namespace": "SELECT nspname::text, nspacl FROM pg_namespace",
        "pg_class": "SELECT relname::text, relacl FROM pg_class",
        "pg_proc": "SELECT proname::text, proacl FROM pg_proc",
        "pg_default_acl": "SELECT defaclobjtype::text, defaclacl FROM pg_default_acl",
    }
    for name, query in sources.items():
        try:
            rows = conn.execute(
                f"""
                SELECT o.name, g.rolname::text, x.privilege_type, x.is_grantable
                  FROM ({query}) AS o(name, acl)
                  CROSS JOIN LATERAL aclexplode(o.acl) x
                  JOIN pg_roles g ON g.oid = x.grantee
                 WHERE g.rolname LIKE 'sopuli\\_probe\\_%'
                   AND g.rolname NOT LIKE 'sopuli\\_probe\\_r%'
                 ORDER BY 1, 2, 3
                """
            ).fetchall()
            shown = "; ".join(f"{o} {g} {p}{' grantable' if gr else ''}" for o, g, p, gr in rows)
            print(f"  PR3  {name}: {shown or 'no fixture grant'}")
        except psycopg.Error as error:
            print(f"  PR3  {name}: {error.sqlstate} {error.diag.message_primary}")
    visible = _one(conn, "SELECT count(*) FROM pg_class WHERE relname = 't2'")
    print(f"  PR3  from postgres, pg_class rows for {DB2}'s t2: {visible}")
    try:
        conn.execute(f"SELECT has_table_privilege('sopuli_probe_app', '{DB2}.public.t2', 'SELECT')")
        print(f"  PR3  has_table_privilege on {DB2}.public.t2 from postgres: answered")
    except psycopg.Error as error:
        print(
            f"  PR3  has_table_privilege on {DB2}.public.t2 from postgres:"
            f" {error.sqlstate} {error.diag.message_primary}"
        )
    try:
        conn.execute(f"SELECT has_table_privilege('sopuli_probe_app', '{SCHEMA}.t', 'SELECT')")
        print(f"  PR3  has_table_privilege by name {SCHEMA}.t: answered")
    except psycopg.Error as error:
        print(
            f"  PR3  has_table_privilege by name {SCHEMA}.t:"
            f" {error.sqlstate} {error.diag.message_primary}"
        )
    for role in ("sopuli_probe_app", "sopuli_probe_noinh", "sopuli_probe_set"):
        answer = _one(
            conn,
            "SELECT has_table_privilege(%s, c.oid, 'SELECT') FROM pg_class c"
            " JOIN pg_namespace n ON n.oid = c.relnamespace"
            " WHERE n.nspname = %s AND c.relname = 't'",
            (role, SCHEMA),
        )
        print(f"  PR3  has_table_privilege({role}, oid of {SCHEMA}.t, SELECT): {answer}")
    # g() keeps its default ACL, which the catalog stores as NULL.
    acl, stored, defaults = conn.execute(
        """
        SELECT p.proacl IS NULL,
               (SELECT count(*) FROM aclexplode(p.proacl)),
               (SELECT string_agg(e, '; ' ORDER BY e)
                  FROM (SELECT CASE x.grantee WHEN 0 THEN 'PUBLIC'
                                    ELSE (SELECT rolname::text FROM pg_roles
                                           WHERE oid = x.grantee)
                               END || ' ' || x.privilege_type AS e
                          FROM aclexplode(acldefault('f', p.proowner)) x) d)
          FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
         WHERE n.nspname = %s AND p.proname = 'g'
        """,
        (SCHEMA,),
    ).fetchone() or (None, None, None)
    print(
        f"  PR3  g() with its default ACL: proacl is NULL={acl}; aclexplode(proacl) rows"
        f" {stored}; aclexplode(acldefault('f', owner)): {defaults}"
    )
    public = _one(conn, "SELECT count(*) FROM pg_roles WHERE oid = 0")
    print(f"  PR3  pg_roles rows for grantee 0 (PUBLIC): {public}")
    # The other catalogs that carry an ACL. The fixture grants a column and a
    # language; the rest are read for whether the tool account can read them.
    others = {
        "pg_attribute": "SELECT attrelid::regclass::text || '.' || attname::text, attacl"
        " FROM pg_attribute WHERE attacl IS NOT NULL",
        "pg_language": "SELECT lanname::text, lanacl FROM pg_language",
        "pg_type": "SELECT typname::text, typacl FROM pg_type",
        "pg_largeobject_metadata": "SELECT oid::text, lomacl FROM pg_largeobject_metadata",
        "pg_foreign_data_wrapper": "SELECT fdwname::text, fdwacl FROM pg_foreign_data_wrapper",
        "pg_foreign_server": "SELECT srvname::text, srvacl FROM pg_foreign_server",
        "pg_tablespace": "SELECT spcname::text, spcacl FROM pg_tablespace",
        "pg_parameter_acl": "SELECT parname::text, paracl FROM pg_parameter_acl",
    }
    for name, query in others.items():
        try:
            rows = conn.execute(
                f"""
                SELECT o.name, g.rolname::text, x.privilege_type
                  FROM ({query}) AS o(name, acl)
                  CROSS JOIN LATERAL aclexplode(o.acl) x
                  JOIN pg_roles g ON g.oid = x.grantee
                 WHERE g.rolname LIKE 'sopuli\\_probe\\_%'
                 ORDER BY 1, 2, 3
                """
            ).fetchall()
            shown = "; ".join(f"{o} {g} {p}" for o, g, p in rows)
            print(f"  PR3  {name}: read; {shown or 'no fixture grant'}")
        except psycopg.Error as error:
            print(f"  PR3  {name}: {error.sqlstate} {error.diag.message_primary}")


def _pr5(conn: psycopg.Connection[Any]) -> None:
    inherit = _inherit(conn)
    roles = _one(conn, "SELECT count(*) FROM pg_roles")
    tables = _one(
        conn,
        "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace"
        " WHERE n.nspname = %s AND c.relkind = 'r'",
        (SCHEMA,),
    )
    privilege_query = """
        SELECT count(*)
          FROM pg_roles r
          CROSS JOIN pg_class c
          JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = %s AND c.relkind = 'r'
           AND has_table_privilege(r.oid, c.oid, 'SELECT')
    """
    # One untimed run of each warms the caches the bulk DDL left cold; then
    # three timed runs, of which the smallest and largest are printed.
    paths = conn.execute(MEMBERSHIP_QUERY.format(inherit=inherit)).fetchall()
    granted = _one(conn, privilege_query, (SCHEMA,))
    membership, privilege = [], []
    for _ in range(3):
        started = time.perf_counter()
        conn.execute(MEMBERSHIP_QUERY.format(inherit=inherit)).fetchall()
        membership.append(time.perf_counter() - started)
        started = time.perf_counter()
        _one(conn, privilege_query, (SCHEMA,))
        privilege.append(time.perf_counter() - started)
    print(
        f"  PR5  {roles} roles: membership query {len(paths)} paths in"
        f" {min(membership):.2f} to {max(membership):.2f} s; has_table_privilege over"
        f" {roles} roles x {tables} tables, {granted} true, in"
        f" {min(privilege):.2f} to {max(privilege):.2f} s"
    )


def probe(version: int) -> None:
    with _connect(version) as su:
        release = _one(su, "SHOW server_version")
    print(f"PostgreSQL {release} (port {_port(version)})")
    _clean(version)
    try:
        _setup(version)
        with _connect(version, ADMIN, ADMIN_PASSWORD) as conn:
            _pr0(conn)
            _pr1(conn)
            _pr2(conn)
            _pr3(conn)
        _bulk(version)
        with _connect(version, ADMIN, ADMIN_PASSWORD) as conn:
            _pr5(conn)
    finally:
        _clean(version)


def main() -> int:
    failed = 0
    for version in VERSIONS:
        try:
            probe(version)
        except (psycopg.Error, RuntimeError) as error:
            failed += 1
            print(f"PostgreSQL {version}: FAILED: {error}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
