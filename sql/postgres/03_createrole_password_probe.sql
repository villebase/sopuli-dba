--------------------------------------------------------------------------------
-- sopuli-dba : what a CREATEROLE role needs to change another role's password
--
-- #1032. The tool account is never a superuser. It has CREATEROLE, and from
-- PostgreSQL 16 the documentation says CREATEROLE also needs ADMIN OPTION on
-- the role. This measures what each release requires, and whether the catalog
-- shows the answer before the change is tried. Each case reads, for the
-- CREATEROLE role and each target: rolcreaterole, the target's rolsuper, the
-- admin_option of pg_auth_members, and pg_has_role(..., 'USAGE WITH ADMIN
-- OPTION'). Then, after SET ROLE, it sends ALTER ROLE ... PASSWORD with a
-- verifier:
--
--   CR1  CREATEROLE, and no membership in the target
--   CR2  CREATEROLE, and ADMIN OPTION on the target. From 16 the grant is
--        WITH ADMIN OPTION, INHERIT FALSE, SET FALSE, which gives the CREATEROLE
--        role none of the target's privileges
--   CR3  ADMIN OPTION on the target, without CREATEROLE
--   CR4  CREATEROLE and ADMIN OPTION, and the target a superuser
--   CR5  a role that the CREATEROLE role created itself
--
-- psql runs with VERBOSITY verbose, so each error shows its SQLSTATE.
--
-- This MEASURES and decides nothing.
--
-- STATUS: run on 13.23, 14.24, 15.19, 16.15, 17.11 and 18.6, the postgres:13
-- to postgres:18 images of test/compose.yaml profile postgres-matrix, as the
-- superuser postgres, on 2026-10-25 (#1032). Twice on each release, exit 0,
-- and the same result every time.
--
-- RESULTS
--
--   CR1  13.23, 14.24, 15.19: accepted. 16.15, 17.11, 18.6: refused, 42501
--        "permission denied to alter role", DETAIL "To change another role's
--        password, the current user must have the CREATEROLE attribute and
--        the ADMIN option on the role."
--   CR2  accepted on all six. On 16.15 to 18.6 with INHERIT FALSE, SET FALSE
--   CR3  refused on all six, 42501. 13.23 to 15.19 say "permission denied",
--        16.15 to 18.6 the CR1 message
--   CR4  refused on all six, 42501. 13.23 says "must be superuser to alter
--        superusers", 14.24 and 15.19 "must be superuser to alter superuser
--        roles or change superuser attribute", 16.15 to 18.6 "permission
--        denied to alter role" with DETAIL "Only roles with the SUPERUSER
--        attribute may alter roles with the SUPERUSER attribute."
--   CR5  accepted on all six. 13.23 to 15.19 add no pg_auth_members row for
--        the creator. 16.15 to 18.6 add one with admin_option true, granted
--        by the bootstrap superuser postgres
--
--   In every case, the admin_option column and pg_has_role(..., 'USAGE WITH
--   ADMIN OPTION') agree, also with INHERIT FALSE and SET FALSE. So the
--   catalog answers the question without trying the change: CREATEROLE, a
--   target that is not a superuser, and, from 16, ADMIN OPTION on the target.
--   CREATEROLE with ADMIN OPTION is accepted on every release measured.
--
-- HOW TO RUN, against the matrix (test/README.md):
--
--     docker exec -i sopuli-test-postgres-16-1 psql -U postgres -d sopuli -X \
--         < sql/postgres/03_createrole_password_probe.sql
--
-- THROWAWAY SERVERS ONLY. Creates and drops five roles, one of them a
-- superuser.
--------------------------------------------------------------------------------
\set ON_ERROR_STOP 1
\set VERBOSITY verbose
\pset footer off

SELECT current_setting('server_version') AS server_version,
       current_setting('server_version_num')::int >= 160000 AS pg16 \gset
\echo server_version :server_version
\echo pg16 :pg16

-- ------------------------------------------------------------------ setup --
DROP ROLE IF EXISTS sopuli_probe_app;
DROP ROLE IF EXISTS sopuli_probe_super;
DROP ROLE IF EXISTS sopuli_probe_own;
DROP ROLE IF EXISTS sopuli_probe_admin;
DROP ROLE IF EXISTS sopuli_probe_seed;

-- A verifier to send, computed by the server from a password no measured
-- statement carries.
SET password_encryption = 'scram-sha-256';
CREATE ROLE sopuli_probe_seed PASSWORD 'PwSeedMarker7q';
SELECT rolpassword AS verifier FROM pg_authid WHERE rolname = 'sopuli_probe_seed' \gset

CREATE ROLE sopuli_probe_admin CREATEROLE;
CREATE ROLE sopuli_probe_app LOGIN;
CREATE ROLE sopuli_probe_super SUPERUSER;

-- What the tool would read before it tries: its own CREATEROLE, the target's
-- SUPERUSER, and its ADMIN OPTION on the target, two ways.
CREATE VIEW pg_temp.sopuli_probe_read AS
SELECT t.rolname AS target,
       a.rolcreaterole AS createrole,
       t.rolsuper AS target_super,
       EXISTS (SELECT 1 FROM pg_auth_members m
                WHERE m.roleid = t.oid AND m.member = a.oid AND m.admin_option) AS admin_option,
       pg_has_role(a.rolname, t.rolname, 'USAGE WITH ADMIN OPTION') AS has_role_admin
  FROM pg_roles a, pg_roles t
 WHERE a.rolname = 'sopuli_probe_admin'
   AND t.rolname IN ('sopuli_probe_app', 'sopuli_probe_super')
 ORDER BY t.rolname;

-- ---------------------------------------------------------------- CR1 --
\echo CR1 CREATEROLE, no membership in the target:
SELECT * FROM pg_temp.sopuli_probe_read;
SET ROLE sopuli_probe_admin;
\set ON_ERROR_STOP 0
ALTER ROLE sopuli_probe_app PASSWORD :'verifier';
\set ON_ERROR_STOP 1
RESET ROLE;

-- ---------------------------------------------------------------- CR2 --
\echo CR2 CREATEROLE, and ADMIN OPTION on the target. From 16, with INHERIT FALSE and SET FALSE:
\if :pg16
GRANT sopuli_probe_app TO sopuli_probe_admin WITH ADMIN OPTION, INHERIT FALSE, SET FALSE;
\else
GRANT sopuli_probe_app TO sopuli_probe_admin WITH ADMIN OPTION;
\endif
SELECT * FROM pg_temp.sopuli_probe_read;
SET ROLE sopuli_probe_admin;
\set ON_ERROR_STOP 0
ALTER ROLE sopuli_probe_app PASSWORD :'verifier';
\set ON_ERROR_STOP 1
RESET ROLE;

-- ---------------------------------------------------------------- CR3 --
\echo CR3 ADMIN OPTION on the target, CREATEROLE taken away:
ALTER ROLE sopuli_probe_admin NOCREATEROLE;
SELECT * FROM pg_temp.sopuli_probe_read;
SET ROLE sopuli_probe_admin;
\set ON_ERROR_STOP 0
ALTER ROLE sopuli_probe_app PASSWORD :'verifier';
\set ON_ERROR_STOP 1
RESET ROLE;
ALTER ROLE sopuli_probe_admin CREATEROLE;

-- ---------------------------------------------------------------- CR4 --
\echo CR4 CREATEROLE and ADMIN OPTION, the target a superuser:
GRANT sopuli_probe_super TO sopuli_probe_admin WITH ADMIN OPTION;
SELECT * FROM pg_temp.sopuli_probe_read;
SET ROLE sopuli_probe_admin;
\set ON_ERROR_STOP 0
ALTER ROLE sopuli_probe_super PASSWORD :'verifier';
\set ON_ERROR_STOP 1
RESET ROLE;

-- ---------------------------------------------------------------- CR5 --
\echo CR5 a role the CREATEROLE role created itself:
SET ROLE sopuli_probe_admin;
CREATE ROLE sopuli_probe_own LOGIN;
RESET ROLE;
SELECT m.admin_option, m.grantor::regrole AS grantor
  FROM pg_auth_members m
 WHERE m.roleid = 'sopuli_probe_own'::regrole AND m.member = 'sopuli_probe_admin'::regrole;
SET ROLE sopuli_probe_admin;
\set ON_ERROR_STOP 0
ALTER ROLE sopuli_probe_own PASSWORD :'verifier';
\set ON_ERROR_STOP 1
RESET ROLE;

-- ---------------------------------------------------------------- cleanup --
DROP ROLE sopuli_probe_own;
DROP ROLE sopuli_probe_app;
DROP ROLE sopuli_probe_super;
DROP ROLE sopuli_probe_admin;
DROP ROLE sopuli_probe_seed;
