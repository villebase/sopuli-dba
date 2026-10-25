--------------------------------------------------------------------------------
-- sopuli-dba : can a role with no grants read the cluster's system_identifier?
--
-- #1032. Two targets that are one cluster are to be refused, and the identity
-- of a cluster is the system_identifier of pg_control_system(). The tool
-- account is never a superuser. This measures whether a role with no grants
-- and no membership can read it:
--
--   SI1  the ACL on pg_control_system() in pg_proc. NULL is the default for a
--        function, which is EXECUTE for PUBLIC
--   SI2  has_function_privilege() for the role, then the read itself, after
--        SET ROLE to it
--
-- This MEASURES and decides nothing.
--
-- STATUS: run on 13.23, 14.24, 15.19, 16.15, 17.11 and 18.6, the postgres:13
-- to postgres:18 images of test/compose.yaml profile postgres-matrix, as the
-- superuser postgres, on 2026-10-25 (#1032). Once on each release from a new
-- data directory, exit 0. An earlier version of the file granted and revoked
-- EXECUTE on 13.23, 16.15 and 18.6, which left an explicit ACL. Those three
-- were then started from new data directories, and the earlier runs are not
-- counted.
--
-- RESULTS -- the same on all six releases
--
--   SI1  the ACL is NULL, the default
--   SI2  has_function_privilege() is true, and the role reads system_identifier
--
--   So no grant and no pg_monitor membership is needed. A site that revoked
--   EXECUTE from PUBLIC is not measured here.
--
-- HOW TO RUN, against the matrix (test/README.md):
--
--     docker exec -i sopuli-test-postgres-16-1 psql -U postgres -d sopuli -X \
--         < sql/postgres/02_system_identifier_probe.sql
--
-- THROWAWAY SERVERS ONLY. Creates and drops one role.
--------------------------------------------------------------------------------
\set ON_ERROR_STOP 1
\pset footer off

SELECT current_setting('server_version') AS server_version;

DROP ROLE IF EXISTS sopuli_probe_plain;
CREATE ROLE sopuli_probe_plain;

\echo SI1 the ACL on pg_control_system, as the catalog holds it. NULL is the default:
SELECT proacl IS NULL AS default_acl, proacl
  FROM pg_proc WHERE oid = 'pg_control_system()'::regprocedure;

\echo SI2 a role with no grants and no membership:
SELECT has_function_privilege('sopuli_probe_plain', 'pg_control_system()', 'EXECUTE') AS can_execute;
SET ROLE sopuli_probe_plain;
\set ON_ERROR_STOP 0
SELECT current_user, system_identifier IS NOT NULL AS read FROM pg_control_system();
\set ON_ERROR_STOP 1
RESET ROLE;

DROP ROLE sopuli_probe_plain;
