--------------------------------------------------------------------------------
-- sopuli-dba : which roles a Supabase database lets the tool change
--
-- #1111. On Supabase, `postgres` is not a superuser, and the supautils library
-- refuses a change to a role in supautils.reserved_roles by anyone but a
-- superuser. Guardrail check 8 reads that setting. This measures, on the
-- database a Supabase project runs:
--
--   SR1  every role with an oid of 16384 or more, every superuser, and their
--        attributes
--   SR2  supautils.reserved_roles and supautils.reserved_memberships, read by
--        a tool account that holds only LOGIN and CREATEROLE
--   SR3  ALTER ROLE ... PASSWORD on each role with an oid of 16384 or more,
--        as postgres
--   SR4  the same, as the tool account, which postgres created, and on a role
--        the tool account created
--   SR5  postgres grants the tool account pg_read_all_data, then the reserved
--        role authenticator
--
-- Each ALTER ROLE runs in a PL/pgSQL block that raises an error of its own
-- after an accepted change, so every change is rolled back, an accepted one
-- included. Each NOTICE names the session's user and the role, then says
-- "accepted", or gives the SQLSTATE and the message. The password is a
-- marker, sent as plaintext: this is a throwaway server.
--
-- This MEASURES and decides nothing.
--
-- STATUS: run on 17.6, the supabase/postgres:17.6.1.095 image of
-- test/compose.yaml profile supabase, on 2026-10-28 (#1111). Twice, exit 0,
-- and the same result both times.
--
-- RESULTS
--
--   SR1  14 roles. One superuser, supabase_admin, with an oid below 16384.
--        postgres has LOGIN, CREATEROLE, REPLICATION and BYPASSRLS.
--        dashboard_user, supabase_auth_admin and supabase_storage_admin have
--        CREATEROLE. The image alone has no supabase_functions_admin and no
--        supabase_realtime_admin: the Supabase CLI's full stack has more roles,
--        which its other services' migrations create
--   SR2  the tool account reads both. reserved_roles is
--          supabase_admin, supabase_auth_admin, supabase_storage_admin,
--          supabase_read_only_user, supabase_realtime_admin,
--          supabase_replication_admin, supabase_etl_admin, dashboard_user,
--          pgbouncer, service_role*, authenticator*, authenticated*, anon*
--        and reserved_memberships is
--          pg_read_server_files, pg_write_server_files,
--          pg_execute_server_program, supabase_admin, supabase_auth_admin,
--          supabase_storage_admin, supabase_read_only_user,
--          supabase_realtime_admin, supabase_replication_admin,
--          supabase_etl_admin, dashboard_user, pgbouncer, authenticator
--   SR3  refused, 42501, on every role. On each role in reserved_roles:
--        ""<role>" is a reserved role, only superusers can modify it". On
--        postgres and supabase_privileged_role, which are not in it:
--        "permission denied to alter role"
--   SR4  as SR3, the same message on each role. The role the tool account
--        created: accepted
--   SR5  pg_read_all_data: granted. authenticator: refused, 42501
--        ""authenticator" role memberships are reserved, only superusers can
--        grant them"
--
-- HOW TO RUN, against the stack (test/README.md):
--
--     docker exec -i -e PGPASSWORD=sopuli-test sopuli-test-supabase-1 \
--         psql -h localhost -U postgres -d postgres -X \
--         < sql/postgres/09_supabase_roles_probe.sql
--
-- THROWAWAY SERVERS ONLY. Creates and drops two roles, and grants one of them
-- pg_read_all_data. The tool account's password is the stack's, so that
-- \connect finds it in PGPASSWORD. A run stopped before the cleanup leaves the
-- two roles, and the next run drops them.
--------------------------------------------------------------------------------
\set ON_ERROR_STOP 1
\set VERBOSITY verbose
\pset footer off

SELECT current_setting('server_version') AS server_version \gset
\echo server_version :server_version

-- ------------------------------------------------------------------ setup --
DROP ROLE IF EXISTS sopuli_probe_own;
DROP ROLE IF EXISTS sopuli_probe_tool;
CREATE ROLE sopuli_probe_tool LOGIN CREATEROLE PASSWORD 'sopuli-test';

-- ---------------------------------------------------------------- SR1 --
\echo SR1 every role with an oid of 16384 or more, and every superuser:
SELECT rolname, oid >= 16384 AS from_16384, rolsuper, rolcreaterole, rolcanlogin,
       rolreplication, rolbypassrls
  FROM pg_roles
 WHERE (oid >= 16384 OR rolsuper) AND rolname NOT LIKE 'sopuli_probe_%'
 ORDER BY rolname;

-- The block SR3 and SR4 run, as whoever the session is.
\set probe 'DO $probe$ DECLARE r text; outcome text; BEGIN FOR r IN SELECT rolname FROM pg_roles WHERE oid >= 16384 AND rolname <> \'sopuli_probe_tool\' ORDER BY rolname LOOP BEGIN EXECUTE format(\'ALTER ROLE %I PASSWORD %L\', r, \'PwProbeMarker7q\'); RAISE EXCEPTION USING ERRCODE = \'P0001\', MESSAGE = \'sopuli_probe_accepted\'; EXCEPTION WHEN OTHERS THEN outcome := CASE WHEN SQLERRM = \'sopuli_probe_accepted\' THEN \'accepted\' ELSE SQLSTATE || \' \' || SQLERRM END; END; RAISE NOTICE \'% %: %\', current_user, r, outcome; END LOOP; END $probe$;'

-- ---------------------------------------------------------------- SR3 --
\echo SR3 ALTER ROLE ... PASSWORD on each role, as postgres:
:probe

-- --------------------------------------------------------- SR2 and SR4 --
\connect - sopuli_probe_tool
\echo SR2 the two settings, read by the tool account:
\x on
SELECT current_user,
       current_setting('supautils.reserved_roles', true) AS reserved_roles,
       current_setting('supautils.reserved_memberships', true) AS reserved_memberships;
\x off

\echo SR4 the same, as the tool account, with a role it created:
CREATE ROLE sopuli_probe_own LOGIN;
:probe
DROP ROLE sopuli_probe_own;

-- ---------------------------------------------------------------- SR5 --
\connect - postgres
\echo SR5 postgres grants the tool account pg_read_all_data, then authenticator:
\set ON_ERROR_STOP 0
GRANT pg_read_all_data TO sopuli_probe_tool;
GRANT authenticator TO sopuli_probe_tool;
\set ON_ERROR_STOP 1

-- ---------------------------------------------------------------- cleanup --
DROP ROLE sopuli_probe_tool;
