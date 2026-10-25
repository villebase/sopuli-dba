--------------------------------------------------------------------------------
-- sopuli-dba : what PostgreSQL keeps of the text of ALTER ROLE ... PASSWORD
--
-- #1032. The PostgreSQL driver is to send a SCRAM-SHA-256 verifier that it
-- computes on the client, and never the password. This measures where the text
-- of the statement lands, with a verifier and with a plaintext password:
--
--   PT1  ALTER ROLE ... PASSWORD 'SCRAM-SHA-256$...', under log_statement = all
--   PT2  the same statement with a plaintext password
--   PT3  both statements failing, because the role does not exist, under the
--        default log_statement = none and log_min_error_statement = error
--   PT4  a second session, opened through dblink, sends a plaintext password
--        and goes idle. This session reads pg_stat_activity.query
--
-- The server log is read back with pg_read_file(), from where it ended when the
-- run started. pg_stat_statements is reset before PT1 and read after PT4. The
-- verifier is computed by the server, from a password that no measured
-- statement carries.
--
-- This MEASURES and decides nothing.
--
-- STATUS: run on 13.23, 14.24, 15.19, 16.15, 17.11 and 18.6, the postgres:13
-- to postgres:18 images of test/compose.yaml profile postgres-matrix, as the
-- superuser postgres, on 2026-10-25 (#1032). Four times on each release, exit
-- 0, and the same result every time. The last two runs wait 2 s before they
-- read the log, because the logging collector writes it in its own process.
-- The first two read it at once and found every line too.
--
-- RESULTS -- the same on all six releases
--
--   PT1  the log keeps the statement, with the verifier in full, and so does
--        pg_stat_statements
--   PT2  the log and pg_stat_statements keep the plaintext password
--   PT3  the log keeps both failed statements in full, in a STATEMENT: line,
--        although log_statement is none. pg_stat_statements keeps neither
--   PT4  pg_stat_activity.query shows the idle session's last statement, with
--        the plaintext password. pg_stat_statements keeps it too
--
--   So on every release measured, the literal an ALTER ROLE carries is kept in
--   clear in each place measured. pg_stat_statements does not replace the
--   literal of this utility statement with a placeholder.
--
-- HOW TO RUN, against the matrix (test/README.md):
--
--     docker exec -i sopuli-test-postgres-16-1 psql -U postgres -d sopuli -X \
--         < sql/postgres/01_password_text_probe.sql
--
-- In a second clone the container name starts with its COMPOSE_PROJECT_NAME.
--
-- THROWAWAY SERVERS ONLY. Creates and drops two roles, and creates and drops
-- the pg_stat_statements and dblink extensions in the database it runs in. The
-- test passwords it sends stay in the server log.
--------------------------------------------------------------------------------
\set ON_ERROR_STOP 1
\pset footer off

SELECT current_setting('server_version') AS server_version,
       current_setting('pg_stat_statements.track_utility', true) AS track_utility,
       current_setting('log_min_error_statement') AS log_min_error_statement;

-- ------------------------------------------------------------------ setup --
DROP ROLE IF EXISTS sopuli_probe_pw;
DROP ROLE IF EXISTS sopuli_probe_seed;
CREATE EXTENSION IF NOT EXISTS pg_stat_statements;
CREATE EXTENSION IF NOT EXISTS dblink;

-- The verifier PT1 sends. The server computes it here, once, from a password
-- that no measured statement carries. log_statement is still the default,
-- `none`, so this statement is not logged.
SET password_encryption = 'scram-sha-256';
CREATE ROLE sopuli_probe_seed PASSWORD 'PwSeedMarker7q';
SELECT rolpassword AS verifier FROM pg_authid WHERE rolname = 'sopuli_probe_seed' \gset
CREATE ROLE sopuli_probe_pw LOGIN;

-- Only what this run writes to the log is read back.
SELECT pg_current_logfile() AS log_file \gset
SELECT size AS log_start FROM pg_stat_file(:'log_file') \gset
SELECT 'done' AS reset FROM (SELECT pg_stat_statements_reset()) AS r;

-- ----------------------------------------------------------------- PT1-PT2 --
SET log_statement = 'all';
-- PT1: the statement the driver sends, with a client-side verifier.
ALTER ROLE sopuli_probe_pw PASSWORD :'verifier';
-- PT2: a plaintext password, to compare.
ALTER ROLE sopuli_probe_pw PASSWORD 'PwPlainMarker4k';
RESET log_statement;

-- -------------------------------------------------------------------- PT3 --
-- PT3: a statement that fails, under the default log_statement. The default
-- log_min_error_statement = error logs the text of a statement that fails.
\set ON_ERROR_STOP 0
ALTER ROLE sopuli_probe_missing PASSWORD 'PwFailMarker9z';
ALTER ROLE sopuli_probe_missing PASSWORD :'verifier';
\set ON_ERROR_STOP 1

-- -------------------------------------------------------------------- PT4 --
-- PT4: another session sends a plaintext password and goes idle. Its last
-- statement stays in pg_stat_activity.query. The pattern is built with `||`, so
-- this session's own query does not match it.
SELECT dblink_connect('sopuli_probe', 'dbname=' || current_database() || ' user=postgres') AS connected;
SELECT dblink_exec('sopuli_probe', 'ALTER ROLE sopuli_probe_pw PASSWORD ''PwIdleMarker2m''') AS idle_session;
\echo PT4 pg_stat_activity, another session idle after a plaintext ALTER ROLE:
SELECT state, query
  FROM pg_stat_activity
 WHERE query LIKE '%PwIdle' || 'Marker%' AND pid <> pg_backend_pid();
SELECT dblink_disconnect('sopuli_probe') AS disconnected;

-- ---------------------------------------------------------------- results --
-- The logging collector writes the file in its own process, after the backend
-- hands it a line. Give it time to write PT3's lines before reading them back.
SELECT pg_sleep(2) IS NULL AS waited;
\echo PT1-PT3 server log, lines this run wrote that hold a password or a verifier:
SELECT line
  FROM regexp_split_to_table(
         pg_read_file(:'log_file', :log_start,
                      (SELECT size FROM pg_stat_file(:'log_file')) - :log_start),
         E'\n') AS line
 WHERE line LIKE '%Marker%' OR line LIKE '%SCRAM-SHA-256$%';

\echo PT1-PT2 pg_stat_statements, ALTER ROLE entries:
SELECT calls, query FROM pg_stat_statements WHERE query ILIKE 'ALTER ROLE%' ORDER BY query;

-- ---------------------------------------------------------------- cleanup --
DROP ROLE sopuli_probe_pw;
DROP ROLE sopuli_probe_seed;
DROP EXTENSION dblink;
DROP EXTENSION pg_stat_statements;
