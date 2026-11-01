-- -----------------------------------------------------------------------------
-- sopuli-dba : what MySQL keeps of the text of ALTER USER ... IDENTIFIED BY
--
-- #1202. Before a MySQL driver is designed, this measures where the text of a
-- password change lands, and whether the server replaces the password in it:
--
--   PT1  ALTER USER ... IDENTIFIED BY '<password>', which succeeds
--   PT2  the same statement for an account that does not exist, which fails
--        when it runs, ER_CANNOT_USER (1396)
--   PT3  the same statement with a syntax error after the password, which
--        fails when it is parsed, ER_PARSE_ERROR (1064)
--   PT4  SET PASSWORD FOR ... = '<password>'
--   PT5  ALTER USER ... IDENTIFIED WITH caching_sha2_password AS 0x<hash>, the
--        form a client that computes the hash itself would send. The hash is
--        the server's own, for a password that no measured statement carries
--
-- Each is read back from the general log and the slow log (as tables, with
-- log_output = FILE,TABLE), the binary log, performance_schema's
-- events_statements_history and events_statements_summary_by_digest. A row
-- has_password = 1 holds a password in clear.
--
-- This MEASURES and decides nothing.
--
-- STATUS: run on 8.0.46, 8.4.13 and 9.7.4, the mysql:8.0, mysql:8.4 and
-- mysql:9 images of test/compose.yaml profile mysql-matrix, as root, on
-- 2026-11-01 (#1202). Twice on each release, with the release's own mysql
-- client, 65 s apart so that the digest samples aged out, and the same result
-- both times, with pt1_read = 1 and a history of 10 rows. After the runs, the
-- general log and slow log files in /var/lib/mysql held no test password
-- either.
--
-- RESULTS -- the same on all three releases, except where noted
--
--   PT1  the general log, the slow log, the statement history and the digest's
--        sample show `IDENTIFIED BY <secret>`. The binary log keeps the
--        statement rewritten to `IDENTIFIED WITH 'caching_sha2_password' AS
--        '$A$...'`, the stored hash
--   PT2  the general log, the slow log and the statement history show it with
--        `<secret>`, the history with mysql_errno 1396. The binary log does
--        not keep it
--   PT3  the statement history keeps it as sent, with the password in clear
--        and mysql_errno 1064. No other place keeps it: not the general log,
--        not the slow log, not the digest, not the binary log
--   PT4  as PT1, written `SET PASSWORD FOR ... =<secret>`
--   PT5  the server stores the hash as sent. The general log keeps the
--        statement as sent, with the hash in hex. The slow log, the statement
--        history (the EXECUTE's row) and the binary log keep it with the hash
--        as a string. On 9.7.4 the history's PREPARE and DEALLOCATE rows also
--        hold the statement as sent, with the hash in hex. On
--        9.7.4 the hash reads `$A$00A$`, 10,000 rounds, and `$A$005$`, 5,000,
--        on 8.0.46 and 8.4.13
--
--   So on every release measured, the server replaces the password in each
--   place measured once the statement parses. A statement that does not parse
--   stays in performance_schema as sent. Not measured: a server started with
--   --log-raw, which turns the replacement off in the general log, and SHOW
--   PROCESSLIST from another session while the statement runs.
--
-- HOW TO RUN, against the matrix (test/README.md):
--
--     docker exec -i sopuli-test-mysql-84-1 mysql -uroot -psopuli-test -f \
--         < sql/mysql/01_password_text_probe.sql
--
-- `-f` carries on after the statements that are meant to fail. In a second
-- clone the container name starts with its COMPOSE_PROJECT_NAME.
--
-- THROWAWAY SERVERS ONLY. Creates and drops two accounts. It turns the general
-- log and the slow log on for the run, and sets them and log_output back. The
-- test passwords it sends stay in performance_schema until the server restarts.
--
-- The rulers are `-- ---`: the mysql client reads a line of dashes with no
-- space after the first two as SQL.
-- -----------------------------------------------------------------------------

SELECT VERSION() AS version, @@log_bin AS log_bin, @@binlog_format AS binlog_format,
       @@log_output AS log_output, @@general_log AS general_log,
       @@slow_query_log AS slow_query_log;

-- ------------------------------------------------------------------ setup --
SET @saved_log_output = @@GLOBAL.log_output,
    @saved_general_log = @@GLOBAL.general_log,
    @saved_slow_query_log = @@GLOBAL.slow_query_log;
DROP USER IF EXISTS 'sopuli_probe_pw'@'%', 'sopuli_probe_seed'@'%';

-- The hash PT5 sends. The server computes it here, from a password that no
-- measured statement carries, before the binary log position is read.
CREATE USER 'sopuli_probe_seed'@'%' IDENTIFIED WITH caching_sha2_password BY 'PwSeedMarker7q';
SELECT HEX(authentication_string) INTO @seed_hash
  FROM mysql.user WHERE user = 'sopuli_probe_seed' AND host = '%';
CREATE USER 'sopuli_probe_pw'@'%' IDENTIFIED WITH caching_sha2_password BY 'PwCreateMarker1a';

-- Only what this run writes is read back.
SELECT JSON_UNQUOTE(LOCAL->'$.binary_log_file'),
       JSON_UNQUOTE(LOCAL->'$.binary_log_position')
  INTO @binlog_file, @binlog_position
  FROM performance_schema.log_status;
SET @started = NOW(6);
SET GLOBAL log_output = 'FILE,TABLE';
SET GLOBAL general_log = ON;
SET GLOBAL slow_query_log = ON;
-- long_query_time is read per session, so this session's every statement is
-- slow.
SET SESSION long_query_time = 0;

-- ---------------------------------------------------------------- PT1-PT5 --
-- Built before PT1, so that PT1 to PT5 fit in the history's 10 rows.
SET @pt5 = CONCAT('ALTER USER ''sopuli_probe_pw''@''%'' IDENTIFIED WITH caching_sha2_password AS 0x',
                  @seed_hash);
ALTER USER 'sopuli_probe_pw'@'%' IDENTIFIED BY 'PwPlainMarker4k';
ALTER USER 'sopuli_probe_missing'@'%' IDENTIFIED BY 'PwFailMarker9z';
ALTER USER 'sopuli_probe_pw'@'%' IDENTIFIED BY 'PwParseMarker5s' sopuli_bogus;
SET PASSWORD FOR 'sopuli_probe_pw'@'%' = 'PwSetMarker3p';
PREPARE pt5 FROM @pt5;
EXECUTE pt5;
DEALLOCATE PREPARE pt5;

-- events_statements_history keeps a thread's last 10 statements, so it is read
-- now, before more statements push PT1 out of it. It is kept in a variable, as
-- a JSON array, because a temporary table needs a database.
SELECT JSON_ARRAYAGG(JSON_OBJECT('sql_text', sql_text, 'mysql_errno', mysql_errno))
  INTO @history
  FROM performance_schema.events_statements_history
 WHERE thread_id = PS_CURRENT_THREAD_ID();

SET GLOBAL general_log = @saved_general_log;
SET GLOBAL slow_query_log = @saved_slow_query_log;
SET GLOBAL log_output = @saved_log_output;
SET SESSION long_query_time = DEFAULT;

-- 1 if the server stored PT5's hash as it was sent.
SELECT 'PT5' AS probe, authentication_string = UNHEX(@seed_hash) AS stored_as_sent
  FROM mysql.user WHERE user = 'sopuli_probe_pw' AND host = '%';

-- ---------------------------------------------------------------- results --
-- `LIKE '%Marker%'` finds a password in clear; each probe statement names an
-- account that starts sopuli_probe_, so every row that names one is shown.
SELECT 'general log' AS place, argument AS text, argument LIKE '%Marker%' AS has_password
  FROM mysql.general_log
 WHERE event_time >= @started AND argument LIKE '%sopuli\_probe\_%';

SELECT 'slow log' AS place, sql_text AS text, sql_text LIKE '%Marker%' AS has_password
  FROM mysql.slow_log
 WHERE start_time >= @started AND sql_text LIKE '%sopuli\_probe\_%';

-- With 10 rows, PT1 is the oldest the history can hold. pt1_read = 0 means
-- it was pushed out, not that the server did not keep it.
SELECT @@performance_schema_events_statements_history_size AS history_size,
       JSON_SEARCH(@history, 'one',
                   'ALTER USER ''sopuli\_probe\_pw''@''\%'' IDENTIFIED BY <secret>') IS NOT NULL
         AS pt1_read;

SELECT 'statement history' AS place, sql_text AS text, mysql_errno,
       sql_text LIKE '%Marker%' AS has_password
  FROM JSON_TABLE(@history, '$[*]' COLUMNS (sql_text LONGTEXT PATH '$.sql_text',
                                            mysql_errno INT PATH '$.mysql_errno')) AS h
 WHERE sql_text LIKE '%sopuli\_probe\_%';

SELECT 'digest' AS place, digest_text, query_sample_text AS text,
       query_sample_text LIKE '%Marker%' AS has_password
  FROM performance_schema.events_statements_summary_by_digest
 WHERE query_sample_seen >= @started AND query_sample_text LIKE '%sopuli\_probe\_%'
   AND query_sample_text NOT LIKE '%performance_schema%'
   AND query_sample_text NOT LIKE '%general_log%' AND query_sample_text NOT LIKE '%slow_log%';

-- The binary log, from where it was when the run started. SHOW BINLOG EVENTS
-- takes no expression, so it is prepared. A server with the binary log off has
-- no file to name.
SET @show_binlog = IF(@binlog_file IS NULL OR @binlog_file = '',
                      'SELECT ''the binary log is off'' AS binary_log',
                      CONCAT('SHOW BINLOG EVENTS IN ''', @binlog_file, ''' FROM ',
                             @binlog_position));
PREPARE show_binlog FROM @show_binlog;
EXECUTE show_binlog;
DEALLOCATE PREPARE show_binlog;

-- ---------------------------------------------------------------- cleanup --
DROP USER 'sopuli_probe_pw'@'%', 'sopuli_probe_seed'@'%';
