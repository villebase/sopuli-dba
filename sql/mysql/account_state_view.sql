-- sopuli-dba : the optional view sopuli.account_state, for report accounts (#1502)
--
-- STATUS: run on 8.0.46, 8.4.13 and 9.7.4 (2026-11-13, #1502), as root,
--         twice each, so the already-exists path ran too. Then the tier-1
--         tests of the view read it as a tool account holding only SELECT
--         on it, on each, and on 8.4.13 report accounts read the limit
--         through it. An extra column, a dropped definer and a definer
--         without SELECT each left it unread. A limit without a lock time
--         never blocked. After the definer was dropped, the script mended
--         the view on each; on 8.4.13 also when run twice by an
--         administrator holding only CREATE USER, SET_ANY_DEFINER, SELECT on
--         mysql.user and CREATE, DROP, CREATE VIEW and SELECT on sopuli.*,
--         all with GRANT OPTION where it passes them on. Without the DROP
--         VIEW below, that run answered 4006. An administrator without
--         SET_ANY_DEFINER stops at CREATE USER with 4006, even with the
--         definer present, and the view it found stays readable.
--
-- What it is for. MySQL keeps an account's failed-login limit only in
-- mysql.user.User_attributes, beside a retained password's hash, which the
-- tool account must never read (#1411, M1). This view selects the keys the
-- tool may need alone, and whether a password is retained, never its value.
-- The tool account reads it with SELECT on the view, never on mysql.user
-- (#1457, measured by 12_definer_view_probe.py, #1490).
--
-- Who reads it. report accounts, for the failed-login limit and the lock
-- time, which the limit needs to block, and report privileges, for the
-- partial revokes (restrictions), where partial_revokes is on. No verb that
-- changes an account reads it. Without the view the reports say "not
-- checked", with the reason, and still run. The retained-password flag is in
-- the view for a later read. A column grant must include every column a
-- command reads, or that command does not read the view.
--
-- What it creates, each step safe to run again:
--   1. the schema sopuli, which holds only the tool's views;
--   2. sopuli_view_definer@localhost, LOCKED, holding only SELECT on
--      mysql.user: the view runs with its rights, and nobody logs in as it;
--   3. the view sopuli.account_state, SQL SECURITY DEFINER, as that account;
--   4. SELECT on the view to the tool account.
--
-- The tool checks the view's columns every session and does not read a view
-- with a column outside the six below. Do not add columns.
--
-- How to run. As an administrator who may name another definer
-- (SET_ANY_DEFINER from 8.2, SET_USER_ID before; without it, CREATE DEFINER =
-- ... answers 1227), and who may create users, grant SELECT on mysql.user and
-- create and drop the schema's views. Set the tool account below first:
--
--   mysql -u root -p < account_state_view.sql
--
-- The tool account. Edit these two values: the user name and the host part of
-- the account in the target's admin: block (02-mysql-privileges.md 2.1).
SET @tool_user = 'sopuli_admin';
SET @tool_host = '192.0.2.10';

CREATE SCHEMA IF NOT EXISTS sopuli;

-- A view whose definer was dropped is dropped first, so the script mends it:
-- while the view names a missing definer, CREATE USER of it answers 4006
-- unless the administrator holds ALLOW_NONEXISTENT_DEFINER (8.2 and later) or
-- SET_USER_ID (8.0). Only then: a view whose definer exists is replaced below,
-- and left as it is if this run stops before that.
SET @drop_view = IF(
  (SELECT COUNT(*) FROM mysql.user
    WHERE User = 'sopuli_view_definer' AND Host = 'localhost') = 0,
  'DROP VIEW IF EXISTS sopuli.account_state',
  'DO 0'
);
PREPARE drop_view FROM @drop_view;
EXECUTE drop_view;
DEALLOCATE PREPARE drop_view;

CREATE USER IF NOT EXISTS 'sopuli_view_definer'@'localhost' ACCOUNT LOCK;
ALTER USER 'sopuli_view_definer'@'localhost' ACCOUNT LOCK;
GRANT SELECT ON mysql.user TO 'sopuli_view_definer'@'localhost';

CREATE OR REPLACE
  DEFINER = 'sopuli_view_definer'@'localhost'
  SQL SECURITY DEFINER
  VIEW sopuli.account_state AS
SELECT User, Host,
       JSON_EXTRACT(User_attributes, '$.Password_locking.failed_login_attempts')
         AS failed_login_attempts,
       JSON_EXTRACT(User_attributes, '$.Password_locking.password_lock_time_days')
         AS password_lock_time_days,
       JSON_EXTRACT(User_attributes, '$.Restrictions') AS restrictions,
       COALESCE(JSON_CONTAINS_PATH(User_attributes, 'one', '$.additional_password'), 0)
         AS retained_password
  FROM mysql.user;

SET @grant_view = CONCAT(
  'GRANT SELECT ON sopuli.account_state TO ', QUOTE(@tool_user), '@', QUOTE(@tool_host)
);
PREPARE grant_view FROM @grant_view;
EXECUTE grant_view;
DEALLOCATE PREPARE grant_view;
