-- sopuli-dba : the optional view sopuli.global_privileges, for report privileges (#1483)
--
-- STATUS: run on 10.11.19, 11.4.13, 11.8.9 and 12.3.3 (2026-11-13, #1483),
--         as root over the socket, twice each, so the already-exists path
--         ran too. Then the tool account read the view through report
--         privileges on each. On 12.3.3 the view was also broken four ways
--         and the script run again to mend it: a definer narrowed to
--         mysql.global_priv, an extra column, a dropped definer and a
--         revoked grant.
--
-- What it is for. MariaDB keeps an account's global privileges in
-- mysql.global_priv, beside the stored password value, which the tool account
-- must never read, and the tool account's grants show it no other account's
-- row of information_schema.USER_PRIVILEGES. This view selects that table's
-- three columns and nothing else, with the rights of a definer that can read
-- mysql.*, so the tool account reads each account's global privileges as the
-- server applies them (#1483, measured by 17_global_privileges_view_probe.py).
--
-- Who reads it. report privileges, for the global level of each account. No
-- verb that changes an account reads it. Without the view the global level is
-- "not checked", with the reason, and the report still runs. A role has no
-- row in it, so a role's global level is not checked either way.
--
-- What it creates, each step safe to run again:
--   1. the schema sopuli, which holds this view and sopuli.account_state
--      (account_state_view.sql);
--   2. sopuli_grants_definer@localhost, LOCKED, holding only SELECT on
--      mysql.*: the view runs with its rights, and nobody logs in as it. With
--      less than mysql.* the view gives the definer's own row alone, with no
--      error, and the tool then does not use it;
--   3. the view sopuli.global_privileges, SQL SECURITY DEFINER, as that
--      account;
--   4. SELECT on the view to the tool account.
--
-- The tool checks the view's columns every session and does not read a view
-- with a column outside the three below. Do not add columns.
--
-- How to run. As an administrator who may name another definer (SET USER or
-- SUPER; without it, CREATE DEFINER = ... answers 1227). Set the tool
-- account below first:
--
--   mariadb -u root -p < global_privileges_view.sql
--
-- The tool account. Edit these two values: the user name and the host part of
-- the account in the target's admin: block (02-mariadb-privileges.md 2.1).
SET @tool_user = 'sopuli_admin';
SET @tool_host = '192.0.2.10';

CREATE SCHEMA IF NOT EXISTS sopuli;

CREATE USER IF NOT EXISTS 'sopuli_grants_definer'@'localhost' ACCOUNT LOCK;
ALTER USER 'sopuli_grants_definer'@'localhost' ACCOUNT LOCK;
GRANT SELECT ON mysql.* TO 'sopuli_grants_definer'@'localhost';

CREATE OR REPLACE
  DEFINER = 'sopuli_grants_definer'@'localhost'
  SQL SECURITY DEFINER
  VIEW sopuli.global_privileges AS
SELECT GRANTEE, PRIVILEGE_TYPE, IS_GRANTABLE
  FROM information_schema.USER_PRIVILEGES;

EXECUTE IMMEDIATE CONCAT(
  'GRANT SELECT ON sopuli.global_privileges TO ', QUOTE(@tool_user), '@', QUOTE(@tool_host)
);
