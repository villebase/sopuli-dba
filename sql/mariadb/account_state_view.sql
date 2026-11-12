-- sopuli-dba : the optional view sopuli.account_state, for the reports (#1491)
--
-- STATUS: run on 10.11.19, 11.4.13, 11.8.9 and 12.3.3 (2026-11-12, #1491),
--         as root over the socket, twice each, so the already-exists path
--         ran too. Then the tool account read the view through report
--         accounts on each. On 12.3.3 the view was also broken three ways and
--         the script run again to mend it: an extra column, a dropped
--         definer and a revoked grant.
--
-- What it is for. MariaDB keeps an account's lock, its password lifetime and
-- the time of its last password change only in mysql.global_priv, beside the
-- stored password value, which the tool account must never read (#1411, R2).
-- This view selects those keys alone, and whether a rollover is open, and
-- nothing else. The tool account reads it with SELECT on the view, never on
-- mysql.global_priv (#1457, measured by 16_definer_view_probe.py, #1479).
--
-- Who reads it. report accounts (the lock and the lifetime), report history
-- (the time of the last change) and account list (the lock). No verb that
-- changes an account reads it. Without the view those are "not checked",
-- with the reason, and the reports still run.
--
-- What it creates, each step safe to run again:
--   1. the schema sopuli, holding only this view;
--   2. sopuli_view_definer@localhost, LOCKED, holding only SELECT on
--      mysql.global_priv: the view runs with its rights, and nobody logs in
--      as it;
--   3. the view sopuli.account_state, SQL SECURITY DEFINER, as that account;
--   4. SELECT on the view to the tool account.
--
-- The tool checks the view's columns every session and does not read a view
-- with a column outside the six below. Do not add columns.
--
-- How to run. As an administrator who may name another definer (SET USER or
-- SUPER; without it, CREATE DEFINER = ... answers 1227). Set the tool
-- account below first:
--
--   mariadb -u root -p < account_state_view.sql
--
-- The tool account. Edit these two values: the user name and the host part of
-- the account in the target's admin: block (02-mariadb-privileges.md 2.1).
SET @tool_user = 'sopuli_admin';
SET @tool_host = '192.0.2.10';

CREATE SCHEMA IF NOT EXISTS sopuli;

CREATE USER IF NOT EXISTS 'sopuli_view_definer'@'localhost' ACCOUNT LOCK;
ALTER USER 'sopuli_view_definer'@'localhost' ACCOUNT LOCK;
GRANT SELECT ON mysql.global_priv TO 'sopuli_view_definer'@'localhost';

CREATE OR REPLACE
  DEFINER = 'sopuli_view_definer'@'localhost'
  SQL SECURITY DEFINER
  VIEW sopuli.account_state AS
SELECT User, Host,
       JSON_VALUE(Priv, '$.account_locked')            AS account_locked,
       JSON_VALUE(Priv, '$.password_lifetime')         AS password_lifetime,
       JSON_VALUE(Priv, '$.password_last_changed')     AS password_last_changed,
       COALESCE(JSON_LENGTH(Priv, '$.auth_or'), 0) > 1 AS rollover_open
  FROM mysql.global_priv;

EXECUTE IMMEDIATE CONCAT(
  'GRANT SELECT ON sopuli.account_state TO ', QUOTE(@tool_user), '@', QUOTE(@tool_host)
);
