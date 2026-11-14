--------------------------------------------------------------------------------
-- sopuli-dba : a view a DBA owns over SYS.USER$'s NAME and LCOUNT   (v1)
--
-- #1511, gap 5. The LCOUNT guard reads SYS.USER$, through the optional
-- SELECT ON SYS.USER$ grant, which also shows the tool account every
-- password verifier (P2). #124 measured SYS.KU$_USER_VIEW as a narrower
-- source and did not adopt it. This measures a third source: a view over
-- NAME and LCOUNT alone, which a DBA creates and grants to the tool account,
-- as #1457 lets MySQL and MariaDB do. The tool account, sopuli_lv_svc, holds
-- CREATE SESSION, ALTER USER and SELECT ON DBA_USERS and DBA_PROFILES from
-- 00_install.sql's base set, and nothing on SYS.USER$. Each view is
--
--     SELECT name, lcount FROM sys.user$ WHERE type# = 1
--
--   LV1  who can own the view. SYS creates it in a schema of its own,
--        NO AUTHENTICATION. sopuli_lv_plain: before it holds anything on
--        SYS.USER$, then with SELECT ON SYS.USER$ and no grant option, the
--        GRANT SELECT on the view to the tool account, and a read by the tool
--        account. sopuli_lv_owner: SELECT ON SYS.USER$ WITH GRANT OPTION, and
--        the same GRANT. sopuli_lv_reader: READ ON SYS.USER$ WITH GRANT
--        OPTION, granting READ on its view. Then the view in SYS's own
--        schema. Then sopuli_lv_dba, an account holding the DBA role, and so
--        GRANT ANY OBJECT PRIVILEGE: creating the view in its own schema, and
--        granting to a third owner, sopuli_lv_byd, SELECT ON SYS.USER$ with
--        and without the grant option, and READ with it
--   LV2  what the tool account reads through it: its columns from
--        ALL_TAB_COLUMNS, the view's text from ALL_VIEWS, its rows against
--        DBA_USERS, a column the view does not have, and SYS.USER$ itself.
--        Then the count: acme_lv_app, FAILED_LOGIN_ATTEMPTS 5, after two
--        wrong passwords, through the view and as SYS reads SYS.USER$, and
--        after a good login
--   LV3  the capability probe: what the tool account gets from a SELECT and
--        from ALL_TAB_COLUMNS for a view that does not exist, for a view it
--        holds no grant on, and for the view after its owner loses SELECT ON
--        SYS.USER$: the view's STATUS, whether the tool account's grant is
--        still there, and what a SELECT gets after the owner's grant comes
--        back. Then after the owner is dropped
--   LV4  locks: SELECT ... FOR UPDATE NOWAIT on one row, by the tool account,
--        through the SELECT grant and through the READ grant, and what
--        V$LOCKED_OBJECT shows the tool account of it before a ROLLBACK. The
--        two reads it needs are granted for this step alone. Then a read and
--        FOR UPDATE through READ ON SYS.USER$ itself, and FOR UPDATE through
--        SELECT ON SYS.USER$ itself, which 00_install.sql grants with
--        grant_user_dollar=Y
--   LV4b by hand, not in this script: what such a lock holds up. A tool
--        account session takes the row lock and sleeps 40 s: through SELECT
--        on the view, and in a second set of runs through SELECT ON SYS.USER$
--        itself. A second session starts 6 s later and times, in three
--        separate runs for each, a login with a wrong password, a login with
--        the right one, and SYS's ALTER USER ... ACCOUNT LOCK on the locked
--        row's account
--   LV5  what an owner outside SYS opens to sopuli_lv_dba: its own SELECT on
--        SYS.USER$'s SPARE4, a read of sopuli_lv_plain's view without a
--        grant on it, then CREATE VIEW over NAME and SPARE4 in
--        sopuli_lv_plain's schema, in sopuli_lv_reader's, in SYS's, and in
--        the tool account's while it holds SELECT ON SYS.USER$, as
--        grant_user_dollar=Y gives, and a read of each. It prints only how
--        many rows hold a verifier, never a value
--   LV6  the audit trail: a unified audit policy on SELECT ON SYS.USER$ and
--        on the view, by the tool account. Two reads of the view, then the
--        rows UNIFIED_AUDIT_TRAIL holds for that session, per object
--
-- This MEASURES and decides nothing.
--
-- STATUS: run 2026-11-14 on 26ai Free 23.26.3.0.0 (gvenzl/oracle-free:latest,
-- FREEPDB1), twice, with the same output both times; LV4b twice by hand for
-- each grant. Four earlier runs of drafts are not counted: they had no LV1g
-- and no LV4 steps on SYS.USER$ itself, two of them had no owner without the
-- grant option and no LV5f, and LV6 counted rows by a date compared across
-- time zones. Every other release UNRUN, the 19.3 base release among them.
--
--
-- RESULTS -- 23.26.3.0.0, 2026-11-14
--
--   LV1  SYS's CREATE VIEW in a schema that holds nothing on SYS.USER$ gets
--        ORA-00942, "table or view "SYS"."USER$" does not exist". With SELECT
--        and no grant option, the view is created and SYS's GRANT SELECT on
--        it to the tool account succeeds and is listed in DBA_TAB_PRIVS, but
--        the tool account's read gets ORA-41900, "missing READ privilege on
--        "SYS"."USER$"". With WITH GRANT OPTION, SELECT or READ, the tool
--        account reads. The view in SYS's schema needs no grant on SYS.USER$.
--        An account with the DBA role gets ORA-41904, "Missing object
--        privilege on "SYS"."USER$" to create a view", in its own schema, and
--        ORA-01031 on each of its grants of SYS.USER$ to another owner: SELECT
--        with and without the grant option, and READ with it. So the view
--        needs SYS: in its own schema, or to grant SYS.USER$ WITH GRANT
--        OPTION to the owner. Whether such an owner can pass the grant on to
--        another schema was not tried
--   LV2  the tool account sees the two columns, NAME VARCHAR2 and LCOUNT
--        NUMBER, in ALL_TAB_COLUMNS, and the view's text in ALL_VIEWS. Each
--        view has one row per row of DBA_USERS, and no name differs. A column
--        the view does not have gets ORA-00904, and SYS.USER$ itself
--        ORA-00942. After two wrong passwords the three views read LCOUNT 2,
--        as SYS reads SYS.USER$, and 0 after a good login
--   LV3  a view that does not exist and a view without the grant both get
--        ORA-00942, and ALL_TAB_COLUMNS gives no row for either. After the
--        owner loses SELECT ON SYS.USER$, DBA_OBJECTS still reads VALID, the
--        tool account's grant on the view is kept, ALL_TAB_COLUMNS still
--        gives the two columns, and a read gets ORA-04063, "view
--        "SOPULI_LV_OWNER.ACCOUNT_LCOUNT" has errors". When the grant comes
--        back the read works again, with no new grant to the tool account.
--        After the owner is dropped, ORA-00942
--   LV4  through the SELECT grant on the view, the tool account's SELECT ...
--        FOR UPDATE NOWAIT succeeds, and V$LOCKED_OBJECT shows SYS.USER$
--        locked in mode 3, row exclusive. Through the READ grant it gets
--        ORA-41900, "missing SELECT privilege on
--        "SOPULI_LV_READER"."ACCOUNT_LCOUNT"". With READ ON SYS.USER$ itself,
--        the tool account reads LCOUNT, and FOR UPDATE gets ORA-01031. With
--        SELECT ON SYS.USER$ itself, FOR UPDATE succeeds and takes the same
--        mode 3 lock on SYS.USER$ as through the view
--   LV4b with either grant, while the lock is held, the wrong password, the
--        right password and SYS's ALTER USER each wait, and each finishes 34
--        to 35 s after it started, when the holder rolls back: the wrong
--        password then gets
--        ORA-01017, the right one logs in, and ALTER USER succeeds
--   LV5  the DBA role gives no read of SYS.USER$: ORA-41900, "missing READ
--        privilege on "SYS"."USER$"". It reads sopuli_lv_plain's view with
--        no grant on it. CREATE VIEW over NAME and SPARE4 succeeds in
--        sopuli_lv_plain's schema, which holds SELECT with no grant option,
--        in sopuli_lv_reader's, which holds READ, and in the tool account's
--        schema while that holds SELECT ON SYS.USER$. Through each, the DBA
--        account counts 47 rows whose SPARE4 is not NULL, as many as
--        DBA_USERS has rows in that run; LV5c also counts 47 that begin S:.
--        In SYS's schema CREATE VIEW gets ORA-01031, and the DBA account
--        reads SYS's narrow view. So any schema outside SYS that holds a
--        grant on SYS.USER$, the tool account's under grant_user_dollar=Y
--        among them, shows every verifier to an account that holds CREATE
--        ANY VIEW and SELECT ANY TABLE, as the DBA role does
--   LV6  two reads of the view in one tool account session leave four rows in
--        UNIFIED_AUDIT_TRAIL: two SELECT on the view and two SELECT on
--        SYS.USER$
--
--
-- HOW TO RUN. Against the tier-1 stack, from this directory, where the SYS
--   password is the public one in test/compose.yaml, as it stands:
--
--     MSYS_NO_PATHCONV=1 docker exec -i sopuli-test-oracle-free-1 \
--       sqlplus -S /nolog < 23_lcount_view_probe.sql
--
--   A second clone's stack names the container after its COMPOSE_PROJECT_NAME,
--   such as sopuli-test-w2-oracle-free-1. On XE the PDB is XEPDB1. /nolog, and
--   every CONNECT made from the script, so no password is ever in argv
--   (invariant 1). Against any other database, copy the file, edit the two
--   DEFINEs in the copy, run the copy and delete it -- never substitute them
--   with sed, which puts the password in argv instead. MSYS_NO_PATHCONV is for
--   Git Bash, which otherwise rewrites /nolog.
--
-- NO AUTHENTICATION, for the four owners, exists from 18c. On an older
-- release, give them a password and ACCOUNT LOCK in a copy.
--
-- WHENEVER SQLERROR is CONTINUE throughout: the refusals are the question.
--
-- THROWAWAY DATABASES ONLY. Creates and drops accounts, a profile, views in
-- SYS's schema and an audit policy, and fails logins on purpose.
--------------------------------------------------------------------------------
define pdb = //localhost:1521/FREEPDB1
define pwd = sopuli-test

WHENEVER SQLERROR CONTINUE
SET LINESIZE 200 PAGESIZE 100 FEEDBACK OFF VERIFY OFF HEADING ON LONG 400
COLUMN name        FORMAT A20
COLUMN owner       FORMAT A16
COLUMN table_name  FORMAT A16
COLUMN column_name FORMAT A12
COLUMN data_type   FORMAT A10
COLUMN object_name FORMAT A16
COLUMN object_schema FORMAT A16
COLUMN action_name FORMAT A10
COLUMN status      FORMAT A8
COLUMN privilege   FORMAT A10
COLUMN grantee     FORMAT A16
COLUMN text_vc     FORMAT A60

define lv_view = "SELECT name, lcount FROM sys.user$ WHERE type# = 1"

CONNECT sys/"&pwd"@&pdb AS SYSDBA
BEGIN
  FOR p IN (SELECT COUNT(*) n FROM audit_unified_enabled_policies WHERE policy_name = 'SOPULI_LV_POL') LOOP
    IF p.n > 0 THEN
      EXECUTE IMMEDIATE 'NOAUDIT POLICY sopuli_lv_pol BY sopuli_lv_svc';
    END IF;
  END LOOP;
  FOR p IN (SELECT DISTINCT policy_name FROM audit_unified_policies WHERE policy_name = 'SOPULI_LV_POL') LOOP
    EXECUTE IMMEDIATE 'DROP AUDIT POLICY sopuli_lv_pol';
  END LOOP;
  FOR v IN (SELECT view_name FROM dba_views WHERE owner = 'SYS' AND view_name LIKE 'SOPULI_LV%') LOOP
    EXECUTE IMMEDIATE 'DROP VIEW sys.' || v.view_name;
  END LOOP;
  FOR u IN (SELECT username FROM dba_users WHERE username LIKE 'ACME_LV%' OR username LIKE 'SOPULI_LV%') LOOP
    EXECUTE IMMEDIATE 'DROP USER ' || u.username || ' CASCADE';
  END LOOP;
  FOR p IN (SELECT DISTINCT profile FROM dba_profiles WHERE profile = 'ACME_LV_PROF') LOOP
    EXECUTE IMMEDIATE 'DROP PROFILE acme_lv_prof CASCADE';
  END LOOP;
END;
/

CREATE PROFILE acme_lv_prof LIMIT FAILED_LOGIN_ATTEMPTS 5 PASSWORD_LOCK_TIME 1;
CREATE USER acme_lv_app IDENTIFIED BY "Acme_Lv_App_1" PROFILE acme_lv_prof;
GRANT CREATE SESSION TO acme_lv_app;
CREATE USER sopuli_lv_svc IDENTIFIED BY "Sopuli_Lv_Svc_1";
GRANT CREATE SESSION, ALTER USER TO sopuli_lv_svc;
GRANT SELECT ON sys.dba_users TO sopuli_lv_svc;
GRANT SELECT ON sys.dba_profiles TO sopuli_lv_svc;
CREATE USER sopuli_lv_plain NO AUTHENTICATION;
CREATE USER sopuli_lv_owner NO AUTHENTICATION;
CREATE USER sopuli_lv_reader NO AUTHENTICATION;
CREATE USER sopuli_lv_byd NO AUTHENTICATION;
CREATE USER sopuli_lv_dba IDENTIFIED BY "Sopuli_Lv_Dba_1";
GRANT DBA TO sopuli_lv_dba;

PROMPT
PROMPT == LV1a  SYS creates the view in sopuli_lv_plain, which holds nothing on SYS.USER$
CREATE VIEW sopuli_lv_plain.account_lcount AS &lv_view;
PROMPT
PROMPT == LV1b  ... with SELECT ON SYS.USER$ and no grant option, then the GRANT SELECT on the view to the tool account
GRANT SELECT ON sys.user$ TO sopuli_lv_plain;
CREATE VIEW sopuli_lv_plain.account_lcount AS &lv_view;
GRANT SELECT ON sopuli_lv_plain.account_lcount TO sopuli_lv_svc;
CONNECT sopuli_lv_svc/"Sopuli_Lv_Svc_1"@&pdb
SELECT COUNT(*) plain_rows FROM sopuli_lv_plain.account_lcount;
CONNECT sys/"&pwd"@&pdb AS SYSDBA
PROMPT
PROMPT == LV1c  sopuli_lv_owner: SELECT ON SYS.USER$ WITH GRANT OPTION, its view, the same GRANT
GRANT SELECT ON sys.user$ TO sopuli_lv_owner WITH GRANT OPTION;
CREATE VIEW sopuli_lv_owner.account_lcount AS &lv_view;
GRANT SELECT ON sopuli_lv_owner.account_lcount TO sopuli_lv_svc;
PROMPT
PROMPT == LV1d  sopuli_lv_reader: READ ON SYS.USER$ WITH GRANT OPTION, its view, GRANT READ to the tool account
GRANT READ ON sys.user$ TO sopuli_lv_reader WITH GRANT OPTION;
CREATE VIEW sopuli_lv_reader.account_lcount AS &lv_view;
GRANT READ ON sopuli_lv_reader.account_lcount TO sopuli_lv_svc;
PROMPT
PROMPT == LV1e  the view in SYS's schema, granted to the tool account
CREATE VIEW sys.sopuli_lv_lcount AS &lv_view;
GRANT SELECT ON sys.sopuli_lv_lcount TO sopuli_lv_svc;
PROMPT
PROMPT == the grants on the three views
SELECT owner, table_name, grantee, privilege FROM dba_tab_privs
 WHERE grantee = 'SOPULI_LV_SVC' AND table_name IN ('ACCOUNT_LCOUNT', 'SOPULI_LV_LCOUNT')
 ORDER BY owner;

PROMPT
PROMPT == LV1f  sopuli_lv_dba, holding DBA, creates the view in its own schema
CONNECT sopuli_lv_dba/"Sopuli_Lv_Dba_1"@&pdb
CREATE VIEW sopuli_lv_dba.account_lcount AS &lv_view;
PROMPT
PROMPT == LV1g  sopuli_lv_dba grants SYS.USER$ WITH GRANT OPTION to sopuli_lv_byd, as GRANT ANY OBJECT PRIVILEGE might
GRANT SELECT ON sys.user$ TO sopuli_lv_byd WITH GRANT OPTION;
GRANT READ ON sys.user$ TO sopuli_lv_byd WITH GRANT OPTION;
GRANT SELECT ON sys.user$ TO sopuli_lv_byd;
CONNECT sys/"&pwd"@&pdb AS SYSDBA
SELECT grantee, privilege, grantable FROM dba_tab_privs WHERE grantee = 'SOPULI_LV_BYD';

PROMPT
PROMPT == LV2a  as the tool account: the columns, the text, the rows against DBA_USERS
CONNECT sopuli_lv_svc/"Sopuli_Lv_Svc_1"@&pdb
SELECT owner, table_name, column_name, data_type FROM all_tab_columns
 WHERE table_name IN ('ACCOUNT_LCOUNT', 'SOPULI_LV_LCOUNT') ORDER BY owner, column_id;
SELECT owner, text_vc FROM all_views WHERE view_name IN ('ACCOUNT_LCOUNT', 'SOPULI_LV_LCOUNT') ORDER BY owner;
SELECT (SELECT COUNT(*) FROM sopuli_lv_owner.account_lcount) owner_rows,
       (SELECT COUNT(*) FROM sopuli_lv_reader.account_lcount) reader_rows,
       (SELECT COUNT(*) FROM sys.sopuli_lv_lcount) sys_rows,
       (SELECT COUNT(*) FROM dba_users) dba_users_rows,
       (SELECT COUNT(*) FROM sopuli_lv_owner.account_lcount v
         WHERE NOT EXISTS (SELECT 1 FROM dba_users d WHERE d.username = v.name)) not_in_dba_users,
       (SELECT COUNT(*) FROM dba_users d
         WHERE NOT EXISTS (SELECT 1 FROM sopuli_lv_owner.account_lcount v WHERE v.name = d.username)) not_in_view
  FROM dual;
PROMPT
PROMPT == LV2b  a column the view does not have, and SYS.USER$ itself
SELECT spare4 FROM sopuli_lv_owner.account_lcount WHERE ROWNUM = 1;
SELECT COUNT(*) FROM sys.user$;

PROMPT
PROMPT == LV2c  two wrong passwords to acme_lv_app
CONNECT acme_lv_app/"wrong-1"@&pdb
CONNECT acme_lv_app/"wrong-2"@&pdb
CONNECT sopuli_lv_svc/"Sopuli_Lv_Svc_1"@&pdb
SELECT 'owner view' src, name, lcount FROM sopuli_lv_owner.account_lcount WHERE name = 'ACME_LV_APP'
UNION ALL SELECT 'reader view', name, lcount FROM sopuli_lv_reader.account_lcount WHERE name = 'ACME_LV_APP'
UNION ALL SELECT 'sys view', name, lcount FROM sys.sopuli_lv_lcount WHERE name = 'ACME_LV_APP';
CONNECT sys/"&pwd"@&pdb AS SYSDBA
SELECT 'SYS.USER$' src, name, lcount FROM sys.user$ WHERE name = 'ACME_LV_APP';
PROMPT
PROMPT == LV2d  a good login, then the view
CONNECT acme_lv_app/"Acme_Lv_App_1"@&pdb
CONNECT sopuli_lv_svc/"Sopuli_Lv_Svc_1"@&pdb
SELECT name, lcount FROM sopuli_lv_owner.account_lcount WHERE name = 'ACME_LV_APP';

PROMPT
PROMPT == LV3a  a view that does not exist, and a view the tool account holds no grant on
CONNECT sys/"&pwd"@&pdb AS SYSDBA
CREATE VIEW sopuli_lv_owner.ungranted AS &lv_view;
CONNECT sopuli_lv_svc/"Sopuli_Lv_Svc_1"@&pdb
SELECT COUNT(*) FROM sopuli_lv_owner.no_such_view;
SELECT COUNT(*) FROM sopuli_lv_owner.ungranted;
SELECT COUNT(*) columns_seen FROM all_tab_columns WHERE owner = 'SOPULI_LV_OWNER' AND table_name IN ('NO_SUCH_VIEW', 'UNGRANTED');
PROMPT
PROMPT == LV3b  the owner loses SELECT ON SYS.USER$
CONNECT sys/"&pwd"@&pdb AS SYSDBA
REVOKE SELECT ON sys.user$ FROM sopuli_lv_owner;
SELECT owner, object_name, status FROM dba_objects WHERE owner = 'SOPULI_LV_OWNER' AND object_name = 'ACCOUNT_LCOUNT';
SELECT owner, table_name, grantee, privilege FROM dba_tab_privs
 WHERE grantee = 'SOPULI_LV_SVC' AND owner = 'SOPULI_LV_OWNER';
CONNECT sopuli_lv_svc/"Sopuli_Lv_Svc_1"@&pdb
SELECT COUNT(*) FROM sopuli_lv_owner.account_lcount;
SELECT COUNT(*) columns_seen FROM all_tab_columns WHERE owner = 'SOPULI_LV_OWNER' AND table_name = 'ACCOUNT_LCOUNT';
PROMPT
PROMPT == LV3c  the owner's grant comes back, WITH GRANT OPTION
CONNECT sys/"&pwd"@&pdb AS SYSDBA
GRANT SELECT ON sys.user$ TO sopuli_lv_owner WITH GRANT OPTION;
CONNECT sopuli_lv_svc/"Sopuli_Lv_Svc_1"@&pdb
SELECT COUNT(*) FROM sopuli_lv_owner.account_lcount;
CONNECT sys/"&pwd"@&pdb AS SYSDBA
SELECT owner, object_name, status FROM dba_objects WHERE owner = 'SOPULI_LV_OWNER' AND object_name = 'ACCOUNT_LCOUNT';
SELECT owner, table_name, grantee, privilege FROM dba_tab_privs
 WHERE grantee = 'SOPULI_LV_SVC' AND owner = 'SOPULI_LV_OWNER';

PROMPT
PROMPT == LV4  SELECT ... FOR UPDATE NOWAIT by the tool account, through SELECT and through READ
GRANT SELECT ON sys.v_$locked_object TO sopuli_lv_svc;
GRANT SELECT ON sys.dba_objects TO sopuli_lv_svc;
CONNECT sopuli_lv_svc/"Sopuli_Lv_Svc_1"@&pdb
PROMPT -- through the SELECT grant
SELECT name FROM sopuli_lv_owner.account_lcount WHERE name = 'ACME_LV_APP' FOR UPDATE NOWAIT;
SELECT o.owner, o.object_name, l.locked_mode FROM v$locked_object l JOIN dba_objects o ON o.object_id = l.object_id
 WHERE l.session_id = SYS_CONTEXT('USERENV', 'SID');
ROLLBACK;
PROMPT -- through the READ grant
SELECT name FROM sopuli_lv_reader.account_lcount WHERE name = 'ACME_LV_APP' FOR UPDATE NOWAIT;
SELECT o.owner, o.object_name, l.locked_mode FROM v$locked_object l JOIN dba_objects o ON o.object_id = l.object_id
 WHERE l.session_id = SYS_CONTEXT('USERENV', 'SID');
ROLLBACK;
PROMPT -- through READ ON SYS.USER$ itself, in place of 00_install.sql's SELECT: a read, then FOR UPDATE
CONNECT sys/"&pwd"@&pdb AS SYSDBA
GRANT READ ON sys.user$ TO sopuli_lv_svc;
CONNECT sopuli_lv_svc/"Sopuli_Lv_Svc_1"@&pdb
SELECT name, lcount FROM sys.user$ WHERE name = 'ACME_LV_APP';
SELECT name FROM sys.user$ WHERE name = 'ACME_LV_APP' FOR UPDATE NOWAIT;
ROLLBACK;
PROMPT -- through SELECT ON SYS.USER$ itself, as 00_install.sql grants it with grant_user_dollar=Y
CONNECT sys/"&pwd"@&pdb AS SYSDBA
REVOKE READ ON sys.user$ FROM sopuli_lv_svc;
GRANT SELECT ON sys.user$ TO sopuli_lv_svc;
CONNECT sopuli_lv_svc/"Sopuli_Lv_Svc_1"@&pdb
SELECT name FROM sys.user$ WHERE name = 'ACME_LV_APP' FOR UPDATE NOWAIT;
SELECT o.owner, o.object_name, l.locked_mode FROM v$locked_object l JOIN dba_objects o ON o.object_id = l.object_id
 WHERE l.session_id = SYS_CONTEXT('USERENV', 'SID');
ROLLBACK;
CONNECT sys/"&pwd"@&pdb AS SYSDBA
REVOKE SELECT ON sys.user$ FROM sopuli_lv_svc;
REVOKE SELECT ON sys.v_$locked_object FROM sopuli_lv_svc;
REVOKE SELECT ON sys.dba_objects FROM sopuli_lv_svc;

PROMPT
PROMPT == LV5a  sopuli_lv_dba's own SELECT on SYS.USER$'s SPARE4
CONNECT sopuli_lv_dba/"Sopuli_Lv_Dba_1"@&pdb
SELECT COUNT(spare4) FROM sys.user$;
PROMPT
PROMPT == LV5b  sopuli_lv_dba: the narrow view in sopuli_lv_plain's schema, with no grant on it
SELECT COUNT(*) plain_rows FROM sopuli_lv_plain.account_lcount;
PROMPT
PROMPT == LV5c  sopuli_lv_dba: a view of its own making in sopuli_lv_plain's schema, over NAME and SPARE4
CREATE VIEW sopuli_lv_plain.wide AS SELECT name, spare4 FROM sys.user$;
SELECT COUNT(spare4) rows_with_verifier, SUM(CASE WHEN spare4 LIKE 'S:%' THEN 1 ELSE 0 END) rows_with_s FROM sopuli_lv_plain.wide;
PROMPT
PROMPT == LV5d  sopuli_lv_dba: the same in sopuli_lv_reader's schema, which holds READ
CREATE VIEW sopuli_lv_reader.wide AS SELECT name, spare4 FROM sys.user$;
SELECT COUNT(spare4) rows_with_verifier FROM sopuli_lv_reader.wide;
PROMPT
PROMPT == LV5e  sopuli_lv_dba: the same in SYS's schema, and SYS's narrow view
CREATE VIEW sys.sopuli_lv_wide AS SELECT name, spare4 FROM sys.user$;
SELECT COUNT(spare4) rows_with_verifier FROM sys.sopuli_lv_wide;
SELECT COUNT(*) sys_rows FROM sys.sopuli_lv_lcount;
PROMPT
PROMPT == LV5f  sopuli_lv_dba: the same in the tool account's schema, once it holds SELECT ON SYS.USER$ itself, as grant_user_dollar=Y gives
CONNECT sys/"&pwd"@&pdb AS SYSDBA
GRANT SELECT ON sys.user$ TO sopuli_lv_svc;
CONNECT sopuli_lv_dba/"Sopuli_Lv_Dba_1"@&pdb
CREATE VIEW sopuli_lv_svc.wide AS SELECT name, spare4 FROM sys.user$;
SELECT COUNT(spare4) rows_with_verifier FROM sopuli_lv_svc.wide;
CONNECT sys/"&pwd"@&pdb AS SYSDBA
DROP VIEW sopuli_lv_svc.wide;
REVOKE SELECT ON sys.user$ FROM sopuli_lv_svc;

PROMPT
PROMPT == LV6  a unified audit policy on SYS.USER$ and the view, by the tool account
CONNECT sys/"&pwd"@&pdb AS SYSDBA
CREATE AUDIT POLICY sopuli_lv_pol ACTIONS SELECT ON sys.user$, SELECT ON sopuli_lv_owner.account_lcount;
AUDIT POLICY sopuli_lv_pol BY sopuli_lv_svc;
CONNECT sopuli_lv_svc/"Sopuli_Lv_Svc_1"@&pdb
COLUMN lv_session NEW_VALUE lv_session NOPRINT
SELECT SYS_CONTEXT('USERENV', 'UNIFIED_AUDIT_SESSIONID') lv_session FROM dual;
SELECT COUNT(*) FROM sopuli_lv_owner.account_lcount;
SELECT lcount FROM sopuli_lv_owner.account_lcount WHERE name = 'ACME_LV_APP';
CONNECT sys/"&pwd"@&pdb AS SYSDBA
-- This session's rows alone, so that rows from an earlier run do not count.
SELECT object_schema, object_name, action_name, COUNT(*) audit_rows FROM unified_audit_trail
 WHERE sessionid = &lv_session AND unified_audit_policies LIKE '%SOPULI_LV_POL%'
 GROUP BY object_schema, object_name, action_name ORDER BY object_schema, object_name;
NOAUDIT POLICY sopuli_lv_pol BY sopuli_lv_svc;
DROP AUDIT POLICY sopuli_lv_pol;

PROMPT
PROMPT == LV3d  the owner is dropped
DROP USER sopuli_lv_owner CASCADE;
CONNECT sopuli_lv_svc/"Sopuli_Lv_Svc_1"@&pdb
SELECT COUNT(*) FROM sopuli_lv_owner.account_lcount;

CONNECT sys/"&pwd"@&pdb AS SYSDBA
BEGIN
  FOR v IN (SELECT view_name FROM dba_views WHERE owner = 'SYS' AND view_name LIKE 'SOPULI_LV%') LOOP
    EXECUTE IMMEDIATE 'DROP VIEW sys.' || v.view_name;
  END LOOP;
  FOR u IN (SELECT username FROM dba_users WHERE username LIKE 'ACME_LV%' OR username LIKE 'SOPULI_LV%') LOOP
    EXECUTE IMMEDIATE 'DROP USER ' || u.username || ' CASCADE';
  END LOOP;
  FOR p IN (SELECT DISTINCT profile FROM dba_profiles WHERE profile = 'ACME_LV_PROF') LOOP
    EXECUTE IMMEDIATE 'DROP PROFILE acme_lv_prof CASCADE';
  END LOOP;
END;
/
PROMPT
PROMPT == done
EXIT
