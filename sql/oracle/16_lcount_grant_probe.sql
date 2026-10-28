--------------------------------------------------------------------------------
-- sopuli-dba : does SELECT_CATALOG_ROLE show LCOUNT without the verifiers?   (v1)
--
-- #124, the `lcount-grant` register entry (docs/README.md). check's LCOUNT
-- guard reads SYS.USER$.LCOUNT, and SELECT ON SYS.USER$ also exposes every
-- verifier in SPARE4. A blog post says the Data Pump views SYS.KU$_USER_VIEW
-- and SYS.KU$_USER_BASE_VIEW, granted to PUBLIC, show LCOUNT to a session
-- holding SELECT_CATALOG_ROLE and mask the verifiers unless it also holds
-- EXP_FULL_DATABASE. This measures that claim:
--
--   LG0  as SYS: which of the two views exist, who holds a grant on them,
--        their columns, and what EXP_FULL_DATABASE holds
--   LG1  as SYS: the target account's LCOUNT and PTIME in SYS.USER$, after
--        three failed logins, and a fingerprint of its verifiers (the tags in
--        PASSWORD and SPARE4, and ORA_HASH of each). No verifier is printed
--   LG2  in the PDB, the same read through KU$_USER_VIEW, by one account per
--        role combination:
--          acme_lc_none    CREATE SESSION only
--          acme_lc_cat     + SELECT_CATALOG_ROLE
--          acme_lc_cat     the same, after SET ROLE NONE
--          acme_lc_exp     + SELECT_CATALOG_ROLE and EXP_FULL_DATABASE
--          acme_lc_dollar  + SELECT ON SYS.USER$ only, the grant 00_install.sql
--                          makes when grant_user_dollar=Y
--          acme_lc_both    + SELECT_CATALOG_ROLE and SELECT ON SYS.USER$
--        and each account's read of KU$_USER_BASE_VIEW
--   LG3  in CDB$ROOT and in the PDB, the same read by common accounts, of a
--        common target whose failed logins differ between the two containers
--   LG4  in the PDB, what a read leaves in UNIFIED_AUDIT_TRAIL under a policy
--        on SELECT ON SYS.KU$_USER_VIEW and one on SELECT ON SYS.USER$
--
-- This MEASURES and decides nothing. What 00_install.sql recommends is #124's
-- decision.
--
-- STATUS: run 2026-10-28 on 26ai Free 23.26.3.0.0 (gvenzl/oracle-free:latest,
-- FREEPDB1 and CDB$ROOT), twice, with the same results apart from timestamps
-- and the hashes of new verifiers. Every other release UNRUN, the 19.3 base
-- release among them.
--
--
-- RESULTS -- 26ai Free 23.26.3.0.0, 2026-10-28
--
--   LG0  KU$_USER_VIEW exists, and PUBLIC holds READ on it. KU$_USER_BASE_VIEW
--        does not exist: ORA-00942 for every account, SYS included. The view
--        has 33 columns, among them LCOUNT, PTIME (a string,
--        YYYY/MM/DD HH24:MI:SS), PASSWORD, SPARE4 and SPARE4_12.
--        EXP_FULL_DATABASE holds SELECT_CATALOG_ROLE and EXECUTE_CATALOG_ROLE.
--        SELECT_CATALOG_ROLE holds 5663 object grants. The view's text has two
--        branches joined by UNION ALL. The first returns the verifiers, and
--        requires DBMS_METADATA.READ_ALLOWED('USER$') and one of the roles
--        EXP_FULL_DATABASE, DATAPUMP_CLOUD_EXP or SELECT_CATALOG_ROLE in
--        SESSION_ROLES. LG4 shows what READ_ALLOWED checks
--
--   LG1  SYS.USER$ after three failed logins: LCOUNT 3, PTIME set, PASSWORD
--        NULL, SPARE4 holding S: and T:. The view read as SYS gives the same
--        LCOUNT and PTIME, SPARE4 with S: only, and SPARE4_12 with S: and T:
--
--   LG2  in FREEPDB1:
--
--          account         rows  LCOUNT  PTIME  PASSWORD  SPARE4
--          acme_lc_none       0  -       -      -         -
--          acme_lc_cat       39  3       set    NULL      one space
--          after SET ROLE     0  -       -      -         -
--          acme_lc_exp       39  3       set    NULL      one space
--          acme_lc_dollar     0  -       -      -         -
--          acme_lc_both      39  3       set    NULL      the verifiers
--
--        "rows" is every row the account sees, its own included. LCOUNT and
--        PTIME equal SYS.USER$'s. "one space" is SPARE4 on every row, DUMP
--        Typ=1 Len=1: 32: one value, not NULL and not absent, and SPARE4_12 is
--        NULL. acme_lc_both sees 38 distinct SPARE4 values and SPARE4_12 with
--        S: and T:, as SYS does. So:
--          - SELECT_CATALOG_ROLE alone shows LCOUNT and PTIME, and masks the
--            verifiers;
--          - EXP_FULL_DATABASE adds nothing in a plain SQL session. It does
--            not unmask the verifiers, as the blog post says it does;
--          - SELECT ON SYS.USER$ beside the role unmasks them;
--          - the role must be enabled in the session. With no role, the view
--            shows no rows at all, not even the reader's own
--
--   LG3  c##acme_lc_target failed four logins in CDB$ROOT and two in FREEPDB1.
--        SYS.USER$ then holds LCOUNT 6 in CDB$ROOT and 0 in FREEPDB1: the
--        failed logins in the PDB were counted in the root's row. Through the
--        view, a common account holding SELECT_CATALOG_ROLE sees what
--        SYS.USER$ holds in the container it is connected to: 6 in CDB$ROOT,
--        0 in FREEPDB1, with SPARE4 masked in both. In FREEPDB1 the common
--        target's PTIME is NULL. A common account with no role sees no rows in
--        CDB$ROOT either
--
--   LG4  under a policy on SELECT ON SYS.KU$_USER_VIEW and one on SELECT ON
--        SYS.USER$, one read of one row through the view leaves, under the
--        reader's own name:
--          - one row for KU$_USER_VIEW and six for USER$, with the reader's
--            statement as SQL_TEXT, with or without the role;
--          - with the role, 74 more USER$ rows for a recursive statement: the
--            READ_ALLOWED check. It is true when USER_TAB_PRIVS holds SELECT
--            or READ on SYS.USER$, when an enabled role holds one
--            (ROLE_TAB_PRIVS joined to SESSION_ROLES), or for SYS.
--        A direct read of SYS.USER$ leaves one row. So a policy on SYS.USER$
--        alone records a read through the view as well as a direct read, both
--        under the reader's name, and only SQL_TEXT tells them apart. It
--        records a read by an account with no role too, which returns no row
--
-- HOW TO RUN
--   As SYS, in the PDB and in CDB$ROOT. Against the tier-1 stack, whose SYS
--   and SYSTEM password is the public one in test/compose.yaml, as it stands:
--
--     MSYS_NO_PATHCONV=1 docker exec -i sopuli-test-oracle-free-1 \
--       sqlplus -S /nolog < 16_lcount_grant_probe.sql
--
--   A second clone's stack names the container after its COMPOSE_PROJECT_NAME,
--   such as sopuli-test-w2-oracle-free-1. /nolog, and every CONNECT made from
--   the script, so no password is ever in argv (invariant 1). Against any other
--   database, copy the file, edit the three DEFINEs in the copy, run the copy
--   and delete it -- never substitute them with sed, which puts the password in
--   argv instead. MSYS_NO_PATHCONV is for Git Bash, which otherwise rewrites
--   /nolog.
--
-- WHENEVER SQLERROR is CONTINUE throughout: the failed logins, and the reads
-- that a role combination is expected to be refused, are the question.
--
-- THROWAWAY DATABASES ONLY. Creates and drops local and common accounts, a
-- profile and two audit policies, fails logins on purpose, grants
-- SELECT_CATALOG_ROLE, EXP_FULL_DATABASE and SELECT ON SYS.USER$, and leaves
-- rows in UNIFIED_AUDIT_TRAIL.
--------------------------------------------------------------------------------
define pdb  = //localhost:1521/FREEPDB1
define root = //localhost:1521/FREE
define pwd  = sopuli-test

WHENEVER SQLERROR CONTINUE
SET LINESIZE 250 PAGESIZE 100 FEEDBACK OFF VERIFY OFF HEADING ON
COLUMN who        FORMAT A16
COLUMN con        FORMAT A9
COLUMN name       FORMAT A18
COLUMN ptime      FORMAT A19
COLUMN pw         FORMAT A5
COLUMN pw_tags    FORMAT A7
COLUMN s4         FORMAT A5
COLUMN s4_tags    FORMAT A7
COLUMN s4_12_tags FORMAT A10
COLUMN owner      FORMAT A6
COLUMN view_name  FORMAT A20
COLUMN grantee    FORMAT A20
COLUMN privilege  FORMAT A9
COLUMN granted_role FORMAT A24
COLUMN column_name FORMAT A20
COLUMN data_type  FORMAT A28
COLUMN dbusername FORMAT A16
COLUMN action_name FORMAT A8
COLUMN object_name FORMAT A14
COLUMN policies   FORMAT A20
COLUMN sql_text   FORMAT A60 WORD_WRAPPED
COLUMN object_schema FORMAT A6
COLUMN spare4_if_constant FORMAT A70

-- One read of the target accounts through the view, the same for every
-- account. The tags are the letters before each ':' in a verifier column, such
-- as S;T for SPARE4; ORA_HASH tells whether two reads returned the same value.
-- The count DUMPs SPARE4 only where every row the reader sees holds the same
-- value, which no real verifier does.
-- Each starts after SELECT: SQL*Plus does not substitute the first word of a
-- command.
define ku_read = "sys_context('userenv','session_user') who, sys_context('userenv','con_name') con, name, lcount, ptime, nvl2(password,'set','NULL') pw, ora_hash(password) pw_hash, nvl2(spare4,'set','NULL') s4, regexp_replace(spare4,'([A-Za-z]):[^;]*','\1') s4_tags, ora_hash(spare4) s4_hash, regexp_replace(spare4_12,'([A-Za-z]):[^;]*','\1') s4_12_tags FROM sys.ku$_user_view"
define ku_count = "count(*) rows_seen, count(lcount) lcount_set, count(password) password_set, count(spare4) spare4_set, count(DISTINCT spare4) spare4_distinct, CASE WHEN count(DISTINCT spare4) = 1 THEN dump(max(spare4)) END spare4_if_constant FROM sys.ku$_user_view"
define base_read = "name, lcount FROM sys.ku$_user_base_view WHERE name = 'ACME_LC_TARGET'"

-------------------------------------------------------------------- setup ----
CONNECT sys/"&pwd"@&pdb AS SYSDBA

BEGIN
  FOR u IN (SELECT username FROM dba_users WHERE username LIKE 'ACME\_LC\_%' ESCAPE '\') LOOP
    EXECUTE IMMEDIATE 'DROP USER ' || u.username || ' CASCADE';
  END LOOP;
  FOR p IN (SELECT policy_name FROM audit_unified_enabled_policies
             WHERE policy_name IN ('ACME_LC_KU_READ','ACME_LC_USER_READ')) LOOP
    EXECUTE IMMEDIATE 'NOAUDIT POLICY ' || p.policy_name;
  END LOOP;
  FOR p IN (SELECT DISTINCT policy_name FROM audit_unified_policies
             WHERE policy_name IN ('ACME_LC_KU_READ','ACME_LC_USER_READ')) LOOP
    EXECUTE IMMEDIATE 'DROP AUDIT POLICY ' || p.policy_name;
  END LOOP;
  EXECUTE IMMEDIATE 'DROP PROFILE acme_lc_prof CASCADE';
EXCEPTION WHEN OTHERS THEN NULL;
END;
/

COLUMN t0 NEW_VALUE t0 NOPRINT
SELECT to_char(sys_extract_utc(systimestamp),'YYYY-MM-DD HH24:MI:SS.FF6') t0 FROM dual;

CREATE PROFILE acme_lc_prof LIMIT FAILED_LOGIN_ATTEMPTS 10 PASSWORD_LOCK_TIME 1;
CREATE USER acme_lc_target IDENTIFIED BY "Acme_Lc_Target_1" PROFILE acme_lc_prof;
GRANT CREATE SESSION TO acme_lc_target;
CREATE USER acme_lc_none   IDENTIFIED BY "Acme_Lc_None_1";
CREATE USER acme_lc_cat    IDENTIFIED BY "Acme_Lc_Cat_1";
CREATE USER acme_lc_exp    IDENTIFIED BY "Acme_Lc_Exp_1";
CREATE USER acme_lc_dollar IDENTIFIED BY "Acme_Lc_Dollar_1";
CREATE USER acme_lc_both   IDENTIFIED BY "Acme_Lc_Both_1";
GRANT CREATE SESSION TO acme_lc_none, acme_lc_cat, acme_lc_exp, acme_lc_dollar, acme_lc_both;
GRANT SELECT_CATALOG_ROLE TO acme_lc_cat, acme_lc_exp, acme_lc_both;
GRANT EXP_FULL_DATABASE TO acme_lc_exp;
GRANT SELECT ON sys.user$ TO acme_lc_dollar, acme_lc_both;

PROMPT
PROMPT == LG0: the release, the views, their grants and columns
SELECT version_full FROM v$instance;
SELECT owner, view_name FROM dba_views
 WHERE view_name IN ('KU$_USER_VIEW','KU$_USER_BASE_VIEW') ORDER BY view_name;
SELECT grantee, privilege, table_name view_name FROM dba_tab_privs
 WHERE table_name IN ('KU$_USER_VIEW','KU$_USER_BASE_VIEW') ORDER BY 3, 1;
SELECT column_name, data_type FROM dba_tab_columns
 WHERE owner = 'SYS' AND table_name = 'KU$_USER_VIEW' ORDER BY column_id;
SELECT granted_role FROM dba_role_privs WHERE grantee = 'EXP_FULL_DATABASE' ORDER BY 1;
SELECT role FROM dba_roles WHERE role IN ('DATAPUMP_CLOUD_EXP','SELECT_CATALOG_ROLE','EXP_FULL_DATABASE') ORDER BY 1;
SELECT count(*) select_catalog_role_object_grants FROM dba_tab_privs WHERE grantee = 'SELECT_CATALOG_ROLE';

PROMPT
PROMPT == three failed logins as acme_lc_target (ORA-01017 expected, three times)
CONNECT acme_lc_target/"wrong-1"@&pdb
CONNECT acme_lc_target/"wrong-2"@&pdb
CONNECT acme_lc_target/"wrong-3"@&pdb

CONNECT sys/"&pwd"@&pdb AS SYSDBA
PROMPT
PROMPT == LG1: SYS.USER$ as SYS, the reference values
SELECT name, lcount, to_char(ptime,'YYYY/MM/DD HH24:MI:SS') ptime,
       nvl2(password,'set','NULL') pw, ora_hash(password) pw_hash,
       nvl2(spare4,'set','NULL') s4,
       regexp_replace(spare4,'([A-Za-z]):[^;]*','\1') s4_tags, ora_hash(spare4) s4_hash
  FROM sys.user$ WHERE name = 'ACME_LC_TARGET';
PROMPT -- the view read as SYS
SELECT &ku_read WHERE name = 'ACME_LC_TARGET';

PROMPT
PROMPT == LG2: KU$_USER_VIEW by role combination, in the PDB

CONNECT acme_lc_none/"Acme_Lc_None_1"@&pdb
PROMPT -- acme_lc_none: CREATE SESSION only
SELECT role FROM session_roles;
SELECT &ku_count;
SELECT &ku_read WHERE name IN ('ACME_LC_TARGET','ACME_LC_NONE');
SELECT &base_read;

CONNECT acme_lc_cat/"Acme_Lc_Cat_1"@&pdb
PROMPT -- acme_lc_cat: SELECT_CATALOG_ROLE
SELECT role FROM session_roles;
SELECT &ku_count;
SELECT &ku_read WHERE name = 'ACME_LC_TARGET';
SELECT &base_read;
PROMPT -- acme_lc_cat: the same account after SET ROLE NONE
SET ROLE NONE;
SELECT &ku_count;
SELECT &ku_read WHERE name IN ('ACME_LC_TARGET','ACME_LC_CAT');

CONNECT acme_lc_exp/"Acme_Lc_Exp_1"@&pdb
PROMPT -- acme_lc_exp: SELECT_CATALOG_ROLE and EXP_FULL_DATABASE
SELECT role FROM session_roles;
SELECT &ku_count;
SELECT &ku_read WHERE name = 'ACME_LC_TARGET';
SELECT &base_read;

CONNECT acme_lc_dollar/"Acme_Lc_Dollar_1"@&pdb
PROMPT -- acme_lc_dollar: SELECT ON SYS.USER$ only
SELECT role FROM session_roles;
SELECT &ku_count;
SELECT &ku_read WHERE name IN ('ACME_LC_TARGET','ACME_LC_DOLLAR');
SELECT &base_read;
SELECT name, lcount FROM sys.user$ WHERE name = 'ACME_LC_TARGET';

CONNECT acme_lc_both/"Acme_Lc_Both_1"@&pdb
PROMPT -- acme_lc_both: SELECT_CATALOG_ROLE and SELECT ON SYS.USER$
SELECT role FROM session_roles;
SELECT &ku_count;
SELECT &ku_read WHERE name = 'ACME_LC_TARGET';

------------------------------------------------------- LG3: CDB$ROOT ----
CONNECT sys/"&pwd"@&root AS SYSDBA
BEGIN
  FOR u IN (SELECT username FROM dba_users WHERE username LIKE 'C##ACME\_LC\_%' ESCAPE '\') LOOP
    EXECUTE IMMEDIATE 'DROP USER ' || u.username || ' CASCADE';
  END LOOP;
  EXECUTE IMMEDIATE 'DROP PROFILE c##acme_lc_prof CASCADE';
EXCEPTION WHEN OTHERS THEN NULL;
END;
/
CREATE PROFILE c##acme_lc_prof LIMIT FAILED_LOGIN_ATTEMPTS 10 PASSWORD_LOCK_TIME 1 CONTAINER = ALL;
CREATE USER c##acme_lc_target IDENTIFIED BY "Acme_Lc_Ctarget_1" PROFILE c##acme_lc_prof CONTAINER = ALL;
CREATE USER c##acme_lc_cat    IDENTIFIED BY "Acme_Lc_Ccat_1" CONTAINER = ALL;
CREATE USER c##acme_lc_none   IDENTIFIED BY "Acme_Lc_Cnone_1" CONTAINER = ALL;
GRANT CREATE SESSION TO c##acme_lc_target, c##acme_lc_cat, c##acme_lc_none CONTAINER = ALL;
GRANT SELECT_CATALOG_ROLE TO c##acme_lc_cat CONTAINER = ALL;

PROMPT
PROMPT == LG3: failed logins as c##acme_lc_target, four in CDB$ROOT and two in the PDB
CONNECT c##acme_lc_target/"wrong-1"@&root
CONNECT c##acme_lc_target/"wrong-2"@&root
CONNECT c##acme_lc_target/"wrong-3"@&root
CONNECT c##acme_lc_target/"wrong-4"@&root
CONNECT c##acme_lc_target/"wrong-1"@&pdb
CONNECT c##acme_lc_target/"wrong-2"@&pdb

CONNECT sys/"&pwd"@&root AS SYSDBA
PROMPT -- SYS.USER$ as SYS in CDB$ROOT
SELECT sys_context('userenv','con_name') con, name, lcount,
       nvl2(spare4,'set','NULL') s4, ora_hash(spare4) s4_hash
  FROM sys.user$ WHERE name = 'C##ACME_LC_TARGET';
CONNECT sys/"&pwd"@&pdb AS SYSDBA
PROMPT -- SYS.USER$ as SYS in the PDB
SELECT sys_context('userenv','con_name') con, name, lcount,
       nvl2(spare4,'set','NULL') s4, ora_hash(spare4) s4_hash
  FROM sys.user$ WHERE name = 'C##ACME_LC_TARGET';

CONNECT c##acme_lc_cat/"Acme_Lc_Ccat_1"@&root
PROMPT -- c##acme_lc_cat: SELECT_CATALOG_ROLE, in CDB$ROOT
SELECT &ku_count;
SELECT &ku_read WHERE name = 'C##ACME_LC_TARGET';
CONNECT c##acme_lc_cat/"Acme_Lc_Ccat_1"@&pdb
PROMPT -- c##acme_lc_cat: SELECT_CATALOG_ROLE, in the PDB
SELECT &ku_count;
SELECT &ku_read WHERE name = 'C##ACME_LC_TARGET';
CONNECT c##acme_lc_none/"Acme_Lc_Cnone_1"@&root
PROMPT -- c##acme_lc_none: CREATE SESSION only, in CDB$ROOT
SELECT &ku_count;
SELECT &ku_read WHERE name IN ('C##ACME_LC_TARGET','C##ACME_LC_NONE');

------------------------------------------------- LG4: the audit trail ----
CONNECT sys/"&pwd"@&pdb AS SYSDBA
PROMPT
PROMPT == LG4: audit policies on SELECT ON SYS.KU$_USER_VIEW and on SELECT ON SYS.USER$
CREATE AUDIT POLICY acme_lc_ku_read   ACTIONS SELECT ON sys.ku$_user_view;
CREATE AUDIT POLICY acme_lc_user_read ACTIONS SELECT ON sys.user$;
AUDIT POLICY acme_lc_ku_read;
AUDIT POLICY acme_lc_user_read;

CONNECT acme_lc_cat/"Acme_Lc_Cat_1"@&pdb
SELECT name, lcount FROM sys.ku$_user_view WHERE name = 'ACME_LC_TARGET';
CONNECT acme_lc_none/"Acme_Lc_None_1"@&pdb
SELECT name, lcount FROM sys.ku$_user_view WHERE name = 'ACME_LC_TARGET';
CONNECT acme_lc_dollar/"Acme_Lc_Dollar_1"@&pdb
SELECT name, lcount FROM sys.user$ WHERE name = 'ACME_LC_TARGET';

CONNECT acme_lc_exp/"Acme_Lc_Exp_1"@&pdb
SELECT name, lcount FROM sys.ku$_user_view WHERE name = 'ACME_LC_TARGET';

-- 23.26 writes the unified trail directly; it has no FLUSH_UNIFIED_AUDIT_TRAIL.
CONNECT sys/"&pwd"@&pdb AS SYSDBA
PROMPT -- the SELECT rows since the script started, one line per account, object
PROMPT -- and statement. The statement is the reader's own, or a recursive one
SELECT dbusername, object_name, policies, sql_text, count(*) n
  FROM (SELECT dbusername, object_name, unified_audit_policies policies,
               substr(regexp_replace(dbms_lob.substr(sql_text, 200, 1), '\s+', ' '), 1, 60) sql_text
          FROM unified_audit_trail
         WHERE event_timestamp_utc > to_timestamp('&t0','YYYY-MM-DD HH24:MI:SS.FF6')
           AND dbusername LIKE 'ACME\_LC\_%' ESCAPE '\'
           AND action_name = 'SELECT')
 GROUP BY dbusername, object_name, policies, sql_text
 ORDER BY dbusername, object_name, sql_text;
PROMPT -- each recursive statement in full
SELECT DISTINCT regexp_replace(dbms_lob.substr(sql_text, 1000, 1), '\s+', ' ') sql_text
  FROM unified_audit_trail
 WHERE event_timestamp_utc > to_timestamp('&t0','YYYY-MM-DD HH24:MI:SS.FF6')
   AND dbusername LIKE 'ACME\_LC\_%' ESCAPE '\'
   AND action_name = 'SELECT'
   AND dbms_lob.instr(sql_text, 'ku$_user_view') = 0
   AND dbms_lob.instr(sql_text, 'FROM sys.user$ WHERE') = 0;

----------------------------------------------------------------- teardown ----
NOAUDIT POLICY acme_lc_ku_read;
NOAUDIT POLICY acme_lc_user_read;
DROP AUDIT POLICY acme_lc_ku_read;
DROP AUDIT POLICY acme_lc_user_read;
DROP USER acme_lc_target CASCADE;
DROP USER acme_lc_none CASCADE;
DROP USER acme_lc_cat CASCADE;
DROP USER acme_lc_exp CASCADE;
DROP USER acme_lc_dollar CASCADE;
DROP USER acme_lc_both CASCADE;
DROP PROFILE acme_lc_prof CASCADE;
CONNECT sys/"&pwd"@&root AS SYSDBA
DROP USER c##acme_lc_target CASCADE;
DROP USER c##acme_lc_cat CASCADE;
DROP USER c##acme_lc_none CASCADE;
DROP PROFILE c##acme_lc_prof CASCADE;
PROMPT
PROMPT == done
EXIT
