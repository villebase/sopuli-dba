--------------------------------------------------------------------------------
-- sopuli-dba : what can UC-5's report commands read?   (v1)
--
-- #1377, the `report-reads` register entry (docs/README.md). UC-5's reports
-- (docs/use-cases/uc-05-fleet-reports.md) read every account on a target, its
-- profile limits, and its effective privileges through nested roles. This
-- measures what an account holding 00_install.sql's grants can read, and what
-- the rest needs:
--
--   RR0  as SYS: which of the columns the reports want exist in DBA_USERS,
--        DBA_PROFILES, DBA_TAB_PRIVS, DBA_SYS_PRIVS and DBA_ROLE_PRIVS
--   RR1  as SYS: fixtures. acme_rr_svc holds the grants 00_install.sql makes
--        for a local service user. acme_rr_app holds SELECT on two tables
--        directly, the default role acme_rr_outer, which holds acme_rr_read
--        (SELECT on three tables, EXECUTE on one procedure, CREATE TABLE),
--        and the non-default role acme_rr_extra (INSERT on one table). One
--        more table is granted to PUBLIC. acme_rr_app is on acme_rr_prof,
--        whose PASSWORD_LIFE_TIME is DEFAULT
--   RR2  as acme_rr_svc: a COUNT(*) from each of DBA_USERS, DBA_PROFILES,
--        DBA_ROLE_PRIVS, DBA_ROLES, DBA_SYS_PRIVS and DBA_TAB_PRIVS
--   RR3  as SYS: SELECT on DBA_SYS_PRIVS and DBA_TAB_PRIVS to acme_rr_svc, and
--        RR2 again; then SELECT ON SYS.USER$ (grant_user_dollar=Y) and a read
--        of NAME, LCOUNT and PTIME for acme_rr_app after two failed logins
--   RR4  as acme_rr_svc: acme_rr_app's effective privileges, by a recursive
--        query over DBA_ROLE_PRIVS joined to DBA_TAB_PRIVS and DBA_SYS_PRIVS,
--        with the role path and the first role's DEFAULT_ROLE
--   RR5  as acme_rr_svc: acme_rr_prof's limits as DBA_PROFILES shows them, and
--        resolved through the DEFAULT profile
--   RR6  in the PDB, as acme_rr_svc: what DBA_USERS and DBA_PROFILES show for
--        a common account on a common profile created in CDB$ROOT
--   RR7  as acme_rr_svc, with SET TIMING ON: RR4's query for every account
--        that Oracle does not maintain, counted only
--
-- This MEASURES and decides nothing. No column holding a verifier is selected
-- anywhere: not PASSWORD, SPARE4 nor SPARE4_12.
--
-- STATUS: run 2026-11-07 on 26ai Free 23.26.3.0.0 (gvenzl/oracle-free:latest,
-- FREEPDB1 and CDB$ROOT), twice, with the same results apart from timestamps
-- and RR7's elapsed time. An earlier run, before RR7's query was corrected,
-- gave the same RR0 to RR6. Every other release UNRUN, the 19.3 base release
-- and 11.2 among them.
--
--
-- RESULTS -- 26ai Free 23.26.3.0.0, 2026-11-07
--
--   RR0  Every column asked for exists: in DBA_USERS PASSWORD_CHANGE_DATE,
--        LAST_LOGIN, ORACLE_MAINTAINED, COMMON, LOCK_DATE, EXPIRY_DATE and
--        INHERITED; in DBA_PROFILES COMMON, INHERITED and IMPLICIT; in
--        DBA_TAB_PRIVS TYPE, COMMON and INHERITED; in DBA_SYS_PRIVS COMMON and
--        INHERITED; in DBA_ROLE_PRIVS DEFAULT_ROLE, COMMON and INHERITED
--   RR2  With 00_install.sql's grants, DBA_USERS (36 rows), DBA_PROFILES (144),
--        DBA_ROLE_PRIVS (202) and DBA_ROLES (112) are read. DBA_SYS_PRIVS and
--        DBA_TAB_PRIVS are refused: ORA-00942, table or view does not exist
--   RR3  After GRANT SELECT ON SYS.DBA_SYS_PRIVS and ON SYS.DBA_TAB_PRIVS, both
--        are read (978 and 14269 rows). After two failed logins, SYS.USER$
--        shows LCOUNT 2 for acme_rr_app to an account holding SELECT ON
--        SYS.USER$. PTIME and DBA_USERS.PASSWORD_CHANGE_DATE give the same
--        time, to the second
--   RR4  The recursive query gives every privilege the fixtures grant, each
--        once, with its path: SELECT on T1 and T2 direct; SELECT on T3, T4 and
--        T5, EXECUTE on P1 (TYPE PROCEDURE) and CREATE TABLE via
--        ACME_RR_OUTER > ACME_RR_READ, DEFAULT_ROLE YES; INSERT on T1 via
--        ACME_RR_EXTRA, DEFAULT_ROLE NO; CREATE SESSION direct. SELECT on T6
--        is found only by reading the grants to PUBLIC: no role path reaches
--        it
--   RR5  DBA_PROFILES shows DEFAULT for each limit acme_rr_prof inherits.
--        Joined to the DEFAULT profile, PASSWORD_LIFE_TIME resolves to
--        UNLIMITED, PASSWORD_LOCK_TIME to 1 and PASSWORD_GRACE_TIME to 7 on
--        this image. FAILED_LOGIN_ATTEMPTS, set on the profile, reads 5
--   RR6  In the PDB, DBA_USERS shows the common account with its common
--        profile, OPEN, COMMON YES and INHERITED YES, and PASSWORD_CHANGE_DATE
--        NULL. DBA_PROFILES shows the common profile's limits, COMMON YES and
--        INHERITED YES. So a PDB has no date of the last password change for a
--        common account, as it has no PTIME for one (#1122)
--   RR7  6 accounts that Oracle does not maintain, 89 object privileges
--        through roles, in 0.15 seconds. A rough cost on an almost empty PDB,
--        not a benchmark
--
--   Cleanup: no account or role named ACME_RR_ is left in any container.
--
-- HOW TO RUN
--   As SYS, in the PDB and in CDB$ROOT. Against the tier-1 stack, whose SYS
--   and SYSTEM password is the public one in test/compose.yaml, as it stands:
--
--     MSYS_NO_PATHCONV=1 docker exec -i sopuli-test-oracle-free-1 \
--       sqlplus -S /nolog < 19_report_read_probe.sql
--
--   A second clone's stack names the container after its COMPOSE_PROJECT_NAME,
--   such as sopuli-test-w2-oracle-free-1. On XE the PDB is XEPDB1 and the root
--   service is XE. /nolog, and every CONNECT made from the script, so no
--   password is ever in argv (invariant 1). Against any other database, copy
--   the file, edit the four DEFINEs in the copy, run the copy and delete it --
--   never substitute them with sed, which puts the password in argv instead.
--   MSYS_NO_PATHCONV is for Git Bash, which otherwise rewrites /nolog.
--
-- WHENEVER SQLERROR is CONTINUE throughout: the reads that a grant is expected
-- to be refused, and the failed logins, are the question.
--
-- THROWAWAY DATABASES ONLY. Creates and drops local and common accounts,
-- roles, profiles, tables and a procedure, fails logins on purpose, and grants
-- SELECT ON SYS.USER$.
--------------------------------------------------------------------------------
define pdb  = //localhost:1521/FREEPDB1
define root = //localhost:1521/FREE
define pwd  = sopuli-test
define pdbname = FREEPDB1

WHENEVER SQLERROR CONTINUE
SET LINESIZE 200 PAGESIZE 200 FEEDBACK OFF VERIFY OFF HEADING ON
COLUMN who            FORMAT A16
COLUMN con            FORMAT A9
COLUMN table_name     FORMAT A16
COLUMN column_name    FORMAT A22
COLUMN username       FORMAT A20
COLUMN name           FORMAT A16
COLUMN profile        FORMAT A18
COLUMN resource_name  FORMAT A22
COLUMN limit          FORMAT A12
COLUMN resolved       FORMAT A12
COLUMN account_status FORMAT A16
COLUMN common         FORMAT A6
COLUMN inherited      FORMAT A9
COLUMN source         FORMAT A40
COLUMN privilege      FORMAT A16
COLUMN object         FORMAT A22
COLUMN type           FORMAT A10
COLUMN first_default  FORMAT A13
COLUMN ptime          FORMAT A19
COLUMN changed        FORMAT A19

define whoami = "sys_context('userenv','session_user') who, sys_context('userenv','con_name') con FROM dual"

-------------------------------------------------------------------- setup ----
CONNECT sys/"&pwd"@&pdb AS SYSDBA
BEGIN
  FOR u IN (SELECT username FROM dba_users WHERE username LIKE 'ACME\_RR\_%' ESCAPE '\') LOOP
    BEGIN EXECUTE IMMEDIATE 'DROP USER ' || u.username || ' CASCADE';
    EXCEPTION WHEN OTHERS THEN NULL; END;
  END LOOP;
  FOR r IN (SELECT role FROM dba_roles WHERE role LIKE 'ACME\_RR\_%' ESCAPE '\') LOOP
    BEGIN EXECUTE IMMEDIATE 'DROP ROLE ' || r.role;
    EXCEPTION WHEN OTHERS THEN NULL; END;
  END LOOP;
  BEGIN EXECUTE IMMEDIATE 'DROP PROFILE acme_rr_prof CASCADE';
  EXCEPTION WHEN OTHERS THEN NULL; END;
END;
/
CONNECT sys/"&pwd"@&root AS SYSDBA
BEGIN
  BEGIN EXECUTE IMMEDIATE 'DROP USER c##acme_rr_common CASCADE';
  EXCEPTION WHEN OTHERS THEN NULL; END;
  BEGIN EXECUTE IMMEDIATE 'DROP PROFILE c##acme_rr_cprof CASCADE';
  EXCEPTION WHEN OTHERS THEN NULL; END;
END;
/

PROMPT
PROMPT == the release
SELECT version_full FROM v$instance;

---------------------------------------------------------- RR0: columns ----
CONNECT sys/"&pwd"@&pdb AS SYSDBA
PROMPT
PROMPT == RR0: the columns that exist (a missing row is a missing column)
SELECT table_name, column_name FROM dba_tab_columns
 WHERE owner = 'SYS'
   AND (   (table_name = 'DBA_USERS' AND column_name IN
             ('PASSWORD_CHANGE_DATE','LAST_LOGIN','ORACLE_MAINTAINED','COMMON',
              'LOCK_DATE','EXPIRY_DATE','INHERITED'))
        OR (table_name = 'DBA_PROFILES'   AND column_name IN ('COMMON','INHERITED','IMPLICIT'))
        OR (table_name = 'DBA_TAB_PRIVS'  AND column_name IN ('TYPE','COMMON','INHERITED'))
        OR (table_name = 'DBA_SYS_PRIVS'  AND column_name IN ('COMMON','INHERITED'))
        OR (table_name = 'DBA_ROLE_PRIVS' AND column_name IN ('DEFAULT_ROLE','COMMON','INHERITED')))
 ORDER BY 1, 2;

--------------------------------------------------------- RR1: fixtures ----
CREATE PROFILE acme_rr_prof LIMIT PASSWORD_LIFE_TIME DEFAULT FAILED_LOGIN_ATTEMPTS 5;

CREATE USER acme_rr_svc IDENTIFIED BY "Acme_Rr_Svc_1";
GRANT CREATE SESSION TO acme_rr_svc;
GRANT ALTER USER     TO acme_rr_svc;
GRANT SELECT ON sys.dba_users      TO acme_rr_svc;
GRANT SELECT ON sys.dba_profiles   TO acme_rr_svc;
GRANT SELECT ON sys.dba_role_privs TO acme_rr_svc;
GRANT SELECT ON sys.dba_roles      TO acme_rr_svc;
GRANT SELECT ON sys.v_$database    TO acme_rr_svc;
GRANT SELECT ON sys.v_$instance    TO acme_rr_svc;

CREATE USER acme_rr_owner IDENTIFIED BY "Acme_Rr_Own_1" QUOTA 10M ON users;
CREATE TABLE acme_rr_owner.t1 (n NUMBER);
CREATE TABLE acme_rr_owner.t2 (n NUMBER);
CREATE TABLE acme_rr_owner.t3 (n NUMBER);
CREATE TABLE acme_rr_owner.t4 (n NUMBER);
CREATE TABLE acme_rr_owner.t5 (n NUMBER);
CREATE TABLE acme_rr_owner.t6 (n NUMBER);
CREATE PROCEDURE acme_rr_owner.p1 AS BEGIN NULL; END;
/

CREATE ROLE acme_rr_read;
CREATE ROLE acme_rr_outer;
CREATE ROLE acme_rr_extra;
GRANT SELECT ON acme_rr_owner.t3 TO acme_rr_read;
GRANT SELECT ON acme_rr_owner.t4 TO acme_rr_read;
GRANT SELECT ON acme_rr_owner.t5 TO acme_rr_read;
GRANT EXECUTE ON acme_rr_owner.p1 TO acme_rr_read;
GRANT CREATE TABLE TO acme_rr_read;
GRANT acme_rr_read TO acme_rr_outer;
GRANT INSERT ON acme_rr_owner.t1 TO acme_rr_extra;
GRANT SELECT ON acme_rr_owner.t6 TO PUBLIC;

CREATE USER acme_rr_app IDENTIFIED BY "Acme_Rr_App_1" PROFILE acme_rr_prof;
GRANT CREATE SESSION TO acme_rr_app;
GRANT SELECT ON acme_rr_owner.t1 TO acme_rr_app;
GRANT SELECT ON acme_rr_owner.t2 TO acme_rr_app;
GRANT acme_rr_outer, acme_rr_extra TO acme_rr_app;
ALTER USER acme_rr_app DEFAULT ROLE acme_rr_outer;

----------------------------------------------- RR2: what 00_install reads ----
CONNECT acme_rr_svc/"Acme_Rr_Svc_1"@&pdb
SELECT &whoami;
PROMPT
PROMPT == RR2: each read as acme_rr_svc (a count, or an ORA- error)
PROMPT -- DBA_USERS
SELECT COUNT(*) FROM dba_users;
PROMPT -- DBA_PROFILES
SELECT COUNT(*) FROM dba_profiles;
PROMPT -- DBA_ROLE_PRIVS
SELECT COUNT(*) FROM dba_role_privs;
PROMPT -- DBA_ROLES
SELECT COUNT(*) FROM dba_roles;
PROMPT -- DBA_SYS_PRIVS
SELECT COUNT(*) FROM dba_sys_privs;
PROMPT -- DBA_TAB_PRIVS
SELECT COUNT(*) FROM dba_tab_privs;

------------------------------------------------ RR3: the grants it needs ----
CONNECT sys/"&pwd"@&pdb AS SYSDBA
GRANT SELECT ON sys.dba_sys_privs TO acme_rr_svc;
GRANT SELECT ON sys.dba_tab_privs TO acme_rr_svc;
CONNECT acme_rr_svc/"Acme_Rr_Svc_1"@&pdb
PROMPT
PROMPT == RR3: after SELECT on DBA_SYS_PRIVS and DBA_TAB_PRIVS
PROMPT -- DBA_SYS_PRIVS
SELECT COUNT(*) FROM dba_sys_privs;
PROMPT -- DBA_TAB_PRIVS
SELECT COUNT(*) FROM dba_tab_privs;

PROMPT
PROMPT == RR3: two failed logins as acme_rr_app (ORA-01017 twice)
CONNECT acme_rr_app/"wrong-1"@&pdb
CONNECT acme_rr_app/"wrong-2"@&pdb
CONNECT sys/"&pwd"@&pdb AS SYSDBA
GRANT SELECT ON sys.user$ TO acme_rr_svc;
CONNECT acme_rr_svc/"Acme_Rr_Svc_1"@&pdb
PROMPT -- SYS.USER$ as acme_rr_svc, after SELECT ON SYS.USER$: NAME, LCOUNT, PTIME only
SELECT name, lcount, to_char(ptime, 'YYYY-MM-DD HH24:MI:SS') ptime
  FROM sys.user$ WHERE name = 'ACME_RR_APP';
PROMPT -- DBA_USERS for the same account
SELECT username, account_status, to_char(password_change_date, 'YYYY-MM-DD HH24:MI:SS') changed
  FROM dba_users WHERE username = 'ACME_RR_APP';

------------------------------------------ RR4: effective privileges ----
PROMPT
PROMPT == RR4: acme_rr_app's effective object privileges, as acme_rr_svc
WITH roles (granted_role, path, first_default) AS (
  SELECT granted_role, granted_role, default_role
    FROM dba_role_privs WHERE grantee = 'ACME_RR_APP'
  UNION ALL
  SELECT p.granted_role, r.path || ' > ' || p.granted_role, r.first_default
    FROM dba_role_privs p JOIN roles r ON p.grantee = r.granted_role
)
SELECT 'direct' source, t.privilege, t.owner || '.' || t.table_name object, t.type, '-' first_default
  FROM dba_tab_privs t WHERE t.grantee = 'ACME_RR_APP'
UNION ALL
SELECT 'via ' || r.path, t.privilege, t.owner || '.' || t.table_name, t.type, r.first_default
  FROM roles r JOIN dba_tab_privs t ON t.grantee = r.granted_role
UNION ALL
SELECT 'PUBLIC', t.privilege, t.owner || '.' || t.table_name, t.type, '-'
  FROM dba_tab_privs t WHERE t.grantee = 'PUBLIC' AND t.owner = 'ACME_RR_OWNER'
 ORDER BY 1, 2, 3;

PROMPT
PROMPT == RR4: acme_rr_app's effective system privileges, as acme_rr_svc
WITH roles (granted_role, path, first_default) AS (
  SELECT granted_role, granted_role, default_role
    FROM dba_role_privs WHERE grantee = 'ACME_RR_APP'
  UNION ALL
  SELECT p.granted_role, r.path || ' > ' || p.granted_role, r.first_default
    FROM dba_role_privs p JOIN roles r ON p.grantee = r.granted_role
)
SELECT 'direct' source, s.privilege, '-' first_default
  FROM dba_sys_privs s WHERE s.grantee = 'ACME_RR_APP'
UNION ALL
SELECT 'via ' || r.path, s.privilege, r.first_default
  FROM roles r JOIN dba_sys_privs s ON s.grantee = r.granted_role
 ORDER BY 1, 2;

PROMPT
PROMPT == RR4: the roles granted to acme_rr_app
SELECT granted_role, admin_option, default_role FROM dba_role_privs
 WHERE grantee = 'ACME_RR_APP' ORDER BY 1;

------------------------------------------- RR5: DEFAULT profile limits ----
PROMPT
PROMPT == RR5: acme_rr_prof's limits, as shown and resolved through DEFAULT
SELECT p.resource_name, p.limit,
       CASE WHEN p.limit = 'DEFAULT' THEN d.limit ELSE p.limit END resolved
  FROM dba_profiles p
  JOIN dba_profiles d ON d.profile = 'DEFAULT' AND d.resource_name = p.resource_name
 WHERE p.profile = 'ACME_RR_PROF'
   AND p.resource_name IN ('PASSWORD_LIFE_TIME','FAILED_LOGIN_ATTEMPTS',
                           'PASSWORD_LOCK_TIME','PASSWORD_GRACE_TIME')
 ORDER BY 1;

------------------------------------------ RR6: a common account in a PDB ----
CONNECT sys/"&pwd"@&root AS SYSDBA
CREATE PROFILE c##acme_rr_cprof LIMIT PASSWORD_LIFE_TIME UNLIMITED FAILED_LOGIN_ATTEMPTS 7 CONTAINER = ALL;
CREATE USER c##acme_rr_common IDENTIFIED BY "Acme_Rr_Common_1" PROFILE c##acme_rr_cprof CONTAINER = ALL;
GRANT CREATE SESSION TO c##acme_rr_common CONTAINER = ALL;
CONNECT acme_rr_svc/"Acme_Rr_Svc_1"@&pdb
PROMPT
PROMPT == RR6: the common account, read in the PDB as acme_rr_svc
SELECT username, profile, account_status, common, inherited,
       to_char(password_change_date, 'YYYY-MM-DD HH24:MI:SS') changed
  FROM dba_users WHERE username = 'C##ACME_RR_COMMON';
PROMPT -- its common profile, read in the PDB
SELECT profile, resource_name, limit, common, inherited FROM dba_profiles
 WHERE profile = 'C##ACME_RR_CPROF'
   AND resource_name IN ('PASSWORD_LIFE_TIME','FAILED_LOGIN_ATTEMPTS')
 ORDER BY 2;

------------------------------------------------------- RR7: the cost ----
PROMPT
PROMPT == RR7: effective object privileges of every account Oracle does not maintain
SET TIMING ON
WITH roles (grantee0, granted_role) AS (
  SELECT grantee, granted_role FROM dba_role_privs
   WHERE grantee IN (SELECT username FROM dba_users WHERE oracle_maintained = 'N')
  UNION ALL
  SELECT r.grantee0, p.granted_role
    FROM dba_role_privs p JOIN roles r ON p.grantee = r.granted_role
)
SELECT (SELECT COUNT(*) FROM dba_users WHERE oracle_maintained = 'N') accounts,
       (SELECT COUNT(*) FROM roles r JOIN dba_tab_privs t ON t.grantee = r.granted_role) via_roles
  FROM dual;
SET TIMING OFF

------------------------------------------------------------- cleanup ----
CONNECT sys/"&pwd"@&pdb AS SYSDBA
DROP USER acme_rr_app CASCADE;
DROP USER acme_rr_svc CASCADE;
DROP USER acme_rr_owner CASCADE;
DROP ROLE acme_rr_read;
DROP ROLE acme_rr_outer;
DROP ROLE acme_rr_extra;
DROP PROFILE acme_rr_prof CASCADE;
CONNECT sys/"&pwd"@&root AS SYSDBA
DROP USER c##acme_rr_common CASCADE;
DROP PROFILE c##acme_rr_cprof CASCADE;
PROMPT
PROMPT == cleanup: what is left (no rows expected)
SELECT username FROM cdb_users WHERE username LIKE '%ACME\_RR\_%' ESCAPE '\';
SELECT role FROM cdb_roles WHERE role LIKE 'ACME\_RR\_%' ESCAPE '\';
EXIT
