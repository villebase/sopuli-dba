--------------------------------------------------------------------------------
-- sopuli-dba : what can UC-5's report commands read?   (v3)
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
--        for a local service user. acme_rr_app holds SELECT on T1 and T2
--        directly; the default role acme_rr_outer, which holds acme_rr_read
--        (SELECT on T3 to T5, EXECUTE on P1, CREATE TABLE) and acme_rr_dup;
--        acme_rr_dup again, directly (SELECT on T2 and T3, so two privileges
--        reach the account by more than one path); and the non-default role
--        acme_rr_extra (INSERT on T1); and UPDATE on one column of T4. PUBLIC
--        holds SELECT on T6 and the role acme_rr_pub (SELECT on T7, CREATE
--        SYNONYM). acme_rr_app is on acme_rr_prof, whose PASSWORD_LIFE_TIME is
--        DEFAULT. The probe grants no system privilege to PUBLIC directly
--   RR2  as acme_rr_svc: a COUNT(*) from each of DBA_USERS, DBA_PROFILES,
--        DBA_ROLE_PRIVS, DBA_ROLES, DBA_SYS_PRIVS, DBA_TAB_PRIVS and
--        DBA_COL_PRIVS
--   RR3  as SYS: SELECT on DBA_SYS_PRIVS, DBA_TAB_PRIVS and DBA_COL_PRIVS to
--        acme_rr_svc, and RR2 again; where the column grant shows; then
--        SELECT ON SYS.USER$ (grant_user_dollar=Y) and a read of NAME, LCOUNT
--        and PTIME for acme_rr_app after two failed logins
--   RR4  as acme_rr_svc: acme_rr_app's effective privileges, by a recursive
--        query over DBA_ROLE_PRIVS, started from the account and from PUBLIC,
--        joined to DBA_TAB_PRIVS and DBA_SYS_PRIVS, with the role path and the
--        first role's DEFAULT_ROLE; then the same rows counted per distinct
--        privilege and object
--   RR5  as acme_rr_svc: acme_rr_prof's limits as DBA_PROFILES shows them, and
--        resolved through the DEFAULT profile
--   RR6  in the PDB: what DBA_USERS and DBA_PROFILES show for a common account
--        on a common profile created in CDB$ROOT, whose FAILED_LOGIN_ATTEMPTS
--        is DEFAULT. RR6a sets the PDB's DEFAULT profile to 2 failed logins,
--        and fails three logins in the PDB by each of: the common account;
--        acme_rr_loc, a local account on a local profile whose
--        FAILED_LOGIN_ATTEMPTS is DEFAULT; and acme_rr_loc2, a local account
--        on the common profile. Then one good login resets the common
--        account's count, the root's count is read, and RR6b restores the
--        PDB's DEFAULT, sets the root's to 2, and fails three more logins in
--        the PDB by the common account and by acme_rr_loc2, reading the
--        root's count after.
--        Which accounts locked shows which DEFAULT each follows. Both DEFAULT
--        profiles are restored, and printed at the start so that a run that
--        stops inside RR6 can be put back by hand
--   RR7  as acme_rr_svc, with SET TIMING ON: RR4's query for every account
--        that Oracle does not maintain, with the direct grants, the role
--        paths from the accounts and from PUBLIC, and the system privileges,
--        counted. PUBLIC's rows are counted once, not once per account
--   RR8  a COMMON-mode service account (C##, grants CONTAINER = ALL), reading
--        the six views in the PDB
--
-- This MEASURES and decides nothing. No column holding a verifier is selected
-- anywhere: not PASSWORD, SPARE4 nor SPARE4_12.
--
-- STATUS: v3 run 2026-11-07 on 26ai Free 23.26.3.0.0
-- (gvenzl/oracle-free:latest, FREEPDB1 and CDB$ROOT), twice, with the same
-- results apart from timestamps and RR7's elapsed time. v1 and v2, the same
-- day, measured less; where they overlap, their results agree with v3. Every
-- other release UNRUN, the 19.3 base release and 11.2 among them.
--
--
-- RESULTS -- 26ai Free 23.26.3.0.0, 2026-11-07, v3
--
--   RR0  Every column asked for exists: in DBA_USERS PASSWORD_CHANGE_DATE,
--        LAST_LOGIN, ORACLE_MAINTAINED, COMMON, LOCK_DATE, EXPIRY_DATE and
--        INHERITED; in DBA_PROFILES COMMON, INHERITED and IMPLICIT; in
--        DBA_TAB_PRIVS TYPE, COMMON and INHERITED; in DBA_SYS_PRIVS COMMON and
--        INHERITED; in DBA_ROLE_PRIVS DEFAULT_ROLE, COMMON and INHERITED
--   RR2  With 00_install.sql's grants, DBA_USERS, DBA_PROFILES, DBA_ROLE_PRIVS
--        and DBA_ROLES are read. DBA_SYS_PRIVS, DBA_TAB_PRIVS and
--        DBA_COL_PRIVS are refused: ORA-00942, table or view does not exist
--   RR3  After GRANT SELECT on each of the three, all are read. The column
--        grant, UPDATE on T4's column N, is in DBA_COL_PRIVS only: DBA_TAB_PRIVS
--        has no row for it. PUBLIC holds no system privilege directly on this
--        image. After two failed logins, SYS.USER$ shows LCOUNT 2 for
--        acme_rr_app to an account holding SELECT ON SYS.USER$. PTIME and
--        DBA_USERS.PASSWORD_CHANGE_DATE give the same time, to the second
--   RR4  The recursive query, started from the account and from PUBLIC,
--        reaches every grant the fixtures make, with its path, the role two
--        levels down and the role granted to PUBLIC among them. It returns
--        one row per path, not one per privilege: 13 rows for 9 distinct
--        privileges. SELECT on T2 comes three ways (direct, via ACME_RR_DUP,
--        via ACME_RR_OUTER > ACME_RR_DUP), and SELECT on T3 three ways. A
--        report has to collapse the rows per privilege and object, keeping
--        the paths. The non-default role shows DEFAULT_ROLE NO, the others
--        YES. DBA_TAB_PRIVS.TYPE reads PROCEDURE for P1. CREATE SYNONYM,
--        held by the role granted to PUBLIC, is reached as
--        PUBLIC > ACME_RR_PUB
--   RR5  DBA_PROFILES shows DEFAULT for each limit acme_rr_prof inherits.
--        Joined to the DEFAULT profile, PASSWORD_LIFE_TIME resolves to
--        UNLIMITED, PASSWORD_LOCK_TIME to 1 and PASSWORD_GRACE_TIME to 7 on
--        this image. FAILED_LOGIN_ATTEMPTS, set on the profile, reads 5
--   RR6  This image's DEFAULT profile has FAILED_LOGIN_ATTEMPTS UNLIMITED in
--        the root and in the PDB. In the PDB, DBA_USERS shows the common
--        account on its common profile, COMMON YES, INHERITED YES, and
--        PASSWORD_CHANGE_DATE NULL. DBA_PROFILES shows the common profile's
--        FAILED_LOGIN_ATTEMPTS as DEFAULT.
--        RR6a, the PDB's DEFAULT at 2, three failed logins each: the local
--        account on a local profile with DEFAULT was refused with ORA-28000 at
--        its third and reads LOCKED(TIMED). The local account on the common
--        profile, and the common account, stay OPEN. The root's LCOUNT for
--        the common account reads 0 after its three failed logins, while the
--        root's limit is UNLIMITED.
--        RR6b, the PDB's DEFAULT restored and the root's at 2, after one good
--        login by the common account: the common account and the local
--        account on the common profile were each refused with ORA-28000 at
--        the third of three failed logins. The local account reads
--        LOCKED(TIMED) in the PDB. The common account reads OPEN in the PDB,
--        and LOCKED(TIMED) with LCOUNT 2 in CDB$ROOT.
--        So a common profile's DEFAULT limit follows the root's DEFAULT
--        profile, for a local account on it as for a common one, though a
--        join to the DEFAULT profile in the PDB gives the PDB's value. And in
--        a PDB, DBA_USERS shows a locked common account as OPEN, as #1122
--        found with probe 17
--   RR7  RR4's query, with the direct grants, the role paths from the
--        accounts and from PUBLIC, and the system privileges, for the 8
--        accounts that Oracle does not maintain: 144 rows for the accounts and
--        4874 for PUBLIC, in 0.60 and 0.67 seconds. PUBLIC's rows are counted
--        once; a report that lists them for each account repeats them. A
--        rough cost on an almost empty PDB, not a benchmark
--   RR8  A common reader whose grants are made CONTAINER = ALL reads the six
--        views it is granted in the PDB, and sees the PDB's local accounts
--
--   Cleanup: no account, role or profile named ACME_RR_ is left in any
--   container, PUBLIC holds no role named ACME_RR_, and both DEFAULT profiles
--   read FAILED_LOGIN_ATTEMPTS UNLIMITED again, as before the run.
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
--   the file, edit the three DEFINEs in the copy, run the copy and delete it --
--   never substitute them with sed, which puts the password in argv instead.
--   MSYS_NO_PATHCONV is for Git Bash, which otherwise rewrites /nolog.
--
-- WHENEVER SQLERROR is CONTINUE throughout: the reads that a grant is expected
-- to be refused, and the failed logins, are the question.
--
-- THROWAWAY DATABASES ONLY. Creates and drops local and common accounts,
-- roles, profiles, tables and a procedure, fails logins on purpose, changes
-- both DEFAULT profiles for the length of RR6, grants a role to PUBLIC for the
-- length of the run, and grants SELECT ON SYS.USER$.
--------------------------------------------------------------------------------
define pdb  = //localhost:1521/FREEPDB1
define root = //localhost:1521/FREE
define pwd  = sopuli-test

WHENEVER SQLERROR CONTINUE
SET LINESIZE 200 PAGESIZE 200 FEEDBACK OFF VERIFY OFF HEADING ON
COLUMN who            FORMAT A18
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
COLUMN source         FORMAT A44
COLUMN privilege      FORMAT A16
COLUMN object         FORMAT A22
COLUMN type           FORMAT A10
COLUMN first_default  FORMAT A13
COLUMN ptime          FORMAT A19
COLUMN changed        FORMAT A19
COLUMN granted_role   FORMAT A16
COLUMN orig_fla NEW_VALUE orig_fla NOPRINT

define whoami = "sys_context('userenv','session_user') who, sys_context('userenv','con_name') con FROM dual"

-------------------------------------------------------------------- setup ----
CONNECT sys/"&pwd"@&pdb AS SYSDBA
BEGIN
  BEGIN EXECUTE IMMEDIATE 'REVOKE acme_rr_pub FROM PUBLIC';
  EXCEPTION WHEN OTHERS THEN NULL; END;
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
  BEGIN EXECUTE IMMEDIATE 'DROP PROFILE acme_rr_prof2 CASCADE';
  EXCEPTION WHEN OTHERS THEN NULL; END;
END;
/
CONNECT sys/"&pwd"@&root AS SYSDBA
BEGIN
  FOR u IN (SELECT username FROM dba_users WHERE username LIKE 'C##ACME\_RR\_%' ESCAPE '\') LOOP
    BEGIN EXECUTE IMMEDIATE 'DROP USER ' || u.username || ' CASCADE';
    EXCEPTION WHEN OTHERS THEN NULL; END;
  END LOOP;
  BEGIN EXECUTE IMMEDIATE 'DROP PROFILE c##acme_rr_cprof CASCADE';
  EXCEPTION WHEN OTHERS THEN NULL; END;
END;
/

PROMPT
PROMPT == the release
SELECT version_full FROM v$instance;
PROMPT
PROMPT == both DEFAULT profiles' FAILED_LOGIN_ATTEMPTS before the run. RR6 changes
PROMPT == and restores them; if a run stops inside RR6, set them back to these by hand
SELECT con_id, limit FROM cdb_profiles
 WHERE profile = 'DEFAULT' AND resource_name = 'FAILED_LOGIN_ATTEMPTS' ORDER BY 1;

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
CREATE TABLE acme_rr_owner.t7 (n NUMBER);
CREATE PROCEDURE acme_rr_owner.p1 AS BEGIN NULL; END;
/

CREATE ROLE acme_rr_read;
CREATE ROLE acme_rr_outer;
CREATE ROLE acme_rr_extra;
CREATE ROLE acme_rr_dup;
CREATE ROLE acme_rr_pub;
GRANT SELECT ON acme_rr_owner.t3 TO acme_rr_read;
GRANT SELECT ON acme_rr_owner.t4 TO acme_rr_read;
GRANT SELECT ON acme_rr_owner.t5 TO acme_rr_read;
GRANT EXECUTE ON acme_rr_owner.p1 TO acme_rr_read;
GRANT CREATE TABLE TO acme_rr_read;
GRANT SELECT ON acme_rr_owner.t2 TO acme_rr_dup;
GRANT SELECT ON acme_rr_owner.t3 TO acme_rr_dup;
GRANT acme_rr_read, acme_rr_dup TO acme_rr_outer;
GRANT INSERT ON acme_rr_owner.t1 TO acme_rr_extra;
GRANT SELECT ON acme_rr_owner.t7 TO acme_rr_pub;
GRANT CREATE SYNONYM TO acme_rr_pub;
GRANT SELECT ON acme_rr_owner.t6 TO PUBLIC;
GRANT acme_rr_pub TO PUBLIC;

CREATE PROFILE acme_rr_prof2 LIMIT FAILED_LOGIN_ATTEMPTS DEFAULT;
CREATE USER acme_rr_loc IDENTIFIED BY "Acme_Rr_Loc_1" PROFILE acme_rr_prof2;
GRANT CREATE SESSION TO acme_rr_loc;

CREATE USER acme_rr_app IDENTIFIED BY "Acme_Rr_App_1" PROFILE acme_rr_prof;
GRANT CREATE SESSION TO acme_rr_app;
GRANT SELECT ON acme_rr_owner.t1 TO acme_rr_app;
GRANT SELECT ON acme_rr_owner.t2 TO acme_rr_app;
GRANT UPDATE (n) ON acme_rr_owner.t4 TO acme_rr_app;
GRANT acme_rr_outer, acme_rr_extra, acme_rr_dup TO acme_rr_app;
ALTER USER acme_rr_app DEFAULT ROLE acme_rr_outer, acme_rr_dup;

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
PROMPT -- DBA_COL_PRIVS
SELECT COUNT(*) FROM dba_col_privs;

------------------------------------------------ RR3: the grants it needs ----
CONNECT sys/"&pwd"@&pdb AS SYSDBA
GRANT SELECT ON sys.dba_sys_privs TO acme_rr_svc;
GRANT SELECT ON sys.dba_tab_privs TO acme_rr_svc;
GRANT SELECT ON sys.dba_col_privs TO acme_rr_svc;
CONNECT acme_rr_svc/"Acme_Rr_Svc_1"@&pdb
PROMPT
PROMPT == RR3: after SELECT on DBA_SYS_PRIVS, DBA_TAB_PRIVS and DBA_COL_PRIVS
PROMPT -- DBA_SYS_PRIVS
SELECT COUNT(*) FROM dba_sys_privs;
PROMPT -- DBA_TAB_PRIVS
SELECT COUNT(*) FROM dba_tab_privs;
PROMPT -- DBA_COL_PRIVS
SELECT COUNT(*) FROM dba_col_privs;
PROMPT -- acme_rr_app's column grant: in DBA_COL_PRIVS, and whether DBA_TAB_PRIVS has it
COLUMN column_name FORMAT A12
SELECT 'DBA_COL_PRIVS' source, privilege, owner || '.' || table_name object, column_name
  FROM dba_col_privs WHERE grantee = 'ACME_RR_APP';
SELECT 'DBA_TAB_PRIVS' source, privilege, owner || '.' || table_name object
  FROM dba_tab_privs WHERE grantee = 'ACME_RR_APP' AND table_name = 'T4';
PROMPT -- the system privileges PUBLIC holds directly, counted (this probe grants none)
SELECT COUNT(*) FROM dba_sys_privs WHERE grantee = 'PUBLIC';

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
PROMPT == RR4: the roles granted to acme_rr_app, and to PUBLIC by this probe
SELECT grantee username, granted_role, admin_option, default_role FROM dba_role_privs
 WHERE grantee = 'ACME_RR_APP' OR (grantee = 'PUBLIC' AND granted_role LIKE 'ACME\_RR\_%' ESCAPE '\')
 ORDER BY 1, 2;

PROMPT
PROMPT == RR4: acme_rr_app's effective object privileges, one row per path, as acme_rr_svc
WITH roles (granted_role, path, first_default) AS (
  SELECT granted_role, grantee || ' > ' || granted_role, default_role
    FROM dba_role_privs WHERE grantee IN ('ACME_RR_APP', 'PUBLIC')
  UNION ALL
  SELECT p.granted_role, r.path || ' > ' || p.granted_role, r.first_default
    FROM dba_role_privs p JOIN roles r ON p.grantee = r.granted_role
),
paths AS (
  SELECT t.grantee || ' direct' source, t.privilege, t.owner || '.' || t.table_name object, t.type, '-' first_default
    FROM dba_tab_privs t WHERE t.grantee IN ('ACME_RR_APP', 'PUBLIC')
  UNION ALL
  SELECT r.path, t.privilege, t.owner || '.' || t.table_name, t.type, r.first_default
    FROM roles r JOIN dba_tab_privs t ON t.grantee = r.granted_role
)
SELECT source, privilege, object, type, first_default FROM paths
 WHERE object LIKE 'ACME\_RR\_OWNER.%' ESCAPE '\'
 ORDER BY 3, 2, 1;

PROMPT
PROMPT == RR4: the same rows, counted per distinct privilege and object
WITH roles (granted_role) AS (
  SELECT granted_role FROM dba_role_privs WHERE grantee IN ('ACME_RR_APP', 'PUBLIC')
  UNION ALL
  SELECT p.granted_role FROM dba_role_privs p JOIN roles r ON p.grantee = r.granted_role
),
paths AS (
  SELECT t.privilege, t.owner, t.table_name FROM dba_tab_privs t
   WHERE t.grantee IN ('ACME_RR_APP', 'PUBLIC')
  UNION ALL
  SELECT t.privilege, t.owner, t.table_name FROM roles r JOIN dba_tab_privs t ON t.grantee = r.granted_role
)
SELECT COUNT(*) rows_with_paths,
       COUNT(DISTINCT privilege || ' ' || owner || '.' || table_name) distinct_privileges
  FROM paths WHERE owner = 'ACME_RR_OWNER';

PROMPT
PROMPT == RR4: acme_rr_app's effective system privileges, one row per path, as acme_rr_svc
WITH roles (granted_role, path, first_default) AS (
  SELECT granted_role, grantee || ' > ' || granted_role, default_role
    FROM dba_role_privs WHERE grantee IN ('ACME_RR_APP', 'PUBLIC')
  UNION ALL
  SELECT p.granted_role, r.path || ' > ' || p.granted_role, r.first_default
    FROM dba_role_privs p JOIN roles r ON p.grantee = r.granted_role
)
SELECT s.grantee || ' direct' source, s.privilege, '-' first_default
  FROM dba_sys_privs s
 WHERE s.grantee = 'ACME_RR_APP'
UNION ALL
SELECT r.path, s.privilege, r.first_default
  FROM roles r JOIN dba_sys_privs s ON s.grantee = r.granted_role
 WHERE r.path LIKE '%ACME\_RR\_%' ESCAPE '\'
 ORDER BY 2, 1;

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
PROMPT
PROMPT == RR6: the root's DEFAULT FAILED_LOGIN_ATTEMPTS, left as it is
SELECT limit FROM dba_profiles WHERE profile = 'DEFAULT' AND resource_name = 'FAILED_LOGIN_ATTEMPTS';
CREATE PROFILE c##acme_rr_cprof LIMIT PASSWORD_LIFE_TIME UNLIMITED FAILED_LOGIN_ATTEMPTS DEFAULT CONTAINER = ALL;
CREATE USER c##acme_rr_common IDENTIFIED BY "Acme_Rr_Common_1" PROFILE c##acme_rr_cprof CONTAINER = ALL;
GRANT CREATE SESSION TO c##acme_rr_common CONTAINER = ALL;

CONNECT sys/"&pwd"@&pdb AS SYSDBA
CREATE USER acme_rr_loc2 IDENTIFIED BY "Acme_Rr_Loc2_1" PROFILE c##acme_rr_cprof;
GRANT CREATE SESSION TO acme_rr_loc2;
SELECT limit orig_fla FROM dba_profiles WHERE profile = 'DEFAULT' AND resource_name = 'FAILED_LOGIN_ATTEMPTS';
PROMPT -- the PDB's DEFAULT FAILED_LOGIN_ATTEMPTS before the change: &orig_fla
ALTER PROFILE DEFAULT LIMIT FAILED_LOGIN_ATTEMPTS 2;

CONNECT acme_rr_svc/"Acme_Rr_Svc_1"@&pdb
PROMPT
PROMPT == RR6: the common account, read in the PDB as acme_rr_svc
SELECT username, profile, account_status, common, inherited,
       to_char(password_change_date, 'YYYY-MM-DD HH24:MI:SS') changed
  FROM dba_users WHERE username = 'C##ACME_RR_COMMON';
PROMPT -- its common profile, read in the PDB, with DEFAULT resolved through the PDB's DEFAULT
SELECT p.profile, p.resource_name, p.limit, p.common, p.inherited,
       CASE WHEN p.limit = 'DEFAULT' THEN d.limit ELSE p.limit END resolved
  FROM dba_profiles p
  JOIN dba_profiles d ON d.profile = 'DEFAULT' AND d.resource_name = p.resource_name
 WHERE p.profile = 'C##ACME_RR_CPROF'
   AND p.resource_name IN ('PASSWORD_LIFE_TIME','FAILED_LOGIN_ATTEMPTS')
 ORDER BY 2;

PROMPT
PROMPT == RR6a: PDB DEFAULT 2, root DEFAULT unchanged. Three failed logins in the PDB
PROMPT -- as c##acme_rr_common (ORA-01017, or ORA-28000 once locked)
CONNECT c##acme_rr_common/"wrong-1"@&pdb
CONNECT c##acme_rr_common/"wrong-2"@&pdb
CONNECT c##acme_rr_common/"wrong-3"@&pdb
PROMPT -- as acme_rr_loc, a local account on acme_rr_prof2, a local profile whose FAILED_LOGIN_ATTEMPTS is DEFAULT
CONNECT acme_rr_loc/"wrong-1"@&pdb
CONNECT acme_rr_loc/"wrong-2"@&pdb
CONNECT acme_rr_loc/"wrong-3"@&pdb
PROMPT -- as acme_rr_loc2, a local account on c##acme_rr_cprof, the common profile
CONNECT acme_rr_loc2/"wrong-1"@&pdb
CONNECT acme_rr_loc2/"wrong-2"@&pdb
CONNECT acme_rr_loc2/"wrong-3"@&pdb
CONNECT sys/"&pwd"@&pdb AS SYSDBA
PROMPT -- their status in the PDB
SELECT username, account_status FROM dba_users
 WHERE username IN ('C##ACME_RR_COMMON', 'ACME_RR_LOC', 'ACME_RR_LOC2') ORDER BY 1;
ALTER PROFILE DEFAULT LIMIT FAILED_LOGIN_ATTEMPTS &orig_fla;
PROMPT -- the PDB's DEFAULT FAILED_LOGIN_ATTEMPTS after the restore
SELECT limit FROM dba_profiles WHERE profile = 'DEFAULT' AND resource_name = 'FAILED_LOGIN_ATTEMPTS';

CONNECT sys/"&pwd"@&root AS SYSDBA
PROMPT -- the common account in CDB$ROOT after RR6a: status, and the root's count
SELECT d.username, d.account_status, u.lcount FROM dba_users d JOIN sys.user$ u ON u.name = d.username
 WHERE d.username = 'C##ACME_RR_COMMON';
PROMPT -- one login with the right password in the PDB, which resets the root's count (#1122)
CONNECT c##acme_rr_common/"Acme_Rr_Common_1"@&pdb
SELECT &whoami;
CONNECT sys/"&pwd"@&root AS SYSDBA
SELECT d.username, d.account_status, u.lcount FROM dba_users d JOIN sys.user$ u ON u.name = d.username
 WHERE d.username = 'C##ACME_RR_COMMON';
SELECT limit orig_fla FROM dba_profiles WHERE profile = 'DEFAULT' AND resource_name = 'FAILED_LOGIN_ATTEMPTS';
ALTER PROFILE DEFAULT LIMIT FAILED_LOGIN_ATTEMPTS 2;
PROMPT
PROMPT == RR6b: root DEFAULT 2, PDB DEFAULT restored. Three more failed logins in the PDB
PROMPT -- as c##acme_rr_common
CONNECT c##acme_rr_common/"wrong-4"@&pdb
CONNECT c##acme_rr_common/"wrong-5"@&pdb
CONNECT c##acme_rr_common/"wrong-6"@&pdb
PROMPT -- as acme_rr_loc2, the local account on the common profile
CONNECT acme_rr_loc2/"wrong-4"@&pdb
CONNECT acme_rr_loc2/"wrong-5"@&pdb
CONNECT acme_rr_loc2/"wrong-6"@&pdb
CONNECT sys/"&pwd"@&pdb AS SYSDBA
PROMPT -- their status in the PDB
SELECT username, account_status FROM dba_users
 WHERE username IN ('C##ACME_RR_COMMON', 'ACME_RR_LOC2') ORDER BY 1;
CONNECT sys/"&pwd"@&root AS SYSDBA
PROMPT -- and in CDB$ROOT, with the root's count
SELECT d.username, d.account_status, u.lcount FROM dba_users d JOIN sys.user$ u ON u.name = d.username
 WHERE d.username = 'C##ACME_RR_COMMON';
ALTER PROFILE DEFAULT LIMIT FAILED_LOGIN_ATTEMPTS &orig_fla;
PROMPT -- the root's DEFAULT FAILED_LOGIN_ATTEMPTS after the restore
SELECT limit FROM dba_profiles WHERE profile = 'DEFAULT' AND resource_name = 'FAILED_LOGIN_ATTEMPTS';

------------------------------------------------------- RR7: the cost ----
CONNECT acme_rr_svc/"Acme_Rr_Svc_1"@&pdb
PROMPT
PROMPT == RR7: RR4's full query for every account Oracle does not maintain
SET TIMING ON
WITH accts AS (SELECT username FROM dba_users WHERE oracle_maintained = 'N'),
roles (grantee0, granted_role, path, first_default) AS (
  SELECT d.grantee, d.granted_role, d.grantee || ' > ' || d.granted_role, d.default_role
    FROM dba_role_privs d WHERE d.grantee IN (SELECT username FROM accts)
  UNION ALL
  SELECT r.grantee0, p.granted_role, r.path || ' > ' || p.granted_role, r.first_default
    FROM dba_role_privs p JOIN roles r ON p.grantee = r.granted_role
),
pubroles (granted_role, path) AS (
  SELECT granted_role, 'PUBLIC > ' || granted_role FROM dba_role_privs WHERE grantee = 'PUBLIC'
  UNION ALL
  SELECT p.granted_role, r.path || ' > ' || p.granted_role
    FROM dba_role_privs p JOIN pubroles r ON p.grantee = r.granted_role
),
rows_ AS (
  SELECT t.grantee g, t.privilege, t.owner || '.' || t.table_name o, 'direct' path FROM dba_tab_privs t
   WHERE t.grantee IN (SELECT username FROM accts) OR t.grantee = 'PUBLIC'
  UNION ALL
  SELECT r.grantee0, t.privilege, t.owner || '.' || t.table_name, r.path
    FROM roles r JOIN dba_tab_privs t ON t.grantee = r.granted_role
  UNION ALL
  SELECT 'PUBLIC', t.privilege, t.owner || '.' || t.table_name, r.path
    FROM pubroles r JOIN dba_tab_privs t ON t.grantee = r.granted_role
  UNION ALL
  SELECT s.grantee, s.privilege, '-', 'direct' FROM dba_sys_privs s
   WHERE s.grantee IN (SELECT username FROM accts) OR s.grantee = 'PUBLIC'
  UNION ALL
  SELECT r.grantee0, s.privilege, '-', r.path FROM roles r JOIN dba_sys_privs s ON s.grantee = r.granted_role
  UNION ALL
  SELECT 'PUBLIC', s.privilege, '-', r.path FROM pubroles r JOIN dba_sys_privs s ON s.grantee = r.granted_role
)
SELECT (SELECT COUNT(*) FROM accts) accounts,
       (SELECT COUNT(*) FROM rows_ WHERE g <> 'PUBLIC') account_rows,
       (SELECT COUNT(*) FROM rows_ WHERE g = 'PUBLIC') public_rows
  FROM dual;
SET TIMING OFF

------------------------------------------------- RR8: a COMMON-mode reader ----
CONNECT sys/"&pwd"@&root AS SYSDBA
CREATE USER c##acme_rr_csvc IDENTIFIED BY "Acme_Rr_Csvc_1" CONTAINER = ALL;
GRANT CREATE SESSION TO c##acme_rr_csvc CONTAINER = ALL;
GRANT SELECT ON sys.dba_users      TO c##acme_rr_csvc CONTAINER = ALL;
GRANT SELECT ON sys.dba_profiles   TO c##acme_rr_csvc CONTAINER = ALL;
GRANT SELECT ON sys.dba_role_privs TO c##acme_rr_csvc CONTAINER = ALL;
GRANT SELECT ON sys.dba_roles      TO c##acme_rr_csvc CONTAINER = ALL;
GRANT SELECT ON sys.dba_sys_privs  TO c##acme_rr_csvc CONTAINER = ALL;
GRANT SELECT ON sys.dba_tab_privs  TO c##acme_rr_csvc CONTAINER = ALL;
CONNECT c##acme_rr_csvc/"Acme_Rr_Csvc_1"@&pdb
SELECT &whoami;
PROMPT
PROMPT == RR8: each read in the PDB as c##acme_rr_csvc, grants CONTAINER = ALL
PROMPT -- DBA_USERS, and the rows for the fixture accounts
SELECT COUNT(*) FROM dba_users;
SELECT COUNT(*) FROM dba_users WHERE username LIKE 'ACME\_RR\_%' ESCAPE '\';
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

------------------------------------------------------------- cleanup ----
CONNECT sys/"&pwd"@&pdb AS SYSDBA
REVOKE acme_rr_pub FROM PUBLIC;
DROP USER acme_rr_app CASCADE;
DROP USER acme_rr_loc CASCADE;
DROP USER acme_rr_loc2 CASCADE;
DROP USER acme_rr_svc CASCADE;
DROP USER acme_rr_owner CASCADE;
DROP ROLE acme_rr_read;
DROP ROLE acme_rr_outer;
DROP ROLE acme_rr_extra;
DROP ROLE acme_rr_dup;
DROP ROLE acme_rr_pub;
DROP PROFILE acme_rr_prof CASCADE;
DROP PROFILE acme_rr_prof2 CASCADE;
CONNECT sys/"&pwd"@&root AS SYSDBA
DROP USER c##acme_rr_common CASCADE;
DROP USER c##acme_rr_csvc CASCADE;
DROP PROFILE c##acme_rr_cprof CASCADE;
PROMPT
PROMPT == cleanup: what is left (no rows expected)
SELECT con_id, username FROM cdb_users WHERE username LIKE '%ACME\_RR\_%' ESCAPE '\';
SELECT con_id, role FROM cdb_roles WHERE role LIKE '%ACME\_RR\_%' ESCAPE '\';
SELECT DISTINCT con_id, profile FROM cdb_profiles WHERE profile LIKE '%ACME\_RR\_%' ESCAPE '\';
SELECT con_id, granted_role FROM cdb_role_privs WHERE grantee = 'PUBLIC' AND granted_role LIKE 'ACME\_RR\_%' ESCAPE '\';
PROMPT -- the PDB's DEFAULT FAILED_LOGIN_ATTEMPTS at the end
SELECT con_id, limit FROM cdb_profiles WHERE profile = 'DEFAULT' AND resource_name = 'FAILED_LOGIN_ATTEMPTS' ORDER BY 1;
EXIT
