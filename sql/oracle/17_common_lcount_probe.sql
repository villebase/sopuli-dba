--------------------------------------------------------------------------------
-- sopuli-dba : where does a common account's failed-login count live?   (v2)
--
-- #1122. 16_lcount_grant_probe.sql found that a common account's failed logins
-- in a PDB are counted in CDB$ROOT's SYS.USER$.LCOUNT, and that the PDB's row
-- reads 0. check's LCOUNT guard reads SYS.USER$ in the container the target
-- names, so on a PDB target it reads 0 for a common account. This measures
-- what that costs and what a PDB session can read instead:
--
--   CL1  which count locks: three failed logins in the PDB on a profile with
--        FAILED_LOGIN_ATTEMPTS 3, then ACCOUNT_STATUS and LCOUNT in both
--        containers, a login with the right password in each, and one with a
--        wrong password in the PDB
--   CL2  whether the two containers share one count: two failed logins in
--        CDB$ROOT and one in the PDB, on the same profile
--   CL3  what a successful login resets: two failed logins in the PDB, then a
--        good one in the PDB; and two in CDB$ROOT, then a good one in the PDB
--   CL4  which limit applies: the common profile allows 10, and the PDB gives
--        the common account a local profile that allows 2. The guard reads the
--        limit from DBA_USERS.PROFILE in the PDB
--   CL4b the other way round: the common profile allows 3, and the PDB's local
--        profile allows 10
--   CL5  what a PDB session can read of the root's count, after four failed
--        logins in the PDB:
--          acme_cl_svc     local, SELECT ON SYS.USER$, the grant 00_install.sql
--                          makes when grant_user_dollar=Y, and SELECT ON
--                          DBA_USERS and CDB_USERS
--          c##acme_cl_svc  common, SELECT ON SYS.USER$ and SET CONTAINER,
--                          both CONTAINER = ALL, the grants 00_install.sql
--                          makes in COMMON mode when grant_user_dollar=Y and
--                          grant_set_container=Y, and SELECT ON DBA_USERS and
--                          CDB_USERS in the PDB
--        each reads SYS.USER$, CONTAINERS(SYS.USER$), CDB_USERS and DBA_USERS;
--        the common one also tries ALTER SESSION SET CONTAINER = CDB$ROOT
--
-- This MEASURES and decides nothing.
--
-- STATUS: run 2026-10-28 on 26ai Free 23.26.3.0.0 (gvenzl/oracle-free:latest,
-- FREEPDB1), 21c XE 21.3.0.0.0 and 18c XE 18.4.0.0.0 (gvenzl/oracle-xe:21-slim
-- and :18-slim, XEPDB1), twice on each, with the same results on all three
-- apart from the lock timestamps. Every other release UNRUN, the 19.3 base
-- release among them.
--
--
-- RESULTS -- 23.26.3.0.0, 21.3.0.0.0 and 18.4.0.0.0, 2026-10-28
--
--   setup  ALTER USER c##acme_cl_d PROFILE acme_cl_prof2, in the PDB, succeeds:
--          DBA_USERS.PROFILE is ACME_CL_PROF2 in the PDB and C##ACME_CL_PROF10
--          in CDB$ROOT
--
--   CL1  after three failed logins in the PDB, on a limit of 3:
--
--          container  LCOUNT  ASTATUS  ACCOUNT_STATUS  LOCK_DATE
--          CDB$ROOT   3       4        LOCKED(TIMED)   set
--          the PDB    0       0        OPEN            NULL
--
--        The right password then gets ORA-28000 in the PDB and in CDB$ROOT,
--        and a wrong one gets ORA-28000 in the PDB. So the account is locked,
--        and the PDB's dictionary says it is open
--
--   CL2  two failed logins in CDB$ROOT and one in the PDB lock the account, as
--        in CL1: LCOUNT 3 and LOCKED(TIMED) in CDB$ROOT, 0 and OPEN in the PDB,
--        and ORA-28000 for the right password in the PDB. The two containers
--        share one count, the root's
--
--   CL3  the root's LCOUNT goes 2 -> 0 on a good login in the PDB, after two
--        failed logins in the PDB (CL3a) or in CDB$ROOT (CL3b). The PDB's
--        reads 0 before and after, in both
--
--   CL4  two failed logins in the PDB do not lock the account, on the PDB's
--        limit of 2: the right password then logs in, in the PDB and in
--        CDB$ROOT. A failed login after the good ones takes the root's LCOUNT
--        to 1
--
--   CL4b three failed logins in the PDB lock the account on the root's limit
--        of 3, while the PDB's profile allows 10: LCOUNT 3 and LOCKED(TIMED)
--        in CDB$ROOT, 0 and OPEN in the PDB, and ORA-28000 for the right
--        password in the PDB. With CL4, the limit that applies is the root
--        profile's, either way round. The PDB's DBA_USERS.PROFILE names a
--        profile that does not apply
--
--   CL5  after four failed logins in the PDB, the root's LCOUNT is 4. In the
--        PDB, both readers, local and common, see 0 in SYS.USER$, one row with
--        CON_ID 3 and LCOUNT 0 from CONTAINERS(SYS.USER$), one row with CON_ID
--        3 and OPEN from CDB_USERS, and OPEN in DBA_USERS. The common reader,
--        after ALTER SESSION SET CONTAINER = CDB$ROOT, reads 4 in SYS.USER$,
--        and 0 again after it switches back. So of the reads tried, only one
--        reaches the root's count from a session that starts in the PDB: a
--        common account that holds SET CONTAINER and SELECT ON SYS.USER$, both
--        CONTAINER = ALL, and leaves the PDB. A database link, the V$ views
--        and KU$_USER_VIEW were not tried
--
-- HOW TO RUN
--   As SYS, in the PDB and in CDB$ROOT. Against the tier-1 stack, whose SYS
--   and SYSTEM password is the public one in test/compose.yaml, as it stands:
--
--     MSYS_NO_PATHCONV=1 docker exec -i sopuli-test-oracle-free-1 \
--       sqlplus -S /nolog < 17_common_lcount_probe.sql
--
--   A second clone's stack names the container after its COMPOSE_PROJECT_NAME,
--   such as sopuli-test-w2-oracle-free-1. On XE the PDB is XEPDB1 and the root
--   service is XE. /nolog, and every CONNECT made from the script, so no
--   password is ever in argv (invariant 1). Against any other database, copy
--   the file, edit the four DEFINEs in the copy, run the copy and delete it --
--   never substitute them with sed, which puts the password in argv instead.
--   MSYS_NO_PATHCONV is for Git Bash, which otherwise rewrites /nolog.
--
-- WHENEVER SQLERROR is CONTINUE throughout: the failed logins, and the reads
-- that a grant is expected to be refused, are the question. After each login
-- with the right password, a SELECT says who is connected where; SP2-0640
-- (not connected) means the login was refused.
--
-- THROWAWAY DATABASES ONLY. Creates and drops local and common accounts and
-- profiles, fails logins on purpose, locks accounts, and grants SELECT ON
-- SYS.USER$ and SET CONTAINER.
--------------------------------------------------------------------------------
define pdb  = //localhost:1521/FREEPDB1
define root = //localhost:1521/FREE
define pwd  = sopuli-test
define pdbname = FREEPDB1

WHENEVER SQLERROR CONTINUE
SET LINESIZE 200 PAGESIZE 100 FEEDBACK OFF VERIFY OFF HEADING ON
COLUMN who            FORMAT A16
COLUMN con            FORMAT A9
COLUMN name           FORMAT A16
COLUMN username       FORMAT A16
COLUMN account_status FORMAT A16
COLUMN profile        FORMAT A18
COLUMN common         FORMAT A6
COLUMN limit          FORMAT A8
COLUMN lock_date      FORMAT A19

-- The row SYS reads for one account in the container it is connected to. It
-- is two DEFINEs because SQL*Plus 21 and earlier cap one at 240 characters.
-- Each starts after SELECT: SQL*Plus does not substitute the first word of a
-- command.
define state = "sys_context('userenv','con_name') con, u.name, u.lcount, u.astatus, d.account_status, to_char(d.lock_date,'YYYY-MM-DD HH24:MI:SS') lock_date, d.profile, p.limit"
define state_from = "FROM sys.user$ u JOIN dba_users d ON d.username = u.name JOIN dba_profiles p ON p.profile = d.profile AND p.resource_name = 'FAILED_LOGIN_ATTEMPTS'"
define whoami = "sys_context('userenv','session_user') who, sys_context('userenv','con_name') con FROM dual"

-------------------------------------------------------------------- setup ----
CONNECT sys/"&pwd"@&pdb AS SYSDBA
BEGIN
  FOR u IN (SELECT username FROM dba_users WHERE username LIKE 'ACME\_CL\_%' ESCAPE '\') LOOP
    BEGIN EXECUTE IMMEDIATE 'DROP USER ' || u.username || ' CASCADE';
    EXCEPTION WHEN OTHERS THEN NULL; END;
  END LOOP;
  BEGIN EXECUTE IMMEDIATE 'DROP PROFILE acme_cl_prof2 CASCADE';
  EXCEPTION WHEN OTHERS THEN NULL; END;
END;
/
CONNECT sys/"&pwd"@&root AS SYSDBA
BEGIN
  FOR u IN (SELECT username FROM dba_users WHERE username LIKE 'C##ACME\_CL\_%' ESCAPE '\') LOOP
    BEGIN EXECUTE IMMEDIATE 'DROP USER ' || u.username || ' CASCADE';
    EXCEPTION WHEN OTHERS THEN NULL; END;
  END LOOP;
  FOR p IN (SELECT profile FROM dba_profiles WHERE profile LIKE 'C##ACME\_CL\_%' ESCAPE '\' GROUP BY profile) LOOP
    BEGIN EXECUTE IMMEDIATE 'DROP PROFILE ' || p.profile || ' CASCADE';
    EXCEPTION WHEN OTHERS THEN NULL; END;
  END LOOP;
END;
/

PROMPT
PROMPT == the release
SELECT version_full FROM v$instance;

CREATE PROFILE c##acme_cl_prof3  LIMIT FAILED_LOGIN_ATTEMPTS 3  PASSWORD_LOCK_TIME 1 CONTAINER = ALL;
CREATE PROFILE c##acme_cl_prof10 LIMIT FAILED_LOGIN_ATTEMPTS 10 PASSWORD_LOCK_TIME 1 CONTAINER = ALL;
CREATE USER c##acme_cl_a IDENTIFIED BY "Acme_Cl_A_1" PROFILE c##acme_cl_prof3  CONTAINER = ALL;
CREATE USER c##acme_cl_b IDENTIFIED BY "Acme_Cl_B_1" PROFILE c##acme_cl_prof3  CONTAINER = ALL;
CREATE USER c##acme_cl_c IDENTIFIED BY "Acme_Cl_C_1" PROFILE c##acme_cl_prof10 CONTAINER = ALL;
CREATE USER c##acme_cl_d IDENTIFIED BY "Acme_Cl_D_1" PROFILE c##acme_cl_prof10 CONTAINER = ALL;
CREATE USER c##acme_cl_e IDENTIFIED BY "Acme_Cl_E_1" PROFILE c##acme_cl_prof10 CONTAINER = ALL;
CREATE USER c##acme_cl_f IDENTIFIED BY "Acme_Cl_F_1" PROFILE c##acme_cl_prof3  CONTAINER = ALL;
CREATE USER c##acme_cl_svc IDENTIFIED BY "Acme_Cl_Csvc_1" CONTAINER = ALL;
GRANT CREATE SESSION TO c##acme_cl_a, c##acme_cl_b, c##acme_cl_c, c##acme_cl_d,
      c##acme_cl_e, c##acme_cl_f, c##acme_cl_svc CONTAINER = ALL;
GRANT SET CONTAINER TO c##acme_cl_svc CONTAINER = ALL;
GRANT SELECT ON sys.user$ TO c##acme_cl_svc CONTAINER = ALL;

CONNECT sys/"&pwd"@&pdb AS SYSDBA
CREATE PROFILE acme_cl_prof2 LIMIT FAILED_LOGIN_ATTEMPTS 2 PASSWORD_LOCK_TIME 1;
CREATE PROFILE acme_cl_prof10l LIMIT FAILED_LOGIN_ATTEMPTS 10 PASSWORD_LOCK_TIME 1;
ALTER USER c##acme_cl_d PROFILE acme_cl_prof2;
ALTER USER c##acme_cl_f PROFILE acme_cl_prof10l;
CREATE USER acme_cl_svc IDENTIFIED BY "Acme_Cl_Svc_1";
GRANT CREATE SESSION TO acme_cl_svc;
GRANT SELECT ON sys.user$ TO acme_cl_svc;
GRANT SELECT ON sys.dba_users TO acme_cl_svc, c##acme_cl_svc;
GRANT SELECT ON sys.cdb_users TO acme_cl_svc, c##acme_cl_svc;
PROMPT -- the profile each common account has in the PDB
SELECT username, common, profile FROM dba_users
 WHERE username LIKE 'C##ACME\_CL\_%' ESCAPE '\' ORDER BY 1;
CONNECT sys/"&pwd"@&root AS SYSDBA
PROMPT -- and in CDB$ROOT
SELECT username, common, profile FROM dba_users
 WHERE username LIKE 'C##ACME\_CL\_%' ESCAPE '\' ORDER BY 1;

------------------------------------------------- CL1: which count locks ----
PROMPT
PROMPT == CL1: three failed logins in the PDB as c##acme_cl_a, limit 3 (ORA-01017 three times)
CONNECT c##acme_cl_a/"wrong-1"@&pdb
CONNECT c##acme_cl_a/"wrong-2"@&pdb
CONNECT c##acme_cl_a/"wrong-3"@&pdb
CONNECT sys/"&pwd"@&root AS SYSDBA
SELECT &state &state_from WHERE u.name = 'C##ACME_CL_A';
CONNECT sys/"&pwd"@&pdb AS SYSDBA
SELECT &state &state_from WHERE u.name = 'C##ACME_CL_A';
PROMPT -- the right password, in the PDB
CONNECT c##acme_cl_a/"Acme_Cl_A_1"@&pdb
SELECT &whoami;
PROMPT -- the right password, in CDB$ROOT
CONNECT c##acme_cl_a/"Acme_Cl_A_1"@&root
SELECT &whoami;
PROMPT -- a wrong password, in the PDB, once locked
CONNECT c##acme_cl_a/"wrong-4"@&pdb

----------------------------------------------- CL2: one count, or two ----
PROMPT
PROMPT == CL2: two failed logins in CDB$ROOT and one in the PDB as c##acme_cl_b, limit 3
CONNECT c##acme_cl_b/"wrong-1"@&root
CONNECT c##acme_cl_b/"wrong-2"@&root
CONNECT c##acme_cl_b/"wrong-3"@&pdb
CONNECT sys/"&pwd"@&root AS SYSDBA
SELECT &state &state_from WHERE u.name = 'C##ACME_CL_B';
CONNECT sys/"&pwd"@&pdb AS SYSDBA
SELECT &state &state_from WHERE u.name = 'C##ACME_CL_B';
PROMPT -- the right password, in the PDB
CONNECT c##acme_cl_b/"Acme_Cl_B_1"@&pdb
SELECT &whoami;

----------------------------------------- CL3: what a good login resets ----
PROMPT
PROMPT == CL3a: two failed logins in the PDB as c##acme_cl_c, then a good one in the PDB
CONNECT c##acme_cl_c/"wrong-1"@&pdb
CONNECT c##acme_cl_c/"wrong-2"@&pdb
CONNECT sys/"&pwd"@&root AS SYSDBA
PROMPT -- before the good login
SELECT &state &state_from WHERE u.name = 'C##ACME_CL_C';
CONNECT c##acme_cl_c/"Acme_Cl_C_1"@&pdb
SELECT &whoami;
CONNECT sys/"&pwd"@&root AS SYSDBA
PROMPT -- after it
SELECT &state &state_from WHERE u.name = 'C##ACME_CL_C';
CONNECT sys/"&pwd"@&pdb AS SYSDBA
SELECT &state &state_from WHERE u.name = 'C##ACME_CL_C';

PROMPT
PROMPT == CL3b: two failed logins in CDB$ROOT as c##acme_cl_c, then a good one in the PDB
CONNECT c##acme_cl_c/"wrong-1"@&root
CONNECT c##acme_cl_c/"wrong-2"@&root
CONNECT sys/"&pwd"@&root AS SYSDBA
PROMPT -- before the good login
SELECT &state &state_from WHERE u.name = 'C##ACME_CL_C';
CONNECT sys/"&pwd"@&pdb AS SYSDBA
SELECT &state &state_from WHERE u.name = 'C##ACME_CL_C';
CONNECT c##acme_cl_c/"Acme_Cl_C_1"@&pdb
SELECT &whoami;
CONNECT sys/"&pwd"@&root AS SYSDBA
PROMPT -- after it
SELECT &state &state_from WHERE u.name = 'C##ACME_CL_C';
CONNECT sys/"&pwd"@&pdb AS SYSDBA
SELECT &state &state_from WHERE u.name = 'C##ACME_CL_C';

---------------------------------------------- CL4: which limit applies ----
PROMPT
PROMPT == CL4: c##acme_cl_d, limit 10 in CDB$ROOT and 2 in the PDB; two failed logins in the PDB
CONNECT c##acme_cl_d/"wrong-1"@&pdb
CONNECT c##acme_cl_d/"wrong-2"@&pdb
CONNECT sys/"&pwd"@&root AS SYSDBA
SELECT &state &state_from WHERE u.name = 'C##ACME_CL_D';
CONNECT sys/"&pwd"@&pdb AS SYSDBA
SELECT &state &state_from WHERE u.name = 'C##ACME_CL_D';
PROMPT -- the right password, in the PDB
CONNECT c##acme_cl_d/"Acme_Cl_D_1"@&pdb
SELECT &whoami;
PROMPT -- the right password, in CDB$ROOT
CONNECT c##acme_cl_d/"Acme_Cl_D_1"@&root
SELECT &whoami;
PROMPT -- one more failed login in CDB$ROOT, then the state in both containers
CONNECT c##acme_cl_d/"wrong-3"@&root
CONNECT sys/"&pwd"@&root AS SYSDBA
SELECT &state &state_from WHERE u.name = 'C##ACME_CL_D';
CONNECT sys/"&pwd"@&pdb AS SYSDBA
SELECT &state &state_from WHERE u.name = 'C##ACME_CL_D';

PROMPT
PROMPT == CL4b: c##acme_cl_f, limit 3 in CDB$ROOT and 10 in the PDB; three failed logins in the PDB
CONNECT c##acme_cl_f/"wrong-1"@&pdb
CONNECT c##acme_cl_f/"wrong-2"@&pdb
CONNECT c##acme_cl_f/"wrong-3"@&pdb
CONNECT sys/"&pwd"@&root AS SYSDBA
SELECT &state &state_from WHERE u.name = 'C##ACME_CL_F';
CONNECT sys/"&pwd"@&pdb AS SYSDBA
SELECT &state &state_from WHERE u.name = 'C##ACME_CL_F';
PROMPT -- the right password, in the PDB
CONNECT c##acme_cl_f/"Acme_Cl_F_1"@&pdb
SELECT &whoami;

------------------------------- CL5: what a PDB session can read of it ----
PROMPT
PROMPT == CL5: four failed logins in the PDB as c##acme_cl_e, limit 10
CONNECT c##acme_cl_e/"wrong-1"@&pdb
CONNECT c##acme_cl_e/"wrong-2"@&pdb
CONNECT c##acme_cl_e/"wrong-3"@&pdb
CONNECT c##acme_cl_e/"wrong-4"@&pdb
CONNECT sys/"&pwd"@&root AS SYSDBA
SELECT &state &state_from WHERE u.name = 'C##ACME_CL_E';

CONNECT acme_cl_svc/"Acme_Cl_Svc_1"@&pdb
PROMPT -- acme_cl_svc, local, in the PDB: SYS.USER$
SELECT &whoami;
SELECT name, lcount FROM sys.user$ WHERE name = 'C##ACME_CL_E';
PROMPT -- CONTAINERS(SYS.USER$)
SELECT con_id, name, lcount FROM containers(sys.user$) WHERE name = 'C##ACME_CL_E';
PROMPT -- CDB_USERS
SELECT con_id, username, account_status FROM cdb_users WHERE username = 'C##ACME_CL_E';
PROMPT -- DBA_USERS
SELECT username, common, account_status FROM dba_users WHERE username = 'C##ACME_CL_E';

CONNECT c##acme_cl_svc/"Acme_Cl_Csvc_1"@&pdb
PROMPT -- c##acme_cl_svc, common, in the PDB: SYS.USER$
SELECT &whoami;
SELECT name, lcount FROM sys.user$ WHERE name = 'C##ACME_CL_E';
PROMPT -- CONTAINERS(SYS.USER$)
SELECT con_id, name, lcount FROM containers(sys.user$) WHERE name = 'C##ACME_CL_E';
PROMPT -- CDB_USERS
SELECT con_id, username, account_status FROM cdb_users WHERE username = 'C##ACME_CL_E';
PROMPT -- DBA_USERS
SELECT username, common, account_status FROM dba_users WHERE username = 'C##ACME_CL_E';
PROMPT -- after ALTER SESSION SET CONTAINER = CDB$ROOT: SYS.USER$
ALTER SESSION SET CONTAINER = CDB$ROOT;
SELECT &whoami;
SELECT name, lcount FROM sys.user$ WHERE name = 'C##ACME_CL_E';
PROMPT -- and back in the PDB
ALTER SESSION SET CONTAINER = &pdbname;
SELECT &whoami;
SELECT name, lcount FROM sys.user$ WHERE name = 'C##ACME_CL_E';

----------------------------------------------------------------- teardown ----
CONNECT sys/"&pwd"@&pdb AS SYSDBA
DROP USER acme_cl_svc CASCADE;
DROP PROFILE acme_cl_prof2 CASCADE;
DROP PROFILE acme_cl_prof10l CASCADE;
CONNECT sys/"&pwd"@&root AS SYSDBA
DROP USER c##acme_cl_a CASCADE;
DROP USER c##acme_cl_b CASCADE;
DROP USER c##acme_cl_c CASCADE;
DROP USER c##acme_cl_d CASCADE;
DROP USER c##acme_cl_e CASCADE;
DROP USER c##acme_cl_f CASCADE;
DROP USER c##acme_cl_svc CASCADE;
DROP PROFILE c##acme_cl_prof3 CASCADE;
DROP PROFILE c##acme_cl_prof10 CASCADE;
PROMPT
PROMPT == done
EXIT
