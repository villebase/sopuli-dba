--------------------------------------------------------------------------------
-- sopuli-dba : a lock somebody set, a lockout, and NO AUTHENTICATION   (v1)
--
-- #1447. A report rule's `login: refused` passes on a lock somebody set and
-- not on a lockout after failed logins, and passes on an account made
-- NO AUTHENTICATION. The survey tells these apart from DBA_USERS,
-- DBA_PROFILES and SYS.USER$. This measures what each one reads:
--
--   KD1  a lockout under a finite lock time: FAILED_LOGIN_ATTEMPTS 1,
--        PASSWORD_LOCK_TIME 1, one failed login
--   KD2  a lockout under PASSWORD_LOCK_TIME UNLIMITED: FAILED_LOGIN_ATTEMPTS 1,
--        one failed login
--   KD3  a lock somebody set under the UNLIMITED profile: ACCOUNT LOCK, no
--        failed login
--   KD4  a lock somebody set after failed logins below the limit: the
--        UNLIMITED profile with FAILED_LOGIN_ATTEMPTS 3, two failed logins,
--        then ACCOUNT LOCK
--   KD5  an account made NO AUTHENTICATION: what it reads, and what a login
--        with a password gets
--   KD6  KD2's lockout after its profile's FAILED_LOGIN_ATTEMPTS is raised
--        from 1 to 10
--
-- For each, as SYS in the PDB: DBA_USERS.ACCOUNT_STATUS and
-- AUTHENTICATION_TYPE, SYS.USER$.ASTATUS and LCOUNT, and the profile's
-- FAILED_LOGIN_ATTEMPTS and PASSWORD_LOCK_TIME.
--
-- This MEASURES and decides nothing.
--
-- STATUS: run 2026-11-11 on 26ai Free 23.26.3.0.0 (gvenzl/oracle-free:latest,
-- FREEPDB1), twice, with the same results apart from the lock timestamps.
-- Every other release UNRUN.
--
--
-- RESULTS -- 23.26.3.0.0, 2026-11-11
--
--   case  ACCOUNT_STATUS  AUTH      ASTATUS  LCOUNT  FAILED_LOGIN_ATTEMPTS  PASSWORD_LOCK_TIME
--   KD1   LOCKED(TIMED)   PASSWORD  4        1       1                      1
--   KD2   LOCKED          PASSWORD  8        1       1                      UNLIMITED
--   KD3   LOCKED          PASSWORD  8        0       1                      UNLIMITED
--   KD4   LOCKED          PASSWORD  8        2       3                      UNLIMITED
--   KD5   OPEN            NONE      0        0       UNLIMITED              1
--
--   KD5 is on the DEFAULT profile, whose two values are the tier-1 stack's.
--   KD6   LOCKED          PASSWORD  8        1       10                     UNLIMITED
--
--   KD2 and KD3 read the same in every column but LCOUNT: under UNLIMITED a
--   lockout is LOCKED, with ASTATUS 8, as a lock somebody set is. KD1 shows
--   the finite case: LOCKED(TIMED) and ASTATUS 4. KD4 shows that a lock
--   somebody set can follow failed logins, with LCOUNT below the limit. KD6
--   shows that raising the limit after a lockout leaves the account LOCKED and
--   LCOUNT 1, now below the limit: the count is compared with the limit the
--   profile has now, not the one in force when it locked.
--   KD5 reads OPEN, and a login with any password gets ORA-01017.
--
--
-- HOW TO RUN. Against the tier-1 stack, from this directory, where the SYS
--   password is the public one in test/compose.yaml, as it stands:
--
--     MSYS_NO_PATHCONV=1 docker exec -i sopuli-test-oracle-free-1 \
--       sqlplus -S /nolog < 22_lock_kind_probe.sql
--
--   A second clone's stack names the container after its COMPOSE_PROJECT_NAME,
--   such as sopuli-test-w2-oracle-free-1. On XE the PDB is XEPDB1. /nolog, and
--   every CONNECT made from the script, so no password is ever in argv
--   (invariant 1). Against any other database, copy the file, edit the two
--   DEFINEs in the copy, run the copy and delete it -- never substitute them
--   with sed, which puts the password in argv instead. MSYS_NO_PATHCONV is for
--   Git Bash, which otherwise rewrites /nolog.
--
-- WHENEVER SQLERROR is CONTINUE throughout: the failed logins are the
-- question, and so is the error a login to the KD5 account gets.
--
-- THROWAWAY DATABASES ONLY. Creates and drops accounts and profiles, fails
-- logins on purpose and locks accounts.
--------------------------------------------------------------------------------
define pdb = //localhost:1521/FREEPDB1
define pwd = sopuli-test

WHENEVER SQLERROR CONTINUE
SET LINESIZE 200 PAGESIZE 100 FEEDBACK OFF VERIFY OFF HEADING ON
COLUMN name           FORMAT A16
COLUMN account_status FORMAT A16
COLUMN auth           FORMAT A9
COLUMN attempts       FORMAT A10
COLUMN lock_time      FORMAT A10

-- One row per probe account, as SYS reads it in the PDB.
define state = "u.name, d.account_status, d.authentication_type auth, u.astatus, u.lcount, a.limit attempts, t.limit lock_time"
define state_from = "FROM sys.user$ u JOIN dba_users d ON d.username = u.name JOIN dba_profiles a ON a.profile = d.profile AND a.resource_name = 'FAILED_LOGIN_ATTEMPTS' JOIN dba_profiles t ON t.profile = d.profile AND t.resource_name = 'PASSWORD_LOCK_TIME'"

CONNECT sys/"&pwd"@&pdb AS SYSDBA
BEGIN
  FOR u IN (SELECT username FROM dba_users WHERE username LIKE 'ACME_KD%') LOOP
    EXECUTE IMMEDIATE 'DROP USER ' || u.username || ' CASCADE';
  END LOOP;
  FOR p IN (SELECT DISTINCT profile FROM dba_profiles WHERE profile LIKE 'ACME_KD%') LOOP
    EXECUTE IMMEDIATE 'DROP PROFILE ' || p.profile || ' CASCADE';
  END LOOP;
END;
/

CREATE PROFILE acme_kd_timed LIMIT FAILED_LOGIN_ATTEMPTS 1 PASSWORD_LOCK_TIME 1;
CREATE PROFILE acme_kd_unl1 LIMIT FAILED_LOGIN_ATTEMPTS 1 PASSWORD_LOCK_TIME UNLIMITED;
CREATE PROFILE acme_kd_unl3 LIMIT FAILED_LOGIN_ATTEMPTS 3 PASSWORD_LOCK_TIME UNLIMITED;
CREATE PROFILE acme_kd_unl6 LIMIT FAILED_LOGIN_ATTEMPTS 1 PASSWORD_LOCK_TIME UNLIMITED;
CREATE USER acme_kd1 IDENTIFIED BY "Acme_Kd1_1" PROFILE acme_kd_timed;
CREATE USER acme_kd2 IDENTIFIED BY "Acme_Kd2_1" PROFILE acme_kd_unl1;
CREATE USER acme_kd3 IDENTIFIED BY "Acme_Kd3_1" PROFILE acme_kd_unl1;
CREATE USER acme_kd4 IDENTIFIED BY "Acme_Kd4_1" PROFILE acme_kd_unl3;
CREATE USER acme_kd5 NO AUTHENTICATION;
CREATE USER acme_kd6 IDENTIFIED BY "Acme_Kd6_1" PROFILE acme_kd_unl6;
GRANT CREATE SESSION TO acme_kd1, acme_kd2, acme_kd3, acme_kd4, acme_kd5, acme_kd6;

PROMPT
PROMPT == KD1, KD2, KD6: one failed login each
CONNECT acme_kd1/"wrong-1"@&pdb
CONNECT acme_kd2/"wrong-1"@&pdb
CONNECT acme_kd6/"wrong-1"@&pdb
PROMPT
PROMPT == KD4: two failed logins
CONNECT acme_kd4/"wrong-1"@&pdb
CONNECT acme_kd4/"wrong-2"@&pdb
PROMPT
PROMPT == KD5: a login with a password to a NO AUTHENTICATION account
CONNECT acme_kd5/"anything-1"@&pdb

CONNECT sys/"&pwd"@&pdb AS SYSDBA
ALTER USER acme_kd3 ACCOUNT LOCK;
ALTER USER acme_kd4 ACCOUNT LOCK;
ALTER PROFILE acme_kd_unl6 LIMIT FAILED_LOGIN_ATTEMPTS 10;

PROMPT
PROMPT == the six accounts, as SYS reads them in the PDB
SELECT &state &state_from WHERE u.name LIKE 'ACME_KD%' ORDER BY u.name;

BEGIN
  FOR u IN (SELECT username FROM dba_users WHERE username LIKE 'ACME_KD%') LOOP
    EXECUTE IMMEDIATE 'DROP USER ' || u.username || ' CASCADE';
  END LOOP;
  FOR p IN (SELECT DISTINCT profile FROM dba_profiles WHERE profile LIKE 'ACME_KD%') LOOP
    EXECUTE IMMEDIATE 'DROP PROFILE ' || p.profile || ' CASCADE';
  END LOOP;
END;
/
PROMPT
PROMPT == done
EXIT
