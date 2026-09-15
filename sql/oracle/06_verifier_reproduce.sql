--------------------------------------------------------------------------------
-- sopuli-dba : password verifier reproduction probe   (v1)
--
-- STATUS: run on 26ai Free 23.26.2.0.0 (FREEPDB1), 21c XE 21.3.0.0.0 (XEPDB1)
-- and 18c XE 18.4.0.0.0 (XEPDB1) on 2026-09-15 (#432), twice each. **Untried on
-- 19c, 12.1 and 12.2**, exactly as the layout probe (#431). 11g carries no 12C
-- verifier and is not a target here. The rollover window opened on 26ai and 21c;
-- 18c has no rollover feature and the section reports a plain rotation there.
--
-- Part 2 of #90's spike (#432). It does NOT derive anything itself: it sets
-- known passwords on a throwaway account and prints, for each, the password
-- bytes (as hex) and the stored SPARE4. The companion 06_verifier_reproduce.py
-- reads this output and regenerates every T:/t: digest client-side, comparing
-- byte-for-byte. Emitting the password bytes rather than hard-coding them in the
-- Python keeps the two halves from drifting and proves the derivation runs on
-- the exact bytes the server hashed.
--
-- THROWAWAY DATABASES ONLY. Creates and drops ACME_KDF_USER and ACME_ROLL_USER
-- and a throwaway profile, and prints passwords next to their verifiers.
--
--
-- RESULTS  (26ai / 21c / 18c, both runs)
--
--   1. EVERY STORED T: REPRODUCES BYTE-FOR-FOR-BYTE. The Python companion
--      prints MATCH for all four static cases on 26ai and 21c, and for the
--      three that fit on 18c:
--
--        label     pw bytes   verifiers  result
--        ascii           12          1   MATCH
--        symbols         15          1   MATCH
--        nonascii        16          1   MATCH   (12 chars, Ä Ö Ω are 2 bytes)
--        longest        128 / 30      1   MATCH   (128 bytes on 26ai; 30 on 21c/18c)
--
--      The password is fed as raw UTF-8 with no case folding or normalisation:
--      the non-ASCII case matches on the multibyte input unchanged. `longest`
--      is the longest the release accepts (#383/#380: 30 bytes below 23ai), so
--      the parameters hold at the length limit, not only for short inputs.
--
--   2. THE ROLLOVER WINDOW CARRIES TWO 12C VERIFIERS, distinguishable by the
--      client-side comparison. After rotating old -> new on a profile with
--      PASSWORD_ROLLOVER_TIME set (26ai and 21c):
--
--        BEFORE  1 verifier(s):  T: = old
--        DURING  2 verifier(s):  T: = old, t: = new
--        AFTER   1 verifier(s):  T: = new
--
--      **The prefix carries the meaning: uppercase `T:` is the PREVIOUS
--      password, lowercase `t:` the CURRENT (just-rotated-to) one.** Both share
--      one salt. `V:` also appears during the window and is not a verifier. So
--      `check` can report ROLLOVER_ACTIVE by seeing two 12C verifiers, and
--      `--include-previous` tells current from previous by which prefix the
--      vault value reproduces -- not by drift. On 18c, with no rollover feature,
--      DURING shows one verifier (= new): a plain rotation, honestly reported.
--
--      Gradual rollover needs 19.12+/21c+; the buildable 19c base is 19.3 and
--      cannot open a window (04-testing.md §5). The two-verifier result is
--      therefore measured on 26ai and 21c here and stays to be confirmed on real
--      19.12+ (maintainer tier), like every other rollover finding.
--
--   INVARIANT 14. This reproduction is entirely client-side: the verifier is
--   read with a SELECT and compared in Python. If a server-side form is ever
--   added, the verifier must not be bound into a SQL predicate --
--   V$SQL_BIND_CAPTURE keeps bind values in clear. Recorded here so the
--   implementation issue inherits the constraint.
--
--
-- HOW TO RUN (from the repo root, against the tier-2 stack):
--
--     docker exec -i -e NLS_LANG=AMERICAN_AMERICA.AL32UTF8 \
--       sopuli-test-oracle-free-1 sqlplus -s / as sysdba \
--       < sql/oracle/06_verifier_reproduce.sql \
--       | python sql/oracle/06_verifier_reproduce.py
--
--   SYSDBA, for the same reason as 05: the script creates, alters and drops
--   users and a profile. A UTF-8 client (NLS_LANG above) so the non-ASCII
--   password reaches the server as the bytes the Python then hashes.
--------------------------------------------------------------------------------

SET PAGESIZE 0 LINESIZE 4000 FEEDBACK OFF HEADING OFF VERIFY OFF TRIMSPOOL ON
SET LONG 4000 LONGCHUNKSIZE 4000
SET SERVEROUTPUT ON
SET DEFINE ON

--------------------------------------------------------------------------------
-- §0  Move into the application PDB if there is one (see 05's §0)
--------------------------------------------------------------------------------
DECLARE
  l_pdb     VARCHAR2(128);
  no_view   EXCEPTION;
  PRAGMA EXCEPTION_INIT(no_view, -942);
BEGIN
  EXECUTE IMMEDIATE
    q'[SELECT MIN(name) FROM v$pdbs WHERE name IN ('FREEPDB1', 'XEPDB1')]'
    INTO l_pdb;
  IF l_pdb IS NOT NULL THEN
    EXECUTE IMMEDIATE 'ALTER SESSION SET CONTAINER = ' || l_pdb;
  END IF;
EXCEPTION
  WHEN no_view THEN
    NULL;  -- 11g: no V$PDBS, a non-CDB
END;
/

SELECT '== release ' || version || ', container '
       || SYS_CONTEXT('USERENV', 'DB_NAME') FROM v$instance;

--------------------------------------------------------------------------------
-- §1  Static password matrix
--------------------------------------------------------------------------------
-- Each ALTER USER is issued directly, never wrapped in a PL/SQL block
-- (invariant 13). RESULT|<label>|<password bytes as hex>|<SPARE4>.
WHENEVER SQLERROR CONTINUE
DROP USER acme_kdf_user CASCADE;
WHENEVER SQLERROR EXIT FAILURE
CREATE USER acme_kdf_user IDENTIFIED BY "Acme-Probe-1";

SELECT 'RESULT|ascii|' || RAWTOHEX(UTL_RAW.CAST_TO_RAW('Acme-Probe-1'))
       || '|' || spare4 FROM sys.user$ WHERE name = 'ACME_KDF_USER';

ALTER USER acme_kdf_user IDENTIFIED BY "P@55-w0rd_#9=+.";
SELECT 'RESULT|symbols|' || RAWTOHEX(UTL_RAW.CAST_TO_RAW('P@55-w0rd_#9=+.'))
       || '|' || spare4 FROM sys.user$ WHERE name = 'ACME_KDF_USER';

ALTER USER acme_kdf_user IDENTIFIED BY "Äcme-Pröbe-Ω9";
SELECT 'RESULT|nonascii|' || RAWTOHEX(UTL_RAW.CAST_TO_RAW('Äcme-Pröbe-Ω9'))
       || '|' || spare4 FROM sys.user$ WHERE name = 'ACME_KDF_USER';

-- The longest password the release accepts: 128 bytes on 23ai+, 30 below it
-- (#383/#380). Picked by version so the ALTER always succeeds and the case is
-- always "at this release's limit" rather than a length one release rejects.
COLUMN longpw NEW_VALUE longpw NOPRINT
SELECT RPAD('Lx9', CASE WHEN TO_NUMBER(REGEXP_SUBSTR(version, '^\d+')) >= 23
                        THEN 128 ELSE 30 END, 'Ab7z') longpw
  FROM v$instance;
ALTER USER acme_kdf_user IDENTIFIED BY "&longpw";
SELECT 'RESULT|longest|' || RAWTOHEX(UTL_RAW.CAST_TO_RAW('&longpw'))
       || '|' || spare4 FROM sys.user$ WHERE name = 'ACME_KDF_USER';

DROP USER acme_kdf_user CASCADE;

--------------------------------------------------------------------------------
-- §2  Rollover window
--------------------------------------------------------------------------------
-- A throwaway profile with a rollover time, so this does not depend on the
-- test-stack init having run. CREATE PROFILE fails below 19.12; the assignment
-- then fails too and the rotation is an ordinary one -- reported honestly as a
-- single verifier rather than pretended to be a window.
WHENEVER SQLERROR CONTINUE
DROP USER acme_roll_user CASCADE;
DROP PROFILE acme_roll_prof;
CREATE PROFILE acme_roll_prof LIMIT PASSWORD_ROLLOVER_TIME 1/24;
WHENEVER SQLERROR EXIT FAILURE
CREATE USER acme_roll_user IDENTIFIED BY "Old-Pa55-word1";
WHENEVER SQLERROR CONTINUE
ALTER USER acme_roll_user PROFILE acme_roll_prof;
WHENEVER SQLERROR EXIT FAILURE

SELECT 'ROLLPW|old|' || RAWTOHEX(UTL_RAW.CAST_TO_RAW('Old-Pa55-word1')) FROM dual;
SELECT 'ROLLPW|new|' || RAWTOHEX(UTL_RAW.CAST_TO_RAW('New-Pa55-word2')) FROM dual;

SELECT 'ROLL|BEFORE|' || spare4 FROM sys.user$ WHERE name = 'ACME_ROLL_USER';
ALTER USER acme_roll_user IDENTIFIED BY "New-Pa55-word2";
SELECT 'ROLL|DURING|' || spare4 FROM sys.user$ WHERE name = 'ACME_ROLL_USER';
SELECT 'ROLLNOTE|account_status=' || account_status
  FROM dba_users WHERE username = 'ACME_ROLL_USER';

WHENEVER SQLERROR CONTINUE
ALTER USER acme_roll_user EXPIRE PASSWORD ROLLOVER PERIOD;
WHENEVER SQLERROR EXIT FAILURE
SELECT 'ROLL|AFTER|' || spare4 FROM sys.user$ WHERE name = 'ACME_ROLL_USER';

WHENEVER SQLERROR CONTINUE
DROP USER acme_roll_user CASCADE;
DROP PROFILE acme_roll_prof;

EXIT
