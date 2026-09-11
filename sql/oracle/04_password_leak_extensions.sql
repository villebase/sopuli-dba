--------------------------------------------------------------------------------
-- sopuli-dba : password leakage probe, extensions   (v1)
--
-- STATUS: run on 26ai Free 23.26.2.0.0 (FREEPDB1) and 21c XE 21.3.0.0.0
-- (XEPDB1) on 2026-09-11 (#407). Every finding below is from those two runs.
-- Untried on 18c, 11.2, 12.x and 19c.
--
-- The three checks `02_password_leak_probe.sql` §6 and §7 described and left for
-- somebody to do by hand. Nobody did, for six weeks, which is the argument for
-- this file existing: a check that is a comment is a check that does not run.
--
--   6a  SELF-ROTATION   -- `ALTER USER … IDENTIFIED BY … REPLACE …`, the path
--                          where the account changes its own password and
--                          therefore exercises no ALTER USER privilege.
--                          Privilege auditing can miss what statement auditing
--                          catches, and the docs claim "rotations are audited".
--   6b  VERIFIER        -- `ALTER USER … IDENTIFIED BY VALUES '<verifier>'`.
--                          Oracle masks a *password*. Whether it masks a
--                          *verifier* is a separate question nobody had asked.
--   T   TRACE           -- the same rotations inside a 10046 level 12 traced
--                          session. sopuli never enables trace; a DBA who
--                          traces the session does, and §4 assumed the worst.
--
-- Canaries continue the main probe's numbering, so a hit in a shared directory
-- still says which path it came from:
--
--   C5  self-rotation, by the account itself
--   C6  ALTER USER issued directly, inside a traced session      <- sopuli's
--   C8  ALTER USER wrapped in a PL/SQL block, literal, traced    <- invariant 13
--   C9  ALTER USER wrapped, password assembled at runtime, traced
--
-- C6 against C8 is the pair that carries the argument, exactly as C2 against C3
-- does in the main probe. They differ only in the wrapper.
--
--
-- RESULTS
--   Identical on both versions, and the trace result is the one worth reading.
--
--   6a  SELF-ROTATION is captured and MASKED, including the old password:
--
--         ALTER USER sopulitest IDENTIFIED BY * REPLACE *
--
--       Attributed to SOPULITEST rather than to a service account, so the
--       privilege-auditing worry is answered: the event is recorded, by the
--       ACTIONS ALTER USER policy on both releases and by traditional
--       `AUDIT USER` on 21c as well. Both secrets are masked -- the REPLACE
--       clause carries the *current* password and is masked with the same `*`.
--
--   6b  THE VERIFIER IS MASKED TOO:
--
--         ALTER USER sopulitest IDENTIFIED BY VALUES *
--
--       So the restore-from-verifier path, if one is ever added, does not
--       widen the audit exposure. It is still offline-crackable wherever the
--       verifier itself can be read, which is ADR-001's question and not this
--       one.
--
--   T   A TRACED SESSION DOES NOT CAPTURE THE PASSWORD, and this reverses the
--       assumption §4 carried. 10046 level 12, five traced sessions across the
--       two versions, every one identical:
--
--         PARSING IN CURSOR #… len=37 dep=0 uid=110 oct=43 lid=110 …
--         ALTER USER sopulitest IDE
--         END OF STMT
--
--       The statement is `ALTER USER sopulitest IDENTIFIED BY "<17 bytes>"`.
--       The trace prints 25 characters of it and stops at `IDE`, one character
--       into `IDENTIFIED`. Neither C6 nor C9 appears anywhere in any trace file.
--
--       C8 does, in full, because the traced statement there is the PL/SQL
--       block and the block's own text contains the password. Invariant 13
--       again, on a fifth surface: wrapping is what exposes it.
--
--       Note `len=37` beside 25 printed characters. Do not read the truncation
--       as a buffer limit that a longer account name would push past -- it is
--       keyed to the statement type, the same way the shared pool's absence of
--       a cursor is. A 30-byte password and a 128-byte one truncate at the same
--       place.
--
--   OS AUDIT FILES, with AUDIT_SYS_OPERATIONS = TRUE, differ by release and the
--   difference is not a leak but a surface:
--
--     21c    adump is populated -- 646 ACTION lines by the end of these runs
--            -- and the DDL appears masked there too:
--              ACTION :[37] 'ALTER USER sopulitest IDENTIFIED BY *'
--            Only the PL/SQL wrapper (C3, from the main probe) appears
--            verbatim, in one file.
--     26ai   adump holds 5 files, each a session header plus exactly one
--            ACTION line, and all five are the same internal call
--            (`dbms_cmp_int.drop_cmp_by_cmpid`). **No CREATE, ALTER or DROP
--            USER text reaches it at all**, and no file mentions SOPULITEST.
--            Traditional auditing is desupported on 23ai+, so
--            AUDIT_SYS_OPERATIONS is accepted and writes nothing useful. Read
--            that as the surface being ABSENT, not as a clean sweep of a
--            populated one -- it is the OS-file form of the `pop=n` rule.
--
--
-- HOW TO RUN
--   Needs `sopuli_svc` to exist already, holding CREATE SESSION and ALTER USER,
--   which is what `02_password_leak_probe.sql` position 1 also needs. Run that
--   first; this script assumes its account and reuses its canary prefix.
--
--     sqlplus -S /nolog @04_password_leak_extensions.sql "//host:1521/SERVICE"
--
--   Then run the greps §4 of this file prints, on the server.
--
--   **Run `02_password_leak_probe.sql` §2 again first, or re-enable auditing by
--   hand.** That script's §8 cleanup drops SOPULI_PROBE_POL and issues
--   `NOAUDIT USER`, so a run of this file straight afterwards records nothing
--   and reports a masking result it did not earn. That cost a run on each
--   version here before it was understood: on 21c the Oracle-supplied
--   ORA_SECURECONFIG policy is enabled and covers ALTER USER, so the trail
--   looked populated anyway; on 26ai nothing was enabled at all and the trail
--   came back empty. The second is the honest failure and the first is the
--   dangerous one.
--
-- THROWAWAY DATABASES ONLY. Creates SOPULITEST, plants four passwords in
-- cleartext across the audit trail and the trace directory, and leaves them.
--------------------------------------------------------------------------------

SET SERVEROUTPUT ON SIZE UNLIMITED FORMAT WRAPPED
SET LINESIZE 200
SET PAGESIZE 1000
SET LONG 8000
SET TRIMSPOOL ON
SET FEEDBACK OFF
SET VERIFY OFF
SET DEFINE ON
SET ECHO OFF

-- Connection. `&1` is the easy-connect string, so the same file serves every
-- container in the stack without editing.
DEFINE tns      = &1
DEFINE sys_user = sys
DEFINE sys_pwd  = CHANGEME_SYS_PASSWORD
DEFINE svc_user = sopuli_svc
DEFINE svc_pwd  = CHANGEME_SVC_PASSWORD

-- Same prefix as the main probe, held apart from its suffix for the same
-- reason: every query below assembles the full string inside PL/SQL, so this
-- script's own SQL text can never match itself. §4's greps take the prefix
-- PLUS A DIGIT, never the bare prefix.
DEFINE cpfx = S0puliCanary
DEFINE c1   = S0puliCanary1Aq7x
DEFINE c5   = S0puliCanary5Eq7x
DEFINE c6   = S0puliCanary6Fq7x
DEFINE c8   = S0puliCanary8Hq7x

WHENEVER SQLERROR EXIT FAILURE
CONNECT &sys_user/"&sys_pwd"@&tns AS SYSDBA
WHENEVER SQLERROR CONTINUE NONE
SET SERVEROUTPUT ON SIZE UNLIMITED FORMAT WRAPPED

PROMPT
PROMPT ================================================================================
PROMPT  0. Setup
PROMPT ================================================================================

DECLARE
  l_cnt PLS_INTEGER;
BEGIN
  SELECT COUNT(*) INTO l_cnt FROM dba_users WHERE username = UPPER('&svc_user');
  IF l_cnt = 0 THEN
    RAISE_APPLICATION_ERROR(-20001,
      '&svc_user does not exist. Run 02_password_leak_probe.sql position 1 '
      || 'first -- this script reuses its service account rather than making '
      || 'a second one that could differ from it.');
  END IF;
END;
/

-- Dropped rather than refused, unlike the main probe: that one plants the
-- canaries a whole release gate is read off and must not touch an account
-- somebody else made. This one runs after it, on the account it made.
DECLARE
BEGIN
  EXECUTE IMMEDIATE 'DROP USER sopulitest CASCADE';
  DBMS_OUTPUT.PUT_LINE('dropped the previous SOPULITEST');
EXCEPTION WHEN OTHERS THEN
  NULL;
END;
/

CREATE USER sopulitest IDENTIFIED BY "&c1";
GRANT CREATE SESSION, ALTER SESSION TO sopulitest;
GRANT ALTER SESSION TO &svc_user;

-- Watermark, so a second run does not read the first one's rows. Read in
-- PL/SQL because 11.2 has no unified trail at all and a bare SELECT would
-- leave the substitution variable undefined -- the main probe's §3 has the
-- full account of what that costs.
SET TERMOUT OFF
VARIABLE ext_mark VARCHAR2(40)
BEGIN
  BEGIN
    EXECUTE IMMEDIATE
      'SELECT TO_CHAR(NVL(MAX(event_timestamp), TIMESTAMP ''1900-01-01 00:00:00''),'
      || ' ''YYYY-MM-DD HH24:MI:SS.FF6'') FROM unified_audit_trail'
      INTO :ext_mark;
  EXCEPTION
    WHEN OTHERS THEN
      IF SQLCODE != -942 THEN
        RAISE;
      END IF;
      :ext_mark := '1900-01-01 00:00:00.000000';
  END;
END;
/
COLUMN ext_mark NEW_VALUE uat_mark NOPRINT
SELECT :ext_mark AS ext_mark FROM dual;
SET TERMOUT ON

PROMPT watermark taken

PROMPT
PROMPT --- is anything actually auditing ALTER USER right now?
PROMPT  If this says (none), stop: every masking result below would be an empty
PROMPT  trail rather than a masked one. Re-run 02_password_leak_probe.sql §2.
DECLARE
  l_out VARCHAR2(4000);
BEGIN
  BEGIN
    EXECUTE IMMEDIATE 'SELECT LISTAGG(policy_name, '', '') WITHIN GROUP '
                   || '(ORDER BY policy_name) FROM audit_unified_enabled_policies'
      INTO l_out;
    DBMS_OUTPUT.PUT_LINE('unified policies enabled    ' || NVL(l_out, '(none)'));
  EXCEPTION WHEN OTHERS THEN
    DBMS_OUTPUT.PUT_LINE('unified policies enabled    n/a on this release');
  END;
  BEGIN
    EXECUTE IMMEDIATE 'SELECT LISTAGG(audit_option, '', '') WITHIN GROUP '
                   || '(ORDER BY audit_option) FROM dba_stmt_audit_opts '
                   || 'WHERE audit_option LIKE ''%USER%'''
      INTO l_out;
    DBMS_OUTPUT.PUT_LINE('traditional statement opts  ' || NVL(l_out, '(none)'));
  EXCEPTION WHEN OTHERS THEN
    DBMS_OUTPUT.PUT_LINE('traditional statement opts  n/a on this release');
  END;
END;
/

--------------------------------------------------------------------------------
-- 1. §6a — self-rotation
--
-- The account changes its own password. No ALTER USER privilege is exercised,
-- which is the whole reason this is a separate question: DBA_PRIV_AUDIT_OPTS
-- records statements executed *by virtue of* a privilege.
--------------------------------------------------------------------------------
PROMPT
PROMPT ================================================================================
PROMPT  1. Self-rotation -- the account changes its OWN password (C5)
PROMPT ================================================================================

WHENEVER SQLERROR EXIT FAILURE
CONNECT sopulitest/"&c1"@&tns
WHENEVER SQLERROR CONTINUE NONE
SET SERVEROUTPUT ON SIZE UNLIMITED FORMAT WRAPPED

COLUMN whoami FORMAT A90
SELECT 'self-rotating as ' || SYS_CONTEXT('USERENV','SESSION_USER')
    || ', isdba=' || NVL(SYS_CONTEXT('USERENV','ISDBA'), '?') AS whoami
  FROM dual;

ALTER USER sopulitest IDENTIFIED BY "&c5" REPLACE "&c1";

PROMPT C5 planted. Note that REPLACE carries the CURRENT password too -- two
PROMPT secrets in one statement, and §3 below shows what happened to both.

--------------------------------------------------------------------------------
-- 2. Trace — the same rotations, in a traced session
--
-- level 12 is level 8 (waits) plus level 4 (binds), which is what a DBA
-- diagnosing a hang actually sets. Nothing here asks sopuli to enable trace;
-- the question is what happens when somebody else has.
--------------------------------------------------------------------------------
PROMPT
PROMPT ================================================================================
PROMPT  2. A traced session issues the rotations (10046 level 12)
PROMPT ================================================================================

WHENEVER SQLERROR EXIT FAILURE
CONNECT &svc_user/"&svc_pwd"@&tns
WHENEVER SQLERROR CONTINUE NONE
SET SERVEROUTPUT ON SIZE UNLIMITED FORMAT WRAPPED

ALTER SESSION SET tracefile_identifier = 'SOPULIPROBE';
ALTER SESSION SET events '10046 trace name context forever, level 12';

-- C6: exactly what sopuli sends, traced.
ALTER USER sopulitest IDENTIFIED BY "&c6";

DECLARE
  l_pwd VARCHAR2(30);
BEGIN
  -- C8: the complete secret is a literal in this block's own text.
  EXECUTE IMMEDIATE 'ALTER USER sopulitest IDENTIFIED BY "&c8"';

  -- C9: assembled at runtime, so the block text holds the halves and never the
  -- whole. A control, not a technique -- the main probe's §0 says why.
  l_pwd := '&cpfx' || '9Iq7x';
  EXECUTE IMMEDIATE 'ALTER USER sopulitest IDENTIFIED BY "' || l_pwd || '"';
END;
/

ALTER SESSION SET events '10046 trace name context off';

COLUMN tracefile FORMAT A110
SELECT value AS tracefile FROM v$diag_info WHERE name = 'Default Trace File';

PROMPT C6 (direct), C8 (wrapped literal) and C9 (assembled) planted under trace.
PROMPT Grep that file in §4. C6 absent and C8 present is the expected result.

--------------------------------------------------------------------------------
-- 3. §6b — IDENTIFIED BY VALUES, and what the trail shows for all of it
--------------------------------------------------------------------------------
PROMPT
PROMPT ================================================================================
PROMPT  3. IDENTIFIED BY VALUES -- does Oracle mask a VERIFIER?
PROMPT ================================================================================

WHENEVER SQLERROR EXIT FAILURE
CONNECT &sys_user/"&sys_pwd"@&tns AS SYSDBA
WHENEVER SQLERROR CONTINUE NONE
SET SERVEROUTPUT ON SIZE UNLIMITED FORMAT WRAPPED

PROMPT
PROMPT --- the verifier being re-applied, truncated here to 150 characters
COLUMN spare4 FORMAT A150
SELECT SUBSTR(spare4, 1, 150) AS spare4 FROM sys.user$ WHERE name = 'SOPULITEST';

DECLARE
  l_v VARCHAR2(4000);
BEGIN
  SELECT spare4 INTO l_v FROM sys.user$ WHERE name = 'SOPULITEST';
  EXECUTE IMMEDIATE 'ALTER USER sopulitest IDENTIFIED BY VALUES ''' || l_v || '''';
  DBMS_OUTPUT.PUT_LINE('verifier re-applied, length ' || LENGTH(l_v));
EXCEPTION WHEN OTHERS THEN
  -- SELECT ON SYS.USER$ is itself an open question (ADR-001). A release or an
  -- install that withholds it leaves 6b unanswerable rather than clean.
  DBMS_OUTPUT.PUT_LINE('6b UNANSWERED here -- ' || SUBSTR(SQLERRM, 1, 120));
END;
/

PROMPT
PROMPT --- unified trail, this run only. Every row should end in `*`.
COLUMN dbusername  FORMAT A14
COLUMN action_name FORMAT A12
COLUMN txt         FORMAT A60
SELECT TO_CHAR(event_timestamp, 'HH24:MI:SS.FF3') AS ts,
       dbusername, action_name, SUBSTR(sql_text, 1, 60) AS txt
  FROM unified_audit_trail
 WHERE object_name = 'SOPULITEST'
   AND event_timestamp > TO_TIMESTAMP('&uat_mark', 'YYYY-MM-DD HH24:MI:SS.FF6')
 ORDER BY event_timestamp;

PROMPT
PROMPT --- traditional trail, where the release still has one
COLUMN username FORMAT A14
COLUMN sql_text FORMAT A60
SELECT TO_CHAR(timestamp, 'HH24:MI:SS') AS ts,
       username, action_name, SUBSTR(sql_text, 1, 60) AS sql_text
  FROM dba_audit_trail
 WHERE obj_name = 'SOPULITEST'
 ORDER BY timestamp;

--------------------------------------------------------------------------------
-- 4. What SQL cannot reach
--------------------------------------------------------------------------------
PROMPT
PROMPT ================================================================================
PROMPT  4. Off-database checks, run these on the server
PROMPT ================================================================================

SET HEADING OFF
SELECT '  grep -rlE ''&cpfx.[0-9]'' ' || value || '/     # trace: C8 only is the pass'
  FROM v$diag_info WHERE name = 'Diag Trace'
UNION ALL
SELECT '  grep -rlE ''&cpfx.[0-9]'' ' || value || '/     # OS audit files'
  FROM v$parameter WHERE name = 'audit_file_dest'
UNION ALL
SELECT '  grep -rhE ''^ACTION'' ' || value || '/ | wc -l     # is adump populated AT ALL?'
  FROM v$parameter WHERE name = 'audit_file_dest';
SET HEADING ON

PROMPT
PROMPT  Read the third one before the second. An `audit_file_dest` with no
PROMPT  ACTION lines is the OS-file form of the sweep's `pop=n`: a clean grep
PROMPT  there is an absence of evidence, not a masked statement. That is exactly
PROMPT  what 26ai gives -- traditional auditing is desupported on 23ai+, so
PROMPT  AUDIT_SYS_OPERATIONS is accepted and writes nothing.
PROMPT
PROMPT  The pattern is the prefix PLUS A DIGIT. The bare prefix appears in this
PROMPT  script's own text, so with AUDIT_SYS_OPERATIONS = TRUE it matches the
PROMPT  probe reading itself -- a false positive in the one place it would
PROMPT  matter most. The main probe's §7 has the full account.
PROMPT
PROMPT  Expected, on 26ai and 21c: the trace directory names the SOPULIPROBE
PROMPT  files and C8 is the only canary in them. C6 and C9 appear nowhere.
PROMPT

--------------------------------------------------------------------------------
-- 5. Cleanup
--
-- The account goes. The trace files and audit records stay -- they are the
-- evidence, and they hold four passwords in clear. Delete them once the
-- findings are written up.
--------------------------------------------------------------------------------
PROMPT ================================================================================
PROMPT  5. Cleanup
PROMPT ================================================================================

DECLARE
BEGIN
  EXECUTE IMMEDIATE 'DROP USER sopulitest CASCADE';
  DBMS_OUTPUT.PUT_LINE('dropped SOPULITEST');
EXCEPTION WHEN OTHERS THEN
  DBMS_OUTPUT.PUT_LINE('drop failed -- ' || SQLERRM);
END;
/

PROMPT
PROMPT  Audit policies are LEFT ENABLED, unlike 02_password_leak_probe.sql §8.
PROMPT  That script turns them off, which is what made this one report an empty
PROMPT  trail when the two were run back to back. Turn them off by hand when the
PROMPT  whole gate is finished, not between its halves.
PROMPT
PROMPT  Then delete the SOPULIPROBE trace files and purge the planted audit
PROMPT  records -- 02_password_leak_probe.sql §8 has the DBMS_AUDIT_MGMT call
PROMPT  and the warning about never deleting from AUDSYS.AUD$UNIFIED by hand.
PROMPT
