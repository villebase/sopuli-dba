--------------------------------------------------------------------------------
-- sopuli-dba : lock, LCOUNT and rollover probe   (v2)
--
-- H4 (#455), the UC-2 reset's open behaviours. Answers what
-- use-cases/uc-02-personal-account-passwords.md sec.5 says has "not been run",
-- and what CLAUDE.md will not let be reasoned about instead:
--
--   Q1  does ALTER USER ... ACCOUNT UNLOCK on an account that is NOT locked
--       reset SYS.USER$.LCOUNT? (i.e. is "it does no harm" true?)
--   Q2  does ALTER USER ... IDENTIFIED BY reset LCOUNT on its own?
--   Q3  does ALTER USER ... IDENTIFIED BY clear LOCKED(TIMED)?
--   Q4  does ALTER USER ... IDENTIFIED BY clear an explicit ACCOUNT LOCK?
--   Q5  does the combined ACCOUNT UNLOCK + IDENTIFIED BY form parse, in either
--       clause order?
--   Q6  the UC-2 reset shape on a rollover profile: IDENTIFIED BY, then
--       EXPIRE PASSWORD ROLLOVER PERIOD back to back in one session. Which
--       passwords authenticate at each step?
--   Q7  EXTRA, and deliberately separate: the `expire-rollover` register entry
--       (docs/README.md) -- what IDENTIFIED BY ... PASSWORD EXPIRE does on a
--       profile with PASSWORD_ROLLOVER_TIME. This section MEASURES and decides
--       nothing; uc-02 sec.4.3 refuses that combination until someone reads it.
--
-- STATUS: run on 26ai Free 23.26.2.0.0 (gvenzl/oracle-free:latest), FREEPDB1,
-- as SYSTEM, 2026-09-16 -- results in RESULTS below. 21c, 18c, 11.2 and 19c
-- UNRUN. 18c and 11.2 have no rollover, so sections 7-9 must report ABSENT
-- there rather than clean; Q1-Q5 should run on every line.
--
-- THROWAWAY DATABASES ONLY. Creates and drops an account, deliberately locks
-- it, and plants known passwords.
--
--
-- RESULTS -- 26ai Free 23.26.2.0.0, FREEPDB1, as SYSTEM, 2026-09-16
--
--   Q1  ACCOUNT UNLOCK on an UNLOCKED account RESETS LCOUNT: 2 -> 0.
--       So "it does no harm even if the account is not locked" is FALSE on this
--       release. It is silent and it leaves ACCOUNT_STATUS alone, but it clears
--       the failed-login counter that UC-1 sec.7's --lockout-margin reads.
--       tests/driver/test_oracle_unlock.py's docstring says the statement
--       "changes nothing" against an open account; it changes this.
--
--   Q2  IDENTIFIED BY does NOT reset LCOUNT: 2 -> 2.
--       The two statements differ on this axis, which is what makes Q1 matter
--       rather than being a curiosity.
--
--   Q3  IDENTIFIED BY does NOT clear LOCKED(TIMED). Status, LOCK_DATE and
--       LCOUNT are all unchanged (LOCKED(TIMED), 3), and a login with the NEW
--       password is ORA-28000. **A reset that does not unlock does not let the
--       person in.** This is the measurement H4's unlock question turns on.
--
--   Q4  IDENTIFIED BY does NOT clear a deliberate ACCOUNT LOCK either: status
--       stays LOCKED and the new password is ORA-28000. LOCKED and
--       LOCKED(TIMED) are distinct ACCOUNT_STATUS strings, so a plan can tell
--       a lock somebody chose from one a failed-login limit produced.
--
--   Q5  BOTH clause orders are ACCEPTED. `ACCOUNT UNLOCK IDENTIFIED BY ...` and
--       `IDENTIFIED BY ... ACCOUNT UNLOCK` each leave the account OPEN, and the
--       password from the combined statement authenticates. So the combined form
--       parses; whether it is the right shape is a design question, and #455
--       answered it the other way -- two statements, because UC-1 sec.5 requires
--       each attribute reported as its own change, and because the combined form
--       is a statement shape no leak probe has ever been run against.
--
--   Q6  The back-to-back reset works, and needs a CLOSED window to be read
--       honestly (see the v1 note below). From a baseline of plain OPEN:
--         step 1  IDENTIFIED BY p2    -> OPEN & IN ROLLOVER; BOTH p1 and p2
--                                        authenticate. UC-1 sec.6.3's window,
--                                        confirmed on the UC-2 statement.
--         step 2  EXPIRE PASSWORD ROLLOVER PERIOD, same session, no verification
--                                     -> OPEN; p1 ORA-01017, p2 authenticates.
--         step 3  the same statement with no window open -> ACCEPTED, silently,
--                 status still OPEN. Matches what `finish_rollover`'s docstring
--                 and UC-1 sec.6.3 already record.
--
--   Q6b The full shape on a locked account -- ACCOUNT UNLOCK, then IDENTIFIED BY,
--       then EXPIRE PASSWORD ROLLOVER PERIOD -- leaves OPEN, the new password
--       working with nothing else needed, and the superseded one ORA-01017.
--       Three statements, in UC-1 sec.5's order.
--
--   Q7  EXTRA, and it is the one that changes a document. On a rollover profile
--       `IDENTIFIED BY ... PASSWORD EXPIRE` is ACCEPTED, and the resulting status
--       is `EXPIRED & IN ROLLOVER` -- both states at once.
--
--       **Expiring does NOT end the old password's window.** Checked with stdin
--       closed, as a separate invocation: the OLD password answers ORA-28001, not
--       ORA-01017. ORA-28001 means it AUTHENTICATED and is expired -- so during
--       the window the old password is still live, and is itself a way to set the
--       new one. The new password answers ORA-28001 too. Both are live, both
--       expired.
--
--       This measures the `expire-rollover` register entry on 26ai only. It does
--       NOT settle it: the entry needs 21c as well, and uc-02 sec.4.3's plan-time
--       refusal stands until it has one. Recorded here, decided nowhere.
--
--
-- HOW TO RUN
--   The admin password is a placeholder, for 02_password_leak_probe.sql sec.0's
--   reason: a working password committed here is in git history for ever.
--   Substitute into a copy on the way past -- the file itself stays clean:
--
--     sed 's/CHANGEME_ADMIN_PASSWORD/<pw>/' 07_lock_and_rollover_probe.sql \
--       | MSYS_NO_PATHCONV=1 docker exec -i sopuli-test-oracle-free-1 sqlplus -S /nolog
--
--   Piped rather than mounted because the compose stack mounts oracle-init/ and
--   nothing else, and CONNECT inside the script keeps every password off the
--   sqlplus command line and so out of `ps` (invariant 1's habit, in a place the
--   invariant itself does not reach). MSYS_NO_PATHCONV is a Git Bash detail:
--   without it `/nolog` is rewritten to a Windows path and sqlplus prints usage.
--
--   admin_user needs ALTER USER, CREATE USER, DROP USER, SELECT ON DBA_USERS and
--   -- for the LCOUNT half -- SELECT ON SYS.USER$, which
--   test/oracle-init/01_test_profiles.sql sec.5 grants to SYSTEM CONTAINER=ALL.
--   Without it Q1 and Q2 cannot be answered at all and section 0 says so rather
--   than reporting a zero it could not read.
--
--
-- THREE SQL*PLUS TRAPS, ALL THREE HIT BY v1 OF THIS FILE
--   - **A PROMPT line must not end in a hyphen.** Trailing `-` is SQL*Plus's
--     continuation character, so `PROMPT -- 6. Q5 ------` silently ate the
--     `BEGIN` on the next line and Q5 did not run at all -- it reported nothing
--     rather than failing. 02_password_leak_probe.sql's header records the same
--     fix in its v2. Every banner here ends in a word.
--   - **CONNECT resets SERVEROUTPUT.** Every DBMS_OUTPUT verdict after the first
--     connect printed nothing in v1. `SET SERVEROUTPUT ON` follows every CONNECT
--     below, which is why it appears so often.
--   - **An expired-password login makes sqlplus PROMPT for a new one**, and the
--     prompt reads the SCRIPT as its answer -- v1's Q7 consumed its own following
--     lines and reported ORA-00988. So section 9 does not attempt that login;
--     it is a separate invocation with stdin closed, documented at the end.
--------------------------------------------------------------------------------

DEFINE tns        = //localhost:1521/FREEPDB1
DEFINE admin_user = system
DEFINE admin_pwd  = CHANGEME_ADMIN_PASSWORD

-- The probe account. Dropped and recreated on every run.
DEFINE acct       = sopuli_h4_user

-- Known passwords, one per step, so a login result names WHICH password worked.
-- Alphanumeric and 12 bytes: inside 11.2's 30-byte limit and the alnum_safe
-- charset, so no quoting or verify-function question is mixed into this test.
DEFINE p1         = Aq7xProbeOne
DEFINE p2         = Bq7xProbeTwo
DEFINE p3         = Cq7xProbeSix
DEFINE p4         = Dq7xProbeFor
DEFINE pwrong     = Zq9xNotThePw

SET LINESIZE 200
SET PAGESIZE 1000
SET FEEDBACK OFF
SET VERIFY OFF
SET DEFINE ON
SET ECHO OFF

COLUMN username        FORMAT A16
COLUMN account_status  FORMAT A22
COLUMN lcount          FORMAT A6
COLUMN lock_date       FORMAT A19
COLUMN profile         FORMAT A16

WHENEVER SQLERROR EXIT FAILURE
CONNECT &admin_user/"&admin_pwd"@&tns
WHENEVER SQLERROR CONTINUE NONE
SET SERVEROUTPUT ON SIZE UNLIMITED

PROMPT
PROMPT ================================================================
PROMPT  sopuli-dba H4 probe v2: lock, LCOUNT and rollover
PROMPT ================================================================
SELECT banner_full FROM v$version;
SELECT SYS_CONTEXT('USERENV','CON_NAME') AS container FROM dual;

--------------------------------------------------------------------------------
-- 0. Can we read LCOUNT at all?
--
-- Its own line, because a probe reporting "LCOUNT 0" when what happened was
-- ORA-01031 would answer Q1 backwards. 02-oracle-privileges.md sec.4 makes the
-- same distinction for check 3: could-not-read is a third answer.
--------------------------------------------------------------------------------
PROMPT
PROMPT ==== 0. LCOUNT readability ====
DECLARE
  l_n PLS_INTEGER;
BEGIN
  EXECUTE IMMEDIATE 'SELECT COUNT(*) FROM sys.user$ WHERE ROWNUM = 1' INTO l_n;
  DBMS_OUTPUT.PUT_LINE('SYS.USER$ readable: YES, so Q1 and Q2 are answerable');
EXCEPTION
  WHEN OTHERS THEN
    DBMS_OUTPUT.PUT_LINE('SYS.USER$ NOT readable (' || SQLERRM || ')');
    DBMS_OUTPUT.PUT_LINE('*** Q1 and Q2 are UNANSWERABLE on this run ***');
END;
/

--------------------------------------------------------------------------------
-- 1. A fresh account on the lockout profile.
--
-- SOPULI_LOCKOUT is FAILED_LOGIN_ATTEMPTS 3, PASSWORD_LOCK_TIME 1/1440 (one
-- minute) -- test/oracle-init/01_test_profiles.sql sec.1. Two failed logins
-- therefore leave the account OPEN with LCOUNT 2, which is the state Q1 needs.
--------------------------------------------------------------------------------
PROMPT
PROMPT ==== 1. Setup ====
BEGIN
  EXECUTE IMMEDIATE 'DROP USER &acct CASCADE';
  DBMS_OUTPUT.PUT_LINE('dropped a pre-existing &acct');
EXCEPTION
  WHEN OTHERS THEN
    DBMS_OUTPUT.PUT_LINE('no pre-existing &acct to drop');
END;
/
CREATE USER &acct IDENTIFIED BY "&p1" PROFILE sopuli_lockout;
GRANT CREATE SESSION TO &acct;
PROMPT created &acct on SOPULI_LOCKOUT with p1

PROMPT a baseline login, so LCOUNT starts from a known zero and p1 is proven good
CONNECT &acct/"&p1"@&tns
SHOW USER
CONNECT &admin_user/"&admin_pwd"@&tns
SET SERVEROUTPUT ON SIZE UNLIMITED

--------------------------------------------------------------------------------
-- 2. Q1 -- does ACCOUNT UNLOCK reset LCOUNT on an account that is not locked?
--------------------------------------------------------------------------------
PROMPT
PROMPT ==== 2. Q1: ACCOUNT UNLOCK on an UNLOCKED account ====
PROMPT two failed logins (the limit is 3, so the account stays OPEN)
CONNECT &acct/"&pwrong"@&tns
CONNECT &acct/"&pwrong"@&tns
CONNECT &admin_user/"&admin_pwd"@&tns
SET SERVEROUTPUT ON SIZE UNLIMITED

PROMPT
PROMPT before ACCOUNT UNLOCK:
SELECT u.username, u.account_status,
       (SELECT TO_CHAR(s.lcount) FROM sys.user$ s WHERE s.name = u.username) AS lcount
  FROM dba_users u WHERE u.username = UPPER('&acct');

ALTER USER &acct ACCOUNT UNLOCK;
PROMPT issued ALTER USER ... ACCOUNT UNLOCK against an account that was NOT locked

PROMPT after ACCOUNT UNLOCK:
SELECT u.username, u.account_status,
       (SELECT TO_CHAR(s.lcount) FROM sys.user$ s WHERE s.name = u.username) AS lcount
  FROM dba_users u WHERE u.username = UPPER('&acct');

--------------------------------------------------------------------------------
-- 3. Q2 -- does IDENTIFIED BY reset LCOUNT on its own?
--
-- The question that decides whether Q1 matters. If setting a password already
-- zeroed the counter, adding ACCOUNT UNLOCK would cost nothing on this axis.
--------------------------------------------------------------------------------
PROMPT
PROMPT ==== 3. Q2: IDENTIFIED BY and LCOUNT ====
PROMPT two more failed logins
CONNECT &acct/"&pwrong"@&tns
CONNECT &acct/"&pwrong"@&tns
CONNECT &admin_user/"&admin_pwd"@&tns
SET SERVEROUTPUT ON SIZE UNLIMITED

PROMPT before IDENTIFIED BY:
SELECT u.username, u.account_status,
       (SELECT TO_CHAR(s.lcount) FROM sys.user$ s WHERE s.name = u.username) AS lcount
  FROM dba_users u WHERE u.username = UPPER('&acct');

ALTER USER &acct IDENTIFIED BY "&p2";
PROMPT issued ALTER USER ... IDENTIFIED BY p2

PROMPT after IDENTIFIED BY:
SELECT u.username, u.account_status,
       (SELECT TO_CHAR(s.lcount) FROM sys.user$ s WHERE s.name = u.username) AS lcount
  FROM dba_users u WHERE u.username = UPPER('&acct');

--------------------------------------------------------------------------------
-- 4. Q3 -- does IDENTIFIED BY clear LOCKED(TIMED)?
--
-- uc-02 sec.5: "Whether setting a password affects the timer has not been run,
-- and nothing here assumes it does." This is that run.
--------------------------------------------------------------------------------
PROMPT
PROMPT ==== 4. Q3: IDENTIFIED BY against LOCKED(TIMED) ====
PROMPT three failed logins, which reaches FAILED_LOGIN_ATTEMPTS 3
CONNECT &acct/"&pwrong"@&tns
CONNECT &acct/"&pwrong"@&tns
CONNECT &acct/"&pwrong"@&tns
CONNECT &admin_user/"&admin_pwd"@&tns
SET SERVEROUTPUT ON SIZE UNLIMITED

PROMPT after the third failure, expecting LOCKED(TIMED):
SELECT u.username, u.account_status,
       TO_CHAR(u.lock_date,'YYYY-MM-DD HH24:MI:SS') AS lock_date,
       (SELECT TO_CHAR(s.lcount) FROM sys.user$ s WHERE s.name = u.username) AS lcount
  FROM dba_users u WHERE u.username = UPPER('&acct');

ALTER USER &acct IDENTIFIED BY "&p3";
PROMPT issued ALTER USER ... IDENTIFIED BY p3, with no ACCOUNT UNLOCK

PROMPT after IDENTIFIED BY, is the timed lock still there?
SELECT u.username, u.account_status,
       TO_CHAR(u.lock_date,'YYYY-MM-DD HH24:MI:SS') AS lock_date,
       (SELECT TO_CHAR(s.lcount) FROM sys.user$ s WHERE s.name = u.username) AS lcount
  FROM dba_users u WHERE u.username = UPPER('&acct');

PROMPT can the owner log in with the NEW password while the timed lock stands?
CONNECT &acct/"&p3"@&tns
SHOW USER
CONNECT &admin_user/"&admin_pwd"@&tns
SET SERVEROUTPUT ON SIZE UNLIMITED

--------------------------------------------------------------------------------
-- 5. Q4 -- does IDENTIFIED BY clear a DELIBERATE lock?
--
-- The distinction H4's unlock answer rests on: LOCKED(TIMED) is a lock nobody
-- chose, LOCKED is one a DBA issued. errors.py's ORA-28000 hint already tells an
-- operator ACCOUNT_STATUS tells them apart; this checks the statuses really are
-- distinct strings, and that a reset does not quietly clear the deliberate one.
--------------------------------------------------------------------------------
PROMPT
PROMPT ==== 5. Q4: IDENTIFIED BY against a deliberate ACCOUNT LOCK ====
ALTER USER &acct ACCOUNT UNLOCK;
ALTER USER &acct ACCOUNT LOCK;
PROMPT issued ALTER USER ... ACCOUNT LOCK, the deliberate kind
SELECT u.username, u.account_status FROM dba_users u WHERE u.username = UPPER('&acct');

ALTER USER &acct IDENTIFIED BY "&p4";
PROMPT issued ALTER USER ... IDENTIFIED BY p4

PROMPT after IDENTIFIED BY, is the deliberate lock still there?
SELECT u.username, u.account_status FROM dba_users u WHERE u.username = UPPER('&acct');

PROMPT can the owner log in? ORA-28000 means the lock survived
CONNECT &acct/"&p4"@&tns
SHOW USER
CONNECT &admin_user/"&admin_pwd"@&tns
SET SERVEROUTPUT ON SIZE UNLIMITED

--------------------------------------------------------------------------------
-- 6. Q5 -- does the combined form parse, in either clause order?
--
-- The instinct in #455 was that one statement doing both "does no harm".
-- Whether it PARSES is the first half of that; whether it is the right shape is
-- a design question this script does not touch. Both orders are tried, because
-- Oracle's alter_user grammar is order-sensitive in places.
--
-- v1 reported NOTHING here: the banner above it ended in hyphens and ate the
-- BEGIN. If this section is silent again, that is the bug, not a result.
--------------------------------------------------------------------------------
PROMPT
PROMPT ==== 6. Q5: the combined statement ====
BEGIN
  EXECUTE IMMEDIATE 'ALTER USER &acct ACCOUNT UNLOCK IDENTIFIED BY "&p1"';
  DBMS_OUTPUT.PUT_LINE('ACCOUNT UNLOCK then IDENTIFIED BY : ACCEPTED');
EXCEPTION
  WHEN OTHERS THEN
    DBMS_OUTPUT.PUT_LINE('ACCOUNT UNLOCK then IDENTIFIED BY : REJECTED, ' || SQLERRM);
END;
/
SELECT u.username, u.account_status FROM dba_users u WHERE u.username = UPPER('&acct');

ALTER USER &acct ACCOUNT LOCK;
BEGIN
  EXECUTE IMMEDIATE 'ALTER USER &acct IDENTIFIED BY "&p2" ACCOUNT UNLOCK';
  DBMS_OUTPUT.PUT_LINE('IDENTIFIED BY then ACCOUNT UNLOCK : ACCEPTED');
EXCEPTION
  WHEN OTHERS THEN
    DBMS_OUTPUT.PUT_LINE('IDENTIFIED BY then ACCOUNT UNLOCK : REJECTED, ' || SQLERRM);
END;
/
SELECT u.username, u.account_status FROM dba_users u WHERE u.username = UPPER('&acct');

PROMPT does the password from the combined statement actually work?
CONNECT &acct/"&p2"@&tns
SHOW USER
CONNECT &admin_user/"&admin_pwd"@&tns
SET SERVEROUTPUT ON SIZE UNLIMITED

--------------------------------------------------------------------------------
-- 7. Q6 -- the UC-2 reset shape on a rollover profile.
--
-- SOPULI_ROLLOVER is PASSWORD_ROLLOVER_TIME 1/24. UC-1 sec.6.3 has the window
-- behaviour measured; what is new is the back-to-back sequence a UC-2 reset
-- issues -- set, then close -- in one session, with no verification between.
--
-- **The baseline must start with the window CLOSED**, which v1 got wrong: moving
-- the account onto the rollover profile and setting p1 opens a window of its own,
-- so v1's "old password" was the one from before p1, and p1 failing during the
-- window looked like a finding when it was the setup. Hence the explicit close
-- and the status assertion before step 1.
--------------------------------------------------------------------------------
PROMPT
PROMPT ==== 7. Q6: reset on a rollover profile ====
ALTER USER &acct ACCOUNT UNLOCK;
ALTER USER &acct PROFILE sopuli_rollover;
ALTER USER &acct IDENTIFIED BY "&p1";
ALTER USER &acct EXPIRE PASSWORD ROLLOVER PERIOD;
PROMPT baseline: profile SOPULI_ROLLOVER, password p1, window deliberately CLOSED
SELECT u.username, u.account_status, u.profile FROM dba_users u WHERE u.username = UPPER('&acct');
PROMPT the status above must read plain OPEN. Anything else invalidates step 1
PROMPT and p1 must authenticate right now:
CONNECT &acct/"&p1"@&tns
SHOW USER
CONNECT &admin_user/"&admin_pwd"@&tns
SET SERVEROUTPUT ON SIZE UNLIMITED

PROMPT
PROMPT step 1: ALTER USER ... IDENTIFIED BY p2, which OPENS the window
ALTER USER &acct IDENTIFIED BY "&p2";
SELECT u.username, u.account_status, u.profile FROM dba_users u WHERE u.username = UPPER('&acct');

PROMPT does the OLD password p1 still authenticate during the window?
CONNECT &acct/"&p1"@&tns
SHOW USER
CONNECT &admin_user/"&admin_pwd"@&tns
SET SERVEROUTPUT ON SIZE UNLIMITED
PROMPT does the NEW password p2 authenticate during the window?
CONNECT &acct/"&p2"@&tns
SHOW USER
CONNECT &admin_user/"&admin_pwd"@&tns
SET SERVEROUTPUT ON SIZE UNLIMITED

PROMPT
PROMPT step 2: ALTER USER ... EXPIRE PASSWORD ROLLOVER PERIOD, same session
ALTER USER &acct EXPIRE PASSWORD ROLLOVER PERIOD;
SELECT u.username, u.account_status, u.profile FROM dba_users u WHERE u.username = UPPER('&acct');

PROMPT does the OLD password p1 still authenticate after the close?
CONNECT &acct/"&p1"@&tns
SHOW USER
CONNECT &admin_user/"&admin_pwd"@&tns
SET SERVEROUTPUT ON SIZE UNLIMITED
PROMPT does the NEW password p2 still authenticate after the close?
CONNECT &acct/"&p2"@&tns
SHOW USER
CONNECT &admin_user/"&admin_pwd"@&tns
SET SERVEROUTPUT ON SIZE UNLIMITED

PROMPT
PROMPT step 3: the same statement again, with NO window open
BEGIN
  EXECUTE IMMEDIATE 'ALTER USER &acct EXPIRE PASSWORD ROLLOVER PERIOD';
  DBMS_OUTPUT.PUT_LINE('EXPIRE PASSWORD ROLLOVER PERIOD, no window open : ACCEPTED');
EXCEPTION
  WHEN OTHERS THEN
    DBMS_OUTPUT.PUT_LINE('EXPIRE PASSWORD ROLLOVER PERIOD, no window open : REJECTED, '
                         || SQLERRM);
END;
/
SELECT u.username, u.account_status FROM dba_users u WHERE u.username = UPPER('&acct');

--------------------------------------------------------------------------------
-- 8. Q6b -- unlock, reset, close: the full UC-2 shape on a locked account.
--
-- Three statements in the order UC-1 sec.5 already uses (unlock first, after the
-- guardrails). This is what a UC-2 reset would issue if H4 answers "unlock by
-- default" and "close the window by default".
--------------------------------------------------------------------------------
PROMPT
PROMPT ==== 8. Q6b: unlock, reset, close on a locked account ====
ALTER USER &acct ACCOUNT LOCK;
PROMPT locked deliberately, and left on the rollover profile:
SELECT u.username, u.account_status, u.profile FROM dba_users u WHERE u.username = UPPER('&acct');
ALTER USER &acct ACCOUNT UNLOCK;
ALTER USER &acct IDENTIFIED BY "&p3";
ALTER USER &acct EXPIRE PASSWORD ROLLOVER PERIOD;
PROMPT issued all three, in that order
SELECT u.username, u.account_status, u.profile FROM dba_users u WHERE u.username = UPPER('&acct');
PROMPT can the owner log in with p3, with nothing else needed?
CONNECT &acct/"&p3"@&tns
SHOW USER
CONNECT &admin_user/"&admin_pwd"@&tns
SET SERVEROUTPUT ON SIZE UNLIMITED
PROMPT and is the superseded p2 dead?
CONNECT &acct/"&p2"@&tns
SHOW USER
CONNECT &admin_user/"&admin_pwd"@&tns
SET SERVEROUTPUT ON SIZE UNLIMITED

--------------------------------------------------------------------------------
-- 9. Q7 -- EXTRA: the `expire-rollover` register entry.
--
-- NOT part of H4's decision. docs/README.md carries this as an unverified entry
-- and uc-02 sec.4.3 refuses a SEEN reset on a rollover profile until it is
-- measured. This section measures; whether the refusal lifts is a decision on
-- #438/#457, not something this script or #455 may settle.
--
-- The login with the expired password is NOT attempted here -- see the third
-- SQL*Plus trap in the header. Run it separately, with stdin closed:
--
--   MSYS_NO_PATHCONV=1 docker exec -i sopuli-test-oracle-free-1 \
--     sqlplus -S -L <acct>/<p2>@//localhost:1521/FREEPDB1 < /dev/null
--------------------------------------------------------------------------------
PROMPT
PROMPT ==== 9. Q7 EXTRA: IDENTIFIED BY ... PASSWORD EXPIRE on a rollover profile ====
ALTER USER &acct IDENTIFIED BY "&p1";
ALTER USER &acct EXPIRE PASSWORD ROLLOVER PERIOD;
PROMPT baseline restored to p1, window closed:
SELECT u.username, u.account_status FROM dba_users u WHERE u.username = UPPER('&acct');

PROMPT
PROMPT is the suffixed statement even ACCEPTED on a rollover profile?
BEGIN
  EXECUTE IMMEDIATE 'ALTER USER &acct IDENTIFIED BY "&p2" PASSWORD EXPIRE';
  DBMS_OUTPUT.PUT_LINE('IDENTIFIED BY ... PASSWORD EXPIRE : ACCEPTED');
EXCEPTION
  WHEN OTHERS THEN
    DBMS_OUTPUT.PUT_LINE('IDENTIFIED BY ... PASSWORD EXPIRE : REJECTED, ' || SQLERRM);
END;
/
PROMPT resulting status: EXPIRED, IN ROLLOVER, or both?
SELECT u.username, u.account_status, u.profile FROM dba_users u WHERE u.username = UPPER('&acct');

PROMPT does the OLD password p1 still authenticate after the expiring reset?
CONNECT &acct/"&p1"@&tns
SHOW USER
CONNECT &admin_user/"&admin_pwd"@&tns
SET SERVEROUTPUT ON SIZE UNLIMITED

PROMPT
PROMPT the account is LEFT IN PLACE for the separate expired-login check.
PROMPT Drop it afterwards with: DROP USER &acct CASCADE;
PROMPT
PROMPT ================================================================
PROMPT  A login line reading USER is "" means that CONNECT FAILED.
PROMPT  The ORA- code is printed immediately above it.
PROMPT ================================================================
