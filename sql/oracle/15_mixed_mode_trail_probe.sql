--------------------------------------------------------------------------------
-- sopuli-dba : does an enabled unified policy record anything, in mixed mode,
--              under each AUDIT_TRAIL setting?   (v3)
--
-- #1006. The audited check reads the policy views, not the trail. On the XE
-- images the views showed an ALTER USER, LOGON policy enabled while the trail
-- recorded nothing. This measures whether the trail records the two actions
-- the check is about, each under a policy of its own:
--
--   MT0  the audit mode (V$OPTION 'Unified Auditing') and AUDIT_TRAIL
--   MT1  a policy ACTIONS LOGON, enabled BY one account. SYSTEM counts the
--        trail's rows for the account's successful logons under that policy,
--        the account logs on, and SYSTEM flushes the trail and counts again
--   MT2  a policy ACTIONS ALTER USER, enabled BY SYSTEM, with
--        ORA_SECURECONFIG disabled. SYSTEM counts the account's ALTER USER
--        rows under that policy, then alters the account and counts again:
--        once in the session that changed the policies (MT2a), and once in a
--        new session (MT2b). Then the policies each of the account's
--        ALTER USER rows names
--
-- Each count reads only rows whose UNIFIED_AUDIT_POLICIES names the probe's
-- policy. The XE images enable ORA_LOGON_FAILURES, which MT1's filter keeps
-- out, and ORA_SECURECONFIG, which covers ALTER USER. MT2 disables
-- ORA_SECURECONFIG for the section. A row left by an earlier run is in every
-- count, so the difference between two counts is what was recorded between
-- them.
--
-- AUDIT_TRAIL is static. To measure both settings, run the file, then as
-- SYSDBA `alter system set audit_trail = DB scope = spfile`, restart the
-- database, and run it again. Set it back the same way.
--
-- This MEASURES and decides nothing. What the check answers under
-- AUDIT_TRAIL = NONE is #1004.
--
-- STATUS: run on 21c XE 21.3.0.0.0 (gvenzl/oracle-xe:21-slim) and 18c XE
-- 18.4.0.0.0 (gvenzl/oracle-xe:18-slim), XEPDB1, as SYSTEM, on 2026-10-23
-- (#1006). Twice under AUDIT_TRAIL = NONE, as the images ship, and twice
-- under AUDIT_TRAIL = DB, each setting from a restarted database. Exit 0
-- every time, and the same differences between the counts in every run of a
-- setting. Run again on 21.3.0.0.0 under NONE on 2026-10-24 (#1014), once,
-- by EZConnect: exit 0, with the same differences. Untried on every other
-- release.
--
-- Once, on 18.4 under NONE, SQL*Plus printed nothing after MT1's policy read
-- and did not return, and V$SESSION showed no session of its own. It was
-- stopped, and that run is not counted. A possible cause is the connect
-- string (#1014), but that run was not captured, so it is not shown. The
-- probe then connected to the alias XEPDB1, and the image's sqlnet.ora tries
-- EZCONNECT before TNSNAMES, so each connect first asked DNS for a host named
-- XEPDB1. On 2026-10-24 Docker Desktop's DNS took about 8 seconds to answer
-- that no such host exists, and a connect by alias took about 24 seconds,
-- against 0.5 by EZConnect. An answer much slower than that once would look
-- like a hang. The probe now connects by EZConnect.
--
--
-- RESULTS -- 21.3.0.0.0 and 18.4.0.0.0, XEPDB1, 2026-10-23
--
--   MT0  Unified Auditing = FALSE: mixed mode, on both releases
--   MT1, MT2 each policy reads in AUDIT_UNIFIED_ENABLED_POLICIES under both
--        settings: MT_LOGON BY USER MT_PERSON, MT_ALTER BY USER SYSTEM.
--        AUDIT_TRAIL = NONE: every count equals the one before it. The logon
--        and both ALTER USER statements leave no row
--        AUDIT_TRAIL = DB: the logon leaves one row that names MT_LOGON, on
--        both releases, and so does MT2b's ALTER USER in a new session.
--        MT2a's ALTER USER, in the session that changed the policies, leaves
--        one row naming MT_ALTER on 21.3 and none on 18.4: there that row
--        names ORA_SECURECONFIG, which the session had disabled. On 18.4 a
--        session keeps the policies enabled when it logged on
--
--   So in mixed mode on these releases, AUDIT_TRAIL = NONE stops these
--   unified records too, while AUDIT_UNIFIED_ENABLED_POLICIES shows the
--   policies enabled. Of the audit parameters, the image's install script
--   (/opt/oracle/install.*.sh) sets only AUDIT_TRAIL and AUDIT_SYS_OPERATIONS,
--   and these runs changed only AUDIT_TRAIL.
--
-- THROWAWAY DATABASES ONLY. Creates and drops an account and two audit
-- policies, and plants a known password. Disables ORA_SECURECONFIG for MT2
-- and enables it again for every user, as the XE images ship it; a run
-- stopped in MT2 leaves it disabled. Under AUDIT_TRAIL = NONE a run leaves
-- nothing in UNIFIED_AUDIT_TRAIL. Under DB it leaves the logon and the
-- ALTER USER rows, and the rows ORA_SECURECONFIG writes for the setup and the
-- teardown: CREATE and DROP USER, the policy statements, AUDIT and NOAUDIT.
--------------------------------------------------------------------------------
define svc      = //localhost:1521/XEPDB1
define sys_conn = system/sopuli-test

set lines 160 pages 200 feedback off verify off
whenever sqlerror exit failure
connect &sys_conn@&svc
col parameter for a20
col value for a8
col name for a12
col policy_name for a16
col enabled_option for a16
col entity_name for a12
col unified_audit_policies for a40

prompt === setup
-- Each step swallows its own error, so a run stopped half way does not stop
-- the next one here. If DROP USER fails, CREATE USER below fails and stops
-- the run.
begin execute immediate 'noaudit policy mt_logon by mt_person'; exception when others then null; end;
/
begin execute immediate 'noaudit policy mt_alter by system'; exception when others then null; end;
/
begin execute immediate 'drop audit policy mt_logon'; exception when others then null; end;
/
begin execute immediate 'drop audit policy mt_alter'; exception when others then null; end;
/
begin execute immediate 'drop user mt_person cascade'; exception when others then null; end;
/
create user mt_person identified by "MtPersonPw_4417";
grant create session to mt_person;

prompt === MT0: the audit mode and AUDIT_TRAIL
select parameter, value from v$option where parameter = 'Unified Auditing';
select name, value from v$parameter where name = 'audit_trail';

prompt === MT1: one logon under ACTIONS LOGON, enabled BY the account
create audit policy mt_logon actions logon;
audit policy mt_logon by mt_person;
select policy_name, enabled_option, entity_name from audit_unified_enabled_policies
 where policy_name = 'MT_LOGON';
exec dbms_audit_mgmt.flush_unified_audit_trail
select count(*) as logon_rows_before from unified_audit_trail
 where dbusername = 'MT_PERSON' and action_name = 'LOGON' and return_code = 0
   and unified_audit_policies like '%MT_LOGON%';
connect mt_person/"MtPersonPw_4417"@&svc
connect &sys_conn@&svc
exec dbms_audit_mgmt.flush_unified_audit_trail
select count(*) as logon_rows_after from unified_audit_trail
 where dbusername = 'MT_PERSON' and action_name = 'LOGON' and return_code = 0
   and unified_audit_policies like '%MT_LOGON%';

prompt === MT2: one ALTER USER under ACTIONS ALTER USER, enabled BY SYSTEM
noaudit policy ora_secureconfig;
create audit policy mt_alter actions alter user;
audit policy mt_alter by system;
select policy_name, enabled_option, entity_name from audit_unified_enabled_policies
 where policy_name in ('MT_ALTER', 'ORA_SECURECONFIG') order by 1;
exec dbms_audit_mgmt.flush_unified_audit_trail
select count(*) as alter_rows_before from unified_audit_trail
 where object_name = 'MT_PERSON' and action_name = 'ALTER USER' and return_code = 0
   and unified_audit_policies like '%MT_ALTER%';
prompt --- MT2a: in the session that enabled the policy
alter user mt_person identified by "MtPersonPw_5528";
exec dbms_audit_mgmt.flush_unified_audit_trail
select count(*) as alter_rows_same_session from unified_audit_trail
 where object_name = 'MT_PERSON' and action_name = 'ALTER USER' and return_code = 0
   and unified_audit_policies like '%MT_ALTER%';
prompt --- MT2b: in a new session
connect &sys_conn@&svc
alter user mt_person identified by "MtPersonPw_6639";
exec dbms_audit_mgmt.flush_unified_audit_trail
select count(*) as alter_rows_new_session from unified_audit_trail
 where object_name = 'MT_PERSON' and action_name = 'ALTER USER' and return_code = 0
   and unified_audit_policies like '%MT_ALTER%';
select unified_audit_policies, count(*) as alter_rows from unified_audit_trail
 where object_name = 'MT_PERSON' and action_name = 'ALTER USER' and return_code = 0
 group by unified_audit_policies order by 1;
audit policy ora_secureconfig;

prompt === teardown
noaudit policy mt_logon by mt_person;
noaudit policy mt_alter by system;
drop audit policy mt_logon;
drop audit policy mt_alter;
drop user mt_person cascade;
exit
