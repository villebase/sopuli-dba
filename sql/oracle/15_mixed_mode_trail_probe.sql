--------------------------------------------------------------------------------
-- sopuli-dba : does an enabled unified policy record anything, in mixed mode,
--              under each AUDIT_TRAIL setting?   (v2)
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
--   MT2  a policy ACTIONS ALTER USER, enabled BY SYSTEM. The same two counts,
--        around SYSTEM's ALTER USER of the account
--
-- MT1 counts only rows whose UNIFIED_AUDIT_POLICIES names MT_LOGON, so
-- ORA_LOGON_FAILURES, which the XE images enable, does not reach it. MT2
-- counts rows under any policy, because ORA_SECURECONFIG, which the images
-- also enable, covers ALTER USER, and 18.4 names only that policy on the row.
-- MT2 prints the policies each row names. A row left by an earlier run is in
-- both counts, so the difference is what this run recorded.
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
-- every time, and the same difference between the two counts in every run of
-- a setting. v1 had only MT1 and counted every LOGON row; its runs gave the
-- same result. One v1 run, on 18.4 under NONE, printed nothing after the
-- policy read and did not return, with no session of its own in V$SESSION.
-- A run started while it was still alive failed with ORA-01017 at the
-- account's logon. Neither is counted. The hang did not recur.
-- Untried on every other release.
--
--
-- RESULTS -- 21.3.0.0.0 and 18.4.0.0.0, XEPDB1, 2026-10-23
--
--   MT0  Unified Auditing = FALSE: mixed mode, on both releases
--   MT1, MT2 each policy reads in AUDIT_UNIFIED_ENABLED_POLICIES under both
--        settings: MT_LOGON BY USER MT_PERSON, MT_ALTER BY USER SYSTEM.
--        AUDIT_TRAIL = NONE: in each section the two counts are equal. The
--        logon and the ALTER USER leave no row
--        AUDIT_TRAIL = DB: in each section the second count is one more than
--        the first. Each action leaves one row
--   MT2  the ALTER USER rows name ORA_SECURECONFIG, MT_ALTER on 21.3, and
--        ORA_SECURECONFIG only on 18.4. An 18.4 row names one policy although
--        two enabled policies cover the action
--
--   So in mixed mode on these releases, AUDIT_TRAIL = NONE stops unified
--   records too, while AUDIT_UNIFIED_ENABLED_POLICIES shows the policies
--   enabled. Of the audit parameters, the image's install script
--   (/opt/oracle/install.*.sh) sets only AUDIT_TRAIL and AUDIT_SYS_OPERATIONS,
--   and these runs changed only AUDIT_TRAIL.
--
-- THROWAWAY DATABASES ONLY. Creates and drops an account and two audit
-- policies, and plants a known password. Under AUDIT_TRAIL = NONE a run
-- leaves nothing in UNIFIED_AUDIT_TRAIL. Under DB it leaves the logon and the
-- ALTER USER rows, and the rows ORA_SECURECONFIG writes for the setup and the
-- teardown: CREATE and DROP USER, the policy statements, AUDIT and NOAUDIT.
--------------------------------------------------------------------------------
define svc      = XEPDB1
define sys_conn = system/sopuli-test

set lines 160 pages 200 feedback off verify off
whenever sqlerror exit failure
connect &sys_conn@&svc
col parameter for a20
col value for a8
col name for a12
col policy_name for a12
col enabled_option for a16
col entity_name for a12
col unified_audit_policies for a40

prompt === setup
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
create audit policy mt_alter actions alter user;
audit policy mt_alter by system;
select policy_name, enabled_option, entity_name from audit_unified_enabled_policies
 where policy_name = 'MT_ALTER';
exec dbms_audit_mgmt.flush_unified_audit_trail
-- Counted under any policy: 18.4 names only ORA_SECURECONFIG on the row,
-- although MT_ALTER is enabled too. The policies each row names are printed.
select count(*) as alter_rows_before from unified_audit_trail
 where object_name = 'MT_PERSON' and action_name = 'ALTER USER' and return_code = 0;
alter user mt_person identified by "MtPersonPw_5528";
exec dbms_audit_mgmt.flush_unified_audit_trail
select count(*) as alter_rows_after from unified_audit_trail
 where object_name = 'MT_PERSON' and action_name = 'ALTER USER' and return_code = 0;
select unified_audit_policies, count(*) as alter_rows from unified_audit_trail
 where object_name = 'MT_PERSON' and action_name = 'ALTER USER' and return_code = 0
 group by unified_audit_policies order by 1;

prompt === teardown
noaudit policy mt_logon by mt_person;
noaudit policy mt_alter by system;
drop audit policy mt_logon;
drop audit policy mt_alter;
drop user mt_person cascade;
exit
