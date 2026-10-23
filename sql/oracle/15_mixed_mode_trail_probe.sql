--------------------------------------------------------------------------------
-- sopuli-dba : does an enabled unified policy record anything, in mixed mode,
--              under each AUDIT_TRAIL setting?   (v1)
--
-- #1006. The audited check reads the policy views, not the trail. On the XE
-- images the views showed a LOGON policy enabled while the trail recorded
-- nothing. This measures whether the trail records the logon the policy names:
--
--   MT0  the audit mode (V$OPTION 'Unified Auditing'), AUDIT_TRAIL, and how
--        many rows UNIFIED_AUDIT_TRAIL holds
--   MT1  a policy ACTIONS LOGON, enabled BY one account. SYSTEM counts the
--        account's LOGON rows, the account logs on, and SYSTEM flushes the
--        trail and counts them again. The policy and the account are dropped
--
-- AUDIT_TRAIL is static. To measure both settings, run the file, then as
-- SYSDBA `alter system set audit_trail = DB scope = spfile`, restart the
-- database, and run it again. Set it back the same way.
--
-- This MEASURES and decides nothing. Whether the check reads AUDIT_TRAIL is
-- #1004.
--
-- STATUS: run on 21c XE 21.3.0.0.0 (gvenzl/oracle-xe:21-slim) and 18c XE
-- 18.4.0.0.0 (gvenzl/oracle-xe:18-slim), XEPDB1, as SYSTEM, on 2026-10-23
-- (#1006). Twice under AUDIT_TRAIL = NONE, as the images ship, and twice under
-- AUDIT_TRAIL = DB, each from a restarted database. Exit 0 every time, and
-- the same difference between the two counts in every run of a setting.
-- One run of an earlier draft, on 18.4 under NONE, printed nothing after the policy read
-- and did not return, with no session of its own in V$SESSION; it was stopped,
-- and is not counted. Untried on every other release.
--
--
-- RESULTS -- 21.3.0.0.0 and 18.4.0.0.0, XEPDB1, 2026-10-23
--
--   MT0  Unified Auditing = FALSE: mixed mode, on both releases
--   MT1  the policy reads BY USER MT_PERSON in AUDIT_UNIFIED_ENABLED_POLICIES
--        under both settings.
--        AUDIT_TRAIL = NONE: the two counts are equal. The logon leaves no row
--        AUDIT_TRAIL = DB: the second count is one more than the first. The
--        logon leaves one LOGON row
--
--   So in mixed mode on these releases, AUDIT_TRAIL = NONE stops unified
--   records too, while AUDIT_UNIFIED_ENABLED_POLICIES shows the policy
--   enabled. Of the audit parameters, the image's install script
--   (/opt/oracle/install.*.sh) sets only AUDIT_TRAIL and AUDIT_SYS_OPERATIONS,
--   and these runs changed only AUDIT_TRAIL.
--
-- THROWAWAY DATABASES ONLY. Creates and drops an account and an audit policy,
-- plants a known password, and leaves a row in UNIFIED_AUDIT_TRAIL.
--------------------------------------------------------------------------------
define svc      = XEPDB1
define sys_conn = system/sopuli-test

set lines 160 pages 200 feedback off verify off
whenever sqlerror exit failure
connect &sys_conn@&svc
col parameter for a20
col value for a8
col name for a12

prompt === setup
begin execute immediate 'noaudit policy mt_logon by mt_person'; exception when others then null; end;
/
begin execute immediate 'drop audit policy mt_logon'; exception when others then null; end;
/
begin execute immediate 'drop user mt_person cascade'; exception when others then null; end;
/
create user mt_person identified by "MtPersonPw_4417";
grant create session to mt_person;

prompt === MT0: the audit mode, AUDIT_TRAIL, and the trail's rows
select parameter, value from v$option where parameter = 'Unified Auditing';
select name, value from v$parameter where name = 'audit_trail';
exec dbms_audit_mgmt.flush_unified_audit_trail
select count(*) as trail_rows from unified_audit_trail;

prompt === MT1: one logon under ACTIONS LOGON, enabled BY the account
create audit policy mt_logon actions logon;
audit policy mt_logon by mt_person;
select policy_name, enabled_option, entity_name from audit_unified_enabled_policies
 where policy_name = 'MT_LOGON';
-- A row left by an earlier run is counted here, so the two counts differ by
-- what this run's logon recorded. The trail has no timestamp column that every
-- release shares: 18.4 has no EVENT_TIMESTAMP_UTC.
select count(*) as logon_rows_before from unified_audit_trail
 where dbusername = 'MT_PERSON' and action_name = 'LOGON';
connect mt_person/"MtPersonPw_4417"@&svc
connect &sys_conn@&svc
exec dbms_audit_mgmt.flush_unified_audit_trail
select count(*) as logon_rows_after from unified_audit_trail
 where dbusername = 'MT_PERSON' and action_name = 'LOGON';

prompt === teardown
noaudit policy mt_logon by mt_person;
drop audit policy mt_logon;
drop user mt_person cascade;
exit
