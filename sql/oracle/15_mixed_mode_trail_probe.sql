--------------------------------------------------------------------------------
-- sopuli-dba : does an enabled unified policy record anything, in mixed mode,
--              under each AUDIT_TRAIL setting?   (v4)
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
-- Two more sections measure what the check needs in order to read AUDIT_TRAIL,
-- and which values the parameter takes (#1098):
--
--   MT3  an account holding only CREATE SESSION reads AUDIT_TRAIL from
--        V$PARAMETER: a local account (MT3a), and again after SYS grants it
--        SELECT on V_$PARAMETER in the PDB (MT3b); a common account in the
--        PDB (MT3c), and again after SYS grants it in CDB$ROOT with
--        CONTAINER = ALL (MT3d)
--   MT4  as SYSDBA in CDB$ROOT, ALTER SYSTEM SET audit_trail = TRUE, then
--        OS, EXTENDED, then EXTENDED, each SCOPE = SPFILE. The parameter is
--        static, so the spfile is where a value is checked. Then, in case one
--        was accepted, it puts back the spfile's value as it read it first,
--        or RESETs the parameter where the spfile did not set it
--
-- Each count reads only rows whose UNIFIED_AUDIT_POLICIES names the probe's
-- policy. The XE images enable ORA_LOGON_FAILURES, which MT1's filter keeps
-- out, and ORA_SECURECONFIG, which covers ALTER USER. MT2 disables
-- ORA_SECURECONFIG for the section. A row left by an earlier run is in every
-- count, so the difference between two counts is what was recorded between
-- them.
--
-- AUDIT_TRAIL is static. To measure another setting, as SYSDBA
-- `alter system set audit_trail = DB scope = spfile`, restart the database,
-- and run the file again. Set it back to NONE the same way.
--
-- This MEASURES and decides nothing. What the check answers under
-- AUDIT_TRAIL = NONE is #1004, and under the other settings #1013.
--
-- STATUS: run on 21c XE 21.3.0.0.0 (gvenzl/oracle-xe:21-slim) and 18c XE
-- 18.4.0.0.0 (gvenzl/oracle-xe:18-slim), XEPDB1, as SYSTEM, on 2026-10-23
-- (#1006). Twice under AUDIT_TRAIL = NONE, as the images ship, and twice
-- under AUDIT_TRAIL = DB, each setting from a restarted database. Exit 0
-- every time, and the same differences between the counts in every run of a
-- setting. On 2026-10-24 (#1013), on the same releases, twice under each of
-- AUDIT_TRAIL = DB, EXTENDED, OS, XML and XML, EXTENDED, each setting from a
-- restarted database. Those runs set svc to //localhost:1521/XEPDB1 in a copy
-- of the file, and changed nothing else: a connect by the alias waits about
-- 24 s on Docker Desktop's DNS (#1014). Exit 0 every time, with the same
-- differences between the counts in every run. Run again on 21.3.0.0.0 under
-- NONE on 2026-10-24 (#1014), once, by EZConnect: exit 0, with the same
-- differences. Untried on every other release.
--
-- v4, with MT3 and MT4, run on the same two releases on 2026-10-27 (#1098),
-- twice on each under AUDIT_TRAIL = NONE, as the images ship. Exit 0 every
-- time, and the same output in every run, on both releases. MT0 to MT2 gave
-- the NONE results below. On 21.3 MT4's restore was also run once with the
-- spfile set to DB, EXTENDED, which it put back, and once with the spfile not
-- setting the parameter, which it left unset. Each exit 0, and the spfile set
-- back to NONE by hand afterwards.
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
-- RESULTS -- 21.3.0.0.0 and 18.4.0.0.0, XEPDB1, 2026-10-23 and 2026-10-24
--
--   MT0  Unified Auditing = FALSE: mixed mode, on both releases
--   MT1, MT2 each policy reads in AUDIT_UNIFIED_ENABLED_POLICIES under every
--        setting: MT_LOGON BY USER MT_PERSON, MT_ALTER BY USER SYSTEM.
--        AUDIT_TRAIL = NONE: every count equals the one before it. The logon
--        and both ALTER USER statements leave no row
--        AUDIT_TRAIL = DB: the logon leaves one row that names MT_LOGON, on
--        both releases, and so does MT2b's ALTER USER in a new session.
--        MT2a's ALTER USER, in the session that changed the policies, leaves
--        one row naming MT_ALTER on 21.3 and none on 18.4: there that row
--        names ORA_SECURECONFIG, which the session had disabled. On 18.4 a
--        session keeps the policies enabled when it logged on
--        AUDIT_TRAIL = DB, EXTENDED, OS, XML and XML, EXTENDED: as under DB,
--        on both releases, row for row
--
-- RESULTS -- MT3 and MT4, 21.3.0.0.0 and 18.4.0.0.0, 2026-10-27, the same
-- output on both releases
--
--   MT3a ORA-00942 on V$PARAMETER
--   MT3b reads audit_trail NONE
--   MT3c ORA-00942 on V$PARAMETER, in XEPDB1
--   MT3d reads audit_trail NONE, in XEPDB1
--   MT4  TRUE: ORA-00096 "invalid value TRUE for parameter audit_trail, must
--        be from among extended, xml, none, os, db"
--        OS, EXTENDED: ORA-32017 "failure in updating SPFILE", then ORA-00096
--        "invalid value OS,EXTENDED for parameter audit_trail, must be from
--        among NONE | OS | DB | DB,EXTENDED | XML | XML,EXTENDED"
--        EXTENDED: ORA-32017, then ORA-00096 "invalid value EXTENDED for
--        parameter audit_trail", with the same six values
--        The spfile's value reads NONE, specified, before and after
--
--   So in mixed mode on these releases, AUDIT_TRAIL = NONE stops these
--   unified records too, while AUDIT_UNIFIED_ENABLED_POLICIES shows the
--   policies enabled. Under each other setting measured, the policies record
--   both actions, in UNIFIED_AUDIT_TRAIL, whichever trail AUDIT_TRAIL names.
--   Of the audit parameters, the image's install script
--   (/opt/oracle/install.*.sh) sets only AUDIT_TRAIL and AUDIT_SYS_OPERATIONS,
--   and these runs changed only AUDIT_TRAIL.
--
-- THROWAWAY DATABASES ONLY. Creates and drops two local accounts, a common
-- account and two audit policies, and plants known passwords. MT4 writes the
-- spfile's own AUDIT_TRAIL value back to it; a run stopped between its
-- attempts and the restore leaves any value that was accepted. Disables ORA_SECURECONFIG for MT2
-- and enables it again for every user, as the XE images ship it; a run
-- stopped in MT2 leaves it disabled. Under AUDIT_TRAIL = NONE a run leaves
-- nothing in UNIFIED_AUDIT_TRAIL. Under each other setting it leaves the
-- logon and the ALTER USER rows, and the rows ORA_SECURECONFIG writes for the
-- setup and the teardown: CREATE and DROP USER, the policy statements, AUDIT
-- and NOAUDIT.
--------------------------------------------------------------------------------
define svc      = //localhost:1521/XEPDB1
define sys_conn = system/sopuli-test
define sysdba   = sys/sopuli-test
define cdb      = //localhost:1521/XE

set lines 160 pages 200 feedback off verify off
whenever sqlerror exit failure
connect &sys_conn@&svc
col parameter for a20
col value for a16
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
begin execute immediate 'drop user mt_svc cascade'; exception when others then null; end;
/
connect &sysdba@&cdb as sysdba
begin execute immediate 'drop user c##mt_svc cascade'; exception when others then null; end;
/
connect &sys_conn@&svc
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

prompt === MT3: who reads AUDIT_TRAIL from V$PARAMETER
prompt --- MT3a: a local account holding only CREATE SESSION
create user mt_svc identified by "MtSvcPw_7731";
grant create session to mt_svc;
connect mt_svc/"MtSvcPw_7731"@&svc
whenever sqlerror continue
select name, value from v$parameter where name = 'audit_trail';
whenever sqlerror exit failure
prompt --- MT3b: after SYS grants it in the PDB
connect &sysdba@&svc as sysdba
grant select on sys.v_$parameter to mt_svc;
connect mt_svc/"MtSvcPw_7731"@&svc
select name, value from v$parameter where name = 'audit_trail';
prompt --- MT3c: a common account holding only CREATE SESSION, in the PDB
connect &sysdba@&cdb as sysdba
create user c##mt_svc identified by "MtSvcPw_8842" container = all;
grant create session to c##mt_svc container = all;
connect c##mt_svc/"MtSvcPw_8842"@&svc
whenever sqlerror continue
select name, value from v$parameter where name = 'audit_trail';
whenever sqlerror exit failure
prompt --- MT3d: after SYS grants it in CDB$ROOT with CONTAINER = ALL
connect &sysdba@&cdb as sysdba
grant select on sys.v_$parameter to c##mt_svc container = all;
connect c##mt_svc/"MtSvcPw_8842"@&svc
select name, value from v$parameter where name = 'audit_trail';

prompt === MT4: values ALTER SYSTEM refuses for AUDIT_TRAIL
connect &sysdba@&cdb as sysdba
col spfile_value for a16
col isspecified for a11
-- A list value has a row for each part, so the parts are joined in order. An
-- spfile that does not set the parameter is put back with RESET.
col restore_stmt new_value restore_stmt noprint
select listagg(display_value, ', ') within group (order by ordinal) as spfile_value,
       max(isspecified) as isspecified,
       case when max(isspecified) = 'TRUE'
            then 'alter system set audit_trail = '
                 || listagg(display_value, ', ') within group (order by ordinal)
                 || ' scope = spfile'
            else 'alter system reset audit_trail scope = spfile'
       end as restore_stmt
  from v$spparameter where name = 'audit_trail';
whenever sqlerror continue
alter system set audit_trail = TRUE scope = spfile;
alter system set audit_trail = OS, EXTENDED scope = spfile;
alter system set audit_trail = EXTENDED scope = spfile;
whenever sqlerror exit failure
-- Put the spfile back as it was, in case a value was accepted.
-- SQL*Plus does not substitute the first word of a command, so the statement
-- runs from a block. RESET gives ORA-32010 when no value was written, which
-- leaves the spfile as it was.
prompt &restore_stmt
declare
  nothing_to_reset exception;
  pragma exception_init(nothing_to_reset, -32010);
begin
  execute immediate '&restore_stmt';
exception
  when nothing_to_reset then null;
end;
/
select listagg(display_value, ', ') within group (order by ordinal) as spfile_value,
       max(isspecified) as isspecified
  from v$spparameter where name = 'audit_trail';

prompt === teardown
drop user c##mt_svc cascade;
connect &sys_conn@&svc
drop user mt_svc cascade;
noaudit policy mt_logon by mt_person;
noaudit policy mt_alter by system;
drop audit policy mt_logon;
drop audit policy mt_alter;
drop user mt_person cascade;
exit
