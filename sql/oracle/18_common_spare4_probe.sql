--------------------------------------------------------------------------------
-- sopuli-dba : what does SPARE4 hold for a common account in a PDB?   (v1)
--
-- #1126. `creds check --method hash` reads SYS.USER$.SPARE4 in the container
-- the target names. On a PDB target it refused a common account, because the
-- PDB's row held a T: with no hex digits. 17_common_lcount_probe.sql found that a
-- PDB's row does not hold a common account's failed-login count. This measures
-- whether the same is true of its verifiers:
--
--   CV1  a common account created in CDB$ROOT with CONTAINER = ALL: SPARE4 in
--        both containers, and a local account in the PDB beside it
--   CV2  after ALTER USER ... IDENTIFIED BY in CDB$ROOT
--   CV3  after a login with the new password in the PDB, and one in CDB$ROOT
--   CV4  ALTER USER ... IDENTIFIED BY for the common account, made in the PDB
--
-- Each read shows the length of each tagged part of SPARE4 (S:, H: and T:,
-- without the tag), how many T: parts there are, how many of its characters
-- are hex digits and how many are blanks, PASSWORD_VERSIONS, and ORA_HASH of
-- the whole value, so that two reads can be compared. Never the value itself.
-- A NULL length means the tag is absent.
--
-- This MEASURES and decides nothing.
--
-- STATUS: run 2026-10-29 on 26ai Free 23.26.3.0.0 (gvenzl/oracle-free:latest,
-- FREEPDB1), 21c XE 21.3.0.0.0 and 18c XE 18.4.0.0.0 (gvenzl/oracle-xe:21-slim
-- and :18-slim, XEPDB1), twice on each, with the same results on all three
-- apart from the root's fingerprints. Every other release UNRUN, the 19.3 base
-- release among them.
--
--
-- RESULTS -- 23.26.3.0.0, 21.3.0.0.0 and 18.4.0.0.0, 2026-10-29
--
--   CV1  after CREATE USER ... CONTAINER = ALL:
--
--          container  LEN  S_LEN  T_LEN  T_PARTS  HEX  BLANKS  PASSWORD_VERSIONS
--          CDB$ROOT   225  60     160    1        220  0       11G 12C
--          the PDB    225  60     160    1        0    220     11G 12C
--
--        So in the PDB, SPARE4 is S: and 60 blanks, then T: and 160 blanks:
--        the shape of a real value, with no hex digit. H: is absent in both.
--        The local account in the PDB has 220 hex digits and no blanks. The
--        PDB's fingerprint is 528163111 on every release and every run
--
--   CV2  ALTER USER in CDB$ROOT changes the root's fingerprint. The PDB's row
--        is as it was in CV1
--
--   CV3  the new password logs in to the PDB and to CDB$ROOT. Neither login
--        changes either row
--
--   CV4  ALTER USER in the PDB gets ORA-65066, and neither row changes. The
--        password it named then gets ORA-01017 in the PDB, and the one set in
--        CV2 logs in
--
-- HOW TO RUN
--   As SYS, in the PDB and in CDB$ROOT. Against the tier-1 stack, whose SYS
--   and SYSTEM password is the public one in test/compose.yaml, as it stands:
--
--     MSYS_NO_PATHCONV=1 docker exec -i sopuli-test-oracle-free-1 \
--       sqlplus -S /nolog < 18_common_spare4_probe.sql
--
--   A second clone's stack names the container after its COMPOSE_PROJECT_NAME,
--   such as sopuli-test-w2-oracle-free-1. On XE the PDB is XEPDB1 and the root
--   service is XE. /nolog, and every CONNECT made from the script, so no
--   password is ever in argv (invariant 1). Against any other database, copy
--   the file, edit the three DEFINEs in the copy, run the copy and delete it --
--   never substitute them with sed, which puts the password in argv instead.
--   MSYS_NO_PATHCONV is for Git Bash, which otherwise rewrites /nolog.
--
-- WHENEVER SQLERROR is CONTINUE throughout: CV4's ALTER USER may be refused,
-- and the refusal is the answer. After each login, a SELECT says who is
-- connected where; SP2-0640 (not connected) means the login was refused.
--
-- THROWAWAY DATABASES ONLY. Creates and drops a local and a common account.
--------------------------------------------------------------------------------
define pdb  = //localhost:1521/FREEPDB1
define root = //localhost:1521/FREE
define pwd  = sopuli-test

WHENEVER SQLERROR CONTINUE
SET LINESIZE 200 PAGESIZE 100 FEEDBACK OFF VERIFY OFF HEADING ON
COLUMN who               FORMAT A16
COLUMN con               FORMAT A9
COLUMN name              FORMAT A16
COLUMN password_versions FORMAT A18

-- The row SYS reads for one account in the container it is connected to. It
-- is two DEFINEs because SQL*Plus 21 and earlier cap one at 240 characters.
-- Each starts after SELECT: SQL*Plus does not substitute the first word of a
-- command.
define v = "sys_context('userenv','con_name') con, u.name, length(u.spare4) len, length(regexp_substr(u.spare4,'S:[^;]*'))-2 s_len, length(regexp_substr(u.spare4,'H:[^;]*'))-2 h_len"
define v_more = "length(regexp_substr(u.spare4,'T:[^;]*'))-2 t_len, regexp_count(u.spare4,'T:') t_parts, regexp_count(u.spare4,'[0-9A-F]') hex, regexp_count(u.spare4,' ') blanks, d.password_versions"
define v_from = "ora_hash(u.spare4) fingerprint FROM sys.user$ u JOIN dba_users d ON d.username = u.name"
define whoami = "sys_context('userenv','session_user') who, sys_context('userenv','con_name') con FROM dual"

-------------------------------------------------------------------- setup ----
CONNECT sys/"&pwd"@&pdb AS SYSDBA
BEGIN
  FOR u IN (SELECT username FROM dba_users WHERE username LIKE 'ACME\_CV\_%' ESCAPE '\') LOOP
    BEGIN EXECUTE IMMEDIATE 'DROP USER ' || u.username || ' CASCADE';
    EXCEPTION WHEN OTHERS THEN NULL; END;
  END LOOP;
END;
/
CONNECT sys/"&pwd"@&root AS SYSDBA
BEGIN
  FOR u IN (SELECT username FROM dba_users WHERE username LIKE 'C##ACME\_CV\_%' ESCAPE '\') LOOP
    BEGIN EXECUTE IMMEDIATE 'DROP USER ' || u.username || ' CASCADE';
    EXCEPTION WHEN OTHERS THEN NULL; END;
  END LOOP;
END;
/

PROMPT
PROMPT == the release
SELECT version_full FROM v$instance;

CREATE USER c##acme_cv_a IDENTIFIED BY "Acme_Cv_A_1" CONTAINER = ALL;
GRANT CREATE SESSION TO c##acme_cv_a CONTAINER = ALL;

CONNECT sys/"&pwd"@&pdb AS SYSDBA
CREATE USER acme_cv_l IDENTIFIED BY "Acme_Cv_L_1";
GRANT CREATE SESSION TO acme_cv_l;

---------------------------------------------------- CV1: after CREATE ----
PROMPT
PROMPT == CV1: c##acme_cv_a created in CDB$ROOT, CONTAINER = ALL
CONNECT sys/"&pwd"@&root AS SYSDBA
SELECT &v, &v_more, &v_from WHERE u.name = 'C##ACME_CV_A';
CONNECT sys/"&pwd"@&pdb AS SYSDBA
SELECT &v, &v_more, &v_from WHERE u.name = 'C##ACME_CV_A';
PROMPT -- the local account beside it, in the PDB
SELECT &v, &v_more, &v_from WHERE u.name = 'ACME_CV_L';

------------------------------------------ CV2: after ALTER USER in root ----
PROMPT
PROMPT == CV2: ALTER USER c##acme_cv_a IDENTIFIED BY ..., in CDB$ROOT
CONNECT sys/"&pwd"@&root AS SYSDBA
ALTER USER c##acme_cv_a IDENTIFIED BY "Acme_Cv_A_2";
SELECT &v, &v_more, &v_from WHERE u.name = 'C##ACME_CV_A';
CONNECT sys/"&pwd"@&pdb AS SYSDBA
SELECT &v, &v_more, &v_from WHERE u.name = 'C##ACME_CV_A';

------------------------------------------------ CV3: after a good login ----
PROMPT
PROMPT == CV3: the new password, in the PDB
CONNECT c##acme_cv_a/"Acme_Cv_A_2"@&pdb
SELECT &whoami;
CONNECT sys/"&pwd"@&pdb AS SYSDBA
SELECT &v, &v_more, &v_from WHERE u.name = 'C##ACME_CV_A';
PROMPT -- and in CDB$ROOT
CONNECT c##acme_cv_a/"Acme_Cv_A_2"@&root
SELECT &whoami;
CONNECT sys/"&pwd"@&root AS SYSDBA
SELECT &v, &v_more, &v_from WHERE u.name = 'C##ACME_CV_A';
CONNECT sys/"&pwd"@&pdb AS SYSDBA
SELECT &v, &v_more, &v_from WHERE u.name = 'C##ACME_CV_A';

------------------------------------------- CV4: ALTER USER in the PDB ----
PROMPT
PROMPT == CV4: ALTER USER c##acme_cv_a IDENTIFIED BY ..., in the PDB
ALTER USER c##acme_cv_a IDENTIFIED BY "Acme_Cv_A_3";
SELECT &v, &v_more, &v_from WHERE u.name = 'C##ACME_CV_A';
CONNECT sys/"&pwd"@&root AS SYSDBA
SELECT &v, &v_more, &v_from WHERE u.name = 'C##ACME_CV_A';
PROMPT -- which password logs in to the PDB now
CONNECT c##acme_cv_a/"Acme_Cv_A_3"@&pdb
SELECT &whoami;
CONNECT c##acme_cv_a/"Acme_Cv_A_2"@&pdb
SELECT &whoami;

------------------------------------------------------------------ cleanup ----
CONNECT sys/"&pwd"@&pdb AS SYSDBA
DROP USER acme_cv_l CASCADE;
CONNECT sys/"&pwd"@&root AS SYSDBA
DROP USER c##acme_cv_a CASCADE;
EXIT
