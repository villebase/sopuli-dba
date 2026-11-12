# Measurements

This file says what has been run on which Oracle, PostgreSQL, MySQL or MariaDB
release, when, and what it showed. It is the one place for that. Other
documents link here instead of listing releases themselves. The PostgreSQL
results are in [their own part](#postgresql-releases), after the Oracle ones,
the MySQL results [after those](#mysql-releases), and the MariaDB results
[last](#mariadb-releases).

A result holds only for the release it names. Oracle's retention and auditing
behaviour is not a documented guarantee, and it differs between releases: 11.2
keeps the `ALTER USER` text in `V$SQLSTATS`, and every later release measured
does not. So always name the full release, such as `19.32.0.0.0`, and never
"19c".

Each script in `sql/oracle/` has a header that records its own runs in detail. A
Python probe's header is its docstring. `tests/test_measurements.py` checks that
the releases a script's header names are the same releases the *Scripts* table
below lists for it. A Python probe with no rows of its own, whose header names the
SQL script of the same name, may name only releases that the SQL script's rows
list. A release a header writes after "Instant Client" is the client the probe
ran with, and is not compared. The *Release* column of the tables below always
names the database a result was measured on, never the client. When you run a
script on a new release, update both.

The tier-1 suite in CI is not a measurement here. It pulls the moving
`gvenzl/oracle-free:latest` image, so a green CI run does not show which
release it ran on. The suite has no rows in this file.

## Releases

| Release | Product, and where it ran |
|---|---|
| `23.26.2.0.0` | 26ai Free, the `gvenzl/oracle-free` container, as pulled for the runs below |
| `23.26.3.3.0` | 26ai, an Autonomous Database (serverless) on OCI |
| `23.26.3.0.0` | 26ai Free, the `gvenzl/oracle-free` container, as pulled on 2026-10-24. Also the number of the Instant Client for Windows that the wallet results below and `14_session_loss_probe.py` ran with. A header writes the client as "Instant Client 23.26.3.0.0" |
| `21.3.0.0.0` | 21c XE, the `gvenzl/oracle-xe:21-slim` container |
| `19.32.0.0.0` | 19c EE, an OCI Base Database Service DB system. A release update |
| `19.24.0.0.0` | 19c EE High Performance. Checked by hand, once |
| `19.3.0.0.0` | 19c EE, the Oracle registry image, `test/compose.yaml` profile `oracle19c`. The 19c base release |
| `18.4.0.0.0` | 18c XE, the `gvenzl/oracle-xe:18-slim` container |
| `12.2.0.1.0` | 12c EE, the Oracle registry slim image, profile `oracle12c`. Its character set is WE8DEC |
| `11.2.0.2.0` | 11g XE, the `gvenzl/oracle-xe:11.2.0.2-slim` container. A non-CDB |

Not measured: 12.1, any 23ai release before 23.26, and every 19c release update
other than 19.24 and 19.32. One release update is not every release update.

## Scripts

<!-- measurements: scripts -->
| Script | Release | Date | Issue | Result |
|---|---|---|---|---|
| `00_install.sql` | `23.26.2.0.0` | 2026-08-26 | — | All three modes, create and already-exists paths, both mode guards. `grant_pwfile` added and run 2026-09-05 (#296); `grant_connect_info` 2026-10-09 (#697) |
| `00_install.sql` | `23.26.3.0.0` | 2026-11-07 | #1387 | `grant_report_reads` added: PDB mode by hand with `Y` and `N`, and the install-script tests |
| `00_install.sql` | `23.26.3.0.0` | 2026-11-08 | #1389 | `grant_report_reads=Y` also grants `DBA_SCHEMA_PRIVS` where the view exists: PDB mode through probe 21 with `Y` and `N`, and the install-script tests. The branch for a release without the view is untried |
| `00_install.sql` | `21.3.0.0.0` | 2026-09-08 | #380 | PDB and `CDB$ROOT`. Ran only after the service account's random password was cut from 31 to 30 bytes |
| `00_install.sql` | `18.4.0.0.0` | 2026-09-08 | #381 | PDB and `CDB$ROOT` |
| `00_install.sql` | `11.2.0.2.0` | 2026-09-08 | #382 | `NONCDB` mode, after two fixes for a non-CDB |
| `00_install.sql` | `19.3.0.0.0` | 2026-09-28 | #479 | PDB and `COMMON` modes; the over-grant query is empty |
| `00_install.sql` | `12.2.0.1.0` | 2026-09-29 | #572 | PDB and `COMMON` modes. The image's root has no `USERS` tablespace |
| `00_install.sql` | `19.32.0.0.0` | 2026-10-01 | #581 | PDB and `COMMON` modes, after section 1's password was changed to pass `ORA12C_STRONG_VERIFY_FUNCTION` |
| `00_install.sql` | `23.26.3.3.0` | 2026-09-28 | #479 | PDB mode as `ADMIN`. `grant_user_dollar=Y` cannot succeed there (#478) |
| `01_audit_policy.sql` | `23.26.2.0.0` | 2026-08-26 | — | Create and already-exists paths; the correlation queries checked against a real audited `ALTER USER` |
| `01_audit_policy.sql` | `21.3.0.0.0` | 2026-09-08 | #380 | Runs. The XE image ships `AUDIT_TRAIL = NONE`, so it records nothing until that is changed |
| `01_audit_policy.sql` | `18.4.0.0.0` | 2026-09-08 | #381 | As on 21.3 |
| `01_audit_policy.sql` | `11.2.0.2.0` | 2026-09-08 | #382 | Refuses with `ORA-20020`: audit policies arrived in 12.1 |
| `01_audit_policy.sql` | `19.3.0.0.0` | 2026-09-28 | #479 | PDB and `CDB$ROOT` |
| `01_audit_policy.sql` | `23.26.2.0.0` | 2026-10-17 | #812 | Common `SOPULI_CDB_*` policies in `CDB$ROOT`, local ones in the PDB; the root's older local policies dropped; the personal-account list, added to on a second run; a name that is not an account refused with `ORA-44001` |
| `02_password_leak_probe.sql` | `23.26.2.0.0` | 2026-08-26 | — | All three positions. No cursor for the DDL; unified audit masks it; the only leak is the PL/SQL block (C3). Position 2 with `AUDIT_SYS_OPERATIONS` 2026-09-11 (#407) |
| `02_password_leak_probe.sql` | `21.3.0.0.0` | 2026-09-08 | #380 | Position 1 as on 26ai; traditional auditing masks too. Position 2 2026-09-11 (#407) |
| `02_password_leak_probe.sql` | `18.4.0.0.0` | 2026-09-08 | #381 | Position 1, as on 21.3 |
| `02_password_leak_probe.sql` | `11.2.0.2.0` | 2026-09-08 | #382 | Position 1. **`V$SQLSTATS` keeps the plain `ALTER USER` text.** It ages out, and `FLUSH SHARED_POOL` clears it (2026-09-09, #387) |
| `02_password_leak_probe.sql` | `19.3.0.0.0` | 2026-09-27 | #548 | All three positions. C3 only; `V$SQLSTATS` clean |
| `02_password_leak_probe.sql` | `12.2.0.1.0` | 2026-09-29 | #572 | All three positions. C3 only; `V$SQLSTATS` clean |
| `02_password_leak_probe.sql` | `19.32.0.0.0` | 2026-10-01 | #581 | All three positions. C3 only; `V$SQLSTATS` and `V$SQL_BIND_CAPTURE` clean with the verify function on. Under `AUDIT_TRAIL = DB` the traditional trail records no statement text |
| `03_app_container_probe.sql` | `23.26.2.0.0` | 2026-09-03 | #204 | An application root and an application PDB can be told apart with no grant |
| `04_password_leak_extensions.sql` | `23.26.2.0.0` | 2026-09-11 | #407 | Self-rotation and `IDENTIFIED BY VALUES` masked. A level-12 trace writes the DDL cut short, `ALTER USER sopulitest IDE`; the wrapped form (C8) leaks. No user DDL reaches the OS audit files |
| `04_password_leak_extensions.sql` | `21.3.0.0.0` | 2026-09-11 | #407 | As on 26ai; the OS audit file has the DDL masked |
| `04_password_leak_extensions.sql` | `19.3.0.0.0` | 2026-09-28 | #479 | As on 21.3 |
| `04_password_leak_extensions.sql` | `19.32.0.0.0` | 2026-10-01 | #581 | As on 19.3, except that `IDENTIFIED BY VALUES` is absent from the traditional trail. The cause is not known |
| `05_verifier_layout_probe.sql` | `23.26.2.0.0` | 2026-09-15 | #431 | `SPARE4` holds `S:` then `T:`; the salt offsets are read off the wire |
| `05_verifier_layout_probe.sql` | `21.3.0.0.0` | 2026-09-15 | #431 | As on 26ai |
| `05_verifier_layout_probe.sql` | `18.4.0.0.0` | 2026-09-15 | #431 | As on 26ai |
| `05_verifier_layout_probe.sql` | `11.2.0.2.0` | 2026-09-15 | #431 | No `T:`; the 10G verifier is in `USER$.PASSWORD` |
| `05_verifier_layout_probe.sql` | `19.3.0.0.0` | 2026-09-27 | #548 | As on 26ai |
| `05_verifier_layout_probe.sql` | `12.2.0.1.0` | 2026-09-29 | #572 | As on 26ai |
| `05_verifier_layout_probe.sql` | `19.32.0.0.0` | 2026-10-01 | #581 | As on 26ai. The wire step could not be seen: the DB system requires NNE |
| `06_verifier_reproduce.sql` | `23.26.2.0.0` | 2026-09-15 | #432 | Every `T:` reproduces client-side. A rollover window holds two verifiers, `T:` old and `t:` new. A 128-byte password is accepted |
| `06_verifier_reproduce.sql` | `21.3.0.0.0` | 2026-09-15 | #432 | As on 26ai, but 128 bytes is refused |
| `06_verifier_reproduce.sql` | `18.4.0.0.0` | 2026-09-15 | #432 | Every `T:` reproduces. No rollover |
| `06_verifier_reproduce.sql` | `19.3.0.0.0` | 2026-09-27 | #548 | Every `T:` reproduces. No rollover |
| `06_verifier_reproduce.sql` | `12.2.0.1.0` | 2026-09-29 | #572 | Every `T:` reproduces, from the password as converted to WE8DEC. No rollover |
| `06_verifier_reproduce.sql` | `19.32.0.0.0` | 2026-10-01 | #581 | Every `T:` reproduces, and a rollover window opens with `T:` old and `t:` new |
| `07_lock_and_rollover_probe.sql` | `23.26.2.0.0` | 2026-09-16 | #455 | `ACCOUNT UNLOCK` resets the failed-login count; `IDENTIFIED BY` unlocks nothing. `PASSWORD EXPIRE` on a rollover profile gives `EXPIRED & IN ROLLOVER`, and the old password still works |
| `07_lock_and_rollover_probe.sql` | `21.3.0.0.0` | 2026-09-26 | #461 | As on 26ai |
| `07_lock_and_rollover_probe.sql` | `19.3.0.0.0` | 2026-09-28 | #479 | Q1–Q5 as on 26ai. No rollover |
| `08_expire_password_probe.sql` | `23.26.2.0.0` | 2026-09-25 | #525 | A second `PASSWORD EXPIRE` is accepted silently; `EXPIRED(GRACE)` to `EXPIRED` is a real change; locks are untouched; expiry does not end a rollover window |
| `08_expire_password_probe.sql` | `19.3.0.0.0` | 2026-09-28 | #479 | E1–E5 as on 26ai, but the grace-period login sends `ORA-28002`. No rollover |
| `09_reset_from_expired_probe.sql` | `23.26.2.0.0` | 2026-09-26 | #529 | From `EXPIRED`, a reset opens no rollover window and every earlier password stops working |
| `09_reset_from_expired_probe.sql` | `21.3.0.0.0` | 2026-09-26 | #461 | As on 26ai |
| `09_reset_from_expired_probe.sql` | `19.3.0.0.0` | 2026-09-28 | #479 | No rollover; the script stops at section 0 |
| `09_reset_from_expired_probe.sql` | `23.26.3.0.0` | 2026-10-28 | #541 | v2 and v3. Every v1 row as on 23.26.2.0.0. From `OPEN` and from `EXPIRED(GRACE)`, the seen form and then `EXPIRE PASSWORD ROLLOVER PERIOD` leave the old password dead. From `EXPIRED & LOCKED(TIMED)`, `ACCOUNT UNLOCK` leaves `EXPIRED`, and the seen form then opens no window and the old password is dead |
| `09_reset_from_expired_probe.sql` | `21.3.0.0.0` | 2026-10-28 | #541 | v2 and v3. As on 23.26.3.0.0 |
| `10_awr_snapshot_probe.sql` | `19.32.0.0.0` | 2026-10-01 | #581 | The wrapped literal (C3) reaches `DBA_HIST_SQLTEXT`. C1, C2 and C4 do not |
| `11_proxy_connect_probe.sql` | `23.26.2.0.0` | 2026-10-01 | #459 | `ALTER USER` alone can grant `CONNECT THROUGH` and connect as the person. With no audit policy, nothing durable records it |
| `11_proxy_connect_probe.sql` | `23.26.3.0.0` | 2026-10-24 | #1014 | As on 23.26.2.0.0, connecting by EZConnect |
| `12_connection_encryption_probe.sql` | `23.26.2.0.0` | 2026-10-09 | #697 | Plain, NNE and TLS. `PUBLIC` reads the view; the account sees only its own SID |
| `12_connection_encryption_probe.sql` | `21.3.0.0.0` | 2026-10-09 | #697 | Plain, NNE and TLS. `PUBLIC` reads the view; it shows the account two SIDs |
| `12_connection_encryption_probe.sql` | `18.4.0.0.0` | 2026-10-09 | #697 | Plain, NNE and TLS. `PUBLIC` reads the view; it shows the account one or two SIDs |
| `12_connection_encryption_probe.sql` | `19.3.0.0.0` | 2026-10-09 | #697 | Plain, NNE and TLS. As on 21.3 |
| `12_connection_encryption_probe.sql` | `12.2.0.1.0` | 2026-10-09 | #697 | Plain, NNE and TLS. As on 21.3 |
| `12_connection_encryption_probe.sql` | `11.2.0.2.0` | 2026-10-09 | #697 | Plain and NNE. The adapter row reads `Oracle Advanced Security: AES256 encryption service adapter`; the view shows the account three SIDs. TLS did not run: `ORA-29106` on the wallet |
| `13_audit_coverage_probe.sql` | `23.26.2.0.0` | 2026-10-15 | #591 | Pure unified mode. A `BY` or `EXCEPT` list applies to the account that issues the statement, so a policy `BY` the person misses the DBA's `ALTER USER`. The account reads the policy views after `SYS` grants `READ`; `SYSTEM` cannot grant it. A common policy enabled in the root records nothing of local accounts' route, and records a common account's logon |
| `13_audit_coverage_probe.sql` | `23.26.2.0.0` | 2026-10-17 | #812 | `01_audit_policy.sql`'s policies, created in the root with no `CONTAINER` clause, record nothing in a PDB, not even the service account's `ALTER USER`. Created `CONTAINER = ALL`, they record common accounts in every container and no local account. Created in the PDB, they record every account's `ALTER USER` there. The logon policy records only the service account's failed logons, so no placement records a proxy logon. A common account reset in the root is recorded there. A common and a PDB policy may have one name |
| `13_audit_coverage_probe.sql` | `23.26.3.0.0` | 2026-10-24 | #1014 | As on 23.26.2.0.0, AC0 to AC10, counts included, connecting by EZConnect |
| `13_audit_coverage_probe.sql` | `21.3.0.0.0` | 2026-10-23 | #820 | Mixed mode, `AUDIT_TRAIL = NONE`, and `ORA_SECURECONFIG` and `ORA_LOGON_FAILURES` enabled from the start. The two policy views have the columns and rows the check reads, as on 26ai. The trail records nothing at run time, also under an enabled policy and after a flush: it holds only the image's build rows. `AUDIT_TRAIL = NONE` is the cause (`15_mixed_mode_trail_probe.sql`) |
| `13_audit_coverage_probe.sql` | `18.4.0.0.0` | 2026-10-23 | #820 | As 21.3 through AC3: mixed mode, and the views have the columns the check reads, beside `USER_NAME` and `ENABLED_OPT`. Stops in AC4: the trail has no `EVENT_TIMESTAMP_UTC`. As on 21.3, the trail holds only the image's build rows, for the same cause |
| `14_session_loss_probe.py` | `23.26.2.0.0` | 2026-10-17 | #775 | Thick mode, Instant Client `23.26.3.0.0`, python-oracledb 26.0.0. A session lost to a PDB closed `IMMEDIATE` or to a CDB shutdown (`IMMEDIATE` or `ABORT`) raises `DPY-4011`, with `ORA-03113` inside its message. A logon while the CDB starts gets `ORA-12528` in NOMOUNT and `ORA-01033` in MOUNT, and `ORA-12514` to a PDB service throughout. `ORA-00028`, `ORA-03135`, `ORA-01034` and `ORA-01089` were not produced |
| `15_mixed_mode_trail_probe.sql` | `21.3.0.0.0` | 2026-10-23 | #1006 | Mixed mode. Under `AUDIT_TRAIL = NONE`, as the image ships, a logon under an enabled `ACTIONS LOGON` policy and an `ALTER USER` under an enabled `ACTIONS ALTER USER` policy leave no row, while the policy view shows both enabled. Under `AUDIT_TRAIL = DB` each leaves one |
| `15_mixed_mode_trail_probe.sql` | `18.4.0.0.0` | 2026-10-23 | #1006 | As on 21.3, in a session that logs on after the policies change. A session keeps the policies enabled when it logged on: its `ALTER USER` is recorded under a policy it disabled, and not under one it enabled. On 21.3 the change reaches the session at once |
| `15_mixed_mode_trail_probe.sql` | `21.3.0.0.0` | 2026-10-24 | #1013 | Under `AUDIT_TRAIL = DB, EXTENDED`, `OS`, `XML` and `XML, EXTENDED` each action leaves one row in `UNIFIED_AUDIT_TRAIL`, as under `DB` |
| `15_mixed_mode_trail_probe.sql` | `18.4.0.0.0` | 2026-10-24 | #1013 | As under `DB` on 18.4, under each of the same four settings |
| `15_mixed_mode_trail_probe.sql` | `21.3.0.0.0` | 2026-10-27 | #1098 | v4, under `AUDIT_TRAIL = NONE`. A local or common account holding only `CREATE SESSION` gets `ORA-00942` on `V$PARAMETER`; after `SYS` grants `SELECT ON V_$PARAMETER`, in the PDB or in `CDB$ROOT` with `CONTAINER = ALL`, it reads `AUDIT_TRAIL` in XEPDB1. `ALTER SYSTEM … SCOPE = SPFILE` refuses `TRUE` with `ORA-00096` naming five values, and `OS, EXTENDED` and `EXTENDED` with `ORA-32017` and an `ORA-00096` naming six |
| `15_mixed_mode_trail_probe.sql` | `18.4.0.0.0` | 2026-10-27 | #1098 | As on 21.3, the same output |
| `16_lcount_grant_probe.sql` | `23.26.3.0.0` | 2026-10-28 | #124 | `KU$_USER_VIEW` shows an account holding only `SELECT_CATALOG_ROLE` every user's `LCOUNT` and `PTIME`, and `SPARE4` as one space. `EXP_FULL_DATABASE` changes nothing; `SELECT ON SYS.USER$` beside the role shows the verifiers. With no role enabled the view shows no rows. `KU$_USER_BASE_VIEW` does not exist. A common account's failed logins in the PDB are counted in `CDB$ROOT`'s `LCOUNT`. A policy on `SELECT ON SYS.USER$` records a read through the view |
| `17_common_lcount_probe.sql` | `23.26.3.0.0` | 2026-10-28 | #1122 | A common account has one failed-login count, the root's. Failed logins in the PDB and in the root add to it, a good login in the PDB resets it, and it locks the account in both containers on the limit of the account's profile in the root, whether that limit is lower or higher than the PDB's. In the PDB, `SYS.USER$` reads 0 and `DBA_USERS` says `OPEN` for the locked account, which answers `ORA-28000` to a right or a wrong password. `CONTAINERS()` and `CDB_USERS` read in the PDB show only the PDB. A common account that holds `SET CONTAINER` and `SELECT ON SYS.USER$`, both `CONTAINER = ALL`, reads the root's count after it switches to `CDB$ROOT` |
| `17_common_lcount_probe.sql` | `21.3.0.0.0` | 2026-10-28 | #1122 | As on 26ai |
| `17_common_lcount_probe.sql` | `18.4.0.0.0` | 2026-10-28 | #1122 | As on 26ai |
| `18_common_spare4_probe.sql` | `23.26.3.0.0` | 2026-10-29 | #1126 | In the PDB, a common account's `SPARE4` is `S:` and 60 blanks, then `T:` and 160 blanks: the shape of a real value, with no hex digit. The root holds the real verifiers. `ALTER USER ... IDENTIFIED BY` in the root changes the root's row and leaves the PDB's as it was, and the new password logs in to the PDB. The same statement in the PDB gets `ORA-65066` |
| `18_common_spare4_probe.sql` | `21.3.0.0.0` | 2026-10-29 | #1126 | As on 26ai |
| `18_common_spare4_probe.sql` | `18.4.0.0.0` | 2026-10-29 | #1126 | As on 26ai |
| `19_report_read_probe.sql` | `23.26.3.0.0` | 2026-11-07 | #1377 | v3. `00_install.sql`'s grants, local or `CONTAINER = ALL`, read `DBA_USERS`, `DBA_PROFILES`, `DBA_ROLE_PRIVS` and `DBA_ROLES`. `DBA_SYS_PRIVS`, `DBA_TAB_PRIVS` and `DBA_COL_PRIVS` give `ORA-00942` until `SELECT` on each is granted; a column grant is in `DBA_COL_PRIVS` only. A recursive query from the account and from `PUBLIC` reaches every object and system privilege with its role path, one row per path. A local profile's `DEFAULT` limit follows the PDB's `DEFAULT` profile; a common profile's follows the root's, for a local account on it too. In a PDB, a locked common account reads `OPEN` and its `PASSWORD_CHANGE_DATE` is NULL |
| `20_grant_chunk_probe.py` | `23.26.3.0.0` | 2026-11-08 | #1396 | Thick mode, Instant Client `23.26.3.0.0`. UC-5's privilege survey with `grantee IN (…)` for 1, 100, 250 and 1,000 grantees per statement, every chunk size giving the same rows. One per statement took 58 seconds for 303 accounts and 221 for 1,103; chunks of 250 took 3.4 and 6.2 with the shared pool flushed. Flushed, chunks of 1,000 took 12.2 seconds for 1,103 accounts; with the statements cached, 2.0 |
| `21_schema_privs_probe.py` | `23.26.3.0.0` | 2026-11-08 | #1389 | Thick mode, Instant Client `23.26.3.0.0`. `DBA_SCHEMA_PRIVS` has `GRANTEE`, `PRIVILEGE`, `SCHEMA`, `ADMIN_OPTION`, `COMMON` and `INHERITED`, one row per grantee, privilege and schema. A schema privilege held through a role is under the role, and is reached by the survey's recursive `WITH`; one granted to `PUBLIC` is under `PUBLIC`. None shows in `DBA_SYS_PRIVS` or `DBA_TAB_PRIVS`. v2: the service account reads `DBA_SCHEMA_PRIVS` with `grant_report_reads=Y` and gets `ORA-00942` with `N`; it reads `USER_SCHEMA_PRIVS` and `SESSION_SCHEMA_PRIVS` with no grant, and they include `PUBLIC`'s |
| `22_lock_kind_probe.sql` | `23.26.3.0.0` | 2026-11-11 | #1447 | A lockout after failed logins reads `LOCKED(TIMED)` and `SYS.USER$.ASTATUS` 4 under a finite `PASSWORD_LOCK_TIME`, and `LOCKED` and `ASTATUS` 8 under `UNLIMITED`, the same as after `ACCOUNT LOCK`; only `LCOUNT` differs. A lock set after failed logins below the limit keeps the count. Raising the limit after a lockout leaves the account `LOCKED`, with its count now below the limit. An account made `NO AUTHENTICATION` reads `OPEN` and `AUTHENTICATION_TYPE` `NONE`, and a login with a password gets `ORA-01017`. v2: a login to an account locked with `ACCOUNT LOCK` gets `ORA-28000`, with a wrong password or the right one, and `LCOUNT` stays 0 |
| `99_uninstall.sql` | `23.26.2.0.0` | 2026-08-26 | — | `COMMON` and PDB installs, both `keep_audit` settings |
| `99_uninstall.sql` | `23.26.2.0.0` | 2026-10-17 | #812 | `keep_audit=N` drops the `SOPULI_CDB_*` policies in `CDB$ROOT`; in a PDB it drops the PDB's own and leaves the root's |
| `99_uninstall.sql` | `21.3.0.0.0` | 2026-09-08 | #380 | Both `keep_audit` settings |
| `99_uninstall.sql` | `18.4.0.0.0` | 2026-09-08 | #381 | As on 21.3 |
| `99_uninstall.sql` | `11.2.0.2.0` | 2026-09-08 | #382 | The account and its grants. There are no audit policies to keep |
| `99_uninstall.sql` | `19.3.0.0.0` | 2026-09-28 | #479 | PDB and `COMMON` installs |

## Other results

These came from the tool itself, from the test suite, or from a check by hand,
not from a script in `sql/oracle/`.

| Surface | Release | Date | Issue | Result |
|---|---|---|---|---|
| Longest password | `23.26.2.0.0` | 2026-09-08 | #383 | 128 bytes accepted |
| Longest password | `21.3.0.0.0`, `18.4.0.0.0`, `11.2.0.2.0` | 2026-09-08 | #383 | 30 bytes; 31 is `ORA-00972` |
| Longest password | `19.3.0.0.0` | 2026-09-27 | #548 | 30 bytes; 31 and 128 are `ORA-00972` |
| Longest password | `12.2.0.1.0` | 2026-09-29 | #572 | 30 bytes; 31 is `ORA-00972` |
| Longest password | `19.32.0.0.0` | 2026-10-01 | #581 | 30 bytes accepted; 128 is refused. 31 was not tried |
| `DBA_USERS.PASSWORD_CHANGE_DATE` | `23.26.2.0.0`, `21.3.0.0.0` | 2026-09-08 | #386 | Present, and equal to `SYS.USER$.PTIME` |
| `DBA_USERS.PASSWORD_CHANGE_DATE` | `18.4.0.0.0`, `11.2.0.2.0` | 2026-09-08 | #386 | Absent (`ORA-00904`); `PTIME` moves with a rotation. 18.4 has `ORACLE_MAINTAINED` (#381) |
| `DBA_USERS.PASSWORD_CHANGE_DATE` | `19.24.0.0.0` | 2026-09-17 | #386 | Present. Only its presence was checked |
| `DBA_USERS.PASSWORD_CHANGE_DATE` | `12.2.0.1.0` | 2026-09-29 | #572 | Absent; the suite's `PTIME` fallback test passes |
| Grace-period login warning | `23.26.2.0.0` | 2026-09-02 | #322 | `ORA-28098` or `ORA-28011`, on a login that succeeds |
| Grace-period login warning | `21.3.0.0.0` | 2026-09-26 | #461 | `ORA-28002`, seen in SQL\*Plus, not through the driver |
| Grace-period login warning | `19.3.0.0.0` | 2026-09-28 | #479 | `ORA-28002` |
| Thin mode | `19.32.0.0.0` | 2026-10-01 | #575 | Refused with `DPY-3001`: the shipped `sqlnet.ora` requires NNE |
| Thin mode | `23.26.3.3.0` | 2026-10-01 | #575 | Connects over TCPS; no NNE is negotiated |
| Wallet failures over mutual TLS | `23.26.3.3.0` | 2026-09-28 | #472 | Missing, misplaced or unreadable: `ORA-28759`. Damaged: `ORA-28768`. Each took 64 s, because the alias sets `retry_count=20`. Instant Client 23.26.3.0.0, on Windows only |
| The tool end to end | `23.26.3.3.0` | 2026-09-28 | #479 | Install, a rotation, a rollback and a rollover window, with a vault-held password. `docs/maintainer-environments.md` §6 has the setup |
| The tool end to end | `19.32.0.0.0` | 2026-10-01 | #581 | As the least-privilege service account, including a rollover window. `docs/maintainer-environments.md` §5 has the setup and the run |

## PostgreSQL releases

A PostgreSQL release is two numbers, such as `16.15`. Name it in full, never
"16": a minor release can change what a major release does. The scripts are in
`sql/postgres/`, and `tests/test_measurements.py` checks their headers against
the table below in the same way. A release a header writes after "libpq" is the
client the probe ran with, and is not compared. It still needs a row in the
table, which says it is a libpq.

| Release | Product, and where it ran |
|---|---|
| `13.23` | The `postgres:13` image, `test/compose.yaml` profile `postgres-matrix`, as pulled on 2026-10-25 |
| `14.24` | The `postgres:14` image, the same profile, as pulled on 2026-10-25 |
| `15.19` | The `postgres:15` image, the same profile, as pulled on 2026-10-25 |
| `16.15` | The `postgres:16` image, the same profile, as pulled on 2026-10-25. Also the `postgres:16-alpine` image of the `postgres` service, as pulled on 2026-10-27, behind PgBouncer 1.26.0 (profile `pgbouncer`) |
| `17.11` | The `postgres:17` image, the same profile, as pulled on 2026-10-25 |
| `18.6` | The `postgres:18` image, the same profile, as pulled on 2026-10-25. Also the number of the libpq that the `postgres:18` image's psql and psycopg 3.3.6's Linux wheels bundle. A header writes the client as "libpq 18.6" |
| `18.4` | libpq only: the one psycopg 3.3.6's Windows wheel bundles. No server ran it |
| `17.6` | The `supabase/postgres:17.6.1.095` image, Supabase's database, `test/compose.yaml` profile `supabase`, as pulled on 2026-10-28. Also the number of the libpq that psycopg 3.2.13's Linux wheel bundles. A header writes the client as "libpq 17.6" |
| `16.3` | libpq only: the one psycopg 3.1.20's Linux wheel bundles |
| `16.0` | libpq only: the one psycopg 3.1.12's Linux wheel bundles |
| `15.0` | libpq only: the one psycopg 3.1.4's Linux wheel bundles |
| `14.4` | libpq only: the one psycopg 3.0.18's Linux wheel bundles |

Not measured: every other minor release, and every managed service. The
Supabase image ran on its own, not as a hosted project.

## PostgreSQL scripts

<!-- measurements: postgres scripts -->
| Script | Release | Date | Issue | Result |
|---|---|---|---|---|
| `01_password_text_probe.sql` | `13.23` | 2026-10-25 | #1032 | The server log and `pg_stat_statements` keep the `ALTER ROLE` text in full, verifier or plaintext. The log keeps a failed statement's text under the default `log_statement = none`. `pg_stat_activity` shows an idle session's last statement with its password |
| `01_password_text_probe.sql` | `14.24` | 2026-10-25 | #1032 | As on 13.23 |
| `01_password_text_probe.sql` | `15.19` | 2026-10-25 | #1032 | As on 13.23 |
| `01_password_text_probe.sql` | `16.15` | 2026-10-25 | #1032 | As on 13.23 |
| `01_password_text_probe.sql` | `17.11` | 2026-10-25 | #1032 | As on 13.23 |
| `01_password_text_probe.sql` | `18.6` | 2026-10-25 | #1032 | As on 13.23 |
| `02_system_identifier_probe.sql` | `13.23` | 2026-10-25 | #1032 | `pg_control_system()` has the default ACL, so a role with no grants reads `system_identifier` |
| `02_system_identifier_probe.sql` | `14.24` | 2026-10-25 | #1032 | As on 13.23 |
| `02_system_identifier_probe.sql` | `15.19` | 2026-10-25 | #1032 | As on 13.23 |
| `02_system_identifier_probe.sql` | `16.15` | 2026-10-25 | #1032 | As on 13.23 |
| `02_system_identifier_probe.sql` | `17.11` | 2026-10-25 | #1032 | As on 13.23 |
| `02_system_identifier_probe.sql` | `18.6` | 2026-10-25 | #1032 | As on 13.23 |
| `03_createrole_password_probe.sql` | `13.23` | 2026-10-25 | #1032 | `CREATEROLE` alone changes another role's password, unless that role is a superuser. A role that creates another gets no membership in it |
| `03_createrole_password_probe.sql` | `14.24` | 2026-10-25 | #1032 | As on 13.23 |
| `03_createrole_password_probe.sql` | `15.19` | 2026-10-25 | #1032 | As on 13.23 |
| `03_createrole_password_probe.sql` | `16.15` | 2026-10-25 | #1032 | `CREATEROLE` also needs `ADMIN OPTION` on the role, which works with `INHERIT FALSE, SET FALSE`. `pg_auth_members.admin_option` and `pg_has_role(…, 'USAGE WITH ADMIN OPTION')` show it. A role that creates another gets `ADMIN OPTION` on it |
| `03_createrole_password_probe.sql` | `17.11` | 2026-10-25 | #1032 | As on 16.15 |
| `03_createrole_password_probe.sql` | `18.6` | 2026-10-25 | #1032 | As on 16.15 |
| `03_createrole_password_probe.sql` | `13.23` | 2026-10-27 | #1098 | CR6: a new role with only `CREATEROLE` grants itself `pg_execute_server_program`. CR1 to CR5 as on 2026-10-25 |
| `03_createrole_password_probe.sql` | `14.24` | 2026-10-27 | #1098 | As on 13.23 |
| `03_createrole_password_probe.sql` | `15.19` | 2026-10-27 | #1098 | As on 13.23 |
| `03_createrole_password_probe.sql` | `16.15` | 2026-10-27 | #1098 | CR6: refused, `42501`, without `ADMIN OPTION` on the built-in role. CR1 to CR5 as on 2026-10-25 |
| `03_createrole_password_probe.sql` | `17.11` | 2026-10-27 | #1098 | As on 16.15 |
| `03_createrole_password_probe.sql` | `18.6` | 2026-10-27 | #1098 | As on 16.15 |
| `03_createrole_password_probe.sql` | `13.23` | 2026-11-01 | #1201 | CR7: `CREATEROLE` alone sets another role `NOLOGIN`. CR8: with `ADMIN OPTION` too, `NOLOGIN` and `LOGIN` are accepted, and a second `NOLOGIN` is accepted silently. CR1 to CR6 as on 2026-10-27 |
| `03_createrole_password_probe.sql` | `14.24` | 2026-11-01 | #1201 | As on 13.23 |
| `03_createrole_password_probe.sql` | `15.19` | 2026-11-01 | #1201 | As on 13.23 |
| `03_createrole_password_probe.sql` | `16.15` | 2026-11-01 | #1201 | CR7: refused, `42501`, without `ADMIN OPTION` on the role. CR8 as on 13.23. CR1 to CR6 as on 2026-10-27 |
| `03_createrole_password_probe.sql` | `17.11` | 2026-11-01 | #1201 | As on 16.15 |
| `03_createrole_password_probe.sql` | `18.6` | 2026-11-01 | #1201 | As on 16.15 |
| `04_md5_line_scram_verifier_probe.py` | `13.23` | 2026-10-25 | #1032 | Under `password_encryption = md5`, a role given a SCRAM verifier logs in with SCRAM through a line that says `md5`. A client held to md5 is refused |
| `04_md5_line_scram_verifier_probe.py` | `14.24` | 2026-10-25 | #1032 | As on 13.23 |
| `04_md5_line_scram_verifier_probe.py` | `15.19` | 2026-10-25 | #1032 | As on 13.23 |
| `04_md5_line_scram_verifier_probe.py` | `16.15` | 2026-10-25 | #1032 | As on 13.23 |
| `04_md5_line_scram_verifier_probe.py` | `17.11` | 2026-10-25 | #1032 | As on 13.23 |
| `04_md5_line_scram_verifier_probe.py` | `18.6` | 2026-10-25 | #1032 | As on 13.23. The server warns that md5 passwords are deprecated |
| `04_md5_line_scram_verifier_probe.py` | `13.23` | 2026-10-27 | #1098 | Under `password_encryption = md5`, the release's own psql `\password` sends an md5 verifier, which a `scram-sha-256` line refuses. After `SET password_encryption = 'scram-sha-256'` it sends a SCRAM one, which logs in, also with `require_auth=scram-sha-256`. The other logins as on 2026-10-25 |
| `04_md5_line_scram_verifier_probe.py` | `14.24` | 2026-10-27 | #1098 | As on 13.23 |
| `04_md5_line_scram_verifier_probe.py` | `15.19` | 2026-10-27 | #1098 | As on 13.23 |
| `04_md5_line_scram_verifier_probe.py` | `16.15` | 2026-10-27 | #1098 | As on 13.23 |
| `04_md5_line_scram_verifier_probe.py` | `17.11` | 2026-10-27 | #1098 | As on 13.23 |
| `04_md5_line_scram_verifier_probe.py` | `18.6` | 2026-10-27 | #1098 | As on 13.23. The server warns at the md5 `\password` that md5 passwords are deprecated |
| `05_psycopg_libpq_probe.py` | `18.6` | 2026-10-25 | #1032 | psycopg 3.3.6 loads libpq 18.4 on Windows AMD64 and libpq 18.6 on Linux x86_64, glibc and musl. 3.2.13, 3.1.20 and 3.1.12 load libpq 17.6, libpq 16.3 and libpq 16.0 on Linux, and accept `require_auth=scram-sha-256`. 3.1.4 and 3.0.18 load libpq 15.0 and libpq 14.4, and refuse it in the client as an invalid connection option. Each computes a SCRAM verifier. Not run on macOS (unverified: psycopg-libpq-macos) |
| `06_saslprep_probe.py` | `13.23` | 2026-10-26 | #1057 | A verifier from libpq 18.4 and the server's own hash agree on every non-ASCII password tried, and each logs in with both spellings SASLprep makes one, by psycopg and by psql with the release's own libpq. A password with a character SASLprep prohibits logs in as given. A verifier computed without SASLprep refuses a password SASLprep changes. The named charsets are ASCII |
| `06_saslprep_probe.py` | `14.24` | 2026-10-26 | #1057 | As on 13.23 |
| `06_saslprep_probe.py` | `15.19` | 2026-10-26 | #1057 | As on 13.23 |
| `06_saslprep_probe.py` | `16.15` | 2026-10-26 | #1057 | As on 13.23 |
| `06_saslprep_probe.py` | `17.11` | 2026-10-26 | #1057 | As on 13.23 |
| `06_saslprep_probe.py` | `18.6` | 2026-10-26 | #1057 | As on 13.23 |
| `07_password_length_probe.py` | `13.23` | 2026-10-26 | #1057 | Set as a verifier from libpq 18.4, a password of 12 bytes to 1 MiB logs in with psycopg, and one character short does not. The login takes about 10 s at 1 MiB and 0.1 s or less up to 8192 bytes. psql with libpq 13.23 fails above 1024 bytes with "out of memory". A plaintext password over 1024 bytes is refused in `ALTER ROLE`, SQLSTATE `54000` |
| `07_password_length_probe.py` | `14.24` | 2026-10-26 | #1057 | As on 13.23, but psql with the release's own libpq logs in at every length up to 8192 bytes, and a plaintext password of any length up to 1 MiB is accepted |
| `07_password_length_probe.py` | `15.19` | 2026-10-26 | #1057 | As on 14.24 |
| `07_password_length_probe.py` | `16.15` | 2026-10-26 | #1057 | As on 14.24 |
| `07_password_length_probe.py` | `17.11` | 2026-10-26 | #1057 | As on 14.24 |
| `07_password_length_probe.py` | `18.6` | 2026-10-26 | #1057 | As on 14.24 |
| `08_pgbouncer_probe.py` | `16.15` | 2026-10-27 | #1045 | Behind PgBouncer 1.26.0, in session and transaction pooling. A connection that sends `options=-c statement_timeout=…` is refused, "unsupported startup parameter in options"; with `ignore_startup_parameters = options` the budget is dropped without a message. A plain `SET` reaches other clients under transaction pooling, and stays on the server connection after its client closes. `SET LOCAL` holds inside an explicit transaction and is gone after its COMMIT or rollback, and in autocommit it only warns, `25P01`. PgBouncer refuses a wrong password with "SASL authentication failed" and no SQLSTATE, so `creds check` reports drift as `ERROR`, and `creds apply` and `rotate` cannot change a password. `doctor`, and `check` of roles in sync, work |
| `08_pgbouncer_probe.py` | `16.15` | 2026-10-27 | #1105 | PgBouncer 1.26.0's refusals of a login, with no SQLSTATE. A role the server does not have reads "no such user". A role with no password, and a wrong password under `auth_query` and under `auth_file`, read "SASL authentication failed". The server sends neither message. Where `auth_file` holds another password than the server, PgBouncer passes on the server's "password authentication failed for user", which the driver reads as `28P01`. With the server stopped, only a wrong `auth_file` password reads "SASL authentication failed"; other logins time out, or read "server login has been failing" |
| `09_supabase_roles_probe.sql` | `17.6` | 2026-10-28 | #1111 | On Supabase's database, a `CREATEROLE` tool account that `postgres` created reads `supautils.reserved_roles` and `supautils.reserved_memberships`. supautils refuses `postgres` and the tool account a password change on each role in `reserved_roles`, `42501`, "is a reserved role, only superusers can modify it". The tool account changes the password of a role it created. `postgres` is refused a change to itself and to `supabase_privileged_role`, "Only superusers can alter privileged roles", and grants `pg_read_all_data`. A grant of `authenticator` is refused: its memberships are reserved |
| `10_report_read_probe.py` | `13.23` | 2026-11-10 | #1443 | A `LOGIN CREATEROLE` tool account reads all 13 columns of `pg_roles`, and is refused `pg_authid`. `rolpassword` is the mask for a role with a password and for one without. No catalog column holds a role's last password change, last login or failed logins. A recursive query over `pg_auth_members` gives each role's memberships with the path; per role pair it agrees with `pg_has_role()`, a pair being inherited where one of its paths is. Inheritance is the member's `rolinherit`. `GRANT … WITH INHERIT FALSE` is refused, `42601`. The ACLs of the connected database read through `aclexplode()`; another database's objects are not visible, and `has_table_privilege()` across databases is refused, `0A000`. An object with its default privileges has a NULL ACL, which `aclexplode()` gives no row for; `acldefault()` gives the defaults, with `PUBLIC` as grantee 0, which `pg_roles` has no row for. The ACLs of `pg_attribute`, with a column grant, `pg_language`, `pg_type`, `pg_largeobject_metadata`, the two foreign-data catalogs and `pg_tablespace` read too; there is no `pg_parameter_acl`. `has_table_privilege()` by a name in a schema the tool account has no `USAGE` on is refused, `42501`; by oid it answers. About 520 roles and 1001 tables, after an untimed run: memberships in 0.01 s, every role and table pair in 1.7 to 2.0 s |
| `10_report_read_probe.py` | `14.24` | 2026-11-10 | #1443 | As on 13.23, but every role and table pair takes under 0.5 s, and `pg_read_all_data` holds `SELECT` on every table |
| `10_report_read_probe.py` | `15.19` | 2026-11-10 | #1443 | As on 14.24, and `pg_parameter_acl` exists and reads |
| `10_report_read_probe.py` | `16.15` | 2026-11-10 | #1443 | As on 15.19, but `GRANT … WITH INHERIT FALSE` is accepted, `pg_auth_members` adds `inherit_option` and `set_option`, and inheritance is the grant's `inherit_option`: such a member is a `MEMBER` without `USAGE` |
| `10_report_read_probe.py` | `17.11` | 2026-11-10 | #1443 | As on 16.15 |
| `10_report_read_probe.py` | `18.6` | 2026-11-10 | #1443 | As on 16.15 |

## MySQL releases

A MySQL release is three numbers, such as `8.4.13`. Name it in full, never
"8.4": a release update can change what a release does. The scripts are in
`sql/mysql/`, and `tests/test_measurements.py` checks their headers against the
table below in the same way. A release a header writes after "client" is the
client the probe ran with, and is not compared.

| Release | Product, and where it ran |
|---|---|
| `8.0.46` | The `mysql:8.0` image, `test/compose.yaml` profile `mysql-matrix`, as pulled on 2026-11-01 |
| `8.4.13` | The `mysql:8.4` image, the same profile, as pulled on 2026-11-01. 8.4 is a long-term support release |
| `9.7.4` | The `mysql:9` image, the same profile, as pulled on 2026-11-01 |

Not measured: every other release and every managed service. MariaDB has
[its own part](#mariadb-releases).

## MySQL scripts

<!-- measurements: mysql scripts -->
| Script | Release | Date | Issue | Result |
|---|---|---|---|---|
| `01_password_text_probe.sql` | `8.0.46` | 2026-11-01 | #1202 | Once `ALTER USER … IDENTIFIED BY` or `SET PASSWORD` parses, the general log, the slow log, `performance_schema`'s statement history and its digest sample show the password as `<secret>`, also when the statement fails. The binary log keeps a statement that succeeded, rewritten with the stored `caching_sha2_password` hash. A statement that fails to parse, `1064`, stays in the statement history as sent, password included, and nowhere else. `IDENTIFIED WITH caching_sha2_password AS 0x…` stores the hash as sent |
| `01_password_text_probe.sql` | `8.4.13` | 2026-11-01 | #1202 | As on 8.0.46 |
| `01_password_text_probe.sql` | `9.7.4` | 2026-11-01 | #1202 | As on 8.0.46. The hash is `$A$00A$`, 10,000 rounds, where 8.0.46 and 8.4.13 store `$A$005$`, 5,000 |
| `02_client_hash_probe.py` | `8.0.46` | 2026-11-02 | #1202, #1223 | A `caching_sha2_password` hash the probe computes agrees with the server's. One it computes with its own salt, at 5,000 or 10,000 rounds, is set with `IDENTIFIED WITH … AS` by an account with only `CREATE USER`, stored as sent, and the password logs in. A malformed value is refused, `1827`. A `mysql_native_password` hash set by the same account is accepted, and its password logs in. The account reads `caching_sha2_password_digest_rounds`, 5,000, and `server_uuid`. A password of up to 256 bytes logs in; one of 257 or more is stored and then refused at login, `1045` |
| `02_client_hash_probe.py` | `8.4.13` | 2026-11-02 | #1202, #1223 | As on 8.0.46, but `mysql_native_password` is refused, `1524`: the plugin ships disabled |
| `02_client_hash_probe.py` | `9.7.4` | 2026-11-02 | #1202, #1223 | As on 8.0.46, but `mysql_native_password` is refused, `1524`: 9.7.4 has no such plugin. The server's own hash, and `caching_sha2_password_digest_rounds`, have 10,000 rounds |
| `03_dual_password_probe.py` | `8.0.46` | 2026-11-01 | #1202 | `RETAIN CURRENT PASSWORD` keeps the old password logging in beside the new one, with `IDENTIFIED BY` or with a hash the client computed. A second `RETAIN` replaces the retained password. A change without `RETAIN` keeps it. `DISCARD OLD PASSWORD` ends it, and is accepted with nothing retained. A `RETAIN` that changes the plugin is refused, `3894`. Only an account that can read `mysql.user` sees the retained password, as the key `additional_password` in `User_attributes` |
| `03_dual_password_probe.py` | `8.4.13` | 2026-11-01 | #1202 | As on 8.0.46 |
| `03_dual_password_probe.py` | `9.7.4` | 2026-11-01 | #1202 | As on 8.0.46 |
| `04_lock_expiry_probe.py` | `8.0.46` | 2026-11-03 | #1202, #1223, #1225 | An account with only `CREATE USER` locks, unlocks and expires another. `ACCOUNT LOCK` reads back as `account_locked = 'Y'`, the password then answers `3118`, a wrong one `1045`, and a second lock is accepted silently. `PASSWORD EXPIRE` reads back as `password_expired = 'Y'`. The mysql client refuses an expired session itself unless given `--connect-expired-password`; then `SELECT 1` answers `1820`, and `ALTER USER USER()` sets a new password. After `FAILED_LOGIN_ATTEMPTS 2 PASSWORD_LOCK_TIME 1`, the second wrong password and then the right one answer `3955`, and nothing in `mysql.user` shows the block; other places were not measured. `ACCOUNT UNLOCK` ends it. With `FAILED_LOGIN_ATTEMPTS 1`, one wrong password blocks the account, `3955`, and a new password set by hash still answers `3955` until `ACCOUNT UNLOCK`. A reset as the driver sends it, `ACCOUNT UNLOCK`, the password by hash with `PASSWORD EXPIRE`, then `DISCARD OLD PASSWORD`, ends a block and leaves `password_expired = 'Y'`, and the new password logs in expired. A password retained with `RETAIN CURRENT PASSWORD` survives a change with `PASSWORD EXPIRE`, expired too, until `DISCARD OLD PASSWORD`. A password set by hash without `PASSWORD EXPIRE` ends an expiry, with `RETAIN CURRENT PASSWORD` or without; with it, the retained password logs in too. `PASSWORD EXPIRE` alone expires the retained password with the current one, and it logs in until `DISCARD OLD PASSWORD`, which leaves the expiry set |
| `04_lock_expiry_probe.py` | `8.4.13` | 2026-11-03 | #1202, #1223, #1225 | As on 8.0.46 |
| `04_lock_expiry_probe.py` | `9.7.4` | 2026-11-03 | #1202, #1223, #1225 | As on 8.0.46 |
| `05_identity_grants_probe.py` | `8.0.46` | 2026-11-01 | #1202 | One user name at the hosts `%`, `localhost` and `192.0.2.%` is three accounts with three passwords: under `skip_name_resolve`, a TCP login from 127.0.0.1 uses the `%` one and a socket login the `localhost` one. A user name with no host means `%`. User names are case-sensitive, host names are not. An account with only `CREATE USER` is refused root's password, and `ACCOUNT LOCK` or `UNLOCK` on root and `mysql.sys`, `1227` for `SYSTEM_USER`, and can change and drop an account with every other privilege. It cannot grant, `1044`, nor read `mysql.user`, `1142`, nor run `SHOW CREATE USER`, `1044`. Given `SELECT` on chosen columns of `mysql.user`, it reads lock and expiry and is refused the hash and `User_attributes`, `1143`. With `SYSTEM_USER` it changes root |
| `05_identity_grants_probe.py` | `8.4.13` | 2026-11-01 | #1202 | As on 8.0.46 |
| `05_identity_grants_probe.py` | `9.7.4` | 2026-11-01 | #1202 | As on 8.0.46 |
| `06_rollover_privileges_probe.py` | `8.0.46` | 2026-11-01 | #1220 | No place the server provides says whether a password is retained, other than `User_attributes`. `INFORMATION_SCHEMA.USER_ATTRIBUTES` holds only the `ATTRIBUTE` metadata, the same before and after `RETAIN`. An account with only `CREATE USER` sees its rows for every account without `SYSTEM_USER`. `SHOW CREATE USER` shows only the current hash. `DISCARD OLD PASSWORD` gives `ROW_COUNT()` 0 and no warnings, with a retained password and without one. The tool account's `DISCARD OLD PASSWORD` does end the rollover: the old password is then refused. An account that holds `SYSTEM_USER` has no row the tool sees. A view root creates with `SQL SECURITY DEFINER`, exposing only `JSON_CONTAINS_PATH(User_attributes, 'one', '$.additional_password')`, reads 1 and then 0 for the tool account. `SELECT` on `mysql.user`'s 31 `*_priv` columns and on `mysql.global_grants` reads another account's static and dynamic privileges, and the hash and `User_attributes` are refused, `1143`. `SHOW GRANTS FOR` is refused, `1142`, and `USER_PRIVILEGES` shows only the tool account's own. A privilege granted to a role shows on the role's row. Which roles an account has, and which are its defaults, is in `mysql.role_edges` and `mysql.default_roles`, and a mandatory role only in `mandatory_roles`, which the tool account can read: an account never granted the role takes it while the setting holds it. Proxy grants and grants on the `mysql` schema are in `mysql.proxies_priv`, `mysql.db` and `mysql.tables_priv`. Each table is refused, `1142`, until it is granted |
| `06_rollover_privileges_probe.py` | `8.4.13` | 2026-11-01 | #1220 | As on 8.0.46 |
| `06_rollover_privileges_probe.py` | `9.7.4` | 2026-11-01 | #1220 | As on 8.0.46 |
| `07_own_grants_probe.py` | `8.0.46` | 2026-11-02 | #1221 | An account reads its own grants with no grant of its own. `SHOW GRANTS` prints one line per grant, static privileges separated by `, ` and dynamic ones by `,`, and expands the active roles, and the roles granted to them, but not a role that is granted and not active. `INFORMATION_SCHEMA.APPLICABLE_ROLES` lists the account's own roles, default or not, and a mandatory role with the account as its grantee; `SHOW GRANTS` never names the mandatory role. `SHOW GRANTS FOR CURRENT_USER() USING` expands exactly the roles it names, active or not, mandatory included. `SHOW GRANTS FOR` a role is refused, `1142`, and `USER_PRIVILEGES` lists only direct grants. A role that holds `SYSTEM_USER` cannot be mandatory, `3880`, a mandatory role cannot be granted it, `3897`, and such a role cannot be granted to a mandatory role, `4027`. A role already granted to a mandatory role can be granted `SYSTEM_USER`, and `USING` the mandatory role then lists it. A mandatory role is not active at login |
| `07_own_grants_probe.py` | `8.4.13` | 2026-11-02 | #1221 | As on 8.0.46 |
| `07_own_grants_probe.py` | `9.7.4` | 2026-11-02 | #1221 | As on 8.0.46, but a mandatory role is active at login, with `activate_all_roles_on_login` off |
| `08_password_rules_probe.py` | `8.0.46` | 2026-11-02 | #1223 | Neither of the server's password rules sees a password set by hash. With `PASSWORD HISTORY 2`, or `PASSWORD REUSE INTERVAL 1 DAY`, the same password set again by hash is accepted and adds a row to `mysql.password_history`; set again as text it is refused with `3638`. With the `validate_password` component at policy `MEDIUM`, `acme` by hash is accepted and logs in; as text it is refused with `1819` |
| `08_password_rules_probe.py` | `8.4.13` | 2026-11-02 | #1223 | As on 8.0.46 |
| `08_password_rules_probe.py` | `9.7.4` | 2026-11-02 | #1223 | As on 8.0.46 |
| `09_plain_login_probe.py` | `8.0.46` | 2026-11-09 | #1407 | Over a plain connection, with the login cache emptied, PyMySQL 1.2.3 and 1.2.4 both ask the server for its RSA public key and send the password encrypted with it. 1.2.4 logs in. 1.2.3 then fails itself, `AttributeError`, but the server has accepted the login: the next plain login succeeds and sends nothing. A wrong password is refused, `1045`. Given the key as `server_public_key`, PyMySQL sends no key request. Without `cryptography`, it fails after the key request and before the password |
| `09_plain_login_probe.py` | `8.4.13` | 2026-11-09 | #1407 | As on 8.0.46 |
| `09_plain_login_probe.py` | `9.7.4` | 2026-11-09 | #1407 | As on 8.0.46 |
| `10_report_read_probe.py` | `8.0.46` | 2026-11-11 | #1448 | With the grants of `02-mysql-privileges.md` §2.1, the tool account reads one row of `mysql.user` per user name and host, each with its own `account_locked`, `password_expired`, `password_lifetime` (the days, `0` for never, NULL for the default) and `password_last_changed`. A role reads as locked and expired, whether an account holds it or not. `User_attributes`, which holds `FAILED_LOGIN_ATTEMPTS` and `PASSWORD_LOCK_TIME`, is refused, `1143`, and so is `SHOW CREATE USER`, `1044`; a definer view over the two keys reads them. A partial revoke reads as the global grant alone. No table holds a count of failed logins; a block answers `3955` and changes nothing the tool account reads. A recursive query over `role_edges` gives the role paths, and the fixture's six grants reached through roles are each in `SHOW GRANTS … USING`. Every privilege level reads from its table. `mysql.default_roles` is refused, `1142`, and reads with `SELECT` on it. `SHOW GRANTS FOR` another account is refused, `1142`. `password_last_changed` moves with a change by hash and with `RETAIN CURRENT PASSWORD`, not with `ACCOUNT LOCK` or `PASSWORD EXPIRE`. About 510 accounts and roles and 1000 tables: the role paths in 0.04 s or less, the table grants reached in 0.06 s or less |
| `10_report_read_probe.py` | `8.4.13` | 2026-11-11 | #1448 | As on 8.0.46 |
| `10_report_read_probe.py` | `9.7.4` | 2026-11-11 | #1448 | As on 8.0.46, and `performance_schema.temporary_account_locks` has a row per account with a failed-login limit: whether it is blocked, the limit, the attempts left and the lock time. `ACCOUNT UNLOCK` resets it. The tool account is refused it, `1142`, and reads it with `SELECT` on it |
| `11_role_activation_probe.py` | `8.0.46` | 2026-11-12 | #1482 | At login, with `activate_all_roles_on_login` off, an account's default roles are active, and so is a role one of them holds; a role granted and not a default is not, `1142` on its table. A role in `@@mandatory_roles` has no row in `role_edges` or `default_roles` and is not active, unless it is set as a default role, which the server takes. With `activate_all_roles_on_login` on, every role the account holds is active, mandatory ones included |
| `11_role_activation_probe.py` | `8.4.13` | 2026-11-12 | #1482 | As on 8.0.46 |
| `11_role_activation_probe.py` | `9.7.4` | 2026-11-12 | #1482 | As on 8.0.46, except that **a mandatory role that is not a default role is active at login** |

## MariaDB releases

A MariaDB release is three numbers, such as `10.11.19`. Name it in full, never
"10.11". The scripts are in `sql/mariadb/`, and `tests/test_measurements.py`
checks their headers against the table below in the same way.

| Release | Product, and where it ran |
|---|---|
| `10.11.19` | The `mariadb:10.11` image, `test/compose.yaml` profile `mariadb-matrix`, as pulled on 2026-11-01. 10.11 is a long-term support release |
| `11.4.13` | The `mariadb:11.4` image, the same profile, as pulled on 2026-11-04. 11.4 is a long-term support release |
| `11.8.9` | The `mariadb:11.8` image, the same profile, as pulled on 2026-11-04. 11.8 is a long-term support release |
| `12.3.3` | The `mariadb:12.3` image, the same profile, as pulled on 2026-11-01. 12.3 is the current long-term support release |

Not measured: every other release, and every managed service. Galera is
measured only as `14_galera_identity_probe.py` runs it, on the image's own
library in docker.

## MariaDB scripts

<!-- measurements: mariadb scripts -->
| Script | Release | Date | Issue | Result |
|---|---|---|---|---|
| `01_password_text_probe.py` | `10.11.19` | 2026-11-01 | #1220 | **The password stays in clear.** The general log, the slow log and `performance_schema`'s statement history keep `CREATE USER` and `ALTER USER … IDENTIFIED BY '…'`, `SET PASSWORD … = PASSWORD('…')` and `USING PASSWORD('…')` as sent, also when the statement fails to run or to parse. The binary log keeps `CREATE USER`, `ALTER USER … IDENTIFIED BY` and `USING PASSWORD('…')` as sent, and rewrites only `SET PASSWORD` to the hash. `IDENTIFIED VIA mysql_native_password USING '<hash>'` lands everywhere with the hash and no password. The digest holds none. The statement consumers are off by default |
| `01_password_text_probe.py` | `11.4.13` | 2026-11-04 | #1267 | As on 10.11.19 |
| `01_password_text_probe.py` | `11.8.9` | 2026-11-04 | #1267 | As on 10.11.19 |
| `01_password_text_probe.py` | `12.3.3` | 2026-11-01 | #1220 | As on 10.11.19 |
| `02_client_hash_probe.py` | `10.11.19` | 2026-11-01 | #1220 | A `mysql_native_password` or `ed25519` value the probe computes agrees with the server's. An account with only `CREATE USER` sets each with `IDENTIFIED VIA … USING`, and `mysql_native_password` also with `IDENTIFIED BY PASSWORD`, and the password logs in. A malformed value is refused, `1396`. Only `mysql_native_password` is loaded by default; `ed25519` installs. `parsec` is refused, `1126`: the library is not in the image |
| `02_client_hash_probe.py` | `11.4.13` | 2026-11-04 | #1267 | As on 10.11.19 |
| `02_client_hash_probe.py` | `11.8.9` | 2026-11-04 | #1267 | As on 12.3.3 |
| `02_client_hash_probe.py` | `12.3.3` | 2026-11-01 | #1220 | As on 10.11.19, and `parsec` installs. A `parsec` value the probe computes, with its own salt, agrees, is set by the same account, and the password logs in |
| `03_dual_password_probe.py` | `10.11.19` | 2026-11-01 | #1220 | No `RETAIN CURRENT PASSWORD`, `1064`. `IDENTIFIED VIA <plugin> USING '<old>' OR <plugin> USING '<new>'`, with values the probe computed, set by an account with only `CREATE USER`, lets both passwords log in, for each plugin, and also with the old on `mysql_native_password` and the new on `ed25519`. Sending the new value alone ends it. The second value is only in `mysql.global_priv`'s `auth_or`, beside the hashes, and in `SHOW CREATE USER`; the `mysql.user` view shows the first |
| `03_dual_password_probe.py` | `11.4.13` | 2026-11-04 | #1267 | As on 10.11.19 |
| `03_dual_password_probe.py` | `11.8.9` | 2026-11-04 | #1267 | As on 12.3.3 |
| `03_dual_password_probe.py` | `12.3.3` | 2026-11-01 | #1220 | As on 10.11.19, and also with `parsec` |
| `04_lock_expiry_probe.py` | `10.11.19` | 2026-11-01 | #1220 | An account with only `CREATE USER` locks, unlocks and expires another. A locked account's password answers `4151`, a wrong one `1045`, and a second lock is accepted. The `mysql.user` view has no `account_locked`, `1054`: the lock is only in `mysql.global_priv`, beside the hash, and in `SHOW CREATE USER`. `PASSWORD EXPIRE` reads back as the view's `password_expired = 'Y'`; an expired session connects, and `SELECT 1` answers `1820`. With `max_password_errors = 2`, the right password then answers `4150`, neither `mysql.global_priv` nor `SHOW CREATE USER` changes, and `ACCOUNT UNLOCK` ends it |
| `04_lock_expiry_probe.py` | `11.4.13` | 2026-11-04 | #1267 | As on 10.11.19 |
| `04_lock_expiry_probe.py` | `11.8.9` | 2026-11-04 | #1267 | As on 10.11.19 |
| `04_lock_expiry_probe.py` | `12.3.3` | 2026-11-01 | #1220 | As on 10.11.19 |
| `05_identity_grants_probe.py` | `10.11.19` | 2026-11-01 | #1220 | One user name at `%` and `localhost` is two accounts, chosen as on MySQL. A user name with no host means `%`. User names are case-sensitive; a host is stored in lower case. **An account with only `CREATE USER` changes root's password, unlocks root, and changes and drops an account with `ALL PRIVILEGES`**: MariaDB has no `SYSTEM_USER`, `1064`. It cannot grant, `1044`, read `mysql.user`, `1142`, or run `SHOW CREATE USER` or `SHOW GRANTS`, `1044`. Given `SELECT` on chosen columns of the `mysql.user` view, it reads them and is refused `Password` and `authentication_string`, `1143`. `BINLOG ADMIN`, `CONNECTION ADMIN` and `READ_ONLY ADMIN` set no `*_priv` column; they are in `global_priv`'s access bits, and `SHOW GRANTS` prints them with the hash. Roles are in `mysql.roles_mapping`, refused, `1142`, until granted |
| `05_identity_grants_probe.py` | `11.4.13` | 2026-11-04 | #1267 | As on 10.11.19 |
| `05_identity_grants_probe.py` | `11.8.9` | 2026-11-04 | #1267 | As on 10.11.19 |
| `05_identity_grants_probe.py` | `12.3.3` | 2026-11-01 | #1220 | As on 10.11.19 |
| `06_pymysql_login_probe.py` | `10.11.19` | 2026-11-04 | #1267 | PyMySQL 1.2.3 logs in on `mysql_native_password`, and on `ed25519` with PyNaCl 1.6.2; a wrong password is refused, `1045`. Without PyNaCl, `ed25519` raises `RuntimeError`. TLS is off, and PyMySQL, given a context, refuses each login itself, `2026` |
| `06_pymysql_login_probe.py` | `11.4.13` | 2026-11-04 | #1267 | As on 10.11.19, but TLS is on, and the same logins work over it |
| `06_pymysql_login_probe.py` | `11.8.9` | 2026-11-04 | #1267 | As on 11.4.13. On `parsec`, PyMySQL refuses the login itself, `2059`: it has no client for the plugin |
| `06_pymysql_login_probe.py` | `12.3.3` | 2026-11-04 | #1267 | As on 11.8.9 |
| `07_readable_state_probe.py` | `10.11.19` | 2026-11-04 | #1267 | The `mysql.user` view has no column for when a password changed, for a lifetime or for a lock. With a column grant on `User`, `Host`, `plugin`, `password_expired` and `is_role`, an account with `CREATE USER` reads the same row before and after a password change, a rollover with `OR`, and `ACCOUNT LOCK`. `PASSWORD EXPIRE` sets `password_expired` to `Y`. It cannot read the account's hash in `mysql.global_priv` with that grant, `1142`, with `SELECT (User, Host)` on `mysql.global_priv`, `1143`, or with `SELECT` on `mysql.user`, `1142`; it reads it with `SELECT` on `mysql.global_priv` or on `mysql.*`. There is no `information_schema.USERS` |
| `07_readable_state_probe.py` | `11.4.13` | 2026-11-04 | #1267 | As on 10.11.19 |
| `07_readable_state_probe.py` | `11.8.9` | 2026-11-04 | #1267 | As on 10.11.19, and `information_schema.USERS` has `USER`, `PASSWORD_ERRORS` and `PASSWORD_EXPIRATION_TIME`. It shows the tool account only its own row, with the column grant, `SELECT (User, Host)` on `mysql.global_priv`, `SELECT` on `mysql.user` or `SELECT` on `mysql.global_priv`; `SELECT` on `mysql.*` shows every row. As root reads it, `PASSWORD_ERRORS` counts wrong passwords up to the `max_password_errors` block, `4150`, and goes back to 0 on `ACCOUNT UNLOCK` and on a login. `PASSWORD_EXPIRATION_TIME` is `NULL` without a lifetime. Under `PASSWORD EXPIRE INTERVAL` it moves with each change and with a rollover, and a lock leaves it as it was. It reads `0000-00-00 00:00:00` after `PASSWORD EXPIRE` |
| `07_readable_state_probe.py` | `12.3.3` | 2026-11-04 | #1267 | As on 11.8.9 |
| `08_split_privileges_probe.py` | `10.11.19` | 2026-11-04 | #1267 | Ten privileges have the context `Server`: those split from `SUPER`, `BINLOG MONITOR`, which is `REPLICATION CLIENT` renamed, and `SLAVE MONITOR`. Of these, only `BINLOG MONITOR` sets a column of the `mysql.user` view, `Repl_client_priv`, and an account with `CREATE USER` reads it with a column grant on the view or `SELECT` on `mysql.user`. The other nine, and `SET USER` held by a role, set none. That account sees none of them in `information_schema.USER_PRIVILEGES`, and is refused `SHOW GRANTS`, `1044`, with the column grant, `SELECT (User, Host)` on `mysql.global_priv`, `SELECT` on `mysql.user` or `SELECT` on `mysql.global_priv`. With `SELECT` on `mysql.*` it sees them, and `SHOW GRANTS` prints them with the hash. `USER_PRIVILEGES` has no row for a role, also for root, also for `PROCESS`, which has a column. It shows only `USAGE` for an account that holds the role as its default role |
| `08_split_privileges_probe.py` | `11.4.13` | 2026-11-04 | #1267 | As on 10.11.19 |
| `08_split_privileges_probe.py` | `11.8.9` | 2026-11-04 | #1267 | As on 10.11.19 |
| `08_split_privileges_probe.py` | `12.3.3` | 2026-11-04 | #1267 | As on 10.11.19 |
| `09_password_length_probe.py` | `10.11.19` | 2026-11-04 | #1268 | **No length limit.** An account with only `CREATE USER` sets the `mysql_native_password` or `ed25519` value of a password of 1 byte to 1 MiB, and PyMySQL 1.2.3 logs in with it; the password with its last byte changed is refused, `1045`. The server sees only the value. A password that is not ASCII logs in when PyMySQL is given its UTF-8 bytes. Given a `str`, PyMySQL encodes it as latin-1: `é` is refused, `1045`, and `€` raises `UnicodeEncodeError` (#1285). The server's own values for three passwords, one of 300 bytes, are recorded in the script |
| `09_password_length_probe.py` | `11.4.13` | 2026-11-04 | #1268 | As on 10.11.19 |
| `09_password_length_probe.py` | `11.8.9` | 2026-11-04 | #1268 | As on 10.11.19 |
| `09_password_length_probe.py` | `12.3.3` | 2026-11-04 | #1268 | As on 10.11.19 |
| `10_role_reads_probe.py` | `10.11.19` | 2026-11-04 | #1269 | A role's host is empty. `mysql.roles_mapping` holds a role granted to an account as (`%`, account, role), and one granted to a role as (empty host, role, role). A role is a row of the `mysql.user` view with an empty host, `is_role` `Y`, and its own `*_priv` columns. An account gets a role's privileges after `SET ROLE`, and a nested role's through the role that holds it; `SET ROLE` to the nested role is refused, `1959`. **`PUBLIC` is a role every account holds, always active.** It is a row of the view with an empty host and `is_role` `Y`. It takes a global privilege, a schema, column or routine grant on `mysql`, and a role; a `PROXY` grant to it is refused, `1133`. An account with no grant of its own, refused each read before, then uses each of them with no `SET ROLE`: it reads `mysql.db`, reads a table the role grants, and sees root's session through `PROCESS`. `SET ROLE` to the role is refused, `1959`. A tool account with the tier-1 tool account's grants reads every row of these |
| `10_role_reads_probe.py` | `11.4.13` | 2026-11-04 | #1269 | As on 10.11.19 |
| `10_role_reads_probe.py` | `11.8.9` | 2026-11-04 | #1269 | As on 10.11.19 |
| `10_role_reads_probe.py` | `12.3.3` | 2026-11-04 | #1269 | As on 10.11.19 |
| `11_rollover_expiry_probe.py` | `10.11.19` | 2026-11-05 | #1271 | **`PASSWORD EXPIRE` does not end a rollover.** After an account with only `CREATE USER` sets two values with `OR` and then sends `PASSWORD EXPIRE`, both passwords still log in, expired, and answer `1820`, with the `mariadb` client on `mysql_native_password` and `ed25519`; a wrong one is refused, `1045`. Sending the new value alone ends the rollover and the expiry: `password_expired` reads `N`, and the old password is refused, `1045`. An expired session can `SET PASSWORD` to one of its own; **that replaces the first method, whichever password the session used**, and the second method still logs in. **PyMySQL 1.2.3 can use only the first method of an `ed25519` `OR`.** For the second method, and for a wrong password, it fails itself, "received multiple auth switch requests", an `OperationalError` with no number; with the new value first, the new password logs in. Over PyMySQL on `mysql_native_password`, both methods log in and a wrong password is refused, `1045` |
| `11_rollover_expiry_probe.py` | `11.4.13` | 2026-11-05 | #1271 | As on 10.11.19 |
| `11_rollover_expiry_probe.py` | `11.8.9` | 2026-11-05 | #1271 | As on 10.11.19 |
| `11_rollover_expiry_probe.py` | `12.3.3` | 2026-11-05 | #1271 | As on 10.11.19 |
| `12_password_check_probe.py` | `10.11.19` | 2026-11-05 | #1310 | **`simple_password_check` and `password_reuse_check` make the server refuse the value the driver sends.** With `simple_password_check` or `password_reuse_check` loaded and `strict_password_validation` `ON`, its default, `ALTER USER … IDENTIFIED VIA <plugin> USING '<value>'` from an account with only `CREATE USER` is refused on `mysql_native_password` and `ed25519` with `1396`, "Operation ALTER USER failed", the same answer a weak password gets. With it `OFF` the value is accepted and no plugin checks it, `password_reuse_check` included, while `IDENTIFIED BY` is still checked. That account reads `@@strict_password_validation` and the loaded validation plugins from `information_schema.PLUGINS`. `cracklib_password_check` is not in the image (`1126`) |
| `12_password_check_probe.py` | `11.4.13` | 2026-11-05 | #1310 | As on 10.11.19 |
| `12_password_check_probe.py` | `11.8.9` | 2026-11-05 | #1310 | As on 10.11.19 |
| `12_password_check_probe.py` | `12.3.3` | 2026-11-05 | #1310 | As on 10.11.19 |
| `13_server_identity_probe.py` | `10.11.19` | 2026-11-06 | #1286 | **No value the server sets is both per server and stable.** An account with only `CREATE USER` reads `@@server_id`, `@@hostname`, `@@port`, `@@datadir`, `@@gtid_domain_id` and `@@server_uid`. `@@server_uid` differs between servers and **changes at each restart**. `server_id` (`1`), `port` (`3306`), `datadir` and `gtid_domain_id` (`0`) are the defaults on every server, and `hostname` differs only because each container has its own. `SHOW GLOBAL STATUS LIKE 'server_uid'` returns no row. **`@@server_uid` also differs between a server and its replica**, a container of the same image replicating from the server's binary log, which the tool account reached only through replication. `hostname` differs too, and `server_id` only because replication needs another; `port`, `datadir` and `gtid_domain_id` are the same. A replica started with the server's hostname has its own `@@server_uid` as well, so the value does not follow from hostname, port and datadir alone |
| `13_server_identity_probe.py` | `11.4.13` | 2026-11-06 | #1286 | As on 10.11.19 |
| `13_server_identity_probe.py` | `11.8.9` | 2026-11-06 | #1286 | As on 10.11.19 |
| `13_server_identity_probe.py` | `12.3.3` | 2026-11-06 | #1286 | As on 10.11.19 |
| `14_galera_identity_probe.py` | `10.11.19` | 2026-11-06 | #1346 | **`wsrep_cluster_state_uuid` is shared by one Galera cluster's nodes and differs between two clusters started from empty data.** On a cluster of three nodes and another of one, both started with the image's own Galera library, an account with only `CREATE USER` reads it with `SHOW GLOBAL STATUS`. It is the same after one node restarts and rejoins, and after the whole cluster stops and starts again. `@@server_uid` and `wsrep_gcomm_uuid` differ per node and change at each restart. `@@wsrep_cluster_name` is `my_wsrep_cluster`, the default, on both clusters and on a server without Galera. `mysql.wsrep_cluster` is refused, `1142`. The same account reads `wsrep_local_state_comment`, `Synced`, and `Donor/Desynced` on a node desynced with `wsrep_desync`, which keeps the UUID. Without Galera, `wsrep_on` is `0`, `wsrep_cluster_state_uuid` is empty, and `wsrep_local_state_comment` has no row. A password set on one node logged in on the others at once, 20 times out of 20 on each |
| `14_galera_identity_probe.py` | `11.4.13` | 2026-11-06 | #1346 | As on 10.11.19 |
| `14_galera_identity_probe.py` | `11.8.9` | 2026-11-06 | #1346 | As on 10.11.19 |
| `14_galera_identity_probe.py` | `12.3.3` | 2026-11-06 | #1346 | As on 10.11.19 |
| `15_report_read_probe.py` | `10.11.19` | 2026-11-11 | #1448 | With the grants of `02-mariadb-privileges.md` §2.1, the tool account reads one row of the `mysql.user` view per user name and host, with its plugin and `password_expired`; a role is a row with an empty host and `is_role` `Y`. `account_locked` and `default_role` are refused, `1143`, `mysql.global_priv` `1142` and `SHOW CREATE USER` `1044`: the lock, the lifetime and the last change are not readable. A definer view over `global_priv` reads them: `account_locked` is `1` when locked and absent otherwise, `password_lifetime` the days, `0` for never and `-1` or absent for the default, and `password_last_changed` seconds since 1970, which `PASSWORD EXPIRE` sets to `0`. `FAILED_LOGIN_ATTEMPTS` is a syntax error, `1064`. With `max_password_errors = 2`, an account with no global privilege, one with `CONNECTION ADMIN` and one with `SUPER` are each blocked, `4150`. A recursive query over `roles_mapping` gives the role paths. Every privilege level the view's columns and the five grant tables hold reads, `PUBLIC`'s grant as user `PUBLIC` at an empty host; an account with only `CONNECTION ADMIN` reads as holding nothing. About 510 accounts and roles and 1000 tables: the role paths in 0.16 s or less, the table grants reached in 1.5 to 3.2 s |
| `15_report_read_probe.py` | `11.4.13` | 2026-11-11 | #1448 | As on 10.11.19 |
| `15_report_read_probe.py` | `11.8.9` | 2026-11-11 | #1448 | As on 10.11.19, and root reads each account's count in `information_schema.USERS`, `PASSWORD_ERRORS`, which shows the tool account only its own row |
| `15_report_read_probe.py` | `12.3.3` | 2026-11-11 | #1448 | As on 11.8.9 |
| `16_definer_view_probe.py` | `10.11.19` | 2026-11-12 | #1479 | A view that root creates with `SQL SECURITY DEFINER` over `User`, `Host`, three keys of `global_priv`'s `Priv` and `COALESCE(JSON_LENGTH(Priv, '$.auth_or'), 0) > 1` gives the tool account, with `SELECT` on it: `account_locked` `NULL` when never locked, `1` when locked, `0` after `ACCOUNT UNLOCK`; an open rollover `1` during one, `PASSWORD EXPIRE` included, and `0` after the close. **The close leaves `auth_or` as one empty entry**, so `JSON_EXISTS` stays `1` and is not the flag. `password_lifetime` and `password_last_changed` as `15_report_read_probe.py` found; `PASSWORD EXPIRE` sets the time to `0`, and the lifetime to `-1` only where it was the default: an account's own 90 days or NEVER stays. A change by value sets a new time. Nothing in `Priv` shows a block by `max_password_errors`. No stored value reached the tool account. It is refused `SHOW CREATE VIEW`, `1142`, and `EXPLAIN`, `1345`, and cannot create a view or a procedure over the view, or update it. `information_schema.COLUMNS` and `SHOW COLUMNS` show it an extra `authentication_string` column before any row is read, but only the columns it may read under a column grant. An absent view, an absent schema and a view without the grant all answer `1142`; a dropped definer answers `1045 (28000)` in a logged-in session, and a definer without `SELECT` on `global_priv` `1356`. A locked definer holding only `SELECT` on `global_priv` works. A DBA without `SET USER` or `SUPER` is refused `DEFINER = root@localhost`, `1227`. The view and its readings survive the image's upgrade to 11.4.13, 11.8.9 and 12.3.3 |
| `16_definer_view_probe.py` | `11.4.13` | 2026-11-12 | #1479 | As on 10.11.19 |
| `16_definer_view_probe.py` | `11.8.9` | 2026-11-12 | #1479 | As on 10.11.19, and root reads `PASSWORD_ERRORS` 2 for the blocked account in `information_schema.USERS`, which `Priv` does not hold |
| `16_definer_view_probe.py` | `12.3.3` | 2026-11-12 | #1479 | As on 11.8.9 |
| `account_state_view.sql` | `10.11.19` | 2026-11-12 | #1491 | The install script for the optional view `sopuli.account_state`, run twice as root: both runs pass, and the tool account then reads the lock, the lifetime and the time of the last change for a locked account, one with a 90-day lifetime, one with `NEVER` and one expired. `report accounts` shows the locked one `LOCKED` and checks the lifetimes |
| `account_state_view.sql` | `11.4.13` | 2026-11-12 | #1491 | As on 10.11.19 |
| `account_state_view.sql` | `11.8.9` | 2026-11-12 | #1491 | As on 10.11.19, and the tier-1 tests of the view, `test_mariadb_account_state_live.py` |
| `account_state_view.sql` | `12.3.3` | 2026-11-12 | #1491 | As on 10.11.19. A view with an extra column, one whose definer was dropped and one whose grant was revoked each leave the lock and lifetime *not checked*, the first two with `SOPULI-W073`; running the script again mends each |
