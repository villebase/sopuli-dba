# Measurements

This file says what has been run on which Oracle or PostgreSQL release, when,
and what it showed. It is the one place for that. Other documents link here
instead of listing releases themselves. The PostgreSQL results are in
[their own part](#postgresql-releases), after the Oracle ones.

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
