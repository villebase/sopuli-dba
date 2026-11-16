# sopuli-dba — SQL Server privileges and grants

Depends on: `00-principles.md`, `01-configuration.md`

This document says what the tool login is granted on a SQL Server instance,
what it reads, and what it must not hold. It is the specification for the SQL
Server driver. The driver is not built yet: each part names the issue that
builds it. The decisions are in the decision log
([#1538](../decisions/log.md#1538)), and the probes are in `sql/mssql/`.

The supported releases are 2019 and later (decision 7). Each probe ran on
15.0.4510.2, 16.0.4325.4 and 17.0.5065.9, the 2019, 2022 and 2025 images of
the `mssql-matrix` profile in `test/compose.yaml`. These are SQL Server on
Linux. Where SQL Server on Windows differs, or may differ, this document says
so. Azure SQL Managed Instance has no image and is not tested. Azure SQL
Database is refused (decision 1): it is not an instance with logins in its
own `master` that the tool can manage. The driver reads the edition from
`SERVERPROPERTY('EngineEdition')`, where Azure SQL Database answers 5 by
Microsoft's documentation, and refuses the target at plan time
(open: #1549).

A SQL Server target is one instance, `type: mssql`, with the connection
settings of [`01-configuration.md`](01-configuration.md) §*`mssql:` on a
target*. An account is a SQL
Server login on that instance: a row of `sys.server_principals` of type `S`.
A *contained user*, a user with a password of its own inside a contained
database, is not an account (§4).

---

## 1. The model: `ALTER ANY LOGIN`, and what the server protects

The tool connects as a login that holds the server permission `ALTER ANY
LOGIN`. With it, a login sets another login's password, by value or in clear,
disables and enables it, and sets `MUST_CHANGE`
(`02_client_hash_probe.py`, CH2; `03_lock_expiry_probe.py`, LK1 and LK5).

The server protects some logins from it. The tool login is refused the
password, `15151`, of a login that (`04_grants_probe.py`, GR1):

- is a member of `sysadmin` or `securityadmin`;
- is a member of a server role that holds `CONTROL SERVER`;
- holds `CONTROL SERVER`, `ALTER ANY LOGIN` or `IMPERSONATE ANY LOGIN`.

**The protection has a gap.** The tool login sets the password of a login
that holds `ALTER ANY SERVER ROLE`. That login can add itself to a server role
that holds `CONTROL SERVER`, and then holds `CONTROL SERVER` and `ALTER ANY
LOGIN` (GR4). So `ALTER ANY LOGIN` reaches `CONTROL SERVER` in two steps.
Guardrail 9 (§5) closes the gap, and refuses at plan time what the server
would refuse during the run.

The tool login may also change some settings of `sa`: `ALTER LOGIN [sa] WITH
DEFAULT_DATABASE = [master]` is accepted (GR2). Whether it may set `sa`'s
password, or disable it, is not measured. `sa` is a member of `sysadmin`, so
guardrail 9 refuses it as a managed account.

So:

- the tool login sets the password of every login outside the protected
  set. Keep its credential as you keep an administrator's;
- the tool login holds nothing beyond §2.1. Every other permission makes it
  stronger than it needs to be (§3).

---

## 2. The grants

### 2.1 The tool login

These statements create the tool login and give it its grant. Run them as an
administrator, each as a batch of its own.

```sql
CREATE LOGIN [sopuli_admin] WITH PASSWORD = N'<password>', CHECK_POLICY = ON;
GRANT ALTER ANY LOGIN TO [sopuli_admin];
```

SQL Server has no form that draws the password on the server. Send the
`CREATE LOGIN` statement on its own, never inside `EXEC` or a larger batch,
and check it for typing errors before you send it. The server keeps a password
statement that parses with its password left out or replaced by `******`. It
keeps one that fails to parse, or that runs inside `EXEC`, with the password
in clear (`01_password_text_probe.py`, PT0, PT3 and PT6). §6 has the details.
Store the password where the target's `admin.auth` reads it
([`01-configuration.md`](01-configuration.md) §*`admin:`*).

`ALTER ANY LOGIN` is enough for every read UC-1 and UC-2 make:

- a login's row in `sys.server_principals` and `sys.sql_logins`, with
  `is_disabled`, `is_policy_checked` and `is_expiration_checked`
  (`02_client_hash_probe.py`, CH7; `07_report_reads_probe.py`, RP1);
- `LOGINPROPERTY`'s `IsLocked`, `BadPasswordCount`, `IsMustChange`,
  `IsExpired`, `DaysUntilExpiration` and `PasswordLastSetTime` (LK1 to LK6,
  RP2);
- every login's rows in `sys.server_role_members` and
  `sys.server_permissions` (GR3, RP3), which guardrail 9 reads.

**The tool login reads `NULL` for every login's hash**, from `LOGINPROPERTY`
and from `sys.sql_logins.password_hash` (CH7, RP1). So it can never compare a
hash (§7).

The driver also reads what the target can do: the host's operating system,
whether the server takes a `0x0300` value, and the Availability Group the
instance is in (§4). Which grant these reads need is not measured
(open: #1550).

Give the login no other permission, no server role, and no database user.

### 2.2 What the reports can read

UC-5's reports run as the tool login (open: #1555). With §2.1's grant alone
they read every login, its policy flags, its dates, and its server roles and
permissions (RP1 to RP3). `VIEW ANY DEFINITION` alone reads the same, and so
does `securityadmin`.

Two grants are optional:

```sql
-- report privileges: the users, roles and permissions in each database.
GRANT CONNECT ANY DATABASE TO [sopuli_admin];
GRANT VIEW ANY DEFINITION TO [sopuli_admin];
```

Without them, every database refuses the tool login, `916` (RP4). Each
database is then *not checked*. Both are needed: `CONNECT ANY DATABASE` alone
opens a database and sees no row of another user, and with `VIEW ANY
DEFINITION` it reads them all (RP4). Neither reads a hash.

**No source measured gives a login's last good login.** No catalog view has a
column for it. At the images' login auditing level, 2, the error log records
failed logins only (RP7). `report history` therefore reports the last login
as *not checked* (open: #1555). A server audit with `SUCCESSFUL_LOGIN_GROUP`
is not measured.

The error log is read by `sp_readerrorlog`, which needs `VIEW SERVER STATE`,
`VIEW ANY ERROR LOG` (2022 and later) or `securityadmin`. `xp_readerrorlog` is
refused to all of them, `229` (RP6). The reports do not read the error log.

---

## 3. What must not be granted

| Not granted | Why |
|---|---|
| `sysadmin`, `CONTROL SERVER` | they hold every permission, and the tool login would then change any login's password, `sa`'s included |
| `securityadmin` | it grants most server permissions. Microsoft's documentation says to treat it as equal to `sysadmin` |
| `ALTER ANY SERVER ROLE` | it adds a login to a server role, and so reaches `CONTROL SERVER` (GR4) |
| `IMPERSONATE ANY LOGIN`, or `IMPERSONATE` or `CONTROL` on a login | it lets the tool login act as another login, with that login's permissions |
| `VIEW SERVER STATE` | it shows every session (RP5). Microsoft documents it as the grant that reads `sys.dm_hadr_availability_replica_states` (§4), and #1550 measures what the tool login reads of a group without it. It stays off this list only if that read needs it and no narrower grant serves |
| a database user in `msdb` | no operation of the tool needs one, and `msdb` holds the SQL Server Agent jobs, which may run as an administrator |

---

## 4. Managed accounts

A managed account is one the config declares on a SQL Server target, by its
login name: `acme_app`. The driver reads it by name from
`sys.server_principals` and `sys.sql_logins`, and the server compares the
name. Under the default collation, `SQL_Latin1_General_CP1_CI_AS`, names
compare without case: `CREATE LOGIN` of `ACME_APP` beside `acme_app` is
refused, `15025`, and `ALTER LOGIN [ACME_APP]` reaches `acme_app`
(`05_identity_probe.py`, ID1). The config's own duplicate check compares names
by `upper()` (invariant 5). The account's name in a report is the server's
spelling (open: #1549).

The tool refuses, at plan time, an account that is not a login with a
password (decision 1, open: #1549):

| Account | Why it is refused |
|---|---|
| a Windows login or group, or an Entra login | it has no password on the server |
| a login mapped to a certificate or an asymmetric key | it has no password |
| a contained user | `ALTER ANY LOGIN` cannot open its database, `18456`, and it has no `HASHED` form, `102` (ID3) |
| a login in a contained Availability Group's own `master` | the group copies it to every replica, so two declared replicas would be one account (below) |

**A contained user may have a login's name.** In its database the user's
password logs in, and the login's is refused, `18456` (ID4). The tool changes
the login's password, and the contained user keeps its own. The tool does not
see contained users. Every login the tool makes names `master` as its
database, so a contained user in the login's default database does not answer
it (§7).

**One hostname is the only identity measured.** `@@SERVERNAME`,
`SERVERPROPERTY('MachineName')` and `SERVERPROPERTY('ServerName')` are each
the host's name. `master`'s `service_broker_guid` is all zeros, and `msdb`'s
comes with the image: a second container of one image reads the same value
(ID2, ID5). So two instances on hosts of one name cannot be told apart
(open: #1549).

**Each replica of an Availability Group is a target of its own**
(decision 4). On 15.0.4510.2 and 17.0.5065.9, a login and its password are
each replica's own. A password set on the primary is refused on the
secondary, `18456`, where the old one still logs in, also for a login made on
both with one SID (`08_availability_group_probe.py`, AG1). `ALTER LOGIN`
works on a secondary (AG4). The promotion gate waits for every declared
replica (invariant 7). Each replica names the group, its own role and every
replica, and gives the same `group_id` (AG3). `doctor` warns when a target is
in a group whose other replicas the config does not declare (open: #1550).
**No group formed on 16.0.4325.4 in the matrix, so none of this is measured
on 2022** (unverified: mssql-ag-2022).

The probe read the group as `sa`. Which of these reads the tool login can
make is not measured: Microsoft documents `VIEW SERVER STATE` as the grant
for `sys.dm_hadr_availability_replica_states` (§3). Where the tool login
cannot tell whether a target is in a group, the group is unknown, not absent:
`doctor` says the check could not be made, and does not report the target as
outside a group (open: #1550).

A contained group, 2022 and later, has a `master` of its own, which it copies
to every replica: on 17.0.5065.9, a login made there on the primary, and a
password set there, log in on the secondary (AG5). The tool refuses such a
login. How a session tells that it is in a contained group's `master` is not
measured (open: #1550).

---

## 5. Guardrail 9: a managed login with administrative grants

The tool refuses to manage a login that, itself or through a server role
(decision 5, open: #1553):

- is a member of `sysadmin` or `securityadmin`;
- holds `CONTROL SERVER`, `ALTER ANY LOGIN`, `IMPERSONATE ANY LOGIN` or `ALTER
  ANY SERVER ROLE`;
- holds `CONTROL`, `ALTER`, `IMPERSONATE` or `TAKE OWNERSHIP` on one login;
- holds `CONTROL`, `ALTER` or `TAKE OWNERSHIP` on a server role this list
  refuses, or owns such a role.

No flag waives it. Membership is followed through server roles that are
members of other server roles. Every login is a member of the server role
`public`, which has no rows in `sys.server_role_members`, so the guardrail
reads `public`'s grants as every login's: a grant of `ALTER ANY SERVER ROLE`
to `public` refuses every managed login. The guardrail applies to the
password verbs, and the tool's own login is exempt, as on MySQL
([#1222](../decisions/log.md#1222)).

The server already refuses the password of a member of `sysadmin`,
`securityadmin` or a role that holds `CONTROL SERVER`, and of a login that
holds `CONTROL SERVER`, `ALTER ANY LOGIN` or `IMPERSONATE ANY LOGIN`, `15151`
(GR1). The guardrail refuses them at plan time instead (invariant 4). The
server does not refuse a login that holds `ALTER ANY SERVER ROLE`, which is
the measured gap (§1, GR4). The grants on one object give the same path
through one login or one role; they are from the documentation and not
measured.

| Where | What it shows |
|---|---|
| `sys.server_role_members` | membership of a fixed or user-defined server role, also of a role in a role |
| `sys.server_permissions` | server permissions, and permissions on one login or one server role, with `class` and `major_id` naming the object |
| `sys.server_principals.owning_principal_id` | the owner of a user-defined server role |

The tool login reads the first two (GR3). Its read of the third is not
measured (open: #1553). The guardrail does not read database
paths, such as `db_owner` in `msdb` or a `TRUSTWORTHY` database owned by a
member of `sysadmin`: they are database-level reads, and none was measured.

---

## 6. Where the password text can surface

### 6.1 What the server keeps

The probe sent each password statement as a batch of its own and read it back
from Extended Events, the plan cache, Query Store, a server audit, the default
trace and the error log (`01_password_text_probe.py`):

| Statement | What the server keeps |
|---|---|
| `CREATE LOGIN` or `ALTER LOGIN … WITH PASSWORD = '…'`, which parses (PT0, PT1, PT2, PT4) | no event with its text; the audit and the default trace replace the password with `******` |
| the same with a syntax error after the password (PT3) | the password in clear, in Extended Events and in the audit's `BATCH_COMPLETED_GROUP` |
| the same inside `EXEC (N'…')` (PT6) | the password in clear, in the same places |
| `… WITH PASSWORD = 0x… HASHED` (PT5) | as the first row: the value is left out or replaced |

The plan cache, Query Store and the error log keep none of these statements.

### 6.2 UC-1: the password never reaches the server

**The password never reaches the server** (decision 2, open: #1551). The
driver computes the stored value on the client and sends it with `HASHED`. A
value is a 2-byte version, a 4-byte salt the driver draws, and a 64-byte
digest of the password in UTF-16LE followed by the salt:

- `0x0200`: SHA-512. Every supported release takes it.
- `0x0300`: PBKDF2-HMAC-SHA512, 100,000 rounds. 2022 and 2025 take it, and
  2025 stores it itself. 2019 refuses it, `15021`.

The driver's value agrees with the server's own for the same password and salt
(CH1). The driver sends `0x0300` where the server takes it. How the driver
reads that capability before a change is not measured
(unverified: mssql-hash-version).

`HASHED` is refused on a login with `CHECK_POLICY = ON`, `33020` (CH4). So a
change runs in this order, on every host:

1. Read the login's `is_policy_checked` and `is_expiration_checked`, and
   record them in the vault's `pending` entry. Where the entry already holds
   recorded flags, keep them and do not read again: a run that stopped after
   step 2 left the policy off, and a second read would record that.
2. Send the value, with the policy turned off in the same statement:

   ```sql
   ALTER LOGIN [acme_app] WITH PASSWORD = 0x0200A1B2C3D4… HASHED, CHECK_POLICY = OFF;
   ```

3. Log in as the login with the new password (§7).
4. Set `CHECK_POLICY` and `CHECK_EXPIRATION` back to the values of step 1.

A run that stops between the steps leaves the policy off. The next run reads
the recorded values from the vault and sets them back. The record stays
until step 4 has run, also when a new `pending` replaces the old one
(open: #1551).

**A login whose `MUST_CHANGE` is pending cannot take a value.** While
`IsMustChange` reads 1, the server refuses to turn `CHECK_POLICY` off,
`15128` (`03_lock_expiry_probe.py`, the note beside LK5), so step 2 cannot
run. The driver reads `IsMustChange` and refuses such a login at plan time,
naming it (invariant 4).

**How `creds apply` tells that a target already holds the password depends
on the host** ([#1551](../decisions/log.md#1551), open: #1551). The tool login
reads no hash (§2.1), and the driver reads the host's platform as a
capability (§7):

- **On Linux**, where no login locks, `apply` logs in first, as on Oracle and
  PostgreSQL, and leaves a password that already works alone. It reads
  `IsLocked` before that login, and reports a locked login as `unavailable`
  without logging in.
- **On Windows**, `apply` and `rotate` do not log in before a change, as on
  MySQL and MariaDB. They set a password only from the vault's `pending`, or
  for a rollback, and an account with only `current` is `SKIPPED`. While a
  rotation's promotion is held, each `apply` sets the `pending` again and
  reports `changed: true`, an exception to invariant 9 that ends when the
  rotation completes. The login of step 3 is the only one, and it runs while
  the policy is off. A login that `IsLocked` reports locked is changed all
  the same, which ends the lockout, and the result names the lock it ended,
  with a warning code. Under a domain's policy, whether a failed login while
  the policy is off counts is not measured (unverified: mssql-domain-policy).

A check that turns the policy off to log in safely was rejected: it would
change the login on every run, also when nothing needs a change.

**The server takes a wrong value.** It checks a value's length and version,
not that a password matches it. A `0x0100` value of 26 bytes, or a `0x0300`
value of zeros, is accepted, and the former password stops logging in (CH3).
The login of step 3 is what catches a bug in the driver's value. Step 3 runs
while the policy is off, so a failure there counts toward no lockout: on
SQL Server 2022 on Windows, under a local policy, seven wrong passwords past a
threshold of 5 left `BadPasswordCount` at 0 (`09_windows_policy_probe.py`,
WP5). A domain's policy is not measured.

**Turning the policy off has side effects.** It sets `BadPasswordCount` back
to 0 (LK3). It also turns `CHECK_EXPIRATION` off, sets `HistoryLength` to 0,
and ends a lockout, so a locked login is unlocked by the change that also sets
its new password (WP4, WP6, WP7). Turning the policy on again leaves
`CHECK_EXPIRATION` off, which is why step 4 sets both flags back. The history
stays cleared.

**The server's password policy does not apply.** A value is accepted for a
password the policy would refuse (CH4). The config's policy checks what `creds
generate` draws, unless `--no-policy-check` is given. Nothing checks a value
put in the vault some other way. A password is at most 128 characters: the
server refuses a longer one in clear, `15156` (CH6). The driver refuses a
longer one before anything is sent.

The value still allows an offline guessing attack, so treat it as sensitive.
On 2019 it is a single round of SHA-512. Where the server's error message
quotes the statement, the driver replaces the value in it before the message
is kept (open: #1549).

SQL Server has no rollover window, as PostgreSQL has none. `--strategy
rollover` is refused, exit 5, and `creds finish-rollover` finds no window to
close (open: #1551).

### 6.3 UC-2: the seen reset sends the password once

`MUST_CHANGE` has no `HASHED` form: `HASHED MUST_CHANGE` is refused, `15099`
or `33020` (CH5). `account reset-password` on the seen path therefore sends
the password in clear, once (decision 2, open: #1554):

```sql
ALTER LOGIN [jdoe] WITH PASSWORD = N'<password>' MUST_CHANGE, CHECK_POLICY = ON, CHECK_EXPIRATION = ON;
```

A reset follows H4's rule on locks. `IsLocked` is a lockout after failed
logins, which nobody chose and which ends by itself, as Oracle's
`LOCKED(TIMED)` does (WP3). Where it reads 1, the statement also unlocks the
login: `PASSWORD = N'<password>' MUST_CHANGE UNLOCK, …`. A new password alone
leaves a locked login locked, and its owner would then be refused, `18456`.
`MUST_CHANGE` and `UNLOCK` are accepted together, and the login then answers
`18488` (`09_windows_policy_probe.py`, WP4). A disabled login,
`is_disabled` 1, is the lock somebody chose, as Oracle's plain `LOCKED` is:
`account suspend` sets it. A reset refuses a disabled login at plan time, on
either path ([#1554](../decisions/log.md#1554), open: #1554).

The statement is a batch of its own, never inside `EXEC`. The password is a
Unicode string literal with each `'` doubled, so the statement always
parses. The server then keeps it with the password left out or masked
(§6.1). It is an exception to invariant 15, which decision 2 accepts.

`MUST_CHANGE` needs `CHECK_POLICY` and `CHECK_EXPIRATION` on, and neither can
be turned off while it is pending (LK5). So the seen reset leaves both on. On
the Linux images a new password then expires after 90 days (LK6).

The unseen path sends a value with steps 1, 2 and 4 of §6.2, which also ends
a lockout. It makes no login with the new password: a reset never verifies,
because a login would use the password outside the store (H4). A wrong value
from the driver is caught by its tier-1 tests, not by the reset.

UC-2 has no `pending` entry, so step 1 records the flags in the reset's
metadata record (UC-2 §3.1), before the change. Where that record already
holds flags that a stopped reset recorded and did not restore, the reset
keeps them and does not read again, as UC-1's step 1 does: a second read
would record the policy that the stopped run left off. Where no store is
configured, neither a `reset_records:` store nor a delivery method's
`vault:`, and the login's `CHECK_POLICY` is on, the unseen reset is refused
at plan time: a run that stopped after step 2 would leave the policy, and
`CHECK_EXPIRATION` with it, off for good. Where both flags are off and no
record holds others, there is nothing to restore, and no record is needed
([#1554](../decisions/log.md#1554), open: #1554).

A login whose `MUST_CHANGE` is pending, such as one a seen reset left before
its owner's first logon, cannot take a value (§6.2). The unseen reset refuses
it at plan time and names the seen reset, which keeps the policy on and so
works on such a login. The unseen path does not clear `MUST_CHANGE` with a
plain password first: that would widen invariant 15's exception beyond the
seen reset.

**`account expire-password` is refused at plan time.** `MUST_CHANGE` is taken
only with a new password, so the server cannot expire a password and keep it.
The verb would replace the password the owner knows.

`account suspend` sends `ALTER LOGIN … DISABLE`, where `is_disabled` is 0
(LK1). It carries no password.

### 6.4 Names in a statement

`ALTER LOGIN` takes no bind parameters. The driver names a login between
brackets, with each `]` doubled, as `QUOTENAME` does. A name that holds `]`
needs no refusal: the doubled bracket escapes it, as Oracle's `"` cannot be
escaped (invariant 11). A name in a vault path follows the rules of
[`01-configuration.md`](01-configuration.md) §7 (decision 8).

---

## 7. Checking a password by login

`creds check` verifies a password by logging in as the login (decision 3,
open: #1552). It never reads a hash, which the tool login cannot (§2.1).
`PWDCOMPARE` would take the password in a predicate, which invariant 14
forbids. So the driver reports no `offline_verify`, and `--method hash` or
`both` is refused at plan time.

The client is pyodbc with Microsoft ODBC Driver 18 (decision 6), because it
gives the server's number for each refusal; the other clients measured do not
(`06_client_library_probe.py`, CL2). A password is passed in braces, with each
`}` doubled; a password of `; { } =` and a space logs in (CL3).

Every login names `master` as its database. A contained user that shares the
login's name answers a login to its own database, and refuses the login's
password there, `18456`; at `master` the login answers (ID4). The login's
default database therefore does not decide the result.

What the server answers:

| Login | Answer |
|---|---|
| open | logs in |
| wrong password | `18456` |
| disabled | `18470` (LK1) |
| must change its password | `18488` (LK5) |

Whether a disabled login, or one that must change its password, answers a
wrong password with `18456` or with its own number is not measured. Until it
is, `18470` and `18488` are `unavailable`, not `pass` (open: #1552).

**No login locks on the Linux images.** With `CHECK_POLICY = ON`, 30 wrong
passwords in a row leave `IsLocked` 0, and the right password then logs in.
`BadPasswordCount` reads 1 after every wrong password: it does not count past
1 (LK2). So a login check on Linux cannot lock the login.

**On Windows the check is refused at plan time.** There `CHECK_POLICY`
applies the host's or the domain's account policy, which locks the login at
its threshold, and `LOGINPROPERTY` gives no threshold, so the tool cannot
compute a lockout margin (`09_windows_policy_probe.py`, WP1 and WP2). **A
locked login answers its right password `18456`**, as a wrong one (WP3), so
any login the driver makes reads `IsLocked` first, and reports a locked
login as `unavailable` without logging in. The tool login reads the host's
platform from `sys.dm_os_host_info` (WP0); the driver reads it as a
capability (open: #1550).
