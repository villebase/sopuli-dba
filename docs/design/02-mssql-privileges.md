# sopuli-dba — SQL Server privileges and grants

Depends on: `00-principles.md`, `01-configuration.md`

This document says what the tool login is granted on a SQL Server instance,
what it reads, and what it must not hold. It is the specification for the SQL
Server driver, which serves `doctor`, UC-1's commands, UC-2's commands and
UC-5's reports. The decisions are in the decision log
([#1538](../decisions/log.md#1538)), and the probes are in `sql/mssql/`.

The supported releases are 2019 and later (decision 7). Each probe ran on
15.0.4510.2, 16.0.4325.4 and 17.0.5065.9, the 2019, 2022 and 2025 images of
the `mssql-matrix` profile in `test/compose.yaml`. These are SQL Server on
Linux. Where SQL Server on Windows differs, or may differ, this document says
so. Azure SQL Managed Instance has no image and is not tested. Azure SQL
Database is refused (decision 1): it is not an instance with logins in its
own `master` that the tool can manage. The driver reads the edition from
`SERVERPROPERTY('EngineEdition')`, where Azure SQL Database answers 5 by
Microsoft's documentation, and refuses the target when it first connects,
before any change. It refuses Azure Synapse's pools, 6 and 11, for the same
reason: each is a logical server, not an instance. No image of these exists,
so the refusal is not measured.

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

- is a member of `sysadmin` or `securityadmin`, or, 2022 and later,
  `##MS_LoginManager##` (`13_fixed_roles_probe.py`, FR3);
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
in clear (`01_password_text_probe.py`, PT0, PT3 and PT6). A server audit with
`BATCH_COMPLETED_GROUP` keeps one character of the password's end for each
`'` in it, so choose a password without `'`. §6 has the details.
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

When it connects, the driver reads the release, the engine edition and
whether `master` takes writes, which `ALTER ANY LOGIN` alone reads (measured
on 16.0.4325.4, #1549). It does not read whether its own connection is
encrypted: `sys.dm_exec_connections` needs `VIEW SERVER STATE`, and the read
is refused, `300`. `doctor` reports the encryption that ODBC Driver 18
enforces: TLS under `encrypt: mandatory` and `strict`, which refuse to
connect without it, and *unknown* under `optional`.

The driver also reads what the target can do: the host's operating system,
whether the server takes a `0x0300` value, and the Availability Group the
instance is in (§4). `ALTER ANY LOGIN` alone tells whether the server takes
a `0x0300` value (§6.2), and reads what the driver reads of the Availability
Group (§4, `14_availability_group_reads_probe.py`).

**A tool login that changes passwords also needs this grant**, for guardrail
9 (§5):

```sql
GRANT VIEW ANY DEFINITION TO [sopuli_admin];
```

With it, the guardrail follows every path to an administrative grant. Without
it, the tool cannot see a user-defined server role or its owner, so the
guardrail refuses every managed login on the password verbs, and names the
missing grant ([#1567](../decisions/log.md#1567)). `creds check`,
`creds status`, `doctor` and the reports work without it. It reads no hash.

Give the login no other permission, no server role, and no database user.

### 2.2 What the reports can read

UC-5's reports run as the tool login (#1555). With §2.1's grant alone
they read every login, its policy flags, its dates, and its server roles and
permissions (RP1 to RP3). `VIEW ANY DEFINITION` alone reads the same, and so
does `securityadmin`. With §2.1's grant alone, a user-defined server role is
read by its id only, and one role's membership of another not at all
(`12_guardrail_paths_probe.py`, PA2). With `VIEW ANY DEFINITION` as well,
both are read (PA4).

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

`report privileges` reads, as the tool login connected to `master` (UC-5 §5):

- the server level: `sys.server_principals`, `sys.server_role_members` and
  `sys.server_permissions`, with `sys.endpoints` for an endpoint's name.
  Without `VIEW ANY DEFINITION` the paths through nested server roles are
  not known, so the server level, and with it every database, is *not
  checked*. `HAS_PERMS_BY_NAME` answers 0 for `VIEW ANY SECURITY
  DEFINITION` when it is not held, as well as when it is denied, so a 0
  reads as a denial only where `VIEW ANY DEFINITION` is held (measured on
  16.0.4325.4, #1555);
- each online database, with three-part names:
  `[database].sys.database_principals`, `sys.database_role_members`,
  `sys.schemas` and `sys.database_permissions`, joined to `sys.all_objects`
  and `sys.all_columns` for names, so a grant on a system object is named
  too, and `sys.all_objects` for an object owned apart from its schema. A
  database where no user has a surveyed login's SID is read for its
  principals alone, unless `--public` asks for its grants. With both grants each database is read; without
  `CONNECT ANY DATABASE` each one but `master`, `tempdb` and `msdb`, where
  `guest` lets the tool login in, refuses it, `916`, and is named as not
  checked (measured on 16.0.4325.4).

The server keeps no record of which Windows or Entra logins are in a group,
so a Windows or Entra login on a server with a group login, or where a
database read has a group user, is not checked in the privilege report
(#1555, Q5). A `DENY` of `VIEW DEFINITION` on a database role hides the
role's row and not the membership naming it (measured on 16.0.4325.4), so
a database whose read names a principal it has no row for is not checked.

**No source measured gives a login's last good login.** No catalog view has a
column for it. At the images' login auditing level, 2, the error log records
failed logins only (RP7). UC-5's reports show no last login on any product,
so nothing is lost. A server audit with `SUCCESSFUL_LOGIN_GROUP` is not
measured.

`report history` reads each login's `PasswordLastSetTime` through the same
read as `describe_user` (§4), with §2.1's grant alone.

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
| `VIEW SERVER STATE`, and `VIEW SERVER PERFORMANCE STATE` (2022 and later) | each shows every session (RP5; `14_availability_group_reads_probe.py`, AR2 and AR3). Each also reads the replica's role in an Availability Group, which the driver does not read: what it reads of a group needs neither (§4) |
| a database user in `msdb` | no operation of the tool needs one, and `msdb` holds the SQL Server Agent jobs, which may run as an administrator |

`doctor --check-privileges` reads each row as the tool login, of itself:
`HAS_PERMS_BY_NAME` and `IS_SRVROLEMEMBER`, which answer through any role and
through `sysadmin`, and the grants on one login held by the tool login,
`public` or a role it is a member of. It warns, and refuses nothing. A user in
`msdb` is read by the tool login's SID in `msdb.sys.database_principals`:
`HAS_DBACCESS('msdb')` answers 1 for every login, because `msdb`'s `guest`
is enabled (measured on 16.0.4325.4, #1550). Where `guest` is closed the
read is refused, and the audit says it could not read `msdb`. The tool login
sees the memberships of its own roles, nested ones included, with `ALTER ANY
LOGIN` alone, where it does not see another login's (PA2; measured on
16.0.4325.4, #1550). So the audit needs no more than §2.1's grant. A denial
of `VIEW ANY SECURITY DEFINITION` hides the tool login's own rows, its
`CONNECT SQL` among them, with or without `VIEW ANY DEFINITION`, while
`HAS_PERMS_BY_NAME` cannot tell it from a permission not held. So where the
tool login cannot see its own `CONNECT SQL` row, the audit reports its grants
on one login as not checked (measured on 16.0.4325.4, #1550).

---

## 4. Managed accounts

A managed account is one the config declares on a SQL Server target, by its
login name: `acme_app`. The driver reads it by name from
`sys.server_principals` and `sys.sql_logins`, and the server compares the
name. Under the default collation, `SQL_Latin1_General_CP1_CI_AS`, names
compare without case: `CREATE LOGIN` of `ACME_APP` beside `acme_app` is
refused, `15025`, and `ALTER LOGIN [ACME_APP]` reaches `acme_app`
(`05_identity_probe.py`, ID1). The config's own duplicate check compares names
by `upper()` (invariant 5). The driver sends the name as a parameter, and
from then on uses the server's spelling, as it reports it.

The tool refuses, at plan time, an account that is not a login with a
password (decision 1):

| Account | Why it is refused | How |
|---|---|---|
| a Windows login or group, or an Entra login or group | it has no password on the server | by its `type` in `sys.server_principals` |
| a login mapped to a certificate or an asymmetric key | it has no password | by its `type` |
| a contained user | `ALTER ANY LOGIN` cannot open its database, `18456`, and it has no `HASHED` form, `102` (ID3) | the tool login does not see it, so the name reads as no login |
| a login in a contained Availability Group's own `master` | the group copies it to every replica, so two declared replicas would be one account (below) | by the `physical_database_name` of the session's database (below) |

A login's state comes from one read (`accounts.py`). `is_disabled` is a lock
a person set, `ALTER LOGIN … DISABLE`, and `LOGINPROPERTY`'s `IsLocked` a
lockout after failed logins, which ends by itself
([#1554](../decisions/log.md#1554)). `IsExpired` and `IsMustChange` each
mean the password has stopped working. `DaysUntilExpiration` is in whole
days, so the expiry date is the latest it can be: that many days and one more
from the read. The failed-login count is unknown:
it does not count past 1 on Linux (LK2), and no threshold is readable.

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
(ID2, ID5). So the driver names an instance by `SERVERPROPERTY('ServerName')`,
and two targets that give one name are refused as one instance, as two
targets on one MySQL server are. Two instances on hosts of one name are
refused too, wrongly: nothing measured tells them apart. Such a pair can't
be declared in one config; each needs a config of its own. The driver does
not use `@@SERVERNAME`: by Microsoft's documentation it keeps the name of the
host the instance was installed on, so hosts cloned from one image would
read one name, where `ServerName` follows each host's own name. That
difference is not measured.

**Each replica of an Availability Group is a target of its own**
(decision 4). On 15.0.4510.2 and 17.0.5065.9, a login and its password are
each replica's own. A password set on the primary is refused on the
secondary, `18456`, where the old one still logs in, also for a login made on
both with one SID (`08_availability_group_probe.py`, AG1). `ALTER LOGIN`
works on a secondary (AG4). The promotion gate waits for every declared
replica (invariant 7). Each replica names the group, its own role and every
replica, and gives the same `group_id` (AG3). `doctor` warns, `SOPULI-W076`,
when a target is in a group with a replica that no target of the run reached,
by the replica's name and each reached target's `ServerName`.
**No group formed on 16.0.4325.4 in the matrix, so none of this is measured
on 2022** (unverified: mssql-ag-2022).

**With `ALTER ANY LOGIN` alone the tool login reads the replicas' names,
and not the group's row or its own role** (`14_availability_group_reads_probe.py`,
AR1, on 15.0.4510.2 and 17.0.5065.9). `sys.availability_replicas` gives every
replica of every group the instance is in, itself among them, and the driver
reads their names, for `doctor`'s warning above.
`sys.availability_groups` gives a row only with `VIEW ANY
DEFINITION`, and the replica's role, PRIMARY or SECONDARY, needs `VIEW SERVER
STATE` or `VIEW SERVER PERFORMANCE STATE`, both of which show every session
(AR2, AR3, §3). So the driver reads neither, and needs no grant beyond
§2.1's for these reads.

A contained group, 2022 and later, has a `master` of its own, which it copies
to every replica: on 17.0.5065.9, a login made there on the primary, and a
password set there, log in on the secondary (AG5). **The tool refuses such a
login**: it refuses the whole target, when it reads the session's scope,
before any login is read, as a configuration fault: `config`, exit 9. A
session in the group's `master` reads `DB_NAME()` as `master` (AR5), and its
database's `physical_database_name` in `sys.databases` as the group's master,
such as `acme_cag_master`, where the instance's `master` reads `master` on
2019, 2022 and 2025 (AR6). The physical name describes the database, not the
connection, so it says where the session is however it got there, through a
group's listener or not. The scope reads it in the same round trip as the
release. Any physical name but `master` is refused as a contained group's
master would be, and the message names what was read: only a contained
group's master was measured to give another name. A database that gives no
physical name is refused too, as `database`, exit 1: the tool cannot tell
where the session is, and the config is not at fault.

---

## 5. Guardrail 9: a managed login with administrative grants

The tool refuses to manage a login that, itself or through a server role
(decision 5, [#1567](../decisions/log.md#1567)):

- is a member of `sysadmin`, `securityadmin` or `##MS_LoginManager##`;
- holds `CONTROL SERVER`, `ALTER ANY LOGIN`, `IMPERSONATE ANY LOGIN` or `ALTER
  ANY SERVER ROLE`;
- holds `CONTROL`, `ALTER` or `IMPERSONATE` on one login;
- holds `CONTROL`, `ALTER` or `TAKE OWNERSHIP` on a server role this list
  refuses, or owns such a role.

No flag waives it. Membership is followed through server roles that are
members of other server roles. Every login is a member of the server role
`public`, which has no rows in `sys.server_role_members`, so the guardrail
reads `public`'s grants as every login's: a grant of `ALTER ANY SERVER ROLE`
to `public` refuses every managed login. The guardrail reads grants, with or
without `WITH GRANT OPTION`, and not denials: a login is refused for a grant
whatever it is denied. A read with no row for the login, or none for
`public`, refuses the login.

**The read checks itself.** `HAS_PERMS_BY_NAME` answers 1 for `VIEW ANY
DEFINITION` while a narrower denial still hides rows. `DENY VIEW DEFINITION
ON SERVER ROLE::` hides that role's row, and not its grants or its
membership rows. `DENY VIEW DEFINITION ON LOGIN::` does the same for a
login. `DENY VIEW ANY SECURITY DEFINITION`, 2022 and later, hides every row
the read makes: principals, grants and memberships
(`13_fixed_roles_probe.py`, FR5). So the guardrail refuses
every login where the tool login is denied `VIEW ANY SECURITY DEFINITION`, or
where a membership, a grant, the object of a grant, or an owner in the read
names a principal the read has no row for. A principal made while the read
runs shows the same way, so such a read is made again, once, before every
login is refused.

The guardrail applies to the password verbs, and the tool's own login is
exempt, as on MySQL ([#1222](../decisions/log.md#1222)).

**A fixed server role has no rows in `sys.server_permissions`**, so the
guardrail reads what one gives from its name (`13_fixed_roles_probe.py`, FR1).
Three give a permission of the list: `sysadmin` all four, and
`securityadmin` and `##MS_LoginManager##`, 2022 and later, `ALTER ANY LOGIN`
(FR2). The guardrail refuses a member of any of the three. No other fixed
role gives one.

The server already refuses the password of a member of `sysadmin`,
`securityadmin`, `##MS_LoginManager##` (FR3) or a role that holds `CONTROL
SERVER`, and of a login that
holds `CONTROL SERVER`, `ALTER ANY LOGIN` or `IMPERSONATE ANY LOGIN`, `15151`
(GR1). The guardrail refuses them at plan time instead (invariant 4). The
server does not refuse a login that holds `ALTER ANY SERVER ROLE`, which is
the measured gap (§1, GR4). The grants on one object are gaps too: the
server lets the tool set the password of a login that holds one of them
(`12_guardrail_paths_probe.py`, PA1). `CONTROL` or `IMPERSONATE` on a login
reaches that login's power through `EXECUTE AS`. `CONTROL` or `ALTER` on a
server role that holds `CONTROL SERVER`, and ownership of one, each let the
holder add itself to the role. `TAKE OWNERSHIP` on such a role does not, at
first, `15151`, but it lets the holder take the role with `ALTER
AUTHORIZATION`, and then add itself (PA3). `ALTER` on a login reached no
power: `EXECUTE AS`, the password and `DISABLE` are refused, and renaming
the login is not measured. The list keeps it: a holder can change the
login's settings, as it set `DEFAULT_DATABASE` (PA3), and on the tool login
that is an attack on the tool. `TAKE OWNERSHIP` on a login cannot be
granted: the `GRANT` is a syntax error (PA3), so the list does not name it.
The server refuses the password of a member of a role nested in a role that
holds `CONTROL SERVER`, `15151` (PA1).

| Where | What it shows |
|---|---|
| `sys.server_role_members` | membership of a fixed or user-defined server role, also of a role in a role |
| `sys.server_permissions` | server permissions, and permissions on one login or one server role, with `class` and `major_id` naming the object |
| `sys.server_principals.owning_principal_id` | the owner of a user-defined server role |

With `ALTER ANY LOGIN` alone, the tool login reads less than the table shows
(PA2). It does not see a user-defined server role's row in
`sys.server_principals`, so it reads neither the role's name nor its
`owning_principal_id`. It does not see a membership row whose member is a
role, so it cannot follow one role nested in another. It reads a login's own
grants and memberships, with a role named by its id, and that role's grants
by the id. With `VIEW ANY DEFINITION` as well, it reads every row the table
names (PA4).

**Where the tool login holds `VIEW ANY DEFINITION`, the guardrail follows
every path. Where it does not, the guardrail refuses every managed login at
plan time, and names the missing grant** ([#1567](../decisions/log.md#1567)).
Without the grant, a role the login owns is invisible, so no
login can be shown to own none, and the guardrail never passes a path it
could not read. `doctor --check-privileges` reports whether the tool login
holds the grant, and says what is refused without it.

The guardrail does not read database paths, such as `db_owner` in `msdb` or
a `TRUSTWORTHY` database owned by a member of `sysadmin`: they are
database-level reads, and none was measured.

---

## 6. Where the password text can surface

### 6.1 What the server keeps

The probe sent each password statement as a batch of its own and read it back
from Extended Events, the plan cache, Query Store, a server audit, the default
trace and the error log (`01_password_text_probe.py`):

| Statement | What the server keeps |
|---|---|
| `CREATE LOGIN` or `ALTER LOGIN … WITH PASSWORD = '…'`, which parses (PT0, PT1, PT2, PT4) | no event with its text; the audit and the default trace replace the password with `******`, but see below for `'` |
| the same with a syntax error after the password (PT3) | the password in clear, in Extended Events and in the audit's `BATCH_COMPLETED_GROUP` |
| the same inside `EXEC (N'…')` (PT6) | the password in clear, in the same places |
| `… WITH PASSWORD = 0x… HASHED` (PT5) | no event with its text; the default trace and every audit record but `BATCH_COMPLETED_GROUP` replace the value with `******`. `BATCH_COMPLETED_GROUP` keeps the value's last 70 hex digits |

The plan cache, Query Store and the error log keep none of these statements.

**A server audit with `BATCH_COMPLETED_GROUP` replaces as many characters as
the value or the password has, and keeps the rest of the literal in clear**
(`16_hash_check_audit_probe.py`). The record is `BCM`. A 70-byte value is
written as `0x` and 140 hex digits, so `BCM` keeps the last 70: 35 of the 64
digest bytes. The version and the salt are in the part it replaces. A
password's literal doubles each `'`, so `BCM` keeps one character of the
password's end for each `'` in it. Measured on 15.0.4510.2, 16.0.4325.4 and
17.0.5065.9, for the hash-version check, UC-1's change and UC-2's seen reset:

```text
BCM: ALTER LOGIN [sopuli_probe_hash] WITH PASSWORD = 0x******<change value: last 70 of 140> HASHED, CHECK_POLICY = OFF
BCM: ALTER LOGIN [sopuli_probe_hash] WITH PASSWORD = N'******<pw2: last 4 of 36>' MUST_CHANGE, CHECK_POLICY = ON, CHECK_EXPIRATION = ON
```

The probe prints each part it found as `<…>`, not as the server wrote it.
The other audit records, Extended Events and the default trace replace the
value and the password whole.

**Operator note.** Whoever can read a server audit with
`BATCH_COMPLETED_GROUP` reads half of each value's digest. Without the salt,
a guess must also try each of the 2^32 salts, and the tool's passwords are
random, but treat the audit's files as sensitive. The password itself
never reaches the server on this path. A seen reset sends a password in
clear, and §6.3 says how `'` is kept out of it.

### 6.2 UC-1: the password never reaches the server

**The password never reaches the server** (decision 2, invariant 15). The
driver computes the stored value on the client and sends it with `HASHED`.
A tier-1 test changes a password through the driver and finds it in no
statement or bind the driver sent. A clear-text statement that parses leaves
no text the server keeps (§6.1), so this is the check that would catch one.
The test also records the tool login's statements, batches, calls and errors
in an Extended Events session, sends the driver's statement for a login that
does not exist, and finds the password in none of the session, the plan
cache, the default trace or the error log. It does not read a server audit
or Query Store. A control finds a password that a statement which does not
parse sends in clear (`tests/driver/test_mssql_no_password_live.py`). A
value is a 2-byte version, a 4-byte salt the driver draws, and a 64-byte
digest of the password in UTF-16LE followed by the salt:

- `0x0200`: SHA-512. Every supported release takes it.
- `0x0300`: PBKDF2-HMAC-SHA512, 100,000 rounds. 2022 and 2025 take it, and
  2025 stores it itself. 2019 refuses it, `15021`.

The driver's value agrees with the server's own for the same password and salt
(CH1). The driver sends `0x0300` where the server takes it. A login with
only `ALTER ANY LOGIN` can tell before a change. `CREATE LOGIN` with a
`0x0300` value, inside a transaction that is rolled back, answers `15021`
where the server refuses `0x0300`, and `ok` where it takes it, and leaves no
login. `15021` also answers a value of the wrong length, so the check means
this only for a value the driver computed. Where the name is taken, 2022
and 2025 answer `15025` first. A refused `0x0300` change changes nothing
(`11_hash_version_probe.py`, HV3, HV6 to HV8).

**The driver reads it once per session, before a change, with the
rolled-back `CREATE LOGIN`, under a random name, and caches the answer as a
capability** ([#1564](../decisions/log.md#1564)). `ok` means the
server takes `0x0300`, and `15021` that it does not. Any other answer,
`15025` among them, refuses the change on that target: the tool cannot see
every name a login would clash with, such as a user-defined role's, and an
answer to a clash says nothing about the value on a release that checks the
name first. The check runs in a session that changes a password, before
anything is written for the login, so the refusal comes after any target
the run changed before it, and after `creds rotate` has written `pending`
([#1551](../decisions/log.md#1551)). It also runs in the `--dry-run` of
`creds apply` and `creds rotate`, on each target with something to send,
and the plan names the value, such as `0x0300 password value
(PBKDF2-HMAC-SHA512)`, or the error where the check gave no answer or a
refusal, so the plan shows each refused target as the run would. A target the run only reads, or
one that is `readonly`, never gets it.

The rolled-back statement changes nothing, but an auditor sees it
(`16_hash_check_audit_probe.py`). A server audit's `CR` record keeps a
`CREATE LOGIN` for a login named `sopuli_hash_check_` and 16 hex digits,
with `succeeded` 1, also where 2019 refuses it and where 2022 and 2025 roll
it back. The value is `******`. The default trace keeps an Audit Addlogin
Event with no text, naming the login, and Extended Events keeps the batch
with the `CREATE LOGIN` replaced by dashes. `BATCH_COMPLETED_GROUP` keeps
the value's last 70 hex digits, as for every `HASHED` value (§6.1). The
value is of a random password nobody holds, so it says nothing about a
managed one. No login of that name exists afterwards.

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
the recorded values from the vault and sets them back: a `creds apply` that
finds the login already holds the password sets the recorded flags back, and
its row says so. Flags that were both off need no record, because step 2
leaves nothing to set back. A record the vault cannot write stops the change
on that login before step 2. The record is `policy_flags`
([UC-1 §3](../use-cases/uc-01-app-credential-sync.md#policy_flags-a-sql-server-logins-settings-while-its-policy-is-off)),
and it stays until step 4 has run, also when a new `pending` replaces the old
one.

**A login whose `MUST_CHANGE` is pending cannot take a value.** While
`IsMustChange` reads 1, the server refuses to turn `CHECK_POLICY` off,
`15128` (`03_lock_expiry_probe.py`, the note beside LK5), so step 2 cannot
run. A pending `MUST_CHANGE` is the login's state, as an expiry is, not a
capability the target lacks. The driver reads `IsMustChange` and refuses
such a login, naming it. `creds rotate`'s pre-flight refuses the run for
it, exit 1, before it stages a password. `creds generate` asks too, on the
connection it already opens for the byte limit, from `describe_user`'s
`pending_must_change`: it stages nothing for that credential, and reports
it `SKIPPED`, naming `MUST_CHANGE` and how to clear it
([#1594](../decisions/log.md#1594)). `creds generate --offline` opens no
connection, so it does not ask. A login can get `MUST_CHANGE` after
`generate` has staged, or have nothing staged because `generate` skipped
it, so `creds apply` still meets it: on its own target it leaves the login
alone before anything is written or sent, with or without `--preflight`,
and reports it `EXPIRED` with its own message, which names `MUST_CHANGE`
and how to clear it: the owner logs in and changes the password, or a DBA
sets one by hand without `MUST_CHANGE`. The run goes on to the other
logins.

**How `creds apply` tells that a target already holds the password depends
on the host** ([#1551](../decisions/log.md#1551)). The tool login
reads no hash (§2.1), and the driver reads the host's platform as a
capability (§7):

- **On Linux**, where no login locks, `apply` logs in first, as on Oracle and
  PostgreSQL, and leaves a password that already works alone. It reads
  `IsLocked` before that login, and reports a locked login as `unavailable`
  without logging in.
- **On Windows**, and on a host that names no platform, `apply` and `rotate`
  do not log in before a change, as on MySQL and MariaDB. They set a
  password only from the vault's `pending`, or for a rollback, and an
  account with only `current` is `SKIPPED`. While a rotation's promotion is
  held, each `apply` sets the `pending` again and reports `changed: true`,
  an exception to invariant 9 that ends when the rotation completes. The
  login of step 3 is the only one, and it runs while the policy is off.
  `creds check` makes no login there. A login that `IsLocked` reports
  locked out, `LOCKED(TIMED)`, is changed all the same: step 2's
  `CHECK_POLICY = OFF` unlocks it and sets its count to 0, and step 4
  keeps it unlocked (WP4). The run warns `SOPULI-W077`, naming the lockout
  it ended, because the server then no longer shows that somebody tried
  wrong passwords. `creds apply --dry-run --preflight` and `creds rotate
  --dry-run` warn before it. A login a person
  disabled, `LOCKED`, is not changed, and neither is one with only
  `current`, for which no change is sent: both are reported `LOCKED`.
  Under a domain's policy, whether a failed
  login while the policy is off counts is not measured (unverified:
  mssql-domain-policy).

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
quotes the statement, the driver replaces the value in it with `0x…` before
the message is kept.

SQL Server has no rollover window, as PostgreSQL has none. `--strategy
rollover` is refused, exit 5, and `creds finish-rollover` finds no window to
close.

### 6.3 UC-2: the seen reset sends the password once

`MUST_CHANGE` has no `HASHED` form: `HASHED MUST_CHANGE` is refused, `15099`
or `33020` (CH5). `account reset-password` on the seen path therefore sends
the password in clear, once ([#1538](../decisions/log.md#1538), decision 2):

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
`account suspend` sets it. A reset refuses a disabled login before anything
is sent, on either path ([#1554](../decisions/log.md#1554)).

The statement is a batch of its own, never inside `EXEC`. The password is a
Unicode string literal with each `'` doubled, so the statement always
parses. The server then keeps it with the password left out or masked
(§6.1), but for one thing. A server audit's `BATCH_COMPLETED_GROUP` keeps
one character of the password's end for each `'` in it. So **the tool
refuses, at plan time, a seen reset on SQL Server whose policy's alphabet
holds `'`**, with exit 5, naming the target and the policy
([#1601](../decisions/log.md#1601)). The refusal needs no connection, and the
capability it names is `seen_reset_quote`. A reset draws from the one
policy the rules that admit the account name, and from `defaults.policy`
only where none names one ([#1605](../decisions/log.md#1605)). Only the
server says whether a `role:` rule admits the login. So where the rule that
names the account has a `policy:`, the check reads that one. Otherwise it
reads every `role:` rule's policy on that target, and `defaults.policy`
where an admitting rule may name none. A `profile:` rule admits nobody on
SQL Server, so it is never read. The run checks the one policy drawn again,
before it draws a password.
The default charset, `alnum_safe`, holds no `'`, and `printable_ascii`
does. The seen
reset is an exception to invariant 15, which decision 2 accepts, and the
server masks the password only because of this refusal. A
tier-1 test sends it through the driver, with a `'`, ODBC's escape
characters `{` `}` `?` and a character outside the Basic Multilingual Plane
in the password. It finds the password in no Extended Events record, the
plan cache, the default trace or the error log, the login then answers
`18488`, and both flags read on. The seen path's plan-time gate is
`expire_on_reset`, which a SQL Server session reports, and not
`expire_password`, which it does not (#1554, Q8).

`MUST_CHANGE` needs `CHECK_POLICY` and `CHECK_EXPIRATION` on, and neither can
be turned off while it is pending (LK5). So the seen reset leaves both on,
also on a login where they were off, which the tier-1 test checks. With
`CHECK_POLICY` on, the server checks the password against the host's policy,
which the tool cannot read: a password the host refuses fails that account
during the run, as a `policy` error. The Linux image answers `33062` for one
too short and `33064` for one not complex enough (measured on 16.0.4325.4);
a Windows host's numbers are not measured. On
the Linux images a new password then expires after 90 days (LK6).

The unseen path sends a value with steps 1, 2 and 4 of §6.2, which also ends
a lockout. It makes no login with the new password: a reset never verifies,
because a login would use the password outside the store (H4). A wrong value
from the driver is caught by its tier-1 tests, not by the reset.

UC-2 has no `pending` entry, so step 1 records the flags in the reset's
metadata record (UC-2 §3.1), before the change. Where that record already
holds flags that a stopped reset recorded and did not restore, the reset
keeps them and does not read again, as UC-1's step 1 does: a second read
would record the policy that the stopped run left off. The flags go under
the record's `policy_flags` key, and the reset's own record drops them once
they are back; where step 4 fails, the record keeps them and the row is
`ERROR`. Where no `reset_records:` store is configured and the login's
`CHECK_POLICY` is on, the unseen reset is refused, whatever the delivery: a
run that stopped after step 2 would leave the policy, and `CHECK_EXPIRATION`
with it, off for good (#1554, Q7). The refusal comes at plan time, exit 9,
only on the unseen path with no `reset_records:` block, and only on a target
where a rule declares the login: one more connection per SQL Server target,
which reads the login and asks the value's version (§6.2's step 1). Where both flags are off and no record
holds others, there is nothing to restore, and no record is needed
([#1554](../decisions/log.md#1554)).

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
(LK1), and reads `is_disabled` back. It carries no password. By
Microsoft's documentation, and not measured here, `DISABLE` refuses new
logins and does not end the login's open sessions; an offboarding that must
end them does so by hand, with `KILL`. A login that
is already disabled is reported unchanged; one that `IsLocked` reports
locked out is not a suspension, and is disabled. A `profile:` predicate is
refused, because SQL Server has no profiles.

**A `role:` predicate names a server role** ([#1554](../decisions/log.md#1554),
Q6). Its members are the logins that hold it directly or through any chain
of nested server roles, read from the catalog guardrail 9 reads (§5), with
the role's name compared by `upper()` and shown as the server spells it. A
verb compares the rule with every server role a login holds through
nesting. Without `VIEW ANY DEFINITION`, or with `VIEW ANY SECURITY
DEFINITION` denied, the tool login cannot see a user-defined server role or
one role's membership of another (PA2), so the read is not complete and the
rule is refused as `role_lookup` missing, naming the grant; `report
accounts` then warns with `SOPULI-W075`. A database role is not what a
`role:` names: a login holds one only through a user in one database.

### 6.4 Names in a statement

`ALTER LOGIN` takes no bind parameters. The driver names a login between
brackets, with each `]` doubled, as `QUOTENAME` does. A name that holds `]`
needs no refusal: the doubled bracket escapes it, as Oracle's `"` cannot be
escaped (invariant 11). A name in a vault path follows the rules of
[`01-configuration.md`](01-configuration.md) §7 (decision 8).

---

## 7. Checking a password by login

`creds check` verifies a password by logging in as the login (decision 3,
#1552). It never reads a hash, which the tool login cannot (§2.1).
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

**A disabled login, and one that must change its password, answers a wrong
password `18456`**, as an open one does, and its own number only to the right
password (`15_login_answers_probe.py`, LA2 to LA4, on 15.0.4510.2,
16.0.4325.4 and 17.0.5065.9). `creds check` reads the login's state first
and reports a disabled login `LOCKED` and a must-change one `EXPIRED`,
with no login. Where the state changes between that read and the login,
`18470` or `18488` makes the row `UNVERIFIABLE`, never `IN_SYNC`, and its
detail says the password is right. The login of `creds apply` and `creds
rotate` after a change reads them as `unavailable` too, never as a pass: a
login that cannot use the password has not confirmed it.

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
platform from `sys.dm_os_host_info` (WP0); the driver reads it once per
session, and caches it as a capability. `creds check` asks each SQL Server
target before any account is checked, and refuses a host that is not Linux
at plan time, exit 5, naming `lockout_threshold`. A host that names no
platform is treated as Windows (#1552).

## 8. UC-3 adds no grant to the tool login

UC-3 (`../use-cases/uc-03-run-statement.md`) runs a statement the operator
writes, as the run-as login the config names in `run_as:`, never as the tool
login.

- UC-3 adds no grant to the tool login, and §2.1 does not change.
- Before any statement runs, the tool reads `ORIGINAL_LOGIN()` and
  `SUSER_SNAME()` and refuses the run when either is the tool login. One login
  is never granted to another, so there is no membership to read. A login can
  act as another only by `EXECUTE AS LOGIN`, which the statement check refuses
  as a first word and the statement list below as a second statement. Every
  `sysadmin` holds `IMPERSONATE` on every login, so reading it would refuse the
  usual DBA login ([#1728](../decisions/log.md#1728), Q4).
- **The run-as login needs `SHOWPLAN` in each database its statement names.**
  T-SQL needs no `;` between two statements, so before anything runs the tool
  asks the server to list the statements with `SET SHOWPLAN_ALL ON`, which
  compiles the batch and runs none of it ([#1728](../decisions/log.md#1728),
  Q1). `SHOWPLAN` is needed in each database the statement names, and not in
  `master`, where the session runs; without it the server refuses with `262`,
  which names the database. A statement that names no database object, such as
  `SELECT 1`, needs none. A `sysadmin` has it. Grant it to the login's user in
  each database it reads or writes: `GRANT SHOWPLAN TO [dba_alpha]`.
- Beyond that, the run-as login needs what its statements need: a user in each
  database they name, and the permissions on the objects. Any login reads
  `ORIGINAL_LOGIN()`, `SUSER_SNAME()`, `SERVERPROPERTY('ServerName')` and
  `DB_NAME()` (`17_statement_run_probe.py`, S1 and S9, #1729).
