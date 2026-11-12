# UC-5 — Account, privilege and rotation reports across a fleet

Depends on: `../design/00-principles.md`, `../design/01-configuration.md`,
`../design/02-oracle-privileges.md`

This document specifies `sopuli report accounts`, `sopuli report privileges`
and `sopuli report history`. **All three are built, on Oracle**, with the
`reports:` rules (§4, §5, §7). **`report history` is built on PostgreSQL,
MySQL and MariaDB** too (§6), and **`report accounts` on PostgreSQL** (§4),
**MySQL and MariaDB** (§8, #1461, #1462). The privilege report on those three
comes later: until then it is refused before it connects. §9 lists the
decisions.

---

## 1. Summary

**Goal.** A DBA answers these questions by hand today, one database at a time:

1. **Application accounts.** Which accounts exist on which target, and is each
   one on the right profile?
2. **Technical accounts**, such as `DBSNMP` and the APEX and ORDS accounts. Is
   each one on a profile whose settings match the rule written for it? An
   account left on `DEFAULT` can have its password expire, and something
   breaks.
3. **Personal accounts.** The owner asks: do I have an account on every
   server, is it locked, have there been failed logins, and what can I do
   there? The DBA runs the report and answers. Owners do not run it.
4. **An auditor.** When was each password rotated, and which roles and
   privileges does each account hold? The auditor judges from what is shown
   whether the privileges are minimal.

The reports read every declared target and change nothing on any target or
store.

**The one thing a report must never do is say an account is fine when it is
not.** §3 says how the design prevents it.

**Not in scope:** comparing grants with an expected list; a history longer
than the store keeps; finding databases the config does not list; fixing
anything.

---

## 2. What the reports read, and invariant 5

Invariant 5 makes the config the whitelist for **changes**. A report changes
nothing, and its first question is which accounts exist. So the `report`
commands read every account on a declared target, whether the config declares
the account or not. They are the only commands that list the accounts the
config does not declare. Every other command keeps what it reads today: an
undeclared account only where a check on a declared one needs it. The MySQL
and MariaDB checks, for example, name a user at a second host that the config
does not declare, because it could answer the declared account's login
([#1376](../decisions/log.md#1376)).

The targets still come from the config, because that is where their connection
details are. A report never reaches a database the config does not list.

A report holds no secret. It does list the privileges and failed logins of
every account on a target, which tells an attacker where to look, so its output
needs the same care as the tool's other output.

---

## 3. Never fine when it is not

**Each check on an account ends in one of five states:**

| State | Meaning |
|---|---|
| problem | the check ran and the account fails it |
| OK | the check ran and the account passes it |
| not checked | the check could not run: the service account cannot read a view, the release lacks a capability, or the target could not be reached. The reason is shown |
| no rule | the config states nothing the check could compare against. Shown, not a problem, and not OK |
| not applicable | the target's product has no concept of the check, such as a password lifetime on PostgreSQL, or a database profile on any product but Oracle ([#1458](https://github.com/villebase/sopuli-dba/issues/1458)). Shown, and counted apart from *not checked* |

An account counts as OK only when every check that applies to it had a rule,
ran, and passed. A target that could not be reached is reported as a target
that could not be reached, never as a target with no problems.

*Not checked* is a gap somebody could close, with a grant, a release or a
reachable target. *Not applicable* is not: no grant gives PostgreSQL a
password lifetime. So it never sets the exit code, and an account whose rules
state only checks its product lacks, with no `login:`, has no rule there. The
driver registry says which checks each product lacks, from the target's
`type:`, with no connection.

**Exit codes**, from the existing set in `00-principles.md`:

| Code | When |
|---|---|
| 0 | every target was reached, no check found a problem, and every check that had a rule ran |
| 1 | a target could not be reached |
| 3 | every target was reached, and at least one problem was found |
| 4 | every target was reached and no problem was found, but something was not checked |
| 5 | at plan time: no target can run a check the command needs (below) |

*No rule* and information never change the exit code. An undeclared account
that no rule names is shown, and a fleet full of them still exits 0.

An unreachable target outranks a problem, as in `creds check`
(UC-1 §7): a report that reached nine targets of ten must not exit 3 as if the
survey were complete. A problem outranks *not checked*, because the target was
reached and the problem is certain. None of 1, 3 and 4 reads as clean, and the
run document carries every count.

**Capabilities, not versions** (invariant 3). Each check names the capability
it needs. Where a target lacks it, the check is *not checked* on that target,
and the capability is named. A missing capability fails the whole command at
plan time, with exit 5, only where no target could run a check that decides a
state. A check that only gives information, such as the failed-login count,
never refuses: where no target can run it, its value is `unknown` everywhere.
So a fleet of Autonomous Databases, which has no `SYS.USER$`, still gets its
accounts report. That is an exception to
invariant 4, recorded in [#1376](../decisions/log.md#1376): a report that
refused the whole fleet for one old target would answer nothing.

---

## 4. The accounts report

**Built, on Oracle:** `sopuli report accounts [--all]`, with the usual target
selectors. `docs/local-testing.md` §9a has a run. One table per target, in the
config's target order. The head of each table names the target, the release
read from it (`V$INSTANCE.VERSION_FULL`, `scope.db_release`), and how many accounts were read, how many
have a problem, how many were not checked, how many have no rule, and how many
are undeclared. Then:

- **problems first, worst first:** a password that will expire on an account
  whose rule says it must not; a locked account, or an account that can log in
  where its rule says `login: refused`; the wrong profile; another
  setting that differs from the rule; a declared account missing from a target
  it is declared for. A missing account is named as the config spells it, and
  in upper case on Oracle, which keeps an unquoted name that way
  ([#1465](https://github.com/villebase/sopuli-dba/issues/1465));
- **then the accounts not checked, with no rule, and undeclared.** An
  undeclared account is information and never sets exit 3;
- **then a count of the accounts that passed everything.** `--all` lists them.

Every row has the account, its kind (application, technical, personal, or
undeclared), its profile, its status, its failed-login count (`unknown` where
it cannot be read truthfully, never 0), its state, and what is wrong in plain
words. The checks are the lock and whatever the rules state: a setting no rule
names is not compared. A `personal_accounts:` rule over a **role** is resolved
on Oracle and PostgreSQL with the two reads `account list` makes: whether the
role exists, then its members through any chain. So the report and the
mutating verbs admit the same accounts ([#1469](../decisions/log.md#1469)).
A role that does not exist admits nobody, and the report says nothing about
it, as it says nothing about a personal rule's `profile:` that names no
profile. Where the target lacks the `role_lookup` capability, the role is not
resolved and its members show as undeclared. As with a profile predicate, a
role does not bring back an account the report leaves out, such as one
Oracle maintains. On MySQL and MariaDB a role predicate is not resolved yet,
so its members show as undeclared.
Accounts that Oracle maintains (`ORACLE_MAINTAINED = 'Y'`) are left out unless a
rule names them, as a rule for `DBSNMP` does. On 11.2, which has no such
column, the report uses the same list of Oracle's own accounts that the
guardrails use there (`02-oracle-privileges.md` §4, check 5), so one estate
gives the same list on every release.
On a PDB target, common accounts are left out too, unless a rule that covers
the target names them. A common account is visible in every PDB, but its lock,
limits and failed-login count are kept in `CDB$ROOT`
([#1122](../decisions/log.md#1122)), so no check that decides a state can run
on it in a PDB. Where the CDB root is a target, its report checks it, and
lists it as undeclared where no rule names it there
([#1438](../decisions/log.md#1438)). The survey reads which accounts are common
from `DBA_USERS.COMMON`. On a release whose `DBA_USERS` read in a PDB lacks
that column, it takes a name with the `C##` prefix as common, as it does for
the lock. An application container keeps its common accounts listed: where it
keeps their values was not measured, and an application-common user's own
container may be the target itself.

**The lock is the check; the failed-login count is information.** The lock
status can be read on every release, with one exception: in a PDB, a locked
common account reads `OPEN`, because its lock is kept in `CDB$ROOT`
(`02-oracle-privileges.md` §2, [#1122](../decisions/log.md#1122)). So on a PDB
target the lock of a common account is *not checked*, and the report never
calls it OK. The count needs the optional
`SELECT ON SYS.USER$` grant, does not exist on Autonomous Database, and reads 0
for a common account in a PDB, because the count is kept in `CDB$ROOT`
(`02-oracle-privileges.md` §2, [#1122](../decisions/log.md#1122)). Where the
count cannot be read truthfully, the report shows `unknown`, never 0.

**A rule's `login:` says what the lock must be**
([#1447](../decisions/log.md#1447)). Without it, a lock is a problem. With
`login: refused`, for an account nobody should log in as, such as a schema
owner, an open account is the problem. An account made `NO AUTHENTICATION`
passes, because nobody can log in to it with a password, though it reads
`OPEN`. Otherwise only a lock somebody set passes: a status with a `LOCKED`
component, such as `LOCKED`, `EXPIRED & LOCKED` or `LOCKED & IN ROLLOVER`, and
not one with `LOCKED(TIMED)`. A lockout after failed logins means somebody
tried. The survey tells the two apart by the status's components, because
`LOCKED(TIMED)` contains `LOCKED`. Under a profile whose `PASSWORD_LOCK_TIME`
is `UNLIMITED`, Oracle shows a lockout as `LOCKED`, so there the survey also
reads the failed-login count: a count that has reached the profile's limit is
a lockout, and a count it cannot read leaves the lock *not checked*
(`01-configuration.md` §8a). Two rules that set `login:` two ways leave the
lock *not checked*.

**Two checks on settings:**

1. **Account → profile, by name.** An account a rule covers has an expected
   profile. For an application account, the expected profile is UC-1's
   `policies.<name>.account.profile`, so it is not written twice.
2. **The account's settings against the rule.** A rule says what it expects,
   such as "the password never expires". On Oracle the values come from the
   account's profile, so a list of database profiles can state them once for
   every account on that profile. A limit that reads `DEFAULT` is resolved
   through the `DEFAULT` profile before it is compared. On a PDB target two
   cases cannot be read, so they are *not checked* there:
   - **a common account**, whatever its profile: its limits come from its
     profile in the root, not from the profile the PDB names
     ([#1122](../decisions/log.md#1122));
   - **a `DEFAULT` limit on a common profile**, for a local account on it
     too: it follows the root's `DEFAULT` profile, not the PDB's.

   Only the settings a rule lists are compared.

**A profile missing on a target is one finding for the target**, however many
accounts are expected on it. A profile is expected on a target where a rule
that covers the target names it, even where no account there matches the
rule, or where an application's policy names it for an account bound there.
To expect a profile only on some targets, give the rule `targets:`. Where it
is expected and absent, the report says
so once, under the target's head line, and it is a problem: the run exits 3.
Each account expected on it still shows its own wrong-profile problem, because
it is on another profile. A `reports.oracle.profiles` entry alone expects
nothing: it says what a profile's limits must be where the profile is, not that
every target has it. Nor does a personal rule's `profile:`, which only selects
accounts. A rule cannot give `oracle.profile` to an application account it
names by name: the config refuses that, because the account's profile is its
policy's. The
profile names come from the `DBA_PROFILES` rows the survey
already reads, so no statement is added (#1390).

**On PostgreSQL** ([#1459](https://github.com/villebase/sopuli-dba/issues/1459)),
the survey is one read of `pg_roles`, which any role can read. The head line's
release is `server_version`. Every role is listed, and the roles `initdb`
made, the bootstrap superuser and every `pg_*` role, are left out unless a
rule names them, as Oracle's own accounts are. PostgreSQL has no lock, no
profile, no password lifetime, no failed-login limit and no failed-login
count:

- **`NOLOGIN` is judged only against a rule's `login:`.** `NOLOGIN` is also
  how a group role is written, so most such roles are not locked accounts.
  Without `login:`, a `NOLOGIN` role is not a problem. With `login: refused`
  it passes, and a role that can log in is the problem. With `login: allowed`,
  `NOLOGIN` is the problem. A role an application logs in as must be able to
  log in, so there `NOLOGIN` is a problem whatever a pattern's `login:` says.
  The status column shows `NOLOGIN`, `EXPIRED` or `OPEN`, as `creds status`
  does.
- **An expired date does not meet `login: refused`.** `VALID UNTIL` limits
  password logins only, so `trust`, `peer` and `cert` lines in
  `pg_hba.conf`, which the tool cannot read, still let the role in. The lock
  check says the role can log in, and that `NOLOGIN` refuses every login
  ([#1468](../decisions/log.md#1468)).
- **A `VALID UNTIL` in the past is an expired password**, and a problem on
  every declared role that can log in, with or without a rule's key: no
  password logs the role in until somebody moves the date. On a `NOLOGIN` role
  it is not a problem, because the role cannot log in and the date only makes
  it safer. It becomes one if the role gets `LOGIN` (#1468). A rule's
  `postgresql.valid_until` compares the date on every role: `required` wants
  one in the future, and `forbidden` wants none.
  `ALTER ROLE` cannot remove a date, so `VALID UNTIL 'infinity'` is how a DBA
  removes one, and it counts as none. The date is compared on the server,
  `rolvaliduntil < now()`, as `creds status` compares it, and shown in UTC.
- **A rule's `password_lifetime`, `failed_login_limit` and `oracle.profile` are
  *not applicable*.** The failed-login count is `unknown` on every role.

---

## 5. The privilege report

**Built, on Oracle:** `sopuli report privileges [--detail] [--account NAME]
[--public]`, for the same accounts `report accounts` covers, and also for the
common accounts it leaves out on a PDB target: their grants made in the PDB
are read there. Each account has the kind `report accounts` gives it,
including a personal rule's `role:` resolved as §4 says.
`docs/local-testing.md` §9a has a run. It needs the optional grant on the
privilege views (`00_install.sql`, `grant_report_reads=Y`); without it, the
part it could not read is *not checked* and the run exits 4. It judges nothing,
so it never exits 3. Two views, for one account or for every account on a
target.

**The summary** shows:

- system privileges, each with where it comes from: directly, or through
  which role;
- the roles granted, with `ADMIN OPTION`, whether each is a default role, and
  whether it is protected by a password or is a secure application role;
- object privileges as counts by privilege and object type, such as "SELECT on
  42 tables (30 direct, 12 through `ACME_READ_ROLE`)", and EXECUTE and DEBUG on
  procedures, functions, packages and types, each type counted on its own;
- column privileges, such as UPDATE on one column of a table, counted
  separately, because they are kept apart from table grants;
- schema privileges (23ai), such as SELECT ANY TABLE on one schema, each with
  its schema and where it comes from. A release without them shows none.

**The detailed list** has one row for each privilege: the privilege, the
object's owner, name and type, where it comes from, with the whole chain of
roles, and `GRANTABLE` or `ADMIN OPTION`.

Both views count **effective** privileges: an account's own grants, and every
grant it reaches through its roles, however deeply they are nested. A privilege
held two ways is counted once and shows both sources. A role that is not a
default role still counts, and is marked, because the account can enable it.
Grants to `PUBLIC` are left out unless a flag asks for them.

**Other products** have the same four parts, each counted in the product's own
terms ([#1411](../decisions/log.md#1411), question 4): *system* is what
applies to the whole database or cluster, *schemas* what applies to one schema
or database, *objects* what applies to one object, and *columns* what applies
to one column. Where a product has more than one level in a part, such as
MySQL's static and dynamic global privileges, each privilege names its level,
as in "SYSTEM_VARIABLES_ADMIN (global dynamic, direct)". A scope the target
cannot reach, such as another database of a PostgreSQL cluster, is listed as
*not checked* on that target. The report is not built on PostgreSQL, MySQL or
MariaDB yet (#1481, #1482, #1483).

---

## 6. Rotation history

**Built, on Oracle, PostgreSQL, MySQL and MariaDB**
([#1460](https://github.com/villebase/sopuli-dba/issues/1460)):
`sopuli report history [--account NAME]`, with the usual target selectors.
`docs/local-testing.md` §9a has a run. The history comes from what the tool
wrote, and it reads no password. It judges nothing, so it never exits 3: 1
where a target or a store gave no answer, and 4 where a history is not
checked.

Names are matched as the config compares them: by `upper()` on Oracle and
PostgreSQL, and on MySQL and MariaDB the user exactly and the host without
case. A bare `--account` where a target is MySQL or MariaDB is refused before
anything connects, as in every other verb. Where the database refuses to
describe one account, such as a MySQL account on a plugin the tool does not
set passwords for, its date is `unknown` with the refusal as the reason, and
the target's other accounts keep theirs.

- **Which accounts:** each application account the config binds to the
  target, and each personal account with a reset record under the target in
  `reset_records:`. A personal account a rule names and that was never reset
  is listed with nothing recorded. One a profile or role predicate admits is
  listed only where it has a record, because resolving the predicate needs
  the database. `--account` may name an account the tool does not manage:
  only its database date is shown.
- **An unreachable target** still gets its histories, which come from the
  store, without the database's dates, and the run exits 1.

- **An application account (UC-1)** has its history in the store's versions.
  A rotation writes more than one version: UC-1 stages `pending`, then
  promotes it. The promotion stamps that UC-1 §3 writes (`rotated_at`,
  `rotated_by`) change only when `current` changes. Where one secret holds
  several accounts, each stamp is a map keyed by account, so the report
  compares the account's own entry, never the whole field. A change of that
  entry is a change of `current`: a rotation, a rollback, or a
  `creds generate --promote --overwrite-current`. The report lists each one
  as a rotation. The stamps cannot tell the three apart: each writes the same
  `rotated_at` and `rotated_by`.
- **On an OCI store with native staging** the stamps are the secret's
  metadata, not part of a version, and each promotion overwrites them
  (UC-1 §3). So only the current version's promotion time is known. The
  report lists the other versions by the time each one was generated
  (`generated_at`), and says that their promotion times are not kept.
- **A personal account (UC-2)** has one reset record for each target and
  account, and each reset overwrites it (UC-2 §3). Its history is that
  record's versions. A seen reset with no store configured writes no record,
  so only the database's date is shown for it.
- **A store that keeps no versions**, such as HashiCorp KV v1, cannot give a
  history, for either kind of account. Versioning is a capability. Without it,
  the history is *not checked*, with the capability named, and only the
  latest stamps or record and the database's date are shown.

**The history says where it ends.** It starts at the oldest version that can
be read. When a store has pruned, deleted or destroyed older versions, the
report says from which version and date it starts, and how many earlier
versions are gone. It never presents the oldest version kept as the first
rotation. A rotation first seen in that version, or just after a gap, may have
been written by an earlier version, and the report says so.

**After the start, every version up to the store's current one is read.** A
version number the store does not list, a version that is deleted, destroyed
or cannot be read, and a stamp that is malformed or has disappeared are each a
gap a rotation could hide in. The history is then *not checked*, and the
version is named.

The database's own date of the last password change is shown beside the last
rotation, as information, and never compared with it
([#1398](../decisions/log.md#1398)). The two often differ for good reasons:
`apply` changes the target before the promotion, and after
`creds generate --promote` it changes the target after it. Oracle reads it from
`DBA_USERS.PASSWORD_CHANGE_DATE` or `SYS.USER$.PTIME` (§8), and MySQL from
`mysql.user.password_last_changed`, which a change by hash sets, and `ACCOUNT
LOCK` and `PASSWORD EXPIRE` do not. PostgreSQL keeps no such date. MariaDB
keeps it only beside the stored value, in `mysql.global_priv`, which the tool
does not read (#1457 decides whether a view would expose it). On those two the
date is `unknown`, with the reason, and the history is complete without it.

A store version does not carry the run's correlation id, so a version is tied
to its run only through its stamps ([#1374](https://github.com/villebase/sopuli-dba/issues/1374)).
For an account the tool does not manage, only the database's date is shown.

---

## 7. Rules in the config

**Built.** The rules are the `reports:` section (`01-configuration.md` §8a),
and `report accounts` (§4) reads them. Where a rule and a
`reports.oracle.profiles` entry, or two rules, set one setting two ways, that
check is *not checked* on the account, and its other checks still run.

A setting that more than one product has is written in words that are not one
product's: `password_lifetime` and `failed_login_limit`, each `unlimited` or a
largest allowed value. On Oracle the values are read through the account's
profile. A key that only one product has goes in that product's block, on a
rule or on the section ([#1447](../decisions/log.md#1447)). Oracle's block
holds a rule's `profile:`, the check of an account's profile by name, and the
section's `profiles:`, a list of database profiles and their expected
settings. PostgreSQL's block holds a rule's `valid_until:`, `required` or
`forbidden` (§4). On a product that has no concept of a setting, a profile or
a `VALID UNTIL`, the check is *not applicable* (§3). Until a product's driver
can survey its accounts, its targets are *not checked*.

- `reports.accounts` rules name accounts by name or `*` pattern, give them
  their expected login, settings or profile, and select targets as `applications:`
  and `personal_accounts:` do. On MySQL and MariaDB a name is `user@host`,
  compared as UC-1 compares it, and a name without a host reaches no account
  there ([#1461](../decisions/log.md#1461)). Where a rule selects only MySQL
  and MariaDB targets, such a name is warned about when the file loads
  (`SOPULI-W072`). A rule does not write a kind: the report
  derives it from where the file declares the account.
- The list of database profiles is `reports.oracle.profiles`. Inside the
  product block it cannot be read as the top-level `profiles:`, which means run
  profiles (`01-configuration.md`, C10).
- An application account's profile comes from its policy, so a rule may give
  it settings and not a profile.
- **There are no built-in rules.** Nothing is assumed about any kind of
  account. A technical account's password never expiring is a rule the DBA
  writes. A DBA who later rotates technical accounts with the tool may want
  their passwords to expire.
- A rule declares nothing a changing command may act on. A name in a rule is
  not a declaration for invariant 5.

---

## 8. What the service account needs to read

The reports read `DBA_USERS`, `DBA_PROFILES`, `DBA_ROLE_PRIVS` and
`DBA_ROLES`, which `sql/oracle/00_install.sql` already grants, and the views of
system and object privileges, which it does not. The failed-login count and
the older releases' date of the last password change are in `SYS.USER$`
(`LCOUNT`, `PTIME`), behind the optional grant. `DBA_USERS.PASSWORD_CHANGE_DATE`
exists from 19c (`02-oracle-privileges.md` §2).

Measured on 23.26.3.0.0 (`02-oracle-privileges.md` §2, #1377):

- the privilege views need `SELECT` on `DBA_SYS_PRIVS`, `DBA_TAB_PRIVS` and
  `DBA_COL_PRIVS`, for a local service account and a common one alike. A
  column grant is in `DBA_COL_PRIVS` only;
- one recursive query over `DBA_ROLE_PRIVS`, started from the account and
  from `PUBLIC`, reaches the effective privileges with their role paths. It
  returns one row per path, so §5 collapses the rows per privilege and object
  and keeps every path;
- a local profile's `DEFAULT` limit resolves through the PDB's `DEFAULT`
  profile, and a common profile's through the root's (§4);
- in a PDB, a locked common account reads `OPEN` (§4), and its
  `PASSWORD_CHANGE_DATE` is NULL, as its `PTIME` is. So §6 has no database
  date for a common account on a PDB target. Reading the root's would need
  `SET CONTAINER`, which the tool does not use, by design
  (`00-principles.md`).

Each extra grant is `SELECT` only and optional, and the tool probes for it. A
report that cannot read a view says *not checked* for what it needed.

On PostgreSQL the tool account reads what the reports need with the grants it
already has: `report accounts` reads `pg_roles`, and `pg_auth_members` for a
personal rule's `role:` (§4). PostgreSQL keeps no date
of a role's last password change, no last login and no failed logins, so the
failed-login count is `unknown` there, and `report history` shows only the
store's records. Object privileges are per database: a session can read only
the grants of the database it connects to. The privilege report on PostgreSQL
is not built yet; #1411 lists what to decide first, such as what it does about
a cluster's other databases. Measured on 13.23 to 18.6
(`02-postgres-privileges.md` §2.5, #1443).

On MySQL (#1461) and MariaDB (#1462), `report accounts` and `report history`
(§6) are built, and the privilege report is not. An account is a user
name at a host, so one name can be several accounts, each with its own
state, and the report shows one row for each. A role is left out. The
product's own accounts, such as `mysql.sys@localhost` and
`mariadb.sys@localhost`, are left out unless a rule names them, as Oracle's
are. On MySQL the failed-login limit is *not checked*, and the count
is `unknown` without the optional grant of `02-mysql-privileges.md` §2.1. With
the grants the tool account holds today, MySQL reads each
account's lock, expiry, lifetime and date of the last change, and every
privilege level with the role path. It cannot read an account's
`FAILED_LOGIN_ATTEMPTS`, which is kept beside a hash, nor its count of failed
logins, which only 9.7.4 keeps in a table, behind a grant of its own. Nor a
partial revoke, nor the default role without `SELECT` on
`mysql.default_roles`. MariaDB reads only the expiry: the lock, the lifetime
and the date of the last change are kept beside the hash, and a DBA would
have to create a view to expose them (#1457). So on MariaDB the lock and a
rule's `password_lifetime` are *not checked*, and an account a rule names is
*not checked* even without `login:`, because the lock is always compared.
The status reads `OPEN` or `EXPIRED`, from `password_expired` alone, as
`account list` shows it: a locked account, and one whose lifetime has run
out, read `OPEN`. MariaDB has no failed-login limit per account, only the
server's `max_password_errors`, so a rule's `failed_login_limit` is *not
applicable*, and the count is `unknown`: the server shows it only to the
account itself. Measured on 8.0.46 to
9.7.4 and on 10.11.19 to 12.3.3 (`02-mysql-privileges.md` §2.4,
`02-mariadb-privileges.md` §2.4, #1448).

---

## 9. Decisions

Decided by the maintainer on 2026-11-07, with the design (#1375). The two
that change an invariant have a record in the decision log, #1376. The rest
are this document's specification, and the sections above give their reasons.
No question here is open, so none has an ID in the decision register.

| Question | Answer |
|---|---|
| May a command read accounts the config does not declare? | yes, in the `report` commands only; changing still needs a declaration ([#1376](../decisions/log.md#1376)) |
| Do existing commands read undeclared accounts too? | no more than they do today ([#1376](../decisions/log.md#1376)) |
| Does a capability that one target lacks fail the whole report? | no; that check is *not checked* on that target, an exception to invariant 4 ([#1376](../decisions/log.md#1376)) |
| Is a profile rule about its name or its settings? | both: account → profile by name, and the settings against the rule (§4) |
| How is the accounts report laid out? | one table per target, problems first (§4) |
| Which privilege views? | a summary, and a detailed list (§5) |
| Does a privilege through a role count for the account? | yes, and the role is named (§5) |
| How long a history? | every rotation the store still has, and where it ends (§6) |
| Which product first? | Oracle |
| Which product after Oracle? | PostgreSQL, decided on 2026-11-10 (#1411) |
| An account with no rule | the `no rule` state: shown, not a problem, not OK (§3) |
| Built-in rules? | none (§7) |
| Is the rule format specific to Oracle? | no; the settings are stated in words common to all products, and Oracle's profiles are an addition (§7) |

---

## 10. The invariants, read for UC-5

| # | Invariant | Here |
|---|---|---|
| 1 | no secret in `argv` | applies unchanged |
| 2 | redaction at the serialiser | applies. A report reads no password. The history reads stamps, never the password fields |
| 3 | branch on capability, not version | applies: each check names its capability (§3) |
| 4 | unavailable capability fails at plan time | applies where no target could run a check. Elsewhere a missing capability is *not checked* on that target, an exception recorded in [#1376](../decisions/log.md#1376) (§3) |
| 5 | the config is the whitelist for changes | the reports are the only commands that list the accounts the config does not declare (§2) |
| 6 | vault is master | nothing to govern: a report changes nothing |
| 7 | never promote before confirmation | nothing to govern: there is no promotion |
| 8 | `--dry-run` and a plan | nothing to govern: the reports change nothing |
| 9 | idempotency | nothing to govern: the reports change nothing |
| 10 | safety settings only ratchet | applies unchanged. The safety settings govern changes, and a report makes none. A report reads under the same settings as `creds check` |
| 11 | passwords with `"` rejected | nothing to govern: a report sets no password |
| 12 | JSON output is a versioned contract | applies: each report's run document has a schema in `docs/schemas/`, and its samples validate against it |
| 13 | no password in a PL/SQL block | nothing to govern: a report sends no password |
| 14 | no password bound into a predicate | applies: no report compares a password or a verifier, by bind or by literal |
| 15 | the password never reaches PostgreSQL, MySQL or MariaDB | nothing to govern: a report sends no password |
