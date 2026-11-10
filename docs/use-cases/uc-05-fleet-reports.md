# UC-5 — Account, privilege and rotation reports across a fleet

Depends on: `../design/00-principles.md`, `../design/01-configuration.md`,
`../design/02-oracle-privileges.md`

This document specifies `sopuli report accounts`, `sopuli report privileges`
and `sopuli report history`. **All three are built, on Oracle**, with the
`reports:` rules (§4, §5, §7). PostgreSQL, MySQL and MariaDB come later: on
them the reports are refused before they connect. §9 lists the decisions.

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

**Each check on an account ends in one of four states:**

| State | Meaning |
|---|---|
| problem | the check ran and the account fails it |
| OK | the check ran and the account passes it |
| not checked | the check could not run: the service account cannot read a view, the release lacks a capability, or the target could not be reached. The reason is shown |
| no rule | the config states nothing the check could compare against. Shown, not a problem, and not OK |

An account counts as OK only when every check that applies to it had a rule,
ran, and passed. A target that could not be reached is reported as a target
that could not be reached, never as a target with no problems.

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
  whose rule says it must not; a locked account; the wrong profile; another
  setting that differs from the rule; a declared account missing from a target
  it is declared for;
- **then the accounts not checked, with no rule, and undeclared.** An
  undeclared account is information and never sets exit 3;
- **then a count of the accounts that passed everything.** `--all` lists them.

Every row has the account, its kind (application, technical, personal, or
undeclared), its profile, its status, its failed-login count (`unknown` where
it cannot be read truthfully, never 0), its state, and what is wrong in plain
words. The checks are the lock and whatever the rules state: a setting no rule
names is not compared. A `personal_accounts:` rule over a **role** is not
resolved here, because the survey reads no roles, so such an account shows as
undeclared.
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
it is on another profile. A `db_profiles` entry alone expects nothing: it says
what a profile's limits must be where the profile is, not that every target
has it. Nor does a personal rule's `profile:`, which only selects accounts.
A rule cannot give `profile:` to an application account it names by name: the
config refuses that, because the account's profile is its policy's. The
profile names come from the `DBA_PROFILES` rows the survey
already reads, so no statement is added (#1390).

---

## 5. The privilege report

**Built, on Oracle:** `sopuli report privileges [--detail] [--account NAME]
[--public]`, for the same accounts `report accounts` covers, and also for the
common accounts it leaves out on a PDB target: their grants made in the PDB
are read there.
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

---

## 6. Rotation history

**Built, on Oracle:** `sopuli report history [--account NAME]`, with the
usual target selectors. `docs/local-testing.md` §9a has a run. The history
comes from what the tool wrote, and it reads no password. It judges nothing,
so it never exits 3: 1 where a target or a store gave no answer, and 4 where a
history is not checked.

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
`creds generate --promote` it changes the target after it.

A store version does not carry the run's correlation id, so a version is tied
to its run only through its stamps ([#1374](https://github.com/villebase/sopuli-dba/issues/1374)).
For an account the tool does not manage, only the database's date is shown.

---

## 7. Rules in the config

**Built.** The rules are the `reports:` section (`01-configuration.md` §8a),
and `report accounts` (§4) reads them. Where a rule and a `db_profiles` entry,
or two rules, set one setting two ways, that check is *not checked* on the
account, and its other checks still run.

The settings are written in words that are not specific to one database
product: `password_lifetime` and `failed_login_limit`, each `unlimited` or a
largest allowed value. On Oracle the values are read through the account's
profile. `reports.db_profiles`, a list of database profiles and their expected
settings, and a rule's `profile:`, the check of an account's profile by name,
are an addition for Oracle on top of that. On another product, a rule reports
*not checked* until that product's driver reads the settings. The format does
not change when it does.

- `reports.accounts` rules name accounts by name or `*` pattern, give them
  their expected settings or profile, and select targets as `applications:`
  and `personal_accounts:` do. A rule does not write a kind: the report
  derives it from where the file declares the account.
- The list of database profiles is `db_profiles`, not `profiles:`, because
  that key already means run profiles (`01-configuration.md`, C10).
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
