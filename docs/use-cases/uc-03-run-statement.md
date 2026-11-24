# UC-3 — Run one statement across many targets

Depends on: `../design/00-principles.md`, `../design/01-configuration.md`,
`../design/02-oracle-privileges.md`

This document specifies a command that runs one statement against a selected
set of declared targets and shows what each target returned. **The statement
check, the row guard, the plan fingerprint and the value conversion are built
(#1659), and so is the `run_as:` configuration with its plan-time refusal of the
service account (#1660), and so is the Oracle runner (#1661), and so is `sql
run` for reads (#1662) and for writes (#1663). UC-3 on Oracle is built.** The
command name, `sopuli sql run`, is a working name. The parts were built in this
order, each by its own issue:

| Part | Issue |
|---|---|
| The pure layer: the statement check, the plan fingerprint and the row guards | #1659, built |
| The `run_as:` configuration | #1660, built. The session check of §2 is part of the runner |
| The Oracle runner | #1661, built. `OracleSession.run_statement`, with `session_user()` for the check of §2. `sql.run` is not in the shared command set, so every other product is refused |
| `sql run` for reads | #1662, built |
| `--write` | #1663, built |

The first release of UC-3 covers Oracle only. A target of another product is
refused at plan time by `require_command`, with `SOPULI-20006`, never by a
version check (invariant 4). The umbrella issue is #1657.

---

## 1. Summary

**Goal.** A DBA often checks or changes one small thing on many databases: an
application setting in a table, a database parameter, a flag. Today the DBA logs
in to each target by hand, with a personal account or the application's owner
account, and runs the same statement each time.

UC-3 runs one statement against the targets a selector picks. It shows one
result for each target, which a person or a script can read. The statements are
small:

- mostly `SELECT` statements that return a few rows and columns;
- sometimes a write that turns a setting on or off: `UPDATE`, `INSERT`, `MERGE`
  or `DELETE`.

**Not in scope:**

- PostgreSQL, MySQL, MariaDB and SQL Server. The driver interface leaves room
  for them, and they come later.
- Statements declared by name in the config. They can be added later without
  changing this design.
- DDL, PL/SQL blocks, `ALTER SYSTEM`, and anything else that is not one query
  or one DML statement.
- Large results, paging and export. Rows are capped (§7).
- Closing every possible gap. This is a DBA tool, and the rights of the account
  it connects as are the real limit. The guards below catch the common
  slips: the wrong targets, and more rows than intended.

**It fails even if it works when:**

- it connects as UC-1's service account, or adds any grant to it. That breaks
  ADR-001;
- a write changes data on a target the operator did not see in the dry run;
- a write changes more rows than the operator expected, and the tool commits it.

**Why free-form statements.** The statement comes from a file or from stdin, and
is different every time, as a DBA's work is. Two other shapes were rejected.
Statements declared by name in the config would be reviewed before use, but
every new question would need a config change first. That is friction without a
matching gain, for the reason ADR-001 rejected the definer-rights package.
Free-form reads with writes only by name is the strongest guard on writes, at
twice the surface, and the plan fingerprint (§4) already covers the risk of the
wrong targets. Wrapping `sqlplus` was dropped: it may not be installed, and it
loses the run document, the selectors and the safety settings. The maintainer
decided this in #1657.

---

## 2. Who the tool connects as

**Never UC-1's service account.** UC-3 does not use the `admin:` credential. A
statement run as the service account would need whatever privilege that
statement needs, which breaks ADR-001. UC-3 adds no grant to any account
(`../design/02-oracle-privileges.md` §9).

**The run-as account has no default.** With no `run_as:` and no `--as`, the tool
refuses the run with exit 9, and the message names both ways to fix it. The
usual choice is the DBA's personal account, such as `dba_alpha`, set in a
`run_as:` block under `defaults:`. A DBA who wants the application's owner
account, or another account, names it in the config and puts its password in the
keyring.

**`run_as:`** is a block with the grammar of `admin:`
(`../design/01-configuration.md` §3a). It goes on a target or under `defaults:`.
It does not go on a group: a group carries only `match` and `safety`, as it does
for `admin:`. The allowed `auth:` methods are `keyring`, `prompt`, `external` and
`env`. `env` carries the same warning as it does for `admin:`: `SOPULI-W022`,
naming the run-as credential. `vault` is not
allowed, so that the tool never logs in with a password that a store holds for
another purpose. `--as USER` with `auth: prompt` covers a run that the config
does not configure. It asks once for the run, whatever the number of targets.
It needs a terminal on stdin, so the statement then comes from `--file`; a run
with `--as` and no terminal is refused with exit 2 before anything connects.

The password is read from the sources the tool already has for its own
credentials. It is never read from stdin, because `admin:` does not offer stdin
either, and so stdin stays free for the statement. It is never read from a store
that UC-1 manages, and UC-1 does not manage this account.

**A run that cannot get the password is refused before it connects.** A
`run_as:` with `auth: prompt` on a run with no terminal is refused with exit 8,
and a `run_as:` in the OS keyring on an install without the `keyring` extra
with exit 9, as the mutating commands refuse an `admin:` of either kind.

**A typed password that a target refuses is not tried again.** The account is
a person's, and its profile may lock it after a few failed logins. So when a
target refuses a password typed for `--as` or for `auth: prompt`, the tool
forgets it and connects no later target where a password would be typed for
the same user, compared by `upper()`. Those targets are reported
`NOT_ATTEMPTED`, with a message naming the user and the target that refused
the password. A typed password for another user was never refused, so it is
asked for and tried as usual. A password from the keyring, a variable or a
wallet is each target's own, and a refusal on one target does not stop the
others.

**Refusing the service account.** The tool checks the run-as account twice.

1. At plan time, from the config. A target whose run-as user name equals its
   `admin:` user name is refused. The comparison uses `upper()`, as invariant 5
   does. A wallet holds one credential for each alias, so a target whose
   `run_as` and `admin` are both `external` on the same `dsn` is refused too.
2. Before any statement runs, from the database. The tool connects to every
   selected target as the run-as account, reads
   `SYS_CONTEXT('USERENV','SESSION_USER')`, and compares it with the service
   account's user name from the config. One match refuses the run on every
   target, before any statement runs. The error is `SOPULI-20010`.

   There is a gap here, and it is accepted. When `admin:` is `external`, the
   config holds no service-account name, so the session check has nothing to
   compare and does not run. The tool never opens a connection with `admin:` to
   learn the name, because UC-3 never uses that credential (ADR-001). The
   plan-time check still refuses `run_as` and `admin` both `external` on the
   same `dsn`. A `run_as` that names a user, on a target whose `admin:` is
   `external`, is not checked against the service account.

---

## 3. Reads and writes

A run is read-only unless the operator passes `--write`.

- **A read** runs in `SET TRANSACTION READ ONLY` and always ends with a
  rollback. The first keyword must be `SELECT` or `WITH`.
- **A write** needs `--write`. The first keyword must be `UPDATE`, `INSERT`,
  `MERGE` or `DELETE`. A write keyword without `--write`, and a read keyword
  with `--write`, are refused with exit 8 and `SOPULI-20009`. Exit 2 is only for
  argv that did not resolve, and it never comes with a run document. A
  `--write` without a row guard, and a `--write` without a selector, are pure
  argv errors and exit 2.
- **Everything else is refused at plan time:** DDL, `ALTER SYSTEM`, `BEGIN`,
  `DECLARE`, `CALL`, `EXEC`, `COMMIT`, `ROLLBACK`, `LOCK`, and more than one
  statement. A refused statement exits 8 with `SOPULI-20009`.

**The keyword check.** The tool skips leading whitespace and comments (`--` and
`/* */`) and compares the first word with `upper()`. It refuses a `;` anywhere
except one at the end. A `;` inside a string literal is a known false refusal,
and it is acceptable.

**Why the keyword check exists.** Oracle commits before any DDL, so
`SET TRANSACTION READ ONLY` does not stop DDL. The keyword check does.

**The autonomous-transaction gap.** A function that uses an autonomous
transaction, called from a `SELECT`, gets past both guards. The read-only
transaction does not cover an autonomous transaction, and the keyword check sees
only a `SELECT`. Work that transaction commits is not undone by the rollback.
A `SELECT seq.NEXTVAL FROM dual` also runs in a read-only transaction and moves
the sequence (measured on 23.26.3.0.0); `SELECT ... FOR UPDATE` does not, because
the server refuses it with `ORA-01456`. This is accepted. The rights of the
run-as account are the real limit, as §1 says.

**`readonly: true`** (`../design/00-principles.md`) refuses `--write`, with or
without `--dry-run`, with exit 8. It does not refuse a read, and `--dry-run`
without `--write` runs the read as usual. A `safety:` block on a target, or on a group that matches
one, applies to a write that selects that target. A write binds no account, so
every selected target counts as reached for `readonly`, and every selected
target of a product `sql run` runs on counts for `max_targets` (§5). The
refusal offers a read without `--write` instead.

---

## 4. Guards on a write

### More rows than intended

`--write` needs a row guard: `--expect-rows N` (exactly N) or `--max-rows N`
(at most N). Each guard applies to each target on its own. A write without a
guard is refused at plan time.

On each target the tool runs the statement, reads the affected row count, and
commits only if the count passes the guard. Otherwise it rolls back and reports
that target as refused by the guard.

`--dry-run` does the same on every target and always rolls back. So a dry run
shows the real row counts. It does not stop at a failing target: it runs every
selected target and reports every count. Only a real write stops at the first
failure (§5). A dry run offers the `--plan` to run it with only when every
target connected and passed its guard, and then says when the real run will
ask for a confirmation (`confirm_environments`). Otherwise it says
that a real run would be refused, and names the targets that did not connect,
and it names the targets that did not pass and the target where a real run
would stop. Where
no selected target is of a product `sql run` runs on, it says nothing would
run. The run document carries the fingerprint in every case.

A dry run is not free of effects. A trigger, a sequence's `NEXTVAL` and an
autonomous transaction commit their own work, and the rollback does not undo it.
Row locks stay held until the rollback.

### Wrong targets

`--write` needs an explicit selector. With no selector, a write means no
targets, never all of them. `max_targets` applies unchanged (invariant 10).
`confirm_environments` asks only on a real run.

**The plan fingerprint.** A dry run prints a short hash of these things:

- the normalised statement text;
- the row guard: its kind (`expect` or `max`) and its value;
- the sorted list of resolved targets, each with its name, its `dsn`, the
  user its session became, and its database identity, which is `DB_UNIQUE_NAME`
  and `CON_NAME`, read when the tool connects. The session user is what the
  database reports, so an `external` login that reaches another user changes
  the hash. A target that did not connect has its configured run-as name, or
  `external`, and no identity.

**Normalisation.** The tool turns CRLF and CR into LF. It removes trailing
ASCII whitespace (space, tab, line feed, form feed, vertical tab), one trailing
line that holds only `/`, and one trailing `;`, and the whitespace around each
of them. A `;` still left in the text is refused. A `/` is refused unless it is
alone on the last line, where it is removed. Nothing else changes: case,
whitespace and literals inside the statement stay as written.

Both the dry run and the real run connect to every target first, check the
session user (§2), and read the database identity. They compute the hash before
any statement runs anywhere. A TNS alias that points at another database then
changes the hash. A target that could not be connected is in the hash with no
identity, so a target that was down in the dry run and is up in the real run
changes it too.

A real `--write` run must be given `--plan HASH`. It is refused at plan time,
with `SOPULI-20011` and exit 8, as `readonly` and `max_targets` are, when the
hash it computes differs. The hash differs when the config adds a target, when a
target points at another database or another account, when the row guard
changes, and when the statement differs by one character that normalisation
keeps. A real `--write` without `--plan` is an argv error, exit 2. A dry run
given `--plan` says whether it matches the dry run's hash, and changes nothing
else. Where `confirm_environments` asks, it asks after the hash matched and
before any statement runs.

A write that affects 0 rows is rolled back, and reports `changed: false` (§6).

### Lock waits

A write, dry or real, sets a call timeout on its session, so a row that the
application holds locked cannot hang the run. The target that times out fails,
and the write stops there (§5). On Oracle the client closes the connection when
the timeout fires, and the server rolls this statement's transaction back once
it ends the session. The rollback does not undo an autonomous transaction (§3).
A session that waits on a lock ends when the wait does. The session reports
`connection_lost`, and nothing more can be sent on it. The client reports
`DPY-4011`, with `ORA-03156` in its message, and the tool keeps both. The
timeout does not bound the commit, so a commit is never abandoned half done.

---

## 5. Order and failure

Targets run one after another, sorted by name. Each write commits on its own
target. There is no atomic commit across targets.

**A real write runs only when every selected target connected.** The tool
connects every target before any statement runs. If one did not connect,
whether it could not be reached, refused the login, or was not tried because
another target refused the same typed password (§2), the write could not
finish everywhere. So the tool refuses the run with exit 8, names each target
that did not connect, closes every session, and runs nothing. Committing on
the targets before it would leave a partial change the tool could have
avoided. A dry run never commits, so it runs every connected target and
reports the others.

**A real write stops at the first target that fails while it runs**, by its row
guard, a database error or a timeout. The targets after it are reported as not
attempted. A guard that fails on a real run means the data changed since the dry
run. The operator fixes the cause, dry-runs the remaining targets again, and runs
again.

A run where some targets committed and others did not exits `4` (partial
success), and its output names each target's outcome. A run where every target
committed, or affected 0 rows and rolled back, exits `0`. A run where no target
committed exits `1`. A dry run exits `0` when every target passed its guard,
`4` when some did, and `1` when none did. A target of another product is
`SKIPPED` (`SOPULI-20006`). It does not stop a real write, and the exit code
leaves it out; a run where every target is one exits `5`. Nothing runs on it,
so the plan leaves it out too, and it counts for neither `max_targets` nor
`confirm_environments`.

**A commit that fails has an unknown outcome.** The statement ran and the
commit was sent, so the change may have taken effect. The target is `ERROR`,
with a message that says the outcome is unknown and to check the rows before
running again, and the server's code and message. The run stops there, and the
exit code counts the target as possibly committed: a failed commit on the
first target exits `4`, not `1`.

**An interrupt keeps the record.** When Ctrl-C stops a real write, the
targets that finished keep their outcome. The target in flight is `ERROR`,
because whether it committed is unknown, and the targets after it are
`NOT_ATTEMPTED`. The tool prints them before it exits.

**A read does not stop.** It reports every target it could read, and the ones it
could not. It exits `0` when every target answered, `4` when some did and some
did not, and `1` when none did. A target of another product is left out of
these, and a read where every target is one exits `5`.

---

## 6. Invariants, read for UC-3

**Invariant 5: the config is the whitelist for changes.** UC-3 changes data,
never accounts: DDL is refused, so a write cannot change an account. For UC-3,
the config is the whitelist of the targets it may connect to, not of the rows it
may touch. Selectors filter the declared targets and cannot extend them.

UC-3 adds one reading exception. `sql run` reads whatever the run-as account may
read, so a statement can list accounts that the config does not declare. The tool
lists nothing on its own. The operator's statement and the account's own grants
decide what is read. The exception is recorded in CLAUDE.md and in
`../design/00-principles.md`, with the reasons in
[#1658](../decisions/log.md#1658).

**Invariant 9: a write does not converge.** The tool cannot see whether a
statement has already taken effect. Oracle reports the rows a statement matched,
not the rows it changed. A second `UPDATE t SET flag = 1` commits again and
reports the same count. So a committed write that affects more than 0 rows
reports `changed: true`, every time. A write that affects 0 rows is rolled back,
and reports `changed: false`, because the count proves nothing changed. The verb
is outside the rule, like `creds generate` and `account reset-password`. A DBA
who wants a repeatable write writes one, for example with `WHERE flag = 0`. The
exception is recorded in `../design/00-principles.md` and in CLAUDE.md, with the
reasons in [#1658](../decisions/log.md#1658).

**Invariant 8: `--dry-run` and a plan.** A write prints its plan first and
supports `--dry-run`. A read changes nothing and needs neither.

**Invariants 3 and 4: capabilities, refused at plan time.** The statement
check, the missing row guard, the missing selector and the plan fingerprint all
refuse at plan time, before any target is touched.

**The run lock is not taken.** The run lock (P5, Q2) is keyed on a vault secret
path. UC-3 writes no vault document, so there is nothing to lock. A write that two operators start at the
same time is guarded by the row guard on each target, and by the database's own
row locks. The plan fingerprint tells each operator which targets and statement
they ran.

**Invariant 1: secrets never in argv.** The statement is a file or stdin, never
an argument, which also spares the operator from shell quoting. The run-as
password comes only from the sources in §2.

**Invariant 2: redaction.** The statement is not a secret. It is shown in the
plan, in the text output and in the run document, so the operator sees what the
fingerprint covers. A statement that holds a secret is the operator's mistake,
and the tool does not look for one.

**Audit.** The run document and the `jsonl` events are the record. There is no
separate audit stream. A committed write carries the run's plan fingerprint
and, for each target, the row count and the outcome. A read changes nothing and
adds no mutation record.

---

## 7. Output

- **Text:** one block for each target, or one table with a target column when
  every target returns the same columns.
- **JSON:** a new `results[]` shape for `sql run` in the run document. It holds
  the columns, the rows, the row count, a truncated flag and the outcome for each
  target. This is a minor schema bump, and a sample is checked against the schema
  (invariant 12).
- **Row cap.** The tool returns up to 100 rows for each target by default.
  `--max-result-rows` changes the cap, for a read only: a write returns no
  rows, so `--write` refuses it as an argv error. A truncated target is marked in the
  output.
- **Value types.** Dates, numbers and LOBs become strings or numbers that JSON
  can carry. A LOB is read as text or bytes, cut at 4000 characters or bytes,
  and the target is marked truncated when one was cut. Oracle `NUMBER` is read
  as a `Decimal`, so a value with a scale is not rounded to a float.

---

## 8. Decisions

| Question | Answer |
|---|---|
| Which account does the tool connect as? | The run-as account, never the service account (§2) |
| May a statement change data? | Yes, with `--write`, a row guard, a selector and a plan fingerprint (§3, §4) |
| What does `--dry-run` mean for SQL the tool does not parse? | It runs the statement on every target and always rolls back, so it shows real row counts. Triggers, sequences and autonomous transactions can still commit their own work (§4) |
| What is a result when targets return different rows? | One result for each target (§7) |
| Does it take the run lock? | No. There is no vault document to lock (§6) |
| Is it convergent? | No. A committed write that affects rows reports `changed: true`; a write that affects 0 rows is rolled back and reports `changed: false` (§6) |

The maintainer decided these in #1657.
