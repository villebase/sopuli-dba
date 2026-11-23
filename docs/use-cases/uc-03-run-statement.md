# UC-3 — Run one statement across many targets

Depends on: `../design/00-principles.md`, `../design/01-configuration.md`,
`../design/02-oracle-privileges.md`

This document specifies a command that runs one statement against a selected
set of declared targets and shows what each target returned. **Nothing in it is
built yet.** The command name, `sopuli sql run`, is a working name. The parts
are built in this order, each by its own issue:

| Part | Issue |
|---|---|
| The pure layer: the statement check, the plan fingerprint and the row guards | (open: #1659) |
| The `run_as:` configuration | (open: #1660) |
| The Oracle runner | (open: #1661) |
| `sql run` for reads | (open: #1662) |
| `--write` | (open: #1663) |

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

**The default is the DBA's personal account**, such as `dba_alpha`. A DBA who
wants the application's owner account, or another account, names it in the
config and puts its password in the keyring.

**`run_as:`** is a block with the grammar of `admin:`
(`../design/01-configuration.md` §3a). It goes on a target or under `defaults:`.
It does not go on a group: a group carries only `match` and `safety`, as it does
for `admin:`. The allowed `auth:` methods are `keyring`, `prompt`, `external` and
`env`. `env` carries the same warning as it does for `admin:`. `vault` is not
allowed, so that the tool never logs in with a password that a store holds for
another purpose. `--as USER` with `auth: prompt` covers a run that the config
does not configure.

The password is read from the sources the tool already has for its own
credentials. It is never read from stdin, because `admin:` does not offer stdin
either, and so stdin stays free for the statement. It is never read from a store
that UC-1 manages, and UC-1 does not manage this account.

**Refusing the service account.** The tool checks the run-as account twice.

1. At plan time, from the config. A target whose run-as user name equals its
   `admin:` user name is refused. A wallet holds one credential for each alias,
   so a target whose `run_as` and `admin` are both `external` on the same alias
   is refused too.
2. Before any statement runs, from the database. Where either side uses
   `auth: external`, the config has no user name to compare. So the tool
   connects to every selected target first, reads
   `SYS_CONTEXT('USERENV','SESSION_USER')`, and compares it with the service
   account's user name. One match refuses the run on every target, before any
   statement runs. The error is `SOPULI-20010`.

   There is a gap here. When `admin:` is `external` and `run_as` names a user,
   the config holds no user name for `admin:`, so the plan-time check cannot
   compare. Only the session check covers this case. It works because it asks
   the database who the session is, and so it sees the service account whatever
   the config says.

---

## 3. Reads and writes

A run is read-only unless the operator passes `--write`.

- **A read** runs in `SET TRANSACTION READ ONLY` and always ends with a
  rollback. The first keyword must be `SELECT` or `WITH`.
- **A write** needs `--write`. The first keyword must be `UPDATE`, `INSERT`,
  `MERGE` or `DELETE`. A write keyword without `--write` is a usage error and
  exits 2.
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
only a `SELECT`. This is accepted. The rights of the run-as account are the real
limit, as §1 says.

**`readonly: true`** (`../design/00-principles.md`) refuses `--write`.

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
shows the real row counts and changes nothing.

### Wrong targets

`--write` needs an explicit selector. With no selector, a write means no
targets, never all of them. `max_targets` and `confirm_environments` apply
unchanged (invariant 10).

**The plan fingerprint.** A dry run prints a short hash of two things: the
normalised statement text, and the sorted list of resolved targets, each with
its name, its `dsn` and its run-as user name (or `external`). A real `--write`
run must be given `--plan HASH`. It is refused at plan time, with `SOPULI-20011`
and exit 8, as `readonly` and `max_targets` are, when the hash it computes
differs. The hash differs when the config adds a
target, when a target points at another database or another account, and when
the statement differs by one character.

### Lock waits

A write, dry or real, sets a call timeout on its session, so a row that the
application holds locked cannot hang the run. The target that times out fails,
and the write stops there (§5).

---

## 5. Order and failure

Targets run one after another. Each write commits on its own target. There is no
atomic commit across targets.

**A write stops at the first target that fails**, whether by its row guard, a
database error or a failed connection. The targets after it are reported as not
attempted. A guard that fails on a real run means the data changed since the dry
run. The operator fixes the cause, dry-runs the remaining targets again, and runs
again.

A run where some targets committed and others did not exits `4` (partial
success), and its output names each target's outcome.

**A read does not stop.** It reports every target it could read, and the ones it
could not.

---

## 6. Invariants, read for UC-3

**Invariant 5: the config is the whitelist for changes.** UC-3 changes data,
never accounts. For UC-3, the config is the whitelist of the targets it may
connect to, not of the rows it may touch. Invariant 5 itself does not change.
Selectors filter the declared targets and cannot extend them.

**Invariant 9: a write does not converge.** The tool cannot see whether a
statement has already taken effect. Oracle reports the rows a statement matched,
not the rows it changed. A second `UPDATE t SET flag = 1` commits again and
reports the same count. So `sql run --write` reports `changed: true` for every
committed write, and `changed: false` never appears for it. It is outside the
rule, like `creds generate` and `account reset-password`. A DBA who wants a
repeatable write writes one, for example with `WHERE flag = 0`. The exception is
recorded in `../design/00-principles.md` and in CLAUDE.md, with the reasons in
[#1658](../decisions/log.md#1658).

**Invariant 8: `--dry-run` and a plan.** A write prints its plan first and
supports `--dry-run`. A read changes nothing and needs neither.

**Invariants 3 and 4: capabilities, refused at plan time.** The statement
check, the missing row guard, the missing selector and the plan fingerprint all
refuse at plan time, before any target is touched.

**The run lock is not taken.** The run lock (P5, Q2) is keyed on a vault secret
path. UC-3 writes no vault document, so there is nothing to lock. The roadmap
said "the same lock", but no lock fits. A write that two operators start at the
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
separate audit stream. A committed write carries, for each target, the
statement's fingerprint, the row count and the outcome. A read changes nothing
and adds no mutation record.

---

## 7. Output

- **Text:** one block for each target, or one table with a target column when
  every target returns the same columns.
- **JSON:** a new `results[]` shape for `sql run` in the run document. It holds
  the columns, the rows, the row count, a truncated flag and the outcome for each
  target. This is a minor schema bump, and a sample is checked against the schema
  (invariant 12).
- **Row cap.** The tool returns up to 100 rows for each target by default.
  `--max-result-rows` changes the cap. A truncated target is marked in the
  output.
- **Value types.** Dates, numbers and LOBs become strings or numbers that JSON
  can carry. A LOB above a size cap is refused or truncated.

---

## 8. Decisions

| Question | Answer |
|---|---|
| Which account does the tool connect as? | The run-as account, never the service account (§2) |
| May a statement change data? | Yes, with `--write`, a row guard, a selector and a plan fingerprint (§3, §4) |
| What does `--dry-run` mean for SQL the tool does not parse? | It runs the statement on every target and always rolls back, so it shows real row counts (§4) |
| What is a result when targets return different rows? | One result for each target (§7) |
| Does it take the run lock? | No. There is no vault document to lock (§6) |
| Is it convergent? | No. A committed write reports `changed: true` (§6) |

The maintainer decided these in #1657. Error codes `SOPULI-20009`,
`SOPULI-20010` and `SOPULI-20011` are planned and are not in the error table yet.
