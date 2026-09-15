# UC-2 — Personal account passwords: reset, expire, hand over

Status: draft / sketch. **Nothing here is built, and most of it is not decided** —
§9 lists what is open, and each open question is a `decision` issue.
Depends on: `../design/00-principles.md`, `../design/01-configuration.md`,
`../design/02-oracle-privileges.md`

This is part 1 of the specification (#438). Delivery — how the new password
reaches a person — is part 2, #456; §6 holds its place.

---

## 1. Summary

**Goal.** A person's own database account — a developer's, a tester's, a DBA's —
gets a new password that the tool generates, sets, and expires on the spot. The
person receives it once and replaces it at first logon. Once they have, **no copy
of any password the tool handled still works anywhere**, and that is the state the
use case exists to reach.

**Actors.**

| Actor | Role |
|---|---|
| DBA | runs the reset, usually because somebody asked for one |
| Account owner | receives the password, logs in once, and sets their own |
| Delivery channel | carries the password, or a way to claim it, to the owner (#456) |

**Direction of truth.** There isn't one, and that is the first way this differs
from UC-1. `docs/README.md` puts it as *a password is handed over, not synced*.
Nothing fetches the value at runtime, so no vault is master of it, and after first
use the only party that knows the password is the person. Invariants 6 and 7
therefore have nothing to govern here (§7). **That does not make the database a
source of truth either**: the tool reads account state from it, as UC-1 does, and
never a password.

**Why this cannot be a mode of UC-1**, from the roadmap, each point being a place
UC-1's design would do the wrong thing:

- **Expiring deliberately is the point.** `PASSWORD EXPIRE` breaks an application
  account and is correct for a person — which is why UC-1 §5 has no such
  attribute and sent the operation here (#302).
- **Lockout tolerance is different.** UC-1 §7's apparatus exists because locking a
  production application account is an outage. Locking a developer out of their
  own account is not (§5).
- **Nothing is promoted, so nothing waits on confirmation.** UC-1's whole safety
  design is the ordering of `pending` → `current`. A handover has no `current`.

**Non-goals.** Creating, dropping or granting accounts (UC-4). Application
accounts (UC-1). A person resetting their own password through the tool, unless
H5 brings it in. Storing the password anywhere as a record of it.

---

## 2. Commands

**Not named yet** — H3 (#451) is the noun and the verbs, and D2's noun-verb
grammar is the only constraint already binding. What the use case needs, whatever
it ends up being called:

| Operation | What it does | Mutates |
|---|---|---|
| reset | generate a password from a policy, set it with expiry, hand it over | yes |
| plan | the same, under `--dry-run`, printing the plan and no password (invariant 8) | no |
| expire only | `PASSWORD EXPIRE` with no new password — "make them change it" | yes |

Whether *expire only* is its own verb, a flag, or out of scope is part of H3.
Whether there is a read verb — "when was this person last reset" — depends on H2:
with nothing recorded, there is nothing for it to read beyond what the database
reports (§3).

Every operation is limited to declared accounts. **Where a personal account is
declared is H1 (#449)** — the application binding that declares UC-1's accounts
means *these accounts are mastered by these secrets*, which is not true of any
account here.

---

## 3. What is recorded

UC-1's vault payload answers three questions at once: when a password last changed
(Q9's `rotated_at`), what to roll back to (`previous`), and where the lock lives
(Q2, keyed on the secret path). UC-2 has no payload, so each needs its own answer.
**H2 (#450) is those answers**; what is already true regardless:

- **Rollback is not a UC-2 operation.** The recovery for a lost or mistyped
  personal password is another reset. Nothing keeps the old value to go back to,
  and keeping one would be exactly the stored copy §1 says should not exist.
- **The run's own output is always a record**, the run document and the jsonl
  stream, and it never carries a password (invariant 2). Whether anything more
  durable exists is H2.
- **The database can report when a password changed**, but not on every release by
  the same route: `DBA_USERS.PASSWORD_CHANGE_DATE` where it exists, `SYS.USER$.PTIME`
  behind the optional grant otherwise (#386), and 12.1, 12.2 and 19c unmeasured
  (unverified: pw-changed-source).

---

## 4. The reset

### 4.1 The statement

One direct statement, and the expiry is part of it:

```sql
ALTER USER <account> IDENTIFIED BY "<password>" PASSWORD EXPIRE
```

Everything UC-1 §6.1 and `02-oracle-privileges.md` §4 settle about issuing
`ALTER USER` binds unchanged:

- **issued directly, never inside a PL/SQL block** (invariant 13). A block
  containing the DDL keeps its text verbatim in `V$SQL` — measured on 26ai, 21c,
  18c and 11.2 — and adding `PASSWORD EXPIRE` to the statement changes nothing
  about that;
- **no password containing `"`** (invariant 11), which generation guarantees by
  construction rather than by a check afterwards;
- **what the direct DDL leaves behind is release-dependent.** On 26ai, 21c and 18c
  no `V$SQL` cursor for it exists at all; on 11.2 `V$SQLSTATS` keeps the text until
  the shared pool ages it out (#387); 12.1, 12.2 and 19c are unrun
  (unverified: ddl-text-versions). Quote none of these without its release.

### 4.2 The password

Generated from a policy, by the same tier-0 code UC-1 uses (01-configuration §8).
A personal policy is likely to differ — a person types this once, from a message —
but nothing about generation does. The maximum length is the same live question it
is for UC-1: the limit is derived against a floor that #383 showed to be wrong, so
a long policy can plan clean and fail mid-run on 21c and older
(unverified: password-byte-limit).

### 4.3 Expiry and the rollover window

On a release with gradual password rollover (UC-1 §6.3), an account whose profile
sets `PASSWORD_ROLLOVER_TIME` keeps accepting its **old** password after
`IDENTIFIED BY`, until the window closes. For UC-1 that is the zero-downtime
feature. For a person it may be the opposite of what the reset was for: a reset
after a suspected compromise leaves the compromised password working.

How `PASSWORD EXPIRE` combines with an open window — whether expiring the new
password also ends the old one's, and whether the statement is accepted at all
during one — has not been run (unverified: expire-rollover). Until it has, the use
case assumes nothing: a reset on an account with a non-zero rollover time is a
plan-time finding, not a silent success, and ending the window is the same
`EXPIRE PASSWORD ROLLOVER PERIOD` statement `creds finish-rollover` issues (#263).
Whether a reset issues it by default is for this document to decide once the
measurement exists.

### 4.4 Guardrails

`02-oracle-privileges.md` §4's five account checks bind unchanged, and one of them
collides with the roadmap. **Check 4 refuses any account holding `DBA`, `PDB_DBA`,
`CDB_DBA` or `AUDIT_ADMIN`**, and the roadmap names DBA accounts as in scope. Under
today's rule every reset of a DBA's personal account needs `--force`, which
overrides checks 2–5 and is recorded in the audit event (#89).

That is stated here rather than solved. It may be the right answer — a DBA account
is precisely where a reset deserves an explicit override — or it may make `--force`
routine in a way #89 did not intend. Neither reading is taken here.

---

## 5. Lockout, unlocking, and self-service

**A reset attempts no login**, so most of UC-1 §7 has nothing to guard: its six
mitigations exist to stop a scheduled *check* from locking an account. Two
questions survive, and both are H4 (#455):

- **Does UC-2 ever verify a delivered password?** A login with it would consume the
  first-use `EXPIRED` state the reset exists to create, so verifying by login is
  probably wrong by construction. Verifying by hash depends on #437 and #90, and
  never by a bound value (invariant 14).
- **Does a reset unlock?** People ask for a reset because they are locked out. But
  01-configuration §8 makes every account attribute opt-in *as a rule, not a
  default*, and `unlock_if_locked` is `false` (#300). That rule was argued for a
  rotation nobody asked to change anything else; a person's reset is arguably
  asked for. H4 decides whether that difference is enough.

**Self-service** is H5 (#452). The constraint on it is ADR-001's: the service
account holds `ALTER USER` because the operator is a DBA who already holds more,
and a person resetting their own password through that account would be using a
privilege they do not have. Until H5 is answered UC-2 is DBA-operated.

---

## 6. Delivery

**Part 2 of this specification, #456.** One rule is binding now, because #438 set
it and every delivery issue is written against it:

> **The channel that notifies may be low-trust. The channel that carries the
> secret may not.** "Your new password is ready" may go anywhere; the password,
> or anything that retrieves it, may not.

Where a single-use retrieval token falls — a Vault wrapping token, a one-time link
— is for #456 to say, since both are ways to retrieve the secret.

The methods, each its own issue: `manual` (#441, blocked on #439, which decides
whether it may exist under invariant 2), `vault_wrapped` (#444) and its
identity-scoped variant (#447), `one_time_link` (#445), `onepassword_share`
(#446). The shared notify channel is #442, the config block #440, and how an
estate restricts the set is H6 (#453).

---

## 7. The invariants, read for UC-2

| # | Invariant | Here |
|---|---|---|
| 1 | no secret in `argv` | binds unchanged, including every delivery credential |
| 2 | redaction at the serialiser | binds; `manual` delivery would widen it and is #439 |
| 3 | branch on capability, not version | binds — rollover (§4.3) is a capability |
| 4 | unavailable capability fails at plan time | binds — §4.3's rollover finding, §4.4's guardrails |
| 5 | the config is the whitelist | binds; *where* the account is declared is H1 |
| 6 | vault is master | nothing to govern — no master (§1) |
| 7 | never promote before confirmation | nothing to govern — no promotion (§1) |
| 8 | `--dry-run` and a plan first | binds |
| 9 | idempotency | **does not fit** — a reset draws a new password every run; H7 (#454) |
| 10 | safety settings only ratchet | binds; H6 would add an axis (#456) |
| 11 | no `"` in a password | binds, by generation |
| 12 | JSON output is versioned | binds — new verbs and events are schema bumps |
| 13 | no password literal in a PL/SQL block | binds, `PASSWORD EXPIRE` included (§4.1) |
| 14 | no password bound into a predicate | binds — relevant only if H4 verifies by hash |

Invariants 6 and 7 not governing is a property of this use case, not an exemption
from them: nothing here writes to a vault as a master, and if H2 answers with a
store, it records metadata, never a value to be synced from.

---

## 8. Testing

Tier 1 covers the core: Oracle Free with its rollover capability, and the Vault
container for the delivery methods that use one. Tier 0 covers everything with no
I/O — the plan, the refusals, generation, and the statement text, which is where
invariant 13's assertion already lives for UC-1.

What a test must show, once there is something to test:

- after a reset, `DBA_USERS.ACCOUNT_STATUS` is `EXPIRED` and a logon with the
  delivered password is forced to change it;
- the statement text sent is the direct DDL and carries `PASSWORD EXPIRE`;
- the password appears in no run document, jsonl event or log sink;
- §4.3's measurement, on 26ai and then 21c — run, not reasoned, which is the only
  way that marker comes off.

Tests declare the capabilities they need and skip with a reason when absent
(`04-testing.md`), never on a version.

---

## 9. Open questions

| # | Question | Issue |
|---|---|---|
| H1 | Where is a personal account declared, so invariant 5 still whitelists it? | #449 |
| H2 | With no vault as master, what is recorded about a reset, and where? | #450 |
| H3 | The noun and the verbs | #451 |
| H4 | Does UC-2 guard against lockout, verify a delivered password, or unlock on reset? | #455 |
| H5 | Is self-service part of UC-2? | #452 |
| H6 | Restricting delivery methods: an `allowed_methods` intersection or a `forbidden_methods` union? | #453 |
| H7 | A reset never converges: a second invariant-9 exemption, or a convergent verb? | #454 |
| — | May `manual` delivery print a working password (invariant 2)? | #439 |

Not yet a question with an issue: §4.4's collision between guardrail check 4 and
DBA accounts in scope, and §4.3's default for ending a rollover window, which waits
on its measurement.
