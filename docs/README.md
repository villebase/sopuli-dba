# sopuli-dba — design documentation

This index is for contributors. If you want to use the tool, start at
[getting-started.md](getting-started.md). The documents below are the
specification. [CONTRIBUTING.md](../CONTRIBUTING.md#how-this-project-is-built-and-what-that-means-for-you)
explains why they record rejected options and name the issue behind each
decision.

The project is alpha. Each use-case document says which parts of it are
built. [measurements.md](measurements.md) says which script in `sql/oracle/` ran
on which Oracle release, and what it showed.

## For a reader outside the project

| Document | Contents |
|---|---|
| [getting-started.md](getting-started.md) | first run: install, a first config file, `config validate`, `doctor`, and one command under `--dry-run` |
| [security-model.md](security-model.md) | what the tool can and cannot do to a database, and what stops a mistake from being silent — plain English, for deciding whether to trust it |
| [scenarios/rotate-and-sync.md](scenarios/rotate-and-sync.md) | one password rotation end to end: stage, apply, check, roll back, and close the rollover window |
| [scenarios/kubernetes-eso.md](scenarios/kubernetes-eso.md) | the vault-write side of an External Secrets Operator setup, and the division of responsibility that makes it safe |
| [scenarios/personal-password-delivery.md](scenarios/personal-password-delivery.md) | one person's password reset end to end, each way to hand the new password over, and which one to choose |
| [scenarios/supabase.md](scenarios/supabase.md) | replacing a shared `postgres` password on Supabase with one vault-managed login role for each service |
| [../examples/](../examples/) | runnable config files with comments, starting with the smallest one that works |
| [reference/](reference/README.md) | every command: its usage, its help text and its options, generated from the command definitions |
| [../CONTRIBUTING.md](../CONTRIBUTING.md) | what a first-time contributor needs that `workflow.md` and `CLAUDE.md` do not say for that audience |
| [../SECURITY.md](../SECURITY.md) | reporting a vulnerability privately |

## Design

| Document | Contents |
|---|---|
| [design/00-principles.md](design/00-principles.md) | P1 multi-product DB support (Oracle first), P2 multi-vault support, P3 config file + precedence, P4 cross-platform, P5 cross-cutting behaviour and exit codes |
| [design/01-configuration.md](design/01-configuration.md) | YAML schema in two shapes (single application inline, `applications:` for several), the estate sections, target templating with labels, profiles (run context), environment variables, SecretRef syntax, password charsets, precedence |
| [design/02-oracle-privileges.md](design/02-oracle-privileges.md) | The grant model: direct `ALTER USER`, common vs per-PDB service accounts, client-side guardrails, auditing |
| [design/02-postgres-privileges.md](design/02-postgres-privileges.md) | The PostgreSQL grant model: `CREATEROLE` and no superuser, `ADMIN OPTION` per managed role, `pg_hba.conf`, what must not be granted, where password text surfaces |
| [design/03-json-output.md](design/03-json-output.md) | The `--output json` / `--output jsonl` contract, redaction, stability policy, `jq` recipes |
| [design/04-testing.md](design/04-testing.md) | What can and cannot be containerised, capability-driven matrix, tiering, fault injection, release gates |
| [use-cases/uc-01-app-credential-sync.md](use-cases/uc-01-app-credential-sync.md) | UC-1: application DB account credentials, vault as master — `generate` / `apply` / `check` / `rotate` |
| [use-cases/uc-02-personal-account-passwords.md](use-cases/uc-02-personal-account-passwords.md) | UC-2: a person's own database account — the `account` verbs, password reset, the reset record, and delivery methods |
| [workflow.md](workflow.md) | Binding: branching (`issue-<n>-<slug>`, no long-lived integration branch), Conventional Commits, release-please and the 0.x policy |
| [measurements.md](measurements.md) | What ran on which Oracle release, when, and what it showed: the one place for release-by-release results |
| [local-testing.md](local-testing.md) | The usual commands, run by hand against the tier-1 stack: setup, the `creds` lifecycle, the `account` verbs, and a few refusals |
| [maintainer-environments.md](maintainer-environments.md) | Setting up other Oracle releases, OCI Base Database and Autonomous Database, wallets, and WSL |

## Decisions

| Document | Contents |
|---|---|
| [decisions/adr-001-privilege-model.md](decisions/adr-001-privilege-model.md) | Why direct `ALTER USER`, what was rejected, and the two triggers for revisiting |
| [decisions/adr-002-cli-framework.md](decisions/adr-002-cli-framework.md) | click as the CLI framework |
| [decisions/adr-003-text-tables.md](decisions/adr-003-text-tables.md) | No table library: columns formatted with click and the standard library, and why output must not depend on the terminal |
| [decisions/adr-004-yaml-parser.md](decisions/adr-004-yaml-parser.md) | PyYAML on a hardened `SafeLoader`, why not ruamel, and the pywin32 dependency for the P4 permission check |
| [decisions/adr-005-vault-client.md](decisions/adr-005-vault-client.md) | The HTTP API directly, over `httpx`, not `hvac`, and why OCI keeps its own SDK |
| [decisions/adr-006-optional-dependencies.md](decisions/adr-006-optional-dependencies.md) | Vendor clients are install extras: what base carries, why base opens no sockets, and what a configured-but-uninstalled backend does |
| [decisions/adr-007-vault-token-flag.md](decisions/adr-007-vault-token-flag.md) | `--vault-token-file` takes a path and `--vault-token` is refused; why a SecretRef cannot authenticate the store it lives in, and where the token chain merges |
| [decisions/adr-008-contribution-provenance.md](decisions/adr-008-contribution-provenance.md) | A DCO sign-off rather than a CLA, why review-time checking rather than CI, and what would change either |
| [decisions/log.md](decisions/log.md) | One short record for each smaller decision: the question, the answer, the reasons and the options rejected |

## Machine-readable artefacts

| File | Purpose |
|---|---|
| [schemas/sopuli-config-3.4.schema.json](schemas/sopuli-config-3.4.schema.json) | JSON Schema (2020-12) for the config file (P3). Generated from the config layer by `python -m sopuli.config.schema` — never edited by hand |
| [schemas/sopuli-run-1.71.schema.json](schemas/sopuli-run-1.71.schema.json) | JSON Schema (2020-12) for the `--output json` document — the current one; earlier minors stay published beside it, with the exceptions that `design/03-json-output.md` §8 names, because a build emitting `schema_version: "1.20"` has to be able to fetch what it validates against |
| [schemas/sopuli-event-1.21.schema.json](schemas/sopuli-event-1.21.schema.json) | JSON Schema for `--output jsonl` events |
| [schemas/example-creds-check-drift.json](schemas/example-creds-check-drift.json) | Worked example: a scheduled check finding drift in one of two PDBs |
| [schemas/example-creds-status-rollover.json](schemas/example-creds-status-rollover.json) | Worked example: `creds status` with a rollover window open, a password in its grace period, and a run-level warning |
| `../sql/oracle/00_install.sql` | Create and grant the service account — `NONCDB` / `COMMON` / `PDB` modes |
| `../sql/oracle/01_audit_policy.sql` | Unified audit policies and correlation queries |
| `../sql/oracle/02_password_leak_probe.sql` | Release gate 2: a canary probe for password text kept anywhere queryable. Findings in `design/02-oracle-privileges.md` §4; what is still open in `design/04-testing.md` §6 gate 2 |
| `../sql/oracle/04_password_leak_extensions.sql` | Gate 2's other three checks: self-rotation, `IDENTIFIED BY VALUES`, and a 10046-traced session. Run it after the probe and **before** the probe's section 8, which turns the audit policies off |
| `../sql/oracle/99_uninstall.sql` | Remove the account; keeps the audit policies by default |
| `../test/compose.yaml` | The test stack, by profile. `tier0`: Vault (KV v1 and v2) and PostgreSQL. `tier1`: adds Oracle Free. `tier2`: adds 21c, 18c and 11g XE. `nne`: an Oracle Free that requires NNE. `oracle19c`, `oracle19c-ru` and `oracle12c`: 19.3, 19.19 and 12.2 EE, maintainer-only. `emulators`: lowkey-vault. `postgres-matrix`: PostgreSQL 13 to 18, for the probes in `sql/postgres/`. `mysql-matrix`: MySQL 8.0, 8.4 and 9, for the probes in `sql/mysql/`. `mariadb-matrix`: MariaDB 10.11 and 12.3, for the probes in `sql/mariadb/` |
| `../test/capabilities.py` | Sketch of capability probing and the pytest skip markers |
| `../test/k8s_eso_probe.py` | Applies [scenarios/kubernetes-eso.md](scenarios/kubernetes-eso.md)'s own manifests to a throwaway Kubernetes cluster, and checks that ESO reads what sopuli wrote. Needs a cluster, not compose |

[measurements.md](measurements.md) lists every script in `sql/oracle/` and the
releases it ran on.

All three schemas validate as Draft 2020-12, and the example validates against
the run schema. `tests/test_schemas.py` checks this on every push and pull
request (invariant 12).

To get completion and inline errors while you edit a config, put
`# yaml-language-server: $schema=./sopuli-config-3.4.schema.json` on the file's
first line. [design/01-configuration.md](design/01-configuration.md) §9b says
why the schema's `$id` is not a URL to paste there.

The config schema is generated, not written. `tests/config/test_schema.py` fails
if the committed file is not what the config layer produces, so a key cannot be
added to a section without the schema. Some rules are left to the validators
instead of the schema: the rules that cross keys, whose errors must name the
key. [design/01-configuration.md](design/01-configuration.md) §9b lists them.

## Conventions

- The binary is `sopuli` and the project is `sopuli-dba` (D1).
- The CLI grammar is noun-verb: `sopuli creds rotate`, `sopuli config validate`
  (D2).
- A question the decision register below calls `open` is a real choice, not a
  placeholder. Decide it before you write code that depends on it.
- **A claim this project has not measured carries a marker naming its register
  entry**: `(unverified: <slug>)`. §*Verify before implementing* below is the
  register.

  Put the marker at every place the claim is made, not only where the question
  was raised. A result that reaches one document and not the others is the
  failure the marker exists to catch (#408, #411). When an entry becomes
  `verified`, `tests/test_verification_register.py` fails and names each file
  that still carries its marker. Removing the markers is part of settling the
  question.

  **Never put a marker in user-visible text.** A click verb's docstring is its
  `--help` output, so a marker there reaches every operator who asks for help.
  Where the claim is in help text, put the marker in a comment beside it and
  name the sentence it belongs to. `sopuli/cli.py`'s `creds_check` is the
  example.
- **Work that waits on an open issue carries a marker naming the issue**:
  `(open: #N)` in Markdown, or `(open: #N, #M)` for several, and `TODO(#N)` in
  code. Write what is true now and put the marker beside it. Do not write "until
  #N lands" or "#N will": `tests/test_pending_work.py` rejects those phrases, and
  rejects a `TODO` that names no issue. The `pending-work` workflow runs weekly
  and fails when a marker names a closed issue. When that happens, say what the
  issue did and remove the marker. The rule above about user-visible text
  applies to these markers too.

## Decision register

This table is the one place that says whether a decision is open. Each row names
the document that raises the question. That document's own table keeps the
question and the answer. The reasons for a decided question are in its record in
[the decision log](decisions/log.md), or in its ADR.
`tests/test_decision_register.py` checks those tables against this one:

- a row whose question is struck through there (`~~…~~`) must be `decided`
  here, and the other way round;
- a `deferred` row must say there what it is deferred to;
- `00-principles.md` has a status column, and it must match;
- every ADR is `decided` and says `Status: **accepted**`.

The weekly `pending-work` workflow also compares the register with GitHub: an
`open` row's issue must be open, a `decided` row's issue must be closed, and every
open issue labelled `decision` must have a row. The label means exactly that.

The statuses are:

- `open`: not answered. Do not write code that depends on it. Ask first.
- `decided`: answered. The answer is the rule.
- `deferred`: answered as "not now". The document's row says what would reopen
  it.

Where: `00` to `04` are `design/00-principles.md` to `design/04-testing.md`;
`UC-1` and `UC-2` are the two use-case documents; `ADR` is the file in
`decisions/` with that number, and `ADR-006` rows are sections of
[ADR-006](decisions/adr-006-optional-dependencies.md).

| ID | Where | Question | Status | Answer | Issue |
|---|---|---|---|---|---|
| D1 | 00 | Binary name | decided | `sopuli`; the project is `sopuli-dba` | |
| D2 | 00 | CLI grammar | decided | noun-verb: `sopuli creds rotate` | |
| D3 | 00 | Implementation language | decided | Python, `python-oracledb` in thick mode | |
| D4 | 00 | Config format | decided | YAML; JSON is accepted because it is valid YAML | |
| D5 | 00 | macOS tier | decided | best effort, untested, no macOS CI | |
| D6 | 00 | Plugin model for drivers and stores | decided | in-tree, also with a second driver | #1030 |
| D7 | 00 | Minimum Oracle version | decided | 11.2 stays in scope | |
| D8 | 00 | CLI framework | decided | click | |
| D9 | 00 | Dependency layering | decided | vendor clients are install extras | #130 |
| D10 | 00 | Which confirmation triggers are built in | decided | none; `safety.confirm_environments` only | #294 |
| E1 | ADR-006 | Does the extras rule bind database drivers? | decided | yes; `python-oracledb` is `sopuli-dba[oracle]` | #130 |
| E2 | ADR-006 | Is the HashiCorp store base or an extra? | decided | an extra, `sopuli-dba[hashicorp]` | #130 |
| E3 | ADR-006 | Does `sopuli-dba[all]` exist? | decided | yes, for CI; not the recommended install | #130 |
| E4 | ADR-006 | Configured but uninstalled backend: fail or warn? | decided | warn | #130 |
| E5 | ADR-006 | Exit code and category for a missing backend | decided | `config`, exit 9, with an `error.code` | #130 |
| E6 | ADR-006 | Does `doctor` always list the install shape? | decided | always | #214 |
| E7 | ADR-006 | Where a notify channel's client goes | decided | a fourth extra category, `sopuli-dba[notify]` | #442 |
| C1 | 01 | Name of the binding section | decided | `applications`, with an inline form | |
| C2 | 01 | Selector syntax | decided | `--select k=v` over labels, and `match:` in groups | #615 |
| C3 | 01 | Arbitrary expressions in secret templates? | decided | no; a fixed token list plus labels | #615 |
| C4 | 01 | Per-account overrides in an application entry | decided | none; write a second application entry | #640 |
| C5 | 01 | Config encryption at rest | decided | out of scope; the config holds no secrets | #615 |
| C6 | 01 | Several vaults for one application (mirror writes) | deferred | to a later use case | |
| C7 | 01 | More than two `target_sets` nesting levels? | decided | no; write a second set | |
| C8 | 01 | Labels on explicit `targets:`? | decided | allowed | |
| C9 | 01 | How the file points at vault auth and the admin credential | decided | one grammar, two vocabularies | #27 |
| C10 | 01 | What profiles are for | decided | run context, not target selection | |
| C11 | 01 | Composable `--profile`? | decided | no; one active profile | #615 |
| C12 | 01 | A built-in `interactive` profile? | decided | no | #615 |
| C13 | 01 | `vault:` under `defaults:` and profiles: a name or a block? | decided | a name, everywhere | #31 |
| C14 | 01 | `@version=` and `@stage=` vocabularies | decided | the tool owns both | #40 |
| C15 | 01 | A binding with a secret and no store | decided | caught at plan time | #118 |
| C16 | 01 | What `--vault-token` takes | decided | refused; `--vault-token-file PATH` instead | #145 |
| C17 | 01 | P5's built-in confirmation against `01-configuration.md` §9's ratchet rule | decided | §9 governs; P5 is reworded | #294 |
| P1 | 02 | Default service user: common `C##` or per-PDB local? | decided | common; per-PDB is documented | #615 |
| P2 | 02 | Grant `SELECT ON SYS.USER$` by default? | decided | no; an optional, probed grant | #86 |
| P3 | 02 | Does `--force` exist? | decided | yes; it overrides account checks 2–5 and 7 (7 from #1059) | #89 |
| P4 | 02 | One service account per database or per application? | decided | per database | #615 |
| P5 | 02 | Does `doctor` fail or warn on over-grants? | decided | warn | #213 |
| P6 | 02 | Keep 11.2 support? | decided | keep (D7) | #615 |
| P7 | 02 | Do schema privileges cover `ALTER USER`? | decided | no, `ORA-00990` | |
| P8 | 02 | 11.2 keeps the `ALTER USER` text in `V$SQLSTATS` | decided | document it | #387 |
| J1 | 03 | Does `--output json` print nothing until the end? | decided | yes; `jsonl` streams | #615 |
| J2 | 03 | `plan` in every run? | decided | in every command that plans | #615 |
| J3 | 03 | Machine-readable warning codes | decided | every warning in a run document has one; one flat series | #641 |
| J4 | 03 | Host and pid in the output | decided | `invocation.actor.host`; no pid | #615 |
| J5 | 03 | OpenTelemetry export | deferred | later; `correlation_id` serves until then | |
| J6 | 03 | Resumable event stream after a crash? | decided | no; run again | #615 |
| J7 | 03 | A run document on a usage error? | decided | no; exit 2 never emits one | #8 |
| T1 | 04 | Does an 11g XE image exist? | decided | yes | #1 |
| T2 | 04 | testcontainers or compose? | decided | compose | #174 |
| T3 | 04 | Is LocalStack Secrets Manager in the community tier? | decided | no; LocalStack is out, an AWS store gets moto | #642 |
| T4 | 04 | Does OCI Vault cost matter in a test loop? | decided | no; tier 3 only, for the tenancy, not the cost | #643 |
| T5 | 04 | Public CI provider | decided | GitHub Actions | |
| T6 | 04 | A real Data Guard standby for the read-only test? | deferred | until a driver bug needs it | |
| T7 | 04 | Snapshot and restore for Oracle resets | deferred | drop and recreate until tier 2 is too slow | |
| Q1 | UC-1 | `check`'s default method | decided | `login` | #86 |
| Q2 | UC-1 | Where the advisory lock lives | decided | in the vault, per secret path | #83 |
| Q3 | UC-1 | Generations of `previous` | decided | one | #84 |
| Q4 | UC-1 | Does the tool alter a profile? | decided | never | #88 |
| Q5 | UC-1 | Notification on drift | decided | out of scope; exit 3 and JSON | #615 |
| Q6 | UC-1 | Self-rotation mode | deferred | to UC-1b | |
| Q7 | UC-1 | One secret per account or per application | decided | per application, a field per account | #85 |
| Q8 | UC-1 | Does `apply` create a missing account? | decided | no; account creation is UC-4 | #615 |
| Q9 | UC-1 | Time source for password age | decided | the vault's `rotated_at` | #87 |
| H1 | UC-2 | Where a personal account is declared | decided | `personal_accounts:`, by name or predicate | #449 |
| H2 | UC-2 | What a reset records, and where | decided | the database, a metadata record, nothing for rollback | #450 |
| H3 | UC-2 | The noun and the verbs | decided | `account reset-password`, `account expire-password` | #451 |
| H4 | UC-2 | Verify, unlock, or end a rollover window? | decided | no verify; unlock timed locks; end the window | #455 |
| H5 | UC-2 | Is self-service part of UC-2? | decided | no | #452 |
| H6 | UC-2 | How an estate restricts delivery methods | decided | `allowed_methods`, by intersection | #453 |
| H7 | UC-2 | A reset never converges | decided | outside invariant 9 by scope | #454 |
| H8 | UC-2 | The stored copy on the unseen path | decided | split by method | #459 |
| H9 | UC-2 | What "unseen" guarantees on `vault_wrapped` | decided | attribution, not access | #496 |
| H10 | UC-2 | Does a reset check that the database audits it? | decided | it records `audited` as `true`, `false` or `unknown`; no warning, no refusal | #591 |
| ADR-001 | ADR | Oracle privilege model | decided | direct `ALTER USER`, no definer-rights package | |
| ADR-002 | ADR | CLI framework | decided | click | |
| ADR-003 | ADR | Text tables | decided | click only, formatted by hand | #15 |
| ADR-004 | ADR | YAML parser | decided | PyYAML, hardened | |
| ADR-005 | ADR | HashiCorp Vault client | decided | the HTTP API over `httpx` | #103 |
| ADR-006 | ADR | Optional dependencies | decided | vendor clients are extras; base opens no sockets | #130 |
| ADR-007 | ADR | The vault token flag | decided | `--vault-token-file PATH` | #145 |
| ADR-008 | ADR | Contribution provenance | decided | DCO sign-off, no CLA | #370 |

Closed decision issues with no ID are not listed here. Each has a record in the
[decision log](decisions/log.md), named by its issue number.

## Verify before implementing

This register lists the questions that need a real database, or a real service,
to answer. Each entry has a status and a slug. Other documents point back to an
entry with the slug, as §Conventions describes. `tests/test_verification_register.py`
reads this section, so the two code spans at the start of each entry are
structure, not decoration.

A `verified` entry was answered by a run, and gives the answer. An `unverified`
entry is not fully answered. It gives what is known and what is still open, and
where the answer is unknown, the code refuses rather than guesses.

There is no partial status. A question whose parts are answered separately is
split into entries that each settle whole.

The status is this register's, not GitHub's. The issue an entry names can be
closed while the measurement is still open: #87, #383 and #387 are. Release-by-release results are in
[measurements.md](measurements.md); an entry here does not list releases.

### Verifiers and grants

- `verified` `t-verifier` (#90) — **Can a client regenerate the `T:` (12C)
  verifier in `SYS.USER$.SPARE4`?**
  Yes. The verifier is `SHA-512(PBKDF2-HMAC-SHA512(pw_utf8, salt ‖
  "AUTH_PBKDF2_SPEEDY_KEY", 4096, 64) ‖ salt)`, where `pw_utf8` is the UTF-8 of
  the password as the database holds it, after conversion to its character set.
  A rollover window's two verifiers, `T:` for the old password and `t:` for the
  new one, are told apart the same way. `sql/oracle/05_verifier_layout_probe.sql`
  reads the layout and `06_verifier_reproduce.{sql,py}` reproduces it. The
  comparison uses `T:` only. An account with no `12C` verifier fails at plan
  time (invariant 4, #433); the gate is a per-account capability, never a
  version. `check --method hash|both` depends on this (#437); the default
  method, `login`, does not (#86). Not claimed on 12.1, which is unmeasured.
- `verified` `lcount-grant` (#124) — **Does `SELECT_CATALOG_ROLE`, through
  `SYS.KU$_USER_VIEW`, expose `LCOUNT` without `SPARE4`?**
  Yes, on the one release measured. To a session with the role enabled, the view
  shows every user's `LCOUNT` and `PTIME`, and `SPARE4` as one space.
  `EXP_FULL_DATABASE` does not unmask the verifiers; a direct `SELECT` grant on
  `SYS.USER$` beside the role does. With no role enabled the view shows no
  rows. `SYS.KU$_USER_BASE_VIEW` does not exist there.
  `sql/oracle/16_lcount_grant_probe.sql` measures it, and
  `02-oracle-privileges.md` §2 has the rest of the result. The tool does not
  use the role ([#124](decisions/log.md#124)), so nothing depends on this
  answer, on this release or any other.

### Connections and wallets

- `unverified` `adb-external-auth` (#471) — **Can `auth: external` work against
  an OCI Autonomous Database, after `mkstore -createCredential` adds a
  credential to the downloaded wallet?**
  Known: the wallet zip holds TLS certificates and no credential, so
  `auth: external` with an unchanged wallet has nothing to log in with. Open: the
  repair is untried. The `mkstore` line in `maintainer-environments.md` §6 is
  Oracle's documented syntax, not a command run here. The tool has run against
  an Autonomous Database with a password from the vault (#479), which is
  unaffected. Nothing in the default path depends on this.
- `verified` `nne-oci-default` (#575) — **Does OCI's Base Database Service
  require Native Network Encryption as provisioned?**
  Yes. The shipped `sqlnet.ora` sets
  `SQLNET.ENCRYPTION_SERVER=REQUIRED` and `SQLNET.CRYPTO_CHECKSUM_SERVER=REQUIRED`.
  A thin-mode connection is refused with `DPY-3001`, and a thick-mode one
  negotiates AES256 and SHA256 with no client configuration
  (`maintainer-environments.md` §5). Exadata Cloud is not part of this entry. Its
  requirement is cited from Oracle's documentation, no run of it is planned, and
  a sentence that names it says "documented, not measured" instead of carrying a
  marker. The local `nne` compose profile is an approximation and is
  unrun. This is one of D3's reasons for thick mode (`design/00-principles.md`,
  *Why thick mode*).
- `verified` `adb-thin-mode` (#575) — **Does Autonomous Database use TLS rather
  than Native Network Encryption, and accept a python-oracledb thin-mode
  connection?**
  Yes to both. Thin mode connects through the wallet over `tcps`, and no NNE is
  negotiated in either mode (`maintainer-environments.md` §6). Thin mode needs
  the wallet's download password, because it reads the encrypted `ewallet.pem`
  and not the auto-login `cwallet.sso`. No change to behaviour: the tool has one
  mode, thick.
- `verified` `session-encryption` (#697) — **Can a session tell whether its own
  connection is encrypted, and does that need a grant?**
  Yes, and no grant on any release measured: 23.26.2.0.0, 21.3.0.0.0,
  18.4.0.0.0, 19.3.0.0.0, 12.2.0.1.0 and 11.2.0.2.0. `NETWORK_PROTOCOL` is
  `tcps` on a TLS connection. With NNE, `V$SESSION_CONNECT_INFO` has a row that
  names the algorithm, and `PUBLIC` reads that view. TLS did not run on
  11.2.0.2.0. `sql/oracle/12_connection_encryption_probe.sql` measures it, and
  `design/02-oracle-privileges.md` §2 says how `doctor` reads it.

### Password text kept by Oracle

These entries share a setup. The probe is
`sql/oracle/02_password_leak_probe.sql` and its extensions are
`sql/oracle/04_password_leak_extensions.sql`. The findings are in
`design/02-oracle-privileges.md` §4 and `design/04-testing.md` §6 gate 2.

- `unverified` `ddl-text-versions` (#387) — **Does `ALTER USER` text leak the
  password into the shared pool on the releases not yet run?**
  On every release measured, `V$SQL` holds no cursor for the `ALTER USER`, and
  an anonymous PL/SQL block that carries the password as a literal leaks it.
  That is invariant 13. On 11.2.0.2.0, `V$SQLSTATS` also keeps the plain
  `ALTER USER` text. 12.2.0.1.0 and every later release measured keep nothing,
  so the change is somewhere after 11.2 and no later than 12.2. Open: 12.1 is
  unrun. Read the 11.2 result as "11.2 keeps it", never as "every older release
  keeps it".
- `unverified` `ddl-text-awr` (#387) — **Does the kept text reach AWR?**
  On 19.32.0.0.0, with the Diagnostics Pack enabled, the wrapped literal (C3)
  reached `DBA_HIST_SQLTEXT` and stayed there. The `ALTER USER` that sopuli
  issues (C2) did not, because it has no cursor to capture. Open: 11.2, where
  `V$SQLSTATS` keeps the plain `ALTER USER`. Answering it needs an 11.2
  database with the Diagnostics Pack. The only 11.2 image in the test stack is
  11g XE, which sets `control_management_pack_access = NONE`, so it cannot
  answer it.
- `verified` `ddl-text-trace` (#407) — **Does a traced session capture the
  password?**
  No. At 10046 level 12 the cursor is written cut short, as
  `ALTER USER sopulitest IDE`, one character into `IDENTIFIED`. The wrapped
  form leaks in full, which is invariant 13 again. The same run answered three
  other surfaces. The OS audit trail masks the statement on 21c, and on 26ai no
  user DDL reaches it. Self-rotation and `IDENTIFIED BY VALUES` are masked.
- `unverified` `expire-ddl-text` (#438, #457) — **Is `ALTER USER … IDENTIFIED BY
  … PASSWORD EXPIRE` kept or masked the same way as the bare `IDENTIFIED BY`?**
  Not run. Gate 2's probe issues only the bare form, so every result in
  `design/02-oracle-privileges.md` §4 is a result for that statement. Oracle
  keys its masking to the statement type, which gives no reason to expect the
  suffix to change it, but that is not a measurement. UC-2's seen (`manual`)
  reset issues the suffixed form. Open: extend the probe to that form and run it
  on 26ai and 21c first. The unseen reset issues the bare form and is covered by
  `ddl-text-versions`.

### Password limits and dates

- `unverified` `password-byte-limit` (#383) — **What is the longest password on
  each release from 12.1 to 23ai?**
  30 bytes on every release measured before 23.26, and 128 bytes on
  23.26.2.0.0. 12.2 raised the identifier limit to 128 bytes, but the password
  limit did not move with it. The tool keys the limit to
  `LONG_PASSWORD_FLOOR = (23, 0)` in `src/sopuli/driver/oracle/limits.py`
  (#595). Below it, `creds generate` refuses at plan time, with exit 9, a policy
  whose password can be longer than 30 bytes. `23` is the only floor the tool can express, because
  `V$INSTANCE.VERSION` reads the base release: every 23ai and 26ai reads
  `23.0.0.0.0`. Open: a 23ai release before 23.26 is unmeasured and reads the
  same as 26ai. 12.1 is unmeasured, but the 30-byte limit applied to it is the
  safe direction. Whether the old limit is 30 bytes or 30 characters has only
  been run with ASCII, and every password that `01-configuration.md` §8 draws is
  ASCII.
- `unverified` `pw-changed-source` (#87, #386) — **Is `SYS.USER$.PTIME` the
  password change date on the releases not yet run?**
  `DBA_USERS.PASSWORD_CHANGE_DATE` exists from 19c and is absent on 18c, 12.2
  and 11.2. Where both exist, `PTIME` equals the column and moves with
  `ALTER USER … IDENTIFIED BY`; `CTIME` does not move. Where the column is
  absent, the tool falls back to `PTIME` behind the optional grant, and warns
  with `SOPULI-W021` when neither answers (#386). Open: 12.1 would take the
  fallback and is unmeasured. This is a display question only: Q9 decided that
  `--max-age-days` reads only the vault.

### Rollover windows

- `verified` `expire-rollover` (#438, #461) — **What does `ALTER USER …
  IDENTIFIED BY … PASSWORD EXPIRE` do to an account whose profile sets
  `PASSWORD_ROLLOVER_TIME`?**
  UC-2's seen (`manual`) reset is that statement. The unseen reset issues no
  expiry and is unaffected. The result depends on the account's status before
  the statement (`sql/oracle/07_lock_and_rollover_probe.sql` Q7 and
  `09_reset_from_expired_probe.sql`):

  - from `OPEN` or `EXPIRED(GRACE)`: the statement is accepted, the status
    becomes `EXPIRED & IN ROLLOVER`, and the expiry does not end the window. The
    old password answers `ORA-28001`, so it still authenticates;
  - from `EXPIRED` or `EXPIRED & IN ROLLOVER`: no window opens, and every
    earlier password answers `ORA-01017`;
  - from `EXPIRED & LOCKED(TIMED)`: a reset's `ACCOUNT UNLOCK` leaves
    `EXPIRED`, and the statement then behaves as it does from `EXPIRED`;
  - from `OPEN` or `EXPIRED(GRACE)`, followed by `EXPIRE PASSWORD ROLLOVER
    PERIOD`: the close ends the window, and the old password answers
    `ORA-01017`.

  So the exposure depends on whether the old password still authenticates, not
  on whether the status reads `EXPIRED`. UC-2 §4.3's seen reset closes the
  window after the set, so it leaves one live password from every start state
  measured (#541). Not measured on a 19c release that has rollover.
- `unverified` `stale-rollover` (#441) — **What does an open rollover window do
  when its profile's `PASSWORD_ROLLOVER_TIME` is set back to zero?**
  On 23.26.2.0.0, `ACCOUNT_STATUS` still reads `OPEN & IN ROLLOVER`, but the old
  password already answers `ORA-01017`. `EXPIRE PASSWORD ROLLOVER PERIOD` is
  accepted in that state and returns the account to `OPEN`. The driver closes
  the window on either signal, the profile's setting or an open window. That is
  correct whatever the answer on other releases, so nothing waits on this entry.
  Open: 19c and 21c.

### PostgreSQL

These entries are for the PostgreSQL driver, which runs UC-1's commands. The
probes are in `sql/postgres/`, and the matrix of releases 13 to 18 is the
`postgres-matrix` profile of `test/compose.yaml`. A major release named here,
such as "from 16", means the one release of it that was measured.
[measurements.md](measurements.md) names each in full.

- `verified` `pg-password-text` (#1032) — **What does PostgreSQL keep of the
  text of `ALTER ROLE … PASSWORD`?**
  The whole text, in every place measured, with a SCRAM verifier or a plaintext
  password. With `log_statement = all` the server log keeps it, and
  `pg_stat_statements` keeps it whatever `log_statement` says. Under the default
  `log_statement = none`, the log still keeps the text of a statement that
  fails, because `log_min_error_statement` is `error`. `pg_stat_activity` shows
  an idle session's last statement, password included. So a password that
  reaches the server in the statement is kept in clear. A verifier computed on
  the client is kept too, and it still allows an offline guessing attack.
  `sql/postgres/01_password_text_probe.sql` measures it.
- `verified` `pg-system-identifier` (#1032) — **Can a role that is not a
  superuser read `system_identifier` from `pg_control_system()`?**
  Yes, with no grant and no `pg_monitor` membership. The function has the
  default ACL, `EXECUTE` for `PUBLIC`. A site that revoked it is not measured.
  `sql/postgres/02_system_identifier_probe.sql` measures it.
- `verified` `pg-createrole-password` (#1032) — **What does a `CREATEROLE` role
  need before it can change another role's password?**
  On 13 to 15, `CREATEROLE`, and the role must not be a superuser. From 16 it
  also needs `ADMIN OPTION` on the role. `GRANT … WITH ADMIN OPTION, INHERIT
  FALSE, SET FALSE` is enough. The catalog shows the answer without trying the
  change: `pg_roles.rolcreaterole`, the role's `rolsuper`, and
  `pg_auth_members.admin_option`, which `pg_has_role(…, 'USAGE WITH ADMIN
  OPTION')` agrees with. `CREATEROLE` with `ADMIN OPTION` is accepted on every
  release measured. From 16, a role that creates another gets `ADMIN OPTION` on
  it. A refusal is SQLSTATE `42501`. `ALTER ROLE … NOLOGIN` needs the same
  grants on every release measured (#1201).
  `sql/postgres/03_createrole_password_probe.sql` measures it.
- `verified` `pg-md5-line-scram` (#1032) — **Does a SCRAM verifier stored on a
  server with `password_encryption = md5` log in through a `pg_hba.conf` line
  that says `md5`?**
  Yes, and the login uses SCRAM. A client that speaks only md5 cannot log in as
  that role. `password_encryption` chooses only how the server hashes a
  plaintext password, and a verifier is stored as sent. 18 warns that md5
  passwords are deprecated. The `postgres:13` image ships with
  `password_encryption = md5` and an `md5` line.
  `sql/postgres/04_md5_line_scram_verifier_probe.py` measures it.
- `verified` `psycopg-libpq` (#1032) — **Which libpq do psycopg's binary wheels
  bundle on Windows and Linux, and does it accept
  `require_auth=scram-sha-256`?**
  It follows when the wheel was built. psycopg 3.3.6 bundles libpq 18 on
  Windows AMD64 and on Linux x86_64, glibc and musl. Earlier wheels bundle
  earlier libpq: 3.2.13 has 17, 3.1.20 and 3.1.12 have 16, 3.1.4 has 15 and
  3.0.18 has 14. From 3.1.12 every wheel measured accepts
  `require_auth=scram-sha-256`. 3.1.4 and 3.0.18 refuse it in the client, as
  an invalid connection option. Every wheel computes a SCRAM verifier with
  `PGconn.encrypt_password`. So `require_auth` depends on the libpq a wheel
  bundles, and `psycopg.pq.version()` reports the libpq a process loaded.
  `sql/postgres/05_psycopg_libpq_probe.py` measures it.
- `verified` `pg-connect-sqlstate` (#1040) — **Does a failed PostgreSQL login
  reach the client with its SQLSTATE?**
  No. With psycopg 3.3.6 and libpq 18.4 on Windows, against 13.23, 14.24,
  15.19, 16.15, 17.11 and 18.6, `sqlstate` is `None` for every failed login.
  The server's `FATAL:` text is the same on all six: `password authentication
  failed for user`, `role "…" is not permitted to log in` and
  `database "…" does not exist`. A role that does not exist reads as a wrong
  password, because the server does not say which. So
  `src/sopuli/driver/postgres/errors.py` reads that text for `28P01`, `28000`
  and `3D000`, and reports any other failed connection as `08001`. The text is
  English, the server's default `lc_messages`. Measured by hand, with no probe
  script. A missing `pg_hba.conf` line was not measured.
- `verified` `pg-saslprep` (#1057) — **Does a SCRAM verifier computed on the
  client log in with a non-ASCII password?**
  Yes, where every client runs SASLprep. A verifier from libpq 18.4 and the
  server's own hash of the plaintext give the same result on 13 to 18. Each
  password logs in with psycopg and with psql of the server's release, whose
  libpq is that release's too (the `-alpine` images), and so
  does the other spelling SASLprep makes the same: e with acute composed and
  decomposed, the fi ligature and f i, a no-break space and a space, a soft
  hyphen and nothing. A password with a character SASLprep prohibits, such as
  a private-use character or one newer than Unicode 3.2, is used as given and
  logs in. A client that skips SASLprep disagrees: a verifier computed over the
  bytes as given refuses both spellings of a password SASLprep changes, unless
  it was computed from the spelling SASLprep gives. So whether a non-ASCII
  password logs in depends on the application's client, which the tool cannot
  see. Only libpq clients were measured. The policy's named charsets are ASCII;
  `charset: custom` and `--from-stdin` can give a non-ASCII password.
  `sql/postgres/06_saslprep_probe.py` measures it.
- `verified` `pg-password-length` (#1057) — **What is the longest password
  that PostgreSQL accepts, set as a verifier?**
  The server sets none up to 1 MiB, and the client may. libpq 18.4 computes a
  133-byte verifier at every length from 12 bytes, and the password logs in
  with psycopg on 13 to 18. psql with libpq 14 to 18 logs in at every length
  it was run with, up to 8192 bytes. **libpq 13 cannot log in with a password
  longer than 1024 bytes**: it fails before it sends anything, with "out of
  memory", ASCII or not. So an application whose client has libpq 13 cannot
  use a longer password that the driver sets. No password one character short
  logged in, so no client cut one short. Only a plaintext password in
  `ALTER ROLE` has a server limit: 13 refuses one over 1024 bytes with
  SQLSTATE `54000`, and 14 to 18 accept 1 MiB. The login time grows with the
  length on every client, because libpq's PBKDF2 hashes the whole password in
  each of its 4096 iterations: 0.1 s or less up to 8192 bytes, under 1 s at
  65536 and about 10 s at 1 MiB, at each login. Clients other than libpq were
  not measured. `sql/postgres/07_password_length_probe.py` measures it.
- `unverified` `psycopg-libpq-macos` (#1032) — **Which libpq does psycopg's
  binary wheel bundle on macOS?**
  Not run: there is no macOS host. Linux arm64 is not run either. The libpq 16
  floor ([#1076](decisions/log.md#1076)) depends on the answer: a wheel that
  bundles an older libpq would reach the refusal that #1076 accepts only
  because the measured installs cannot.

### MySQL

These entries are measured before a MySQL driver is designed (#1202). The
probes are in `sql/mysql/`, and the matrix of 8.0, 8.4 and 9 is the
`mysql-matrix` profile of `test/compose.yaml`.
[measurements.md](measurements.md) names each release in full.

- `verified` `mysql-password-text` (#1202) — **What does MySQL keep of the text
  of `ALTER USER … IDENTIFIED BY`?**
  Once the statement parses, the server replaces the password with `<secret>`
  in the general log, the slow log, and `performance_schema`'s statement
  history and digest sample, also for a statement that fails when it runs. The
  binary log keeps a statement that succeeded, rewritten with the stored
  `caching_sha2_password` hash. A statement that fails to parse stays in
  `performance_schema.events_statements_history` as sent, password included.
  A server started with `--log-raw` was not measured.
  `sql/mysql/01_password_text_probe.sql` measures it.
- `verified` `mysql-client-hash` (#1202) — **Can the tool compute a
  `caching_sha2_password` hash, and set it so that the password logs in?**
  Yes. The hash is SHA-crypt with SHA-256 and a 20-byte salt, stored as `$A$`,
  the rounds, the salt and the digest. A hash computed in Python agrees with the
  server's own. One with a salt the tool draws is set with `IDENTIFIED WITH
  caching_sha2_password AS 0x…` by an account that holds only `CREATE USER`, and
  the password logs in, at 5,000 or 10,000 rounds. The server refuses a value
  of the wrong form, `1827`, but cannot tell whether it matches a password.
  `mysql_native_password` works on 8.0.46 only: 8.4.13 ships it disabled and
  9.7.4 has none. `sql/mysql/02_client_hash_probe.py` measures it.
- `verified` `mysql-dual-password` (#1202) — **Does `RETAIN CURRENT PASSWORD`
  give UC-1 a rollover window, and can its state be read?**
  Yes, as long as the account's plugin stays the same: a `RETAIN` that changes
  it is refused, `3894`. The old and new passwords both log in, with
  `IDENTIFIED BY` or with a hash the client computed. A second `RETAIN`
  replaces the retained password, a change without `RETAIN` keeps it, and
  `DISCARD OLD PASSWORD` ends it, also when nothing is retained. The state is
  the key `additional_password` in `mysql.user`'s `User_attributes`, which an
  account with only `CREATE USER` cannot read, and `SHOW CREATE USER` does not
  show. `sql/mysql/03_dual_password_probe.py` measures it.
- `verified` `mysql-lock-expiry` (#1202) — **How do a lock, an expiry and a
  timed block read back, and what does each answer at login?**
  `ACCOUNT LOCK` reads back as `mysql.user.account_locked = 'Y'`, and the
  password then answers `3118`. `PASSWORD EXPIRE` reads back as
  `password_expired = 'Y'`; the account logs in, `SELECT 1` answers `1820`,
  and `ALTER USER USER()` sets its own password. Other statements were not
  tried. A block from `FAILED_LOGIN_ATTEMPTS`
  answers `3955`, also to the right password, and nothing in `mysql.user`
  shows it. Other places, such as `performance_schema`, were not measured.
  `ACCOUNT UNLOCK` ends a lock and a block. An account with only `CREATE USER` does all of these.
  `sql/mysql/04_lock_expiry_probe.py` measures it.
- `verified` `mysql-identity` (#1202) — **What is one MySQL account?**
  A user name and a host pattern. One name at several hosts is several
  accounts, each with its own password, and which one a login uses depends on
  how the client connects. A name with no host means `'%'`. User names are
  case-sensitive and host names are not, so `Acme_App` and `acme_app` are two
  accounts, which invariant 5's `upper()` comparison would take as one.
  `sql/mysql/05_identity_grants_probe.py` measures it.
- `verified` `mysql-tool-grants` (#1202) — **What is the least privilege that
  changes other accounts' passwords, and what keeps it off the administrative
  ones?**
  `CREATE USER` alone changes, locks, expires and drops other accounts.
  `SYSTEM_USER` keeps it off root and `mysql.sys`, which hold it, as long as
  the tool account does not: root's password, and a lock on either, are
  refused, `1227`. With `SYSTEM_USER` it changes root's password. The other
  `mysql.*` system accounts hold `SYSTEM_USER` too, and were not tried. An
  administrative account without `SYSTEM_USER` is not protected. With
  `CREATE USER` alone, reading `mysql.user` is refused, `1142`, and so is
  `SHOW CREATE USER`, `1044`. A column grant on `mysql.user` reads lock and
  expiry, away from the hashes; a retained password's state is only in
  `User_attributes`, beside its hash.
  `sql/mysql/05_identity_grants_probe.py` measures it.

### MariaDB

These entries are measured before the MySQL driver is built, so that its
capabilities assume nothing MariaDB breaks (#1220). MariaDB gets a driver of
its own after MySQL (decision 2 of #1202). The probes are in `sql/mariadb/`,
and the matrix of 10.11 and 12.3 is the `mariadb-matrix` profile of
`test/compose.yaml`. [measurements.md](measurements.md) names each release in
full.

- `verified` `mariadb-password-text` (#1220) — **What does MariaDB keep of the
  text of a password change?**
  The password, in clear. The general log, the slow log and
  `performance_schema`'s statement history keep `CREATE USER` and `ALTER USER
  … IDENTIFIED BY '…'`, `SET PASSWORD … = PASSWORD('…')` and `USING
  PASSWORD('…')` as sent, also when the statement fails. The binary log keeps
  all of these but `SET PASSWORD` as sent. Only a value the client computed,
  `IDENTIFIED VIA <plugin> USING '<value>'`, keeps the password out of every
  place. `sql/mariadb/01_password_text_probe.py` measures it.
- `verified` `mariadb-client-hash` (#1220) — **Can the tool compute the
  stored value, and set it so that the password logs in?**
  Yes, for `mysql_native_password`, `ed25519` and `parsec`. `ed25519` stores
  the Ed25519 public key whose seed is the password; `parsec` stores a salt
  and the public key whose seed is PBKDF2-HMAC-SHA512 of the password. Values
  computed in Python agree with the server's, an account with only `CREATE
  USER` sets them with `IDENTIFIED VIA … USING`, and the password logs in. A
  malformed value is refused with the plain `1396`. Only
  `mysql_native_password` is loaded by default: `ed25519` must be installed,
  and `parsec` too, on 12.3 only. `caching_sha2_password` does not exist.
  Whether PyMySQL logs in on `ed25519` and `parsec` was not measured.
  `sql/mariadb/02_client_hash_probe.py` measures it.

### Vault

- `verified` `vault-cas-conflict` (#103, #104) — **What does a real Vault's
  compare-and-set conflict look like on the wire?**
  On `hashicorp/vault:2.0.4`, every lost compare-and-set is a 400 with the body
  `{"errors": ["check-and-set parameter did not match the current version"]}`,
  whatever caused it. A malformed `cas` is a different 400, `"error parsing
  check-and-set parameter"`. `CAS_MESSAGE_FRAGMENT` in
  `src/sopuli/store/hashicorp/_errors.py` matches the first string.
  `tests/store/test_hashicorp_cas_conflict.py` checks it against a running Vault
  and skips when there is none. The probe is `test/vault_cas_probe.py`.
- `verified` `vault-client` (#103) — **Which HashiCorp Vault client?**
  The HTTP API directly, over `httpx`, and not `hvac`. The reasons and the
  measurements are in [ADR-005](decisions/adr-005-vault-client.md). `httpx` is in
  the `sopuli-dba[hashicorp]` extra, not in base (ADR-006, E2). The probe is
  `test/vault_auth_probe.py`.
- `verified` `oci-vault-cost-limits` (#643, #1135) — **Do the OCI Vault tests
  in tier 3 still cost nothing?**
  Yes. The tenancy's cost analysis, read on 2026-10-30 for 1 to 30 October,
  holds the tier-3 runs of #1129 to #1164 on 28 and 29 October, among them one
  secret filled to its 30 versions. It lists every service the tenancy used,
  at a cost of zero where it is free, and it has no line for Vault, Key
  Management or Secrets, in cost or in usage.
  The vault is a default vault, its key is software-protected, and no secret
  is replicated. Oracle's pages on 2026-10-14 said the same: Secret Management
  free, a software-protected key free, and API calls to Key Management not
  billed (T4). The version limit is `oci-version-limit` below.
- `verified` `oci-name-rules` (#1129) — **What may an OCI secret name hold,
  how long can it be, and is it case-sensitive?**
  Letters, digits, `-`, `_` and `.`, in any position, leading, trailing or
  doubled. `/`, `@`, a space and `~` are refused with `400 InvalidParameter`.
  Up to 255 characters; at 256 OCI answers `400 InvalidParameter`. Names are
  case-sensitive: `acme-db` and `ACME-DB` can both exist in one vault. The
  probe is `test/oci_vault_probe.py`, M1 and M1b.
- `verified` `oci-pending-stage` (#1129) — **Can a reader see a PENDING
  version?**
  Only by asking for it. After an update with `stage = PENDING`, a read by name
  with no stage, or with `stage=CURRENT`, returns the old CURRENT version. Only
  `stage=PENDING` returns the new one. M2.
- `verified` `oci-etag-cas` (#1129) — **Does an ETag guard an OCI secret
  update?**
  Yes. An update whose `if_match` is a stale ETag is refused with
  `409 Conflict`, not 412. A content update, a PENDING update, a promotion and
  a metadata-only update each change the ETag. M3.
- `verified` `oci-updating-state` (#1129) — **Can a secret be updated again
  straight after an update?**
  No. It is `UPDATING` for a little over 20 seconds, and an update meanwhile
  is refused with `409 IncorrectState`. The probe measured 19.9 and 21.7
  seconds from a point after the update returned, so the window is longer than
  that. M4.
- `verified` `oci-promote-metadata` (#1129) — **Do a promotion and a metadata
  change happen in one call?**
  Yes. `current_version_number=N` with `metadata` in the same update makes N
  CURRENT, makes the old CURRENT PREVIOUS, and changes the metadata. The
  metadata sent replaces the whole map, so an update must send every key it
  keeps. Promoting the CURRENT version changes only the metadata. A version
  that does not exist
  is `404 NotAuthorizedOrNotFound`. OCI also promotes a DEPRECATED version
  without complaint. M5.
- `verified` `oci-pending-replace` (#1129) — **What happens to a PENDING
  version, and can it be removed?**
  A second PENDING makes the first DEPRECATED. A CURRENT update leaves a
  PENDING in place. Scheduling the deletion of a PENDING version is refused with
  `409 IncorrectState`. Of the calls tried, only a promotion or a newer PENDING
  takes the stage off a version, so a secret that has had a PENDING keeps one
  until it is promoted. M6.
- `verified` `oci-version-limit` (#1129) — **How many versions does a secret
  keep?**
  30. The create makes version 1. The content update that would make version
  31 is refused with `400 LimitExceeded`, and OCI removes no version by itself. A metadata-only update adds no version.
  Scheduling the deletion of a DEPRECATED version frees its place at once: the
  next content update succeeds. M7, M7b and M7c.
- `verified` `oci-create-pending` (#1151) — **Can a secret be created with its
  only version in PENDING?**
  No. `CreateSecret` with `stage = PENDING` is refused with
  `400 InvalidParameter: stage must be one of CURRENT.` A secret's first version
  is always CURRENT. M9.
- `verified` `oci-create-taken` (#1151) — **What does a create answer for a
  name that is already held?**
  `400 InvalidParameter: name already exists`, not a 409. The answer is the same
  when the name belongs to a secret scheduled for deletion, both while it is
  `SCHEDULING_DELETION` and once it is `PENDING_DELETION`, which followed
  within 20 seconds. M10.
- `verified` `oci-create-state` (#1151) — **Is a new secret ready at once?**
  No. A create answers `CREATING`, and an update in that state is refused with
  `409 IncorrectState`. It was `ACTIVE` 20.8 and 18.7 seconds after the create
  answered. Scheduling a version's deletion makes the secret `UPDATING`, and it
  was `ACTIVE` 19.7 and 21.8 seconds later. M11.
- `verified` `oci-metadata-limits` (#1151) — **What may a secret's metadata
  hold?**
  About 5,100 characters for the whole map, counted in characters, not bytes.
  Under a 12-character key, one ASCII value of 5,101 characters is accepted
  and 5,159 is refused; two values of 2,629 characters each are refused
  together; 5,101 two-byte characters are accepted. The refusal is
  `400 InvalidParameter: metadata exceeds max allowed size`. A list, a nested
  object and an integer are accepted and read back as sent. A read by name
  carries the same metadata as `GetSecret`. M12.
- `verified` `oci-read-while-updating` (#1151) — **Does a read see a write
  straight away?**
  No. A read by name made while the secret is `UPDATING`, after an update that
  changed the content and the metadata, returns the old version and the old
  metadata. Once it is `ACTIVE`, the read returns both new. So a read's content
  and its write counter always belong together. M13.
- `verified` `oci-etag-settle` (#1133) — **Is the ETag read when a secret
  turns ACTIVE the one the next update must send?**
  Not always. The ETag moves once more 2.2 to 5.4 seconds after the secret is
  `ACTIVE`, with no field of the secret changing, and an update sent with the
  ETag read at the moment of `ACTIVE` is refused with `409 Conflict`. So a
  `409 Conflict` alone does not prove that somebody else wrote. M14.
- `verified` `oci-read-while-creating` (#1152) — **Can a new secret be read
  by name at once?**
  No. While it is `CREATING`, a read by name is refused with
  `404 NotAuthorizedOrNotFound`, though `ListSecrets` already lists it as
  `CREATING`. Once it is `ACTIVE`, the read returns version 1. M15.
- `unverified` `moto-secrets-manager` (#642) — **Does moto's server image cover
  every Secrets Manager call an AWS store makes?**
  Known: moto is open source, `motoserver/moto` needs no token, and it emulates
  Secrets Manager (T3). Open: whether it serves each call the store makes,
  checked against the image itself and not its documentation. The pull request
  that builds an AWS store answers it. No AWS store exists yet, so nothing
  depends on this.

### 1Password

No 1Password store exists. These answer #1193, whether one could. The probe is
`test/onepassword_store_probe.py`, run against `onepassword-sdk` 0.4.2.

- `verified` `onepassword-item-cas` (#1193) — **Does an item update refuse a
  write when the item has changed since it was read?**
  Yes. `Items.put` succeeds only when the item's `version` is the current one.
  A version behind, ahead or 0 is refused with `The submitted item is not up to
  date`, even when the stale write changes only a field the other write did not
  touch. Of two puts of one version sent at once, one succeeds and the other is
  refused with `data conflict occurred on the server`. Both are plain
  `Exception`, so the message is the only way to know a conflict. A put that
  changes nothing still makes a new version. S1.
- `verified` `onepassword-item-history` (#1193) — **Can the SDK read an
  earlier version of an item?**
  No. `Items.get` takes a vault and an item id only, and a secret reference
  refuses `?version=` and `?revision=` as unknown query keys. S2.
- `verified` `onepassword-stages` (#1193) — **Can `pending` and `current` be
  two fields of one item, promoted in one write?**
  Yes. One put changed both fields under one new version. Field ids with a
  space, `_`, `-`, `.` or a digit were accepted, and one with `/` was refused.
  The notes field holds JSON and reads back as written. S3.
- `verified` `onepassword-titles` (#1193) — **Is an item title a unique key?**
  No. A second item with an existing title is created without complaint, and a
  secret reference to that title then fails with `more than one item matched`.
  A reference matches a title without regard to case. It can name only a title
  of letters, digits, `_`, `.`, `-` and spaces: a title with `/`, `@` or `=`
  can be created, and cannot be named by a reference. S4.
- `verified` `onepassword-rate-limits` (#1193) — **What does a store call cost
  against a service account's limits?**
  A get or a secret reference read costs 1 read. A put costs 1 write and 2
  reads, so 3 against the daily limit. Listing a vault's items cost nothing.
  `op service-account ratelimit` reported 100 writes and 1,000 reads an hour
  for the token, and 1,000 requests a day for the account. 1Password publishes
  those for its 1Password and Families plans, with 5,000 a day for Teams, and
  1,000 writes, 10,000 reads and 50,000 a day for Business. S6.
- `verified` `onepassword-errors` (#1193) — **Can the SDK's errors be told
  apart?**
  Only by their messages. Every failure the probe met is a plain `Exception`.
  No run reached a rate limit, for which the SDK's source raises
  `RateLimitExceededException`. A missing item reads `item couldn't be found`,
  a deleted one `item is not in an active state`, and a get in a missing vault
  `vault couldn't be found`, though a list of the same vault reads `item
  couldn't be found`. A service account sees only the vaults it was granted,
  so a vault it may not read looks like one that does not exist. S7.

## Next use cases

None of these is specified. Each has a number so that work deferred from a
specified use case can name where it goes. A number does not change once it is
written down, because documents, issues and pull requests cite it. A new use case
takes the next free number.

### UC-3 — run a statement across many targets

Run one statement against a selected set of targets and report what each one
returned: "run this against all twenty-one PDBs and tell me what each one said".
It would use the run document's per-target results, the same selectors, and the
same lock and safety ratchets.

The hard part is the privilege model, not the fan-out. ADR-001 rests on the
service account holding `ALTER USER` and nothing else.
`02-oracle-privileges.md` §3 lists what must never be granted, and the guardrails
in §4 exist because even `ALTER USER` reaches `SYS`. A verb that runs any SQL
needs whatever privilege that SQL needs. So it either connects as a different
principal or it breaks the model. That is the first question this use case must
answer.

Also open: whether a statement may change data or only read it; what
`--dry-run` means for SQL the tool does not understand; and what a result is
when twenty targets each return different rows.

### UC-4 — user provisioning

Creating and dropping accounts, and what an account needs in order to exist:
grants, roles, quotas, profiles, and default and temporary tablespaces.

UC-1 does none of this. A missing account is `ACCOUNT_MISSING`, a state to
report, not a failure to recover from. Invariant 5 makes the config a whitelist
of what may be touched, not a list of what should exist.

UC-1 assigns a profile (#301) and never creates or alters one. Q4 (#88) decided
this, because `ALTER PROFILE` changes a shared object and so reaches accounts
nobody selected. That reason does not apply in the same way to provisioning,
where a profile is written on purpose. So whether this use case may issue
`CREATE PROFILE` and `ALTER PROFILE` is an open question of its own, and #88
does not decide it. #88 does decide that the credential-sync verbs never do it.
If the answer here is yes, the privilege belongs to a principal this use case
defines, not to UC-1's service account.

*Deferred to it:* Q8 (`apply` does not create a missing account), the creating
and altering of profiles, UC-1 §5's default and temporary tablespace
attribute (#303), and how the tool's own service account is installed (#655).

`ALTER USER … DEFAULT TABLESPACE` moves no existing segment, so during a
rotation it is a half-change that looks complete. During provisioning the
account has no objects yet, so it is simply part of creating the account.

Installing the service account is provisioning too, and it needs SYSDBA or an
equivalent account, which the tool otherwise never holds. A DBA runs
`sql/oracle/00_install.sql` for it. [#655](decisions/log.md#655) declined an
`admin install` command. This use case decides whether provisioning covers the
install, and in what form.

### UC-5 — drift and compliance reporting across a fleet

`creds check` answers "does the vault agree with this database" for the
accounts one config declares. This use case asks the same across the estate:
which accounts exist that nobody declared, which profiles are in use, where
password versions or verifiers are older than policy allows, and what the fleet
looks like to an auditor.

It differs from UC-1 in what it may change, which is nothing.

### UC-1b — self-rotation, where there is no admin credential

`ALTER USER … IDENTIFIED BY new REPLACE old`, connecting as the account being
rotated, for estates that will not create a service account holding
`ALTER USER`. It is a variant of UC-1, with the same vault, direction and
promotion order, so it keeps UC-1's number with a `b`.

*Deferred to it:* Q6 (UC-1 §12).
