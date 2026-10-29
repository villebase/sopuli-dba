# Decision log

This file records why each small decision was made. A large decision has its
own ADR in this folder instead.

The [decision register](../README.md#decision-register) says whether a decision
is open. This file says why a closed one was decided the way it was. A
document's own decision table keeps the question and a one-line answer, and
links here for the reasons.

Each record is a section named by the decision's ID in the register. A decision
with no register ID is named by its issue number, for example `## #10`. Each
record has five fields in this order:

- **Decided:** the date, and the issue that holds the full discussion.
- **Question:** what had to be decided.
- **Decision:** the answer.
- **Why:** the reasons, including the cost that was accepted.
- **Rejected:** the other options, and why each one lost.

A record must make sense without its issue. The issue is extra depth, not the
only copy.

A pull request that closes an issue labelled `decision` adds its record here.
`tests/test_decision_log.py` checks the format, and that each record agrees with
the register.

## D1

- **Decided:** 2026-08-08
- **Question:** What is the binary called?
- **Decision:** `sopuli`. The project and its package are `sopuli-dba`.
- **Why:** The maintainer chose it as a sensible way for the tool to work.
  There was no particular reason beyond that.
- **Rejected:** No alternatives were weighed.

## D2

- **Decided:** 2026-08-08
- **Question:** What grammar does the CLI use?
- **Decision:** Noun-verb, for example `sopuli creds rotate` and
  `sopuli target list`.
- **Why:** The maintainer chose it as a sensible way for the tool to work.
  There was no particular reason beyond that.
- **Rejected:** No alternatives were weighed.

## D3

- **Decided:** 2026-08-08
- **Question:** What language is the tool written in?
- **Decision:** Python, with `python-oracledb` in thick mode, on every target.
- **Why:** Thin mode cannot be used, for three independent reasons. It does not
  support Native Network Encryption, which Base Database Service and any
  database that requires NNE refuse to do without (measured on 19.32.0.0.0,
  #575). It connects only to 12.1 and later, and 11.2 is supported. And
  `auth: external` needs the Oracle client libraries. So Instant Client must be
  installed at run time anyway. Python is also easier to review for a DBA who
  is not mainly a developer, which matters for code that handles credentials.
  `00-principles.md` P4, *Why thick mode*, has the detail.
- **Rejected:**
  - Go: its advantage is a single binary with no runtime dependencies, and
    Instant Client removes that advantage.

## D4

- **Decided:** 2026-08-08
- **Question:** What format is the configuration file?
- **Decision:** YAML. JSON is also accepted, because JSON is valid YAML.
- **Why:** The maintainer chose it as a sensible way for the tool to work.
  There was no particular reason beyond that. JSON is accepted because a YAML
  parser reads it anyway.
- **Rejected:** No alternatives were weighed.

## D5

- **Decided:** 2026-08-08
- **Question:** Is macOS a supported platform?
- **Decision:** Best effort. The code stays portable, the README claims no
  support, and there is no macOS CI.
- **Why:** Instant Client exists for macOS, including Apple Silicon, so the
  tool can run there. The problem is testing. There is no Oracle server build
  for macOS, so a Mac cannot host the full test stack locally and needs a remote
  database (`SOPULI_TEST_ORACLE_DSN`). The 11.2 test image is `linux/amd64`
  only, and Apple Silicon has only a 23.x client, which cannot reach 11.2. Excluding macOS would save nothing,
  because the code has almost nothing macOS-specific. `00-principles.md` P4 has
  the detail.
- **Rejected:**
  - A supported tier: a Mac cannot run the test stack locally, there would be
    no macOS CI behind the claim, and there is no evidence of demand.
  - Excluding macOS: saves nothing, and would have to be undone when someone
    asks.

## D6

- **Decided:** 2026-10-24, #1030
- **Question:** How are drivers and stores added: in the tree, or through a
  plugin API?
- **Decision:** In the tree, also with a second driver. An entry-point plugin
  API comes only when someone wants to ship a driver outside this repo.
- **Why:** First decided on 2026-08-08, as "in the tree until a second driver
  exists". Reviewed when the PostgreSQL driver was planned, and kept. A plugin
  API makes the driver interface a public contract. Writing
  the PostgreSQL driver will change that interface, because finding where
  Oracle's shape leaked into it is part of the work. Under a plugin API, each
  of those changes would break drivers outside the repo, and would need a
  version rule between the tool and each driver. Nobody outside the project
  writes a driver, so that cost buys nothing yet. Install extras (D9) already
  keep a driver's client out of an install that does not use it, and they
  control which dependencies are installed, not which modules exist. A
  target's `type:` reads the same either way, so a plugin API can be added
  later without changing any config.
- **Rejected:**
  - A plugin API before a second driver: it would be designed against a single
    driver.
  - A plugin API with the second driver: the interface is still changing, and
    each change would break drivers outside the repo.

## D7

- **Decided:** 2026-08-08
- **Question:** What is the oldest Oracle release the tool supports?
- **Decision:** 11.2. It was confirmed again on 2026-09-09 (#387), after the
  `V$SQLSTATS` finding.
- **Why:** 11.2 is cheap to test: `gvenzl/oracle-xe:11.2.0.2-slim` pulls freely
  and starts in seconds (T1). On 11.2 the `ALTER USER` text stays in
  `V$SQLSTATS`. Every later release measured keeps nothing
  ([measurements](../measurements.md)); 12.1 is unmeasured. 11.2 stayed in scope anyway,
  because the text ages out of the shared pool and one `FLUSH SHARED_POOL`
  clears it, and dropping 11.2 would move the rotation to SQL\*Plus, which keeps
  the same text and records nothing (P8). Apple Silicon cannot reach 11.2,
  because only the 23.x client exists there.
- **Rejected:**
  - Drop 11.2: the rotations would still happen, outside the tool.

## D8

- **Decided:** 2026-08-09
- **Question:** Which CLI framework does the tool use?
- **Decision:** click.
- **Why:** `click.testing.CliRunner` runs CLI tests in-process with no I/O, and
  click has a real exception hierarchy to map errors onto. The noun-verb grammar
  (D2) and exit code 2 on a usage error are equally easy in either candidate.
  ADR-002 has the detail.
- **Rejected:**
  - `argparse`: more verbose, and harder to test in-process.
  - `typer`: click with an implicit layer on top, which loses the explicitness
    that a reviewer who is a DBA first needs.

## D9

- **Decided:** 2026-08-18, #130
- **Question:** Which dependencies does the base install carry?
- **Decision:** Only the CLI framework, the YAML parser, `pywin32` on Windows,
  and sopuli itself. Vendor clients, for stores and database drivers, are
  install extras. The base install opens no sockets. ADR-006 holds the full
  decision, and E1 to E7 are its parts.
- **Why:** The dependency tree of a credential tool is something a security
  review reads. "Only the vendors you use" is a better answer than "all of them".
  Vendor SDKs also pin versions that can collide, and a site should not inherit
  the pins of a backend it never configured. Extras are a published interface,
  so this had to be decided before the first release.
- **Rejected:** See ADR-006.

## D10

- **Decided:** 2026-09-05, #294
- **Question:** Which confirmation prompts are built in, with no configuration?
- **Decision:** None. `safety.confirm_environments` is the only trigger, and an
  estate lists its production environments there.
- **Why:** P5 asked for three triggers, and `01-configuration.md` §9 forbids two
  of them. A built-in `[prod]` would be a floor that no layer could remove,
  because the list merges by union. That is the trap §9 uses `confirm` to
  illustrate. A prompt whenever more than one target is touched would prompt on
  every multi-target change for an estate that configured nothing, and it would
  read `max_targets` as a threshold when it is a ceiling. §9 governs, and P5 is
  reworded to match.
- **Rejected:**
  - `environment: prod` as a separate built-in trigger: the same unremovable
    floor, outside the ratchet instead of inside it.
  - All three triggers as P5 first stated them: a default install would prompt
    on any multi-target change.

## C1

- **Decided:** 2026-08-08
- **Question:** What is the section that binds accounts to secrets called?
- **Decision:** `applications`. A file whose one application applies to all
  its targets can instead put the binding keys at the top level. This inline
  form is the default shape. An application that covers only some targets needs
  `applications:`, for example in an estate that also has a CDB root for
  maintenance.
- **Why:** The common case is one application over every target, so the default
  shape is the simplest one: a file that reads like a list of targets.
  `01-configuration.md` §1 describes both forms. No reason was recorded for the
  name itself.
- **Rejected:** No alternatives were weighed.

## C2

- **Decided:** 2026-10-03, #615
- **Question:** What syntax selects targets?
- **Decision:** `--select k=v` over labels on the command line, and `match:` in
  a group. Revisit only if a real case needs negation or set membership.
- **Why:** It is what the build does, and no real case has needed negation or
  set membership.
- **Rejected:**
  - A richer expression language now: negation and set membership have no real
    case yet.

## C3

- **Decided:** 2026-10-03, #615
- **Question:** Can a secret template contain arbitrary expressions?
- **Decision:** No. A template uses a fixed list of tokens, plus labels.
- **Why:** The template is the account-to-secret mapping, which is the
  safety-critical part of the configuration. With a fixed token list, a reviewer
  can see exactly which path each account maps to.
- **Rejected:**
  - Arbitrary expressions: a reviewer would have to evaluate code to know where
    a password goes.

## C4

- **Decided:** 2026-10-14, #640
- **Question:** How does a configuration give one account in an application
  entry a different setting from the other accounts in that entry?
- **Decision:** It does not. An application entry has no per-account
  exceptions. An account that needs a different `policy`, `oracle` block or
  anything else goes in an application entry of its own. The loader refuses
  the two shapes someone would try, with a hint that says to write a second
  entry: an `accounts:` item that is a mapping, and an `account` or `accounts`
  key under `overrides[].where`, whatever the targets' labels are.
- **Why:** A second entry costs nothing to write. With a secret path of its own,
  it also gives the account its own document, and so its own promotion
  (UC-1 §5), which is usually what an account with different rules wants. A
  per-account form would add a second resolution axis to `bindings.py` and the
  §2 resolution table, beside `overrides:`, for a case the existing grammar
  already covers. Before this, `where: { account: … }` was accepted as a label
  match. `where:` matches a whole target, so it cannot single out an account.
  Where no target had the label, the override matched nothing and its exception
  silently did not apply. Where one did, it patched every account on that
  target. So the key is refused whatever the labels say, and a target label
  with that name has to be renamed to be matched in `where:`.
- **Rejected:**
  - A map form in `accounts:` (`[{name: x, policy: y}]`): it changes the config
    schema and the resolution chain.
  - An account matcher in `where:`: `where` matches labels, and this would mix
    two kinds of key in one matcher.
  - Allowing `account` in `where:` where some target carries that label: a test
    of the key alone ignores the label's value and the application's own
    targets, and a real match patches every account on the target.

## C5

- **Decided:** 2026-10-03, #615
- **Question:** Does the tool encrypt the configuration file at rest?
- **Decision:** No. It is out of scope.
- **Why:** The configuration holds no secrets, by construction. Secrets are
  references to a store, and auth material is a reference to an environment
  variable or a file. There is nothing in the file to protect with encryption.
- **Rejected:**
  - Encryption at rest: there is nothing secret in the file to protect.

## C7

- **Decided:** 2026-08-10
- **Question:** Can `target_sets` nest more than two levels?
- **Decision:** No. Write a second target set instead.
- **Why:** A general templating language in a credential tool is hard to debug.
  Two levels cover an environment with a list of tenants. A deeper or mixed
  shape is refused rather than quietly flattened. `01-configuration.md` §4,
  rules 2, 6 and 7, say what is refused.
- **Rejected:**
  - Deeper nesting: more power than the estates need, and harder to read and
    debug.

## C8

- **Decided:** 2026-08-10
- **Question:** Can explicit `targets:` carry labels, or only `environment`?
- **Decision:** Labels are allowed on explicit targets.
- **Why:** Generated targets get labels from their dimensions. If explicit
  targets could not carry labels too, an estate with both kinds could not be
  selected the same way.
- **Rejected:**
  - `environment` only: a mixed estate could not be selected uniformly.

## C9

- **Decided:** 2026-08-12, #27
- **Question:** How does the configuration point at vault auth material, and at
  the database admin credential?
- **Decision:** One grammar with two vocabularies: `{ method: ..., ... }`, with
  a scalar shorthand where a method needs nothing else.
  - A vault's auth material is a MaterialRef, with one key, `env` or `file`.
    Identity fields stay inline. `method: token`'s chain of sources stops inside
    the method. A token helper is deferred.
  - The admin credential uses P2's four sources. `method: vault` names a whole
    SecretRef, `method: env` names its own variable, and `external` limits the
    `dsn` to a TNS alias and refuses a `username`.
  - `oracle.scope` and `container` on a target are assertions, checked on
    connect.
- **Why:** With a MaterialRef, the file can only point at a secret, never hold
  one. So P2's no-plaintext rule is enforced by the grammar, not by care. One
  grammar for both places means one thing to learn and validate.
  `01-configuration.md` §3a has the detail.
- **Rejected:**
  - An `_env` / `_file` suffix on each key: the rule against plaintext would
    then be a validation someone must remember to write, not a missing slot.
  - Allowing `role_id` inline because it is an identifier: one exception would
    have to be argued again for every method added later.
  - A separate field for the admin credential's vault path: `method: vault`
    reuses the SecretRef type instead.
  - A token helper (`command:`): running a command from a credential tool
    needs its own decision, so it is deferred.

## C10

- **Decided:** 2026-08-10
- **Question:** What are profiles for?
- **Decision:** Run context, not target selection. A profile changes how the
  tool behaves (prompts, verification method, output, logging), never which
  targets or accounts are in scope. A profile may contain only a fixed list of
  keys.
- **Why:** The same configuration runs from a laptop, a CI job and a scheduler,
  and those need different behaviour. Without profiles, that lives in
  environment variables scattered across workflow files, where nobody reviews
  it. A profile that could change the scope would be a selector that does not
  look like one, which is dangerous in a tool that rotates credentials.
- **Rejected:**
  - Profiles that also select targets: a selector in disguise.
  - `policies.*.verify.scheduled_method`: run context hidden in a password
    policy.

## C11

- **Decided:** 2026-10-03, #615
- **Question:** Can several profiles be active at once?
- **Decision:** No. One active profile, and no inheritance between profiles.
  Revisit only if a real configuration repeats itself across three or more
  profiles.
- **Why:** Composition would be worth its precedence rules only if
  configurations repeated themselves across profiles, and no real configuration
  has shown that.
- **Rejected:**
  - Composable profiles: precedence rules between profiles, for a need not yet
    seen.

## C12

- **Decided:** 2026-10-03, #615
- **Question:** Does the tool ship a built-in `interactive` profile as the
  implicit default?
- **Decision:** No. No profile means "just `defaults`".
- **Why:** An invisible built-in profile would be one more thing to explain when
  output surprises someone.
- **Rejected:**
  - A built-in `interactive` profile: hidden behaviour.

## C13

- **Decided:** 2026-08-18, #31
- **Question:** Is `vault:` under `defaults:` and in a profile a store name, or a
  block of settings?
- **Decision:** A name, everywhere. To change a store's settings, `defaults:`
  and a profile may carry partial `vaults:` entries for a store declared at the
  top level. They may change how the store is reached (such as `addr`, `mount`
  and `auth`), but not `type`, `non_production` or `locking`. Invariant 10 keeps
  the last two out of the run context.
- **Why:** The environment variables had already chosen this shape:
  `SOPULI_VAULT` names a store, and `SOPULI_VAULT__VAULT_DEV__ADDR` sets one of
  its settings. Settings that follow a store's name cannot leak to another
  store. `01-configuration.md` §3a and §5 have the detail, and `config show
  --explain` reports which layer set each key.
- **Rejected:**
  - A `vault_settings:` block that applies to whichever store is active:
    shorter, but auth written for dev would follow a changed `vault:` into prod.

## C14

- **Decided:** 2026-08-16, #40
- **Question:** What values can `@version=` and `@stage=` take in a SecretRef,
  and who defines them?
- **Decision:** The tool defines both. `stage` is one of `current`, `pending`
  and `previous`, matched in any case and stored in lower case. `version` is a
  whole number from 1. Neither may hold a `{token}`.
- **Why:** OCI Vault's rotation states are a fixed set (`CURRENT`, `PENDING`,
  `LATEST`, `PREVIOUS`, `DEPRECATED`), not labels a user defines, and its
  versions are integers. So there was no backend vocabulary to pass through,
  and passing values through would only move a typo from load time to rotation
  time. This also settled Q3 at one `previous`.
- **Rejected:**
  - Pass the value through to the backend: a typo would fail during a rotation
    instead of when the file is loaded.

## C15

- **Decided:** 2026-08-18, #118
- **Question:** A binding names a secret, and no store is named anywhere. Does
  the tool refuse, warn, or leave it to plan time?
- **Decision:** Mostly plan time. `config show --resolved` shows the store as
  `-`, and the command that needs a store fails at plan time, once the run's
  profile is known. The file is refused at load only when `vaults:` declares no
  store at all, so nothing could ever fill the gap.
- **Why:** A missing store is not always a mistake. A profile's `vault:` or
  `SOPULI_VAULT` may supply one, and neither is known while the bindings are
  built. Plan time is when the answer is exact.
- **Rejected:**
  - Refuse at load whenever a binding's store is unnamed: it rejects a valid
    file that declares stores and names no `defaults.vault`, where the run's
    profile or `SOPULI_VAULT` supplies the store's name.

## C16

- **Decided:** 2026-08-19, #145
- **Question:** What does `--vault-token` take?
- **Decision:** Nothing. A bare `--vault-token` is refused with a message that
  names invariant 1 and the working sources. `--vault-token-file PATH` is the
  command line's place in `method: token`'s chain. ADR-007 holds the full
  decision.
- **Why:** A token as an option value is visible in `ps` and in the Windows
  process list (invariant 1). A vault ref cannot help, because a ref is resolved
  by a store that is already authenticated.
- **Rejected:**
  - `--vault-token env:NAME` or `file:PATH`, borrowing MaterialRef's keys: on a
    command line, `env:NAME` has the shape of a SecretRef (`[<vault>:]<path>`),
    which would address path `NAME` in a store called `env`. One string would
    read as one type and be the other, which blurs the line
    `01-configuration.md` §3a draws between MaterialRef and SecretRef.
  - `--vault-token-stdin`: deferred rather than rejected, because
    `--from-stdin` already uses the pipe.

## C17

- **Decided:** 2026-09-05, #294
- **Question:** P5 asked for a confirmation prompt by default for a `prod`
  target or a large blast radius. `01-configuration.md` §9 forbids a built-in
  that takes part in a ratchet. Which one holds?
- **Decision:** §9 holds, and P5 is reworded. This is the same decision as D10,
  seen from the configuration side.
- **Why:** See D10. `creds rotate` and `lock break` confirm every time, and were
  never part of this question.
- **Rejected:** See D10.

## P1

- **Decided:** 2026-10-03, #615
- **Question:** Is the documented default service user one common `C##` user
  for the whole CDB, or a local user in each PDB?
- **Decision:** A common user. A local user per PDB is documented for a CDB whose
  PDBs have different owners.
- **Why:** The choice is about how far one stolen credential reaches, not about
  what the tool can do. Both are supported. Usually one DBA team owns the whole
  CDB, and then a common user means one grant set, one credential, and new PDBs
  covered automatically. Where PDBs belong to different teams or tenants,
  limiting a stolen credential to one PDB is worth the extra setup.
  `02-oracle-privileges.md` §2 has the comparison.
- **Rejected:**
  - A local user per PDB as the default: N grant sets and N credentials, and
    each new PDB needs setup, for isolation the usual estate does not need.

## P2

- **Decided:** 2026-08-18, #86
- **Question:** Does the install script grant `SELECT ON SYS.USER$` by default?
  The grant enables the `LCOUNT` lockout guard and `check --method hash`.
- **Decision:** No. It is an optional grant. The tool probes for it at run time
  and uses it where it exists. `check` defaults to `login` whether or not the
  grant is present (Q1).
- **Why:** The grant makes password verifiers readable by the service account,
  and a verifier can be attacked offline. That is a different kind of exposure
  from what `ALTER USER` already allows, so a site should choose it, not get it
  by default. Without the grant, `check` still runs, with the other lockout
  guards. A narrower grant was measured and not adopted ([#124](#124)).
- **Rejected:**
  - Grant by default: every site would expose its verifiers to the service
    account, whether or not it uses the features that need them.

## P3

- **Decided:** 2026-08-17, #89
- **Question:** Does `--force` exist, and what does it override?
- **Decision:** Yes. It is one flag that overrides account checks 2 to 5 in
  `02-oracle-privileges.md` §4: Oracle-maintained accounts, password-file users,
  privileged roles, and the 11.2 deny list. It never overrides check 1, the
  configuration whitelist (invariant 5), and it never relaxes a safety setting.
  It is not a setting itself. It is recorded in the audit event and in the run
  document. [#1059](#1059) added check 7, the tool's own account, to the checks
  it overrides, and check 6, a superuser, to the ones it never overrides.
  [#1111](#1111) added check 8, a role the server reserves, to the ones it never
  overrides.
- **Why:** Managing the password of an Oracle-maintained account such as
  `DBSNMP` is ordinary DBA work. A tool with no override does not stop that
  change. It moves it to SQL\*Plus, where nothing records it. An audited
  override is better than an unrecorded workaround. The accepted cost: a DBA who
  wants to bypass one check bypasses every check the flag overrides, and the
  audit record is there for that.
- **Rejected:**
  - No override: the tool gets worked around, and the workaround is not
    audited.
  - One flag per check: a growing set of flags for a rare case, and a new flag
    with every new check.

## P4

- **Decided:** 2026-10-03, #615
- **Question:** One service account per database, or one per application?
- **Decision:** One per database.
- **Why:** The configuration already limits which accounts the tool may touch,
  because it declares them per application (invariant 5). The database privilege
  is the same `ALTER USER` either way, so a service account per application would
  add accounts and credentials to install and store without narrowing what each
  one can do.
- **Rejected:**
  - One per application: more accounts and credentials, and no narrower
    privilege.

## P5

- **Decided:** 2026-08-26, #213
- **Question:** Does `doctor --check-privileges` fail or warn when the service
  account holds more privileges than it should?
- **Decision:** Warn. The run document lists them in `scope.over_granted`, the
  text output names what to `REVOKE`, and the exit code does not change.
- **Why:** Failing would block the person who ran `doctor`, perhaps during an
  incident, over a grant they did not make and cannot fix from the tool's side.
  The over-grant is somebody else's decision. A tier-1 test against a live
  Oracle checks the behaviour.
- **Rejected:**
  - Fail: it blocks the wrong person.
  - A `--fail-on-over-grant` flag: P3 already rejected flags for rare cases, and
    a flag is easy to add later and hard to remove.

## P6

- **Decided:** 2026-10-03, #615
- **Question:** Is 11.2 support worth its special cases, such as
  `DBA_AUDIT_TRAIL` and the missing `ORACLE_MAINTAINED` column?
- **Decision:** Keep 11.2 (D7). Drop it if it starts to cost real complexity.
- **Why:** 11.2 is cheap to test, because a free 11g XE image exists (T1), so
  its special cases cost little. D7 has the full reasoning, including why 11.2
  stays in scope after the `V$SQLSTATS` finding (P8).
- **Rejected:**
  - Drop 11.2 now: it removes support that costs little to keep.

## P7

- **Decided:** 2026-08-17
- **Question:** Do the schema privileges of the 23 codebase cover `ALTER USER`?
  If they did, the service account could be limited to one schema.
- **Decision:** No. The direct `ALTER USER` grant is the model on every release.
- **Why:** Measured on 26ai 23.26.2.0.0. `GRANT ALTER USER ON SCHEMA` fails with
  `ORA-00990: missing or invalid privilege`. `GRANT SELECT ANY TABLE ON SCHEMA`
  succeeds in the same session, so schema privileges work, and the refusal is
  specific to `ALTER USER`. This closes ADR-001's P7 trigger for revisiting.
- **Rejected:**
  - There was no choice between options: the scoped grant does not exist.

## P8

- **Decided:** 2026-09-09, #387
- **Question:** On 11.2, the `ALTER USER` text, with the password, stays in
  `V$SQLSTATS`. Does the tool document this, warn at run time, or refuse to
  rotate on 11.2?
- **Decision:** Document it, in `02-oracle-privileges.md` §4 and
  `../security-model.md` §5.
- **Why:** Reading the view needs a dictionary grant. The service account itself
  gets `ORA-00942`. The text stays until it ages out of the shared pool. On an
  idle test instance it survived 2,000 further distinct statements, and on a
  quiet database it can stay much longer. `ALTER SYSTEM FLUSH SHARED_POOL`
  removes it at once. Both were measured.
- **Rejected:**
  - Warn at run time: a session holding the tool's grants cannot ask whether a
    release keeps DDL text. The warning would have to branch on the version
    number, which invariant 3 forbids.
  - Refuse on 11.2: it reverses D7 over an exposure that ends when the text
    ages out and can be cleared at once. The operator would rotate in SQL\*Plus
    instead, which keeps the same text and records nothing.

## J1

- **Decided:** 2026-10-03, #615
- **Question:** Does `--output json` print nothing until the run ends, even for
  a long run?
- **Decision:** Yes. `--output jsonl` streams events for the case that needs
  them.
- **Why:** A partial JSON document is worse than none: a consumer cannot parse
  it, and cannot tell how much of the run it describes.
- **Rejected:**
  - Stream the document as the run goes: it leaves invalid JSON when a run
    stops early.

## J2

- **Decided:** 2026-10-03, #615
- **Question:** Is `plan` in every run document, or only with `--dry-run` or
  `--verbose`?
- **Decision:** In every command that plans. A command with no units, such as
  `doctor`, has none.
- **Why:** The plan is small, and having it in every document makes comparing
  the plan with the result a mechanical job.
- **Rejected:**
  - Only with `--dry-run` or `--verbose`: a consumer could not compare plan and
    result for an ordinary run.

## J3

- **Decided:** 2026-10-14, #641
- **Question:** Which warnings get a machine-readable code (`SOPULI-Wnnn`), and
  how are the numbers allocated?
- **Decision:** Every warning that reaches a run document has a code, including
  the config layer's findings. The codes are one flat series. A number is never
  reused, and it is fixed when it reaches `main`. A test fails when two codes
  share a number or the numbers have a gap. Error codes (`SOPULI-2nnnn`) are a
  series of their own from `SOPULI-20001`, numbered by the same rules. An error
  gets a code only where a consumer must tell it from the other errors in its
  category.
- **Why:** A consumer branches on the code, because the message may change. A
  warning with no code can only be matched on its text. An error already has a
  category and an exit code to branch on, so it needs a code only where those do
  not tell it apart. The 32 warning codes allocated
  before this were already one series, and moving them would be a breaking
  change. Two pull requests written in parallel often take the same next number,
  and the test makes the second one take a new number before it merges.
- **Rejected:**
  - A code only where the exit code cannot say it: it leaves warnings that a
    consumer can only match by their text. It stays the rule for which `doctor`
    findings exist.
  - Ranges by category for new codes: it mixes two schemes beside 32 codes that
    cannot move.
  - A code for every one of the tool's own errors: the category and the exit
    code already do that work.

## J4

- **Decided:** 2026-10-03, #615
- **Question:** Does the run document carry a host name and a process id for
  log correlation?
- **Decision:** The host, as `invocation.actor.host`. No process id.
- **Why:** `correlation_id` already ties a run to the audit and vault trails. A
  process id means nothing once the process has exited.
- **Rejected:**
  - A process id: it adds nothing that `correlation_id` does not give.

## J6

- **Decided:** 2026-10-03, #615
- **Question:** Can the event stream resume after a crash?
- **Decision:** No. Run the command again.
- **Why:** `check` finds the true state cheaply, so a rerun recovers without a
  resume protocol.
- **Rejected:**
  - A resumable stream: a protocol to design and test, for a case a rerun
    already covers.

## J7

- **Decided:** 2026-08-13, #8
- **Question:** Does `--output json` emit a run document on a usage error?
- **Decision:** No. A run document describes a run, and a run begins when the
  invocation resolves. Exit code 2 is the only exit code that never produces a
  document, and stdout is empty on exit 2. An invalid configuration file moved
  to its own exit code, 9, and does produce a document.
- **Why:** The schema requires `command` and `invocation`. A command line that
  did not parse has neither, so a document for it would either break the schema
  or force every consumer to handle a document that describes nothing. An
  invalid configuration is different: the command line was valid, and
  `config validate --output json` must report it. So the two needed different
  exit codes.
- **Rejected:**
  - A document on a usage error too: it weakens the schema for every consumer.
  - Keep exit 2 for both usage and configuration errors: then "empty stdout and
    exit 2" no longer means one thing.
  - Move configuration errors to exit 1: loses the most useful distinction the
    tool has, because a broken configuration is something an operator can fix.

## T1

- **Decided:** 2026-08-08, #1
- **Question:** Is there a freely pullable Oracle 11g XE image for the test
  stack?
- **Decision:** Yes. `gvenzl/oracle-xe:11.2.0.2-slim` pulls, starts in about 15
  seconds, and accepts the test profiles. 11.2 is a tier-2 compose service.
- **Why:** This was a measurement. It made D7 cheap to keep. The image is
  `linux/amd64` only, which is a second reason Apple Silicon cannot test 11.2
  locally.
- **Rejected:** Not a choice between options.

## T2

- **Decided:** 2026-08-20, #174
- **Question:** Does the test harness start containers with
  `testcontainers-python`, or use `test/compose.yaml` and fixtures?
- **Decision:** Compose. The harness reads a DSN and probes whatever answers. It
  starts and stops nothing. `SOPULI_TEST_ORACLE_DSN` points it elsewhere.
- **Why:** The users are DBAs, who will want to run the stack by hand and look
  at it. A harness that managed containers would be a second definition of the
  stack beside `test/compose.yaml`.
- **Rejected:**
  - `testcontainers-python`: a second definition of the stack, which the tests
    and the by-hand stack could disagree on.

## T3

- **Decided:** 2026-10-14, #642
- **Question:** Is Secrets Manager in LocalStack's free community image, so
  that it can be the test emulator for an AWS store?
- **Decision:** No. LocalStack is out: the `localstack` service is removed from
  `test/compose.yaml`. When an AWS Secrets Manager store is built, its emulator
  is moto's server image, `motoserver/moto`. The pull request that builds the
  store checks that the image serves every call the store makes, against the
  image itself and not its documentation.
- **Why:** LocalStack has no free community image any more. From release
  2026.03.0 the Community and Pro images are one image, and it needs an auth
  token to start. The services it serves depend on the token's plan, and the
  free Hobby plan is for non-commercial use only. The bypass,
  `LOCALSTACK_ACKNOWLEDGE_ACCOUNT_REQUIREMENT`, ended on 2026-04-06. The public
  suite runs only on images anyone can pull, and an image that needs a token
  fails that rule whatever the plan. moto is open source, needs no token, and
  emulates Secrets Manager. No test used the `localstack` service.
- **Rejected:** Keeping LocalStack in tier 3 with a maintainer's Hobby token. It
  puts a token in CI, and a project's test loop may not count as non-commercial
  use.

## T4

- **Decided:** 2026-10-14, #643
- **Question:** Does running tests against a real OCI Vault cost enough to
  matter?
- **Decision:** No. Cost is not a reason to limit the OCI Vault tests. They run
  only in tier 3, because they need a tenancy and its credentials. They use one
  default vault, a software-protected key and a fixed set of secrets, and they
  replicate nothing across regions. The pull request that builds an OCI store
  checks the prices again in the tenancy's cost analysis, and records the date.
  It also checks the service limits that a fixed set of secrets can reach, such
  as the number of versions a secret keeps.
- **Why:** Oracle's pages, checked on 2026-10-14, list OCI Secret Management as
  free. Key Management does not bill API calls. A software-protected key is
  free, and an HSM-protected key is billed per key version after the first 20.
  A private vault is billed by the hour, and replicating a secret to another
  region can bring charges for the target vault and its keys. A test set-up
  that avoids those three costs nothing.
- **Rejected:** Limiting the number of OCI Vault test runs, or sharing one
  secret between them to save cost: there is no cost to save.

## T5

- **Decided:** 2026-08-09
- **Question:** Which public CI provider does the project use?
- **Decision:** GitHub Actions.
- **Why:** The repository and release-please were already on GitHub, so a second
  provider would have added nothing. Oracle Free containers run on its amd64
  hosted runners.
- **Rejected:** No other provider was evaluated.

## Q1

- **Decided:** 2026-08-18, #86
- **Question:** Does `creds check` default to `--method login` or
  `--method hash`?
- **Decision:** `login`, always. The default does not depend on the profile.
- **Why:** Hash mode needs the optional `SELECT ON SYS.USER$` grant (P2), so it
  cannot be the default. A login check needs no site-specific grant. A
  successful login resets the failed-login counter, and where the grant exists
  the `LCOUNT` guard stops a check before it could lock the account.
  `--method hash` exists and is opt-in.
- **Rejected:**
  - `login` interactively and `hash` under an unattended profile: it assumed
    that the grant was standard and that hash mode existed. Neither was true when
    this was decided.

## Q2

- **Decided:** 2026-08-16, #83
- **Question:** Where does the advisory lock live: in the vault, or in the
  database with `DBMS_LOCK`?
- **Decision:** In the vault. There is one lock record per secret path, written
  with check-and-set, with holder details and a TTL, under a `locks/` prefix on
  the secret's own mount. A store without check-and-set (KV v1, or the `file`
  backend, which is not built) refuses mutations unless it is configured
  `locking: advisory-only`.
- **Why:** The vault is the one participant every mutating command talks to.
  `DBMS_LOCK` has one advantage: a lock is released when its session dies. That
  does not help with the real risk. A stalled run's session is still alive, so
  its lock prevents nothing while its plan goes out of date. A fencing token
  prevents that: the vault version, checked again before each change. With
  fencing in place, automatic release is not worth a wider grant set. The lock
  is keyed on the path, because two accounts can share one secret. The `locks/`
  prefix keeps lock writes out of the secret's own version history, which
  `previous` and rollback use.
- **Rejected:**
  - `DBMS_LOCK`: it needs `EXECUTE ON DBMS_LOCK`, cannot cover `creds generate`
    or coordinate across targets, and puts Oracle-specific behaviour in the
    command layer.
  - Both, one per scope: two mechanisms, two ways to fail, and two places to
    look for a stuck lock.
  - Keyed per target or per account: per target means nothing when every target
    gets the same value, and per account misses two accounts that share one
    secret.

## Q3

- **Decided:** 2026-08-16, #84
- **Question:** How many generations of `previous` does the vault payload keep?
- **Decision:** Exactly one, plus whatever version history the store keeps on
  its own.
- **Why:** C14 settled it. OCI Vault has exactly one `PREVIOUS` stage, and the
  tool's fixed stage names (`current`, `pending`, `previous`) cannot address an
  older generation. One `previous` keeps the emulated payload the same shape as
  the native one, and `check --include-previous` never has to say which previous
  it accepted. Rollback goes back one generation only.
- **Rejected:**
  - A configurable list of N: an unbounded payload, emulation on every backend,
    and stage names that cannot address the older entries.
  - None, relying on the store's history: rollback would depend on the backend,
    and KV v1 has no history, nor would the unbuilt `file` backend.

## Q4

- **Decided:** 2026-09-03, #88
- **Question:** May the tool ever alter a database profile, for example to
  enable password rollover?
- **Decision:** Never. The tool prints the exact `ALTER PROFILE` an operator
  would run, and runs none. It may assign a profile to an account, but it never
  creates or alters one. Whether UC-4 may create or alter profiles is a question
  for UC-4, and would need a privilege outside this grant set.
- **Why:** A profile is shared. Changing one affects accounts nobody selected,
  and invariant 5 cannot limit that, because the configuration lists accounts,
  not profiles.
- **Rejected:**
  - An `--allow-profile-change` flag: a flag cannot grant a privilege at run
    time, so every service account would need `ALTER PROFILE` from install,
    whether or not anyone used the flag.
  - Alter a profile only when declared accounts are its only users: the check
    and the `ALTER` race each other. The usual profile is `DEFAULT`, which fails
    the check anyway.

## Q5

- **Decided:** 2026-10-03, #615
- **Question:** Does the tool send a notification when `check` finds drift?
- **Decision:** No. Exit code 3 and the JSON run document are the integration
  point.
- **Why:** Exit code 3 means drift, and the run document says which accounts
  drifted. Whatever runs `check` on a schedule can act on those, so the tool
  needs no notification client of its own.
- **Rejected:**
  - Built-in notification: the caller that schedules `check` can already
    alert on exit code 3 and read the run document. UC-2's `delivery.notify`
    exists for a different job, telling a person a password is ready, and
    is not a drift alert.

## Q7

- **Decided:** 2026-08-17, #85
- **Question:** One secret per account, or one secret per application with a
  field per account?
- **Decision:** One secret per application, with a field per account, is the
  documented default. One secret per account stays fully supported.
- **Why:** An application's accounts are usually rotated together. Across a
  dozen tenants and environments, one secret per account can mean 48 vault paths
  instead of 8. On a store that bills per secret that is a cost, and on any
  store it is more access policy to maintain. The lock is keyed on the path
  (Q2), and a write changes one field without touching the others, so the
  account is still the unit of work.
- **Rejected:**
  - One secret per account as the default: more paths and policies, for a
    separate lifecycle that most accounts do not have. It is still the right
    choice where an account's lifecycle really is its own.

## Q8

- **Decided:** 2026-10-03, #615
- **Question:** Can `creds apply` create an account that does not exist?
- **Decision:** No. Creating accounts is provisioning, which is UC-4.
- **Why:** UC-1 manages the passwords of accounts that already exist. Creating
  one is provisioning, and `CREATE USER` is outside the service account's grant
  set (`02-oracle-privileges.md` §3).
- **Rejected:**
  - Create on `apply`: it mixes provisioning into password sync, and needs a
    wider grant set.

## Q9

- **Decided:** 2026-08-18, #87
- **Question:** Which clock decides a password's age for
  `rotate --max-age-days`: the vault's `rotated_at`, or the database's password
  change time?
- **Decision:** The vault's `rotated_at`, always. `creds status` shows the
  database's own time beside it, as a sign of drift.
- **Why:** The vault has one age per secret path, however many targets share
  it. With the database as the clock, an account on several targets has several
  ages, and the CLI would need a rule for which one counts: oldest, newest or
  any. The database time also changes when anyone else runs `ALTER USER`, and a
  target the tool cannot reach would have no age at all.
- **Rejected:**
  - The database as the clock: the problems above.
  - The vault for selection, with a warning when the database age differs: it
    needs a warning code, and how codes were allocated was then open (J3).

## H1

- **Decided:** 2026-09-16, #449
- **Question:** Where is a personal account declared, so that invariant 5 (the
  configuration is the whitelist) still covers it?
- **Decision:** In a top-level `personal_accounts:` section. An entry names
  accounts, or gives a predicate over a profile or a role, which is resolved
  against the database at run time.
  - A listing verb, `account list`, shows what a predicate matched.
  - A mutating verb also needs the account named on the command line. It refuses
    a name the predicate does not admit, so one run touches exactly one account.
  - A name may not be declared both here and in an application binding.
  - A predicate that names a profile or role that does not exist is refused. A
    predicate that matches no accounts is not an error.
- **Why:** An application binding means "these accounts are mastered by these
  secrets". A personal account has no secret, no desired state for `check`, and
  no fan-out, so it fits none of the things a binding exists for. Listing four
  hundred developers by name is copying, not review, so a predicate is allowed.
  The accepted cost: whoever can grant the role or assign the profile can bring
  an account into scope, without a change to the reviewed file. The checks in
  `02-oracle-privileges.md` §4 still refuse the most privileged accounts, and a
  run touches only the one account the operator typed.
- **Rejected:**
  - An application entry marked personal: a binding that serves none of a
    binding's purposes, and every validator would need a branch for it.
  - A `personal: true` flag on an account in `accounts:`: the same problem, and
    one `secret_template` could then mix synced and handed-over accounts.

## H2

- **Decided:** 2026-09-17, #450
- **Question:** UC-2 has no vault as master. What does a reset record, and
  where?
- **Decision:** Three facts, three places.
  - When the password changed: the database. `DBA_USERS.PASSWORD_CHANGE_DATE`,
    or `SYS.USER$.PTIME` where that grant exists. The `PTIME` fallback is
    unmeasured on 12.1 (unverified: pw-changed-source).
  - Who reset it, which path was used, and where it was delivered: a metadata
    record in a store, written when a store is configured. It never holds the
    password. The advisory lock keys on its path.
  - What to roll back to: nothing. Rollback is not a UC-2 operation. A lost
    password gets another reset.

  A reset with no store configured warns at plan time and runs.
- **Why:** Reading a fact from the database is safe here, because nothing is
  mastered, so invariant 6 does not apply. The record's own timestamp is not
  used for age. On the seen path the person must change the password at first
  logon, so the record's time goes stale by design. This is a deliberate
  difference from Q9. The record also gives two concurrent resets of one account
  a lock to collide on.
- **Rejected:**
  - Only the run's own output: no memory for `status` or for age, and nothing to
    lock on.
  - A store as a requirement: UC-2 exists for estates without a vault as master,
    so the record is optional.

## H3

- **Decided:** 2026-09-16, #451
- **Question:** What noun and verbs does UC-2 use? The grammar is noun-verb
  (D2).
- **Decision:** The noun is `account`. The verbs are `account reset-password`,
  `account expire-password` (a verb of its own, not a flag), `account suspend`
  and `account list`.
- **Why:** `account` is the configuration's own word for what is managed,
  whichever key declares it. `suspend` is used instead of `lock`, so that `lock`
  keeps its one meaning, the advisory lock. `account list` is needed because a
  predicate (H1) has to be resolved and shown somewhere, and `creds status` would
  show empty vault columns for accounts nothing masters.
- **Rejected:**
  - `creds`: every `creds` verb means the vault is master. One noun for both
    sync and handover makes `--help` and the run document's verb ambiguous.
  - `user`: the natural noun for UC-4's account provisioning. Taking it now
    forces UC-4 to share it or to pick a worse one.
  - `password` or `handover`: `password` reads as a synonym for `creds`, and
    `handover` is unfamiliar to a DBA.

## H4

- **Decided:** 2026-09-16, #455
- **Question:** Does a reset verify the new password, unlock the account, or end
  an open rollover window?
- **Decision:**
  - Verify: never. The reset reports `ACCOUNT_STATUS` afterwards instead.
  - Unlock: a `LOCKED(TIMED)` account is unlocked by default. A plain `LOCKED`
    account is refused at plan time. An account with no lock gets no
    `ACCOUNT UNLOCK`.
  - Rollover window: ended by default with `EXPIRE PASSWORD ROLLOVER PERIOD`. A
    flag keeps it open.
- **Why:** Each part was measured on 26ai 23.26.2.0.0 with
  `sql/oracle/07_lock_and_rollover_probe.sql`.
  - Verifying means the tool logs in with the password, or reads the verifier
    through an optional grant. Either one uses the password outside the store,
    which the unseen path exists to avoid. On the seen path, a login would also
    use up the expiry that forces the person to choose a new password.
  - `IDENTIFIED BY` does not clear a lock. A login with the new password fails
    with `ORA-28000`, so a reset that does not unlock leaves the person locked
    out. `LOCKED(TIMED)` is a lock nobody chose. A plain `LOCKED` on a personal
    account usually means somebody disabled it on purpose, for example when the
    person left, so a reset must not clear it silently.
  - `ACCOUNT UNLOCK` on an account that is not locked resets
    `SYS.USER$.LCOUNT`, so it is issued only where a lock exists.
  - After a reset, the only holder of the old password is the person, who has
    lost it. Keeping the window open helps nobody. UC-1 §6.3 is different,
    because there the holders are applications. Ending a window on an account
    that has none is accepted and changes nothing.
- **Rejected:**
  - Verify by hash: needs the optional grant, and still uses the password
    outside the store.
  - Never unlock: the most common request would need a second command.
  - Unlock any lock: would re-enable an account somebody disabled on purpose.
  - One combined `IDENTIFIED BY … ACCOUNT UNLOCK` statement: it works, but no
    leak probe has been run against that statement shape, and it reports two
    changes as one result.
  - Never end the window: the old password would keep working after a reset.

## H5

- **Decided:** 2026-09-15, #452
- **Question:** Is self-service part of UC-2?
- **Decision:** Not in the sense of a person resetting their own password
  through sopuli. In UC-2, self-service means the person fetches a password the
  DBA set, from a place only they can read, such as a Vault response-wrapping
  token.
- **Why:** The question assumed the person would reset through the tool. That
  would use the service account's `ALTER USER` for someone who does not hold it,
  which ADR-001's argument does not cover, and the tool has no way to
  authenticate a person. It is also not needed. A person who knows their
  password changes it without the tool: before expiry with
  `ALTER USER … IDENTIFIED BY new REPLACE old`, and after expiry through
  Oracle's change flow at logon. A DBA reset is needed only when the person no
  longer knows the password, and then the person fetches the new one.
- **Rejected:**
  - The person runs the tool as themselves with `REPLACE old`: it needs the old
    password, which is exactly what a person who needs a reset does not have.
  - An identity provider in front of the tool: needs a server component and an
    identity mapping, and would reopen ADR-001.

## H6

- **Decided:** 2026-09-18, #453
- **Question:** How does an estate restrict delivery methods, so that a
  higher-precedence layer cannot add a method back?
- **Decision:** `safety.delivery.allowed_methods`, merged across layers by
  intersection. Each layer can only narrow the set.
  - Unset means no constraint.
  - Two layers whose lists share no method are refused at plan time, naming both
    layers.
  - There is no `forbidden_methods` key.
- **Why:** An intersection fails closed: a delivery method added in a later
  release cannot be used until an estate names it. A forbidden list fails open:
  a new method would be allowed everywhere on upgrade. The cost is a fourth merge
  shape in the settings registry. It is declared per setting, as `safe_bool` is,
  because both options are lists of strings and the type cannot say which merge
  applies.
- **Rejected:**
  - `forbidden_methods`, merged by union: no new code, but it fails open.
  - Both keys: two ways to write one guard, and an evaluation order to document.

## H7

- **Decided:** 2026-09-20, #454
- **Question:** Running a reset twice gives two different passwords. Is the
  reset a second exception to invariant 9 (idempotency), or should it be made
  convergent?
- **Decision:** Neither. Invariant 9 is restated as a scope rule. It applies to
  convergent commands, and a verb that draws a fresh random password has no
  state to converge on, so it is outside the invariant. The reset reports
  `changed: true` on every run, and says that the password delivered before no
  longer works.
- **Why:** One scope rule covers `creds generate`, this reset and UC-4's account
  creation by the same test, so no later verb needs its own argument. The test
  is not open to an implementer: anything with an observable target state must
  report `changed: false`. The accepted cost is that an unattended retry
  delivers twice, and the warning is what tells people.
- **Rejected:**
  - A second listed exception: a list grows one entry at a time, and each new
    verb repeats the argument.
  - Convergent on a request id: needs a record that an estate need not
    configure, and that record is missing in exactly the partly failed runs that
    get retried.
  - Convergent on account state ("already expired since the last reset"): the
    same problem, and the unseen path issues no `PASSWORD EXPIRE`, so there is
    no state to read.

## H8

- **Decided:** 2026-10-01, #459
- **Question:** On the unseen path, what happens to the stored copy of the
  password after the person has it? And how is it shown that the DBA cannot
  read it?
- **Decision:** It depends on the delivery method.
  - `vault_wrapped`: nothing persists. The tool calls only
    `sys/wrapping/wrap`, and the person's unwrap is the last read.
  - `vault_path`: before writing, the tool must ask Vault for the DBA token's
    capabilities on the person's path. If they include `read` or `root`, the
    reset is refused at plan time.

  `vault_path` is not built yet. How long its stored copy lives is decided
  together with the method itself. [#447](#447) later decided it: Vault
  deletes the copy when the method's `ttl` runs out.
- **Why:** "The DBA cannot read it" has to be checked, not assumed. A DBA token
  that can read the path lets the DBA learn the password, and then act as the
  person while the database audit trail shows only the person's name. A root
  token reports only `root`, so it is checked by name. For `vault_wrapped`, the
  single read was measured against the Vault test container: a second unwrap
  fails, and an expired token no longer unwraps.
- **Rejected:**
  - Document the requirement only: a wrong Vault policy would silently make an
    unseen reset readable by the DBA, with no expiry to limit it.
  - Fall back to the seen path when the token can read: the operator asked for
    one guarantee and would silently get a different one.

## H9

- **Decided:** 2026-10-01, #496
- **Question:** On `vault_wrapped`, the wrapping token comes back to the DBA's
  terminal, and whoever holds it can unwrap it. What does "unseen" guarantee,
  then? Should the tool carry the token to the person by some other channel?
- **Decision:** The guarantee is about attribution, not access. Where the
  database audits `ALTER USER` and logons, the DBA cannot act as the person
  without leaving their own name in a record the DBA does not control: the
  database audit trail, or Vault's audit device. An unwrap the person did not
  make is detectable, and attributable where Vault has an audit device. There is
  no second channel.
- **Why:** A DBA who can reset a password can always get into the account: by
  resetting it, or by granting themselves `CONNECT THROUGH` with the same
  `ALTER USER` privilege. The proxy route was measured on 26ai 23.26.2.0.0 with
  `sql/oracle/11_proxy_connect_probe.sql`. Both routes leave the DBA's name
  behind where auditing is on. The one route that must stay closed is learning
  the person's real password, because then only the person's name is recorded.
  The reset record does not count as an audit trail, because the DBA's own run
  writes it. The guarantee ends where Vault has no audit device, or where the
  token output was redirected. Whether a reset checks the database's audit
  settings is [H10](#h10).
- **Rejected:**
  - `vault_path` as the default method: it needs human-identity auth and a Vault
    policy that sopuli does not create, so the default would not work on a stock
    Vault, and estates would fall back to the seen path.
  - A `notify:` channel declared trusted: the trust level would be an assertion
    in the configuration, not something the tool can check.

## H10

- **Decided:** 2026-10-15, #591
- **Question:** UC-2 §1's attribution guarantee holds only where the database
  audits `ALTER USER` and logons. Does a reset check that, and warn, refuse or
  record what it found?
- **Decision:** An unseen reset records what it found, as
  `audited: true | false | unknown`, in the reset record and in the run
  document's result. It does not warn and does not refuse. The check reads the
  enabled unified audit policies. `true` means that enabled policies cover
  `LOGON` for the person and `ALTER USER` for every user. `false` means the
  database is in pure unified mode, and for one of the two, no enabled policy
  covers it or might cover it. Everything else is `unknown`, with the reason. The check needs an optional
  grant, `READ` on two audit views. The Vault half of the condition stays
  stated, not checked.
- **Why:** Without a record, an estate with no audit policy runs unseen resets
  and believes it has a guarantee it does not have, and nothing says which
  guarantee each reset had. `ALTER USER` must be covered for every user because
  a `BY` or `EXCEPT` list applies to the account that issues the statement.
  The DBA issues the `ALTER USER`, and the tool cannot know which DBA.
  `sql/oracle/13_audit_coverage_probe.sql` measured this on 26ai 23.26.2.0.0: a
  policy enabled `BY` the person records the proxy logon and not the DBA's
  `ALTER USER`. A reading the tool cannot finish never gives `false`, because a
  wrong `false` and a wrong `true` both mislead. A warning or a refusal can be
  added on top of the record later, without changing what is recorded. The
  check is a moment in time: an account holding `AUDIT SYSTEM` can disable a
  policy after it, and that case is not measured. For the Vault half, a reset
  token would need `sudo` on `sys/audit` to see whether an audit device exists,
  and no reset token should hold that.
- **Rejected:**
  - Stated only, with no check: nothing in the output says which guarantee a
    reset had.
  - A warning on every reset: in an estate with no audit policy it repeats on
    every run, and people stop reading it.
  - A refusal: it blocks the default path on every database without an audit
    policy, and a config switch to waive it would need an answer under the
    ratchet (invariant 10).
  - "The policy applies to the person" for both actions: a policy enabled `BY`
    the person would give `true` and record nothing of the DBA's `ALTER USER`.
  - "The policy applies to the run's service account" for `ALTER USER`: it
    shows that the reset itself is audited, not that a DBA's own account is.

## #10

- **Decided:** 2026-08-13, #10
- **Question:** An option such as `--dry-run` can appear before or after the
  subcommand, and also come from the environment or the configuration. How is
  one value chosen?
- **Decision:** One resolver, keyed on settings rather than on click options.
  Each setting declares its type, the layers that may supply it, and a merge
  policy. A merge policy is a required field with no default. Safety settings
  ratchet toward safe, and one generic test checks that no combination of layers
  resolves to a less safe value. Inert options such as `--output` are accepted
  in both positions. The safety flags are accepted only after the subcommand,
  and a safety flag before it is refused with a message that shows the right
  place. Both positions are one layer, `cli`.
- **Why:** Some settings that need a merge policy have no flag at all, such as
  `readonly`, so a resolver keyed on options would have nowhere to declare their
  policy. "The most specific wins" is wrong for `--dry-run`: once anything asks
  for a dry run, nothing may withdraw it (invariant 10). Accepting a safety flag
  in only one position means there is nothing to merge at that layer.
- **Rejected:**
  - A merge policy per click option: settings without a flag would have none.
  - A default merge policy: a new setting would silently inherit `override`.
  - Accepting safety flags in both positions: buys only typing tolerance, at the
    cost of a merge rule where it is least visible in review.

## #68

- **Decided:** 2026-08-12, #68
- **Question:** How does an operator see what a password policy produces,
  without changing anything?
- **Decision:** A read-only verb, `sopuli policy sample NAME`, with `--reveal`
  to print the sample passwords. This is the third exception to invariant 2.
  `--reveal` is refused with `--output json`, and the run schema has no
  property a sample password could go in.
- **Why:** The questions a new policy raises can only be answered by looking: a
  custom character set that loads but leaves out a character someone meant to
  include, or passwords too long in bytes for a target. A sample is not a
  credential: nothing logs in with it, it is never stored, and it guards
  nothing.
- **Rejected:**
  - `creds generate --dry-run` that shows the password: `--dry-run` means
    "redacted plan" everywhere else, and `generate` is a mutating verb that
    needs a store and the lock.

## #90

- **Decided:** 2026-10-01, #90
- **Question:** Can the `T:` (12C) verifier in `SYS.USER$.SPARE4` be reproduced
  client-side from a known password? `creds check --method hash` depends on it.
- **Decision:** Yes. The derivation is
  `SHA-512(PBKDF2-HMAC-SHA512(pw_utf8, salt ‖ "AUTH_PBKDF2_SPEEDY_KEY", 4096, 64) ‖ salt)`.
  `--method hash` compares `T:` only, and an account with no `12C` verifier
  fails at plan time.
- **Why:** Measured. Every stored `T:` reproduces byte for byte on 26ai, 21c,
  18c, 12.2.0.1.0, 19.3.0.0.0 and 19.32.0.0.0. So does a rollover window's
  `T:`/`t:` pair on 19.32.0.0.0. `pw_utf8` is the password as the database holds
  it, after conversion to the database character set. 12.1 is unread. The
  `t-verifier` entry in `docs/README.md` holds the details.
- **Rejected:** Not a choice between options. Had it not reproduced, hash mode
  would have been dropped.

## #195

- **Decided:** 2026-08-22, #195
- **Question:** The capabilities `container_scope` and `common_users` shared one
  probe. What does each mean, and how is each probed?
- **Decision:** `container_scope` is removed as a capability: `scope.type`
  already answers where a session is. `common_users` stays, and means "this
  session holds the privilege to manage a common user". It is probed from
  `USER_SYS_PRIVS`.
- **Why:** Measured on 26ai 23.26.2.0.0. The shared probe asked
  `sys_context('userenv','cdb')`, which raises `ORA-02003` in the root and in a
  PDB alike, so both capabilities were reported absent everywhere. `scope.type`
  is read on the same connection and is what the code branches on, and one fact
  stored twice is two things that can disagree. `common_users` is different: a
  root session can hold `ALTER USER` locally and still be unable to touch a
  common user, and no scope field says so. Removing it needed no schema change:
  `scope.capabilities` is an array of plain strings with no enum, so no
  capability name is part of the typed contract.
- **Rejected:**
  - A corrected `container_scope` probe: a second copy of what `scope.type`
    says.
  - Removing `common_users` too: it carries a fact nothing else observes.

## #250

- **Decided:** 2026-08-28, #250
- **Question:** C15 left a binding's store to be completed at plan time. Where
  does that resolution live?
- **Decision:** In a separate plan-time step. Bindings stay as loaded, and a run
  resolves each binding's store once the active profile is known, before the
  plan is built. A binding still without a store is refused at plan time.
- **Why:** The `vault` setting in the registry means "which store the unnamed
  environment variables address", and a binding's store is a different question
  with the same name. A separate step keeps the two apart.
- **Rejected:**
  - Widening the `vault` setting to the profile layer: less code, but it mixes
    two meanings in one setting.

## #254

- **Decided:** 2026-08-28, #254
- **Question:** Running `creds generate` twice gives two different passwords. Is
  it an exception to invariant 9 (idempotency)?
- **Decision:** It is outside the invariant. A second `generate` replaces
  `pending` and reports `changed: true`. H7 later restated this as a scope rule
  covering every verb that draws fresh randomness. [#769](#769) later made the
  replacement need `--overwrite-pending`. Without the flag, a second `generate`
  refuses over a staged `pending`. With it, the run still reports
  `changed: true`, so this ruling on invariant 9 stands.
- **Why:** Invariant 9 governs convergent commands. Drawing a fresh password has
  no fixed point to converge on.
- **Rejected:**
  - A sticky `pending`, replaced only with `--force`: it keeps invariant 9
    literally true, but charges a flag for the ordinary case, a password that
    went into a ticket and must be replaced.

## #257

- **Decided:** 2026-09-04, #257
- **Question:** `creds generate --promote` writes `current` directly, with no
  database confirming. How does it fit invariant 7, and what state does it
  report?
- **Decision:**
  - It may write over an existing `current` only with `--overwrite-current`.
    Without the flag, such an account is refused at plan time (exit 8). There is
    no prompt. In the same write, `previous` takes the value `current` held.
    This is the one documented exception to invariant 7.
  - `results[].state` gains `VAULT_ONLY`.
- **Why:** Invariant 7 protects a window: a `current` that applications read,
  replaced before any database can serve the new value. `--promote` is for when
  the operator already knows the password and no rotation is in flight. A
  dedicated flag can later be loosened without breaking anyone. A `--confirm`
  gate could not later be narrowed without breaking scheduled runs. `--confirm`
  means "proceed without asking", so every future question would fold into it.
- **Rejected:**
  - Refuse whenever `current` exists: the flag could not mean "I know what I am
    doing".
  - `--confirm` as the gate: its scope would grow with every question the verb
    learns to ask.
  - `--force` buying the overwrite: gives `--force` a meaning it has nowhere
    else.
  - `SKIPPED` as the state: it is not true. No `results[]` at all: the verb that
    writes the field applications read would have nothing machine-readable to
    say.

## #263

- **Decided:** 2026-08-29, #263
- **Question:** `creds finish-rollover` ends a rollover window early. Does it
  check anything before cutting off the old password?
- **Decision:** It checks each account with two gates, and closes the window
  only where both pass.
  - A staged `pending` means the rotation is unfinished: the window stays open
    and the account is reported `PENDING_APPLY`. No login is spent.
  - One login with the vault's `current`: if the database refuses it, the window
    stays open and the account is reported `DRIFT`. The run exits 3.
  - An account with no open window reports `changed: false`.
- **Why:** With a window open, both passwords work, so a successful login
  proves little. A refused login does prove something: neither password is the
  one applications fetch, and closing the window would leave nothing that
  works. A staged `pending` means `current` is the old password, and closing
  then would strand every application not yet given the new one.
- **Rejected:**
  - Close without checking: it could close a window on the only password that
    still works.

## #264

- **Decided:** 2026-08-30, #264
- **Question:** Where does `creds apply --repair` get its list of what drifted?
- **Decision:** From a previous run's document: `--repair result.json` narrows
  the run to the (account, target) pairs that run reported as not confirmed.
  It filters on each row's state, not on the document's exit code.
- **Why:** `apply` already converges, so `--repair` buys fewer logins, not a new
  capability. Each login is an attempt against the failed-login counter, a
  connection and an audit entry on a database that had nothing wrong. Reading a
  previous document is the only option that saves those logins.
- **Rejected:**
  - Run `check`'s logic first in the same process: spends exactly the logins
    `--repair` is meant to save. The pre-flight already does this.
  - A target list from the operator: that is the selectors that already exist.
  - Filtering by exit code: it would refuse an `apply` that failed everywhere,
    which is the document most worth repairing from.

## #265

- **Decided:** 2026-08-29, #265
- **Question:** `creds apply --source` chooses the stage to apply. How does
  `--source previous`, the rollback, work?
- **Decision:** A named stage is read exactly and never falls back. A stage that
  holds nothing is a failure naming that stage. `previous` needs `--confirm`, and
  refuses (exit 8) where nothing can be asked. Once every target confirms, the
  vault swaps: `current` takes the rolled-back value and `previous` takes the
  one just removed, in one compare-and-set write.
- **Why:** A fallback is what someone naming a stage is trying to avoid: applying
  `current` to an operator who asked for `previous` is a rollback that did not
  happen and said it did. A rollback is the one invocation whose success stops an
  application's credential working, so it is confirmed. Swapping the vault keeps
  the vault and the database in agreement, so `check` does not report drift
  afterwards.
- **Rejected:**
  - Leave `current` alone after a rollback: the vault and the database would
    disagree on purpose, and `check` would report drift until somebody fixed it.

## #266

- **Decided:** 2026-09-03, #266
- **Question:** What would `creds apply --continue-on-error` govern that is not
  already the default?
- **Decision:** Nothing, so the flag is removed from UC-1 §5 rather than built.
- **Why:** A failure that belongs to one target, one account or one document is
  already confined to it, and the run continues. The run-wide stops that remain
  must stay stops: a lock held by somebody else, a stolen lock found by a fence
  check, a blocking pre-flight finding, and a missing capability. Each of them
  promises that nothing more is written.
- **Rejected:**
  - Build the flag: it would either do nothing, or override one of the stops
    above.

## #268

- **Decided:** 2026-09-01, #268
- **Question:** When the server refuses a password with `ORA-28003` (verify
  function) or `ORA-28007` (reuse), does `creds apply` draw a new one?
- **Decision:** Yes. `apply` redraws, up to three draws, only for a password the
  tool drew itself (the `origin` beside `pending`), never on an unmapped error
  code, and it reports each redraw. It re-applies the account to its whole
  target set.
- **Why:** Neither refusal can be predicted before the `ALTER USER`: checking a
  candidate against the verify function would need the password in a PL/SQL
  block (invariant 13) or in a bind (invariant 14). So `generate` cannot prevent
  it, and a refusal the operator cannot act on is worse than a bounded,
  reported redraw. A password an external system dictated is never replaced.
- **Rejected:**
  - Report and point at `creds generate`: the operator can do nothing different
    with the refusal.
  - Re-apply only the target that refused: the others would hold a value the
    vault no longer has.

## #301

- **Decided:** 2026-09-01, #301
- **Question:** May `creds apply` assign an account to a profile, without
  deciding Q4 (altering profiles)?
- **Decision:** Yes. A policy's `account.profile` makes `apply` run
  `ALTER USER … PROFILE …` where the account is on a different profile. The tool
  never creates or alters a profile (Q4). A profile that does not exist on a
  target is a pre-flight finding.
- **Why:** Assigning changes which shared profile one whitelisted account sits
  under, which is safe. A profile missing on one target of twenty is an ordinary
  misconfiguration, and finding it on the twentieth would leave nineteen
  accounts moved.
- **Rejected:**
  - Let `ORA-02380` surface during the run: the run would stop half way.

## #302

- **Decided:** 2026-09-01, #302
- **Question:** UC-1 §5 listed "`PASSWORD_EXPIRE` handling" as an account
  attribute. What should it do?
- **Decision:** Nothing. The attribute is removed.
- **Why:** Setting a password already clears `EXPIRED`, which is Oracle's
  behaviour and not optional. What remains is expiring a password on purpose,
  which forces the next login to choose a new one. An application account
  cannot answer that prompt, so the rotation would break the application it
  serves.
- **Rejected:**
  - An opt-in expiry attribute: for the accounts UC-1 manages, using it
    successfully is a failure.

## #303

- **Decided:** 2026-09-01, #303
- **Question:** UC-1 §5 listed default and temporary tablespace as account
  attributes. Does `apply` set them?
- **Decision:** No. Tablespaces belong to provisioning, UC-4, with account
  creation (Q8).
- **Why:** `ALTER USER … DEFAULT TABLESPACE` moves no existing segment. During a
  credential rotation it looks done and is half done. During provisioning, the
  account has no objects yet, so it is simply part of creating one.
- **Rejected:**
  - A tablespace attribute in `apply`: a half change at the worst moment.

## #344

- **Decided:** 2026-09-06, #344
- **Question:** A path containing `..` let `lock break` write a lock record onto
  the secret itself. Is `.` or `..` stripped or refused, and where?
- **Decision:** Refused. `normalise_path`, which every producer of a lock path
  goes through, raises on a `.` or `..` segment. A SecretRef in the
  configuration is also refused at load, with a message that names its
  location.
- **Why:** A relative segment walks out of the `locks/` prefix: the lock path
  became the secret's own path, and the run wrote a lock record onto the
  credential document. Measured against the tier-1 Vault. Stripping the segment
  would rewrite what the operator typed, so `lock status` and `lock break` could
  disagree about which record they mean.
- **Rejected:**
  - Strip `.` and `..`: a silent rewrite.
  - Refuse only in the lock-key functions: a later caller would have to
    remember to.

## #348

- **Decided:** 2026-09-05, #348
- **Question:** `locking.break_expired` was parsed, validated and ratcheted, but
  never passed to the lock manager. Wire it, or document it as inert?
- **Decision:** Wire it: the resolved setting is passed to every lock manager.
- **Why:** Unlike the inert keys, this one has a complete implementation and a
  documented safety story behind it. The refusal's own hint already told
  operators to set it.
- **Rejected:**
  - Document it as inert: keeps a feature that is built and promised switched
    off.

## #360

- **Decided:** 2026-09-06, #360
- **Question:** `db.query_timeout_s` was parsed and read by nothing. Wire it to
  the driver, or leave it inert?
- **Decision:** Wire it. `db.connect_timeout_s` was found half-wired too, and
  both now reach the driver. Neither built-in changes: there is no query
  timeout by default.
- **Why:** A key that validates and changes nothing misleads whoever sets it.
  The default stays unbounded for a reason that is about what the tool imposes:
  a call timeout cancels the round trip without undoing what the server did,
  and `ALTER USER` is not transactional, so a rotation cut off at the wrong
  moment cannot say whether the password changed. An operator may still choose
  a timeout.
- **Rejected:**
  - Read the key only for verbs that do not mutate: one setting with two
    behaviours.
  - Warn when it is set on a mutating run: re-argues a decision the default
    already makes.
  - Leave it inert and say so: the key would mean nothing.

## #386

- **Decided:** 2026-09-13, #386
- **Question:** `DBA_USERS.PASSWORD_CHANGE_DATE` does not exist below 19c, so
  `creds status` showed no date there and did not say why. Fall back to
  `SYS.USER$.PTIME`, or make it a capability?
- **Decision:** Fall back to `PTIME` where the optional `SELECT ON SYS.USER$`
  grant exists. When the date is still unknown, say why, with `SOPULI-W021`.
  Exactly one source is read per release: `PTIME` is never read where the
  column exists, not even to fill a `NULL`.
- **Why:** `PTIME` is the same clock, which was measured. Reading one source per
  release keeps a second source from becoming a second opinion that can
  disagree. A capability would have changed the driver protocol, `doctor`, the
  schema and the skip vocabulary, all for one display column.
- **Rejected:**
  - Leave it absent and say nothing more: the column stays empty with no reason.
  - A capability: too much machinery for a display column.

## #392

- **Decided:** 2026-09-11, #392
- **Question:** The run schema's `command` enum listed `creds.promote`, a verb
  that was declined and will never exist. Remove it with a major bump, remove it
  with a minor bump, or keep it as reserved?
- **Decision:** Remove it, as a minor bump (schema 1.21). The rule is written
  into `03-json-output.md` §8: a value that no released build has ever emitted
  can be removed without a major bump. The test is the emitter, not the schema.
- **Why:** Invariant 12 protects readers of emitted documents, and no document
  could ever have contained this value. The rule is stated narrowly so that a
  later removal cannot stretch it: it does not cover a value some build did
  emit, or a property, or a value that is only not built yet.
- **Rejected:**
  - A major bump: paid for a change that cannot break any reader.
  - Keep it as reserved: it keeps a misleading value for a verb that will not
    arrive.

## #395

- **Decided:** 2026-09-09, #395
- **Question:** What colour scheme does the text output use?
- **Decision:** Four roles: `good`, `attention`, `bad` and `inconclusive`. One
  function, `role_for_state`, maps a state to a role. Converged states are cyan,
  not green. Colour never carries meaning on its own, and JSON output is never
  coloured.
- **Why:** In a wall of monospace, `IN_SYNC` and `FAILED` looked the same until
  read. Green next to yellow is the pairing a reader with
  deuteranopia cannot tell apart, and that is exactly the distinction this tool
  reports.
- **Rejected:**
  - Green for converged: unreadable for deuteranopic readers.

## #406

- **Decided:** 2026-09-30, #406
- **Question:** The promotion gate counted only the (account, target) pairs this
  run visited. Should a narrowed run promote?
- **Decision:** No. "Every target" in invariant 7 means every target the
  configuration declares. A run narrowed past a pair the promotion needs still
  changes what it was pointed at, then withholds the promotion (`SOPULI-W027`,
  exit 4). `creds rotate` refuses such a narrowing up front.
- **Why:** Counting only the visited pairs let `apply --target` promote a
  credential whose other target still held the old password, with nothing
  failing. It also let `--repair` strand a sibling account: new password on its
  database, old one in `current`.
- **Rejected:**
  - Leave it and document it: the stranded state is reachable with no failure.
  - Re-verify every account in the document before promoting: costs exactly the
    logins the narrowing was meant to save.

## #409

- **Decided:** 2026-09-13, #409
- **Question:** Three documented command lines used flags that do not exist.
  Fix them, mark them illustrative, or both?
- **Decision:** Rewrite all three on real flags, and add
  `tests/test_doc_command_lines.py`, which parses every documented `sopuli`
  command line against the real CLI.
- **Why:** A real example existed for each case, so none needed an exemption.
  A test with no unconditional exemption keeps every example honest. A block
  that shows a refused option on purpose passes only when it also shows click's
  rejection.
- **Rejected:**
  - Mark the examples illustrative: an exemption the test would have to honour
    forever.
  - A split, rewriting some and marking others: still leaves an exemption.

## #422

- **Decided:** 2026-09-14, #422
- **Question:** Does `--vault-addr` exist as the command-line layer for a
  store's address, which store does it address, and is there a form that names
  a store?
- **Decision:** It exists, addresses the active store (what `SOPULI_VAULT` or
  `defaults.vault` names), and is refused where neither names one. There is no
  form that names a store. It applies to `vaults.*.addr` and no other key.
- **Why:** An environment variable outlives the command. On Linux,
  `env VAR=… sopuli …` is a clean one-shot, but PowerShell has no inline prefix,
  and Windows is a supported platform. That asymmetry is the whole case, and it
  does not extend to `mount` or `namespace`, which nobody changes for one
  command. Several stores are already addressed by
  `SOPULI_VAULT__<NAME>__ADDR`.
- **Rejected:**
  - No flag: Windows users would have no one-shot way to point one run at
    another address.
  - A form that names a store: the per-store environment variables already
    cover it.

## #424

- **Decided:** 2026-09-14, #424
- **Question:** A `safety:` block on a target, group or target set was parsed
  and never enforced. When a readonly target is in a run's plan, what happens?
- **Decision:** The whole run is refused at plan time, `--dry-run` included. The
  error names the readonly targets, the key that marked each one, and the
  selectors that would leave them out. `max_targets` and `confirm_environments`
  on those objects were inert too, and are enforced now. `lock break` is not
  gated at this layer.
- **Why:** A refusal before anything is touched is the safe direction, and
  naming the selector lets the operator narrow the run. `lock break` takes no
  selector, and every verb that could use a lock to change a target is refused
  by the same block, so gating it would block a harmless cleanup and guard
  nothing.
- **Rejected:**
  - Skip the readonly targets and run the rest: turns a refusal into a partial
    run, with a new state and an exit-code rule to define.
  - Refuse with no hint about how to exclude them: one readonly PDB would block
    a 200-PDB run with no way forward.

## #426

- **Decided:** 2026-09-14, #426
- **Question:** `config show --explain` printed `safety.readonly = false
  [built-in default]` for a file whose target set it. How should `config show`
  report a `safety:` block written on a target, group or target set?
- **Decision:** A `safety` section in `config show`, with one row for each
  object that writes a block, and its key path. The JSON gains `safety` on
  `config.targets[]`. The `--explain` row itself does not change.
- **Why:** The `--explain` row was correct: `config show` does not merge the
  selected targets' `safety:` blocks into the run's settings, and is not gated
  by the setting. What was missing was anything saying a block
  existed.
- **Rejected:**
  - A `SAFETY` column in the target table: a group is not a row in that table,
    so it could not report the main use of the feature, and the column would be
    mostly empty.
  - An annotation on the `--explain` row: `[source]` has one fixed meaning, and
    a second meaning inside it would need a JSON answer as well.

## #428

- **Decided:** 2026-09-14, #428
- **Question:** `config show` said a store's key was layered, never which layer
  set it. Where is that reported?
- **Decision:** In text, per-store rows in `--explain`'s settings table, such as
  `vaults.vault-dev.addr = … [cli --vault-addr]`, for the keys some layer
  wrote. In JSON, `config` gains a `vaults` array with each store's effective
  settings and where each came from.
- **Why:** P3's own format example is a vault key, and the existing note column
  already deferred to a view that did not exist. The effective address was in
  neither JSON mode before: `--explain` emitted the address the file wrote, not
  the one the run used.
- **Rejected:**
  - A `SOURCE` column: a truncated variable name is useless at exactly the
    moment the view is needed.
  - The layer appended to the note: keeps the layer and loses the location,
    which is the part that says what to edit.

## #438

- **Decided:** 2026-09-18, #438
- **Question:** How does UC-2, personal account passwords, work, and how does a
  new password reach a person?
- **Decision:** UC-2 is specified in
  `docs/use-cases/uc-02-personal-account-passwords.md`. The default path is
  unseen: the tool writes the password where only its owner can fetch it, and
  does not expire it. The seen path, `manual`, is not the default, is confirmed
  every time, and always expires the password. The individual questions are
  H1 to H9 and #439.
- **Why:** With no vault as master, a password is handed over, not synced, so
  UC-1's flow could not be assumed. Expiry is needed only where the DBA has seen
  the password.
- **Rejected:**
  - Expiry on every path: an unseen password needs none, because nobody but its
    owner has it.

## #439

- **Decided:** 2026-09-18, #439
- **Question:** May UC-2's `manual` delivery print a working password, which
  invariant 2 otherwise forbids?
- **Decision:** Yes, as invariant 2's fourth exception, under five structural
  guards:
  - one reveal site, reachable only when the delivery method is `manual`;
  - refused with `--output json` and `jsonl`, and the run schema has no property
    for a password;
  - refused unless stdout is a terminal;
  - confirmed every time, and `--confirm` does not answer the prompt in advance;
  - `force_expire: true` required on the method.

  A `--dry-run` is exempt from the middle three, because it prints a plan and
  never a password.
- **Why:** This is a credential, unlike a policy sample, so the third
  exception's reason does not carry over. What allows it is that it is
  deliberate, witnessed and expired at once: the person's first logon must
  change it. Because that reason is weaker, the guards are stricter than
  `--reveal`'s. The terminal check carries the argument: a value in a file or a
  CI log outlives the one logon it is good for. If nobody is present to answer
  the prompt, nobody is present to receive the password.
- **Rejected:**
  - Write it to a file: a file outlives the logon, like a log.
  - No `manual` path: the seen path is how many estates hand over passwords
    today.
  - `--confirm` answering the prompt: a shell alias would remove the one guard
    between a DBA and a password they will see.

## #481

- **Decided:** 2026-10-07, #481
- **Question:** `auth: prompt` with no terminal was meant to exit 8, and every
  verb reported it as one target's finding and exited 1. Where does the run stop?
- **Decision:** A verb that changes something checks every target it may connect
  to, judged from the config, before it reads the vault or connects. If any of them would ask for a password and stdin is
  not a terminal, the whole run is refused at exit 8, and the message names
  those targets. A `--dry-run` is refused when its preview connects, and
  `creds apply --dry-run` without `--preflight` or `--strategy` does not. A verb that only reads, such as `doctor`,
  `creds check` or `creds status`, reports the target as unreachable and exits 1.
  `creds generate` is not gated: it reads the targets only for password limits,
  and a target it cannot read is already a caveat, not an error.
- **Why:** A mutating run that cannot reach one target would change the others
  and then fail, and a rollover left half applied cannot be promoted. Refusing
  before anything is touched is invariant 4's shape. A survey is different: one
  target nobody can reach must not hide what the others say.
- **Rejected:**
  - Let the refusal stop every verb: `doctor` would stop at the first target
    that asks, which is the opposite of what it is for.
  - Exit 8 only when every selected target was refused: a scheduler cannot write
    a reliable branch on an exit code that depends on a count.
  - Check only the targets with something staged or due: that needs the vault
    read first, and the same scheduled run would pass on some days and fail on
    others.

## #525

- **Decided:** 2026-09-25, #525
- **Question:** `account expire-password` forces a change and draws nothing.
  What does it do with an open rollover window, and does it write a reset
  record or take the reset lock?
- **Decision:** Close the window, then expire: `EXPIRE PASSWORD ROLLOVER
  PERIOD`, then `PASSWORD EXPIRE`, in that order. No reset record and no reset
  lock. Whether to close is decided from the account's state and the database's
  rollover capability, never from a version number. There is no flag to keep
  the window.
- **Why:** If the second statement fails, close-then-expire leaves an `OPEN`
  account whose old password is already dead, which is the safe half. Closing
  is safe whatever the release does: a close with no window open is accepted
  and changes nothing. The only holder of the old password is the owner, as
  for the reset (H4). An expiry draws and delivers nothing, so there is nothing
  to journal or protect, and the run document is its record. The accepted
  cost: a person who knows only the old password loses the self-service change
  and needs a reset.
- **Rejected:**
  - Expire only: the old password keeps working through the window.
  - Expire, then close: a failure between the two leaves the expire-only state
    by accident.
  - A reset record or the reset lock: they exist for deliveries, and an expiry
    has none.

## #531

- **Decided:** 2026-09-25, #531
- **Question:** `account list` resolves a `role:` predicate through
  `DBA_ROLES`, which the install did not grant, so it refused every role
  predicate as a misspelling. What changes? The mutating `account` verbs were
  not affected: they check the named account's roles through `DBA_ROLE_PRIVS`,
  which was already granted.
- **Decision:** `GRANT SELECT ON SYS.DBA_ROLES` joins the base grant set and
  `00_install.sql`. Resolving a `role:` predicate is gated on the
  `role_lookup` capability, so an estate installed before the grant is refused
  at plan time with the capability and the target named. The grant is not a
  required read for `creds apply` or `rotate`, so older installs can still
  rotate.
- **Why:** Measured on 26ai 23.26.2.0.0: a service account holding exactly the
  documented grants gets `ORA-00942` from `DBA_ROLES`. Telling an operator a
  correctly spelled role is misspelled is the wrong refusal. Invariant 4 asks
  for a plan-time refusal naming the capability.
- **Rejected:**
  - Only add the grant: existing installs would still get the misleading
    refusal.
  - Only gate on the capability: role predicates would never work on a standard
    install.

## #568

- **Decided:** 2026-09-30, #568
- **Question:** A rollback (`apply --source previous`) can be refused with
  `ORA-28007` on a profile with reuse limits, including ADB's `DEFAULT`. Whether
  it is depends on how many changes and how much time have passed, some of them
  outside the tool. Warn, refuse at plan time, or only document it?
- **Decision:** Warn and document. `SOPULI-W028` names the profile's
  `PASSWORD_REUSE_MAX` and `PASSWORD_REUSE_TIME` whichever way the statement
  goes. The docs name a rollover window as the way back on such a profile: the
  previous password keeps working until `finish-rollover`.
- **Why:** With both limits set, the outcome depends on password changes made
  outside the tool, which it cannot see, so the rule is reported, not
  interpreted. A new code was used instead of widening `SOPULI-W017`, because
  W017's documented meaning is a supplied password, and changing what an
  emitted code means would mislead a reader that branches on it.
- **Rejected:**
  - Refuse at plan time: the tool would have to interpret Oracle's reuse rule,
    and would sometimes be wrong.
  - Widen `SOPULI-W017`: changes the meaning of a code already emitted.

## #606

- **Decided:** 2026-10-02, #606
- **Question:** Pre-flight's non-blocking findings reached only
  `--output json`. Print them in text mode?
- **Decision:** Yes, wherever a survey passes, as run-level notes: one note per
  target, with findings that share a message sharing one line. A survey that
  refuses is unchanged.
- **Why:** These findings say how much the pre-flight could establish. Keeping
  them JSON-only hid them from everyone who ran the command by hand.
- **Rejected:**
  - JSON only: the caveat reaches nobody running by hand.
  - Only under `--dry-run --preflight`: a real run has the same caveat.

## #610

- **Decided:** 2026-10-03, #610
- **Question:** Six documented behaviours did not exist in the build. Implement
  or delete each?
- **Decision:**
  - `SOPULI_LOG_LEVEL`: delete the claim. Profile `log_level` and `log_file`
    stay parsed and documented as unused. [#629](#629) later removed both keys,
    so a config that writes them is refused.
  - A profile's `confirm: false`: implement. A gated run then refuses with exit
    8 unless `--confirm` is given.
  - A policy's `rotation.*` and `verify.*`, and the `rotation.strategy:
    rollover` error: delete the claims. [#787](#787) later removed the keys.
  - The `printable_ascii` below 12.2 warning: delete. It gave no reason, every
    `printable_ascii` character is one byte, and the byte limit is enforced per
    target.
  - `password_redrawn` and `password_not_redrawn`: rename to registered codes,
    `SOPULI-W029` and `SOPULI-W030`.
- **Why:** Each claim was drift: a document promising what the code did not do.
  Logging would need a log subsystem that nothing uses yet. `confirm: false`
  only makes runs stricter and was already specified. The policy keys would
  duplicate what flags already do, and #86 stands.
- **Rejected:**
  - Build logging now: a subsystem with no consumer.
  - Implement the policy keys: a second way in beside the flags.

## #663

- **Decided:** 2026-10-11, #663
- **Question:** `plan.confirmation_required` was in the run schema, and no
  command emitted it. It waited for a profile's `confirm:` to reach the
  resolver, which #610 did. Emit it, remove it from the schema, or leave it
  unemitted?
- **Decision:** Emit it, on every plan. It is `true` when a real run of the
  plan needs an explicit yes before it changes anything, and `false` otherwise.
  A `--dry-run`, and a run given `--confirm`, report the value of the run that
  prompts. The seen reset's prompt to show the password is not counted. Run
  schema 1.34.
- **Why:** `plan` is the same on a dry run and a real run (J2), so the field
  cannot depend on `--dry-run` or `--confirm`. Read that way, it answers the
  question a scheduler asks before the real run: will it need `--confirm`? The
  seen reset's prompt comes after the password has changed, and no flag can
  answer it, so it is not a gate on the plan.
- **Rejected:**
  - Remove it from the schema. `invocation.options` shows the resolved
    `confirm`, but not whether a gate applies to this run. Removing a property
    is a major bump.
  - Leave it unemitted. The reason it waited for no longer holds.
  - Report `false` on a dry run, because a dry run never prompts. The dry run's
    plan would then differ from the real run's.

## #671

- **Decided:** 2026-10-11, #671
- **Question:** A real run of `account reset-password` refuses on a target for
  two reasons of its own: the seen path's rollover refusal (UC-2 §4.3), and a
  policy that cannot fit the target's byte limit (UC-2 §4.2). A `--dry-run`
  asked neither, so it showed "would be reset" where the real run reported
  `ERROR`. Should the preview ask them?
- **Decision:** Yes. Both are asked before the preview returns, and the preview
  row is the row the real run would report. The byte limit is checked without
  drawing a password. The real run asks again before it draws.
- **Why:** Both are reads, so invariant 8 holds. A preview that says "would be
  reset" for a reset that fails is the trap UC-1 §5's `--dry-run --preflight`
  exists to avoid, and invariant 4 wants a refusal named before anything runs.
  The cost is two reads on a connection the preview already opens. The preview
  is still a snapshot: an `ALTER PROFILE` between the preview and the run can
  change the answer, which is why the real run asks again.
- **Rejected:** Keep the preview a plan of intent and document the gap. The
  operator would learn about the refusal from the real run, after the plan was
  approved.

## #697

- **Decided:** 2026-10-09, #697
- **Question:** The tool sends `ALTER USER … IDENTIFIED BY` over whatever
  connection it has, so on an unencrypted one the new password crosses the
  network in clear. Warn or refuse? Does reading the encryption need a new
  grant? What should happen when the tool cannot tell?
- **Decision:**
  - Warn, never refuse. `SOPULI-W031` where a password was sent over a
    connection that is not encrypted.
  - The grant on `V$SESSION_CONNECT_INFO` is optional. `00_install.sql` offers
    it as parameter 7, off by default.
  - "Could not tell" warns too, with its own code, `SOPULI-W032`.
- **Why:** A refusal would need a new safety setting, and invariant 10 says
  safety settings only ratchet toward safe. A warning needs only a new code and
  a run schema minor bump. The grant is optional because `PUBLIC` reads the
  view on every release measured (`sql/oracle/12_connection_encryption_probe.sql`).
  "Could not tell" has its own code for `SOPULI-W018`'s reason: a check that
  did not run is not a pass.
- **Rejected:**
  - Refuse: needs a new safety setting.
  - Require the grant: measurement found it unnecessary.
  - One code for both: a consumer could not tell "in clear" from "did not
    look" without reading the message.

## #741

- **Decided:** 2026-10-11, #741
- **Question:** On the seen path, `account reset-password` asks once per target
  whether to show the new password, and printed every accepted password at the
  end of the run. A prompt declined on a later target aborts the run before that
  print, so a password the operator had accepted was never shown. Its account
  kept an expired password that nobody held. How should the run hand over an
  accepted password?
- **Decision:** Print each password on its own target, as soon as the operator
  accepts it and its record is written. Wrapping tokens from an unseen method
  still print at the end of the run.
- **Why:** This removes the cause rather than handling the abort. Every guard
  in UC-2 §6.5 has passed for an accepted password, so printing it earlier adds
  no emission. It prints after the record, so UC-2 §3.1's order holds: the
  record is written a moment before the password reaches the screen. A token
  has no prompt, so a decline cannot lose one, and in JSON mode the end-of-run
  print is what sends it to stderr.
- **Cost accepted:** In a run that finishes, each password appears before the
  result table, not after it.
- **Rejected:**
  - Print the accepted passwords on the abort path, after the table. This
    adds a second place that prints a working password.
  - Keep the behaviour and document that a decline loses the earlier
    passwords. The recovery is another reset of each such account.

## #742

- **Decided:** 2026-10-10, #742
- **Question:** `$` and `^` are specials in `alnum_safe`, the default charset.
  A POSIX shell expands `$`, unquoted or in double quotes, and Docker Compose
  expands it in a `.env` file. Windows `cmd.exe` reads `^` as its escape
  character. Keep them and tell the operator to quote every password, or drop
  them?
- **Decision:** Drop both. The specials are `_ # - . + = ~`.
- **Why:** `01-configuration.md` §8 says `alnum_safe` avoids shell hazards.
  With `$` that was false in `sh`, where `aB3$xy_9` arrives as `aB3`, and in a
  `.env` file, which loses the same tail. With `^` it was false in `cmd.exe`,
  where `set PW=aB3^xy_9` sets `aB3xy_9`. A rule that every password must be
  quoted is one an operator forgets, and the failure is a password changed
  with no error. The cost is two symbols, 71 to 69, and a supplied password
  with `$` or `^` is no longer compliant under `alnum_safe`. A policy that
  wants either can name it in `charset: custom`.
- **Rejected:** Keep them and require quoting. Only `alnum` would then be safe
  unquoted, and the default charset would need a quoting rule for each path.

## #743

- **Decided:** 2026-10-11, #743
- **Question:** In a JDBC thin URL, `jdbc:oracle:thin:user/password@//host:port/service`,
  the driver refuses a password that contains `-` or `.`. Both are specials in
  `alnum_safe`, the default charset. Drop them, or tell the operator to put the
  password in double quotes in the URL?
- **Decision:** Keep them. `01-configuration.md` §8 says to quote the password
  in a JDBC URL: `user/"password"@…`.
- **Why:** Quoting is one rule for one path, and with it every
  `printable_ascii` character logs in, `@` included. The failure names its
  cause: the driver fails the connection with ORA-17067, "Invalid Oracle URL
  specified", and not with a wrong-password error. Dropping `-` and `.` would
  leave five specials, and a tight policy would give up generating more often.
- **Cost accepted:** An application that puts an `alnum_safe` password in an
  unquoted JDBC URL can work for several rotations and then fail. The failure
  comes after the rotation has set and promoted a password with `-` or `.`, at
  the application's next connect. About half of 24-character `alnum_safe`
  passwords contain one. #742 accepted no such cost for `$`, which a shell and
  a `.env` file change without an error.
- **Rejected:** Drop `-` and `.` from `alnum_safe`, so that it needs no quoting
  in a JDBC URL either. That is a second breaking change to the alphabet after
  #742.

## #629

- **Decided:** 2026-10-13, #629
- **Question:** Should the tool have debug output, and should it write it to a
  file? The profile keys `log_level` and `log_file` were parsed and read by
  nothing. Implement them or delete them?
- **Decision:** A `--debug` flag writes debug output to stderr, at one level.
  The tool writes no log file. The profile keys `log_level` and `log_file` are
  deleted, and the config schema moves to 2.0.
- **Why:** Errors already carry the vendor code, a category, a hint and the
  server's message. The run document and the events, joined to the database
  audit trail by `run_id`, are the audit record. What is missing is what
  happened inside a run: the capabilities found, the statements sent, the vault
  calls made, and why a unit was skipped. stderr is where most command-line
  tools put this, and a shell or a scheduler already captures it. `2> file`
  works in bash and PowerShell. A file the tool writes on every run would hold
  host names, account names and vault paths in the user's home directory, and
  it would need permissions, a location and retention on each platform. Debug
  output is not part of the JSON contract, so a new debug line is not a schema
  change. The cost accepted: a failure seen once, without `--debug`, has no
  debug record, and a scheduled run that wants one adds the flag to its
  command line.
- **Rejected:**
  - No debug output: a failure the error does not explain would need a code
    reading or Oracle Net tracing, and Oracle Net tracing can record the
    password.
  - `-v` levels: every new debug line would need a level chosen, and one level
    is enough for a run the operator repeats with the flag.
  - `--log-file PATH`: possible later, and adding it breaks nothing. It saves a
    redirect, and costs a file the tool must create with the right permissions
    on POSIX and Windows.
  - A log file on every run, as gcloud and npm write: see above.
  - Keep `log_level` and `log_file` as profile defaults for the flag: a config
    would then turn debug output on for every run of a profile, including
    scheduled runs nobody watches. Keeping them unread leaves keys that look as
    if they work. [#787](#787) removed a profile's `verify.*` and
    `rotation.strategy` for the same reason.

## #786

- **Decided:** 2026-10-14, #786
- **Question:** `03-json-output.md` §4 said driver errors pass through a
  scrubber, and none existed. Can a server message hold the password, and if it
  can, what does the tool do about it?
- **Decision:** It can. The Oracle driver replaces the exact password with
  `***` in the message of any error from a statement that carried one. The
  statement does the replacing, so the value never leaves the type that already
  holds it. The client's exception still holds the unscrubbed message, so the
  driver's error is not chained to it.
- **Why:** A password verify function is site-written PL/SQL, and it receives
  the password. The text it raises comes back as an `ORA-20000` inside the
  `ORA-28003`. Measured on 26ai 23.26.2.0.0 with a function that quotes the
  value: the client's message held it, and `creds apply --debug` wrote every
  refused draw to stderr, the last of them the value staged as `pending`. Text
  and JSON output were clean only because `_as_error` keeps the first line of a
  per-target error. The `ORA-20000` text says which rule was broken. Normal
  output drops it with the rest of the second line. It shows under `--debug`,
  where an operator looks to find out why a draw was refused, and when a driver
  error ends the run. The cost accepted: a function that quotes part of the
  value, or the value changed, is not caught.
- **Why not at the serialiser:** invariant 2 puts redaction there for a value
  the tool holds as a `Secret`. This text comes from outside: the server wrote
  it. The serialiser cannot tell which part of a message is a password, and the
  driver is the one place that knows which value the statement carried.
- **Rejected:**
  - Fix the doc only, on the grounds that an ORA- message does not echo the
    statement: the verify function's text is not the statement, and it is not
    Oracle's.
  - Drop the text after the codes in a reply to a password-bearing statement:
    nothing could leak, but `--debug` would lose which rule was broken.
  - Replace the exact value, and also drop an `ORA-20xxx` line that still holds
    a long run of the value's characters: safer against a partial quote, but it
    is a heuristic in a credential path.

## #785

- **Decided:** 2026-10-14, #785
- **Question:** The catch-all in `main()`, `_classify` and `_as_error` print the
  message of an exception that a library raised and the tool did not convert.
  Can that message hold a secret, and should these places print only its type?
- **Decision:** They keep printing the message. Code that passes a `Secret`, or
  bytes read as one, to a library converts every error that library raises into
  a tool error. The tool error names the library's error by its type and leaves
  out its message.
- **Why:** The audit found these places where a library's message could quote
  a secret:
  - The webhook parsed its URL before its `try`, and `httpx.InvalidURL` is not
    an `httpx.HTTPError`. Its message quotes part of the URL, such as
    `Invalid port: 'abc'`, and the URL is the credential. A URL with a
    character httpx cannot encode raises `UnicodeEncodeError`, which quotes it.
  - httpx encodes a header as ASCII. A token with any other character raised
    `UnicodeEncodeError` with that character and its position.
  - A token with a line break, such as a `
` left by a file saved on Windows,
    raised `httpx.LocalProtocolError`, and its message quoted the whole token.
  - The vault transport raised every httpx error other than a timeout or a
    connection failure as it was. One is an encoding error for a body, and the
    body of a write or a login holds a secret.
  - `--from-stdin` read stdin as text with `surrogateescape`. A byte that is not
    UTF-8 became a surrogate character inside the password, and the vault
    write's encoding error then quoted it with its position.

  Each now converts the error, and `--from-stdin` reads bytes and refuses a
  byte that is not UTF-8. An Oracle error from a query passes through
  unconverted and carries no secret: its statement holds no password
  (invariants 13 and 14). This follows #786: the code that holds the value is
  the code that knows to keep it out.
- **Rejected:**
  - Print only the type of any exception the tool did not raise: the rule would
    hold by structure, not by each call site. But an Oracle error from a query,
    such as an `ORA-01031` for a missing grant, would show only its class name
    unless `traced_cursor` converted every error. A bug would show only
    `KeyError`. And `--debug` prints the message of the exception at the top of
    its traceback, so it would need the same change.

## #240

- **Decided:** 2026-10-14, #240
- **Question:** Should `doctor` check that the TNS alias in an `external`
  target's `dsn` resolves?
- **Decision:** No. `doctor` does not look up the alias.
- **Why:** The connection already reports this case well. An alias that does
  not resolve fails with `ORA-12154`. Instant Client 23.26.3.0.0 raised it with
  the default `sqlnet.ora`, with `NAMES.DIRECTORY_PATH=(TNSNAMES)`, and with
  `(TNSNAMES, EZCONNECT, HOSTNAME)`. Its message names the file it searched.
  The driver maps it to `UNREACHABLE`, with a hint that names the dsn and
  `TNS_ADMIN`, in the target's own `targets[]` entry. #215 added the wallet
  report because a wallet fault shows up as an error about the login, which
  points at the wrong cause. A missing alias shows up as an error about name
  resolution, which is the right cause. A check would report it only a few
  seconds earlier. It would also be wrong in some estates. An alias can come
  from LDAP, through `names.directory_path` and `ldap.ora`, and a parser of
  `tnsnames.ora` cannot see it. The file, or a file that `IFILE` names, can be
  unreadable to this process. A false "alias not found" sends someone to fix a
  file that is correct.
- **Rejected:** A parser that reports a missing alias only when it can see
  every source: a readable `tnsnames.ora`, every file that its `IFILE` lines
  name, and no directory path other than `TNSNAMES`. In every other case its
  only honest output is "not in the file I could read", and that is not worth
  the code.

## #655

- **Decided:** 2026-10-14, #655
- **Question:** What does `sopuli admin install` do, if anything? The run
  schema's `command` enum held `admin.install` from the first commit, but no
  document said what the command does.
- **Decision:** No `admin install` command. A DBA installs the service account
  by running `sql/oracle/00_install.sql` as SYSDBA or an equivalent account.
  `admin.install` is removed from the enum in run schema 1.37. The verb is
  declined and no build ever emitted it, so the removal is minor
  (`03-json-output.md` §8). UC-4 decides whether provisioning covers installing
  the service account. If it does, that is a UC-4 verb with its own name, and
  adding it to the enum is a minor bump.
- **Why:** The command would add the most by generating the service account's
  password and writing it to the vault first. That is also the expensive part.
  It needs a credential the tool otherwise never holds, SYSDBA or an
  equivalent. It also needs an order for the vault write and `CREATE USER`, and
  a plan for when one succeeds and the other fails (invariant 7, UC-1 §3).
  Creating the service account is provisioning, and UC-4 must define a
  privileged principal for provisioning anyway. So the question belongs there.
- **Rejected:**
  - Print the script with its values filled in, for a DBA to review and run.
    A DBA already passes the script's few values directly, so this saves
    little.
  - A full install now: a credential to run it, config for the script's mode,
    tablespace and grants, and a plan, `--dry-run` and `changed: false` on a
    second run. It is the largest new privilege surface since UC-1, for a step
    done once per database.

## #516

- **Decided:** 2026-10-15, #516
- **Question:** UC-2's journal and its delivery can use different vaults. When
  the journal's store is down and the delivery's store is up, should
  `account reset-password` still refuse?
- **Decision:** Yes. When `reset_records:` is declared and its store cannot be
  reached, the reset refuses before any DDL, even when the delivery's store is
  up. UC-2 §3.3 applies to two stores as it does to one.
- **Why:** The journal's store holds the lock, and the lock is what stops two
  DBAs from resetting the same person at once. A reset without its lock would
  look like a locked one in the output, which is the failure #515's review
  found. A journal vault outage is rare and short. An estate that must reset
  during one can remove `reset_records:`: the run then takes no lock, and
  `SOPULI-W024` says so at plan time. That way an operator chooses it.
- **Rejected:**
  - Go ahead with no lock, and warn. Neither `SOPULI-W024` nor `SOPULI-W025`
    describes a store that was declared, could not be reached when the lock was
    taken, and answered later. So this needs a third code, and it makes two
    resets at once possible without anyone choosing that.
  - Require the journal and the delivery to use the same store, at load time.
    It forbids the split that UC-2 §3.5 describes. `01-configuration.md` §1
    documents it under `delivery:`: `vault_wrapped.vault` does not fall back to
    `reset_records.vault`.
  - A command-line flag to go ahead without the lock. It adds one more flag in
    front of a guardrail, and removing `reset_records:` already does this.

## #769

- **Decided:** 2026-10-15, #769
- **Question:** `creds rotate` checks its fence and then writes the secret
  document, in two requests. A takeover can land between them, and the write
  still goes through. Should the tool close that window, report it, or accept
  it?
- **Decision:** Accept the window, and never stage over a `pending` (#804).
  `creds rotate` and `creds generate` refuse where a selected account already
  has one. `generate --overwrite-pending` discards it, for an operator who
  means to. UC-1 §4 and §8 state the rule, the window and what follows.
- **Why:** Vault has no compare-and-set across two paths, so the fence check
  on the lock and the write to the secret cannot be one operation. As first
  decided, the window looked safe: what lands in it is a `pending` that holds a
  random password nobody has, the stale run's next fence check stops it before
  its `ALTER USER`, and the next `apply` applies and promotes that `pending`.
  The review of PR #803 found the case that is not safe. A `pending` is staged;
  a takeover `apply` sets it on the database; the stale `rotate` stages over
  it; the `apply`'s promotion then loses its compare-and-set. The database
  holds a password the vault has nowhere. That was reproduced on tier 1 on 3
  runs out of 3. With the refusal, the stale run's write can land only where
  its own read, under its lock, found no `pending`. A `pending` staged after
  that read changes the document's version, so the stale write loses its
  compare-and-set. The accepted cost is unchanged: if the run that took over is
  a `rotate`, the stale write can make that run's staging compare-and-set fail.
  It exits 1 and applies nothing, and it can be run again, but its error names a
  conflict and not the takeover. `tests/test_fault_lock.py` produces each case.
  The refusal changes [#254](#254): it rejected a sticky `pending` because the
  flag would cost the ordinary case, a password that went into a ticket. That
  cost is now paid, because the alternative loses a password.
- **Rejected:**
  - Write the lock's version into the secret document, and have `apply`
    refuse or ignore a `pending` written under an older fence. It is the only
    option that closes the window. But it changes the secret document's format,
    and it needs a rule for documents written before the change. The harm it
    prevents is that a password nobody holds gets applied, which is not worth
    that cost.
  - Check the fence again after the write, and report a `pending` that landed
    after a takeover. It costs one more read per document, and it closes
    nothing: removing the `pending` would be another write with the same
    window.

## #787

- **Decided:** 2026-10-16, #787
- **Question:** A profile's `verify:` and `rotation:` blocks, and a policy's,
  were parsed, validated and read by nothing. A policy that wrote either block
  got `SOPULI-W034`, and a profile got no warning. Warn about the profile's
  too, wire them as defaults for the flags, or remove them?
- **Decision:** Remove all four blocks before the repository goes public. A
  config that writes one is refused with exit 9. The message says the block was
  removed, and the hint names the flags that set what it named: `--method`,
  `--lockout-margin`, `--strategy` and `--max-age-days`. `SOPULI-W034` is
  retired. The config schema moves to 3.0.
- **Why:** Adding an optional key later is a minor bump, and every config still
  loads. Removing one later breaks every config that wrote it. So a key kept for
  a reader to come later saves nothing: it can come back with its reader.
  Keeping it also costs something. A config that wrote `verify: { method: hash }`
  would change behaviour on the upgrade that wired it. Before any outside user
  has a config, removing a key breaks nobody.
- **Rejected:**
  - Warn about a profile's keys, as for a policy's. It keeps keys that do
    nothing, and the same upgrade problem.
  - Wire them as defaults for the flags. `verify.method` accepts `none`, and
    `--method` does not. `rotation.strategy` needs two decisions first: whether
    a strategy in a profile counts as given, so that the refusals `--strategy`
    triggers apply, and whether `--strategy` may relax it. `direct` ends a grace
    window early. A profile default can still be added later, with its own
    issue.

## #819

- **Decided:** 2026-10-16, #819
- **Question:** A label key in a group `match:`, a `targets: { match: … }` or an
  override `where:` that no target in the estate carries can match nothing, so
  the entry silently applies nowhere. Refuse it, warn about it, or leave it?
- **Decision:** Refuse it with exit 9, before the repository goes public. The
  message names the key, and the hint lists the label keys the targets carry.
  The estate is checked after expansion. A label value that matches no target
  stays allowed.
- **Why:** `01-configuration.md` §2 allows a value that matches nothing,
  because the estate changes underneath a label. A key no target has is a
  different case: nothing can match it until somebody adds that label, and the
  usual cause is a typo (`tenent:`) or another word for an account (`user:`).
  Adding a refusal later would make configs that load today fail, so it is
  cheap only before anyone outside uses the tool. The cost accepted: a group
  written ahead of the label it matches, such as one that carries only
  `safety: { readonly: true }` for `tier: critical` before any target has
  `tier`, is refused too. Its author adds the label to a target first. A
  `--select` on the command line is not checked: refusing there is a separate
  question.
- **Rejected:**
  - Warn. It needs a code, and tightening it to a refusal later is the
    breaking change this decision avoids.
  - Leave it. #818 refuses only `account` and `accounts` in `where:`, so other
    typos stay silent.

## #830

- **Decided:** 2026-10-17, #830
- **Question:** Several bindings that resolve to one field and pointer in one
  document hold one password. An override, or a second application entry, can
  give them different policies. What happens then?
- **Decision:** Refuse the file at load, with exit 9, before the repository
  goes public. The error names the account, the ref, and each policy with a
  target it governs. The hint says to use one policy, or to give each target its
  own secret with a target label in the ref.
- **Why:** One stored password cannot follow two policies. `creds generate`
  drew one password per binding, and the last draw won, so the stored value
  followed only the last binding's policy, and nothing said so. `creds check`
  would then report it against the other policy on every run. The contradiction
  is in the file, so the file is what is refused, and every verb and
  `config validate` see it. A config that loads today stops loading, which is
  cheap only before anyone outside uses the tool. The check uses the stores the
  file states. A binding whose store comes only from a profile or
  `SOPULI_VAULT` is not compared with one that names a store, as the
  stage-collision rule is not.
- **Rejected:**
  - Check again once a run has filled in the stores. The run's selectors have
    already narrowed the bindings by then, so whether it refused would depend
    on the selection.
  - Refuse in `creds generate` and `creds rotate` only. The config would still
    load, and `creds check` would still judge one password by two policies.
  - Draw one value that satisfies every policy. It cannot work when the
    policies disagree on an exact length, so that case would still need a
    refusal.

## #841

- **Decided:** 2026-10-17, #841
- **Question:** `01-configuration.md` §10 refuses one entry whose ref gives two
  accounts one ref. Two entries can still put two accounts on the same field
  and pointer, or on places where one contains the other. Refuse that too?
- **Decision:** Refuse it at load with exit 9, before the repository goes
  public, on every store, for the same place and for nested places. The error
  names both accounts, where they are declared, and the refs. It runs before
  the stage-collision rule. Where one store comes only from a profile or
  `SOPULI_VAULT`, the file cannot show the pair. `generate.draw_once` then
  draws each account its own value, and `generate.group` refuses a write
  that carries two values for one password, before anything is written.
- **Why:** Two accounts on one field are one password for two principals. The
  second write overwrites the first, and the application that reads the first is
  locked out at the next rotation, which is the reason
  `01-configuration.md` §10 gives for the in-entry rule.
  Where staging is emulated, the stage-collision rule already refused such a
  file, with a hint about a bare `#{account}` that did not fit. Where a store
  stages natively, as OCI does, nothing refused it. A config that loads today
  on such a store stops loading, which is cheap only before anyone outside
  uses the tool.
- **Rejected:**
  - Refuse the pair in `generate.draw_once`, once the run knows every store.
    It saw only the bindings the run's selectors kept, so a selector could
    remove the pair it was there to catch, as #830 found for the policy rule.
  - Widen the in-entry rule to look across entries. It reads the ref template,
    not the rendered refs, so it cannot tell when two templates meet on one
    field. The bindings can.

## #547

- **Decided:** 2026-10-17, #547
- **Question:** `04-testing.md` §6 says gate 2 runs on each supported major
  release and gate 4 on every Oracle release in the matrix, and that no release
  happens while a gate is red. Does every release re-run them on each Oracle
  release?
- **Decision:** No. A release runs gates 1, 3, 5 and 6, and gate 4 in tier 1
  on the 26ai image. For gate 2 it cites the probe runs recorded in
  `docs/measurements.md`, which stand until the probe or the statement text the
  tool sends changes. Gate 4 runs on the other releases when the verification
  path or its lockout guard changes. Then that gate runs again on each release.
- **Why:** the other releases run on the maintainer images, which need an
  Oracle account, and on OCI, which costs money. Their results depend on the
  Oracle release and on the code the gate measures, not on the rest of a
  release.
- **Rejected:**
  - Re-run gates 2 and 4 on every Oracle release for every release. The cost is
    a day's maintainer time and an OCI bill, for runs that would repeat the
    recorded ones while the probe and the measured code are unchanged.

## #892

- **Decided:** 2026-10-18, #892
- **Question:** `SOPULI-W051` warns when `VAULT_ADDR` overrides the address the
  file declares for a store. `VAULT_NAMESPACE` and `VAULT_CACERT` override the
  file at the same layer. Should they warn, and under which code?
- **Decision:** `VAULT_NAMESPACE` over a different `namespace` in the file warns,
  with a code of its own, `SOPULI-W052`. It warns where the file declares no
  `namespace` too, because that means the root namespace. `VAULT_CACERT` over
  a different `tls.ca_file` does not warn.
- **Why:** a namespace left over from other work sends the login and the writes
  to another Vault Enterprise namespace, which is the hazard `SOPULI-W051` is
  for. A CA file sends nothing to another place. It can only make TLS fail, or
  verify against another CA, which still has to have issued the certificate the
  server presents. A warning on every run for that would teach operators to
  ignore the others.
- **Rejected:**
  - Widen `SOPULI-W051` to name the setting. Its published meaning is the
    address, and a consumer that filters on it would start to get namespace
    messages.
  - Warn about `VAULT_CACERT` too. It is noise for a case that cannot send auth
    material elsewhere.

## #902

- **Decided:** 2026-10-19, #902
- **Question:** When a backend's or driver's client is not installed, the hint
  gives a `pip install` line. After a pipx install, that line installs a second
  copy into the user's own Python, and the copy that ran still has no client.
  What should the hint say?
- **Decision:** Both lines. The pip line stays as it was, and a pipx line
  follows it: `pipx runpip sopuli-dba install "sopuli-dba[<extra>]"`. The JSON
  keeps `install_command` and adds `pipx_install_command` beside it.
- **Why:** pipx is the recommended install (`getting-started.md` §2), so the
  pip line alone sends most new users to the wrong command. `pipx runpip` runs
  pip inside the environment pipx made. pip finds the tool already installed
  and upgrades only what a requirement needs, so it adds the extra's
  dependencies and nothing else. On pipx 1.0.0 and 1.18.4 this kept the
  install's Python, its version and its other extras, and they stayed after a
  `pipx upgrade`. The cost: pipx does not record an extra added this way, so a
  `pipx reinstall` drops it.
- **Rejected:**
  - Detect pipx from `sys.prefix` and print only the matching line. It is a
    guess about pipx's folder layout, which pipx does not promise, and a wrong
    guess sends the reader to the wrong command.
  - A neutral line that names the extra and links to getting-started. It never
    goes stale, but the reader cannot paste it.
  - `pipx install --force "sopuli-dba[<every extra wanted>]"`. On pipx 1.18.4
    it reinstalls from PyPI and upgrades to the latest release, so adding one
    client also upgrades the tool, and an install from a wheel or another index
    is replaced. The line also has to name every extra already present, or
    `--force` removes them.

## #904

- **Decided:** 2026-10-19, #904
- **Question:** A proxy or WAF in front of Vault can block the PATCH method and
  answer 401 itself, while it lets GET, POST and DELETE through. The KV v2
  adapter reads a 401 as an invalid token, so every write fails with an auth
  error and never falls back to read-modify-write. How does an operator use the
  tool behind such a proxy?
- **Decision:** A store key, `merge_patch`, default `true`. `merge_patch: false`
  drops `merge_patch` from the KV v2 store's `supports()`, so every write goes
  straight to read-modify-write under compare-and-set, the existing fallback. It
  is a per-store setting like `timeout_s`, so `defaults.vaults:` or a profile can
  set it too. It has no environment variable.
- **Why:** the operator knows the proxy is there and the tool cannot. The
  fallback it selects is the one a Vault policy without `patch` already gets,
  with the same compare-and-set and the same reporting. It is as safe against a
  concurrent writer, and it sends the whole document. A per-store setting fits
  a network where only some machines are behind the proxy.

  A layer may set it, and it does not ratchet. Under a merge patch a sibling
  account's password is never read into the process, so `false` is the wider of
  the two. It is still not a safety setting in invariant 10's sense: it relaxes
  no guardrail, and a Vault policy can already force the same fallback with no
  configuration at all. The run reports read-modify-write each time it is used,
  and the message names `merge_patch: false` as one of the causes. A ratchet
  would make `true` win, which breaks the case the key exists for: a profile for
  the machines behind the proxy.

  It is refused where nothing reads it: on a store that is not HashiCorp, and on
  KV v1, which has no merge patch. P3 refuses a key the tool would ignore. The
  check runs on the merged values, so a layer cannot write it there either.
- **Rejected:**
  - Read a PATCH 401 whose body is not Vault's `{"errors": [...]}` as a patch
    refusal. It needs no configuration, but it guesses from the shape of a body,
    and a proxy that copies Vault's format would defeat it.
  - Leave it to the infrastructure: let PATCH through and grant `patch` in the
    policy. That is the better fix where an operator can get it done. It is
    outside the tool, and often outside the operator's reach.

## #909

- **Decided:** 2026-10-20, #909
- **Question:** Should the tool connect with an administrative privilege
  (`SYSDBA`), so that a DBA can point a target at `SYS`? A DBA trying the tool
  often uses `SYS` before installing the service account. `SYS` logs on only as
  SYSDBA or SYSOPER, so the connect fails with `ORA-28009`.
- **Decision:** No. The tool connects only as an ordinary account. `ORA-28009`
  is mapped to `config` and exit 9, and its hint names the service account that
  `sql/oracle/00_install.sql` creates, and `SYSTEM` for a trial in a PDB (#908).
- **Why:** a change made as `SYS` is recorded in the audit trail under `SYS`,
  not under a named account. The audit trail is the evidence that a rotation
  happened and who made it, and the security model calls auditing the boundary.
  A trial does not need SYSDBA: `SYSTEM` connects to a PDB with no setup. On
  2026-10-20, `creds generate`, `creds apply` and `creds check` as `SYSTEM`
  succeeded in `FREEPDB1` on 26ai Free 23.26.2.0.0.

  `SYSTEM` is for a trial only, and the hint says so. It has the same audit
  problem as `SYS`: its changes are recorded under `SYSTEM`, and it holds `DBA`.
  In `CDB$ROOT` it also falls short: its `ALTER USER` comes through a role, which
  reads as absent (`02-oracle-privileges.md`), so common accounts are refused.
  `doctor --check-privileges` reports how much more than the tool needs it holds.
- **Rejected:**
  - `admin.privilege: sysdba`, with a warning on every run. It is the easiest
    start, and every rotation would be attributed to `SYS`. It also needs a
    config key, a warning code, a run-schema bump and tier-1 coverage, and
    nobody has checked capability probing or `container_scope` for a SYS session
    in `CDB$ROOT`, which sees every container.
  - SYSDBA for the read-only verbs only, refused at plan time for a verb that
    changes something. No rotation is attributed to `SYS`, but it costs most of
    the option above, and `SYSTEM` already gives a trial in a PDB without it.

## #792

- **Decided:** 2026-10-20, #792
- **Question:** The `ORA-28003` hint said the server message carries an
  `ORA-20000` naming the broken rule. A per-target error keeps only the first
  line of the message, and the `ORA-20000` is on the second, so text and JSON
  showed the hint and dropped the line it pointed at. Should the hint change, or
  should the line be kept?
- **Decision:** Change the hint. It now says where the verify function's own
  message is: above the hint when the error ends the run, and under `--debug`
  otherwise. It also says not to share that output, because the message can
  quote part of the password. A per-target `error.message` still keeps the
  first line only.
- **Why:** the verify function is site-written PL/SQL that receives the
  password. The driver masks the exact value (#786), and a function that quotes
  part of it is not caught. Today that partial quote reaches `--debug` output,
  which an operator asks for, and stderr when a driver error ends the run. It
  does not reach `error.message`. Keeping the line would put it in
  `error.message` on every run, in the JSON a scheduler stores and ships.
  The first-line trim in `cli._as_error` exists for table layout, and its
  comment now says it also does this job.
- **Rejected:**
  - Keep the `ORA-20000` line in a policy error's message. The reader sees
    which rule failed without a second run, but a partial quote then reaches
    every run's output. That loosens invariant 2's guard on what leaves the
    process.

## #935

- **Decided:** 2026-10-21, #935
- **Question:** A placeholder's value goes into a secret ref as written, so a
  `/` in it adds a level. The account `acme/web` in `#DB/{account}` stores its
  password under `acme`, then `web`. Should such a value be escaped, refused,
  or left alone?
- **Decision:** Refuse a `/` or `#` in a name that a ref uses: `{account}` and
  its case variants, `{application}`, and `{container}` when the target has an
  Oracle container. `#` is in the rule as well as `/`, because Oracle allows it
  in an unquoted name. `01-configuration.md` §7 states the rule, with examples.
- **Why:** the password would land at a key, or in a document, that the
  operator never wrote. #928 and the empty-segment rule refuse the same kind
  of silent addressing in the pointer. A name is chosen for the database, not
  for the template, so the template cannot have meant the level or the field it
  makes. A common user's `C##` name was already refused through a placeholder,
  by the parser's "more than one `#`", so for those names this refuses nothing
  that loaded; it says why. `{target}`, `{env}` and the labels are chosen by whoever writes the
  template, so they may mean a level. A plain check for two characters has no
  edge cases to get wrong.
- **Rejected:**
  - Escape the value (`/` as `~1`). The name would mean what it says, but a
    file that nests through a placeholder today would store its password
    somewhere else after the change, with no error.
  - Refuse any name that changes the shape of the ref, found by comparing the
    rendered ref with the template's. It also covers a `~1`, a leading `vault:`
    and `@stage=`, but three review rounds each found new edge cases in it. Those
    three are decided in #940.
  - Leave it. A `/` in a name is rare, and the overlap check (#841) catches it
    only when two accounts collide.

## #940

- **Decided:** 2026-10-21, #940
- **Question:** Decision #935 refuses a `/` or `#` in a name a ref uses. A name
  can re-address a ref in three more ways: a `~` in the pointer starts an
  escape, a `:` before any `/` or `#` names a vault, and `@version=` or
  `@stage=` selects a version. Should those names be refused too?
- **Decision:** Refuse them, for the same names as #935. A `:`, `@`, `=` or `~`
  in a name is refused only where it does that job in the rendered ref, found
  by the parser's own rules. `01-configuration.md` §7 states the rule, with
  examples.
- **Why:** the password would land at a key, in a vault or at a version that
  the operator never wrote, as with #935. Refusing the character only where it
  does a job keeps names that work today, such as `acme:web` mid-path. Each
  name's span in the rendered ref is compared with where the separators are,
  so two names that make a qualifier between them are refused too.
- **Rejected:**
  - Refuse `~`, `:` and `@` in a name wherever it lands. It is simpler, but it
    refuses names that load and address the right secret today.
  - Leave it. Only quoted Oracle identifiers can hold these characters, so
    such names are rare, but each one is a password stored where nobody wrote.

## #809

- **Decided:** 2026-10-22, #809
- **Question:** `creds generate` named the accounts with a staged `pending`,
  and under `--promote` the ones whose `current` would be replaced, only in its
  text output. Where should the JSON say it: in `plan`, as diagnostics with a
  J3 code, or per row?
- **Decision:** Per unit in `plan`. Each `plan.units[]` entry of `creds
  generate` has `pending` (`staged`, `absent` or `unknown`), and under
  `--promote` `current` (`seeded`, `replaced` or `unknown`). `unknown` is a
  document the plan could not read. The read happens before `plan.resolved`,
  so the stream and the document carry one plan. Run schema 1.49, event
  schema 1.10.
- **Why:** a consumer that runs `--dry-run` to decide which flag to pass needs
  the answer per account. `plan.units[]` has the grain and order of
  `results[]`, and `plan` is the same on a dry run and a real run (J2).
- **Rejected:**
  - A list per document in `plan`, as the text tables show it. The consumer
    would have to join documents to accounts to units.
  - Diagnostics with J3 codes. Seeding a `current` is a normal state, not a
    warning, and on a real run they would repeat `SOPULI-W046` and
    `SOPULI-W047`.

## #825

- **Decided:** 2026-10-22, #825
- **Question:** `creds rotate --finish-rollover` reported the rollover windows
  it left open as one `SOPULI-W043` for the run, with the accounts and targets
  only in the message. Emit one entry per account and target, or keep one entry
  and add a structured list of the pairs?
- **Decision:** One `SOPULI-W043` per account and target, each with `account`
  and `target`. The text output keeps one line that names every pair. Run
  schema 1.50.
- **Why:** J3 says the message is not contract, so a consumer must not parse
  it. Every other per-account warning carries `account` and `target`, and a
  `diagnostic` already has both fields. The code means what it meant: a window
  was left open. A consumer that only tests for the code still sees it.
- **Rejected:**
  - One entry with a list of the pairs. `diagnostic` has
    `additionalProperties: false`, so the list would be a new field on every
    diagnostic that only W043 uses.
  - Moving W043 to `results[].warnings[]`, on each affected row. A consumer
    that reads the run-level W043 would stop seeing it.

## #979

- **Decided:** 2026-10-22, #979
- **Question:** Is the number of entries a diagnostic code emits part of the
  JSON contract? #825 changed `SOPULI-W043` from one entry per run to one per
  account and target, and bumped the run schema to 1.50, a file that differs
  from 1.49 only in its `$id`.
- **Decision:** The count is contract. Changing how many entries a code emits
  is a minor bump of every schema that carries the code: the run schema, and
  the event schema where the code is streamed. For W043 that is run schema
  1.50 and event schema 1.11. `03-json-output.md` §8 states the rule.
- **Why:** a consumer may count a code's entries, and `schema_version` is how
  it learns which builds behave which way. The change is minor, not major,
  because every entry keeps the code's meaning and a consumer that only tests
  whether the code is present sees the same answer.
- **Rejected:**
  - The count as wording, like the message. Changes like #825's would need no
    bump, but a consumer that relied on one entry per run would break with no
    version to tell it why.

## #855

- **Decided:** 2026-10-22, #855
- **Question:** Does a later `--config` file count as a higher-precedence
  source for invariant 10? The loader merged the files before the resolver saw
  any layers, so a later file could set `readonly: false` over an earlier
  file's `true`.
- **Decision:** Yes. Where two files write a safety setting at the same key in
  a mapping, the merged value is the safer one, by the resolver's own shapes.
  A later file whose value loses gets `SOPULI-W039`, naming both files. A
  later file that erases such a key, or writes it with the wrong type, is
  refused. A `targets:` list is still replaced whole, safety blocks included. W039 now
  fires in a case it did not before, so run schema 1.51 and event schema 1.12
  (#979). `01-configuration.md` §9 states the rule.
- **Why:** invariant 10 already reads this way, and P3 lists `--config` as a
  source whose later files override earlier ones. The case the ratchet exists
  for is a shared base file that holds a site's floor, with a team's own file
  layered on top.
- **Rejected:**
  - Exempting file layering, because whoever passes the files owns them. The
    person who passes the files often does not own the base file, and the base
    file is the one written to be relied on.
  - Matching a later `targets:` list's entries to an earlier one's by name, so
    that per-target safety held too. It breaks §9's rule that a list is a whole
    answer. A floor belongs in `defaults.safety`, which no later file can
    narrow to fewer targets.
  - A new warning code. W039 already means "a layer asked to relax a safety
    setting, and the ratchet held".

## #866

- **Decided:** 2026-10-22, #866
- **Question:** Should a password policy have a floor? `length: 1` loaded, and
  so did `charset: custom` with `allow: "a"`.
- **Decision:** A fixed floor. A policy is refused at load time if its
  `length:` is below 12, or its alphabet has fewer than 10 distinct characters
  after `"` is removed. The floor is the same for every policy, and no setting
  lowers it. A policy with no `length:` still loads.
- **Why:** A typo or a copied policy could give an application account a
  one-character password. Oracle's verify function may reject it, but not
  every profile has one. A fixed floor is simple to state in an error message.
  Twelve ASCII characters are 12 bytes, inside Oracle's smallest limit of 30.
  A `custom` alphabet of 3-byte characters is not: 12 of them are 36 bytes,
  so such a policy cannot be drawn on a release before 23. All three named
  charsets have more than 10 characters, so the alphabet rule
  refuses only a short `allow:`.
- **Rejected:**
  - A floor stated as entropy, such as 64 bits. It judges length and alphabet
    together, but the error message would have to explain bits to a DBA who
    wrote `length: 8`.
  - No floor. The typo case would stay open.
  - A setting to lower the floor. A site with a legacy account that needs
    shorter passwords cannot manage that account with the tool.

## #874

- **Decided:** 2026-10-22, #874
- **Question:** May two application entries declare the same database user on
  the same target with refs that address different places?
- **Decision:** No. The loader refuses two entries that bind one user on one
  target to different places. Names are compared with `upper()`, as the driver
  compares them, and targets after expansion. Two entries that bind the user to
  one place, in one spelling, hold one password and stay allowed. Two
  spellings are refused even at one place, because every later step keys on
  the name as written. A store that comes from a profile or `SOPULI_VAULT`
  counts as different from a store an entry names, because nothing after the
  load compares the two once the run has chosen.
- **Why:** The database holds one password for the user. Two places give two
  documents: `creds generate` draws two passwords, one run rotates the user
  twice, and the document applied second wins. The other application is locked
  out. Invariant 5 already says a name may not be declared twice. No verb
  writes one password to two places, so a mirror config fails at its first
  rotation.
- **Rejected:**
  - A mirror: `generate` draws once and writes the value to every place the
    user is bound to. It is a new feature, and invariant 7's promotion gate
    would then span documents. Mirror writes are C6, which is deferred to a
    later use case. Until C6 is decided, two entries are not a way to mirror:
    the loader refuses them.
  - Leaving it, with the double rotation and the lockout above. A config that
    loaded before this decision now stops loading; that cost is accepted.

## #856

- **Decided:** 2026-10-22, #856
- **Question:** Should the tool refuse, or warn about, a vault `addr` or a
  webhook `url` that is not `https`?
- **Decision:** Refuse it, unless the host is `127.0.0.1`, `::1` or
  `localhost`. The host is compared whole, so `localhost.example.com` is not
  exempt. A HashiCorp store's address is refused when the file is read, after
  the layers are merged, so `VAULT_ADDR` and `--vault-addr` are refused the
  same way as the file's `addr`. The webhook URL is refused when a run
  resolves it, before a password is drawn, because the file names only where
  the URL is. No setting waives the refusal.
- **Why:** Over plain HTTP everything the tool sends to a vault crosses the
  network in clear: the token, an AppRole `secret_id`, a userpass password,
  every password it writes, and the plaintext sent to `sys/wrapping/wrap`. A
  webhook URL carries the chat token. `tls.verify: false` already raises
  `SOPULI-W004` on every run, and plain HTTP is weaker than that. A loopback
  address never leaves the machine, so the tier-1 stack and a local Vault agent
  keep working.
- **Rejected:**
  - A warning on every run, like `SOPULI-W004`. A warning on every run is easy
    to stop reading, and the exposure here is the credentials themselves.
  - Leaving it. That the operator chose the address does not make the channel
    safe.
  - A setting to waive the refusal. It would be a ratchet setting, which is a
    separate decision. A site that runs Vault on plain HTTP inside its own
    network cannot use the tool until it adds TLS.

## #857

- **Decided:** 2026-10-22, #857
- **Question:** Should a config be able to require an encrypted Oracle
  connection before a password is sent? #697 reports an unencrypted connection
  with a notice, and the run goes on, so `ALTER USER ... IDENTIFIED BY` crosses
  the network in clear.
- **Decision:** Yes. `safety.require_encryption`, off by default, is a safety
  setting under invariant 10. With it on, `creds apply`, `creds rotate` and
  `account reset-password` refuse a target whose connection is not encrypted,
  or whose encryption could not be read, at plan time: exit 5, capability
  `encrypted_connection`, before a password is drawn or a database changed.
  It is resolved per target, and the connection that sends is read again
  before each statement. `01-configuration.md` §3a states the rule. Config
  schema 3.2.
- **Why:** the server setting, `SQLNET.ENCRYPTION_SERVER = REQUIRED`, is the
  fix, and the notice says so. A DBA who cannot change `sqlnet.ora` on every
  target still needs a way to stop the tool sending a password in clear, and a
  notice cannot stop a run that has already gone on. It is per target rather
  than for the whole run, unlike `readonly` (#424), because it decides whether
  one connection may carry a password: a group that requires it for `prod`
  should not refuse a `dev` target in the same run. It is exit 5 rather than a
  new code, because a missing capability is what invariant 4 gives exit 5 to.
- **Rejected:**
  - Leaving it as a warning. It informs, but it cannot stop the password
    crossing the wire.

## #872

- **Decided:** 2026-10-22, #872
- **Question:** Should `creds apply` run the guardrails on every target an
  account is bound to before it changes the account anywhere? It asked them per
  target as it reached each one, so it could change and confirm an account on
  one target before another refused it. #870 then held the document back with
  `SOPULI-W050`, leaving the changed target ahead of `current` on every run.
- **Decision:** Ask first. Before the first change, the run reads the guardrail
  state of each credential with a `pending` (or, on a rollback, a `previous`)
  to promote, on every target it is bound to, and skips a refused credential on
  all of them. The check at the point of change stays, and W050 covers a
  refusal found only there. `creds rotate` does the same, because it applies
  through the same code. W050 is now raised on fewer runs, so run schema 1.52
  and event schema 1.13 (#979). UC-1 §5 states the rule.
- **Why:** invariant 4 says a run finds what stops it at plan time, not part
  way through. Asking first means no database moves ahead of `current`, and
  the rule for an account skipped everywhere lets its neighbours promote. The
  read is a second connection to each target, made only for a credential
  bound to more than one target. With one target the run's own check already
  comes before the change, so most runs open no extra connection.
- **Rejected:**
  - Holding every target's session open across the run, so the read costs no
    second connection. It would keep connections idle for the length of the
    run.
  - Keeping #870's behaviour. W050 names the remedy and a rollover profile can
    cover the window, but the passing targets stay ahead of `current` until
    someone acts, and without a rollover profile their readers are locked out.

## #988

- **Decided:** 2026-10-23, #988
- **Question:** Should `creds apply --dry-run` say which credentials #872's
  guardrail pass would skip on every target? A dry run never ran the pass, so
  it did not say that a credential refused on one target would be changed on
  none.
- **Decision:** Only under `--preflight`. The survey already reads each account,
  so the pass's question is asked of what it read, and each credential the run
  would skip everywhere is `SOPULI-W055`. Under `--force` only the checks no
  flag waives refuse, as in the real run ([#1111](#1111)). A new code, so run schema 1.54 and event schema 1.15. UC-1 §5
  states the rule.
- **Why:** `--preflight` is where an operator asks what the databases will
  say, and it already connects, so the forecast costs no connection. A plain
  `--dry-run` opens none without `--preflight` or `--strategy`, and keeping that
  is worth more than the forecast.
- **Rejected:**
  - Running the pass in every dry run. A plain dry run would then connect to
    every target a shared credential is bound to.
  - Leaving it. The real run's `SKIPPED` rows already say which target refused
    and why, but only after the run has started.

## #998

- **Decided:** 2026-10-23, #998
- **Question:** A real `creds apply --preflight` surveyed each account and then
  #872's guardrail pass opened a second session per target to read the same
  accounts again, under the same lock. Should the pass decide from the
  survey's reads instead?
- **Decision:** Yes, wherever a full survey ran: `creds apply --preflight` and
  every `creds rotate`. The pass applies the same rule (`_refusals`) to the
  survey's reads and opens no session. Without `--preflight`, or with
  `--strategy` alone, it reads as before. Output does not change, so no schema
  bump. UC-1 §5 states the rule.
- **Why:** the second read cost one login per target, so one more entry in
  each database's audit trail, and lease time, for an answer the run already
  held. A survey that lets the run through has read every account the pass asks
  about. Its reads are a moment older, but the check at the point of change
  still asks the database, and `SOPULI-W050` covers a refusal found only there.
- **Rejected:** keeping the second read for a fresher answer. Being fresher
  than the survey protects nothing that the point-of-change check does not
  already protect.

## #997

- **Decided:** 2026-10-23, #997
- **Question:** Should a rotation preview say which credentials #872's
  guardrail pass would skip, as `creds apply --dry-run --preflight` does
  (#988)?
- **Decision:** Yes. `creds rotate --dry-run` raises `SOPULI-W055` for each
  credential the real rotation would change on no target. Nothing is staged
  yet, so the pass's credentials are the ones the rotation would stage: every
  credential due gets a `pending` that a promotion follows. The decision is the
  one `apply` uses. Not under `--force`, and not when the survey refuses the
  run. Run schema 1.55 and event schema 1.16, because the code is raised on a
  verb where it was not before.
- **Why:** a rotation's dry run always surveys every account it would rotate,
  so the forecast costs no connection, and it says before the run what the
  run's `SKIPPED` rows would.
- **Rejected:**
  - Leaving rotate out. A rotation preview would then pass while the rotation
    changed a shared credential on no target.

## #1013

- **Decided:** 2026-10-24, #1013
- **Question:** In mixed audit mode, which `AUDIT_TRAIL` values keep the
  `audited` check's `true`? #1004 made `NONE` give `unknown`, and every other
  value kept `true`, measured or not.
- **Decision:** An allow-list. `DB`, `DB, EXTENDED`, `OS`, `XML` and
  `XML, EXTENDED` keep `true`. #1025 measured that under each of them an
  enabled unified policy records a logon and an `ALTER USER`, on 21.3.0.0.0
  and 18.4.0.0.0. Under any other value the answer is `unknown`, and the
  detail names the value. The check compares the value in upper case, with
  `, ` between its parts. The values are unchanged, so no schema bump.
- **Why:** where the answer is unknown, the code refuses rather than guesses. A
  value nobody has measured is not taken as one that records. The measurement
  left no documented setting that loses a `true`. On 21.3.0.0.0 the
  `ORA-00096` message for a refused value lists exactly the measured settings
  and `NONE`.
- **Rejected:**
  - Only `NONE` gives `unknown` (option 1). It answers `true` for any value the
    tool does not expect.

## #1004

- **Decided:** 2026-10-23, #1004
- **Question:** In mixed audit mode with `AUDIT_TRAIL = NONE`, what should a
  reset's `audited` check answer? #1006 measured that there an enabled unified
  policy records nothing, on 21.3.0.0.0 and 18.4.0.0.0, while the policy views
  show it enabled. The check, which reads the views, answered `true`.
- **Decision:** The check reads `AUDIT_TRAIL` from `V$PARAMETER`, in mixed
  mode only. Under `NONE` the answer is `unknown`, never `true`, with a detail
  that names the parameter. Where the parameter cannot be read, a `true` is
  `unknown` too, with a detail that names the grant. The grant,
  `SELECT ON SYS.V_$PARAMETER`, joins the optional audit grants in
  02-oracle-privileges.md §2. The values are unchanged, so no schema bump.
- **Why:** it removes a `true` that the database does not back, without
  claiming a `false` that rests on two measured releases.
- **Rejected:**
  - `false` under `NONE`. It matches what was measured, but 12.2.0.1.0 and
    19.3.0.0.0 are untried.
  - Leaving it. The wrong `true` would stay on every mixed-mode database with
    `AUDIT_TRAIL = NONE`, the 19.3 maintainer image among them.

## #999

- **Decided:** 2026-10-23, #999
- **Question:** An application whose secret path moves in the config leaves its
  old document and that document's lock record in the vault, and no command
  removes or even shows them. Should the tool clean them up?
- **Decision:** Report only. `sopuli vault orphans`, a new `vault` command
  group, lists every record in a store `vaults:` declares that this tool wrote
  and that no binding declares: a document whose root holds `origin` or
  `rotated_at`, and a lock record under `locks/`. It prints the
  `vault kv metadata delete` command for each, and deletes nothing. It prints
  no command for a path whose lock is held and has not expired. A path any
  binding names is declared in every store, so a live document is never listed
  under a second name for its store. `getting-started.md` §8 lists the checks
  to make before deleting. Run schema 1.57 adds the `orphans` section and
  `SOPULI-W056`.
- **Why:** it would have been the first verb to delete from a vault, and the
  vault is master (invariant 6). A record may belong to another config that
  shares the mount, which the tool cannot tell. The operator can, so the
  operator runs the delete. `vault` and not `lock` or `creds`, because a lock
  record is half of what it reports, and a later verb about vault contents fits
  the same group.
- **Rejected:**
  - A delete verb, such as `vault prune`. It would need a `delete` method on the
    store interface, a new capability and a mutation audit event, and an answer
    to why `lock break` never deletes a lock record.
  - Documentation alone. The operator would have to find the old paths by hand.

## #1009

- **Decided:** 2026-10-23, #1009
- **Question:** An account the guardrails skip, such as one that holds `DBA`,
  keeps its `pending` when its siblings are promoted. `creds rotate` then
  refused over that `pending` (#769), so no account in the document could be
  rotated, and neither command the hint named got out of it.
- **Decision:** `creds rotate` does not stage an account its guardrails would
  skip. Step 3's reads decide it, as they decide the guardrail pass (#998). The
  `pending` refusal moves after step 3 and counts only the accounts the run
  stages, so a `pending` a skipped account already has is left as it is and
  refuses nothing. Under `--force` the account is staged and counted, as before.
  `creds generate` is unchanged.
- **Why:** the refusal protects a `pending` from being drawn over, and a
  rotation that does not stage the account does not draw over it. That clears
  a `pending` left by `generate` too.
- **Rejected:**
  - Leaving out skipped accounts in `creds generate` as well. It connects to no
    database, and `generate --offline` needs none, so it cannot tell that an
    account holds `DBA`.
  - Keeping the refusal for a skipped account's `pending`, with a hint that
    names the ways out. The document would still not rotate.

## #1018

- **Decided:** 2026-10-23, #1018
- **Question:** `sopuli vault orphans` exits 0 when every store it surveys
  failed its listing, with `listed` empty and one `SOPULI-W056` per store. A
  scheduled job that reads only the exit code sees a clean estate. Should the
  run fail?
- **Decision:** Fail when nothing was listed and at least one store that can
  list failed. The run exits 1 with category `vault`, names those stores, and
  keeps its `orphans` section and its `SOPULI-W056` warnings. This holds with
  and without `--vault`. A run where at least one store was listed still exits
  0, and a run where no store can list still exits 5.
- **Why:** the verb is meant to run on a schedule, and a survey that read
  nothing must not look clean to a job that reads the exit code. Exit 1,
  because no specific code fits: 5 is a missing capability, 6 is right only
  when every store refused the login for that reason, and 4 means some work
  succeeded. Each store's `SOPULI-W056` already gives its own reason.
- **Rejected:**
  - Keeping exit 0. It holds only for a consumer that reads the document.
  - Failing only under `--vault`. A default survey with one store, or with
    every store down at once, would still report a clean estate.
  - Exit with the first store's own category. With several stores the
    categories can differ, and the first is no more the reason than the rest.

## #884

- **Decided:** 2026-10-24, #884
- **Question:** The HashiCorp transport sent a path as written, and httpx drops
  everything after a `#` as a URL fragment. So every Oracle common user (`C##`)
  on a target shared one reset record and one lock, at `<prefix>/<target>/c`.
  Once each path segment is percent-encoded, a `C##` account's record is at
  `<prefix>/<target>/c##<name>`. What happens to the records and locks already
  at the old path?
- **Decision:** Accept the loss. The tool neither moves the old records nor
  says what they are. A reset of a `C##` account after the upgrade does not
  find the record an earlier release wrote, and takes its lock at the new
  path. `lock status` still lists a lock left at the old path, as the lock of
  an account `c`, and `lock break` can break it. The old path is also the path
  of an account named `C`, whose reset reads and locks the old record as its
  own.
- **Why:** the records are a journal, not a source of truth, and the vault keeps
  the old document for anyone who reads it by hand. A migration cannot be done
  reliably, because the one old record mixed every `C##` account on the
  target, and it does not say which account wrote it last. The cost accepted:
  while one operator runs an earlier release and another this one, they lock a
  `C##` account at two paths, so two resets of it are not kept apart. Every
  operator who resets `C##` accounts upgrades together.
- **Rejected:**
  - Migrate the old records to the new paths. The old record cannot say which
    account it belongs to.
  - Report the old path as a leftover in `lock status` and the reset path. It
    costs code for a state that exists only once, during the upgrade.

## #891

- **Decided:** 2026-10-24, #891
- **Question:** a vault address can hold a user name and password, as in
  `https://ops:token@proxy.example.com`. `config show` and `--explain` print
  the address as written, and `SOPULI-W051` masked it only in its own message.
  Should the tool refuse such an address, or mask it wherever one is shown?
- **Decision:** Refuse it in `vaults.*.addr`, in a profile or `defaults:`
  entry, in `SOPULI_VAULT_ADDR`, in `SOPULI_VAULT__<STORE>__ADDR` and in
  `--vault-addr`, when the file is read. For `VAULT_ADDR`, drop the user name
  and password, keep the rest of the address, and warn with `SOPULI-W057`.
  The refusal is of any `@` after the scheme, so a password holding `/`, `?`
  or `#` is found too. It applies to every store type. `VAULT_ADDR` is cut only
  where its one `@` ends the host part of a URL with a host after it.
  Otherwise the variable is not applied, with the same warning, because the
  cut address is the one the run connects to: cutting
  `https://vault.example.com/ui/@other.example.net` at the `@` would send the
  token to `other.example.net`. This was found in review (PR #1029).
- **Why:** Vault does not authenticate through the address, so a credential
  there is a proxy credential or a mistake. Refusing it removes the case, so
  no output has to remember to mask it. `VAULT_ADDR` belongs to another tool,
  and `01-configuration.md` §6 does not fail a run over another tool's
  variable. A proxy that needs a credential reads it from `HTTPS_PROXY`.
- **Rejected:**
  - Masking the user name and password in one shared renderer, used by every
    output that names an address. It keeps proxy credentials in the address
    working, but every new output would have to use the renderer, and
    invariant 2 puts redaction at the serialiser, not at each call site.
  - Refusing `VAULT_ADDR` too. The variable may belong to something else on
    the machine.

## #1059

- **Decided:** 2026-10-26, #1059
- **Question:** The PostgreSQL design refuses the tool's own account and a
  superuser, both "never overridable, like check 1". The guardrails are
  product-neutral, so the rule for the tool's own account reaches Oracle too,
  where `creds rotate` changes `C##SOPULI_SVC` today when it is declared. How
  should these two checks behave?
- **Decision:** Two checks join `02-oracle-privileges.md` §4. Check 6 refuses a
  superuser and is never waived. Check 7 refuses the account the session is
  connected as, and `--force` waives it, as it waives checks 2 to 5, with the
  waiver recorded. Both read `UserState`: `superuser`, which only the
  PostgreSQL driver sets, and `session_account`, which every driver sets.
- **Why:** A superuser's password is one a tool account that is not a superuser
  cannot change, and a superuser tool account is refused when it connects, so
  a waiver for check 6 would only move the refusal to the server. Changing the
  tool's own password mid-run can lock the tool out of the targets it has not
  reached, so it is refused by default. Rotating the tool's own password on
  purpose is ordinary work, so a waiver exists for it, as P3 gives one for
  `DBSNMP`.
- **Rejected:**
  - Never waiving check 7. Rotating the tool's own password would then have to
    happen outside the tool on both products, a change for Oracle, where it
    works today.
  - No check 7. The whitelist would be the only protection, and declaring the
    tool account by mistake, say through a role predicate, would go unnoticed
    until the run locked itself out.

## #1060

- **Decided:** 2026-10-26, #1060
- **Question:** With a verifier, the PostgreSQL server accepts a password of
  any length. libpq 13 cannot log in with one over 1024 bytes, and libpq 14 to
  18 can go much further (`pg-password-length`, #1057). What is the longest
  password on a PostgreSQL target?
- **Decision:** 1024 bytes, counted in UTF-8. For the generated charsets, which
  are ASCII, that is 1024 characters. A longer password is refused before
  anything is sent.
- **Why:** an application may still connect with libpq 13, and a password it
  cannot log in with would break it at its next login, after the vault and the
  database agreed. 1024 bytes is far above any policy in use, so the ceiling
  costs nothing.
- **Rejected:**
  - No ceiling. A libpq 13 client would fail with "out of memory", which
    names neither the password nor its length.

## #447

- **Decided:** 2026-10-27, #447
- **Question:** For `delivery.method: vault_path`, three things H8 left open or
  did not ask. How long does the stored copy live? Which path does the tool
  write, so that it is the one the person's policy lets them read? And what
  does the run document record about the hand-over?
- **Decision:**
  - **Lifetime:** the `vault_path:` block takes a required `ttl`. The tool
    writes it as the path's `delete_version_after` in KV v2, **before** it
    writes the value, and Vault deletes the version when the time runs out. A
    KV v1 mount is refused at plan time. The deletion time reported is the
    `deletion_time` in Vault's response to the write, and a response without
    one refuses the reset before the DDL.
  - **Path:** `<prefix>/<account>/<target>`: a configured prefix, the
    account's name exactly as the database stores it, and the target's name,
    such as `personal/ACME_DEV_ALICE/<target>`. Each name is one segment: a
    name containing `/` is refused, and other characters are percent-encoded.
    The Vault admin maps a person to that name with metadata on their identity
    entity, such as `db_account = ACME_DEV_ALICE`, and the person's policy
    grants `read` on
    `<mount>/data/<prefix>/{{identity.entity.metadata.db_account}}/*`.
  - **Record:** `results[].handover` gains `path` and `version`, the path
    written and the KV version the write created. `accessor` is `null` and
    `expires_at` is the version's `deletion_time`.
- **Why:**
  - A copy that persists keeps open, for as long as it exists, the one route
    by which a DBA can act as the person with no name of their own on record
    (UC-2 §1). Vault enforces `delete_version_after` itself, so nothing in the
    tool has to run later. `delete_version_after` applies only to versions
    written after it is set: on the tier-1 Vault (2.0.4), set after the write,
    it left the version without a `deletion_time`. Hence the order.
  - An alias name comes from the auth method: the LDAP login name, or the OIDC
    claim a role names. It matches a database account name only by
    coincidence, and Oracle stores names in upper case. Entity metadata is set
    by the Vault admin and kept with the identity. Measured on the tier-1
    Vault: the mapped identity read the value; an identity mapped to another
    account, one with no `db_account` key and one mapped in lower case were
    refused. A missing key grants nothing, so a missing mapping fails closed.
    The target is in the path because each target holds a separate password.
  - Vault's audit device logs the person's read under their own identity, and
    the path and version find it. Neither retrieves anything.
  - The costs are accepted. The deletion is a soft delete, so a token holding
    `undelete` on the path can bring the version back, and the documentation
    says "deleted", never "destroyed". A person who has not read the value by
    then needs another reset. The tool cannot see the mapping, so whoever can
    write entity metadata can point a person's path at their own identity. The
    DBA's token needs `create` and `update` on the metadata path too, and the
    plan-time check asks about both.
- **Rejected:**
  - The copy persists until the next reset overwrites it. A live credential
    would stay in Vault indefinitely, guarded only by the path's policy.
  - The tool destroys the copy later. Nothing in the tool runs later, so it
    would need a scheduler or a verb the DBA must remember.
  - A fixed name rule: the account name in lower case, with `C##` removed. It
    works only where directory names follow database names.
  - A map from account to alias name in the tool's config. It works for any
    naming, but it is a second list of people to keep in step with the
    directory, and an account a predicate admits would need an entry before it
    could be reset this way.

## #1045

- **Decided:** 2026-10-27, #1045
- **Question:** Is a connection pooler such as PgBouncer a supported
  PostgreSQL target? #1078 measured PostgreSQL 16.15 behind PgBouncer 1.26.0.
  A `db.query_timeout_s` sent as a startup parameter is refused, or dropped
  without a message. A plain `SET` leaks to other clients under transaction
  pooling. PgBouncer refuses a wrong password as "SASL authentication failed"
  with no SQLSTATE, so `creds check` reports drift as `ERROR`, and `creds apply`
  and `rotate` cannot change a password. `doctor` and `require_encryption`
  read the encryption of the pooler's hop to the server, not of the tool's own
  hop.
- **Decision:** Not supported, for now. A PostgreSQL target's `dsn` names the
  server. 01-configuration says so, and says what a run behind a pooler does.
  The driver does not change and does not detect a pooler, so a run there
  behaves as measured.
- **Why:** a DBA tool can usually reach the server directly, and poolers mostly
  sit in front of applications. Support would first need the pooler's
  authentication messages measured, a way to say a target is a pooler, a rule
  for the query budget, and a decision on what "encrypted" means across two
  hops. No estate has asked for it.
- **Rejected:**
  - Supported in session pooling, with no budget through the pooler. About a
    day of driver work and a tier-1 job, plus the encryption decision and a
    rule against `auth_file`, which checks a login against a file, not the
    server.
  - Supported in transaction pooling as well. Everything above, and every
    statement wrapped in a transaction with `SET LOCAL statement_timeout`, three
    round trips each, for a budget that is off by default.

## #445

- **Decided:** 2026-10-27, #445
- **Question:** How does `delivery.method: one_time_link` work with a Yopass
  server? Yopass's server stores only ciphertext. The client encrypts with
  OpenPGP, using a random key as the password, and the key travels in the
  link's fragment, which the browser never sends. So the tool must encrypt, and
  needs an OpenPGP library. Which one? And what does the tool print, check and
  record?
- **Decision:**
  - **Encryption:** `pysequoia`, Python bindings to Sequoia PGP, in a new
    `yopass` extra beside `httpx`. The tool encrypts the password with a random
    22-character key and sends `one_time: true` always, so the method has no
    key for it.
  - **Configuration:** the `one_time_link:` block takes `base_url`, the
    server's address; `ttl`, a duration in the grammar `vault_wrapped`'s `ttl`
    uses, such as `1h`, sent to the server in seconds; and `split_key`, a
    boolean.
  - **Split mode:** `split_key` is `false` by default. Off, the tool
    prints one link, `<link base>/#/s/<id>/<key>`. On, it prints the link
    without the key, `<link base>/#/s/<id>`, and the key, as two values for
    two channels. The tool also splits when the server's `/config` reports
    `DISABLE_ONE_CLICK_LINK`, because the server's admin has said not to hand
    out a link that holds its key, and when it reports `PREFETCH_SECRET` false,
    because then the page fetches a full link's secret as soon as it loads.
  - **Invariant 2:** the password reaches `pysequoia`'s encryption in the
    process, and only the ciphertext leaves it. That call is the method's
    store write, as the vault write is, and the `reveal()` it needs is in the
    method's module. The fifth exception widens from the wrapping token to the
    retrieval credential an unseen delivery returns: the wrapping token, the
    full link, or the key. `CLAUDE.md`, `03-json-output.md` and
    `tests/test_reveal_sites.py` change with the method.
  - **Plan-time checks:** the tool reads the server's `GET /config` before a
    password is drawn, and refuses with exit 5, naming the server and the
    setting, a server that is `READ_ONLY`, one that has `REQUIRE_AUTH`, and a
    `ttl` the server would refuse. The server accepts exactly
    `FORCE_EXPIRATION` when it reports one, any value from `MIN_EXPIRATION` to
    `MAX_EXPIRATION` when `ALLOW_CUSTOM_EXPIRATION` is true, and otherwise an
    hour, a day or a week, which the `ttl` grammar writes `1h`, `24h` or `168h`.
    A `--dry-run` reads `/config` too, because it needs no credential.
  - **The link base** is the `PUBLIC_URL` that `/config` reports, else the
    configured `base_url`. Both follow #856: plain `http` is refused unless the
    host is loopback. `base_url` is refused when the file is read, and
    `PUBLIC_URL` at plan time, with exit 5.
  - **Record:** `results[].handover` gains `id`, the secret's id. `accessor`
    is `null`. `expires_at` is the `Date` header of the server's answer to the
    create, plus `ttl`, so it comes from the server's clock, as Vault's expiry
    does. An answer without a `Date` header leaves it `null`.
- **Why:**
  - `pysequoia` is maintained and the encryption is one call. Its own code is
    Apache-2.0, and its wheels contain Sequoia PGP, which is
    LGPL-2.0-or-later. sopuli does not ship the wheel: an estate that installs
    the extra installs it from PyPI. The wheels build Sequoia with its
    RustCrypto backend and allow variable-time algorithms. This method uses
    only password-based AES-256 and SHA-256, so no secret key operation is
    involved. It has wheels for CPython 3.10 to 3.14 on Linux, macOS and
    Windows, and for 3.15 on Linux x86_64, which is the 3.15 CI cell. On
    Windows or macOS with 3.15 the extra builds from source and needs a Rust
    toolchain until a wheel appears. Measured with 0.1.35: it writes a
    password-encrypted session key (AES-256, iterated and salted SHA-256), then
    an integrity-protected data packet in the older SEIPD v1 format. GnuPG
    2.4.9 decrypted it with the key.
  - Split mode is the one handover in which no single channel carries
    everything that reads the password. Off by default, because the person has
    to type or paste 22 characters, and an estate with one channel gains
    nothing. In Yopass 16.0.1's web page, a link without its key asks for the
    key and fetches nothing until it is entered, so a link scanner cannot use
    up the view.
  - A Yopass secret on an unlicensed server is single-use and expires, but
    nothing records that the person read it. The id is the hand-over's only
    record. It names the secret and cannot read it: the key is not in it. Like
    a Vault accessor, it can destroy what it names. Whoever holds it can fetch
    the ciphertext once, which uses up the view, or delete it. Either is
    visible, because the person's fetch then fails. So the id goes in the run
    document, and the link without the key, which is the id with the link base
    in front, is printed in plain text. The key and the full link are
    secrets.
  - `REQUIRE_AUTH` needs an API token, which needs a Yopass licence. The tool
    refuses it now, and adding a token is a separate issue.
  - With `PREFETCH_SECRET` true, the default, the page asks before it fetches
    a one-time secret, so a scanner that opens a full link does not use up the
    view. A server run with `--prefetch-secret=false` fetches on load, but
    never for a link without its key. So the tool splits for that server,
    rather than refusing it or handing out a link a scanner can use up.
- **Rejected:**
  - `python-gnupg`. GnuPG would become a runtime prerequisite on every
    platform, as Instant Client is.
  - `PGPy`. Its last release is from 2022, and it does not import on 3.13.
  - Our own OpenPGP code on `cryptography`. About 150 lines of crypto code
    owned by this project, in credential handling.
  - The `yopass` Go client. Another binary prerequisite.
  - Split mode on by default. It costs every estate the typing, for a gain
    only an estate with a second channel gets.
  - A fixed set of `ttl` values in the config. It would refuse values a server
    with `--allow-custom-expiration` accepts.

## #124

- **Decided:** 2026-10-28, #124
- **Question:** Should the tool offer `SELECT_CATALOG_ROLE` as a narrower
  source of `LCOUNT` than `SELECT ON SYS.USER$` (P2)? Measured on 26ai Free
  23.26.3.0.0: to a session with the role enabled, `SYS.KU$_USER_VIEW` shows
  every user's `LCOUNT` and `PTIME` and masks the password verifiers.
- **Decision:** No. `SELECT ON SYS.USER$` stays the only source of `LCOUNT`,
  as an optional grant. `00_install.sql` and the driver do not change. The
  measurement stays in `02-oracle-privileges.md` §2.
- **Why:** the role's one gain is that the tool account cannot read the
  verifiers, so a stolen copy of its credentials gives no offline attack on
  them. That gain is small. The same account can already run `ALTER USER` on
  every account it manages. Hash mode needs `SYS.USER$` anyway. The role is not
  narrow: it holds 5663 object grants and shows much of the data dictionary.
  The view is not documented by Oracle and has release-specific branches, so
  every release would need measuring. A read through it leaves more rows in
  the audit trail, not fewer. And the driver would need a second `LCOUNT` path,
  a probe that recognises the masked view, and a split capability flag.
- **Rejected:**
  - Offer the role in `00_install.sql` beside `grant_user_dollar`, with a
    second `LCOUNT` path in the driver. The cost above, for the small gain.
  - Use the role automatically where a site already grants it. The same
    driver work, and a guard that turns on without the site asking.

## #1111

- **Decided:** 2026-10-28, #1111
- **Question:** On Supabase, supautils refuses a change to any role in
  `supautils.reserved_roles` by anyone but a superuser. The account guardrails
  should refuse such a role before anything changes, as they refuse a
  superuser, so that the server does not refuse the `ALTER ROLE` halfway
  through a run. Can `--force` waive that refusal?
- **Decision:** No. Check 8 joins `02-oracle-privileges.md` §4. It refuses an
  account the server reserves, and nothing waives it, as nothing waives check 6.
  It reads `UserState.reserved_by`, which only the PostgreSQL driver sets, from
  `current_setting('supautils.reserved_roles', true)`. Under `--force` the
  guardrail pass before the first change still runs, with only checks 6 and 8
  refusing, so a shared credential that one target refuses is changed on none.
- **Why:** Only a superuser may change a reserved role, and the tool refuses to
  connect as a superuser. A waiver would only move the refusal to the server,
  after the run had started, which is the failure check 8 exists to prevent.
  This is the reason #1059 gives for check 6.
- **Rejected:**
  - Reporting a reserved role as vendor-maintained, so that check 2 refuses it.
    No new check, but `--force` waives check 2, and a forced run would then fail
    at `ALTER ROLE` with the server's error. Check 2's message would not name
    the setting either.

## #1122

- **Decided:** 2026-10-28, #1122
- **Question:** A common account's failed logins are counted in `CDB$ROOT`.
  It locks on the limit of its profile in the root. In a PDB, `LCOUNT` reads
  0, `ACCOUNT_STATUS` reads `OPEN` while the account is locked, and
  `DBA_USERS.PROFILE` may name a profile that does not apply. Measured by
  `17_common_lcount_probe.sql` on 23.26.3.0.0, 21.3.0.0.0 and 18.4.0.0.0. What
  should the `LCOUNT` guard do for a common account on a target that is not
  the root?
- **Decision:** Report the guard as unavailable, as when the `SYS.USER$`
  grant is absent, and say why: the account's failed logins are counted in
  `CDB$ROOT`. The driver neither reads nor reports `LCOUNT` or the profile
  limit for it there. The login still runs. `DBA_USERS.COMMON` says whether
  the account is common, because `COMMON_USER_PREFIX` can be changed. An
  application-common account in an application container gets the same
  answer, because where its failed logins are counted was not measured. In an
  `unknown` scope, which may have no `COMMON` column, a `C##` name decides. A
  `--method hash` row says that a lock from failed logins may not show, since
  `ACCOUNT_STATUS` in the PDB reads `OPEN`.
- **Why:** The guard read 0 and a limit that may not apply, so it looked
  satisfied while it protected nothing. Saying that it is absent is UC-1 §7's
  rule for a guard that is not running. The login itself still shows a lock:
  the account answers `ORA-28000` to a right or a wrong password. Application
  accounts are rarely common accounts, so the gap is small.
- **Rejected:**
  - Read the root's count with `ALTER SESSION SET CONTAINER = CDB$ROOT`. Only
    a common tool account that holds `SET CONTAINER` can, so a PDB-mode
    install would still need this decision. And the driver opens one
    connection per target and never switches containers (`session.py`).
  - Skip the login for a common account outside the root. `check` could then
    never verify such an account by login. A site that wants no login spent
    on it already has `--method hash`.
  - Document the gap only. The guard would go on looking satisfied.

## #541

- **Decided:** 2026-10-28, #541
- **Question:** UC-2 §4.3 refused a seen (`manual`) reset of any account whose
  profile grants a rollover window, because `IDENTIFIED BY … PASSWORD EXPIRE`
  leaves the old password live there (07's Q7). Probe 09 then showed that from
  `EXPIRED` the same statement opens no window, so the refusal turned away
  UC-2's main case. Should the refusal narrow, and how?
- **Decision:** Remove the refusal. The seen reset closes the window after the
  set, with `EXPIRE PASSWORD ROLLOVER PERIOD`, as the unseen reset does. It
  refuses `--keep-rollover`, at plan time and again in the driver. A close that
  fails after the set is reported with the old password still working, and the
  statement that closes the window by hand.
- **Why:** The close was checked by logon. Probe 09 measured the set and then the
  close from `OPEN` and from `EXPIRED(GRACE)`, on 26ai 23.26.3.0.0 and 21c
  21.3.0.0.0, twice each: the old password answers `ORA-01017`, and only the new,
  expired one authenticates. From the expired states no window opens. One
  statement then ends the exposure on both paths. It also serves the `OPEN`
  account whose owner forgot the password. 19c with rollover is not measured;
  the reset keys on the capability.
- **Rejected:**
  - Keep the refusal. It refuses the expired account UC-2 exists for.
  - Allow only accounts whose status is `EXPIRED` or `EXPIRED & IN ROLLOVER`.
    It rests on `ACCOUNT_STATUS`, which #504 showed can disagree with what
    authenticates, and `EXPIRED(GRACE)` starts with `EXPIRED` but behaves like
    `OPEN`. It still refuses the `OPEN` account.

## #1137

- **Decided:** 2026-10-28, #1137
- **Question:** An OCI secret name allows only letters, digits, `-`, `_` and
  `.`, and is unique within a vault. A SecretRef path such as
  `apps/acme/prod/db` holds `/`. How does a ref on an OCI store name its
  secret?
- **Decision:** The ref's path is the OCI secret name, exactly. A path that is
  not one valid OCI name, is longer than 242 characters (255 less the lock
  record's `sopuli-locks.` prefix), or starts with the
  reserved `sopuli-locks.` is refused when the file is read, or when the run
  completes a binding's store. A rotated OCI ref names a field, and the
  payload rules of `01-configuration.md` §7 apply on OCI too.
- **Why:** External Secrets Operator reads an OCI secret by name
  (`GetSecretBundleByName`), so the name the tool writes must be the one the
  operator wrote, and one they can type into an `ExternalSecret`. The limits
  were measured in #1129 (`oci-name-rules`): 255 characters, and names are
  case-sensitive. A version's content holds the password beside the stamps
  that describe it, so a rotated ref needs a field.
- **Rejected:**
  - Translate `/` into `.` or another allowed character. `a.b/c` and `a/b.c`
    would name one secret, and the name in the vault would not be the one in
    the config.
  - Encode the path, for example as a hash. Nobody could predict the name to
    put in an `ExternalSecret`.

## #1138

- **Decided:** 2026-10-28, #1138
- **Question:** OCI Vault is the second secret store (#1128). Beyond how a ref
  names a secret (#1137), three things decide its scope. May the tool create
  OCI secrets, or only update ones that exist? Does the first OCI store serve
  personal accounts (UC-2) as well as application credentials (UC-1)? And
  what does the tool do with an OCI secret it did not create?
- **Decision:** The tool creates secrets. An `oci` store therefore declares a
  vault, a compartment and a KMS key, and IAM must allow `manage secrets`
  there. The first OCI store serves UC-1 only: a `reset_records:` store or a
  delivery store that is an OCI store is refused, when the file is read where
  the file names it, and before the reset's plan where a target or
  `defaults.vault` supplies it. A secret the
  tool did not create, such as one made by Terraform or ESO PushSecret, is used
  as it is when its content is a JSON object, and refused otherwise. Which KMS
  key encrypts it is not checked.
- **Why:** Every path the tool mutates gets a lock record, and nobody can
  create those ahead of time, so the tool must be able to create secrets; and
  `creds generate` seeds a new secret on HashiCorp too. UC-2 needs reset
  records and, for `vault_wrapped`, HashiCorp's response wrapping, which OCI
  has no equivalent of, so it is separate work. Refusing a foreign secret
  outright would make a Terraform-managed estate unusable, while content that
  is not a JSON object has no field for the tool to write.
- **Rejected:**
  - Only update secrets that already exist. Lock records cannot be created
    ahead of time.
  - UC-1 and UC-2 together. It doubles the first OCI work, and UC-2 needs a
    delivery design for OCI.
  - Refuse every secret the tool did not create. It rules out estates where
    Terraform or ESO creates the secret and the tool rotates it.

## #1133

- **Decided:** 2026-10-28, on #1128 (decision 8)
- **Question:** OCI keeps a secret busy for about 20 seconds after every write,
  refuses another write meanwhile with `409 IncorrectState`, and answers a read
  meanwhile with the old content (#1136, #1151). Does the store wait, and what
  does the operator see while it does?
- **Decision:** Each OCI write waits until the secret is `ACTIVE` again before
  it returns, polling every 2 seconds, bounded by the store's `timeout_s`
  (120 seconds when it is not set). The wait runs under the existing spinner,
  naming the secret. The spinner is the terminal's only: JSON output, a stream
  that is not a terminal, and `--debug` are unchanged. The store layer writes
  to no stream, so the CLI hands it the spinner for the length of a verb
  (`sopuli/store/waiting.py`), and outside a verb the wait shows nothing. If
  the wait gives up, the error says the write was made.
- **Why:** Without the wait, a `check` straight after `apply` reads the old
  password and reports a mismatch, and the next write to the same secret fails.
  Twenty silent seconds per write look like a hang. Handing the store a notice
  keeps the rule that the store layer neither prints nor imports the output
  layer.
- **Rejected:**
  - Wait only before the next write to the same secret. A read straight after
    the write would still see the old content.
  - Pass the emitter to every store. Each backend would then depend on the
    output layer, and the HashiCorp backend has nothing to wait for.
  - A separate setting for the wait. `timeout_s` already bounds how long the
    run may stall on this store, and the lock is held throughout either way.
