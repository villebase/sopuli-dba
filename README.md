<p align="center">
  <img src="https://github.com/villebase/sopuli-dba/raw/main/docs/assets/sopuli-dba-logo-glow.png" alt="sopuli-dba logo" width="240">
</p>

# sopuli-dba

**Change a database account's password without anybody having to know it.**

sopuli-dba is a command-line tool for database administrators. It keeps the
password of a database account in a *vault* — a server built to store secrets and
hand them out to the applications that need them — and then makes the database
agree with what the vault holds. The vault is always the source of truth for a
password. The database never is.

It supports Oracle, PostgreSQL, MySQL, MariaDB and SQL Server. It is designed so that other
database products can be added.

---

## Why use it

### The problem it solves

If you've looked after databases for a while, you probably know this picture:

- An application account's password was set years ago, and nobody dares change
  it. Nobody is sure which application servers, batch jobs and reporting tools
  have it in a config file, and a single missed one means a 3 a.m. call.
- When it *does* get changed, it's a planned change window with the application
  teams on standby. Someone changes the password on the database, someone else
  edits config files, and everyone hopes the list of places was complete.
- The one place that was missed keeps trying the old password until the
  database's failed-login limit locks the account, and then *every* application
  using it is down.
- The password has passed through e-mails, tickets, wiki pages and the heads of
  people who have since left.
- An auditor asks when this account's password was last changed and who knows it.
  The honest answers are "a long time ago" and "we're not sure".

The root cause is that **the password lives in too many places, and people have
to carry it between them.**

### What changes with sopuli-dba

The password is stored in one place: the vault. Applications read it from there
when they start or reconnect, instead of from a config file. The tool's job is to
keep the database in agreement with the vault. That gives you:

- **Nobody has to know the password.** The tool draws a random one, writes it to
  the vault and sets it on the database. No person reads it, types it or pastes it
  anywhere, so nobody can leak it or take it with them when they leave.
- **Rotation becomes routine instead of an event.** `sopuli creds rotate`
  generates, applies, verifies and publishes a new password in one guarded
  operation. Because nobody has to update config files by hand, you can run it as
  often as your policy asks: monthly, quarterly, or right after someone who knew
  the old password leaves.
- **The new password is published only after it works.** The vault holds the new
  password as `pending` while the tool sets it on the database and then *logs in
  with it*. Only when that succeeds is it promoted to `current`, the version
  applications read. If a run fails partway, nothing is promoted and the new
  password stays in the vault as `pending`, so running `sopuli creds apply` again
  finishes the job. That keeps the vault honest, but it does not by itself keep
  applications running: once a database has the new password, the old one stops
  working there, unless a rollover window (the next point) keeps it valid.
- **Applications don't have to switch at the same second.** On Oracle releases
  with gradual password rollover, and on MySQL and MariaDB, the tool can keep
  the old password working for a while beside the new one. Applications pick up
  the new one as they reconnect. When you close the window with
  `sopuli creds finish-rollover`, only the new password works. On Oracle the
  window also closes by itself after the time you chose.
- **One account on many databases stays consistent.** The same application account
  on twenty tenant databases, or across dev, test and prod, is one entry in the
  config file. One command brings them all in line, and `--dry-run` shows exactly
  what it would do first.
- **You find out about drift before the applications do.** `sopuli creds check`,
  run from a scheduler, logs in with the vault's password and reports whether each
  database still accepts it. If someone changed the password by hand, you hear
  about it from a report, not from an outage. On Oracle, and on MySQL 9.7 and
  later, it first reads the account's failed-login count, and does not try if one more failure
  would come too close to the lockout limit. Reading that count needs one
  optional grant; without it the check still runs, and each result says that
  the lockout guard was unavailable.
- **You get evidence for the auditor.** Every run can produce a machine-readable
  report of what was checked and what was changed. `sopuli creds status` shows
  each account's vault version, how old that password is, and when the database
  last recorded a password change, and the vault entry itself records when the
  tool last rotated it and which user on which host ran it. "When was it last
  changed, and by whom?" gets a real answer.

### What it asks of you

The benefits depend on one thing: **applications have to read the password from
the vault.** If today they hold it in a properties file, moving them to the vault
is the first step, and it's work the tool can't do for you. It doesn't have to
happen all at once, though. You can move one application at a time, and an
application that already reads from a vault gains everything above as soon as its
account is in the config file.

For applications on Kubernetes, the vault-to-application step can be automatic:
see [`docs/scenarios/kubernetes-eso.md`](https://github.com/villebase/sopuli-dba/blob/main/docs/scenarios/kubernetes-eso.md).

---

## Status

[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/villebase/sopuli-dba/badge)](https://scorecard.dev/viewer/?uri=github.com/villebase/sopuli-dba)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/15767/badge)](https://www.bestpractices.dev/projects/15767)

**Beta: the application-credential commands (UC-1), `sopuli creds …`, on
Oracle and PostgreSQL, with HashiCorp Vault. The rest is experimental.**

The version stays `0.x`. Beta promises three things for the beta part:

- **You may use it on production databases, with care.** A bug is still
  possible. The `--dry-run` and the plan a command prints first are there to
  catch one before it changes anything.
- **A change you have to act on comes with an upgrade note.** A change to the
  config format, to where and how the tool stores records in the vault, to an
  exit code, or to the JSON output's schemas is in
  [the changelog](https://github.com/villebase/sopuli-dba/blob/main/CHANGELOG.md),
  and [`docs/upgrading.md`](https://github.com/villebase/sopuli-dba/blob/main/docs/upgrading.md)
  says what to do about it. A change that only adds something optional, such
  as a new JSON field or config key, is in the changelog and needs no note.
  The JSON output's schemas are versioned too, so a change is never silent.
- **No silent loss of vault data.** What a release from 0.86.0 on wrote in the
  vault is still read by later releases, or the release that changes it says
  how to move it. [UC-1 §3](https://github.com/villebase/sopuli-dba/blob/main/docs/use-cases/uc-01-app-credential-sync.md#records-in-the-store)
  lists what the tool writes there.

**Experimental** parts work, and anything that goes wrong in them is a bug,
but they make none of the promises above. They are:

- the personal-account commands (UC-2), `sopuli account …`, on every database;
- the fleet reports (UC-5), `sopuli report …`, which read and change nothing;
- MySQL, MariaDB and SQL Server;
- OCI Vault, the `file` store, and the tool's own credentials in the OS
  keyring.

Each can become beta in its own release, once it has had the runs.

| | |
|---|---|
| **Install** | `pipx install "sopuli-dba[oracle,hashicorp]"`, with your database's extra in place of `oracle` (`postgres`, `mysql`, `mariadb` or `mssql`) and your store's in place of `hashicorp` (`oci` or `file`). SQL Server also needs Microsoft's ODBC Driver 18 for SQL Server as a system package. The *Installing* section below lists the extras and says how to get pipx. `sopuli --version` and `sopuli about` report the installed version. PostgreSQL needs libpq 16 or later: the `postgres` extra's wheels bundle one on Windows and Linux x86_64, and a psycopg built against an older system libpq is not supported |
| **Databases** | Oracle, for every command. PostgreSQL, MySQL, MariaDB and SQL Server, for every command that connects to a database, with `creds check` on SQL Server on a Linux host only. What a database has no counterpart for, such as a forced password change at next login on PostgreSQL, is refused before anything changes. Azure SQL Database and Azure Synapse are refused when the tool connects |
| **Not tested** | Each database has releases and platforms that nobody has run the tool on. [`docs/tested-releases.md`](https://github.com/villebase/sopuli-dba/blob/main/docs/tested-releases.md) lists the releases each database ran on, and the ones it has not. If you run another one, please report what you find |
| **Vaults** | HashiCorp Vault, KV v2 and KV v1, with token, AppRole, Kubernetes and userpass auth, for every command. OCI Vault, with API key, session token, instance principal and resource principal auth, for the application-credential commands (UC-1). With one account per secret, a pending password is an OCI PENDING version, which External Secrets Operator does not read, so an application cannot see it before the tool promotes it. The personal-account commands refuse an OCI store. A `file` store, one age-encrypted file, for local development and CI and the application-credential commands. It has no compare-and-set, so a command that changes it needs `locking: advisory-only` on it, and every run that opens one warns that it is not for production. The OS keyring is not a store, but it can hold the tool's own credentials, a vault token or a target's admin password, with `{ keyring: NAME }` and `method: keyring` |
| **What works** | The commands `sopuli --help` lists, including a full password rotation from end to end. [`docs/local-testing.md`](https://github.com/villebase/sopuli-dba/blob/main/docs/local-testing.md) runs the usual commands by hand |

If you want the full design picture — every decision, and every question that is
still open — start at [`docs/README.md`](https://github.com/villebase/sopuli-dba/blob/main/docs/README.md).

---

## What this is not

- It **does not create or drop database accounts.** The account has to exist
  already.
- It **does not manage grants, roles or privileges.** That is a separate feature,
  and it is not built.
- It **does not support a database that keeps no passwords**, such as IBM
  Db2, where the operating system, LDAP, Kerberos or RACF checks the logon. The tool
  changes a password the database stores, so it has nothing to change there.
- It **never reads a password back out of a database.** No database it supports
  stores a password in a form anything can read back, and the tool does not try.
- It **is not a general-purpose secrets manager.** It reads and writes the
  passwords of the database accounts your config names, in documents of its own
  shape. Beside them it keeps its own records: a lock, so two runs cannot change
  one password at once, and a record of each personal password reset. A reset
  delivered through HashiCorp Vault also leaves a wrapping token holding the new
  password, for the owner to unwrap. Everything else in your vault is none
  of its business.

---

## Installing

Install the tool with *pipx*. pipx installs a Python program that you run as a
command. It gives the program its own private set of packages and puts the
`sopuli` command on your `PATH`, with nothing to activate. A plain `pip install`
can leave the command in a folder that your shell does not search, and then the
shell does not recognize `sopuli`.

This installs pipx and then the tool, on Windows:

```powershell
python -m pip install --user pipx
python -m pipx ensurepath
# Open a new terminal, then:
pipx install "sopuli-dba[oracle,hashicorp]"
sopuli --version
```

On Linux, pipx usually comes from the system packages, such as
`sudo apt install pipx` on Debian and Ubuntu. The tool needs Python 3.11 or
newer. Where the system's own Python is older, such as on Ubuntu 22.04 or Oracle
Linux 9, install a newer one first. [`docs/getting-started.md`](https://github.com/villebase/sopuli-dba/blob/main/docs/getting-started.md)
§2 has the steps for each platform, what to do when the shell does not find
`sopuli`, and how to install without pipx.

**Install the backends you have, not all of them.** Every client that exists to
reach one vendor — a secret store or a database — is an install extra. The base
install carries the CLI, the config layer and nothing that opens a socket, so
`pip install sopuli-dba` gives you a tool that can read and validate a config and
reach nothing.

An *extra* is Python packaging's word for an optional part of a package. You ask
for one by putting its name in square brackets after the package name, and pipx
or pip then installs the extra dependencies that part needs. Name several in one
pair of brackets, separated by commas.

| Install | Adds | Use it when |
|---|---|---|
| `sopuli-dba` | nothing beyond the CLI and the config layer | you only need `config validate`, `config show`, `target list` — in an editor, a linter, a pre-commit hook |
| `"sopuli-dba[oracle]"` | `python-oracledb` | you manage Oracle databases |
| `"sopuli-dba[postgres]"` | `psycopg`, with the libpq it bundles | you manage PostgreSQL clusters |
| `"sopuli-dba[mysql]"` | PyMySQL, with `cryptography` for its RSA key exchange | you manage MySQL servers |
| `"sopuli-dba[mariadb]"` | PyMySQL, with PyNaCl for the `ed25519` plugin | you manage MariaDB servers |
| `"sopuli-dba[mssql]"` | `pyodbc`. Microsoft's ODBC Driver 18 for SQL Server is a system package, which you install from Microsoft, and on Linux and macOS so is unixODBC | you manage SQL Server instances |
| `"sopuli-dba[hashicorp]"` | the HashiCorp Vault client | your secrets are in HashiCorp Vault |
| `"sopuli-dba[oci]"` | the OCI SDK | your secrets are in OCI Vault / Secrets |
| `"sopuli-dba[file]"` | `pyrage`, an age library | your secrets are in a `file` store, for development and CI |
| `"sopuli-dba[notify]"` | an HTTP client for the notify webhook | `account reset-password` posts a notice to a webhook |
| `"sopuli-dba[yopass]"` | an HTTP client and `pysequoia`, an OpenPGP library | `account reset-password` hands a password over as a one-time Yopass link |
| `"sopuli-dba[onepassword]"` | 1Password's SDK, on Python 3.13 and earlier | `account reset-password` hands a password over as a 1Password share link that opens once |
| `"sopuli-dba[keyring]"` | the `keyring` package | a vault token or an admin password is read from the OS keyring |
| `"sopuli-dba[all]"` | every extra | CI, or you genuinely have all of them |

A working install is one store plus one database. For most sites that is:

```
pipx install "sopuli-dba[oracle,hashicorp]"      # or [oracle,oci], [postgres,hashicorp], [mssql,hashicorp]
```

`sopuli-dba[all]` exists for CI and the test matrix. It is deliberately not the
recommended line: a tool that handles credentials should be able to answer "what
is in its dependency tree" with the vendors you actually use, and vendor SDKs
carry version constraints — the OCI SDK pins `cryptography` and `pyOpenSSL` —
that a site with no OCI should not inherit.

**Oracle needs Instant Client too.** `sopuli-dba[oracle]` installs the driver;
thick mode is required — for Native Network Encryption, for Oracle 11.2 and for
`auth: external` — so Instant Client is a
runtime prerequisite on every platform. `sopuli doctor` checks for it, and
reports which backends are installed against which your config declares.

If a config names a backend this machine cannot serve — the client is not
installed, or this build has no module for that backend yet — `config validate`
warns and still passes. The file is fine; the install is incomplete. The first
command that needs to connect stops instead, with the install line where there
is one to give:

```
$ sopuli creds check
sopuli: vault "vault-dev" declares type "hashicorp", but that backend is not installed
  hint: install it with:  pip install "sopuli-dba[hashicorp]", or after a pipx install:  pipx runpip sopuli-dba install "sopuli-dba[hashicorp]"
```

The rule and what it costs: [ADR-006](https://github.com/villebase/sopuli-dba/blob/main/docs/decisions/adr-006-optional-dependencies.md).

Step-by-step, including your first config file:
[`docs/getting-started.md`](https://github.com/villebase/sopuli-dba/blob/main/docs/getting-started.md).

---

## Is this safe to use?

The status above says which parts are beta and which are experimental. Either
way, try a part against a test database before you trust it with a production
one. What follows is what the tool does to protect you once you do.

**You can always see a change before it happens.** Every command that changes
something takes `--dry-run`, which prints exactly what the command would do and
then stops without doing it. A confirmation never blocks a dry run, because a
preview is how you work out whether to say yes. `safety.readonly` does refuse
one, because it makes every changing command unavailable. So does
`safety.max_targets`, which will not show a plan bigger than its limit as though
it could run.

**You can require somebody to say yes.** In the config file you can list the
environments — `prod`, `uat`, whatever you call them — that a change may not
enter without an explicit confirmation. That is the `safety.confirm_environments`
setting. When a run reaches one of those environments it asks first. There is no
built-in list: if you write nothing, nothing prompts.

**A safety setting can only be made stricter, never looser.** A config file can
be layered — a site-wide file, then a team's file, then a command-line flag.
For most settings the most specific layer wins. For the safety settings it is the
*safest* layer that wins, wherever it sits. So a subteam's file cannot switch off
a rule the site-wide file turned on. It can only add more.

**A scheduled check is guarded against locking the account out.** To find out
whether the vault's password still works, the tool has to try logging in — and a
failed login counts against the database's failed-login limit. So on Oracle,
and on MySQL 9.7 and later, before it tries, it reads how many failed attempts
the account has already collected. If one more attempt would come too close to the limit, it
does not try. It reports that it could not check, and says why. Checking is
never worth locking out the account you were checking on.

That guard needs one optional grant, which lets the tool read the failed-login
count: `READ ON SYS.USER$` on Oracle, and `SELECT` on
`performance_schema.temporary_account_locks` on MySQL. Neither is part of the
standard install. Without it, the check still runs. It logs in once per account
per run (twice with `--include-previous`, which also tries the previous
password), and every result from a login it attempted says that the lockout
guard was unavailable. On Oracle the grant is a broad read.
[`docs/security-model.md`](https://github.com/villebase/sopuli-dba/blob/main/docs/security-model.md) §3 explains the trade-off.

The other databases need no guard, or offer none. MySQL 8.0 and 8.4 keep the
count in no table the tool can read. PostgreSQL has no failed-login lockout. On SQL Server, `creds check` logs in only on a Linux
host, where no login locks. MariaDB has no count the tool can read, so its
logins are unguarded, and `creds check` logs in only where no other account can
answer.

**Passwords do not reach your logs.** A password is held in a wrapper type whose
text form is `***`, so printing one prints the mask, in ordinary output and in a
crash traceback alike. A secret reaches output in only these cases, and each
one is asked for on purpose:

- `policy sample --reveal` shows sample passwords, so you can see what your
  password rules produce. Nothing logs in with a sample.
- `account reset-password` with `delivery.method: manual` prints the new
  password for a person to read. It asks every time, needs a terminal, and
  expires the password so the person must change it at first logon.
- `account reset-password` with `delivery.method: vault_wrapped` prints a
  short-lived, single-use token that fetches the password. It is never in the
  JSON run document; with `--output json` it goes to stderr.

The two that print a password refuse machine-readable JSON output, because JSON
output is what gets shipped to a log collector.

**A password containing a double quote is rejected, not escaped.** The rule
comes from Oracle, whose quoted identifiers have no escape sequence for `"`, so
there is no correct way to send one there. The tool applies it on every
database, and refuses the password rather than mangling it.

**What each database keeps is measured, not assumed.** On Oracle, `ALTER USER`
takes the password as a literal — DDL cannot use bind variables — so the
question is what the server retains afterwards. A probe plants a canary per
execution path and sweeps every source a statement's text can come to rest in,
on each version; that is release gate 2, and its results are the reason two of
the tool's design rules exist. The findings, per version and with their scope:
[`docs/design/02-oracle-privileges.md`](https://github.com/villebase/sopuli-dba/blob/main/docs/design/02-oracle-privileges.md) §4.

On PostgreSQL, MySQL, MariaDB and SQL Server the password never reaches the
server. The tool computes the value the server stores, on the client, and sends
that, because each of these servers keeps a statement's text somewhere, in a
log or a statement history, password included. One exception is accepted: the
SQL Server personal-account reset that a person reads sends the password in a
statement the server masks. An audit still keeps one character of the
password's end for each `'` in it, so the tool refuses that reset when the
policy's characters include `'`. The measurements are in §6 of
[`02-postgres-privileges.md`](https://github.com/villebase/sopuli-dba/blob/main/docs/design/02-postgres-privileges.md),
[`02-mysql-privileges.md`](https://github.com/villebase/sopuli-dba/blob/main/docs/design/02-mysql-privileges.md),
[`02-mariadb-privileges.md`](https://github.com/villebase/sopuli-dba/blob/main/docs/design/02-mariadb-privileges.md)
and
[`02-mssql-privileges.md`](https://github.com/villebase/sopuli-dba/blob/main/docs/design/02-mssql-privileges.md).

The longer version, for deciding whether to trust this with a production
credential: [`docs/security-model.md`](https://github.com/villebase/sopuli-dba/blob/main/docs/security-model.md).
To report a security problem privately: [SECURITY.md](https://github.com/villebase/sopuli-dba/blob/main/SECURITY.md).

---

## Quick example

Three commands take a password from nowhere to in-use. This is a real run against
a local Oracle container, trimmed to the lines that matter.

```bash
# 1. Draw a new random password and park it in the vault as `pending`.
#    No database is changed. It does connect, to read how long a password may
#    be and whether each account may be managed (--offline connects to none).
sopuli --config sopuli.yaml creds generate

# 2. Set that password on the database, check it works by logging in,
#    and only then promote it in the vault from `pending` to `current`.
sopuli --config sopuli.yaml creds apply

# 3. Ask whether the vault's password still works. Run this from a scheduler.
sopuli --config sopuli.yaml creds check
```

Step 1 says what it staged, and reminds you that no database has changed yet:

```
ACCOUNT        SECRET                 RESULT
acme_app_user  vault-dev:acme/dev/db  staged v1

1 staged; no database was changed -- run `sopuli creds apply` to use them
```

Step 2 shows the order that makes this safe. `SOURCE pending` is the password it
took from the vault; `1 promoted to current` happened only after the database
accepted it:

```
ACCOUNT        TARGET    SECRET                 SOURCE
acme_app_user  free-pdb  vault-dev:acme/dev/db  pending

ACCOUNT        TARGET    STATE    DETAIL
acme_app_user  free-pdb  IN_SYNC  changed and verified by login

1 changed, 1 promoted to `current`
```

Step 3 answers one question per account, and exits 0 because there is nothing
wrong:

```
ACCOUNT        TARGET    STATE    DETAIL
acme_app_user  free-pdb  IN_SYNC  vault v2 verified by login

all 1 in sync
```

Running step 2 a second time changes nothing and says so — which is what makes
the tool safe to run from a scheduler.

The full walkthroughs, with the config file these commands read and what to do
when an answer is not `IN_SYNC`, are in
[`docs/scenarios/`](https://github.com/villebase/sopuli-dba/tree/main/docs/scenarios/).

---

## How this project is built

sopuli-dba is developed with AI coding agents, under a process designed to make
that safe for a tool that handles credentials. Design decisions are the
maintainer's, and each is recorded as a GitHub issue or decision record,
including the options that were rejected and why. An agent that meets an open
design question while implementing stops and asks, or proposes an answer in the
pull request, and the answer stands only once the maintainer accepts it. Agents
implement against the design documents, which are the specification rather than
a description written afterwards. A change that alters behaviour updates the
relevant document in the same pull request.

What the tool claims about a database is measured on real releases, not reasoned
about, and every sample output in the documentation is pasted from a real run.
That is why the documentation is long: it is written so a reviewer, human or not,
can see *why* each rule exists before changing it.

How this works in practice, and what it expects of contributors:
[CONTRIBUTING.md](https://github.com/villebase/sopuli-dba/blob/main/CONTRIBUTING.md#how-this-project-is-built-and-what-that-means-for-you).

---

## Learn more

| Read this | If you want to |
|---|---|
| [docs/getting-started.md](https://github.com/villebase/sopuli-dba/blob/main/docs/getting-started.md) | install the tool, write your first config file, and run one command safely |
| [docs/scenarios/rotate-and-sync.md](https://github.com/villebase/sopuli-dba/blob/main/docs/scenarios/rotate-and-sync.md) | follow one password rotation from start to finish |
| [docs/scenarios/kubernetes-eso.md](https://github.com/villebase/sopuli-dba/blob/main/docs/scenarios/kubernetes-eso.md) | let applications running in Kubernetes pick up the new password automatically |
| [docs/scenarios/supabase.md](https://github.com/villebase/sopuli-dba/blob/main/docs/scenarios/supabase.md) | on Supabase, give each service its own login role instead of the shared `postgres` password |
| [docs/scenarios/env-file-over-ssh.md](https://github.com/villebase/sopuli-dba/blob/main/docs/scenarios/env-file-over-ssh.md) | rotate a small app's PostgreSQL password on a VM over SSH, and update its `.env` file |
| [examples/](https://github.com/villebase/sopuli-dba/tree/main/examples/) | complete config files with comments, starting with the smallest one that works |
| [docs/reference/](https://github.com/villebase/sopuli-dba/blob/main/docs/reference/README.md) | look up a command: its usage, its help text and every option |
| [docs/security-model.md](https://github.com/villebase/sopuli-dba/blob/main/docs/security-model.md) | decide whether to trust this with a production credential |
| [docs/upgrading.md](https://github.com/villebase/sopuli-dba/blob/main/docs/upgrading.md) | find out what to do when you move to a new release |
| [docs/tested-releases.md](https://github.com/villebase/sopuli-dba/blob/main/docs/tested-releases.md) | see which releases of your database the tool has run on |
| [docs/local-testing.md](https://github.com/villebase/sopuli-dba/blob/main/docs/local-testing.md) | run the usual commands by hand against the local test stack |
| [CONTRIBUTING.md](https://github.com/villebase/sopuli-dba/blob/main/CONTRIBUTING.md) | send a change |
| [SECURITY.md](https://github.com/villebase/sopuli-dba/blob/main/SECURITY.md) | report a security problem privately |
| [CODE_OF_CONDUCT.md](https://github.com/villebase/sopuli-dba/blob/main/CODE_OF_CONDUCT.md) | know what is expected of everyone taking part |
| [docs/README.md](https://github.com/villebase/sopuli-dba/blob/main/docs/README.md) | read the full design: principles, configuration reference, each database's privileges, JSON output contract, testing strategy, and every decision record |

Licensed under [Apache 2.0](https://github.com/villebase/sopuli-dba/blob/main/LICENSE).
