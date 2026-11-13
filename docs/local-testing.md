# Testing sopuli by hand

This guide sets up the local test stack and runs the usual commands against it.
You see each command succeed, and a few of them refuse on purpose.

Every sample is pasted from a real run on Windows 11, with Instant Client
23.26.3.0.0 and the `tier1` container stack: Oracle 26ai Free, PostgreSQL 16
and Vault. Most come from main at caf2645, after the 0.78.0 release, on
2026-10-23. A sample added since then comes from a run of the change that added
it. Every sample that shows PostgreSQL is one of these, from 18a0ceb to 50ea18d,
2026-10-25 and 2026-10-26. The samples in §11 come from main at ee0f077 on
2026-11-07.
Commands are written for Git Bash or WSL. Where a sample was shortened, `...`
marks the cut. The tokens and passwords the runs
printed are replaced with `<TOKEN>` and `<PASSWORD>`, and the local user and
host name with `op@ws1.example.com`. Nothing else is edited.

Other places to read:

- [`../test/README.md`](../test/README.md): the container stack.
- [`design/04-testing.md`](design/04-testing.md): the automated test tiers.
- [`maintainer-environments.md`](maintainer-environments.md): other Oracle
  releases, OCI, wallets and WSL.
- [`getting-started.md`](getting-started.md): a first run for a new user.

---

## 1. What this build has

These are the commands:

<!-- checked-list: commands -->
```
sopuli config validate      sopuli creds generate         sopuli account list
sopuli config show          sopuli creds apply            sopuli account suspend
sopuli target list          sopuli creds check            sopuli account reset-password
sopuli policy sample        sopuli creds rotate           sopuli account expire-password
sopuli lock status          sopuli creds status           sopuli doctor
sopuli lock break           sopuli creds finish-rollover  sopuli about
sopuli vault orphans        sopuli report accounts        sopuli report privileges
sopuli report history       sopuli keyring set            sopuli keyring delete
```

The `creds` commands manage application credentials (UC-1). The `account`
commands manage personal accounts (UC-2). `vault orphans` lists vault records
the tool wrote at paths the config no longer declares (§13).

There is no `sopuli admin` command. To install the Oracle service account, run
the SQL in `sql/oracle/` by hand. The PostgreSQL tool role is created by hand in
`psql` (§7). The store backends are `hashicorp`, `oci` (§8.8) and `file`
(§8.9). A PostgreSQL target runs `doctor`, the
`creds` commands (§7) and the `account` commands (§9). It refuses
`account expire-password` and the seen reset, because PostgreSQL cannot make a
role change its password at its next login. A MySQL target and a MariaDB target
each run `doctor`, the `creds` commands (§7) and the `account` commands (§9).

---

## 2. Install sopuli

You need Python 3.11 or later.

```bash
git clone https://github.com/villebase/sopuli-dba.git
cd sopuli-dba
python -m venv .venv
source .venv/Scripts/activate      # Git Bash; on WSL: source .venv/bin/activate
pip install -e ".[dev,all]"
```

Check the install:

```
$ sopuli --version
sopuli, version 0.78.0
```

`sopuli --version` reports the version recorded when the editable install was
made, not the version in the tree. After a pull that crossed a release, refresh
it:

```bash
pip install -e . --no-deps
```

`sopuli about` needs no config, no database and no vault. It prints a banner, the
version and the project links.

---

## 3. Oracle Instant Client

sopuli runs `python-oracledb` in thick mode, so Instant Client is required.
[`design/00-principles.md`](design/00-principles.md) §*Why thick mode* says why.

Download **Basic** from Oracle's Instant Client page. **SQL\*Plus** is optional
but useful.

- **Windows:** unzip to a path with no spaces, such as
  `C:\oracle\instantclient_23_26`, and add it to `PATH`.
- **WSL or Linux:** unzip to `/opt/oracle/instantclient_23_26`, install
  `libaio1`, and set `LD_LIBRARY_PATH`.

Instead of `PATH`, you can name the directory in the config:

```yaml
runtime:
  oracle:
    client_lib_dir: C:\oracle\instantclient_23_26
```

`sopuli doctor` shows whether the client loaded, in its `client` section (§7).

---

## 4. Start Oracle and Vault

From `test/`:

```bash
docker compose --profile tier1 up -d
```

Oracle takes about a minute to report `healthy` in `docker ps`. Vault is ready in
seconds.

- Vault: `http://127.0.0.1:8200`, root token `sopuli-test-root`.
- Oracle: `127.0.0.1:1521/FREEPDB1`, user `SYSTEM`, password `sopuli-test`.

Two things to know about this stack:

- **`docker compose down` does nothing here.** Every service has a profile. Stop
  the stack with `docker compose --profile '*' down`.
- **Vault keeps its data in memory.** A restart loses the `kv` mounts. After a
  `stop` and `start`, run `docker compose --profile tier0 up -d vault-init` to
  create them again.

The container has no application accounts. Save this as `accounts.sql`. The
first line is the logon. SQL\*Plus reads it from stdin, so the password is not
on a command line.

```sql
system/sopuli-test@localhost:1521/FREEPDB1
CREATE USER acme_app_user   IDENTIFIED BY "Placeholder#1";
CREATE USER acme_batch_user IDENTIFIED BY "Placeholder#1" PROFILE sopuli_rollover;
CREATE USER acme_priv_user  IDENTIFIED BY "Placeholder#1";
CREATE USER acme_dev_alice  IDENTIFIED BY "Placeholder#1";
CREATE USER acme_dev_bob    IDENTIFIED BY "Placeholder#1";
GRANT CREATE SESSION TO acme_app_user, acme_batch_user, acme_priv_user, acme_dev_alice, acme_dev_bob;
GRANT DBA TO acme_priv_user;
```

Then run it with the container's own SQL\*Plus:

```bash
docker exec -i sopuli-test-oracle-free-1 sqlplus -S < accounts.sql
```

The accounts are used like this:

| Account | Used for |
|---|---|
| `acme_app_user` | application credentials (§8) |
| `acme_batch_user` | the same, with the `SOPULI_ROLLOVER` profile, so a password change opens a rollover window |
| `acme_priv_user` | holds `DBA`, so the tool refuses it (§10) |
| `acme_dev_alice`, `acme_dev_bob` | personal accounts (§9) |

The guide uses the vault CLI inside the container. This alias saves typing:

```bash
alias vault='docker exec -i -e VAULT_ADDR=http://127.0.0.1:8200 -e VAULT_TOKEN=sopuli-test-root sopuli-test-vault-1 vault'
```

---

## 5. A config file

Save this as `sopuli.yaml`, outside the repository:

```yaml
version: 1

defaults:
  policy: standard
  vault: vault-dev

vaults:
  vault-dev:
    type: hashicorp
    addr: http://127.0.0.1:8200
    mount: kv
    kv_version: 2
    auth: { method: token }

targets:
  - name: free-pdb
    type: oracle
    environment: dev
    vault: vault-dev
    dsn: "127.0.0.1:1521/FREEPDB1"
    admin: { username: SYSTEM, auth: { method: env } }
    oracle: { scope: pdb, container: FREEPDB1 }

policies:
  standard:
    password:
      length: 24
      charset: alnum_safe
      first_char: alpha
      require: { upper: 1, lower: 1, digit: 1, special: 1 }

applications:
  - name: acme
    accounts: [acme_app_user, acme_batch_user]
    secret_template: "vault-dev:acme/{env}/{application}#DB_CREDENTIALS/{account}"

personal_accounts:
  - accounts: [acme_dev_alice, acme_dev_bob]

delivery:
  method: vault_wrapped
  vault_wrapped:
    ttl: 15m

reset_records:
  vault: vault-dev
  prefix: sopuli/personal-resets
```

[`design/01-configuration.md`](design/01-configuration.md) is the reference for
every key.

### The permission check

The tool refuses a config file that other users can read or write. The file
holds no secrets, but anyone who can change it can point `secret_template` at a
vault path they control. A new file on Windows often inherits a grant to other
users:

```
$ sopuli --config sopuli.yaml config validate
sopuli: sopuli.yaml: config file is accessible to NT AUTHORITY\INTERACTIVE
  hint: remove the extra grant, e.g. icacls "<file>" /inheritance:r /grant:r "%USERNAME%:R"
```

Exit 9. Remove the inherited grants and give yourself full control:

```powershell
icacls sopuli.yaml /inheritance:r /grant:r "$($env:USERNAME):F"   # PowerShell
```
```bash
chmod 600 sopuli.yaml                                             # WSL or Linux
```

In Git Bash, put `MSYS_NO_PATHCONV=1` in front of `icacls`. Otherwise Git Bash
rewrites `/grant` into a file path.

### Commands that open no connection

These work with Docker stopped.

```
$ sopuli --config sopuli.yaml config validate
config: sopuli.yaml

ok: 1 target, 2 bindings, 0 warnings
```

```
$ sopuli --config sopuli.yaml target list
config: sopuli.yaml

NAME      DSN                      ENV  SCOPE  SOURCE
free-pdb  127.0.0.1:1521/FREEPDB1  dev  pdb    targets

1 target (1 explicit)
```

`config show --explain` prints the whole configuration, and then each effective
setting with the layer it came from:

```
$ sopuli --config sopuli.yaml config show --explain
...
settings
  db.connect_timeout_s        = 30                     [built-in default]
  db.query_timeout_s          = 0                      [built-in default]
  output                      = text                   [built-in default]
  safety.dry_run              = false                  [built-in default]
  safety.readonly             = false                  [built-in default]
  safety.require_encryption   = false                  [built-in default]
  vault                       = vault-dev              [defaults.vault]
  vaults.vault-dev.addr       = http://127.0.0.1:8200  [vaults.vault-dev.addr]
  vaults.vault-dev.kv_version = 2                      [vaults.vault-dev.kv_version]
  vaults.vault-dev.mount      = kv                     [vaults.vault-dev.mount]
```

Set `VAULT_ADDR` or `SOPULI_OUTPUT=json` and run it again to see a layer change.

`policy sample` shows what a policy produces. It prints the shape of each sample,
not the password:

```
$ sopuli --config sopuli.yaml policy sample
config: sopuli.yaml
policy: standard    length 24, alnum_safe, first_char alpha, require digit 1, lower 1, special 1, upper 1

#  CHARS  BYTES  CLASSES
1  24     -      u5 l7 d9 s3
2  24     -      u10 l10 d2 s2
3  24     -      u10 l12 d1 s1

3 samples, all compliant. Not stored anywhere; pass --reveal to print them.
```

---

## 6. The vault token

A vault token is never a command-line value. The tool reads it from
`--vault-token-file`, `SOPULI_VAULT_TOKEN`, `VAULT_TOKEN`, or `~/.vault-token`.
Without one:

```
$ sopuli --config sopuli.yaml lock status
sopuli: vault "vault-dev": no token, and none of the places it is looked for had one
  hint: write `token: { file: … }` on the store, or supply one of: --vault-token-file PATH, $SOPULI_VAULT_TOKEN, $VAULT_TOKEN, or `vault login` so that ~/.vault-token exists
```

Exit 9. A token the vault rejects is exit 6 instead:

```
$ VAULT_TOKEN=not-a-token sopuli --config sopuli.yaml lock status
sopuli: the store refused this token at 'locks/': permission denied; invalid token
  hint: check the token's policy for this path, and that it has not expired
```

Set the token for the rest of the guide:

```
$ export VAULT_TOKEN=sopuli-test-root
$ sopuli --config sopuli.yaml lock status
config: sopuli.yaml
mode:   cas

0 of 1 declared lock paths held
```

`mode: cas` means the store supports compare-and-set, so two runs cannot both
take the same lock.

### The token in the OS keyring

With the `sopuli-dba[keyring]` extra, the token can live in Windows Credential
Manager, the macOS Keychain, or the Secret Service on a Linux desktop. Name the
entry on the store:

```yaml
    auth: { method: token, token: { keyring: vault-dev } }
```

Write the entry. The value comes from stdin, or, at a terminal, from a prompt
asked twice:

```
$ printf '%s' "$VAULT_TOKEN" | sopuli --config sopuli.yaml keyring set vault-dev
keyring
  backend           keyring.backends.Windows.WinVaultKeyring
  sopuli/vault-dev  added  vaults.vault-dev.auth.token
```

The same command again reports `unchanged`. A different value needs
`--replace`. `sopuli keyring delete vault-dev` removes the entry. Neither
command needs a config.

---

## 7. `doctor`

`doctor` connects to every target and every vault, and changes nothing. The
config reads the admin password from `SOPULI_DB_ADMIN_PASSWORD`. Without it, the
target is unreachable:

```
$ sopuli --config sopuli.yaml doctor
...
TARGET    REACHABLE  SCOPE  CONTAINER  OPEN MODE  CAPABILITIES  ENCRYPTION
free-pdb  no         -      -          -          -             -
  free-pdb: target 'free-pdb' admin credential: the environment variable SOPULI_DB_ADMIN_PASSWORD is not set
    hint: an empty value counts as unset (01-configuration.md §6). Check the name, and that whatever exports it runs in the same process tree as this command
```

Exit 1. Set it and run again:

```
$ export SOPULI_DB_ADMIN_PASSWORD=sopuli-test
$ sopuli --config sopuli.yaml doctor
install
  KIND     NAME        STATUS     CONFIGURED
  backend  file        installed  -
  backend  hashicorp   installed  vault-dev
  backend  oci         installed  -
  driver   mariadb     installed  -
  driver   mysql       installed  -
  driver   oracle      installed  1 target
  driver   postgresql  installed  -

vaults
  VAULT      TYPE       STATUS  AUTH  SKEW
  vault-dev  hashicorp  ok      yes   -78ms

client
  tns_admin         (unset)
  instant_client    23.26.3.0.0
  reaches           19.1 and later
  psycopg           3.3.6
  libpq             18.4
  require_auth      accepted

TARGET    REACHABLE  SCOPE  CONTAINER  OPEN MODE   CAPABILITIES  ENCRYPTION
free-pdb  yes        pdb    FREEPDB1   READ WRITE  7             none
  free-pdb: the connection is not encrypted, so a password the tool sets crosses it in clear: require NNE or TLS on the server (SQLNET.ENCRYPTION_SERVER = REQUIRED in its sqlnet.ora, or a TCPS listener endpoint)

1 note:
  free-pdb: the admin credential came from the environment variable SOPULI_DB_ADMIN_PASSWORD, which P2 supports and flags as low assurance
```

The note is `SOPULI-W022`. Every verb that connects puts it in the JSON output,
and only `doctor` prints it. `--output json` lists the capabilities by name.

`ENCRYPTION` is `none` because the tier-1 container does not require NNE or
TLS. On a connection that uses NNE it reads `native AES256`, and on TLS `tls`.

`doctor --check-privileges` also lists privileges the admin account holds and
the tool does not need. Against `SYSTEM` that list is long. For a realistic
setup, create the least-privilege service account with
[`../sql/oracle/00_install.sql`](../sql/oracle/00_install.sql), and point the
target at it.

### A typed admin password

A target can ask for the admin password instead of reading it from the
environment. Save this as `prompt.yaml`:

```yaml
version: 1
targets:
  - name: free-pdb
    type: oracle
    environment: dev
    dsn: "127.0.0.1:1521/FREEPDB1"
    admin: { username: SYSTEM, auth: prompt }
    oracle: { scope: pdb, container: FREEPDB1 }
```

The prompt needs a console. On Windows, run it in PowerShell, in Windows
Terminal or in WSL. The default Git Bash window is not a console, so there the
run does not ask.

Run `doctor` and type `sopuli-test` at the prompt:

```
$ sopuli --config prompt.yaml doctor
password for SYSTEM on free-pdb:
...
vaults

...
TARGET    REACHABLE  SCOPE  CONTAINER  OPEN MODE   CAPABILITIES  ENCRYPTION
free-pdb  yes        pdb    FREEPDB1   READ WRITE  7             none
  free-pdb: the connection is not encrypted, so a password the tool sets crosses it in clear: require NNE or TLS on the server (SQLNET.ENCRYPTION_SERVER = REQUIRED in its sqlnet.ora, or a TCPS listener endpoint)
```

This config declares no vault, so the `vaults` list is empty. There is no
`SOPULI-W022` note, because the password did not come from the environment.

The rest of the guide uses `sopuli.yaml`. With `auth: prompt`, every command
that connects to the target asks for the password again. With no console there
is nobody to ask: the target is reported unreachable, with the message
`asks for its admin password interactively, and there is nobody here to ask`,
and the run exits 1.

### A PostgreSQL cluster

The stack also runs PostgreSQL 16 at `127.0.0.1:5432`, superuser `postgres`,
password `sopuli-test`. `doctor` connects to it and reports what it found, and
the UC-1 commands run against it: `creds generate`, `apply`, `check`, `rotate`,
`status` and `finish-rollover`, which finds no window to close. The UC-2
commands `account list`, `account reset-password` and `account suspend` run
against it, and `account expire-password` refuses it with exit 5.

The tool connects as an ordinary role with `CREATEROLE`
([`design/02-postgres-privileges.md`](design/02-postgres-privileges.md) §2).
Create it as the superuser, and choose its password at the prompt:

```
$ docker exec -it sopuli-test-postgres-1 psql -U postgres
postgres=# SET password_encryption = 'scram-sha-256';
postgres=# CREATE ROLE sopuli_admin LOGIN CREATEROLE;
postgres=# \password sopuli_admin
```

Export that password as `SOPULI_DB_ADMIN_PASSWORD`, and save this as
`postgres.yaml`:

```yaml
version: 1
targets:
  - name: pg-dev
    type: postgresql
    environment: dev
    dsn: "127.0.0.1:5432"
    admin: { username: sopuli_admin, auth: { method: env } }
    postgres: { sslmode: disable }
```

The container has no TLS, so the target sets `sslmode: disable`. Without it the
driver asks for `verify-full`. Every command then warns that the target does
not verify the server. Run `doctor`:

```
$ sopuli --config postgres.yaml doctor
...
client
  tns_admin         (unset)
  instant_client    23.26.3.0.0
  reaches           19.1 and later
  psycopg           3.3.6
  libpq             18.4
  require_auth      accepted

TARGET  REACHABLE  SCOPE    CONTAINER  OPEN MODE   CAPABILITIES  ENCRYPTION
pg-dev  yes        cluster  -          READ WRITE  1             none
  pg-dev: the connection is not encrypted, so a password the tool sets crosses it in clear: set `postgres.sslmode` to verify-full, and give the server a certificate (`ssl = on`)
...
1 warning:
  targets[0].postgres.sslmode: target 'pg-dev' does not verify the server (`sslmode: disable`)
    hint: anything between this run and the server can present its own certificate and read the password a run sets. Use `sslmode: verify-full` (the default), with `sslrootcert` naming the CA that issued the server's certificate
```

`libpq` is the one psycopg loaded. `require_auth` needs libpq 16 or later.

`doctor --check-privileges` also reports what the tool account holds and should
not. With `GRANT pg_monitor TO sopuli_admin`, it prints:

```
$ sopuli --config postgres.yaml doctor --check-privileges
...
TARGET  REACHABLE  SCOPE    CONTAINER  OPEN MODE   CAPABILITIES  ENCRYPTION
pg-dev  yes        cluster  -          READ WRITE  1             none
  pg-dev: the connection is not encrypted, so a password the tool sets crosses it in clear: set `postgres.sslmode` to verify-full, and give the server a certificate (`ssl = on`)
  pg-dev: over-granted, and the tool needs none of it: pg_monitor, pg_read_all_stats
...
```

`pg_monitor` includes `pg_read_all_stats`, which shows other sessions' statement
text. `REVOKE pg_monitor FROM sopuli_admin` clears the line.

To check a managed role, add the vault and an application to `postgres.yaml`,
as §8 does for Oracle, and create the role with the vault's password as above.
The stack's `pg_hba.conf` already has a `scram-sha-256` line for every role.
Here the vault holds another value for `acme_drift_user`:

```
$ sopuli --config postgres.yaml creds check
Plan: 2 accounts x 1 target = 2 checks   [dev]

ACCOUNT          TARGET  INTENT  SECRET
acme_app_user    pg-dev  verify  vault-dev:acme/pg-dev
acme_drift_user  pg-dev  verify  vault-dev:acme/pg-dev

shared secrets (1 document):
SECRET                 TARGETS  ACCOUNTS
vault-dev:acme/pg-dev  pg-dev   acme_app_user, acme_drift_user

ACCOUNT          TARGET  STATE    DETAIL
acme_app_user    pg-dev  IN_SYNC  vault v1 verified by login
acme_drift_user  pg-dev  DRIFT    vault v1 the server refused the password (28P01). It gives the same answer for a role whose stored verifier is md5, which no password opens through a scram-sha-256 line; `creds apply` stores a SCRAM verifier

1 drift

1 warning:
  targets[0].postgres.sslmode: target 'pg-dev' does not verify the server (`sslmode: disable`)
    hint: anything between this run and the server can present its own certificate and read the password a run sets. Use `sslmode: verify-full` (the default), with `sslrootcert` naming the CA that issued the server's certificate
```

A wrong password exits 3. A role that `pg_hba.conf` does not let in is
`UNVERIFIABLE`, and a `NOLOGIN` role is `LOCKED`. Use the default
`--method login`: `hash` and `both` are refused on PostgreSQL.

To set passwords, declare the roles the run sets (here `acme_app_user` and
`acme_batch_user`) and create the second one. On PostgreSQL 16 and later the
tool account needs `ADMIN OPTION` on each
([`design/02-postgres-privileges.md`](design/02-postgres-privileges.md) §2.2):

```
postgres=# CREATE ROLE acme_batch_user LOGIN;
postgres=# GRANT acme_app_user TO sopuli_admin WITH ADMIN OPTION, INHERIT FALSE, SET FALSE;
postgres=# GRANT acme_batch_user TO sopuli_admin WITH ADMIN OPTION, INHERIT FALSE, SET FALSE;
```

Stage passwords with `creds generate`, then run `creds apply`:

```
$ sopuli --config postgres.yaml creds apply
Plan: 2 accounts x 1 target = 2 applys   [dev]

ACCOUNT          TARGET  INTENT                               SECRET
acme_app_user    pg-dev  verify, password_set, vault_promote  vault-dev:acme/pg-dev
acme_batch_user  pg-dev  verify, password_set, vault_promote  vault-dev:acme/pg-dev

shared secrets (1 document):
SECRET                 TARGETS  ACCOUNTS
vault-dev:acme/pg-dev  pg-dev   acme_app_user, acme_batch_user

ACCOUNT          TARGET  SECRET                 SOURCE
acme_app_user    pg-dev  vault-dev:acme/pg-dev  pending
acme_batch_user  pg-dev  vault-dev:acme/pg-dev  pending

ACCOUNT          TARGET  STATE    DETAIL
acme_app_user    pg-dev  IN_SYNC  changed and verified by login
acme_batch_user  pg-dev  IN_SYNC  changed and verified by login

2 changed, 1 promoted to `current`

1 note:
  pg-dev: a password was sent over a connection that is not encrypted: set `postgres.sslmode` to verify-full, and give the server a certificate (`ssl = on`)

1 warning:
  targets[0].postgres.sslmode: target 'pg-dev' does not verify the server (`sslmode: disable`)
    hint: anything between this run and the server can present its own certificate and read the password a run sets. Use `sslmode: verify-full` (the default), with `sslrootcert` naming the CA that issued the server's certificate
```

The server never sees the password: the statement carries a SCRAM verifier
computed on this machine. The stack preloads `pg_stat_statements`; create its
view once, and it shows what the server kept:

```
$ docker exec sopuli-test-postgres-1 psql -U postgres -c "CREATE EXTENSION IF NOT EXISTS pg_stat_statements"
$ docker exec sopuli-test-postgres-1 psql -U postgres -tAc "select query from pg_stat_statements where query ilike 'alter role%'"
ALTER ROLE "acme_app_user" PASSWORD 'SCRAM-SHA-256$4096:…'
ALTER ROLE "acme_batch_user" PASSWORD 'SCRAM-SHA-256$4096:…'
```

Run `creds apply` again and it changes nothing.

`creds rotate` draws, stages, applies and promotes in one run:

```
$ sopuli --config postgres.yaml creds rotate --confirm
Plan: 2 accounts x 1 target = 2 rotations   [dev]

ACCOUNT          TARGET  INTENT                                                              SECRET
acme_app_user    pg-dev  generate, vault_write_pending, verify, password_set, vault_promote  vault-dev:acme/pg-dev
acme_batch_user  pg-dev  generate, vault_write_pending, verify, password_set, vault_promote  vault-dev:acme/pg-dev

shared secrets (1 document):
SECRET                 TARGETS  ACCOUNTS
vault-dev:acme/pg-dev  pg-dev   acme_app_user, acme_batch_user

ACCOUNT          TARGET  STATE    DETAIL
acme_app_user    pg-dev  IN_SYNC  changed and verified by login
acme_batch_user  pg-dev  IN_SYNC  changed and verified by login

2 changed, 1 promoted to `current`

rotation: staged 1 document, promoted 1 document

1 note:
  pg-dev: a password was sent over a connection that is not encrypted: set `postgres.sslmode` to verify-full, and give the server a certificate (`ssl = on`)

1 warning:
  targets[0].postgres.sslmode: target 'pg-dev' does not verify the server (`sslmode: disable`)
    hint: anything between this run and the server can present its own certificate and read the password a run sets. Use `sslmode: verify-full` (the default), with `sslrootcert` naming the CA that issued the server's certificate
```

PostgreSQL keeps one password per role, so `--strategy rollover` is refused
with exit 5. So is a policy that declares `account: { unlock_if_locked: true }`
or `account: { profile: … }`: a `NOLOGIN` role is not a lock, and there are no
password profiles.

`creds status` shows the vault's age for each password. PostgreSQL does not
record when a password was changed, so `DB_PW_CHANGED` is empty and the run
says why. It has no rollover window, so `ROLLOVER` reads `not supported`:

```
$ sopuli --config postgres.yaml creds status
Plan: 2 accounts x 1 target = 2 accounts   [dev]

ACCOUNT          TARGET  INTENT  SECRET
acme_app_user    pg-dev  none    vault-dev:acme/pg-dev
acme_batch_user  pg-dev  none    vault-dev:acme/pg-dev

shared secrets (1 document):
SECRET                 TARGETS  ACCOUNTS
vault-dev:acme/pg-dev  pg-dev   acme_app_user, acme_batch_user

ACCOUNT          TARGET  STATE         VAULT_V  AGE  DB_PW_CHANGED  PROFILE  ROLLOVER
acme_app_user    pg-dev  UNVERIFIABLE  7        0d   -              -        not supported
acme_batch_user  pg-dev  UNVERIFIABLE  7        0d   -              -        not supported

2 accounts, nothing to act on

1 note:
  pg-dev: DB_PW_CHANGED is empty for 2 accounts: PostgreSQL does not record when a role's password was changed

1 warning:
  targets[0].postgres.sslmode: target 'pg-dev' does not verify the server (`sslmode: disable`)
    hint: anything between this run and the server can present its own certificate and read the password a run sets. Use `sslmode: verify-full` (the default), with `sslrootcert` naming the CA that issued the server's certificate
```

### A MySQL server

The stack also runs MySQL 8.4 at `127.0.0.1:3306`, user `root`, password
`sopuli-test`. `doctor` connects to it and reports what it found, and the UC-1
commands run against it: `creds generate`, `apply`, `check`, `rotate`,
`finish-rollover` and `status`, and so do the `account` commands (§9).

Connecting needs no privilege. Create the tool account as root, with a
password of your own, and export the same password as
`SOPULI_DB_ADMIN_PASSWORD`:

```
$ docker exec -it -e MYSQL_PWD=sopuli-test sopuli-test-mysql-1 mysql -uroot
mysql> CREATE USER 'sopuli_admin'@'%' IDENTIFIED BY '…';
```

Save this as `mysql.yaml`:

```yaml
version: 1
targets:
  - name: mysql-dev
    type: mysql
    environment: dev
    dsn: "127.0.0.1:3306"
    admin: { username: sopuli_admin, auth: { method: env } }
    mysql: { ssl_mode: REQUIRED }
```

The image's certificate is self-signed, so the target sets `REQUIRED`. Run
`doctor`:

```
$ sopuli --config mysql.yaml doctor
...
client
  tns_admin         (unset)
  instant_client    23.26.3.0.0
  reaches           19.1 and later
  psycopg           3.3.6
  libpq             18.4
  require_auth      accepted
  pymysql           1.2.4

TARGET     REACHABLE  SCOPE   CONTAINER  OPEN MODE   CAPABILITIES  ENCRYPTION
mysql-dev  yes        server  -          READ WRITE  3             tls

1 note:
  mysql-dev: the admin credential came from the environment variable SOPULI_DB_ADMIN_PASSWORD, which P2 supports and flags as low assurance

1 warning:
  targets[0].mysql.ssl_mode: target 'mysql-dev' does not verify the server (`ssl_mode: REQUIRED`)
    hint: anything between this run and the server can present its own certificate and read the password a run sets. Use `ssl_mode: VERIFY_IDENTITY` (the default), with `ssl_ca` naming the CA that issued the server's certificate
```

Keep TLS on: with `ssl_mode: DISABLED` a login sends the password encrypted
with a key that nothing checks (`01-configuration.md` §3a, `mysql:`).

To manage passwords, give the tool account the grants in
[`design/02-mysql-privileges.md`](design/02-mysql-privileges.md) §2.1, with
`'sopuli_admin'@'%'` as the account. Then create two accounts, one at any host
and one at a named host:

```
mysql> CREATE USER 'acme_app'@'%' IDENTIFIED BY '…';
mysql> CREATE USER 'acme_batch'@'192.0.2.%' IDENTIFIED BY '…';
```

Add the vault from §5 and an application to `mysql.yaml`. An account on a MySQL
target names its host, and `{host}` writes `%` as `any`:

```yaml
targets:
  - name: mysql-dev
    ...
    vault: vault-dev

applications:
  - name: acme-mysql
    targets: [mysql-dev]
    accounts: [acme_app@%, acme_batch@192.0.2.%]
    secret_template: "vault-dev:acme/mysql/{host}#DB_CREDENTIALS/{user}"
```

Stage passwords with `creds generate`, then run `creds apply`:

```
$ sopuli --config mysql.yaml creds apply
Plan: 2 accounts x 1 target = 2 applys   [dev]

ACCOUNT               TARGET     INTENT                               SECRET
acme_app@%            mysql-dev  verify, password_set, vault_promote  vault-dev:acme/mysql/any
acme_batch@192.0.2.%  mysql-dev  verify, password_set, vault_promote  vault-dev:acme/mysql/192.0.2.any

ACCOUNT               TARGET     SECRET                            SOURCE
acme_app@%            mysql-dev  vault-dev:acme/mysql/any          pending
acme_batch@192.0.2.%  mysql-dev  vault-dev:acme/mysql/192.0.2.any  pending

ACCOUNT               TARGET     STATE    DETAIL
acme_app@%            mysql-dev  IN_SYNC  changed and verified by login
acme_batch@192.0.2.%  mysql-dev  IN_SYNC  changed, and the server records the change; no login can reach this account to verify it

2 changed, 2 promoted to `current`

1 warning:
  targets[0].mysql.ssl_mode: target 'mysql-dev' does not verify the server (`ssl_mode: REQUIRED`)
    hint: anything between this run and the server can present its own certificate and read the password a run sets. Use `ssl_mode: VERIFY_IDENTITY` (the default), with `ssl_ca` naming the CA that issued the server's certificate
```

The server never sees the password: the statement carries a
`caching_sha2_password` hash computed on this machine. `apply` does not log in
before the change, because on MySQL one wrong login can block an account. After
it, a login checks `acme_app@%`. A login from the tool's host could reach
another account than `acme_batch@192.0.2.%`, so the server's record of the change
stands in for it, as the verification result `stored`.

Run `creds apply` again and it changes nothing. With only `current` in the
vault there is no rotation in flight, and without a login the tool cannot tell
whether a change is needed, so it skips each account:

```
$ sopuli --config mysql.yaml creds apply
...
ACCOUNT               TARGET     STATE    DETAIL
acme_app@%            mysql-dev  SKIPPED  not changed: on this target the tool does not log in before a change, so it cannot tell whether the account already has the vault's `current`, and it sets a password only for a rotation in flight. `creds check` compares them, and `creds rotate` changes the password
acme_batch@192.0.2.%  mysql-dev  SKIPPED  not changed: on this target the tool does not log in before a change, so it cannot tell whether the account already has the vault's `current`, and it sets a password only for a rotation in flight. `creds check` compares them, and `creds rotate` changes the password

nothing changed, 2 skipped
...
```

It exits 0. `creds check` logs in only where nothing but the declared account
can answer:

```
$ sopuli --config mysql.yaml creds check
Plan: 2 accounts x 1 target = 2 checks   [dev]

ACCOUNT               TARGET     INTENT  SECRET
acme_app@%            mysql-dev  verify  vault-dev:acme/mysql/any
acme_batch@192.0.2.%  mysql-dev  verify  vault-dev:acme/mysql/192.0.2.any

ACCOUNT               TARGET     STATE         DETAIL
acme_app@%            mysql-dev  IN_SYNC       vault v2 verified by login; the lockout guard is unavailable: MySQL keeps FAILED_LOGIN_ATTEMPTS and its counter in mysql.user.User_attributes, which the tool account does not read
acme_batch@192.0.2.%  mysql-dev  UNVERIFIABLE  a login reaches the account the server matches from the tool's host, which may not be acme_batch@192.0.2.%, so its password is checked by login only where its host is `%` and it is the user's only account; no login was attempted

1 unverifiable
...
```

A wrong password counts toward the account's `FAILED_LOGIN_ATTEMPTS`, which the
tool cannot read. With `FAILED_LOGIN_ATTEMPTS 1`, one `check` of a drifted
account blocks it, and the block lasts `PASSWORD_LOCK_TIME` days, through a new
password, until `ALTER USER … ACCOUNT UNLOCK`. `--lockout-margin` has nothing to
guard here, as the detail says. Use the default `--method login`: `hash` and
`both` are refused on MySQL.

`creds rotate` draws, stages, applies and promotes in one run:

```
$ sopuli --config mysql.yaml creds rotate --confirm
Plan: 2 accounts x 1 target = 2 rotations   [dev]

ACCOUNT               TARGET     INTENT                                                              SECRET
acme_app@%            mysql-dev  generate, vault_write_pending, verify, password_set, vault_promote  vault-dev:acme/mysql/any
acme_batch@192.0.2.%  mysql-dev  generate, vault_write_pending, verify, password_set, vault_promote  vault-dev:acme/mysql/192.0.2.any

ACCOUNT               TARGET     STATE    DETAIL
acme_app@%            mysql-dev  IN_SYNC  changed and verified by login
acme_batch@192.0.2.%  mysql-dev  IN_SYNC  changed, and the server records the change; no login can reach this account to verify it

2 changed, 2 promoted to `current`

rotation: staged 2 documents, promoted 2 documents
...
```

Each password change discards an old password someone kept with `RETAIN
CURRENT PASSWORD`, so only the vault's works. With `--strategy rollover` the
old password keeps working beside the new one:

```
$ sopuli --config mysql.yaml creds rotate --strategy rollover --confirm
...
ACCOUNT               TARGET     STATE            DETAIL
acme_app@%            mysql-dev  ROLLOVER_ACTIVE  changed and verified by login; the previous password also logs in until `sopuli creds finish-rollover`
acme_batch@192.0.2.%  mysql-dev  ROLLOVER_ACTIVE  changed, and the server records the change; no login can reach this account to verify it; the previous password also logs in until `sopuli creds finish-rollover`

2 changed, 2 promoted to `current`
...
```

Only `rotate` opens one: `creds apply --strategy rollover` is refused before
anything changes. `creds finish-rollover` ends it:

```
$ sopuli --config mysql.yaml creds finish-rollover --confirm
...
ACCOUNT               TARGET     WINDOW
acme_app@%            mysql-dev  unknown
acme_batch@192.0.2.%  mysql-dev  unknown

ACCOUNT               TARGET     STATE    DETAIL
acme_app@%            mysql-dev  IN_SYNC  any retained password discarded
acme_batch@192.0.2.%  mysql-dev  IN_SYNC  any retained password discarded; the vault's `current` was not verified by login, because no login can reach this account

2 closed
...
```

The server keeps a retained password where the tool account does not read, so
the window is `unknown`, and every run sends `DISCARD OLD PASSWORD` and reports
a change. `creds status` shows when the server last changed each password, and
its `ROLLOVER` column reads `unknown` for the same reason.

Two targets that reach one server are refused with `SOPULI-20008`: the tool
knows a server by its `server_uuid`.

### A MariaDB server

The stack also runs MariaDB 11.8 at `127.0.0.1:3307`. Its init creates the
tool account `sopuli_admin`, password `sopuli-test-admin`, with the grants
that [`design/02-mariadb-privileges.md`](design/02-mariadb-privileges.md) lists
for it. `doctor` runs against it, and so do the UC-1 commands `creds
generate`, `apply`, `check`, `rotate`, `status` and `finish-rollover`, and the
personal-account commands of §9.

Save this as `mariadb.yaml`, and export `SOPULI_DB_ADMIN_PASSWORD=sopuli-test-admin`:

```yaml
version: 1
targets:
  - name: mariadb-dev
    type: mariadb
    environment: dev
    dsn: "127.0.0.1:3307"
    admin: { username: sopuli_admin, auth: { method: env } }
    mariadb: { ssl_mode: REQUIRED }
```

The image's certificate is self-signed, so the target sets `REQUIRED`. Run
`doctor`:

```
$ sopuli --config mariadb.yaml doctor
...
TARGET       REACHABLE  SCOPE   CONTAINER  OPEN MODE   CAPABILITIES  ENCRYPTION
mariadb-dev  yes        server  -          READ WRITE  0             tls

1 note:
  mariadb-dev: the admin credential came from the environment variable SOPULI_DB_ADMIN_PASSWORD, which P2 supports and flags as low assurance

1 warning:
  targets[0].mariadb.ssl_mode: target 'mariadb-dev' does not verify the server (`ssl_mode: REQUIRED`)
    hint: anything between this run and the server can present its own certificate and read the password a run sets. Use `ssl_mode: VERIFY_IDENTITY` (the default), with `ssl_ca` naming the CA that issued the server's certificate
```

`doctor --check-privileges` audits the tool account and prints nothing more
when it holds exactly those grants. Declare accounts under `applications:`, and it
names one that does not exist, one on a plugin other than
`mysql_native_password` and `ed25519`, and the same user name at a host the
config does not declare. With any declared account, it also says what
guardrail 9 cannot see, and that a second login method is not seen:

```
  mariadb-dev: check 9 cannot see BINLOG ADMIN, BINLOG REPLAY, CONNECTION ADMIN, FEDERATED ADMIN, READ_ONLY ADMIN, REPLICATION MASTER ADMIN, REPLICATION SLAVE ADMIN, SET USER or SLAVE MONITOR: they set no column of the mysql.user view, so it does not refuse a declared account that holds one. Revoke them from accounts the tool manages (02-mariadb-privileges.md section 5)
  mariadb-dev: a declared account with a second login method, joined by OR, shows one of them: the mysql.user view does not show the other. A password change sends one method and ends the other, so a login by unix_socket, for example, stops working. Check SHOW CREATE USER for accounts the tool manages (02-mariadb-privileges.md section 4)
```

Two targets that reach one server are refused with `SOPULI-20008`: the tool
knows a server by its `@@server_uid`.

To manage passwords, create two accounts as root, one at any host and one at a
named host:

```
$ docker exec -it -e MYSQL_PWD=sopuli-test sopuli-test-mariadb-1 mariadb -uroot
MariaDB> CREATE USER 'acme_app'@'%' IDENTIFIED BY '…';
MariaDB> CREATE USER 'acme_batch'@'192.0.2.%' IDENTIFIED BY '…';
```

Add the vault from §5 and an application to `mariadb.yaml`. An account names
its host, as on MySQL:

```yaml
targets:
  - name: mariadb-dev
    ...
    vault: vault-dev

applications:
  - name: acme-mariadb
    targets: [mariadb-dev]
    accounts: [acme_app@%, acme_batch@192.0.2.%]
    secret_template: "vault-dev:acme/mariadb/{host}#DB_CREDENTIALS/{user}"
```

Stage passwords with `creds generate`, then run `creds apply`:

```
$ sopuli --config mariadb.yaml creds apply
Plan: 2 accounts x 1 target = 2 applys   [dev]

ACCOUNT               TARGET       INTENT                               SECRET
acme_app@%            mariadb-dev  verify, password_set, vault_promote  vault-dev:acme/mariadb/any
acme_batch@192.0.2.%  mariadb-dev  verify, password_set, vault_promote  vault-dev:acme/mariadb/192.0.2.any

ACCOUNT               TARGET       SECRET                              SOURCE
acme_app@%            mariadb-dev  vault-dev:acme/mariadb/any          pending
acme_batch@192.0.2.%  mariadb-dev  vault-dev:acme/mariadb/192.0.2.any  pending

ACCOUNT               TARGET       STATE         DETAIL
acme_app@%            mariadb-dev  IN_SYNC       changed and verified by login
acme_batch@192.0.2.%  mariadb-dev  UNVERIFIABLE  the server refused the password (1045), but the login reaches the account the server matches from the tool's host, which need not be acme_batch@192.0.2.%, so it says nothing certain about acme_batch@192.0.2.%

2 changed, 1 promoted to `current`, 1 not confirmed
repair with: sopuli creds apply --config mariadb.yaml
         or: --repair FILE, if you captured this run with --output json
...
```

It exits 4. The server never sees the password: the statement carries the
value the account's plugin stores, computed on this machine. `apply` does not
log in before the change, because a failed login counts toward
`max_password_errors`, which the tool cannot read. After the change it logs in
with the new password, and `acme_app@%` is verified. A login for
`acme_batch@192.0.2.%` could reach another account, so this login is the one
the staged `pending` allows on this target. First the vault records that it is
spent, beside the `pending`:

```
"reached": {"acme_batch": {"mariadb-dev": "spent"}}
```

The tool's host is not in `192.0.2.%`, so the login reaches no account, the
refusal says nothing, and the account stays `pending`. A login that passed
would have been recorded as `passed` too, and would count as confirmed for this
`pending` in a later run.

Run `creds apply` again. `acme_app@%` has only `current` now, and without a
login the tool cannot tell whether it needs a change, so it is left alone.
`acme_batch@192.0.2.%` still has its `pending`, which is set again, and its
reach is spent, so no login is made:

```
$ sopuli --config mariadb.yaml creds apply
...
ACCOUNT               TARGET       STATE         DETAIL
acme_app@%            mariadb-dev  SKIPPED       not changed: on this target the tool does not log in before a change, so it cannot tell whether the account already has the vault's `current`, and it sets a password only for a rotation in flight. `creds check` compares them, and `creds rotate` changes the password
acme_batch@192.0.2.%  mariadb-dev  UNVERIFIABLE  no login was attempted, because the login reaches the account the server matches from the tool's host, which need not be acme_batch@192.0.2.%

1 changed, 1 skipped, 1 not confirmed
...
```

`creds check` logs in only where nothing but the declared account can answer.
A wrong password counts toward `max_password_errors` on whatever account the
login reaches, and checks repeat:

```
$ sopuli --config mariadb.yaml creds check
Plan: 2 accounts x 1 target = 2 checks   [dev]

ACCOUNT               TARGET       INTENT  SECRET
acme_app@%            mariadb-dev  verify  vault-dev:acme/mariadb/any
acme_batch@192.0.2.%  mariadb-dev  verify  vault-dev:acme/mariadb/192.0.2.any

ACCOUNT               TARGET       STATE         DETAIL
acme_app@%            mariadb-dev  IN_SYNC       vault v2 verified by login; the lockout guard is unavailable: MariaDB counts failed logins against max_password_errors in mysql.global_priv, which the tool account does not read
acme_batch@192.0.2.%  mariadb-dev  UNVERIFIABLE  `current` is empty and a password is staged in `pending`; `creds apply` promotes it once every target confirms

1 unverifiable
...
```

`creds rotate` draws, stages, applies and promotes in one run. It refuses an
account that already has a `pending` staged, so name the other one:

```
$ sopuli --config mariadb.yaml creds rotate --account 'acme_app@%' --confirm
Plan: 1 account x 1 target = 1 rotation   [dev]

ACCOUNT     TARGET       INTENT                                                              SECRET
acme_app@%  mariadb-dev  generate, vault_write_pending, verify, password_set, vault_promote  vault-dev:acme/mariadb/any

ACCOUNT     TARGET       STATE    DETAIL
acme_app@%  mariadb-dev  IN_SYNC  changed and verified by login

1 changed, 1 promoted to `current`

rotation: staged 1 document, promoted 1 document
...
```

`acme_batch@192.0.2.%` stays `pending` until a new password is staged with
`creds generate --overwrite-pending` and applied from a host whose login
reaches the account. A new `pending` brings a new reaching login.

An expired account is changed too, because the new password ends the expiry.
`acme_batch@192.0.2.%` still has its `pending`, so name the other account.
Stage a password with `creds generate --account 'acme_app@%'`, expire the
account as root with `ALTER USER 'acme_app'@'%' PASSWORD EXPIRE`, and apply:

```
$ sopuli --config mariadb.yaml creds apply --account 'acme_app@%'
...
ACCOUNT     TARGET       STATE    DETAIL
acme_app@%  mariadb-dev  IN_SYNC  changed and verified by login

1 changed, 1 promoted to `current`
...
```

`password_expired` in `mysql.user` then reads `N`.

`creds rotate --strategy rollover` keeps the old password working beside the
new one. MariaDB keeps it as a second login method, joined by `OR`:

```
$ sopuli --config mariadb.yaml creds rotate --account 'acme_app@%' --strategy rollover --confirm
...
ACCOUNT     TARGET       STATE            DETAIL
acme_app@%  mariadb-dev  ROLLOVER_ACTIVE  changed and verified by login; the previous password also logs in until `sopuli creds finish-rollover`

1 changed, 1 promoted to `current`
...
```

On an `ed25519` account a PyMySQL client can use only the new password. The
row ends with that, and the run, `--dry-run` included, warns of it:

```
$ sopuli --config mariadb.yaml creds rotate --account 'acme_app@%' --strategy rollover --dry-run
...
nothing was rotated (--dry-run)

2 warnings:
  targets[0].mariadb.ssl_mode: target 'mariadb-dev' does not verify the server (`ssl_mode: REQUIRED`)
    hint: anything between this run and the server can present its own certificate and read the password a run sets. Use `ssl_mode: VERIFY_IDENTITY` (the default), with `ssl_ca` naming the CA that issued the server's certificate
  mariadb-dev: acme_app@%: the account uses ed25519, so a PyMySQL client cannot log in with the old password while the rollover is open; other clients can
```

`creds finish-rollover` sends the current password alone, which ends the old
one. The tool cannot read whether an old password is kept, so the window is
`unknown`, and every run reports a change:

```
$ sopuli --config mariadb.yaml creds finish-rollover --account 'acme_app@%' --confirm
Plan: 1 account x 1 target = 1 window   [dev]

ACCOUNT     TARGET       INTENT                   SECRET
acme_app@%  mariadb-dev  verify, rollover_finish  vault-dev:acme/mariadb/any

ACCOUNT     TARGET       WINDOW
acme_app@%  mariadb-dev  unknown

ACCOUNT     TARGET       STATE    DETAIL
acme_app@%  mariadb-dev  IN_SYNC  any second password ended; the current password was sent alone

1 closed
...
```

---

## 8. Application credentials (UC-1)

The vault is the master copy of each password. The `creds` commands make the
database match the vault. [`use-cases/uc-01-app-credential-sync.md`](use-cases/uc-01-app-credential-sync.md)
specifies them.

Every command prints its plan first, and every command that changes something
takes `--dry-run`. The `STATE` column is coloured. The word is always printed
too, so `--color never` and `NO_COLOR=1` lose nothing:

<!-- checked-list: state-colours -->
| Looks like | Means | States |
|---|---|---|
| cyan | nothing to do | `IN_SYNC` |
| yellow | somebody has to act, the run is fine | `DRIFT`, `PENDING_APPLY`, `ROLLOVER_ACTIVE`, `VAULT_ONLY`, `RESET` |
| red, bold | the tool could not do the job, or the estate is not in a state it can | `ERROR`, `ACCOUNT_MISSING`, `LOCKED`, `EXPIRED`, `REPORT_PROBLEM`, `PROFILE_MISSING` |
| dim | nothing could be concluded | `UNVERIFIABLE`, `SKIPPED`, `DECLARED`, `NOT_CHECKED`, `NO_RULE`, `UNDECLARED`, `REPORT_OK` |

### 8.1 `status`: what is there

`status` reads the vault and the database dictionary. It does not log in as the
accounts.

```
$ sopuli --config sopuli.yaml creds status
Plan: 2 accounts x 1 target = 2 accounts   [dev]

ACCOUNT          TARGET    INTENT  SECRET
acme_app_user    free-pdb  none    vault-dev:acme/dev/acme
acme_batch_user  free-pdb  none    vault-dev:acme/dev/acme

shared secrets (1 document):
SECRET                   TARGETS   ACCOUNTS
vault-dev:acme/dev/acme  free-pdb  acme_app_user, acme_batch_user

ACCOUNT          TARGET    STATE         VAULT_V  AGE  DB_PW_CHANGED  PROFILE          ROLLOVER
acme_app_user    free-pdb  UNVERIFIABLE  -        -    2026-10-23     DEFAULT          not configured
acme_batch_user  free-pdb  UNVERIFIABLE  -        -    2026-10-23     SOPULI_ROLLOVER  60m configured

2 accounts, nothing to act on
```

The vault holds nothing yet, so `VAULT_V` is empty.

### 8.2 `generate`: stage a password in the vault

`generate` draws a password for each account and writes it to the vault's
`pending` stage. It changes no database.

```
$ sopuli --config sopuli.yaml creds generate
...
constraints: 128 bytes in AL32UTF8, from free-pdb

SECRET                   STAGE    ACCOUNTS
vault-dev:acme/dev/acme  pending  acme_app_user, acme_batch_user

ACCOUNT          SECRET                   RESULT
acme_app_user    vault-dev:acme/dev/acme  staged v1
acme_batch_user  vault-dev:acme/dev/acme  staged v1

2 staged; no database was changed -- run `sopuli creds apply` to use them
```

The `constraints` line is the byte limit the tool read from the target.

### 8.3 `apply`: put the password on the database

`apply` sets the `pending` password on each database, logs in with it, and then
promotes it to `current` in the vault.

```
$ sopuli --config sopuli.yaml creds apply
...
ACCOUNT          TARGET    SECRET                   SOURCE
acme_app_user    free-pdb  vault-dev:acme/dev/acme  pending
acme_batch_user  free-pdb  vault-dev:acme/dev/acme  pending

ACCOUNT          TARGET    STATE            DETAIL
acme_app_user    free-pdb  IN_SYNC          changed and verified by login
acme_batch_user  free-pdb  ROLLOVER_ACTIVE  changed and verified; a rollover window is open, so the previous password authenticates until it closes

2 changed, 1 promoted to `current`

1 note:
  free-pdb: a password was sent over a connection that is not encrypted: require NNE or TLS on the server (SQLNET.ENCRYPTION_SERVER = REQUIRED in its sqlnet.ora, or a TCPS listener endpoint)
```

"1 promoted" counts vault documents, and both accounts share one. The note is
`SOPULI-W031`: the tier-1 container does not require NNE or TLS, so the new
passwords crossed the network in clear. Every command that sends a password
prints it, once per target.

Run it again. Nothing changes, because the database already has the vault's
password:

```
$ sopuli --config sopuli.yaml creds apply
...
ACCOUNT          TARGET    STATE            DETAIL
acme_app_user    free-pdb  IN_SYNC          the vault's password is already accepted; nothing to change
acme_batch_user  free-pdb  ROLLOVER_ACTIVE  the vault's password is already accepted, and a rollover window is open: the previous password still works too

nothing changed
```

### 8.4 `finish-rollover`: close a rollover window

`acme_batch_user` has a profile with `PASSWORD_ROLLOVER_TIME`, so after a change
its old password also works for an hour. `finish-rollover` ends that window:

```
$ sopuli --config sopuli.yaml creds finish-rollover --confirm
...
ACCOUNT          TARGET    WINDOW
acme_app_user    free-pdb  none open
acme_batch_user  free-pdb  open, 59m left

ACCOUNT          TARGET    STATE    DETAIL
acme_app_user    free-pdb  IN_SYNC  no rollover window is open
acme_batch_user  free-pdb  IN_SYNC  rollover window closed, 59m early

1 closed
```

### 8.5 `check`: find drift

`check` logs in as each account with the vault's password. Change a password
behind the tool's back, then check:

```bash
printf '%s\n' 'system/sopuli-test@localhost:1521/FREEPDB1' \
  'ALTER USER acme_app_user IDENTIFIED BY "Changed-by-hand#1";' | \
  docker exec -i sopuli-test-oracle-free-1 sqlplus -S
```

```
$ sopuli --config sopuli.yaml creds check
...
ACCOUNT          TARGET    STATE    DETAIL
acme_app_user    free-pdb  DRIFT    vault v2 the database rejected this password (ORA-01017): ORA-01017: invalid credential or not authorized; logon denied
acme_batch_user  free-pdb  IN_SYNC  vault v2 verified by login

1 drift
```

Exit 3 means drift. `apply` repairs it from the vault's `current`:

```
$ sopuli --config sopuli.yaml creds apply
...
ACCOUNT          TARGET    STATE    DETAIL
acme_app_user    free-pdb  IN_SYNC  changed and verified by login
acme_batch_user  free-pdb  IN_SYNC  the vault's password is already accepted; nothing to change

1 changed

1 note:
  free-pdb: a password was sent over a connection that is not encrypted: require NNE or TLS on the server (SQLNET.ENCRYPTION_SERVER = REQUIRED in its sqlnet.ora, or a TCPS listener endpoint)
```

A login that fails counts toward the account's lockout limit. `--method hash`
compares the password with the account's verifier instead, and needs no login:

```
$ sopuli --config sopuli.yaml creds check --method hash
...
ACCOUNT          TARGET    STATE    DETAIL
acme_app_user    free-pdb  IN_SYNC  vault v2 verified by hash; matches the account's current 12C verifier, with no login attempted
acme_batch_user  free-pdb  IN_SYNC  vault v2 verified by hash; matches the account's current 12C verifier, with no login attempted

all 2 in sync
```

### 8.6 `rotate`: generate and apply in one run

`rotate` asks for confirmation. With no terminal to ask on, it refuses:

```
$ sopuli --config sopuli.yaml creds rotate < /dev/null
sopuli: rotating a password needs confirmation, and there is nobody here to ask
  hint: pass --confirm to answer in advance, or --dry-run to see the plan without touching anything
```

Exit 8. With `--confirm`:

```
$ sopuli --config sopuli.yaml creds rotate --confirm
...
ACCOUNT          TARGET    STATE            DETAIL
acme_app_user    free-pdb  IN_SYNC          changed and verified by login
acme_batch_user  free-pdb  ROLLOVER_ACTIVE  changed and verified; a rollover window is open, so the previous password authenticates until it closes

2 changed, 1 promoted to `current`

rotation: staged 1 document, promoted 1 document

1 note:
  free-pdb: a password was sent over a connection that is not encrypted: require NNE or TLS on the server (SQLNET.ENCRYPTION_SERVER = REQUIRED in its sqlnet.ora, or a TCPS listener endpoint)
```

### 8.7 Roll back

The vault keeps the password `current` held before, as `previous`. Applying it
rolls back:

```
$ sopuli --config sopuli.yaml creds apply --source previous --confirm
...
ACCOUNT          TARGET    SECRET                   SOURCE
acme_app_user    free-pdb  vault-dev:acme/dev/acme  previous
acme_batch_user  free-pdb  vault-dev:acme/dev/acme  previous

ACCOUNT          TARGET    STATE            DETAIL
acme_app_user    free-pdb  IN_SYNC          changed and verified by login
acme_batch_user  free-pdb  ROLLOVER_ACTIVE  the vault's password is already accepted, and a rollover window is open: the previous password still works too

1 rolled back, 1 promoted to `current`

1 note:
  free-pdb: a password was sent over a connection that is not encrypted: require NNE or TLS on the server (SQLNET.ENCRYPTION_SERVER = REQUIRED in its sqlnet.ora, or a TCPS listener endpoint)
```

`acme_batch_user` needs no change: its rollover window is still open, so the old
password still works.

### 8.8 With OCI Vault as the store

The same commands run with an OCI vault as the master. This needs an OCI
tenancy, a vault and a key in it, the `oci` extra, and a profile in
`~/.oci/config`; the test stack has no OCI emulator. The samples below ran
with this config, on a second test stack's port. The `9bf135` in the template is the run's own, so that each
run makes fresh secrets:

```yaml
version: 1
vaults:
  vault-oci:
    type: oci
    vault_id:       ocid1.vault.oc1.eu-frankfurt-1.exampleuniqueid
    compartment_id: ocid1.compartment.oc1..exampleuniqueid
    key_id:         ocid1.key.oc1.eu-frankfurt-1.exampleuniqueid
    auth: config_file
defaults:
  policy: app-standard
policies:
  app-standard:
    password: {length: 24, charset: alnum, first_char: alpha}
targets:
  - name: free-pdb
    type: oracle
    dsn: 127.0.0.1:1521/FREEPDB1
    environment: dev
    vault: vault-oci
    admin: {username: SYSTEM, auth: {method: env}}
    oracle: {scope: pdb, container: FREEPDB1}
applications:
  - name: acme
    accounts: [acme_native_user]
    secret_template: "acme-9bf135-{account}#password"
```

`ACME_NATIVE_USER` is an account created for the run, with `CREATE SESSION`.
A ref on an OCI store is the OCI secret name, so a `secret_template` uses no
`/`. An application with one
account per secret gets OCI's own stages: `pending` is a PENDING version, and
the results name OCI's version numbers. Each OCI write waits about 20 seconds
for the secret to settle.

```
$ sopuli --config sopuli.yaml creds generate --promote
...
ACCOUNT           SECRET                                  RESULT
acme_native_user  vault-oci:acme-9bf135-acme_native_user  promoted to v1

1 promoted to current; no database was changed -- run `sopuli creds apply` to use them

1 note:
  the lock path for vault-oci:acme-9bf135-acme_native_user is not guarded against a write carrying no compare-and-set: OCI has no setting that makes secret "sopuli-locks.acme-9bf135-acme_native_user" in vault "vault-oci" refuse a write without a compare-and-set, so only IAM keeps other writers off it
    hint: grant the right to manage secrets in the store's compartment to this tool's principal alone
```

The note is `SOPULI-W019`, and every run that takes a lock on an OCI store
prints it. The tool keeps its locks in secrets named `sopuli-locks.<name>`.
The samples below leave it out, and `SOPULI-W031` with it.

`generate` then stages version 2 as PENDING, and `apply` promotes it:

```
$ sopuli --config sopuli.yaml creds generate
...
ACCOUNT           SECRET                                  RESULT
acme_native_user  vault-oci:acme-9bf135-acme_native_user  staged v2

$ sopuli --config sopuli.yaml creds apply
...
ACCOUNT           TARGET    SECRET                                  SOURCE
acme_native_user  free-pdb  vault-oci:acme-9bf135-acme_native_user  pending

ACCOUNT           TARGET    STATE    DETAIL
acme_native_user  free-pdb  IN_SYNC  changed and verified by login

1 changed, 1 promoted to `current`
```

OCI now holds version 1 as PREVIOUS and version 2 as CURRENT. `rotate`, `check`
and `apply --source previous` run as in §8.5 to §8.7. After a `rotate`, `check`
names the OCI version it verified:

```
$ sopuli --config sopuli.yaml creds check
...
ACCOUNT           TARGET    STATE    DETAIL
acme_native_user  free-pdb  IN_SYNC  vault v3 verified by login

all 1 in sync
```

OCI keeps at most 30 versions of a secret. When a write would make a 31st, the
tool schedules the deletion of the oldest DEPRECATED version first, and says
so as `SOPULI-W059`. To read the password from Kubernetes, see
[`scenarios/kubernetes-eso.md`](scenarios/kubernetes-eso.md) §8.

### 8.9 With a file store

A `file` store keeps every secret in one file, encrypted with age. It needs no
server, so it is the quickest store to try the commands with. It is for local
development and CI, not for production: every run that opens one says so. It
needs the `file` extra:

```
pip install "sopuli-dba[file]"
```

The store is opened with an age identity, a secret key that decrypts every
password in the store. The tool does not check who can read it, so keep it
readable only by you. Make one with the library the extra installed; this
writes the file as UTF-8 and, on Linux and macOS, makes it mode 0600:

```
$ mkdir ~/sopuli-file
$ python -c "import os; from pyrage import x25519; p = os.path.expanduser('~/sopuli-file/identity.txt'); open(p, 'w', encoding='utf-8').write(f'{x25519.Identity.generate()}\n'); os.chmod(p, 0o600)"
```

`age-keygen -o ~/sopuli-file/identity.txt` makes the same file, if you have
`age`. On Windows, give the file to your user alone, as for the config file
(§5). The samples below ran against the PostgreSQL cluster of §7, with this
config as `file.yaml`:

```yaml
version: 1
vaults:
  vault-file:
    type: file
    addr: ~/sopuli-file/acme-dev.age
    identity: { file: ~/sopuli-file/identity.txt }
    locking: advisory-only
defaults:
  vault: vault-file
targets:
  - name: pg-dev
    type: postgresql
    environment: dev
    dsn: "127.0.0.1:5432"
    admin: { username: sopuli_admin, auth: { method: env } }
    postgres: { sslmode: disable }
policies:
  standard:
    password: { length: 24, charset: alnum, first_char: alpha }
accounts:
  - acme_app_user
secret_template: "vault-file:acme/{env}/db#DB_CREDENTIALS/{account}"
policy: standard
```

`addr` must be a full path, or one that starts with `~`. The store has no
compare-and-set, so a command that changes it needs `locking: advisory-only`;
without it, `creds generate` stops with exit 5. The file does not exist until
the first write creates it, readable only by you. `config show` prints the
store's keys under the table:

```
$ sopuli --config file.yaml config show
...
vaults
NAME        TYPE  ADDRESS                     NOTE
vault-file  file  ~/sopuli-file/acme-dev.age  advisory-only
  vault-file  identity      file ~/sopuli-file/identity.txt
              max_versions  10 (default)
```

The commands then run as they do against Vault. The samples leave out the
`sslmode` warning and note of §7:

```
$ sopuli --config file.yaml creds generate
...
ACCOUNT        SECRET                  RESULT
acme_app_user  vault-file:acme/dev/db  staged v1

1 staged; no database was changed -- run `sopuli creds apply` to use them

2 warnings:
...
  vault "vault-file" is a file store, for local development and CI: it is not for production

$ sopuli --config file.yaml creds apply
...
ACCOUNT        TARGET  STATE    DETAIL
acme_app_user  pg-dev  IN_SYNC  changed and verified by login

1 changed, 1 promoted to `current`

$ sopuli --config file.yaml creds check
...
ACCOUNT        TARGET  STATE    DETAIL
acme_app_user  pg-dev  IN_SYNC  vault v2 verified by login

all 1 in sync

$ sopuli --config file.yaml creds rotate --confirm
...
ACCOUNT        TARGET  STATE    DETAIL
acme_app_user  pg-dev  IN_SYNC  changed and verified by login

1 changed, 1 promoted to `current`

rotation: staged 1 document, promoted 1 document
```

The last warning is `SOPULI-W070`, and every run that opens a file store prints
it. The store keeps the last 10 versions of each secret, or `max_versions` of
them. The personal-account commands refuse a file store as the store for
reset records or for a delivery.

---

## 9. Personal accounts (UC-2)

A personal account belongs to a person. The vault is not its master copy: the
tool hands a new password to the person and keeps no copy.
[`use-cases/uc-02-personal-account-passwords.md`](use-cases/uc-02-personal-account-passwords.md)
specifies these commands.

These commands are experimental in the alpha.

### `account list`

`list` shows the accounts `personal_accounts:` declares, as the database sees
them:

```
$ sopuli --config sopuli.yaml account list
ACCOUNT         TARGET    DECLARED BY  STATUS  DB_PW_CHANGED  RESET_AT
ACME_DEV_ALICE  free-pdb  names        OPEN    2026-10-23     -
ACME_DEV_BOB    free-pdb  names        OPEN    2026-10-23     -

2 declared accounts, 2 on the selected targets
```

`personal_accounts:` can also select accounts by a database profile or role, with
`profile:` or `role:` instead of `accounts:`. `list` is how you see which
accounts that selects.

On the PostgreSQL cluster of §7, make a role with three members, one of them
`NOLOGIN`:

```
postgres=# CREATE ROLE acme_dev_team NOLOGIN;
postgres=# CREATE ROLE acme_dev_alice LOGIN IN ROLE acme_dev_team;
postgres=# CREATE ROLE acme_dev_bob LOGIN IN ROLE acme_dev_team;
postgres=# CREATE ROLE acme_dev_carol NOLOGIN IN ROLE acme_dev_team;
```

Add a policy and a `role:` predicate to `postgres.yaml`:

```yaml
policies:
  personal-standard:
    password: { length: 20 }
personal_accounts:
  - role: acme_dev_team
    policy: personal-standard
```

```
$ sopuli --config postgres.yaml account list
ACCOUNT         TARGET  DECLARED BY           STATUS   DB_PW_CHANGED  RESET_AT
acme_dev_alice  pg-dev  role 'acme_dev_team'  OPEN     -              -
acme_dev_bob    pg-dev  role 'acme_dev_team'  OPEN     -              -
acme_dev_carol  pg-dev  role 'acme_dev_team'  NOLOGIN  -              -

3 declared accounts, 3 on the selected targets

2 notes:
  pg-dev: DB_PW_CHANGED is empty for 3 accounts: PostgreSQL does not record when a role's password was changed
  no `reset_records:` block is declared, so there is no reset journal to read and RESET_AT is empty for every account; the database's own password-change date is unaffected and is reported beside it

1 warning:
  targets[0].postgres.sslmode: target 'pg-dev' does not verify the server (`sslmode: disable`)
    hint: anything between this run and the server can present its own certificate and read the password a run sets. Use `sslmode: verify-full` (the default), with `sslrootcert` naming the CA that issued the server's certificate
```

A cluster has no profiles, so a `profile:` predicate on a PostgreSQL target is
refused with exit 5.

On the MySQL server of §7, with the tool account's grants, make a role and
grant it to two people:

```
mysql> CREATE ROLE 'acme_dev_team';
mysql> CREATE USER 'acme_dev_alice'@'%' IDENTIFIED BY '…';
mysql> CREATE USER 'acme_dev_bob'@'localhost' IDENTIFIED BY '…';
mysql> GRANT 'acme_dev_team' TO 'acme_dev_alice'@'%', 'acme_dev_bob'@'localhost';
```

A MySQL role is an account, so the rule names its host. Add to `mysql.yaml`:

```yaml
policies:
  personal-standard:
    password: { length: 20 }
personal_accounts:
  - role: acme_dev_team@%
    policy: personal-standard
```

```
$ sopuli --config mysql.yaml account list
ACCOUNT                 TARGET     DECLARED BY             STATUS  DB_PW_CHANGED  RESET_AT
acme_dev_alice@%        mysql-dev  role 'acme_dev_team@%'  OPEN    2026-11-03     -
acme_dev_bob@localhost  mysql-dev  role 'acme_dev_team@%'  OPEN    2026-11-03     -

2 declared accounts, 2 on the selected targets

2 notes:
  no `reset_records:` block is declared, so there is no reset journal to read and RESET_AT is empty for every account; the database's own password-change date is unaffected and is reported beside it
  mysql-dev: MySQL keeps a block after failed logins (error 3955) outside mysql.user, so the tool cannot read it, and an account shown as OPEN may be blocked until PASSWORD_LOCK_TIME ends or somebody runs ALTER USER … ACCOUNT UNLOCK

1 warning:
  targets[0].mysql.ssl_mode: target 'mysql-dev' does not verify the server (`ssl_mode: REQUIRED`)
    hint: anything between this run and the server can present its own certificate and read the password a run sets. Use `ssl_mode: VERIFY_IDENTITY` (the default), with `ssl_ca` naming the CA that issued the server's certificate
```

The role counts whether or not it is active. MySQL has no profiles, so a
`profile:` rule on a MySQL target is refused with exit 5, and a `role:` rule
without a host is refused when the file loads, with exit 9.

### `account reset-password`

This config delivers by `vault_wrapped`. The tool sets a new password, wraps it in
a single-use Vault token, and prints the token. You never see the password.

```
$ sopuli --config sopuli.yaml account reset-password --account acme_dev_alice
Plan: 1 account x 1 target = 1 account   [dev]

ACCOUNT         TARGET    INTENT        SECRET
acme_dev_alice  free-pdb  password_set  -
Plan: 1 account x 1 target = 1 account   [dev]

ACCOUNT         TARGET    INTENT        SECRET
acme_dev_alice  free-pdb  password_set  -

ACCOUNT         TARGET    STATE  WAS   DETAIL
acme_dev_alice  free-pdb  RESET  OPEN  declared by accounts 'acme_dev_alice', 'acme_dev_bob'

reset acme_dev_alice on 1 of 1 targets


1 note:
  free-pdb: a password was sent over a connection that is not encrypted: require NNE or TLS on the server (SQLNET.ENCRYPTION_SERVER = REQUIRED in its sqlnet.ora, or a TCPS listener endpoint)

hand this to acme_dev_alice for free-pdb; it unwraps once:

    <TOKEN>

It stops working at 2026-10-23T08:29:54.669686Z, and the first unwrap is the
last. Do not unwrap it to check -- that spends the person's one read, and
them finding it spent is the only warning either of you gets.
```

The plan appears twice. The first copy goes to stderr before anything changes,
so a run that fails part way still shows what it was about to touch. The second
is part of the result on stdout.

`SECRET` is `-`, because no vault document holds a personal password. Add
`--dry-run` to see the plan without resetting.

The person unwraps the token once:

```
$ vault unwrap -format=json <TOKEN>
{
  "request_id": "afd1393d-f78e-e748-c877-01791f9ba871",
  "lease_id": "",
  "lease_duration": 0,
  "renewable": false,
  "data": {
    "account": "acme_dev_alice",
    "password": "<PASSWORD>",
    "target": "free-pdb"
  },
  "warnings": null,
  "mount_type": "system"
}
```

A second unwrap fails. If the person finds the token already spent, somebody else
read it.

```
$ vault unwrap <TOKEN>
Error unwrapping: Error making API request.

URL: PUT http://127.0.0.1:8200/v1/sys/wrapping/unwrap
Code: 400. Errors:

* wrapping token is not valid or does not exist
```

The reset is recorded under `reset_records:`, and `list` shows when:

```
$ sopuli --config sopuli.yaml account list
ACCOUNT         TARGET    DECLARED BY  STATUS  DB_PW_CHANGED  RESET_AT
ACME_DEV_ALICE  free-pdb  names        OPEN    2026-10-23     2026-10-23T08:14:54.701090Z
ACME_DEV_BOB    free-pdb  names        OPEN    2026-10-23     -

2 declared accounts, 2 on the selected targets
```

A reset draws a new password every time, so running it twice resets twice.

### `account reset-password` on PostgreSQL

On the cluster of §7, with the roles from `account list` above, give the tool
account `ADMIN OPTION` on each role it may reset, and let one role's
`VALID UNTIL` pass:

```
postgres=# GRANT acme_dev_alice TO sopuli_admin WITH ADMIN OPTION, INHERIT FALSE, SET FALSE;
postgres=# GRANT acme_dev_bob TO sopuli_admin WITH ADMIN OPTION, INHERIT FALSE, SET FALSE;
postgres=# GRANT acme_dev_carol TO sopuli_admin WITH ADMIN OPTION, INHERIT FALSE, SET FALSE;
postgres=# ALTER ROLE acme_dev_bob VALID UNTIL '2000-01-01';
```

Add the `vaults:`, `defaults.vault`, `delivery:` and `reset_records:` blocks of
§5 to `postgres.yaml`. A role past its `VALID UNTIL` is `EXPIRED`, and the
reset sets the date to `infinity` with the password:

```
$ sopuli --config postgres.yaml account reset-password --account acme_dev_bob
Plan: 1 account x 1 target = 1 account   [dev]

ACCOUNT       TARGET  INTENT        SECRET
acme_dev_bob  pg-dev  password_set  -

ACCOUNT       TARGET  STATE  WAS      DETAIL
acme_dev_bob  pg-dev  RESET  EXPIRED  declared by role 'acme_dev_team'

reset acme_dev_bob on 1 of 1 targets


1 note:
  pg-dev: a password was sent over a connection that is not encrypted: set `postgres.sslmode` to verify-full, and give the server a certificate (`ssl = on`)

hand this to acme_dev_bob for pg-dev; it unwraps once:

    <TOKEN>

It stops working at 2026-10-31T18:59:39.448848Z, and the first unwrap is the
last. Do not unwrap it to check -- that spends the person's one read, and
them finding it spent is the only warning either of you gets.

1 warning:
  targets[0].postgres.sslmode: target 'pg-dev' does not verify the server (`sslmode: disable`)
    hint: anything between this run and the server can present its own certificate and read the password a run sets. Use `sslmode: verify-full` (the default), with `sslrootcert` naming the CA that issued the server's certificate
```

```
$ docker exec sopuli-test-postgres-1 psql -U postgres -tAc "select rolname, rolvaliduntil from pg_roles where rolname like 'acme_dev_%' order by 1"
acme_dev_alice|
acme_dev_bob|infinity
acme_dev_carol|
acme_dev_team|
```

A `NOLOGIN` role is `SKIPPED`, as a locked Oracle account is. `delivery.method:
manual` is refused with exit 5, because PostgreSQL cannot make a role change its
password at its next login:

```
$ sopuli --config postgres.yaml account reset-password --account acme_dev_alice --dry-run
...
sopuli: target "pg-dev" does not support expire_password
  hint: the seen path expires the password so that the copy the DBA saw stops working at the owner's first login (UC-2 §1), and this target cannot expire one; use an unseen delivery method
```

### `account reset-password` on MySQL

On the server of §7, with the role from `account list` above, add the
`vaults:`, `defaults.vault`, `delivery:` and `reset_records:` blocks of §5 to
`mysql.yaml`. The account is named with its host. Give `acme_dev_alice` a
failed-login limit and one wrong password, which blocks it:

```
mysql> ALTER USER 'acme_dev_alice'@'%' FAILED_LOGIN_ATTEMPTS 1 PASSWORD_LOCK_TIME 1;
$ docker exec sopuli-test-mysql-1 mysql -h127.0.0.1 -uacme_dev_alice -pWrong -e "select 1"
ERROR 3955 (HY000): Access denied for user 'acme_dev_alice'@'127.0.0.1'. Account is blocked for 1 day(s) (1 day(s) remaining) due to 1 consecutive failed logins.
```

`mysql.user` does not show the block, so the account reads `OPEN`. The reset
ends the block anyway:

```
$ sopuli --config mysql.yaml account reset-password --account 'acme_dev_alice@%'
Plan: 1 account x 1 target = 1 account   [dev]

ACCOUNT           TARGET     INTENT        SECRET
acme_dev_alice@%  mysql-dev  password_set  -

ACCOUNT           TARGET     STATE  WAS   DETAIL
acme_dev_alice@%  mysql-dev  RESET  OPEN  declared by role 'acme_dev_team@%'

reset acme_dev_alice@% on 1 of 1 targets

hand this to acme_dev_alice@% for mysql-dev; it unwraps once:

    <TOKEN>

It stops working at 2026-11-03T17:08:28.294814Z, and the first unwrap is the
last. Do not unwrap it to check -- that spends the person's one read, and
them finding it spent is the only warning either of you gets.

1 warning:
  targets[0].mysql.ssl_mode: target 'mysql-dev' does not verify the server (`ssl_mode: REQUIRED`)
    hint: anything between this run and the server can present its own certificate and read the password a run sets. Use `ssl_mode: VERIFY_IDENTITY` (the default), with `ssl_ca` naming the CA that issued the server's certificate
```

The password in the token logs in. The record is at
`sopuli/personal-resets/mysql-dev/acme_dev_alice@any`: a path holds no `%`.
`--keep-rollover` is refused with exit 5, because a reset on MySQL always
discards the old password.

### Delivering to the person's own Vault path

With this `delivery:` block, the tool writes the password to a Vault path that
only the person's own Vault login can read, and Vault deletes it when the `ttl`
runs out:

```yaml
delivery:
  method: vault_path
  vault_path:
    ttl: 8h
    prefix: personal
```

The stack's Vault is set up for it. A `userpass` login `alice` (password
`sopuli-test-alice`) has `db_account = ACME_DEV_ALICE` on its identity, and its
policy reads `kv/data/personal/{{identity.entity.metadata.db_account}}/*`. The
token `sopuli-test-personal-writer` can write under `personal/` and cannot read
it. It cannot write `reset_records:` either, so this run used a config without
that block. Run the reset with that token:

```
$ VAULT_TOKEN=sopuli-test-personal-writer sopuli --config sopuli.yaml account reset-password --account acme_dev_alice
...
ACCOUNT         TARGET    STATE  WAS   DETAIL
acme_dev_alice  free-pdb  RESET  OPEN  declared by accounts 'acme_dev_alice', 'acme_dev_bob'

reset acme_dev_alice on 1 of 1 targets
...
tell acme_dev_alice the new password for free-pdb is waiting at:

    kv/personal/ACME_DEV_ALICE/free-pdb

They read it with their own Vault login. Vault deletes it at 2026-10-27T23:29:13.926882Z;
a token that holds `undelete` on the path can still restore it.
```

The path uses the account name as the database stores it. The person logs in and
reads it. The `vault` alias from §4 sends the root token, so use a shell in the
container instead; `vault login` asks for the password:

```
$ docker exec -it -e VAULT_ADDR=http://127.0.0.1:8200 sopuli-test-vault-1 sh
/ # vault login -method=userpass username=alice
/ # vault kv get -mount=kv personal/ACME_DEV_ALICE/free-pdb
============== Secret Path ==============
kv/data/personal/ACME_DEV_ALICE/free-pdb

======= Metadata =======
Key                Value
---                -----
created_time       2026-10-27T15:29:13.926882676Z
custom_metadata    <nil>
deletion_time      2026-10-27T23:29:13.926882676Z
destroyed          false
version            2

====== Data ======
Key         Value
---         -----
account     ACME_DEV_ALICE
password    <PASSWORD>
target      free-pdb
```

Logged in as `bob`, the same read answers `Code: 403` and `permission denied`.

A token that can also read the path is refused before anything changes:

```
$ VAULT_TOKEN=sopuli-test-personal-writer-read sopuli --config sopuli.yaml account reset-password --account acme_dev_alice
sopuli: the token for 'vault-dev' holds read on kv/data/personal/acme_dev_alice/free-pdb, so it could read acme_dev_alice's password back
  hint: on `vault_path` the DBA must not be able to read the person's path (UC-2 6.6). Remove `read` from this token's policy on that path, or use a token without the root policy
```

### Delivering a one-time link

With this `delivery:` block, the tool encrypts the password, stores the
ciphertext on the stack's Yopass server as a one-time secret, and prints a link.
It needs the `yopass` extra.

```yaml
delivery:
  method: one_time_link
  one_time_link:
    base_url: http://127.0.0.1:1337
    ttl: 1h
```

```
$ sopuli --config sopuli.yaml account reset-password --account acme_dev_alice
...
ACCOUNT         TARGET    STATE  WAS   DETAIL
acme_dev_alice  free-pdb  RESET  OPEN  declared by accounts 'acme_dev_alice', 'acme_dev_bob'

reset acme_dev_alice on 1 of 1 targets
...
hand this link to acme_dev_alice for free-pdb; it opens once:

    http://127.0.0.1:1337/#/s/<ID>/<KEY>

It stops working at 2026-10-27T19:36:18Z, and the first open is the last.
Do not open it to check -- that uses up the person's one view, and them
finding it gone is the only warning either of you gets.
```

The person opens the link in a browser. The page says the message can be opened
only once and has a button to show it. The button shows the password. The server
then no longer has the secret:

```
$ curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:1337/secret/<ID>
404
```

With `split_key: true`, the tool prints the link without the key, and the key,
to send by two different channels. The page asks for the key:

```
hand these to acme_dev_alice for free-pdb, by two different channels:

    link:  http://127.0.0.1:1337/#/s/<ID>
    key:   <KEY>

The link asks for the key. Send each one a different way, so that neither
channel alone can read the password.
```

A `ttl` the server does not accept, here `2h`, is refused before anything
changes. Exit 5:

```
$ sopuli --config sopuli.yaml account reset-password --account acme_dev_alice
sopuli: `delivery.method: one_time_link` cannot use the Yopass server at http://127.0.0.1:1337: the server does not accept a ttl of 2h: it accepts 1h, 24h or 168h
  hint: change the server's setting, or `delivery.one_time_link`, or choose another method (UC-2 6.2). Nothing was drawn or changed
```

### The seen path

With this `delivery:` block, the tool prints the password on your terminal once
and expires it, so the owner must change it at first logon:

```yaml
delivery:
  method: manual
  manual:
    force_expire: true
```

It asks for confirmation every time, and `--confirm` does not answer the prompt.
It refuses when stdout or stdin is not a terminal, or when the output is JSON. UC-2 §6.5
lists its guards. This run used a config with no `reset_records:` block, and
the tier-1 container does not encrypt connections, so it ends with two notes:

```
$ sopuli account reset-password --account acme_dev_alice
Plan: 1 account x 1 target = 1 account   [dev]

ACCOUNT         TARGET    INTENT        SECRET
acme_dev_alice  free-pdb  password_set  -
show the new password for acme_dev_alice on free-pdb on this terminal? [y/N]: y
password for acme_dev_alice, shown once:

    <PASSWORD>

It is expired: the owner must change it at first logon, which is what ends
your sight of it. It is not stored anywhere and will not be shown again.

Plan: 1 account x 1 target = 1 account   [dev]

ACCOUNT         TARGET    INTENT        SECRET
acme_dev_alice  free-pdb  password_set  -

ACCOUNT         TARGET    STATE  WAS   DETAIL
acme_dev_alice  free-pdb  RESET  OPEN  declared by accounts 'acme_dev_alice', 'acme_dev_bob'

reset acme_dev_alice on 1 of 1 targets


2 notes:
  no `reset_records:` block is declared, so no record of this reset will be written and no advisory lock is taken on the account: the run document and the database are the whole record of it
  free-pdb: a password was sent over a connection that is not encrypted: require NNE or TLS on the server (SQLNET.ENCRYPTION_SERVER = REQUIRED in its sqlnet.ora, or a TCPS listener endpoint)
```

The prompt comes after the password is set, and the password prints as soon as
you answer `y`, before the result. Answer `n` and the account keeps a password
nobody has seen; reset it again to fix that. On several targets, a password you
have already seen stays valid when you answer `n` on a later one.

### `account expire-password`

This makes the person change their password at the next logon:

```
$ sopuli --config sopuli.yaml account expire-password --account acme_dev_alice --confirm
...
ACCOUNT         TARGET    STATE    STATUS  DETAIL
acme_dev_alice  free-pdb  EXPIRED  OPEN    account was open; password expired

expired acme_dev_alice's password on 1 of 1 targets
```

A second run changes nothing:

```
ACCOUNT         TARGET    STATE    STATUS   DETAIL
acme_dev_alice  free-pdb  EXPIRED  EXPIRED  the password is already expired

acme_dev_alice's password was already expired on 1 of 1
```

### `account suspend`

This locks the account, for example when a person leaves:

```
$ sopuli --config sopuli.yaml account suspend --account acme_dev_bob --confirm
...
ACCOUNT       TARGET    STATE   STATUS  DETAIL
acme_dev_bob  free-pdb  LOCKED  OPEN    account was open; locked

suspended acme_dev_bob on 1 of 1 targets
```

A second run changes nothing:

```
ACCOUNT       TARGET    STATE   STATUS  DETAIL
acme_dev_bob  free-pdb  LOCKED  LOCKED  the account is already locked

acme_dev_bob was already locked on 1 of 1
```

### `account suspend` on PostgreSQL

On the cluster of §7, with the grants from `account reset-password` on
PostgreSQL above, the command sets the role `NOLOGIN`:

```
$ sopuli --config postgres.yaml account suspend --account acme_dev_bob --confirm
Plan: 1 account x 1 target = 1 account   [dev]

ACCOUNT       TARGET  INTENT        SECRET
acme_dev_bob  pg-dev  account_lock  -

ACCOUNT       TARGET  STATE   STATUS  DETAIL
acme_dev_bob  pg-dev  LOCKED  OPEN    role was open; set NOLOGIN

suspended acme_dev_bob on 1 of 1 targets
...
```

A second run changes nothing:

```
ACCOUNT       TARGET  STATE   STATUS   DETAIL
acme_dev_bob  pg-dev  LOCKED  NOLOGIN  the role is already NOLOGIN

acme_dev_bob was already locked on 1 of 1
```

`account reset-password` now skips `acme_dev_bob`. Run `ALTER ROLE acme_dev_bob
LOGIN` in `psql` to undo the suspension. `account expire-password` is refused
with exit 5:

```
$ sopuli --config postgres.yaml account expire-password --account acme_dev_alice --confirm
...
sopuli: target "pg-dev" does not support expire_password
  hint: this target cannot make an account change its password at its next login; hand the owner a new password with an unseen `account reset-password`, or end the account with `account suspend`
```

### `account suspend` and `account expire-password` on MySQL

On the server of §7, with `mysql.yaml` from `account reset-password` on MySQL
above. `expire-password` discards a password someone kept with `RETAIN CURRENT
PASSWORD`, then expires the password:

```
$ sopuli --config mysql.yaml account expire-password --account 'acme_dev_alice@%'
Plan: 1 account x 1 target = 1 account   [dev]

ACCOUNT           TARGET     INTENT           SECRET
acme_dev_alice@%  mysql-dev  password_expire  -

ACCOUNT           TARGET     STATE    STATUS  DETAIL
acme_dev_alice@%  mysql-dev  EXPIRED  OPEN    sent DISCARD OLD PASSWORD, so no retained password logs in; password expired

expired acme_dev_alice@%'s password on 1 of 1 targets
...
```

A second run changes nothing:

```
ACCOUNT           TARGET     STATE    STATUS   DETAIL
acme_dev_alice@%  mysql-dev  EXPIRED  EXPIRED  the password is already expired

acme_dev_alice@%'s password was already expired on 1 of 1
```

`suspend` sends `ACCOUNT LOCK`:

```
$ sopuli --config mysql.yaml account suspend --account 'acme_dev_bob@localhost'
Plan: 1 account x 1 target = 1 account   [dev]

ACCOUNT                 TARGET     INTENT        SECRET
acme_dev_bob@localhost  mysql-dev  account_lock  -

ACCOUNT                 TARGET     STATE   STATUS  DETAIL
acme_dev_bob@localhost  mysql-dev  LOCKED  OPEN    account was open; sent ACCOUNT LOCK

suspended acme_dev_bob@localhost on 1 of 1 targets
...
```

A second run reports `the account is already locked (ACCOUNT LOCK)`, and
`account reset-password` now skips `acme_dev_bob@localhost`. Run `ALTER USER
'acme_dev_bob'@'localhost' ACCOUNT UNLOCK` to undo the suspension.

### Personal accounts on MariaDB

On the server of §7, as root, make a role and two accounts that hold it:

```
mariadb> CREATE ROLE acme_dev_team;
mariadb> CREATE USER 'acme_dev_alice'@'%' IDENTIFIED BY '…';
mariadb> CREATE USER 'acme_dev_bob'@'localhost' IDENTIFIED BY '…';
mariadb> GRANT acme_dev_team TO 'acme_dev_alice'@'%', 'acme_dev_bob'@'localhost';
```

A MariaDB role has no host, so the rule names it alone. Add the `vaults:`,
`defaults.vault`, `delivery:` and `reset_records:` blocks of §5 to
`mariadb.yaml`, and:

```yaml
policies:
  personal-standard:
    password: { length: 20 }
personal_accounts:
  - role: acme_dev_team
    policy: personal-standard
```

`CREATE ROLE` grants the role to the account that created it, so the rule
admits root too, and on MariaDB check 9 refuses root for every verb:

```
$ sopuli --config mariadb.yaml account list
ACCOUNT                 TARGET       DECLARED BY           STATUS  DB_PW_CHANGED  RESET_AT
acme_dev_alice@%        mariadb-dev  role 'acme_dev_team'  OPEN    -              -
acme_dev_bob@localhost  mariadb-dev  role 'acme_dev_team'  OPEN    -              -
root@localhost          mariadb-dev  role 'acme_dev_team'  OPEN    -              -

3 declared accounts, 3 on the selected targets

2 notes:
  root@localhost on mariadb-dev: a mutating verb refuses this account at plan time: check 9 (the account holds ALTER ON *.*, ALTER ROUTINE ON *.*, BINLOG MONITOR ON *.*, CREATE ON *.*, CREATE ROUTINE ON *.* and 26 more grants). no flag overrides check 9, so no verb will act on this account
  mariadb-dev: DB_PW_CHANGED is empty for 3 accounts: MariaDB keeps the time of a password change beside the stored value, which the tool does not read
...
```

`STATUS` says nothing of the lock here: without the optional view `sopuli.account_state` (§9a),
`OPEN` means only that nobody expired the password. With the view installed,
a locked account shows `LOCKED`:

```
$ sopuli --config mariadb.yaml account list
ACCOUNT                 TARGET       DECLARED BY           STATUS  DB_PW_CHANGED  RESET_AT
acme_dev_alice@%        mariadb-dev  role 'acme_dev_team'  OPEN    -              -
acme_dev_bob@localhost  mariadb-dev  role 'acme_dev_team'  LOCKED  -              -
root@localhost          mariadb-dev  role 'acme_dev_team'  OPEN    -              -
...
```

`account suspend --account 'root@localhost'` reports `SKIPPED` with the same
reason. A reset sets the value for the account's own plugin:

```
$ sopuli --config mariadb.yaml account reset-password --account 'acme_dev_alice@%'
Plan: 1 account x 1 target = 1 account   [dev]

ACCOUNT           TARGET       INTENT        SECRET
acme_dev_alice@%  mariadb-dev  password_set  -
2 warnings:
  targets[0].mariadb.ssl_mode: target 'mariadb-dev' does not verify the server (`ssl_mode: REQUIRED`)
    hint: anything between this run and the server can present its own certificate and read the password a run sets. Use `ssl_mode: VERIFY_IDENTITY` (the default), with `ssl_ca` naming the CA that issued the server's certificate
  mariadb-dev: where the account is reset, the password is set as the only login method. Any other method it has, such as unix_socket, stops working, and the tool cannot see one
...
ACCOUNT           TARGET       STATE  WAS   DETAIL
acme_dev_alice@%  mariadb-dev  RESET  OPEN  declared by role 'acme_dev_team'

reset acme_dev_alice@% on 1 of 1 targets

hand this to acme_dev_alice@% for mariadb-dev; it unwraps once:

    <TOKEN>
...
```

The second warning is `SOPULI-W065`. It is printed with the plan, before the
reset, and `--dry-run` prints it too: a DBA's own `unix_socket` login ends
with the reset. The password in the token logs in.
A reset never sends `ACCOUNT UNLOCK`, because the tool cannot tell a
suspension from a block after failed logins: a locked account keeps its new
password and still answers `4151`, and the JSON row's `actions[].detail` says
the lock cannot be read. Unlock by hand, after checking that nobody suspended
the account. `--keep-rollover` is refused with exit 5.

`expire-password` sends `PASSWORD EXPIRE` alone, and a second run changes
nothing:

```
$ sopuli --config mariadb.yaml account expire-password --account 'acme_dev_alice@%' --confirm
...
ACCOUNT           TARGET       STATE    STATUS  DETAIL
acme_dev_alice@%  mariadb-dev  EXPIRED  OPEN    password expired

expired acme_dev_alice@%'s password on 1 of 1 targets
```

`suspend` sends `ACCOUNT LOCK` on every run, because the lock cannot be read:

```
$ sopuli --config mariadb.yaml account suspend --account 'acme_dev_bob@localhost' --confirm
...
ACCOUNT                 TARGET       STATE   STATUS  DETAIL
acme_dev_bob@localhost  mariadb-dev  LOCKED  OPEN    sent ACCOUNT LOCK; whether the account was already locked cannot be read on MariaDB

suspended acme_dev_bob@localhost on 1 of 1 targets
```

---

## 9a. Reports (UC-5)

`report accounts` reads every account on each target and checks it against the
`reports:` rules (`design/01-configuration.md` §8a). It changes nothing. It
runs on every product, and so do `report privileges` and `report history`.

Make two accounts on a profile whose passwords expire after 180 days, and one
locked account that nothing declares. As SYS in the PDB:

```sql
CREATE PROFILE acme_rpt_prof LIMIT PASSWORD_LIFE_TIME 180 FAILED_LOGIN_ATTEMPTS 5;
CREATE USER acme_rpt_user IDENTIFIED BY "Acme_Rpt_User_1" PROFILE acme_rpt_prof;
CREATE USER acme_rpt_ok IDENTIFIED BY "Acme_Rpt_Ok_1" PROFILE acme_rpt_prof;
CREATE USER acme_rpt_stray IDENTIFIED BY "Acme_Rpt_Stray_1";
ALTER USER acme_rpt_stray ACCOUNT LOCK;
```

And a config with three rules, one of them for an account that does not exist:

```yaml
version: 1
targets:
  - name: free-pdb
    type: oracle
    dsn: localhost:1521/FREEPDB1
    admin: { username: system, auth: { method: env } }
reports:
  accounts:
    - accounts: [acme_rpt_user]
      settings: { password_lifetime: unlimited }
    - accounts: [acme_rpt_ok]
      settings: { password_lifetime: 365 }
      oracle: { profile: ACME_RPT_PROF }
    - accounts: [acme_rpt_gone]
      oracle: { profile: ACME_RPT_PROF }
```

```
$ sopuli --config report.yaml report accounts
free-pdb  (23.26.3.0.0, 38 accounts read, 2 with a problem, 5 undeclared)
  ACCOUNT          KIND        PROFILE          STATUS              FAILED LOGINS  STATE            FINDING
  ACME_RPT_USER    technical   ACME_RPT_PROF    OPEN                0              REPORT_PROBLEM   password_lifetime: 180 days, rule says unlimited
  ACME_RPT_GONE    technical   -                -                   -              ACCOUNT_MISSING  present: not on this target
  ACME_APP_USER    undeclared  DEFAULT          OPEN                0              UNDECLARED       not in config
  ACME_BATCH_USER  undeclared  SOPULI_ROLLOVER  OPEN & IN ROLLOVER  0              UNDECLARED       not in config
  ACME_RPT_STRAY   undeclared  DEFAULT          LOCKED              0              UNDECLARED       not in config
  PDBADMIN         undeclared  DEFAULT          OPEN                0              UNDECLARED       not in config
  SOPULI_PROBE     undeclared  DEFAULT          OPEN                0              UNDECLARED       not in config
  1 account OK
```

It exits 3, because a check found a problem. The accounts Oracle maintains,
such as `SYSTEM`, are left out unless a rule names them. An undeclared account
is listed as information and never changes the exit code. `--all` also lists
the accounts that passed, here `ACME_RPT_OK`. The release in the head line is
the full release, `V$INSTANCE.VERSION_FULL`. `doctor --output json` shows it
as `scope.db_release`.

A schema owner that nobody logs in as should be locked, or have no
authentication at all. `login: refused` says so. Make four owners as SYS in
the PDB: one locked, one with no authentication, one open, and one locked by a
failed login:

```sql
CREATE PROFILE acme_owner_prof LIMIT FAILED_LOGIN_ATTEMPTS 1 PASSWORD_LOCK_TIME 1;
CREATE USER acme_owner_locked IDENTIFIED BY "Acme_Own_Lock_1" ACCOUNT LOCK;
CREATE USER acme_owner_schema NO AUTHENTICATION;
CREATE USER acme_owner_open IDENTIFIED BY "Acme_Own_Open_1";
CREATE USER acme_owner_timed IDENTIFIED BY "Acme_Own_Timed_1" PROFILE acme_owner_prof;
GRANT CREATE SESSION TO acme_owner_timed;
```

Log in once as `acme_owner_timed` with a wrong password, then run the report
with this config:

```yaml
version: 1
targets:
  - name: free-pdb
    type: oracle
    dsn: localhost:1521/FREEPDB1
    admin: { username: system, auth: { method: env } }
reports:
  accounts:
    - accounts: ["ACME_OWNER*"]
      login: refused
```

```
$ sopuli --config owners.yaml report accounts --all
free-pdb  (23.26.3.0.0, 40 accounts read, 2 with a problem, 5 undeclared)
  ACCOUNT            KIND        PROFILE          STATUS         FAILED LOGINS  STATE           FINDING
  ACME_OWNER_OPEN    technical   DEFAULT          OPEN           0              REPORT_PROBLEM  lock: can log in: OPEN, rule says login refused
  ACME_OWNER_TIMED   technical   ACME_OWNER_PROF  LOCKED(TIMED)  1              REPORT_PROBLEM  lock: locked by failed logins: LOCKED(TIMED), 1 failed login reached the limit of 1, rule says login refused
  ACME_RPT_OK        undeclared  ACME_RPT_PROF    OPEN           0              UNDECLARED      not in config
  ACME_RPT_STRAY     undeclared  DEFAULT          LOCKED         0              UNDECLARED      not in config
  ACME_RPT_USER      undeclared  ACME_RPT_PROF    OPEN           0              UNDECLARED      not in config
  PDBADMIN           undeclared  DEFAULT          OPEN           0              UNDECLARED      not in config
  SOPULI_PROBE       undeclared  DEFAULT          OPEN           0              UNDECLARED      not in config
  ACME_OWNER_LOCKED  technical   DEFAULT          LOCKED         0              REPORT_OK       -
  ACME_OWNER_SCHEMA  technical   DEFAULT          OPEN           0              REPORT_OK       -
```

It exits 3. The owner somebody locked passes, and so does the one with no
authentication, though it reads `OPEN`: nobody can log in to it with a
password. A lock after
failed logins does not pass: somebody tried, and the lock ends by itself after
the profile's `PASSWORD_LOCK_TIME`.

On PostgreSQL the report reads `pg_roles`, with the tool account from §7's
*A PostgreSQL cluster*. Make six roles as `postgres`:

```sql
CREATE ROLE acme_rpt_app LOGIN;
CREATE ROLE acme_rpt_expired LOGIN VALID UNTIL '2001-01-01 00:00:00+00';
CREATE ROLE acme_rpt_temp LOGIN VALID UNTIL '2099-01-01 00:00:00+00';
CREATE ROLE acme_rpt_readers NOLOGIN;
CREATE ROLE acme_rpt_owner NOLOGIN;
CREATE ROLE acme_rpt_batch NOLOGIN;
```

And a config whose rules say no role may have a `VALID UNTIL` date, the owner
must not log in, and two roles must:

```yaml
version: 1
targets:
  - name: pg-dev
    type: postgresql
    environment: dev
    dsn: "127.0.0.1:5432"
    admin: { username: sopuli_admin, auth: { method: env } }
    postgres: { sslmode: disable }
reports:
  accounts:
    - accounts: ["acme_rpt_*"]
      postgresql: { valid_until: forbidden }
    - accounts: [acme_rpt_owner]
      login: refused
    - accounts: [acme_rpt_app, acme_rpt_batch]
      login: allowed
    - accounts: [acme_rpt_gone]
      login: allowed
```

```
$ sopuli --config pg-report.yaml report accounts --all
pg-dev  (16.15, 22 accounts read, 4 with a problem, 1 undeclared)
  ACCOUNT           KIND        PROFILE  STATUS   FAILED LOGINS  STATE            FINDING
  acme_rpt_expired  technical   -        EXPIRED  unknown        REPORT_PROBLEM   valid_until: password expired: VALID UNTIL 2001-01-01T00:00:00Z, rule says forbidden
  acme_rpt_temp     technical   -        OPEN     unknown        REPORT_PROBLEM   valid_until: VALID UNTIL 2099-01-01T00:00:00Z, rule says forbidden
  acme_rpt_batch    technical   -        NOLOGIN  unknown        REPORT_PROBLEM   lock: cannot log in: NOLOGIN, rule says login allowed
  acme_rpt_gone     technical   -        -        -              ACCOUNT_MISSING  present: not on this target
  sopuli_admin      undeclared  -        OPEN     unknown        UNDECLARED       not in config
  acme_rpt_app      technical   -        OPEN     unknown        REPORT_OK        -
  acme_rpt_owner    technical   -        NOLOGIN  unknown        REPORT_OK        -
  acme_rpt_readers  technical   -        NOLOGIN  unknown        REPORT_OK        -
  failed logins unknown: PostgreSQL keeps no failed-login count
```

It exits 3. `acme_rpt_readers` is `NOLOGIN` and passes, because no rule gives
it a `login:`: `NOLOGIN` is also how a group role is written. A date in the
past is a problem with or without `valid_until:` on a role that can log in,
and not on a `NOLOGIN` role. The roles `initdb` made, such
as `postgres` and the `pg_*` roles, are counted in the head line and left out
unless a rule names them. PostgreSQL has no profile and keeps no failed-login
count, so both read `-` and `unknown`. A rule's `password_lifetime`,
`failed_login_limit` or `oracle.profile` is *not applicable* there. A role an
application logs in as must be able to log in, so `NOLOGIN` on one is a
problem with or without `login:`.

On MySQL, `report accounts` shows one row per `user@host`, and a rule names
each account that way. Use the tool account of §*A MySQL server*, with the
grants of `design/02-mysql-privileges.md` §2.1. As root, make one name at two
hosts, a locked owner, an owner blocked after failed logins, a role, and an
account nothing declares:

```sql
CREATE USER 'acme_app'@'%' IDENTIFIED BY 'Acme-App-Rpt-1' PASSWORD EXPIRE INTERVAL 90 DAY;
CREATE USER 'acme_app'@'192.0.2.%' IDENTIFIED BY 'Acme-App-Rpt-2' PASSWORD EXPIRE NEVER;
CREATE USER 'acme_owner'@'%' IDENTIFIED BY 'Acme-Own-Rpt-1' ACCOUNT LOCK;
CREATE USER 'acme_timed'@'%' IDENTIFIED BY 'Acme-Tim-Rpt-1' FAILED_LOGIN_ATTEMPTS 2 PASSWORD_LOCK_TIME 1;
CREATE USER 'acme_stray'@'%' IDENTIFIED BY 'Acme-Str-Rpt-1';
CREATE ROLE 'acme_read';
GRANT 'acme_read' TO 'acme_app'@'%';
```

Log in twice as `acme_timed` with a wrong password, so that the server blocks
it, `3955`. Then run the report with this config:

```yaml
version: 1
targets:
  - name: mysql-dev
    type: mysql
    environment: dev
    dsn: "127.0.0.1:3306"
    admin: { username: sopuli_admin, auth: { method: env } }
    mysql: { ssl_mode: REQUIRED }
reports:
  accounts:
    - accounts: ["acme_app@%", "acme_gone@%"]
      settings: { password_lifetime: 60 }
    - accounts: ["acme_owner@%", "acme_timed@%"]
      login: refused
```

```
$ sopuli --config mysql-report.yaml report accounts
mysql-dev  (8.4.13, 11 accounts read, 3 with a problem, 5 undeclared)
  ACCOUNT             KIND        PROFILE  STATUS  FAILED LOGINS  STATE            FINDING
  acme_app@%          technical   -        OPEN    unknown        REPORT_PROBLEM   password_lifetime: 90 days, rule says at most 60 days
  acme_timed@%        technical   -        OPEN    unknown        REPORT_PROBLEM   lock: can log in: OPEN, rule says login refused
  acme_gone@%         technical   -        -       -              ACCOUNT_MISSING  present: not on this target
  acme_app@192.0.2.%  undeclared  -        OPEN    unknown        UNDECLARED       not in config
  acme_stray@%        undeclared  -        OPEN    unknown        UNDECLARED       not in config
  root@%              undeclared  -        OPEN    unknown        UNDECLARED       not in config
  root@localhost      undeclared  -        OPEN    unknown        UNDECLARED       not in config
  sopuli_admin@%      undeclared  -        OPEN    unknown        UNDECLARED       not in config
  1 account OK
  failed logins unknown: the tool account has no SELECT on performance_schema.temporary_account_locks, or the server has no such table, as 8.0 and 8.4 have not
```

It exits 3. `acme_app@192.0.2.%` is another account than `acme_app@%`, so the
rule for one does not reach the other. The role and MySQL's own accounts,
such as `mysql.sys@localhost`, are left out. `acme_timed@%` reads `OPEN`: on
8.4 a block after failed logins is in no table the tool account can read. On
MySQL 9.7.4, with the optional `SELECT` on
`performance_schema.temporary_account_locks` of
`design/02-mysql-privileges.md` §2.1, the same account reads
`LOCKED(TIMED)` with its count, and the lock is still a problem, because
somebody tried to log in.

On MariaDB, with the grants of `design/02-mariadb-privileges.md` §2.1,
`report accounts` reads only each account's
expiry: the lock and the lifetime are kept beside the stored value, which the
tool account does not read. The optional view below reads them. Use the target and tool account of §*A MariaDB server*. As root, make
one name at two hosts, a locked owner, an expired account, a role, and an
account nothing declares. No account here needs a password for the report:

```sql
CREATE USER 'acme_app'@'%' PASSWORD EXPIRE INTERVAL 90 DAY;
CREATE USER 'acme_app'@'192.0.2.%' PASSWORD EXPIRE NEVER;
CREATE USER 'acme_owner'@'%' ACCOUNT LOCK;
CREATE USER 'acme_old'@'%' PASSWORD EXPIRE;
CREATE USER 'acme_stray'@'%';
CREATE ROLE 'acme_read';
GRANT 'acme_read' TO 'acme_app'@'%';
```

Run the report with this config:

```yaml
version: 1
targets:
  - name: mariadb-dev
    type: mariadb
    environment: dev
    dsn: "127.0.0.1:3307"
    admin: { username: sopuli_admin, auth: { method: env } }
    mariadb: { ssl_mode: REQUIRED }
reports:
  accounts:
    - accounts: ["acme_app@%", "acme_old@%", "acme_gone@%"]
      settings: { password_lifetime: 60, failed_login_limit: 5 }
    - accounts: ["acme_owner@%"]
      login: refused
```

```
$ sopuli --config mariadb-report.yaml report accounts
mariadb-dev  (11.8.9, 12 accounts read, 1 with a problem, 3 not checked, 8 undeclared, 2 with a check not applicable)
  ACCOUNT                KIND        PROFILE  STATUS   FAILED LOGINS  STATE            FINDING
  acme_gone@%            technical   -        -        -              ACCOUNT_MISSING  present: not on this target
  acme_app@%             technical   -        OPEN     unknown        NOT_CHECKED      lock: MariaDB keeps it in mysql.global_priv, beside the stored value, and the optional view sopuli.account_state that reads it without the value is absent or not granted to the tool account: run sql/mariadb/account_state_view.sql as an administrator; password_lifetime: MariaDB keeps it in mysql.global_priv, beside the stored value, and the optional view sopuli.account_state that reads it without the value is absent or not granted to the tool account: run sql/mariadb/account_state_view.sql as an administrator
  acme_old@%             technical   -        EXPIRED  unknown        NOT_CHECKED      lock: MariaDB keeps it in mysql.global_priv, beside the stored value, and the optional view sopuli.account_state that reads it without the value is absent or not granted to the tool account: run sql/mariadb/account_state_view.sql as an administrator; password_lifetime: MariaDB keeps it in mysql.global_priv, beside the stored value, and the optional view sopuli.account_state that reads it without the value is absent or not granted to the tool account: run sql/mariadb/account_state_view.sql as an administrator
  acme_owner@%           technical   -        OPEN     unknown        NOT_CHECKED      lock: MariaDB keeps it in mysql.global_priv, beside the stored value, and the optional view sopuli.account_state that reads it without the value is absent or not granted to the tool account: run sql/mariadb/account_state_view.sql as an administrator
  acme_app@192.0.2.%     undeclared  -        OPEN     unknown        UNDECLARED       not in config
  acme_stray@%           undeclared  -        OPEN     unknown        UNDECLARED       not in config
  healthcheck@127.0.0.1  undeclared  -        OPEN     unknown        UNDECLARED       not in config
  healthcheck@::1        undeclared  -        OPEN     unknown        UNDECLARED       not in config
  healthcheck@localhost  undeclared  -        OPEN     unknown        UNDECLARED       not in config
  root@%                 undeclared  -        OPEN     unknown        UNDECLARED       not in config
  root@localhost         undeclared  -        OPEN     unknown        UNDECLARED       not in config
  sopuli_admin@%         undeclared  -        OPEN     unknown        UNDECLARED       not in config
  0 accounts OK
  failed logins unknown: MariaDB shows an account's failed logins, PASSWORD_ERRORS in information_schema.USERS, only to the account itself
```

It exits 3, for `acme_gone@%`; without it, the run exits 4. Every account a
rule names is *not checked*, because the lock is compared even without
`login:`. `acme_owner@%` is locked and reads `OPEN`: the status is the
expiry alone, as `account list` shows it. A rule's `failed_login_limit` is
*not applicable*: MariaDB has no limit per account, only the server's
`max_password_errors`. The role and `mariadb.sys@localhost` are left out.
The `healthcheck` accounts are the image's own.

The optional view `sopuli.account_state` reads the lock, the lifetime and the
time of the last change without the stored value
(`design/02-mariadb-privileges.md` §2.1). Edit the two `SET` lines at the top
of `sql/mariadb/account_state_view.sql` to name the tool account, here
`sopuli_admin` at `%`, and run it as root:

```
$ docker exec -i sopuli-test-mariadb-1 mariadb -uroot -psopuli-test < account_state_view.sql
```

The same report then checks the lock and the lifetimes:

```
$ sopuli --config mariadb-report.yaml report accounts
mariadb-dev  (11.8.9, 13 accounts read, 3 with a problem, 9 undeclared, 2 with a check not applicable)
  ACCOUNT                        KIND        PROFILE  STATUS   FAILED LOGINS  STATE            FINDING
  acme_app@%                     technical   -        OPEN     unknown        REPORT_PROBLEM   password_lifetime: 90 days, rule says at most 60 days
  acme_old@%                     technical   -        EXPIRED  unknown        REPORT_PROBLEM   password_lifetime: unlimited, rule says at most 60 days
  acme_gone@%                    technical   -        -        -              ACCOUNT_MISSING  present: not on this target
  acme_app@192.0.2.%             undeclared  -        OPEN     unknown        UNDECLARED       not in config
  acme_stray@%                   undeclared  -        OPEN     unknown        UNDECLARED       not in config
  healthcheck@127.0.0.1          undeclared  -        OPEN     unknown        UNDECLARED       not in config
  healthcheck@::1                undeclared  -        OPEN     unknown        UNDECLARED       not in config
  healthcheck@localhost          undeclared  -        OPEN     unknown        UNDECLARED       not in config
  root@%                         undeclared  -        OPEN     unknown        UNDECLARED       not in config
  root@localhost                 undeclared  -        OPEN     unknown        UNDECLARED       not in config
  sopuli_admin@%                 undeclared  -        OPEN     unknown        UNDECLARED       not in config
  sopuli_view_definer@localhost  undeclared  -        LOCKED   unknown        UNDECLARED       not in config
  1 account OK
  failed logins unknown: MariaDB shows an account's failed logins, PASSWORD_ERRORS in information_schema.USERS, only to the account itself
```

`acme_owner@%` now reads `LOCKED`, and its `login: refused` rule passes: it
is the one account OK. `acme_old@%` was made with `PASSWORD EXPIRE`, which
leaves the server's default lifetime, here none. `sopuli_view_definer` is the
view's definer, locked by the script. A view that exists and cannot be used,
such as one with another column, is not read, and `SOPULI-W073` says why.

`report privileges` shows each account's effective privileges, through every
role, for the Oracle accounts above. The service account needs `SELECT` on `DBA_SYS_PRIVS`, `DBA_TAB_PRIVS`, `DBA_COL_PRIVS` and, on 23ai,
`DBA_SCHEMA_PRIVS`: run `sql/oracle/00_install.sql` with
`grant_report_reads=Y`. Without them, those parts say `not checked` and the run
exits 4. Make an account with a direct grant, a column grant, a default role
holding a nested role, a role that is not a default role, and a schema
privilege. As SYS in the PDB:

```sql
CREATE USER acme_rp_owner IDENTIFIED BY "Acme_Rp_Own_1" QUOTA 10M ON users;
CREATE TABLE acme_rp_owner.orders (n NUMBER);
CREATE TABLE acme_rp_owner.items (n NUMBER);
CREATE PROCEDURE acme_rp_owner.post_order AS BEGIN NULL; END;
/
CREATE ROLE acme_rp_read;
CREATE ROLE acme_rp_app;
CREATE ROLE acme_rp_batch;
GRANT SELECT ON acme_rp_owner.orders TO acme_rp_read;
GRANT SELECT ON acme_rp_owner.items TO acme_rp_read;
GRANT EXECUTE ON acme_rp_owner.post_order TO acme_rp_app;
GRANT acme_rp_read TO acme_rp_app;
GRANT INSERT ON acme_rp_owner.orders TO acme_rp_batch;
CREATE USER acme_rp_user IDENTIFIED BY "Acme_Rp_User_1";
GRANT CREATE SESSION TO acme_rp_user;
GRANT SELECT ON acme_rp_owner.orders TO acme_rp_user;
GRANT UPDATE (n) ON acme_rp_owner.items TO acme_rp_user;
GRANT acme_rp_app, acme_rp_batch TO acme_rp_user;
ALTER USER acme_rp_user DEFAULT ROLE acme_rp_app;
GRANT SELECT ANY TABLE ON SCHEMA acme_rp_owner TO acme_rp_user;
```

With a rule naming `acme_rp_user` in the config:

```
$ sopuli --config priv.yaml report privileges --account acme_rp_user --detail
free-pdb  (23.26.3.0.0, 1 account)
  ACME_RP_USER  (technical)
    roles: ACME_RP_APP (default), ACME_RP_BATCH (not default)
    KIND    PRIVILEGE         OBJECT                    TYPE       FROM                                    GRANTABLE
    system  CREATE SESSION    -                         -          direct                                  no
    object  EXECUTE           ACME_RP_OWNER.POST_ORDER  PROCEDURE  via ACME_RP_APP                         no
    object  INSERT            ACME_RP_OWNER.ORDERS      TABLE      via ACME_RP_BATCH, not a default role   no
    object  SELECT            ACME_RP_OWNER.ITEMS       TABLE      via ACME_RP_APP > ACME_RP_READ          no
    object  SELECT            ACME_RP_OWNER.ORDERS      TABLE      direct, via ACME_RP_APP > ACME_RP_READ  no
    column  UPDATE            ACME_RP_OWNER.ITEMS.N     -          direct                                  no
    schema  SELECT ANY TABLE  ACME_RP_OWNER             SCHEMA     direct                                  no
```

Without `--detail` the same account reads as a summary:

```
  ACME_RP_USER  (technical)
    roles: ACME_RP_APP (default), ACME_RP_BATCH (not default)
    system: CREATE SESSION (direct)
    objects: EXECUTE on 1 procedure (0 direct, 1 via roles); INSERT on 1 table (0 direct, 1 via roles, 1 through a role that is not a default role); SELECT on 2 tables (1 direct, 1 via roles)
    columns: UPDATE on 1 column (1 direct, 0 via roles)
    schemas: SELECT ANY TABLE on ACME_RP_OWNER (direct)
```

`SELECT` on `ORDERS` is granted directly and through a role, and is counted
once, as direct. `--public` adds the grants to `PUBLIC`, once per target.

On MySQL, `report privileges` names each privilege's level and reads it with
the grants of `design/02-mysql-privileges.md` §2.1. The optional `SELECT` on
`mysql.default_roles` there says which roles are active at login. Use the
tool account of §*A MySQL server*. As root, make an account with a direct
table, column and routine grant, a default role holding a nested role, and a
role that is not a default role. Then make an account with global privileges
and a proxy:

```sql
CREATE DATABASE acme;
CREATE TABLE acme.orders (n int, total int);
CREATE TABLE acme.items (n int);
CREATE PROCEDURE acme.close_day() SELECT 1;
CREATE ROLE 'acme_read', 'acme_nested', 'acme_batch';
GRANT SELECT ON acme.* TO 'acme_read';
GRANT SELECT ON acme.items TO 'acme_nested';
GRANT 'acme_nested' TO 'acme_read';
GRANT INSERT ON acme.items TO 'acme_batch';
CREATE USER 'acme_app'@'%' IDENTIFIED BY 'Acme-App-Rpt-1';
GRANT INSERT ON acme.orders TO 'acme_app'@'%';
GRANT UPDATE (total) ON acme.orders TO 'acme_app'@'%';
GRANT EXECUTE ON PROCEDURE acme.close_day TO 'acme_app'@'%';
GRANT 'acme_read', 'acme_batch' TO 'acme_app'@'%';
SET DEFAULT ROLE 'acme_read' TO 'acme_app'@'%';
CREATE USER 'acme_ops'@'localhost' IDENTIFIED BY 'Acme-Ops-Rpt-1';
GRANT PROCESS ON *.* TO 'acme_ops'@'localhost' WITH GRANT OPTION;
GRANT CONNECTION_ADMIN ON *.* TO 'acme_ops'@'localhost';
GRANT PROXY ON 'acme_app'@'%' TO 'acme_ops'@'localhost';
```

`GRANT PROXY` goes over the socket: in the image only `root@localhost` holds
`PROXY WITH GRANT OPTION`. With a rule naming `acme_app@%` and
`acme_ops@localhost` in the config:

```
$ sopuli --config mysql-priv.yaml report privileges --target mysql-84 --account acme_app@% --detail
mysql-84  (8.4.13, 1 account)
  acme_app@%  (technical)
    roles: acme_batch@% (not default), acme_read@% (default)
    KIND               PRIVILEGE  OBJECT             TYPE       FROM                                  GRANTABLE
    object (routine)   EXECUTE    acme.close_day     PROCEDURE  direct                                no
    object (table)     INSERT     acme.items         TABLE      via acme_batch@%, not a default role  no
    object (table)     INSERT     acme.orders        TABLE      direct                                no
    object (table)     SELECT     acme.items         TABLE      via acme_read@% > acme_nested@%       no
    column (column)    UPDATE     acme.orders.total  -          direct                                no
    schema (database)  SELECT     acme               SCHEMA     via acme_read@%                       no
```

```
$ sopuli --config mysql-priv.yaml report privileges --target mysql-84 --account acme_ops@localhost --detail
mysql-84  (8.4.13, 1 account)
  acme_ops@localhost  (technical)
    KIND                     PRIVILEGE         OBJECT      TYPE     FROM    GRANTABLE
    system (global dynamic)  CONNECTION_ADMIN  -           -        direct  no
    system (global static)   GRANT OPTION      -           -        direct  yes
    system (global static)   PROCESS           -           -        direct  yes
    object (proxy)           PROXY             acme_app@%  ACCOUNT  direct  no
```

Both exit 0. The same accounts read the same on 8.0.46 and 9.7.4. `SELECT`
on `acme.*` is a database grant, under *schemas*; the one on `acme.items` is
reached through the nested role. `GRANT OPTION` is listed with its level and
makes `PROCESS` grantable. Without the optional `SELECT` on
`mysql.default_roles`, whether each role is a default is *not checked*, each
privilege reached through a role is *not checked whether active at login*,
the summary counts it apart, and the run exits 4:

```
$ sopuli --config mysql-priv.yaml report privileges --target mysql-84 --account acme_app@%
mysql-84  (8.4.13, 1 account)
  acme_app@%  (technical)
    roles: acme_batch@% (default not checked), acme_read@% (default not checked)
    system: none
    objects: routine: EXECUTE on 1 procedure (1 direct, 0 via roles); table: INSERT on 2 tables (1 direct, 1 via roles, 1 through a role not checked for being active at login); table: SELECT on 1 table (0 direct, 1 via roles, 1 through a role not checked for being active at login)
    columns: column: UPDATE on 1 column (1 direct, 0 via roles)
    schemas: SELECT on acme (database, via acme_read@%, not checked whether active at login)
  not checked: whether a role is a default role, and so active without SET ROLE: the tool account has no SELECT on mysql.default_roles, the optional grant of 02-mysql-privileges.md §2.1
```

On *A PostgreSQL cluster*, the report needs no grant beyond `CREATEROLE`. Make
the same shape as `postgres`, with one grant `WITH INHERIT FALSE` and one
built-in role:

```sql
CREATE ROLE acme_rp_owner;
CREATE ROLE acme_rp_read;
CREATE ROLE acme_rp_app;
CREATE ROLE acme_rp_batch;
CREATE ROLE acme_rp_user LOGIN;
CREATE SCHEMA acme_rp AUTHORIZATION acme_rp_owner;
SET ROLE acme_rp_owner;
CREATE TABLE acme_rp.orders (n int);
CREATE TABLE acme_rp.items (n int);
CREATE FUNCTION acme_rp.post_order() RETURNS void LANGUAGE sql AS 'SELECT';
REVOKE EXECUTE ON FUNCTION acme_rp.post_order() FROM PUBLIC;
GRANT USAGE ON SCHEMA acme_rp TO acme_rp_read, acme_rp_batch, acme_rp_user;
GRANT SELECT ON acme_rp.orders, acme_rp.items TO acme_rp_read;
GRANT EXECUTE ON FUNCTION acme_rp.post_order() TO acme_rp_app;
GRANT INSERT ON acme_rp.orders TO acme_rp_batch;
GRANT SELECT ON acme_rp.orders TO acme_rp_user;
GRANT UPDATE (n) ON acme_rp.items TO acme_rp_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA acme_rp GRANT SELECT ON TABLES TO acme_rp_read;
RESET ROLE;
GRANT acme_rp_read TO acme_rp_app;
GRANT acme_rp_app TO acme_rp_user;
GRANT acme_rp_batch TO acme_rp_user WITH INHERIT FALSE;
GRANT pg_read_all_stats TO acme_rp_user;
```

With `postgres.yaml`'s target and a rule naming `acme_rp_user`:

```
$ sopuli --config postgres.yaml report privileges --account acme_rp_user
pg-dev  (16.15, 1 account)
  acme_rp_user  (technical)
    roles: acme_rp_app (inherit, set), acme_rp_batch (no inherit, set), pg_read_all_stats (inherit, set)
    system: pg_read_all_stats (predefined role, via pg_read_all_stats)
    objects: EXECUTE on 3 functions (0 direct, 3 via roles); INSERT on 1 table (0 direct, 1 via roles, 1 only after SET ROLE); SELECT on 2 tables (1 direct, 1 via roles); SELECT on 2 views (0 direct, 2 via roles); default for acme_rp_owner: SELECT on 1 table (0 direct, 1 via roles)
    columns: UPDATE on 1 column (1 direct, 0 via roles)
    schemas: USAGE on acme_rp (schema, direct, via acme_rp_app > acme_rp_read, via acme_rp_batch)
  not checked: the schemas and objects of the cluster's other databases were not read (sopuli): a target reads only the database it connects to; declare a target for each at the same host and port in its dsn: to report on it
```

It exits 4: the stack's cluster has a second database, `sopuli`, which a
target on `postgres` cannot see into. `INSERT` comes through the grant
`WITH INHERIT FALSE`, so the account has it only after `SET ROLE
acme_rp_batch`. `pg_read_all_stats` gives privileges no ACL shows, so it is
listed under its own name, and the functions and views it is granted on are
counted too. The default privilege is what `acme_rp_owner`'s future tables
will grant. `--detail` lists each one, with `KIND` naming the level, such as
`object (default for acme_rp_owner)`.

To cover `sopuli`, copy `postgres.yaml` to `pg-report.yaml` and add a second
target at the same `dsn:`. Keep it out of `postgres.yaml`: the other commands
in this guide run without `--target`, and a run that reaches both targets
refuses the second (`SOPULI-20008`).

```yaml
  - name: pg-dev-sopuli
    type: postgresql
    environment: dev
    dsn: "127.0.0.1:5432"
    admin: { username: sopuli_admin, auth: { method: env } }
    postgres: { database: sopuli, sslmode: disable }
```

The two targets are one cluster, so run one per run with `--target`. Each
run exits 0: `pg-dev` no longer names `sopuli`, and `pg-dev-sopuli` reads
it:

```
$ sopuli --config pg-report.yaml report privileges --target pg-dev --account acme_rp_user
pg-dev  (16.15, 1 account)
  acme_rp_user  (technical)
    roles: acme_rp_app (inherit, set), acme_rp_batch (no inherit, set), pg_read_all_stats (inherit, set)
    system: pg_read_all_stats (predefined role, via pg_read_all_stats)
    objects: EXECUTE on 3 functions (0 direct, 3 via roles); INSERT on 1 table (0 direct, 1 via roles, 1 only after SET ROLE); SELECT on 2 tables (1 direct, 1 via roles); SELECT on 2 views (0 direct, 2 via roles); default for acme_rp_owner: SELECT on 1 table (0 direct, 1 via roles)
    columns: UPDATE on 1 column (1 direct, 0 via roles)
    schemas: USAGE on acme_rp (schema, direct, via acme_rp_app > acme_rp_read, via acme_rp_batch)
$ sopuli --config pg-report.yaml report privileges --target pg-dev-sopuli --account acme_rp_user
pg-dev-sopuli  (16.15, 1 account)
  acme_rp_user  (technical)
    roles: acme_rp_app (inherit, set), acme_rp_batch (no inherit, set), pg_read_all_stats (inherit, set)
    system: pg_read_all_stats (predefined role, via pg_read_all_stats)
    objects: EXECUTE on 2 functions (0 direct, 2 via roles); SELECT on 2 views (0 direct, 2 via roles)
    columns: none
    schemas: none
```

On *A MariaDB server*, as root, make the same shape. A role has no host, and
`PUBLIC` is a role every account holds:

```sql
CREATE DATABASE acme;
CREATE TABLE acme.orders (n int, total int);
CREATE TABLE acme.notices (n int);
CREATE PROCEDURE acme.close_day() SELECT 1;
CREATE ROLE acme_top;
CREATE ROLE acme_mid;
GRANT SELECT ON acme.orders TO acme_top;
GRANT acme_top TO acme_mid;
CREATE USER 'acme_rp'@'%' IDENTIFIED BY '…';
CREATE USER 'acme_rp_ops'@'localhost' IDENTIFIED BY '…';
GRANT acme_mid TO 'acme_rp'@'%';
SET DEFAULT ROLE acme_mid FOR 'acme_rp'@'%';
GRANT acme_top TO 'acme_rp_ops'@'localhost' WITH ADMIN OPTION;
GRANT SELECT ON `acme%`.* TO 'acme_rp'@'%';
GRANT INSERT ON acme.orders TO 'acme_rp'@'%' WITH GRANT OPTION;
GRANT UPDATE (total) ON acme.orders TO 'acme_rp'@'%';
GRANT EXECUTE ON PROCEDURE acme.close_day TO 'acme_rp'@'%';
GRANT CONNECTION ADMIN ON *.* TO 'acme_rp_ops'@'localhost';
GRANT SELECT ON acme.notices TO PUBLIC;
GRANT SELECT (default_role) ON mysql.user TO 'sopuli_admin'@'%';
```

The last line is the optional column grant of
`design/02-mariadb-privileges.md` §2.1, which reads the default role.

With a rule in `mariadb.yaml` naming `acme_rp@%` and `acme_rp_ops@localhost`:

```
$ sopuli --config mariadb.yaml report privileges --account 'acme_rp@%' --detail
mariadb-dev  (11.8.9, 1 account)
  acme_rp@%  (technical)
    roles: acme_mid (default)
    KIND               PRIVILEGE     OBJECT             TYPE       FROM                     GRANTABLE
    system             not checked
    object (routine)   EXECUTE       acme.close_day     PROCEDURE  direct                   no
    object (table)     GRANT OPTION  acme.orders        TABLE      direct                   yes
    object (table)     INSERT        acme.orders        TABLE      direct                   yes
    object (table)     SELECT        acme.orders        TABLE      via acme_mid > acme_top  no
    column             UPDATE        acme.orders.total  -          direct                   yes
    schema (database)  SELECT        acme%              SCHEMA     direct                   no
  not checked: global privileges: MariaDB keeps the privileges split from SUPER, such as CONNECTION ADMIN, only in mysql.global_priv, beside the stored value, and they set no column of the mysql.user view, so the global level as the tool account reads it would be incomplete; the optional view sopuli.global_privileges that reads them is absent or not granted to the tool account: run sql/mariadb/global_privileges_view.sql as an administrator
```

It exits 4: without the optional view the global level is not checked on
MariaDB. Edit the two `SET` lines at the top of
`sql/mariadb/global_privileges_view.sql` to name the tool account, here
`sopuli_admin` at `%`, and run it as root, as for `account_state_view.sql`
above. The global level then reads:

```
$ sopuli --config mariadb.yaml report privileges --account 'acme_rp_ops@localhost'
mariadb-dev  (11.8.9, 1 account)
  acme_rp_ops@localhost  (technical)
    roles: acme_top (not default, admin option)
    system: CONNECTION ADMIN (global, direct)
    objects: table: SELECT on 1 table (0 direct, 1 via roles, 1 through a role that is not a default role)
    columns: none
    schemas: none
  not checked: the global privileges of a role and of PUBLIC: information_schema.USER_PRIVILEGES, which the optional view sopuli.global_privileges reads, has no row for either
```

`CONNECTION ADMIN` is one of the privileges split from `SUPER`, which only the
view shows. It still exits 4: the account holds a role, and the server's list
of global privileges has no row for a role. `acme_rp_ops` reaches `SELECT`
through `acme_top`, which is not its default role, so the count says so.
`--public` adds `PUBLIC` once, with its `SELECT` on `acme.notices`.

`report history` shows when each password the tool manages was rotated or
reset, from the store's versions, with the database's own date of the last
change beside it. It reads no password. This run used §5's config with fresh
accounts: `acme_rh_app` and `acme_rh_batch` in `acme`, and `acme_rh_alice` and
`acme_rh_bob` in `personal_accounts:`. Then `creds generate`, `creds apply`,
two `creds rotate --account acme_rh_app --confirm` runs, and two
`account reset-password` runs for `acme_rh_alice`:

```
$ sopuli --config history.yaml report history
free-pdb  (23.0.0.0.0, 4 accounts)
  acme_rh_app  (application)
    database changed: 2026-11-08T10:57:18Z
    WHEN                  CHANGE    VERSION  BY
    2026-11-08T10:57:18Z  rotation  v6       jdba@admin-ws
    2026-11-08T10:57:13Z  rotation  v4       jdba@admin-ws
    2026-11-08T10:57:08Z  rotation  v2       jdba@admin-ws
    history from v1 (2026-11-08T10:57:04Z); 0 earlier versions gone
  acme_rh_batch  (application)
    database changed: 2026-11-08T10:57:08Z
    WHEN                  CHANGE    VERSION  BY
    2026-11-08T10:57:08Z  rotation  v2       jdba@admin-ws
    history from v1 (2026-11-08T10:57:04Z); 0 earlier versions gone
  acme_rh_alice  (personal)
    database changed: 2026-11-08T10:57:36Z
    WHEN                  CHANGE            VERSION  BY
    2026-11-08T10:57:36Z  reset (not seen)  v2       jdba@admin-ws
    2026-11-08T10:57:32Z  reset (not seen)  v1       jdba@admin-ws
    history from v1 (2026-11-08T10:57:32Z); 0 earlier versions gone
  acme_rh_bob  (personal)
    database changed: 2026-11-08T10:56:42Z
    nothing recorded
    note: no reset record
```

A rotation writes two versions: `creds generate` stages `pending`, and the
promotion writes the next one. Only the promotion moves the account's own
`rotated_at`, so each rotation is listed once. When the store prunes old
versions, the history says where it starts. With `max_versions` 3 on the
secret and one more rotation:

```
$ sopuli --config history.yaml report history --account acme_rh_app
free-pdb  (23.0.0.0.0, 1 account)
  acme_rh_app  (application)
    database changed: 2026-11-08T10:58:56Z
    WHEN                  CHANGE    VERSION        BY
    2026-11-08T10:58:56Z  rotation  v8             jdba@admin-ws
    2026-11-08T10:57:18Z  rotation  v6 or earlier  jdba@admin-ws
    history from v6 (2026-11-08T10:57:18Z); 5 earlier versions gone
```

`v6 or earlier`: version 5 is gone, so it may be the one that wrote that
stamp. A version that is listed and cannot be read, a gap in the numbers, or a
store that keeps no versions makes the history *not checked*, and the run exits
4.

The history comes from the store on every product. This run used the tool
accounts from §7's PostgreSQL, MySQL and MariaDB sections, one application
account on each (`acme_rh_pg`, `acme_rh_my@%`, `acme_rh_maria@%`), then `creds
generate`, `creds apply` and one `creds rotate --confirm`:

```
$ sopuli --config history.yaml report history
pg-dev  (16.15, 1 account)
  acme_rh_pg  (application)
    database changed: unknown, PostgreSQL does not record when a role's password was changed
    WHEN                  CHANGE    VERSION  BY
    2026-11-11T20:55:50Z  rotation  v4       jdba@admin-ws
    2026-11-11T20:55:39Z  rotation  v2       jdba@admin-ws
    history from v1 (2026-11-11T20:55:36Z); 0 earlier versions gone

mysql-dev  (8.4.13, 1 account)
  acme_rh_my@%  (application)
    database changed: 2026-11-11T20:55:50Z
    WHEN                  CHANGE    VERSION  BY
    2026-11-11T20:55:50Z  rotation  v4       jdba@admin-ws
    2026-11-11T20:55:39Z  rotation  v2       jdba@admin-ws
    history from v1 (2026-11-11T20:55:37Z); 0 earlier versions gone

mariadb-dev  (11.8.9, 1 account)
  acme_rh_maria@%  (application)
    database changed: unknown, MariaDB keeps the time of a password change beside the stored value, which the tool does not read
    WHEN                  CHANGE    VERSION  BY
    2026-11-11T20:55:50Z  rotation  v4       jdba@admin-ws
    2026-11-11T20:55:39Z  rotation  v2       jdba@admin-ws
    history from v1 (2026-11-11T20:55:37Z); 0 earlier versions gone
```

It exits 0. MySQL's date is `mysql.user.password_last_changed`. PostgreSQL
keeps no such date, and MariaDB keeps it where the tool does not read it, so
there the date is `unknown`, with the reason; the history is still complete.

---

## 10. Refusals worth seeing once

### An account with too much privilege

The tool refuses to change an account that holds `DBA` or a similar privilege.
Copy `sopuli.yaml` to `priv.yaml`, add `acme_priv_user` to the `acme`
application, and run `creds generate` and then `creds apply`:

```
$ sopuli --config priv.yaml creds apply
...
ACCOUNT          TARGET    STATE            DETAIL
acme_app_user    free-pdb  IN_SYNC          changed and verified by login
acme_batch_user  free-pdb  ROLLOVER_ACTIVE  changed and verified; a rollover window is open, so the previous password authenticates until it closes
acme_priv_user   free-pdb  SKIPPED          the account holds DBA

2 changed, 1 promoted to `current`, 1 skipped

1 note:
  free-pdb: a password was sent over a connection that is not encrypted: require NNE or TLS on the server (SQLNET.ENCRYPTION_SERVER = REQUIRED in its sqlnet.ora, or a TCPS listener endpoint)
```

Exit 0. The tool skips the account and does the rest of the job. Its staged
password stays in `pending`. `creds rotate` skips it too, stages nothing for it,
and rotates the others:

```
$ sopuli --config priv.yaml creds rotate --confirm
...
ACCOUNT          TARGET    STATE            DETAIL
acme_app_user    free-pdb  IN_SYNC          changed and verified by login
acme_batch_user  free-pdb  ROLLOVER_ACTIVE  changed and verified; a rollover window is open, so the previous password authenticates until it closes
acme_priv_user   free-pdb  SKIPPED          the account holds DBA

2 changed, 1 promoted to `current`, 1 skipped

rotation: staged 1 document, promoted 1 document

1 note:
  free-pdb: a password was sent over a connection that is not encrypted: require NNE or TLS on the server (SQLNET.ENCRYPTION_SERVER = REQUIRED in its sqlnet.ora, or a TCPS listener endpoint)
```

Name the account on the command line, and the same refusal fails the run,
because you asked for exactly that account:

```
$ sopuli --config priv.yaml creds apply --account acme_priv_user
...
ACCOUNT         TARGET    STATE  DETAIL
acme_priv_user  free-pdb  ERROR  the account holds DBA -- you named this account, so the run stopped short: pass --force to override, which is recorded

nothing changed, 1 not confirmed
```

Exit 1. [`design/02-oracle-privileges.md`](design/02-oracle-privileges.md) §4
lists the guardrails.

### An account the config does not declare

A selector narrows the declared accounts. It cannot add one:

```
$ sopuli --config sopuli.yaml creds status --account nosuch
sopuli: --account: name not declared in the configuration: `nosuch`
  hint: the configuration declares acme_app_user, acme_batch_user -- a selector filters the declared set and cannot extend it (invariant 5)
```

Exit 2.

### A lock somebody else holds

`creds generate`, `apply` and `rotate` first take a lock in the vault, and so
does `account reset-password` where `reset_records:` is declared. To see a
held lock, write one by hand. Save this as `held.json`, with an `expires_at` in
the future:

```json
{"state":"held","command":"creds rotate","correlation_id":"11111111-2222-3333-4444-555555555555","acquired_at":"2026-10-23T12:00:00.000000Z","expires_at":"2026-10-24T23:59:00.000000Z","holder":{"host":"beta.example.com","os_user":"someone-else","pid":1234}}
```

The write must name the lock path's current version. Read it, then write:

```bash
ver=$(vault kv metadata get -mount=kv locks/acme/dev/acme | awk '/^current_version/ {print $2}')
vault kv put -mount=kv -cas="$ver" locks/acme/dev/acme - < held.json
```

`lock status` now shows the lock as held:

```
$ sopuli --config sopuli.yaml lock status
config: sopuli.yaml
mode:   cas

LOCK                     STATE  HOLDER                        COMMAND       SINCE                 EXPIRES
vault-dev:acme/dev/acme  held   someone-else@beta.example...  creds rotate  2026-10-23T12:00:00Z  2026-10-24T23:59:00Z

personal-account resets, under the prefix this config declares:
LOCK                                                      STATE     HOLDER              COMMAND           SINCE                        EXPIRES
vault-dev:sopuli/personal-resets/free-pdb/acme_dev_alice  released  op@ws1.example.com  account reset...  2026-10-23T08:14:54.002965Z  2026-10-23T08:29:54.002965Z

1 of 1 declared lock paths held; 1 reset lock under the declared prefix (0 held)
```

`check` changes nothing and takes no lock, so it still runs. `apply` stops:

```
$ sopuli --config sopuli.yaml creds apply
sopuli: vault-dev:acme/dev/acme is locked by someone-else@beta.example.com pid 1234 running creds rotate
  hint: wait for it to finish, or coordinate with whoever is running it
```

Exit 7. `lock break` refuses too, because the lock has not expired:

```
$ sopuli --config sopuli.yaml lock break vault-dev:acme/dev/acme --confirm
sopuli: vault-dev:acme/dev/acme is held by someone-else@beta.example.com pid 1234 running creds rotate and has not expired
  hint: wait for it to finish, or coordinate with whoever is running it. `--force` breaks a lock that is still live -- the holder is fenced and stops at its next check, having applied whatever it applied
```

Exit 7. `--force` breaks it:

```
$ sopuli --config sopuli.yaml lock break vault-dev:acme/dev/acme --force --confirm
...
broke this lock at version 19; someone-else@beta.example.com pid 1234 running creds rotate is fenced at version 20 and stops at its next check
```

The two version numbers are the fence. Before its next change, the old holder
reads the lock again, finds version 20, and stops.

---

## 11. JSON output

`--output json` prints one JSON document for the run.
[`design/03-json-output.md`](design/03-json-output.md) specifies it, and the
schemas are in [`schemas/`](schemas/). For example, read the summary with Python:

```
$ sopuli --config sopuli.yaml --output json creds check > check.json
$ python -c "import json; d=json.load(open('check.json')); print(d['schema_version'], d['exit_code'], d['summary'])"
1.81 0 {'total': 2, 'ok': 1, 'changed': 0, 'failed': 0, 'unchanged': 2, 'drift': 0, 'unverifiable': 0, 'by_state': {'IN_SYNC': 1, 'ROLLOVER_ACTIVE': 1}}
```

`acme_batch_user` is `ROLLOVER_ACTIVE` because the `apply` in §10 opened its
rollover window. It is `IN_SYNC` once the window closes, after an hour or after
`creds finish-rollover`.

No field holds a password. Every exit code except 2 produces a document.

`--output jsonl` prints one event per line, as the run happens. `creds check`,
`creds apply`, `creds rotate`, `creds generate` and `account reset-password` take
it. The last event carries the summary and the exit code:

```
$ sopuli --config sopuli.yaml creds check --output jsonl
{"schema_version":"1.24","event":"run.started","seq":0,"ts":"2026-11-07T14:07:38.375411Z","correlation_id":"2256d846-1c08-4e5d-ab2f-96b06f8de3a4","data":{"command":"creds.check","dry_run":false}}
...
{"schema_version":"1.24","event":"run.finished","seq":6,"ts":"2026-11-07T14:07:39.557810Z","correlation_id":"2256d846-1c08-4e5d-ab2f-96b06f8de3a4","data":{"summary":{"total":2,"ok":1,"changed":0,"failed":0,"unchanged":2,"drift":0,"unverifiable":0,"by_state":{"IN_SYNC":1,"ROLLOVER_ACTIVE":1}},"exit_code":0}}
```

Other commands refuse it:

```
$ sopuli --config sopuli.yaml config show --output jsonl
sopuli: --output (verb): `config show` does not stream, so it has no jsonl output
  hint: use --output json for the same run as one document; jsonl is offered by: account reset-password, creds apply, creds check, creds generate, creds rotate
```

---

## 12. Exit codes

Scripts can branch on these. P5 in
[`design/00-principles.md`](design/00-principles.md) defines them.

| Code | Meaning | Example in this guide |
|---|---|---|
| 0 | success, or nothing to do | most runs |
| 1 | failure | `doctor` with no admin password (§7); a named account the guardrails refuse (§10) |
| 2 | the command line is wrong; no JSON document | `--account nosuch` (§10); `--output jsonl` on `config show` (§11) |
| 3 | `check` found drift | §8.5 |
| 4 | partial: some of what the run was asked to do happened, some did not | `creds apply` on MariaDB where one login does not confirm (§7) |
| 5 | a target lacks a capability the command needs | `account expire-password` on PostgreSQL (§9); a Yopass `ttl` the server does not accept (§9) |
| 6 | authentication failed | a token the vault rejects (§6) |
| 7 | a lock is held | §10 |
| 8 | aborted, or confirmation declined | `rotate` with nobody to confirm (§8.6) |
| 9 | the configuration is unusable | file permissions (§5); no vault token (§6) |

---

## 13. Cleanup

To throw everything away, stop the stack from `test/`:

```bash
docker compose --profile '*' down
```

To keep the containers, remove only what this guide created. Save this as
`cleanup.sql` and run it as in §4:

```sql
system/sopuli-test@localhost:1521/FREEPDB1
DROP USER acme_app_user CASCADE;
DROP USER acme_batch_user CASCADE;
DROP USER acme_priv_user CASCADE;
DROP USER acme_dev_alice CASCADE;
DROP USER acme_dev_bob CASCADE;
```

Then delete the vault paths. The application secret, the reset record, and a lock
for each:

```bash
vault kv metadata delete -mount=kv acme/dev/acme
vault kv metadata delete -mount=kv locks/acme/dev/acme
vault kv metadata delete -mount=kv sopuli/personal-resets/free-pdb/acme_dev_alice
vault kv metadata delete -mount=kv locks/sopuli/personal-resets/free-pdb/acme_dev_alice
```

`vault kv list -mount=kv` then answers `No value found at kv/metadata`. Finally,
delete `sopuli.yaml`, `priv.yaml`, `held.json` and the two SQL files.

`vault orphans` prints the first two commands for you. It lists the records the
tool wrote at paths the config does not declare. Copy `sopuli.yaml` to
`noapps.yaml`, delete its `applications:` entry, and run it before the deletes:

```
$ sopuli --config noapps.yaml vault orphans
config: noapps.yaml

VAULT      PATH                 KIND    LOCK
vault-dev  acme/dev/acme        secret  -
vault-dev  locks/acme/dev/acme  lock    released

2 orphans in 1 vault (vault-dev): records that look like this tool's, at paths no binding in this config declares

They may be another config's. Check each one before you delete it (getting-started.md, "Moving a secret path"). To delete them:

  vault kv metadata delete -address=http://127.0.0.1:8200 -mount=kv acme/dev/acme
  vault kv metadata delete -address=http://127.0.0.1:8200 -mount=kv locks/acme/dev/acme
```

The reset record and its lock are not listed, because they are under the
`reset_records:` prefix the config still declares.
