# Testing sopuli by hand

This guide sets up the local test stack and runs the usual commands against it.
You see each command succeed, and a few of them refuse on purpose.

Every sample is pasted from a real run on Windows 11, with Instant Client
23.26.3.0.0 and the `tier1` container stack: Oracle 26ai Free, PostgreSQL 16
and Vault. Most come from main at caf2645, after the 0.78.0 release, on
2026-10-23. A sample added since then comes from a run of the change that added
it. Every sample that shows PostgreSQL is one of these, from 18a0ceb to 50ea18d,
2026-10-25 and 2026-10-26. The samples in §11 come from main at 50ea18d on
2026-10-27.
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
sopuli vault orphans
```

The `creds` commands manage application credentials (UC-1). The `account`
commands manage personal accounts (UC-2). `vault orphans` lists vault records
the tool wrote at paths the config no longer declares (§13).

There is no `sopuli admin` command. To install the Oracle service account, run
the SQL in `sql/oracle/` by hand. The PostgreSQL tool role is created by hand in
`psql` (§7). The store backends are `hashicorp` and `oci` (§8.8); `doctor`
lists the others as `not_implemented`. A PostgreSQL target runs `doctor`, the
`creds` commands (§7) and the `account` commands (§9). It refuses
`account expire-password` and the seen reset, because PostgreSQL cannot make a
role change its password at its next login. A MySQL target runs only `doctor`
so far (§7).

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
  KIND     NAME        STATUS           CONFIGURED
  backend  file        not_implemented  -
  backend  hashicorp   installed        vault-dev
  backend  keyring     not_implemented  -
  backend  oci         installed        -
  driver   oracle      installed        1 target
  driver   postgresql  installed        -

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
`sopuli-test`. `doctor` connects to it and reports what it found. Every other
command refuses a MySQL target.

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
  pymysql           1.2.3

TARGET     REACHABLE  SCOPE   CONTAINER  OPEN MODE   CAPABILITIES  ENCRYPTION
mysql-dev  yes        server  -          READ WRITE  0             tls

1 note:
  mysql-dev: the admin credential came from the environment variable SOPULI_DB_ADMIN_PASSWORD, which P2 supports and flags as low assurance

1 warning:
  targets[0].mysql.ssl_mode: target 'mysql-dev' does not verify the server (`ssl_mode: REQUIRED`)
    hint: anything between this run and the server can present its own certificate and read the password a run sets. Use `ssl_mode: VERIFY_IDENTITY` (the default), with `ssl_ca` naming the CA that issued the server's certificate
```

Keep TLS on: with `ssl_mode: DISABLED` a login can fail
(`01-configuration.md` §3a, `mysql:`).

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
| red, bold | the tool could not do the job, or the estate is not in a state it can | `ERROR`, `ACCOUNT_MISSING`, `LOCKED`, `EXPIRED` |
| dim | nothing could be concluded | `UNVERIFIABLE`, `SKIPPED`, `DECLARED` |

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

2 changed, 1 promoted to `current`, 1 not confirmed

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

2 changed, 1 promoted to `current`, 1 not confirmed

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

Every command that changes a password first takes a lock in the vault. To see a
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
1.66 0 {'total': 2, 'ok': 1, 'changed': 0, 'failed': 0, 'unchanged': 2, 'drift': 0, 'unverifiable': 0, 'by_state': {'IN_SYNC': 1, 'ROLLOVER_ACTIVE': 1}}
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
{"schema_version":"1.19","event":"run.started","seq":0,"ts":"2026-10-29T19:22:44.035132Z","correlation_id":"06079ed6-f71a-402c-b40f-f75541363294","data":{"command":"creds.check","dry_run":false}}
...
{"schema_version":"1.19","event":"run.finished","seq":6,"ts":"2026-10-29T19:22:45.013889Z","correlation_id":"06079ed6-f71a-402c-b40f-f75541363294","data":{"summary":{"total":2,"ok":1,"changed":0,"failed":0,"unchanged":2,"drift":0,"unverifiable":0,"by_state":{"IN_SYNC":1,"ROLLOVER_ACTIVE":1}},"exit_code":0}}
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
| 4 | partial: some of the work succeeded, some failed | not shown |
| 5 | a target lacks a capability the command needs | not shown |
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
