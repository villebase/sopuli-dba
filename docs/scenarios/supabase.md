# Scenario: Supabase, one login role for each service

Many Supabase projects connect every service with the same `DATABASE_URL`, and
that URL carries the `postgres` password. This scenario replaces it with one
login role for each service. sopuli-dba keeps each role's password in the vault
and changes it there and on the database together.

Supabase's own documentation also recommends a separate role for each service.

## Who this is for

This is for a service that opens its own PostgreSQL connection: for example an
application that uses Prisma, Drizzle or `psycopg` with a `DATABASE_URL`.

It is not for an application that reaches the database only through Supabase's
HTTP API (PostgREST, through `supabase-js`). That application logs in with API
keys, and the database roles behind it (`anon`, `authenticated`,
`service_role`) are `NOLOGIN` roles with no password. There is nothing for
sopuli-dba to change.

Two things are out of scope:

- **The `postgres` password.** Supabase manages it. You change it in the
  dashboard or through Supabase's Management API. `ALTER ROLE postgres
  PASSWORD` is refused.
- **Supabase's API keys** (`sb_secret_…`, `sb_publishable_…`). They are not
  database passwords.

Two terms, used throughout:

- **supautils** is a PostgreSQL library that Supabase loads into every project.
  It protects Supabase's own roles. Its setting `supautils.reserved_roles` lists
  them.
- **The tool account** is the role sopuli-dba logs in as to change passwords.

The samples below come from a real run against a local Supabase stack
(`supabase start`, Supabase CLI 2.78.1, PostgreSQL 17.6), with the tier-1 test
stack's Vault ([`../local-testing.md`](../local-testing.md)). The local stack has
no TLS, so every sample warns about `sslmode: disable`. §3 says what to set for a
hosted project.

---

## 1. Create the tool account

Do not use `postgres` as the tool account. On Supabase, `postgres` is not a
superuser, but it holds much more than the tool needs. With §3's config changed
to `username: postgres`, saved as `as-postgres.yaml`, `doctor
--check-privileges` lists what it should not hold:

```
$ sopuli --config as-postgres.yaml doctor --check-privileges
...
TARGET        REACHABLE  SCOPE    CONTAINER  OPEN MODE   CAPABILITIES  ENCRYPTION
supabase-dev  yes        cluster  -          READ WRITE  0             none
  supabase-dev: the connection is not encrypted, so a password the tool sets crosses it in clear: set `postgres.sslmode` to verify-full, and give the server a certificate (`ssl = on`)
  supabase-dev: over-granted, and the tool needs none of it: BYPASSRLS, REPLICATION, pg_monitor, pg_read_all_data, pg_read_all_stats, pg_signal_backend
...
```

`pg_read_all_data` reads every table. `pg_read_all_stats` shows other sessions'
statement text. [`../design/02-postgres-privileges.md`](../design/02-postgres-privileges.md)
§3 gives the reason for each.

Create a dedicated tool account instead. Connect as `postgres`, with the SQL
editor or `psql`, and run:

```sql
SET password_encryption = 'scram-sha-256';
CREATE ROLE sopuli_admin LOGIN CREATEROLE PASSWORD '<a password you keep in the vault>';
```

`CREATEROLE` is the only attribute the tool account needs
([`../design/02-postgres-privileges.md`](../design/02-postgres-privileges.md)
§2.1).

---

## 2. Create one role for each service

Create a login role for each service, still as `postgres`. Then give the tool
account `ADMIN OPTION` on each one. On PostgreSQL 16 and later, `CREATEROLE`
alone does not let the tool account change another role's password. `INHERIT
FALSE, SET FALSE` keeps the tool account from using the role's privileges:

```sql
CREATE ROLE acme_web_user LOGIN;
CREATE ROLE acme_worker_user LOGIN;
GRANT acme_web_user TO sopuli_admin WITH ADMIN OPTION, INHERIT FALSE, SET FALSE;
GRANT acme_worker_user TO sopuli_admin WITH ADMIN OPTION, INHERIT FALSE, SET FALSE;
```

On a project that runs PostgreSQL 15, leave out the two `GRANT` statements.
There `CREATEROLE` alone is enough, and a membership would give the tool account
the role's privileges
([`../design/02-postgres-privileges.md`](../design/02-postgres-privileges.md)
§2.2). On 15, `CREATEROLE` also reaches every role that is not a superuser, so
the config's list of accounts is what keeps the tool to your roles. Run `SELECT
version();` to see which release a project runs. This scenario was run on 17.6
only.

The roles have no password yet. sopuli-dba sets the first one in §4.

Grant each role only what its service uses, with ordinary `GRANT` statements on
schemas and tables. A role you create is not a member of `anon`,
`authenticated` or `service_role`, so a row-level security policy written `TO
authenticated` does not apply to it. Write the policies and grants for each
role.

**Declare only roles you created.** Supabase's own roles are refused (§6).

---

## 3. The config

This config declares the two roles, as one application with one vault
document:

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
  - name: supabase-dev
    type: postgresql
    environment: dev
    vault: vault-dev
    dsn: "127.0.0.1:54322"
    admin: { username: sopuli_admin, auth: { method: env } }
    postgres: { sslmode: disable }

policies:
  standard:
    password:
      length: 24
      charset: alnum_safe
      first_char: alpha
      require: { upper: 1, lower: 1, digit: 1, special: 1 }

applications:
  - name: acme
    accounts: [acme_web_user, acme_worker_user]
    secret_template: "vault-dev:acme/{env}/{application}#DB_CREDENTIALS/{account}"
```

Port 54322 is the local stack's database. For a hosted project, change two
things:

- **`dsn`** names the direct connection, `db.<project-ref>.supabase.co:5432`.
  Supabase's documentation says this host has only an IPv6 address unless the
  project has the IPv4 add-on. Run sopuli-dba from a machine that reaches it.
- **`postgres`** becomes `{ sslmode: verify-full, sslrootcert: <path> }`, with
  the CA certificate that the project's database settings in the dashboard
  offer for download. Remove `sslmode: disable`. It is for the local stack only.

Do not point `dsn` at Supabase's connection pooler, Supavisor. The tool does
not support a pooler: behind one, the encryption checks read the pooler's
connection to the server, not the tool's
([#1045](../decisions/log.md#1045)). Whether to support Supavisor is not
decided (open: #1111).

The tool account's password comes from `SOPULI_DB_ADMIN_PASSWORD` here. The
other ways to supply it are in
[`../design/01-configuration.md`](../design/01-configuration.md).

---

## 4. Set the first passwords

`doctor` connects as the tool account and reports what it found. With the
dedicated tool account it reports nothing over-granted:

```
$ sopuli --config supabase.yaml doctor --check-privileges
...
TARGET        REACHABLE  SCOPE    CONTAINER  OPEN MODE   CAPABILITIES  ENCRYPTION
supabase-dev  yes        cluster  -          READ WRITE  0             none
  supabase-dev: the connection is not encrypted, so a password the tool sets crosses it in clear: set `postgres.sslmode` to verify-full, and give the server a certificate (`ssl = on`)
...
```

`creds generate` draws a password for each role and stages it in the vault. It
changes no database:

```
$ sopuli --config supabase.yaml creds generate
...
constraints: 1024 bytes in UTF8, from supabase-dev

SECRET                   STAGE    ACCOUNTS
vault-dev:acme/dev/acme  pending  acme_web_user, acme_worker_user

ACCOUNT           SECRET                   RESULT
acme_web_user     vault-dev:acme/dev/acme  staged v1
acme_worker_user  vault-dev:acme/dev/acme  staged v1

2 staged; no database was changed -- run `sopuli creds apply` to use them
...
```

`creds apply` sets each staged password on the database, logs in with it, and
then promotes it to `current` in the vault:

```
$ sopuli --config supabase.yaml creds apply
Plan: 2 accounts x 1 target = 2 applys   [dev]
...
ACCOUNT           TARGET        STATE    DETAIL
acme_web_user     supabase-dev  IN_SYNC  changed and verified by login
acme_worker_user  supabase-dev  IN_SYNC  changed and verified by login

2 changed, 1 promoted to `current`
...
```

`creds check` logs in with the vault's password and changes nothing:

```
$ sopuli --config supabase.yaml creds check
...
ACCOUNT           TARGET        STATE    DETAIL
acme_web_user     supabase-dev  IN_SYNC  vault v2 verified by login
acme_worker_user  supabase-dev  IN_SYNC  vault v2 verified by login

all 2 in sync
...
```

[`rotate-and-sync.md`](rotate-and-sync.md) explains each of these steps in more
detail.

---

## 5. Give each service its password, and rotate it

Each service now logs in as its own role. Its `DATABASE_URL` names that role,
and its password is the vault's `current` value. This command reads one role's
password from the vault:

```
$ vault kv get -format=json -field=DB_CREDENTIALS kv/acme/dev/acme
```

How the password reaches the service depends on where it runs. For Kubernetes,
[`kubernetes-eso.md`](kubernetes-eso.md) has a setup in which the service never
holds a vault credential. Once every service uses its own role, remove the
`postgres` password from their configuration.

`creds rotate --confirm` replaces the passwords in one run:

```
$ sopuli --config supabase.yaml creds rotate --confirm
Plan: 2 accounts x 1 target = 2 rotations   [dev]
...
ACCOUNT           TARGET        STATE    DETAIL
acme_web_user     supabase-dev  IN_SYNC  changed and verified by login
acme_worker_user  supabase-dev  IN_SYNC  changed and verified by login

2 changed, 1 promoted to `current`

rotation: staged 1 document, promoted 1 document
...
```

PostgreSQL keeps one password for each role, so the old password stops working
when the run changes it. A service that still holds it fails its next login.
Rotate when the services can collect the new password, or restart them after
the run.

---

## 6. Supabase's own roles are refused

supautils lets only a superuser change a role in `supautils.reserved_roles`, and
the tool never connects as a superuser. On the local stack the list is:

```
supabase_admin, supabase_auth_admin, supabase_storage_admin, supabase_read_only_user,
supabase_realtime_admin, supabase_replication_admin, supabase_etl_admin, dashboard_user,
pgbouncer, service_role*, authenticator*, authenticated*, anon*
```

The tool reads this setting before it changes anything, and refuses each
declared role on the list. This is guardrail check 8
([`../design/02-postgres-privileges.md`](../design/02-postgres-privileges.md)
§5). `--force` does not waive it. Here `declared.yaml` is §3's config with
`authenticator` added to `accounts:`, after `creds generate` staged a password
for it:

```
$ sopuli --config declared.yaml creds apply
...
ACCOUNT           TARGET        STATE    DETAIL
acme_web_user     supabase-dev  IN_SYNC  the vault's password is already accepted; nothing to change
acme_worker_user  supabase-dev  IN_SYNC  the vault's password is already accepted; nothing to change
authenticator     supabase-dev  SKIPPED  the server reserves this account in supautils.reserved_roles, and only a superuser may change it

nothing changed, 1 not confirmed
```

`creds rotate` with the same config refuses the whole run in its privilege
check, and asks for `ADMIN OPTION` on `authenticator`. supautils does not allow
that grant (open: #1117). Take the role out of `accounts:`.

Supabase's other roles, such as `supabase_functions_admin`, are not on the
local list. The tool account cannot change them anyway, because it has no
`ADMIN OPTION` on them. Leave them out of the config too.

---

## 7. What the server keeps

Supabase loads `pg_stat_statements`, which keeps the text of each statement, and
the dashboard shows it. The tool never sends the password to the server. It
computes a SCRAM-SHA-256 verifier on the client and sends that
([`../design/02-postgres-privileges.md`](../design/02-postgres-privileges.md)
§6). This query, run as `postgres` after the rotation, shows the statements the
tool sent. The connection options are left out:

```
$ psql -tAc "select left(query, 60) from pg_stat_statements where query ilike 'alter role%acme%'"
ALTER ROLE "acme_worker_user" PASSWORD 'SCRAM-SHA-256$4096:7
ALTER ROLE "acme_web_user" PASSWORD 'SCRAM-SHA-256$4096:OYw3
```

A verifier still allows an offline guessing attack, so treat this view as
sensitive. A long random password, as the `standard` policy draws, makes that
attack impractical.
