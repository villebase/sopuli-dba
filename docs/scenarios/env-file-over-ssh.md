# Scenario: a small app on one VM, with its password in `.env`

This scenario is for one small application on one virtual machine. PostgreSQL
runs on the same machine and listens only on `localhost`. The application reads
its database password from `DATABASE_URL` in a `.env` file. You reach the
machine over SSH from your own computer.

sopuli-dba runs on your computer. It reaches PostgreSQL through an SSH tunnel
and keeps the password in the vault. After each rotation, a short script on the
machine writes the new password into `.env` and restarts the application. You
start the script over SSH, and the password goes to it on standard input.

The names in this scenario are fictional: the machine is `app.example.com`,
the SSH user is `deploy`, and the application is `acme`, which logs in as
`acme_app_user`. The setup comes from a maintainer's own application,
anonymised.

The samples come from a real run against a stand-in for the machine: an Ubuntu
24.04 container with PostgreSQL 16.15 and OpenSSH, and an application that
logs in every two seconds and logs the result. The vault is the tier-1 test
stack's Vault ([`../local-testing.md`](../local-testing.md)). The container has
no systemd, so there a small script stands in for `systemctl restart acme`.
The run's warning about `sslmode: require` (§3) is left out of the samples
after the first.

---

## 1. On the machine: the tool account

**The tool account** is the role sopuli-dba logs in as to change the
application's password. Create it as `postgres`, and choose its password at the
prompt:

```
$ ssh -t deploy@app.example.com sudo -u postgres psql
postgres=# SET password_encryption = 'scram-sha-256';
postgres=# CREATE ROLE sopuli_admin LOGIN CREATEROLE;
postgres=# \password sopuli_admin
postgres=# GRANT acme_app_user TO sopuli_admin WITH ADMIN OPTION, INHERIT FALSE, SET FALSE;
```

Do not make the tool account a superuser. `CREATEROLE` is the only attribute it
needs. On PostgreSQL 16 and later it also needs `ADMIN OPTION` on the
application's role, and `INHERIT FALSE, SET FALSE` keeps it from using the
role's privileges. On 15 and earlier, leave out the `GRANT`
([`../design/02-postgres-privileges.md`](../design/02-postgres-privileges.md)
§2).

Do not write a password into a `CREATE ROLE` or `ALTER ROLE` statement:
PostgreSQL can keep the statement's text in its log. `\password` sends only a
verifier.

sopuli-dba connects to the database `postgres`, as the tool account to change
the password and as `acme_app_user` to check it. Both connections arrive
through the tunnel from `127.0.0.1`. Ubuntu's default `pg_hba.conf` already
allows them:

```
host    all             all             127.0.0.1/32            scram-sha-256
```

If your file names databases or users instead, add a line for each of the two
roles and the database `postgres`, above any broader `host` line, and reload
PostgreSQL.

---

## 2. On your computer: the tunnel

Open the tunnel in its own terminal and leave it open while you run
sopuli-dba:

```
$ ssh -N -L 15432:127.0.0.1:5432 deploy@app.example.com
```

Port 15432 on your computer now leads to PostgreSQL on the machine. The
database port stays closed to the internet, and the tunnel encrypts the
connection between the two computers.

---

## 3. The config

```yaml
version: 1

vaults:
  vault-prod:
    type: hashicorp
    addr: http://127.0.0.1:8200
    mount: kv
    kv_version: 2
    auth: { method: token }

defaults:
  vault: vault-prod

targets:
  - name: acme-db
    type: postgresql
    environment: prod
    dsn: "127.0.0.1:15432"
    admin:
      username: sopuli_admin
      auth: { method: vault, secret: "vault-prod:acme/prod/sopuli-admin#password" }
    postgres: { database: postgres, sslmode: require }

policies:
  env-safe:
    password:
      length: 32
      charset: alnum
      require: { upper: 1, lower: 1, digit: 1 }

applications:
  - name: acme
    accounts: [acme_app_user]
    targets: [acme-db]
    secret: "vault-prod:acme/prod/app#password"
    policy: env-safe
```

Three choices in it:

- **`dsn`** is the tunnel's end on your computer, not the machine's address.
- **The tool account's password** is in the vault, beside the application's.
  The vault's own credential opens it, so nothing depends on a database
  connection. Store it once with `vault kv put kv/acme/prod/sopuli-admin
  password=-`, which reads the value from standard input.
- **The policy** draws letters and digits only. The password goes into a URL,
  where characters such as `@`, `:`, `/` and `#` would need percent-encoding,
  and into a `.env` file, which can expand `$`
  ([`../design/01-configuration.md`](../design/01-configuration.md) §8). Thirty-two characters from 62 still give about 190 bits.

`sslmode: require` encrypts the connection but does not check the server's
certificate. Ubuntu's PostgreSQL uses a self-signed certificate, and its name
is the machine's, while the tunnel connects to `127.0.0.1`, so `verify-full`
cannot pass. Every run warns about this:

```
$ sopuli --config sopuli.yaml config validate
config: sopuli.yaml

ok: 1 target, 1 binding, 1 warning

1 warning:
  targets[0].postgres.sslmode: target 'acme-db' does not verify the server (`sslmode: require`)
    hint: anything between this run and the server can present its own certificate and read the password a run sets. Use `sslmode: verify-full` (the default), with `sslrootcert` naming the CA that issued the server's certificate
```

Here the part of the path that the certificate check would protect is the
tunnel's last step, inside the machine. The SSH host key protects the rest.

With OCI Vault instead, only the store changes. `vault_id`, `compartment_id`
and `key_id` are your vault's OCIDs, and a secret's name is the part of the
SecretRef before `#`, such as `acme-app-db` in
`"vault-oci:acme-app-db#password"`:

```yaml
vaults:
  vault-oci:
    type: oci
    vault_id:       ocid1.vault.oc1.eu-frankfurt-1.exampleuniqueid
    compartment_id: ocid1.compartment.oc1..exampleuniqueid
    key_id:         ocid1.key.oc1.eu-frankfurt-1.exampleuniqueid
    auth: config_file
```

`doctor` connects through the tunnel and reports what it found:

```
$ sopuli --config sopuli.yaml doctor --check-privileges
...
vaults
  VAULT       TYPE       STATUS  AUTH  SKEW
  vault-prod  hashicorp  ok      yes   -20ms
...
TARGET   REACHABLE  SCOPE    CONTAINER  OPEN MODE   CAPABILITIES  ENCRYPTION
acme-db  yes        cluster  -          READ WRITE  1             tls
```

---

## 4. Put the current password in the vault

The application already has a password. Store it in the vault as `current`
before the first rotation. `creds generate --promote --from-stdin` does this
and does not touch the database. This command reads the password out of `.env`
on the machine and sends it straight on, so it never appears on your screen or
in a command line:

```
$ ssh deploy@app.example.com "sudo sed -n 's|^DATABASE_URL=postgresql://[^:]*:\([^@]*\)@.*|\1|p' /opt/acme/.env" \
    | sopuli --config sopuli.yaml creds generate --app acme --promote --from-stdin
...
sopuli: the supplied password for 'acme_app_user' violates policy 'env-safe'
  hint: length (is 24 characters, policy asks for at least 32) -- fix the password, or pass `--no-policy-check`, which records in the audit event what it let through
```

A password chosen before the policy existed may not meet it. The first
rotation replaces it with one that does, so adopt it as it is:

```
$ ssh deploy@app.example.com "sudo sed -n 's|^DATABASE_URL=postgresql://[^:]*:\([^@]*\)@.*|\1|p' /opt/acme/.env" \
    | sopuli --config sopuli.yaml creds generate --app acme --promote --from-stdin --no-policy-check
Plan: 1 account x 1 target = 1 generation   [prod]

ACCOUNT        TARGET   INTENT                   SECRET
acme_app_user  acme-db  generate, vault_promote  vault-prod:acme/prod/app

constraints: 1024 bytes in UTF8, from acme-db

SECRET                    SEEDED         REPLACED
vault-prod:acme/prod/app  acme_app_user  -

ACCOUNT        SECRET                    RESULT
acme_app_user  vault-prod:acme/prod/app  promoted to v1

1 promoted to current; no database was changed -- run `sopuli creds apply` to use them
```

`creds check` logs in as the application with the vault's password, and
changes nothing. `IN_SYNC` means the vault holds the password the application
uses:

```
$ sopuli --config sopuli.yaml creds check --app acme
Plan: 1 account x 1 target = 1 check   [prod]

ACCOUNT        TARGET   INTENT  SECRET
acme_app_user  acme-db  verify  vault-prod:acme/prod/app

ACCOUNT        TARGET   STATE    DETAIL
acme_app_user  acme-db  IN_SYNC  vault v1 verified by login

all 1 in sync
```

---

## 5. On the machine: the script that updates `.env`

Install this script as `/usr/local/sbin/acme-set-db-password`, owned by root,
mode 755. It reads the new password from standard input, writes it into
`DATABASE_URL`, and restarts the application. The password is never an
argument, so `ps` on the machine never shows it:

```bash
#!/bin/bash
# Reads the new password from stdin, puts it into DATABASE_URL in
# /opt/acme/.env, and restarts the app. The password is never an argument.
set -euo pipefail
env_file=/opt/acme/.env

IFS= read -r pw || [ -n "$pw" ]
case $pw in
  '' | *[!A-Za-z0-9]*) echo "refused: the password must be letters and digits" >&2; exit 1 ;;
esac

tmp=$(mktemp "$env_file.XXXXXX")
while IFS= read -r line || [ -n "$line" ]; do
  case $line in
    DATABASE_URL=*) printf 'DATABASE_URL=postgresql://acme_app_user:%s@127.0.0.1:5432/acme\n' "$pw" ;;
    *) printf '%s\n' "$line" ;;
  esac
done < "$env_file" > "$tmp"
chown --reference="$env_file" "$tmp"
chmod --reference="$env_file" "$tmp"
mv "$tmp" "$env_file"

systemctl restart acme
echo "updated $env_file and restarted acme"
```

What it does, and why:

- It refuses anything but letters and digits, the policy's character set. A
  wrong value never reaches `.env`, and nothing in the value can break the URL.
- It writes a new file next to `.env`, gives it the old file's owner and mode,
  and then renames it over `.env`. The application never reads a half-written
  file, and `.env` stays as readable as it was.
- `printf` is a shell builtin, so the password is not an argument of any
  process.
- It keeps every other line of `.env` as it was.

Change the URL and the restart command to match your application. If the
`deploy` user should run only this command as root, give it a sudoers line
such as:

```
deploy ALL=(root) NOPASSWD: /usr/local/sbin/acme-set-db-password
```

---

## 6. Rotate, then update `.env`

PostgreSQL keeps one password for each role. When the rotation changes it, the
old password stops working at once, and the application cannot log in until it
has the new one. Sessions that are already open stay open; new logins fail.
So run the rotation and the update together, the update only if the rotation
succeeded:

```
$ sopuli --config sopuli.yaml creds rotate --app acme --dry-run
Plan: 1 account x 1 target = 1 rotation   [prod]

ACCOUNT        TARGET   INTENT                                                              SECRET
acme_app_user  acme-db  generate, vault_write_pending, verify, password_set, vault_promote  vault-prod:acme/prod/app

nothing was rotated (--dry-run)
```

```
$ sopuli --config sopuli.yaml creds rotate --app acme --confirm \
    && vault kv get -field=password kv/acme/prod/app \
     | ssh deploy@app.example.com sudo /usr/local/sbin/acme-set-db-password
Plan: 1 account x 1 target = 1 rotation   [prod]

ACCOUNT        TARGET   INTENT                                                              SECRET
acme_app_user  acme-db  generate, vault_write_pending, verify, password_set, vault_promote  vault-prod:acme/prod/app

ACCOUNT        TARGET   STATE    DETAIL
acme_app_user  acme-db  IN_SYNC  changed and verified by login

1 changed, 1 promoted to `current`

rotation: staged 1 document, promoted 1 document
updated /opt/acme/.env and restarted acme
```

`--confirm` answers the rotation's question in advance. Without a terminal to
ask, `creds rotate` refuses to run without it, and the `&&` then keeps the
update from running at all. `vault kv get` reads the new `current` password
and writes it to the pipe, not to your screen.

The application's log on the machine shows the gap. One login failed between
the password change and the restart, and the restarted application logged in
with the new password:

```
$ ssh deploy@app.example.com tail -8 /var/log/acme.log
19:04:50 ok
19:04:52 ok
19:04:54 ok
19:04:56 ok
19:04:58 login FAILED
19:04:58 ok
19:05:01 ok
19:05:03 ok
```

In this run the gap was about a second. It lasts as long as the rotation's end,
the vault read, the SSH connection and the restart together, so rotate when a
short gap suits the application.

With OCI Vault, read the new password with the OCI CLI instead of `vault kv
get`. The tool stores each version as a JSON document, `{"password": "…"}`,
base64-encoded, so decode it and pick out the field before the pipe to `ssh`.

---

## 7. Check it afterwards

`creds check` confirms that the vault and the database agree. It logs in, so
it also proves the new password works:

```
$ sopuli --config sopuli.yaml creds check --app acme
...
ACCOUNT        TARGET   STATE    DETAIL
acme_app_user  acme-db  IN_SYNC  vault v3 verified by login

all 1 in sync
```

`creds apply` changes nothing when the database already has the vault's
password:

```
$ sopuli --config sopuli.yaml creds apply --app acme --confirm
...
ACCOUNT        TARGET   STATE    DETAIL
acme_app_user  acme-db  IN_SYNC  the vault's password is already accepted; nothing to change

nothing changed
```

`.env` keeps its owner and mode, and only `DATABASE_URL` changed. The password
is masked here:

```
$ ssh deploy@app.example.com 'ls -l /opt/acme/.env; sudo sed "s|:[A-Za-z0-9]*@|:***@|" /opt/acme/.env'
-rw-r----- 1 root acme 123 Nov 10 19:04 /opt/acme/.env
NODE_ENV=production
DATABASE_URL=postgresql://acme_app_user:***@127.0.0.1:5432/acme
PORT=8080
```

---

## What to do when it goes wrong

The update line, on its own, is:

```
$ vault kv get -field=password kv/acme/prod/app | ssh deploy@app.example.com sudo /usr/local/sbin/acme-set-db-password
```

It writes the vault's `current` password each time, so running it again does
no harm.

- **The rotation fails.** The `&&` stops the update. A run can stop before it
  changes the password or after, so run `creds check` to see where things
  stand. [`rotate-and-sync.md`](rotate-and-sync.md) §*What to do when it goes
  wrong* says what each state means. Once `creds check` reports `IN_SYNC`, run
  the update line, so that `.env` holds the vault's `current` password.
- **The rotation succeeds, but the update fails**, for example because the SSH
  connection drops. The database and the vault have the new password, and
  `.env` has the old one. Run the update line.
- **The tunnel is closed.** Every command that connects fails with a timeout,
  and `doctor` reports the target as not reachable. Open the tunnel (§2) and
  run the command again:

  ```
  $ sopuli --config sopuli.yaml creds check --app acme
  ...
  ACCOUNT        TARGET   STATE  DETAIL
  acme_app_user  acme-db  ERROR  08001: connection timeout expired

  1 failed
  ```
