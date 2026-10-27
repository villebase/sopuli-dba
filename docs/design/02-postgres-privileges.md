# sopuli-dba — PostgreSQL privileges and grants

Depends on: `00-principles.md`, `../use-cases/uc-01-app-credential-sync.md`

This document says what the tool account is granted on a PostgreSQL cluster,
what it must not be granted, and what the tool can leave behind on the server.
The probes are in `sql/postgres/`. Which release each probe ran on, and what it
showed, is in [`../measurements.md`](../measurements.md). A major release named
here, such as "from 16", means the one release of it that was measured.

A PostgreSQL target is the whole cluster, not one database in it
([`01-configuration.md`](01-configuration.md) §*`postgres:` on a target*). Every
role belongs to the cluster, so one tool account and one set of grants covers
every database in it.

---

## 1. The model: `CREATEROLE`, never a superuser

The tool connects as an ordinary role that has the `CREATEROLE` attribute. That
attribute lets a role change another role's password, unless the other role is
a superuser.

**The tool account is never a superuser.** A superuser can do anything on the
cluster, including read every stored password verifier in `pg_authid`. No
operation of the tool needs that. This is the PostgreSQL form of the Oracle rule
that the tool never connects `AS SYSDBA`.

So the tool refuses a superuser. The first read of every session asks
`pg_roles.rolsuper` for the role that logged in and for `current_user`, and
whether either is a member of a superuser role through any chain of grants.
Both are asked because a role's `SET role` default changes `current_user` at
login, and `RESET ROLE` changes it back. A member can `SET ROLE` to
that role, so it is refused too. Either way the target is refused with
`SOPULI-20007` ([`03-json-output.md`](03-json-output.md) §3) before anything
else is asked of it. The login itself succeeds, so the refusal is the tool's
and not the server's.

### What `CREATEROLE` reaches

What `CREATEROLE` reaches depends on the release. The
`pg-createrole-password` entry in [`../README.md`](../README.md)
§*Verify before implementing* has the measurement.

- **On 13 to 15**, `CREATEROLE` alone changes the password of every role that
  is not a superuser. There is nothing narrower to grant. It can also grant
  itself any role that is not a superuser, the built-in roles of §3 included:
  on 15.19 a `CREATEROLE` role granted itself `pg_execute_server_program`. So
  on these releases the tool account is close to a superuser, and its password
  needs the same care.
- **From 16**, `CREATEROLE` also needs `ADMIN OPTION` on the role. So the grant
  of §2.2 limits the tool account to the roles it is granted, and the server
  refuses any other with SQLSTATE `42501`.

So from 16 the server enforces the config's whitelist (invariant 5) a second
time, for the roles a DBA granted. On 13 to 15 only the tool enforces it.

---

## 2. The grants

### 2.1 The tool account

These psql commands create the tool account and set its password. Run them as
a superuser.

```sql
SET password_encryption = 'scram-sha-256';
CREATE ROLE sopuli_admin LOGIN CREATEROLE;
\password sopuli_admin
```

`\password` asks for the password and sends only a SCRAM verifier that libpq
computes on the client, so the password never reaches the server (§6). libpq
chooses the algorithm from the session's `password_encryption`. The `SET` is
what makes it SCRAM on a server set to `md5`, as the `postgres:13` image is.
Without it the verifier is md5, and the `scram-sha-256` line of §2.3 refuses
the login. On 13.23, with `password_encryption = md5`, libpq's call gave an
md5 verifier before the `SET` and a SCRAM one after it, and the role then
logged in with `require_auth=scram-sha-256`.

The target's `admin.username` names this role
([`01-configuration.md`](01-configuration.md) §*`postgres:` on a target*). Give
it no other attribute. §3 lists the ones that must not be given.

### 2.2 Each managed role

A managed role is one that the config declares as an account on this target.
How the tool account is given each one depends on the release.

**From 16**, grant each managed role to the tool account with `ADMIN OPTION`,
and with `INHERIT FALSE` and `SET FALSE`:

```sql
GRANT acme_web_user TO sopuli_admin WITH ADMIN OPTION, INHERIT FALSE, SET FALSE;
```

`ADMIN OPTION` is what `CREATEROLE` needs before it may change the role's
password. `INHERIT FALSE` means the tool account does not use the role's
privileges, and `SET FALSE` means it cannot `SET ROLE` to it. So the tool can
change the role's password and can do nothing else as that role. This was run
on 16.15:

```text
    rolname    | admin_option | inherit_option | set_option
---------------+--------------+----------------+------------
 acme_web_user | t            | f              | f
```

From 16, a role that the tool account creates gets `ADMIN OPTION` on it. The
tool does not create roles, so this matters only for a role a DBA created while
connected as the tool account.

**On 13 to 15**, grant nothing. `CREATEROLE` alone is enough there (§1). These
releases have no `INHERIT` or `SET` option on a grant. Any membership in a
managed role lets the tool account `SET ROLE` to it, and by default use its
privileges. A membership there gives the tool more than it needs and nothing it
lacks.

**The tool tells the releases apart by the catalog, not by a version number**
(invariant 3). The `INHERIT` and `SET` options are columns of
`pg_auth_members`, `inherit_option` and `set_option`. They arrived in 16 with
the rule that `CREATEROLE` needs `ADMIN OPTION`. A server whose
`pg_auth_members` has `set_option` is one that requires `ADMIN OPTION`. On
every release measured, 13.23 to 18.6, the column and the rule go together:
the column is absent on 13.23, 14.24 and 15.19, and present on 16.15, 17.11
and 18.6. A managed service or a fork is not measured.

### 2.3 `pg_hba.conf`

The tool host logs in as the tool account. UC-1 also tests a managed role's
password by logging in with it. So `pg_hba.conf` needs a line for the tool
account and a line for each managed role, from the tool host, with
`scram-sha-256`.

These lines allow the tool host `192.0.2.10` to log in as the tool account and
as one managed role, over TLS:

```text
# TYPE   DATABASE  USER           ADDRESS        METHOD
hostssl  postgres  sopuli_admin   192.0.2.10/32  scram-sha-256
hostssl  postgres  acme_web_user  192.0.2.10/32  scram-sha-256
```

`DATABASE` is the target's `postgres.database`, `postgres` by default. Use
`host` instead of `hostssl` only where the target's `postgres.sslmode` is
`disable`.

Use `scram-sha-256`, not `password` or `md5`. With `password`, the client sends
the password itself to log in. A line that says `md5` still accepts a role
whose stored verifier is md5, so it does not make the login SCRAM. For a role
whose verifier is SCRAM it uses SCRAM; the `pg-md5-line-scram` entry in
[`../README.md`](../README.md) §*Verify before implementing* has the
measurement.

**The tool logs in as a managed role with `require_auth=scram-sha-256`.** libpq
then refuses, before it sends the password, a server that asks for any other
method or that lets the role in without asking. So a `password` line cannot
make it send the password in clear, and a `trust` line cannot make a wrong
password look right. The login also uses the target's `sslmode` and timeouts.
What each outcome means:

- the login succeeds: the password matches;
- `28P01`: the server refused the password. It gives the same answer for a
  role whose stored verifier is md5, which no password opens through a
  `scram-sha-256` line;
- `28000`, or a server that did not use SCRAM: the login was refused for
  another reason, such as no line for this host and role. That says nothing
  about the password, and the run says which line to add;
- no `CONNECT` on the database (`42501`), or the role at its `CONNECTION
  LIMIT` (`53300`): the server says these only after it accepted the password,
  so the password matches, and the run says why the session did not open;
- a role that does not exist, a `NOLOGIN` role and a role whose `VALID UNTIL`
  has passed are reported before any login. The server would answer the first
  and the last as a wrong password, even with the right one (measured on
  16.15).

`require_auth` needs libpq 16 or later. With an older libpq the tool refuses the
login and sends nothing. It refuses each account as it reaches it, during the
run, not at plan time as invariant 4 asks. Whether to move the refusal to plan
time is an open decision (open: #1076). The `psycopg[binary]` wheels the
`postgres` extra installs bundle libpq 16 or later.

### 2.4 What `doctor --check-privileges` reads

`sopuli doctor --check-privileges` reports what the tool account holds. It
warns and never fails ([P5](../decisions/log.md#p5)). It reads only catalogs
that every role can read, so the audit needs no grant of its own.

| Reported as | What it reads |
|---|---|
| held or missing | `CREATEROLE` on the tool account, from `pg_roles.rolcreaterole` |
| held or missing | `ADMIN OPTION` on each managed role, from `pg_has_role(…, 'USAGE WITH ADMIN OPTION')`, where the server requires it (§2.2) |
| over-granted | `SUPERUSER`, `REPLICATION` and `BYPASSRLS`, from `pg_roles` |
| over-granted | §3's built-in roles, held through any chain of grants in `pg_auth_members`. From 16 a role counts only where some chain to it has `INHERIT` on every grant, or `SET` on every grant. A role's privileges pass only down `INHERIT` grants and `SET ROLE` reaches only down `SET` grants, so a chain of one of each gives neither |
| over-granted | a managed role whose privileges the tool account uses, from `pg_has_role(…, 'USAGE')`, or that it can `SET ROLE` to, from `pg_has_role(…, 'SET')`. Before 16, every member can `SET ROLE`, so it reads `'MEMBER'` |

The report lists every role the tool account holds, through any chain, usable
or not.

A managed role is matched to the config's account name as written, and then by
`upper()`, as the config compares names. The report uses the cluster's
spelling.

Each over-granted managed role comes with the statement that removes the
over-grant, with the names quoted. From 16 that statement is a `GRANT` with
the new options. It changes the grant made by the role that runs it, so it is
run as the role that made the grant. Where the role also reaches the tool
account through another role, a statement about the direct grant would not
remove that path, so the report says so. A managed role that does not exist
gets a line that says so. It is not missing, since no grant fixes it, and it
is not an error here. The tool does not create roles.

`pg_has_role` answers true for every role when the tool account is a
superuser. So the built-in roles are read from `pg_auth_members` instead, and a
superuser's managed roles are not reported one by one: its `SUPERUSER` finding
covers them.

---

## 3. What must not be granted

| Not granted | Why |
|---|---|
| `SUPERUSER` | it can do anything on the cluster, and read every stored verifier. The tool refuses to run as a superuser (§1) |
| `REPLICATION` | it can copy the whole cluster through streaming replication, and no operation of the tool needs it |
| `BYPASSRLS` | it ignores every row-level security policy, and no operation of the tool reads table data |
| `pg_execute_server_program`, `pg_read_server_files`, `pg_write_server_files` | they run programs and read or write files on the database server, as the server's operating system user |
| `pg_read_all_data`, `pg_write_all_data` | they read or write every table in every database |
| `pg_signal_backend` | it can cancel or end other sessions |
| `pg_read_all_stats`, and `pg_monitor`, which includes it | it shows every session's statement text in `pg_stat_activity` and `pg_stat_statements`, and §6 says that text can hold a password |
| a membership in a managed role with `INHERIT TRUE` or `SET TRUE` | the tool account gets the role's privileges, or can act as the role. From 16, grant `INHERIT FALSE, SET FALSE` (§2.2) |
| any membership in a managed role, on 13 to 15 | it is not needed there, and it cannot be granted without `SET` (§2.2) |

`doctor --check-privileges` names anything on this list that the tool account
holds. Over-granting is the usual result of fixing a permissions problem in a
hurry. The tool notices it and says so.

---

## 4. Roles that something else manages

A Kubernetes operator such as CloudNativePG, Zalando's postgres-operator or
Crunchy PGO can own a role's password. It may set the password back after the
tool changes it, and an application then logs in with a password the vault no
longer holds.

The tool cannot tell from SQL that an operator owns a role. The config is the
whitelist (invariant 5), so the rule is in the config: **declare only roles
that nothing else sets a password for.** Never declare the roles an operator
creates for itself, such as its replication role.

---

## 5. Roles the tool refuses to change

The account guardrails of `02-oracle-privileges.md` §4 apply to PostgreSQL too.
The rules are product-neutral. The driver reads the facts from `pg_roles` and
`pg_auth_members`, which any role can read, so the guardrails need no grant:

| Check | Refuses | From | `--force` |
|---|---|---|---|
| 2 | a role `initdb` created: the bootstrap superuser and every `pg_*` role | the role's oid is below 16384 | waives |
| 4 | a role with `REPLICATION`, `BYPASSRLS` or `CREATEROLE` | `pg_roles` | waives |
| 4 | a member of `pg_execute_server_program`, `pg_read_server_files`, `pg_write_server_files`, `pg_read_all_data`, `pg_write_all_data` or `pg_signal_backend`, through any chain of grants | `pg_auth_members`, walked up from the role | waives |
| 6 | a superuser | `rolsuper` | never |
| 7 | the tool's own account, the one the session logged in as | `session_user` | waives |

Check 3, the password file, does not exist on PostgreSQL, so it always passes
and leaves no caveat. Check 5 is for an Oracle release with no answer to check 2.
PostgreSQL always answers it.

`pg_monitor` and `pg_read_all_stats` are not refused for an application role.
The tool account must not hold them (§3), but a monitoring application often
needs them.

Two more facts come from the same read:

- **`NOLOGIN` is reported as locked.** `check` does not try a login that cannot
  succeed, and `apply` does not change a password it cannot confirm.
- **A past `VALID UNTIL` is reported as expired.** The role cannot log in with
  any password until somebody moves the date, so a new password does not fix
  it.

A name is matched by `upper()`, as the config compares names (invariant 5). The
role keeps the spelling `pg_roles` gives back. Two roles whose names differ only
in case are refused, because the config cannot tell them apart.

---

## 6. Where the password text can surface

PostgreSQL keeps the whole text of `ALTER ROLE … PASSWORD` in every place
measured, on 13 to 18. The `pg-password-text` entry in
[`../README.md`](../README.md) §*Verify before implementing* has the
measurement. In short:

- the server log keeps it with `log_statement = all`, and keeps the text of a
  statement that fails even with the default `log_statement = none`;
- `pg_stat_statements` keeps it, whatever `log_statement` says;
- `pg_stat_activity` shows an idle session's last statement, password included.

The tool cannot see or control any of these. So **a password must never reach
the server inside a statement.** A SCRAM verifier computed on the client is
kept in the same places. It still allows an offline guessing attack, which the
password policy's minimum length protects against.

So the driver computes the verifier on the client, through libpq, and sends
`ALTER ROLE "<role>" PASSWORD 'SCRAM-SHA-256$…'` (invariant 15). libpq applies
SASLprep as the server does at login, so the two agree on a non-ASCII password
(`pg-saslprep` in [`../README.md`](../README.md)). The algorithm is named in
the call, so a server whose `password_encryption` is `md5` still gets a SCRAM
verifier. The role's name is quoted as `pg_roles` spells it.

The longest password is **1024 bytes of UTF-8**. libpq 13 cannot log in with a
longer one (`pg-password-length`), and an application may still use it. The
server takes any length behind a verifier, so this is the tool's ceiling, and a
longer password is refused before anything is sent.

---

## 7. Files

| File | Purpose |
|---|---|
| `sql/postgres/01_password_text_probe.sql` | what the server log, `pg_stat_statements` and `pg_stat_activity` keep of `ALTER ROLE … PASSWORD` (§6) |
| `sql/postgres/02_system_identifier_probe.sql` | whether a role with no grants can read `system_identifier`, which tells two targets on one cluster apart (`01-configuration.md` §*`postgres:` on a target*) |
| `sql/postgres/03_createrole_password_probe.sql` | what a `CREATEROLE` role needs before it can change another role's password (§1, §2.2) |
| `sql/postgres/04_md5_line_scram_verifier_probe.py` | whether a SCRAM verifier logs in through a `pg_hba.conf` line that says `md5` (§2.3) |
| `sql/postgres/05_psycopg_libpq_probe.py` | which libpq each psycopg wheel bundles, and whether it accepts `require_auth` |
| `sql/postgres/06_saslprep_probe.py` | whether a verifier computed on the client and the server's SASLprep agree on a non-ASCII password (`pg-saslprep`) |
| `sql/postgres/07_password_length_probe.py` | the longest password that sets as a verifier and logs in (`pg-password-length`) |

The probes are for throwaway servers only: each header says what it creates.
