# sopuli-dba — MySQL privileges and grants

Depends on: `00-principles.md`, `01-configuration.md`

This document says what the tool account is granted on a MySQL server, and what
it must not hold. The probes are in `sql/mysql/`. Which release each probe ran
on, and what it showed, is in [`../measurements.md`](../measurements.md).

A MySQL target is the whole server
([`01-configuration.md`](01-configuration.md) §*`mysql:` on a target*). An
account is a user name and a host pattern, such as `'acme_app'@'10.%'`. The
user name is case-sensitive and the host is not (`05_identity_grants_probe.py`,
ID1 to ID3).

---

## 1. The model: `CREATE USER`, never `SYSTEM_USER`

The tool connects as an account that holds the global privilege `CREATE USER`.
That privilege lets an account change another account's password, lock and
unlock it, expire its password, and drop it. It works on any account that does
not hold `SYSTEM_USER`, also one that holds every other privilege
(`05_identity_grants_probe.py`, TG3).

`SYSTEM_USER` protects an account from an account that does not hold it. An
account with `CREATE USER` alone is refused root's password, and `ACCOUNT LOCK`
on root and `mysql.sys`, with `1227` (TG1). On a new server, root and the
`mysql.*` system accounts hold `SYSTEM_USER` (TG2).

**The tool account never holds `SYSTEM_USER`.** With it, the tool account
changes root's password (TG6). No operation of the tool needs that. This is the
MySQL form of the PostgreSQL rule that the tool account is never a superuser
([`02-postgres-privileges.md`](02-postgres-privileges.md) §1).

So the tool refuses an account that can use `SYSTEM_USER`. Every session reads
the server's version first, and then the tool account's own grants (§2.2). It
refuses the target with `SOPULI-20007`
([`03-json-output.md`](03-json-output.md) §3) before it reads anything else.
The login itself succeeds, so the refusal is the tool's and not the server's.

"Can use" includes a role. The tool refuses an account that holds
`SYSTEM_USER` through a role granted to it, whether the role is active or not,
and through a role granted to that role. The account can `SET ROLE` to a role
that is not active, so the privilege is one statement away. PostgreSQL refuses
a member of a superuser role for the same reason. A `GRANT` line of
`SHOW GRANTS` that the tool cannot parse, and that names `SYSTEM_USER` or
`ALL PRIVILEGES`, is refused too: the tool cannot tell where it applies.

The refusal covers `SYSTEM_USER` that the account holds or can activate. It
does not cover a privilege that lets the account grant itself more, such as
`ROLE_ADMIN`, which grants any role, or `SET_USER_ID` and `SET_ANY_DEFINER`,
which create a routine that runs as root. The tool account must not hold
these either. `doctor --check-privileges` reports them as over-granted (§2.3).

A mandatory role, which the server gives every account, is read as any other
role is. The server refuses to make a role that holds `SYSTEM_USER` mandatory,
`3880`, and refuses to grant `SYSTEM_USER` to a mandatory role, `3897`. It
does accept `SYSTEM_USER` on a role already granted to a mandatory role, and
the tool account then reaches it (`07_own_grants_probe.py`, OG4 to OG6).

`SYSTEM_USER` protects only the accounts that hold it. An administrative
account without it is not protected, and the tool account can change its
password. Guardrail 9 refuses such an account as a managed account (§5).

---

## 2. The grants

### 2.1 The tool account

The account name includes the host the tool connects from. These statements
create the tool account for the tool host `192.0.2.10` and give it its grants.
Run them as an administrator.

```sql
CREATE USER 'sopuli_admin'@'192.0.2.10' IDENTIFIED BY RANDOM PASSWORD;
GRANT CREATE USER ON *.* TO 'sopuli_admin'@'192.0.2.10';
GRANT SELECT (User, Host, plugin, account_locked, password_expired,
              password_last_changed, password_lifetime,
              Select_priv, Insert_priv, Update_priv, Delete_priv, Create_priv,
              Drop_priv, Reload_priv, Shutdown_priv, Process_priv, File_priv,
              Grant_priv, References_priv, Index_priv, Alter_priv, Show_db_priv,
              Super_priv, Create_tmp_table_priv, Lock_tables_priv, Execute_priv,
              Repl_slave_priv, Repl_client_priv, Create_view_priv, Show_view_priv,
              Create_routine_priv, Alter_routine_priv, Create_user_priv, Event_priv,
              Trigger_priv, Create_tablespace_priv, Create_role_priv, Drop_role_priv)
  ON mysql.user TO 'sopuli_admin'@'192.0.2.10';
GRANT SELECT ON mysql.global_grants TO 'sopuli_admin'@'192.0.2.10';
GRANT SELECT ON mysql.db            TO 'sopuli_admin'@'192.0.2.10';
GRANT SELECT ON mysql.tables_priv   TO 'sopuli_admin'@'192.0.2.10';
GRANT SELECT ON mysql.columns_priv  TO 'sopuli_admin'@'192.0.2.10';
GRANT SELECT ON mysql.procs_priv    TO 'sopuli_admin'@'192.0.2.10';
GRANT SELECT ON mysql.proxies_priv  TO 'sopuli_admin'@'192.0.2.10';
GRANT SELECT ON mysql.role_edges    TO 'sopuli_admin'@'192.0.2.10';
```

`IDENTIFIED BY RANDOM PASSWORD` makes the server draw the password. The server
returns it once, in the statement's result, in the column `generated
password`. The statement text holds no password. The server writes a password
it parsed as `<secret>` in its logs, but a statement that fails to parse stays
in `performance_schema`'s statement history as it was sent, password included
(`01_password_text_probe.sql`). With `RANDOM PASSWORD`, a mistyped statement
holds no password either. Store the returned password where the target's
`admin.auth` reads it ([`01-configuration.md`](01-configuration.md)
§*`admin:`*).

The target's `admin.username` is the user name alone, `sopuli_admin`. The
server chooses the account by the host the tool connects from.

The column grant on `mysql.user` lets the tool read an account's plugin, lock
state and password expiry. It names columns, so the tool account cannot read
the stored hash, `authentication_string`, or `User_attributes`, which holds a
retained password's hash. The server refuses both with `1143`
(`05_identity_grants_probe.py`, TG5). Do not grant `SELECT` on the whole table
instead. §4 says what the tool reads with it.

The `*_priv` columns and the seven whole tables are what guardrail 9 reads
(§5): another account's global privileges, its grants on the `mysql` schema,
its proxies and its roles. None of them holds a hash. Probe 06
(`06_rollover_privileges_probe.py`) read the `*_priv` columns (PV1),
`global_grants` (PV2), `role_edges` (PV5), and `proxies_priv`, `db` and
`tables_priv` (PV7) with these grants. `columns_priv` and `procs_priv` hold
names and privilege sets only: their columns on 8.4.13 are `Host`, `Db`,
`User`, the table and column or routine name, `Grantor`, the privileges and
`Timestamp`.

Give the account no other privilege, and no role.

### 2.2 What the tool reads about itself

The tool reads the tool account's own grants with two statements. Both need no
grant: any account can read its own grants.

1. The roles granted to the tool account itself, from
   `INFORMATION_SCHEMA.APPLICABLE_ROLES`, where the grantee is the account. The
   view lists every role the account has, default or not, and a mandatory role
   with the account as its grantee.
2. `SHOW GRANTS FOR CURRENT_USER() USING` each of those roles, or `SHOW GRANTS`
   where there are none.

Neither statement is enough alone (`07_own_grants_probe.py`, OG2 and OG3):

- `SHOW GRANTS` without `USING` expands only the active roles. A role that is
  granted and not active is listed by name, and its privileges are not.
- `SHOW GRANTS … USING` expands exactly the roles it names, and the roles
  granted to them. It drops an active role that it does not name. So the tool
  names every role from the first statement.
- `SHOW GRANTS FOR` a role is refused, `1142`: it needs `SELECT` on
  `mysql.user`.
- `INFORMATION_SCHEMA.USER_PRIVILEGES` lists only the grants made to the
  account itself, never a role's.

`SHOW GRANTS` prints one line per grant. The tool parses each line by its
shape. A line of another shape, such as the `REVOKE` lines that
`partial_revokes` prints, is kept as text. §1 says when such a line is
refused, and §2.3 how the audit reports it.

### 2.3 What `doctor --check-privileges` reads

`sopuli doctor --check-privileges` reports what the tool account holds. It
warns and never fails ([P5](../decisions/log.md#p5)). It reads the grants of
§2.2, with every role expanded, the account's name from `CURRENT_USER()`, and
every role the account reaches from `INFORMATION_SCHEMA.APPLICABLE_ROLES`. None
of these reads needs a grant.

| Reported as | What it is |
|---|---|
| held or missing | `CREATE USER` on `*.*` |
| held or missing | `SELECT` on each column of `mysql.user` in §2.1. Column names are compared without case, as MySQL compares them |
| held or missing | `SELECT` on each of the seven whole tables in §2.1. `ALL PRIVILEGES` on one of them holds it too |
| over-granted | every other privilege the account holds or can activate, on any object, each as `<privilege> ON <object>`. This includes `GRANT OPTION`, and `ADMIN OPTION` on a role |
| unaudited | a line of `SHOW GRANTS` that the tool cannot parse |
| unreadable | `mysql.user`, where the server refuses the read of §4 with `1142` or `1143`: the column grant of §2.1 is missing |
| a remedy line | each declared account that does not exist, that uses another plugin, or whose user name also exists at a host the config does not declare (§4) |

**Everything outside §2.1 is over-granted.** The audit does not keep a list of
dangerous privileges. MySQL adds dynamic privileges in new releases, and a list
would miss them. A privilege that comes through a role is reported as one
granted directly is, because the account can use it either way. The report
lists every role the account reaches, so a reader can see where an over-grant
comes from.

A broader grant that includes one of §2.1's counts as held, because the tool
can do what it needs, and as over-granted, because it can do more. `SELECT` on
`mysql.user` as a whole, on `mysql.*` or on `*.*` holds the column grant;
`SELECT` on `mysql.*` or `*.*` holds the seven tables too; and
`ALL PRIVILEGES ON *.*` holds every grant. Where `SHOW GRANTS` also prints a
line the tool cannot parse, such as a `partial_revokes` `REVOKE` that may take
`mysql` out of a broader grant, only the exact column grant counts as held.
A database pattern, such as `` `%`.* ``, never counts: the tool does not
match patterns. Database and table names are
compared exactly, as a Linux server compares them, so a grant on `MYSQL`.`USER`
is not the system table's. Where something is missing, the hint gives the
statements that grant it.

`USAGE` is not reported. It means no privilege, and every account has it.

---

## 3. What must not be granted

Every privilege outside §2.1 is over-granted (§2.3). These matter most:

| Not granted | Why |
|---|---|
| `SYSTEM_USER` | it lets the tool account change root's password. The tool refuses to run with it (§1) |
| `ROLE_ADMIN` | it grants any role, also one that holds `SYSTEM_USER`, to any account, the tool account included |
| `SET_USER_ID`, `SET_ANY_DEFINER` | they create a stored routine or view that runs as another account, such as root |
| `GRANT OPTION`, and `ADMIN OPTION` on a role | they let the tool account pass its privileges or a role on to another account |
| `SUPER` | it bypasses `read_only` and other server-wide limits, and no operation of the tool needs it |
| `PROCESS` | it shows every session's current statement in `SHOW PROCESSLIST`, and no operation of the tool needs it |
| `SELECT` on `mysql.user` as a whole, or on its columns `authentication_string` or `User_attributes` | they read every stored hash, and every retained one |
| any privilege on `performance_schema` | its statement history keeps a statement that fails to parse as it was sent, password included (`01_password_text_probe.sql`) |
| `FILE` | it reads and writes files on the database server, as the server's operating system user |
| `PROXY` | it lets the tool account log in as another account |

---

## 4. Managed accounts

A managed account is one the config declares on a MySQL target, as
`user@host`: `acme_app@10.%`. A bare name is a config error (#1202, decision 4).
The tool splits the name at the last `@`, because a user name may hold `@` and
a host pattern may not.

The tool reads an account from the columns of `mysql.user` that §2.1 grants.
It sends the user name as a bind value and gets every account with that user
name, at any host. It reads all the declared user names in one statement. The
user name compares by case: the column's collation is binary, so `acme_app`
and `Acme_App` are two users. Trailing spaces do not count. The column is
`char(32)`, and 8.4.13 refused `CREATE USER 'acme_app '` beside `'acme_app'`
with `1396`, so the two are one account. The tool drops them too. The host
compares without case,
as the server compares it (`05_identity_grants_probe.py`, ID3): only ASCII
letters fold, as in the column's `ascii_general_ci` collation. The
account's name in a report is the server's spelling.

| Read from | Reported as |
|---|---|
| `account_locked` | locked. A person set it with `ACCOUNT LOCK`. The temporary lock after failed logins is not in `mysql.user` (`04_lock_expiry_probe.py`), so the tool does not know of it |
| `password_expired` | expired. Only `PASSWORD EXPIRE` sets it |
| `password_last_changed` | when the password changed. The session sets `time_zone` to UTC at login, so the server returns this `TIMESTAMP` in UTC |
| `password_lifetime` | when the password expires: that many days after it changed. Once that date has passed, the password is reported as expired too: the server refuses it, and does not set `password_expired`. `NULL` follows the server's `default_password_lifetime`, which any account can read. `0`, in either place, is no limit |
| `plugin` | the refusal below |

**The tool changes only `caching_sha2_password` accounts** (#1202, decision
5). An account on another plugin, such as `sha256_password`, is refused with a
config error, exit 9, when the tool reads it. Every command reads an account
before it changes it, so the refusal comes before anything is sent. The tool
does not move an account to another plugin.

**A user name at an undeclared host is reported.** One user name can exist at
several hosts, each with a password of its own (ID1). The tool changes the
password of the account the config declares, and the other one keeps logging
in with its own password. `doctor --check-privileges` names it (§2.3). It does
not name a locked one, which cannot log in. A role is a locked account with
an expired password, so a role with the same name is not named either.

Where the read of the declared accounts fails, `mysql.user` is unreadable, and
a line says why. The audit of the tool account's own grants is kept, so a
missing grant is still reported.

**The tool knows its own account.** When it reads an account, the tool reads
`CURRENT_USER()`, the account the server matched at login, and compares it as
above: the user exactly, the host without ASCII case. The match is the tool's
own account. Guardrail 7 refuses it unless `--force` waives that, and
guardrail 9 (§5) does not apply to it (#1225, [#1222](../decisions/log.md#1222)).

**A name typed on the command line is compared the same way.** An `account`
verb admits `jdoe@%` for a declared `jdoe@%`, and not `JDOE@%`, which is
another account. It refuses a name without a host at plan time, with exit 9,
because a `profile:` or `role:` rule admits names the file never held
([UC-2](../use-cases/uc-02-personal-account-passwords.md) §2, #1225).

---

## 5. Guardrail 9: a managed account with a global privilege

The tool refuses to manage an account that holds, or can activate, any of
these (decided in [#1222](../decisions/log.md#1222)):

- any privilege `ON *.*` but `USAGE`, static or dynamic;
- any privilege on the `mysql` schema, one of its tables, or one of their
  columns;
- any `PROXY` grant.

No flag waives it. The tool account's `CREATE USER` changes the password of
any account that does not hold `SYSTEM_USER`, an administrative one included
(§1). The tool would then know the password of an account that can change the
server. The rule covers every global privilege rather than a list of
administrative ones. MySQL adds dynamic privileges in new releases, and a list
would miss them. `SELECT ON *.*` also reads every stored hash. An application
account that was given a global privilege out of habit is refused until its
grant is narrowed to its own schema.

**Roles count whether they are active or not.** The account can `SET ROLE` to
any role granted to it, and to a role granted to that role. So the tool follows
`mysql.role_edges` to the end, and reads every role in `mandatory_roles`,
which has no row in `role_edges` (`06_rollover_privileges_probe.py`, PV6). A
default role is a granted role, so `mysql.default_roles` adds nothing. The
setting is split as `SHOW GRANTS` lines are, so a quoted role name may hold
`,` or `@`. A role reached twice, in two spellings of its host, is read once:
hosts compare without case.

| Where | What it shows |
|---|---|
| the `*_priv` columns of `mysql.user` | static privileges `ON *.*` |
| `mysql.global_grants` | dynamic privileges, which are all `ON *.*` |
| `mysql.db` | privileges on a schema. A pattern that matches `mysql`, such as `mysq%`, counts, unless `partial_revokes` is on: the server then reads `%` and `_` as themselves, so only a grant on `mysql` itself counts |
| `mysql.tables_priv`, `mysql.columns_priv` | privileges on a table or column of `mysql` |
| `mysql.procs_priv` | privileges on a stored routine in `mysql` |
| `mysql.proxies_priv` | `PROXY` grants |
| `mysql.role_edges`, `@@global.mandatory_roles` | the roles, read for each of the above |

The refusal names each privilege as `<privilege> ON <object>`, with
`through <role>` where a role gives it.

---

## 6. Where the password text can surface

**The password never reaches the server** (invariant 15). The driver
computes the account's `caching_sha2_password` hash on the client and sends:

```sql
ALTER USER `acme_app`@`10.%` IDENTIFIED WITH caching_sha2_password AS 0x2441243030...
```

The hash is SHA-crypt with SHA-256, a 20-byte salt the driver draws, and the
server's own rounds, from `caching_sha2_password_digest_rounds`, which any
account reads. It agrees with the hash the server computes for the same
password, salt and rounds, and a password set this way logs in
(`02_client_hash_probe.py`, CH1, CH2 and CH5). The stored hash writes the
rounds in thousands, so a server whose rounds are not a multiple of 1,000 is
refused before anything is sent.

The account is named as `mysql.user` spells it, each part between backquotes:
`ALTER USER` takes no bind parameters. A backquoted name escapes only a doubled
backquote, so it names the same account under every `sql_mode`. A string
literal does not: `NO_BACKSLASH_ESCAPES` changes what a backslash in it means.
A tier-1 test sets the password of an account whose name holds a quote and a
backslash, under the default mode, `NO_BACKSLASH_ESCAPES` and `ANSI_QUOTES`.

**Why not `IDENTIFIED BY`.** The server writes a password it parsed as
`<secret>` in the general log, the slow log and `performance_schema`'s
statement history. A statement that fails to parse is kept in that history as
it was sent, password included (`01_password_text_probe.sql`). A hex literal
always parses, so that cannot happen with the hash.

**What the server keeps is the hash.** With the general log written to a table
and `events_statements_history_long` on, a tier-1 test has the driver set a
password on 8.4.13. The general log keeps the statement with the hex literal,
and the history keeps it with the hash as a string. Neither holds the
password, and the account then logs in with it. The hash still allows an
offline guessing attack, so treat it as sensitive. The policy's length is the
protection against that. Where the server's error message quotes the
statement, the driver writes any hex literal in it as `0x***`, and any other
run of 16 or more hex digits as `***`, before the message is kept.

**A password is at most 256 bytes of UTF-8.** The server stores the hash of a
longer one and then refuses it at login, `1045`, on 8.0.46, 8.4.13 and 9.7.4
(CH6). The driver refuses such a password before anything is sent, as it
refuses an empty one and one with control characters.

---

## 7. Checking a password by login

`creds check` verifies a password by logging in as the account, over the
target's own TLS settings, timeouts and `program_name`. It cannot compare a
hash: the hash is in `authentication_string`, which the tool account does not
read, so the driver reports no `offline_verify`, and `--method hash` or
`both` is refused at plan time, exit 5.

**A login reaches the account the server matches from the client's host.**
The tool sends only the user name, and the server picks the account by host.
Measured on 8.4.13: with `acme_app@%` and `acme_app@10.%`, a login from the
tool's host reached `acme_app@%`, and `acme_app@10.%`'s own password was
refused with `1045`. A refusal names the client's host, not the account, so it
cannot be told apart from a wrong password. **The tool therefore logs in only
as a `user@%` account that is the user's only account** (decided on
[#1223](../decisions/log.md#1223)). Any other declared account is
`unavailable`, with no login, and the detail says why. After a login,
`CURRENT_USER()` confirms which account answered.

What a login answers, measured on 8.4.13 with PyMySQL 2.2.8:

| Account | Right password | Wrong password |
|---|---|---|
| open | logs in: `pass` | `1045`: `fail` |
| expired | `1862` at connect: `pass` | `1045`: `fail` |
| locked | `3118`: `pass` | `1045`: `fail` |

PyMySQL does not say it can handle an expired password, so the server refuses
it at connect with `1862`; the mysql client's `1820` after login does not
arise. Both say the password is right. A block after failed logins, `3955`,
answers the right password too, so it is `unavailable`. An account that does
not exist, or that `mysql.user` reports locked, is `unavailable` with no login.

**There is no lockout guard.** `FAILED_LOGIN_ATTEMPTS` and its counter are in
`User_attributes`, which the tool account does not read (#1202, decision 6).
A login goes ahead, as on Oracle without the `SYS.USER$` grant, and each
result's detail says the guard is unavailable.
