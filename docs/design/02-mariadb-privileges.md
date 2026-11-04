# sopuli-dba — MariaDB privileges and grants

Depends on: `00-principles.md`, `01-configuration.md`, `02-mysql-privileges.md`

This document says what the tool account is granted on a MariaDB server, what
it reads, what it never reads, and what it must not hold. It is the
specification for the MariaDB driver. The driver is not built yet: each part
names the issue that builds it. The decisions are in the decision log
([#1267](../decisions/log.md#1267)), and the probes are in `sql/mariadb/`.

The supported releases are 10.11 and later
([#1267](../decisions/log.md#1267), decision 6). Each probe ran on 10.11.19,
11.4.13, 11.8.9 and 12.3.3, the long-term support releases. Where this
document says "checked on 11.8.9", the check was made by hand on 2026-11-04
against the tier-1 service (`test/compose.yaml`, `mariadb`), and no probe
repeats it. "Checked on all four" means the same check on 10.11.19, 11.4.13,
11.8.9 and 12.3.3.

A MariaDB target is the whole server, as a MySQL target is. An
account is a user name and a host, as on MySQL. The user name is
case-sensitive, the host is stored in lower case, and a name with no host means
`'%'` (`sql/mariadb/05_identity_grants_probe.py`, ID1 to ID3). The MariaDB and
MySQL drivers share this account model, the PyMySQL connection and the error
numbers both servers send, in `sopuli/driver/mysql_family/`.

---

## 1. The model: `CREATE USER`, and nothing protects root

The tool connects as an account that holds the global privilege `CREATE USER`.
With it, an account sets another account's password, locks and unlocks it,
expires its password, and drops it (`02_client_hash_probe.py`, CH2;
`04_lock_expiry_probe.py`, LK1 to LK4; `05_identity_grants_probe.py`, TG3).

**MariaDB has no `SYSTEM_USER`** (TG2, `1064`). On MySQL, `SYSTEM_USER` keeps
an account with `CREATE USER` off root and the other administrative accounts
([`02-mysql-privileges.md`](02-mysql-privileges.md) §1). On MariaDB nothing
does: an account with `CREATE USER` alone sets root's password, and the
password of an account that holds `ALL PRIVILEGES WITH GRANT OPTION` (TG1,
TG3). So:

- the tool account is as strong as root over every account. Keep its
  credential as you keep root's;
- guardrail 9 (§5) is the only thing that keeps a mistaken config entry from
  giving the tool an administrative account's password;
- the tool account holds nothing beyond §2.1. Every other privilege makes it
  stronger than it needs to be (§3).

---

## 2. The grants

### 2.1 The tool account

The account name includes the host the tool connects from. These statements
create the tool account for the tool host `192.0.2.10` and give it its grants.
Run them as an administrator.

```sql
CREATE USER 'sopuli_admin'@'192.0.2.10'
  IDENTIFIED VIA mysql_native_password USING '<value>';
GRANT CREATE USER ON *.* TO 'sopuli_admin'@'192.0.2.10';
GRANT SELECT (User, Host, plugin, password_expired, is_role,
              Select_priv, Insert_priv, Update_priv, Delete_priv, Create_priv,
              Drop_priv, Reload_priv, Shutdown_priv, Process_priv, File_priv,
              Grant_priv, References_priv, Index_priv, Alter_priv, Show_db_priv,
              Super_priv, Create_tmp_table_priv, Lock_tables_priv, Execute_priv,
              Repl_slave_priv, Repl_client_priv, Create_view_priv, Show_view_priv,
              Create_routine_priv, Alter_routine_priv, Create_user_priv, Event_priv,
              Trigger_priv, Create_tablespace_priv, Delete_history_priv)
  ON mysql.user TO 'sopuli_admin'@'192.0.2.10';
GRANT SELECT ON mysql.roles_mapping TO 'sopuli_admin'@'192.0.2.10';
GRANT SELECT ON mysql.db            TO 'sopuli_admin'@'192.0.2.10';
GRANT SELECT ON mysql.tables_priv   TO 'sopuli_admin'@'192.0.2.10';
GRANT SELECT ON mysql.columns_priv  TO 'sopuli_admin'@'192.0.2.10';
GRANT SELECT ON mysql.procs_priv    TO 'sopuli_admin'@'192.0.2.10';
GRANT SELECT ON mysql.proxies_priv  TO 'sopuli_admin'@'192.0.2.10';
```

**Set the password as a value computed on the client.** MariaDB keeps the
password in clear when a statement carries it: `IDENTIFIED BY '…'` and `USING
PASSWORD('…')` stay as sent in the general log, the slow log and
`performance_schema`'s statement history, also when the statement fails, and in
the binary log when it succeeds (`01_password_text_probe.py`). MariaDB has no
`IDENTIFIED BY RANDOM PASSWORD`: it is a syntax error, `1064` (checked on
11.8.9). `<value>` is `*` followed by the SHA-1 of the SHA-1 of the password,
in upper-case hex. This computes it, and reads the password without echoing
it:

```bash
python -c "import getpass, hashlib; p = getpass.getpass().encode(); print('*' + hashlib.sha1(hashlib.sha1(p).digest()).hexdigest().upper())"
```

The value agrees with the one the server computes, and an account created with
it logs in with the password (`02_client_hash_probe.py`, CH1; checked on
11.8.9). Store the password where the target's `admin.auth` reads it
([`01-configuration.md`](01-configuration.md) §*`admin:`*). The target's
`admin.username` is the user name alone, `sopuli_admin`.

**The column grant reads no hash.** `mysql.user` is a view on MariaDB. The
grant names its columns, so the tool account reads an account's plugin, its
expiry, whether it is a role, and its static global privileges. It cannot read
`Password` or `authentication_string`: the server refuses both with `1143`
(TG5; checked on 11.8.9 with exactly these grants). Do not grant `SELECT` on the
whole view instead. §4 says what the tool reads with it.

**The six tables read no hash either.** `mysql.roles_mapping` says which roles
each account holds. `mysql.db`, `tables_priv`, `columns_priv`, `procs_priv` and
`proxies_priv` hold names, privilege columns, the grantor and a timestamp, and
no hash (checked on all four). The statements above are accepted on each of
them, and the view has the same `*_priv` columns on each (checked on all
four). Guardrail 9 reads the six tables (§5). Without the grant,
`roles_mapping` is refused with `1142` (TG7), and so is `mysql.db` (checked on
11.8.9).

Give the account no other privilege, and no role.

### 2.2 What the tool reads about itself

**The tool reads its own grants from `information_schema`, never from `SHOW
GRANTS`.** Any account can run `SHOW GRANTS` for itself, and on MariaDB its
first line carries the account's stored value, such as ``GRANT CREATE USER ON
*.* TO `sopuli_admin`@`192.0.2.10` IDENTIFIED BY PASSWORD '*…'`` (checked on
11.8.9). `information_schema`'s `USER_PRIVILEGES`, `SCHEMA_PRIVILEGES`,
`TABLE_PRIVILEGES` and `COLUMN_PRIVILEGES` show an account its own grants with
no grant of their own, and no stored value. The audit reads each by the tool
account's own grantee, since an account that holds `SELECT` on `mysql.*` sees
every account's rows there (RD1). They show only grants made to the account
itself: what a role gives it is not there, and `doctor` says so where the
account holds a role (`sopuli/driver/mariadb/privileges.py`). Grants to
`PUBLIC` are in none of them either (11.8.9), and every run says so.

**The reads that matter most are tried directly.** `SELECT … LIMIT 0` on
`mysql.global_priv`, and on the view's `authentication_string` and `Password`,
returns no row, and is refused with `1142` or `1143` for an account with §2.1
alone. Where the server allows one, by any route (a direct grant, a role,
`PUBLIC` or a broader grant), `doctor` reports it as over-granted. A role that
is not a default role is not active, so the audit sets each role in turn, tries
the reads, and sets back the role the session had, read by `CURRENT_ROLE()`:
MariaDB has no `SET ROLE DEFAULT`.

`SHOW GRANTS FOR` another account, and `SHOW CREATE USER` for one, are refused
with `1044` (TG5). Both print that account's hash to an account allowed to run
them, so the tool never needs that.

### 2.3 What `doctor` reports

`doctor` connects to the server and reports the scope, `server`: the release,
whether it takes writes (`read_only` and the session's `tx_read_only`), and the
session's encryption. A server whose version does not name MariaDB is refused,
exit 9. `doctor --check-privileges` audits the tool account against §2.1 and
§3. It names a declared account that does not exist, and one on a plugin the
tool does not change. Two targets on one server are not caught yet (#1286):
MariaDB has no `server_uuid`. It warns, and never fails
([P5](../decisions/log.md#p5)), about:

- each declared user name that also exists at a host the config does not
  declare, as on MySQL ([`02-mysql-privileges.md`](02-mysql-privileges.md) §4).
  The other account keeps its own password. On MariaDB the line names it even
  when it is locked, because the lock cannot be read (decision 2);
- the gap in guardrail 9 that §5 describes, wherever an application's
  `accounts:` are bound to the target. Check 9 cannot read the nine privileges
  that MariaDB split from `SUPER`, so it cannot fully check the managed
  accounts, and the line names the nine
  ([#1267](../decisions/log.md#1267), decision 4). Check 9 itself refuses
  once the driver changes passwords (open: #1270).

---

## 3. What must not be granted

| Not granted | Why |
|---|---|
| `SELECT` on `mysql.global_priv`, on `mysql.*` or on `*.*` | each reads every account's stored value, and the lock and rollover state beside it (`07_readable_state_probe.py`, RD1; `08_split_privileges_probe.py`, SP3) |
| `SELECT` on the `mysql.user` view as a whole, or on its `Password` or `authentication_string` columns | they read every stored value |
| `SET USER` | with `CREATE ROUTINE` on one database, it creates a procedure whose definer is an administrator, and through it changes any account's password. On 12.3.3 an account did this, and the view showed no privilege of that account ([#1267](../decisions/log.md#1267), decision 4) |
| `SUPER` | it bypasses `read_only` and other server-wide limits, and no operation of the tool needs it |
| `GRANT OPTION`, and `ADMIN OPTION` on a role | they let the tool account pass its privileges or a role on to another account |
| any privilege on `performance_schema` | its statement history keeps a statement that sets a password as it was sent, password included (`01_password_text_probe.py`) |
| `FILE` | it reads files on the database server, such as a general log written to a file |
| `PROXY` | it lets the tool account log in as another account |

---

## 4. Managed accounts

A managed account is one the config declares on a MariaDB target, as
`user@host`: `acme_app@10.%`. A bare name is a config error, as on MySQL. A
`role:` rule names a role without a host: a MariaDB role has none (TG7).

**What the tool reads.** The `mysql.user` view gives the tool account the
plugin and the expiry of another account, and nothing else about its password
(`07_readable_state_probe.py`, RD1). A change of password, a rollover and a
lock leave everything it reads as it was (RD2 to RD5).

| Read from the view | Reported as |
|---|---|
| `plugin` | the refusal below |
| `password_expired` | expired. `PASSWORD EXPIRE` sets it, and the password then logs in and every statement but setting it answers `1820` (`04_lock_expiry_probe.py`, LK3) |
| `is_role` | whether the row is a role. Guardrail 9 reads a role's privileges from its row (§5) |

**What the tool never reads.** Each of these is only in `mysql.global_priv` or
in `SHOW CREATE USER`, beside the stored value, so reading it would read every
hash.

| Never read | What the tool does instead |
|---|---|
| the lock, `account_locked` (LK2) | `account list` says the lock cannot be read. `account suspend` always sends `ACCOUNT LOCK` and reports `changed: true` ([#1267](../decisions/log.md#1267), decision 2; open: #1272) |
| an open rollover, `auth_or` (`03_dual_password_probe.py`, DP4) | `creds finish-rollover` always sends the new value alone and reports `changed: true` (decision 3; open: #1271) |
| when the password changed, and its lifetime (RD1) | a change is verified by login (§7), not by its time (decision 8) |
| a block after failed logins, `max_password_errors` (LK4, RD6) | `ACCOUNT UNLOCK` ends it, and a reset sends it only with `--unlock` (decision 9; open: #1272) |

**The tool changes only `mysql_native_password` and `ed25519` accounts**
(decision 1). `doctor --check-privileges` names an account on `parsec`, or on
any other plugin, today. A command that changes a password refuses it at plan
time, naming the plugin and the account (open: #1270).
PyMySQL 1.2.3 has no client for `parsec` (`06_pymysql_login_probe.py`, PL1), so
a `parsec` password could be changed and never checked. The tool never moves an
account to another plugin.

**A user name at an undeclared host is reported** by `doctor` (§2.3).

---

## 5. Guardrail 9: a managed account with a global privilege

The tool refuses to manage an account that holds, or can get through a role,
any of these (open: #1269):

- any global privilege but `USAGE`;
- any privilege on the `mysql` schema, one of its tables, or one of their
  columns;
- any `PROXY` grant.

No flag waives it. Nothing protects root on MariaDB (§1), so the tool account
can set the password of any administrative account, and the tool would then
know it. The rule is the one MySQL's check 9 applies
([`02-mysql-privileges.md`](02-mysql-privileges.md) §5,
[#1222](../decisions/log.md#1222)).

| Where | What it shows |
|---|---|
| the `*_priv` columns of the `mysql.user` view | static global privileges. `Repl_client_priv` is set by `BINLOG MONITOR`, which is `REPLICATION CLIENT` renamed (SP2) |
| `mysql.db` | privileges on a schema |
| `mysql.tables_priv`, `mysql.columns_priv` | privileges on a table or column of `mysql` |
| `mysql.procs_priv` | privileges on a stored routine in `mysql` |
| `mysql.proxies_priv` | `PROXY` grants |
| `mysql.roles_mapping` | the roles an account holds, followed to the end. A role is a row of the view, with `is_role = 'Y'`, so its global privileges read as an account's do (TG7) |

**What it cannot see.** `SHOW PRIVILEGES` lists ten privileges whose context is
`Server`. Only `BINLOG MONITOR` sets a column of the view. The other nine set
none: `BINLOG ADMIN`, `BINLOG REPLAY`, `CONNECTION ADMIN`, `FEDERATED ADMIN`,
`READ_ONLY ADMIN`, `REPLICATION MASTER ADMIN`, `REPLICATION SLAVE ADMIN`, `SET
USER` and `SLAVE MONITOR` (SP1, SP2). They are in `mysql.global_priv`, and in
`SHOW GRANTS` and `information_schema.USER_PRIVILEGES` only for an account that
can also read every hash (SP3). Check 9 does not see them, held directly or
through a role.

**This is an accepted risk** ([#1267](../decisions/log.md#1267), decision 4).
An account that holds `SET USER` is managed if the config declares it, and
through it its holder can act as any account (§3). Check 9 guards against a
mistaken config entry, not against the tool account, which can already set
root's password. Granting the tool account the hashes to close the gap would
cost more: a changed password is noticed, and a read hash is not. `doctor`
says so (§2.3).

---

## 6. Where the password text can surface

**Only a value computed on the client keeps the password out of every log.**
The general log, the slow log and `performance_schema`'s statement history keep
`CREATE USER` and `ALTER USER … IDENTIFIED BY '…'`, `SET PASSWORD … =
PASSWORD('…')` and `USING PASSWORD('…')` as sent, also when the statement
fails. The binary log keeps the ones that succeed, the password included, except
`SET PASSWORD`, which it rewrites to the hash. Only `IDENTIFIED VIA <plugin>
USING '<value>'`, with a value the client computed, keeps the password out of
all of them (`01_password_text_probe.py`). So the driver computes the value for
the account's plugin and sends (open: #1270):

```sql
ALTER USER `acme_app`@`10.%` IDENTIFIED VIA ed25519 USING '<value>'
```

The value is the plugin's (`02_client_hash_probe.py`, CH1):

- `mysql_native_password`: `*` and the SHA-1 of the SHA-1 of the password, in
  upper-case hex (§2.1);
- `ed25519`: the Ed25519 public key derived from the password's UTF-8 bytes
  as RFC 8032 derives one from a private key: SHA-512 of the bytes, of any
  length, then the clamped scalar times the base point. It is written in
  base64 without the trailing `=`. The password is not a 32-byte Ed25519 seed,
  so a library that takes only such a seed does not compute it.

`sopuli.driver.mariadb.password` computes both. Values computed in Python agree
with the server's, and an account with only `CREATE USER` sets them (CH1, CH2).
**There is no length limit**: the server sees only the value, and a password of
1 byte to 1 MiB is set and logs in (`09_password_length_probe.py`, PW1). The
driver refuses an empty password, control characters, and text that cannot be
encoded as UTF-8, as the other drivers do. The server refuses a malformed value with
the plain `1396` (CH3). A new server loads only `mysql_native_password`;
`ed25519` must be installed with `INSTALL SONAME 'auth_ed25519'` (CH4).

**The value is sensitive.** A `mysql_native_password` value is an unsalted
SHA-1 hash. It allows an offline guess, and with one captured login handshake
it is enough to log in ([#1267](../decisions/log.md#1267), decision 4). Treat
it as the password: it is a `Secret`, and a server message that quotes the
statement is scrubbed before it is kept, as on MySQL
([`02-mysql-privileges.md`](02-mysql-privileges.md) §6).

**A rollover is `OR`.** MariaDB has no `RETAIN CURRENT PASSWORD`: it is a
syntax error, `1064` (DP1). `IDENTIFIED VIA <plugin> USING '<old>' OR <plugin>
USING '<new>'` lets both passwords log in, also across two plugins, and the new
value alone ends it (DP2, DP3, DP5). The tool computes both values from the
`current` and `pending` passwords it holds (open: #1271).

**The other statements carry no password.** `ACCOUNT LOCK`, `ACCOUNT UNLOCK`
and `PASSWORD EXPIRE` need only `CREATE USER` (LK1 to LK4). A locked account
answers its password with `4151`, and a blocked one with `4150`. `account
reset-password` sends `ACCOUNT UNLOCK` only with `--unlock`
([#1267](../decisions/log.md#1267), decision 9), because it cannot read whether
the account is locked by `account suspend` or blocked after failed logins
(open: #1272).

---

## 7. Checking a password by login

The tool verifies a password by logging in as the account, over the target's
own TLS settings (open: #1270). PyMySQL logs in on `mysql_native_password`,
and on `ed25519` with PyNaCl, which the `mariadb` extra installs
(`06_pymysql_login_probe.py`, PL1 and PL3). The driver reports no
`offline_verify`: the stored value is in a column the tool account does not
read.

**A change is verified only when `CURRENT_USER()` is the declared account**
([#1267](../decisions/log.md#1267), decision 8). A login reaches the account
the server matches from the client's host, which need not be the declared one
(ID1). After the login, the tool reads `CURRENT_USER()`. Where it names another
account, or the login reaches none, the change is not verified, and its
`pending` is not promoted (invariant 7). MySQL verifies such an account by
`password_last_changed` instead ([#1223](../decisions/log.md#1223)); MariaDB
keeps that time only beside the hash.

What the server answers at a login, measured with the `mariadb` client:

| Account | Right password | Wrong password |
|---|---|---|
| open | logs in | `1045` |
| expired | logs in, then `1820` to a statement (LK3) | `1045` |
| locked | `4151` (LK1) | `1045` |
| blocked after failed logins | `4150` (LK4) | `1045` |

A failed verification login counts toward `max_password_errors` on the account
it reaches. That is an accepted cost of decision 8.

**TLS.** The `mariadb` images of 11.4 and later start with TLS on. The 10.11
image starts with it off, and
PyMySQL, given a TLS context, refuses the login itself with `2026`
(`06_pymysql_login_probe.py`, PL2). A 10.11 target whose `ssl_mode` requires
TLS needs TLS turned on at the server.
