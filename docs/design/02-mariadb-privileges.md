# sopuli-dba — MariaDB privileges and grants

Depends on: `00-principles.md`, `01-configuration.md`, `02-mysql-privileges.md`

This document says what the tool account is granted on a MariaDB server, what
it reads, what it never reads, and what it must not hold. It is the
specification for the MariaDB driver, which is in `src/sopuli/driver/mariadb/`.
The decisions are in the decision log ([#1267](../decisions/log.md#1267) and
the entries after it), and the probes are in `sql/mariadb/`.

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
  giving the tool an administrative account's password. The one exception is
  `mariadb.sys@localhost`, the account a new server creates to own the system
  views: 10.11.19, 11.8.9 and 12.3.3 all create it, and the driver reports it
  as the database's own, so guardrail 2 refuses it;
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

**One optional column grant.** `SELECT (default_role)` on `mysql.user` reads
each account's default role, for the privilege report (#1411, R3, #1483).
Without it, whether a role is active without `SET ROLE` is not checked. It holds a role's name only. The audit counts it as held
where it is granted, and never as missing.

```sql
GRANT SELECT (default_role) ON mysql.user TO 'sopuli_admin'@'192.0.2.10';
```

**Two optional views,** each made by its own script in `sql/mariadb/`, which
grants `SELECT` on it to the tool account. Both live in the schema `sopuli`,
and neither gives a stored value:

- `account_state_view.sql` makes `sopuli.account_state` (#1491): for each
  account, the lock, the password lifetime and the time of the last change,
  from `mysql.global_priv`. `report accounts`, `report history` and `account
  list` read it;
- `global_privileges_view.sql` makes `sopuli.global_privileges` (#1483): each
  account's global privileges, from `information_schema.USER_PRIVILEGES`, as
  a definer that reads `mysql.*` sees them. `report privileges` reads it.

Nothing that changes an account reads either. Without them, the reports say
what they give is *not checked*, and `account list` shows `OPEN` or
`EXPIRED`, which say nothing of the lock. §2.4 says what each gives. Edit the
two `SET` lines at the top of each script to name the tool account, and run it
as an administrator who may name another definer (`SET USER` or `SUPER`).
`doctor --check-privileges` counts `SELECT` on each view as held where it is
granted, and never as missing; any other privilege on them is over-granted.

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
whether it takes writes (`read_only` and the session's `tx_read_only`), the
session's encryption, and the capabilities, `password_value` among them unless
a password validation plugin refuses the value (§6, #1310). A server whose
version does not name MariaDB is refused, exit 9. `doctor --check-privileges`
says why a scope lacks `password_value`: the plugins that refuse the value, or
that the settings could not be read. It audits the tool account against §2.1 and
§3. It names a declared account that does not exist, and one on a plugin the
tool does not change. Two targets on one server are refused, `SOPULI-20008`,
as on MySQL ([#1286](../decisions/log.md#1286)). MariaDB has no
`server_uuid`, so the tool knows a server by `@@server_uid`, which any account
reads. It changes at each restart. Between restarts it differed on every
server measured, a replica from its primary included, even one with the
primary's hostname, port and datadir; `server_id`, `port`, `datadir` and
`gtid_domain_id` keep their defaults unless a DBA sets them
(`13_server_identity_probe.py`). The tool compares identities only within one
run, so a server that restarts during a run can let two targets on it through.
A Galera cluster's nodes share their accounts, and each node has its own
`@@server_uid`. So on a Galera node that is `Synced` the tool also knows the
cluster, by the status variable `wsrep_cluster_state_uuid`. One cluster's
nodes shared it, two clusters started from empty data had different ones, it
survived a node's restart and the whole cluster's, and an account with only
`CREATE USER` read it and the node's state (`14_galera_identity_probe.py`).
Two targets on nodes of one cluster are refused as one Galera cluster. The
server is claimed too, whatever the node's state, so two targets on one node
are always refused. A node in another state, such as `Donor/Desynced` while a
backup runs, gives no cluster: the probe measured only `Synced` as the state
to trust. Another target on its cluster is then not refused, and every command
that connects says so: `SOPULI-W068` in `diagnostics[]` and the text view,
and in `doctor` also a note on the target
([#1363](../decisions/log.md#1363)). A cluster started from a copy of another cluster's data was not
measured: it is expected to keep that cluster's UUID, and the two would then
be refused as one ([#1346](../decisions/log.md#1346)).
`doctor` warns, and never fails ([P5](../decisions/log.md#p5)), about:

- each declared user name that also exists at a host the config does not
  declare, as on MySQL ([`02-mysql-privileges.md`](02-mysql-privileges.md) §4).
  The other account keeps its own password. On MariaDB the line names it even
  when it is locked, because the lock cannot be read (decision 2);
- the gap in guardrail 9 that §5 describes, wherever an application's
  `accounts:` are bound to the target. Check 9 cannot read the nine privileges
  that MariaDB split from `SUPER`, so it cannot fully check the managed
  accounts, and the line names the nine
  ([#1267](../decisions/log.md#1267), decision 4). Check 9 itself refuses
  what it can read, in the verbs that change an account (§5);
- the second login method that §4 describes, on the same condition: the view
  shows one method of an account that has two, and a password change ends the
  other ([#1301](../decisions/log.md#1301)).

### 2.4 What the reports can read

`report accounts` (#1462) and `report history` (#1460) are built on MariaDB,
and so is the privilege report, without the global level (#1483). This is what
the tool account can read for
them with §2.1's grants, and what each further read would cost. It was
measured on 10.11.19, 11.4.13, 11.8.9 and 12.3.3 (`15_report_read_probe.py`,
#1448). `report accounts` reads `User`, `Host` and `password_expired` from
the view, with `is_role = 'N'`
(`sopuli/driver/mariadb/survey.py`), and, where the optional view
`sopuli.account_state` exists and passes its column check, the lock and the
lifetime from it (#1491). Where a `personal_accounts:` rule names a `role:`,
it also reads that role's members from `mysql.roles_mapping`, as `account
list` does (#1495). `report history` reads the time of the last change from
that view.

- **An account is a user name at a host.** One name at three hosts is three
  rows of the `mysql.user` view. A role is a row with an empty host and
  `is_role = 'Y'`, so a role is never mistaken for an account.
- **The lock, the lifetime and the date of the last change cannot be read
  with §2.1**, on every release, as `04_lock_expiry_probe.py` (LK2) found
  for the lock. They are kept only in
  `mysql.global_priv`, beside the hash, and in `SHOW CREATE USER`, which
  prints the value. The view has no `account_locked` column, `1143`;
  `global_priv` is refused, `1142`, and `SHOW CREATE USER` for another
  account, `1044`. Only the expiry, `password_expired`, reads.
- **A view that a DBA creates reads them, and an open rollover**
  (`16_definer_view_probe.py`, #1479, for #1457). The tool reads it as
  `sopuli.account_state`, which `sql/mariadb/account_state_view.sql` makes
  (#1491). It has `SQL SECURITY DEFINER` and selects `User`, `Host`, three
  keys of `global_priv`'s `Priv` and one flag. The probe's own copy:

  ```sql
  CREATE SQL SECURITY DEFINER VIEW sopuli_probe.account_state AS
  SELECT User, Host,
         JSON_VALUE(Priv, '$.account_locked')        AS account_locked,
         JSON_VALUE(Priv, '$.password_lifetime')     AS password_lifetime,
         JSON_VALUE(Priv, '$.password_last_changed') AS password_last_changed,
         COALESCE(JSON_LENGTH(Priv, '$.auth_or'), 0) > 1 AS rollover_open
    FROM mysql.global_priv;
  ```

  With `SELECT` on it, the tool account reads:
  - `account_locked`: `NULL` for an account never locked, `1` when locked,
    `0` after `ACCOUNT UNLOCK`;
  - `password_lifetime`: the days, `0` for `PASSWORD EXPIRE NEVER`, and
    `NULL` or `-1` for the server's default. `PASSWORD EXPIRE` sets `-1`
    where the lifetime was the default, and keeps an account's own;
  - `password_last_changed`: seconds since 1970, by the server's clock.
    `PASSWORD EXPIRE` sets it to `0`, which is how MariaDB marks an expired
    password, so after an expiry the date of the last change is lost;
  - `rollover_open`: `1` while a rollover by `OR` is open, `PASSWORD
    EXPIRE` during it included, and `0` after the close. The close leaves
    `auth_or` as one empty entry, so whether the key exists is not the flag.

  The view gives every row of `global_priv`, roles and `root` among them,
  and no stored value: the probe looked for every fixture value in all the
  tool account read, refusals included, and found none. The tool account is
  refused `SHOW CREATE VIEW`, `1142`, and `EXPLAIN`, `1345`, and cannot
  create a view or a procedure over the view, or update it. The
  view and what it gives survive the image's upgrade from 10.11.19 to
  11.4.13, 11.8.9 and 12.3.3.
- **The view's shape and presence, as the tool account sees them.**
  `information_schema.COLUMNS` and `SHOW COLUMNS` list the view's columns
  before any row is read. A second view, made with an extra
  `authentication_string` column to test this, showed that column in both.
  Under a column grant they list only the columns granted. An absent view, an
  absent schema and a view without the grant all answer `1142`, so the tool
  cannot tell them apart. A dropped definer answers `1045 (28000)`, "Access
  denied", in a session that is already logged in. A definer that exists
  without `SELECT` on `global_priv` answers `1356`. The definer can be a
  locked account that holds only `SELECT` on `mysql.global_priv`. A DBA
  without `SET USER` or `SUPER` cannot name another definer, `1227`.
- **The view does not show a block by `max_password_errors`.** `Priv` has no
  key for it; only `information_schema.USERS` has the count, from 11.8.
- **There is no failed-login limit per account.** `FAILED_LOGIN_ATTEMPTS` is a
  syntax error, `1064`. The limit is the server's `max_password_errors`,
  which the tool account reads; its default, 4294967295, means no limit.
  With the limit at 2, an account with no global privilege, one with
  `CONNECTION ADMIN` and one with `SUPER` were all blocked, `4150`, the right
  password too. The count is `PASSWORD_ERRORS` in `information_schema.USERS`,
  per account, from 11.8; it shows the tool account only its own row.
- **The date of the last change, through the view**, moves with a change by
  value, as the driver sends it, with a rollover by `OR` and with its close.
  `ACCOUNT LOCK` and a new lifetime leave it. `PASSWORD EXPIRE` sets it to
  `0`, and the next change by value sets a new time.
- **Roles.** A recursive query over `mysql.roles_mapping` gives each
  account's roles, nested ones included, with the path and `Admin_option`.
  The default role is the view's `default_role` column, which §2.1's
  required grants do not cover, `1143`; §2.1's optional column grant reads
  it, and it holds a role's name only.
- **Privilege levels.** Static global privileges are the view's `*_priv`
  columns, and schema, table, column, routine and proxy grants are in `db`,
  `tables_priv`, `columns_priv`, `procs_priv` and `proxies_priv`, which §2.1
  reads. A grant to `PUBLIC` is a row whose user is `PUBLIC` and host is
  empty. The privileges split from `SUPER`, such as `CONNECTION ADMIN`, set
  no column of the view (`08_split_privileges_probe.py`): an account that
  holds only `CONNECTION ADMIN` reads as holding nothing.
  `information_schema`'s `*_PRIVILEGES` views show the tool account none of
  another account's grants.
- **A second view that a DBA creates reads the global level**
  (`17_global_privileges_view_probe.py`, #1483). `report privileges` reads
  it as `sopuli.global_privileges`, which
  `sql/mariadb/global_privileges_view.sql` makes. It has `SQL SECURITY
  DEFINER`, and a locked definer that holds `SELECT` on `mysql.*`. The
  probe's own copy:

  ```sql
  CREATE USER 'sopuli_probe_gp_definer'@'localhost' ACCOUNT LOCK;
  GRANT SELECT ON mysql.* TO 'sopuli_probe_gp_definer'@'localhost';
  CREATE DEFINER = 'sopuli_probe_gp_definer'@'localhost'
    SQL SECURITY DEFINER VIEW sopuli_probe.global_privileges AS
  SELECT GRANTEE, PRIVILEGE_TYPE, IS_GRANTABLE
    FROM information_schema.USER_PRIVILEGES;
  ```

  With `SELECT` on it, the tool account reads each account's global
  privileges as the server applies them. They were the same as `SHOW GRANTS`
  for every account the probe made, on every release in the matrix, split
  privileges and `ALL PRIVILEGES` included, and `IS_GRANTABLE` was `YES`
  where the grant had `WITH GRANT OPTION`. The probe found no stored value in
  anything the tool account read.
  - **Not `global_priv`'s access bits.** The bit of each privilege is the same
    on every release, but an upgrade does not rewrite them, and the release
    that reads them decides what they mean. `SUPER` stored by 10.6.28 reads
    as `SUPER` there, as `SUPER` and `READ_ONLY ADMIN` on 10.11.19, and as
    `SUPER` and all ten split privileges from 11.4.13. Only the server knows
    which, so the tool would have to copy each release's rules. The view
    gives what `SHOW GRANTS` gives on each of those releases.
  - **Accounts only.** A role has no row, and a privilege an account holds
    through a role is not in the account's rows. The account shows `USAGE`.
  - **`GRANTEE` is `'user'@'host'`, and a quote in the name is not
    escaped**: `'sopuli_probe_gp_o'q'@'192.0.2.%'`. Compare it with the
    string built from `User` and `Host`, never split it.
  - **A definer with less than `SELECT` on `mysql.*` gives no error.** With
    `SELECT` on `mysql.global_priv` or `mysql.user` only, the view answers
    with one row, the definer's own. The tool account's own row is missing,
    and that is how to tell.
  - **Presence**, as for `account_state`: an absent view, an absent schema
    and a view without the grant answer `1142`, and a dropped definer
    `1045 (28000)` in a logged-in session. A view dropped while the tool
    account's grant on it is left answers `1146`.
  - **Cost.** About 525 accounts and roles: the whole view in 0.001 s or
    less.
- **Cost.** With about 510 accounts and roles and 1000 tables, after one
  untimed run, the role query took 0.16 s or less, and the table grants every
  account reaches through its roles 1.5 to 3.2 s.

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

**Who a `role:` rule admits.** The accounts that hold the role, granted to
them or to a role they hold, followed to the end through `mysql.roles_mapping`,
whether it is active or not (`10_role_reads_probe.py`, RR2). A role in the
chain is not admitted: a role cannot log in. `CREATE ROLE` grants the role to
the account that created it, with `ADMIN OPTION`, so that account holds it
too: usually root or the tool account. Where it holds a privilege §5 counts,
guardrail 9 refuses it for every UC-2 verb, `account suspend` and `account
expire-password` included (§5, #1272). For those two it refuses the session's
own account too. A reset still exempts it, as on MySQL: setting the tool's own
password hands over nothing, and guardrail 7 refuses it unless `--force`. A
role that `PUBLIC` holds, directly or through another role, is refused with
exit 9: every account holds it (RR3), and a rule that
admits every account is not a whitelist. MySQL refuses a mandatory role for
the same reason. `sopuli/driver/mariadb/roles.py` holds the rule.

**What the tool reads.** The `mysql.user` view gives the tool account the
plugin and the expiry of another account, and nothing else about its password
(`07_readable_state_probe.py`, RD1). A change of password, a rollover and a
lock leave everything it reads as it was (RD2 to RD5).

| Read from the view | Reported as |
|---|---|
| `plugin` | the refusal below |
| `password_expired` | expired. `PASSWORD EXPIRE` sets it, and the password then logs in and every statement but setting it answers `1820` (`04_lock_expiry_probe.py`, LK3) |
| `is_role` | whether the row is a role. Guardrail 9 reads a role's privileges from its row (§5) |

**What the tool never reads to change an account.** Each of these is only in
`mysql.global_priv` or in `SHOW CREATE USER`, beside the stored value, so
reading it would read every hash. The optional view `sopuli.account_state`
(§2.1, §2.4) gives the first three without a stored value. The reports and
`account list` read it, and no verb that changes an account does (#1491). It
does not give the fourth.

| Never read by a verb that changes an account | What the tool does instead |
|---|---|
| the lock, `account_locked` (LK2) | `account suspend` always sends `ACCOUNT LOCK` and reports `changed: true` ([#1267](../decisions/log.md#1267), decision 2). `account list` shows a locked account `LOCKED` where the view is readable, and `OPEN` or `EXPIRED` from `password_expired` alone where it is not |
| an open rollover, `auth_or` (`03_dual_password_probe.py`, DP4) | `creds finish-rollover` always sends the current value alone and reports `changed: true` ([#1271](../decisions/log.md#1271), decision 2) |
| when the password changed, and its lifetime (RD1) | a change is verified by login (§7), not by its time (decision 8) |
| a block after failed logins, `max_password_errors` (LK4, RD6) | `ACCOUNT UNLOCK` ends it. A reset never sends it, and a DBA unlocks by hand after checking for a suspension ([#1272](../decisions/log.md#1272), decision 1). `account list` adds `SOPULI-W063` for a target where it lists an account that is not locked ([#1500](../decisions/log.md#1500)) |

**The tool changes only `mysql_native_password` and `ed25519` accounts**
(decision 1). `doctor --check-privileges` names an account on `parsec`, or on
any other plugin. The driver refuses to describe it or change its password, and
names the plugin and the account, before it sends anything.
PyMySQL 1.2.3 has no client for `parsec` (`06_pymysql_login_probe.py`, PL1), so
a `parsec` password could be changed and never checked. The tool never moves an
account to another plugin: the change names the account's own plugin (§6).

**An account with a second method is not seen, and the gap is accepted**
([#1301](../decisions/log.md#1301)). An account can log in by two methods joined by `OR`, such as
`mysql_native_password` and `unix_socket`. The view shows one of them, the
same one as the top-level `plugin` in `mysql.global_priv`, and gives no sign
of the other. Only `auth_or` in `mysql.global_priv` and `SHOW CREATE USER`
show it, and the tool account reads neither (§2.2, §3). Measured by hand on
11.8.9, creating each account as root (#1301):

| Account | The view's `plugin` |
|---|---|
| `mysql_native_password OR ed25519` | `mysql_native_password` |
| `ed25519 OR mysql_native_password` | `mysql_native_password` |
| `unix_socket OR mysql_native_password` | `mysql_native_password` |
| `mysql_native_password OR unix_socket` | `mysql_native_password` |
| `unix_socket OR ed25519` | `ed25519` |

So the plugin check admits such an account. A password change sends one
method, which ends the other: a login by `unix_socket` stops working. No grant
closes the gap without reading every stored value. `doctor --check-privileges`
says so for a target that an application's `accounts:` are bound to, and the
DBA checks `SHOW CREATE USER` for the accounts the tool manages. The gap is
accepted for personal accounts too ([#1317](../decisions/log.md#1317)), where
a DBA's own socket login is the likely case. `account reset-password` warns
of it at plan time, `SOPULI-W065`, `--dry-run` included, and the row says the
same.

**A user name at an undeclared host is reported** by `doctor` (§2.3).

---

## 5. Guardrail 9: a managed account with a global privilege

The tool refuses to manage an account that holds, or can get through a role,
any of these:

- any global privilege but `USAGE`;
- any privilege on the `mysql` schema, one of its tables, or one of their
  columns or routines;
- any `PROXY` grant.

`sopuli.driver.mariadb.admin` reads them, and the driver reads them whenever it
describes an account. The refusal applies to `creds apply`, `creds rotate` and
`account reset-password`, except on the session's own account, which check 7
refuses instead ([#1270](../decisions/log.md#1270)). Unlike on MySQL, it also
applies to `creds finish-rollover`, whose close here sends the current
password's value and so changes the login: a refused account keeps its window,
no login is spent ([#1344](../decisions/log.md#1344)), and the run exits 4 or,
where `--account` named the account, 1 ([#1352](../decisions/log.md#1352)).
And it applies to
`account suspend` and `account expire-password`, which set no password, and
to the session's own account for those two: a `role:` rule admits a role's
creator (§4), and this is what stops one locking root or the tool account. It
also refuses an administrator declared by name; such an account is locked by
hand (#1272). `creds check` and `doctor` refuse nothing by it. Each finding
names the privilege and its object, and the role it comes through, such as
`PROCESS ON *.* through PUBLIC`.

No flag waives it. Nothing protects root on MariaDB (§1), so the tool account
can set the password of any administrative account, and the tool would then
know it. The rule is the one MySQL's check 9 applies
([`02-mysql-privileges.md`](02-mysql-privileges.md) §5,
[#1222](../decisions/log.md#1222)).

| Where | What it shows |
|---|---|
| the `*_priv` columns of the `mysql.user` view | static global privileges. `Repl_client_priv` is set by `BINLOG MONITOR`, which is `REPLICATION CLIENT` renamed (SP2) |
| `mysql.db` | privileges on a schema. A grant on a pattern that matches `mysql`, such as `mysq%`, counts. The columns differ between releases, so the tool reads every `*_priv` column there is |
| `mysql.tables_priv`, `mysql.columns_priv` | privileges on a table or column of `mysql` |
| `mysql.procs_priv` | privileges on a stored routine in `mysql` |
| `mysql.proxies_priv` | `PROXY` grants |
| `mysql.roles_mapping` | the roles an account holds, followed to the end, active or not. A role is a row of the view at host `''`, with `is_role = 'Y'`, so its global privileges read as an account's do (TG7, `10_role_reads_probe.py`, RR1) |
| the `PUBLIC` role | read for every account. Every account holds `PUBLIC`, always active: what it holds, and what a role granted to it holds, any account uses with no `SET ROLE` (RR3). So a grant to `PUBLIC` that check 9 counts refuses every managed account |

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
the account's plugin and sends:

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
**A password is at most 1024 bytes of UTF-8**
([#1270](../decisions/log.md#1270)). The server sees only the value, and a
password of 1 byte to 1 MiB is set and logs in with PyMySQL
(`09_password_length_probe.py`, PW1). The limit is for an application's client,
which was not measured. The driver refuses a longer password before anything is
sent. It also refuses an empty password, control characters, and text that
cannot be encoded as UTF-8, as the other drivers do. The server refuses a
malformed value with the plain `1396` (CH3). A new server loads only
`mysql_native_password`; `ed25519` must be installed with `INSTALL SONAME
'auth_ed25519'` (CH4). **With `simple_password_check` or
`password_reuse_check` loaded, the server refuses every value the driver
sends** while `strict_password_validation` is `ON`, which is its default. The
change fails with the plain `1396`, the answer a weak password gets
(`12_password_check_probe.py`, PC1, PC3). With it `OFF` the value is accepted
and neither plugin checks it (PC2, PC3). `cracklib_password_check` and other
plugins were not measured. An account with only `CREATE USER` reads
`@@strict_password_validation` and the loaded plugins from
`information_schema.PLUGINS` (PC4), and the session reads them with its scope.
Where an active plugin would refuse the value, the scope lacks
`password_value`, and `creds apply`, `creds rotate`, `creds finish-rollover`
and `account reset-password` refuse the target at plan time, exit 5, naming
the capability and the setting ([#1310](../decisions/log.md#1310)). The
driver asks again before it sends, and its refusal names the plugins. A DBA
who wants the tool to manage passwords on such a server sets
`strict_password_validation` to `OFF`. The plugin then still checks every
password sent in clear, and no longer refuses a value it cannot check.

**The value is sensitive.** A `mysql_native_password` value is an unsalted
SHA-1 hash. It allows an offline guess, and with one captured login handshake
it is enough to log in ([#1267](../decisions/log.md#1267), decision 4). Treat
it as the password: it is a `Secret`, and a server message that quotes the
statement is scrubbed before it is kept, as on MySQL
([`02-mysql-privileges.md`](02-mysql-privileges.md) §6).

**A rollover is `OR`.** MariaDB has no `RETAIN CURRENT PASSWORD`: it is a
syntax error, `1064` (DP1). Two methods joined by `OR` both log in, also
across two plugins, and the new value alone ends them (DP2, DP3, DP5). The
tool opens a rollover with
`IDENTIFIED VIA <plugin> USING '<new>' OR <plugin> USING '<old>'`, the new
value first, on the account's own plugin. It computes both values from the
passwords the vault holds (#1271). PyMySQL uses
only the first method of an `ed25519` `OR`, so the tool's login after the
change uses the new password (`11_rollover_expiry_probe.py`, RE5). A change
names every method the account keeps, so `creds apply` sends both values
again when it sets a held rollover's `pending` again. `creds finish-rollover`
sends the current value alone, which ends the old password and any expiry
(RE4). `PASSWORD EXPIRE` does not end a rollover (RE2).

**The other statements carry no password.** `ACCOUNT LOCK`, `ACCOUNT UNLOCK`
and `PASSWORD EXPIRE` need only `CREATE USER` (LK1 to LK4). A locked account
answers its password with `4151`, and a blocked one with `4150`. `account
reset-password` never sends `ACCOUNT UNLOCK`, because it cannot read whether
the account is locked by `account suspend` or blocked after failed logins
([#1272](../decisions/log.md#1272), decision 1). It sets the value with
`PASSWORD EXPIRE` in the same statement, so a failure leaves neither. `account
expire-password` sends `PASSWORD EXPIRE` alone, which does not end a second
method joined by `OR`: both passwords keep logging in, expired
(`11_rollover_expiry_probe.py`; decision 2).

---

## 7. Checking a password by login

The tool verifies a password by logging in as the account, over the target's
own TLS settings. PyMySQL logs in on `mysql_native_password`,
and on `ed25519` with PyNaCl, which the `mariadb` extra installs
(`06_pymysql_login_probe.py`, PL1 and PL3). The driver reports no
`offline_verify`: the stored value is in a column the tool account does not
read.

**The tool logs in only where no other account can answer the login**
([#1270](../decisions/log.md#1270), decision 3): the declared account is
`user@%`, it is the user's only account, and no anonymous account sits at a
named host. This is the MySQL driver's rule
([#1223](../decisions/log.md#1223)). Any other account is `unavailable`
without a login, and the detail names the other account. A failed login counts
toward `max_password_errors` on the account it reaches, and `creds check` and
a scheduled `creds apply` repeat.

**A change is verified only when `CURRENT_USER()` is the declared account**
([#1267](../decisions/log.md#1267), decision 8). Once per staged `pending` and
target, the login after a change logs in wherever a login may reach (decision
5). Before it, `creds apply` writes the `reached` mark beside the `pending` in
the vault (UC-1 §3), so a scheduled `apply` of the same `pending` does not
repeat it. If the mark cannot be written, no login is made. Such a login may
reach an account the config does not declare, the exception to invariant 5
that CLAUDE.md records. A login reaches the account the server matches from
the client's host, which need not be the declared one (ID1).
After the login, the tool reads `CURRENT_USER()`. Where it names another
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
| blocked after failed logins | `4150` (LK4) | `4150` once the block is set, measured on 11.8.9 with `max_password_errors = 1`; the failed logins that set it got `1045` (LK4) |

With PyMySQL 1.2.3 on 11.8.9, an expired account's first statement after login
gets `1820`, which is the tool's TLS read. With `disconnect_on_expired_password
= ON`, the right password gets `1862` at connect instead. An account with
`REQUIRE SSL` answers its right password with `1045` over a session without
TLS.

`1820`, `1862` and `4151` come only to the right password, but before the tool
can read `CURRENT_USER()`. `1045` does not say which account refused. The tool
logs in only where no other account can answer, so there each answer counts.
After a reaching login, where another account could answer, each is
`unavailable`, and the detail names the other account. `1045` is a `fail` only
where the target's `ssl_mode` requires TLS. `4150` answers any password, so it is
`unavailable` everywhere. On an `ed25519` account with `OR`, a rollover in
progress, PyMySQL 1.2.3 logs in only with the first method: the server asks
for a second authentication for the second method, and for a wrong password,
and PyMySQL fails itself with "received multiple auth switch requests"
(#1271; probe 11, #1304). That login is `unavailable` too, and stays so while
the `OR` is in place: it cannot tell a wrong password from the second
method's. `sopuli/driver/mariadb/verification.py` holds the rule.

A failed reaching login counts toward `max_password_errors` on the account it
reaches. That is an accepted cost of decision 8. It happens once per staged
`pending` and target, with the password just set.

**TLS.** The `mariadb` images of 11.4 and later start with TLS on. The 10.11
image starts with it off, and
PyMySQL, given a TLS context, refuses the login itself with `2026`
(`06_pymysql_login_probe.py`, PL2). A 10.11 target whose `ssl_mode` requires
TLS needs TLS turned on at the server.
