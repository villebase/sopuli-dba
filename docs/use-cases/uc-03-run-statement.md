# UC-3 — Run one statement across many targets

Depends on: `../design/00-principles.md`, `../design/01-configuration.md`,
`../design/02-oracle-privileges.md`, `../design/02-postgres-privileges.md`,
`../design/02-mysql-privileges.md`, `../design/02-mariadb-privileges.md`

This document specifies a command that runs one statement against a selected
set of declared targets and shows what each target returned. **UC-3 is built on
Oracle, PostgreSQL, MySQL, MariaDB and SQL Server.** The command name, `sopuli sql run`, is
a working name.
The parts were built in this order, each by its own issue:

| Part | Issue |
|---|---|
| The pure layer: the statement check, the plan fingerprint and the row guards | #1659, built |
| The `run_as:` configuration | #1660, built. The session check of §2 is part of the runner |
| The Oracle runner | #1661, built. `OracleSession.run_statement`, with `session_user()` for the check of §2 |
| `sql run` for reads | #1662, built |
| `--write` | #1663, built |
| What PostgreSQL does, measured | #1691, built. `sql/postgres/12_statement_run_probe.py` |
| The statement check's PostgreSQL dialect | #1692, built (§3) |
| The PostgreSQL runner | #1693, built. `PostgresSession.run_statement` |
| The refusal of a run-as role that holds the service role's privileges | #1700, built (§2) |
| `sql run` on PostgreSQL | #1694, built |
| MySQL and MariaDB: decisions | #1713, decided |
| The statement check's MySQL and MariaDB dialect | #1715, built (§3) |
| What MySQL and MariaDB do, measured | #1714, built. `13_statement_run_probe.py`, `18_statement_run_probe.py` |
| The MySQL and MariaDB runner | #1716, built. `StatementRunning` in `src/sopuli/driver/mysql_family/statement_run.py` |
| The refusal of a MySQL run-as account that holds the service account as a role, and of a write to a table without transactions | #1717, built (§2, §4) |
| `sql run` on MySQL and MariaDB | #1718, built |
| SQL Server: decisions | #1728, decided |
| The statement check's T-SQL dialect | #1730, built (§3) |
| The SQL Server runner | #1731, built. `StatementRunning` in `src/sopuli/driver/mssql/statement_run.py` |
| The statement list on SQL Server, and the refusal of a text that is not one statement of the run's kind | #1732, built (§2, §3) |
| What SQL Server does, measured | #1729, built. `17_statement_run_probe.py` |
| `sql run` on SQL Server | #1733, built |

`sql run` runs on every product the tool supports: Oracle, PostgreSQL, MySQL,
MariaDB and SQL Server. `sql.run` is not in the shared command set: each driver
lists it, so a driver added later runs it only once it has a runner and a
dialect. Until then a target of that product is refused at plan time by
`require_command`, with `SOPULI-20006`, never by a version check (invariant 4).
The umbrella issues are #1657 for Oracle, #1689 for PostgreSQL, #1712 for MySQL
and MariaDB, and #1727 for SQL Server.

---

## 1. Summary

**Goal.** A DBA often checks or changes one small thing on many databases: an
application setting in a table, a database parameter, a flag. Today the DBA logs
in to each target by hand, with a personal account or the application's owner
account, and runs the same statement each time.

UC-3 runs one statement against the targets a selector picks. It shows one
result for each target, which a person or a script can read. The statements are
small:

- mostly `SELECT` statements that return a few rows and columns;
- sometimes a write that turns a setting on or off: `UPDATE`, `INSERT`, `MERGE`
  or `DELETE`.

**Not in scope:**

- Statements declared by name in the config. They can be added later without
  changing this design.
- DDL, PL/SQL blocks, `ALTER SYSTEM`, and anything else that is not one query
  or one DML statement.
- Large results, paging and export. Rows are capped (§7).
- Closing every possible gap. This is a DBA tool, and the rights of the account
  it connects as are the real limit. The guards below catch the common
  slips: the wrong targets, and more rows than intended.

**It fails even if it works when:**

- it connects as UC-1's service account, or adds any grant to it. That breaks
  ADR-001;
- a write changes data on a target the operator did not see in the dry run;
- a write changes more rows than the operator expected, and the tool commits it.

**Why free-form statements.** The statement comes from a file or from stdin, and
is different every time, as a DBA's work is. Two other shapes were rejected.
Statements declared by name in the config would be reviewed before use, but
every new question would need a config change first. That is friction without a
matching gain, for the reason ADR-001 rejected the definer-rights package.
Free-form reads with writes only by name is the strongest guard on writes, at
twice the surface, and the plan fingerprint (§4) already covers the risk of the
wrong targets. Wrapping `sqlplus` was dropped: it may not be installed, and it
loses the run document, the selectors and the safety settings. The maintainer
decided this in #1657.

---

## 2. Who the tool connects as

**Never UC-1's service account.** UC-3 does not use the `admin:` credential. A
statement run as the service account would need whatever privilege that
statement needs, which breaks ADR-001. UC-3 adds no grant to any account
(`../design/02-oracle-privileges.md` §9).

**The run-as account has no default.** With no `run_as:` and no `--as`, the tool
refuses the run with exit 9, and the message names both ways to fix it. The
usual choice is the DBA's personal account, such as `dba_alpha`, set in a
`run_as:` block under `defaults:`. A DBA who wants the application's owner
account, or another account, names it in the config and puts its password in the
keyring.

**`run_as:`** is a block with the grammar of `admin:`
(`../design/01-configuration.md` §3a). It goes on a target or under `defaults:`.
It does not go on a group: a group carries only `match` and `safety`, as it does
for `admin:`. The allowed `auth:` methods are `keyring`, `prompt`, `external` and
`env`. `env` carries the same warning as it does for `admin:`: `SOPULI-W022`,
naming the run-as credential. `vault` is not
allowed, so that the tool never logs in with a password that a store holds for
another purpose. `--as USER` with `auth: prompt` covers a run that the config
does not configure. It asks once for the run, whatever the number of targets. A
`run_as:` with `auth: prompt` asks once for each place the file declares it, and
each user name: twenty explicit targets that inherit one `defaults.run_as` give
one prompt, but a `run_as:` written on each of two targets gives two, because two
databases may hold different passwords for one name. `--as`
needs a terminal on stdin, so the statement then comes from `--file`; a run
with `--as` and no terminal is refused with exit 2 before anything connects.

The password is read from the sources the tool already has for its own
credentials. It is never read from stdin, because `admin:` does not offer stdin
either, and so stdin stays free for the statement. It is never read from a store
that UC-1 manages, and UC-1 does not manage this account.

**A run that cannot get the password is refused before it connects.** A
`run_as:` with `auth: prompt` on a run with no terminal is refused with exit 8,
and a `run_as:` in the OS keyring on an install without the `keyring` extra
with exit 9, as the mutating commands refuse an `admin:` of either kind.

**A typed password that a target refuses is not tried again.** The account is
a person's, and its profile may lock it after a few failed logins. So when a
target refuses a password typed for `--as` or for `auth: prompt`, the tool
forgets it and connects no later target where a password would be typed for
the same user, compared by `upper()`. Those targets are reported
`NOT_ATTEMPTED`, with a message naming the user and the target that refused
the password. A typed password for another user was never refused, so it is
asked for and tried as usual. A password from the keyring, a variable or a
wallet is each target's own, and a refusal on one target does not stop the
others.

**Refusing the service account.** The tool checks the run-as account twice.

1. At plan time, from the config. A target whose run-as user name equals its
   `admin:` user name is refused. The comparison uses `upper()`, as invariant 5
   does. A wallet holds one credential for each alias, so a target whose
   `run_as` and `admin` are both `external` on the same `dsn` is refused too.
   The check reads the auth method. A user whose name is `external`, with a
   password, is an ordinary account: it is compared by name, and it is not a
   wallet login. The plan and the results write both as `external`, so they do
   not show which one a target used; the config does.
2. Before any statement runs, from the database. The tool connects to every
   selected target as the run-as account, reads
   `SYS_CONTEXT('USERENV','SESSION_USER')`, and compares it with the service
   account's user name from the config. One match refuses the run on every
   target, before any statement runs. The error is `SOPULI-20010`.

   On PostgreSQL a login role can hold another role's privileges without
   logging in as it, so two more reads refuse the run the same way. The
   tool reads `current_user`, which differs from the session user where the
   login role has a default role (`ALTER ROLE … SET role`), and refuses it
   when it is the service account. It also reads `pg_auth_members`, and
   refuses a login role that is a member of the service role, directly or
   through other roles, whatever the membership's `INHERIT` or `SET` option:
   a member without `INHERIT` can still take the role with
   `set_config('role', …)`. A superuser is not counted as a member, because
   it gains nothing from the service role. A superuser login whose default
   role is a member is refused, because its statements run as that member.
   Every role may read
   `pg_auth_members`. On Oracle one user is never granted to another, so
   neither read applies ([#1690](../decisions/log.md#1690)).

   On MySQL a role is an account, so the service account can be granted to
   the run-as account, and a default role gives a statement its privileges at
   login. The tool reads `information_schema.APPLICABLE_ROLES`, which any
   account may read for itself, and refuses the run the same way when the
   service account's user name is among the roles, directly or through other
   roles, active or not. A `GRANT PROXY` is not refused: a password login does
   not become the proxied account, and a login that does is refused by its
   name. On MariaDB a role is never an account, so the read does not apply
   ([#1713](../decisions/log.md#1713), Q1).

   On SQL Server the tool reads `ORIGINAL_LOGIN()` and `SUSER_SNAME()`, and
   refuses the run when either is the service login. One login is never
   granted to another, so there is no membership to read. A login acts as
   another only through `EXECUTE AS LOGIN`, which the statement check refuses
   as a first word and the statement list of §3 as a second statement. A
   `sysadmin` run-as login is not refused, though it holds `IMPERSONATE` on
   every login: refusing that would refuse the usual DBA login
   ([#1728](../decisions/log.md#1728), Q4).

   There is a gap here, and it is accepted. When `admin:` is `external`, the
   config holds no service-account name, so the session check has nothing to
   compare and does not run. The tool never opens a connection with `admin:` to
   learn the name, because UC-3 never uses that credential (ADR-001). The
   plan-time check still refuses `run_as` and `admin` both `external` on the
   same `dsn`. A `run_as` that names a user, on a target whose `admin:` is
   `external`, is not checked against the service account.

---

## 3. Reads and writes

A run is read-only unless the operator passes `--write`.

- **A read** runs in `SET TRANSACTION READ ONLY` and always ends with a
  rollback. The first keyword must be `SELECT` or `WITH`.
- **A write** needs `--write`. The first keyword must be `UPDATE`, `INSERT`,
  `MERGE` or `DELETE`. A write keyword without `--write`, and a read keyword
  with `--write`, are refused with exit 8 and `SOPULI-20009`. Exit 2 is only for
  argv that did not resolve, and it never comes with a run document. A
  `--write` without a row guard, and a `--write` without a selector, are pure
  argv errors and exit 2.
- **Everything else is refused at plan time:** DDL, `ALTER SYSTEM`, `BEGIN`,
  `DECLARE`, `CALL`, `EXEC`, `COMMIT`, `ROLLBACK`, `LOCK`, and more than one
  statement. A refused statement exits 8 with `SOPULI-20009`.

**The keyword check.** The tool skips leading whitespace and comments (`--` and
`/* */`) and compares the first word with `upper()`. It refuses a `;` anywhere
except one at the end, which only comments may follow. A `;` inside a string literal is a known false refusal,
and it is acceptable.

**Each product reads comments and literals its own way.** The check scans by the
rules of the target's product. On Oracle, a block comment ends at the first
`*/`, and `q'[...]'` is a literal. On PostgreSQL, block comments nest, and
`$$...$$`, `$tag$...$tag$` and `E'...'` are literals. In an `E'...'` literal,
`\'` does not end it, and a part that continues it on a later line keeps that
rule. So `/* /* */ SELECT */ DELETE FROM t` is a `SELECT` on
Oracle and a `DELETE` on PostgreSQL. A run over both products checks the
statement once for each. If one check refuses it, it is refused. If the two
give a different text or a different first word, it is refused too, because
the plan fingerprint and every target need one text.

MySQL and MariaDB share one set of rules. `#` starts a comment, and `--` starts
one only before whitespace, a control character or the end of the text, so
`SELECT 1--1` is arithmetic. A block comment ends at the first `*/`. `'...'`
and `"..."` are strings in which `\` escapes the next character, and
`` `...` `` is a name. `/*! ... */`, `/*!NNNNN ... */` and MariaDB's
`/*M! ... */` look like comments, but the server runs the text inside them, so
the check refuses each one anywhere outside a literal. `INTO OUTFILE` and
`INTO DUMPFILE` write a file on the database server, which no transaction
covers, so the check refuses them too (#1713, Q4). The server's `sql_mode`
decides whether a backslash escapes a quote (`NO_BACKSLASH_ESCAPES`) and whether
`"..."` is a name (`ANSI_QUOTES`), and the tool cannot see it before it
connects. So the check reads the statement each way a server can: with
backslash escapes in `'...'` and `"..."`, with none, and with `ANSI_QUOTES`
alone, where `"..."` is a name with no escapes and `'...'` keeps them. It
refuses what any reading refuses, and a statement that two readings cut
differently. A `\'` followed by a comment after the
terminator is then a false refusal; `''` reads the same way in both.

SQL Server's rules are T-SQL's. Block comments nest, as on PostgreSQL, and
`--` always starts a comment. `'...'` and `N'...'` are strings in which `''`
is one quote and a backslash is an ordinary character. `[...]` is a name, in
which `]]` is one `]`, and so is `"..."`. `#` starts no comment: `#t` is a
temporary table. A `WITH` is classified by the statement it leads to, the
first `SELECT`, `INSERT`, `UPDATE`, `DELETE` or `MERGE` outside brackets, so
`WITH c AS (...) DELETE FROM c` is a write, refused without `--write`. `GO`
alone on a line, or with a count, ends a batch in sqlcmd and SSMS. The server
does not read it that way: `GO` is not a reserved word, so `SELECT 1` and a
`GO` line run as `SELECT 1 AS GO`. So the check refuses a `GO` line by name,
a false refusal where it was meant as an alias. T-SQL needs no `;` between two
statements, so `UPDATE t SET a = 1 DELETE FROM u` is two, and refusing a
`;` cannot refuse the second. On SQL Server the server's own list of the
statements does that, before any statement runs
([#1728](../decisions/log.md#1728), Q1).

**The statement list on SQL Server.** After the session check of §2, and
before any statement runs on any target, the tool sends `SET SHOWPLAN_ALL ON`,
the statement, and `SET SHOWPLAN_ALL OFF` on each SQL Server target. Under
`SHOWPLAN_ALL` the server compiles the batch, runs none of it, and lists each
statement with its type. A read passes as one `SELECT`, and a write as one
`UPDATE`, `INSERT`, `DELETE` or `MERGE`; a `WITH` has its main statement's
type. Anything else refuses the run on every target with `SOPULI-20009`, a
read as well as a write: two statements, a `SELECT … INTO`, which makes a
table, and a write keyword that the server reads as a `SELECT`. The message
names the target and what the server read. A statement that a function or a
procedure runs is not counted as one of the batch's. A `DECLARE` with no value
has no row of its own, and passes: it declares a variable that ends with the
batch. The run-as login needs `SHOWPLAN` in each database the statement names
(`../design/02-mssql-privileges.md` §8); a server that refuses the check, as
with `262` for a login without it, refuses the run too. `--timeout` bounds the
check. Measured on 16.0.4325.4 (#1729, #1732).

On MySQL and MariaDB a read runs in `START TRANSACTION READ ONLY`, and the
server refuses a write with `1792`, `SELECT ... FOR UPDATE` and a `WITH` that
writes among them. As on Oracle, DDL commits before it runs, so the keyword
check is the only guard against it. The server refuses two statements in one
text with `1064`. The gaps are a session's effects that outlive the rollback:
a user lock (`GET_LOCK()`), a user variable (`SELECT ... INTO @v`, which is
refused because it returns no rows), and a write to a table without
transactions (§4). Measured on MySQL 8.0.46, 8.4.13 and 9.7.4 and MariaDB
10.11.19, 11.4.13, 11.8.9 and 12.3.3 (`13_statement_run_probe.py`,
`18_statement_run_probe.py`).

SQL Server has no read-only transaction. A read runs in `BEGIN TRANSACTION`
with `XACT_ABORT ON`, and always ends with a rollback, as a write does that
does not commit ([#1728](../decisions/log.md#1728), Q2). The rollback undoes
DDL and a `GRANT` too, unlike on Oracle and MySQL. It does not undo a
sequence's `NEXT VALUE FOR`, an identity value, a table variable's rows, or
an application lock a session holds (`sp_getapplock`). The statement runs in
`master`, where every login the tool makes lands, and names another
database's objects by three-part names, such as `acme.dbo.orders`
([#1728](../decisions/log.md#1728), Q3). A `SELECT … INTO` returns no rows,
and is refused when it runs. A write on a loopback linked server inside the
transaction is refused, `3910`, but that is the loopback's own limit: with
MSDTC, a write on a linked server to another host may join the transaction,
so `sql run` does not rely on the refusal. Measured on 15.0.4510.2,
16.0.4325.4, 17.0.5065.9 and 16.0.1000.6 (`17_statement_run_probe.py`,
#1729).

On PostgreSQL, `standard_conforming_strings = off` lets `\'` escape a quote in a
plain `'...'` literal too. The tool cannot see the setting, and it has been on
by default since PostgreSQL 9.1. A wrong reading can only cut the text inside a
literal, and the server then refuses the statement as unterminated.

On PostgreSQL, two statements pass the keyword check as reads although they
write. `SELECT ... INTO t2` creates a table, and a `WITH` whose query is an
`UPDATE`, `INSERT` or `DELETE` changes rows. A read runs in a read-only
transaction, so the server is what refuses them. With `--write`, both are
refused as reads. What the server refuses, and with which code, is in
*On PostgreSQL* below.

**Why the keyword check exists.** Oracle commits before any DDL, so
`SET TRANSACTION READ ONLY` does not stop DDL. The keyword check does.

**The autonomous-transaction gap.** A function that uses an autonomous
transaction, called from a `SELECT`, gets past both guards. The read-only
transaction does not cover an autonomous transaction, and the keyword check sees
only a `SELECT`. Work that transaction commits is not undone by the rollback.
A `SELECT seq.NEXTVAL FROM dual` also runs in a read-only transaction and moves
the sequence (measured on 23.26.3.0.0); `SELECT ... FOR UPDATE` does not, because
the server refuses it with `ORA-01456`. This is accepted. The rights of the
run-as account are the real limit, as §1 says.

**On PostgreSQL** a read is declared as a cursor in `BEGIN READ ONLY`, so
two guards on the server stand behind the keyword check. The cursor takes one
query: it refuses two statements, `SELECT ... INTO` and DDL with `42601`, and
a `WITH` query that writes with `0A000`. The read-only transaction refuses
`nextval()`, `SELECT ... FOR UPDATE` and a function that writes with `25006`
(`0A000` for a `STABLE` function). A write is sent as a prepared statement,
which the server refuses with `42601` when the text holds two. PostgreSQL does
not commit before DDL, so the transaction would cover DDL too. Measured on
releases 13 to 18 (`../measurements.md`, `12_statement_run_probe.py`), and the
cursor's refusals on 16.15 (#1693).

The gap is any function whose effect is outside the transaction, which the
rollback does not undo. `dblink_exec()` writes through another connection,
and once the `dblink` extension is in a database, any role there may call it;
a role that is not a superuser gives a password in its connection string.
`pg_cancel_backend()` and `pg_terminate_backend()` end another session's work,
`pg_reload_conf()` reloads the server's configuration, and a session advisory
lock, `pg_advisory_lock()`, is still held after the rollback. Each runs in a
read on 16.15, where the run-as account has the right to call it. This is
accepted, for the reason above.

**`readonly: true`** (`../design/00-principles.md`) refuses `--write`, with or
without `--dry-run`, with exit 8. It does not refuse a read, and `--dry-run`
without `--write` runs the read as usual. A `safety:` block on a target, or on
a group that matches one, applies to a write that selects that target. A write
binds no account, so every selected target counts as reached for `readonly`,
and every selected target of a product `sql run` runs on counts for
`max_targets` (§5). The refusal offers a read without `--write` instead.

---

## 4. Guards on a write

### More rows than intended

`--write` needs a row guard: `--expect-rows N` (exactly N) or `--max-rows N`
(at most N). Each guard applies to each target on its own. A write without a
guard is refused at plan time.

On each target the tool runs the statement, reads the affected row count, and
commits only if the count passes the guard. Otherwise it rolls back and reports
that target as refused by the guard.

`--dry-run` does the same on every target and always rolls back. So a dry run
shows the real row counts. It does not stop at a failing target: it runs every
selected target and reports every count. Only a real write stops at the first
failure (§5). A dry run offers the `--plan` to run it with only when every
target connected and passed its guard, and then says when the real run will
ask for a confirmation (`confirm_environments`). Otherwise, where a target
did not connect, it says that a real run would be refused, and names those
targets and then the others that did not pass. A target that logged in and
then failed, such as on the identity read, did not pass, but it did connect.
Where every target connected, it names the targets that did not pass and the
target where a real run would stop. Where no selected target is of a product
`sql run` runs on, it says nothing would run. The run document carries the
fingerprint in every case.

A dry run is not free of effects. A trigger, a sequence's `NEXTVAL` and an
autonomous transaction commit their own work, and the rollback does not undo it.
Row locks stay held until the rollback.

### Wrong targets

`--write` needs an explicit selector. With no selector, a write means no
targets, never all of them. `max_targets` applies unchanged (invariant 10).
`confirm_environments` asks only on a real run.

**The plan fingerprint.** A dry run prints a short hash of these things:

- the normalised statement text;
- the row guard: its kind (`expect` or `max`) and its value;
- the sorted list of resolved targets, each with its name, its `dsn`, the
  user its session became, and its database identity, read when the tool
  connects. On Oracle that is `DB_UNIQUE_NAME` and `CON_NAME`, and on
  PostgreSQL the cluster's `system_identifier` and `current_database()`. On
  MySQL it is `@@global.server_uuid` and `DATABASE()`, and on MariaDB
  `@@global.server_uid` and `DATABASE()`; a session with no default database
  has `""`. MariaDB's `server_uid` changes at each restart, so a restart
  between the dry run and the real run changes the hash, and the operator runs
  the dry run again. On SQL Server it is `SERVERPROPERTY('ServerName')` and
  `DB_NAME()`, which is `master`, so an Availability Group failover between
  the two runs changes the hash too. Where
  a PostgreSQL session starts as another role, that role is in the hash too,
  so a default role set between the dry run and the real run changes it. On
  MySQL and MariaDB the account the server matched, `user@host`, is in the
  hash, so a login that reaches another account of the same user changes it.
  The session user is what the
  database reports, so an `external` login that reaches another user changes
  the hash. A target that did not connect, or that failed after it logged in,
  has its configured run-as name, or `external`, and no identity. A target of
  another product has neither a user nor an identity.

**Normalisation.** The tool turns CRLF and CR into LF. It removes trailing
ASCII whitespace (space, tab, line feed, form feed, vertical tab), one trailing
line that holds only `/`, and one trailing `;`, and the whitespace around each
of them. Comments (`--` and `/* */`) that follow the `;` or the `/` line, in
any order, are removed with it, so `SELECT 1 FROM dual; -- note` runs. Text
after the terminator is not part of the statement, as in SQL\*Plus. The removed
comment is not in the text sent to the server, and it is not in the plan
fingerprint. A write whose `WHERE` is commented out after the terminator runs
without it, and the row guard, which a write needs, is what stops it. A
comment after a statement with no terminator stays in the text, and a statement
after a comment that follows a `;` is still refused. The scan reads string
literals, quoted names and `q'[...]'` literals whole, so a `--` or `/*` in one
is not a comment. On PostgreSQL the scan reads dollar quotes and `E'...'`
literals whole instead of `q'[...]'`, and a nested comment ends at its own
`*/` (§3). On MySQL and MariaDB it reads backtick names whole, and `#` is a
comment, and so is `--` followed by whitespace, a control character or the
end of the text (§3). On SQL Server it reads `[...]` names whole, and a nested
comment ends at its own `*/`. The trailing `/` line is removed on every product, so one
statement reads the same way on a run over more than one. A `/*` that never
closes after the terminator is refused as an unclosed comment. A second line that holds only `/`, left at the end, is
refused, and so is a `;` still left in the text. A `/` inside the statement, such as a
division, stays. Nothing else changes: case, whitespace and literals inside the
statement stay as written.

Both the dry run and the real run connect to every target first, check the
session user (§2), and read the database identity. They compute the hash before
any statement runs anywhere. A TNS alias that points at another database then
changes the hash. A target that could not be connected is in the hash with no
identity, so a target that was down in the dry run and is up in the real run
changes it too.

A real `--write` run must be given `--plan HASH`. It is refused at plan time,
with `SOPULI-20011` and exit 8, as `readonly` and `max_targets` are, when the
hash it computes differs. The hash differs when the config adds a target, when a
target points at another database or another account, when the row guard
changes, and when the statement differs by one character that normalisation
keeps. A real `--write` without `--plan` is an argv error, exit 2. A dry run
given `--plan` says whether it matches the dry run's hash, and changes nothing
else. Where `confirm_environments` asks, it asks after the hash matched and
before any statement runs.

A write that affects 0 rows is rolled back, and reports `changed: false` (§6).

### A table without transactions

On MySQL and MariaDB a table's engine may have no transactions: MyISAM, Aria,
MEMORY and others. A rollback does not undo a change to such a table, so a dry
run, or a write its guard refuses, would leave the rows changed. So a write,
dry or real, is refused before any statement runs on any target where it names
such a table that the run-as account can see. It names one where it writes
`schema.name`, with backticks or double quotes or neither, or where it writes
the name alone and the session's default database holds it. The statement is
read each way a server's `sql_mode` can read a backslash, as in §3. The refusal
exits 8 with `SOPULI-20009` and names each table and its engine. A column or an
alias with such a table's name is refused too. The check sends one read of
`information_schema`, bounded by `--timeout`; a read that fails refuses the run
as well. It does not ask `EXPLAIN`: `EXPLAIN` names an alias, the alias inside
a view's own definition too, and MariaDB's can run a stored function that
writes. A view's base tables are often hidden from the run-as account, so the
check cannot name them.

A trigger or a function can still write such a table, and on MariaDB so can a
write through a view. The rollback then tells: the server warns `1196`, and the
target is `ERROR` with `outcome_unknown: true`, because the rows changed
although nothing was committed. The warning is read before the tool's rollback
too, for a transaction the server rolled back itself, as on a deadlock. A write
whose connection is lost while it runs, as at `--timeout` on MySQL, is treated
the same way: the server rolls it back, and its warning cannot be read. The run
stops there, a dry run included, and a dry run counts the target as changed in
its exit code ([#1713](../decisions/log.md#1713), Q3). A Ctrl-C does not wait
for the warning: an interrupted dry run says nothing was committed, which is
true, and that such a table may still have kept a change, so to check the rows
before a dry run again. Oracle and
PostgreSQL roll every table back, and refuse nothing here.

### Lock waits

A write, dry or real, sets a call timeout on its session, so a row that the
application holds locked cannot hang the run. The target that times out fails,
and the write stops there (§5). On Oracle the client closes the connection when
the timeout fires, and the server rolls this statement's transaction back once
it ends the session. The rollback does not undo an autonomous transaction (§3).
A session that waits on a lock ends when the wait does. The session reports
`connection_lost`, and nothing more can be sent on it. The client reports
`DPY-4011`, with `ORA-03156` in its message, and the tool keeps both. The
timeout does not bound the commit, so a commit is never abandoned half done.

On PostgreSQL the timeout is `statement_timeout`, set for the statement's
transaction only. Where the role or the database already has a lower one, the
lower one stays. It counts the time a statement waits for a lock. The server
cancels a statement past it with `57014` and rolls its transaction back, and
the session stays usable. No timeout bounds the commit. A commit the server
refuses, such as on a deferred constraint, was rolled back, so its outcome is
known. Only a commit whose connection is lost has `outcome_unknown: true`
(§5).

On MariaDB the timeout is `max_statement_time`, which bounds every statement
and counts a lock wait. The server ends a statement past it with `1969`, and
the session stays usable. On MySQL, `max_execution_time` bounds a `SELECT`
alone, a locking `SELECT`'s wait for a row lock included (`3024`), and
`innodb_lock_wait_timeout` and `lock_wait_timeout`, in whole seconds, bound a
write's wait for a row or a table lock (`1205`). Nothing on the
server bounds a long write, so the client's read timeout does, one second past
the lock timeouts. It closes the connection, and the server finishes the
statement and then rolls it back. On both, a lower bound the account already
has stays, `--timeout` replaces the tool's own query budget for the
statement, and the session's own values come back after it. The tool reads
its own queries in UTC, but the statement runs in the server's own time zone,
`@@global.time_zone`, so `NOW()` and a `TIMESTAMP` value mean what they mean
in the operator's own client. After
`1205` or `1969` the server leaves the transaction open, and the tool rolls it
back. No bound is left on the commit: on MySQL a commit the client lost to its
read timeout still commits. A commit whose connection is lost has
`outcome_unknown: true` (§5). Measured on MySQL 8.0.46, 8.4.13 and 9.7.4 and
MariaDB 10.11.19, 11.4.13, 11.8.9 and 12.3.3 (`13_statement_run_probe.py`,
`18_statement_run_probe.py`, #1714).

On SQL Server no server setting bounds a statement. `SET LOCK_TIMEOUT` bounds
a wait for a lock (`1222`), and the client's query timeout, one second past
it in whole seconds, bounds the call (`HYT00`). A lower `LOCK_TIMEOUT` the
login already has stays. With `XACT_ABORT ON` either one rolls the
transaction back and releases its locks, and the session stays usable. A
deadlock's victim (`1205`) is rolled back too. No bound is left on the
commit. The row count is `@@ROWCOUNT`, the statement's own: pyodbc's count
comes first from a trigger that changes other rows. A commit whose
connection is lost has `outcome_unknown: true` (§5). Measured on 15.0.4510.2,
16.0.4325.4, 17.0.5065.9 and 16.0.1000.6 (`17_statement_run_probe.py`,
#1729).

---

## 5. Order and failure

Targets run one after another, sorted by name. Each write commits on its own
target. There is no atomic commit across targets.

**A real write runs only when every selected target connected.** The tool
connects every target before any statement runs. If one did not connect,
whether it could not be reached, refused the login, or was not tried because
another target refused the same typed password (§2), the write could not
finish everywhere. So the tool refuses the run with exit 8, names each target
that did not connect, closes every session, and runs nothing. Committing on
the targets before it would leave a partial change the tool could have
avoided. A dry run never commits, so it runs every connected target and
reports the others.

**A real write stops at the first target that fails while it runs**, by its row
guard, a database error or a timeout. The targets after it are reported as not
attempted. A guard that fails on a real run means the data changed since the dry
run. The operator fixes the cause, dry-runs the remaining targets again, and runs
again.

A run where some targets committed and others did not exits `4` (partial
success), and its output names each target's outcome. A run where every target
committed, or affected 0 rows and rolled back, exits `0`. A run where no target
committed exits `1`, unless a rollback kept a change to a table without
transactions (§4): rows changed there, so it exits `4`. A dry run exits `0`
when every target passed its guard, `4` when some did or a rollback kept a
change, and `1` when none did. A target of another product is
`SKIPPED` (`SOPULI-20006`). It does not stop a real write, and the exit code
leaves it out; a run where every target is one exits `5`. Nothing runs on it,
so the plan leaves it out too, and it counts for neither `max_targets` nor
`confirm_environments`.

**A commit that fails has an unknown outcome.** The statement ran and the
commit was sent, so the change may have taken effect. On PostgreSQL this
holds only where the connection was lost: a commit the server refused was
rolled back, and is an ordinary `ERROR` (§4). The target is `ERROR`,
with a message that says the outcome is unknown and to check the rows before
running again, and the server's code and message. Its result in the run
document has `outcome_unknown: true`, so a script need not parse the message.
The run stops there, and the exit code counts the target as possibly
committed: a failed commit on the first target exits `4`, not `1`.

**An interrupt keeps the record.** When Ctrl-C stops a real write, the
targets that finished keep their outcome. The target in flight is `ERROR`,
with `outcome_unknown: true`, because whether it committed is unknown, and
the targets after it are `NOT_ATTEMPTED`. The tool prints them to stderr
before it exits, and under `--output json` the run document holds them in
`results[]`, and its `summary` counts them. The exit code is `8`, as for any
abort and for every verb, even when some targets committed. Exit `8` here does
not mean nothing ran: `results[]` and `summary` say what did.

On MySQL and MariaDB a rollback that could not undo a change to a table
without transactions has `outcome_unknown: true` too, a dry run's included,
and stops the run (§4). Every other write result has `outcome_unknown: false`,
a dry run's included, because a dry run commits nothing. A read's results do
not have the field.

**A read does not stop.** It reports every target it could read, and the ones it
could not. It exits `0` when every target answered, `4` when some did and some
did not, and `1` when none did. A target of another product is left out of
these, and a read where every target is one exits `5`.

---

## 6. Invariants, read for UC-3

**Invariant 5: the config is the whitelist for changes.** UC-3 changes data,
never accounts: DDL is refused, so a write cannot change an account. For UC-3,
the config is the whitelist of the targets it may connect to, not of the rows it
may touch. Selectors filter the declared targets and cannot extend them.

UC-3 adds one reading exception. `sql run` reads whatever the run-as account may
read, so a statement can list accounts that the config does not declare. The tool
lists nothing on its own. The operator's statement and the account's own grants
decide what is read. The exception is recorded in CLAUDE.md and in
`../design/00-principles.md`, with the reasons in
[#1658](../decisions/log.md#1658).

**Invariant 9: a write does not converge.** The tool cannot see whether a
statement has already taken effect. Oracle reports the rows a statement matched,
not the rows it changed. A second `UPDATE t SET flag = 1` commits again and
reports the same count. So a committed write that affects more than 0 rows
reports `changed: true`, every time. A write that affects 0 rows is rolled back,
and reports `changed: false`, because the count proves nothing changed. The verb
is outside the rule, like `creds generate` and `account reset-password`. A DBA
who wants a repeatable write writes one, for example with `WHERE flag = 0`. The
exception is recorded in `../design/00-principles.md` and in CLAUDE.md, with the
reasons in [#1658](../decisions/log.md#1658).

**Invariant 8: `--dry-run` and a plan.** A write prints its plan first and
supports `--dry-run`. A read changes nothing and needs neither.

**Invariants 3 and 4: capabilities, refused at plan time.** The statement
check, the missing row guard, the missing selector and the plan fingerprint all
refuse at plan time, before any target is touched.

**The run lock is not taken.** The run lock (P5, Q2) is keyed on a vault secret
path. UC-3 writes no vault document, so there is nothing to lock. A write that two operators start at the
same time is guarded by the row guard on each target, and by the database's own
row locks. The plan fingerprint tells each operator which targets and statement
they ran.

**Invariant 1: secrets never in argv.** The statement is a file or stdin, never
an argument, which also spares the operator from shell quoting. The run-as
password comes only from the sources in §2.

**Invariant 2: redaction.** The statement is not a secret. It is shown in the
plan, in the text output and in the run document, so the operator sees what the
fingerprint covers. A statement that holds a secret is the operator's mistake,
and the tool does not look for one.

**Audit.** The run document and the `jsonl` events are the record. There is no
separate audit stream. A committed write carries the run's plan fingerprint
and, for each target, the row count and the outcome. A read changes nothing and
adds no mutation record.

---

## 7. Output

- **Text:** one block for each target, or one table with a target column when
  every target returns the same columns.
- **JSON:** a new `results[]` shape for `sql run` in the run document. It holds
  the columns, the rows, the row count, a truncated flag and the outcome for each
  target. This is a minor schema bump, and a sample is checked against the schema
  (invariant 12).
- **Row cap.** The tool returns up to 100 rows for each target by default.
  `--max-result-rows` changes the cap, for a read only: a write returns no
  rows, so `--write` refuses it as an argv error. A truncated target is marked in the
  output.
- **Value types.** Dates, numbers and LOBs become strings or numbers that JSON
  can carry. A LOB is read as text or bytes, cut at 4000 characters or bytes,
  and the target is marked truncated when one was cut. Oracle `NUMBER` is read
  as a `Decimal`, so a value with a scale is not rounded to a float. On
  PostgreSQL, `numeric` is a `Decimal` too; `json` and `jsonb` are the server's
  text, so a number in one is not rounded; an array and a record are JSON text;
  a date or time that Python cannot hold, such as `infinity` or a BC date, is
  the server's text; and any value whose text is longer than 4000 characters,
  or a `bytea` longer than 4000 bytes, is cut. On MySQL and MariaDB, `DECIMAL`
  is read as a `Decimal`, so a whole value is a JSON number and any other is
  its text, such as `"1.50"`; `JSON`, `ENUM`, `SET` and a zero date are the
  server's text;
  `TIME` is an ISO 8601 duration, so a negative one and one past 24 hours keep
  their value; `BIT`, the binary types and a geometry are hex; and a text
  longer than 4000 characters, or a binary value longer than 4000 bytes, is
  cut. A write's row count is the rows it matched, as on Oracle and
  PostgreSQL, so `UPDATE … SET v = 1` counts a row whose `v` is already 1
  (#1713, Q2).

---

## 8. Decisions

| Question | Answer |
|---|---|
| Which account does the tool connect as? | The run-as account, never the service account (§2) |
| May a statement change data? | Yes, with `--write`, a row guard, a selector and a plan fingerprint (§3, §4) |
| What does `--dry-run` mean for SQL the tool does not parse? | It runs the statement on every target and always rolls back, so it shows real row counts. Triggers, sequences and autonomous transactions can still commit their own work (§4) |
| What is a result when targets return different rows? | One result for each target (§7) |
| Does it take the run lock? | No. There is no vault document to lock (§6) |
| Is it convergent? | No. A committed write that affects rows reports `changed: true`; a write that affects 0 rows is rolled back and reports `changed: false` (§6) |

The maintainer decided these in #1657.
