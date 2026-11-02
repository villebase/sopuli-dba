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
a member of a superuser role for the same reason.

A mandatory role, which the server gives every account, is read as any other
role is. The server refuses to make a role that holds `SYSTEM_USER` mandatory,
`3880`, and refuses to grant `SYSTEM_USER` to a mandatory role, `3897`. It
does accept `SYSTEM_USER` on a role already granted to a mandatory role, and
the tool account then reaches it (`07_own_grants_probe.py`, OG4 to OG6).

`SYSTEM_USER` protects only the accounts that hold it. An administrative
account without it is not protected, and the tool account can change its
password. A guardrail that refuses such an account as a managed account is
decided in [#1202](../decisions/log.md#1202) (open: #1222).

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
              password_last_changed, password_lifetime)
  ON mysql.user TO 'sopuli_admin'@'192.0.2.10';
```

`IDENTIFIED BY RANDOM PASSWORD` makes the server draw the password. The server
returns it once, in the statement's result, in the column `generated
password`. The statement text holds no password. The general log and
`performance_schema`'s statement history keep a statement's text as it was
sent (`01_password_text_probe.sql`), so a password written in the statement
would be kept there. Store the returned password where the target's
`admin.auth` reads it ([`01-configuration.md`](01-configuration.md)
§*`admin:`*).

The target's `admin.username` is the user name alone, `sopuli_admin`. The
server chooses the account by the host the tool connects from.

The column grant on `mysql.user` lets the tool read an account's plugin, lock
state and password expiry. It names columns, so the tool account cannot read
the stored hash, `authentication_string`, or `User_attributes`, which holds a
retained password's hash. The server refuses both with `1143`
(`05_identity_grants_probe.py`, TG5). Do not grant `SELECT` on the whole table
instead. No command reads accounts on MySQL yet (open: #1221).

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
`partial_revokes` prints, is not a finding for the refusal of §1.
