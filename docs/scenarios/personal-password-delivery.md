# Scenario: reset a person's password and hand it over

A developer cannot log in to their own database account. The password expired,
and they no longer know it. You are the DBA. This document follows one reset
from start to finish: find the account, preview the reset, set a new password,
and get it to the person.

The hard part is the last step. The tool gives you several ways to hand the
password over. They do not make the same promise, so this document shows each
one and then helps you choose.

It picks up where [getting-started.md](../getting-started.md) stops. If you have
not written a config file yet, start there.

Every command and every block of output below is from real runs against the
project's own test containers and a 1Password test account, on 2026-10-30, with
sopuli built from `main` after 0.82.0. The account is `acme_dev_alice` in
`FREEPDB1`. `acme` is a fictional application name this project uses
throughout its documentation. Passwords, tokens, links and keys are replaced
with `<PASSWORD>`, `<TOKEN>`, `<LINK>`, `<ID>` and `<KEY>`.

---

## Two ways to hand a password over

A *personal account* is a database account that a person logs in with, as
opposed to an account an application uses. No vault holds its password as the
master copy. The password belongs to the person, and the tool keeps no copy of
it.

A reset takes one of two paths:

| Path | You see the password | How the person gets it | The password is expired |
|---|---|---|---|
| **unseen**, the default | no | they fetch it from a place meant for them alone | no |
| **seen**, `manual` | yes | you pass it on | yes, so they must change it at first logon |

**Use the unseen path when you can.** On it, nobody but the person is meant to
read the password, so it does not need to be expired. On the seen path you know
a working password until the person logs in and changes it.

`delivery.method` in the config chooses the method. Sections 3 to 7 show each
one. Section 8 helps you choose. Section 9 adds a message that tells the person
a password is waiting.

---

## The config this uses

One person, one database. The file holds a block for each delivery method, and
`delivery.method` selects one of them. The tool ignores the blocks that are not
selected, so you switch methods by changing one line. Save it as `sopuli.yaml`,
outside the repository.

```yaml
version: 1

vaults:
  vault-dev:
    type: hashicorp
    addr: http://127.0.0.1:8200
    mount: kv
    kv_version: 2
    auth: { method: token }

  # The same Vault, with a token that can write the person's path but not
  # read it. Only `vault_path` uses it.
  vault-handover:
    type: hashicorp
    addr: http://127.0.0.1:8200
    mount: kv
    kv_version: 2
    auth: { method: token, token: { env: SOPULI_VAULT_TOKEN_HANDOVER } }

defaults:
  vault: vault-dev

targets:
  - name: free-pdb
    type: oracle
    environment: dev
    dsn: "127.0.0.1:1521/FREEPDB1"
    admin: { username: SYSTEM, auth: { method: env } }
    oracle: { scope: pdb, container: FREEPDB1 }

policies:
  personal-standard:
    password:
      length: 20
      charset: alnum_safe
      first_char: alpha
      require: { upper: 1, lower: 1, digit: 1, special: 1 }

personal_accounts:
  - accounts: [acme_dev_alice]
    policy: personal-standard

delivery:
  method: vault_wrapped

  vault_wrapped:
    ttl: 15m

  vault_path:
    ttl: 8h
    prefix: personal
    vault: vault-handover

  one_time_link:
    base_url: http://127.0.0.1:1337
    ttl: 1h

  onepassword_share:
    onepassword_vault: sopuli-test
    ttl: 1h
    token: { file: ~/.config/sopuli/op-sa-token.txt }

  manual:
    force_expire: true

reset_records:
  vault: vault-dev
  prefix: sopuli/personal-resets
```

Set the credentials the run needs. None of them is written in the file, and none
is ever a command-line option:

```bash
export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_TOKEN=sopuli-test-root
export SOPULI_VAULT_TOKEN_HANDOVER=sopuli-test-personal-writer
export SOPULI_DB_ADMIN_PASSWORD=sopuli-test
```

`vault-handover` is the same Vault as `vault-dev`, with a narrower token. Section
4 says why `vault_path` needs one.

**`reset_records:` is the record of each reset**: who reset which account, when,
and how the password was handed over. It never holds the password. While a reset
runs, the tool also holds a lock beside the record, so two DBAs cannot reset one
account at the same time.

---

## 1. See which accounts you can reset

`personal_accounts:` is a list of the accounts the tool may reset. The tool never
resets an account that the list does not declare. `account list` shows the
declared accounts as the database sees them, and changes nothing:

```bash
sopuli --config sopuli.yaml account list
```
```
ACCOUNT         TARGET    DECLARED BY  STATUS  DB_PW_CHANGED  RESET_AT
ACME_DEV_ALICE  free-pdb  names        OPEN    2026-10-30     -

1 declared account, 1 on the selected targets
```

`ACCOUNT` is the name as the database stores it. `STATUS` is the database's own
account status. `RESET_AT` is empty, because the tool has not reset this account
yet.

---

## 2. Preview the reset

Add `--dry-run` to see what a reset would do. It reads the account's state from
the database, and changes nothing:

```bash
sopuli --config sopuli.yaml account reset-password --account acme_dev_alice --dry-run
```
```
Plan: 1 account x 1 target = 1 account   [dev]

ACCOUNT         TARGET    INTENT        SECRET
acme_dev_alice  free-pdb  password_set  -

ACCOUNT         TARGET    STATE  WAS   DETAIL
acme_dev_alice  free-pdb  RESET  OPEN  declared by accounts 'acme_dev_alice'; would be reset

would reset acme_dev_alice on 1 of 1 targets
```

The plan says how much the run would touch: one account on one database, in the
`dev` environment. `SECRET` is `-`, because no vault document holds a personal
password. `--account` names exactly one account. A reset never runs on every
declared account at once.

---

## 3. The default: a wrapping token (`vault_wrapped`)

With `method: vault_wrapped`, the tool sets the new password, gives it to Vault,
and gets back a *wrapping token*. A wrapping token is a short-lived Vault token
that can be exchanged for the stored value once. The tool prints the token, not
the password. You never see the password.

```bash
sopuli --config sopuli.yaml account reset-password --account acme_dev_alice
```
```
Plan: 1 account x 1 target = 1 account   [dev]

ACCOUNT         TARGET    INTENT        SECRET
acme_dev_alice  free-pdb  password_set  -
Plan: 1 account x 1 target = 1 account   [dev]

ACCOUNT         TARGET    INTENT        SECRET
acme_dev_alice  free-pdb  password_set  -

ACCOUNT         TARGET    STATE  WAS   DETAIL
acme_dev_alice  free-pdb  RESET  OPEN  declared by accounts 'acme_dev_alice'

reset acme_dev_alice on 1 of 1 targets


1 note:
  free-pdb: a password was sent over a connection that is not encrypted: require NNE or TLS on the server (SQLNET.ENCRYPTION_SERVER = REQUIRED in its sqlnet.ora, or a TCPS listener endpoint)

hand this to acme_dev_alice for free-pdb; it unwraps once:

    <TOKEN>

It stops working at 2026-10-30T18:53:53.361208Z, and the first unwrap is the
last. Do not unwrap it to check -- that spends the person's one read, and
them finding it spent is the only warning either of you gets.
```

The plan appears twice. The first copy goes to stderr before anything changes,
so a run that fails part way still shows what it was about to touch. The second
is part of the result.

The note is about the test container, which does not encrypt its connections.
The new password crossed the network in clear. Require encryption on a real
database.

**Pass the token to the person on a channel only they read**, such as a direct
message to them. Do not unwrap it to check it. The token works once, so checking
it spends the person's only read.

### What the person does with the token

The person exchanges the token for the password with `vault unwrap`. No other
Vault login is needed, because the token is the login:

```
$ vault unwrap -format=json <TOKEN>
{
  "request_id": "10f402a1-c462-12d8-fdb6-5202515491cf",
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

A second unwrap fails:

```
$ vault unwrap <TOKEN>
Error unwrapping: Error making API request.

URL: PUT http://127.0.0.1:8200/v1/sys/wrapping/unwrap
Code: 400. Errors:

* wrapping token is not valid or does not exist
```

### What the token promises, and what it does not

- **It works once.** If the person's unwrap fails before the token's expiry,
  somebody else read the password first. Nobody can hide that from the person.
  Tell them to report it, and reset the password again.
- **It expires.** The token stops working after the `ttl` in the config, 15
  minutes here. A person who misses it needs another reset.
- **Whoever holds it can use it.** Vault does not check who unwraps the token.
  That is why the channel matters. Never put the token in a ticket, a shared
  chat or a log that other people read.
- **It needs nothing but Vault.** Any Vault can wrap a value. That is why this
  method is the default. It is not the strongest method in every way, as
  section 8 shows.

The record holds the token's *accessor*, an identifier that names the token but
cannot unwrap it. With an audit device enabled on Vault, the accessor finds both
the wrap and the unwrap in Vault's audit log.

`account list` now shows when the reset happened:

```bash
sopuli --config sopuli.yaml account list
```
```
ACCOUNT         TARGET    DECLARED BY  STATUS  DB_PW_CHANGED  RESET_AT
ACME_DEV_ALICE  free-pdb  names        OPEN    2026-10-30     2026-10-30T18:38:53.384396Z

1 declared account, 1 on the selected targets
```

A reset draws a new password every time, so running it twice resets twice.

---

## 4. A path only the person can read (`vault_path`)

With `method: vault_path`, the tool writes the password to a Vault path that
only the person's own Vault login can read. Nothing is used up on read. Instead,
Vault deletes the value when the `ttl` runs out.

This method uses the person's identity instead of a token that anyone holding it
can use. To read the password, somebody needs the person's own Vault login.

### What the Vault admin sets up first

The tool sets up none of this. Somebody who administers Vault does it once:

1. The people log in to Vault as themselves, for example through LDAP or OIDC.
   The test stack uses Vault's `userpass` logins `alice` and `bob`.
2. Each person's Vault identity carries their database account name as
   metadata. Here, `alice`'s identity has `db_account = ACME_DEV_ALICE`.
3. A policy lets each person read the paths under their own account name, and
   nothing else. Vault fills in the name from the person's identity:

   ```
   $ vault policy read personal-reader
   path "kv/data/personal/{{identity.entity.metadata.db_account}}/*" {
     capabilities = ["read"]
   }
   ```

4. The token the tool uses for delivery can write those paths but not read
   them:

   ```
   $ vault policy read personal-writer
   path "kv/data/personal/*" {
     capabilities = ["create", "update"]
   }
   path "kv/metadata/personal/*" {
     capabilities = ["create", "update"]
   }
   ```

   The tool writes the path's metadata as well as its value, because the
   metadata tells Vault when to delete the value.

**The tool checks the last point before every reset.** If its delivery token can
read the person's path, the tool could read the password back, and the reset
would no longer be unseen. So the tool asks Vault what the token can do, and
refuses if the answer includes `read`. That is why this config gives
`vault_path` its own vault entry, `vault-handover`, with the narrow token.

**The tool checks only the token it delivers with.** Any other token you hold
that can read the path can read the password too. In this test setup that
includes the root token used for the records, which can read everything. In a
real estate, the DBA's own Vault tokens must not hold `read` on the personal
paths, and the record store needs a token of its own without it.

### The reset

Set `method: vault_path`, and run the same command. The output is the same as in
section 3 down to the note, so only the end is shown here:

```bash
sopuli --config sopuli.yaml account reset-password --account acme_dev_alice
```
```
...
ACCOUNT         TARGET    STATE  WAS   DETAIL
acme_dev_alice  free-pdb  RESET  OPEN  declared by accounts 'acme_dev_alice'

reset acme_dev_alice on 1 of 1 targets
...
tell acme_dev_alice the new password for free-pdb is waiting at:

    kv/personal/ACME_DEV_ALICE/free-pdb

They read it with their own Vault login. Vault deletes it at 2026-10-31T02:39:21.499668Z;
a token that holds `undelete` on the path can still restore it.
```

The path uses the account name as the database stores it, in capitals. Tell the
person where the password is. The path is not a secret: knowing it does not let
anybody read it.

### What the person does

The person logs in to Vault as themselves and reads the path. `vault login` asks
for their Vault password:

```
$ vault login -method=userpass username=alice
$ vault kv get -mount=kv personal/ACME_DEV_ALICE/free-pdb
============== Secret Path ==============
kv/data/personal/ACME_DEV_ALICE/free-pdb

======= Metadata =======
Key                Value
---                -----
created_time       2026-10-30T18:39:21.49966856Z
custom_metadata    <nil>
deletion_time      2026-10-31T02:39:21.49966856Z
destroyed          false
version            1

====== Data ======
Key         Value
---         -----
account     ACME_DEV_ALICE
password    <PASSWORD>
target      free-pdb
```

Anybody else is refused, even another person with the same policy. Logged in as
`bob`, the same read fails:

```
$ vault kv get -mount=kv personal/ACME_DEV_ALICE/free-pdb
Error reading kv/data/personal/ACME_DEV_ALICE/free-pdb: Error making API request.

URL: GET http://127.0.0.1:8200/v1/kv/data/personal/ACME_DEV_ALICE/free-pdb
Code: 403. Errors:

* 1 error occurred:
	* permission denied
```

### What the path promises, and what it does not

- **Only the person's identity can read it**, if no other token holds `read`
  on the path, and for as long as the Vault policy and the identity metadata
  say so. The tool cannot see the metadata, so it cannot check that
  `db_account` names the right person. That rests on whoever administers Vault
  identities.
- **The person can read it more than once.** The copy at the path stays
  readable until Vault deletes it at the `ttl`, 8 hours here. The password
  itself is not expired, so it keeps working on the database until somebody
  changes it.
- **Vault deletes it, but does not destroy it.** A token that holds `undelete`
  on the path can bring the value back.

A delivery token that can read the path is refused before anything changes.
Here `SOPULI_VAULT_TOKEN_HANDOVER` holds a token that also has `read` on
`kv/data/personal/*`. Exit 5:

```bash
sopuli --config sopuli.yaml account reset-password --account acme_dev_alice
```
```
sopuli: the token for 'vault-handover' holds read on kv/data/personal/acme_dev_alice/free-pdb, so it could read acme_dev_alice's password back
  hint: on `vault_path` the DBA must not be able to read the person's path (UC-2 6.6). Remove `read` from this token's policy on that path, or use a token without the root policy
```

The tool asks first with the name as you typed it, before it connects to the
database. Just before it draws a password, it asks again with the name as the
database stores it.

---

## 5. A one-time link (`one_time_link`)

With `method: one_time_link`, the tool hands the person a link to a
[Yopass](https://github.com/jhaals/yopass) server. The link opens once. This
method needs a Yopass server, which the tool does not provide, and the `yopass`
install extra:

```bash
pipx install "sopuli-dba[oracle,hashicorp,yopass]"
```

The tool encrypts the password before it sends anything. The server stores only
the encrypted text. The key that decrypts it is in the link, after the `#`. A
browser never sends that part of a link to the server, so the server never holds
anything that can decrypt the password.

Set `method: one_time_link`, and run the same command:

```bash
sopuli --config sopuli.yaml account reset-password --account acme_dev_alice
```
```
...
ACCOUNT         TARGET    STATE  WAS   DETAIL
acme_dev_alice  free-pdb  RESET  OPEN  declared by accounts 'acme_dev_alice'

reset acme_dev_alice on 1 of 1 targets
...
hand this link to acme_dev_alice for free-pdb; it opens once:

    http://127.0.0.1:1337/#/s/<ID>/<KEY>

It stops working at 2026-10-30T19:39:48Z, and the first open is the last.
Do not open it to check -- that uses up the person's one view, and them
finding it gone is the only warning either of you gets.
```

The person opens the link in a browser. The page has a button that shows the
password. The button fetches the encrypted text from the server, and the server
deletes it as it answers. Here `curl` makes the same fetch twice. The first
answers 200, and the second finds nothing:

```
$ curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:1337/secret/<ID>
200
$ curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:1337/secret/<ID>
404
```

### What the link promises, and what it does not

- **It opens once**, like the wrapping token. If the person finds it already
  used, somebody else opened it first.
- **Whoever holds the link can open it**, like the wrapping token. Pass it on a
  channel only the person reads.
- **It adds a third party.** You trust the Yopass server and whoever runs it to
  serve the page that decrypts the password.
- **Link previews can use it up.** Some chat and mail tools open links to
  preview them. The Yopass page fetches nothing until the person presses the
  button, so a preview does not use up the view. A server set up to fetch when
  the page loads would let a preview use it up. When the server reports that
  setting, the tool splits the link by itself, as below, whatever `split_key`
  says.

### Two channels: `split_key`

With `split_key: true`, the tool prints the link without its key, and the key on
its own. Send them by two different channels, such as the link by email and the
key by phone. Neither channel alone can read the password. The end of the
output then reads:

```
hand these to acme_dev_alice for free-pdb, by two different channels:

    link:  http://127.0.0.1:1337/#/s/<ID>
    key:   <KEY>

The link asks for the key. Send each one a different way, so that neither
channel alone can read the password.

It stops working at 2026-10-30T19:40:01Z, and the first open is the last.
Do not open it to check -- that uses up the person's one view, and them
finding it gone is the only warning either of you gets.
```

The tool reads the server's settings before it draws a password. A server it
cannot use is refused before anything changes. Here the config asks for a `ttl`
of `2h`, which the server does not accept. Exit 5:

```bash
sopuli --config sopuli.yaml account reset-password --account acme_dev_alice
```
```
sopuli: `delivery.method: one_time_link` cannot use the Yopass server at http://127.0.0.1:1337: the server does not accept a ttl of 2h: it accepts 1h, 24h or 168h
  hint: change the server's setting, or `delivery.one_time_link`, or choose another method (UC-2 6.2). Nothing was drawn or changed
```

---

## 6. A 1Password share link (`onepassword_share`)

With `method: onepassword_share`, the tool hands the person a 1Password share
link. The link opens once. The person needs only a browser, not a 1Password
account. This method needs a 1Password account with a *service account*, a
1Password login for programs, and the `onepassword` install extra:

```bash
pipx install "sopuli-dba[oracle,hashicorp,onepassword]"
```

The extra installs 1Password's SDK only on Python 3.13 and older. If pipx uses
a newer Python, pick an older one as [getting-started.md](../getting-started.md)
shows, with `--python 3.13`.

The service account needs permission to read, write and share items in the
vault that `onepassword_vault` names. Here that is a vault called `sopuli-test`.
`token` names the file that holds the service account's token. Never write the
token in the config file itself.

The tool creates an item that holds the password, shares it, and then deletes
the item. A share is a copy, so the link still opens after the delete, and no
copy stays in the vault.

Set `method: onepassword_share`, and run the same command. The end of the
output reads:

```
hand this link to acme_dev_alice for free-pdb; it opens once:

    <LINK>

It stops working at 2026-10-30T20:11:11Z, and the first open is the last.
Do not open it to check -- that uses up the person's one view, and them
finding it gone is the only warning either of you gets.
```

The person opens the link in a browser. The page shows the account name, with
the password behind a button. A second open says "Maximum views reached".

### What the link promises, and what it does not

- **It opens once**, like the Yopass link. If the person finds it already used,
  somebody else opened it first.
- **Whoever holds the link can open it.** Pass it on a channel only the person
  reads.
- **It adds 1Password as a third party.** You trust 1Password to serve the page
  and to keep the shared copy only until the `ttl`.
- **Link previews may use it up.** 1Password's page fetches the item as soon as
  it loads. A chat preview or a mail scanner that runs the page may use up the
  view. Send the link by a channel that does not open links.

The tool reads the account's sharing policy before it draws a password. A `ttl`
longer than the policy allows, or a policy that does not allow a link anyone can
open, is refused before anything changes, with exit 5.

---

## 7. The seen path: you see the password (`manual`)

With `method: manual`, the tool prints the password on your terminal, once. Use
it only when the person can be reached by none of the unseen methods, for
example when there is no Vault they can use.

**The password is always expired.** The person must change it at first logon,
and after that the password you saw no longer works. Until then, anybody who saw
it can log in as them. The config must say `force_expire: true` in the `manual`
block. When `manual` is the selected method, a `manual` block without it is
refused when the config is loaded, with exit 9.

The tool guards the seen path in other ways too:

- It asks for confirmation every time. `--confirm` does not answer the
  question, because it would claim that somebody is watching the screen.
- It refuses when stdout or stdin is not a terminal. A password written to a
  file or a CI log stays readable long after its one logon.
- It refuses `--output json` and `--output jsonl`, so no machine-readable
  document can hold the password.

Set `method: manual`, and run the same command at a terminal:

```bash
sopuli --config sopuli.yaml account reset-password --account acme_dev_alice
```
```
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
acme_dev_alice  free-pdb  RESET  OPEN  declared by accounts 'acme_dev_alice'

reset acme_dev_alice on 1 of 1 targets


1 note:
  free-pdb: a password was sent over a connection that is not encrypted: require NNE or TLS on the server (SQLNET.ENCRYPTION_SERVER = REQUIRED in its sqlnet.ora, or a TCPS listener endpoint)
```

The same command with its output sent to a file is refused before a password is
drawn. Exit 8:

```bash
sopuli --config sopuli.yaml account reset-password --account acme_dev_alice > manual.log
```
```
sopuli: `delivery.method: manual` prints a password, and stdout is not a terminal
  hint: a value redirected to a file or captured in a CI log outlives the single logon it is good for, and expiry does not unpublish it. Run this at a terminal and read the password off the screen -- `| clip` and `| pbcopy` do not work here, deliberately -- or use an unseen delivery method
```

The prompt comes after the password is set. The password prints as soon as you
answer `y`. If you answer `n`, the account keeps a password nobody has seen, and
you need to reset it again.

Pass the password on in a way that does not leave a copy where other people can
read it, and tell the person they must change it.

---

## 8. Which method should I use

| Method | The person needs | Read more than once | Who can read it | You see it |
|---|---|---|---|---|
| `vault_wrapped` | a Vault they can reach | no | whoever holds the token | no |
| `vault_path` | their own Vault login, set up by a Vault admin | yes, until the `ttl` | their Vault identity, and any token with `read` on the path | no |
| `one_time_link` | a browser; you need a Yopass server | no | whoever holds the link | no |
| `onepassword_share` | a browser; you need a 1Password account | no | whoever holds the link | no |
| `manual` | nothing | yes, until they change it | anybody who saw it | yes |

- **Start with `vault_wrapped`.** It works with the Vault you already have. A
  read by somebody else cannot be prevented, but the person finds out.
- **Choose `vault_path` when your people already log in to Vault as
  themselves.** There is no token or link to intercept on the way. To read the
  password, somebody needs the person's own login, or a token that holds `read`
  on the path, so keep such tokens away from DBAs. The copy stays readable until
  the `ttl`, so keep it short.
- **Choose `one_time_link` or `onepassword_share` when the person has no Vault
  access.** Use `one_time_link` if you run a Yopass server you trust, and
  `onepassword_share` if your estate already uses 1Password. On a Yopass link,
  `split_key: true` sends the key by a second channel.
- **Use `manual` only when none of these is possible.** It is the one path
  where you know a working password.

An estate can limit the methods its DBAs may use with
`safety.delivery.allowed_methods`. A file can only narrow that list, never widen
it. [01-configuration.md](../design/01-configuration.md) §9 has the rules.

---

## 9. Tell the person a password is waiting

A reset can also post a short message to a *webhook*:
an address that a chat service, such as Slack or Mattermost, gives you for
posting into a channel. The message says that a password is waiting. It never
carries the password, and never the token, link or key that fetches it.

**The rule is that the channel that notifies may be low-trust, and the channel
that carries the password may not.** A chat channel is read by many people, and
its history is kept. "A new password is waiting" harms nobody there. A token or
a link would let anybody who reads the channel fetch the password first. So the
tool still prints the token or the link to you, and you pass it on as before.

Add a `notify:` block inside `delivery:`. This one names the address in an
environment variable, because a chat webhook address contains its own secret:

```yaml
delivery:
  method: vault_wrapped
  vault_wrapped:
    ttl: 15m
  notify:
    method: webhook
    webhook:
      url: { env: SOPULI_NOTIFY_WEBHOOK }
      template: "{account}: a new password for {target} is waiting. It stops working at {expires_at}."
```

It needs the `notify` install extra. A real address, such as
`https://chat.example.com/hooks/...`, must use `https://`. Plain `http://` is
allowed only to the machine's own address, as here.

`template` is the message. It may use only `{account}`, `{target}` and
`{expires_at}`. The tool refuses any other name when it loads the file, so a
template cannot ask for the token, whatever it calls it. Here `bad.yaml` is the
same file, with the template's last sentence changed to
`Unwrap {wrapping_token}.`:

```
$ sopuli --config bad.yaml config validate
sopuli: bad.yaml: delivery.notify.webhook.template: a notify template may not reference {wrapping_token}
  hint: UC-2 6.1: the channel that notifies may be low-trust and the channel that carries the secret may not -- and that covers the password *or anything that retrieves it*, because the rule is about reach rather than value. Say that a password is ready and let the person fetch it: available: `{account}`, `{target}`, `{expires_at}`
```

That run exited 9, and nothing connected.

### Trying it without a chat service

This run used a small receiver on the same machine. It prints every message
posted to it. Save it as `receiver.py`, start it with `python receiver.py`, and
leave it running:

```python
# receiver.py: print every message posted to it. For trying this out only.
from http.server import BaseHTTPRequestHandler, HTTPServer


class Receiver(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        print(self.path, body.decode(), flush=True)
        self.send_response(200)
        self.end_headers()


HTTPServer(("127.0.0.1", 8099), Receiver).serve_forever()
```

Point the config at it, and reset as in section 3:

```bash
export SOPULI_NOTIFY_WEBHOOK=http://127.0.0.1:8099/hooks/acme-dba
sopuli --config sopuli.yaml account reset-password --account acme_dev_alice
```

The output is the same as in section 3, with a new token and expiry. The
receiver prints the message it got:

```
/hooks/acme-dba {"text":"acme_dev_alice: a new password for free-pdb is waiting. It stops working at 2026-10-30T19:32:59.199532Z."}
127.0.0.1 - - [30/Oct/2026 21:17:59] "POST /hooks/acme-dba HTTP/1.1" 200 -
```

The body is `{"text": ...}`, which Slack and Mattermost incoming webhooks
accept.

**A failed post does not fail the reset.** The password has already changed,
and the person can fetch it. With the receiver stopped, the same reset exits 0
and adds a note:

```
2 notes:
  the password for acme_dev_alice on free-pdb was delivered and the notification could not be sent, so nobody has been told it is waiting -- tell them another way today and look at `delivery.notify.webhook.url` afterwards: the webhook could not be reached: ConnectError
  free-pdb: a password was sent over a connection that is not encrypted: require NNE or TLS on the server (SQLNET.ENCRYPTION_SERVER = REQUIRED in its sqlnet.ora, or a TCPS listener endpoint)
```

The note does not show the webhook address, because the address is a secret.

### Why there is no "trusted" notify channel

It would be convenient to send the token through a second channel that the
config marks as trusted. The tool does not do this. "Trusted" would be a word
in a config file, written by whoever wrote the file, and the tool cannot check
it. The token comes back to you instead, and you choose how it reaches the
person.
[uc-02-personal-account-passwords.md](../use-cases/uc-02-personal-account-passwords.md)
§6.8 has the reasons.

---

## What to do when it goes wrong

| What you see | What it means |
|---|---|
| the person's unwrap answers `wrapping token is not valid or does not exist` | Vault answers the same for a token already used and one past its `ttl`. Compare the time with the expiry the reset printed. Before it, somebody else read the password first: reset again, and find out who. With an audit device on Vault, the accessor in the record finds the unwrap |
| the person's link finds no secret | somebody opened it first, or the `ttl` ran out. Reset again |
| `holds read on …`, exit 5 | the `vault_path` delivery token can read the person's path. Remove `read` from its policy. Nothing was changed |
| `cannot use the Yopass server`, exit 5 | a server setting rules out this config. The message names the setting. Nothing was changed |
| `SOPULI-W061` on `onepassword_share` | the link was made, but the tool could not delete the item afterwards. The item holds a working password: delete it in 1Password |
| exit 7 | another DBA's reset holds the lock on this account. `sopuli lock status` names them |
| exit 8 on `manual` | you declined the confirmation, or stdout or stdin is not a terminal |
| exit 9 | the config is unusable, for example `method: manual` with a `manual` block that lacks `force_expire: true` |

Every unseen method also takes `--output json` for a machine-readable version
of the same run, without the password. The token, link, key or path you hand
over then goes to stderr, because stdout carries the document. `manual` refuses
`--output json`, as section 7 says. The contract is in
[03-json-output.md](../design/03-json-output.md).

---

## Next

- [../use-cases/uc-02-personal-account-passwords.md](../use-cases/uc-02-personal-account-passwords.md)
  §6 — the full specification of each method, and the reasons behind it.
- [../security-model.md](../security-model.md) — what the tool can and cannot do,
  before you point this at production.
- [rotate-and-sync.md](rotate-and-sync.md) — the other half of the tool:
  application passwords, where the vault is the master copy.
