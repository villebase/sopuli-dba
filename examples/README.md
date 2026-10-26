# Example configurations

Complete config files, starting with the smallest one that works. Each is
commented for a reader who has not written one before.

| File | Shows |
|---|---|
| [single-application.yaml](single-application.yaml) | the smallest config that does something useful: one vault, one database, one account |
| [multiple-applications.yaml](multiple-applications.yaml) | the `applications:` shape, target groups, and per-application selection |
| [safety-hardened.yaml](safety-hardened.yaml) | `confirm_environments`, `max_targets`, `readonly`, and profiles |
| [target-sets.yaml](target-sets.yaml) | many pluggable databases from one `target_sets:` entry, a container root per environment, `overrides:`, and groups that keep an application off the roots |
| [admin-credentials.yaml](admin-credentials.yaml) | the four places the password of the account the tool connects as can come from: a wallet, a vault, a prompt, or an environment variable |
| [personal-accounts.yaml](personal-accounts.yaml) | resetting the passwords people log in with: `personal_accounts:` by name and by profile, common users on the container root, `delivery:`, and `reset_records:` |
| [app-creds-and-personal-accounts.yaml](app-creds-and-personal-accounts.yaml) | a whole estate with both: three environments, application accounts and personal accounts, in one file |

Check any of them before you use it. This opens no network connection:

```bash
sopuli --config single-application.yaml config validate
```

**All of them are checked in CI** (`tests/test_examples.py`), so an example
cannot silently drift out of date with the config layer.

**They point at addresses that are not yours.** The first two point at the
project's own test containers on `127.0.0.1`, port 1521 for the database and
8200 for the vault. The others point at `example.com` and `192.0.2.0/24`, which
are reserved for documentation and reach nothing. Change the addresses, the
account names and the vault paths before running anything against a real
database.

## The one thing that will stop you first

**The tool refuses to read a config file that other people on the machine can
reach.** A file checked out of a repository is readable by everyone who checks it
out, so copying one of these and running it straight away gives you exit 9:

```
sopuli: sopuli.yaml: config file is accessible to BUILTIN\Users
  hint: remove the extra grant, e.g. icacls "<file>" /inheritance:r /grant:r "%USERNAME%:R"
```

That check is not about confidentiality — these files hold no secrets. It is
about tampering: anyone who can write the file can repoint `secret_template` at a
vault path they control, and the tool would then faithfully rotate a production
password into it.

Copy the example somewhere of your own and fix the permissions:

```powershell
# Windows: drop inherited permissions, then grant only yourself.
icacls sopuli.yaml /inheritance:r /grant:r "${env:USERNAME}:F"
```
```bash
# Linux, WSL: owner only, nobody else at all.
chmod 600 sopuli.yaml
```

## Seeing what a file resolves to

Two commands answer most questions about a config without connecting to
anything:

```bash
# Which databases does this file actually resolve to?
sopuli --config safety-hardened.yaml target list
```
```
config: safety-hardened.yaml

NAME         DSN                                ENV   SCOPE  SOURCE
prod-orders  db-orders.example.com:1521/ORDERS  prod  pdb    targets
uat-orders   db-uat.example.com:1521/ORDERS     uat   pdb    targets

2 targets (2 explicit)
```

```bash
# Every effective setting, and which layer of config produced it.
sopuli --config safety-hardened.yaml config show --explain
```

`--explain` is worth knowing because of the safety ratchet: a safety setting can
be made stricter by any layer and looser by none, so "which layer won" is not
always the one you would expect. Running it against `safety-hardened.yaml` with
its `audit` profile selected shows the ratchet saying so out loud.

`--output text` is on that command line because the `audit` profile sets
`output: json`, and without the flag you get the same information as a JSON
document. A flag on the command line beats a profile, which is precedence
working. The output starts with the vaults, targets and other sections that
`config show` prints; these are its last two:

```
$ sopuli --config safety-hardened.yaml --profile audit config show --explain --output text
...
safety
KEY                                       VALUE                         NOTE
defaults.safety.confirm_environments      prod, uat
defaults.safety.delivery.allowed_methods  vault_wrapped, one_time_link
defaults.safety.max_targets               4                             defeated by the ratchet
profiles.audit.safety.max_targets         2
profiles.audit.safety.readonly            true

settings
  db.connect_timeout_s            = 30                                      [built-in default]
  db.query_timeout_s              = 0                                       [built-in default]
  output                          = text                                    [cli --output (verb)]
  profile                         = audit                                   [cli --profile (group)]
  safety.confirm_environments     = prod, uat                               [defaults.safety.confirm_environments]
  safety.delivery.allowed_methods = one_time_link, vault_wrapped            [defaults.safety.delivery.allowed_methods]
  safety.dry_run                  = false                                   [built-in default]
  safety.max_targets              = 2                                       [profiles.audit.safety.max_targets]
                                    defaults.safety.max_targets asked for 4; safety.max_targets stays 2 (profiles.audit.safety.max_targets) -- safety settings only ratchet toward safe
  safety.readonly                 = true                                    [profiles.audit.safety.readonly]
  vault                           = vault-prod                              [defaults.vault]
  vaults.vault-prod.addr          = https://vault.example.com:8200          [vaults.vault-prod.addr]
  vaults.vault-prod.kv_version    = 2                                       [vaults.vault-prod.kv_version]
  vaults.vault-prod.mount         = kv                                      [vaults.vault-prod.mount]
  vaults.vault-prod.tls.ca_file   = /etc/ssl/certs/example-internal-ca.pem  [vaults.vault-prod.tls.ca_file]
```

## More

- [../docs/getting-started.md](../docs/getting-started.md) — writing your first
  config from scratch, with the surrounding steps.
- [../docs/design/01-configuration.md](../docs/design/01-configuration.md) — the
  full reference: every key, every rule, and the validation errors worth causing
  on purpose.
- [../docs/schemas/sopuli-config-3.3.schema.json](../docs/schemas/sopuli-config-3.3.schema.json)
  — the JSON Schema. Put
  `# yaml-language-server: $schema=<path to it>` on the first line of your config
  to get completion and inline errors in an editor, as these examples do.
