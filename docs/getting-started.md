# Getting started

This is a first run, from nothing to one working command. It assumes you know
Oracle and it does **not** assume you have installed a Python program before.

By the end you will have installed the tool, written a config file, checked that
the file is valid, and previewed a change without making one.

**Do this against a test database.** The tool is alpha, and the last step of
this guide is deliberately a preview rather than a change.

What you need before you start:

- **Python 3.11 or newer** on the machine you are working from.
- **Oracle Instant Client**, which is Oracle's set of client libraries. This is
  not optional — section 2 explains why.
- **An Oracle database** you may change a password on, and an admin account that
  can do it.
- **A HashiCorp Vault** you can write to. A *vault* is a server built to store
  secrets and hand them out to the applications that need them; HashiCorp Vault
  is the one this build supports. If you have none, section 1 gives you a
  throwaway one in a container.

Everything below was run on Windows 11 with sopuli 0.58.0 and Instant Client
23.26.3.0.0, against the project's own test containers. The output shown is what
those runs printed, except the install samples in section 2. Those come from
installing 0.75.0 from PyPI with pipx, on Windows 11 and on Ubuntu 24.04 in a
container.

Both versions are a **record of what each capture printed**, not a claim about
what the current build is. Your own `sopuli --version` prints the version you
installed. A version in a sample changes when that sample is captured again, not
when a release is cut, so do not "correct" either to the current number:
`pyproject.toml` owns that number.
[`local-testing.md`](local-testing.md) §2 keeps the same kind of per-sample note.

---

## 1. Get a database and a vault, if you do not have them

Skip this if you already have both. Otherwise the repository ships a container
stack that gives you an Oracle database and a Vault, neither of which installs
anything on your machine. You need Docker.

```bash
git clone https://github.com/villebase/sopuli-dba.git
cd sopuli-dba/test
# Start Oracle Free and Vault. Oracle takes about 30-60 seconds to become
# healthy the first time; Vault is ready in seconds.
docker compose --profile tier1 up -d
```

That gives you:

| | |
|---|---|
| Oracle | `127.0.0.1:1521/FREEPDB1`, admin account `SYSTEM`, password `sopuli-test` |
| Vault | `http://127.0.0.1:8200`, root token `sopuli-test-root` |

Neither is secure and neither survives a restart of the container. That is the
point: it is a sandbox.

Create an account for this guide to manage. It has to exist already — this tool
changes passwords, it does not create accounts. Save this as `accounts.sql`:

```sql
CREATE USER acme_app_user IDENTIFIED BY "Placeholder#1" QUOTA UNLIMITED ON USERS;
GRANT CREATE SESSION TO acme_app_user;
EXIT
```

```bash
# Feed that file to the container's own sqlplus, so you need no client installed.
docker exec -i sopuli-test-oracle-free-1 \
  sqlplus -S system/sopuli-test@localhost:1521/FREEPDB1 < accounts.sql
```
```
User created.

Grant succeeded.
```

Details of the stack, including the two ways tearing it down surprises people,
are in [`../test/README.md`](../test/README.md).

---

## 2. Install the tool

The recommended way to install the tool is *pipx*. pipx installs a Python
program that you run as a command. It gives the program its own private folder of
Python packages, called a *virtual environment*, so the tool cannot disturb
anything else on the machine. It also puts the `sopuli` command on your `PATH`,
the list of folders your shell searches for commands. There is nothing to
activate before each use.

pipx does not come with Python, so install it first.

### 2a. Install pipx

**Windows.** In PowerShell, install pipx for your own user, then let it add its
folders to your `PATH`:

```powershell
python -m pip install --user pipx
python -m pipx ensurepath
```

Both commands start with `python -m` on purpose. pip puts `pipx.exe` in a folder
that is not on your `PATH` yet, so the plain `pipx` command does not work until
`ensurepath` has run. If `python` itself is not recognized, use `py`, the Python
launcher for Windows, in its place: `py -m pip install --user pipx`.

**Linux: check your Python first.** The tool needs Python 3.11 or newer. Ask the
system Python for its version:

```bash
python3 --version
```

If it prints 3.11 or newer, the steps below work as written. Ubuntu 24.04 has
3.12. If it is older, the next steps say what to add. Ubuntu 22.04 has 3.10, and
Oracle Linux 9 has 3.9.

**Debian and Ubuntu.** Install pipx from the system packages. On recent releases,
such as Ubuntu 24.04, `pip install --user` is refused with
`error: externally-managed-environment`, so the system package is the way in:

```bash
sudo apt install pipx
pipx ensurepath
```

If your `python3` is older than 3.11, also install a newer Python, and name it
when you install the tool in section 2b. On Ubuntu 22.04:

```bash
sudo apt install python3.11 python3.11-venv
```

**Oracle Linux and other Red Hat-style systems.** The system `python3` can be
older than the 3.11 this tool needs. On Oracle Linux 9 it is 3.9. Install a newer
Python next to it, and run pipx with that Python:

```bash
sudo dnf install python3.12 python3.12-pip
python3.12 -m pip install --user pipx
python3.12 -m pipx ensurepath
```

pipx then installs programs with the Python that runs it, here 3.12.

On every platform, `ensurepath` says which folders it added to your `PATH`, and
ends by telling you to open a new terminal. On Ubuntu 24.04 it printed:

```
Success! Added /home/dba/.local/bin to the PATH environment variable.

Consider adding shell completions for pipx. Run 'pipx completions' for
instructions.

You will need to open a new terminal or re-login for the PATH changes to take
effect.

Otherwise pipx is ready to go! ✨ 🌟 ✨
```

**Open a new terminal now.** A terminal that is already open keeps its old `PATH`.

### 2b. Install sopuli-dba

This command downloads the tool from PyPI, the public Python package index, and
installs it with the two optional parts named in the brackets: the Oracle driver
and the HashiCorp Vault client. It is the same on Windows and Linux:

```bash
pipx install "sopuli-dba[oracle,hashicorp]"
```
```
creating virtual environment...
creating shared libraries...
upgrading shared libraries...
installing sopuli-dba from spec 'sopuli-dba[hashicorp,oracle]'...
  installed package sopuli-dba 0.75.0, installed using Python 3.13.12
  These apps are now available
    - sopuli.exe
done! ✨ 🌟 ✨
```

Those names in square brackets are *extras* — Python packaging's word for an
optional part of a package that brings its own dependencies. This tool installs
nothing that talks to a vendor unless you ask for it, so a site with no OCI never
inherits the OCI SDK's version constraints. The reasoning is in
[ADR-006](decisions/adr-006-optional-dependencies.md). The README lists every
extra.

If you installed a newer Python in section 2a because your `python3` is older
than 3.11, name it with `--python`. Without it, pipx uses its own older Python,
and the install fails with `No matching distribution found`. On Ubuntu 22.04:

```bash
pipx install --python python3.11 "sopuli-dba[oracle,hashicorp]"
```

**Windows with Python 3.15.** PyYAML, which the tool uses to read its config,
has no ready-built package for Python 3.15 on Windows yet. pip then tries to
build it, and without a C compiler the install fails with
`error: Microsoft Visual C++ 14.0 or greater is required`. Either name an
older Python, if you have one:

```powershell
pipx install --python 3.13 "sopuli-dba[oracle,hashicorp]"
```

Or tell PyYAML to install without its C part, which is slower but works the
same:

```powershell
$env:PYYAML_FORCE_LIBYAML = "0"
pipx install "sopuli-dba[oracle,hashicorp]"
```

The variable lasts until you close the terminal. Set it again before a later
`pipx upgrade` or `pipx reinstall`, and before `pip install` in a virtual
environment (section 2e). The `[oci]` extra has the same problem with two
other packages, and they have no such switch, so for `[oci]` use Python 3.13 or
3.14.

Check it arrived. It prints the version you installed:

```bash
sopuli --version
```
```
sopuli, version 0.75.0
```

If the shell says it does not know `sopuli`, or the version is not the one you
installed, see section 2d.

To add an extra later, run pip inside the environment pipx made. This adds the
`notify` extra's packages and changes nothing else, not the version and not the
other extras:

```bash
pipx runpip sopuli-dba install "sopuli-dba[notify]"
```

Do not use `pipx install --force` for this. It also upgrades the tool to the
latest release.

To upgrade to a newer release, run `pipx upgrade sopuli-dba`. It keeps the extras
you installed. `pipx reinstall` keeps only the extras you named in
`pipx install`, so run the `runpip` line again after it.

### 2c. Install Oracle Instant Client

**This one is mandatory and there is no configuration that avoids it.** The
Oracle driver can run in two modes. Thin mode needs no Oracle libraries, but it
cannot do three things this tool needs: Native Network Encryption, which a
database can be configured to require; a connection to Oracle 11.2; and a logon
through an external password store (`auth: external`). So
this tool always uses thick mode, and thick mode needs Oracle's client libraries
present on the machine.

(If your database is an Autonomous Database, it is not the first of those that
applies to you — Autonomous encrypts with TLS, not Native Network Encryption.
The client is needed all the same.)

Download **Basic** from Oracle's Instant Client downloads page. (Take
**SQL\*Plus** as well if you want a command-line SQL client for sanity checks;
the tool does not need it.)

- **Windows** — unzip to a path with no spaces, for example
  `C:\oracle\instantclient_23_26`. Then either add that folder to your `PATH`, or
  name it in the config file you are about to write:

  ```yaml
  runtime:
    oracle:
      client_lib_dir: C:\oracle\instantclient_23_26
  ```

- **Linux, WSL** — unzip to `/opt/oracle/instantclient_23_26`, install the
  `libaio1` package, and either set the `LD_LIBRARY_PATH` environment variable to
  that folder or use `client_lib_dir` as above.

### 2d. When the `sopuli` command is not found

PowerShell says this when no folder on your `PATH` holds the `sopuli` command:

```
The term 'sopuli' is not recognized as a name of a cmdlet, function, script file, or executable program.
Check the spelling of the name, or if a path was included, verify that the path is correct and try again.
```

On Linux, bash says `bash: sopuli: command not found`.

First, open a new terminal, because a terminal that is already open keeps its old
`PATH`. If that does not help, the folder that holds the command is not on your
`PATH`. Which folder it is depends on how you installed:

| Installed with | Windows folder | Linux folder |
|---|---|---|
| `pipx install` | `%USERPROFILE%\.local\bin` | `~/.local/bin` |
| `pip install --user`, or a `pip install` that said `Defaulting to user installation` | the folder pip names in its warning, usually `%APPDATA%\Python\Python3xx\Scripts`, where `3xx` is your Python version, such as `313` | `~/.local/bin` |

pip says where it put the command. Look for `WARNING: The script sopuli.exe is
installed in '...' which is not on PATH` in its output, and use that folder. It
is a different folder if your Python came from the Microsoft Store.

On Windows, add the folder to your own `PATH` in the settings dialog. It needs
no administrator rights:

1. Open the Start menu, type `environment variables`, and choose **Edit
   environment variables for your account**.
2. Under *User variables*, select `Path` and choose **Edit**.
3. Choose **New**, paste the folder, and choose **OK** in both windows.

Then open a new terminal. On Linux, run `pipx ensurepath` again, or add the
folder to `PATH` in your `~/.bashrc`.

**If you cannot change `PATH`**, for example on a managed work laptop, you can
still run the tool:

- After `pip install`, run `python -m sopuli`. It runs the same tool, with the
  same options: `python -m sopuli --version`. Start it the same way you started
  pip: if you ran `py -m pip install`, run `py -m sopuli`. It does not work after
  `pipx install`, because pipx keeps the tool away from your own `python`.
- After `pipx install`, run the command by its full path:
  `& "$env:USERPROFILE\.local\bin\sopuli.exe" --version` in PowerShell, or
  `~/.local/bin/sopuli --version` on Linux.

**If `sopuli --version` prints an older version** than the one you installed,
another copy of the tool is on your `PATH` and comes first. This happens when an
earlier `pip install` is still there. List every copy, in the order the shell
tries them:

```powershell
where.exe sopuli        # Windows
```
```bash
which -a sopuli         # Linux
```

Remove the one you do not want. A copy that pip installed goes with
`python -m pip uninstall sopuli-dba`, run with the Python that installed it.

### 2e. Without pipx: a virtual environment

If you cannot use pipx, make a virtual environment yourself and install into it
with pip. Make it outside the repository you cloned in section 1, for example in
your home folder. On Windows:

```powershell
cd ~
python -m venv .venv
```

On Linux the command is `python3`, and it must be 3.11 or newer, as section 2a
says. Debian and Ubuntu also need the `python3-venv` package, or the command
fails with `ensurepip is not available`. On Ubuntu 24.04:

```bash
sudo apt install python3-venv
cd ~
python3 -m venv .venv
```

On Oracle Linux 9, use `python3.12 -m venv .venv` after the `dnf install` in
section 2a.

Then *activate* it. This points the `python`, `pip` and `sopuli` commands at that
folder for the rest of your terminal session:

```powershell
.venv\Scripts\Activate.ps1        # Windows PowerShell
```
```bash
source .venv/bin/activate         # Linux, macOS, WSL
```

Install the tool into it:

```bash
pip install "sopuli-dba[oracle,hashicorp]"
```

You need to activate the environment again in every new terminal. That is the
step people forget, and the reason pipx is the recommended way.

---

## 3. Write your first config file

The config file is the whole point of the tool, so it is worth understanding
rather than pasting. It is written in *YAML*, a plain-text format for structured
data where indentation shows what belongs inside what.

The file says four things: which vaults may be used, which databases may be
touched, what a password has to look like, and which account's password lives
where. Save this as `sopuli.yaml`, in a folder of your own — **not** inside the
repository:

```yaml
version: 1

# The secret stores this file is allowed to use. One entry per store.
vaults:
  vault-dev:
    type: hashicorp
    addr: http://127.0.0.1:8200
    mount: kv
    kv_version: 2
    auth: { method: token }

# Settings every part of this file inherits unless it says otherwise.
defaults:
  vault: vault-dev

# The databases this file is allowed to touch. One entry per endpoint.
targets:
  - name: free-pdb
    type: oracle
    environment: dev
    dsn: "127.0.0.1:1521/FREEPDB1"
    admin: { username: SYSTEM, auth: { method: env } }
    oracle: { scope: pdb, container: FREEPDB1 }

# The rules a generated password has to satisfy.
policies:
  standard:
    password:
      length: 24
      charset: alnum_safe
      first_char: alpha
      require: { upper: 1, lower: 1, digit: 1, special: 1 }

# The one account this file manages, and where its password is mastered.
accounts:
  - acme_app_user
secret_template: "vault-dev:acme/{env}/db#DB_CREDENTIALS/{account}"
policy: standard
```

Four parts of it are worth a sentence each.

**`admin: { username: SYSTEM, auth: { method: env } }`** — how the tool logs in to
the database as an administrator. `method: env` means the password comes from an
environment variable, not from this file. **No password is ever written in this
file.** Section 4 sets that variable.

**`accounts:`** — the list of database accounts this tool is allowed to touch, and
it is a whitelist rather than a starting point. The tool will never change an
account that is not named here. Command-line options can narrow this list; nothing
can extend it.

**`secret_template:`** — where each account's password is mastered in the vault.
Read `vault-dev:acme/{env}/db#DB_CREDENTIALS/{account}` in three pieces: the store
name before the colon, then the path to a document inside it, then after the `#`
the field inside that document. `{env}` and `{account}` are filled in per target
and per account, so one line covers an estate. For the account and target above
it resolves to `vault-dev:acme/dev/db`, field `DB_CREDENTIALS/acme_app_user`.

**The file has no `applications:` section**, because there is only one
application here. With two or more, the binding keys at the bottom
(`accounts`, `secret_template` or `secret`, `policy`, `overrides`) move into an
`applications:` list, one entry each. The full reference is
[`design/01-configuration.md`](design/01-configuration.md).

### The file's permissions matter, and will stop you first

The tool refuses to read a config file that other people on the machine can
reach. This is not about confidentiality — the file holds no secrets. It is about
tampering: anyone who can write this file can repoint `secret_template` at a path
they control, and the tool would then faithfully rotate a production password into
it.

A file you just created will usually fail that check:

```
sopuli: sopuli.yaml: config file is accessible to BUILTIN\Users
  hint: remove the extra grant, e.g. icacls "<file>" /inheritance:r /grant:r "%USERNAME%:R"
```

The exit code is 9, which means *fix your config*. Fix it with:

```powershell
# Windows: drop inherited permissions, then grant only yourself.
icacls sopuli.yaml /inheritance:r /grant:r "${env:USERNAME}:F"
```
```bash
# Linux, WSL: owner only, nobody else at all.
chmod 600 sopuli.yaml
```

Note for later: editing the file with a tool that replaces it rather than writing
in place can restore the inherited permissions, and the same error comes back.
Re-run the command above if it does.

---

## 4. Tell the tool its passwords, without writing them down

Two credentials are needed at run time and neither belongs in a file you edit:
the token that authenticates you to the vault, and the database admin password.
Both come from environment variables.

```powershell
# Windows PowerShell
$env:VAULT_ADDR = "http://127.0.0.1:8200"
$env:VAULT_TOKEN = "sopuli-test-root"
$env:SOPULI_DB_ADMIN_PASSWORD = "sopuli-test"
```
```bash
# Linux, WSL
export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_TOKEN=sopuli-test-root
export SOPULI_DB_ADMIN_PASSWORD=sopuli-test
```

These are the sandbox's throwaway values. On a real system the vault token would
come from `~/.vault-token` or a file named with `--vault-token-file`, and the
admin password from whatever your site already uses for that.

**No option to any command takes a password as its value**, here or anywhere
else. Command-line arguments are visible to every other user on the machine.
Where a flag has to name a secret it names the *file* the secret is in.

---

## 5. Check the file before you use it

```bash
sopuli --config sopuli.yaml config validate
```
```
config: sopuli.yaml

ok: 1 target, 1 binding, 0 warnings
```

This opens no network connection. It reads the file, checks every rule that can
be checked without asking anything, and tells you what it found. "1 binding"
means one account-to-secret pairing was resolved.

`config validate` warns rather than fails when your file names a backend this
machine cannot reach — the file is fine, the install is incomplete.

Two more commands that also connect to nothing, both worth running now:

```bash
# What databases does this file actually resolve to?
sopuli --config sopuli.yaml target list
```
```
config: sopuli.yaml

NAME      DSN                      ENV  SCOPE  SOURCE
free-pdb  127.0.0.1:1521/FREEPDB1  dev  pdb    targets

1 target (1 explicit)
```

```bash
# Every effective setting, and which layer of config produced it.
sopuli --config sopuli.yaml config show --explain
```
```
settings
  db.connect_timeout_s = 30         [built-in default]
  db.query_timeout_s   = 0          [built-in default]
  output               = text       [built-in default]
  safety.dry_run       = false      [built-in default]
  safety.readonly      = false      [built-in default]
  vault                = vault-dev  [defaults.vault]
```

`--explain` is the one to remember. Settings can arrive from several places at
once, and this is how you find out which one won.

---

## 6. Check that everything is reachable

```bash
sopuli --config sopuli.yaml doctor
```
```
install
  KIND     NAME       STATUS           CONFIGURED
  backend  file       not_implemented  -
  backend  hashicorp  installed        vault-dev
  backend  keyring    not_implemented  -
  backend  oci        not_implemented  -
  driver   oracle     installed        1 target

vaults
  VAULT      TYPE       STATUS  AUTH  SKEW
  vault-dev  hashicorp  ok      yes   -58ms

client
  tns_admin         (unset)
  instant_client    23.26.3.0.0
  reaches           19.1 and later

TARGET    REACHABLE  SCOPE  CONTAINER  OPEN MODE   CAPABILITIES  ENCRYPTION
free-pdb  yes        pdb    FREEPDB1   READ WRITE  7             none
  free-pdb: the connection is not encrypted, so a password the tool sets crosses it in clear: require NNE or TLS on the server (SQLNET.ENCRYPTION_SERVER = REQUIRED in its sqlnet.ora, or a TCPS listener endpoint)

1 note:
  free-pdb: the admin credential came from the environment variable SOPULI_DB_ADMIN_PASSWORD, which P2 supports and flags as low assurance
```

`doctor` connects to everything your config names and reports what it found. Read
it in five parts:

- **install** — which backends this machine has code for, against which your
  config asks for. `not_implemented` means this build has no module for that
  backend yet, not that you installed something wrong.
- **vaults** — whether the store answered, whether your token authenticated, and
  how far its clock is from yours.
- **client** — whether Instant Client loaded, and which Oracle versions it can
  reach. If this says `instant_client  not loaded`, go back to section 2c; a
  `detail:` line underneath says why the library was not found. This part works
  with nothing else set up, so it is the first thing to run when something is
  wrong.
- **the target table** — whether each database answered, whether it is where
  you said it was, and whether the connection to it is encrypted. The test
  container's is not, so `doctor` warns that a password would cross it in clear.
  On a real database, require NNE or TLS before you let the tool set a password.
- **notes** — facts that are not faults. Here, the admin password came from an
  environment variable, which the tool accepts and calls low assurance. That is
  fine for the sandbox. On a real system, take it from whatever your site
  already uses for that, as section 4 says.

---

## 7. Ask what would happen, without making it happen

Now a command that changes something — except it will not, because of the flag.

```bash
sopuli --config sopuli.yaml creds generate --dry-run
```
```
Plan: 1 account x 1 target = 1 generation   [dev]

ACCOUNT        TARGET    INTENT                         SECRET
acme_app_user  free-pdb  generate, vault_write_pending  vault-dev:acme/dev/db

constraints: 128 bytes in AL32UTF8, from free-pdb

SECRET                 STAGE    ACCOUNTS
vault-dev:acme/dev/db  pending  acme_app_user

nothing was written (--dry-run)
```

`--dry-run` means: work out the whole plan, print it, change nothing. Every
command that changes something accepts it. `safety.readonly` refuses even a dry
run, and so does `safety.max_targets` when the plan is over the limit.

Read the plan from the top. `1 account x 1 target = 1 generation` is the blast
radius — how much this run would touch. The `INTENT` column is what would be done
to each row: draw a password, and write it into the vault as `pending`. Nothing
in that list touches the database, which is why `creds generate` is the safe
first verb.

The `constraints:` line is the one thing that will surprise you. `generate` does
connect — it asks each database how long a password may be in that database's own
character set, and the strictest answer governs the draw. It reads and never
writes. Pass `--offline` to skip asking, and the policy's declared length is used
instead.

Now drop the flag, if you are on a database you are happy to change:

```bash
sopuli --config sopuli.yaml creds generate
```
```
ACCOUNT        SECRET                 RESULT
acme_app_user  vault-dev:acme/dev/db  staged v1

1 staged; no database was changed -- run `sopuli creds apply` to use them
```

The password now exists in the vault, as `pending`. Applications read `current`,
which has not changed, so nothing has been disturbed. `creds apply` is what sets
it on the database and then promotes it — and that is the next document.

---

## 8. Moving a secret path

Sooner or later you will change where an application's password lives, for
example by editing its `secret_template`. The next `creds generate` and
`creds apply` write to the new path. The old document stays in the vault, and
so does its lock record, under `locks/`. The tool never touches a path the
config does not declare, so nothing removes them.

`vault orphans` lists them. It reads every store in `vaults:`, and changes
nothing. Here the path moved from `acme/acme/dev` to `acme/dev/acme`:

```
$ sopuli --config sopuli.yaml vault orphans
config: sopuli.yaml

VAULT      PATH                 KIND    LOCK
vault-dev  acme/acme/dev        secret  -
vault-dev  locks/acme/acme/dev  lock    released

2 orphans in 1 vault (vault-dev): records that look like this tool's, at paths no binding in this config declares

They may be another config's. Check each one before you delete it (getting-started.md, "Moving a secret path"). To delete them:

  vault kv metadata delete -address=http://127.0.0.1:8200 -mount=kv acme/acme/dev
  vault kv metadata delete -address=http://127.0.0.1:8200 -mount=kv locks/acme/acme/dev
```

It lists a document only if the document has a field this tool writes, `origin`
or `rotated_at`. So another team's secrets in the same mount are not listed.
But it has to read each document to see that, and each read is in the vault's
audit log, under your token. A document your token may not read is counted in
a warning.

A document that another sopuli config manages has those fields too. Before you
delete anything, check each record:

1. The new path has `current` for every account. `sopuli creds check` says so.
2. Nothing else still reads the old path, such as an External Secrets Operator
   or the application's own settings.
3. No other sopuli config declares the old path. If one does, the record is not
   an orphan.
4. The old document holds no fields this tool did not write. Read it with
   `vault kv get`.
5. The lock is not held. `vault orphans` prints no command for a path whose lock
   is held, and `sopuli lock status` says who holds it.

Then run the commands it printed. They name the vault's address, so they reach
the vault in your config whatever `VAULT_ADDR` says. They are quoted for bash.
`vault kv metadata delete` removes the record and all its versions. Do not use
`vault kv delete` on a KV v2 mount. It keeps the metadata, and on a lock path
the next lock there could never be taken. Your token needs the `delete`
capability on `<mount>/metadata/<path>`.

Run it again to see that they are gone:

```
$ sopuli --config sopuli.yaml vault orphans
config: sopuli.yaml

no orphans in 1 vault (vault-dev)
```

---

## 9. Where to go next

| Read this | For |
|---|---|
| [scenarios/rotate-and-sync.md](scenarios/rotate-and-sync.md) | the rest of this story: `apply`, `check`, rolling back, and closing a rollover window |
| [scenarios/kubernetes-eso.md](scenarios/kubernetes-eso.md) | letting applications in Kubernetes collect the new password by themselves |
| [../examples/](../examples/) | three complete config files, commented, from smallest to safety-hardened |
| [security-model.md](security-model.md) | what the tool can and cannot do, before you trust it with production |
| [design/01-configuration.md](design/01-configuration.md) | the full config reference — every key, every rule |
| [local-testing.md](local-testing.md) | the usual commands, run by hand against the local test stack |

---

## Troubleshooting the first run

| What you see | What it means |
|---|---|
| `The term 'sopuli' is not recognized`, or `sopuli: command not found` | the folder that holds the command is not on your `PATH`. Section 2d |
| `sopuli --version` prints an older version than you installed | another copy of the tool comes first on your `PATH`. Section 2d |
| `error: externally-managed-environment` from `pip install` | your Linux distribution does not let pip install into its own Python. Install pipx from the system packages. Section 2a |
| `config file is accessible to ...`, exit 9 | the file's permissions are too open. Section 3 has the fix |
| `instant_client  not loaded` in `doctor` | Instant Client is missing or not on the library path. Section 2c |
| `... declares type "oci", but this build has no oci backend yet`, exit 9 | your config names a store this build has no code for |
| `... declares type "hashicorp", but that backend is not installed`, exit 9 | the store's client is not installed. The hint gives two lines. Use the `pipx` one if you installed with pipx, as section 2 recommends, and the `pip` one otherwise |
| `cannot be locked safely: its lock path does not require compare-and-set`, exit 5 | the lock path was created without `cas_required`, by something other than this tool. Set it once with `vault kv metadata put -cas-required=true` on the lock path. See UC-1 §8, *What the fence does in this build*, in [`use-cases/uc-01-app-credential-sync.md`](use-cases/uc-01-app-credential-sync.md) |
| `VAULT_ADDR is set and was not applied` (a warning) | you have `VAULT_ADDR` in your environment and your config names no default store. Harmless if the variable belongs to something else; write `defaults.vault` to silence it |
| exit 3 from `creds check` | not an error. Exit 3 means drift was found — the vault's password does not work on the database. It has its own exit code so a scheduler can tell it apart from a failure |
