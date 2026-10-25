"""sopuli-dba : which method a pg_hba.conf line that says md5 uses for a SCRAM verifier

#1032. The PostgreSQL driver is to store a SCRAM-SHA-256 verifier, whatever the
server's password_encryption says. This measures what happens at the next
login when the server is set to md5 and the role's pg_hba.conf line says md5.
On each server it sets password_encryption = md5 and creates two roles:
sopuli_probe_scram, given a SCRAM verifier, and sopuli_probe_md5, given a
plaintext password that the server stores as md5. A first line in pg_hba.conf
sends both roles to md5. Each role then logs in over TCP three ways, with
require_auth unset, = md5 and = scram-sha-256. require_auth=md5 stands in for a
client that speaks only md5.

The client is psql in the postgres-18 container, with libpq 18.6, which has
require_auth. It reaches each server by its compose service name. The password
reaches it through the environment of `docker exec`, never through argv.

It MEASURES and decides nothing.

STATUS: run on 13.23, 14.24, 15.19, 16.15, 17.11 and 18.6, the postgres:13 to
postgres:18 images of test/compose.yaml profile postgres-matrix, on 2026-10-25
(#1032). Twice, exit 0, the same result each time. Two earlier versions are not
counted. The first sent its shell step with Windows line endings, so
pg_hba.conf was not changed. The second ran its shell steps as root, so the
restored pg_hba.conf was root's and the server could not read it again. Its
logins gave the results below, but it ignored failed steps, so its exit code
showed nothing.

RESULTS -- the same on all six releases

  The server stores sopuli_probe_scram's verifier as SCRAM-SHA-256 and
  sopuli_probe_md5's password as md5. 18.6 warns at the md5 one: "setting an
  MD5-encrypted password", DETAIL "MD5 password support is deprecated and will
  be removed in a future release of PostgreSQL."

  sopuli_probe_scram  unset: logs in. md5: refused by the client,
                      'authentication method requirement "md5" failed: server
                      requested SASL authentication'. scram-sha-256: logs in
  sopuli_probe_md5    unset: logs in. md5: logs in. scram-sha-256: refused by
                      the client, 'authentication method requirement
                      "scram-sha-256" failed: server requested a hashed
                      password'

  So a line that says md5 uses SCRAM for a role whose verifier is SCRAM, also
  with password_encryption = md5. A client that speaks only md5 cannot log in
  as that role.

HOW TO RUN (from the repo root, against the matrix; test/README.md):

    python sql/postgres/04_md5_line_scram_verifier_probe.py

It needs only the standard library and the docker CLI. The container names
follow COMPOSE_PROJECT_NAME, so a second clone's matrix is the one it changes.

A setup or restore step that fails stops the probe with exit 1 and that step's
output, and so does a pg_hba.conf whose first rule is not the probe's line. So
a login against a server the setup did not change is never printed as a result.

THROWAWAY SERVERS ONLY. On each server it changes password_encryption and
pg_hba.conf, and creates three roles. Whatever happens, it then puts
pg_hba.conf back, resets password_encryption and drops the roles. Before it
starts on a server, it undoes what an interrupted run left there.
"""

from __future__ import annotations

import os
import subprocess
import sys

#: The stack's project name, so a second clone's stack is the one probed.
PROJECT = os.environ.get("COMPOSE_PROJECT_NAME", "sopuli-test")
VERSIONS = (13, 14, 15, 16, 17, 18)
#: The client runs in this server's container: its psql has libpq 18, which
#: has require_auth.
CLIENT = 18
#: A test password, not a credential. It reaches the client through the
#: environment of `docker exec`, never through argv.
PASSWORD = "PwHbaMarker3x"
ROLES = ("sopuli_probe_scram", "sopuli_probe_md5")
HBA_LINE = f"host all {','.join(ROLES)} all md5"


def _container(version: int) -> str:
    return f"{PROJECT}-postgres-{version}-1"


class StepError(Exception):
    """A setup or restore step failed, so nothing after it is a result."""


def _run(
    argv: list[str], stdin: str = "", env: dict[str, str] | None = None, measured: bool = False
) -> str:
    """Run a command and return its output.

    A step that is not ``measured`` must succeed, or the probe stops: a login
    against a server the setup did not change is not a result. A measured step,
    a login, may fail, and its output is the result.
    """
    # Bytes, not text: in text mode Windows writes `\r\n` to the pipe, and the
    # container's sh reads the `\r` as part of each command.
    done = subprocess.run(argv, input=stdin.encode(), capture_output=True, env=env, check=False)
    out = (done.stdout + done.stderr).decode("utf-8", "replace").strip()
    if done.returncode != 0 and not measured:
        raise StepError(f"{' '.join(argv[:4])} exited {done.returncode}:\n{out}")
    return out


def _psql(version: int, sql: str) -> str:
    """Run SQL as the superuser, over the container's own socket."""
    argv = ["docker", "exec", "-i", _container(version)]
    argv += ["psql", "-U", "postgres", "-d", "sopuli", "-X", "-q", "-At", "-v", "ON_ERROR_STOP=1"]
    return _run(argv, sql)


def _shell(version: int, script: str) -> str:
    """Run a shell script as the server's own user, so the files it makes are the
    server's. As root, cp makes a root-owned backup, and once it is moved back
    the server cannot read its pg_hba.conf."""
    argv = ["docker", "exec", "-i", "-u", "postgres", _container(version), "sh", "-s"]
    return _run(argv, script)


def _login(server: int, role: str, require_auth: str) -> str:
    """Log in from the client container, and say what happened."""
    conninfo = f"host=postgres-{server} dbname=sopuli user={role}"
    if require_auth:
        conninfo += f" require_auth={require_auth}"
    argv = ["docker", "exec", "-e", "PGPASSWORD", _container(CLIENT)]
    argv += ["psql", conninfo, "-X", "-At", "-c", "SELECT 'logged in'"]
    env = {**os.environ, "PGPASSWORD": PASSWORD}
    return _run(argv, env=env, measured=True).replace("\n", " | ")


def _setup(version: int) -> str:
    sql = f"""
ALTER SYSTEM SET password_encryption = 'md5';
SELECT pg_reload_conf();
DROP ROLE IF EXISTS {ROLES[0]};
DROP ROLE IF EXISTS {ROLES[1]};
DROP ROLE IF EXISTS sopuli_probe_seed;
SET password_encryption = 'scram-sha-256';
CREATE ROLE sopuli_probe_seed PASSWORD '{PASSWORD}';
SELECT rolpassword AS verifier FROM pg_authid WHERE rolname = 'sopuli_probe_seed' \\gset
RESET password_encryption;
CREATE ROLE {ROLES[0]} LOGIN PASSWORD :'verifier';
CREATE ROLE {ROLES[1]} LOGIN PASSWORD '{PASSWORD}';
DROP ROLE sopuli_probe_seed;
SELECT 'password_encryption=' || current_setting('password_encryption');
SELECT rolname || ' stored ' || split_part(rolpassword, '$', 1)
  FROM pg_authid WHERE rolname IN ('{ROLES[0]}', '{ROLES[1]}') ORDER BY rolname;
"""
    hba = f"""
set -e
test ! -e "$PGDATA/pg_hba.conf.sopuli-probe"
cp "$PGDATA/pg_hba.conf" "$PGDATA/pg_hba.conf.sopuli-probe"
sed -i '1i {HBA_LINE}' "$PGDATA/pg_hba.conf"
"""
    out = _psql(version, sql)
    out += "\n" + _shell(version, hba)
    rule = _psql(
        version,
        "SELECT pg_reload_conf();"
        " SELECT 'first rule: ' || line_number || ' ' || type || ' '"
        " || array_to_string(user_name, ',') || ' ' || auth_method"
        " FROM pg_hba_file_rules ORDER BY line_number LIMIT 1;",
    )
    if not rule.endswith(f"first rule: 1 host {','.join(ROLES)} md5"):
        raise StepError(f"pg_hba.conf does not start with the probe's line:\n{rule}")
    return f"{out}\n{rule}".strip()


def _restore(version: int) -> str:
    """Undo the setup, or what an interrupted run left of it."""
    out = _shell(
        version,
        'set -e\nif [ -e "$PGDATA/pg_hba.conf.sopuli-probe" ]; then\n'
        '  mv "$PGDATA/pg_hba.conf.sopuli-probe" "$PGDATA/pg_hba.conf"\nfi\n',
    )
    out += "\n" + _psql(
        version,
        f"""
ALTER SYSTEM RESET password_encryption;
SELECT pg_reload_conf();
DROP ROLE IF EXISTS {ROLES[0]};
DROP ROLE IF EXISTS {ROLES[1]};
DROP ROLE IF EXISTS sopuli_probe_seed;
""",
    )
    return out.strip()


def main() -> int:
    try:
        for version in VERSIONS:
            print(f"=== server {version}")
            print(_psql(version, "SHOW server_version;"))
            # An interrupted run may have left its changes. Undo them first, so
            # that the setup starts from the server's own pg_hba.conf.
            _restore(version)
            try:
                print(_setup(version))
                for role in ROLES:
                    for require_auth in ("", "md5", "scram-sha-256"):
                        result = _login(version, role, require_auth)
                        print(f"{role} require_auth={require_auth or '(unset)'}: {result}")
            finally:
                print(_restore(version))
    except StepError as exc:
        print(f"STOPPED: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
