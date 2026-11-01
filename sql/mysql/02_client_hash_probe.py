"""sopuli-dba : a caching_sha2_password hash computed by the client

#1202. A MySQL driver could compute the account's hash itself and send
`ALTER USER ... IDENTIFIED WITH caching_sha2_password AS 0x<hash>`, so that the
password does not reach the server, as the PostgreSQL driver sends a SCRAM
verifier. This measures, on each server:

  CH1  that the hash this probe computes agrees with the server's own. The
       server sets each password below with IDENTIFIED BY, and the probe
       recomputes the stored hash from the password and the stored salt and
       rounds
  CH2  a hash the probe computes with a salt it draws, at 5,000 and at 10,000
       rounds, set with AS by a tool account that holds only CREATE USER. Then
       a login with the password, one with a wrong password, and one with the
       password the account had before
  CH3  AS with a value that is not a hash, and with a hash cut short
  CH4  IDENTIFIED WITH mysql_native_password AS '*<hex>', with the hash
       computed by the probe, set by the tool account, then a login with the
       password and with a wrong one

The hash is SHA-crypt with SHA-256, as glibc's `$5$`, with a salt of 20 bytes
where glibc takes 16 at most. The stored form is `$A$`, the rounds in
thousands as three hex digits, `$`, the salt, and the digest in crypt's base
64. The probe draws its salt from crypt's 64 characters.

Logins use the server's own mysql client, in its container, over TCP. A
password reaches it through the environment of `docker exec`, as MYSQL_PWD,
never through argv.

The probe checks each result against the one RESULTS below records, and
prints each that differs. A difference, or a step that fails, makes it exit 1.
A failed step on one server does not stop the others, and each server's
accounts are dropped either way. The helpers that the later probes in this
folder use are here.

It MEASURES and decides nothing.

STATUS: run on 8.0.46, 8.4.13 and 9.7.4, the mysql:8.0, mysql:8.4 and mysql:9
images of test/compose.yaml profile mysql-matrix, on 2026-11-01 (#1202), with
Python 3.13.12 on Windows 11 AMD64. Twice, exit 0, and the same result both
times.

RESULTS -- the same on all three releases, except where noted

  CH1  the probe's hash agrees with the server's for each password: 14 bytes,
       17 bytes with one character that is not ASCII, and 100 bytes. The
       server uses 5,000 rounds on 8.0.46 and 8.4.13, and 10,000 on 9.7.4
  CH2  the tool account, with only CREATE USER, sets the hash, and the server
       stores it as sent, at 5,000 and at 10,000 rounds on every release. The
       password logs in. A wrong password and the former password are refused,
       1045 (28000)
  CH3  both values are refused, 1827 (HY000), "The password hash doesn't have
       the expected format", and the former password still logs in
  CH4  8.0.46 accepts the hash from the tool account, the password logs in,
       and a wrong one is refused, 1045 (28000). 8.4.13 and 9.7.4
       refuse it, 1524 (HY000), "Plugin 'mysql_native_password' is not
       loaded": 8.4.13 ships the plugin disabled, and 9.7.4 has none

  So the tool can compute the hash, a server accepts it from an account with
  only CREATE USER, and the password logs in. The server checks the hash's
  form, not that it matches a password.

HOW TO RUN, against the matrix (test/README.md), from the repo root:

    .venv/Scripts/python sql/mysql/02_client_hash_probe.py

It needs only the standard library and the docker CLI. The container names
follow COMPOSE_PROJECT_NAME, so a second clone's matrix is the one it uses.

THROWAWAY SERVERS ONLY. On each server it creates the accounts
sopuli_probe_hash and sopuli_probe_tool and drops them at the end, and before
it starts it drops ones an interrupted run left.
"""

from __future__ import annotations

import hashlib
import os
import re
import secrets
import subprocess
import sys
from collections.abc import Callable

#: The stack's project name, so a second clone's stack is the one probed.
PROJECT = os.environ.get("COMPOSE_PROJECT_NAME", "sopuli-test")
SERVICES = ("mysql-80", "mysql-84", "mysql-9")
#: The matrix's public root password, from test/compose.yaml.
ROOT_PASSWORD = "sopuli-test"
ACCOUNT = "sopuli_probe_hash"
TOOL = "sopuli_probe_tool"
#: Test passwords, not credentials.
TOOL_PASSWORD = "Acme-Tool-pw1"
WRONG = "Acme-Wrong-pw9"
#: Test passwords, not credentials. One is not ASCII: e with acute, written as
#: a code point so the source stays ASCII.
PASSWORDS = ("Acme-Probe-pw1", "acme probe " + chr(0xE9) + " pw2", "A" * 100)
#: crypt's base 64, which is also the salt's alphabet.
B64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
SALT_LENGTH = 20


class StepError(Exception):
    """A step that is not a result failed."""


# ---------------------------------------------------------------- the hash --


def _b64(b2: int, b1: int, b0: int, n: int) -> str:
    word = (b2 << 16) | (b1 << 8) | b0
    out = []
    for _ in range(n):
        out.append(B64[word & 0x3F])
        word >>= 6
    return "".join(out)


def sha256_crypt(password: bytes, salt: bytes, rounds: int) -> str:
    """SHA-crypt's digest, without glibc's 16-byte limit on the salt."""
    a = hashlib.sha256(password + salt)
    b = hashlib.sha256(password + salt + password).digest()
    n = len(password)
    while n > 32:
        a.update(b)
        n -= 32
    a.update(b[:n])
    n = len(password)
    while n:
        a.update(b if n & 1 else password)
        n >>= 1
    digest = a.digest()
    dp = hashlib.sha256(password * len(password)).digest()
    p = (dp * (len(password) // 32 + 1))[: len(password)]
    ds = hashlib.sha256(salt * (16 + digest[0])).digest()
    s = (ds * (len(salt) // 32 + 1))[: len(salt)]
    c = digest
    for i in range(rounds):
        h = hashlib.sha256()
        h.update(p if i & 1 else c)
        if i % 3:
            h.update(s)
        if i % 7:
            h.update(p)
        h.update(c if i & 1 else p)
        c = h.digest()
    order = (
        (0, 10, 20), (21, 1, 11), (12, 22, 2), (3, 13, 23), (24, 4, 14),
        (15, 25, 5), (6, 16, 26), (27, 7, 17), (18, 28, 8), (9, 19, 29),
    )  # fmt: skip
    return "".join(_b64(c[x], c[y], c[z], 4) for x, y, z in order) + _b64(0, c[31], c[30], 3)


def caching_sha2_hash(password: str, salt: bytes, rounds: int) -> bytes:
    """The value MySQL stores for `password`, with this salt and these rounds."""
    digest = sha256_crypt(password.encode("utf-8"), salt, rounds)
    return b"$A$%03X$" % (rounds // 1000) + salt + digest.encode("ascii")


def draw_salt() -> bytes:
    return "".join(secrets.choice(B64) for _ in range(SALT_LENGTH)).encode("ascii")


def native_hash(password: str) -> str:
    """mysql_native_password's stored value: `*` and SHA1(SHA1(password)) in hex."""
    inner = hashlib.sha1(password.encode("utf-8")).digest()  # noqa: S324 -- MySQL's format
    return "*" + hashlib.sha1(inner).hexdigest().upper()  # noqa: S324


# ------------------------------------------------------------------ server --


def container(service: str) -> str:
    return f"{PROJECT}-{service}-1"


def client(
    service: str, user: str, password: str, statements: str, *flags: str
) -> tuple[int, str, str]:
    """Run the server's mysql client as `user`: its exit code, output and errors.

    Over TCP unless `flags` say otherwise. The client's warning about a password
    in its environment is left out of the errors.
    """
    done = subprocess.run(
        [
            "docker", "exec", "-i", "-e", "MYSQL_PWD", container(service),
            "mysql", f"-u{user}", "-N", "-B", "--default-character-set=utf8mb4",
            *(flags or ("-h127.0.0.1",)),
        ],
        input=statements.encode("utf-8"),
        env={**os.environ, "MYSQL_PWD": password},
        capture_output=True,
        check=False,
    )  # fmt: skip
    err = "\n".join(
        line
        for line in done.stderr.decode("utf-8", "replace").splitlines()
        if "Using a password" not in line
    ).strip()
    return done.returncode, done.stdout.decode("utf-8", "replace").strip(), err


def mysql(service: str, user: str, password: str, statement: str) -> tuple[bool, str]:
    """Run one statement as `user` over TCP. True and the output, or False and the error."""
    returncode, out, err = client(service, user, password, statement)
    if returncode == 0:
        return True, out
    # "ERROR 1045 (28000) at line 1: Access denied ..." -> "1045 (28000): Access denied ..."
    found = re.match(r"ERROR (\d+ \(\w+\))(?: at line \d+)?: (.*)", err, re.DOTALL)
    if found is None:
        # Not the server's answer: docker, or the client itself.
        raise StepError(f"{service}: {user}: {(err or out)[:200]}")
    return False, f"{found[1]}: {found[2][:110]}"


def code(answer: str) -> str:
    """`ok`, or a refusal's error number and SQLSTATE, such as `1045 (28000)`."""
    return answer.split(":")[0]


def root(service: str, statement: str) -> str:
    ok, out = mysql(service, "root", ROOT_PASSWORD, statement)
    if not ok:
        raise StepError(f"{service}: {statement[:60]}: {out}")
    return out


def as_tool(service: str, statement: str) -> str:
    """`ok`, or the refusal, for a statement the tool account sends."""
    ok, out = mysql(service, TOOL, TOOL_PASSWORD, statement)
    return "ok" if ok else out


def login(service: str, password: str, account: str = ACCOUNT) -> str:
    """`ok`, or the error number and SQLSTATE of the refusal."""
    ok, out = mysql(service, account, password, "SELECT CURRENT_USER()")
    return "ok" if ok else code(out)


#: Each result that differs from the one this header records.
DIFFERENCES: list[str] = []


def check(label: str, got: object, recorded: object) -> None:
    if got != recorded:
        DIFFERENCES.append(f"{label}: got {got!r}, recorded {recorded!r}")


def setup(service: str, password: str) -> str:
    """Create the tool account and the account with `password`; return the release."""
    release = root(service, "SELECT VERSION()")
    print(f"\n== {service}: {release}")
    teardown(service)
    root(
        service,
        f"CREATE USER '{TOOL}'@'%' IDENTIFIED BY '{TOOL_PASSWORD}';"
        f"GRANT CREATE USER ON *.* TO '{TOOL}'@'%';"
        f"CREATE USER '{ACCOUNT}'@'%' IDENTIFIED BY {quote(password)}",
    )
    return release


def teardown(service: str) -> None:
    root(service, f"DROP USER IF EXISTS '{ACCOUNT}'@'%', '{TOOL}'@'%'")


def run(probe: Callable[[str], None]) -> int:
    """Run `probe` on each server. Exit 1 on a difference or a failed step."""
    failed = False
    for service in SERVICES:
        try:
            probe(service)
        # ValueError too: a stored value the probe cannot parse, such as an
        # empty SELECT or a hash of another plugin.
        except (StepError, ValueError) as exc:
            print(f"STEP FAILED: {service}: {type(exc).__name__}: {exc}")
            failed = True
        finally:
            try:
                teardown(service)
            except StepError as exc:
                print(f"CLEAN-UP FAILED: {exc}")
                failed = True
    for difference in DIFFERENCES:
        print(f"DIFFERS: {difference}")
    if failed or DIFFERENCES:
        print("\nA RESULT DIFFERS FROM THE HEADER, OR A STEP FAILED")
        return 1
    print("\nevery result as recorded")
    return 0


def quote(text: str) -> str:
    return "'" + text.replace("\\", "\\\\").replace("'", "''") + "'"


def stored_hash(service: str) -> bytes:
    hexed = root(
        service,
        f"SELECT HEX(authentication_string) FROM mysql.user "
        f"WHERE user = '{ACCOUNT}' AND host = '%'",
    )
    return bytes.fromhex(hexed)


# ------------------------------------------------------------------ probes --


#: CH4's recorded refusal on 8.4.13, which ships the plugin disabled, and on
#: 9.7.4, which has none. 8.0.46 accepts the hash.
NATIVE_REFUSED = "1524 (HY000)"


def probe(service: str) -> None:
    """Run CH1 to CH4 on one server, print each result, and check it."""
    release = setup(service, "Acme-Probe-pw0")

    for password in PASSWORDS:
        root(service, f"ALTER USER '{ACCOUNT}'@'%' IDENTIFIED BY {quote(password)}")
        stored = stored_hash(service)
        rounds = int(stored[3:6], 16) * 1000
        agrees = caching_sha2_hash(password, stored[7:27], rounds) == stored
        check(f"CH1 {len(password.encode())} bytes", agrees, True)
        print(f"CH1 {len(password.encode())} bytes, {rounds} rounds: agrees={agrees}")

    before = PASSWORDS[-1]
    for rounds in (5000, 10000):
        password = f"Acme-Probe-r{rounds}"
        value = caching_sha2_hash(password, draw_salt(), rounds)
        answer = as_tool(
            service,
            f"ALTER USER '{ACCOUNT}'@'%' IDENTIFIED WITH caching_sha2_password AS 0x{value.hex()}",
        )
        stored = stored_hash(service) == value
        good, wrong = login(service, password), login(service, WRONG)
        former = login(service, before)
        print(
            f"CH2 {rounds} rounds, set by the tool: {answer}; "
            f"stored as sent={stored}; password: {good}; wrong: {wrong}; former: {former}"
        )
        check(
            f"CH2 {rounds}",
            (answer, stored, good, wrong, former),
            ("ok", True, "ok", "1045 (28000)", "1045 (28000)"),
        )
        before = password

    for label, value in (("not a hash", "'not-a-hash'"), ("cut short", "'$A$005$tooshort'")):
        answer = as_tool(
            service, f"ALTER USER '{ACCOUNT}'@'%' IDENTIFIED WITH caching_sha2_password AS {value}"
        )
        former = login(service, before)
        print(f"CH3 {label}: {answer}; former password: {former}")
        check(f"CH3 {label}", (code(answer), former), ("1827 (HY000)", "ok"))

    password = "Acme-Probe-native"
    answer = as_tool(
        service,
        f"ALTER USER '{ACCOUNT}'@'%' IDENTIFIED WITH mysql_native_password "
        f"AS '{native_hash(password)}'",
    )
    if answer == "ok":
        good, wrong = login(service, password), login(service, WRONG)
        print(f"CH4 set by the tool: ok; password: {good}; wrong: {wrong}")
        got: tuple[str, ...] = (answer, good, wrong)
    else:
        print(f"CH4 set by the tool: {answer}")
        got = (code(answer),)
    recorded = ("ok", "ok", "1045 (28000)") if release.startswith("8.0.") else (NATIVE_REFUSED,)
    check("CH4", got, recorded)


def main() -> int:
    return run(probe)


if __name__ == "__main__":
    sys.exit(main())
