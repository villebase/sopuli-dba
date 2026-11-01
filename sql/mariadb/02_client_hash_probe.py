"""sopuli-dba : a MariaDB password hash computed by the client

#1220. MariaDB keeps the password of `ALTER USER ... IDENTIFIED BY` in clear in
its logs (01), so a MariaDB driver would compute the stored value itself and
send `IDENTIFIED VIA <plugin> USING '<value>'`, as the PostgreSQL driver sends a
SCRAM verifier. This measures, on each server, for the three plugins that take
a password: mysql_native_password, ed25519 and parsec.

  CH1  that the value this probe computes agrees with the server's own. The
       server sets the password with USING PASSWORD('<password>'), and the
       probe recomputes the stored value: for parsec, from the stored salt and
       the stored digit
  CH2  a value the probe computes, set with IDENTIFIED VIA ... USING by a tool
       account that holds only CREATE USER, and for mysql_native_password also
       with IDENTIFIED BY PASSWORD. Then a login with the password, one with a
       wrong password, and one with the password the account had before
  CH3  USING with a value that is not one, for each plugin, then a login with
       the password the account had before
  CH4  which of the plugins the server has before the probe installs ed25519
       and parsec, and whether each installs

mysql_native_password stores `*` and SHA1(SHA1(password)) in hex. ed25519
stores the Ed25519 public key whose seed is the password, in base 64 without
padding. parsec stores `P`, a digit for the rounds, `:`, a salt of 18 bytes in
base 64, `:`, and the Ed25519 public key whose seed is PBKDF2-HMAC-SHA512 of the
password and salt, 1024 rounds for the digit 0, 32 bytes. The probe draws its
own salt. The Ed25519 arithmetic is here, in the standard library.

Logins use the server's own mariadb client, in its container, over TCP. A
password reaches it through the environment of `docker exec`, as MYSQL_PWD,
never through argv.

The probe checks each result against the one RESULTS below records, as
sql/mysql/02_client_hash_probe.py does, whose helpers this one loads and points
at the mariadb client and the MariaDB servers. The helpers the later probes in
this folder use are here. A difference, or a step that fails, makes it exit 1.

It MEASURES and decides nothing.

STATUS: run on 10.11.19 and 12.3.3, the mariadb:10.11 and mariadb:12.3 images
of test/compose.yaml profile mariadb-matrix, on 2026-11-01 (#1220), with Python
3.13.12 on Windows 11 AMD64. Twice, exit 0, and the same result both times.

RESULTS -- the same on both releases, except where noted

  CH1  the probe's value agrees with the server's, for each plugin the server
       has
  CH2  the tool account, with only CREATE USER, sets each value. The password
       logs in, and a wrong password and the former password are refused,
       1045 (28000)
  CH3  each value is refused, 1396 (HY000), "Operation ALTER USER failed",
       and the former password still logs in
  CH4  both start with mysql_native_password alone. ed25519 installs on both.
       parsec installs on 12.3.3, and is refused on 10.11.19, 1126 (HY000):
       the library is not in the image

HOW TO RUN, against the matrix (test/README.md), from the repo root:

    .venv/Scripts/python sql/mariadb/02_client_hash_probe.py

It needs only the standard library and the docker CLI, and
sql/mysql/02_client_hash_probe.py. The container names follow
COMPOSE_PROJECT_NAME, so a second clone's matrix is the one it uses.

THROWAWAY SERVERS ONLY. On each server it installs the ed25519 and parsec
plugins, creates the accounts sopuli_probe_hash and sopuli_probe_tool, and
drops the accounts and uninstalls the plugins at the end. Before it starts, it
drops accounts an interrupted run left, and uninstalls ed25519 and parsec even
where the server had them, because CH4 measures what a new server loads.
"""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import secrets
import sys
from collections.abc import Callable
from pathlib import Path

# MySQL's 02 holds the client and the checks. Its name starts with a digit, so
# it is loaded by its path.
_SPEC = importlib.util.spec_from_file_location(
    "mysql_client_hash_probe",
    Path(__file__).resolve().parents[1] / "mysql" / "02_client_hash_probe.py",
)
assert _SPEC is not None
assert _SPEC.loader is not None
base = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(base)
base.SERVICES = ("mariadb-1011", "mariadb-123")
base.CLIENT = "mariadb"

StepError = base.StepError
ACCOUNT, TOOL, TOOL_PASSWORD = base.ACCOUNT, base.TOOL, base.TOOL_PASSWORD
ROOT_PASSWORD, WRONG = base.ROOT_PASSWORD, base.WRONG
client, mysql, code, root = base.client, base.mysql, base.code, base.root
as_tool, login, check, quote = base.as_tool, base.login, base.check, base.quote
native_hash = base.native_hash
OK, REFUSED = "ok", "1045 (28000)"
FAILED = "1396 (HY000)"

# --------------------------------------------------------------- Ed25519 --

_P = 2**255 - 19
_D = -121665 * pow(121666, _P - 2, _P) % _P
_GY = 4 * pow(5, _P - 2, _P) % _P


def _recover_x(y: int) -> int:
    xx = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    x = pow(xx, (_P + 3) // 8, _P)
    if (x * x - xx) % _P:
        x = x * pow(2, (_P - 1) // 4, _P) % _P
    return _P - x if x & 1 else x


_GX = _recover_x(_GY)
_G = (_GX, _GY, 1, _GX * _GY % _P)


def _add(a: tuple[int, int, int, int], b: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    """Two points added, in extended coordinates."""
    x1, y1, z1, t1 = a
    x2, y2, z2, t2 = b
    p, q = (y1 - x1) * (y2 - x2) % _P, (y1 + x1) * (y2 + x2) % _P
    r, s = 2 * t1 * t2 * _D % _P, 2 * z1 * z2 % _P
    e, f, g, h = q - p, s - r, s + r, q + p
    return e * f % _P, g * h % _P, f * g % _P, e * h % _P


def ed25519_public(seed: bytes) -> bytes:
    """The Ed25519 public key for `seed`, as the standard derives it."""
    scalar = bytearray(hashlib.sha512(seed).digest()[:32])
    scalar[0] &= 248
    scalar[31] &= 63
    scalar[31] |= 64
    n = int.from_bytes(scalar, "little")
    point, total = _G, (0, 1, 1, 0)
    while n:
        if n & 1:
            total = _add(total, point)
        point = _add(point, point)
        n >>= 1
    x, y, z, _ = total
    inverse = pow(z, _P - 2, _P)
    x, y = x * inverse % _P, y * inverse % _P
    return (y | (x & 1) << 255).to_bytes(32, "little")


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii").rstrip("=")


def ed25519_value(password: str) -> str:
    """The value the ed25519 plugin stores for `password`."""
    return _b64(ed25519_public(password.encode("utf-8")))


def parsec_value(password: str, salt: bytes | None = None, digit: int = 0) -> str:
    """The value the parsec plugin stores for `password`, with this salt."""
    salt = secrets.token_bytes(18) if salt is None else salt
    key = hashlib.pbkdf2_hmac("sha512", password.encode("utf-8"), salt, 1024 << digit, 32)
    return f"P{digit}:{base64.b64encode(salt).decode('ascii')}:{_b64(ed25519_public(key))}"


#: Each plugin, and how the probe computes its value.
COMPUTE = {
    "mysql_native_password": native_hash,
    "ed25519": ed25519_value,
    "parsec": parsec_value,
}

# ---------------------------------------------------------------- server --


def plugins(service: str) -> str:
    """The authentication plugins the server has loaded, by name."""
    return root(
        service,
        "SELECT GROUP_CONCAT(plugin_name ORDER BY plugin_name) FROM information_schema.plugins "
        "WHERE plugin_type = 'AUTHENTICATION' AND plugin_status = 'ACTIVE' "
        "AND plugin_name IN ('mysql_native_password', 'ed25519', 'parsec')",
    )


def install_plugins(service: str) -> str:
    """Install ed25519, and parsec where the image has it: `ok` or parsec's refusal."""
    root(service, "INSTALL PLUGIN IF NOT EXISTS ed25519 SONAME 'auth_ed25519'")
    ok, answer = mysql(
        service, "root", ROOT_PASSWORD, "INSTALL PLUGIN IF NOT EXISTS parsec SONAME 'auth_parsec'"
    )
    return OK if ok else code(answer)


def uninstall_plugins(service: str, keep: str = "") -> None:
    """Uninstall ed25519 and parsec, except those named in `keep`, as plugins() lists them."""
    for plugin in ("ed25519", "parsec"):
        if plugin not in keep.split(","):
            root(service, f"UNINSTALL PLUGIN IF EXISTS {plugin}")


def stored(service: str, account: str = ACCOUNT) -> str:
    return root(
        service,
        f"SELECT authentication_string FROM mysql.user WHERE user = '{account}' AND host = '%'",
    )


run = base.run


def cleaned(service: str, body: Callable[[], None], *cleanups: Callable[[], None]) -> None:
    """Run `body`, then every clean-up, each even when one before it failed.

    When `body` fails, its own error is the one raised, and a clean-up that
    fails as well is only reported.
    """
    try:
        body()
    except BaseException:
        for cleanup in cleanups:
            try:
                cleanup()
            except StepError as exc:
                print(f"CLEAN-UP FAILED: {service}: {exc}")
        raise
    failed: StepError | None = None
    for cleanup in cleanups:
        try:
            cleanup()
        except StepError as exc:
            failed = failed or exc
    if failed is not None:
        raise failed


# ---------------------------------------------------------------- probes --


def probe(service: str) -> None:
    """Run CH1 to CH4 on one server, and uninstall the plugins whatever happens."""
    cleaned(
        service,
        lambda: cases(service),
        lambda: base.teardown(service),
        lambda: uninstall_plugins(service),
    )


def cases(service: str) -> None:
    release = base.setup(service, "Acme-Probe-pw0")
    uninstall_plugins(service)
    before_install = plugins(service)
    parsec_install = install_plugins(service)
    have = plugins(service).split(",")
    print(
        f"CH4 before installing: {before_install}; installing parsec: {parsec_install}; "
        f"after: {','.join(have)}"
    )
    recorded = (
        (OK, "ed25519,mysql_native_password,parsec")
        if release.startswith("12.3.")
        else ("1126 (HY000)", "ed25519,mysql_native_password")
    )
    check(
        "CH4",
        (before_install, parsec_install, ",".join(have)),
        ("mysql_native_password", *recorded),
    )

    for plugin in have:
        password = f"Acme-Probe-{plugin[:6]}"
        root(
            service,
            f"ALTER USER '{ACCOUNT}'@'%' IDENTIFIED VIA {plugin} USING PASSWORD({quote(password)})",
        )
        value = stored(service)
        if plugin == "parsec":
            # `P<digit>:<salt>:<key>`, the digit giving the rounds.
            head, salt, _ = value.split(":")
            agrees = parsec_value(password, base64.b64decode(salt), int(head[1:])) == value
        else:
            agrees = COMPUTE[plugin](password) == value
        print(f"CH1 {plugin}: agrees={agrees}")
        check(f"CH1 {plugin}", agrees, True)

    forms = [(p, f"IDENTIFIED VIA {p} USING '{{}}'") for p in have]
    forms.append(("mysql_native_password", "IDENTIFIED BY PASSWORD '{}'"))
    # CH1 left the account on the last plugin's password.
    before = f"Acme-Probe-{have[-1][:6]}"
    for number, (plugin, form) in enumerate(forms):
        password = f"Acme-Set-{number}-{plugin[:6]}"
        statement = form.format(COMPUTE[plugin](password))
        answer = as_tool(service, f"ALTER USER '{ACCOUNT}'@'%' {statement}")
        good, wrong = login(service, password), login(service, WRONG)
        former = login(service, before)
        label = form.split(" USING")[0].split(" '")[0]
        print(f"CH2 {label}: {answer}; password: {good}; wrong: {wrong}; former: {former}")
        check(f"CH2 {label}", (answer, good, wrong, former), (OK, OK, REFUSED, REFUSED))
        before = password

    for plugin in have:
        answer = as_tool(
            service, f"ALTER USER '{ACCOUNT}'@'%' IDENTIFIED VIA {plugin} USING 'not-a-value'"
        )
        former = login(service, before)
        print(f"CH3 {plugin}: {code(answer)}; former password: {former}")
        check(f"CH3 {plugin}", (code(answer), former), (FAILED, OK))


def main() -> int:
    return run(probe)


if __name__ == "__main__":
    sys.exit(main())
