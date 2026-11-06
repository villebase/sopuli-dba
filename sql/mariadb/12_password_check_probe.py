"""sopuli-dba : whether a MariaDB password check plugin refuses the value the driver sends

#1310. The MariaDB driver sets a password with `ALTER USER ... IDENTIFIED VIA
<plugin> USING '<value>'`, the value computed on the client (02, invariant
15). MariaDB's documentation says that while a password validation plugin is
loaded and `strict_password_validation` is ON, the server refuses a password
it cannot validate because it is given as a hash. This measures that, on each
server, as a tool account that holds only CREATE USER:

  PC1  with simple_password_check installed and strict_password_validation
       set ON: the tool account sends, for mysql_native_password and
       ed25519, the value of a strong password with USING. Then, as
       controls, IDENTIFIED BY a weak password and IDENTIFIED BY a strong one
  PC2  the same with strict_password_validation OFF
  PC3  with password_reuse_check installed instead, first with
       strict_password_validation ON, then OFF: the tool account sends the
       same USING value twice, for each plugin; and, as a control,
       IDENTIFIED BY the same strong password twice
  PC4  as the tool account, while both check plugins are installed and
       strict_password_validation is as the server started it:
       @@strict_password_validation, and the password validation plugins
       information_schema.PLUGINS lists
  PC5  cracklib_password_check: whether INSTALL SONAME takes it on this
       image, and if so, PC1's USING statements with it

A statement answers `ok`, or its refusal's number and SQLSTATE. Each server's
refusal messages are printed after its cases.

The probe checks each result against the one RESULTS below records. A
difference, or a step that fails, makes it exit 1.

It MEASURES and decides nothing.

STATUS: run on 10.11.19, 11.4.13, 11.8.9 and 12.3.3, the mariadb:10.11,
mariadb:11.4, mariadb:11.8 and mariadb:12.3 images of test/compose.yaml profile
mariadb-matrix, on 2026-11-05 (#1310), with Python 3.13.12 on Windows 11
AMD64. Twice, exit 0, and the same result both times.

RESULTS -- the same on every release; RECORDED below holds each value

  PC1  strict_password_validation starts ON. simple_password_check installs.
       **The tool account's USING value is refused on both plugins**: 1396,
       "Operation ALTER USER failed for '<user>'@'<host>'", the same answer a
       weak password gets. A strong password with IDENTIFIED BY is accepted
  PC2  with strict_password_validation OFF, the USING value is accepted on
       both plugins and nothing checks it. A weak password with IDENTIFIED
       BY is still refused, 1396
  PC3  with password_reuse_check alone and strict ON, the USING value is
       refused, 1396, as in PC1. With strict OFF it is accepted, twice in a
       row: the plugin does not see a value. IDENTIFIED BY the same password
       twice is refused the second time, 1396. The plugin keeps its history
       after it is uninstalled
  PC4  the tool account, with only CREATE USER, reads
       @@strict_password_validation (1) and the loaded validation plugins
       from information_schema.PLUGINS
  PC5  cracklib_password_check is not in these images: INSTALL SONAME
       answers 1126, the library cannot be opened

  So while simple_password_check or password_reuse_check is loaded and
  strict_password_validation is ON, which is its default, every password the
  driver sets is refused, with a 1396 that does not say why. With it OFF,
  neither plugin checks what the driver sends. The tool account can read
  both conditions without a new grant. cracklib_password_check and other
  plugins were not measured.

HOW TO RUN, against the matrix (test/README.md), from the repo root:

    .venv/Scripts/python sql/mariadb/12_password_check_probe.py

It needs the docker CLI, and 02 beside it, with MySQL's 02, whose helpers it
uses; 02 computes both plugins' values itself. A password reaches the client
through the environment of `docker exec`, as MYSQL_PWD, never through argv
(02).

THROWAWAY SERVERS ONLY. It installs the ed25519, simple_password_check,
password_reuse_check and cracklib_password_check plugins, sets
strict_password_validation, creates the accounts sopuli_probe_hash and
sopuli_probe_tool, and drops them at the end, also after a failed step. It
uninstalls each plugin it installed, leaves one the server had before, and
sets strict_password_validation back to the value it read.
"""

from __future__ import annotations

import importlib.util
import secrets
import sys
from pathlib import Path
from typing import Any

# 02's name starts with a digit, so it is loaded by its path.
_SPEC = importlib.util.spec_from_file_location(
    "mariadb_client_hash_probe", Path(__file__).with_name("02_client_hash_probe.py")
)
assert _SPEC is not None
assert _SPEC.loader is not None
ch = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(ch)

PLUGINS = ("mysql_native_password", "ed25519")
ACCOUNT = f"'{ch.ACCOUNT}'@'%'"
CHECKS = ("simple_password_check", "password_reuse_check", "cracklib_password_check")
STRONG, WEAK = "Acme-Check-Strong7#Pw", "abc"
VALIDATION_PLUGINS = (
    "SELECT GROUP_CONCAT(plugin_name ORDER BY plugin_name) FROM information_schema.plugins "
    "WHERE plugin_type = 'PASSWORD VALIDATION'"
)

#: This server's refusal messages, printed after its cases.
MESSAGES: set[str] = set()


def as_tool(service: str, statement: str) -> tuple[bool, str]:
    """The statement as the tool account: whether it ran, and its output or
    its refusal."""
    ok, out = ch.mysql(service, ch.TOOL, ch.base.TOOL_PASSWORD, statement)
    return bool(ok), str(out)


def tool(service: str, statement: str) -> str:
    """`ok`, or the refusal's number and SQLSTATE. The message is kept for the
    end, because 1396 says only that ALTER USER failed."""
    ok, out = as_tool(service, statement)
    if ok:
        return ch.OK
    MESSAGES.add(out)
    return str(ch.code(out))


def read_as_tool(service: str, statement: str) -> str:
    """What a SELECT returns to the tool account, or its refusal's number."""
    ok, out = as_tool(service, statement)
    return out if ok else str(ch.code(out))


def using(service: str, plugin: str, password: str) -> str:
    value = ch.COMPUTE[plugin](password)
    return tool(service, f"ALTER USER {ACCOUNT} IDENTIFIED VIA {plugin} USING '{value}'")


def identified_by(service: str, password: str) -> str:
    return tool(service, f"ALTER USER {ACCOUNT} IDENTIFIED BY {ch.quote(password)}")


def install(service: str, plugin: str) -> str:
    """INSTALL SONAME as root: `ok`, or the refusal's number."""
    ok, out = ch.mysql(service, "root", ch.ROOT_PASSWORD, f"INSTALL SONAME '{plugin}'")
    return ch.OK if ok else str(ch.code(out))


def uninstall(service: str, plugin: str, keep: set[str]) -> None:
    """UNINSTALL SONAME as root, unless the server had the plugin before the
    probe. A refusal fails the step: a plugin left loaded would be measured
    as another's."""
    if plugin in keep:
        return
    ok, out = ch.mysql(service, "root", ch.ROOT_PASSWORD, f"UNINSTALL SONAME '{plugin}'")
    if not ok and not str(out).startswith(("1305", "1126")):
        # 1305: not installed; 1126: never could be.
        raise ch.StepError(f"{service}: UNINSTALL SONAME '{plugin}': {out}")


def probe(service: str) -> None:
    had = ch.root(service, VALIDATION_PLUGINS)
    keep = set() if had == "NULL" else set(had.split(","))
    auth = ch.root(
        service,
        "SELECT GROUP_CONCAT(plugin_name) FROM information_schema.plugins "
        "WHERE plugin_name IN ('ed25519', 'parsec')",
    )
    strict = ch.root(service, "SELECT @@GLOBAL.strict_password_validation")
    MESSAGES.clear()
    # The accounts are dropped before the plugins they use are uninstalled.
    ch.cleaned(
        service,
        lambda: cases(service, strict, keep),
        lambda: ch.root(service, f"SET GLOBAL strict_password_validation = {strict}"),
        lambda: [uninstall(service, one, keep) for one in CHECKS],
        lambda: ch.base.teardown(service),
        lambda: ch.uninstall_plugins(service, keep=auth if auth != "NULL" else ""),
    )


def cases(service: str, strict: str, keep: set[str]) -> None:
    ch.base.setup(service, STRONG)
    ch.install_plugins(service)
    print(f"strict_password_validation at start: {strict}; checks loaded: {sorted(keep)}")

    got: Any = install(service, "simple_password_check")
    print(f"PC1 install simple_password_check: {got}")
    ch.check("PC1 install", got, RECORDED.get("PC1 install"))
    for setting, label in (("ON", "PC1"), ("OFF", "PC2")):
        ch.root(service, f"SET GLOBAL strict_password_validation = {setting}")
        got = (
            *(using(service, plugin, STRONG) for plugin in PLUGINS),
            identified_by(service, WEAK),
            identified_by(service, STRONG),
        )
        print(f"{label} strict {setting}: USING native {got[0]}; USING ed25519 {got[1]}; "
              f"BY weak {got[2]}; BY strong {got[3]}")  # fmt: skip
        ch.check(label, got, RECORDED.get(label))
    ch.root(service, f"SET GLOBAL strict_password_validation = {strict}")

    got = (
        install(service, "password_reuse_check"),
        read_as_tool(service, "SELECT @@strict_password_validation"),
        read_as_tool(service, VALIDATION_PLUGINS),
    )
    print(f"PC4 install password_reuse_check {got[0]}; as the tool account: strict "
          f"{got[1]}; checks {got[2]}")  # fmt: skip
    ch.check("PC4", got, RECORDED.get("PC4"))

    uninstall(service, "simple_password_check", keep)
    # The plugin keeps its history after a run, so each run's passwords are new.
    fresh = secrets.token_hex(4)
    for setting in ("ON", "OFF"):
        ch.root(service, f"SET GLOBAL strict_password_validation = {setting}")
        reuse = []
        for plugin in PLUGINS:
            twice = f"{STRONG}{plugin[:2]}{setting}{fresh}"
            reuse += [using(service, plugin, twice), using(service, plugin, twice)]
        reuse += [identified_by(service, f"{STRONG}by{setting}{fresh}"),
                  identified_by(service, f"{STRONG}by{setting}{fresh}")]  # fmt: skip
        got = tuple(reuse)
        print(f"PC3 reuse, strict {setting}: USING native twice {got[0]}, {got[1]}; USING "
              f"ed25519 twice {got[2]}, {got[3]}; BY twice {got[4]}, {got[5]}")  # fmt: skip
        ch.check(f"PC3 {setting}", got, RECORDED.get(f"PC3 {setting}"))
    ch.root(service, f"SET GLOBAL strict_password_validation = {strict}")
    uninstall(service, "password_reuse_check", keep)

    taken = install(service, "cracklib_password_check")
    got = (
        (taken, *(using(service, plugin, STRONG) for plugin in PLUGINS))
        if taken == ch.OK
        else (taken,)
    )
    print(f"PC5 cracklib_password_check: {got}")
    ch.check("PC5", got, RECORDED.get("PC5"))
    for message in sorted(MESSAGES):
        print(f"  refusal: {message}")


#: ALTER USER failed: MariaDB's whole answer to a refused password, whatever
#: the reason, with "Operation ALTER USER failed for '<user>'@'<host>'".
FAILED = "1396 (HY000)"

#: Each case's results, the same on every release.
RECORDED: dict[str, tuple[str, ...] | str] = {
    "PC1 install": "ok",
    "PC1": (FAILED, FAILED, FAILED, "ok"),
    "PC2": ("ok", "ok", FAILED, "ok"),
    "PC4": ("ok", "1", "password_reuse_check,simple_password_check"),
    "PC3 ON": (FAILED, FAILED, FAILED, FAILED, "ok", FAILED),
    "PC3 OFF": ("ok", "ok", "ok", "ok", "ok", FAILED),
    # 1126: the server cannot open the plugin's library; the image has none.
    "PC5": ("1126 (HY000)",),
}


def main() -> int:
    result: int = ch.run(probe)
    return result


if __name__ == "__main__":
    sys.exit(main())
