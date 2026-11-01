"""sopuli-dba : two passwords at once on MariaDB

#1220. MySQL keeps an account's old password logging in beside the new one
with RETAIN CURRENT PASSWORD (sql/mysql/03_dual_password_probe.py). This
measures what MariaDB has instead, on each server:

  DP1  ALTER USER ... IDENTIFIED BY ... RETAIN CURRENT PASSWORD, from the tool
       account
  DP2  IDENTIFIED VIA <plugin> USING '<old>' OR <plugin> USING '<new>', both
       values computed by the probe and set by the tool account, for each
       plugin the server has: mysql_native_password, ed25519 and parsec. Then
       a login with the old password, with the new one and with a wrong one
  DP3  the same with the old password on mysql_native_password and the new
       one on ed25519, so that the rollover also changes the plugin
  DP4  what an OR leaves to read, with the old password on
       mysql_native_password and the new one on ed25519, so that the two
       methods can be told apart: the mysql.user view's plugin and
       authentication_string, how many values the account has in
       mysql.global_priv's auth_or, as root, and what SHOW CREATE USER shows
  DP5  IDENTIFIED VIA ed25519 USING '<new>' alone, from the tool account,
       after DP4. Then a login with each password, and auth_or again

auth_or is read with JSON_LENGTH(Priv, '$.auth_or'): an account that has
never had OR has no auth_or, and reads NULL.

The probe checks each result against the one RESULTS below records, as
02_client_hash_probe.py does. A difference, or a step that fails, makes it exit
1.

It MEASURES and decides nothing.

STATUS: run on 10.11.19 and 12.3.3, the mariadb:10.11 and mariadb:12.3 images
of test/compose.yaml profile mariadb-matrix, on 2026-11-01 (#1220), with Python
3.13.12 on Windows 11 AMD64. Twice, exit 0, and the same result both times.

RESULTS -- the same on both releases, except that 10.11.19 has no parsec

  DP1  refused, 1064 (42000): MariaDB has no RETAIN CURRENT PASSWORD
  DP2  the tool account sets both values, for each plugin. The old and the
       new password both log in, and a wrong one is refused, 1045 (28000)
  DP3  as DP2: the old password logs in on mysql_native_password and the new
       one on ed25519
  DP4  the mysql.user view's plugin and authentication_string are the first
       method's, mysql_native_password and the old value. auth_or holds 2
       values. SHOW CREATE USER shows both values and OR
  DP5  the old password is refused, 1045 (28000), the new one logs in, and
       auth_or holds 1 value

  So OR gives MariaDB a rollover: the tool sends both values, which it can
  compute from the two passwords it holds, and ends the rollover by sending
  the new value alone. Whether a rollover is open is in mysql.global_priv,
  beside the hashes, and in SHOW CREATE USER, which prints them.

HOW TO RUN, against the matrix (test/README.md), from the repo root:

    .venv/Scripts/python sql/mariadb/03_dual_password_probe.py

It needs 02_client_hash_probe.py beside it.

THROWAWAY SERVERS ONLY. It installs the ed25519 and parsec plugins, creates
the accounts sopuli_probe_hash and sopuli_probe_tool, as 02 does, and drops
them at the end. It uninstalls each plugin it installed, and leaves one the
server had before.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

# 02's name starts with a digit, so it is loaded by its path.
_SPEC = importlib.util.spec_from_file_location(
    "mariadb_client_hash_probe", Path(__file__).with_name("02_client_hash_probe.py")
)
assert _SPEC is not None
assert _SPEC.loader is not None
ch = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(ch)

ACCOUNT = f"'{ch.ACCOUNT}'@'%'"


def auth_or(service: str) -> str:
    return ch.root(
        service,
        "SELECT IFNULL(JSON_LENGTH(Priv, '$.auth_or'), 'NULL') FROM mysql.global_priv "
        f"WHERE user = '{ch.ACCOUNT}' AND host = '%'",
    )


def both(service: str, old: tuple[str, str], new: tuple[str, str]) -> str:
    """Set the old and the new password with OR, each as its plugin's value."""
    (old_plugin, old_password), (new_plugin, new_password) = old, new
    return ch.as_tool(
        service,
        f"ALTER USER {ACCOUNT} IDENTIFIED VIA {old_plugin} USING "
        f"'{ch.COMPUTE[old_plugin](old_password)}' OR {new_plugin} USING "
        f"'{ch.COMPUTE[new_plugin](new_password)}'",
    )


def probe(service: str) -> None:
    # A plugin the server had before the run stays installed after it.
    loaded = ch.plugins(service)
    ch.cleaned(
        service,
        lambda: cases(service),
        lambda: ch.base.teardown(service),
        lambda: ch.uninstall_plugins(service, keep=loaded),
    )


def cases(service: str) -> None:
    ch.base.setup(service, "Acme-Probe-pw0")
    ch.install_plugins(service)
    have = ch.plugins(service).split(",")

    answer = ch.as_tool(
        service, f"ALTER USER {ACCOUNT} IDENTIFIED BY 'Acme-Dual-new0' RETAIN CURRENT PASSWORD"
    )
    print(f"DP1 RETAIN CURRENT PASSWORD: {ch.code(answer)}")
    ch.check("DP1", ch.code(answer), "1064 (42000)")

    pairs = [(plugin, plugin) for plugin in have]
    pairs.append(("mysql_native_password", "ed25519"))
    for old_plugin, new_plugin in pairs:
        old, new = f"Acme-Old-{old_plugin[:6]}", f"Acme-New-{new_plugin[:6]}"
        answer = both(service, (old_plugin, old), (new_plugin, new))
        got = (answer, ch.login(service, old), ch.login(service, new), ch.login(service, ch.WRONG))
        case = "DP2" if old_plugin == new_plugin else "DP3"
        print(f"{case} {old_plugin} OR {new_plugin}: set, old, new, wrong: {got}")
        ch.check(f"{case} {old_plugin} {new_plugin}", got, (ch.OK, ch.OK, ch.OK, ch.REFUSED))

    # Two plugins, so that the view's row tells the first method from the second.
    old, new = "Acme-Old-four", "Acme-New-four"
    old_value = ch.COMPUTE["mysql_native_password"](old)
    new_value = ch.COMPUTE["ed25519"](new)
    answer = both(service, ("mysql_native_password", old), ("ed25519", new))
    if answer != ch.OK:
        raise ch.StepError(f"{service}: DP4's OR was refused: {answer}")
    plugin, string = ch.root(
        service,
        "SELECT plugin, authentication_string FROM mysql.user "
        f"WHERE user = '{ch.ACCOUNT}' AND host = '%'",
    ).split("\t")
    view = (
        "first"
        if (plugin, string) == ("mysql_native_password", old_value)
        else "second"
        if (plugin, string) == ("ed25519", new_value)
        else f"neither: {plugin}"
    )
    shown = ch.root(service, f"SHOW CREATE USER {ACCOUNT}")
    values = sum(shown.count(value) for value in (old_value, new_value))
    count = auth_or(service)
    print(
        f"DP4 view's plugin and value: the {view} method's; auth_or: {count}; "
        f"SHOW CREATE USER values: {values}, OR: {' OR ' in shown}"
    )
    ch.check("DP4", (view, count, values, " OR " in shown), ("first", "2", 2, True))

    answer = ch.as_tool(
        service,
        f"ALTER USER {ACCOUNT} IDENTIFIED VIA ed25519 USING '{new_value}'",
    )
    got = (answer, ch.login(service, old), ch.login(service, new), auth_or(service))
    print(f"DP5 new alone: set, old, new, auth_or: {got}")
    ch.check("DP5", got, (ch.OK, ch.REFUSED, ch.OK, "1"))


def main() -> int:
    return ch.run(probe)


if __name__ == "__main__":
    sys.exit(main())
