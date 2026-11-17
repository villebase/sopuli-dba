"""sopuli-dba : what a disabled login and a must-change login answer to a wrong password

#1552. `creds check` on SQL Server logs in as the login
(`02-mssql-privileges.md` §7). A disabled login answers its right password
18470 (LK1), and one whose MUST_CHANGE is pending answers 18488 (LK5). Until
it is known what each answers to a wrong password, those numbers say nothing
about the password. This measures, for one login of each kind and an open one:

  LA1  an open login: what its right password and a wrong one answer
  LA2  a disabled login (ALTER LOGIN ... DISABLE): what its right password
       and a wrong one answer
  LA3  a login made WITH ... MUST_CHANGE, CHECK_POLICY = ON,
       CHECK_EXPIRATION = ON: what its right password and a wrong one answer
  LA4  a login both disabled and MUST_CHANGE: the same

Each answer is `ok` for a login, or the error number.

STATUS: run on 15.0.4510.2, 16.0.4325.4 and 17.0.5065.9, the
mcr.microsoft.com/mssql/server 2019-latest, 2022-latest and 2025-latest images
of test/compose.yaml profile mssql-matrix, as pulled on 2026-11-15, with
Python 3.13.12 on Windows 11 AMD64, on 2026-11-17 (#1552). Three times, the
last two against this header, exit 0, and the same result every time.

RESULTS -- the same on every release

  LA1  an open login logs in with its right password, and answers a wrong
       one 18456
  LA2  **a disabled login answers a wrong password 18456**, and its right
       one 18470
  LA3  **a must-change login answers a wrong password 18456**, and its right
       one 18488
  LA4  a login both disabled and must-change answers its right password
       18470, and a wrong one 18456

So 18470 and 18488 are answered only to the right password: each says the
password is right, and why the login was still refused.

HOW TO RUN, against the matrix (test/README.md), from the repo root:

    .venv/Scripts/python sql/mssql/15_login_answers_probe.py

It needs 02_client_hash_probe.py beside it.

THROWAWAY SERVERS ONLY. It creates the logins sopuli_probe_la_open,
sopuli_probe_la_off, sopuli_probe_la_must and sopuli_probe_la_both, and drops
them at the end.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

# 02's name starts with a digit, so it is loaded by its path.
_SPEC = importlib.util.spec_from_file_location(
    "mssql_client_hash_probe", Path(__file__).with_name("02_client_hash_probe.py")
)
assert _SPEC is not None
assert _SPEC.loader is not None
ch = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(ch)

#: Test passwords, not credentials.
RIGHT = "Acme-Login-pw1"
WRONG = "Acme-Login-pw9"

#: What follows the password in CREATE LOGIN, for each kind of login.
OPEN_LOGIN = ", CHECK_POLICY = OFF"
MUST_CHANGE = " MUST_CHANGE, CHECK_POLICY = ON, CHECK_EXPIRATION = ON"

#: Each case's login, what follows its password, and what is done after.
LOGINS = {
    "LA1 open": ("sopuli_probe_la_open", OPEN_LOGIN, ""),
    "LA2 disabled": ("sopuli_probe_la_off", OPEN_LOGIN, "DISABLE"),
    "LA3 must change": ("sopuli_probe_la_must", MUST_CHANGE, ""),
    "LA4 disabled and must change": ("sopuli_probe_la_both", MUST_CHANGE, "DISABLE"),
}

#: What each login answers, as (right password, wrong password). The same on
#: every release measured.
RECORDED: dict[str, tuple[str, str]] = {
    "LA1 open": ("ok", "18456"),
    "LA2 disabled": ("18470", "18456"),
    "LA3 must change": ("18488", "18456"),
    "LA4 disabled and must change": ("18470", "18456"),
}


def answer(service: str, name: str, password: str) -> str:
    """`ok` for a login, or the server's error number."""
    _, errors = ch.client(service, name, password, "SELECT 1")
    return ch.code(errors) if errors else "ok"


def drop_all(service: str) -> None:
    for name, _, _ in LOGINS.values():
        ch.sa(service, ch.drop_login(name))


def cases(service: str) -> None:
    ch.setup(service)
    drop_all(service)
    for label, (name, options, after) in LOGINS.items():
        ch.sa(service, f"CREATE LOGIN [{name}] WITH PASSWORD = {ch.quote(RIGHT)}{options}")
        if after:
            ch.sa(service, f"ALTER LOGIN [{name}] {after}")
        # The wrong password first, so a right one cannot have changed the
        # login's state before it is tried.
        wrong = answer(service, name, WRONG)
        got = (answer(service, name, RIGHT), wrong)
        print(f"{label}: right password {got[0]}, wrong password {got[1]}")
        ch.check(label, got, RECORDED.get(label))


def probe(service: str) -> None:
    ch.cleaned(service, lambda: cases(service), lambda: drop_all(service))


def main() -> int:
    return ch.run(probe)


if __name__ == "__main__":
    sys.exit(main())
