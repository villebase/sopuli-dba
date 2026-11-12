"""sopuli-dba : which of an account's roles are active without SET ROLE, on MySQL

#1482. `report privileges` says, for each privilege an account reaches through a
role, whether the account holds it without SET ROLE (UC-5 §5). On MySQL that
depends on the default roles, @@mandatory_roles and
@@activate_all_roles_on_login. 10_report_read_probe.py (#1448) read the two
variables and mysql.default_roles; this measures what they mean for a login.

The fixture, which root creates on each server, all at '%':

  sopuli_probe_app        the account. Granted sopuli_probe_def, set as its
                          default role, and sopuli_probe_plain, not a default
  sopuli_probe_def        a role, granted sopuli_probe_nested
  sopuli_probe_nested     a role
  sopuli_probe_plain      a role
  sopuli_probe_mand       a role, put in @@mandatory_roles for RA2 and RA3
  schema sopuli_probe, with tables t_def, t_nested, t_plain and t_mand, each
  granted SELECT to the role of its name

  RA1  with @@mandatory_roles empty and @@activate_all_roles_on_login OFF:
       CURRENT_ROLE() at login, and which of the four tables the account
       reads. Then the rows of mysql.default_roles and mysql.role_edges for
       the account, as root reads them
  RA2  with sopuli_probe_mand in @@mandatory_roles, the same, and whether
       role_edges or default_roles has a row for the mandatory role
  RA3  the same, after SET DEFAULT ROLE sopuli_probe_def, sopuli_probe_mand
       TO the account: whether the server takes a mandatory role as a
       default role, and what default_roles then holds
  RA4  with @@activate_all_roles_on_login ON, the same as RA2

It MEASURES and decides nothing, and reads no hash. It prints each result and
checks none: compare a new run with RESULTS below by eye. It exits 1 only when
a step fails.

STATUS: run on 8.0.46, 8.4.13 and 9.7.4, the mysql:8.0, mysql:8.4 and
mysql:9 images of test/compose.yaml profile mysql-matrix, on 2026-11-12
(#1482), with Python 3.13.12 on Windows 11 AMD64. Twice, exit 0, the same
result both times.

RESULTS -- the same on every release, except where noted

  RA0  @@mandatory_roles is empty and @@activate_all_roles_on_login 0
  RA1  at login, CURRENT_ROLE() is the default role alone. The account reads
       t_def and **t_nested, which a role of the default role holds**, and is
       refused t_plain and t_mand, 1142 (42000). default_roles has the one
       default role; role_edges has the two roles granted
  RA2  with the mandatory role set: on 8.0.46 and 8.4.13, as RA1: the
       mandatory role is not active, and t_mand is refused, 1142 (42000).
       **On 9.7.4 it is active at login**: CURRENT_ROLE() lists it beside
       the default role, and t_mand reads. On every release neither
       role_edges nor default_roles has a row for it
  RA3  the server takes the mandatory role as a default role. default_roles
       then has both rows, and the mandatory role is active at login, t_mand
       read, on every release
  RA4  with activate_all_roles_on_login ON, every role the account holds is
       active at login, the plain role and the mandatory role included, and
       default_roles is unchanged

  So a role is active without SET ROLE when it is a default role (in
  default_roles), or every role is when activate_all_roles_on_login is ON,
  and a role a role held that way holds is active too. A mandatory role that
  is not a default role is inactive on 8.0.46 and 8.4.13 and active on
  9.7.4, and nothing the tool account reads says which a server does.

HOW TO RUN, against the matrix (test/README.md), from the repo root:

    .venv/Scripts/python sql/mysql/11_role_activation_probe.py

It needs 02_client_hash_probe.py beside it.

THROWAWAY SERVERS ONLY. It creates the accounts, roles and schema above and
drops them at the end. It sets @@mandatory_roles and
@@activate_all_roles_on_login and puts both back, also after a failed step.
Before it starts, it drops what an interrupted run left.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

# 02's name starts with a digit, so it is loaded by its path.
_SPEC = importlib.util.spec_from_file_location(
    "mysql_client_hash_probe", Path(__file__).with_name("02_client_hash_probe.py")
)
assert _SPEC is not None
assert _SPEC.loader is not None
ch = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(ch)

SCHEMA = "sopuli_probe"
APP = "sopuli_probe_app"
ACCOUNT = f"'{APP}'@'%'"
#: A test password, not a credential.
PASSWORD = "Acme-Roles-pw1"
ROLES = ("def", "nested", "plain", "mand")


def role(name: str) -> str:
    return f"'sopuli_probe_{name}'@'%'"


def root(service: str, statement: str) -> str:
    return str(ch.root(service, statement))


def clean(service: str) -> None:
    root(
        service,
        f"DROP USER IF EXISTS {ACCOUNT};"
        + "".join(f"DROP ROLE IF EXISTS {role(name)};" for name in ROLES)
        + f"DROP DATABASE IF EXISTS {SCHEMA}",
    )


def setup(service: str) -> None:
    root(
        service,
        ";".join(
            [
                f"CREATE DATABASE {SCHEMA}",
                *(f"CREATE TABLE {SCHEMA}.t_{name} (n int)" for name in ROLES),
                *(f"CREATE ROLE {role(name)}" for name in ROLES),
                *(f"GRANT SELECT ON {SCHEMA}.t_{name} TO {role(name)}" for name in ROLES),
                f"GRANT {role('nested')} TO {role('def')}",
                f"CREATE USER {ACCOUNT} IDENTIFIED BY {ch.quote(PASSWORD)}",
                f"GRANT {role('def')}, {role('plain')} TO {ACCOUNT}",
                f"SET DEFAULT ROLE {role('def')} TO {ACCOUNT}",
            ]
        ),
    )


def login(service: str, label: str) -> None:
    """CURRENT_ROLE() at login, and which tables the account reads."""
    ok, current = ch.mysql(service, APP, PASSWORD, "SELECT CURRENT_ROLE()")
    print(f"  {label}  CURRENT_ROLE() at login: {current if ok else ch.code(current)}")
    reads = []
    for name in ROLES:
        ok, out = ch.mysql(service, APP, PASSWORD, f"SELECT COUNT(*) FROM {SCHEMA}.t_{name}")
        reads.append(f"t_{name} {'reads' if ok else ch.code(out)}")
    print(f"  {label}  tables: {'; '.join(reads)}")


def rows(service: str, label: str) -> None:
    defaults = root(
        service,
        "SELECT GROUP_CONCAT(CONCAT(DEFAULT_ROLE_USER, '@', DEFAULT_ROLE_HOST)"
        f" ORDER BY DEFAULT_ROLE_USER) FROM mysql.default_roles WHERE USER = '{APP}'",
    )
    edges = root(
        service,
        "SELECT GROUP_CONCAT(CONCAT(FROM_USER, '@', FROM_HOST) ORDER BY FROM_USER)"
        f" FROM mysql.role_edges WHERE TO_USER = '{APP}'",
    )
    print(f"  {label}  default_roles: {defaults}; role_edges: {edges}")


def probe(service: str) -> None:
    release = root(service, "SELECT VERSION()")
    print(f"\n== {service}: {release}")
    was_mandatory = root(service, "SELECT @@global.mandatory_roles")
    was_all = root(service, "SELECT @@global.activate_all_roles_on_login")
    clean(service)
    try:
        setup(service)
        print(f"  RA0  @@mandatory_roles [{was_mandatory}], activate_all {was_all}")
        root(service, "SET GLOBAL activate_all_roles_on_login = OFF")
        login(service, "RA1")
        rows(service, "RA1")
        root(service, f"SET GLOBAL mandatory_roles = {ch.quote(role('mand'))}")
        login(service, "RA2")
        rows(service, "RA2")
        ok, answer = ch.mysql(
            service,
            "root",
            ch.ROOT_PASSWORD,
            f"SET DEFAULT ROLE {role('def')}, {role('mand')} TO {ACCOUNT}",
        )
        print(f"  RA3  SET DEFAULT ROLE def, mand: {'ok' if ok else answer}")
        login(service, "RA3")
        rows(service, "RA3")
        root(service, f"SET DEFAULT ROLE {role('def')} TO {ACCOUNT}")
        root(service, "SET GLOBAL activate_all_roles_on_login = ON")
        login(service, "RA4")
        rows(service, "RA4")
    finally:
        root(service, f"SET GLOBAL mandatory_roles = {ch.quote(was_mandatory)}")
        root(service, f"SET GLOBAL activate_all_roles_on_login = {was_all}")
        clean(service)


def main() -> int:
    """Run the probe on each server. Exit 1 when a step fails on any."""
    failed = False
    for service in ch.SERVICES:
        try:
            probe(service)
        except (ch.StepError, ValueError) as exc:
            print(f"STEP FAILED: {service}: {type(exc).__name__}: {exc}")
            failed = True
    print("\nA STEP FAILED" if failed else "\nevery step ran; no result is checked")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
