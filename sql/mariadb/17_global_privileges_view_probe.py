"""sopuli-dba : the optional view of global privileges on MariaDB

#1483, option C, decided by the maintainer on 2026-11-12. 08_split_privileges_probe.py
found that the privileges split from SUPER set no column of the mysql.user
view: the tool account cannot read them without reading the stored values
beside them. This measures a second optional view that a DBA creates with SQL
SECURITY DEFINER, beside 16_definer_view_probe.py's account_state:

    CREATE SQL SECURITY DEFINER VIEW sopuli_probe.global_privileges AS
    SELECT GRANTEE, PRIVILEGE_TYPE, IS_GRANTABLE
      FROM information_schema.USER_PRIVILEGES

and, for comparison, the access key of mysql.global_priv's Priv, which holds
the same privileges as bits. Its definer is a locked account. The tool account
holds the grants of 02-mariadb-privileges.md §2.1 and SELECT on the view,
unless a step says otherwise.

  GP1  the bits: an account granted each privilege of SHOW PRIVILEGES alone
       ON *.*, other than USAGE and PROXY, and then ALL PRIVILEGES WITH GRANT
       OPTION. As root: the access value of each, and the version_id of Priv
  GP2  the view, with a definer that holds SELECT ON mysql.*: for an account
       granted each privilege SHOW PRIVILEGES gives the context Server, alone,
       one granted SUPER, one granted ALL PRIVILEGES WITH GRANT OPTION, one
       with USAGE only, one at host 192.0.2.% whose name holds a quote, and
       one whose privilege, CONNECTION ADMIN, comes from its default role:
       whether the privileges the tool account reads through the view, and
       IS_GRANTABLE, are those root's SHOW GRANTS gives for ON *.*. Then the
       rows of the role, and the GRANTEE of the quoted name
  GP3  the definer's grant: how many accounts the view shows when its
       definer holds SELECT ON mysql.global_priv only, SELECT ON mysql.user
       only, and SELECT ON mysql.*, and whether the tool account's own row is
       one of them
  GP4  the capability: what the tool account gets from a SELECT and from
       information_schema.COLUMNS when the view is absent from an existing
       schema, when the schema is absent, when the view exists without the
       grant, when its definer has been dropped, and when the view has been
       dropped and the tool account's grant on it left. SHOW CREATE VIEW and
       EXPLAIN as the tool account
  GP5  whether anything the tool account reads in GP2 to GP4 holds a stored
       value, as 16_definer_view_probe.py's DV1 checks. Root reads the
       fixture's stored values to compare, and the probe prints only whether
       one was found. A run that reads no stored value to compare with fails
  GP6  the cost: about 500 accounts, each granted one privilege, and how
       long the tool account takes to read every row of the view
  GP7  upgrades: on a data directory of its own, accounts granted SUPER,
       REPLICATION CLIENT, REPLICATION SLAVE and ALL PRIVILEGES on 10.4 and
       on 10.6, and the view, created on 10.6. Then the images mariadb:10.4,
       mariadb:10.6, mariadb:10.11, mariadb:11.4, mariadb:11.8 and
       mariadb:12.3 in turn with MARIADB_AUTO_UPGRADE=1. After each start:
       each account's access and version_id as root reads them, and whether
       the view gives the tool account what root's SHOW GRANTS gives. Then
       GP5's check over everything the tool account read in GP7

It MEASURES and decides nothing.

STATUS: GP1 to GP6 run on 10.11.19, 11.4.13, 11.8.9 and 12.3.3, the
mariadb:10.11, mariadb:11.4, mariadb:11.8 and mariadb:12.3 images of
test/compose.yaml profile mariadb-matrix, on 2026-11-12 (#1483), with Python
3.13.12 on Windows 11 AMD64. GP7 run on the images mariadb:10.4, 10.4.34,
and mariadb:10.6, 10.6.28, pulled on 2026-11-12, and then the same four.
Twice, exit 0, and the same results both times but the timings. Run twice
again after review fixes, with the same results, GP7's leak check included.

RESULTS

  GP1  the same bits on every release: bit 0 SELECT to bit 29 DELETE
       HISTORY, then SET USER 30, FEDERATED ADMIN 31, CONNECTION ADMIN 32,
       READ_ONLY ADMIN 33, REPLICATION SLAVE ADMIN 34, REPLICATION MASTER
       ADMIN 35, BINLOG ADMIN 36, BINLOG REPLAY 37 and SLAVE MONITOR 38.
       SUPER is bit 15, GRANT OPTION bit 10 and BINLOG MONITOR bit 20, the
       bit of REPLICATION CLIENT. 11.4.13 and later add SHOW CREATE ROUTINE,
       bit 39. ALL PRIVILEGES WITH GRANT OPTION reads 549755813887 on
       10.11.19 and 1099511627775 later. version_id is the release that last
       wrote the row: 101119, 110413, 110809 and 120303
  GP2  the view and SHOW GRANTS agree on all 15 accounts, on every release:
       each split privilege alone, SUPER, ALL PRIVILEGES, whose rows are
       IS_GRANTABLE YES, USAGE only, and the name with a quote. The member of the role reads USAGE
       only: a privilege through a role is not in the member's rows. The role
       has no row. GRANTEE does not escape a quote in a name:
       'sopuli_probe_gp_o'q'@'192.0.2.%'
  GP3  a definer with SELECT ON mysql.global_priv or SELECT ON mysql.user
       only: the view answers, with one account, the definer itself, and no
       row for the tool account. With SELECT ON mysql.*: all 23 accounts, the
       tool account's own row among them
  GP4  present: rows, and 3 COLUMNS rows. SHOW CREATE VIEW 1142 (42000),
       EXPLAIN 1345 (HY000). Without the grant: 1142 (42000), 0 COLUMNS
       rows. Definer dropped: 1045 (28000) in a logged-in session, and 3
       COLUMNS rows. View dropped with the tool account's grant left: 1146
       (42S02), 0 rows. View absent and schema absent: 1142 (42000), 0 rows
  GP5  no stored value in anything the tool account read: 74 outputs, 2
       values, on every release
  GP6  525 accounts and roles: 634 rows on 10.11.19 and 637 later, in
       0.001 s or less
  GP7  the stored bits never change. An account written by 10.4.34 keeps
       version_id NULL and its access value through every upgrade, and one
       written by 10.6.28 keeps 100628. What they mean changes with the
       release that reads them. SUPER written by 10.4.34 reads, in SHOW
       GRANTS, as SUPER and seven split privileges on 10.6.28 and 10.11.19,
       and as SUPER and all ten from 11.4.13. SUPER written by 10.6.28 reads
       as SUPER on 10.6.28, as SUPER and READ_ONLY ADMIN on 10.11.19, and as
       SUPER and all ten from 11.4.13. REPLICATION CLIENT written by 10.4.34
       reads as BINLOG MONITOR and SLAVE MONITOR from 10.6.28. On every
       release, for every account, the view gives what SHOW GRANTS gives,
       and no stored value reached the tool account: 80 outputs, 2 values

  So the access bits are not a reading of the privileges: the same stored
  value means different privileges on different releases, and only the
  server knows which. information_schema.USER_PRIVILEGES gives the
  privileges as the server applies them, through a definer view, without a
  stored value, for accounts and never for roles. Its definer needs SELECT
  ON mysql.*. With less, the view still answers, with the definer's row
  alone, and the tool account's own row is missing.

HOW TO RUN, against the matrix (test/README.md), from the repo root:

    .venv/Scripts/python sql/mariadb/17_global_privileges_view_probe.py

It needs 02_client_hash_probe.py and 15_report_read_probe.py beside it, and
what 02 needs: sql/mysql/02_client_hash_probe.py. GP7 needs the six images
pulled and docker run; it uses the container {COMPOSE_PROJECT_NAME}-gp-upgrade-1
and the volume {COMPOSE_PROJECT_NAME}-gp-upgrade, and removes both.

THROWAWAY SERVERS ONLY. It creates accounts, roles and a schema whose names
start sopuli_probe_ and drops them at the end, also after a failed step.
Before it starts, it drops what an interrupted run left.
"""

from __future__ import annotations

import importlib.util
import re
import subprocess
import sys
import time
from pathlib import Path


def _load(name: str, file: str):  # type: ignore[no-untyped-def]
    # The probes' names start with a digit, so they are loaded by path.
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(file))
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


rr = _load("mariadb_report_read_probe", "15_report_read_probe.py")
ch = rr.ch

TOOL = rr.TOOL
SCHEMA = "sopuli_probe"
VIEW = f"{SCHEMA}.global_privileges"
VIEW_SQL = "SELECT GRANTEE, PRIVILEGE_TYPE, IS_GRANTABLE FROM information_schema.USER_PRIVILEGES"
#: A test password, not a credential.
PASSWORD = "Acme-Grants-pw1"
P = "sopuli_probe_gp_"
DEFINER = f"'{P}definer'@'localhost'"
#: A name with a quote in it, at a documentation host.
QUOTED = (f"{P}o'q", "192.0.2.%")
#: The schema, the locked definer, the view, and the tool account's grant on it.
VIEW_STATEMENTS = (
    f"CREATE DATABASE {SCHEMA}",
    f"CREATE USER {DEFINER} IDENTIFIED BY '{PASSWORD}' ACCOUNT LOCK",
    f"GRANT SELECT ON mysql.* TO {DEFINER}",
    f"CREATE DEFINER = {DEFINER} SQL SECURITY DEFINER VIEW {VIEW} AS {VIEW_SQL}",
    f"GRANT SELECT ON {VIEW} TO {TOOL}",
)
BULK = 500
FIXTURE_LIKE = rr.FIXTURE_LIKE

#: Everything the tool account read on this server, refusals included.
SEEN: list[str] = []
#: The fixture's stored values, as root reads them. Never printed.
STORED: set[str] = set()
LEAKED: list[str] = []


def root(service: str, statement: str) -> str:
    return str(ch.root(service, statement))


def tool(service: str, statement: str) -> str:
    """What the tool account reads, or the refusal's error number and SQLSTATE."""
    returncode, out, err = ch.client(service, ch.TOOL, ch.TOOL_PASSWORD, statement, "-h127.0.0.1")
    SEEN.append(out)
    SEEN.append(err)
    if returncode == 0:
        return out
    found = re.search(r"^ERROR (\d+ \(\w+\))", err, re.MULTILINE)
    if found is None:
        raise ch.StepError(f"{service}: tool account: {(err or out)[:200]}")
    return found[1]


def account(user: str, host: str = "%") -> str:
    return f"{ch.quote(user)}@{ch.quote(host)}"


def clean(service: str) -> None:
    """15's clean-up: every sopuli_probe_ account and role, and the schema.

    The account whose name holds a quote goes first: 15's clean-up reads names
    through the client, which escapes the quote.
    """
    root(service, f"DROP USER IF EXISTS {account(*QUOTED)}")
    rr.clean(service)


def remember(service: str) -> None:
    rows = root(service, f"SELECT Priv FROM mysql.global_priv WHERE User LIKE {FIXTURE_LIKE}")
    for found in re.findall(r'"authentication_string":"([^"]+)"', rows):
        STORED.add(found)


# ------------------------------------------------------------ what's read --


def all_privileges(service: str) -> set[str]:
    """What ALL PRIVILEGES means on this server: SHOW PRIVILEGES, less three."""
    names = {line.split("\t")[0].upper() for line in root(service, "SHOW PRIVILEGES").splitlines()}
    return names - {"USAGE", "PROXY", "GRANT OPTION"}


def shown(service: str, who: str, everything: set[str]) -> tuple[set[str], bool]:
    """The privileges root's SHOW GRANTS gives `who` ON *.*, and WITH GRANT OPTION.

    Only the words before ON and the end of the line are kept: the line may
    hold a stored value.
    """
    for line in root(service, f"SHOW GRANTS FOR {who}").splitlines():
        found = re.match(r"GRANT (.+?) ON \*\.\* TO ", line)
        if found is None:
            continue
        grantable = line.rstrip().endswith("WITH GRANT OPTION")
        names = {name.strip() for name in found[1].split(",")}
        if names == {"ALL PRIVILEGES"}:
            names = set(everything)
        return names, grantable
    return set(), False


def viewed(service: str, grantee: str) -> tuple[set[str], set[str]] | str:
    """The privileges and IS_GRANTABLE values the tool account reads for one GRANTEE."""
    out = tool(
        service,
        f"SELECT PRIVILEGE_TYPE, IS_GRANTABLE FROM {VIEW} WHERE GRANTEE = {ch.quote(grantee)}",
    )
    if re.fullmatch(r"\d+ \(\w+\)", out):
        return out
    rows = [line.split("\t") for line in out.splitlines() if line]
    return {name for name, _ in rows}, {grantable for _, grantable in rows}


def grantee(user: str, host: str = "%") -> str:
    """information_schema's GRANTEE for an account: each part in single quotes, unescaped."""
    return f"'{user}'@'{host}'"


def agree(service: str, user: str, host: str, everything: set[str]) -> str:
    """`same`, or how the view and SHOW GRANTS differ for one account."""
    names, grantable = shown(service, account(user, host), everything)
    got = viewed(service, grantee(user, host))
    if isinstance(got, str):
        return got
    privileges, grantables = got
    if not names:
        names = {"USAGE"}
    view_grantable = grantables == {"YES"}
    if privileges == names and view_grantable == grantable:
        return "same"
    return (
        f"view only {sorted(privileges - names)}, SHOW GRANTS only {sorted(names - privileges)},"
        f" IS_GRANTABLE {sorted(grantables)} against WITH GRANT OPTION {grantable}"
    )


# ------------------------------------------------------------------ setup --


def setup(service: str) -> list[tuple[str, str]]:
    """The fixture, and the accounts GP2 compares."""
    server = [
        line.split("\t")[0]
        for line in root(service, "SHOW PRIVILEGES").splitlines()
        if line.split("\t")[1] == "Server"
    ]
    statements = [
        f"CREATE USER {TOOL} IDENTIFIED BY {ch.quote(ch.TOOL_PASSWORD)}",
        *rr.TOOL_GRANTS,
        *VIEW_STATEMENTS,
    ]
    compared: list[tuple[str, str]] = []
    for n, name in enumerate(server):
        user = f"{P}s{n}"
        statements.append(f"CREATE USER {account(user)} IDENTIFIED BY {ch.quote(PASSWORD)}")
        statements.append(f"GRANT {name} ON *.* TO {account(user)}")
        compared.append((user, "%"))
    for user, grant in (
        (f"{P}super", "GRANT SUPER ON *.* TO {a}"),
        (f"{P}all", "GRANT ALL PRIVILEGES ON *.* TO {a} WITH GRANT OPTION"),
        (f"{P}usage", ""),
        (f"{P}member", ""),
    ):
        statements.append(f"CREATE USER {account(user)} IDENTIFIED BY {ch.quote(PASSWORD)}")
        if grant:
            statements.append(grant.format(a=account(user)))
        compared.append((user, "%"))
    statements += [
        f"CREATE USER {account(*QUOTED)} IDENTIFIED BY {ch.quote(PASSWORD)}",
        f"GRANT PROCESS ON *.* TO {account(*QUOTED)}",
        f"CREATE ROLE {P}role",
        f"GRANT CONNECTION ADMIN ON *.* TO {P}role",
        f"GRANT {P}role TO {account(P + 'member')}",
        f"SET DEFAULT ROLE {P}role FOR {account(P + 'member')}",
    ]
    compared.append(QUOTED)
    root(service, ";".join(statements))
    remember(service)
    return compared


# ------------------------------------------------------------------ steps --


def bit(value: str) -> str:
    """`bit N` for a power of two, or the value."""
    if value.isdigit() and int(value) and int(value) & (int(value) - 1) == 0:
        return f"bit {int(value).bit_length() - 1}"
    return value


def gp1(service: str) -> None:
    names = [
        line.split("\t")[0]
        for line in root(service, "SHOW PRIVILEGES").splitlines()
        if line.split("\t")[0].upper() not in ("USAGE", "PROXY")
    ]
    # One account per privilege, bit0, bit1, ..., and `every` for ALL PRIVILEGES.
    statements = []
    for n, name in enumerate(names):
        user = account(f"{P}bit{n}")
        statements += [f"CREATE USER {user}", f"GRANT {name} ON *.* TO {user}"]
    every_user = account(f"{P}every")
    statements += [
        f"CREATE USER {every_user}",
        f"GRANT ALL PRIVILEGES ON *.* TO {every_user} WITH GRANT OPTION",
    ]
    root(service, ";".join(statements))
    read = root(
        service,
        "SELECT User, JSON_VALUE(Priv, '$.access'), JSON_VALUE(Priv, '$.version_id')"
        f" FROM mysql.global_priv WHERE User LIKE '{P}bit%' OR User = '{P}every'",
    )
    values = {}
    for line in read.splitlines():
        user, value, version = (line.split("\t") + ["", "", ""])[:3]
        values[user] = (value, version)
    every, version = values.pop(f"{P}every")
    bits = [(bit(values[f"{P}bit{n}"][0]), name) for n, name in enumerate(names)]
    root(service, "DROP USER " + ", ".join(account(user) for user in [*values, f"{P}every"]))
    order = sorted(
        bits, key=lambda pair: int(pair[0].split()[1]) if pair[0].startswith("bit") else 99
    )
    print(f"  GP1  {len(bits)} privileges: " + "; ".join(f"{b} {n}" for b, n in order))
    print(f"  GP1  ALL PRIVILEGES WITH GRANT OPTION: {every}; version_id {version}")


def gp2(service: str, compared: list[tuple[str, str]]) -> None:
    everything = all_privileges(service)
    differ = []
    for user, host in compared:
        result = agree(service, user, host, everything)
        if result != "same":
            differ.append(f"{user}@{host}: {result}")
    print(
        f"  GP2  {len(compared)} accounts: the view and SHOW GRANTS agree on"
        f" {len(compared) - len(differ)}"
    )
    for line in differ:
        print(f"  GP2    differs: {line}")
    member = viewed(service, grantee(P + "member"))
    print(f"  GP2  the member of the role, through the view: {member}")
    role = tool(service, f"SELECT COUNT(*) FROM {VIEW} WHERE GRANTEE LIKE '%{P}role%'")
    print(f"  GP2  rows for the role: {role}")
    quoted = tool(
        service,
        f"SELECT GRANTEE FROM {VIEW} WHERE GRANTEE LIKE '%192.0.2.%'",
    )
    print(f"  GP2  GRANTEE of {QUOTED[0]!r} at {QUOTED[1]}: {quoted or 'no row'}")


def regrant(service: str, grant: str) -> None:
    """Leave the definer holding `grant` alone."""
    root(service, f"REVOKE ALL PRIVILEGES, GRANT OPTION FROM {DEFINER}; GRANT {grant} TO {DEFINER}")


def gp3(service: str) -> None:
    accounts = root(service, "SELECT COUNT(*) FROM mysql.global_priv WHERE Host <> ''")
    own = grantee(ch.TOOL)
    results = []
    for grant in ("SELECT ON mysql.global_priv", "SELECT ON mysql.user", "SELECT ON mysql.*"):
        regrant(service, grant)
        out = tool(
            service,
            f"SELECT COUNT(DISTINCT GRANTEE), SUM(GRANTEE = {ch.quote(own)}) > 0 FROM {VIEW}",
        )
        count, has_own = (out.split("\t") + ["?"])[:2]
        results.append(f"{grant}: {count} of {accounts} accounts, own row {has_own}")
    print("  GP3  " + "; ".join(results))


def gp4(service: str) -> None:
    def columns() -> str:
        return tool(
            service,
            "SELECT COUNT(*) FROM information_schema.COLUMNS"
            f" WHERE TABLE_SCHEMA = '{SCHEMA}' AND TABLE_NAME = 'global_privileges'",
        )

    def state(label: str) -> None:
        answer = tool(service, f"SELECT COUNT(*) FROM {VIEW}")
        selected = "rows" if answer.isdigit() else answer
        print(f"  GP4  {label}: SELECT {selected}, COLUMNS {columns()}")

    state("present")
    ddl = tool(service, f"SHOW CREATE VIEW {VIEW}")
    explain = tool(service, f"EXPLAIN SELECT * FROM {VIEW}")
    print(
        f"  GP4  SHOW CREATE VIEW {ddl if len(ddl) < 20 else 'answers'},"
        f" EXPLAIN {explain if len(explain) < 20 else 'answers'}"
    )
    root(service, f"REVOKE SELECT ON {VIEW} FROM {TOOL}")
    state("without the grant")
    root(service, f"GRANT SELECT ON {VIEW} TO {TOOL}; DROP USER {DEFINER}")
    state("definer dropped")
    root(service, f"DROP VIEW {VIEW}")
    state("view dropped, its grant left")
    root(service, f"REVOKE SELECT ON {VIEW} FROM {TOOL}")
    state("view absent")
    root(service, f"DROP DATABASE {SCHEMA}")
    state("schema absent")


def gp5(service: str, step: str = "GP5") -> None:
    """Whether a stored value reached the tool account. setup() and gp7() fill STORED."""
    if not STORED:
        raise ch.StepError(f"{service}: no stored value read to compare with")
    found = [value for value in STORED if any(value in text for text in SEEN)]
    print(
        f"  {step}  stored values in anything the tool account read ({len(SEEN)} outputs,"
        f" {len(STORED)} values): {len(found) or 'none'}"
    )
    if found:
        LEAKED.append(service)


def gp6(service: str) -> None:
    names = ("PROCESS", "CONNECTION ADMIN", "SELECT", "BINLOG MONITOR", "SUPER")
    statements = []
    for n in range(BULK):
        user = account(f"{P}b{n}")
        statements.append(f"CREATE USER {user}")
        statements.append(f"GRANT {names[n % len(names)]} ON *.* TO {user}")
    for start in range(0, len(statements), 400):
        root(service, ";".join(statements[start : start + 400]))
    accounts = root(service, "SELECT COUNT(*) FROM mysql.global_priv")
    batch = ";".join(
        f"SET @t = NOW(6); SELECT COUNT(*) INTO @n FROM {VIEW};"
        " SELECT TIMESTAMPDIFF(MICROSECOND, @t, NOW(6))"
        for _ in range(3)
    )
    rows = tool(service, f"SELECT COUNT(*) FROM {VIEW}")
    times = [int(line) / 1e6 for line in tool(service, batch).splitlines() if line]
    print(
        f"  GP6  {accounts} accounts and roles: {rows} rows"
        f" in {min(times):.3f} to {max(times):.3f} s"
    )


def probe(service: str) -> None:
    release = root(service, "SELECT VERSION()")
    print(f"\n== {service}: {release}")
    SEEN.clear()
    STORED.clear()
    clean(service)
    try:
        gp1(service)
        compared = setup(service)
        gp2(service, compared)
        gp3(service)
        regrant(service, "SELECT ON mysql.*")
        gp6(service)
        gp4(service)
        gp5(service)
    finally:
        clean(service)


# --------------------------------------------------------------- upgrades --

UPGRADE = "gp-upgrade"
IMAGES = (
    "mariadb:10.4", "mariadb:10.6", "mariadb:10.11", "mariadb:11.4", "mariadb:11.8", "mariadb:12.3",
)  # fmt: skip
OLD_GRANTS = (
    ("super", "SUPER"),
    ("rc", "REPLICATION CLIENT"),
    ("rs", "REPLICATION SLAVE"),
    ("all", "ALL PRIVILEGES"),
)


def docker(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["docker", *args], capture_output=True, text=True, check=False)


def upgrade_names() -> tuple[str, str]:
    return ch.base.container(UPGRADE), f"{ch.base.PROJECT}-{UPGRADE}"


def upgrade_clean() -> None:
    container, volume = upgrade_names()
    docker("rm", "-f", container)
    docker("volume", "rm", "-f", volume)


def start(image: str) -> None:
    container, volume = upgrade_names()
    docker("rm", "-f", container)
    started = docker(
        "run", "-d", "--name", container, "-v", f"{volume}:/var/lib/mysql",
        "-e", f"MARIADB_ROOT_PASSWORD={ch.ROOT_PASSWORD}", "-e", "MARIADB_AUTO_UPGRADE=1",
        image,
    )  # fmt: skip
    if started.returncode:
        raise ch.StepError(f"docker run {image}: {started.stderr.strip()[:200]}")
    for _ in range(90):
        time.sleep(2)
        # The entrypoint first starts a temporary server without networking, which
        # logs "port: 0". The real server logs the port it listens on.
        if "port: 3306" not in docker("logs", container).stderr:
            continue
        ready = docker("exec", container, "healthcheck.sh", "--connect", "--innodb_initialized")
        if ready.returncode == 0:
            return
    raise ch.StepError(
        f"{image}: not healthy after 3 minutes:"
        f" {docker('logs', '--tail', '5', container).stderr[-300:]}"
    )


def gp7() -> None:
    print(f"\n== GP7: upgrades, {' > '.join(IMAGES)}")
    upgrade_clean()
    SEEN.clear()
    STORED.clear()
    container, _ = upgrade_names()
    users: list[str] = []
    try:
        for n, image in enumerate(IMAGES):
            if n:
                stopped = docker("stop", "-t", "60", container)
                if stopped.returncode:
                    raise ch.StepError(f"docker stop: {stopped.stderr.strip()[:200]}")
            start(image)
            release = root(UPGRADE, "SELECT VERSION()").split("-")[0]
            if image in ("mariadb:10.4", "mariadb:10.6"):
                tag = release.replace(".", "_")
                for key, grant in OLD_GRANTS:
                    user = f"{P}{key}_{tag}"
                    users.append(user)
                    root(
                        UPGRADE,
                        f"CREATE USER {account(user)} IDENTIFIED BY {ch.quote(PASSWORD)};"
                        f"GRANT {grant} ON *.* TO {account(user)}",
                    )
            if image == "mariadb:10.6":
                root(
                    UPGRADE,
                    ";".join(
                        [
                            f"CREATE USER {TOOL} IDENTIFIED BY {ch.quote(ch.TOOL_PASSWORD)}",
                            *VIEW_STATEMENTS,
                        ]
                    ),
                )
            print(f"  GP7  {image}: {release}")
            everything = all_privileges(UPGRADE)
            for user in users:
                stored = root(
                    UPGRADE,
                    "SELECT CONCAT(JSON_VALUE(Priv, '$.access'), ' version_id ',"
                    " COALESCE(JSON_VALUE(Priv, '$.version_id'), 'NULL'))"
                    f" FROM mysql.global_priv WHERE User = '{user}'",
                )
                names, _ = shown(UPGRADE, account(user), everything)
                listed = "ALL" if names == everything else ", ".join(sorted(names))
                # The view is created on the second image.
                view = agree(UPGRADE, user, "%", everything) if n > 0 else "no view yet"
                print(f"  GP7    {user}: access {stored}; SHOW GRANTS {listed}; view {view}")
            remember(UPGRADE)
        gp5(UPGRADE, "GP7")
    finally:
        upgrade_clean()


def main() -> int:
    """Run the probe on each server, then GP7. Exit 1 when a step fails or a value leaks."""
    failed = False
    for service in ch.base.SERVICES:
        try:
            probe(service)
        except (ch.StepError, ValueError, IndexError) as exc:
            print(f"STEP FAILED: {service}: {type(exc).__name__}: {exc}")
            failed = True
    try:
        gp7()
    except (ch.StepError, ValueError, IndexError) as exc:
        print(f"STEP FAILED: GP7: {type(exc).__name__}: {exc}")
        failed = True
    if LEAKED:
        print(f"\nA STORED VALUE REACHED THE TOOL ACCOUNT on {', '.join(LEAKED)}")
    print("\nA STEP FAILED" if failed else "\nevery step ran; no result is checked")
    return 1 if failed or LEAKED else 0


if __name__ == "__main__":
    sys.exit(main())
