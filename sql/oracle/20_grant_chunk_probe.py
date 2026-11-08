"""sopuli-dba : how many grantees should one privilege-survey statement bind?   (v1)

#1396. UC-5's privilege survey (driver/oracle/grants.py) sent four statements
per grantee. The proposal anchors each statement on ``grantee IN (:g0, …)``
instead, for up to 1,000 grantees, Oracle's IN-list limit. This times
``survey_grants`` itself, with its ``CHUNK`` set to each size, as SYSTEM:

  GC1  fixtures: ACME_M_OWNER with 20 tables; roles ACME_M_R0 to ACME_M_R9, of
       which R0 holds R1, R1 holds R2, R2 holds R3, and R4 holds R1, each with
       SELECT on one table and INSERT on another, R3 with CREATE TABLE and R5
       with CREATE VIEW; and 1,100 accounts, ACME_M0000_USER to
       ACME_M1099_USER, each with CREATE SESSION, two roles (one of them not a
       default role), SELECT on three tables and UPDATE on one column
  GC2  the first 303 accounts that Oracle does not maintain, and PUBLIC:
       CHUNK 1 (one grantee per statement, as before #1396, though bound as
       ``IN (:g0)`` rather than ``= :grantee``) three times, then
       CHUNK 100, 250 and 1,000 five times each, in turn, with the shared pool
       flushed before each (cold) and without (warm). Every run's survey is
       compared with the first one's
  GC3  GC2 for all 1,103 accounts, with CHUNK 1 once
  GC4  drops the fixtures

It MEASURES and decides nothing. The decision is grants.CHUNK. No statement
reads a password or verifier column.

STATUS: run on 26ai Free 23.26.3.0.0 (gvenzl/oracle-free:latest), with Instant
Client 23.26.3.0.0 for Windows and python-oracledb in thick mode, 2026-11-08.
Run twice. The first run shared the database with a tier-1 test, so only the
second is quoted; its 64 surveys all returned the same rows as its first.

RESULTS -- 26ai Free 23.26.3.0.0 (seconds, median of the runs)

                     303 accounts      1,103 accounts
                     cold    warm      cold    warm
  CHUNK 1              --    58.2        --   221.0  (3 runs and 1 run)
  CHUNK 100           3.7     1.8       6.5     5.3
  CHUNK 250           3.4     1.1       6.2     3.1
  CHUNK 1000          2.7     0.7      12.2     2.0

  Statements: 4 per chunk, so 1,216 and 4,416 with CHUNK 1, and 8 and 20 with
  CHUNK 250. Cold is with the shared pool flushed before the survey. The
  first parse of a statement grows faster than its IN list: cold, 1,103
  accounts took twice as long in chunks of 1,000 as in chunks of 250. Warm,
  the larger chunk was faster at both sizes.

HOW TO RUN (from the repo root, against the tier-1 stack):

    python sql/oracle/20_grant_chunk_probe.py

It connects as SYSTEM to FREEPDB1 at 127.0.0.1 and SOPULI_TEST_ORACLE_PORT,
with tier 1's public password from test/compose.yaml. Against any other
database, copy the file, edit the constants in the copy, run the copy and delete
it, as 07 prescribes. It first drops every ACME_M account and role an earlier
run left.

THROWAWAY DATABASES ONLY. It flushes the shared pool, creates 1,100 accounts
and drops them.
"""

from __future__ import annotations

import os
import statistics
import time

import oracledb

from sopuli.driver.oracle import grants
from sopuli.driver.oracle import session as oracle_session

PORT = os.environ.get("SOPULI_TEST_ORACLE_PORT", "1521")
DSN = f"127.0.0.1:{PORT}/FREEPDB1"
USER = "system"
PASSWORD = "sopuli-test"

OWNER = "ACME_M_OWNER"
TABLES = 20
ROLES = 10
ACCOUNTS = 1100
SIZES = (100, 250, 1000)


def account(index: int) -> str:
    return f"ACME_M{index:04d}_USER"


def fixtures(cursor: oracledb.Cursor) -> None:
    """GC1."""
    run = cursor.execute
    run(f"create user {OWNER} no authentication quota unlimited on users")
    for table in range(TABLES):
        run(f"create table {OWNER}.T{table} (id number, note varchar2(10))")
    for role in range(ROLES):
        run(f"create role ACME_M_R{role}")
    for holder, held in ((0, 1), (1, 2), (2, 3), (4, 1)):
        run(f"grant ACME_M_R{held} to ACME_M_R{holder}")
    for role in range(ROLES):
        run(f"grant select on {OWNER}.T{role} to ACME_M_R{role}")
        run(f"grant insert on {OWNER}.T{role + 10} to ACME_M_R{role}")
    run("grant create table to ACME_M_R3")
    run("grant create view to ACME_M_R5")
    for index in range(ACCOUNTS):
        name = account(index)
        run(f"create user {name} no authentication")
        run(f"grant create session to {name}")
        run(f"grant ACME_M_R{index % 5}, ACME_M_R{5 + index % 5} to {name}")
        run(f"alter user {name} default role ACME_M_R{index % 5}")
        for offset in range(3):
            run(f"grant select on {OWNER}.T{(index + offset) % TABLES} to {name}")
        run(f"grant update (note) on {OWNER}.T{index % TABLES} to {name}")


def drop(cursor: oracledb.Cursor) -> None:
    """GC4. Also run first, so a run that stopped part way is cleaned up."""
    cursor.execute("select username from dba_users where username like 'ACME\\_M%' escape '\\'")
    for (name,) in cursor.fetchall():
        cursor.execute(f"drop user {name} cascade")
    cursor.execute("select role from dba_roles where role like 'ACME\\_M\\_R%' escape '\\'")
    for (role,) in cursor.fetchall():
        cursor.execute(f"drop role {role}")


def timed(
    cursor: oracledb.Cursor, accounts: list[str], size: int, *, cold: bool
) -> tuple[float, int, grants.GrantSurvey]:
    """One survey with ``CHUNK`` at ``size``: seconds, statements, survey."""
    if cold:
        cursor.execute("alter system flush shared_pool")
    counted = _Counting(cursor)
    grants.CHUNK = size
    start = time.perf_counter()
    survey = grants.survey_grants(counted, accounts, public=True)
    return time.perf_counter() - start, counted.statements, survey


class _Counting:
    """The cursor, counting the statements sent through it."""

    def __init__(self, cursor: oracledb.Cursor) -> None:
        self.cursor = cursor
        self.statements = 0

    def execute(self, sql: str, parameters: object = None) -> object:
        self.statements += 1
        return self.cursor.execute(sql, parameters)

    def __getattr__(self, name: str) -> object:
        return getattr(self.cursor, name)


def step(cursor: oracledb.Cursor, label: str, accounts: list[str], old_runs: int) -> None:
    """GC2 or GC3."""
    print(f"{label}  {len(accounts)} accounts and PUBLIC")
    first: grants.GrantSurvey | None = None
    plan = [(1, False)] * old_runs
    for cold in (True, False):
        for run in range(5):
            sizes = SIZES if run % 2 == 0 else tuple(reversed(SIZES))
            plan.extend((size, cold) for size in sizes)
    times: dict[tuple[int, bool], list[float]] = {}
    for size, cold in plan:
        seconds, statements, survey = timed(cursor, accounts, size, cold=cold)
        if first is None:
            first = survey
            print(
                f"  rows: roles {len(survey.roles)}, system {len(survey.system or ())}, "
                f"objects {len(survey.objects or ())}, columns {len(survey.columns or ())}"
            )
        same = "same rows" if survey == first else "DIFFERENT ROWS"
        print(
            f"  CHUNK {size:4d} {'cold' if cold else 'warm'}  {seconds:7.3f}s  "
            f"{statements:5d} statements  {same}"
        )
        times.setdefault((size, cold), []).append(seconds)
    for (size, cold), values in times.items():
        median = statistics.median(values)
        print(
            f"  CHUNK {size:4d} {'cold' if cold else 'warm'}  median {median:7.3f}s"
            f"  min {min(values):7.3f}s  max {max(values):7.3f}s  ({len(values)} runs)"
        )


def main() -> None:
    oracle_session.initialise(env=os.environ)
    with oracledb.connect(user=USER, password=PASSWORD, dsn=DSN) as connection:
        cursor = connection.cursor()
        cursor.execute("select version_full from v$instance")
        print(f"release {cursor.fetchone()[0]}")
        drop(cursor)
        try:
            fixtures(cursor)
            cursor.execute(
                "select username from dba_users where oracle_maintained = 'N' order by username"
            )
            accounts = [name for (name,) in cursor.fetchall()]
            step(cursor, "GC2", accounts[:303], old_runs=3)
            step(cursor, "GC3", accounts, old_runs=1)
        finally:
            drop(cursor)


if __name__ == "__main__":
    main()
