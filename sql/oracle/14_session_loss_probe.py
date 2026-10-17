"""sopuli-dba : what the client raises when a database goes away   (v1)

#775. A run that holds a session can lose it: its PDB is closed, or the CDB is
shut down. A run that logs on while the CDB starts gets refused. This records
the code python-oracledb raises in each case, in thick mode, which is the mode
the tool runs in (D3), so the driver maps the codes a run actually gets:

  SL1  a session held on the PDB when the PDB is closed IMMEDIATE: the next
       call, a second call, and a new logon to the PDB
  SL2  a session held on the PDB when the CDB shuts down IMMEDIATE: the next
       call; then, with the instance down, a logon to the PDB service and to
       the CDB service
  SL3  logons while the CDB starts: to the PDB service and to the CDB
       service, in NOMOUNT and in MOUNT
  SL4  a session held on the PDB when the CDB is shut down ABORT: the next
       call

It MEASURES and maps nothing. The mapping is driver/oracle/errors.py.

STATUS: run on 26ai Free 23.26.2.0.0 (gvenzl/oracle-free:latest), with Instant
Client 23.26.3.0.0 for Windows and python-oracledb 26.0.0 in thick mode,
2026-10-17, three times, with the same codes each time.

RESULTS -- 26ai Free 23.26.2.0.0

  SL1  next call: DPY-4011 "the database or network closed the connection".
       Its message goes on "DPI-1080: connection was closed by ORA-03113" and
       "ORA-03113: end-of-file on communication channel", but full_code is
       DPY-4011, so that is the code the tool reads. Second call: DPY-1001
       "not connected to database". New logon: ORA-01109
  SL2  next call: DPY-4011, as SL1. Logons with the instance down: ORA-12514
       to both services
  SL3  NOMOUNT: ORA-12514 to the PDB service, ORA-12528 "all appropriate
       instances are blocking new connections" to the CDB service. MOUNT:
       ORA-12514 to the PDB service, ORA-01033 "initialization or shutdown in
       progress" to the CDB service
  SL4  next call: DPY-4011, as SL1

  Not produced by any step: ORA-00028, ORA-03113 and ORA-03135 as the code
  itself (ORA-03113 arrives inside DPY-4011), ORA-01034 and ORA-01089.

HOW TO RUN (from the repo root, against the tier-1 stack):

    python sql/oracle/14_session_loss_probe.py

It connects as SYSTEM over the listener at 127.0.0.1:1521 and drives the DBA
side through SQL*Plus inside the container, with the SQL on stdin, so no
password is ever in argv (invariant 1). The passwords are tier 1's public ones
from test/compose.yaml. Against any other database, copy the file, edit the
constants in the copy, run the copy and delete it, as 07 prescribes.

THROWAWAY DATABASES ONLY. It closes the PDB, shuts the CDB down twice (once
with ABORT) and starts it again. Every session on the database is lost.
"""

from __future__ import annotations

import subprocess
import time

import oracledb

CONTAINER = "sopuli-test-oracle-free-1"
PDB_DSN = "127.0.0.1:1521/FREEPDB1"
CDB_DSN = "127.0.0.1:1521/FREE"
USER = "system"
PASSWORD = "sopuli-test"


def dba(sql: str) -> None:
    """Run SQL as SYSDBA inside the container. The SQL goes on stdin."""
    subprocess.run(
        ["docker", "exec", "-i", CONTAINER, "sqlplus", "-S", "/ as sysdba"],
        input=f"whenever sqlerror continue\n{sql}\nexit\n".encode(),
        capture_output=True,
        check=True,
    )


def described(error: BaseException) -> str:
    """The code the tool reads, ``full_code``, and the message's first line."""
    detail = error.args[0] if error.args else None
    code = getattr(detail, "full_code", None)
    message = str(getattr(detail, "message", "") or error).splitlines()[0]
    return f"{code} {message!r}"


def call(conn: oracledb.Connection, label: str) -> None:
    try:
        with conn.cursor() as cursor:
            cursor.execute("select 1 from dual")
            cursor.fetchone()
        print(f"  {label}: no error")
    except oracledb.Error as error:
        print(f"  {label}: {described(error)}")


def logon(dsn: str, label: str) -> None:
    try:
        oracledb.connect(user=USER, password=PASSWORD, dsn=dsn).close()
        print(f"  {label}: logon succeeded")
    except oracledb.Error as error:
        print(f"  {label}: {described(error)}")


def held() -> oracledb.Connection:
    """A session on the PDB, once the PDB accepts one."""
    for _ in range(60):
        try:
            return oracledb.connect(user=USER, password=PASSWORD, dsn=PDB_DSN)
        except oracledb.Error:
            time.sleep(5)
    raise SystemExit("FREEPDB1 did not open within five minutes")


def main() -> None:
    oracledb.init_oracle_client()
    print(f"thick mode: {not oracledb.is_thin_mode()}, python-oracledb {oracledb.__version__}")

    print("SL1: the PDB closed IMMEDIATE under a held session")
    conn = held()
    dba("alter pluggable database freepdb1 close immediate;")
    call(conn, "next call")
    call(conn, "second call")
    logon(PDB_DSN, "new logon to the PDB")
    dba("alter pluggable database freepdb1 open;")

    print("SL2: the CDB shut down IMMEDIATE under a held session")
    conn = held()
    dba("shutdown immediate")
    call(conn, "next call")
    logon(PDB_DSN, "instance down, logon to the PDB service")
    logon(CDB_DSN, "instance down, logon to the CDB service")

    print("SL3: logons while the CDB starts")
    dba("startup nomount")
    time.sleep(15)  # until the instance registers with the listener
    logon(PDB_DSN, "NOMOUNT, logon to the PDB service")
    logon(CDB_DSN, "NOMOUNT, logon to the CDB service")
    dba("alter database mount;")
    time.sleep(15)
    logon(PDB_DSN, "MOUNT, logon to the PDB service")
    logon(CDB_DSN, "MOUNT, logon to the CDB service")
    dba("alter database open;\nalter pluggable database all open;")

    print("SL4: the CDB shut down ABORT under a held session")
    conn = held()
    dba("shutdown abort")
    call(conn, "next call")
    dba("startup\nalter pluggable database all open;")
    held().close()
    print("done: the CDB and FREEPDB1 are open again")


if __name__ == "__main__":
    main()
