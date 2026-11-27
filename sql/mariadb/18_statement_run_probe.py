"""sopuli-dba : what `sql run` (UC-3) relies on, on MariaDB

#1714, part of #1712. The steps are sql/mysql/13_statement_run_probe.py's,
T1 to T10, run on MariaDB, and that probe's docstring says what each does.
This probe loads that one, so the two run the same statements. What differs
on MariaDB:

  T1   adds INSERT, UPDATE and DELETE on an Aria table, NEXTVAL of a sequence
       created NOCACHE, read afterwards by its next_not_cached_value, and
       DELETE ... RETURNING
  T4   adds DELETE ... RETURNING and INSERT ... RETURNING
  T5   the statement timer is SET SESSION max_statement_time = 0.5, and the
       transaction's state is also read from @@in_transaction
  T6   adds the Aria table to the ROLLBACK after a non-transactional write
  T7   GRANT of an account as a role is MySQL's: here it shows what MariaDB
       answers. GRANT PROXY is the same step
  T8   adds UUID and INET6
  T9   reads @@server_uid, the identity the MariaDB driver uses
  T10  uses src/sopuli/driver/mariadb/errors.py

It MEASURES and decides nothing.

STATUS: run on 10.11.19, 11.4.13, 11.8.9 and 12.3.3, the mariadb:10.11,
mariadb:11.4, mariadb:11.8 and mariadb:12.3 images of test/compose.yaml
profile mariadb-matrix, on 2026-11-27 (#1714). The client was PyMySQL 2.2.8,
Python 3.13.12, on Windows 11 AMD64. Twice, exit 0, the same result both
times but for the timings, which are the ranges below. Earlier runs, while
the probe was written, are not counted.

RESULTS -- as the MySQL probe's, except as written here, and the same on
every release, except where noted

  T1   START TRANSACTION READ ONLY refuses INSERT, UPDATE and DELETE on
       InnoDB, MyISAM and Aria, NEXTVAL of a sequence, whose
       next_not_cached_value stays 1, and DELETE ... RETURNING, all with 1792
       "Cannot execute statement in a READ ONLY transaction". WITH ... UPDATE
       and WITH ... DELETE are a syntax error, 1064, on 10.11.19, 11.4.13 and
       11.8.9; 12.3.3 parses them and refuses them, 1792. FOR SHARE is a
       syntax error, 1064, on every release. LOCK IN SHARE MODE runs and
       holds the row, as on MySQL. CREATE TABLE and TRUNCATE commit and run,
       and INTO OUTFILE, INTO DUMPFILE, INTO @v and GET_LOCK() outlive the
       rollback, as on MySQL. secure_file_priv is NULL, so the file is
       written in /tmp
  T2   as on MySQL
  T3   MariaDB runs /*! ... */ only up to MySQL 5.6: /*!50600 DELETE deletes
       the row, and /*!50700, /*!80000 and /*!99999 are comments. /*M! ...
       */ and /*M!100000 ... */ run their content: the DELETE deletes the row
  T4   as on MySQL. DELETE ... RETURNING counts the row it deleted, 1, and
       INSERT ... RETURNING the rows it inserted, 2, both ways
  T5   max_statement_time 0.5 interrupts every statement with 1969 after
       0.50 s: SELECT SLEEP(2), a slow SELECT, UPDATE ... SET v = SLEEP(2),
       and the wait of an UPDATE, a SELECT ... FOR UPDATE and a SELECT ...
       LOCK IN SHARE MODE on root's row lock with innodb_lock_wait_timeout 3. Its
       message is "Query execution was interrupted (max_statement_time
       exceeded)" up to 11.8.9, and "Query was interrupted: execution time
       limit 0.5 sec exceeded" on 12.3.3. After each 1205 and 1969 the
       transaction is still open, @@in_transaction 1, with its earlier
       write. read_timeout behaves as on MySQL: the lock goes at 3.1 s.
       max_statement_time ends a COMMIT that waits on root's FLUSH TABLES
       WITH READ LOCK, 1969 after 0.50 s, and the row is not changed. With
       read_timeout 1 s the client gets 2013 after 1.00 to 1.01 s, and,
       unlike MySQL, the COMMIT does not happen: the row still reads 30 one
       second after root unlocks
  T6   gtid_strict_mode is 0, and the binary log is on. EXPLAIN names both
       tables of a multi-table UPDATE, a DELETE with a join and the two
       UPDATEs with a subquery: ti first on 10.11.19, tm first from 11.4.13.
       For an INSERT ... SELECT, it names only tm, the table read, and not
       ti, the table written. A view, a trigger and a function are as on
       MySQL. A write to ti and tm or ta, or to tm or ta alone, then a
       ROLLBACK, gives 1196, read as on MySQL, and the MyISAM and Aria
       tables keep their change
  T7   MariaDB has no GRANT of an account as a role: root's GRANT
       'sopuli_probe_svc'@'%' TO 'sopuli_probe_dba'@'%' is a syntax error,
       1064, and activate_all_roles_on_login is unknown, 1193. CURRENT_ROLE()
       is NULL with no role. Root at '%' may GRANT PROXY, and SHOW GRANTS
       then gives "GRANT PROXY ON `sopuli_probe_svc`@`%` TO
       `sopuli_probe_dba`@`%`". An account's own SHOW GRANTS holds its
       stored hash, in IDENTIFIED BY PASSWORD; the probe prints it as
       '<hash>'
  T8   as on MySQL. UUID and INET6 are str
  T9   as on MySQL, with @@server_uid in place of server_uuid
  T10  as on MySQL, through the MariaDB driver

  So, beyond MySQL's answers: MariaDB's timer bounds every statement,
  COMMIT included, and lock waits. A COMMIT lost to read_timeout did not
  commit. EXPLAIN does not name the table an INSERT ... SELECT writes.
  /*M! runs, and /*! runs only for a MySQL version below 5.7.

HOW TO RUN, against the matrix (test/README.md), from the repo root, with the
repo's virtual environment:

    .venv/Scripts/python sql/mariadb/18_statement_run_probe.py

The ports follow SOPULI_TEST_MARIADB1011_PORT, SOPULI_TEST_MARIADB114_PORT,
SOPULI_TEST_MARIADB118_PORT and SOPULI_TEST_MARIADB123_PORT. It needs
sql/mysql/13_statement_run_probe.py. A service name as an argument, such as
mariadb-1011, runs that server alone.

THROWAWAY SERVERS ONLY. It creates and drops what the MySQL probe does.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any


def _load(name: str, path: Path) -> Any:
    # The probes' names start with a digit, so they are loaded by path.
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # A dataclass looks its module up in sys.modules.
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


shared = _load(
    "mysql_statement_run_probe",
    Path(__file__).resolve().parents[1] / "mysql" / "13_statement_run_probe.py",
)

MARIADB = shared.Product(
    name="MariaDB",
    servers=(
        shared.Server("mariadb-1011", "SOPULI_TEST_MARIADB1011_PORT", 3311),
        shared.Server("mariadb-114", "SOPULI_TEST_MARIADB114_PORT", 3314),
        shared.Server("mariadb-118", "SOPULI_TEST_MARIADB118_PORT", 3318),
        shared.Server("mariadb-123", "SOPULI_TEST_MARIADB123_PORT", 3323),
    ),
    nontransactional=("tm", "ta"),
    timer=f"SET SESSION max_statement_time = {shared.TIMER_MS / 1000}",
    identity="SELECT @@server_uid",
    errors_module="sopuli.driver.mariadb.errors",
    client="mariadb",
    explain="EXPLAIN",
    settings="SELECT @@global.gtid_strict_mode, @@global.log_bin",
    extra_types=(
        ("c_uuid", "UUID", "'a3bb189e-8bf9-3888-9912-ace4e6543002'"),
        ("c_inet6", "INET6", "'2001:db8::1'"),
    ),
    extra_read_only=(
        ("NEXTVAL of a sequence", "SELECT NEXTVAL({s}.s)"),
        ("DELETE ... RETURNING", "DELETE FROM {s}.ti WHERE id = 1 RETURNING id"),
    ),
    extra_counts=(
        ("DELETE ... RETURNING", "DELETE FROM {s}.ti WHERE id = 2 RETURNING id"),
        ("INSERT ... RETURNING", "INSERT INTO {s}.ti VALUES (6, 60), (7, 70) RETURNING id"),
    ),
    mariadb=True,
)


if __name__ == "__main__":
    sys.exit(shared.main(MARIADB))
