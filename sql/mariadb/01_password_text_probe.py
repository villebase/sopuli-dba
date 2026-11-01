"""sopuli-dba : what MariaDB keeps of the text of a password change

#1220. sql/mysql/01_password_text_probe.sql measured that MySQL replaces the
password in each place it measured once the statement parses. This measures
the same on MariaDB, where each statement lands and whether the password is
in it:

  PT0  CREATE USER ... IDENTIFIED BY '<password>'
  PT1  ALTER USER ... IDENTIFIED BY '<password>', which succeeds
  PT2  the same statement for an account that does not exist, which fails
       when it runs, 1396
  PT3  the same statement with a syntax error after the password, which fails
       when it is parsed, 1064
  PT4  SET PASSWORD FOR ... = PASSWORD('<password>')
  PT5  ALTER USER ... IDENTIFIED VIA mysql_native_password USING '<hash>', the
       form a client that computes the hash itself would send
  PT6  ALTER USER ... IDENTIFIED VIA mysql_native_password USING
       PASSWORD('<password>')

Each is read back from the general log and the slow log (as tables), the
binary log, performance_schema's events_statements_history and
events_statements_summary_by_digest. The servers run with performance_schema
and the binary log on (test/compose.yaml says why), and the probe turns on the
two statement consumers, which are off by default, the general log and the slow
log, for the run, and sets them back.

Each row that names the probe's account is labelled with the case whose
password it holds, as `PT1 clear`, or with the case it is when it holds none,
as `PT4 hash`.

The probe checks each result against the one RESULTS below records, as
02_client_hash_probe.py does. A difference, or a step that fails, makes it exit
1.

It MEASURES and decides nothing.

STATUS: run on 10.11.19 and 12.3.3, the mariadb:10.11 and mariadb:12.3 images
of test/compose.yaml profile mariadb-matrix, on 2026-11-01 (#1220), with Python
3.13.12 on Windows 11 AMD64. Twice, the first time on servers just created,
exit 0, and the same result both times.

RESULTS -- the same on both releases

  consumers  events_statements_current and events_statements_history are off
       before the probe turns them on
  general log, slow log and statement history
       PT0, PT1, PT2, PT3, PT4 and PT6 as sent, password in clear. PT5 as
       sent, with the hash
  binary log
       PT0, PT1 and PT6 as sent, password in clear. PT4 rewritten to `SET
       PASSWORD FOR ... = '<hash>'`. PT5 as sent, with the hash. PT2 and PT3
       not at all
  digest
       no row holds a password

  So MariaDB replaces the password nowhere measured, except PT4 in the
  binary log. Only PT5, where the client computed the hash, keeps the
  password out of every place.

HOW TO RUN, against the matrix (test/README.md), from the repo root:

    .venv/Scripts/python sql/mariadb/01_password_text_probe.py

It needs 02_client_hash_probe.py beside it.

THROWAWAY SERVERS ONLY. It creates and drops the account sopuli_probe_pw. The
test passwords it sends stay in the binary log and in performance_schema until
the server is recreated, and in the log tables until they are truncated.
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

ACCOUNT = "'sopuli_probe_pw'@'%'"
#: The markers each case's password holds, so a row can be told apart.
MARKERS = {
    "PT0": "PwCreateMarker1a",
    "PT1": "PwPlainMarker4k",
    "PT2": "PwFailMarker9z",
    "PT3": "PwParseMarker5s",
    "PT4": "PwSetMarker3p",
    "PT6": "PwUsingMarker6t",
}
#: PT5's hash, of a password that no statement carries.
SEED_HASH = ch.native_hash("PwSeedMarker7q")
STATEMENTS = {
    "PT0": f"CREATE USER {ACCOUNT} IDENTIFIED BY '{MARKERS['PT0']}'",
    "PT1": f"ALTER USER {ACCOUNT} IDENTIFIED BY '{MARKERS['PT1']}'",
    "PT2": f"ALTER USER 'sopuli_probe_missing'@'%' IDENTIFIED BY '{MARKERS['PT2']}'",
    "PT3": f"ALTER USER {ACCOUNT} IDENTIFIED BY '{MARKERS['PT3']}' sopuli_bogus",
    "PT4": f"SET PASSWORD FOR {ACCOUNT} = PASSWORD('{MARKERS['PT4']}')",
    "PT5": f"ALTER USER {ACCOUNT} IDENTIFIED VIA mysql_native_password USING '{SEED_HASH}'",
    "PT6": (
        f"ALTER USER {ACCOUNT} IDENTIFIED VIA mysql_native_password "
        f"USING PASSWORD('{MARKERS['PT6']}')"
    ),
}
CONSUMERS = "('events_statements_current', 'events_statements_history')"
THREAD = "(SELECT thread_id FROM performance_schema.threads WHERE processlist_id = CONNECTION_ID())"
NAMES = r"'%sopuli\_probe\_%'"


def label(text: str) -> str:
    """Which case a row is, and whether it holds a password, a hash or neither."""
    for case, marker in MARKERS.items():
        if marker in text:
            return f"{case} clear"
    if SEED_HASH in text:
        return "PT5 hash"
    if text.upper().startswith("SET PASSWORD") and "'*" in text:
        return "PT4 hash"
    return f"other: {text[:60]}"


def session(service: str) -> list[tuple[str, str]]:
    """Run the cases in one session and read back what the session can see."""
    script = ";\n".join(
        [
            "SET @saved_output = @@GLOBAL.log_output, @saved_general = @@GLOBAL.general_log, "
            "@saved_slow = @@GLOBAL.slow_query_log",
            "SET @saved_current = (SELECT enabled FROM performance_schema.setup_consumers "
            "WHERE name = 'events_statements_current')",
            "SET @saved_history = (SELECT enabled FROM performance_schema.setup_consumers "
            "WHERE name = 'events_statements_history')",
            "UPDATE performance_schema.setup_consumers SET enabled = 'YES' "
            f"WHERE name IN {CONSUMERS}",
            "SET GLOBAL log_output = 'TABLE'",
            "SET GLOBAL general_log = ON",
            "SET GLOBAL slow_query_log = ON",
            # The slow log is switched per session too, and long_query_time is
            # read per session, so this session's every statement is slow.
            "SET SESSION slow_query_log = ON",
            "SET SESSION long_query_time = 0",
            "SET @started = NOW(6)",
            *STATEMENTS.values(),
            # The history keeps a thread's last 10 statements, so it is read
            # now, before more statements push PT0 out of it.
            "SELECT 'history', sql_text FROM performance_schema.events_statements_history "
            f"WHERE thread_id = {THREAD} AND sql_text LIKE {NAMES}",
            "SET SESSION slow_query_log = OFF",
            "SET GLOBAL general_log = @saved_general",
            "SET GLOBAL slow_query_log = @saved_slow",
            "SET GLOBAL log_output = @saved_output",
            "UPDATE performance_schema.setup_consumers SET enabled = "
            "IF(name = 'events_statements_current', @saved_current, @saved_history) "
            f"WHERE name IN {CONSUMERS}",
            "SELECT 'general log', argument FROM mysql.general_log "
            f"WHERE event_time >= @started AND argument LIKE {NAMES}",
            "SELECT 'slow log', sql_text FROM mysql.slow_log "
            f"WHERE start_time >= @started AND sql_text LIKE {NAMES}",
            "SELECT 'digest', COUNT(*) FROM performance_schema.events_statements_summary_by_digest "
            "WHERE digest_text LIKE '%Marker%'",
        ]
    )
    # -f carries on after PT2 and PT3, which are meant to fail.
    returncode, out, err = ch.client(service, "root", ch.ROOT_PASSWORD, script, "-h127.0.0.1", "-f")
    if "ERROR 1396" not in err or "ERROR 1064" not in err:
        raise ch.StepError(f"{service}: PT2 or PT3 did not fail as written: {err[:300]}")
    return [tuple(line.split("\t", 1)) for line in out.splitlines()]  # type: ignore[misc]


def probe(service: str) -> None:
    ch.cleaned(
        service, lambda: cases(service), lambda: ch.root(service, f"DROP USER IF EXISTS {ACCOUNT}")
    )


def cases(service: str) -> None:
    print(f"\n== {service}: {ch.root(service, 'SELECT VERSION()')}")
    ch.root(service, f"DROP USER IF EXISTS {ACCOUNT}")
    consumers = ch.root(
        service,
        "SELECT GROUP_CONCAT(enabled) FROM performance_schema.setup_consumers "
        f"WHERE name IN {CONSUMERS}",
    )
    print(f"consumers before the run: {consumers}")
    ch.check("consumers", consumers, "NO,NO")
    log_file, position = ch.root(service, "SHOW MASTER STATUS").split("\t")[:2]

    places: dict[str, list[str]] = {"general log": [], "slow log": [], "history": []}
    digest = ""
    for place, text in session(service):
        if place == "digest":
            digest = text
        else:
            # A row from a place not listed is reported as a difference below.
            places.setdefault(place, []).append(label(text))
    events = ch.root(service, f"SHOW BINLOG EVENTS IN '{log_file}' FROM {position}")
    # Log_name, Pos, Event_type, Server_id, End_log_pos, Info.
    fields = [line.split("\t") for line in events.splitlines()]
    places["binary log"] = [
        label(field[5])
        for field in fields
        if len(field) >= 6 and field[2] == "Query" and "sopuli_probe_" in field[5]
    ]

    as_sent = [
        "PT0 clear",
        "PT1 clear",
        "PT2 clear",
        "PT3 clear",
        "PT4 clear",
        "PT5 hash",
        "PT6 clear",
    ]
    recorded = {
        "general log": as_sent,
        "slow log": as_sent,
        "history": as_sent,
        "binary log": ["PT0 clear", "PT1 clear", "PT4 hash", "PT5 hash", "PT6 clear"],
    }
    # The history is a ring, so its rows come back in no fixed order.
    places["history"].sort()
    for place, labels in places.items():
        print(f"{place}: {', '.join(labels)}")
        ch.check(place, labels, recorded.get(place, []))
    print(f"digest rows holding a password: {digest}")
    ch.check("digest", digest, "0")


def main() -> int:
    return ch.run(probe)


if __name__ == "__main__":
    sys.exit(main())
