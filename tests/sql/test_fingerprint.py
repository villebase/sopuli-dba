"""The plan fingerprint for `sql run`. Tier 0, pure."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import replace

from sopuli.sql.fingerprint import PlannedTarget, fingerprint
from sopuli.sql.guard import row_guard
from sopuli.sql.statement import classify

ONE = PlannedTarget("pdb-dev-1", "db-dev.example.com:1521/PDB1", "DBA_ALPHA", "CDBDEV", "PDB1")
TWO = PlannedTarget("pdb-dev-2", "db-dev.example.com:1521/PDB2", "external", "CDBDEV", "PDB2")
GUARD = row_guard(1, None)
UPDATE = classify("update t set v = 1 where k = 2")


def test_stable_and_short() -> None:
    first = fingerprint(UPDATE, GUARD, [ONE])
    assert first == fingerprint(UPDATE, GUARD, [ONE])
    assert re.fullmatch(r"[0-9a-f]{12}", first)


def test_crlf_and_terminator_do_not_change_it() -> None:
    a = fingerprint(classify("update t set v = 1\r\n;\r\n"), GUARD, [ONE])
    b = fingerprint(classify("update t set v = 1"), GUARD, [ONE])
    assert a == b


def test_target_order_does_not_change_it() -> None:
    assert fingerprint(UPDATE, GUARD, [ONE, TWO]) == fingerprint(UPDATE, GUARD, [TWO, ONE])


def test_one_character_changes_it() -> None:
    a = fingerprint(classify("update t set v = 1"), GUARD, [ONE])
    b = fingerprint(classify("update t set v = 2"), GUARD, [ONE])
    assert a != b


def test_literal_case_changes_it() -> None:
    a = fingerprint(classify("update t set v = 'on'"), GUARD, [ONE])
    b = fingerprint(classify("update t set v = 'ON'"), GUARD, [ONE])
    assert a != b


def test_guard_changes_it() -> None:
    prints = {
        fingerprint(UPDATE, row_guard(None, 1), [ONE]),
        fingerprint(UPDATE, row_guard(None, 100000), [ONE]),
        fingerprint(UPDATE, row_guard(1, None), [ONE]),
        fingerprint(UPDATE, None, [ONE]),
    }
    assert len(prints) == 4


def test_added_target_changes_it() -> None:
    assert fingerprint(UPDATE, GUARD, [ONE]) != fingerprint(UPDATE, GUARD, [ONE, TWO])


def test_changed_dsn_changes_it() -> None:
    other = replace(ONE, dsn="db-dev.example.com:1521/PDB9")
    assert fingerprint(UPDATE, GUARD, [ONE]) != fingerprint(UPDATE, GUARD, [other])


def test_changed_run_as_changes_it() -> None:
    other = replace(ONE, run_as="external")
    assert fingerprint(UPDATE, GUARD, [ONE]) != fingerprint(UPDATE, GUARD, [other])


def test_changed_database_identity_changes_it() -> None:
    unique = replace(ONE, system="CDBOTHER")
    con = replace(ONE, database="PDB9")
    base = fingerprint(UPDATE, GUARD, [ONE])
    assert base != fingerprint(UPDATE, GUARD, [unique])
    assert base != fingerprint(UPDATE, GUARD, [con])


def test_a_target_with_no_role_hashes_as_before_role_existed() -> None:
    # The document the hash covered before #1700, written out by hand.
    document = {
        "statement": UPDATE.text,
        "guard": ["expect", 1],
        "targets": [["pdb-dev-1", "db-dev.example.com:1521/PDB1", "DBA_ALPHA", "CDBDEV", "PDB1"]],
    }
    text = json.dumps(document, sort_keys=True, separators=(",", ":"))
    assert fingerprint(UPDATE, GUARD, [ONE]) == hashlib.sha256(text.encode()).hexdigest()[:12]


def test_a_role_changes_it() -> None:
    assert fingerprint(UPDATE, GUARD, [ONE]) != fingerprint(
        UPDATE, GUARD, [replace(ONE, role="ACME_OWNER")]
    )


def test_no_user_name_stands_in_for_a_role() -> None:
    # PostgreSQL names may hold spaces, so the role is never joined into the name.
    joined = replace(ONE, run_as="DBA_ALPHA as ACME_OWNER")
    split = replace(ONE, role="ACME_OWNER")
    assert fingerprint(UPDATE, GUARD, [joined]) != fingerprint(UPDATE, GUARD, [split])
