"""`creds rotate` beside an account a guardrail skips (#1000, #1009).

The rotation stages no `pending` for that account (#1009). One that `creds
generate` left there does not refuse the rotation, and is left as it was. Step 8
reads back each document the run promoted, and a promotion moves only the
accounts that confirmed, so the read-back must not count the skipped account's
`pending` as the vault serving the wrong password (#1000).

This needs only the tier-1 services, Oracle Free and Vault, and skips without
them.
"""

from __future__ import annotations

import contextlib
import json
from collections.abc import Iterator
from typing import Any

import pytest

from conftest import PASSWORD, USER
from fault_harness import ACCOUNT, SECRET, Estate
from sopuli.diagnostics import ROTATION_UNCONFIRMED
from sopuli.exit_codes import ExitCode

#: Holds `DBA`, so every guardrail pass refuses it.
PRIVILEGED = "acme_fault_priv"


@pytest.fixture
def privileged(fault_estate: Estate) -> Iterator[str]:
    """A second account, beside the harness's own, that holds `DBA`."""
    oracledb = pytest.importorskip("oracledb")
    connection = oracledb.connect(user=USER, password=PASSWORD, dsn=fault_estate.dsn)

    def sql(statement: str) -> None:
        with connection.cursor() as cursor:
            cursor.execute(statement)

    try:
        with contextlib.suppress(Exception):  # absent is the ordinary case
            sql(f"drop user {PRIVILEGED} cascade")
        sql(f'create user {PRIVILEGED} identified by "Old-Pa55word-Priv1"')
        sql(f"grant create session, dba to {PRIVILEGED}")
        yield PRIVILEGED
    finally:
        try:
            with contextlib.suppress(Exception):  # absent if create user failed
                sql(f"drop user {PRIVILEGED} cascade")
        finally:
            connection.close()


def test_a_skipped_account_is_not_staged(
    fault_estate: Estate, vault_stack: Any, privileged: str
) -> None:
    config = fault_estate.config(vault_stack.addr, accounts=(ACCOUNT, privileged))

    rotated = fault_estate.sopuli(config, "creds", "rotate", "--confirm")

    document = json.loads(rotated.stdout)
    assert rotated.returncode == ExitCode.SUCCESS, rotated.stdout
    after, _ = fault_estate.read(SECRET)
    assert fault_estate.login(after["DB_CREDENTIALS"][ACCOUNT])
    assert privileged not in after.get("pending", {})
    assert privileged not in after["DB_CREDENTIALS"]
    assert ROTATION_UNCONFIRMED not in [one.get("code") for one in document["diagnostics"]]


def test_a_pending_left_for_a_skipped_account_does_not_block_the_rotation(
    fault_estate: Estate, vault_stack: Any, privileged: str
) -> None:
    """#1009's sequence: `generate` stages every account, `apply` skips the
    privileged one and leaves its `pending`, and `rotate` then rotates the
    other account."""
    config = fault_estate.config(vault_stack.addr, accounts=(ACCOUNT, privileged))
    generated = fault_estate.sopuli(config, "creds", "generate")
    assert generated.returncode == ExitCode.SUCCESS, generated.stderr
    applied = fault_estate.sopuli(config, "creds", "apply")
    assert applied.returncode == ExitCode.SUCCESS, applied.stdout
    left, _ = fault_estate.read(SECRET)
    staged = left["pending"][privileged]

    rotated = fault_estate.sopuli(config, "creds", "rotate", "--confirm")

    document = json.loads(rotated.stdout)
    codes = [one.get("code") for one in document["diagnostics"]]
    assert ROTATION_UNCONFIRMED not in codes, document["diagnostics"]
    assert rotated.returncode == ExitCode.SUCCESS, rotated.stdout
    after, _ = fault_estate.read(SECRET)
    assert after["DB_CREDENTIALS"][ACCOUNT] != left["DB_CREDENTIALS"][ACCOUNT]
    assert fault_estate.login(after["DB_CREDENTIALS"][ACCOUNT])
    assert after["pending"][privileged] == staged
    assert privileged not in after["DB_CREDENTIALS"]
