"""`creds rotate`'s read-back, beside an account a guardrail skipped (#1000).

Step 8 reads back each document the run promoted. A promotion moves only the
accounts that confirmed, so an account a guardrail skipped keeps its staged
password in `pending`. The read-back must not count that as the vault serving
the wrong password.

This needs only the tier-1 services, Oracle Free and Vault, and skips without
them.
"""

from __future__ import annotations

import contextlib
import json
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from conftest import PASSWORD, USER
from fault_harness import ACCOUNT, CONFIG, SECRET, TARGET, Estate
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


def two_accounts(estate: Estate, addr: str) -> Path:
    """The harness's config, with both accounts in the one document."""
    path = estate.tmp_path / "two-accounts.yaml"
    path.write_text(
        CONFIG.format(
            locking="",
            addr=addr,
            mount=estate.mount,
            targets=TARGET.format(name="free-pdb", dsn=estate.dsn, user=estate.user),
            account=f"{ACCOUNT}, {PRIVILEGED}",
        ),
        encoding="utf-8",
    )
    if sys.platform != "win32":
        path.chmod(0o600)
    return path


def test_a_skipped_account_is_not_a_read_back_disagreement(
    fault_estate: Estate, vault_stack: Any, privileged: str
) -> None:
    config = two_accounts(fault_estate, vault_stack.addr)

    rotated = fault_estate.sopuli(config, "creds", "rotate", "--confirm")

    document = json.loads(rotated.stdout)
    codes = [one.get("code") for one in document["diagnostics"]]
    assert ROTATION_UNCONFIRMED not in codes, document["diagnostics"]
    assert rotated.returncode == ExitCode.SUCCESS, rotated.stdout
    after, _ = fault_estate.read(SECRET)
    assert fault_estate.login(after["DB_CREDENTIALS"][ACCOUNT])
    assert privileged in after["pending"]
    assert privileged not in after["DB_CREDENTIALS"]
