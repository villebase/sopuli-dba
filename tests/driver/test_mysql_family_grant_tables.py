"""The grant-table reads MySQL and MariaDB share. Tier 0."""

from __future__ import annotations

import pytest

from sopuli.driver.mysql_family.grant_tables import set_members


@pytest.mark.parametrize(
    ("value", "members"),
    [
        ("Select,Update", ["SELECT", "UPDATE"]),
        ({"Select", "Grant"}, ["GRANT OPTION", "SELECT"]),
        (b"Execute,Alter Routine", ["ALTER ROUTINE", "EXECUTE"]),
        # MariaDB's tables_priv member for DELETE HISTORY (11.8.9).
        ("Delete versioning rows", ["DELETE HISTORY"]),
        ("", []),
        (None, []),
    ],
)
def test_a_set_column_reads_as_grant_spells_it(value: object, members: list[str]) -> None:
    assert list(set_members(value)) == members
