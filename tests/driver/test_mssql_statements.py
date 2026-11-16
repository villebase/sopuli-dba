"""The statements that change a SQL Server login's password (#1551). Tier 0."""

from __future__ import annotations

import pytest

from sopuli.driver.mssql.password import SHA512, password_value
from sopuli.driver.mssql.statements import (
    MAX_NAME_CHARACTERS,
    quoted_name,
    restore_policy,
    set_password_value,
)
from sopuli.secrets import Secret

SALT = bytes.fromhex("A1B2C3D4")


@pytest.mark.parametrize(
    ("login", "quoted"),
    [
        ("acme_app", "[acme_app]"),
        ("acme]app", "[acme]]app]"),
        ("]", "[]]]"),
        ("acme[app", "[acme[app]"),
        ("acme 'app\"", "[acme 'app\"]"),
        ("ACME\\acme_app", "[ACME\\acme_app]"),
    ],
)
def test_a_name_is_bracketed_as_quotename_writes_it(login: str, quoted: str) -> None:
    assert quoted_name(login) == quoted


def test_the_longest_name_is_taken() -> None:
    assert quoted_name("a" * MAX_NAME_CHARACTERS) == "[" + "a" * MAX_NAME_CHARACTERS + "]"


@pytest.mark.parametrize(
    ("login", "message"),
    [
        ("", "empty"),
        ("acme\napp", "control characters"),
        ("acme\x00app", "control characters"),
        ("a" * (MAX_NAME_CHARACTERS + 1), "at most 128"),
        # Outside the Basic Multilingual Plane: two code units each.
        (chr(0x1F600) * 65, "at most 128"),
    ],
)
def test_a_name_no_login_can_have_is_refused(login: str, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        quoted_name(login)


def test_the_change_sends_the_value_and_turns_the_policy_off() -> None:
    value = password_value(Secret("Acme-App-pw1"), SHA512, salt=SALT)

    statement = set_password_value("acme_app", value)

    assert statement == (
        f"ALTER LOGIN [acme_app] WITH PASSWORD = 0x{value.hex().upper()} HASHED, CHECK_POLICY = OFF"
    )
    assert "Acme-App-pw1" not in statement


def test_the_change_refuses_what_is_not_a_value() -> None:
    """The server takes a wrong value (CH3), so the statement does not."""
    with pytest.raises(ValueError, match="70-byte"):
        set_password_value("acme_app", b"\x01\x00" + bytes(24))


@pytest.mark.parametrize(
    ("policy", "expiration", "clause"),
    [
        (True, True, "CHECK_POLICY = ON, CHECK_EXPIRATION = ON"),
        (True, False, "CHECK_POLICY = ON, CHECK_EXPIRATION = OFF"),
        (False, False, "CHECK_POLICY = OFF, CHECK_EXPIRATION = OFF"),
    ],
)
def test_the_flags_are_set_back_both_at_once(policy: bool, expiration: bool, clause: str) -> None:
    statement = restore_policy("acme]app", policy=policy, expiration=expiration)

    assert statement == f"ALTER LOGIN [acme]]app] WITH {clause}"


def test_expiration_without_the_policy_is_refused() -> None:
    with pytest.raises(ValueError, match="only with CHECK_POLICY on"):
        restore_policy("acme_app", policy=False, expiration=True)
