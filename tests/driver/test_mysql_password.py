"""The client-side caching_sha2_password hash (invariant 15). Tier 0.

The vector is the hash MySQL 8.4.13 stored for `Acme-Vector-pw1` with
`CREATE USER … IDENTIFIED BY`, read back from `mysql.user` as root. The
server's salt is 20 raw bytes, not limited to crypt's alphabet.
"""

from __future__ import annotations

import pytest

from sopuli.driver.mysql.password import (
    B64,
    MAX_PASSWORD_BYTES,
    PasswordNotAdmissibleError,
    admit,
    alter_user,
    caching_sha2_hash,
    draw_salt,
)
from sopuli.secrets import Secret

STORED = b"$A$005$ABl&\x03l GH\x1dn\x19\x7frY51gj\x1fFID/qcGe7m3zOD70x.p.lhj1i5nj0.QJPBGe7.ZSo11"


def test_the_hash_agrees_with_the_servers_own() -> None:
    salt = STORED[7:27]

    assert caching_sha2_hash(Secret("Acme-Vector-pw1"), 5000, salt=salt) == STORED


def test_a_new_hash_has_the_servers_shape_and_a_fresh_salt() -> None:
    first = caching_sha2_hash(Secret("Acme-App-pw1"), 10000)
    second = caching_sha2_hash(Secret("Acme-App-pw1"), 10000)

    assert first.startswith(b"$A$00A$")
    assert len(first) == 7 + 20 + 43
    assert first != second, "each hash draws its own salt"


def test_a_drawn_salt_is_crypts_alphabet() -> None:
    salt = draw_salt()

    assert len(salt) == 20
    assert set(salt.decode("ascii")) <= set(B64)


@pytest.mark.parametrize("rounds", [0, 999, 5500])
def test_rounds_must_be_whole_thousands(rounds: int) -> None:
    with pytest.raises(ValueError, match="multiple of 1000"):
        caching_sha2_hash(Secret("x"), rounds)


def test_the_statement_carries_the_hash_as_hex_and_never_the_password() -> None:
    stored = caching_sha2_hash(Secret("Acme-App-pw1"), 5000)

    statement = alter_user("acme_app", "10.%", stored)

    assert statement == (
        f"ALTER USER `acme_app`@`10.%` IDENTIFIED WITH caching_sha2_password AS 0x{stored.hex()}"
    )
    assert "Acme-App-pw1" not in statement


def test_the_account_is_backquoted_whatever_it_holds() -> None:
    """Only a backquote is doubled: a quote and a backslash are themselves,
    whatever the session's `sql_mode`."""
    statement = alter_user("o'b\\r`n", "%", b"$A$005$x")

    assert statement.startswith("ALTER USER `o'b\\r``n`@`%` ")


@pytest.mark.parametrize(
    ("password", "words"),
    [
        ("", "is empty"),
        ("Acme\x00pw", "control characters"),
        ("Acme\ud800pw", "cannot be encoded"),
        ("A" * (MAX_PASSWORD_BYTES + 1), f"at most {MAX_PASSWORD_BYTES}"),
    ],
)
def test_a_password_the_target_cannot_take_is_refused(password: str, words: str) -> None:
    with pytest.raises(PasswordNotAdmissibleError, match=words) as caught:
        admit(Secret(password))

    assert caught.value.category == "policy"


def test_the_longest_password_that_logs_in_is_admitted() -> None:
    """256 bytes logged in on 8.0.46, 8.4.13 and 9.7.4, and 257 did not (CH6)."""
    admit(Secret("A" * MAX_PASSWORD_BYTES))
    admit(Secret("é" * (MAX_PASSWORD_BYTES // 2)))
