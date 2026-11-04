"""The values MariaDB stores for a password, computed on the client
(invariant 15). Tier 0.

The vectors are the values the server itself stored for each password with
``IDENTIFIED VIA <plugin> USING PASSWORD(…)`` over a ``utf8mb4`` connection,
read back from ``mysql.user`` as root: the same on 10.11.19, 11.4.13, 11.8.9 and
12.3.3 (``sql/mariadb/09_password_length_probe.py``, PW3).
"""

from __future__ import annotations

import pytest

from sopuli.secrets import Secret

# Before the module, which imports PyNaCl: it comes with the `mariadb` extra.
pytest.importorskip("nacl", reason="PyNaCl comes with the `mariadb` extra")

from sopuli.driver.mariadb.password import (  # noqa: E402
    ED25519,
    NATIVE,
    VALUES,
    PasswordNotAdmissibleError,
    admit,
    ed25519_value,
    native_value,
)

LONG = "Acme-Long-" * 30

SERVER_VALUES = [
    (NATIVE, "Acme-Vector-1", "*BCF4821599FD729D65B1D7FD05E7F500E4353A95"),
    (NATIVE, "pässwörd-é", "*90CD6D75F1B3F438B7F982777542A9E4479A252D"),
    (NATIVE, LONG, "*028C62DD118198F89D80E6C42D1FEA2869F94C81"),
    (ED25519, "Acme-Vector-1", "dqRDrLM3a3AWJrFD6+djW8n30QHqxVemmN5u/6RydE8"),
    (ED25519, "pässwörd-é", "S7h7+pLYaV0vchpKE7ou3ooRNfyTTGxVuXj3CPd5rhM"),
    (ED25519, LONG, "TOe22qLnfsCgQIX4C0MkoHz7M5yy9/FVv40uu6jgQvU"),
]


@pytest.mark.parametrize(("plugin", "password", "stored"), SERVER_VALUES)
def test_the_value_agrees_with_the_servers_own(plugin: str, password: str, stored: str) -> None:
    assert VALUES[plugin](Secret(password)).reveal() == stored


def test_the_long_password_is_longer_than_an_ed25519_seed() -> None:
    """The vector covers what a seed-only library gets wrong."""
    assert len(LONG.encode("utf-8")) == 300


@pytest.mark.parametrize("plugin", [NATIVE, ED25519])
def test_the_value_is_a_secret(plugin: str) -> None:
    """A native value and one captured handshake log in (#1267, decision 4)."""
    value = VALUES[plugin](Secret("Acme-App-pw1"))

    assert isinstance(value, Secret)
    assert str(value) == repr(value) == "***"


def test_the_values_have_the_servers_shape() -> None:
    native = native_value(Secret("Acme-App-pw1")).reveal()
    ed = ed25519_value(Secret("Acme-App-pw1")).reveal()

    assert native.startswith("*")
    assert len(native) == 41
    assert native[1:] == native[1:].upper()
    assert len(ed) == 43, "32 bytes in base 64, without the trailing `=`"
    assert not ed.endswith("=")


def test_the_value_does_not_carry_the_password() -> None:
    password = "Acme-App-pw1"

    for compute in VALUES.values():
        assert password not in compute(Secret(password)).reveal()


@pytest.mark.parametrize(
    ("password", "words"),
    [
        ("", "is empty"),
        ("Acme\x00pw", "control characters"),
        ("Acme\npw", "control characters"),
        ("Acme\ud800pw", "cannot be encoded"),
    ],
)
def test_a_password_the_target_cannot_take_is_refused(password: str, words: str) -> None:
    with pytest.raises(PasswordNotAdmissibleError, match=words) as caught:
        admit(Secret(password))

    assert caught.value.category == "policy"
    if password:
        assert password not in str(caught.value)


@pytest.mark.parametrize(
    "password", ["A" * 1_048_576, "é€😀-Acme", "x"], ids=["1 MiB", "not ASCII", "1 byte"]
)
def test_any_length_and_any_character_is_admitted(password: str) -> None:
    """A password of 1 byte to 1 MiB, ASCII or not, was set and logged in on
    every release (PW1, PW2)."""
    admit(Secret(password))
