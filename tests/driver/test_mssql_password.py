"""The client-side SQL Server password value (#1551). Tier 0.

The vectors were computed by ``sql/mssql/02_client_hash_probe.py``'s
``password_hash``, whose values agreed with the server's own on 15.0.4510.2,
16.0.4325.4 and 17.0.5065.9 (CH1). They are written out here so that a change
to this module cannot change them with it.
"""

from __future__ import annotations

import pytest

from sopuli.driver.mssql.password import (
    MAX_PASSWORD_CHARACTERS,
    PBKDF2_SHA512,
    SHA512,
    VALUE_LENGTH,
    PasswordNotAdmissibleError,
    admit,
    hex_literal,
    password_value,
)
from sopuli.secrets import Secret

SALT = bytes.fromhex("A1B2C3D4")
#: 'Acme vector é pw2', with é as a code point so the source stays ASCII.
NOT_ASCII = "Acme vector " + chr(0xE9) + " pw2"

VECTORS = [
    (
        "Acme-Vector-pw1",
        SHA512,
        "0200A1B2C3D43CBFC54D402D1C1B399764124E0628AB80542D22E5AA3649A37B3CFF42075AF9E25E07"
        "17D52578866F81B84A31A3765DA3407D1A11DD7FD95FA984BB584D7C34",
    ),
    (
        "Acme-Vector-pw1",
        PBKDF2_SHA512,
        "0300A1B2C3D41B8DA5FF2461285F5B67AAF758D4C1771519E8EA73A60FAD4EE3DB735DB82E5C7DE49B"
        "312E2B8CD9668987F358E8088A4BC50C9961E9E05DE6C2E3C0F6167FA3",
    ),
    (
        NOT_ASCII,
        SHA512,
        "0200A1B2C3D41B6B3844ED1BCBAE25675EE7B887C13548DD104C2CA77BE658E2E55EBE7C311AC7E90E"
        "63CC59106135D3E37CAC42FBEACA236C5CFD0CA170B130B4BF2CA6FA43",
    ),
    (
        NOT_ASCII,
        PBKDF2_SHA512,
        "0300A1B2C3D40DCEE7C74908DDB1506DA4008B8B4B31154359FFF01CD7EDE911A1D20F7F7EF446D9A4"
        "B7A32E1867257AA331A3C837569DDDFAEAC105B5004B5AC745232DE105",
    ),
]


@pytest.mark.parametrize(("password", "version", "expected"), VECTORS)
def test_the_value_agrees_with_the_measured_reference(
    password: str, version: int, expected: str
) -> None:
    value = password_value(Secret(password), version, salt=SALT)

    assert hex_literal(value) == "0x" + expected


@pytest.mark.parametrize("version", [SHA512, PBKDF2_SHA512])
def test_a_new_value_has_the_servers_shape_and_a_fresh_salt(version: int) -> None:
    first = password_value(Secret("Acme-App-pw1"), version)
    second = password_value(Secret("Acme-App-pw1"), version)

    assert len(first) == VALUE_LENGTH == 70
    assert first[:2] == version.to_bytes(2, "big")
    assert first[2:6] != second[2:6], "each value draws its own salt"


@pytest.mark.parametrize("version", [0x0100, 0x0400, 2, 0])
def test_a_version_this_driver_does_not_compute_is_refused(version: int) -> None:
    with pytest.raises(ValueError, match="version"):
        password_value(Secret("x"), version)


@pytest.mark.parametrize("salt", [b"", b"abc", b"abcde"])
def test_a_given_salt_is_checked_and_never_replaced(salt: bytes) -> None:
    with pytest.raises(ValueError, match="4 bytes"):
        password_value(Secret("x"), SHA512, salt=salt)


@pytest.mark.parametrize(
    "value",
    [
        b"",
        bytes.fromhex("0100") + bytes(24),  # CH3: the server takes this one
        bytes.fromhex("0200") + bytes(67),
        bytes.fromhex("0200") + bytes(69),
        bytes.fromhex("0400") + bytes(68),
    ],
)
def test_the_literal_refuses_what_is_not_a_value(value: bytes) -> None:
    """The server checks only a value's length and version (CH3), so the
    driver checks them too, before anything is sent."""
    with pytest.raises(ValueError, match="70-byte"):
        hex_literal(value)


def test_the_literal_holds_no_password() -> None:
    literal = hex_literal(password_value(Secret("Acme-App-pw1"), SHA512))

    assert literal.startswith("0x0200")
    assert len(literal) == 2 + 2 * VALUE_LENGTH
    assert "Acme" not in literal


def test_the_longest_password_is_admitted() -> None:
    admit(Secret("A" * MAX_PASSWORD_CHARACTERS))


@pytest.mark.parametrize(
    ("password", "message"),
    [
        ("", "empty"),
        ("Acme\tpw", "control characters"),
        ("Acme\x85pw", "control characters"),
        ("Acme\x00pw", "control characters"),
        ("Acme" + chr(0xD800) + "pw", "UTF-16"),
        ("A" * (MAX_PASSWORD_CHARACTERS + 1), "129 characters"),
        # Outside the Basic Multilingual Plane: two code units each.
        (chr(0x1F600) * 65, "130 characters"),
    ],
)
def test_admit_refuses_what_the_target_cannot_take(password: str, message: str) -> None:
    with pytest.raises(PasswordNotAdmissibleError, match=message) as raised:
        admit(Secret(password))

    assert raised.value.category == "policy"
