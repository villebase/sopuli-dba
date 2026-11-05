"""Each driver's ``refuses`` says what its own admission check refuses (#1335).

`creds generate --no-policy-check` reads
:attr:`sopuli.driver.registry.DatabaseDriver.refuses` to know
what it cannot waive, without importing a driver. These tests pin that literal
to the driver: for every rule :func:`sopuli.passwords.check` reports, one
password breaks it, and the driver's admission check must refuse it exactly
when the literal lists the rule. A refusal added to a driver and not to the
literal, or the other way round, fails here.
"""

from __future__ import annotations

from collections.abc import Callable

import pytest

from sopuli.driver.protocol import DriverError
from sopuli.driver.registry import DRIVERS, refused_password_rules
from sopuli.passwords import (
    BYTE_LENGTH,
    CHARSET,
    CONTROL,
    ENCODING,
    FIRST_CHAR,
    FORBIDDEN,
    LENGTH,
    REQUIRE,
    ByteLimit,
)
from sopuli.secrets import Secret

#: One password per rule. The policy rules (charset, first_char, require,
#: length) need no special text: no driver reads the policy, so a plain
#: password stands for them.
ORACLE_LIMIT = ByteLimit(max_bytes=30, encoding="ascii", charset="US7ASCII")


def _oracle() -> tuple[Callable[[Secret], None], dict[str, str]]:
    from sopuli.driver.oracle.statements import admissible

    return (
        lambda secret: admissible(secret, ORACLE_LIMIT),
        {ENCODING: "Abcdefgh1é", BYTE_LENGTH: "A" * 31},
    )


def _postgresql() -> tuple[Callable[[Secret], None], dict[str, str]]:
    from sopuli.driver.postgres.limits import MAX_PASSWORD_BYTES
    from sopuli.driver.postgres.password import admit

    return admit, {ENCODING: "Abcdefgh1\ud800", BYTE_LENGTH: "A" * (MAX_PASSWORD_BYTES + 1)}


def _mysql() -> tuple[Callable[[Secret], None], dict[str, str]]:
    from sopuli.driver.mysql.limits import MAX_PASSWORD_BYTES
    from sopuli.driver.mysql.password import admit

    return admit, {ENCODING: "Abcdefgh1\ud800", BYTE_LENGTH: "A" * (MAX_PASSWORD_BYTES + 1)}


def _mariadb() -> tuple[Callable[[Secret], None], dict[str, str]]:
    pytest.importorskip("nacl", reason="the mariadb extra is not installed")
    from sopuli.driver.mariadb.limits import MAX_PASSWORD_BYTES
    from sopuli.driver.mariadb.password import admit

    return admit, {ENCODING: "Abcdefgh1\ud800", BYTE_LENGTH: "A" * (MAX_PASSWORD_BYTES + 1)}


ADMISSION = {"oracle": _oracle, "postgresql": _postgresql, "mysql": _mysql, "mariadb": _mariadb}

COMMON = {
    CONTROL: "Abcdefgh1\x01",
    FORBIDDEN: 'Abcdefgh1"',
    CHARSET: "Abcdefgh1",
    FIRST_CHAR: "Abcdefgh1",
    REQUIRE: "Abcdefgh1",
    LENGTH: "Abcdefgh1",
}


def _refused(admit: Callable[[Secret], None], text: str) -> bool:
    try:
        admit(Secret(text))
    except DriverError:
        return True
    return False


def test_every_product_has_an_admission_check_here() -> None:
    assert set(ADMISSION) == set(DRIVERS)


@pytest.mark.parametrize("product", sorted(ADMISSION))
@pytest.mark.parametrize(
    "rule", [CHARSET, FORBIDDEN, CONTROL, FIRST_CHAR, REQUIRE, LENGTH, BYTE_LENGTH, ENCODING]
)
def test_refuses_lists_exactly_what_the_driver_refuses(product: str, rule: str) -> None:
    admit, samples = ADMISSION[product]()
    text = {**COMMON, **samples}[rule]

    assert _refused(admit, text) is (rule in DRIVERS[product].refuses)


def test_the_rules_of_several_products_are_their_union() -> None:
    assert refused_password_rules(["postgresql", "oracle"]) == DRIVERS["oracle"].refuses
    assert FORBIDDEN not in refused_password_rules(["postgresql", "mysql", "mariadb"])
