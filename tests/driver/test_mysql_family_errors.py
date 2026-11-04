"""The shared error rows, classified without a driver's own rows. Tier 0.

A driver that adds no rows of its own, as the MariaDB driver may for a
number, still gets the right category and exit code for every shared number.
"""

from __future__ import annotations

import pytest

from sopuli.driver.mysql_family import errors as family
from sopuli.driver.protocol import AuthenticationError
from sopuli.exit_codes import ExitCode


@pytest.mark.parametrize(
    "number", [family.AUTH_PLUGIN_CANNOT_LOAD, family.AUTH_PLUGIN_ERROR, family.ACCESS_DENIED]
)
def test_a_shared_login_refusal_is_an_authentication_failure(number: int) -> None:
    diagnosis = family.classify(number, "refused", rules=family.RULES)
    assert diagnosis.category == AuthenticationError.category
    assert diagnosis.exit_code == ExitCode.AUTH_FAILURE


def test_a_server_with_no_tls_names_no_products_config_key() -> None:
    diagnosis = family.classify(family.TLS_CONNECTION_ERROR, "SSL is required", rules=family.RULES)
    assert diagnosis.category == "connectivity"
    assert diagnosis.hint is not None
    assert "mysql." not in diagnosis.hint


def test_every_shared_hint_names_no_mysql_config_key_or_plugin() -> None:
    for rule in family.RULES.values():
        assert "mysql." not in (rule.hint or "")
        assert "caching_sha2" not in (rule.hint or "")
