"""A MariaDB `role:` rule: written without a host, and refused by every verb
where `PUBLIC` reaches its role (#1272). Tier 0.

No verb is registered for MariaDB yet, so the verb-time question is asked of
:func:`sopuli.cli._refuse_mandatory_roles` directly, with a session that
answers as the driver does.
"""

from __future__ import annotations

from typing import Any

import pytest

from sopuli import cli
from sopuli.config.errors import ConfigError
from sopuli.config.loading import build_config
from sopuli.driver.mariadb.roles import PublicRoleError

TARGET = {
    "name": "mariadb-dev",
    "type": "mariadb",
    "environment": "dev",
    "dsn": "mariadb-dev.example.com:3306",
    "admin": {"username": "sopuli_svc@%", "auth": "prompt"},
}


def _config(role: str) -> Any:
    return build_config({"version": 1, "targets": [TARGET], "personal_accounts": [{"role": role}]})


def test_a_role_written_with_a_host_is_refused_when_the_file_loads() -> None:
    with pytest.raises(ConfigError) as caught:
        _config("dev_role@%")

    assert "a MariaDB role has none" in str(caught.value)
    assert "`dev_role`" in (caught.value.hint or "")


class PublicReachSession:
    """Answers `resolve_role` as the MariaDB session does for a role that
    `PUBLIC` reaches."""

    def __init__(self) -> None:
        self.asked: list[str] = []

    def resolve_role(self, role: str) -> str:
        self.asked.append(role)
        raise PublicRoleError(role, through=role, target="mariadb-dev")


def test_a_verb_asks_the_listing_s_question_on_mariadb() -> None:
    config = _config("dev_role")
    session = PublicReachSession()

    with pytest.raises(PublicRoleError):
        cli._refuse_mandatory_roles(session, config, config.expanded_targets[0])

    assert session.asked == ["dev_role"]
