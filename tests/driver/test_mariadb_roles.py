"""MariaDB roles for a `role:` rule (#1272). Tier 0: the refusal's words."""

from __future__ import annotations

from sopuli.driver.mariadb.roles import PublicRoleError
from sopuli.exit_codes import ExitCode


def test_a_role_granted_to_public_is_refused_as_config() -> None:
    error = PublicRoleError("acme_dev", through="acme_dev", target="mariadb-dev")

    assert error.category == "config"
    assert error.exit_code == ExitCode.CONFIG_INVALID
    assert 'role "acme_dev" is granted to PUBLIC, so every account holds it' in str(error)


def test_a_role_held_through_another_names_that_role() -> None:
    error = PublicRoleError("acme_dev", through="acme_all", target="mariadb-dev")

    assert "is held by acme_all, which is granted to PUBLIC" in str(error)
