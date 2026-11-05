"""How a PyMySQL exception from a MariaDB server is classified. Tier 0.

The shared rules (:mod:`sopuli.driver.mysql_family.errors`): the numbers both
products send, measured on both, and PyMySQL's own. Then the numbers MariaDB
alone sends, each joining with the verb that meets it: ``4151`` for a locked
account and ``4150`` for a blocked one, which a login meets (#1270).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from sopuli.driver.mysql_family import errors as family
from sopuli.driver.mysql_family.errors import AUTHENTICATION, Diagnosis, Rule
from sopuli.exit_codes import ExitCode

#: ``ER_ACCOUNT_HAS_BEEN_LOCKED``: ``ACCOUNT LOCK``, answered only to the right
#: password: "Access denied, this account is locked" (11.8.9; LK1).
ACCOUNT_LOCKED = 4151
#: ``ER_USER_IS_BLOCKED``: ``max_password_errors`` failed logins, answered to
#: any password: "User is blocked because of too many credential errors;
#: unblock with 'ALTER USER / FLUSH PRIVILEGES'" (11.8.9; LK4).
ACCOUNT_BLOCKED = 4150

#: The numbers MariaDB alone sends.
MARIADB_RULES = {
    ACCOUNT_LOCKED: Rule(
        AUTHENTICATION,
        exit_code=ExitCode.AUTH_FAILURE,
        hint="the account is locked (ACCOUNT LOCK); ACCOUNT UNLOCK ends it",
    ),
    ACCOUNT_BLOCKED: Rule(
        AUTHENTICATION,
        exit_code=ExitCode.AUTH_FAILURE,
        hint=(
            "too many failed logins blocked the account (max_password_errors), and the "
            "server refuses the right password too until ACCOUNT UNLOCK or FLUSH "
            "PRIVILEGES ends it. Nothing the tool account reads shows the block"
        ),
    ),
}

#: Every number the MariaDB driver names: the shared ones and its own.
RULES = {**family.RULES, **MARIADB_RULES}

CERTIFICATE_HINT = (
    "the server certificate did not pass the check `mariadb.ssl_mode` asks for: set "
    "`mariadb.ssl_ca` to the CA file that issued it, and connect by the name it carries"
)


def from_error(
    exc: Any, *, connecting: bool = False, scrub: Callable[[str], str] = family.unchanged
) -> Diagnosis:
    """Classify a PyMySQL exception from a MariaDB server under :data:`RULES`,
    with :data:`CERTIFICATE_HINT`."""
    return family.from_error(
        exc, rules=RULES, certificate_hint=CERTIFICATE_HINT, connecting=connecting, scrub=scrub
    )
