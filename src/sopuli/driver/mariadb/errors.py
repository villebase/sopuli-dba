"""How a PyMySQL exception from a MariaDB server is classified. Tier 0.

The shared rules (:mod:`sopuli.driver.mysql_family.errors`) only: the numbers
both products send, measured on both, and PyMySQL's own. A number MariaDB
alone sends, such as ``4151`` for a locked account or ``4150`` for a blocked
one (#1220), joins here with the verb that meets it (#1270, #1272).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from sopuli.driver.mysql_family import errors as family
from sopuli.driver.mysql_family.errors import Diagnosis

#: Every number the MariaDB driver names so far: the shared ones.
RULES = dict(family.RULES)

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
