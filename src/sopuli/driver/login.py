"""Who a connection logs in as, checked the same way for every client-side
driver. Tier 0.

PostgreSQL's libpq and MySQL's PyMySQL both fill a missing username or
password from the machine: the operating-system user, ``PGPASSWORD``,
``~/.pgpass``, or an empty password. A run would then log in as someone the
config does not name. One check, so the two drivers cannot drift apart on it.
"""

from __future__ import annotations

from sopuli.config.errors import ConfigError
from sopuli.config.model import ExpandedTarget
from sopuli.driver.protocol import Credential
from sopuli.secrets import Secret


def require_login(target: ExpandedTarget, credential: Credential) -> tuple[str, Secret]:
    """The username and password ``credential`` holds, or a refusal naming the
    part that is missing."""
    if credential.username is None:
        raise ConfigError(
            f"target {target.name!r} has no username to connect as",
            hint="write `admin: { username: … }`, or set $SOPULI_DB_ADMIN_USER",
        )
    if credential.secret is None:
        raise ConfigError(f"target {target.name!r} resolved no password")
    return credential.username, credential.secret


def session_label(correlation_id: str) -> str:
    """What the server shows for this run's sessions: PostgreSQL's
    ``application_name``, MySQL's ``program_name`` connect attribute.

    The correlation id is the join between the tool's output, the server's own
    record of the session and the vault, as ``DBMS_SESSION.SET_IDENTIFIER`` is
    on Oracle. 43 characters, inside the 63 PostgreSQL keeps.
    """
    return f"sopuli {correlation_id}"
