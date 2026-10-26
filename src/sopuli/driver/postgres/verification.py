"""What a login as a managed role says about its password. Tier 0.

`creds check` on PostgreSQL verifies a password by logging in with it
(``--method login``). The login asks libpq for SCRAM with
``require_auth=scram-sha-256``, so the password never crosses the network,
whatever the ``pg_hba.conf`` line says: a ``password`` line would have libpq
send it in clear, and a ``trust`` line would let any password in, which would
read as a match. libpq refuses either before it sends the password.

A failed login is one of three things here:

* ``28P01``, a wrong password: :data:`~sopuli.driver.protocol.FAIL`, which is
  drift;
* the server asked for another method than SCRAM, or ``28000``, a login
  refused for a reason other than the password, such as no ``pg_hba.conf``
  line for this host and role:
  :data:`~sopuli.driver.protocol.UNAVAILABLE`, which `check` reports as
  ``UNVERIFIABLE`` and not as drift;
* anything else, such as a server that did not answer: not an answer about
  the password, so the session raises it.
"""

from __future__ import annotations

import re

from sopuli.driver.postgres.errors import LOGIN_REFUSED, WRONG_PASSWORD, Diagnosis
from sopuli.driver.protocol import FAIL, UNAVAILABLE

#: The one method the tool logs in with as a managed role
#: (``02-postgres-privileges.md`` §2.3).
REQUIRED_METHOD = "scram-sha-256"

#: libpq's own message when the server asks for another method than the one
#: ``require_auth`` allows, or completes the login without asking at all, as a
#: ``trust`` line does. No SQLSTATE: libpq ends the login itself. The text after
#: the colon says what the server asked for, such as ``server requested a
#: cleartext password``. Measured with ``require_auth=md5`` in #1032; the
#: message has the same shape for every method.
_METHOD_REFUSED = re.compile(r'authentication method requirement "[^"]+" failed: ([^\n]+)')

#: What to do about a login the server refused for a reason other than the
#: password.
HBA_HINT = (
    "give the tool host a pg_hba.conf line for this role with scram-sha-256 "
    "(02-postgres-privileges.md §2.3)"
)


def login_outcome(diagnosis: Diagnosis) -> tuple[str, str | None] | None:
    """The result and detail for a login that failed with ``diagnosis``, or
    ``None`` where the failure says nothing about the password, and the caller
    raises it."""
    refused = _METHOD_REFUSED.search(diagnosis.message)
    if refused is not None:
        return UNAVAILABLE, (
            f"the server did not log in with {REQUIRED_METHOD} "
            f"({refused.group(1).strip()}), and the tool sends a managed role's "
            f"password only that way; the password was not tried: {HBA_HINT}"
        )
    if diagnosis.code == WRONG_PASSWORD:
        return FAIL, None
    if diagnosis.code == LOGIN_REFUSED:
        return UNAVAILABLE, (
            f"{diagnosis.first_line}. The server refused the login for a reason "
            f"other than the password, so this says nothing about it: {HBA_HINT}"
        )
    return None
