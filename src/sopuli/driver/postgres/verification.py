"""What a login as a managed role says about its password. Tier 0.

`creds check` on PostgreSQL verifies a password by logging in with it
(``--method login``). The login asks libpq for SCRAM with
``require_auth=scram-sha-256``, so the password never crosses the network,
whatever the ``pg_hba.conf`` line says: a ``password`` line would have libpq
send it in clear, and a ``trust`` line would let any password in, which would
read as a match. libpq refuses either before it sends the password.

A failed login is one of four things here:

* ``28P01``, a wrong password: :data:`~sopuli.driver.protocol.FAIL`, which is
  drift;
* a refusal the server makes only after it accepted the password, such as no
  ``CONNECT`` on the database: :data:`~sopuli.driver.protocol.PASS`, with the
  refusal in the detail;
* the server asked for another method than SCRAM, or ``28000``, a login
  refused for a reason other than the password, such as no ``pg_hba.conf``
  line for this host and role:
  :data:`~sopuli.driver.protocol.UNAVAILABLE`, which `check` reports as
  ``UNVERIFIABLE`` and not as drift;
* anything else, such as a server that did not answer: not an answer about
  the password, so the session raises it.

A message can hold one attempt per address the host name resolves to. As in
:func:`~sopuli.driver.postgres.errors.from_error`, the first attempt's reason
is the one that counts.
"""

from __future__ import annotations

import re

from sopuli.driver.postgres.errors import (
    INSUFFICIENT_PRIVILEGE,
    LOGIN_REFUSED,
    TOO_MANY_CONNECTIONS,
    WRONG_PASSWORD,
    Diagnosis,
    first_reason_at,
)
from sopuli.driver.protocol import FAIL, PASS, UNAVAILABLE

#: Refusals the server makes only after it has accepted the password: no
#: CONNECT on the database, or the role at its CONNECTION LIMIT. The password
#: matches, and the session still did not open.
_AFTER_THE_PASSWORD = frozenset({INSUFFICIENT_PRIVILEGE, TOO_MANY_CONNECTIONS})

#: The one method the tool logs in with as a managed role
#: (``02-postgres-privileges.md`` §2.3).
REQUIRED_METHOD = "scram-sha-256"

#: libpq's own message when the server asks for another method than the one
#: ``require_auth`` allows, or completes the login without asking at all, as a
#: ``trust`` line does. No SQLSTATE: libpq ends the login itself. The text after
#: the colon says what the server asked for: ``server requested a cleartext
#: password``, or ``server did not complete authentication`` for a ``trust``
#: line (measured on 16.15, #1067).
_METHOD_REFUSED = re.compile(r'authentication method requirement "[^"]+" failed: ([^\n]+)')

#: What to do about a login the server refused for a reason other than the
#: password.
HBA_HINT = (
    "give the tool host a pg_hba.conf line for this role with scram-sha-256 "
    "(02-postgres-privileges.md §2.3)"
)

#: A wrong password, and the one other cause the server gives the same answer
#: for. A role whose stored verifier is md5 cannot log in through a
#: ``scram-sha-256`` line with any password, and the tool account cannot read
#: ``pg_authid`` to tell the two apart.
WRONG_PASSWORD_DETAIL = (
    "the server refused the password (28P01). It gives the same answer for a role "
    "whose stored verifier is md5, which no password opens through a scram-sha-256 "
    "line; `creds apply` stores a SCRAM verifier"
)


def login_outcome(diagnosis: Diagnosis) -> tuple[str, str | None] | None:
    """The result and detail for a login that failed with ``diagnosis``, or
    ``None`` where the failure says nothing about the password, and the caller
    raises it."""
    refused = _METHOD_REFUSED.search(diagnosis.message)
    reason = first_reason_at(diagnosis.message)
    if refused is not None and (reason is None or refused.start() < reason):
        return UNAVAILABLE, (
            f"the server did not log in with {REQUIRED_METHOD} "
            f"({refused.group(1).strip()}), and the tool sends a managed role's "
            f"password only that way; the password was not tried: {HBA_HINT}"
        )
    if diagnosis.code == WRONG_PASSWORD:
        return FAIL, WRONG_PASSWORD_DETAIL
    if diagnosis.code in _AFTER_THE_PASSWORD:
        return PASS, (
            f"the server accepted the password, and then refused the session: "
            f"{diagnosis.first_line}"
        )
    if diagnosis.code == LOGIN_REFUSED:
        return UNAVAILABLE, (
            f"{diagnosis.first_line}. The server refused the login for a reason "
            f"other than the password, so this says nothing about it: {HBA_HINT}"
        )
    return None
