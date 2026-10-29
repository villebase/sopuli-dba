"""How the OCI store reports an OCI service error.

Every report keeps what OCI sent: the HTTP status, OCI's error code, and the
``opc-request-id``, which is what Oracle support asks for. The status alone is
not enough, because OCI answers 409 for two different things (#1136):
``Conflict`` is a lost compare-and-set, and ``IncorrectState`` is a secret
still ``UPDATING`` from the last write.
"""

from __future__ import annotations

from typing import Any


def describe(exc: Any) -> str:
    """``OCI <status> <code>, opc-request-id <id>``, for the end of a message.

    ``exc`` is an ``oci.exceptions.ServiceError``.
    """
    return f"OCI {exc.status} {exc.code}, opc-request-id {exc.request_id or '-'}"
