"""OCI service errors, as the tool's store errors.

Every message keeps what OCI sent: the HTTP status, OCI's error code, and the
``opc-request-id``, which is what Oracle support asks for. The status alone is
not enough, because OCI answers 409 for two different things (#1136):
``Conflict`` is a lost compare-and-set, and ``IncorrectState`` is a secret
still ``UPDATING`` from the last write.

OCI answers 404 ``NotAuthorizedOrNotFound`` both for a resource that does not
exist and for one the caller may not see, by design. So a 404 says "not found
or not authorised", never just one of them.
"""

from __future__ import annotations

from typing import Any, NoReturn

from sopuli.exit_codes import ExitCode
from sopuli.store.protocol import CasConflictError, StoreError

#: A lost compare-and-set: a stale ``if_match`` ETag (#1136, ``oci-etag-cas``).
CONFLICT = "Conflict"


class OciAuthError(StoreError):
    """OCI refused the request's signature, or the caller's policy refused it."""

    category = "authorization"
    exit_code = ExitCode.AUTH_FAILURE


class OciUnavailableError(StoreError):
    """OCI did not answer, was throttling, or failed on its side."""

    category = "connectivity"


def describe(exc: Any) -> str:
    """``OCI <status> <code>, opc-request-id <id>``, for the end of a message.

    ``exc`` is an ``oci.exceptions.ServiceError``.
    """
    return f"OCI {exc.status} {exc.code}, opc-request-id {exc.request_id or '-'}"


def raise_for(exc: Any, *, what: str, missing: type[StoreError] = StoreError) -> NoReturn:
    """Raise the store error for an ``oci.exceptions.ServiceError``.

    ``what`` names the thing asked about, such as ``secret "acme-db"``.
    ``missing`` is the class for a 404, for a caller to whom a missing thing
    means something more specific, such as a wrong ``vault_id``.
    """
    message = f"{what}: {exc.message or 'refused'} ({describe(exc)})"
    if not exc.request_id:
        # OCI sends an opc-request-id with every answer, so this one came from
        # something in between, such as a proxy.
        raise OciUnavailableError(
            f"{what}: answered HTTP {exc.status}, which did not come from OCI",
            hint="check a proxy between this host and OCI",
        ) from exc
    if exc.status == 401:
        raise OciAuthError(
            message,
            hint="check the OCI config profile, its key, and that a session has not expired",
        ) from exc
    if exc.status == 404:
        raise missing(
            f"{what} was not found, or this principal may not see it ({describe(exc)})",
            hint="check the OCID, the region, and the IAM policy for this principal",
        ) from exc
    if exc.status == 409 and exc.code == CONFLICT:
        raise CasConflictError(message) from exc
    if exc.status == 429 or exc.status >= 500:
        raise OciUnavailableError(message) from exc
    raise StoreError(message) from exc


def unreachable(exc: Exception, *, what: str, maybe_written: bool = False) -> OciUnavailableError:
    """The error for a request that got no answer at all.

    ``maybe_written`` is for a create or an update: a request that timed out
    may still have been applied, and the operator must look before trying
    again.
    """
    if maybe_written:
        return OciUnavailableError(
            f"{what}: OCI did not answer, and the write may have been made: {exc}",
            hint="read the secret before running again; check the network, a proxy, and the region",
        )
    return OciUnavailableError(
        f"{what}: OCI did not answer: {exc}",
        hint="check the network, a proxy, and the region",
    )
