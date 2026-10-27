"""`delivery.method: one_time_link` — a link a Yopass server opens once.

UC-2 §6.6 and decision #445 specify it. **The server stores only ciphertext.**
The tool draws a random key, encrypts the password with OpenPGP using the key as
the password, and sends the ciphertext as a one-time secret. The server answers
with the secret's id. The link is ``<link base>/#/s/<id>/<key>``. The key is in
the fragment, which a browser never sends, so the server never holds anything
that decrypts. The person's browser runs Yopass's page, which fetches the
ciphertext once and decrypts it with the key.

**What it promises**, from §6.6: one use, like a wrapping token. The server
deletes a one-time secret as part of the read that returns it, so a person whose
fetch fails knows somebody else fetched first. The link is a bearer credential:
whoever holds it and its key can read the password. An unlicensed Yopass server
keeps no record of the read, so the secret's id is the hand-over's only record.

**Split mode** prints the link without the key, and the key, as two values for
two channels. It is on when the file says ``split_key: true``, and also when the
server's `/config` reports ``DISABLE_ONE_CLICK_LINK``, or reports
``PREFETCH_SECRET`` false. On a server without ``PREFETCH_SECRET`` the page
fetches a full link's secret as soon as it loads, so a link scanner would use
up the one view. A link without its key fetches nothing until the key is
entered.

**The server's own settings are read at plan time**, from `/config`, before a
password is drawn (invariant 4). A server that is ``READ_ONLY``, one that has
``REQUIRE_AUTH``, a ``ttl`` it would refuse, and a ``PUBLIC_URL`` that is plain
``http`` off loopback are refused with exit 5.

**`httpx` and `pysequoia` are imported inside the functions that use them.**
This module is in no registry, so ADR-006 rule 1 applies to it as it does to
:mod:`sopuli.delivery.vault_wrapped`, and `tests/store/test_install_shape.py`
imports it with both blocked.
"""

from __future__ import annotations

import secrets
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime
from typing import TYPE_CHECKING, Any

from sopuli.config.errors import ROOT, ConfigError
from sopuli.config.plain_http import plain_http_scheme
from sopuli.delivery import Receipt
from sopuli.exit_codes import ExitCode
from sopuli.extras import install_hint
from sopuli.output.debug import logger
from sopuli.safety import RefusedError
from sopuli.secrets import Secret
from sopuli.store.protocol import StoreError

if TYPE_CHECKING:  # pragma: no cover -- annotations only
    import httpx

#: The method's name in `delivery.method`, and what a receipt records.
METHOD = "one_time_link"

#: The install extra that carries `httpx` and `pysequoia` (ADR-006).
EXTRA = "yopass"

#: How long to wait for the server. A reset holds UC-2 §3.3's lock while this
#: runs, so a hung request must not hold it for long.
TIMEOUT_S = 10

#: What a server without custom expiry accepts: an hour, a day and a week, in
#: seconds. Measured on Yopass 16.0.1 (`tests/test_yopass_server.py`).
DEFAULT_EXPIRATIONS = (3600, 86400, 604800)

#: Seconds in each unit of the config layer's TTL shape (``TTL_PATTERN``).
UNITS = {"s": 1, "m": 60, "h": 3600}

#: Bytes of randomness in the key. 16 bytes are 22 characters of base64url, the
#: length of the key Yopass's own client draws.
KEY_BYTES = 16

LOG = logger("yopass")


class YopassNotInstalledError(ConfigError):
    """The `yopass` extra is not installed, so this method cannot deliver.

    ADR-006 rule 2: a missing client is a diagnosable condition with exit 9,
    naming the extra, not a traceback.
    """

    def __init__(self, module: str) -> None:
        super().__init__(
            f"`delivery.method: {METHOD}` needs {module}, which is not installed",
            at=ROOT,
            hint=f"install it with:  {install_hint(EXTRA)}",
        )


class YopassRefusedError(RefusedError):
    """The Yopass server cannot take this delivery, so the reset is refused.

    Exit 5, for :class:`~sopuli.delivery.vault_wrapped.NotWrappableError`'s
    reason: the estate asked for something the server it named cannot do, and
    the refusal comes before a password is drawn (invariant 4).
    """

    exit_code = ExitCode.UNSUPPORTED_CAPABILITY
    category = "capability"


@dataclass(frozen=True)
class ServerPolicy:
    """What the server's `/config` says, as far as this method reads it.

    Pure: built from the parsed answer, with no I/O, so every rule below is
    testable from a dict.
    """

    read_only: bool = False
    require_auth: bool = False
    allow_custom_expiration: bool = False
    min_expiration: int | None = None
    max_expiration: int | None = None
    force_expiration: int | None = None
    prefetch_secret: bool = True
    disable_one_click_link: bool = False
    public_url: str | None = None

    @classmethod
    def from_config(cls, body: Mapping[str, Any]) -> ServerPolicy:
        """Read `/config`. A key the server leaves out takes Yopass's default."""
        return cls(
            read_only=body.get("READ_ONLY") is True,
            require_auth=body.get("REQUIRE_AUTH") is True,
            allow_custom_expiration=body.get("ALLOW_CUSTOM_EXPIRATION") is True,
            min_expiration=_seconds(body.get("MIN_EXPIRATION")),
            max_expiration=_seconds(body.get("MAX_EXPIRATION")),
            force_expiration=_seconds(body.get("FORCE_EXPIRATION")),
            # Absent is the default, true. Only an explicit false turns it off.
            prefetch_secret=body.get("PREFETCH_SECRET") is not False,
            disable_one_click_link=body.get("DISABLE_ONE_CLICK_LINK") is True,
            public_url=_text(body.get("PUBLIC_URL")),
        )

    def accepts(self, seconds: int) -> bool:
        """Whether the server takes this expiration, by Yopass 16.0.1's rules."""
        if self.force_expiration is not None:
            return seconds == self.force_expiration
        if self.allow_custom_expiration:
            low = self.min_expiration if self.min_expiration is not None else 0
            high = self.max_expiration if self.max_expiration is not None else seconds
            return low <= seconds <= high
        return seconds in DEFAULT_EXPIRATIONS

    def accepted(self) -> str:
        """The values :meth:`accepts` takes, for a message."""
        if self.force_expiration is not None:
            return f"exactly {self.force_expiration}s (FORCE_EXPIRATION)"
        if self.allow_custom_expiration:
            return f"{self.min_expiration}s to {self.max_expiration}s (ALLOW_CUSTOM_EXPIRATION)"
        return "1h, 24h or 168h"


def ttl_seconds(ttl: str) -> int:
    """The config layer's TTL, such as ``1h``, in seconds.

    The config layer has already checked the shape: digits, then one of
    ``s``, ``m`` or ``h``.
    """
    return int(ttl[:-1]) * UNITS[ttl[-1]]


def refusal(policy: ServerPolicy, *, ttl: str) -> str | None:
    """Why this server cannot take the delivery, or ``None`` if it can.

    Pure. Each answer names the server setting that refuses, so the operator
    knows what to ask the server's admin for.
    """
    if policy.read_only:
        return "the server reports READ_ONLY, so it creates no secrets"
    if policy.require_auth:
        return (
            "the server reports REQUIRE_AUTH. Creating a secret there needs an API token, "
            "which needs a Yopass licence, and sopuli does not send one"
        )
    seconds = ttl_seconds(ttl)
    if not policy.accepts(seconds):
        return f"the server does not accept a ttl of {ttl}: it accepts {policy.accepted()}"
    if policy.public_url is not None:
        scheme = plain_http_scheme(policy.public_url)
        if scheme is not None:
            return (
                f"the server's PUBLIC_URL uses {scheme}, and the person's browser would load "
                f"the page that reads the key from it"
            )
    return None


def splits(policy: ServerPolicy, *, split_key: bool) -> bool:
    """Whether the link and the key are handed over as two values."""
    return split_key or policy.disable_one_click_link or not policy.prefetch_secret


def link_base(policy: ServerPolicy, *, base_url: str) -> str:
    """The server's `PUBLIC_URL` when it reports one, else the configured address."""
    return (policy.public_url or base_url).removesuffix("/")


#: Builds the HTTP client. A parameter so that a test can hand in one built on
#: `httpx.MockTransport`; a run uses :func:`_client`.
ClientFactory = Callable[[str], "httpx.Client"]


def _client(base_url: str) -> httpx.Client:
    """An `httpx` client for the server, with a short timeout."""
    try:
        import httpx
    except ModuleNotFoundError as error:
        raise YopassNotInstalledError("httpx") from error
    return httpx.Client(base_url=base_url, timeout=TIMEOUT_S)


@dataclass
class Yopass:
    """Creates one-time secrets on one Yopass server.

    Not frozen: :meth:`preflight` keeps what the server's `/config` said, so a
    run that reaches several targets asks once.
    """

    base_url: str
    ttl: str
    split_key: bool = False
    client_factory: ClientFactory = _client
    _policy: ServerPolicy | None = field(default=None, init=False, repr=False)

    #: A link is not addressed to a name, so the name as typed is enough.
    stored_name = False

    def preflight(self, *, account: str, target: str) -> None:
        """Read the server's `/config` and refuse what it would not take.

        Also checks that `pysequoia` is installed, because :meth:`deliver` runs
        after the password is drawn and must not be the first to find out.
        """
        _sequoia()
        self._server_policy()

    def deliver(self, secret: Secret, *, account: str, target: str) -> Receipt:
        """Encrypt, create the one-time secret, and return the link.

        **The password leaves this process only as ciphertext.** It reaches
        `pysequoia` in memory, and the request carries the armored result. That
        call is the method's store write, as the vault write is for the Vault
        methods (decision #445), and `tests/test_reveal_sites.py` records this
        module with that reason.

        The plaintext is the password alone. The page shows it to the person
        as it is, and anything beside it would be copied with it.
        """
        policy = self._server_policy()
        key = Secret(secrets.token_urlsafe(KEY_BYTES))
        armored = (
            _sequoia()
            .encrypt(secret.reveal().encode("utf-8"), passwords=[key.reveal()])
            .decode("ascii")
        )

        body = {"message": armored, "expiration": ttl_seconds(self.ttl), "one_time": True}
        answer = self._request("POST", "/create/secret", json=body)
        secret_id = _created_id(answer.json() if _is_json(answer) else None)
        expires_at = _server_time(answer.headers.get("Date"), ttl=ttl_seconds(self.ttl))

        base = link_base(policy, base_url=self.base_url)
        keyless = f"{base}/#/s/{secret_id}"
        if splits(policy, split_key=self.split_key):
            return Receipt(
                method=METHOD, token=key, id=secret_id, link=keyless, expires_at=expires_at
            )
        return Receipt(
            method=METHOD,
            token=Secret(f"{keyless}/{key.reveal()}"),
            id=secret_id,
            expires_at=expires_at,
        )

    def _server_policy(self) -> ServerPolicy:
        """`/config`, read once, or a refusal."""
        if self._policy is None:
            answer = self._request("GET", "/config")
            body = answer.json() if _is_json(answer) else None
            if not isinstance(body, dict):
                raise StoreError(
                    f"the Yopass server at {self.base_url} answered /config with something "
                    f"that is not a JSON object",
                    hint="check that `delivery.one_time_link.base_url` is the Yopass server",
                )
            policy = ServerPolicy.from_config(body)
            reason = refusal(policy, ttl=self.ttl)
            if reason is not None:
                raise YopassRefusedError(
                    f"`delivery.method: {METHOD}` cannot use the Yopass server at "
                    f"{self.base_url}: {reason}",
                    hint=(
                        "change the server's setting, or `delivery.one_time_link`, or choose "
                        "another method (UC-2 6.2). Nothing was drawn or changed"
                    ),
                )
            self._policy = policy
        return self._policy

    def _request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        """One request, or a :class:`StoreError` that names the server and the path."""
        try:
            import httpx
        except ModuleNotFoundError as error:
            raise YopassNotInstalledError("httpx") from error

        started = time.monotonic()
        try:
            with self.client_factory(self.base_url) as client:
                response = client.request(method, path, **kwargs)
        except httpx.HTTPError as error:
            LOG.debug(
                "%s %s: %s in %.3fs", method, path, type(error).__name__, time.monotonic() - started
            )
            raise StoreError(
                f"the Yopass server at {self.base_url} could not be reached: "
                f"{type(error).__name__}",
                hint="check `delivery.one_time_link.base_url`, and that the server is running",
            ) from error
        LOG.debug(
            "%s %s: %s in %.3fs", method, path, response.status_code, time.monotonic() - started
        )
        if response.status_code != 200:
            raise StoreError(
                f"the Yopass server at {self.base_url} refused {method} {path}: "
                f"HTTP {response.status_code} {_server_message(response)}".rstrip(),
                hint=(
                    "the server's own message is above. Nothing was handed over, and the "
                    "account's password has not changed"
                ),
            )
        return response


def _sequoia() -> Any:
    """`pysequoia`, or the refusal that names the extra."""
    try:
        import pysequoia
    except ModuleNotFoundError as error:
        raise YopassNotInstalledError("pysequoia") from error
    return pysequoia


def _created_id(body: Any) -> str:
    """The id in the answer to a create, or a failure.

    **A missing id is a failure, not an empty receipt**, for
    :mod:`sopuli.delivery.vault_wrapped`'s reason: the caller would go on to
    change the password, and nobody could fetch it.
    """
    secret_id = body.get("message") if isinstance(body, dict) else None
    if not isinstance(secret_id, str) or not secret_id or "/" in secret_id:
        raise StoreError(
            "the Yopass server answered the create with no usable secret id, so nothing "
            "was handed over",
            hint="check that `delivery.one_time_link.base_url` is a Yopass server",
        )
    return secret_id


def _server_time(date: str | None, *, ttl: int) -> datetime | None:
    """When the secret expires, by the server's clock.

    Yopass returns no expiry, so this is the answer's ``Date`` header plus the
    ``ttl`` sent (decision #445). ``None`` when the header is missing or is not
    a date, rather than a time from this host's clock.
    """
    if not date:
        return None
    try:
        sent = parsedate_to_datetime(date)
    except (TypeError, ValueError):
        return None
    if sent.tzinfo is None:
        sent = sent.replace(tzinfo=UTC)
    return sent + timedelta(seconds=ttl)


def _is_json(response: httpx.Response) -> bool:
    kind: str = response.headers.get("content-type", "")
    return kind.startswith("application/json")


def _server_message(response: httpx.Response) -> str:
    """Yopass's own ``{"message": ...}``, or nothing."""
    if not _is_json(response):
        return ""
    try:
        body = response.json()
    except ValueError:
        return ""
    message = body.get("message") if isinstance(body, dict) else None
    return f"({message})" if isinstance(message, str) else ""


def _seconds(value: Any) -> int | None:
    """A whole number of seconds from `/config`, or ``None``."""
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def _text(value: Any) -> str | None:
    """A non-empty string from `/config`, or ``None``."""
    return value if isinstance(value, str) and value else None
