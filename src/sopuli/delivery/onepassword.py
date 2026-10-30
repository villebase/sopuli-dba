"""`delivery.method: onepassword_share` — a 1Password share link that opens once.

UC-2 §6.6 and #446 specify it. The tool creates an item holding the password in
a 1Password vault, shares it as a view-once link with an expiry, and deletes the
item. A share is a copy, so the link still opens after the delete, and no copy
of the password stays in the vault. Measured on a 1Password account on
2026-10-30 (#446).

**A service account does the work**, through 1Password's Python SDK
(`onepassword-sdk`). It needs read, write and share items on the vault. Without
share items, 1Password refuses the share.

**What is checked at plan time**, before a password is drawn (invariant 4): the
SDK imports, the token logs in, the vault exists and is unique, and the
account's sharing policy allows the `ttl`. 1Password gives the policy only for
an item, so the check creates an empty Secure Note, reads the policy through it,
and deletes it. The note holds no password.

**`onepassword` is imported inside the functions that use it.** This module is
in no registry, so ADR-006 rule 1 applies to it as it does to
:mod:`sopuli.delivery.yopass`, and `tests/store/test_install_shape.py` imports it
with the SDK blocked.

TODO(#446): deliver, and the wiring that makes the method usable.
"""

from __future__ import annotations

import asyncio
import importlib
import time
from collections.abc import Awaitable, Callable, Collection
from dataclasses import dataclass, field
from typing import Any

from sopuli.config.delivery import ONEPASSWORD_TTLS
from sopuli.config.errors import ROOT, ConfigError
from sopuli.exit_codes import ExitCode
from sopuli.extras import install_hint
from sopuli.output.debug import logger
from sopuli.safety import RefusedError
from sopuli.secrets import Secret
from sopuli.store.protocol import StoreError
from sopuli.version import DISTRIBUTION, get_version

#: The method's name in `delivery.method`, and what a receipt records.
METHOD = "onepassword_share"

#: The install extra that carries the SDK (ADR-006).
EXTRA = "onepassword"

#: The title of the empty note the plan-time check creates and deletes.
PLACEHOLDER_TITLE = "sopuli plan-time check"

LOG = logger("onepassword")


class OnePasswordNotInstalledError(ConfigError):
    """The `onepassword` extra is not installed, so this method cannot deliver.

    ADR-006 rule 2: a missing client is a diagnosable condition with exit 9,
    naming the extra, not a traceback. The SDK has wheels for CPython 3.9 to 3.13
    only, so on 3.14 and later the extra installs nothing and this is the answer.

    ``loaded`` names the error when the SDK is installed and its native library
    does not load, as on a Linux with glibc older than 2.32.
    """

    def __init__(self, *, loaded: str | None = None) -> None:
        state = (
            "is not installed" if loaded is None else f"is installed and failed to load: {loaded}"
        )
        super().__init__(
            f"`delivery.method: {METHOD}` needs 1Password's SDK (onepassword-sdk), which {state}",
            at=ROOT,
            hint=(
                f"install it with:  {install_hint(EXTRA)}. The SDK runs on Python 3.9 to "
                f"3.13 and needs glibc 2.32 or later on Linux"
            ),
        )


class OnePasswordRefusedError(RefusedError):
    """The 1Password account cannot take this delivery, so the reset is refused.

    Exit 5, for :class:`~sopuli.delivery.yopass.YopassRefusedError`'s reason:
    the estate asked for something the account it named cannot do, and the
    refusal comes before a password is drawn (invariant 4).
    """

    exit_code = ExitCode.UNSUPPORTED_CAPABILITY
    category = "capability"


class OnePasswordLoginError(StoreError):
    """The service account token did not log in. Exit 6, as a vault login's is."""

    exit_code = ExitCode.AUTH_FAILURE


#: 1Password's name for a share that anyone with the link can open, as the
#: sharing policy lists it in its allowed types. The method makes only this kind.
PUBLIC = "Public"


def refusal(*, ttl: str, max_expiry: str, allowed_types: Collection[str]) -> str | None:
    """Why the account's sharing policy refuses this share, or ``None`` if it allows it.

    Pure. ``ttl`` is the file's value. ``max_expiry`` and ``allowed_types`` are
    1Password's names for the policy's maximum, such as ``SevenDays``, and for
    the kinds of share it allows, such as ``Public``. A maximum this build does
    not know is a refusal, not a guess.

    The order of :data:`~sopuli.config.delivery.ONEPASSWORD_TTLS` is the order
    of the expiries, shortest first. A test holds the dict to that order.
    """
    if PUBLIC not in allowed_types:
        return (
            "the account's sharing policy does not allow a link anyone can open, "
            f"which is the only share this method makes. It allows: "
            f"{', '.join(sorted(allowed_types)) or 'none'}"
        )
    names = list(ONEPASSWORD_TTLS.values())
    if max_expiry not in names:
        return f"the account's sharing policy reports a maximum expiry of {max_expiry!r}"
    if names.index(ONEPASSWORD_TTLS[ttl]) > names.index(max_expiry):
        longest = next(key for key, name in ONEPASSWORD_TTLS.items() if name == max_expiry)
        return f"the account's sharing policy allows a ttl of {longest} at most, not {ttl}"
    return None


#: Logs in and returns an SDK client. A parameter so that a test can hand in a
#: fake; a run uses :func:`_authenticate`.
ClientFactory = Callable[[Secret], Awaitable[Any]]


async def _authenticate(token: Secret) -> Any:
    """An SDK client logged in with the service account token.

    The token is revealed here, to the SDK that presents it to 1Password, as a
    vault token is revealed on the wire (`tests/test_reveal_sites.py`).

    The SDK raises plain ``Exception`` for a bad token and for a 1Password it
    cannot reach alike, so its message is kept: it is the only thing that tells
    the two apart. The token is cut out of it first, because the message is
    about the token it was given (#785). On SDK 0.4.2, the two bad tokens tried
    gave messages that did not quote them.
    """
    client_type = _sdk().Client
    revealed = token.reveal()
    try:
        return await client_type.authenticate(
            auth=revealed, integration_name=DISTRIBUTION, integration_version=get_version()
        )
    except Exception as error:  # noqa: BLE001 -- the SDK raises plain Exception
        message = str(error).replace(revealed, "***") if revealed else str(error)
        raise OnePasswordLoginError(
            f"the 1Password service account did not log in: {message}",
            hint=(
                f"the SDK's message is above. If it is about the token, check the token "
                f"`delivery.{METHOD}.token` names: a service account token starts with "
                f"`ops_`, with no line break or space around it. Otherwise check that "
                f"this host reaches 1Password"
            ),
        ) from None


@dataclass
class OnePassword:
    """Shares items from one 1Password vault.

    Not frozen: :meth:`preflight` records that it ran, so a run that reaches
    several targets checks once.
    """

    onepassword_vault: str
    ttl: str
    token: Secret = field(repr=False)
    client_factory: ClientFactory = _authenticate
    _checked: bool = field(default=False, init=False, repr=False)

    #: A link is not addressed to a name, so the name as typed is enough.
    stored_name = False

    def preflight(self, *, account: str, target: str) -> None:
        """Log in, find the vault, and refuse a `ttl` the sharing policy refuses."""
        if not self._checked:
            asyncio.run(self._preflight())
            self._checked = True

    async def _preflight(self) -> None:
        types = _sdk_types()
        client = await self.client_factory(self.token)
        vault_id = await self._vault_id(client)
        note = await _call(
            "create an item",
            vault=self.onepassword_vault,
            call=lambda: client.items.create(
                types.ItemCreateParams(
                    category=types.ItemCategory.SECURENOTE,
                    vault_id=vault_id,
                    title=PLACEHOLDER_TITLE,
                )
            ),
        )
        # The delete runs whatever ends the read, an interrupt included. When the
        # read failed, its failure is the one to report: a failed delete is then
        # added to its hint, because the note holds no password.
        read_failed: BaseException | None = None
        try:
            policy = await _call(
                "read the sharing policy",
                vault=self.onepassword_vault,
                call=lambda: client.items.shares.get_account_policy(vault_id, note.id),
            )
        except BaseException as error:
            read_failed = error
            raise
        finally:
            try:
                await _call(
                    f"delete the item {PLACEHOLDER_TITLE!r} ({note.id})",
                    vault=self.onepassword_vault,
                    call=lambda: client.items.delete(vault_id, note.id),
                )
            except StoreError as error:
                if read_failed is None:
                    raise
                if isinstance(read_failed, StoreError):
                    read_failed.hint = (
                        f"{read_failed.hint}. The empty note {PLACEHOLDER_TITLE!r} "
                        f"({note.id}) could not be deleted either, and can be deleted by "
                        f"hand: {error.message}"
                    )
        reason = refusal(
            ttl=self.ttl,
            max_expiry=_name(policy.max_expiry),
            allowed_types=[_name(kind) for kind in policy.allowed_types],
        )
        if reason is not None:
            raise OnePasswordRefusedError(
                f"`delivery.method: {METHOD}` cannot share from the 1Password vault "
                f"{self.onepassword_vault!r}: {reason}",
                at=ROOT.key("delivery").key(METHOD),
                hint=(
                    f"change the account's sharing settings in 1Password, or lower "
                    f"`delivery.{METHOD}.ttl`, or choose another method (UC-2 6.2). "
                    f"Nothing was drawn or changed"
                ),
            )

    async def _vault_id(self, client: Any) -> str:
        """The id of the one vault titled :attr:`onepassword_vault`, or a refusal."""
        vaults = await _call(
            "list its vaults", vault=self.onepassword_vault, call=client.vaults.list
        )
        found = [vault.id for vault in vaults if vault.title == self.onepassword_vault]
        if len(found) == 1:
            return str(found[0])
        if not found:
            message = "the service account sees no vault with that title"
            hint = (
                "check the title, and that the service account was given read, write and "
                "share items on the vault"
            )
        else:
            message = f"the service account sees {len(found)} vaults with that title"
            hint = "rename one of them, so the title names one vault"
        raise OnePasswordRefusedError(
            f"`delivery.method: {METHOD}` cannot use the 1Password vault "
            f"{self.onepassword_vault!r}: {message}",
            at=ROOT.key("delivery").key(METHOD).key("onepassword_vault"),
            hint=hint,
        )


async def _call(what: str, *, vault: str, call: Callable[[], Awaitable[Any]]) -> Any:
    """One SDK call, or a :class:`StoreError` that says what was being done.

    ``call`` is called here, not by the caller, so an error raised while its
    arguments are built is mapped too. The SDK raises plain ``Exception`` with
    1Password's message, which is kept. A missing permission arrives here, so
    the hint names the three the method needs.
    """
    started = time.monotonic()
    try:
        result = await call()
    except Exception as error:  # noqa: BLE001 -- the SDK raises plain Exception
        LOG.debug("%s: %s in %.3fs", what, type(error).__name__, time.monotonic() - started)
        raise StoreError(
            f"1Password could not {what} in the vault {vault!r}: {error}",
            hint=(
                "1Password's own message is above. The service account needs read, write "
                "and share items on the vault. Nothing was handed over, and the account's "
                "password has not changed"
            ),
        ) from None
    LOG.debug("%s: ok in %.3fs", what, time.monotonic() - started)
    return result


def _name(value: Any) -> str:
    """An SDK enum's value, such as ``SevenDays``, or the value as text."""
    return str(getattr(value, "value", value))


def _sdk() -> Any:
    """`onepassword.client`, or the refusal that names the extra."""
    return _sdk_module("onepassword.client")


def _sdk_types() -> Any:
    """`onepassword.types`, or the refusal that names the extra."""
    return _sdk_module("onepassword.types")


def _sdk_module(name: str) -> Any:
    """One module of the SDK, or the refusal that names the extra.

    A missing module counts as the SDK missing only when the module is the
    SDK's own. A dependency the SDK cannot import, such as `pydantic`, means
    the SDK is installed and failed to load.
    """
    try:
        return importlib.import_module(name)
    except ModuleNotFoundError as error:
        if error.name is not None and error.name.split(".")[0] == "onepassword":
            raise OnePasswordNotInstalledError() from error
        raise OnePasswordNotInstalledError(loaded=f"no module {error.name!r}") from error
    except (ImportError, OSError) as error:
        raise OnePasswordNotInstalledError(loaded=type(error).__name__) from error
