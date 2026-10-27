"""`delivery.method: vault_path` — a KV v2 path only the person's identity reads.

UC-2 §6.6 has what it promises, and decision #447 the three choices it rests on.

**The path is the account's and the target's.** The value goes to
``<prefix>/<account>/<target>`` in the store's KV v2 mount, with the account
named exactly as the database stores it. The person's Vault policy reaches that
path through metadata the Vault admin puts on their identity entity, such as
``db_account = ACME_DEV_ALICE``. The tool cannot see that mapping, and it sets up
neither the auth method, nor the entities, nor the policy.

**Each name is one path segment.** A name containing ``/`` would add a level to
the path, so it is refused. Every other character is percent-encoded by the
transport, so the ``#`` in a common user's ``C##`` prefix reaches Vault as part
of the name.

**"The DBA never sees it" is checked, not assumed** (H8). Before anything is
written, ``sys/capabilities-self`` is asked about the data path and the metadata
path. A token that holds ``read`` or ``root`` on the data path is refused, and so
is one that lacks ``create`` or ``update`` on either, because the write would
then fail after a password had been drawn. The check runs twice: at plan time on
the account name as typed, before anything connects, and on each target on the
name the database returned, just before a password is drawn.

**The metadata is written first.** ``delete_version_after`` applies only to
versions written after it is set (measured on the tier-1 Vault, #447). The
deletion time reported is the ``deletion_time`` in Vault's answer to the write,
because a mount's own setting can shorten the configured one. An answer without
one means Vault will not delete the value, and that is a failure: both writes
come before the DDL (UC-2 §6.4), so the password has not changed yet.

**The write sends no check-and-set.** A mount or path that requires it refuses
the write, before the DDL.

**The two imports that reach `httpx` are inside the functions that use them**,
for :mod:`sopuli.delivery.vault_wrapped`'s reason (ADR-006 rule 1).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from sopuli.delivery import Receipt
from sopuli.exit_codes import ExitCode
from sopuli.safety import RefusedError
from sopuli.secrets import Secret
from sopuli.store.protocol import VERSIONING, SecretStore, StoreError

if TYPE_CHECKING:  # pragma: no cover -- annotations only
    from sopuli.store.hashicorp._transport import Transport

#: The method's name in `delivery.method`, and what a receipt records.
METHOD = "vault_path"

#: Vault's endpoint for the calling token's own capabilities on given paths.
CAPABILITIES_PATH = "sys/capabilities-self"

#: What the person reads at the path, as in a wrapped delivery's cubbyhole.
PASSWORD_KEY = "password"

#: Capabilities that would let the DBA read the value back. `root` is named
#: because a root-policy token answers ``["root"]`` and never lists ``read``.
READS = frozenset({"read", "root"})

#: What both writes need, on the data path and on the metadata path.
WRITES = frozenset({"create", "update"})


class NotAPathStoreError(RefusedError):
    """The configured store cannot hold a `vault_path` delivery.

    Exit 5, for :class:`~sopuli.delivery.vault_wrapped.NotWrappableError`'s
    reason: the estate asked for something this backend cannot do. A store that
    is not a HashiCorp one has no identity policies, and a KV v1 mount has
    neither versions nor ``delete_version_after``.
    """

    exit_code = ExitCode.UNSUPPORTED_CAPABILITY
    category = "capability"

    def __init__(self, vault: str, *, why: str) -> None:
        super().__init__(
            f"`delivery.method: vault_path` cannot use {vault!r}: {why}",
            hint=(
                "the method needs a `type: hashicorp` store with a KV v2 mount, because "
                "Vault deletes the value on a clock only there (UC-2 6.6). Name one in "
                "`delivery.vault_path.vault`, on the target, or as `defaults.vault`"
            ),
        )


class PathCapabilityError(RefusedError):
    """The DBA's token could read the person's path, or could not write it.

    Exit 5: what the run lacks is a property of the store's policy, knowable
    before a password is drawn (invariant 4). A token that can read is refused
    rather than used, because the unseen path skips expiry on the ground that the
    DBA cannot see the value (UC-2 §6.6).
    """

    exit_code = ExitCode.UNSUPPORTED_CAPABILITY
    category = "capability"


@dataclass(frozen=True)
class VaultPath:
    """Writes a password to the person's KV v2 path, and returns where."""

    transport: Transport
    vault: str
    mount: str
    prefix: str
    ttl: str

    def path(self, *, account: str, target: str) -> str:
        """``<prefix>/<account>/<target>``, or a refusal for a name with a ``/``."""
        for what, name in (("account", account), ("target", target)):
            if not name or "/" in name:
                raise PathCapabilityError(
                    f"the {what} name {name!r} cannot be one segment of a vault path",
                    hint=(
                        "`vault_path` writes to <prefix>/<account>/<target>, and a `/` in "
                        "a name would add a level to the path, so the person's policy "
                        "would not cover it. Use another delivery method for this account"
                    ),
                )
        return f"{self.prefix}/{account}/{target}"

    def preflight(self, *, account: str, target: str) -> None:
        """Refuse a token that could read the path, or could not write it."""
        path = self.path(account=account, target=target)
        data = f"{self.mount}/data/{path}"
        metadata = f"{self.mount}/metadata/{path}"
        held = self._capabilities(data, metadata)
        readable = sorted(held[data] & READS)
        if readable:
            raise PathCapabilityError(
                f"the token for {self.vault!r} holds {', '.join(readable)} on {data}, "
                f"so it could read {account}'s password back",
                hint=(
                    "on `vault_path` the DBA must not be able to read the person's path "
                    "(UC-2 6.6). Remove `read` from this token's policy on that path, or "
                    "use a token without the root policy"
                ),
            )
        for where in (data, metadata):
            missing = sorted(WRITES - held[where])
            if missing:
                raise PathCapabilityError(
                    f"the token for {self.vault!r} lacks {', '.join(missing)} on {where}",
                    hint=(
                        "`vault_path` writes the path's metadata, then the value, and "
                        "both need `create` and `update`. Grant them on "
                        f"{self.mount}/data/{self.prefix}/* and "
                        f"{self.mount}/metadata/{self.prefix}/*"
                    ),
                )

    def deliver(self, secret: Secret, *, account: str, target: str) -> Receipt:
        """Write the metadata, then the value, and return the path and version.

        **This is invariant 2's first exception**, the vault write, as in
        :mod:`sopuli.delivery.vault_wrapped`: the plaintext goes to Vault over the
        run's authenticated connection, and to nobody else.
        """
        from sopuli.store.hashicorp._errors import raise_for

        path = self.path(account=account, target=target)
        meta = f"{self.mount}/metadata/{path}"
        response = self.transport.request("POST", meta, json={"delete_version_after": self.ttl})
        if not response.ok:
            raise_for(response.status, response.body, path=meta)

        data = f"{self.mount}/data/{path}"
        body: dict[str, Any] = {
            "data": {PASSWORD_KEY: secret.reveal(), "account": account, "target": target}
        }
        response = self.transport.request("POST", data, json=body)
        if not response.ok:
            raise_for(response.status, response.body, path=data)
        return _receipt(response.body, path=f"{self.mount}/{path}")

    def _capabilities(self, *paths: str) -> dict[str, frozenset[str]]:
        """The calling token's capabilities on each path, from Vault."""
        from sopuli.store.hashicorp._errors import raise_for

        response = self.transport.request("POST", CAPABILITIES_PATH, json={"paths": list(paths)})
        if not response.ok:
            raise_for(response.status, response.body, path=CAPABILITIES_PATH)
        body = response.body if isinstance(response.body, dict) else {}
        held: dict[str, frozenset[str]] = {}
        for path in paths:
            listed = body.get(path)
            if not isinstance(listed, list):
                raise StoreError(
                    f"{CAPABILITIES_PATH} gave no capabilities for {path}",
                    hint="the answer is the tool's only proof that the DBA cannot read the "
                    "path, so the reset does not go on without it",
                )
            held[path] = frozenset(str(one) for one in listed)
        return held


def _receipt(body: Any, *, path: str) -> Receipt:
    """The version and the deletion time from Vault's answer to the write.

    **No ``deletion_time`` is a failure**, because it means Vault will not delete
    the value, and the ``ttl`` is the whole of what this method promises about it.
    The DDL has not run yet, so the password is unchanged.
    """
    data = body.get("data") if isinstance(body, dict) else None
    if not isinstance(data, dict):
        data = {}
    version = data.get("version")
    if not isinstance(version, int) or isinstance(version, bool):
        raise StoreError(
            f"the write to {path} returned no version",
            hint="the version is what the run document records about the hand-over",
        )
    deletion = _when(data.get("deletion_time"))
    if deletion is None:
        raise StoreError(
            f"Vault will not delete the value at {path}: its answer has no deletion time",
            hint=(
                "the path's `delete_version_after` did not apply to the version written. "
                "The account's password is unchanged. Check the mount's settings with "
                "`vault read <mount>/config`"
            ),
        )
    return Receipt(method=METHOD, expires_at=deletion, path=path, version=version)


def _when(value: Any) -> datetime | None:
    """An RFC 3339 timestamp, or ``None`` for Vault's empty one or a malformed one."""
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


def for_store(store: SecretStore, *, vault: str, ttl: str, prefix: str) -> VaultPath:
    """The backend for a store the run has already opened, or a refusal.

    A store with no transport is not a HashiCorp one, which is answerable
    without importing anything, as :func:`sopuli.delivery.vault_wrapped.for_store`
    explains. A store without :data:`~sopuli.store.protocol.VERSIONING` is a
    KV v1 mount.
    """
    transport = getattr(store, "transport", None)
    if transport is None:
        raise NotAPathStoreError(vault, why="it is not a HashiCorp store")

    from sopuli.store.hashicorp._transport import Transport

    if not isinstance(transport, Transport):
        raise NotAPathStoreError(vault, why="it is not a HashiCorp store")
    if VERSIONING not in store.supports():
        raise NotAPathStoreError(vault, why="its mount is KV v1, which has no versions")
    mount = getattr(store, "mount", None)
    if not isinstance(mount, str) or not mount:
        raise NotAPathStoreError(vault, why="its mount is not known")
    return VaultPath(transport=transport, vault=vault, mount=mount, prefix=prefix, ttl=ttl)
