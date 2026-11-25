"""An application's ``kubernetes:`` block: which ExternalSecret to refresh (C18).

After ``creds apply`` or ``creds rotate`` promotes a document, the tool asks
External Secrets Operator to read it again at once, rather than at its next
``refreshInterval``. This module reads the block and resolves it for one
account in one target. It does no I/O: running ``kubectl`` is the commands'
business.

The block resolves the way a secret ref does. Its values may hold §7's tokens,
and ``overrides:`` patch it key by key, a later override winning. Once any key
is set, all three must be, because a refresh sent to a guessed namespace or
context reaches the wrong ExternalSecret, or the wrong cluster.
"""

from __future__ import annotations

import re
from typing import Any

from sopuli.config.errors import ConfigError, KeyPath
from sopuli.config.fields import mapping, optional_string, reject_unknown_keys
from sopuli.config.model import Application, ExternalSecretRef, KubernetesOptions, Override
from sopuli.config.templates import substitute

KUBERNETES_KEYS = ("context", "namespace", "external_secret")

#: A namespace is a DNS-1123 label: Kubernetes refuses any other name.
_LABEL = re.compile(r"[a-z0-9]([-a-z0-9]*[a-z0-9])?")
_LABEL_MAX = 63

#: An ExternalSecret's name is a DNS-1123 subdomain.
_SUBDOMAIN = re.compile(r"[a-z0-9]([-a-z0-9.]*[a-z0-9])?")
_SUBDOMAIN_MAX = 253

_TOKEN_SOURCE = "a `kubernetes:` value resolves from §7's tokens, as a secret ref does"


def build_kubernetes(raw: Any, *, at: KeyPath) -> KubernetesOptions:
    """The block as written. Absent builds the empty block."""
    if raw is None:
        return KubernetesOptions()
    block = mapping(raw, at=at)
    reject_unknown_keys(block, allowed=KUBERNETES_KEYS, at=at)
    options = KubernetesOptions(
        context=optional_string(block, "context", at=at),
        namespace=optional_string(block, "namespace", at=at),
        external_secret=optional_string(block, "external_secret", at=at),
    )
    if options.is_empty:
        raise ConfigError(
            "a `kubernetes:` block must set at least one key",
            at=at,
            hint="set `context`, `namespace` and `external_secret`, or delete the block",
        )
    return options


def resolve_external_secret(
    application: Application,
    patches: list[tuple[int, Override]],
    tokens: dict[str, str],
    *,
    has_secret: bool,
    at: KeyPath,
) -> ExternalSecretRef | None:
    """The ExternalSecret for one account in one target, or ``None`` without a block.

    ``patches`` are the overrides that match the target, in document order, as
    :func:`sopuli.config.bindings._patches_for` gives them. ``tokens`` is the
    account's §7 scope. ``has_secret`` says whether the binding has a secret
    ref: without one nothing is promoted, so there is nothing to refresh.
    """
    written = _merge(application, patches, at=at)
    if not written:
        return None

    missing = [key for key in KUBERNETES_KEYS if key not in written]
    if missing:
        names = ", ".join(f"`{key}`" for key in missing)
        raise ConfigError(
            f"application {application.label!r} has a `kubernetes:` block without {names}",
            at=at.key("kubernetes"),
            hint=(
                "all three keys are required, on the entry or from an override that "
                "matches this target: a refresh needs the exact context, namespace "
                "and ExternalSecret"
            ),
        )
    if not has_secret:
        raise ConfigError(
            f"application {application.label!r} has a `kubernetes:` block and no secret ref",
            at=at.key("kubernetes"),
            hint=(
                "the refresh follows a promotion in the vault, so it needs `secret` "
                "or `secret_template`"
            ),
        )

    values = {
        key: substitute(value, tokens, at=where, source=_TOKEN_SOURCE)
        for key, (value, where) in written.items()
    }
    _check_context(values["context"], at=written["context"][1])
    _check_name(
        values["namespace"],
        pattern=_LABEL,
        limit=_LABEL_MAX,
        kind="a namespace",
        characters="lowercase letters, digits and `-`",
        at=written["namespace"][1],
    )
    _check_name(
        values["external_secret"],
        pattern=_SUBDOMAIN,
        limit=_SUBDOMAIN_MAX,
        kind="an ExternalSecret name",
        characters="lowercase letters, digits, `-` and `.`",
        at=written["external_secret"][1],
    )
    return ExternalSecretRef(
        context=values["context"],
        namespace=values["namespace"],
        name=values["external_secret"],
    )


def _merge(
    application: Application, patches: list[tuple[int, Override]], *, at: KeyPath
) -> dict[str, tuple[str, KeyPath]]:
    """Each key's value and the place it was written, the last patch winning."""
    written: dict[str, tuple[str, KeyPath]] = {}
    sources = [(application.kubernetes, at.key("kubernetes"))]
    sources.extend(
        (override.kubernetes, at.key("overrides").index(position).key("kubernetes"))
        for position, override in patches
    )
    for options, where in sources:
        for key in KUBERNETES_KEYS:
            value = getattr(options, key)
            if value is not None:
                written[key] = (value, where.key(key))
    return written


def _check_context(value: str, *, at: KeyPath) -> None:
    """A kubeconfig context may be any name, but not an empty or unprintable one."""
    if not value or any(not character.isprintable() for character in value):
        raise ConfigError(
            f"{value!r} is not a kubeconfig context name",
            at=at,
            hint="name the context as `kubectl config get-contexts` lists it",
        )


def _check_name(
    value: str,
    *,
    pattern: re.Pattern[str],
    limit: int,
    kind: str,
    characters: str,
    at: KeyPath,
) -> None:
    if len(value) > limit or pattern.fullmatch(value) is None:
        raise ConfigError(
            f"{value!r} is not {kind} Kubernetes accepts",
            at=at,
            hint=(
                f"{characters}, at most {limit} "
                "characters, starting and ending with a letter or digit. An account "
                "name with `_` cannot be used as it is"
            ),
        )
