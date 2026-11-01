"""Which keys belong to which product, checked once the estate is expanded.

A key written for another product loads and then does nothing. An `oracle:`
block on a PostgreSQL target asserts a container the driver never checks, and
a `postgres:` block on an Oracle target names a database nothing connects
through. Each is refused here, naming the target and the key, for the reason
the config's key sets are closed at all.

After expansion, because a target set's `overrides:` may change a target's
`type` or add a block, so the pair only exists on the rendered target. The same
reason :mod:`sopuli.config.references` gives for the `auth: external` rules.

An application's `oracle: container_clause` is the one rule about an
application rather than a target. It is checked where the application binds to
its targets (:mod:`sopuli.config.bindings`), with
:func:`refuse_a_container_clause`.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass

from sopuli.config.errors import ConfigError, KeyPath
from sopuli.config.expansion import declared_at
from sopuli.config.model import (
    Application,
    Config,
    ExpandedTarget,
    Override,
    Target,
    TargetOracle,
)
from sopuli.config.targets import (
    EXTERNAL,
    MYSQL,
    MYSQL_VERIFYING_SSL_MODES,
    ORACLE,
    POSTGRESQL,
    VERIFYING_SSLMODES,
)

#: One label of a host name (RFC 1123): letters, digits and inner hyphens.
_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?"

#: `host:port`, where the host is a name or an IPv4 address (dot-separated
#: labels, with an optional root dot) or a bracketed IPv6 address with an
#: optional zone id. The range of the port is checked after the match.
_HOST_AND_PORT = re.compile(
    rf"(?:\[[0-9A-Fa-f:.]+(?:%[A-Za-z0-9._-]+)?\]|{_LABEL}(?:\.{_LABEL})*\.?):([0-9]{{1,5}})"
)


@dataclass(frozen=True)
class _Tls:
    """A product's TLS keys: the mode, the CA file, the modes that check the
    server against the file, and the fix a refusal names."""

    mode: str
    ca: str
    verifying: tuple[str, ...]
    fix: str


@dataclass(frozen=True)
class _Product:
    """What a message says about one product, written once."""

    #: The product's name with its article, as in "an Oracle target".
    a_name: str
    #: Its own block of keys on a target.
    block: str
    #: What one target of it is.
    whole: str
    #: Who on it has a password, and what it belongs to. ``None`` for Oracle,
    #: where accounts live in a container.
    owner: str | None = None
    #: The `dsn:` hint, for a product whose dsn is host:port.
    dsn_hint: str | None = None
    tls: _Tls | None = None

    @property
    def name(self) -> str:
        return self.a_name.split(" ", 1)[1]


_PRODUCTS: dict[str, _Product] = {
    ORACLE: _Product(a_name="an Oracle", block="oracle", whole="database"),
    POSTGRESQL: _Product(
        a_name="a PostgreSQL",
        block="postgres",
        whole="cluster",
        owner="a PostgreSQL role belongs to the whole cluster",
        dsn_hint=(
            "write host:port, such as pg-dev.example.com:5432. The database goes in "
            "`postgres.database` and TLS in `postgres.sslmode`; the password is never "
            "written in this file (P2)"
        ),
        tls=_Tls(
            mode="sslmode",
            ca="sslrootcert",
            verifying=VERIFYING_SSLMODES,
            fix="use `sslmode: verify-full` (the default) or `verify-ca`",
        ),
    ),
    MYSQL: _Product(
        a_name="a MySQL",
        block="mysql",
        whole="server",
        owner="a MySQL account belongs to the whole server",
        dsn_hint=(
            "write host:port, such as mysql-dev.example.com:3306. TLS goes in "
            "`mysql.ssl_mode`; the password is never written in this file (P2)"
        ),
        tls=_Tls(
            mode="ssl_mode",
            ca="ssl_ca",
            verifying=MYSQL_VERIFYING_SSL_MODES,
            fix="use `ssl_mode: VERIFY_IDENTITY` (the default) or `VERIFY_CA`",
        ),
    ),
}


def check_products(config: Config) -> None:
    """Refuse a key written for another product than the target's own."""
    for expanded in config.expanded_targets:
        _refuse_other_blocks(expanded)
        if expanded.target.type != ORACLE:
            _check_host_and_port_product(expanded)


def _written_blocks(target: Target) -> dict[str, bool]:
    """Which product blocks the target writes. `oracle:` always exists on the
    model, with defaults, so a block that differs from them is a written one."""
    return {
        ORACLE: target.oracle != TargetOracle(),
        POSTGRESQL: target.postgres is not None,
        MYSQL: target.mysql is not None,
    }


def _refuse_other_blocks(expanded: ExpandedTarget) -> None:
    """A block of another product's keys on this target."""
    target = expanded.target
    own = _PRODUCTS[target.type]
    for kind, present in _written_blocks(target).items():
        if not present or kind == target.type:
            continue
        other = _PRODUCTS[kind]
        if kind == ORACLE:
            # Oracle's block asserts a container, which no other product has.
            way_out = (
                f"drop `oracle:`. A {own.name} target is the whole {own.whole}, so there is "
                "no container to assert"
            )
        else:
            way_out = (
                f"drop `{other.block}:`, or set `type: {kind}` if this is {other.a_name} "
                f"{other.whole}"
            )
        raise ConfigError(
            f"target {expanded.name!r} is {own.a_name} target, so its `{other.block}:` "
            f"block would do nothing",
            at=declared_at(expanded, other.block),
            hint=way_out + _one_set_per_product(expanded, other.block, own.name),
        )


def _one_set_per_product(expanded: ExpandedTarget, block: str, product: str) -> str:
    """The way out for a target set whose template writes the other product's
    block: an override can change `type` but cannot remove a block. A block the
    override wrote is dropped from the override, which needs no extra words."""
    if expanded.target_set is None or block in expanded.patched:
        return ""
    return (
        f". An override cannot remove a block its template writes, so put the "
        f"{product} targets in a target set of their own"
    )


def _check_host_and_port_product(expanded: ExpandedTarget) -> None:
    """PostgreSQL's and MySQL's rules: a CA file only under a mode that checks
    the server with it, no Oracle wallet, and a host:port dsn."""
    target = expanded.target
    product = _PRODUCTS[target.type]
    _refuse_an_unused_ca_file(expanded, product)
    auth = None if target.admin is None else target.admin.auth
    if auth is not None and auth.method == EXTERNAL:
        raise ConfigError(
            f"target {expanded.name!r} is {product.a_name} target, and external "
            f"authentication is an Oracle wallet",
            at=declared_at(expanded, "admin").key("auth"),
            hint="use `vault`, `prompt` or `env`",
        )
    _check_dsn(expanded, product)


def _refuse_an_unused_ca_file(expanded: ExpandedTarget, product: _Product) -> None:
    """A CA file the mode ignores. libpq ignores it below `require`, and under
    `require` turns the mode into `verify-ca` without saying so; MySQL checks
    the server against it only under its two verifying modes."""
    tls = product.tls
    block = getattr(expanded.target, product.block)
    if tls is None or block is None or getattr(block, tls.ca) is None:
        return
    mode = getattr(block, tls.mode)
    if mode in tls.verifying:
        return
    raise ConfigError(
        f"target {expanded.name!r} names a CA file under `{tls.mode}: {mode}`, "
        f"which does not verify the server with it",
        at=declared_at(expanded, product.block),
        hint=(
            tls.fix
            # An override cannot clear a key its template wrote.
            + ("" if product.block in expanded.patched else f", or drop `{tls.ca}`")
        ),
    )


def _check_dsn(expanded: ExpandedTarget, product: _Product) -> None:
    """A PostgreSQL or MySQL `dsn:` is `host:port` and nothing more.

    A connection URI and a keyword string can both carry a password, which is
    what #891 refused in a vault address. No message here repeats the value, for
    the same reason.
    """
    hint = product.dsn_hint
    dsn = expanded.target.dsn
    at = declared_at(expanded, "dsn")
    if "://" in dsn:
        raise ConfigError(
            f"target {expanded.name!r}: `dsn:` is a connection URI, which can carry a password",
            at=at,
            hint=hint,
        )
    if "=" in dsn:
        raise ConfigError(
            f"target {expanded.name!r}: `dsn:` is a keyword connection string, which can "
            f"carry a password",
            at=at,
            hint=hint,
        )
    match = _HOST_AND_PORT.fullmatch(dsn)
    if match is None or not 1 <= int(match.group(1)) <= 65535:
        raise ConfigError(
            f"target {expanded.name!r} is {product.a_name} target, so its `dsn:` must be host:port",
            at=at,
            hint=hint,
        )


def refuse_a_container_clause(
    expanded: ExpandedTarget,
    application: Application,
    patches: Sequence[tuple[int, Override]],
    *,
    at: KeyPath,
) -> None:
    """An application's `oracle: container_clause` binds to Oracle targets only.

    ``patches`` are the application's overrides that apply to this target, with
    their positions, and ``at`` is where the application is written. The error
    names the first place that wrote the clause: the application's own block,
    else the first override.
    """
    product = _PRODUCTS[expanded.target.type]
    if product.owner is None:
        return
    if application.oracle.container_clause is not None:
        written = at.key("oracle")
    else:
        position = next(
            (index for index, patch in patches if patch.oracle.container_clause is not None),
            None,
        )
        if position is None:
            return
        written = at.key("overrides").index(position).key("oracle")
    name = "the application" if application.name is None else f"application {application.name!r}"
    raise ConfigError(
        f"{name} sets `oracle: container_clause`, and binds to {product.name} target "
        f"{expanded.name!r}",
        at=written.key("container_clause"),
        hint=(
            f"{product.owner}, so there is no container. Move the Oracle targets to an "
            "application of their own, or narrow this one's `targets:`"
        ),
    )
