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

from sopuli.config.errors import ConfigError, KeyPath
from sopuli.config.expansion import declared_at
from sopuli.config.model import Application, Config, ExpandedTarget, Override, TargetOracle
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

#: Each product's name in a message, and the block that holds its own keys.
_PRODUCTS = {ORACLE: "Oracle", POSTGRESQL: "PostgreSQL", MYSQL: "MySQL"}
_BLOCKS = {ORACLE: "oracle", POSTGRESQL: "postgres", MYSQL: "mysql"}

_DSN_HINTS = {
    POSTGRESQL: (
        "write host:port, such as pg-dev.example.com:5432. The database goes in "
        "`postgres.database` and TLS in `postgres.sslmode`; the password is never "
        "written in this file (P2)"
    ),
    MYSQL: (
        "write host:port, such as mysql-dev.example.com:3306. TLS goes in "
        "`mysql.ssl_mode`; the password is never written in this file (P2)"
    ),
}

#: Why a block of another product's keys has nothing to say on this target.
_NOTHING_TO_SAY = {
    POSTGRESQL: "A PostgreSQL target is the whole cluster, so there is no container to assert",
    MYSQL: "A MySQL target is the whole server, so there is no container to assert",
}


def check_products(config: Config) -> None:
    """Refuse a key written for another product than the target's own."""
    for expanded in config.expanded_targets:
        kind = expanded.target.type
        if kind == POSTGRESQL:
            _check_postgresql(expanded)
        elif kind == MYSQL:
            _check_mysql(expanded)
        else:
            _refuse_other_blocks(expanded)


def _refuse_other_blocks(expanded: ExpandedTarget) -> None:
    """A `postgres:` or `mysql:` block on a target of another type.

    The `oracle:` block is the one exception: it always exists on the model,
    with defaults, so its rule is the one each product's check writes itself.
    """
    target = expanded.target
    written = {POSTGRESQL: target.postgres is not None, MYSQL: target.mysql is not None}
    for kind, present in written.items():
        if not present or kind == target.type:
            continue
        block = _BLOCKS[kind]
        product = _PRODUCTS[target.type]
        raise ConfigError(
            f"target {expanded.name!r} is {_article(product)} {product} target, so its "
            f"`{block}:` block would do nothing",
            at=declared_at(expanded, block),
            hint=(
                f"drop `{block}:`, or set `type: {kind}` if this is {_article(_PRODUCTS[kind])} "
                f"{_PRODUCTS[kind]} {'cluster' if kind == POSTGRESQL else 'server'}"
                + _one_set_per_product(expanded, block, product)
            ),
        )


def _article(product: str) -> str:
    return "an" if product == "Oracle" else "a"


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


def _check_postgresql(expanded: ExpandedTarget) -> None:
    _refuse_an_oracle_block(expanded)
    _refuse_other_blocks(expanded)
    postgres = expanded.target.postgres
    if (
        postgres is not None
        and postgres.sslrootcert is not None
        and postgres.sslmode not in VERIFYING_SSLMODES
    ):
        raise ConfigError(
            f"target {expanded.name!r} names a CA file under `sslmode: {postgres.sslmode}`, "
            f"which does not verify the server with it",
            at=declared_at(expanded, "postgres"),
            hint=(
                "use `sslmode: verify-full` (the default) or `verify-ca`"
                # An override cannot clear a key its template wrote.
                + ("" if "postgres" in expanded.patched else ", or drop `sslrootcert`")
            ),
        )
    _refuse_external(expanded)
    _check_dsn(expanded)


def _check_mysql(expanded: ExpandedTarget) -> None:
    _refuse_an_oracle_block(expanded)
    _refuse_other_blocks(expanded)
    mysql = expanded.target.mysql
    if (
        mysql is not None
        and mysql.ssl_ca is not None
        and (mysql.ssl_mode not in MYSQL_VERIFYING_SSL_MODES)
    ):
        raise ConfigError(
            f"target {expanded.name!r} names a CA file under `ssl_mode: {mysql.ssl_mode}`, "
            f"which does not verify the server with it",
            at=declared_at(expanded, "mysql"),
            hint=(
                "use `ssl_mode: VERIFY_IDENTITY` (the default) or `VERIFY_CA`"
                + ("" if "mysql" in expanded.patched else ", or drop `ssl_ca`")
            ),
        )
    _refuse_external(expanded)
    _check_dsn(expanded)


def _refuse_an_oracle_block(expanded: ExpandedTarget) -> None:
    kind = expanded.target.type
    if expanded.target.oracle == TargetOracle():
        return
    product = _PRODUCTS[kind]
    raise ConfigError(
        f"target {expanded.name!r} is a {product} target, so its `oracle:` block would do nothing",
        at=declared_at(expanded, "oracle"),
        hint=(
            f"drop `oracle:`. {_NOTHING_TO_SAY[kind]}"
            + _one_set_per_product(expanded, "oracle", product)
        ),
    )


def _refuse_external(expanded: ExpandedTarget) -> None:
    target = expanded.target
    auth = None if target.admin is None else target.admin.auth
    if auth is not None and auth.method == EXTERNAL:
        raise ConfigError(
            f"target {expanded.name!r} is a {_PRODUCTS[target.type]} target, and external "
            f"authentication is an Oracle wallet",
            at=declared_at(expanded, "admin").key("auth"),
            hint="use `vault`, `prompt` or `env`",
        )


def _check_dsn(expanded: ExpandedTarget) -> None:
    """A PostgreSQL or MySQL `dsn:` is `host:port` and nothing more.

    A connection URI and a keyword string can both carry a password, which is
    what #891 refused in a vault address. No message here repeats the value, for
    the same reason.
    """
    kind = expanded.target.type
    hint = _DSN_HINTS[kind]
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
            f"target {expanded.name!r} is a {_PRODUCTS[kind]} target, so its `dsn:` must be "
            f"host:port",
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
    kind = expanded.target.type
    if kind == ORACLE:
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
    owner = (
        "a PostgreSQL role belongs to the whole cluster"
        if kind == POSTGRESQL
        else "a MySQL account belongs to the whole server"
    )
    raise ConfigError(
        f"{name} sets `oracle: container_clause`, and binds to {_PRODUCTS[kind]} target "
        f"{expanded.name!r}",
        at=written.key("container_clause"),
        hint=(
            f"{owner}, so there is no container. Move the Oracle targets to an "
            "application of their own, or narrow this one's `targets:`"
        ),
    )
