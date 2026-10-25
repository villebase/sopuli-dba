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
from sopuli.config.targets import EXTERNAL, ORACLE, POSTGRESQL

#: One label of a host name (RFC 1123): letters, digits and inner hyphens.
_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?"

#: `host:port`, where the host is a name or an IPv4 address (dot-separated
#: labels, with an optional root dot) or a bracketed IPv6 address with an
#: optional zone id. The range of the port is checked after the match.
_HOST_AND_PORT = re.compile(
    rf"(?:\[[0-9A-Fa-f:.]+(?:%[A-Za-z0-9._-]+)?\]|{_LABEL}(?:\.{_LABEL})*\.?):([0-9]{{1,5}})"
)

_DSN_HINT = (
    "write host:port, such as pg-dev.example.com:5432. The database goes in "
    "`postgres.database` and TLS in `postgres.sslmode`; the password is never "
    "written in this file (P2)"
)


#: The `sslmode` values under which libpq verifies the server with
#: `sslrootcert`. Below `require` it ignores the file, and under `require` the
#: file turns the mode into `verify-ca` without saying so.
_VERIFYING_SSLMODES = ("verify-ca", "verify-full")


def check_products(config: Config) -> None:
    """Refuse a key written for another product than the target's own."""
    for expanded in config.expanded_targets:
        if expanded.target.type == POSTGRESQL:
            _check_postgresql(expanded)
        elif expanded.target.type == ORACLE and expanded.target.postgres is not None:
            raise ConfigError(
                f"target {expanded.name!r} is an Oracle target, so its `postgres:` "
                f"block would do nothing",
                at=declared_at(expanded, "postgres"),
                hint=(
                    "drop `postgres:`, or set `type: postgresql` if this is a PostgreSQL "
                    "cluster" + _one_set_per_product(expanded, "postgres", "Oracle")
                ),
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


def _check_postgresql(expanded: ExpandedTarget) -> None:
    target = expanded.target
    if target.oracle != TargetOracle():
        raise ConfigError(
            f"target {expanded.name!r} is a PostgreSQL target, so its `oracle:` "
            f"block would do nothing",
            at=declared_at(expanded, "oracle"),
            hint=(
                "drop `oracle:`. A PostgreSQL target is the whole cluster, so there is "
                "no container to assert" + _one_set_per_product(expanded, "oracle", "PostgreSQL")
            ),
        )
    postgres = target.postgres
    if (
        postgres is not None
        and postgres.sslrootcert is not None
        and postgres.sslmode not in _VERIFYING_SSLMODES
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
    auth = None if target.admin is None else target.admin.auth
    if auth is not None and auth.method == EXTERNAL:
        raise ConfigError(
            f"target {expanded.name!r} is a PostgreSQL target, and external "
            f"authentication is an Oracle wallet",
            at=declared_at(expanded, "admin").key("auth"),
            hint="use `vault`, `prompt` or `env`",
        )
    _check_dsn(expanded)


def _check_dsn(expanded: ExpandedTarget) -> None:
    """A PostgreSQL `dsn:` is `host:port` and nothing more.

    A connection URI and a keyword string can both carry a password, which is
    what #891 refused in a vault address. No message here repeats the value, for
    the same reason.
    """
    dsn = expanded.target.dsn
    at = declared_at(expanded, "dsn")
    if "://" in dsn:
        raise ConfigError(
            f"target {expanded.name!r}: `dsn:` is a connection URI, which can carry a password",
            at=at,
            hint=_DSN_HINT,
        )
    if "=" in dsn:
        raise ConfigError(
            f"target {expanded.name!r}: `dsn:` is a keyword connection string, which can "
            f"carry a password",
            at=at,
            hint=_DSN_HINT,
        )
    match = _HOST_AND_PORT.fullmatch(dsn)
    if match is None or not 1 <= int(match.group(1)) <= 65535:
        raise ConfigError(
            f"target {expanded.name!r} is a PostgreSQL target, so its `dsn:` must be host:port",
            at=at,
            hint=_DSN_HINT,
        )


def refuse_a_container_clause(
    expanded: ExpandedTarget,
    application: Application,
    patches: Sequence[tuple[int, Override]],
    *,
    at: KeyPath,
) -> None:
    """An application's `oracle: container_clause` cannot bind to a PostgreSQL target.

    ``patches`` are the application's overrides that apply to this target, with
    their positions, and ``at`` is where the application is written. The error
    names the first place that wrote the clause: the application's own block,
    else the first override.
    """
    if expanded.target.type != POSTGRESQL:
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
        f"{name} sets `oracle: container_clause`, and binds to PostgreSQL target {expanded.name!r}",
        at=written.key("container_clause"),
        hint=(
            "a PostgreSQL role belongs to the whole cluster, so there is no container. "
            "Move the Oracle targets to an application of their own, or narrow this "
            "one's `targets:`"
        ),
    )
