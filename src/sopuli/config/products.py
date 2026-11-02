"""Which keys belong to which product, checked once the estate is expanded.

A key written for another product loads and then does nothing. An `oracle:`
block on a PostgreSQL target asserts a container the driver never checks, and
a `postgres:` block on an Oracle target names a database nothing connects
through. Each is refused here, naming the target and the key, for the reason
the config's key sets are closed at all.

After expansion, because a target set's `overrides:` may change a target's
`type` or add a block, so the pair only exists on the rendered target. The same
reason :mod:`sopuli.config.references` gives for the `auth: external` rules.

Two rules are about what an application binds rather than about a target. An
application's `oracle: container_clause`, and an account on a MySQL target that
does not name its host, are checked where the application binds to its targets
(:mod:`sopuli.config.bindings`), with :func:`refuse_a_container_clause` and
:func:`refuse_a_bare_mysql_account`. A personal account names its host too,
checked by :func:`check_personal_mysql_accounts`.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from sopuli.config.errors import ROOT, ConfigError, KeyPath
from sopuli.config.expansion import block_key_at, declared_at
from sopuli.config.model import (
    Application,
    Config,
    ExpandedTarget,
    Override,
    Target,
    TargetMysql,
    TargetOracle,
    TargetPostgres,
)
from sopuli.config.selection import select
from sopuli.config.targets import (
    EXTERNAL,
    MYSQL,
    MYSQL_UNENCRYPTED_SSL_MODE,
    MYSQL_VERIFYING_SSL_MODES,
    ORACLE,
    POSTGRESQL,
    UNENCRYPTED_SSLMODE,
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
    """A product's TLS keys, and the values that matter about them."""

    #: The key that holds the mode, and the key that holds the CA file.
    mode: str
    ca: str
    #: The modes that check the server against the CA file.
    verifying: tuple[str, ...]
    #: The one mode certain to connect without encryption.
    unencrypted: str
    #: The default mode, which is the one a message recommends.
    default: str
    #: The other verifying mode, named beside the default in a refusal.
    alternative: str
    #: The block as the run reads it, with its defaults filled in.
    settings: Callable[[Target], TargetPostgres | TargetMysql]


@dataclass(frozen=True)
class _Product:
    """What a message says about one product, written once."""

    name: str
    #: The article before the name, as in "an Oracle target".
    article: str
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
    def a_name(self) -> str:
        return f"{self.article} {self.name}"


_PRODUCTS: dict[str, _Product] = {
    ORACLE: _Product(name="Oracle", article="an", block="oracle", whole="database"),
    POSTGRESQL: _Product(
        name="PostgreSQL",
        article="a",
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
            unencrypted=UNENCRYPTED_SSLMODE,
            default="verify-full",
            alternative="verify-ca",
            settings=lambda target: target.postgres_settings,
        ),
    ),
    MYSQL: _Product(
        name="MySQL",
        article="a",
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
            unencrypted=MYSQL_UNENCRYPTED_SSL_MODE,
            default="VERIFY_IDENTITY",
            alternative="VERIFY_CA",
            settings=lambda target: target.mysql_settings,
        ),
    ),
}


@dataclass(frozen=True)
class TlsSetting:
    """A target's TLS mode as the run reads it, and what it means.

    The one place the warning (:mod:`sopuli.config.references`), the
    ``require_encryption`` refusal and this module read each product's TLS
    keys from, so a product is added in :data:`_PRODUCTS` and nowhere else.
    """

    #: Where the mode is written: the override's line where one wrote it.
    at: KeyPath
    #: The key, such as ``sslmode``, and its value.
    key: str
    mode: str
    #: The key that names a CA file.
    ca: str
    #: The default mode, which is the one to recommend.
    default: str
    #: Whether the mode checks the server's certificate.
    verifies: bool
    #: Whether the mode is certain to connect without encryption.
    never_encrypts: bool


def tls_setting(expanded: ExpandedTarget) -> TlsSetting | None:
    """The target's TLS mode, or ``None`` for a product that has no TLS keys
    of its own (Oracle, whose transport is NNE or TLS by the connect string)."""
    product = _PRODUCTS[expanded.target.type]
    tls = product.tls
    if tls is None:
        return None
    mode = getattr(tls.settings(expanded.target), tls.mode)
    return TlsSetting(
        at=block_key_at(expanded, product.block, tls.mode),
        key=tls.mode,
        mode=mode,
        ca=tls.ca,
        default=tls.default,
        verifies=mode in tls.verifying,
        never_encrypts=mode == tls.unencrypted,
    )


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
    # An override cannot clear a key its template wrote. Dropping the file is a
    # way out unless the template wrote it and an override changed the block.
    template_wrote_it = (
        product.block in expanded.patched and f"{product.block}.{tls.ca}" not in expanded.patched
    )
    raise ConfigError(
        f"target {expanded.name!r} names a CA file under `{tls.mode}: {mode}`, "
        f"which does not verify the server with it",
        # The line to change: the mode, where only the mode can change.
        at=block_key_at(expanded, product.block, tls.mode if template_wrote_it else tls.ca),
        hint=(
            f"use `{tls.mode}: {tls.default}` (the default) or `{tls.alternative}`"
            + ("" if template_wrote_it else f", or drop `{tls.ca}`")
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
    raise ConfigError(
        f"{named(application)} sets `oracle: container_clause`, and binds to {product.name} target "
        f"{expanded.name!r}",
        at=written.key("container_clause"),
        hint=(
            f"{product.owner}, so there is no container. Move the Oracle targets to an "
            "application of their own, or narrow this one's `targets:`"
        ),
    )


def named(application: Application) -> str:
    """An application entry, as the start of a message names it."""
    return "the application" if application.name is None else f"application {application.name!r}"


#: Where a MySQL account name puts its host: after the last `@`.
MYSQL_HOST_SEPARATOR = "@"

#: What a part of an account name may not start or end with: SQL's quotes, and
#: space. The config holds the names, not the statement that quotes them.
_NOT_AT_AN_END = ("'", '"', "`", " ", "\t")


def mysql_account(name: str) -> tuple[str, str] | None:
    """The user and the host of a MySQL account written as ``user@host``.

    Split at the last ``@``, because MySQL allows ``@`` in a user name and not
    in a host. ``None`` where either part is empty, which includes a name with
    no ``@`` at all.
    """
    user, separator, host = name.rpartition(MYSQL_HOST_SEPARATOR)
    if not separator or not user or not host:
        return None
    return user, host


def mysql_host_token(host: str) -> str:
    """A MySQL host pattern as ``{host}`` writes it: ``%`` as ``any`` and ``_``
    as ``one``, so that no vault path holds a MySQL wildcard. ``10.%`` is
    ``10.any`` (decided on #1221)."""
    return host.replace("%", "any").replace("_", "one")


def refuse_a_bare_mysql_account(
    expanded: ExpandedTarget, account: str, *, declared_by: str, at: KeyPath
) -> None:
    """A MySQL account names its host, as ``acme_app@10.%`` (#1202, decision 4).

    MySQL keeps ``acme_app@%`` and ``acme_app@localhost`` as two accounts with
    two passwords, and which one a login reaches depends on how the client
    connects. Reading a bare name as one of them would rotate it and leave the
    other on the old password. ``declared_by`` is who declares the account,
    such as "application 'acme'", and ``at`` is where the name is written. A
    name on another product's target is not checked.

    A part quoted as SQL quotes it, as in ``'acme_app'@'%'``, or with a space
    at an end, is refused too. It splits, but the quotes would become part of
    the name the driver looks for, and no account would match.
    """
    if expanded.target.type != MYSQL:
        return
    split = mysql_account(account)
    if split is None:
        raise ConfigError(
            f"{declared_by} declares {account!r} on MySQL target {expanded.name!r}, "
            "and a MySQL account must name its host as user@host",
            at=at,
            hint=(
                "write the host after the last `@`, as `acme_app@10.%`, or `acme_app@%` "
                "for the account any host reaches: MySQL keeps one account per host, each "
                "with its own password"
            ),
        )
    if any(part.startswith(_NOT_AT_AN_END) or part.endswith(_NOT_AT_AN_END) for part in split):
        raise ConfigError(
            f"{declared_by} declares {account!r} on MySQL target {expanded.name!r}, "
            "whose user or host starts or ends with a quote or a space",
            at=at,
            hint=(
                "write the name without SQL's quotes, as `acme_app@10.%`: the tool "
                "quotes each part itself"
            ),
        )


def check_personal_mysql_accounts(config: Config) -> None:
    """A `personal_accounts:` rule names its hosts on a MySQL target too.

    Personal accounts never become bindings, so :mod:`sopuli.config.bindings`
    does not see them. A rule declared by ``profile:`` or ``role:`` names no
    account, and has nothing to check. Run after references are resolved, so
    the rule's ``targets:`` names exist.
    """
    for index, rule in enumerate(config.personal_accounts):
        at = ROOT.key("personal_accounts").index(index)
        for expanded in select(config, rule.targets):
            for position, account in enumerate(rule.accounts):
                refuse_a_bare_mysql_account(
                    expanded,
                    account,
                    declared_by="a personal account rule",
                    at=at.key("accounts").index(position),
                )
