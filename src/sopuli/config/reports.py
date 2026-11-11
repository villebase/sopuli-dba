"""The `reports:` section: the rules UC-5's `report accounts` checks.

A rule says what an account should look like: which profile it is on, and what
its password limits are. The report reads every account on a target and
compares. Nothing here reads a database: this module checks the *shape* of the
rules, and the report decides what a database's answer means
(`docs/use-cases/uc-05-fleet-reports.md` §4 and §7).

**The settings are not Oracle's words.** `password_lifetime` and
`failed_login_limit` say what is expected, and each product reads them from
where it keeps them (UC-5 §7). A value is `unlimited` or a whole number that the
database's value must not exceed. A key that only one product has goes in that
product's block: `oracle:` on a rule holds `profile:`, and `oracle:` on the
section holds `profiles:`, the list of database profiles.

**A rule declares nothing for invariant 5.** A name in `reports.accounts` lets
the report check an account; it does not let any changing command touch it.
"""

from __future__ import annotations

from typing import Any

from sopuli.config.applications import account_owners, build_target_selector
from sopuli.config.errors import ROOT, ConfigError, KeyPath
from sopuli.config.fields import (
    describe,
    mapping,
    optional_string,
    reject_moved_keys,
    reject_unknown_keys,
    required_string,
    sequence,
    string_list,
)
from sopuli.config.model import (
    Application,
    DbProfileRule,
    Limit,
    ReportAccountRule,
    Reports,
    Settings,
)

REPORTS_KEYS = ("accounts", "oracle")
REPORT_ACCOUNT_KEYS = ("accounts", "targets", "settings", "oracle")
#: `reports.oracle`: what only Oracle has, for the whole section.
ORACLE_REPORTS_KEYS = ("profiles",)
#: `reports.accounts[].oracle`: what only Oracle has, for one rule.
ORACLE_RULE_KEYS = ("profile",)
DB_PROFILE_KEYS = ("name", "settings")
SETTINGS_KEYS = ("password_lifetime", "failed_login_limit")

#: Keys that config schema 5.0 moved into a product block (#1447). The old
#: place is refused by name, so a file written for 4.x is told where the key
#: went rather than that it has a typo. Each maps to its new place and how to
#: write it there, because a dotted path such as `oracle.profile` reads like
#: one YAML key with a dot in its name.
MOVED_SINCE = "5.0"
MOVED_REPORTS_KEYS = {
    "db_profiles": (
        "`reports.oracle.profiles`",
        "write `oracle: { profiles: [...] }` under `reports:`",
    ),
}
MOVED_RULE_KEYS = {
    "profile": ("the rule's `oracle:` block", "write `oracle: { profile: <name> }` on the rule"),
}

#: The one value a limit takes that is not a number.
UNLIMITED = "unlimited"

#: A pattern's only wildcard. The report matches names in the tool, against
#: the names it read, and never sends a pattern to the database: so `_` and `%`
#: are plain characters here, as in an Oracle name, and never SQL `LIKE`
#: wildcards. The glob wildcards other than `*` are refused, so that a name
#: holding one is never read as a pattern by accident.
WILDCARD = "*"
_REFUSED_WILDCARDS = ("?", "[", "]")


def build_reports(document: dict[str, Any]) -> Reports:
    """Normalise `reports:`. Absent means no rules."""
    if "reports" not in document:
        return Reports()

    at = ROOT.key("reports")
    section = mapping(document["reports"], at=at)
    reject_moved_keys(section, moved=MOVED_REPORTS_KEYS, since=MOVED_SINCE, at=at)
    reject_unknown_keys(section, allowed=REPORTS_KEYS, at=at)
    if not section:
        raise ConfigError(
            "must declare `accounts:` or `oracle:`",
            at=at,
            hint="delete the section to declare no report rules",
        )

    accounts = _entries(section, "accounts", at=at)
    profiles_at = at.key("oracle").key("profiles")
    profiles = _oracle_profiles(section, at=at)
    built_profiles = tuple(
        _build_db_profile(raw, at=profiles_at.index(index)) for index, raw in enumerate(profiles)
    )
    _reject_duplicate_profiles(built_profiles, at=profiles_at)
    built_rules = tuple(
        _build_account_rule(raw, at=at.key("accounts").index(index))
        for index, raw in enumerate(accounts)
    )
    _reject_duplicate_accounts(built_rules, at=at.key("accounts"))
    return Reports(accounts=built_rules, oracle_profiles=built_profiles)


def _product_block(
    container: dict[str, Any], product: str, *, allowed: tuple[str, ...], at: KeyPath
) -> dict[str, Any] | None:
    """A product's block, such as `oracle:`, checked for its keys; ``None`` if absent.

    Present and empty is refused: somebody meant to write something, and a
    silent "nothing" would look like it took. The published schema agrees
    (`minProperties: 1`).
    """
    if product not in container:
        return None
    block_at = at.key(product)
    block = mapping(container[product], at=block_at)
    reject_unknown_keys(block, allowed=allowed, at=block_at)
    if not block:
        keys = " or ".join(f"`{key}:`" for key in allowed)
        raise ConfigError(
            f"must declare {keys}",
            at=block_at,
            hint=f"delete `{product}:` to declare nothing for {product}",
        )
    return block


def _oracle_profiles(section: dict[str, Any], *, at: KeyPath) -> list[Any]:
    """`reports.oracle.profiles`, the entries as written. Absent means none."""
    block = _product_block(section, "oracle", allowed=ORACLE_REPORTS_KEYS, at=at)
    if block is None:
        return []
    return _entries(block, "profiles", at=at.key("oracle"))


def _reject_duplicate_accounts(rules: tuple[ReportAccountRule, ...], *, at: KeyPath) -> None:
    """One account name appears in one rule, compared by ``upper()``.

    Two rules naming one account could expect two profiles, and the report
    would have to pick. A rule for one account on some targets and another on
    others is one rule per target selection in a later version, if it is ever
    needed; refusing now is the reversible half. Patterns are not compared: which
    accounts two patterns share is a fact about a database, so the report
    handles that.
    """
    seen: dict[str, tuple[int, KeyPath]] = {}
    for index, rule in enumerate(rules):
        for position, name in enumerate(rule.accounts):
            if is_pattern(name):
                continue
            where = at.index(index).key("accounts").index(position)
            spelled = name.upper()
            if spelled in seen:
                first_rule, first_at = seen[spelled]
                same = first_rule == index
                raise ConfigError(
                    f"account {name!r} is named twice in one rule"
                    if same
                    else f"account {name!r} is named by two rules",
                    at=where,
                    hint=f"already named at {first_at}; "
                    + ("name it once" if same else "name each account in one rule"),
                )
            seen[spelled] = (index, where)


def _entries(section: dict[str, Any], key: str, *, at: KeyPath) -> list[Any]:
    if key not in section:
        return []
    entries = sequence(section[key], at=at.key(key))
    if not entries:
        # Present and empty means somebody meant to write something; a silent
        # "none" would look like it took.
        raise ConfigError(
            "must declare at least one entry",
            at=at.key(key),
            hint=f"delete `{key}:` to declare none",
        )
    return entries


def _build_account_rule(raw: Any, *, at: KeyPath) -> ReportAccountRule:
    entry = mapping(raw, at=at)
    reject_moved_keys(entry, moved=MOVED_RULE_KEYS, since=MOVED_SINCE, at=at)
    reject_unknown_keys(entry, allowed=REPORT_ACCOUNT_KEYS, at=at)
    if "accounts" not in entry:
        raise ConfigError("must declare `accounts:`", at=at)
    accounts = string_list(entry["accounts"], at=at.key("accounts"))
    if not accounts:
        raise ConfigError("must declare at least one account", at=at.key("accounts"))
    for position, name in enumerate(accounts):
        _check_pattern(name, at=at.key("accounts").index(position))

    profile = _oracle_rule_profile(entry, at=at)
    settings = Settings()
    if "settings" in entry:
        settings = _build_settings(entry["settings"], at=at.key("settings"))
    if profile is None and settings.is_empty:
        raise ConfigError(
            "must declare `settings:` or `oracle.profile`",
            at=at,
            hint="a rule with neither has nothing to check",
        )
    return ReportAccountRule(
        accounts=accounts,
        targets=build_target_selector(entry.get("targets"), at=at.key("targets")),
        profile=profile,
        settings=settings,
    )


def _oracle_rule_profile(entry: dict[str, Any], *, at: KeyPath) -> str | None:
    """A rule's `oracle.profile`, or ``None`` where the rule has no `oracle:` block."""
    block = _product_block(entry, "oracle", allowed=ORACLE_RULE_KEYS, at=at)
    if block is None:
        return None
    return optional_string(block, "profile", at=at.key("oracle"))


def _build_db_profile(raw: Any, *, at: KeyPath) -> DbProfileRule:
    entry = mapping(raw, at=at)
    reject_unknown_keys(entry, allowed=DB_PROFILE_KEYS, at=at)
    name = required_string(entry, "name", at=at)
    if "settings" not in entry:
        raise ConfigError(
            "must declare `settings:`", at=at, hint="a profile entry says what it must be"
        )
    settings = _build_settings(entry["settings"], at=at.key("settings"))
    if settings.is_empty:
        raise ConfigError("must declare at least one setting", at=at.key("settings"))
    return DbProfileRule(name=name, settings=settings)


def _build_settings(raw: Any, *, at: KeyPath) -> Settings:
    block = mapping(raw, at=at)
    reject_unknown_keys(block, allowed=SETTINGS_KEYS, at=at)
    if not block:
        # Present and empty means somebody meant to write a setting; the
        # published schema refuses it too (`minProperties: 1`).
        raise ConfigError(
            "must declare at least one setting",
            at=at,
            hint="delete `settings:` to declare none",
        )
    return Settings(
        password_lifetime=_limit(block, "password_lifetime", at=at),
        failed_login_limit=_limit(block, "failed_login_limit", at=at),
    )


def _limit(block: dict[str, Any], key: str, *, at: KeyPath) -> Limit | None:
    if key not in block:
        return None
    value = block[key]
    # `bool` is an `int` in Python, and YAML reads `yes` as one; neither is a limit.
    if value == UNLIMITED or (type(value) is int and value > 0):
        return value  # type: ignore[no-any-return]
    # A limit is not a secret, so the message can show it; `describe` names
    # only the type, which does not say what was wrong with a 0.
    found = repr(value) if isinstance(value, (int, float, str)) else describe(value)
    raise ConfigError(
        f"`{key}` must be `{UNLIMITED}` or a whole number above 0 (found {found})",
        at=at.key(key),
    )


def _check_pattern(name: str, *, at: KeyPath) -> None:
    for refused in _REFUSED_WILDCARDS:
        if refused in name:
            raise ConfigError(
                f"{name!r} uses {refused!r}; the only wildcard is {WILDCARD!r}",
                at=at,
            )


def is_pattern(name: str) -> bool:
    """Whether a name in a rule is a pattern rather than one account."""
    return WILDCARD in name


def _reject_duplicate_profiles(profiles: tuple[DbProfileRule, ...], *, at: KeyPath) -> None:
    """One profile name appears once, compared by ``upper()`` as names are everywhere."""
    seen: dict[str, KeyPath] = {}
    for index, profile in enumerate(profiles):
        spelled = profile.name.upper()
        where = at.index(index).key("name")
        if spelled in seen:
            raise ConfigError(
                f"duplicate profile {profile.name!r}",
                at=where,
                hint=f"already declared at {seen[spelled]}",
            )
        seen[spelled] = where


def reject_profile_on_application_accounts(
    applications: tuple[Application, ...], reports: Reports
) -> None:
    """A rule may not give an application account an `oracle.profile`.

    An application account's expected profile is its policy's
    `account.profile` (UC-5 §4). A second source could disagree with the first,
    and the report would have to pick one. A rule may still give such an
    account `settings:`.

    Only names are checked. A pattern is matched against a database, so the
    report is where a pattern that reaches an application account is handled:
    there the policy's profile wins.
    """
    owners = account_owners(applications)

    for index, rule in enumerate(reports.accounts):
        if rule.profile is None:
            continue
        for position, name in enumerate(rule.accounts):
            owner = owners.get(name.upper())
            if owner is None or is_pattern(name):
                continue
            raise ConfigError(
                f"account {name!r} belongs to {owner}, so its profile comes from its policy",
                at=ROOT.key("reports").key("accounts").index(index).key("accounts").index(position),
                hint=(
                    "set `account.profile` in the application's policy, "
                    "or drop `oracle.profile` here"
                ),
            )
