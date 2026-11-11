"""UC-5's accounts report: what state each account on a target is in.

Pure: the config and a survey of the target's accounts come in, rows come out.
Nothing here connects. `docs/use-cases/uc-05-fleet-reports.md` §3 and §4 are
the specification.

**Four outcomes for a check, and OK has to be earned.** A check ends in
`problem`, `ok`, `not_checked` (it could not run truthfully on this target) or
`no_rule` (the file states nothing to compare). An account is `REPORT_OK` only
when every check had a rule, ran, and passed. That is the design's one hard
rule: never report an account as fine when it is not.

**Names are matched in the tool.** A rule's names and `*` patterns are compared
with the names the survey read, by `upper()`. No pattern is ever sent to the
database, so `_` and `%` are plain characters, as they are in an Oracle name.
"""

from __future__ import annotations

from collections.abc import Collection, Sequence
from dataclasses import dataclass
from fnmatch import fnmatchcase

from sopuli.config.model import (
    Config,
    DbProfileRule,
    Limit,
    Login,
    Policy,
    ReportAccountRule,
    Settings,
    ValidUntilRule,
)
from sopuli.config.reports import (
    LOGIN_REFUSED,
    UNLIMITED,
    VALID_UNTIL_REQUIRED,
    is_pattern,
)
from sopuli.config.selection import select
from sopuli.driver.registry import DRIVERS
from sopuli.driver.survey import SurveyedAccount
from sopuli.personal import rules_for
from sopuli.report_exit import exit_code_for

REPORT_OK = "REPORT_OK"
REPORT_PROBLEM = "REPORT_PROBLEM"
NOT_CHECKED = "NOT_CHECKED"
NO_RULE = "NO_RULE"
UNDECLARED = "UNDECLARED"
ACCOUNT_MISSING = "ACCOUNT_MISSING"
#: A target's state for a profile the file expects there and the target does
#: not have (UC-5 §4). About the target, not an account.
PROFILE_MISSING = "PROFILE_MISSING"

#: What expects a profile, as :attr:`MissingProfile.expected_by` names it: the
#: config's own path, ``reports.accounts`` or ``policies.<name>``.
BY_RULE = "reports.accounts"
BY_POLICY = "policies."

#: The states this report gives an account, worst first. ``ERROR`` (a target
#: that could not be reached) is not here: it belongs to a target, not an
#: account.
STATES = (REPORT_PROBLEM, ACCOUNT_MISSING, NOT_CHECKED, NO_RULE, UNDECLARED, REPORT_OK)

OK, PROBLEM, NOT_CHECKED_OUTCOME, NO_RULE_OUTCOME = "ok", "problem", "not_checked", "no_rule"
#: A check the target's product has no concept of, such as `password_lifetime`
#: on PostgreSQL (#1458). Never a gap: it is counted apart from `not_checked`
#: and never sets the exit code.
NOT_APPLICABLE_OUTCOME = "not_applicable"
OUTCOMES = (OK, PROBLEM, NOT_CHECKED_OUTCOME, NO_RULE_OUTCOME, NOT_APPLICABLE_OUTCOME)

APPLICATION, PERSONAL, TECHNICAL, UNDECLARED_KIND = (
    "application",
    "personal",
    "technical",
    "undeclared",
)
KINDS = (APPLICATION, PERSONAL, TECHNICAL, UNDECLARED_KIND)

#: The checks, in the order a problem is listed (UC-5 §4): a password that will
#: expire, or has, a lock, the wrong profile, another setting, then a missing
#: account. `valid_until` is PostgreSQL's `VALID UNTIL` (#1459).
CHECKS = ("password_lifetime", "valid_until", "lock", "profile", "failed_login_limit", "present")

_ORDER = {state: rank for rank, state in enumerate(STATES)}
_CHECK_ORDER = {check: rank for rank, check in enumerate(CHECKS)}


@dataclass(frozen=True)
class Finding:
    """One check on one account: which, how it ended, and why, in plain words."""

    check: str
    outcome: str
    detail: str


@dataclass(frozen=True)
class AccountRow:
    """One account on one target, as the report shows it."""

    target: str
    account: str
    kind: str
    profile: str | None
    status: str | None
    findings: tuple[Finding, ...]
    state: str
    #: Information, never a check: the failed-login count, or ``None`` where the
    #: target cannot read it truthfully. Shown as `unknown`, never as 0.
    failed_logins: int | None = None
    #: Why ``failed_logins`` is ``None``, as the survey said it.
    failed_logins_reason: str | None = None


@dataclass(frozen=True)
class MissingProfile:
    """A profile the file expects on a target that the target does not have.

    One finding for the target, however many accounts are expected on it (UC-5
    §4). Each such account still shows its own wrong-profile problem, because it
    is on another profile.
    """

    target: str
    #: As the file first spells it.
    profile: str
    #: What expects it: :data:`BY_RULE`, then ``policies.<name>`` for each
    #: application policy, in that order.
    expected_by: tuple[str, ...]


#: The survey's fields that can be ``None``, in the order it writes their
#: reasons into :attr:`SurveyedAccount.unreadable` (one reason per ``None``).
_REASON_ORDER = ("locked", "password_lifetime", "failed_login_limit", "failed_logins")

#: Said when the survey gave no reason for a value it could not read.
_UNREAD = "cannot be read on this target"


def _reasons(surveyed: SurveyedAccount) -> dict[str, str]:
    """Each unreadable field's reason, matched to the field by the survey's order."""
    missing = [name for name in _REASON_ORDER if getattr(surveyed, name) is None]
    if len(missing) != len(surveyed.unreadable):
        # The survey did not give one reason per field. Never drop what it
        # said: every unreadable field carries all of it.
        joined = "; ".join(surveyed.unreadable) or _UNREAD
        return dict.fromkeys(missing, joined)
    return dict(zip(missing, surveyed.unreadable, strict=True))


@dataclass(frozen=True)
class _Expectation:
    """What the file expects of one account on one target."""

    profile: str | None
    settings: Settings
    #: The checks two sources set two ways, which are not checked.
    conflicts: frozenset[str] = frozenset()
    #: A rule's `login:`, ``refused`` or ``allowed``, or ``None`` where no rule says.
    login: Login | None = None
    #: A rule's `postgresql.valid_until`, or ``None`` where no rule says.
    valid_until: ValidUntilRule | None = None
    #: Whether an application logs in as the account, so it must be able to.
    application: bool = False


def evaluate(
    target: str,
    config: Config,
    survey: Sequence[SurveyedAccount],
    *,
    keep_kept_in_root: bool = False,
) -> tuple[AccountRow, ...]:
    """Every row the report shows for ``target``, worst first.

    A row for each surveyed account the report covers, and an
    ``ACCOUNT_MISSING`` row for each account the file names on this target by
    name that the survey did not find. An account that Oracle maintains is left
    out unless the file names it, by name or by pattern. So is a common account
    in a PDB (:attr:`SurveyedAccount.kept_in_root`), unless
    ``keep_kept_in_root``: the privilege report keeps it, because its grants
    made in the PDB are read there, though its lock and limits are not.
    """
    rules = _rules_on(config, target)
    applications = _application_profiles(config, target)
    personal_names, personal_profiles = _personal_on(config, target)
    not_applicable = not_applicable_on(config, target)

    built: list[AccountRow] = []
    found: set[str] = set()
    for surveyed in survey:
        name = surveyed.name.upper()
        found.add(name)
        matching = [rule for rule in rules if _names(rule, name)]
        named = bool(matching) or name in applications or name in personal_names
        left_out = surveyed.vendor_maintained or (surveyed.kept_in_root and not keep_kept_in_root)
        if left_out and not named:
            # Oracle's own accounts are left out unless the file names one, by
            # name or by a report rule's pattern. So is a common account in a
            # PDB: its lock, limits and count are kept in the root, so no check
            # that decides a state can run on it here, and the CDB target's
            # report checks it (#1438). A personal predicate over a profile
            # does not count: `profile: DEFAULT` would bring in SYS.
            continue
        if name in applications:
            kind = APPLICATION
        elif name in personal_names or surveyed.profile.upper() in personal_profiles:
            kind = PERSONAL
        elif matching:
            kind = TECHNICAL
        else:
            kind = UNDECLARED_KIND
        if kind == UNDECLARED_KIND:
            built.append(_row(target, surveyed, kind, (), UNDECLARED))
            continue
        expectation = _expectation(
            matching,
            applications.get(name),
            config.reports.oracle_profiles,
            surveyed.profile,
            application=kind == APPLICATION,
        )
        findings = _check(surveyed, expectation, not_applicable)
        state = _state(findings, login_stated=expectation.login is not None)
        built.append(_row(target, surveyed, kind, findings, state))

    for name in _declared_names(rules, applications, personal_names):
        if name in found:
            continue
        missing = Finding("present", PROBLEM, "not on this target")
        built.append(
            AccountRow(
                target,
                name,
                _kind_of(name, applications, personal_names),
                None,
                None,
                (missing,),
                ACCOUNT_MISSING,
            )
        )

    return tuple(sorted(built, key=_sort_key))


def missing_profiles(
    target: str, config: Config, profiles: Collection[str]
) -> tuple[MissingProfile, ...]:
    """Each profile the file expects on ``target`` that ``profiles`` lacks, by name.

    ``profiles`` is every profile the target has. A profile is expected where a
    ``reports.accounts`` rule that covers the target names it, or where an
    application's policy names it for an account bound there. A
    ``reports.oracle.profiles`` entry alone expects nothing: it says what a
    profile's limits must be where the profile is, not that every target has it
    (#1390). Nor does a personal rule's ``profile:``, which selects accounts. A
    rule that covers the target expects its profile there even where no account
    on the target matches it, as the maintainer decided for #1390: the rule says
    what the target must have. A rule cannot name an application account by name
    with an ``oracle.profile``; the config refuses that. Names are compared by
    ``upper()``. A target whose product has no profiles expects none: there the
    profile is *not applicable* (#1458), never missing.
    """
    if "profile" in not_applicable_on(config, target):
        return ()
    present = {name.upper() for name in profiles}
    expected: dict[str, tuple[str, list[str]]] = {}

    def expect(profile: str, source: str) -> None:
        _, sources = expected.setdefault(profile.upper(), (profile, []))
        if source not in sources:
            sources.append(source)

    for rule in _rules_on(config, target):
        if rule.profile is not None:
            expect(rule.profile, BY_RULE)
    for policy in _bound_policies(config, target).values():
        if policy is not None and policy.account.profile is not None:
            expect(policy.account.profile, f"{BY_POLICY}{policy.name}")
    return tuple(
        MissingProfile(target, spelled, tuple(sources))
        for key, (spelled, sources) in sorted(expected.items())
        if key not in present
    )


def exit_code(
    rows: Sequence[AccountRow],
    *,
    unreachable: int,
    unsupported: int = 0,
    targets: int = 0,
    missing: Sequence[MissingProfile] = (),
) -> int:
    """UC-5 §3: 5 if no target can run the report, 1 if a target was not reached,
    then 3 for a problem, then 4 for anything not checked.

    ``unsupported`` counts the targets of a product the report is not written
    for. Where every target is one, nothing could run, which is exit 5. Where
    only some are, those targets are not checked, which is exit 4 at most. A
    profile in ``missing`` is a problem (#1390).
    """
    states = {row.state for row in rows}
    return exit_code_for(
        unreachable=unreachable,
        unsupported=unsupported,
        targets=targets,
        problem=bool(states & {REPORT_PROBLEM, ACCOUNT_MISSING}) or bool(missing),
        incomplete=NOT_CHECKED in states,
    )


# ---------------------------------------------------------------- the file ---


def not_applicable_on(config: Config, target: str) -> frozenset[str]:
    """The checks ``target``'s product has no concept of (the driver registry).

    Pure: the registry says it from the target's `type:`, with no connection.
    A name the config does not have gives none, so nothing is hidden by a typo.
    """
    for expanded in config.expanded_targets:
        if expanded.name == target:
            return DRIVERS[expanded.target.type].not_applicable
    return frozenset()


def _rules_on(config: Config, target: str) -> tuple[ReportAccountRule, ...]:
    return tuple(
        rule
        for rule in config.reports.accounts
        if target in {expanded.name for expanded in select(config, rule.targets)}
    )


def _bound_policies(config: Config, target: str) -> dict[str, Policy | None]:
    """Each application account on ``target``, by ``upper()``, with its policy.

    ``None`` where the binding names no policy, or one the config lacks. The
    one walk of the bindings that :func:`evaluate` and :func:`missing_profiles`
    both use, so the two cannot disagree on what a policy expects.
    """
    policies = {policy.name: policy for policy in config.policies}
    return {
        binding.account.upper(): (
            policies.get(binding.policy) if binding.policy is not None else None
        )
        for binding in config.bindings
        if binding.target == target
    }


def _application_profiles(config: Config, target: str) -> dict[str, str | None]:
    """Each application account on ``target``, with its policy's expected profile."""
    return {
        account: policy.account.profile if policy is not None else None
        for account, policy in _bound_policies(config, target).items()
    }


def _personal_on(config: Config, target: str) -> tuple[set[str], set[str]]:
    """Personal accounts on ``target``: names, and the profiles a predicate names.

    A predicate over a **role** is not resolved here: the survey reads no roles,
    so such an account shows as undeclared until the report reads them.
    """
    names: set[str] = set()
    profiles: set[str] = set()
    for rule in rules_for(config, target):
        names.update(account.upper() for account in rule.accounts)
        if rule.profile is not None:
            profiles.add(rule.profile.upper())
    return names, profiles


def _names(rule: ReportAccountRule, name: str) -> bool:
    return any(
        fnmatchcase(name, written.upper()) if is_pattern(written) else written.upper() == name
        for written in rule.accounts
    )


def _declared_names(
    rules: Sequence[ReportAccountRule],
    applications: dict[str, str | None],
    personal_names: set[str],
) -> list[str]:
    """Every account the file names on this target by name, not by pattern."""
    names = set(applications) | personal_names
    for rule in rules:
        names.update(written.upper() for written in rule.accounts if not is_pattern(written))
    return sorted(names)


def _kind_of(name: str, applications: dict[str, str | None], personal: set[str]) -> str:
    if name in applications:
        return APPLICATION
    if name in personal:
        return PERSONAL
    return TECHNICAL


def _expectation(
    matching: Sequence[ReportAccountRule],
    application_profile: str | None,
    oracle_profiles: Sequence[DbProfileRule],
    actual_profile: str,
    *,
    application: bool,
) -> _Expectation:
    """What the file expects of one account.

    Rules combine field by field: a profile from one rule and a setting from
    another both apply. Only one field set two ways by two rules is a conflict.
    An application account's profile is its policy's, and never a rule's, also
    when its policy names none (`01-configuration.md` §8a).
    """
    # A `reports.oracle.profiles` entry for the account's profile states
    # settings too, so it takes part as one more source: a rule and the profile
    # entry that disagree are a conflict, never a silent precedence.
    profile_settings = next(
        (
            entry.settings
            for entry in oracle_profiles
            if entry.name.upper() == actual_profile.upper()
        ),
        Settings(),
    )
    sources = [rule.settings for rule in matching] + [profile_settings]
    lifetimes = {s.password_lifetime for s in sources if s.password_lifetime is not None}
    limits = {s.failed_login_limit for s in sources if s.failed_login_limit is not None}
    profiles = {rule.profile.upper() for rule in matching if rule.profile is not None}
    # An application logs in as its account, so a pattern's `login:` does not
    # reach it, as a rule's profile does not: the config refuses both for an
    # application account named by name.
    logins = set() if application else {rule.login for rule in matching if rule.login is not None}
    valid_untils = {rule.valid_until for rule in matching if rule.valid_until is not None}
    conflicts = frozenset(
        check
        for check, values in (
            ("password_lifetime", lifetimes),
            ("failed_login_limit", limits),
            ("profile", set() if application else profiles),
            ("lock", logins),
            ("valid_until", valid_untils),
        )
        if len(values) > 1
    )
    if application:
        profile = application_profile
    else:
        profile = next((rule.profile for rule in matching if rule.profile is not None), None)
    return _Expectation(
        profile=profile,
        settings=Settings(
            password_lifetime=next(iter(lifetimes), None),
            failed_login_limit=next(iter(limits), None),
        ),
        conflicts=conflicts,
        login=next(iter(logins), None),
        valid_until=next(iter(valid_untils), None),
        application=application,
    )


# ---------------------------------------------------------------- the checks ---


def _check(
    surveyed: SurveyedAccount, expectation: _Expectation, not_applicable: frozenset[str]
) -> tuple[Finding, ...]:
    """:func:`_stated`, with each check the product has no concept of made *not applicable*.

    A stated check the product lacks, such as `password_lifetime` on
    PostgreSQL or an `oracle.profile` on any product but Oracle, is
    `not_applicable` (#1458). Each stays in the findings, so the run document
    names it; :func:`_state` decides what an account whose every stated check
    is one of those is.
    """
    findings = _stated(surveyed, expectation)
    if not not_applicable:
        return findings
    return tuple(
        Finding(f.check, NOT_APPLICABLE_OUTCOME, f"this product has no {f.check}")
        if f.check in not_applicable and f.outcome != NO_RULE_OUTCOME
        else f
        for f in findings
    )


def _stated(surveyed: SurveyedAccount, expectation: _Expectation) -> tuple[Finding, ...]:
    """The lock, and each thing the file expects. A setting nobody names is not a check.

    `01-configuration.md` §8a: a setting a rule does not name is not compared.
    So the checks that apply are the lock and whatever the file states. Where it
    states nothing at all, the account is in the `no rule` state (U8). A rule's
    `login:` is something stated: it says what the lock must be. A PostgreSQL
    `VALID UNTIL` in the past is a problem whatever the file states (#1459).
    """
    reasons = _reasons(surveyed)
    if "lock" in expectation.conflicts:
        lock = Finding("lock", NOT_CHECKED_OUTCOME, "two rules expect different things")
    else:
        lock = _lock(
            surveyed,
            reasons.get("locked", _UNREAD),
            expectation.login,
            application=expectation.application,
            count_reason=reasons.get("failed_logins")
            or reasons.get("failed_login_limit")
            or _UNREAD,
        )
    settings = expectation.settings
    expiry = _valid_until(surveyed, expectation)
    findings = [lock] if expiry is None else [lock, expiry]
    if (
        expectation.profile is None
        and settings.is_empty
        and expectation.login is None
        and expectation.valid_until is None
    ):
        findings.append(
            Finding("profile", NO_RULE_OUTCOME, "no rule states a login, a profile or a setting")
        )
        return tuple(findings)
    # A field two sources set two ways is not checked; the account's other
    # checks still run.
    conflicted = [
        Finding(check, NOT_CHECKED_OUTCOME, "two rules expect different things")
        for check in ("profile", "password_lifetime", "failed_login_limit")
        if check in expectation.conflicts
    ]
    findings.extend(conflicted)
    if expectation.profile is not None and "profile" not in expectation.conflicts:
        findings.append(_profile(surveyed, expectation.profile))
    if settings.password_lifetime is not None and "password_lifetime" not in expectation.conflicts:
        findings.append(
            _setting(
                "password_lifetime",
                surveyed.password_lifetime,
                settings.password_lifetime,
                unit=" days",
                reason=reasons.get("password_lifetime", _UNREAD),
            )
        )
    if (
        settings.failed_login_limit is not None
        and "failed_login_limit" not in expectation.conflicts
    ):
        findings.append(
            _setting(
                "failed_login_limit",
                surveyed.failed_login_limit,
                settings.failed_login_limit,
                unit="",
                reason=reasons.get("failed_login_limit", _UNREAD),
            )
        )
    return tuple(findings)


def _lock(
    surveyed: SurveyedAccount,
    reason: str,
    login: Login | None,
    *,
    count_reason: str,
    application: bool = False,
) -> Finding:
    """The lock against the rule's `login:`, or against "not locked" where none says.

    `login: refused` passes on an account nobody can log in to with a password,
    whatever its lock, and otherwise only on a lock somebody set (#1447). A
    lockout after failed logins does not pass: somebody tried to log in. The
    survey says which a lock is (:class:`~sopuli.driver.survey.SurveyedAccount`),
    and where it cannot, the lock is not checked: never OK without proof.
    ``count_reason`` says why the survey could not tell.
    """
    if surveyed.locked is None:
        return Finding("lock", NOT_CHECKED_OUTCOME, reason)
    if surveyed.lock_is_login_attribute and surveyed.locked:
        # PostgreSQL's NOLOGIN, which is also how a group role is written: only
        # a rule's `login:` judges it (#1459).
        if application:
            # An application logs in as its account, so it must be able to,
            # whatever a pattern's `login:` says (#1464 review).
            return Finding(
                "lock", PROBLEM, f"cannot log in: {surveyed.status}, an application logs in as it"
            )
        if login is None:
            return Finding("lock", OK, f"{surveyed.status}, which only a rule's login: judges")
        if login == LOGIN_REFUSED:
            return Finding("lock", OK, f"cannot log in: {surveyed.status}")
        return Finding(
            "lock", PROBLEM, f"cannot log in: {surveyed.status}, rule says login allowed"
        )
    if login != LOGIN_REFUSED:
        if surveyed.locked:
            return Finding("lock", PROBLEM, f"locked: {surveyed.status}")
        return Finding("lock", OK, surveyed.status)
    if surveyed.no_authentication:
        return Finding("lock", OK, f"no authentication: {surveyed.status}")
    if not surveyed.locked:
        return Finding("lock", PROBLEM, f"can log in: {surveyed.status}, rule says login refused")
    if surveyed.deliberately_locked is None:
        return Finding(
            "lock",
            NOT_CHECKED_OUTCOME,
            f"locked: {surveyed.status}; the profile's PASSWORD_LOCK_TIME is UNLIMITED or "
            "unreadable, where a lockout reads LOCKED too, and the failed-login count "
            f"that would tell them apart cannot be read: "
            f"{count_reason}",
        )
    if not surveyed.deliberately_locked:
        counted = ""
        limit, failed = surveyed.failed_login_limit, surveyed.failed_logins
        if isinstance(limit, int) and failed is not None and failed >= limit:
            logins = "failed login" if failed == 1 else "failed logins"
            counted = f", {failed} {logins} reached the limit of {limit}"
        return Finding(
            "lock",
            PROBLEM,
            f"locked by failed logins: {surveyed.status}{counted}, rule says login refused",
        )
    return Finding("lock", OK, f"locked on purpose: {surveyed.status}")


def _valid_until(surveyed: SurveyedAccount, expectation: _Expectation) -> Finding | None:
    """PostgreSQL's ``VALID UNTIL`` against a rule's `postgresql.valid_until` (#1459).

    A date in the past is a problem with or without the key: no password logs
    the role in until somebody moves it. Without the key, any other date is not
    compared, so there is no finding. `required` wants a date in the future,
    and `forbidden` none, where ``infinity`` counts as none
    (:class:`~sopuli.driver.survey.ValidUntil`). On a product with no such
    date, a rule's key is a finding that the registry makes *not applicable*.
    """
    if "valid_until" in expectation.conflicts:
        return Finding("valid_until", NOT_CHECKED_OUTCOME, "two rules expect different things")
    wanted = expectation.valid_until
    read = surveyed.valid_until
    if read is None:
        return None if wanted is None else Finding("valid_until", NOT_CHECKED_OUTCOME, _UNREAD)
    shown = "no VALID UNTIL" if read.text is None else f"VALID UNTIL {read.text}"
    says = "" if wanted is None else f", rule says {wanted}"
    if read.expired:
        return Finding("valid_until", PROBLEM, f"password expired: {shown}{says}")
    if wanted is None:
        return None
    # `required` wants a date that will pass; `forbidden` wants none.
    met = not read.never if wanted == VALID_UNTIL_REQUIRED else read.never
    if met:
        return Finding("valid_until", OK, shown)
    return Finding("valid_until", PROBLEM, f"{shown}{says}")


def _profile(surveyed: SurveyedAccount, expected: str) -> Finding:
    if surveyed.profile.upper() == expected.upper():
        return Finding("profile", OK, surveyed.profile)
    return Finding("profile", PROBLEM, f"on {surveyed.profile}, expected {expected}")


def _setting(
    check: str, actual: Limit | None, expected: Limit, *, unit: str, reason: str
) -> Finding:
    if actual is None:
        return Finding(check, NOT_CHECKED_OUTCOME, reason)
    if _meets(actual, expected):
        return Finding(check, OK, _limit_text(actual, unit))
    wanted = UNLIMITED if expected == UNLIMITED else f"at most {expected}{unit}"
    return Finding(check, PROBLEM, f"{_limit_text(actual, unit)}, rule says {wanted}")


def _meets(actual: Limit, expected: Limit) -> bool:
    """``unlimited`` matches only unlimited; a number is a largest allowed value."""
    if expected == UNLIMITED:
        return actual == UNLIMITED
    if actual == UNLIMITED:
        return False
    assert isinstance(actual, int)
    assert isinstance(expected, int)
    return actual <= expected


def _limit_text(value: Limit, unit: str) -> str:
    return UNLIMITED if value == UNLIMITED else f"{value}{unit}"


def _state(findings: Sequence[Finding], *, login_stated: bool = False) -> str:
    """An account's state from its findings, worst first.

    A `not_applicable` finding never makes an account worse. But where every
    check the file states is one the product lacks, and no `login:` makes the
    lock a stated check, the file says nothing this product can compare: the
    account is `no rule`, its findings still naming each check (#1458).
    """
    outcomes = {finding.outcome for finding in findings}
    if PROBLEM in outcomes:
        return REPORT_PROBLEM
    if NOT_CHECKED_OUTCOME in outcomes:
        return NOT_CHECKED
    if NO_RULE_OUTCOME in outcomes:
        return NO_RULE
    stated = [f for f in findings if f.check != "lock" or login_stated]
    if stated and all(f.outcome == NOT_APPLICABLE_OUTCOME for f in stated):
        return NO_RULE
    return REPORT_OK


def undeclared_row(target: str, surveyed: SurveyedAccount) -> AccountRow:
    """An account no rule covers, as this module builds it, reasons included.

    For a caller that asks for one account by name, such as
    ``report privileges --account``, where the account is one :func:`evaluate`
    leaves out: one Oracle maintains, that nothing names.
    """
    return _row(target, surveyed, UNDECLARED_KIND, (), UNDECLARED)


def _row(
    target: str,
    surveyed: SurveyedAccount,
    kind: str,
    findings: tuple[Finding, ...],
    state: str,
) -> AccountRow:
    return AccountRow(
        target=target,
        account=surveyed.name,
        kind=kind,
        profile=surveyed.profile,
        status=surveyed.status,
        findings=findings,
        state=state,
        failed_logins=surveyed.failed_logins,
        failed_logins_reason=(
            _reasons(surveyed).get("failed_logins", _UNREAD)
            if surveyed.failed_logins is None
            else None
        ),
    )


def _sort_key(row: AccountRow) -> tuple[int, int, str]:
    worst = min(
        (_CHECK_ORDER[finding.check] for finding in row.findings if finding.outcome == PROBLEM),
        default=len(CHECKS),
    )
    # A missing account is a problem, ranked among the problems by its check.
    state = REPORT_PROBLEM if row.state == ACCOUNT_MISSING else row.state
    return (_ORDER[state], worst, row.account)
