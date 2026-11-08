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

from collections.abc import Sequence
from dataclasses import dataclass
from fnmatch import fnmatchcase

from sopuli.config.model import Config, DbProfileRule, Limit, ReportAccountRule, Settings
from sopuli.config.reports import UNLIMITED, is_pattern
from sopuli.config.selection import select
from sopuli.driver.survey import SurveyedAccount
from sopuli.exit_codes import ExitCode
from sopuli.personal import rules_for

REPORT_OK = "REPORT_OK"
REPORT_PROBLEM = "REPORT_PROBLEM"
NOT_CHECKED = "NOT_CHECKED"
NO_RULE = "NO_RULE"
UNDECLARED = "UNDECLARED"
ACCOUNT_MISSING = "ACCOUNT_MISSING"

#: The states this report gives an account, worst first. ``ERROR`` (a target
#: that could not be reached) is not here: it belongs to a target, not an
#: account.
STATES = (REPORT_PROBLEM, ACCOUNT_MISSING, NOT_CHECKED, NO_RULE, UNDECLARED, REPORT_OK)

OK, PROBLEM, NOT_CHECKED_OUTCOME, NO_RULE_OUTCOME = "ok", "problem", "not_checked", "no_rule"

APPLICATION, PERSONAL, TECHNICAL, UNDECLARED_KIND = (
    "application",
    "personal",
    "technical",
    "undeclared",
)
KINDS = (APPLICATION, PERSONAL, TECHNICAL, UNDECLARED_KIND)

#: The checks, in the order a problem is listed (UC-5 §4): a password that will
#: expire, a lock, the wrong profile, another setting, then a missing account.
CHECKS = ("password_lifetime", "lock", "profile", "failed_login_limit", "present")

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


def evaluate(
    target: str, config: Config, survey: Sequence[SurveyedAccount]
) -> tuple[AccountRow, ...]:
    """Every row the report shows for ``target``, worst first.

    A row for each surveyed account the report covers, and an
    ``ACCOUNT_MISSING`` row for each account the file names on this target by
    name that the survey did not find. An account that Oracle maintains is left
    out unless the file names it, by name or by pattern.
    """
    rules = _rules_on(config, target)
    applications = _application_profiles(config, target)
    personal_names, personal_profiles = _personal_on(config, target)

    built: list[AccountRow] = []
    found: set[str] = set()
    for surveyed in survey:
        name = surveyed.name.upper()
        found.add(name)
        matching = [rule for rule in rules if _names(rule, name)]
        named = bool(matching) or name in applications or name in personal_names
        if surveyed.vendor_maintained and not named:
            # Oracle's own accounts are left out unless the file names one, by
            # name or by a report rule's pattern. A personal predicate over a
            # profile does not count: `profile: DEFAULT` would bring in SYS.
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
            config.reports.db_profiles,
            surveyed.profile,
            application=kind == APPLICATION,
        )
        findings = _check(surveyed, expectation)
        built.append(_row(target, surveyed, kind, findings, _state(findings)))

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


def exit_code(
    rows: Sequence[AccountRow], *, unreachable: int, unsupported: int = 0, targets: int = 0
) -> int:
    """UC-5 §3: 5 if no target can run the report, 1 if a target was not reached,
    then 3 for a problem, then 4 for anything not checked.

    ``unsupported`` counts the targets of a product the report is not written
    for. Where every target is one, nothing could run, which is exit 5. Where
    only some are, those targets are not checked, which is exit 4 at most.
    """
    if targets and unsupported == targets:
        return int(ExitCode.UNSUPPORTED_CAPABILITY)
    if unreachable:
        return int(ExitCode.FAILURE)
    states = {row.state for row in rows}
    if states & {REPORT_PROBLEM, ACCOUNT_MISSING}:
        return int(ExitCode.DRIFT)
    if NOT_CHECKED in states or unsupported:
        return int(ExitCode.PARTIAL)
    return int(ExitCode.SUCCESS)


# ---------------------------------------------------------------- the file ---


def _rules_on(config: Config, target: str) -> tuple[ReportAccountRule, ...]:
    return tuple(
        rule
        for rule in config.reports.accounts
        if target in {expanded.name for expanded in select(config, rule.targets)}
    )


def _application_profiles(config: Config, target: str) -> dict[str, str | None]:
    """Each application account on ``target``, with its policy's expected profile."""
    policies = {policy.name: policy for policy in config.policies}
    bound: dict[str, str | None] = {}
    for binding in config.bindings:
        if binding.target != target:
            continue
        policy = policies.get(binding.policy) if binding.policy is not None else None
        bound[binding.account.upper()] = policy.account.profile if policy is not None else None
    return bound


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
    db_profiles: Sequence[DbProfileRule],
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
    # A `db_profiles` entry for the account's profile states settings too, so it
    # takes part as one more source: a rule and the profile entry that disagree
    # are a conflict, never a silent precedence.
    profile_settings = next(
        (entry.settings for entry in db_profiles if entry.name.upper() == actual_profile.upper()),
        Settings(),
    )
    sources = [rule.settings for rule in matching] + [profile_settings]
    lifetimes = {s.password_lifetime for s in sources if s.password_lifetime is not None}
    limits = {s.failed_login_limit for s in sources if s.failed_login_limit is not None}
    profiles = {rule.profile.upper() for rule in matching if rule.profile is not None}
    conflicts = frozenset(
        check
        for check, values in (
            ("password_lifetime", lifetimes),
            ("failed_login_limit", limits),
            ("profile", set() if application else profiles),
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
    )


# ---------------------------------------------------------------- the checks ---


def _check(surveyed: SurveyedAccount, expectation: _Expectation) -> tuple[Finding, ...]:
    """The lock, and each thing the file expects. A setting nobody names is not a check.

    `01-configuration.md` §8a: a setting a rule does not name is not compared.
    So the checks that apply are the lock and whatever the file states. Where it
    states nothing at all, the account is in the `no rule` state (U8).
    """
    reasons = _reasons(surveyed)
    lock = _lock(surveyed, reasons.get("locked", _UNREAD))
    settings = expectation.settings
    if expectation.profile is None and settings.is_empty:
        return (
            lock,
            Finding("profile", NO_RULE_OUTCOME, "no rule states a profile or a setting"),
        )
    findings = [lock]
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


def _lock(surveyed: SurveyedAccount, reason: str) -> Finding:
    if surveyed.locked is None:
        return Finding("lock", NOT_CHECKED_OUTCOME, reason)
    if surveyed.locked:
        return Finding("lock", PROBLEM, f"locked: {surveyed.status}")
    return Finding("lock", OK, surveyed.status)


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


def _state(findings: Sequence[Finding]) -> str:
    outcomes = {finding.outcome for finding in findings}
    if PROBLEM in outcomes:
        return REPORT_PROBLEM
    if NOT_CHECKED_OUTCOME in outcomes:
        return NOT_CHECKED
    if NO_RULE_OUTCOME in outcomes:
        return NO_RULE
    return REPORT_OK


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
