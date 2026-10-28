"""Whether the database audits the DBA's routes to acting as one person.

An unseen reset records the answer (UC-2 §1, H10). `02-oracle-privileges.md` §5
is the specification, and `sql/oracle/13_audit_coverage_probe.sql` measured it on
26ai 23.26.2.0.0. Two facts from that probe shape everything here:

- **A ``BY`` or ``EXCEPT`` list applies to the account that issues the
  statement.** The person issues the logon, so ``LOGON`` is checked against the
  person. A DBA issues the ``ALTER USER``, and the tool cannot know which DBA, so
  ``ALTER USER`` counts only from a policy enabled for every user.
- **A common policy enabled in the root records nothing of local accounts**, and
  looks like an every-user policy from the PDB. It does record a common
  account's logon, in the root and in the PDB (AC6's control, AC9). So a common
  policy counts for ``LOGON`` only where the person is a common account and the
  policy is enabled ``BY`` them, the one shape AC9a measured for a proxy logon.
  It never counts for ``ALTER USER``, whose DBA may be local.

Each enabled policy is sorted, for each of the two actions, into *covers*,
*might cover* or *does not cover*. One policy that covers an action settles it.
A policy that might cover matters only for an action that nothing covers, and
then the answer is unknown. A reading the tool cannot finish never becomes
``False``.

Nothing here imports ``oracledb``: the SQL and the decision are pure, so tier 0
tests them, and :func:`coverage_of` takes any cursor.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from sopuli.driver.oracle.accounts import COMMON_QUERY
from sopuli.driver.oracle.capabilities import UNREADABLE_CODES, Cursor
from sopuli.driver.oracle.errors import from_error
from sopuli.driver.oracle.privileges import is_yes
from sopuli.driver.protocol import AuditCoverage

#: The two actions a DBA's routes use (UC-2 §1): an ``ALTER USER``, to reset the
#: password to a known value or to grant ``CONNECT THROUGH``, and a logon as the
#: person.
ALTER_USER = "ALTER USER"
LOGON = "LOGON"
ACTIONS = (LOGON, ALTER_USER)

#: The system privilege a logon uses.
CREATE_SESSION = "CREATE SESSION"

#: ``AUDIT_OPTION_TYPE`` values the probe has seen. A row of another type might
#: record one of the two actions, and nobody has measured it.
STANDARD_ACTION = "STANDARD ACTION"
SYSTEM_PRIVILEGE = "SYSTEM PRIVILEGE"
OBJECT_ACTION = "OBJECT ACTION"
XS_ACTION = "XS ACTION"
KNOWN_TYPES = frozenset({STANDARD_ACTION, SYSTEM_PRIVILEGE, OBJECT_ACTION, XS_ACTION})

#: ``ENABLED_OPTION`` values, and the ``ENTITY_NAME`` of a policy enabled for
#: every user.
BY_USER = "BY USER"
EXCEPT_USER = "EXCEPT USER"
BY_ROLE = "BY GRANTED ROLE"
ALL_USERS = "ALL USERS"

#: The ``ENABLED_OPTION`` values the probe has seen. A policy enabled another way
#: might cover either action, and nobody has measured how.
ENABLED_OPTIONS = frozenset({BY_USER, EXCEPT_USER, BY_ROLE})

#: The audit mode. ``TRUE`` is unified auditing only, ``FALSE`` is mixed mode, and
#: no row at all is a release with no unified auditing (11.2).
MODE_QUERY = "select value from v$option where parameter = 'Unified Auditing'"

# Whether the person is a common account is ``accounts.COMMON_QUERY``, shared
# with the lockout guard. ``COMMON`` came with multitenant, in 12.1, as did
# unified auditing, so a database that answers MODE_QUERY has the column.
# ``_is_common`` reads it its own way: a failed read is ``False`` here, the safe
# reading for coverage.

#: One row per way an enabled policy is enabled.
ENABLED_QUERY = (
    "select policy_name, enabled_option, entity_name, success from audit_unified_enabled_policies"
)

#: The audit options of the enabled policies only. The view holds thousands of
#: rows for the policies Oracle ships, and almost none of them are enabled.
OPTIONS_QUERY = (
    "select policy_name, audit_option, audit_option_type, audit_condition, common "
    "from audit_unified_policies "
    "where policy_name in (select policy_name from audit_unified_enabled_policies)"
)

#: What a failed read of the two policy views is called in a detail.
POLICY_VIEWS = "the audit policy views"

#: What an operator can do when the policy views cannot be read.
UNREADABLE = (
    "the audit policy views are not readable; GRANT READ ON "
    "SYS.AUDIT_UNIFIED_ENABLED_POLICIES and SYS.AUDIT_UNIFIED_POLICIES to the "
    "service account (02-oracle-privileges.md section 2)"
)
NO_UNIFIED = "this database has no unified auditing, and traditional auditing is not read"

#: ``ORA-00904``, invalid identifier: the policy views here lack a column the
#: check reads. Checked before :data:`UNREADABLE_CODES`, because no grant fixes it.
NO_COLUMN = "ORA-00904"
OTHER_COLUMNS = (
    "the audit policy views on this database do not have the columns the check "
    "reads; the columns were measured on 23.26.2.0.0, 21.3.0.0.0 and 18.4.0.0.0 "
    "only, so this release is not measured"
)
MIXED = (
    "the database is in mixed audit mode, and traditional auditing, which is "
    "not read, might record it"
)

#: ``AUDIT_TRAIL``, read in mixed mode only. Under ``NONE`` the enabled unified
#: policies recorded nothing on 21.3.0.0.0 and 18.4.0.0.0
#: (``15_mixed_mode_trail_probe.sql``), so a policy that covers an action does
#: not make the answer ``True`` there (#1004). In pure unified mode the parameter
#: does not apply, and it is not read.
TRAIL_QUERY = "select value from v$parameter where name = 'audit_trail'"
TRAIL_NONE = (
    "the database is in mixed audit mode with AUDIT_TRAIL = NONE, where enabled "
    "unified policies were measured to record nothing on 21.3.0.0.0 and 18.4.0.0.0, "
    "and other releases are not measured"
)
#: The settings under which enabled unified policies were measured to record, in
#: mixed mode, on 21.3.0.0.0 and 18.4.0.0.0 (``15_mixed_mode_trail_probe.sql``).
#: Any other value is unknown, not ``True`` (#1013).
TRAIL_MEASURED = frozenset({"DB", "DB, EXTENDED", "OS", "XML", "XML, EXTENDED"})
TRAIL_UNMEASURED = (
    "the database is in mixed audit mode with AUDIT_TRAIL = {value}, a setting "
    "under which enabled unified policies were not measured"
)
#: Why ``AUDIT_TRAIL`` was not read. A missing grant names it; any other failure
#: keeps the server's code and names no grant, which would not fix it.
TRAIL_UNREADABLE = (
    "the database is in mixed audit mode, and AUDIT_TRAIL is not readable ({error}); "
    "GRANT SELECT ON SYS.V_$PARAMETER to the service account "
    "(02-oracle-privileges.md section 2)"
)
TRAIL_FAILED = "the database is in mixed audit mode, and reading AUDIT_TRAIL failed ({error})"


@dataclass(frozen=True)
class Enablement:
    """One row of ``AUDIT_UNIFIED_ENABLED_POLICIES``."""

    policy: str
    option: str
    entity: str
    success: bool


@dataclass(frozen=True)
class Option:
    """One row of ``AUDIT_UNIFIED_POLICIES``, for an enabled policy."""

    policy: str
    option: str
    type: str
    condition: str | None
    common: bool


COVERS = "covers"
MIGHT = "might cover"
DOES_NOT = "does not cover"


def verdict(
    action: str,
    account: str,
    enablements: Sequence[Enablement],
    options: Sequence[Option],
    *,
    common: bool = False,
    unread: str | None = None,
) -> tuple[str, str | None]:
    """Whether one policy covers ``action`` for ``account``, and why it might.

    ``enablements`` and ``options`` are one policy's rows, all of them: a policy
    enabled for a list has one row per user, and the list is read as a whole.
    ``common`` is whether ``account`` is a common account, and ``unread`` the
    server's error where that could not be read. Returns the group and, for
    :data:`MIGHT`, the reason.
    """
    names = [one for one in options if _names(one, action)]
    unmeasured = [one for one in options if _unmeasured(one, action)]
    if not names and not unmeasured:
        return DOES_NOT, None
    recorded = [one for one in enablements if one.success]
    if not recorded:
        return DOES_NOT, None

    policy = recorded[0].policy
    strange = sorted({one.option for one in recorded if one.option not in ENABLED_OPTIONS})
    if strange:
        return MIGHT, f"{policy} is enabled as {', '.join(strange)}, which nobody has measured"

    every = any(one.option == BY_USER and one.entity == ALL_USERS for one in recorded)
    listed = {one.entity for one in recorded if one.option == BY_USER and one.entity != ALL_USERS}
    excepted = {one.entity for one in recorded if one.option == EXCEPT_USER}
    roles = {one.entity for one in recorded if one.option == BY_ROLE}
    # Who the policy applies to comes first: a policy that records nothing of the
    # person's own statements cannot record their logon, whatever its rows say.
    reaches = every or account in listed or bool(excepted and account not in excepted)
    if action == LOGON and not reaches and not roles:
        return DOES_NOT, None

    if not names:
        kinds = sorted({f"{one.type} {one.option}" for one in unmeasured})
        return MIGHT, f"{policy} has {', '.join(kinds)}, which nobody has measured"
    if any(one.common for one in names):
        # The person issues the logon, so a common person's logon is recorded
        # (AC9). A DBA issues the ALTER USER, and that DBA may be local.
        if action == ALTER_USER:
            return MIGHT, (
                f"{policy} is a common policy, which records nothing of a local DBA's {action}"
            )
        if unread is not None:
            return MIGHT, (
                f"{policy} is a common policy, and whether {account} is a common account "
                f"could not be read: {unread}"
            )
        if not common:
            return MIGHT, f"{policy} is a common policy, which records nothing of local accounts"
        # AC9a measured a common policy enabled BY the person. For every user,
        # EXCEPT a list or for a role, nobody has measured the proxy logon.
        if account not in listed:
            return MIGHT, (
                f"{policy} is a common policy not enabled BY the person, and only that "
                f"shape is measured to record a common person's logon"
            )
    if any(one.condition for one in names):
        return MIGHT, f"{policy} has a condition, which is not evaluated"

    if action == LOGON:
        if reaches:
            return COVERS, None
    elif every:
        return COVERS, None
    elif listed or excepted:
        return MIGHT, f"{policy} records {action} only for a list of users"
    if roles:
        return MIGHT, f"{policy} is enabled for a role, whose holders are not read"
    return DOES_NOT, None


def classify(
    mode: str | None,
    enablements: Sequence[Enablement],
    options: Sequence[Option],
    account: str,
    *,
    common: bool = False,
    unread: str | None = None,
    trail: str | None = None,
    trail_unread: str | None = None,
) -> AuditCoverage:
    """The answer for ``account``, from what the reads returned.

    ``mode`` is ``V$OPTION``'s value for ``Unified Auditing``, or ``None`` where it
    has no such row. ``common`` is ``DBA_USERS.COMMON`` for ``account``, and
    ``unread`` the server's error where that read failed. ``trail`` is
    ``AUDIT_TRAIL``, which matters in mixed mode only. There one of ``trail`` and
    ``trail_unread`` is given: ``trail_unread`` says, for the detail, why the
    parameter was not read, and a ``True`` then becomes unknown, because the tool
    cannot rule out ``NONE``. A setting outside :data:`TRAIL_MEASURED` makes a
    ``True`` unknown too, and the detail names it.

    Raises ``ValueError`` in mixed mode when neither is given: a caller that
    forgot the parameter would otherwise turn every ``True`` into unknown quietly.
    """
    mixed = is_mixed(mode)
    if mixed and trail is None and trail_unread is None:
        raise ValueError("mixed audit mode needs AUDIT_TRAIL, or why it was not read")
    setting = _setting(trail) if mixed and trail is not None else None
    none = setting == "NONE"
    # Where the parameter was not read, or holds a setting not measured, the
    # reason goes into every mixed-mode detail, as for a doubt about a policy.
    trail_doubt = trail_unread if mixed and trail is None else None
    if setting is not None and not none and setting not in TRAIL_MEASURED:
        trail_doubt = TRAIL_UNMEASURED.format(value=setting)
    covered: dict[str, list[str]] = {action: [] for action in ACTIONS}
    doubts: dict[str, list[str]] = {action: [] for action in ACTIONS}
    for policy in sorted({one.policy for one in enablements}):
        rows = [one for one in enablements if one.policy == policy]
        names = [one for one in options if one.policy == policy]
        for action in ACTIONS:
            group, reason = verdict(action, account, rows, names, common=common, unread=unread)
            if group == COVERS:
                covered[action].append(policy)
            elif group == MIGHT and reason is not None:
                doubts[action].append(reason)

    if all(covered[action] for action in ACTIONS):
        detail = "; ".join(f"{action} by {', '.join(covered[action])}" for action in ACTIONS)
        if none:
            return AuditCoverage(audited=None, detail=f"{detail}, but {TRAIL_NONE}")
        if trail_doubt is not None:
            return AuditCoverage(audited=None, detail=f"{detail}, but {trail_doubt}")
        return AuditCoverage(audited=True, detail=detail)

    # **An action that nothing covers or might cover decides the answer**, whatever
    # the other action's doubts: the route through it is certainly unrecorded,
    # which is `false` on a database that uses unified auditing only (§5).
    certain = [action for action in ACTIONS if not covered[action] and not doubts[action]]
    if certain:
        nothing = f"no enabled policy records {' or '.join(certain)} for {account}"
        if mode is None:
            return AuditCoverage(audited=None, detail=f"{nothing}, and {NO_UNIFIED}")
        if none:
            # Not `false`: what was measured on two releases is not assumed of
            # the rest (#1004). TRAIL_NONE says so.
            return AuditCoverage(audited=None, detail=f"{nothing}, and {TRAIL_NONE}")
        if trail_doubt is not None:
            return AuditCoverage(audited=None, detail=f"{nothing}, but {MIXED}; {trail_doubt}")
        if mixed:
            return AuditCoverage(audited=None, detail=f"{nothing}, but {MIXED}")
        return AuditCoverage(audited=False, detail=nothing)

    # Unknown: every uncovered action has a doubt. The detail keeps what is known,
    # the actions that are covered, beside the doubts, each said once.
    parts = []
    for action in ACTIONS:
        if covered[action]:
            parts.append(f"{action} by {', '.join(covered[action])}")
        else:
            reasons = "; ".join(dict.fromkeys(doubts[action]))
            parts.append(f"{action} might be recorded: {reasons}")
    if none:
        parts.append(TRAIL_NONE)
    elif trail_doubt is not None:
        parts.append(trail_doubt)
    return AuditCoverage(audited=None, detail="; ".join(parts))


def is_mixed(mode: str | None) -> bool:
    """Whether ``V$OPTION``'s ``Unified Auditing`` value is mixed mode.

    ``None`` is a release with no unified auditing, which is neither. The one rule
    :func:`coverage_of` and :func:`classify` both use.
    """
    return mode is not None and mode.strip().upper() != "TRUE"


def coverage_of(cursor: Cursor, account: str) -> AuditCoverage:
    """Read the audit mode and the enabled policies, and classify them.

    **Never raises.** An unreadable view is ``audited=None`` naming the grant, and
    any other failure is ``audited=None`` with the server's code and message:
    a reset records this and acts on nothing, so it must not stop one.
    """
    reading = "V$OPTION"
    try:
        cursor.execute(MODE_QUERY)
        row = cursor.fetchone()
        mode = str(row[0]) if row and row[0] else None
        if mode is None:
            return AuditCoverage(audited=None, detail=NO_UNIFIED)
        trail, trail_unread = _audit_trail(cursor) if is_mixed(mode) else (None, None)
        reading = POLICY_VIEWS
        cursor.execute(ENABLED_QUERY)
        enabled = [
            Enablement(
                policy=str(policy),
                option=str(option),
                entity=str(entity),
                success=is_yes(success),
            )
            for policy, option, entity, success in cursor.fetchall()
        ]
        cursor.execute(OPTIONS_QUERY)
        options = [
            Option(
                policy=str(policy),
                option=str(option),
                type=str(kind),
                condition=None if not condition or condition == "NONE" else str(condition),
                common=is_yes(common),
            )
            for policy, option, kind, condition, common in cursor.fetchall()
        ]
        # Asked only where it can change the answer: a person's commonness
        # matters for a common policy and for nothing else.
        person_common, unread = (
            _is_common(cursor, account) if any(one.common for one in options) else (False, None)
        )
        return classify(
            mode,
            enabled,
            options,
            account,
            common=person_common,
            unread=unread,
            trail=trail,
            trail_unread=trail_unread,
        )
    except Exception as error:  # noqa: BLE001 -- mapped on the next line, code kept
        diagnosis = from_error(error)
        if reading == POLICY_VIEWS and diagnosis.code == NO_COLUMN:
            return AuditCoverage(audited=None, detail=f"{OTHER_COLUMNS}: {diagnosis.first_line}")
        if reading == POLICY_VIEWS and diagnosis.code in UNREADABLE_CODES:
            return AuditCoverage(audited=None, detail=UNREADABLE)
        return AuditCoverage(
            audited=None, detail=f"reading {reading} failed: {diagnosis.first_line}"
        )


def _is_common(cursor: Cursor, account: str) -> tuple[bool, str | None]:
    """Whether ``account`` is a common account, and the server's error if that read failed.

    A failed read is ``False``, the safe reading: it can only turn a common
    policy's *covers* into *might cover*. The error is kept, with its code, so
    the detail can say why the person was not counted as common.
    """
    try:
        cursor.execute(COMMON_QUERY, {"name": account})
        row = cursor.fetchone()
    except Exception as error:  # noqa: BLE001 -- mapped on the next line, code kept
        return False, from_error(error).first_line
    return bool(row) and is_yes(row[0]), None


def _setting(trail: str) -> str:
    """``AUDIT_TRAIL`` in one spelling: upper case, with ``", "`` between parts.

    ``V$PARAMETER`` prints ``DB, EXTENDED``. The spelling is fixed here, so that a
    space more or less does not turn a measured setting into an unmeasured one.
    """
    return ", ".join(part.strip() for part in trail.upper().split(","))


def _audit_trail(cursor: Cursor) -> tuple[str | None, str | None]:
    """``AUDIT_TRAIL``'s value, or why it was not read, said for the detail.

    The default install grants no read of ``V$PARAMETER``, so this fails with
    ``ORA-00942`` unless §2's optional grant was taken (measured on 21.3.0.0.0 and
    18.4.0.0.0). Only a code in :data:`UNREADABLE_CODES` names the grant. The
    server's message is kept, by its first line.
    """
    try:
        cursor.execute(TRAIL_QUERY)
        row = cursor.fetchone()
    except Exception as error:  # noqa: BLE001 -- mapped on the next line, code kept
        diagnosis = from_error(error)
        reason = TRAIL_UNREADABLE if diagnosis.code in UNREADABLE_CODES else TRAIL_FAILED
        return None, reason.format(error=diagnosis.first_line)
    if not row:
        return None, TRAIL_FAILED.format(error="no row")
    if row[0] is None:
        return None, TRAIL_FAILED.format(error="the value is NULL")
    return str(row[0]), None


def _names(option: Option, action: str) -> bool:
    """Whether a row records ``action``, by a shape the probe measured."""
    if option.type == STANDARD_ACTION:
        return option.option in (action, "ALL")
    return action == ALTER_USER and option.type == SYSTEM_PRIVILEGE and option.option == ALTER_USER


def _unmeasured(option: Option, action: str) -> bool:
    """Whether a row might record ``action``, by a kind nobody has measured.

    A ``SYSTEM PRIVILEGE`` row records the statements that use the privilege. A
    logon uses ``CREATE SESSION``, so that row might record ``LOGON``. The
    ``ALTER USER`` privilege is measured and is in :func:`_names`, and no other
    privilege is used by either route. A ``ROLE PRIVILEGE`` row, and a type the
    probe has not seen, might record either.
    """
    if option.type == SYSTEM_PRIVILEGE:
        return action == LOGON and option.option == CREATE_SESSION
    return option.type not in KNOWN_TYPES
