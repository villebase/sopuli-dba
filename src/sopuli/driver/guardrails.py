"""Which accounts the tool refuses to touch (`02-oracle-privileges.md` §4).

These checks run in the tool, not in the database (ADR-001), and §4 is
unusually direct about what that costs: they **are not a security boundary**.
A compromised service credential bypasses them entirely. What they are instead
is protection against a typo, and against a config change with a wider blast
radius than intended — which is all they could be for an operator who already
holds SYSDBA.

Worth keeping, worth being honest about, and worth writing here rather than
inside the Oracle driver:

**The rule is product-neutral; the facts are the driver's.** "Refuse an account
the driver reports as vendor-maintained, or as holding administrative
privileges" is a sentence about credentials, not about Oracle. So this module
reads :class:`~sopuli.driver.protocol.UserState`, which each driver fills from
its own catalog: the Oracle driver from `DBA_USERS`, the PostgreSQL driver from
`pg_roles` and `pg_auth_members` (:mod:`sopuli.driver.postgres.roles`), and the
MySQL and MariaDB drivers from `mysql.user` and the grant tables. None of them
reimplements the reasoning.
Which roles count as administrative, and which names the product supplies, are
the driver's lists: it reports them as ``admin_roles`` and ``supplied_name``,
and this module holds no product's names.

**It reviews; it does not decide.** Like :mod:`sopuli.driver.oracle.errors`,
this returns a value. Whether a refusal stops the whole run or skips one unit
depends on something this layer cannot see — see :class:`Review` for the rule
the command layer applies.

### The checks, in §4's own numbering

1. **not declared in the config.** Invariant 5: the config is the whitelist, and
   selectors filter it rather than extend it.
2. **vendor-maintained** — Oracle's ``DBA_USERS.ORACLE_MAINTAINED = 'Y'``, which
   covers SYS, SYSTEM, DBSNMP, GSMADMIN_INTERNAL and the rest without a
   hand-maintained list going stale.
3. **in the password file** — ``V$PWFILE_USERS``. The one check that routinely
   has no input: §2 does not grant that view, so on a correctly installed estate
   this answers neither yes nor no — see below.
4. **holds an administrative role** — on Oracle ``DBA``, ``PDB_DBA``,
   ``CDB_DBA``, ``AUDIT_ADMIN`` (:data:`sopuli.driver.oracle.accounts.ADMIN_ROLES`).
5. **on a literal deny list**, for the version that has no answer to check 2
   (:data:`sopuli.driver.oracle.accounts.ORACLE_SUPPLIED`).
6. **a superuser**, an account every privilege check passes. Only a PostgreSQL
   driver reports one. Never waived, like check 1.
7. **the tool's own account**, the one this session is connected as. Changing
   it mid-run can lock the tool out of the targets still to come.
8. **reserved by the server**, which lets only a superuser change it: on
   PostgreSQL, a role in supautils' ``reserved_roles``. Never waived, like
   check 6 (#1111).
9. **holds a global privilege**, a privilege beyond the account's own data
   that the driver reports in ``global_privileges``: on MySQL and MariaDB, any
   privilege ``ON *.*`` but ``USAGE``, any on the ``mysql`` schema, and any
   ``PROXY`` grant, held or reached through a role. Never waived (#1222). On
   MySQL it runs only for a verb that sets a password, and not on the
   session's own account, which check 7 covers. On MariaDB it also runs for
   `creds finish-rollover`, `account suspend` and `account expire-password`,
   and for the last two on the session's own account too
   (:data:`GUARDED_TYPES`). `creds check` and `doctor` refuse nothing by it.

### Refused, permitted, or *could not establish*

The third answer exists because ``if state.password_file_member:`` would read
``None`` ("nobody looked") as "not a member", and check 3 would never fire.

Reading the view (:func:`sopuli.driver.oracle.accounts.password_file_member`)
does not settle it, because the view is deliberately outside §2's grant set: the
answer for most estates is *unknown*. Unknown is a :class:`Caveat`: reported at
warning level, refusing nothing, and pointing at the optional grant that would
settle it. "I looked and found nothing" and "I could not look" are answers a
safety report must never merge, which is what
:mod:`sopuli.driver.oracle.privileges` says one layer up about the same view.

### `--force` overrides 2 to 5 and 7, and never 1, 6, 8 or 9

Checks 6 and 8 are never waived because nothing could use the waiver: only a
superuser can change a superuser's password or a reserved role's, and a tool
account that is a superuser is refused when it connects. A waiver would only
move the refusal to the server, after the run had started.

Check 9 is never waived for the opposite reason: the server would allow it. A
MySQL tool account with ``CREATE USER`` can set the password of any account
that lacks ``SYSTEM_USER``, however much else it holds, so whoever runs the tool
could log in as that account. One mistaken config entry would be enough, and a
flag would be one more mistake (#1202, decision 7). The same reason limits it:
`account suspend` and `account expire-password` set no password, so they may
lock such an account, and the tool's own account hands over no power the tool
does not already have.

Check 7 is waived for the deliberate rotation of the tool's own password, which
is ordinary work (#1059).

This is decision P3 in ``docs/decisions/log.md``. `DBSNMP` is the case it exists
for: rotating its password is ordinary DBA work and it is `ORACLE_MAINTAINED`, so a
tool with no override does not prevent that rotation — it moves it to SQL\\*Plus,
where nothing records that it happened. An audited override is the better failure.

**It takes two deliberate acts, not one.** `--force` alone will not rotate
`DBSNMP`: check 1 still applies, so the account has to be declared in
`accounts:` as well. That is what keeps "unusual account, deliberately managed"
distinguishable from "typo that happened to be forced past", and it is why
:class:`Review` reports what was overridden rather than merely allowing it — the
override is an audit record, not a silence.

**`--force` is not a setting**, and that is structural rather than careful. It
never enters :mod:`sopuli.settings.registry`, so it has no merge policy and no
layer to win on, which is why it cannot relax `readonly`, `max_targets`,
`confirm_environments` or `dry_run` (invariant 10). Here it is an argument to a
function and nothing else.
"""

from __future__ import annotations

from collections.abc import Collection
from dataclasses import dataclass

from sopuli.config.targets import MARIADB
from sopuli.driver.protocol import UserState

#: §4 check 1. Never waived (:data:`NEVER_WAIVED`).
DECLARED = "declared"

#: §4 check 2 — the driver said this account belongs to the product.
VENDOR_MAINTAINED = "vendor_maintained"

#: §4 check 3.
PASSWORD_FILE = "password_file"

#: §4 check 4.
PRIVILEGED_ROLE = "privileged_role"

#: §4 check 5.
DENY_LIST = "deny_list"

#: Check 6. Never waived (:data:`NEVER_WAIVED`).
SUPERUSER = "superuser"

#: Check 7.
OWN_ACCOUNT = "own_account"

#: Check 8. Never waived (:data:`NEVER_WAIVED`).
RESERVED = "reserved"

#: Check 9. Never waived (:data:`NEVER_WAIVED`).
GLOBAL_PRIVILEGE = "global_privilege"

#: The checks no flag waives.
NEVER_WAIVED = frozenset({DECLARED, SUPERUSER, RESERVED, GLOBAL_PRIVILEGE})

#: The target types where check 9 refuses every verb, `account suspend` and
#: `account expire-password` too, and the session's own account for those two.
#: On MariaDB a `role:` rule admits the account that created the role, often
#: root or the tool account, and nothing else marks root as the database's own.
#: So an administrator is refused whatever the verb, even one declared by name
#: (#1272, option B).
GUARDED_TYPES = frozenset({MARIADB})


def every_verb(target_type: str | None) -> bool:
    """Whether check 9 refuses every verb on ``target_type``: the
    ``every_account`` that :func:`review` takes, for a verb that sets no
    password. ``None`` answers yes, the safe side: a caller that leaves the
    type out refuses more, never less. The verbs and `account list` both ask
    it, so the listing says what the verbs refuse."""
    return target_type is None or target_type in GUARDED_TYPES


#: The checks no flag waives that refuse a declared account: whatever is granted
#: to the tool, no run changes such an account. :func:`server_refusal` and
#: `creds apply`'s "run `creds generate` first" row both read it.
UNWAIVABLE = NEVER_WAIVED - {DECLARED}

#: §4's number for each check, for a message that names one. A test holds it to
#: every check :func:`review` can return.
NUMBERS = {
    DECLARED: 1,
    VENDOR_MAINTAINED: 2,
    PASSWORD_FILE: 3,
    PRIVILEGED_ROLE: 4,
    DENY_LIST: 5,
    SUPERUSER: 6,
    OWN_ACCOUNT: 7,
    RESERVED: 8,
    GLOBAL_PRIVILEGE: 9,
}


@dataclass(frozen=True)
class Refusal:
    """One reason not to touch this account.

    ``reason`` is written for the operator who has to decide what to do about
    it, so it says which check and what was observed. Nothing here is a secret:
    an account name, a role name, a flag.
    """

    check: str
    account: str
    reason: str

    @property
    def overridable(self) -> bool:
        """Whether `--force` can waive this one.

        Everything except checks 1, 6, 8 and 9. Acting on an account absent from
        the config would make the tool's own audit trail meaningless, so no flag
        reaches it (invariant 5). A superuser's password, and a reserved role's,
        are ones the tool cannot change, so waiving check 6 or 8 would only move
        the refusal to the server. An account with a global privilege is one the
        tool could change, and changing it hands its power to whoever runs the
        tool, so no flag reaches check 9 either.
        """
        return self.check not in NEVER_WAIVED


@dataclass(frozen=True)
class Caveat:
    """One check that could not be run, on an account nothing refused.

    A :class:`Review` carries three answers: refused, passed, and this one, *could
    not check*. It is a type rather than a ``None`` somewhere because "I looked and
    found nothing" and "I could not look" are answers a safety report must never
    merge -- :mod:`sopuli.driver.oracle.privileges` says so about ``SYSDBA`` in the
    privilege audit, and guardrail 3 would make exactly that merge one layer down. A
    check with no input reads as a pass, and a pass is what a guardrail is there not
    to give away by accident.

    **A caveat does not refuse**, and that is the decision rather than a
    consequence of where the field sits. Check 3's input is ``V$PWFILE_USERS``,
    which ``02-oracle-privileges.md`` §2 deliberately does not grant, so the
    correctly installed estate is the one that cannot answer -- refusing on it
    would mean the tool refusing every mutation everywhere. So it reports, at
    warning level, and the run goes on: the same shape `--preflight` already has
    for a privilege audit the service account may not read.

    Same three fields as :class:`Refusal`, and deliberately not the same type. A
    caller that wanted to know whether it may proceed must not be able to reach
    for a sequence that mixes the two and get the answer wrong by iterating the
    wrong one.
    """

    check: str
    account: str
    reason: str


@dataclass(frozen=True)
class Review:
    """What the guardrails found, and what `--force` did about it.

    ``overridden`` is the reason this is a pair rather than a boolean. §4
    requires the override to be recorded in the audit event and in the JSON
    output, so a waived refusal has to survive the waiving — a `--force` that
    merely returned "allowed" would leave the run document unable to say that
    somebody rotated `DBSNMP` on purpose.

    **The rule for what a caller does with ``refusals``**, decided here so that
    every mutating verb applies the same one:

    * an account the operator **named** — `--account DBSNMP` — refuses the run.
      They asked for something the tool will not do, and quietly skipping it
      would report success for work nobody did.
    * an account that merely **fell inside** a broad selection is `SKIPPED` with
      its reason, and the run does the rest of its job. Refusing 200 rotations
      because the 47th selected account turned out to be `ORACLE_MAINTAINED`
      would make a guardrail more disruptive than the mistake it caught.

    Which of the two happened is a fact about *selection*, which this layer
    cannot see — so the rule lives here and the command applies it.
    """

    account: str
    refusals: tuple[Refusal, ...] = ()
    overridden: tuple[Refusal, ...] = ()
    #: Checks that could not be run at all. Reported, never refusing --
    #: see :class:`Caveat`. Unaffected by ``force``, because there is nothing to
    #: waive: a check that produced no answer produced no refusal either, and a
    #: run that would have overridden the answer had it come still did not get
    #: one. Suppressing these under ``--force`` would hide the missing grant from
    #: the one operator most likely to be looking at what the guardrails did.
    caveats: tuple[Caveat, ...] = ()

    @property
    def permitted(self) -> bool:
        """Whether the tool may proceed against this account.

        Caveats are **not** consulted. A check that could not be run has refused
        nothing: an unestablished guardrail reports rather than blocks, because the
        alternative refuses every account on every estate
        installed exactly as §2 documents.
        """
        return not self.refusals


def is_declared(account: str, declared: Collection[str]) -> bool:
    """Whether ``account`` is in the config's declared set (§4 check 1).

    **Compared by ``upper()``**, because the two sides spell accounts differently
    and neither is wrong: `01-configuration.md` writes `acme_web_user` and Oracle
    stores `ACME_WEB_USER`, since an unquoted identifier is upper-cased on the
    way in. Comparing exactly would refuse every correctly-declared account on
    Oracle, which is a guardrail that fires only on its own users.

    ``upper()`` and not ``casefold()``, because ``upper()`` is how the drivers
    look a name up and how invariant 5 compares names. The two differ outside
    ASCII: ``'acme_ıt'.upper()`` is ``'ACME_IT'``, while its casefold keeps the
    dotless i (#1208).

    The residual risk is an estate holding both `ACME_WEB_USER` and a quoted
    `"acme_web_user"` as genuinely different accounts, where this would accept
    one on the strength of the other's declaration. That is worth naming and not
    worth solving: a binding addresses one account, and an estate spelling two
    accounts the same way has a problem this check would not be the first to hit.
    """
    return account.upper() in {name.upper() for name in declared}


def server_reserved(state: UserState) -> bool:
    """Whether a check no flag waives refuses the account whatever is granted:
    check 6 (a superuser), check 8 (a role the server reserves) and check 9 (a
    global privilege) today.

    No grant to the tool account changes any of these answers. For checks 6 and
    8 the server is what refuses the change; for check 9 the tool refuses it,
    whatever the server would allow. So the pre-flight asks for no grant on such
    an account (#1117), because the guardrails skip the account anyway.

    Read from :func:`review` and :data:`NEVER_WAIVED`, not restated, so a later
    check of the same kind is included without an edit here. Check 1 is left
    out: an undeclared account never reaches the survey, so the account is
    reviewed as declared.
    """
    return server_refusal(state) is not None


def server_refusal(state: UserState) -> Refusal | None:
    """The first refusal :func:`server_reserved` is true for, with its reason, or
    ``None``. `creds generate` reports it on the account it skips (#1174)."""
    found = review(state, declared=(state.name,)).refusals
    return next((refusal for refusal in found if refusal.check in UNWAIVABLE), None)


#: How many of an account's global privileges check 9's reason names before it
#: counts the rest. ``ALL PRIVILEGES ON *.*`` is about 90 of them on MySQL, and
#: the reason is printed on every row and target that refuses the account.
NAMED_PRIVILEGES = 5


def review(
    state: UserState,
    *,
    declared: Collection[str],
    force: bool = False,
    sets_password: bool = True,
    every_account: bool = False,
) -> Review:
    """Every §4 check, against one account.

    ``state.name`` is the spelling the **database** gave back, which is what the
    checks run on: config says which accounts may be touched, and the database
    says what they are.

    ``force`` waives checks 2 to 5 and 7 and never 1, 6, 8 or 9, and what it waives
    is reported in :attr:`Review.overridden` rather than dropped.

    ``sets_password`` says whether the verb sets a password. `account suspend`
    and `account expire-password` pass ``False``, and check 9 does not run for
    them: its reason is that the tool could log in with a password it set, and
    locking an account or expiring its password takes power away instead
    (#1222). It defaults to ``True``, the safe side: a new verb that forgets
    it refuses more, never less.

    ``every_account`` runs check 9 whatever the verb, and on the session's own
    account too. The session account's exemption is for a password the tool
    sets, which hands over nothing; locking it hands over nothing either, but
    takes the account away. On MariaDB `account suspend` and `account
    expire-password` pass it, because a `role:` rule there admits the role's
    creator, root or the tool account (:func:`every_verb`,
    #1272).

    **A check with no input is neither**, and that is the third answer:
    it lands in :attr:`Review.caveats`, refuses nothing, and survives ``force``
    untouched. Check 3 is the only one that can produce one today.
    """
    found: list[Refusal] = []
    caveats: list[Caveat] = []
    name = state.name

    if not is_declared(name, declared):
        found.append(
            Refusal(
                DECLARED,
                name,
                "the config does not declare this account, and no flag extends the whitelist",
            )
        )

    if state.vendor_maintained:
        found.append(
            Refusal(VENDOR_MAINTAINED, name, "the database reports this account as its own")
        )
    elif state.vendor_maintained is None and state.supplied_name:
        # Check 5 runs only where check 2 had nothing to say. On a version that
        # answers, the answer wins -- a list maintained by us must not overrule
        # the database describing itself.
        found.append(
            Refusal(
                DENY_LIST,
                name,
                "this version cannot say whether the account is vendor-maintained, "
                "and the name is one the product supplies",
            )
        )

    if state.password_file_member:
        found.append(Refusal(PASSWORD_FILE, name, "the account is in the password file"))
    elif state.password_file_member is None:
        # The third answer, and the ordinary one. `V$PWFILE_USERS` is not
        # in §2's grant set, so a correctly installed service account gets here
        # -- which is why this is a caveat and not a refusal. What it must not
        # be is silence: an unread check reads as a pass.
        caveats.append(
            Caveat(
                PASSWORD_FILE,
                name,
                "could not establish whether the account is in the password file",
            )
        )

    held = sorted(state.admin_roles)
    if held:
        found.append(Refusal(PRIVILEGED_ROLE, name, f"the account holds {', '.join(held)}"))

    if state.superuser:
        found.append(Refusal(SUPERUSER, name, "the account is a superuser"))

    if state.session_account:
        found.append(
            Refusal(
                OWN_ACCOUNT,
                name,
                "this is the account the tool is connected as; changing it can lock the "
                "tool out of the targets it has not reached yet",
            )
        )

    if state.reserved_by:
        found.append(
            Refusal(
                RESERVED,
                name,
                f"the server reserves this account in {state.reserved_by}, and only a "
                "superuser may change it",
            )
        )

    # The session's own account is exempt when the verb sets a password: the
    # tool already has its power, so setting its password hands over nothing.
    # Check 7 still refuses it unless `--force` waives that (#1059, #1222).
    # `every_account` ends the exemption, for MariaDB's suspend and expire
    # (#1272).
    privileges = sorted(state.global_privileges)
    if privileges and (every_account or (sets_password and not state.session_account)):
        named = ", ".join(privileges[:NAMED_PRIVILEGES])
        rest = len(privileges) - NAMED_PRIVILEGES
        if rest > 0:
            # Grants, not privileges: one privilege held directly and through
            # a role is two entries.
            named += f" and {rest} more grant{'s' if rest > 1 else ''}"
        found.append(Refusal(GLOBAL_PRIVILEGE, name, f"the account holds {named}"))

    if not force:
        return Review(account=name, refusals=tuple(found), caveats=tuple(caveats))

    return Review(
        account=name,
        refusals=tuple(refusal for refusal in found if not refusal.overridable),
        overridden=tuple(refusal for refusal in found if refusal.overridable),
        # Carried through the waiver unchanged. `--force` waives an answer, and a
        # caveat is the absence of one -- see :attr:`Review.caveats`.
        caveats=tuple(caveats),
    )
