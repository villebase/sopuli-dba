"""Reading an account's state from the dictionary.

`DBA_USERS`, `DBA_PROFILES`, `DBA_ROLE_PRIVS` and -- opportunistically --
`V$PWFILE_USERS`: all reads, no `SYS.USER$`, which is an optional grant (decision P2) and
which nothing here touches. Three consumers want this object: UC-1 §5's pre-flight
step 3, the client-side guardrails, and `creds status`'s inventory.

The last of the four is the one that is **expected to fail on a correct install**.
`V$PWFILE_USERS` is not in §2's grant set by design, so
:func:`password_file_member` answers `None` where nobody could look --
and the guardrail turns that into a caveat rather than into a pass.

These things were measured on 26ai Free 23.26.2.0.0 rather than reasoned
about, and reasoning would have got each of them wrong.

**Rollover state is in ``ACCOUNT_STATUS``, and nowhere else.** No column in any
`DBA_*` view mentions rollover — the dictionary was searched, not assumed. What
the status does instead is compound, joined with ``&``:

    OPEN                              EXPIRED & IN ROLLOVER
    OPEN & IN ROLLOVER                EXPIRED & LOCKED & IN ROLLOVER
    LOCKED & IN ROLLOVER              LOCKED(TIMED)

So the three flags are read as **tokens within** the status rather than by
comparing it to a value. A rotation opens the window and the status says so
immediately; equality against ``"OPEN"`` would have reported a healthy account as
neither open nor anything else.

**An unset profile resource reads as the string ``DEFAULT``**, meaning *inherit
from the ``DEFAULT`` profile*, not *this is the default value*. A profile created
with one limit set reports ``DEFAULT`` for the other eight, so a caller reading
``FAILED_LOGIN_ATTEMPTS`` off a custom profile gets a word where it wanted a
number. :data:`PROFILE_QUERY` resolves it in the database, and what reaches
:class:`~sopuli.driver.protocol.UserState` is always the **effective** limit.

**``PASSWORD_VERIFY_FUNCTION`` reads as ``FROM ROOT`` inside a PDB**, and the
numeric limits do not. Whether the other resources behave like the verify
function decides whether :mod:`sopuli.driver.oracle.rollover` can trust the dictionary at all.
Measured on a common profile with `CONTAINER=ALL`, read from `CDB$ROOT` and from `FREEPDB1`:

    resource                    root                             pdb
    FAILED_LOGIN_ATTEMPTS       4                                4
    PASSWORD_ROLLOVER_TIME      1                                1
    PASSWORD_VERIFY_FUNCTION    ORA12C_STRONG_VERIFY_FUNCTION    FROM ROOT

So the limits this module reads are trustworthy from a PDB and the verify
function is not. :func:`password_constraints` reads it, and reports the
not-knowing rather than an absence.

**``FROM ROOT`` is narrower than that reading suggests.** Three profiles read
from inside ``FREEPDB1``:

    profile             created                      PASSWORD_VERIFY_FUNCTION
    ACME_COMMON_PROF    in the root, CONTAINER=ALL   FROM ROOT
    ACME_LOCAL_PROF     in the PDB                   ORA12C_STRONG_VERIFY_FUNCTION
    DEFAULT             Oracle's own                 NULL

So the unreadable case is a **user-created common profile seen from a PDB**, and
not "a PDB" -- a local profile answers with its function's name, and even
``DEFAULT``, which is common, answers ``NULL`` rather than deferring. An
implementation that treated every PDB as unknowable would refuse to report the
ordinary case, and one that treated the reading as absent would tell an operator
that nothing will judge their password when something will.

Two values that a caller must not mistake for data came out of the same run:
``PASSWORD_VERIFY_FUNCTION`` is the string ``NULL`` where a profile names none
(:data:`NO_FUNCTION`), and ``PASSWORD_REUSE_MAX``/``PASSWORD_REUSE_TIME`` are
``UNLIMITED`` on the ``DEFAULT`` profile -- vendor words in a column a reader
expects numbers in, resolved through :data:`PROFILE_QUERY`'s ``DEFAULT`` join
like every other resource.

**``PASSWORD_CHANGE_DATE`` does track a rotation** on this release — two
rotations two minutes apart moved it. On 18c and 11.2 the column does not exist,
and on 19c it does (19.24.0.0.0) — though the server's ``ORA-00904`` is what
decides, not a version. Decision #386: the value comes from ``SYS.USER$.PTIME``
there, behind the optional grant, rather than going missing. That is a second
source for one field, and it is admitted only because it is **the same clock**
rather than an estimate of it — measured on 23.26.2.0.0, 21.3.0.0.0, 18.4.0.0.0
and 11.2.0.2.0 (``docs/measurements.md``): ``PTIME`` equals
``PASSWORD_CHANGE_DATE`` to the second where both exist, moves on ``ALTER USER
... IDENTIFIED BY`` where only it exists, and ``CTIME`` beside it does not move.
See :data:`PTIME_QUERY` for the rules that keep the two from disagreeing, and
:func:`_password_changed` for what is reported when neither answers. 12.2.0.1.0
takes the fallback, and ``PTIME`` moved with a rotation there; 12.1 would
take it too and is unmeasured (unverified: pw-changed-source).

**``EXPIRED(GRACE)`` is a value of ``ACCOUNT_STATUS``, and it contains the token
``EXPIRED``.** The grace state compounds like the rest, and the hard expiry was measured
alongside it as a control — it is the fourth value below:

    EXPIRED(GRACE)                    EXPIRED(GRACE) & LOCKED
    EXPIRED(GRACE) & LOCKED(TIMED)    EXPIRED

So a token reading alone would make :attr:`~sopuli.driver.protocol.UserState.expired`
``True`` for an account whose password still works. :func:`login_state`
therefore excludes ``EXPIRED(GRACE)`` from ``expired`` and reports it as
``in_grace``. That is safe: every locked form carries ``LOCKED`` and therefore
parses ``locked=True``, and every caller tests ``locked`` before ``expired``.
Excluding ``(GRACE)`` from ``expired`` cannot make a locked account read as open.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
from datetime import datetime
from typing import Any

from sopuli.constraints import AccountConstraints
from sopuli.driver.oracle.capabilities import read
from sopuli.driver.oracle.errors import INSTALL_SCRIPT, from_error
from sopuli.driver.oracle.privileges import is_yes
from sopuli.driver.oracle.rollover import days, is_enabled, window_end
from sopuli.driver.oracle.statements import COMMON_PREFIX
from sopuli.driver.protocol import Cursor, DriverError, UserState
from sopuli.driver.survey import Limit, SurveyedAccount

#: The roles guardrail 4 refuses (`02-oracle-privileges.md` §4), reported as
#: :attr:`UserState.admin_roles`. Upper-cased, because that is how a database
#: spells a role and how :attr:`UserState.roles` carries one.
ADMIN_ROLES = frozenset({"DBA", "PDB_DBA", "CDB_DBA", "AUDIT_ADMIN"})

#: :data:`ADMIN_ROLES` for a sentence, so a hint cannot name another list.
_ADMIN_ROLES_IN_WORDS = ", ".join(sorted(ADMIN_ROLES)[:-1]) + f" or {sorted(ADMIN_ROLES)[-1]}"

#: Guardrail 5's list, reported as :attr:`UserState.supplied_name` and consulted
#: **only where check 2 could not answer** — that is, where
#: :attr:`UserState.vendor_maintained` is ``None`` because the column does not
#: exist, which on Oracle means 11.2.
#:
#: Three things about it, because a list like this invites the wrong
#: expectations:
#:
#: * **It is necessarily incomplete.** An Oracle install has dozens of supplied
#:   accounts and they vary by installed option. This is the set that is
#:   common to essentially every 11.2, not an inventory.
#: * **Incompleteness is survivable and over-inclusion is cheap**, which is why
#:   it errs long. A missing entry means a maintained account is not caught by
#:   *this* check on one old version; a spurious entry means a refusal an
#:   operator clears with `--force`, audited. Those costs are not symmetrical.
#: * **It is a constant rather than a data file.** It is Oracle's list, not the
#:   site's, so nothing about it is configurable — and a file would need a
#:   schema, a loader and an error path for a fixed set of strings.
#:
#: Verifying it against the 11g XE image is a tier-2 test nobody has written
#: (`04-testing.md` §2); until then it is reasoning, and it is labelled as such.
ORACLE_SUPPLIED = frozenset(
    {
        "ANONYMOUS",
        "APPQOSSYS",
        "BI",
        "CTXSYS",
        "DBSNMP",
        "DIP",
        "EXFSYS",
        "FLOWS_FILES",
        "HR",
        "IX",
        "LBACSYS",
        "MDDATA",
        "MDSYS",
        "OE",
        "OLAPSYS",
        "ORACLE_OCM",
        "ORDDATA",
        "ORDPLUGINS",
        "ORDSYS",
        "OUTLN",
        "OWBSYS",
        "PM",
        "SCOTT",
        "SH",
        "SI_INFORMTN_SCHEMA",
        "SPATIAL_CSW_ADMIN_USR",
        "SPATIAL_WFS_ADMIN_USR",
        "SYS",
        "SYSMAN",
        "SYSTEM",
        "TSMSYS",
        "WMSYS",
        "XDB",
        "XS$NULL",
    }
)

#: The account, as the database spells it. ``PASSWORD_CHANGE_DATE`` is selected
#: unconditionally: it exists on 21c and 26ai, and on 18c and 11.2 the query fails with
#: ``ORA-00904`` — which :func:`~sopuli.driver.oracle.capabilities.read` already
#: treats as an enumerated negative, so the fallback is a query rather than a
#: guess. See :data:`USER_QUERY_NO_CHANGE_DATE`, and :data:`PTIME_QUERY` for where
#: the date comes from instead.
#:
#: **Bound, never interpolated.** The account name is not a secret, so invariant
#: 14 does not forbid binding it — and it is exactly the kind of value that must
#: not be pasted into SQL text.
#: ``EXPIRY_DATE`` is **appended** rather than slotted in beside
#: ``ACCOUNT_STATUS`` where it reads most naturally, and that is deliberate:
#: :func:`_maintained` and :func:`_password_changed` read fixed positions, so a column
#: inserted in the middle would move two fields that nothing would fail loudly
#: about -- ``ORACLE_MAINTAINED`` would come back as a date and read as *not
#: vendor-maintained*, which is guardrail check 5's input.
USER_QUERY = (
    "select username, account_status, profile, password_versions, "
    "oracle_maintained, password_change_date, expiry_date "
    "from dba_users where username = :name"
)

#: The same seven columns for a release that has no ``PASSWORD_CHANGE_DATE``.
#:
#: **The two columns do not travel together.** Measured:
#:
#: ===============  =====================  ======================
#: release          ``ORACLE_MAINTAINED``  ``PASSWORD_CHANGE_DATE``
#: ===============  =====================  ======================
#: 26ai 23.26       present                present
#: 21c 21.3         present                present
#: **18c 18.4**     **present**            **ORA-00904**
#: 11g 11.2         ORA-00904              ORA-00904
#: ===============  =====================  ======================
#:
#: So 18c must not be treated as 11.2: ``vendor_maintained`` has to come from the
#: ``ORACLE_MAINTAINED`` column that 18c has, or guardrail check 2 switches off
#: and drops to check 5's literal deny list on a release that can answer properly.
#:
#: Every query projects the **same seven columns in the same order**, with
#: ``NULL`` where the release has nothing to put. :func:`_maintained` needs no
#: length test, and a column cannot move under a fixed index.
USER_QUERY_NO_CHANGE_DATE = (
    "select username, account_status, profile, password_versions, "
    "oracle_maintained, cast(null as date), expiry_date "
    "from dba_users where username = :name"
)

#: 11.2, which has neither column. Same seven, two of them ``NULL``.
#:
#: ``ORACLE_MAINTAINED`` being absent here is what the ``None`` in
#: :func:`_maintained` is *for*: the guardrails fall back to their literal deny
#: list (``02-oracle-privileges.md`` §4 check 5) rather than reading a missing
#: column as "no".
USER_QUERY_LEGACY = (
    "select username, account_status, profile, password_versions, "
    "cast(null as varchar2(1)), cast(null as date), expiry_date "
    "from dba_users where username = :name"
)

#: The profile's password limits, with ``DEFAULT`` already resolved.
#:
#: The join is the whole point: ``DBA_PROFILES`` reports the string ``DEFAULT``
#: for every resource the profile does not set, and a caller that took it at face
#: value would read the word ``DEFAULT`` as a lockout threshold.
PROFILE_QUERY = (
    "select p.resource_name, "
    "case when p.limit = 'DEFAULT' then d.limit else p.limit end "
    "from dba_profiles p "
    "join dba_profiles d on d.profile = 'DEFAULT' and d.resource_name = p.resource_name "
    "where p.profile = :profile and p.resource_type = 'PASSWORD'"
)

#: Every role the account holds, **including the ones it holds through another
#: role**. Guardrail 4 refuses the roles in :data:`ADMIN_ROLES`, and a flat read
#: of ``DBA_ROLE_PRIVS`` sees only direct grants -- so an account granted a site
#: role that itself holds ``DBA`` would have been reported as holding nothing the
#: guardrail cares about, and passed.
#:
#: Measured on 26ai, which is how the hole was confirmed rather than argued:
#: ``ACME_APP_ADMIN`` granted ``DBA``, then granted to an account, reads as
#: ``ACME_APP_ADMIN`` alone flat and as ``ACME_APP_ADMIN, DBA, …`` traversed.
#:
#: ``NOCYCLE`` is **defensive rather than load-bearing**, and the distinction is
#: worth writing down because the obvious justification for it is false. Oracle
#: refuses to build a cycle in the first place: ``grant a to b`` followed by
#: ``grant b to a`` fails with ``ORA-01934: circular role grant detected``, so
#: the role graph is acyclic by construction and ``CONNECT BY`` cannot loop on
#: it. It is kept because it costs nothing and the alternative failure --
#: ``ORA-01436`` at a site whose role graph reached a shape this reasoning did
#: not anticipate -- would be a tool that cannot describe any account there.
ROLES_QUERY = (
    "select granted_role from dba_role_privs "
    "start with grantee = :name "
    "connect by nocycle prior granted_role = grantee"
)

#: Whether the account is in the password file -- guardrail 3's only input, and
#: the one dictionary read here that a correctly installed service account is
#: **expected to be refused**.
#:
#: ``V$PWFILE_USERS`` is not in ``02-oracle-privileges.md`` §2's grant set, and
#: that is a decision rather than an omission: the accounts check 3 catches are
#: largely caught by checks 2 and 4 as well, and widening what every service
#: account needs for the remainder is a poor trade. So the grant is **optional**,
#: the way ``SELECT ON SYS.USER$`` is (decision P2), and the answer here is three-valued:
#: a member, not a member, or *nobody looked*.
#:
#: ``count(*)`` rather than selecting the row, because the question is membership
#: and a count answers it in one column that is never null. What distinguishes
#: "not a member" from "could not look" is therefore whether there is a row at
#: all, which is exactly the distinction :func:`~sopuli.driver.oracle.capabilities.read`
#: draws: an enumerated negative (``ORA-00942`` for the ungranted view,
#: ``ORA-41900`` where the asker is privileged enough to be told it exists) is
#: ``None``, and anything else raises.
PWFILE_QUERY = "select count(*) from v$pwfile_users where username = :name"

#: Who this session is, for guardrail 7: the account whose password the next
#: connection needs. ``PROXY_USER`` where the tool logged on as a proxy
#: (``sopuli_svc[acme_web_user]``): ``SESSION_USER`` is then the client account,
#: which logged on with no password of its own. Otherwise ``SESSION_USER``, not
#: ``CURRENT_USER``, which a definer's-rights call can move. The spelling is
#: ``DBA_USERS``'s, so it compares exactly with ``UserState.name``. Needs no
#: grant.
SESSION_USER_QUERY = (
    "select nvl(sys_context('USERENV', 'PROXY_USER'), sys_context('USERENV', 'SESSION_USER')) "
    "from dual"
)

#: Just the spelling, for the one caller that needs the name and nothing else.
#:
#: Separate from :data:`USER_QUERY` rather than reusing :func:`describe`, because
#: the two questions have different costs and different failure modes: a
#: mutation needs to know how the database spells the account, and does not need
#: the roles read -- whose absent grant is a refusal (:class:`RolesUnreadableError`)
#: that would then be raised by `set_password` for a reason unrelated to setting
#: a password.
#:
#: It exists at all because an Oracle quoted identifier is **case-sensitive**.
#: `"acme_orders_user"` and `"ACME_ORDERS_USER"` are different accounts to the
#: server, so a statement built from the config's spelling would get
#: `ORA-01918: user does not exist` against a database that plainly has it.
NAME_QUERY = "select username from dba_users where username = :name"

#: A profile's own spelling, and by the same token whether it exists at all.
#:
#: :data:`NAME_QUERY`'s argument, one object along: an Oracle quoted identifier is
#: case-sensitive, so ``PROFILE "acme_app_prof"`` and ``PROFILE
#: "ACME_APP_PROF"`` are different requests and only one of them names a profile
#: the database has. A config file writes whichever it likes, so the spelling
#: that reaches the statement is read back out of the dictionary first.
#:
#: ``DISTINCT`` because ``DBA_PROFILES`` holds one row per resource, so a profile
#: is a dozen rows and the question here is about the name.
PROFILE_NAME_QUERY = "select distinct profile from dba_profiles where profile = :profile"

#: A role's own spelling, and whether it exists -- :data:`PROFILE_NAME_QUERY`'s
#: argument again, for the other kind of predicate (`account list`).
#:
#: It exists because UC-2 §2 draws an asymmetry that cannot be drawn without it:
#: a `role:` predicate naming a role that **does not exist** is a misspelling and
#: is refused, while one that exists and matches **no accounts** is a true answer
#: about today's estate and is not an error. Both produce an empty account list,
#: so the empty list cannot tell them apart and something has to ask.
ROLE_NAME_QUERY = "select role from dba_roles where role = :role"

#: Every account carrying a profile -- a `profile:` predicate resolved the other
#: way round (H1).
#:
#: ``DBA_USERS`` rather than ``SYS.USER$``, so this needs no grant beyond the one
#: :data:`USER_QUERY` already has. The order is the dictionary's own so that two
#: runs list an estate identically -- an unordered listing that shuffles between
#: runs is one nobody can diff.
ACCOUNTS_WITH_PROFILE_QUERY = (
    "select username from dba_users where profile = :profile order by username"
)

#: Every account holding a role, **including through another role**.
#:
#: :data:`ROLES_QUERY` walked **up** from an account to the roles it holds; this
#: walks **down** from a role to the accounts that hold it, and it has to, or the
#: two disagree. ``admits()`` decides membership from the traversed set, so a
#: flat ``where granted_role = :role`` here would list *fewer* accounts than a
#: reset would accept -- an operator reviewing what a predicate admits would be
#: shown a shorter estate than the one the verb acts on, which is the one wrong
#: answer a listing verb must not give.
#:
#: The ``join`` is what keeps roles out of the answer. A role granted to another
#: role is a grantee like any other, so the traversal returns both accounts and
#: roles, and only the ones ``DBA_USERS`` knows are accounts. Filtering here
#: rather than in Python because the dictionary is what decides what an account
#: is.
#:
#: ``NOCYCLE`` for :data:`ROLES_QUERY`'s reason, and the same caveat: Oracle
#: refuses a circular grant (``ORA-01934``), so it is defensive rather than
#: load-bearing.
ACCOUNTS_WITH_ROLE_QUERY = (
    "select distinct u.username from dba_users u "
    "join (select grantee from dba_role_privs "
    "start with granted_role = :role "
    "connect by nocycle prior grantee = granted_role) g "
    "on g.grantee = u.username "
    "order by u.username"
)

#: Consecutive failed logins, behind the optional ``SELECT ON SYS.USER$`` grant
#: (decision P2). Gated on the ``offline_verify`` capability, which gates this and
#: :data:`PTIME_QUERY` in this build and nothing else.
#:
#: Read immediately before an attempt and never cached: it changes with every
#: failed login, including ones this tool did not make, so a value carried from
#: earlier in the run would be a lockout guard computing on a number that has
#: moved.
LCOUNT_QUERY = "select lcount from sys.user$ where name = :name"

#: When the password was last set, on a release with no
#: ``DBA_USERS.PASSWORD_CHANGE_DATE`` (decision #386). Behind the same optional grant as
#: :data:`LCOUNT_QUERY`, and gated on the same capability.
#:
#: **A second source for one field, and three rules keep it from becoming a
#: second opinion** -- which is the failure ``limits.py`` is the standing warning
#: about, where a version-dependent fact was derived from the wrong place and
#: reported confidently:
#:
#: * **It is never consulted where the column exists.** The column answering is
#:   what selects the source, so no release ever has two, and a ``NULL`` in the
#:   column is reported as a ``NULL`` rather than retried here.
#: * **It is not a version test.** ``ORA-00904`` on the column is what sends the
#:   read here, exactly as it narrows :func:`_user_row`.
#: * **It was measured as the same clock, not an approximation of it.** Equal to
#:   ``PASSWORD_CHANGE_DATE`` to the second on 26ai and 21c; moved by ``ALTER
#:   USER ... IDENTIFIED BY`` on 18c and 11.2, with ``CTIME`` unmoved beside it.
#:   ``tests/driver/test_oracle_accounts.py`` pins the equality on
#:   every release that has both, so a future one where they part fails there.
#:
#: Bound unchanged, for :func:`failed_logins`' reason: ``name`` is already the
#: spelling ``DBA_USERS`` gave back.
PTIME_QUERY = "select ptime from sys.user$ where name = :name"

#: Whether the account is common, for the ``LCOUNT`` guard and for
#: :mod:`sopuli.driver.oracle.audit`. ``DBA_USERS`` is in the baseline grant
#: set. The column exists from 12.1, and only a CDB asks it.
#: It is read rather than taken from the ``C##`` prefix, because
#: ``COMMON_USER_PREFIX`` can be changed, and an application-common account in
#: an application container has no prefix. Bound unchanged, for
#: :func:`failed_logins`' reason.
COMMON_QUERY = "select common from dba_users where username = :name"

#: The account's stored password verifiers, for ``check --method hash``.
#: Behind the same optional grant as :data:`LCOUNT_QUERY`, and gated on the same
#: capability.
#:
#: **The account name is the only bind**, and that is invariant 14 rather than
#: style: the comparison happens client-side in
#: :mod:`sopuli.driver.oracle.verifier`, so neither the password nor a verifier
#: derived from it is ever sent to the server, where ``V$SQL_BIND_CAPTURE`` would
#: keep it in clear. ``WHERE spare4 = :v`` is the shape this exists to rule out.
SPARE4_QUERY = "select spare4 from sys.user$ where name = :name"

FAILED_LOGIN_ATTEMPTS = "FAILED_LOGIN_ATTEMPTS"
PASSWORD_ROLLOVER_TIME = "PASSWORD_ROLLOVER_TIME"
PASSWORD_REUSE_MAX = "PASSWORD_REUSE_MAX"
PASSWORD_REUSE_TIME = "PASSWORD_REUSE_TIME"
PASSWORD_VERIFY_FUNCTION = "PASSWORD_VERIFY_FUNCTION"

#: What ``DBA_PROFILES`` reports for a profile that names no verify function --
#: **the four characters, not a SQL null**. Measured on 26ai: the ``DEFAULT``
#: profile carries it, in the root and in a PDB alike. A caller that read the
#: column without knowing this would report every default-profile account as
#: having a verify function called ``NULL``.
NO_FUNCTION = "NULL"

#: What a **common** profile's verify function reads as from inside a PDB, and
#: the reason :attr:`~sopuli.constraints.AccountConstraints.verify_function_known`
#: exists. Measured on 26ai, alongside the two readings that bound it (see the
#: module docstring).
FROM_ROOT = "FROM ROOT"

#: The token the status carries during a gradual rollover window.
IN_ROLLOVER = "IN ROLLOVER"
LOCKED = "LOCKED"
EXPIRED = "EXPIRED"

#: What a password in its grace period reads as -- and the reason :data:`EXPIRED`
#: is not enough on its own. The whole string is matched rather than the bare word
#: ``GRACE``, because the point is that this **contains** :data:`EXPIRED`: an
#: account here still authenticates, and a substring test for the shorter token
#: reported it as a hard expiry. Measured, with every compound form, in the
#: module docstring above.
EXPIRED_GRACE = "EXPIRED(GRACE)"


#: What a **failed-login limit** produced, which is not the same event as a lock
#: somebody chose. ``PASSWORD_LOCK_TIME`` clears this one on its own.
LOCKED_TIMED = "LOCKED(TIMED)"

#: How Oracle joins the components of a compound ``ACCOUNT_STATUS``.
STATUS_SEPARATOR = " & "


def deliberately_locked(status: str) -> bool:
    """Whether ``status`` says a **person** locked this account.

    Not the same question as :attr:`~sopuli.driver.protocol.UserState.locked`,
    which is true of every locked form, and the difference is what UC-2 turns on:
    a reset clears ``LOCKED(TIMED)`` by default and refuses a deliberate
    ``LOCKED`` (H4), and `account suspend` is the verb that sets the second
    one.

    **Parsed by component rather than by substring**, and that is the whole
    reason this is a function. ``LOCKED(TIMED)`` *contains* ``LOCKED``, so
    ``LOCKED in status`` is true of a timed lock, and equality against the whole
    string is wrong the other way -- the status compounds, so a deliberately
    locked account can read ``EXPIRED & LOCKED``, ``LOCKED & IN ROLLOVER`` or
    ``EXPIRED & LOCKED & IN ROLLOVER``. Splitting on the separator answers both,
    as it does for :attr:`~sopuli.driver.protocol.UserState.expired`, where a
    substring test would read ``EXPIRED(GRACE)`` as a hard expiry.
    """
    return LOCKED in {part.strip().upper() for part in status.split(STATUS_SEPARATOR)}


class RolesUnreadableError(DriverError):
    """``DBA_ROLE_PRIVS`` could not be read, so guardrail 4 has no input.

    **Raised rather than reported as "no roles"**, which is the entire reason
    this class exists. Guardrail 4 refuses an account holding a role in
    :data:`ADMIN_ROLES`; an empty set means *this account holds none of them*
    and reads as a pass. A missing grant would therefore turn
    a safety check into a silent success, which is the same failure shape as a
    capability probe that could not be answered reporting absent (decision #195) — and the
    reason `02-oracle-privileges.md` §2 grants the view.
    """

    category = "authorization"


class DictionaryUnreadableError(DriverError):
    """A view ``02-oracle-privileges.md`` §2 grants could not be read.

    :func:`~sopuli.driver.oracle.capabilities.read` turns ``ORA-00942`` and its
    kin into ``None``, which is right for a probe -- an optional grant nobody
    made is the ordinary estate -- and wrong for ``DBA_USERS``. There ``None``
    means *the database has no such account*, so a service account missing the
    grant reported every account in the estate as ``ACCOUNT_MISSING``, and the
    operator went looking for accounts rather than for a grant.

    The server's code and message are carried, and the hint names the grant.
    """

    category = "authorization"


#: What a refused read of a granted view says.
#: :data:`~sopuli.driver.oracle.capabilities.ABSENT_CODES` without ``ORA-00904``: a
#: missing column is how :func:`_user_row` finds a release's shape, and is never a
#: missing grant.
_GRANT_CODES = frozenset({"ORA-00942", "ORA-01031", "ORA-41900"})

#: The one code :func:`_user_row` narrows on rather than raises.
_NO_SUCH_COLUMN = "ORA-00904"


def _unreadable(error: Exception, view: str) -> DriverError:
    """``error`` from reading ``view``, as something to raise.

    A refused grant becomes :class:`DictionaryUnreadableError` naming the grant;
    anything else is classified as every other statement is, so an unrelated
    failure is not misdiagnosed as a missing grant.
    """
    diagnosis = from_error(error)
    if diagnosis.code in _GRANT_CODES:
        return DictionaryUnreadableError(
            f"could not read {view}: {diagnosis.message}",
            code=diagnosis.code,
            retryable=diagnosis.retryable,
            hint=(
                f"GRANT SELECT ON SYS.{view} to the service account -- "
                f"02-oracle-privileges.md section 2, or {INSTALL_SCRIPT}"
            ),
        )
    return diagnosis.as_error()


def _lookup(cursor: Cursor, statement: str, view: str, **binds: Any) -> Any:
    """One row of a view §2 grants, or ``None`` where the query found none.

    Not :func:`~sopuli.driver.oracle.capabilities.read`, whose rule is right for
    a probe and wrong here: a refused grant raises (:func:`_unreadable`) rather
    than reading as an absence.
    """
    try:
        cursor.execute(statement, binds)
        return cursor.fetchone()
    except Exception as error:  # noqa: BLE001 -- classified, never swallowed
        raise _unreadable(error, view) from error


def describe(cursor: Cursor, account: str, *, user_dollar: bool = False) -> UserState | None:
    """One account as the database describes it, or ``None`` if there is none.

    ``None`` is UC-1's ``ACCOUNT_MISSING`` and is **not** an error: the tool does
    not create accounts (Q8 — provisioning is its own use case), so a missing one
    is a state to report rather than a failure to recover from.

    Four queries, and roles are one of them rather than something a caller opts
    into. The alternative is a lazy read, since role membership is consulted
    only before a mutation and `creds status` reads this object for every
    account in an estate. It is refused because of what it would cost when it
    went wrong: a caller that forgot to ask for roles would get a
    :class:`~sopuli.driver.protocol.UserState` whose empty ``roles`` reads exactly
    like an account holding none, and guardrail 4 would pass. A safety check must
    not depend on a caller remembering to enable its input.

    **The fourth is the password file**, and it is here rather than in
    :func:`login_state` for the same reason roles are: it is a guardrail input, so
    it belongs on the object a mutation reads and not on the one `creds check`
    reads. Unlike roles it is allowed to fail — the grant is optional — and the
    ``None`` it then carries keeps guardrail 3 from reading "nobody looked" as
    "not a member".

    ``user_dollar`` is whether the session may read ``SYS.USER$``, and it is the
    caller's to say because it is a capability the session probed once
    (:data:`PTIME_QUERY`).
    """
    state = login_state(cursor, account, user_dollar=user_dollar)
    if state is None:
        return None
    roles = _roles(cursor, state.name)
    return replace(
        state,
        roles=roles,
        admin_roles=ADMIN_ROLES & roles,
        password_file_member=password_file_member(cursor, state.name),
    )


def login_state(cursor: Cursor, account: str, *, user_dollar: bool = False) -> UserState | None:
    """The account without its roles, for the callers that must not need them.

    `creds check` is the caller. It needs no site-specific grant to run (decisions P2 and Q1),
    and reading roles is a *guardrail* input consulted before a mutation -- so
    making a read-only command depend on `DBA_ROLE_PRIVS` would widen what
    `check` requires for a reason that has nothing to do with checking.

    :func:`describe` is this plus roles, and it is what a mutation uses.

    ``user_dollar`` defaults to ``False`` so that a caller which never asked
    whether the grant exists issues no ``SYS.USER$`` read: a refused one is an
    audit record on a site that audits failed selects, per account.
    """
    found = _user_row(cursor, account)
    if found is None:
        return None
    query, row = found

    name = str(row[0])
    status = str(row[1] or "")
    profile = str(row[2]) if row[2] else None
    limits = _limits(cursor, profile) if profile else {}
    changed_at, changed_unknown = _password_changed(
        cursor, name, row, has_column=query == USER_QUERY, user_dollar=user_dollar
    )

    return UserState(
        name=name,
        status=status,
        locked=LOCKED in status,
        deliberately_locked=deliberately_locked(status),
        # `EXPIRED(GRACE)` carries the token `EXPIRED`, so the two are read
        # together or the grace period comes out as a hard expiry. Every caller
        # tests `locked` before either, and every locked form carries `LOCKED`,
        # so an account that is both stays locked to all of them.
        expired=EXPIRED in status and EXPIRED_GRACE not in status,
        in_grace=EXPIRED_GRACE in status,
        profile=profile,
        password_versions=_versions(row[3]),
        password_changed_at=changed_at,
        password_changed_unknown=changed_unknown,
        password_expires_at=_expires_at(row),
        failed_login_limit=limits.get(FAILED_LOGIN_ATTEMPTS),
        # Carried rather than discarded, because one query already resolved
        # them: `sopuli.driver.oracle.rollover` reads the rollover time at plan
        # time, and UC-1 §4's bounded regeneration exists because of the reuse
        # policy. Reading them again from a second, uncoordinated query would be
        # a second chance to disagree about the same profile.
        rollover_time=limits.get(PASSWORD_ROLLOVER_TIME),
        password_reuse_max=limits.get(PASSWORD_REUSE_MAX),
        password_reuse_time=limits.get(PASSWORD_REUSE_TIME),
        rollover_active=IN_ROLLOVER in status,
        # Whether the profile grants a window at all, as opposed to whether one
        # is open. Parsed here because `rollover_time` is Oracle's own spelling
        # and `sopuli.strategy`, which reads this, is above the driver.
        rollover_enabled=is_enabled(limits.get(PASSWORD_ROLLOVER_TIME)),
        # **Derived, and only while a window is open.** No dictionary column
        # exposes the end -- searched, not assumed -- so the choice is between
        # Oracle's own documented arithmetic over two measured values and
        # telling an operator nothing about their deadline.
        # `rollover.window_end` carries the reasoning and the limits.
        rollover_ends_at=(
            window_end(changed_at, limits.get(PASSWORD_ROLLOVER_TIME))
            if IN_ROLLOVER in status
            else None
        ),
        rollover_days=days(limits.get(PASSWORD_ROLLOVER_TIME)),
        vendor_maintained=_maintained(row),
        supplied_name=name.upper() in ORACLE_SUPPLIED,
    )


def password_constraints(cursor: Cursor, account: str) -> AccountConstraints | None:
    """What this target says about a password for one account (UC-1 §4 step 2).

    ``None`` where the target has no such account, which is
    :func:`login_state`'s answer and means the same thing here: `creds generate`
    stages into a vault and does not need the account to exist yet, so this is a
    thing not reported rather than a failure.

    **Deliberately not a :class:`~sopuli.driver.protocol.UserState`.** The
    obvious implementation is to call :func:`login_state` and let the caller take
    the four fields it wants, and it is refused for the reason :func:`describe`
    gives for reading roles eagerly: a ``UserState`` with no ``roles`` reads
    exactly like an account holding none, and guardrail 4 would pass on it. A
    reporting path must not be able to hand that object to a safety check, so it
    returns a type that has no such field to misread.

    Two queries, both on the baseline grant set (``02-oracle-privileges.md`` §2),
    so reading them costs `creds generate` no privilege it did not already need
    -- and no third: the roles :func:`describe` reads are a guardrail input and a
    staging command has nothing to guard.
    """
    found = _user_row(cursor, account)
    if found is None:
        return None
    _, row = found

    profile = str(row[2]) if row[2] else None
    limits = _limits(cursor, profile) if profile else {}
    verify = limits.get(PASSWORD_VERIFY_FUNCTION)
    return AccountConstraints(
        account=str(row[0]),
        profile=profile,
        # `NULL` is the profile naming none, `FROM ROOT` is the dictionary
        # declining to say, and both are the string in the column rather than a
        # SQL null. They land on the same `verify_function` and are told apart by
        # `verify_function_known`, which is the distinction that matters: not
        # knowing is not a finding, and it is not an absence either.
        verify_function=None if verify in (None, NO_FUNCTION, FROM_ROOT) else verify,
        verify_function_known=verify is not None and verify != FROM_ROOT,
        reuse_max=limits.get(PASSWORD_REUSE_MAX),
        reuse_time=limits.get(PASSWORD_REUSE_TIME),
        versions=_versions(row[3]),
    )


def resolve_profile(cursor: Cursor, profile: str) -> str | None:
    """The profile as the dictionary spells it, or ``None`` if there is no such one.

    Two questions with one query, which is deliberate rather than thrifty: *does
    this profile exist here* and *how is it spelled* have the same answer, and a
    caller that asked them separately could act on a name between the two reads.

    Upper-cased on the way in for :func:`_user_row`'s reason -- Oracle stores an
    unquoted identifier upper-cased, and a config file writing ``acme_app_prof``
    means the profile the database calls ``ACME_APP_PROF``. A site that created a
    genuinely lower-case profile with quotes gets ``None`` here and a refusal
    naming what it looked for, which is the honest outcome: guessing at a second
    spelling would be the tool deciding which of two profiles the file meant.

    ``None`` only where the query answered with no row. A refused grant
    raises :class:`DictionaryUnreadableError`, because "no such profile" is the
    refusal a misspelling earns and a missing grant is not one.
    """
    row = _lookup(cursor, PROFILE_NAME_QUERY, "DBA_PROFILES", profile=profile.upper())
    return None if row is None else str(row[0])


def resolve_role(cursor: Cursor, role: str) -> str | None:
    """The role as the dictionary spells it, or ``None`` if there is no such one.

    :func:`resolve_profile`'s argument for the other predicate, and it exists for
    a reason that is not symmetry: UC-2 §2 refuses a predicate naming a role that
    does not exist and accepts one that matches nothing, and both of those look
    like an empty list from :func:`accounts_with_role`. Only asking separately
    tells them apart.

    Upper-cased on the way in, as :func:`resolve_profile` is, and the same
    consequence follows for a genuinely lower-case quoted role: ``None``, and a
    refusal naming what was looked for, rather than the tool guessing at a second
    spelling.

    ``None`` only where the query answered with no row. A refused grant raises
    :class:`DictionaryUnreadableError`: read through the capability probes'
    rule, an ungranted ``DBA_ROLES`` would be "no such role", and every
    ``role:`` predicate would be refused as a misspelling.
    """
    row = _lookup(cursor, ROLE_NAME_QUERY, "DBA_ROLES", role=role.upper())
    return None if row is None else str(row[0])


def accounts_with_profile(cursor: Cursor, profile: str) -> tuple[str, ...]:
    """Every account carrying ``profile``, in the dictionary's own order.

    The **resolution** half of a `profile:` predicate: :func:`sopuli.personal.admits`
    answers "does this rule admit that account" for a verb acting on one name,
    and this answers "which accounts does this rule admit" for the verb that
    lists them.

    An empty tuple is a true answer about today's estate and not an error (UC-2
    §2). Whether the profile *exists* is :func:`resolve_profile`'s question, and
    the caller asks it first -- a misspelling and an empty profile are the same
    empty tuple here.
    """
    return _names(cursor, ACCOUNTS_WITH_PROFILE_QUERY, profile=profile.upper())


def accounts_with_role(cursor: Cursor, role: str) -> tuple[str, ...]:
    """Every account holding ``role``, directly or through another role.

    **Transitive, and that is a correctness requirement rather than a courtesy.**
    :func:`sopuli.personal.admits` decides membership against the set
    :data:`ROLES_QUERY` traverses, so an enumeration that read only direct grants
    would show an operator fewer accounts than a reset would accept. A listing
    verb that under-reports what a predicate admits is worse than no listing
    verb, because it would be read as the whole set.

    Empty is a true answer; existence is :func:`resolve_role`'s question.
    """
    return _names(cursor, ACCOUNTS_WITH_ROLE_QUERY, role=role.upper())


def _names(cursor: Cursor, statement: str, **binds: Any) -> tuple[str, ...]:
    """Every first column of a multi-row read, as the dictionary spelled it.

    Not :func:`~sopuli.driver.oracle.capabilities.read`, which fetches one row.
    The :data:`~sopuli.driver.oracle.capabilities.ABSENT_CODES` rule does not apply
    either: these two views are the ones ``02-oracle-privileges.md`` §2 already
    grants, so a failure to read one is a broken installation rather than an absent
    capability, and turning it into an empty list would report an estate with nobody
    in it.
    """
    cursor.execute(statement, binds or None)
    return tuple(str(row[0]) for row in cursor.fetchall())


def _user_row(cursor: Cursor, account: str) -> tuple[str, Any] | None:
    """``DBA_USERS``, narrowing one column at a time until the server answers.

    Returns the query that answered beside its row, because *which* one answered
    is itself a reading: :func:`_password_changed` needs to know whether the
    release has ``PASSWORD_CHANGE_DATE`` at all, and a ``NULL`` in position 5
    cannot say -- the narrower shapes select one there too.

    Each fallback is driven by the server refusing a column rather than by a
    version test, which is invariant 3 in the small: `ORA-00904` *is* the answer
    to "does this release have `PASSWORD_CHANGE_DATE`", and it needs no capability
    of its own because the query itself is the probe.

    **Three shapes, not two, and they are tried in that order for a reason.**
    18c has `ORACLE_MAINTAINED` and not `PASSWORD_CHANGE_DATE`; 11.2 has neither
    (measured -- see :data:`USER_QUERY_NO_CHANGE_DATE`). Dropping both together
    made 18c answer as 11.2 and gave up a guardrail input it could have read.
    Every shape projects the same seven columns, so a caller reads fixed
    positions whichever one answered.

    **Only ``ORA-00904`` narrows.** The capability probes'
    :func:`~sopuli.driver.oracle.capabilities.read` is not used here: an
    ungranted view would be ``None`` three times over and read as a missing
    account. A refused grant raises :class:`DictionaryUnreadableError`, and a
    query that answered with no row is the account's absence -- asking the narrower shapes the same
    question cannot change that answer.
    """
    query, row = first_shape(
        cursor,
        (USER_QUERY, USER_QUERY_NO_CHANGE_DATE, USER_QUERY_LEGACY),
        "DBA_USERS",
        lambda answered: answered.fetchone(),
        {"name": account.upper()},
    )
    return (query, row) if row is not None else None


def first_shape(
    cursor: Cursor,
    shapes: tuple[str, ...],
    view: str,
    fetch: Callable[[Cursor], Any],
    binds: dict[str, Any] | None = None,
) -> tuple[str, Any]:
    """The first of ``shapes`` the server accepts, with what ``fetch`` read from it.

    Only ``ORA-00904`` moves to the next shape. Any other failure raises, and so
    does a failure of the last shape: a refused grant as
    :class:`DictionaryUnreadableError`, anything else classified.
    """
    for query in shapes[:-1]:
        try:
            cursor.execute(query, binds)
            return query, fetch(cursor)
        except Exception as error:  # noqa: BLE001 -- classified, never swallowed
            if from_error(error).code != _NO_SUCH_COLUMN:
                raise _unreadable(error, view) from error
    try:
        cursor.execute(shapes[-1], binds)
        return shapes[-1], fetch(cursor)
    except Exception as error:  # noqa: BLE001 -- classified, never swallowed
        raise _unreadable(error, view) from error


def _limits(cursor: Cursor, profile: str) -> dict[str, str]:
    cursor.execute(PROFILE_QUERY, {"profile": profile})
    return {str(name): str(limit) for name, limit in cursor.fetchall() if limit is not None}


def password_file_member(cursor: Cursor, name: str) -> bool | None:
    """Whether ``name`` is in the password file, or ``None`` if nobody could look.

    Guardrail 3's input (``02-oracle-privileges.md`` §4), and the **only**
    guardrail input that is allowed to come back unknown. The contrast with
    :func:`_roles` is the decision worth stating, because the two look like the
    same situation and are not:

    * ``DBA_ROLE_PRIVS`` is granted by §2, so a service account that cannot read
      it is **misinstalled**, and an empty role set would read as a pass on a
      check whose whole job is to refuse. That one raises
      (:class:`RolesUnreadableError`).
    * ``V$PWFILE_USERS`` is **not** granted by §2, and is left out
      by design: the accounts check 3 catches are largely caught by checks 2 and 4 as well,
      and widening the baseline install for the remainder is a poor trade. So the
      ordinary, correct estate cannot answer this, and raising would refuse every
      mutation on every correctly installed target.

    What must not happen either way is the merge :mod:`sopuli.driver.oracle.privileges`
    refuses one layer up — "I looked and found nothing" reported as the same thing
    as "I could not look". So the answer is three-valued, the guardrail turns the
    third into a caveat rather than a pass, and the command reports it.

    ``name`` is bound **unchanged**, for the reason :func:`failed_logins` gives:
    it is already the spelling ``DBA_USERS`` gave back, ``V$PWFILE_USERS.USERNAME``
    carries the same one, and upper-casing here would miss a quoted lower-case
    account and return a zero count -- which reads as *not a member* and is the
    one wrong answer that is silent.
    """
    row = read(cursor, PWFILE_QUERY, name=name)
    return None if row is None else bool(row[0])


def _roles(cursor: Cursor, name: str) -> frozenset[str]:
    """The roles ``name`` holds, directly or through other roles.

    A refused grant is :class:`RolesUnreadableError`, carrying the server's code
    and message. Anything else is classified as any other statement is:
    prescribing a ``GRANT`` for a timeout or a lost connection sends the reader
    the wrong way.
    """
    try:
        cursor.execute(ROLES_QUERY, {"name": name})
        return frozenset(str(role[0]).upper() for role in cursor.fetchall())
    except Exception as error:  # noqa: BLE001 -- classified, never swallowed
        diagnosis = from_error(error)
        if diagnosis.code not in _GRANT_CODES:
            raise diagnosis.as_error() from error
        raise RolesUnreadableError(
            f'could not read the roles held by "{name}": {diagnosis.message}',
            code=diagnosis.code,
            retryable=diagnosis.retryable,
            hint=(
                f"guardrail 4 refuses an account holding {_ADMIN_ROLES_IN_WORDS}, and "
                "cannot tell an account with none from a view it cannot read: "
                "GRANT SELECT ON SYS.DBA_ROLE_PRIVS to the service account"
            ),
        ) from error


def _versions(value: Any) -> tuple[str, ...]:
    """``PASSWORD_VERSIONS`` is a space-separated list -- ``"11G 12C"``."""
    return tuple(str(value).split()) if value else ()


def _password_changed(
    cursor: Cursor, name: str, row: Any, *, has_column: bool, user_dollar: bool
) -> tuple[datetime | None, str | None]:
    """When the password was last set, and -- where that is unknown -- why.

    **Exactly one source per release**, chosen by what the server answered and
    never by a version: ``DBA_USERS.PASSWORD_CHANGE_DATE`` where the column
    exists, and ``SYS.USER$.PTIME`` where it does not and the session may read
    it. A column that exists and is empty is reported as empty rather than
    retried against ``PTIME``, because that is the one path by which a release
    would acquire two sources and the chance to disagree between them.

    The second value is the reason, and it is ``None`` exactly when the first is
    not. It exists because ``-`` in `creds status` and an omitted
    ``password_age_days`` in the run document would otherwise mean both *this
    release has no such column* and *something could not be read*, and only one
    of those is worth anybody's time. It is a sentence in the driver's words, which
    keeps Oracle's vocabulary out of :class:`~sopuli.driver.protocol.UserState`
    while still naming the grant that fixes it.
    """
    if has_column:
        if isinstance(row[5], datetime):
            return row[5], None
        return None, "DBA_USERS.PASSWORD_CHANGE_DATE is empty for this account"
    if not user_dollar:
        return None, (
            "this release has no DBA_USERS.PASSWORD_CHANGE_DATE; GRANT SELECT ON "
            "SYS.USER$ to the service account to read the same date from SYS.USER$.PTIME"
        )
    found = read(cursor, PTIME_QUERY, name=name)
    if found is None:
        return None, (
            "this release has no DBA_USERS.PASSWORD_CHANGE_DATE, and SYS.USER$ could "
            "not be read for this account"
        )
    if isinstance(found[0], datetime):
        return found[0], None
    return None, (
        "this release has no DBA_USERS.PASSWORD_CHANGE_DATE, and SYS.USER$.PTIME is "
        "empty for this account"
    )


def _expires_at(row: Any) -> datetime | None:
    """``EXPIRY_DATE``, which every query selects and every one selects **last**.

    ``row[-1]`` rather than a number: all three shapes project the same seven
    columns, so this is the last of seven and `row[6]` would be as correct. It is
    the one index that cannot go wrong if a fourth shape is ever added with a
    column dropped from the middle.

    ``None`` where the profile expires nothing. A caller must not read that as
    *not expiring soon* and then as *expiring never*: it is the same answer either
    way here, and the expiry warning simply has nothing to say about such an account.
    """
    return row[-1] if isinstance(row[-1], datetime) else None


def _maintained(row: Any) -> bool | None:
    """``ORACLE_MAINTAINED``, which is ``None`` rather than ``False`` on 11.2.

    The distinction is load-bearing: guardrail check 5's literal deny list is
    consulted **only** where check 2 could not answer, so a missing column
    reading as "not vendor-maintained" would quietly switch off the fallback that
    exists for exactly that release.

    **No length test.** Every query in :func:`_user_row` projects the same seven
    columns, selecting ``NULL`` where the release has nothing to put, so this
    reads one fixed position on every version and a ``None`` here means the
    column said nothing rather than that the row was short.
    """
    return str(row[4]).upper() == "Y" if row[4] is not None else None


def resolve_name(cursor: Cursor, account: str) -> str | None:
    """How the database spells ``account``, or ``None`` if it has no such user.

    ``02-oracle-privileges.md`` §4: the name that reaches a statement is the one
    read back from the dictionary, never the raw string from a config file.

    ``None`` only where the query answered with no row. A refused grant raises,
    for :class:`DictionaryUnreadableError`'s reason.
    """
    row = _lookup(cursor, NAME_QUERY, "DBA_USERS", name=account.upper())
    return str(row[0]) if row else None


def failed_logins(cursor: Cursor, name: str) -> int | None:
    """``SYS.USER$.LCOUNT``, or ``None`` where the grant was never made.

    Measured on 26ai: a failed login takes it 0 -> 1 -> 2, and a **successful**
    login puts it back to 0. That last part is UC-1 §7 mitigation 3 and it needs
    no code -- the database does it -- which is what makes the happy path
    self-cleaning.
    """
    # Bound **unchanged**. ``name`` is already the spelling `DBA_USERS` gave
    # back, and ``SYS.USER$.NAME`` preserves it -- so upper-casing here would
    # miss a quoted lower-case account, return no row, and be indistinguishable
    # from "the grant was never made". That failure is silent and it is the
    # dangerous direction: an absent counter reads as an unavailable guard, and
    # the login goes ahead spending lockout budget the guard was there to
    # protect.
    row = read(cursor, LCOUNT_QUERY, name=name)
    return int(row[0]) if row and row[0] is not None else None


def is_common(cursor: Cursor, name: str) -> bool | None:
    """Whether ``DBA_USERS.COMMON`` says ``YES`` for ``name``, or ``None`` if unread.

    ``name`` is the spelling ``DBA_USERS`` gave back, bound unchanged.

    **It fails closed.** ``None`` is any read that did not answer: an error, or
    no row. :func:`read` is not used, because it turns ``ORA-00942`` and
    ``ORA-00904`` into an empty answer, and here an empty answer would read as
    *not common* and give the account a guard that counts the wrong container.
    The caller reports ``None`` as a gap.
    """
    try:
        cursor.execute(COMMON_QUERY, {"name": name})
        row = cursor.fetchone()
    except Exception:  # noqa: BLE001 -- any failure is "could not tell", reported as a gap
        return None
    return is_yes(row[0]) if row else None


#: Every account, for UC-5's reports (``02-oracle-privileges.md`` §2, *What the
#: report commands read*). ``DBA_USERS`` only, on the baseline grant set. No
#: column that holds or describes a password is read. ``COMMON`` and
#: ``ORACLE_MAINTAINED`` exist from 12.1; :data:`SURVEY_USERS_QUERY_LEGACY` is
#: the shape for a release that answers ``ORA-00904`` to them.
#: ``AUTHENTICATION_TYPE`` says how the account logs in, not what with: it is
#: ``NONE`` for an account made ``NO AUTHENTICATION``, which nobody can log in
#: to (18c and later, #1447).
SURVEY_USERS_QUERY = (
    "select username, account_status, profile, common, oracle_maintained, "
    "authentication_type from dba_users"
)

#: :data:`SURVEY_USERS_QUERY` with ``NULL`` in place of ``COMMON`` and
#: ``ORACLE_MAINTAINED``, in the same positions. Measured on 11.2.0.2.0, which
#: has neither. ``AUTHENTICATION_TYPE`` is ``NULL`` too: ``NONE`` is from 18c,
#: and this shape is for a release older than 12.1.
SURVEY_USERS_QUERY_LEGACY = (
    "select username, account_status, profile, "
    "cast(null as varchar2(3)), cast(null as varchar2(1)), cast(null as varchar2(8)) "
    "from dba_users"
)

#: The two limits UC-5 checks, and ``PASSWORD_LOCK_TIME``, for every profile.
#: Each row has the limit as ``DBA_PROFILES`` shows it, the limit resolved
#: through the ``DEFAULT`` profile of this container, and whether the profile
#: is common. The raw value is kept because a ``DEFAULT`` on a common profile
#: follows the root's ``DEFAULT`` profile, and a PDB cannot read that (§2).
#: ``PASSWORD_LOCK_TIME`` tells whether a ``LOCKED`` status can be a lockout
#: after failed logins: only where it is ``UNLIMITED`` (#1447).
SURVEY_LIMITS_QUERY = (
    "select p.profile, p.resource_name, p.limit, "
    "case when p.limit = 'DEFAULT' then d.limit else p.limit end, p.common "
    "from dba_profiles p "
    "join dba_profiles d on d.profile = 'DEFAULT' and d.resource_name = p.resource_name "
    "where p.resource_name in "
    "('PASSWORD_LIFE_TIME', 'FAILED_LOGIN_ATTEMPTS', 'PASSWORD_LOCK_TIME')"
)

#: :data:`SURVEY_LIMITS_QUERY` for a release with no ``DBA_PROFILES.COMMON``.
SURVEY_LIMITS_QUERY_LEGACY = (
    "select p.profile, p.resource_name, p.limit, "
    "case when p.limit = 'DEFAULT' then d.limit else p.limit end, "
    "cast(null as varchar2(3)) "
    "from dba_profiles p "
    "join dba_profiles d on d.profile = 'DEFAULT' and d.resource_name = p.resource_name "
    "where p.resource_name in "
    "('PASSWORD_LIFE_TIME', 'FAILED_LOGIN_ATTEMPTS', 'PASSWORD_LOCK_TIME')"
)

#: Every account's failed-login count, behind the optional ``SELECT ON
#: SYS.USER$`` grant and sent only with ``offline_verify``. ``NAME`` and
#: ``LCOUNT`` only: no verifier column. ``TYPE# = 1`` is a user; roles are 0.
SURVEY_LCOUNT_QUERY = "select name, lcount from sys.user$ where type# = 1"

PASSWORD_LIFE_TIME = "PASSWORD_LIFE_TIME"
PASSWORD_LOCK_TIME = "PASSWORD_LOCK_TIME"

#: ``DBA_USERS.AUTHENTICATION_TYPE`` of an account made ``NO AUTHENTICATION``.
NO_AUTHENTICATION = "NONE"

#: What ``DBA_PROFILES`` shows for a limit that the profile inherits.
_INHERITED = "DEFAULT"

#: The root, where a common account's lock, limits and count are kept.
_ROOT = "CDB$ROOT"

#: Why a common account's values are ``None``, by what is held elsewhere. In a
#: PDB they are in the root (§2). In an application container where they are
#: kept was not measured, as :mod:`sopuli.driver.oracle.session`'s guard says.
_HELD_IN_ROOT = {
    "lock": (
        "{name} is a common account, and this container does not show its lock, "
        f"which is kept in {_ROOT}"
    ),
    "limit": (
        "{name} is a common account, so its {resource} comes from its profile in "
        f"{_ROOT}, which this container cannot read"
    ),
    "count": (
        "{name} is a common account, and its failed logins are counted in "
        f"{_ROOT}, which this container cannot read"
    ),
}
_HELD_IN_APPLICATION = {
    "lock": (
        "{name} is a common account, and where an application container keeps "
        "its lock has not been measured"
    ),
    "limit": (
        "{name} is a common account, and which profile sets its {resource} in an "
        "application container has not been measured"
    ),
    "count": (
        "{name} is a common account, and where an application container counts "
        "its failed logins has not been measured"
    ),
}


def survey(
    cursor: Cursor, *, own_container: bool, user_dollar: bool, application: bool = False
) -> tuple[SurveyedAccount, ...]:
    """Every account on this target, ordered by name: :func:`survey_with_profiles`'
    accounts, for a report that does not need the profile names."""
    accounts, _ = survey_with_profiles(
        cursor, own_container=own_container, user_dollar=user_dollar, application=application
    )
    return accounts


def survey_with_profiles(
    cursor: Cursor, *, own_container: bool, user_dollar: bool, application: bool = False
) -> tuple[tuple[SurveyedAccount, ...], frozenset[str]]:
    """Every account on this target, ordered by name, for UC-5's reports, and
    every profile on it.

    The profile names come from the limits statement's rows: ``DBA_PROFILES``
    lists every resource of every profile, so each profile has a
    ``PASSWORD_LIFE_TIME`` row. No statement is added for them (#1390).

    ``own_container`` is whether this container holds every account's own lock,
    limits and failed-login count: true in ``CDB$ROOT`` and in a non-CDB. In
    any other container a common account's values are kept in the root, so they
    are ``None`` here, each with a reason. So is a ``DEFAULT`` limit on a common
    profile, which follows the root's ``DEFAULT`` profile. These were measured
    with ``sql/oracle/19_report_read_probe.sql`` (``02-oracle-privileges.md`` §2).
    ``application`` is whether this is an application container, which only
    changes how the reasons are worded.

    ``user_dollar`` is whether the session may read ``SYS.USER$``. Without it no
    statement goes there, and every count is ``None`` with the grant named.

    Three statements, or two without the grant. Nothing is bound: no statement
    names an account. A refused ``DBA_USERS`` or ``DBA_PROFILES`` read raises
    :class:`DictionaryUnreadableError`. Only ``ORA-00904`` narrows a query.

    Where the narrowed shape leaves ``COMMON`` unread outside ``CDB$ROOT`` and
    a non-CDB, an account named with the ``C##`` prefix is taken as common and
    a profile is taken as common, so a value that may be held elsewhere is
    ``None`` rather than the value this container shows.
    """
    _, users = first_shape(
        cursor, (SURVEY_USERS_QUERY, SURVEY_USERS_QUERY_LEGACY), "DBA_USERS", fetch_all
    )
    _, limit_rows = first_shape(
        cursor, (SURVEY_LIMITS_QUERY, SURVEY_LIMITS_QUERY_LEGACY), "DBA_PROFILES", fetch_all
    )
    limits = {(str(row[0]), str(row[1])): row for row in limit_rows}
    counts, counts_gap = _lcounts(cursor) if user_dollar else ({}, _NO_GRANT)
    held_reason = _HELD_IN_APPLICATION if application else _HELD_IN_ROOT

    surveyed = []
    for row in users:
        name, status, profile = str(row[0]), str(row[1] or ""), str(row[2] or "")
        if row[3] is not None:
            common = is_yes(row[3])
        else:
            common = not own_container and name.upper().startswith(COMMON_PREFIX)
        maintained = _maintained(row)
        vendor = maintained if maintained is not None else name.upper() in ORACLE_SUPPLIED
        held_elsewhere = common and not own_container
        reasons: list[str] = []

        locked: bool | None = LOCKED in status
        if held_elsewhere:
            locked = None
            reasons.append(held_reason["lock"].format(name=name))

        resolved: dict[str, Limit] = {}
        for resource in (PASSWORD_LIFE_TIME, FAILED_LOGIN_ATTEMPTS):
            if held_elsewhere:
                resolved[resource] = None
                reasons.append(held_reason["limit"].format(name=name, resource=resource))
                continue
            value, reason = _limit(
                limits.get((profile, resource)), profile, resource, own_container
            )
            resolved[resource] = value
            if reason is not None:
                reasons.append(reason)

        failed: int | None = None
        if held_elsewhere:
            reasons.append(held_reason["count"].format(name=name))
        elif counts_gap is not None:
            reasons.append(counts_gap)
        elif name not in counts:
            reasons.append(f"SYS.USER$ has no row for {name}")
        elif counts[name] is None:
            reasons.append(f"SYS.USER$.LCOUNT is empty for {name}")
        else:
            failed = counts[name]

        deliberate: bool | None = None
        if locked is not None:
            lock_time = limits.get((profile, PASSWORD_LOCK_TIME))
            deliberate = _locked_by_somebody(
                status,
                lock_time_unlimited=_lock_time_unlimited(lock_time, own_container),
                limit=resolved[FAILED_LOGIN_ATTEMPTS],
                failed=failed,
            )

        surveyed.append(
            SurveyedAccount(
                name=name,
                status=status,
                locked=locked,
                profile=profile,
                common=common,
                vendor_maintained=vendor,
                password_lifetime=resolved[PASSWORD_LIFE_TIME],
                failed_login_limit=resolved[FAILED_LOGIN_ATTEMPTS],
                failed_logins=failed,
                unreadable=tuple(reasons),
                kept_in_root=held_elsewhere and not application,
                deliberately_locked=deliberate,
                no_authentication=str(row[5] or "").upper() == NO_AUTHENTICATION,
            )
        )
    accounts = tuple(sorted(surveyed, key=lambda account: account.name))
    return accounts, frozenset(str(row[0]) for row in limit_rows)


def _lock_time_unlimited(row: Any, own_container: bool) -> bool | None:
    """Whether a profile's ``PASSWORD_LOCK_TIME`` is ``UNLIMITED``; ``None`` if unknown.

    Only ``UNLIMITED`` matters here, so a fraction of a day, the usual value,
    is simply "not unlimited". A ``DEFAULT`` that a container cannot resolve is
    unknown, as for the other limits (:func:`_limit`).
    """
    if row is None:
        return None
    shown, value, profile_common = row[2], row[3], row[4]
    unresolvable = profile_common is None or is_yes(profile_common)
    if str(shown).upper() == _INHERITED and not own_container and unresolvable:
        return None
    return str(value or "").strip().upper() == "UNLIMITED"


def _locked_by_somebody(
    status: str, *, lock_time_unlimited: bool | None, limit: Limit, failed: int | None
) -> bool | None:
    """Whether somebody set the lock this status shows; ``None`` where Oracle cannot say.

    A lockout after failed logins reads ``LOCKED(TIMED)``, so a ``LOCKED``
    component is a lock somebody set, except under a ``PASSWORD_LOCK_TIME`` of
    ``UNLIMITED``. There Oracle shows the lockout as ``LOCKED``, and
    ``SYS.USER$.ASTATUS`` is 8 for both (measured on 23.26.3.0.0). The
    maintainer decided (#1447) that a ``LOCKED`` account whose failed-login
    count has reached the profile's ``FAILED_LOGIN_ATTEMPTS`` is taken as a
    lockout there, and that where the count or the limit cannot be read, the
    answer is unknown. A lock time that cannot be read is treated as possibly
    ``UNLIMITED``.
    """
    if not deliberately_locked(status):
        return False
    if lock_time_unlimited is False or limit == "unlimited":
        return True
    if limit is None or failed is None:
        return None
    return failed < limit


#: Why no failed-login count was read, where the optional grant was not made.
_NO_GRANT = (
    "the failed-login count is in SYS.USER$; GRANT SELECT ON SYS.USER$ to the "
    "service account to read it"
)


def fetch_all(cursor: Cursor) -> list[Any]:
    """Every row of the statement ``cursor`` just ran, for :func:`first_shape`."""
    return list(cursor.fetchall())


def _lcounts(cursor: Cursor) -> tuple[dict[str, int | None], str | None]:
    """Every user's ``LCOUNT``, by name as ``SYS.USER$`` spells it.

    A ``NULL`` count is kept as ``None``, so the caller can tell it from a
    missing row. The capability probe found the table readable. If the read is
    refused now, each count is ``None`` with the server's words as the reason.
    Any other failure raises.
    """
    try:
        cursor.execute(SURVEY_LCOUNT_QUERY)
        rows = cursor.fetchall()
    except Exception as error:  # noqa: BLE001 -- classified, never swallowed
        diagnosis = from_error(error)
        if diagnosis.code not in _GRANT_CODES:
            raise diagnosis.as_error() from error
        return {}, f"SYS.USER$ could not be read: {diagnosis.code}: {diagnosis.message}"
    return {str(name): None if count is None else int(count) for name, count in rows}, None


def _limit(row: Any, profile: str, resource: str, own_container: bool) -> tuple[Limit, str | None]:
    """One limit from :data:`SURVEY_LIMITS_QUERY`'s row, or ``None`` and why.

    Outside ``CDB$ROOT`` and a non-CDB, a ``DEFAULT`` limit is ``None`` on a
    common profile, and on a profile whose ``COMMON`` the narrowed shape could
    not read.
    """
    if row is None:
        return None, f"DBA_PROFILES has no {resource} for profile {profile}"
    shown, value, profile_common = row[2], row[3], row[4]
    if str(shown).upper() == _INHERITED and not own_container:
        if profile_common is None:
            return None, (
                f"{resource} on profile {profile} is DEFAULT, and whether the profile "
                f"is common, so that the DEFAULT profile in {_ROOT} applies, could not "
                "be read"
            )
        if is_yes(profile_common):
            return None, (
                f"{resource} on common profile {profile} is DEFAULT, which follows the "
                f"DEFAULT profile in {_ROOT}, and this container cannot read it"
            )
    text = str(value or "").strip().upper()
    if text == "UNLIMITED":
        return "unlimited", None
    if text.isdigit():
        return int(text), None
    return None, f"{resource} on profile {profile} reads {value!r}, not a whole number"


def stored_verifiers(cursor: Cursor, name: str) -> str | None:
    """``SYS.USER$.SPARE4`` for ``name``, or ``None`` where it could not be read.

    Bound unchanged, for :func:`failed_logins`' reason. ``None`` covers both the
    grant being absent and an empty column; the caller checks the capability
    first, so here it means the account has no verifier stored there at all.
    """
    row = read(cursor, SPARE4_QUERY, name=name)
    return str(row[0]) if row and row[0] is not None else None
