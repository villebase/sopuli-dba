"""MariaDB roles, for a `role:` rule in `personal_accounts:` (#1272). Tier 0.

A MariaDB role has no host. ``CREATE ROLE dev_role`` makes a row of the
``mysql.user`` view with an empty host and ``is_role = 'Y'``, and
``mysql.roles_mapping`` names it without one
(``05_identity_grants_probe.py``, TG7). So a `role:` rule names the role
alone, and the name is compared exactly, as a user name is.

**Who holds a role.** An account holds a role granted to it, or granted to a
role it holds, followed to the end, whether the role is active or not: the
account can ``SET ROLE`` to it, and gets a nested role's privileges through it
(``10_role_reads_probe.py``, RR2). ``mysql.roles_mapping`` records each grant
as (``Host``, ``User``, ``Role``); a role that holds a role is a row whose
``User`` is the role and whose ``Host`` is empty (RR1). The tool account reads
it by §2.1's grants. A role cannot log in, so the members are the accounts
alone; a role in the chain is followed, not listed.

**The account that created a role holds it.** ``CREATE ROLE`` grants the role
to its creator, with ``ADMIN OPTION`` (a ``roles_mapping`` row with
``Admin_option = 'Y'``; seen on 11.8.9), and the creator can ``SET ROLE`` to
it. So that account is a member, as MariaDB has it. Where it is an
administrator, check 9 refuses to change it.

**A role ``PUBLIC`` reaches is refused.** Every account holds ``PUBLIC``,
always active, and what a role granted to ``PUBLIC`` holds every account uses
(RR3). A rule naming such a role would admit every account on the server, and
a rule that admits every account is not a whitelist. MySQL refuses a mandatory
role for the same reason (decision 5 of #1225). :func:`resolve` refuses it,
with exit 9, naming the role ``PUBLIC`` reaches it through.
"""

from __future__ import annotations

from sopuli.driver.mariadb.admin import PUBLIC, ROLE_EDGES
from sopuli.driver.mysql_family.accounts import Principal, text
from sopuli.driver.mysql_family.grant_tables import follow
from sopuli.driver.protocol import Cursor, DriverError
from sopuli.exit_codes import ExitCode

#: Whether a role of that name exists.
ROLE_ROW = "select User from mysql.user where is_role = 'Y' and User = %s"
#: The accounts and roles a role is granted to: one step down. A role is at
#: host '', and :func:`~sopuli.driver.mysql_family.grant_tables.follow` passes
#: it with its host, which the second placeholder takes.
MEMBERS = "select User, Host from mysql.roles_mapping where Role = %s and '' = %s"
#: Every role on the server, to tell a role reached in the chain from an account.
ROLE_NAMES = "select User from mysql.user where is_role = 'Y'"


class PublicRoleError(DriverError):
    """A `role:` rule names a role every account holds, through ``PUBLIC``.

    ``config`` and exit 9: the fix is in the config or the server's grants,
    and running again changes nothing."""

    category = "config"
    exit_code = ExitCode.CONFIG_INVALID

    def __init__(self, role: str, *, through: str, target: str) -> None:
        how = (
            "is granted to PUBLIC"
            if through == role
            else f"is held by {through}, which is granted to PUBLIC"
        )
        super().__init__(
            f'target "{target}": role "{role}" {how}, so every account holds it, and a '
            "`role:` rule naming it would admit every account",
            hint=(
                "name a role that only the people the rule is for hold, or list the "
                "accounts under `accounts:`"
            ),
        )


def resolve(cursor: Cursor, role: str, *, target: str) -> str | None:
    """The role named ``role`` on ``target``, or ``None`` where there is none.
    Refuses a role ``PUBLIC`` reaches with :class:`PublicRoleError`."""
    cursor.execute(ROLE_ROW, (role,))
    row = cursor.fetchone()
    if row is None:
        return None
    found = text(row[0])
    # PUBLIC's roles, followed to the end: a chain of grants downward from it.
    reached = follow(cursor, [PUBLIC], ROLE_EDGES)
    if (found, "") in reached:
        raise PublicRoleError(found, through=_holder(cursor, found), target=target)
    return found


def _holder(cursor: Cursor, role: str) -> str:
    """The role granted to ``PUBLIC`` that reaches ``role``: ``role`` itself
    where it is granted to ``PUBLIC`` directly."""
    cursor.execute(ROLE_EDGES, (PUBLIC.user, PUBLIC.host))
    for direct, _ in cursor.fetchall():
        name = text(direct)
        if name == role or (role, "") in follow(cursor, [Principal(name, "")], ROLE_EDGES):
            return name
    return role  # pragma: no cover -- resolve found the role through PUBLIC


def members_of(cursor: Cursor, role: str) -> tuple[str, ...]:
    """Every account that holds ``role``, directly or through another role,
    ``user@host`` in the server's spelling, sorted. ``role`` is the spelling
    :func:`resolve` gave back. A role in the chain is followed and not listed:
    it cannot log in."""
    start = Principal(role, "")
    reached = follow(cursor, [start], MEMBERS)
    reached.pop(start.key(), None)
    cursor.execute(ROLE_NAMES)
    roles = {text(name) for (name,) in cursor.fetchall()}
    accounts = (
        member for member in reached.values() if not (member.host == "" and member.user in roles)
    )
    return tuple(str(member) for member in sorted(accounts))
