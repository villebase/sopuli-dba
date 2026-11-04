"""MySQL roles, for a `role:` rule in `personal_accounts:` (#1225). Tier 0.

A MySQL role is an account: a user name and a host, a row in ``mysql.user``.
``CREATE ROLE dev_role`` makes ``dev_role@%``. So a `role:` rule names its
host, as an account does (decision 4 of #1225), and is compared as an account
is: the user exactly, the host without ASCII case.

**Who holds a role.** An account holds a role granted to it, or granted to a
role it holds, followed to the end, whether the role is active or not: the
account can ``SET ROLE`` to any of them. :mod:`~sopuli.driver.mysql.admin`
reads roles by the same rule for guardrail 9. ``mysql.role_edges`` records
each grant, and the tool account is granted ``SELECT`` on it
(``02-mysql-privileges.md`` §2.1).

**A mandatory role is refused** (decision 5 of #1225). The server grants every
role in ``@@global.mandatory_roles`` to every account, with no row in
``role_edges``. A rule naming one would admit every account on the server,
and a rule that admits every account is not a whitelist. So is a role a
mandatory role holds: every account reaches it through the mandatory role.
:func:`resolve` refuses both, with exit 9, naming the setting. For the same
reason, :func:`granted` does not follow mandatory roles: an account's roles
are the ones granted to it.
"""

from __future__ import annotations

from sopuli.driver.mysql import accounts, admin
from sopuli.driver.mysql_family.accounts import Principal, split
from sopuli.driver.protocol import Cursor, DriverError
from sopuli.exit_codes import ExitCode

#: The accounts and roles a role is granted to: one step down.
MEMBERS = "select TO_USER, TO_HOST from mysql.role_edges where FROM_USER = %s and FROM_HOST = %s"


class MandatoryRoleError(DriverError):
    """A `role:` rule names a role every account holds (decision 5 of #1225).

    ``config`` and exit 9: the fix is in the config or the server's setting,
    and running again changes nothing."""

    category = "config"
    exit_code = ExitCode.CONFIG_INVALID

    def __init__(self, role: str, *, through: str, target: str) -> None:
        how = "is" if role == through else f"is held by {through}, which is"
        super().__init__(
            f'target "{target}": role "{role}" {how} in @@global.mandatory_roles, so every '
            "account holds it, and a `role:` rule naming it would admit every account",
            hint=(
                "name a role that only the people the rule is for hold, or list the "
                "accounts under `accounts:`"
            ),
        )


def resolve(cursor: Cursor, role: str, *, target: str) -> str | None:
    """The role ``role`` names on ``target``, as ``mysql.user`` spells it, or
    ``None`` where there is none.

    ``role`` is ``user@host``; the config refuses a bare name first, and
    :func:`~sopuli.driver.mysql_family.accounts.split` refuses one again.
    Refuses a mandatory role, and a role a mandatory role holds, with
    :class:`MandatoryRoleError`.
    """
    user, host = split(role)
    found = accounts.find(accounts.read(cursor, [user])[user], host)
    if found is None:
        return None
    _refuse_mandatory(cursor, Principal(found.user, found.host), target=target)
    return found.name


def _refuse_mandatory(cursor: Cursor, role: Principal, *, target: str) -> None:
    for mandatory in admin.read_mandatory_roles(cursor):
        if role.key() in admin.follow(cursor, [mandatory], admin.ROLE_EDGES):
            raise MandatoryRoleError(str(role), through=str(mandatory), target=target)


def granted(cursor: Cursor, account: Principal) -> tuple[str, ...]:
    """Every role ``account`` holds by a grant, ``user@host`` in the server's
    spelling, sorted. Mandatory roles are not followed (module docstring)."""
    reached = admin.follow(cursor, [account], admin.ROLE_EDGES)
    reached.pop(account.key(), None)
    return tuple(str(role) for role in sorted(reached.values()))


def members_of(cursor: Cursor, role: str) -> tuple[str, ...]:
    """Every account that holds ``role``, directly or through another role,
    ``user@host`` in the server's spelling, sorted.

    ``role`` is the spelling :func:`resolve` gave back. A role in the chain is
    listed too: it is an account, and an account holds what is granted to it,
    so a verb that describes it admits it. The listing must show exactly the
    accounts a verb admits, and a verb admits by :func:`granted`, which follows
    the same grants the other way.
    """
    user, host = split(role)
    start = Principal(user, host)
    reached = admin.follow(cursor, [start], MEMBERS)
    reached.pop(start.key(), None)
    return tuple(str(member) for member in sorted(reached.values()))
