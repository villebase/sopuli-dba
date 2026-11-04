"""Resolving a `role:` rule on MySQL, on a scripted server. Tier 0.

The fake holds ``mysql.user`` rows, ``mysql.role_edges`` grants and
``@@global.mandatory_roles``, and answers the driver's reads of them as the
server does: the user by case, the host without ASCII case.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

import pytest

from sopuli.exit_codes import ExitCode

roles = pytest.importorskip("sopuli.driver.mysql.roles")
admin = pytest.importorskip("sopuli.driver.mysql.admin")
family = pytest.importorskip("sopuli.driver.mysql_family.accounts")

Principal = family.Principal


def _fold(host: str) -> str:
    return host.translate(str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"))


class Server:
    """``users`` are ``user@host``; each edge grants its first to its second."""

    def __init__(
        self, users: list[str], edges: Sequence[tuple[str, str]] = (), mandatory: str = ""
    ) -> None:
        self.users = [family.split(name) for name in users]
        self.edges = [(family.split(role), family.split(to)) for role, to in edges]
        self.mandatory = mandatory
        self._result: Any = None

    def execute(self, query: str, args: Any = None, /) -> None:
        if query.startswith("select User,"):
            self._result = [
                (user, host, "caching_sha2_password", "Y", "N", None, None)
                for user, host in self.users
                if user in args
            ]
        elif query == admin.MANDATORY_ROLES:
            self._result = [(self.mandatory,)]
        elif query == admin.ROLE_EDGES:
            self._result = [role for role, to in self.edges if self._is(to, args)]
        elif query == roles.MEMBERS:
            self._result = [to for role, to in self.edges if self._is(role, args)]
        else:
            raise AssertionError(f"unexpected query: {query}")

    @staticmethod
    def _is(principal: tuple[str, str], args: tuple[str, str]) -> bool:
        return principal[0] == args[0] and _fold(principal[1]) == _fold(args[1])

    def fetchone(self) -> Any:
        return self._result[0] if self._result else None

    def fetchall(self) -> Any:
        return self._result


# ------------------------------------------------------------------ resolve ---


def test_a_role_resolves_to_the_servers_spelling() -> None:
    """The host compares without case, and the server's spelling comes back."""
    server = Server(["dev_role@localhost"])

    assert roles.resolve(server, "dev_role@LOCALHOST", target="t") == "dev_role@localhost"


def test_a_role_whose_user_differs_by_case_is_another_role() -> None:
    """`DEV_ROLE@%` and `dev_role@%` are two roles (#1202, decision 3)."""
    server = Server(["DEV_ROLE@%"])

    assert roles.resolve(server, "dev_role@%", target="t") is None


def test_a_role_that_does_not_exist_is_none() -> None:
    assert roles.resolve(Server(["dev_role@localhost"]), "dev_role@%", target="t") is None


def test_a_bare_role_is_refused_by_the_driver_too() -> None:
    with pytest.raises(family.BareAccountError):
        roles.resolve(Server([]), "dev_role", target="t")


def test_a_mandatory_role_is_refused() -> None:
    """Every account holds it, so a rule naming it admits every account
    (decision 5 of #1225)."""
    server = Server(["dev_role@%"], mandatory="dev_role")

    with pytest.raises(roles.MandatoryRoleError) as caught:
        roles.resolve(server, "dev_role@%", target="mysql-dev")

    assert caught.value.exit_code == ExitCode.CONFIG_INVALID
    assert caught.value.category == "config"
    assert '"dev_role@%" is in @@global.mandatory_roles' in str(caught.value)
    assert 'target "mysql-dev"' in str(caught.value)


def test_a_role_a_mandatory_role_holds_is_refused() -> None:
    """Every account reaches it through the mandatory role."""
    server = Server(
        ["base@%", "dev_role@%"], edges=[("dev_role@%", "base@%")], mandatory="`base`@`%`"
    )

    with pytest.raises(roles.MandatoryRoleError) as caught:
        roles.resolve(server, "dev_role@%", target="t")

    assert "is held by base@%, which is in @@global.mandatory_roles" in str(caught.value)


def test_a_role_beside_a_mandatory_one_resolves() -> None:
    server = Server(["base@%", "dev_role@%"], mandatory="base@%")

    assert roles.resolve(server, "dev_role@%", target="t") == "dev_role@%"


# --------------------------------------------------------------- members_of ---


def test_members_are_every_account_below_the_role_through_any_chain() -> None:
    """A role granted to a role is held by that role's members too, and the
    role in between is listed: it is an account a verb would admit."""
    server = Server(
        ["dev_role@%", "team@%", "alice@%", "bob@10.%"],
        edges=[("dev_role@%", "team@%"), ("team@%", "alice@%"), ("dev_role@%", "bob@10.%")],
    )

    assert roles.members_of(server, "dev_role@%") == ("alice@%", "bob@10.%", "team@%")


def test_members_follow_a_cycle_once() -> None:
    server = Server(
        ["a@%", "b@%", "carol@%"],
        edges=[("a@%", "b@%"), ("b@%", "a@%"), ("b@%", "carol@%")],
    )

    assert roles.members_of(server, "a@%") == ("b@%", "carol@%")


def test_a_role_nobody_holds_has_no_members() -> None:
    assert roles.members_of(Server(["dev_role@%"]), "dev_role@%") == ()


# ------------------------------------------------------------------ granted ---


def test_granted_follows_grants_and_not_mandatory_roles() -> None:
    """The other direction of `members_of`, so a verb admits exactly the
    accounts the listing shows. A mandatory role is not followed."""
    server = Server(
        ["dev_role@%", "team@%", "alice@%", "base@%"],
        edges=[("dev_role@%", "team@%"), ("team@%", "alice@%")],
        mandatory="base@%",
    )

    assert roles.granted(server, Principal("alice", "%")) == ("dev_role@%", "team@%")
