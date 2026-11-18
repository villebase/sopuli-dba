"""A `personal_accounts:` rule's `role:` on SQL Server names a server role,
whose members are followed through nested server roles (#1554, Q6). Tier 0:
the catalog is built here, as the tool login would read it. The catalog
tests need no vendor client; the session tests skip without pyodbc."""

from __future__ import annotations

from typing import Any

import pytest

from sopuli.config.model import ExpandedTarget, Target
from sopuli.driver.mssql.admin import ROLE_TYPE, Catalog, Principal
from sopuli.driver.protocol import DriverError

LOGIN = "S"

#: acme_staff holds acme_ops, which holds jdoe; asmith holds acme_staff
#: directly; acme_other is a login in no role.
PRINCIPALS = [
    Principal(principal_id=1, name="public", type=ROLE_TYPE),
    Principal(principal_id=300, name="acme_staff", type=ROLE_TYPE, owner_id=10),
    Principal(principal_id=301, name="acme_ops", type=ROLE_TYPE, owner_id=10),
    Principal(principal_id=10, name="sopuli_svc", type=LOGIN),
    Principal(principal_id=400, name="acme_jdoe", type=LOGIN),
    Principal(principal_id=401, name="acme_asmith", type=LOGIN),
    Principal(principal_id=402, name="acme_other", type=LOGIN),
]
MEMBERSHIPS = [(300, 301), (301, 400), (300, 401)]


def catalog() -> Catalog:
    return Catalog.read(PRINCIPALS, MEMBERSHIPS, [])


def test_a_role_is_found_by_upper() -> None:
    [found] = catalog().server_roles("ACME_STAFF")
    assert found.name == "acme_staff"
    assert catalog().server_roles("acme_nobody") == ()
    assert catalog().server_roles("acme_jdoe") == (), "a login is not a role"


def test_members_are_followed_through_nested_roles() -> None:
    members = catalog().members(300)
    assert [one.name for one in members] == ["acme_asmith", "acme_jdoe"]
    assert [one.name for one in catalog().members(301)] == ["acme_jdoe"]


def test_a_cycle_of_roles_ends() -> None:
    """The server refuses a cycle, but a read is not trusted to be free of one."""
    looped = Catalog.read(PRINCIPALS, [*MEMBERSHIPS, (301, 300)], [])
    assert [one.name for one in looped.members(301)] == ["acme_asmith", "acme_jdoe"]


def test_a_login_holds_every_role_above_it_upper_cased() -> None:
    """Upper-cased, as `UserState.roles` holds roles on every product."""
    assert catalog().roles_of(400) == {"ACME_OPS", "ACME_STAFF"}
    assert catalog().roles_of(401) == {"ACME_STAFF"}
    assert catalog().roles_of(402) == frozenset()


def test_only_sql_logins_are_members() -> None:
    """A Windows login has no password the tool sets, so the rule does not
    name it, and the listing does not fail on it every run."""
    windows = Principal(principal_id=500, name="EXAMPLE\\dbas", type="G")
    read = Catalog.read([*PRINCIPALS, windows], [*MEMBERSHIPS, (301, 500)], [])
    assert [one.name for one in read.members(300)] == ["acme_asmith", "acme_jdoe"]


def opened(read: Catalog) -> Any:
    pytest.importorskip("pyodbc")
    from sopuli.driver.mssql.session import MssqlSession

    one: Any = MssqlSession(
        connection=None,
        target=ExpandedTarget(target=Target(name="mssql-dev", type="mssql", dsn="127.0.0.1:1433")),
    )
    one.scope = lambda: None
    one._catalog = read
    return one


def test_the_session_resolves_a_role_and_lists_its_logins() -> None:
    one = opened(catalog())

    assert one.resolve_role("Acme_Staff") == "acme_staff"
    assert one.resolve_role("acme_nobody") is None
    assert one.accounts_matching(role="acme_staff") == ("acme_asmith", "acme_jdoe")
    assert one.accounts_matching(role="acme_nobody") == ()


def test_two_roles_in_two_cases_are_refused_as_ambiguous() -> None:
    """A case-sensitive server can hold both. A verb compares by `upper()`
    and would admit the members of both, so the listing refuses rather than
    show one role's."""
    other = Principal(principal_id=302, name="ACME_STAFF", type=ROLE_TYPE)
    one = opened(Catalog.read([*PRINCIPALS, other], MEMBERSHIPS, []))

    with pytest.raises(DriverError, match="2 server roles"):
        one.resolve_role("acme_staff")


def test_public_is_refused_because_every_login_holds_it() -> None:
    """As MySQL refuses a mandatory role: the rule would admit every login."""
    one = opened(catalog())
    from sopuli.driver.mssql.session import PublicServerRoleError

    with pytest.raises(PublicServerRoleError) as caught:
        one.resolve_role("PUBLIC")
    assert caught.value.exit_code == 9
    with pytest.raises(PublicServerRoleError):
        one.accounts_matching(role="public")
