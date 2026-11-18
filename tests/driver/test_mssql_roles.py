"""A `personal_accounts:` rule's `role:` on SQL Server names a server role,
whose members are followed through nested server roles (#1554, Q6). Tier 0:
the catalog is built here, as the tool login would read it."""

from __future__ import annotations

from typing import Any

import pytest

from sopuli.driver.mssql.admin import ROLE_TYPE, Catalog, Principal

pytest.importorskip("pyodbc")
session = pytest.importorskip("sopuli.driver.mssql.session")

from sopuli.config.model import ExpandedTarget, Target  # noqa: E402

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


def test_a_role_is_found_by_upper_and_spelled_as_the_server_does() -> None:
    found = catalog().server_role("ACME_STAFF")
    assert found is not None
    assert found.name == "acme_staff"
    assert catalog().server_role("acme_nobody") is None
    assert catalog().server_role("acme_jdoe") is None, "a login is not a role"


def test_members_are_followed_through_nested_roles() -> None:
    members = catalog().members(300)
    assert [one.name for one in members] == ["acme_asmith", "acme_jdoe"]
    assert [one.name for one in catalog().members(301)] == ["acme_jdoe"]


def test_a_cycle_of_roles_ends() -> None:
    """The server refuses a cycle, but a read is not trusted to be free of one."""
    looped = Catalog.read(PRINCIPALS, [*MEMBERSHIPS, (301, 300)], [])
    assert [one.name for one in looped.members(301)] == ["acme_asmith", "acme_jdoe"]


def test_a_login_holds_every_role_above_it() -> None:
    assert catalog().roles_of(400) == {"acme_ops", "acme_staff"}
    assert catalog().roles_of(401) == {"acme_staff"}
    assert catalog().roles_of(402) == frozenset()


def opened(read: Catalog) -> Any:
    one = session.MssqlSession(
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
