"""The PostgreSQL privilege audit, from scripted catalog rows. Tier 0."""

from __future__ import annotations

from typing import Any

from sopuli.driver.postgres.privileges import (
    GRANT_OPTIONS_ROW,
    MANAGED_ROLES,
    MEMBERSHIPS,
    SELF_ROW,
    USABLE_EDGE,
    ManagedRole,
    audit,
    classify,
)

USER = "sopuli_admin"


def _classify(
    *,
    attributes: frozenset[str] = frozenset({"CREATEROLE"}),
    grant_options: bool = True,
    memberships: frozenset[str] = frozenset(),
    accounts: tuple[str, ...] = ("acme_web_user",),
    managed: tuple[ManagedRole, ...] = (ManagedRole("acme_web_user", True, False, False),),
) -> Any:
    return classify(
        user=USER,
        attributes=attributes,
        grant_options=grant_options,
        memberships=memberships,
        accounts=accounts,
        managed=managed,
    )


def test_the_documented_install_from_16_holds_everything_and_nothing_more() -> None:
    found = _classify()

    assert found.held == ("ADMIN OPTION ON acme_web_user", "CREATEROLE")
    assert found.missing == ()
    assert found.over_granted == ()
    assert found.complete


def test_a_role_without_admin_option_is_missing_it_from_16() -> None:
    found = _classify(managed=(ManagedRole("acme_web_user", False, False, False),))

    assert found.missing == ("ADMIN OPTION ON acme_web_user",)
    assert "02-postgres-privileges.md section 2" in found.hint
    assert USER in found.hint


def test_a_grant_that_inherits_or_sets_is_over_granted_with_its_remedy() -> None:
    found = _classify(managed=(ManagedRole("acme_web_user", True, True, True),))

    assert found.over_granted == (
        "INHERIT TRUE ON acme_web_user",
        "SET TRUE ON acme_web_user",
    )
    (remedy,) = found.remedies
    assert remedy.startswith(f"GRANT acme_web_user TO {USER} WITH INHERIT FALSE, SET FALSE ")


def test_before_16_createrole_alone_is_the_install() -> None:
    """No grant options means the server does not require ADMIN OPTION."""
    found = _classify(
        grant_options=False, managed=(ManagedRole("acme_web_user", False, False, False),)
    )

    assert found.held == ("CREATEROLE",)
    assert found.missing == ()
    assert found.over_granted == ()


def test_before_16_any_membership_in_a_managed_role_is_over_granted() -> None:
    found = _classify(
        grant_options=False, managed=(ManagedRole("acme_web_user", True, True, True),)
    )

    assert found.over_granted == ("MEMBER OF acme_web_user",)
    assert "CREATEROLE alone changes its password" in found.remedies[0]


def test_a_declared_role_the_cluster_lacks_is_missing_and_not_an_error() -> None:
    found = _classify(accounts=("acme_web_user", "acme_batch_user"))

    assert found.missing == ("role acme_batch_user, which does not exist",)


def test_the_forbidden_attributes_and_built_in_roles_are_over_granted() -> None:
    found = _classify(
        attributes=frozenset({"CREATEROLE", "REPLICATION", "BYPASSRLS"}),
        memberships=frozenset({"pg_read_all_stats", "pg_monitor", "acme_reader"}),
    )

    assert found.over_granted == ("BYPASSRLS", "REPLICATION", "pg_read_all_stats")
    assert found.roles == ("acme_reader", "pg_monitor", "pg_read_all_stats")


def test_an_account_without_createrole_is_missing_it() -> None:
    found = _classify(attributes=frozenset())

    assert found.held == ("ADMIN OPTION ON acme_web_user",)
    assert found.missing == ("CREATEROLE",)


class _Cursor:
    """Answers the four reads in order and records what was sent."""

    def __init__(self, grant_options: bool) -> None:
        self.grant_options = grant_options
        self.sent: list[tuple[str, Any]] = []

    def execute(self, query: str, params: Any = None, /) -> None:
        self.sent.append((query, params))

    def fetchone(self) -> Any:
        query = self.sent[-1][0]
        if query == SELF_ROW:
            return (USER, False, True, False, False)
        assert query == GRANT_OPTIONS_ROW
        return (self.grant_options,)

    def fetchall(self) -> Any:
        if self.sent[-1][0] == MANAGED_ROLES:
            return [("acme_web_user", True, False, False)]
        return [("pg_signal_backend",)]


def test_the_audit_reads_the_catalog_and_classifies_it() -> None:
    cursor = _Cursor(grant_options=True)

    found = audit(cursor, ("acme_web_user",))

    assert [query for query, _ in cursor.sent] == [
        SELF_ROW,
        GRANT_OPTIONS_ROW,
        MEMBERSHIPS.format(edge=USABLE_EDGE),
        MANAGED_ROLES,
    ]
    assert cursor.sent[-1][1] == ("SET", ["acme_web_user"])
    assert found.held == ("ADMIN OPTION ON acme_web_user", "CREATEROLE")
    assert found.over_granted == ("pg_signal_backend",)


def test_before_16_the_walk_follows_every_grant_and_asks_for_membership() -> None:
    cursor = _Cursor(grant_options=False)

    audit(cursor, ("acme_web_user",))

    assert cursor.sent[2][0] == MEMBERSHIPS.format(edge="")
    assert cursor.sent[-1][1] == ("MEMBER", ["acme_web_user"])


def test_with_no_declared_account_the_roles_are_not_read() -> None:
    cursor = _Cursor(grant_options=True)

    found = audit(cursor, ())

    assert MANAGED_ROLES not in [query for query, _ in cursor.sent]
    assert found.held == ("CREATEROLE",)
