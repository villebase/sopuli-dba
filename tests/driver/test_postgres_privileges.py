"""The PostgreSQL privilege audit, from scripted catalog rows. Tier 0."""

from __future__ import annotations

from typing import Any

from sopuli.driver.postgres.privileges import (
    DIRECT_MEMBER,
    DIRECT_USABLE,
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
WEB = "acme_web_user"


def _classify(
    *,
    attributes: frozenset[str] = frozenset({"CREATEROLE"}),
    grant_options: bool = True,
    memberships: dict[str, bool] | None = None,
    accounts: tuple[str, ...] = (WEB,),
    managed: tuple[ManagedRole, ...] = (ManagedRole(WEB, True, False, False),),
) -> Any:
    return classify(
        user=USER,
        attributes=attributes,
        grant_options=grant_options,
        memberships={WEB: False} if memberships is None else memberships,
        accounts=accounts,
        managed=managed,
    )


def test_the_documented_install_from_16_holds_everything_and_nothing_more() -> None:
    found = _classify()

    assert found.held == (f"ADMIN OPTION ON {WEB}", "CREATEROLE")
    assert found.missing == ()
    assert found.over_granted == ()
    assert found.roles == (WEB,), "an ADMIN-only grant is still a role held"
    assert found.complete


def test_a_role_without_admin_option_is_missing_it_from_16() -> None:
    found = _classify(managed=(ManagedRole(WEB, False, False, False),))

    assert found.missing == (f"ADMIN OPTION ON {WEB}",)
    assert "02-postgres-privileges.md section 2" in found.hint
    assert USER in found.hint


def test_a_grant_that_inherits_or_sets_is_over_granted_with_its_remedy() -> None:
    found = _classify(managed=(ManagedRole(WEB, True, True, True),))

    assert found.over_granted == (f"INHERIT TRUE ON {WEB}", f"SET TRUE ON {WEB}")
    (remedy,) = found.remedies
    assert remedy.startswith(f'GRANT "{WEB}" TO "{USER}" WITH INHERIT FALSE, SET FALSE ')


def test_a_remedy_quotes_the_names_it_puts_in_a_statement() -> None:
    found = classify(
        user='Tool"Admin',
        attributes=frozenset({"CREATEROLE"}),
        grant_options=True,
        memberships={},
        accounts=("Acme-Web",),
        managed=(ManagedRole("Acme-Web", True, True, False),),
    )

    assert found.remedies[0].startswith('GRANT "Acme-Web" TO "Tool""Admin" ')


def test_a_role_reached_through_another_role_names_no_statement() -> None:
    """The direct grant is not what gives it, so changing that grant fixes nothing."""
    found = _classify(managed=(ManagedRole(WEB, True, True, True, direct=False),))

    assert found.over_granted == (f"INHERIT TRUE ON {WEB}", f"SET TRUE ON {WEB}")
    assert "through another role" in found.remedies[0]
    assert "GRANT" not in found.remedies[0]


def test_before_16_createrole_alone_is_the_install() -> None:
    """No grant options means the server does not require ADMIN OPTION."""
    found = _classify(grant_options=False, managed=(ManagedRole(WEB, False, False, False),))

    assert found.held == ("CREATEROLE",)
    assert found.missing == ()
    assert found.over_granted == ()


def test_before_16_any_membership_in_a_managed_role_is_over_granted() -> None:
    found = _classify(grant_options=False, managed=(ManagedRole(WEB, True, True, True),))

    assert found.over_granted == (f"MEMBER OF {WEB}",)
    assert found.remedies[0].startswith(f'REVOKE "{WEB}" FROM "{USER}": CREATEROLE alone')


def test_a_declared_role_the_cluster_lacks_is_reported_and_not_an_error() -> None:
    found = _classify(accounts=(WEB, "acme_batch_user"))

    assert found.missing == ("ADMIN OPTION ON acme_batch_user",)
    assert found.remedies == (
        "acme_batch_user does not exist on this cluster, and the tool does not create roles",
    )


def test_before_16_a_role_the_cluster_lacks_needs_no_grant() -> None:
    found = _classify(grant_options=False, accounts=(WEB, "acme_batch_user"), managed=())

    assert found.missing == ()
    assert "acme_batch_user does not exist" in found.remedies[-1]


def test_the_forbidden_attributes_and_usable_built_in_roles_are_over_granted() -> None:
    found = _classify(
        attributes=frozenset({"CREATEROLE", "REPLICATION", "BYPASSRLS"}),
        memberships={
            "pg_monitor": True,
            "pg_read_all_stats": True,
            "pg_read_all_data": False,
            "acme_reader": True,
        },
    )

    assert found.over_granted == ("BYPASSRLS", "REPLICATION", "pg_monitor", "pg_read_all_stats")
    assert found.roles == ("acme_reader", "pg_monitor", "pg_read_all_data", "pg_read_all_stats")


def test_a_superuser_is_one_finding_and_not_one_per_managed_role() -> None:
    """pg_has_role is true for every role when the account is a superuser."""
    found = _classify(
        attributes=frozenset({"SUPERUSER", "CREATEROLE"}),
        managed=(ManagedRole(WEB, True, True, True),),
    )

    assert found.over_granted == ("SUPERUSER",)
    assert found.remedies == ()


def test_an_account_without_createrole_is_missing_it() -> None:
    found = _classify(attributes=frozenset())

    assert found.held == (f"ADMIN OPTION ON {WEB}",)
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
        if self.sent[-1][1] is not None:
            return [(WEB, True, False, False, False)]
        return [("pg_signal_backend", True), (WEB, False)]


def test_the_audit_reads_the_catalog_and_classifies_it() -> None:
    cursor = _Cursor(grant_options=True)

    found = audit(cursor, (WEB,))

    assert [query for query, _ in cursor.sent] == [
        SELF_ROW,
        GRANT_OPTIONS_ROW,
        MEMBERSHIPS.format(edge=USABLE_EDGE),
        MANAGED_ROLES.format(direct=DIRECT_USABLE),
    ]
    assert cursor.sent[-1][1] == ("SET", [WEB])
    assert found.held == (f"ADMIN OPTION ON {WEB}", "CREATEROLE")
    assert found.over_granted == ("pg_signal_backend",)
    assert found.roles == (WEB, "pg_signal_backend")


def test_before_16_the_walk_follows_every_grant_and_asks_for_membership() -> None:
    cursor = _Cursor(grant_options=False)

    audit(cursor, (WEB,))

    assert cursor.sent[2][0] == MEMBERSHIPS.format(edge="true")
    assert cursor.sent[-1] == (MANAGED_ROLES.format(direct=DIRECT_MEMBER), ("MEMBER", [WEB]))


def test_with_no_declared_account_the_roles_are_not_read() -> None:
    cursor = _Cursor(grant_options=True)

    found = audit(cursor, ())

    assert len(cursor.sent) == 3
    assert found.held == ("CREATEROLE",)
