"""Guardrail 9 on SQL Server, over constructed catalogs (`02-mssql-privileges.md` §5).

Each path of probe 12 (`12_guardrail_paths_probe.py`) as rows of
`sys.server_principals`, `sys.server_role_members` and
`sys.server_permissions`, with ids as the server gives them: `public` is 2,
`sysadmin` 3 and `securityadmin` 4.
"""

from __future__ import annotations

from typing import Any

import pytest

from sopuli.driver.guardrails import GLOBAL_PRIVILEGE, review, server_refusal
from sopuli.driver.mssql.admin import (
    DENIED_SECURITY,
    MEMBERSHIPS,
    MISSING_GRANT,
    MISSING_LOGIN,
    MISSING_PUBLIC,
    PARTIAL_READ,
    PERMISSIONS,
    PRINCIPAL_CLASS,
    PRINCIPALS,
    READS,
    SERVER_CLASS,
    VIEW_DEFINITIONS,
    Assessment,
    Catalog,
    Permission,
    Principal,
    assess,
    read_catalog,
    refused_roles,
)
from sopuli.driver.protocol import UserState

PUBLIC = Principal(2, "public", "R")
SYSADMIN = Principal(3, "sysadmin", "R")
SECURITYADMIN = Principal(4, "securityadmin", "R")
SERVERADMIN = Principal(5, "serveradmin", "R")
SA = Principal(1, "sa", "S")
APP = Principal(300, "acme_app_user", "S")
OTHER = Principal(301, "acme_batch_user", "S")
OPS = Principal(400, "acme_ops", "R", owner_id=1)
NEST = Principal(401, "acme_nest", "R", owner_id=1)
PLAIN = Principal(402, "acme_readers", "R", owner_id=1)

FIXED = [PUBLIC, SYSADMIN, SECURITYADMIN, SERVERADMIN, SA, APP, OTHER]
CONNECT = Permission(2, "CONNECT SQL", SERVER_CLASS, 0)
VIEW_DATABASES = Permission(2, "VIEW ANY DATABASE", SERVER_CLASS, 0)


def catalog(
    *extra: Principal,
    members: tuple[tuple[int, int], ...] = (),
    grants: tuple[Permission, ...] = (),
) -> Catalog:
    return Catalog.read([*FIXED, *extra], members, [CONNECT, VIEW_DATABASES, *grants])


def grants_of(read: Catalog, login: Principal = APP) -> set[str]:
    found = assess(login.principal_id, read)
    assert found.unread is None
    return set(found.grants)


def test_a_login_with_no_grant_passes() -> None:
    assert assess(APP.principal_id, catalog()) == Assessment()


def test_public_s_ordinary_grants_refuse_nothing() -> None:
    assert grants_of(catalog(PLAIN, members=((PLAIN.principal_id, APP.principal_id),))) == set()


@pytest.mark.parametrize("role", [SYSADMIN, SECURITYADMIN])
def test_a_member_of_an_administrative_fixed_role_is_refused(role: Principal) -> None:
    read = catalog(members=((role.principal_id, APP.principal_id),))
    assert grants_of(read) == {role.name}


def test_another_fixed_role_is_not_on_the_list() -> None:
    read = catalog(members=((SERVERADMIN.principal_id, APP.principal_id),))
    assert grants_of(read) == set()


@pytest.mark.parametrize(
    "permission",
    ["CONTROL SERVER", "ALTER ANY LOGIN", "IMPERSONATE ANY LOGIN", "ALTER ANY SERVER ROLE"],
)
def test_a_server_permission_on_the_list_is_refused(permission: str) -> None:
    read = catalog(grants=(Permission(APP.principal_id, permission, SERVER_CLASS, 0),))
    assert grants_of(read) == {permission}


def test_a_server_permission_off_the_list_is_not_refused() -> None:
    read = catalog(grants=(Permission(APP.principal_id, "VIEW SERVER STATE", SERVER_CLASS, 0),))
    assert grants_of(read) == set()


def test_with_grant_option_counts_and_a_deny_is_not_read() -> None:
    granted = Permission(APP.principal_id, "CONTROL SERVER", SERVER_CLASS, 0, state="W")
    denied = Permission(APP.principal_id, "ALTER ANY LOGIN", SERVER_CLASS, 0, state="D")
    assert grants_of(catalog(grants=(granted, denied))) == {"CONTROL SERVER"}


@pytest.mark.parametrize("permission", ["CONTROL", "ALTER", "IMPERSONATE"])
def test_a_grant_on_one_login_is_refused(permission: str) -> None:
    """PA1: whatever the login it is on, `sa` here, or a plain one."""
    for on in (SA, OTHER):
        read = catalog(
            grants=(Permission(APP.principal_id, permission, PRINCIPAL_CLASS, on.principal_id),)
        )
        assert grants_of(read) == {f"{permission} ON LOGIN::[{on.name}]"}


def test_take_ownership_on_a_login_is_not_on_the_list() -> None:
    """It cannot be granted (PA3, #1567), so a row of it is not read."""
    read = catalog(
        grants=(
            Permission(APP.principal_id, "TAKE OWNERSHIP", PRINCIPAL_CLASS, OTHER.principal_id),
        )
    )
    assert grants_of(read) == set()


def test_a_grant_through_a_role_names_the_role() -> None:
    read = catalog(
        OPS,
        members=((OPS.principal_id, APP.principal_id),),
        grants=(Permission(OPS.principal_id, "CONTROL SERVER", SERVER_CLASS, 0),),
    )
    assert grants_of(read) == {"CONTROL SERVER through [acme_ops]"}


def test_a_nested_role_is_followed() -> None:
    """PA1's nested path: the login is in acme_nest, which is in acme_ops."""
    read = catalog(
        OPS,
        NEST,
        members=((OPS.principal_id, NEST.principal_id), (NEST.principal_id, APP.principal_id)),
        grants=(Permission(OPS.principal_id, "CONTROL SERVER", SERVER_CLASS, 0),),
    )
    assert grants_of(read) == {"CONTROL SERVER through [acme_ops]"}
    assert refused_roles(read) == {SYSADMIN.principal_id, SECURITYADMIN.principal_id, 400, 401}


def test_a_role_nested_in_sysadmin_refuses_its_members() -> None:
    read = catalog(
        NEST,
        members=((SYSADMIN.principal_id, NEST.principal_id), (NEST.principal_id, APP.principal_id)),
    )
    assert grants_of(read) == {"sysadmin"}


def test_public_s_grant_refuses_every_login() -> None:
    """PA1's public path: `public` has no membership rows."""
    read = catalog(
        grants=(Permission(PUBLIC.principal_id, "ALTER ANY SERVER ROLE", SERVER_CLASS, 0),)
    )
    for login in (APP, OTHER):
        assert grants_of(read, login) == {"ALTER ANY SERVER ROLE through [public]"}


@pytest.mark.parametrize("permission", ["CONTROL", "ALTER", "TAKE OWNERSHIP"])
def test_a_grant_on_a_refused_role_is_refused(permission: str) -> None:
    """PA3: each lets its holder add itself to the role."""
    read = catalog(
        OPS,
        grants=(
            Permission(OPS.principal_id, "CONTROL SERVER", SERVER_CLASS, 0),
            Permission(APP.principal_id, permission, PRINCIPAL_CLASS, OPS.principal_id),
        ),
    )
    assert grants_of(read) == {f"{permission} ON SERVER ROLE::[acme_ops]"}


def test_a_grant_on_a_role_off_the_list_is_not_refused() -> None:
    read = catalog(
        PLAIN,
        grants=(Permission(APP.principal_id, "CONTROL", PRINCIPAL_CLASS, PLAIN.principal_id),),
    )
    assert grants_of(read) == set()


def test_a_grant_on_a_fixed_administrative_role_is_refused() -> None:
    read = catalog(
        grants=(Permission(APP.principal_id, "ALTER", PRINCIPAL_CLASS, SYSADMIN.principal_id),)
    )
    assert grants_of(read) == {"ALTER ON SERVER ROLE::[sysadmin]"}


def test_the_owner_of_a_refused_role_is_refused() -> None:
    """PA1's owner path."""
    owned = Principal(403, "acme_owned", "R", owner_id=APP.principal_id)
    read = catalog(
        owned, grants=(Permission(owned.principal_id, "CONTROL SERVER", SERVER_CLASS, 0),)
    )
    assert grants_of(read) == {"ownership of SERVER ROLE::[acme_owned]"}


def test_the_owner_of_a_role_off_the_list_is_not_refused() -> None:
    owned = Principal(403, "acme_owned", "R", owner_id=APP.principal_id)
    assert grants_of(catalog(owned)) == set()


def test_paths_compose_to_a_fixed_point() -> None:
    """acme_readers owns acme_nest, which holds ALTER on acme_ops, which holds
    CONTROL SERVER. A member of acme_readers can take each in turn."""
    readers = Principal(402, "acme_readers", "R", owner_id=1)
    nest = Principal(401, "acme_nest", "R", owner_id=readers.principal_id)
    read = catalog(
        OPS,
        nest,
        readers,
        members=((readers.principal_id, APP.principal_id),),
        grants=(
            Permission(OPS.principal_id, "CONTROL SERVER", SERVER_CLASS, 0),
            Permission(nest.principal_id, "ALTER", PRINCIPAL_CLASS, OPS.principal_id),
        ),
    )
    assert grants_of(read) == {"ownership of SERVER ROLE::[acme_nest] through [acme_readers]"}
    assert {400, 401, 402} <= refused_roles(read)
    assert grants_of(read, OTHER) == set()


@pytest.mark.parametrize(
    ("members", "grants"),
    [
        (((999, APP.principal_id),), ()),
        (((OPS.principal_id, 999),), ()),
        ((), (Permission(999, "CONTROL SERVER", SERVER_CLASS, 0),)),
        ((), (Permission(OTHER.principal_id, "ALTER", PRINCIPAL_CLASS, 999),)),
    ],
    ids=["role", "member", "grantee", "object"],
)
def test_an_id_with_no_principal_row_makes_the_read_partial(
    members: tuple[tuple[int, int], ...], grants: tuple[Permission, ...]
) -> None:
    """A denial hides a row and not the rows that name it (FR5), so every
    login is refused, not only the one the row is about."""
    read = catalog(OPS, members=members, grants=grants)
    assert read == Catalog(unread=PARTIAL_READ)
    assert assess(SA.principal_id, read).unread == PARTIAL_READ


def test_a_denial_naming_a_principal_with_no_row_is_not_read() -> None:
    """Denials are not read for the list, so they do not make the read partial."""
    read = catalog(grants=(Permission(999, "CONTROL SERVER", SERVER_CLASS, 0, state="D"),))
    assert read.complete


def test_a_name_with_a_bracket_is_quoted() -> None:
    odd = Principal(404, "acme]ops", "R", owner_id=1)
    read = catalog(
        odd,
        members=((odd.principal_id, APP.principal_id),),
        grants=(Permission(odd.principal_id, "CONTROL SERVER", SERVER_CLASS, 0),),
    )
    assert grants_of(read) == {"CONTROL SERVER through [acme]]ops]"}


def test_without_view_any_definition_every_login_is_refused() -> None:
    """#1567: the tool cannot see which roles a login owns."""
    assert assess(APP.principal_id, Catalog(unread=MISSING_GRANT)) == Assessment(
        unread=MISSING_GRANT
    )
    assert "VIEW ANY DEFINITION" in MISSING_GRANT


def test_a_login_missing_from_a_complete_catalog_is_refused_without_blaming_the_grant() -> None:
    assert assess(12345, catalog()).unread == MISSING_LOGIN
    assert "VIEW ANY DEFINITION" not in MISSING_LOGIN


def test_a_complete_catalog_without_public_refuses_every_login() -> None:
    """`public`'s grants are every login's, so a read without its row never passes."""
    read = Catalog.read([p for p in FIXED if p is not PUBLIC], (), ())
    assert assess(APP.principal_id, read) == Assessment(unread=MISSING_PUBLIC)


def test_the_catalog_s_indexes_are_built_once() -> None:
    read = catalog(OPS, grants=(Permission(OPS.principal_id, "CONTROL SERVER", SERVER_CLASS, 0),))
    assert read.refused is read.refused
    assert refused_roles(read) is read.refused


def test_an_unread_path_does_not_make_creds_generate_skip_the_login() -> None:
    """The grant to the tool login changes the answer, so generate stages
    the login, and check 9 refuses it on the password verbs (#1567)."""
    state = UserState(name=APP.name, status="OPEN", admin_unread=MISSING_GRANT)
    assert server_refusal(state) is None
    assert not review(state, declared=(APP.name,)).permitted


def test_guardrail_nine_prints_the_findings() -> None:
    read = catalog(
        OPS,
        members=((OPS.principal_id, APP.principal_id),),
        grants=(
            Permission(OPS.principal_id, "CONTROL SERVER", SERVER_CLASS, 0),
            Permission(APP.principal_id, "IMPERSONATE", PRINCIPAL_CLASS, SA.principal_id),
        ),
    )
    found = assess(APP.principal_id, read)
    state = UserState(name=APP.name, status="OPEN", global_privileges=found.grants)

    (refusal,) = review(state, declared=(APP.name,)).refusals
    assert refusal.check == GLOBAL_PRIVILEGE
    assert refusal.reason == (
        "the account holds CONTROL SERVER through [acme_ops], IMPERSONATE ON LOGIN::[sa]"
    )


def test_a_member_of_login_manager_is_refused() -> None:
    """FR2: `##MS_LoginManager##` gives ALTER ANY LOGIN with no permission row."""
    manager = Principal(16, "##MS_LoginManager##", "R", owner_id=1)
    read = catalog(manager, members=((manager.principal_id, APP.principal_id),))
    assert grants_of(read) == {"##MS_LoginManager##"}


class FakeCursor:
    """Answers each of `read_catalog`'s statements, and records them."""

    def __init__(self, answers: dict[str, list[Any]]) -> None:
        self.answers = answers
        self.sent: list[tuple[object, ...]] = []
        self.rows: list[tuple[object, ...]] = []

    def execute(self, *args: object) -> None:
        self.sent.append(args)
        answer = self.answers[str(args[0])]
        # A list of answers, one per call, stands for a server that changes
        # between reads; the last is kept.
        if answer and isinstance(answer[0], list):
            self.rows = answer.pop(0) if len(answer) > 1 else answer[0]
        else:
            self.rows = answer

    def fetchone(self) -> object:
        return self.rows[0] if self.rows else None

    def fetchall(self) -> object:
        return self.rows


@pytest.mark.parametrize("answer", [0, None])
def test_read_catalog_stops_without_view_any_definition(answer: int | None) -> None:
    cursor = FakeCursor({VIEW_DEFINITIONS: [(answer, 1)]})
    assert read_catalog(cursor) == Catalog(unread=MISSING_GRANT)
    assert cursor.sent == [(VIEW_DEFINITIONS,)]
    assert assess(APP.principal_id, read_catalog(cursor)).unread == MISSING_GRANT


def test_read_catalog_stops_where_view_any_security_definition_is_denied() -> None:
    """2022+: the denial hides every row the read makes (FR5)."""
    cursor = FakeCursor({VIEW_DEFINITIONS: [(1, 0)]})
    read = read_catalog(cursor)
    assert read == Catalog(unread=DENIED_SECURITY)
    assert assess(APP.principal_id, read).unread == DENIED_SECURITY


#: The rows of a small server: public owned by sa, a fixed role owned by sa,
#: a login, and a user-defined role it owns.
SERVER_ROWS: dict[str, list[tuple[object, ...]]] = {
    PRINCIPALS: [
        (1, "sa", "S ", None, False),
        (2, "public", "R ", 1, False),
        (3, "sysadmin", "R ", 1, True),
        (300, "acme_app_user", "S ", None, False),
        (400, "acme_ops", "R ", 300, False),
    ],
    MEMBERSHIPS: [(3, 1)],
    PERMISSIONS: [(300, "CONTROL SERVER", 100, 0, "G ")],
}


def test_read_catalog_reads_the_three_views_without_parameters() -> None:
    """pyodbc binds a `None` as a parameter, so none is passed. 2019 answers
    `NULL` for VIEW ANY SECURITY DEFINITION, which it does not have."""
    cursor = FakeCursor({VIEW_DEFINITIONS: [(1, None)], **SERVER_ROWS})
    read = read_catalog(cursor)

    assert cursor.sent == [(VIEW_DEFINITIONS,), (PRINCIPALS,), (MEMBERSHIPS,), (PERMISSIONS,)]
    assert read == Catalog.read(
        [
            Principal(1, "sa", "S"),
            # sa "owns" public and the fixed roles; the read leaves it out.
            Principal(2, "public", "R"),
            Principal(3, "sysadmin", "R"),
            Principal(300, "acme_app_user", "S"),
            Principal(400, "acme_ops", "R", owner_id=300),
        ],
        [(3, 1)],
        [Permission(300, "CONTROL SERVER", 100, 0, "G")],
    )
    assert assess(300, read).grants == frozenset({"CONTROL SERVER"})
    assert assess(1, read).grants == frozenset({"sysadmin"})


@pytest.mark.parametrize(
    "hidden",
    [
        {MEMBERSHIPS: [(3, 1), (401, 300)]},
        {PERMISSIONS: [(401, "CONTROL SERVER", 100, 0, "G")]},
        {
            PRINCIPALS: [
                *SERVER_ROWS[PRINCIPALS],
                (402, "acme_owned", "R ", 401, False),
            ]
        },
    ],
    ids=["membership", "grantee", "owner"],
)
def test_an_id_with_no_principal_row_refuses_every_login(
    hidden: dict[str, list[tuple[object, ...]]],
) -> None:
    """A DENY VIEW DEFINITION on one role hides its row from a tool that holds
    VIEW ANY DEFINITION (`13_fixed_roles_probe.py`, FR5), and a role made between the
    three statements has no row either. Either way the read cannot be
    trusted, whatever login it is asked about."""
    cursor = FakeCursor({VIEW_DEFINITIONS: [(1, 1)], **SERVER_ROWS, **hidden})
    read = read_catalog(cursor)

    assert read == Catalog(unread=PARTIAL_READ)
    assert assess(1, read).unread == PARTIAL_READ
    # Read twice: a denial hides the row both times.
    assert cursor.sent.count((PRINCIPALS,)) == READS


def test_a_principal_made_during_the_read_is_seen_by_the_second() -> None:
    """The first read names role 401 in a membership but has no row for it;
    the second read has the row."""
    made = [*SERVER_ROWS[PRINCIPALS], (401, "acme_new", "R ", 1, False)]
    cursor = FakeCursor(
        {
            VIEW_DEFINITIONS: [(1, 1)],
            PRINCIPALS: [SERVER_ROWS[PRINCIPALS], made],
            MEMBERSHIPS: [(3, 1), (401, 300)],
            PERMISSIONS: SERVER_ROWS[PERMISSIONS],
        }
    )
    read = read_catalog(cursor)

    assert read.complete
    assert 401 in read.principals
