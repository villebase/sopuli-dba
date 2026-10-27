"""The Vault side of `vault_path` delivery (UC-2 §6.6), against the real container.

sopuli will write a person's password to
`<mount>/personal/<ACCOUNT as the database stores it>/<target>`, and the person
reads it through a policy keyed on their entity's `db_account` metadata. Nothing
here runs sopuli's delivery code. These tests show that the fixture
`test/compose.yaml`'s vault-init sets up behaves as the method relies on:

- the person whose entity maps to the account reads what the DBA's token wrote;
- a person mapped to another account, and one with no mapping, get 403;
- the DBA's token holds `create` and `update` and no `read`, so the plan-time
  `sys/capabilities-self` check passes it, and the second token, with `read`, is
  there for the check to refuse;
- `delete_version_after` written to the metadata before the value deletes that
  version on a clock, and written after it, leaves the version alone.

Plain HTTP calls, as the method will make them. Tier 1: it skips without the
container (`04-testing.md` §3).
"""

from __future__ import annotations

import time
from collections.abc import Iterator
from typing import Any

import pytest

PASSWORD = "Correct#Horse9Battery"

#: The tier-1 Oracle target name, as the method's path will carry it.
TARGET = "tier1-oracle"


def _data_path(stack: Any, account: str, target: str) -> str:
    return f"/v1/{stack.kv2_mount}/data/{stack.personal_prefix}/{account}/{target}"


def _metadata_path(stack: Any, account: str, target: str) -> str:
    return f"/v1/{stack.kv2_mount}/metadata/{stack.personal_prefix}/{account}/{target}"


def _login(stack: Any, person: Any) -> str:
    """The client token a userpass login gives the person."""
    response = stack.client.post(
        f"/v1/auth/{stack.userpass_mount}/login/{person.login}",
        json={"password": person.password},
        headers={"X-Vault-Token": ""},
    )
    assert response.status_code == 200, response.text
    token: str = response.json()["auth"]["client_token"]
    return token


def _as(token: str) -> dict[str, str]:
    return {"X-Vault-Token": token}


@pytest.fixture(autouse=True)
def _personal_setup(vault_personal: Any) -> None:
    """Every test here needs vault-init's setup, and skips once without it."""


@pytest.fixture
def path(vault_stack: Any, request: pytest.FixtureRequest) -> Iterator[str]:
    """alice's path for one test, removed before and after it with the root token.

    Removed rather than assumed absent: the `kv` mount is shared with whatever has
    been run by hand against the same container.
    """
    target = f"{TARGET}-{request.node.originalname.replace('_', '-')}"
    metadata = _metadata_path(vault_stack, vault_stack.alice.db_account, target)
    vault_stack.client.delete(metadata)
    yield target
    vault_stack.client.delete(metadata)


def _write(stack: Any, target: str) -> int:
    """Write the value with the DBA's token and return the version it created."""
    response = stack.client.post(
        _data_path(stack, stack.alice.db_account, target),
        json={"data": {"password": PASSWORD}},
        headers=_as(stack.personal_writer_token),
    )
    assert response.status_code == 200, response.text
    version: int = response.json()["data"]["version"]
    return version


def test_the_mapped_person_reads_what_the_writer_wrote(vault_stack: Any, path: str) -> None:
    _write(vault_stack, path)

    response = vault_stack.client.get(
        _data_path(vault_stack, vault_stack.alice.db_account, path),
        headers=_as(_login(vault_stack, vault_stack.alice)),
    )

    assert response.status_code == 200, response.text
    assert response.json()["data"]["data"] == {"password": PASSWORD}


@pytest.mark.parametrize("login", ["bob", "carol"])
def test_another_person_is_refused(vault_stack: Any, path: str, login: str) -> None:
    """bob's entity maps to ACME_DEV_BOB. carol's has no `db_account`, so the
    template does not resolve and the policy grants nothing."""
    _write(vault_stack, path)
    person = getattr(vault_stack, login)

    response = vault_stack.client.get(
        _data_path(vault_stack, vault_stack.alice.db_account, path),
        headers=_as(_login(vault_stack, person)),
    )

    assert response.status_code == 403, response.text


@pytest.mark.parametrize(
    ("token_field", "expected"),
    [
        ("personal_writer_token", ["create", "update"]),
        ("personal_writer_read_token", ["create", "read", "update"]),
    ],
)
def test_the_writer_tokens_capabilities(
    vault_stack: Any, token_field: str, expected: list[str]
) -> None:
    """What the plan-time check sees: the same capabilities on the data path and
    the metadata path. The method passes the first token and refuses the second."""
    account = vault_stack.alice.db_account
    data = _data_path(vault_stack, account, TARGET).removeprefix("/v1/")
    metadata = _metadata_path(vault_stack, account, TARGET).removeprefix("/v1/")

    response = vault_stack.client.post(
        "/v1/sys/capabilities-self",
        json={"paths": [data, metadata]},
        headers=_as(getattr(vault_stack, token_field)),
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert sorted(body[data]) == expected
    assert sorted(body[metadata]) == expected


def test_the_writer_cannot_read_back(vault_stack: Any, path: str) -> None:
    _write(vault_stack, path)

    response = vault_stack.client.get(
        _data_path(vault_stack, vault_stack.alice.db_account, path),
        headers=_as(vault_stack.personal_writer_token),
    )

    assert response.status_code == 403, response.text


def _set_delete_after(stack: Any, target: str, duration: str) -> None:
    response = stack.client.post(
        _metadata_path(stack, stack.alice.db_account, target),
        json={"delete_version_after": duration},
        headers=_as(stack.personal_writer_token),
    )
    assert response.status_code == 204, response.text


def _deletion_time(stack: Any, target: str, version: int) -> str:
    """The version's `deletion_time`, read with the root token. Empty when unset."""
    response = stack.client.get(_metadata_path(stack, stack.alice.db_account, target))
    assert response.status_code == 200, response.text
    deletion_time: str = response.json()["data"]["versions"][str(version)]["deletion_time"]
    return deletion_time


def test_delete_version_after_set_first_deletes_the_version(vault_stack: Any, path: str) -> None:
    """The order the method uses: metadata first, then the value. The person
    reads it at once, and gets 404 once the clock has run.

    alice logs in before the clock starts, and the window is 5 s, so a slow
    runner still reads the value before it goes."""
    alice = _as(_login(vault_stack, vault_stack.alice))
    read = _data_path(vault_stack, vault_stack.alice.db_account, path)
    _set_delete_after(vault_stack, path, "5s")
    version = _write(vault_stack, path)
    assert _deletion_time(vault_stack, path, version) != ""
    assert vault_stack.client.get(read, headers=alice).status_code == 200

    deadline = time.monotonic() + 15
    while (status := vault_stack.client.get(read, headers=alice).status_code) == 200:
        assert time.monotonic() < deadline, "the version was still readable after 15 s"
        time.sleep(0.5)

    assert status == 404


def test_delete_version_after_set_later_leaves_the_version(vault_stack: Any, path: str) -> None:
    """`delete_version_after` applies only to versions written after it is set,
    which is why the method writes the metadata first."""
    version = _write(vault_stack, path)
    _set_delete_after(vault_stack, path, "1s")
    time.sleep(2)

    assert _deletion_time(vault_stack, path, version) == ""
    response = vault_stack.client.get(
        _data_path(vault_stack, vault_stack.alice.db_account, path),
        headers=_as(_login(vault_stack, vault_stack.alice)),
    )
    assert response.status_code == 200, response.text
