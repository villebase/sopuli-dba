"""Resolving the account `sql run` connects as (UC-3 §5). Tier 0.

Every test passes its own mapping and suppliers, as `test_admin.py` does.
"""

from __future__ import annotations

from collections.abc import Mapping

import pytest

from sopuli.admin import (
    AdminCredentialError,
    NobodyToAskError,
    refuse_service_account,
    resolve_run_as,
    run_as_user,
)
from sopuli.config.model import AdminAuth, AdminCredential, ExpandedTarget, Target
from sopuli.exit_codes import ExitCode
from sopuli.safety import RefusedError
from sopuli.secrets import Secret

DSN = "db-test.example.com:1521/CDBQA.pdb.example.com"


def target(
    *,
    admin: AdminCredential | None = None,
    run_as: AdminCredential | None = None,
    dsn: str = DSN,
) -> ExpandedTarget:
    return ExpandedTarget(
        target=Target(name="cdb-root-qa", type="oracle", dsn=dsn, admin=admin, run_as=run_as),
        index=0,
        run_as=run_as,
    )


def credential(
    user: str | None, method: str, *, entry: str | None = None, password_env: str | None = None
) -> AdminCredential:
    auth = AdminAuth(method=method, entry=entry, password_env=password_env)
    return AdminCredential(username=user, auth=auth)


def answer(_: ExpandedTarget, username: str | None) -> Secret:
    return Secret(f"typed for {username}")


def refuse_prompt(_: ExpandedTarget, __: str | None) -> Secret:
    raise AssertionError("the operator was asked and should not have been")


def env(**values: str) -> Mapping[str, str]:
    return values


def test_as_user_wins_and_prompts() -> None:
    declared = credential("acme_owner", "keyring", entry="owner")

    resolved = resolve_run_as(
        target(run_as=declared), env=env(), prompt=answer, as_user="alice_personal"
    )

    assert resolved.method == "prompt"
    assert resolved.credential.username == "alice_personal"
    assert resolved.credential.secret is not None


def test_run_as_user_names_the_account() -> None:
    declared = target(run_as=credential("acme_owner", "prompt"))

    assert run_as_user(declared, None) == "acme_owner"
    assert run_as_user(declared, "alice_personal") == "alice_personal"
    wallet = target(dsn="CDBQA", run_as=AdminCredential(auth=AdminAuth(method="external")))
    assert run_as_user(wallet, None) == "external"


def test_a_declared_run_as_prompts_for_its_own_user() -> None:
    resolved = resolve_run_as(
        target(run_as=credential("acme_owner", "prompt")), env=env(), prompt=answer, as_user=None
    )

    assert resolved.credential.username == "acme_owner"


def test_the_admin_user_variable_does_not_rename_run_as() -> None:
    resolved = resolve_run_as(
        target(run_as=credential("acme_owner", "prompt")),
        env=env(SOPULI_DB_ADMIN_USER="somebody_else"),
        prompt=answer,
        as_user=None,
    )

    assert resolved.credential.username == "acme_owner"


def test_missing_run_as_and_no_as_is_exit_9() -> None:
    with pytest.raises(AdminCredentialError) as caught:
        resolve_run_as(target(), env=env(), prompt=refuse_prompt, as_user=None)

    assert caught.value.exit_code == ExitCode.CONFIG_INVALID
    rendered = str(caught.value)
    assert "cdb-root-qa" in rendered
    assert "--as USER" in rendered
    assert "run_as" in rendered


def test_a_run_as_without_a_prompter_says_nobody_is_there() -> None:
    with pytest.raises(NobodyToAskError) as caught:
        resolve_run_as(
            target(run_as=credential("acme_owner", "prompt")), env=env(), prompt=None, as_user=None
        )

    assert caught.value.exit_code == ExitCode.ABORTED
    assert "run_as" in str(caught.value)


def test_env_method_is_low_assurance() -> None:
    declared = credential("dba_alpha", "env", password_env="SOPULI_RUN_AS_PASSWORD")

    resolved = resolve_run_as(
        target(run_as=declared),
        env=env(SOPULI_RUN_AS_PASSWORD="from-the-environment"),
        prompt=refuse_prompt,
        as_user=None,
    )

    assert resolved.low_assurance is True
    assert resolved.credential.username == "dba_alpha"


def test_env_run_as_does_not_read_the_admin_password_variable() -> None:
    declared = credential("dba_alpha", "env", password_env="SOPULI_RUN_AS_PASSWORD")

    with pytest.raises(AdminCredentialError) as caught:
        resolve_run_as(
            target(run_as=declared),
            env=env(SOPULI_DB_ADMIN_PASSWORD="the-admins"),
            prompt=refuse_prompt,
            as_user=None,
        )

    assert "run_as credential" in str(caught.value)
    assert "targets[0].run_as.auth.password_env" in str(caught.value)


def test_external_run_as_carries_no_username() -> None:
    wallet = target(dsn="CDBQA", run_as=AdminCredential(auth=AdminAuth(method="external")))

    resolved = resolve_run_as(wallet, env=env(), prompt=refuse_prompt, as_user=None)

    assert resolved.credential.external is True
    assert resolved.credential.username is None


def test_service_account_name_refused() -> None:
    declared = target(
        admin=credential("c##sopuli_svc", "keyring", entry="svc"),
        run_as=credential("C##SOPULI_SVC", "prompt"),
    )

    with pytest.raises(RefusedError) as caught:
        refuse_service_account(declared, None)

    assert caught.value.code == "SOPULI-20010"
    assert caught.value.exit_code == ExitCode.ABORTED
    assert caught.value.category == "policy"


def test_service_account_name_refused_through_as() -> None:
    declared = target(admin=credential("c##sopuli_svc", "keyring", entry="svc"))

    with pytest.raises(RefusedError) as caught:
        refuse_service_account(declared, "C##Sopuli_Svc")

    assert caught.value.code == "SOPULI-20010"


def test_the_admin_user_variable_counts_as_the_admin() -> None:
    declared = target(
        admin=credential("c##sopuli_svc", "keyring", entry="svc"),
        run_as=credential("dba_alpha", "prompt"),
    )

    with pytest.raises(RefusedError):
        refuse_service_account(declared, None, env=env(SOPULI_DB_ADMIN_USER="DBA_ALPHA"))


def test_another_account_is_allowed() -> None:
    declared = target(
        admin=credential("c##sopuli_svc", "keyring", entry="svc"),
        run_as=credential("dba_alpha", "prompt"),
    )

    refuse_service_account(declared, None)
    refuse_service_account(declared, "alice_personal")


def test_both_external_same_dsn_refused() -> None:
    wallet = AdminCredential(auth=AdminAuth(method="external"))
    declared = target(dsn="CDBQA", admin=wallet, run_as=wallet)

    with pytest.raises(RefusedError) as caught:
        refuse_service_account(declared, None)

    assert caught.value.code == "SOPULI-20010"


def test_admin_external_run_as_named_is_allowed() -> None:
    """The documented gap: a wallet has no name to compare."""
    declared = target(
        dsn="CDBQA",
        admin=AdminCredential(auth=AdminAuth(method="external")),
        run_as=credential("c##sopuli_svc", "prompt"),
    )

    refuse_service_account(declared, None)
    refuse_service_account(declared, "c##sopuli_svc")
