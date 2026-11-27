"""Resolving the account `sql run` connects as (UC-3 §2). Tier 0.

Every test passes its own mapping and suppliers, as `test_admin.py` does.
"""

from __future__ import annotations

from collections.abc import Mapping

import pytest

from sopuli.admin import (
    AdminCredentialError,
    AskOncePerUser,
    NobodyToAskError,
    PasswordPrompt,
    forget,
    refuse_service_account,
    refuse_session_user,
    resolve_run_as,
    run_as_is_wallet,
    run_as_prompts,
    run_as_user,
    run_as_uses_keyring,
)
from sopuli.config.model import AdminAuth, AdminCredential, ExpandedTarget, Target
from sopuli.exit_codes import ExitCode
from sopuli.safety import RefusedError, ServiceAccountRefusedError
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
    # The advice fits `run_as:`, which has no vault method and never reads the
    # admin's variable.
    hint = caught.value.hint or ""
    assert "keyring" in hint
    assert "password_env" in hint
    assert "vault" not in hint
    assert "SOPULI_DB_ADMIN_PASSWORD" not in hint


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


def from_defaults(
    declared: AdminCredential, *, admin: AdminCredential | None = None, dsn: str = DSN
) -> ExpandedTarget:
    """A target with no `run_as:` of its own, which `defaults.run_as` filled."""
    return ExpandedTarget(
        target=Target(name="cdb-root-qa", type="oracle", dsn=dsn, admin=admin),
        index=0,
        run_as=declared,
    )


def test_errors_from_defaults_point_at_defaults() -> None:
    with pytest.raises(NobodyToAskError) as caught:
        resolve_run_as(
            from_defaults(credential("dba_alpha", "prompt")),
            env=env(),
            prompt=None,
            as_user=None,
        )

    assert "defaults.run_as.auth" in str(caught.value)
    assert "targets[0]" not in str(caught.value)


def test_a_nobody_to_ask_error_for_as_does_not_name_a_run_as_key() -> None:
    declared = target(run_as=credential("acme_owner", "keyring", entry="owner"))

    with pytest.raises(NobodyToAskError) as caught:
        resolve_run_as(declared, env=env(), prompt=None, as_user="alice_personal")

    rendered = str(caught.value)
    assert "--as" in rendered
    assert "run_as" not in rendered
    assert "targets[0]" not in rendered


def test_env_error_from_defaults_points_at_defaults() -> None:
    declared = from_defaults(credential("dba_alpha", "env", password_env="NOT_SET_HERE"))

    with pytest.raises(AdminCredentialError) as caught:
        resolve_run_as(declared, env=env(), prompt=None, as_user=None)

    assert "defaults.run_as.auth.password_env" in str(caught.value)


def test_a_keyring_with_no_entry_names_its_block() -> None:
    declared = target(run_as=AdminCredential(username="u", auth=AdminAuth(method="keyring")))

    with pytest.raises(AdminCredentialError) as caught:
        resolve_run_as(declared, env=env(), prompt=None, as_user=None)

    assert "run_as" in str(caught.value)
    assert "targets[0].run_as.auth.entry" in str(caught.value)


def test_the_service_account_refusal_points_at_the_run_as_side() -> None:
    declared = from_defaults(
        credential("C##SOPULI_SVC", "prompt"),
        admin=credential("c##sopuli_svc", "keyring", entry="svc"),
    )

    with pytest.raises(RefusedError) as caught:
        refuse_service_account(declared, None)

    assert "defaults.run_as.username" in str(caught.value)
    assert "targets[0].admin" not in str(caught.value)


def test_the_service_account_refusal_through_as_says_as() -> None:
    declared = target(admin=credential("c##sopuli_svc", "keyring", entry="svc"))

    with pytest.raises(RefusedError) as caught:
        refuse_service_account(declared, "C##Sopuli_Svc")

    rendered = str(caught.value)
    assert "--as" in rendered
    assert "run_as" not in rendered.split("hint:")[0]


def test_the_service_account_refusal_says_when_the_variable_named_the_admin() -> None:
    declared = target(
        admin=credential("c##sopuli_svc", "keyring", entry="svc"),
        run_as=credential("dba_alpha", "prompt"),
    )

    with pytest.raises(RefusedError) as caught:
        refuse_service_account(declared, None, env=env(SOPULI_DB_ADMIN_USER="DBA_ALPHA"))

    assert "SOPULI_DB_ADMIN_USER" in str(caught.value)


def test_the_external_refusal_points_at_the_run_as_block() -> None:
    wallet = AdminCredential(auth=AdminAuth(method="external"))
    declared = from_defaults(wallet, admin=wallet, dsn="CDBQA")

    with pytest.raises(RefusedError) as caught:
        refuse_service_account(declared, None)

    assert "defaults.run_as" in str(caught.value)


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


def test_a_user_named_external_is_not_a_wallet_login() -> None:
    """The check branches on the auth method, not on the string (#1674). An
    Oracle user named EXTERNAL with a password is a named account."""
    wallet = AdminCredential(auth=AdminAuth(method="external"))
    declared = target(dsn="CDBQA", admin=wallet, run_as=credential("external", "prompt"))

    refuse_service_account(declared, None)
    refuse_service_account(declared, "external")


def test_a_user_named_external_that_is_the_admin_is_refused_by_name() -> None:
    """The admin is the user EXTERNAL, with a password. A run-as login of the same
    name, with a password, is that account, and not a wallet login (#1674)."""
    declared = target(
        admin=credential("EXTERNAL", "keyring", entry="svc"),
        run_as=credential("external", "prompt"),
    )

    with pytest.raises(RefusedError) as caught:
        refuse_service_account(declared, None)

    assert caught.value.code == "SOPULI-20010"
    assert "run_as.username" in str(caught.value)


@pytest.mark.parametrize("from_variable", [False, True])
def test_a_wallet_run_as_against_a_password_admin_named_external_is_allowed(
    from_variable: bool,
) -> None:
    """The reverse (#1674): the admin is the user EXTERNAL with a password, and
    the run-as login is a wallet. A wallet has no name to compare, so it is not
    refused here, and `refuse_session_user` is the backstop."""
    wallet = AdminCredential(auth=AdminAuth(method="external"))
    admin = credential(None if from_variable else "EXTERNAL", "keyring", entry="svc")
    declared = target(dsn="CDBQA", admin=admin, run_as=wallet)
    variables = env(SOPULI_DB_ADMIN_USER="external") if from_variable else env()

    refuse_service_account(declared, None, env=variables)


def test_run_as_is_wallet_reads_the_method() -> None:
    wallet = AdminCredential(auth=AdminAuth(method="external"))

    assert run_as_is_wallet(target(run_as=wallet), None)
    assert not run_as_is_wallet(target(run_as=credential("external", "prompt")), None)
    assert not run_as_is_wallet(target(run_as=wallet), "external")
    assert not run_as_is_wallet(target(), None)


def test_admin_external_run_as_named_is_allowed() -> None:
    """The documented gap: a wallet has no name to compare."""
    declared = target(
        dsn="CDBQA",
        admin=AdminCredential(auth=AdminAuth(method="external")),
        run_as=credential("c##sopuli_svc", "prompt"),
    )

    refuse_service_account(declared, None)
    refuse_service_account(declared, "c##sopuli_svc")


def test_which_run_as_accounts_are_typed() -> None:
    assert run_as_prompts(target(), "alice_personal")
    assert run_as_prompts(target(run_as=credential("dba_alpha", "prompt")), None)
    assert not run_as_prompts(target(run_as=credential("dba_alpha", "keyring", entry="a")), None)
    assert run_as_uses_keyring(target(run_as=credential("dba_alpha", "keyring", entry="a")), None)
    assert not run_as_uses_keyring(
        target(run_as=credential("dba_alpha", "keyring", entry="a")), "x"
    )


def test_a_password_refused_on_another_target_is_forgotten() -> None:
    """Target 1 asked and logged in; target 2 refused the same answer; the next
    ask prompts again, whichever target asked first."""
    asked: list[str] = []

    def ask(line: str) -> str:
        asked.append(line)
        return "typed"

    prompt = AskOncePerUser(PasswordPrompt(ask=ask))
    # The first and the third share a declaration site, so the inner prompter
    # keys them alike, and the second does not.
    first, second, third = (
        ExpandedTarget(target=Target(name=name, type="oracle", dsn=DSN), index=index)
        for index, name in ((0, "one-qa"), (1, "two-qa"), (0, "three-qa"))
    )

    prompt(first, "dba_beta")
    prompt(second, "dba_beta")
    forget(prompt, second, "dba_beta")
    prompt(third, "dba_beta")

    assert len(asked) == 2


def _explicit(name: str, index: int, run_as: AdminCredential | None) -> ExpandedTarget:
    return ExpandedTarget(
        target=Target(name=name, type="oracle", dsn=DSN, run_as=run_as), index=index, run_as=run_as
    )


def test_run_as_answers_are_kept_per_declaration() -> None:
    """Two targets that each write their own `run_as: dba_alpha` are two acts,
    and the two databases may hold different passwords: asked twice (#1677)."""
    asked: list[str] = []

    def ask(line: str) -> str:
        asked.append(line)
        return f"typed {len(asked)}"

    prompt = AskOncePerUser(PasswordPrompt(ask=ask), by_declaration=True)
    own = credential("dba_alpha", "prompt")
    first, second = _explicit("one", 0, own), _explicit("two", 1, own)

    one = prompt(first, "dba_alpha")
    two = prompt(second, "dba_alpha")

    assert len(asked) == 2
    assert one.reveal() != two.reveal()


def test_targets_that_inherit_one_run_as_share_its_answer() -> None:
    asked: list[str] = []

    def ask(line: str) -> str:
        asked.append(line)
        return "typed"

    prompt = AskOncePerUser(PasswordPrompt(ask=ask), by_declaration=True)
    first, second, third = (_explicit(name, index, None) for index, name in enumerate("abc"))

    for one in (first, second, third):
        prompt(one, "dba_alpha")

    assert len(asked) == 1


def test_another_user_on_the_same_declaration_is_asked_for() -> None:
    asked: list[str] = []

    def ask(line: str) -> str:
        asked.append(line)
        return "typed"

    prompt = AskOncePerUser(PasswordPrompt(ask=ask), by_declaration=True)
    first, second = _explicit("a", 0, None), _explicit("b", 1, None)

    prompt(first, "dba_alpha")
    prompt(second, "dba_beta")

    assert len(asked) == 2


def test_a_refused_answer_is_forgotten_only_where_it_was_kept() -> None:
    """The answer typed for a declaration is dropped when its target refuses
    it, and the other declaration's answer stays."""
    asked: list[str] = []

    def ask(line: str) -> str:
        asked.append(line)
        return "typed"

    prompt = AskOncePerUser(PasswordPrompt(ask=ask), by_declaration=True)
    own = credential("dba_alpha", "prompt")
    first, second = _explicit("one", 0, own), _explicit("two", 1, own)
    prompt(first, "dba_alpha")
    prompt(second, "dba_alpha")

    forget(prompt, first, "dba_alpha")
    prompt(second, "dba_alpha")
    prompt(first, "dba_alpha")

    assert len(asked) == 3


def test_a_refused_typed_password_is_asked_again() -> None:
    asked: list[str] = []

    def ask(line: str) -> str:
        asked.append(line)
        return "typed"

    prompt = AskOncePerUser(PasswordPrompt(ask=ask))
    one = target()

    prompt(one, "dba_beta")
    prompt(one, "dba_beta")
    forget(prompt, one, "dba_beta")
    prompt(one, "dba_beta")

    assert len(asked) == 2


@pytest.mark.parametrize(
    ("product", "words"),
    [("mysql", "hold the service account as a role"), ("postgresql", "member of the service role")],
)
def test_a_run_as_account_holding_the_service_account_is_refused_in_its_products_words(
    product: str, words: str
) -> None:
    """#1713 Q1: on MySQL the service account is granted as a role, and the
    hint says to revoke it; PostgreSQL keeps its own words (#1690)."""
    declared = ExpandedTarget(
        target=Target(
            name=f"{product}-dev",
            type=product,
            dsn=f"{product}-dev.example.com:3306",
            admin=credential("sopuli_svc", "keyring", entry="svc"),
        ),
        index=0,
    )
    with pytest.raises(ServiceAccountRefusedError) as raised:
        refuse_session_user(
            declared,
            "dba_alpha",
            None,
            env=env(),
            member_of=lambda account: account.upper() == "SOPULI_SVC",
        )
    assert raised.value.hint is not None
    assert words in raised.value.hint
