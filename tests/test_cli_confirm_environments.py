"""`safety.confirm_environments` asked of every mutating verb.

The tier-0 half is `tests/test_safety_confirm.py`, which is about what the
setting *means*. This file is about whether it is consulted at all. A setting
that is resolved and never consulted looks like protection and is not, so what
matters is that **each verb consults it** — and that adding it to one verb does
not leave the others behind.

Two properties carry the file:

* **a refused run mutates nothing**, asserted on the store and the recorded
  statements rather than on the exit code;
* **the gate is the same gate everywhere** — one parametrised case per verb, so a
  verb added later without the gate fails here rather than shipping unguarded.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

import click
import pytest
from click.testing import CliRunner, Result

from sopuli import cli as cli_module
from sopuli.admin import Resolved
from sopuli.cli import cli
from sopuli.config.model import Vault
from sopuli.config.targets import EXTERNAL
from sopuli.driver.protocol import (
    EXPIRE_PASSWORD,
    PASS,
    PASSWORD_ROLLOVER,
    ChangeResult,
    Credential,
    PrivilegeAudit,
    Scope,
    UserState,
    VerifyResult,
)
from sopuli.exit_codes import ExitCode
from sopuli.safety import RefusedError
from sopuli.secrets import Secret
from sopuli.store import MemoryStore, SecretStore
from sopuli.store.protocol import StoreError
from sopuli.store.registry import BackendNotInstalledError

LIVE = "Correct-Horse-Battery-9"
STAGED = "Vertical-Anchor-Marble-4"

#: Two targets in two environments, so a selector can narrow a run *out* of the
#: listed one -- which is the case that separates "asks about the run" from
#: "asks about the estate".
CONFIG = """\
version: 1
defaults:
  policy: app-standard
  safety:
    confirm_environments: [prod]
policies:
  app-standard:
    password: { length: 24, charset: alnum, first_char: alpha }
vaults:
  vault-prod:
    type: hashicorp
    addr: https://vault-prod.example.com:8200
targets:
  - name: appdb-alpha
    type: oracle
    dsn: db-prod.example.com:1521/alpha.pdb.example.com
    environment: prod
    labels: { env: prod, tenant: alpha }
    vault: vault-prod
  - name: appdb-beta
    type: oracle
    dsn: db-dev.example.com:1521/beta.pdb.example.com
    environment: dev
    labels: { env: dev, tenant: beta }
    vault: vault-prod
applications:
  - name: acme
    accounts: [acme_web_user]
    secret_template: "apps/acme/{target}#DB_CREDENTIALS/{account}"
"""

#: The same estate with nobody asking to be asked, which is what every other
#: suite in this repository is implicitly running under.
UNGUARDED = CONFIG.replace("  safety:\n    confirm_environments: [prod]\n", "")


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


class FakeSession:
    def __init__(self, *, rollover: bool = False, window: bool = False) -> None:
        self.rollover = rollover
        #: A window already open before the run, as a rotation leaves one.
        self.window = window
        self.changed: list[tuple[str, str]] = []
        self.finished: list[str] = []

    def scope(self) -> Scope:
        capabilities = (
            frozenset({PASSWORD_ROLLOVER, EXPIRE_PASSWORD}) if self.rollover else frozenset()
        )
        return Scope(type="pdb", container="ALPHA", read_write=True, capabilities=capabilities)

    def privileges(self, *, accounts: tuple[str, ...] = ()) -> PrivilegeAudit:
        return PrivilegeAudit()

    def describe_user(self, account: str) -> UserState | None:
        return UserState(
            name=account.upper(),
            status="OPEN",
            rollover_enabled=self.rollover,
            rollover_active=self.rollover and (self.window or bool(self.changed)),
        )

    def require_rollover(self, account: str) -> None:
        return None

    def finish_rollover(self, account: str) -> ChangeResult:
        self.finished.append(account.upper())
        return ChangeResult(changed=True, detail="rollover window ended")

    def verify_password(self, account: str, secret: Secret, **_: Any) -> VerifyResult:
        return VerifyResult("login", PASS, latency_ms=9)

    def set_password(
        self, account: str, secret: Secret, *, old_password: str = "discard"
    ) -> ChangeResult:
        self.changed.append((account.upper(), secret.reveal()))
        return ChangeResult(changed=True)

    def close(self) -> None:
        return None


Harness = Callable[..., dict[str, Any]]


@pytest.fixture
def estate(monkeypatch: pytest.MonkeyPatch) -> Harness:
    def install(*, rollover: bool = False, window: bool = False) -> dict[str, Any]:
        store = MemoryStore()
        for target in ("appdb-alpha", "appdb-beta"):
            store.write(
                f"apps/acme/{target}",
                {"DB_CREDENTIALS": {"acme_web_user": LIVE}, "pending": {"acme_web_user": STAGED}},
                cas=0,
            )
        sessions: list[FakeSession] = []

        def fake_connect(
            vault: Vault, *, env: Mapping[str, str], token_file: Path | None = None
        ) -> SecretStore:
            return store

        class FakeDriver:
            def __init__(self, context: Any) -> None:
                pass

            def connect(self, target: Any, credential: Any) -> FakeSession:
                session = FakeSession(rollover=rollover, window=window)
                sessions.append(session)
                return session

        monkeypatch.setattr("sopuli.cli.connect", fake_connect)
        monkeypatch.setattr("sopuli.cli.driver_for", lambda target, context: FakeDriver(context))
        monkeypatch.setattr("sopuli.cli.admin_resolve", lambda target, **_: _credential())
        return {"store": store, "sessions": sessions}

    return install


def _credential() -> Any:
    """The admin credential the CLI would have resolved.

    A real :class:`~sopuli.admin.Resolved` rather than a stub with one attribute.
    The command reads its *provenance* as well as its value -- it reports
    where an admin credential came from -- and a stub stops being enough the
    moment anything but `.credential` is read. `external` because these estates
    declare no `admin:` block at all, and it is the one source that carries
    neither a username nor a secret.
    """
    return Resolved(
        credential=Credential(external=True),
        method=EXTERNAL,
        source="an external password store",
    )


def versions(harness: dict[str, Any]) -> dict[str, int]:
    """Every document's version, so "nothing was written" is one comparison."""
    return {
        path: harness["store"].read(path).version
        for path in ("apps/acme/appdb-alpha", "apps/acme/appdb-beta")
    }


def issued(harness: dict[str, Any]) -> list[tuple[str, str]]:
    return [one for session in harness["sessions"] for one in session.changed]


def radius(result: Result) -> int:
    """How many targets the run resolved to, from its own plan.

    The declined `max_targets` trigger (decision C17) is about the *radius*, so a
    test for it has to establish the radius rather than infer it from an estate
    that happened to be written to twice.
    """
    return int(json.loads(result.output)["plan"]["blast_radius"]["targets"])


def reached(result: Result) -> list[str]:
    """The environments the run resolved to, likewise."""
    return list(json.loads(result.output)["plan"]["blast_radius"]["environments"])


#: Every verb the setting governs, and the argv that reaches its mutation.
#: `creds rotate` is absent on purpose -- it asks unconditionally (UC-1 §8 step
#: 1), so the setting can only ever make its gate weaker. Its own suite covers
#: that, and a case here would assert the wrong reason for the right outcome.
VERBS = [
    pytest.param(["creds", "generate", "--overwrite-pending"], id="generate"),
    pytest.param(["creds", "apply"], id="apply"),
    pytest.param(["creds", "finish-rollover"], id="finish-rollover"),
]


def run(runner: CliRunner, argv: list[str], config: Path, *args: str) -> Result:
    return runner.invoke(cli, [*argv, "--config", str(config), *args])


# ------------------------------------------------------- every verb consults it ---


@pytest.mark.parametrize("argv", VERBS)
def test_an_unattended_run_into_a_listed_environment_is_refused(
    argv: list[str], runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """The point of the setting: a listed environment is refused, not waved through.

    `CliRunner` has no terminal, which is the scheduler's situation exactly.
    """
    harness = estate()
    before = versions(harness)
    result = run(runner, argv, write_config(CONFIG), "--select", "tenant=alpha")

    assert result.exit_code != ExitCode.SUCCESS
    assert versions(harness) == before
    assert issued(harness) == []


@pytest.mark.parametrize("argv", VERBS)
def test_confirm_satisfies_the_setting(
    argv: list[str], runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """P5 says every mutating command supports `--confirm`, and the setting says
    these environments are not entered without an explicit yes. The flag is that
    yes given in advance -- so it satisfies the gate rather than being a second
    one that also has to pass."""
    estate()
    result = run(runner, argv, write_config(CONFIG), "--select", "tenant=alpha", "--confirm")

    assert result.exit_code == ExitCode.SUCCESS


@pytest.mark.parametrize("argv", VERBS)
def test_a_run_narrowed_out_of_the_listed_environment_is_not_gated(
    argv: list[str], runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """Matched against the run, not the estate. An implementation reading the
    config rather than the blast radius would stop this, and a gate that asks
    every time is one that gets turned off."""
    estate()
    result = run(runner, argv, write_config(CONFIG), "--select", "tenant=beta")

    assert result.exit_code == ExitCode.SUCCESS


@pytest.mark.parametrize("argv", VERBS)
def test_an_unguarded_config_is_unaffected(
    argv: list[str], runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """No built-in, so an estate that never wrote the key keeps behaving exactly
    as it did -- which is every other suite in this repository."""
    estate()
    result = run(runner, argv, write_config(UNGUARDED), "--select", "tenant=alpha")

    assert result.exit_code == ExitCode.SUCCESS


@pytest.mark.parametrize("argv", VERBS)
def test_a_dry_run_is_never_gated(
    argv: list[str], runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """The opposite of what `readonly` does, for the opposite reason. `readonly`
    is about whether the verb is available; this is about assent, and a preview
    is how somebody decides what to assent to. Prompting before showing the plan
    would ask for a yes to the question they ran the command to see."""
    harness = estate()
    before = versions(harness)
    result = run(runner, argv, write_config(CONFIG), "--select", "tenant=alpha", "--dry-run")

    assert result.exit_code == ExitCode.SUCCESS
    assert versions(harness) == before


# ------------------------------------------------- the triggers that were declined ---
#
# P5 asked for three confirmation triggers and decision C17 kept one. The other
# two are **declined, not deferred**, which is a thing tests can say and prose
# cannot: if somebody later reads the absent behaviour as a gap and builds it,
# these fail.
#
# Both run unattended -- `CliRunner` has no terminal -- so a gate that fired would
# refuse (exit 8) rather than block on a prompt. What is asserted is the exit code
# plus the **plan**: that the run really did resolve to a prod target, or to two
# targets, so a case that quietly narrowed to nothing cannot pass by having
# nothing to be gated about. Deliberately not "the estate was written to":
# `creds finish-rollover` legitimately writes nothing when no window is open, and
# an assertion it cannot satisfy is one that gets deleted rather than fixed.


@pytest.mark.parametrize("argv", VERBS)
def test_a_prod_target_nobody_listed_is_not_prompted_for(
    argv: list[str], runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """P5's second trigger, declined: `environment: prod` is a label like any other.

    A built-in `confirm_environments: [prod]` is what that trigger amounts to, and
    `01-configuration.md` §9 forbids a built-in that joins a union ratchet — no
    layer could remove `prod` again, and §9 uses `confirm` itself as the worked
    example of that trap. So the estate below marks a target `prod`, lists
    nothing, and is not asked.

    `tenant=alpha` **is** the prod target, which is what makes this the trigger's
    case rather than a general smoke test -- and it is asserted from the plan
    rather than from a write, because `creds finish-rollover` legitimately writes
    nothing when no window is open and would pass a "the estate changed" check
    vacuously.
    """
    estate()
    result = run(
        runner, argv, write_config(UNGUARDED), "--select", "tenant=alpha", "--output", "json"
    )

    assert result.exit_code == ExitCode.SUCCESS
    assert reached(result) == ["prod"]


@pytest.mark.parametrize("argv", VERBS)
def test_a_multi_target_run_is_not_prompted_for(
    argv: list[str], runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """P5's third trigger, declined: blast radius is not a confirmation threshold.

    "Confirmation is required when blast radius exceeds `max_targets` (default 1)"
    would make **every** multi-target mutation prompt on an estate that wrote no
    safety block — which is most estates and every other suite in this repository.
    `max_targets` is a ceiling, and `refuse_if_over_limit` already declines to read
    an unset one as a limit of anything.

    No selector, so both targets are in scope: the radius is 2 against an unset
    ceiling, which is exactly the combination the declined trigger would have
    caught. The radius is read off the plan rather than assumed -- a run that
    resolved to one target would pass the exit-code check while testing nothing.
    """
    estate()
    result = run(runner, argv, write_config(UNGUARDED), "--output", "json")

    assert result.exit_code == ExitCode.SUCCESS
    assert radius(result) == 2


def test_the_declined_triggers_do_not_return_when_the_setting_is_present(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """The combination, because the two decisions could disagree and only here.

    An estate that lists `dev` and runs against `prod` gets **no** prompt: the
    setting is what decides, and `environment: prod` contributes nothing of its
    own. A built-in that had survived as a union member would show up precisely
    here — as a gate firing on an environment the file did not name.
    """
    harness = estate()
    before = versions(harness)
    listed_dev = CONFIG.replace("confirm_environments: [prod]", "confirm_environments: [dev]")
    result = run(runner, ["creds", "apply"], write_config(listed_dev), "--select", "tenant=alpha")

    assert result.exit_code == ExitCode.SUCCESS
    assert versions(harness) != before, "`creds apply` writes, so this one can say so"


# --------------------------------------------------------------- the refusal ---


def test_the_refusal_names_the_setting_the_place_and_the_remedy(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """Asserted on the exception rather than on stdout.

    `main()` is what maps a `ConfigError` to its exit code and prints it;
    `CliRunner` invokes the group, so a refusal reaches the test as the raised
    exception and stdout stays empty. Every other suite here asserts refusals the
    same way.
    """
    estate()
    result = run(runner, ["creds", "apply"], write_config(CONFIG), "--select", "tenant=alpha")

    assert isinstance(result.exception, RefusedError)
    assert "safety.confirm_environments" in str(result.exception)
    assert "prod" in str(result.exception)
    assert "--confirm" in str(result.exception.hint)


def test_the_refusal_is_a_policy_decision_and_not_a_broken_config(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """Exit 8 with category `policy` through the boundary that maps it -- exit 9
    would send a scheduler to look for a defect in a file that is right."""
    estate()
    result = run(
        runner,
        ["creds", "apply"],
        write_config(CONFIG),
        "--select",
        "tenant=alpha",
        "--output",
        "json",
    )

    body = json.loads(result.output)
    assert body["error"]["category"] == "policy"
    assert body["exit_code"] == ExitCode.ABORTED


def test_it_refuses_before_the_database_is_reached(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """Invariant 4's timing, and `readonly`'s precedent: the refusal happens at
    plan time, so a gated run spends no connection and no login attempt."""
    harness = estate()
    run(runner, ["creds", "apply"], write_config(CONFIG), "--select", "tenant=alpha")

    assert harness["sessions"] == []


def test_a_run_spanning_both_environments_is_gated_by_the_listed_one(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """One prod target in a run of ten is still a run that reaches prod, and the
    gate is about reach rather than proportion."""
    harness = estate()
    result = run(runner, ["creds", "apply"], write_config(CONFIG))

    assert result.exit_code != ExitCode.SUCCESS
    assert issued(harness) == []


# ------------------------------------------------------------ the other gates ---


def test_force_does_not_satisfy_it(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """Decision P3: `--force` overrides the account guardrails of §4 and never a
    safety setting. It is not a setting, has no layer to arrive on, and so has
    nothing to relax (invariant 10).

    `creds apply` has a real `--force` -- it waives §4's *account* guardrails --
    so this asserts the claim directly rather than relying on the parser to
    reject the flag. The run is accepted as valid argv and still refused by the
    confirmation gate.
    """
    estate()
    result = run(
        runner, ["creds", "apply"], write_config(CONFIG), "--select", "tenant=alpha", "--force"
    )

    assert isinstance(result.exception, RefusedError)
    assert "safety.confirm_environments" in str(result.exception)


def test_readonly_still_outranks_it(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """Both refuse on exit 8, so what is asserted is that answering the weaker
    gate does not make the run available: `--confirm` satisfies confirmation and
    nothing satisfies `readonly`.

    `readonly` is set **in the file**, which is the only place it can be set --
    there is no `--readonly` flag, by design (invariant 10: a flag would be a
    layer, and a layer is something that could later be argued about).
    """
    estate()
    result = run(
        runner,
        ["creds", "apply"],
        write_config(CONFIG.replace("    confirm_environments: [prod]", "    readonly: true")),
        "--select",
        "tenant=alpha",
        "--confirm",
    )

    assert isinstance(result.exception, RefusedError)
    assert "safety.readonly" in str(result.exception)


# ------------------------------------------------------- a profile's `confirm:` ---

#: The guarded estate with a profile that says nobody can answer.
PROFILED = CONFIG + "profiles:\n  ci:\n    confirm: false\n  desk:\n    confirm: true\n"


@pytest.mark.parametrize("argv", VERBS)
def test_a_profile_that_cannot_answer_refuses_even_at_a_terminal(
    argv: list[str],
    runner: CliRunner,
    write_config: Callable[[str], Path],
    estate: Harness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`confirm: false` makes a gated run refuse with exit 8 (P5). A terminal is
    faked, so the refusal is the profile's rather than the missing stdin's."""
    monkeypatch.setattr("sopuli.cli._can_prompt", lambda: True)
    harness = estate()
    before = versions(harness)
    result = run(
        runner, argv, write_config(PROFILED), "--select", "tenant=alpha", "--profile", "ci"
    )

    assert isinstance(result.exception, RefusedError)
    assert result.exception.exit_code == ExitCode.ABORTED
    assert "profiles.ci.confirm" in str(result.exception.hint)
    assert versions(harness) == before
    assert issued(harness) == []


@pytest.mark.parametrize("argv", VERBS)
def test_confirm_answers_a_profile_that_cannot(
    argv: list[str], runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """`--confirm` is the yes given in advance, so nothing is left to ask."""
    estate()
    result = run(
        runner,
        argv,
        write_config(PROFILED),
        "--select",
        "tenant=alpha",
        "--profile",
        "ci",
        "--confirm",
    )

    assert result.exit_code == ExitCode.SUCCESS


def test_a_profile_that_can_answer_still_needs_a_terminal(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """`confirm: true` cannot make a prompt answerable where there is no stdin."""
    estate()
    result = run(
        runner,
        ["creds", "apply"],
        write_config(PROFILED),
        "--select",
        "tenant=alpha",
        "--profile",
        "desk",
    )

    assert isinstance(result.exception, RefusedError)
    assert "profile" not in str(result.exception)


def test_the_profile_answer_is_reported(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """A setting that changed a run appears in `invocation.options`."""
    estate()
    result = run(
        runner,
        ["creds", "apply"],
        write_config(PROFILED),
        "--select",
        "tenant=beta",
        "--profile",
        "ci",
        "--output",
        "json",
    )

    options = json.loads(result.output)["invocation"]["options"]
    assert options["confirm"]["value"] is False
    assert options["confirm"]["source_detail"] == "profiles.ci.confirm"


# ------------------------------------------------- plan.confirmation_required ---


def required(result: Result) -> bool:
    """The run document's answer to "does the real run need a yes"."""
    return bool(json.loads(result.output)["plan"]["confirmation_required"])


@pytest.mark.parametrize("argv", VERBS)
@pytest.mark.parametrize("answer", ["--dry-run", "--confirm"])
def test_a_gated_plan_says_so_however_the_gate_was_answered(
    argv: list[str],
    answer: str,
    runner: CliRunner,
    write_config: Callable[[str], Path],
    estate: Harness,
) -> None:
    """Neither run prompts, and both report the value of the run that would.
    `plan` is the same on a dry run and a real run (#663)."""
    estate()
    result = run(
        runner, argv, write_config(CONFIG), "--select", "tenant=alpha", answer, "--output", "json"
    )

    assert result.exit_code == ExitCode.SUCCESS
    assert required(result) is True


@pytest.mark.parametrize("argv", VERBS)
@pytest.mark.parametrize(
    ("config", "tenant"), [(CONFIG, "beta"), (UNGUARDED, "alpha")], ids=["unlisted", "unguarded"]
)
def test_a_plan_no_gate_covers_says_so(
    argv: list[str],
    config: str,
    tenant: str,
    runner: CliRunner,
    write_config: Callable[[str], Path],
    estate: Harness,
) -> None:
    """`false` is a claim, and it is true here: the real run asks nothing."""
    estate()
    result = run(
        runner, argv, write_config(config), "--select", f"tenant={tenant}", "--output", "json"
    )

    assert result.exit_code == ExitCode.SUCCESS
    assert required(result) is False


@pytest.mark.parametrize("verb", ["check", "status"])
def test_a_verb_that_changes_nothing_needs_no_yes(
    verb: str, runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """Into a listed environment, which is the case a reading of the setting
    alone would get wrong."""
    estate()
    result = run(
        runner,
        ["creds", verb],
        write_config(CONFIG),
        "--select",
        "tenant=alpha",
        "--output",
        "json",
    )

    assert required(result) is False


def test_the_config_warnings_are_printed_before_the_prompt(
    runner: CliRunner,
    write_config: Callable[[str], Path],
    estate: Harness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """W051 can say the run is about to write to another vault, so the operator
    reads it before answering, and a declined prompt does not print it again
    (#897). This estate names no default store, so the variable raises W038
    instead; where the block goes is the same for every warning."""
    monkeypatch.setenv("VAULT_ADDR", "https://vault-other.example.com:8200")
    monkeypatch.setattr("sopuli.cli._can_prompt", lambda: True)
    estate()
    config = write_config(CONFIG)

    result = runner.invoke(
        cli,
        ["creds", "apply", "--config", str(config), "--select", "tenant=alpha"],
        input="n\n",
    )

    assert result.exit_code == ExitCode.ABORTED, result.output
    assert result.output.count("1 warning:") == 1
    assert result.output.index("1 warning:") < result.output.index("[y/N]")


# ------------------------------------------- the question after the checks ---

#: The verbs that open their stores before they ask (#1257).
READ_FIRST = [
    pytest.param(["creds", "apply"], id="apply"),
    pytest.param(["creds", "apply", "--source", "previous"], id="apply-rollback"),
    pytest.param(["creds", "finish-rollover"], id="finish-rollover"),
]


@pytest.mark.parametrize("argv", READ_FIRST)
def test_a_store_refusal_comes_before_the_question(
    argv: list[str],
    runner: CliRunner,
    write_config: Callable[[str], Path],
    estate: Harness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A yes followed by a refusal means nothing (#1257). At a terminal, a run
    whose store cannot be opened is refused before anybody is asked: the
    `confirm_environments` question, and on `--source previous` the rollback's.
    The store's client not being installed (exit 9) is the case the #1251
    review named."""
    estate()
    asked: list[str] = []

    def refusing(vault: Vault, **_: Any) -> SecretStore:
        raise BackendNotInstalledError(f"the client for `{vault.name}` is not installed")

    def answer(question: str, **_: Any) -> bool:
        asked.append(question)
        return True

    monkeypatch.setattr("sopuli.cli.connect", refusing)
    monkeypatch.setattr("sopuli.cli._can_prompt", lambda: True)
    monkeypatch.setattr("sopuli.cli._confirm", answer)
    result = run(runner, argv, write_config(CONFIG), "--select", "tenant=alpha")

    assert isinstance(result.exception, BackendNotInstalledError), result.output
    assert asked == []


@pytest.mark.parametrize("argv", READ_FIRST)
def test_the_plan_comes_before_the_store_and_the_question_after(
    argv: list[str],
    runner: CliRunner,
    write_config: Callable[[str], Path],
    estate: Harness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The plan is printed before the first connection, so a store or target
    that asks for a password asks after the operator has seen it (invariant 8),
    and the question comes after the stores are read. A no takes no lock and
    changes nothing."""
    harness = estate()
    before = versions(harness)
    events: list[str] = []
    store: SecretStore = harness["store"]

    def opening(vault: Vault, **_: Any) -> SecretStore:
        events.append("store")
        return store

    def showing(plan: Any, run: Any, *, noun: str) -> None:
        events.append("plan")

    def declining(question: str, **_: Any) -> bool:
        events.append("asked")
        raise click.Abort

    monkeypatch.setattr("sopuli.cli.connect", opening)
    monkeypatch.setattr("sopuli.cli._show_plan", showing)
    monkeypatch.setattr("sopuli.cli._can_prompt", lambda: True)
    monkeypatch.setattr("sopuli.cli._confirm", declining)
    result = run(runner, argv, write_config(CONFIG), "--select", "tenant=alpha")

    assert result.exit_code == ExitCode.ABORTED, result.output
    # The stubbed `_show_plan` does not mark the plan shown, so a run that asks
    # twice records "plan" twice; only the order matters here.
    assert list(dict.fromkeys(events)) == ["plan", "store", "asked"]
    assert events.count("asked") == 1
    assert versions(harness) == before
    assert issued(harness) == []
    assert harness["sessions"] == []


@pytest.mark.parametrize("argv", READ_FIRST)
def test_a_store_that_cannot_be_read_refuses_before_the_question(
    argv: list[str],
    runner: CliRunner,
    write_config: Callable[[str], Path],
    estate: Harness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Opening a store with token auth connects to nothing, so a wrong token or
    a denied path shows only at the first read. That read comes before the
    question (#1257)."""
    harness = estate()
    asked: list[str] = []

    def denied(path: str, **_: Any) -> Any:
        raise StoreError(f"permission denied reading `{path}`")

    def answer(question: str, **_: Any) -> bool:
        asked.append(question)
        return True

    monkeypatch.setattr(harness["store"], "read", denied)
    monkeypatch.setattr("sopuli.cli._can_prompt", lambda: True)
    monkeypatch.setattr("sopuli.cli._confirm", answer)
    result = run(runner, argv, write_config(CONFIG), "--select", "tenant=alpha")

    assert result.exit_code != ExitCode.SUCCESS, result.output
    assert asked == []
    assert issued(harness) == []


def test_a_pending_staged_while_the_question_waits_keeps_the_window_open(
    runner: CliRunner,
    write_config: Callable[[str], Path],
    estate: Harness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`creds finish-rollover` reads before its question and again after the
    answer, which can take minutes. A `pending` a rotation staged meanwhile
    keeps the window open: closing it would cut off whatever has not been given
    the new password."""
    harness = estate(rollover=True, window=True)
    store: MemoryStore = harness["store"]
    path = "apps/acme/appdb-alpha"
    stored = store.read(path)
    assert stored is not None
    store.write(path, {"DB_CREDENTIALS": {"acme_web_user": LIVE}}, cas=stored.version)

    def staging(question: str, **_: Any) -> bool:
        now = store.read(path)
        assert now is not None
        store.write(
            path,
            {"DB_CREDENTIALS": {"acme_web_user": LIVE}, "pending": {"acme_web_user": STAGED}},
            cas=now.version,
        )
        return True

    monkeypatch.setattr("sopuli.cli._can_prompt", lambda: True)
    monkeypatch.setattr("sopuli.cli._confirm", staging)
    run(runner, ["creds", "finish-rollover"], write_config(CONFIG), "--select", "tenant=alpha")

    assert harness["sessions"], "the run reached the database"
    assert [one for session in harness["sessions"] for one in session.finished] == []


def test_with_nothing_staged_the_window_is_closed(
    runner: CliRunner,
    write_config: Callable[[str], Path],
    estate: Harness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The control for the test above: the same estate, answered yes with
    nothing staged, closes the window."""
    harness = estate(rollover=True, window=True)
    store: MemoryStore = harness["store"]
    path = "apps/acme/appdb-alpha"
    stored = store.read(path)
    assert stored is not None
    store.write(path, {"DB_CREDENTIALS": {"acme_web_user": LIVE}}, cas=stored.version)

    monkeypatch.setattr("sopuli.cli._can_prompt", lambda: True)
    monkeypatch.setattr("sopuli.cli._confirm", lambda question, **_: True)
    run(runner, ["creds", "finish-rollover"], write_config(CONFIG), "--select", "tenant=alpha")

    assert [one for session in harness["sessions"] for one in session.finished] == ["ACME_WEB_USER"]


@pytest.mark.parametrize("terminal", [True, False], ids=["terminal", "unattended"])
@pytest.mark.parametrize(
    "argv",
    [
        ["creds", "apply"],
        ["creds", "finish-rollover"],
        ["creds", "generate"],
        ["creds", "rotate"],
    ],
)
def test_a_run_with_nothing_to_do_is_neither_asked_nor_refused(
    argv: list[str],
    terminal: bool,
    runner: CliRunner,
    write_config: Callable[[str], Path],
    estate: Harness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A selection that binds no secret does nothing, so a yes to it would mean
    nothing, and a scheduler is not refused for lacking one (#1257)."""
    estate()
    asked: list[str] = []

    def answer(question: str, **_: Any) -> bool:
        asked.append(question)
        return True

    monkeypatch.setattr("sopuli.cli._can_prompt", lambda: terminal)
    monkeypatch.setattr("sopuli.cli._confirm", answer)
    unbound = write_config(CONFIG.replace("secret_template", "# secret_template"))
    result = run(runner, argv, unbound, "--select", "tenant=alpha")

    assert result.exit_code == ExitCode.SUCCESS, result.output
    assert "nothing to" in result.output
    assert asked == []
    reported = run(runner, argv, unbound, "--select", "tenant=alpha", "--output", "json")
    assert required(reported) is False


# ------------------------------------- generate and rotate, in that order ---

#: The verbs #1261 reordered. `creds rotate` asks every run, so these cases
#: hold for it with or without the setting.
ASK_LAST = [
    pytest.param(["creds", "generate", "--overwrite-pending"], id="generate"),
    pytest.param(["creds", "rotate"], id="rotate"),
]


def _recording(
    monkeypatch: pytest.MonkeyPatch, harness: dict[str, Any], *, answer: bool
) -> list[str]:
    """Record the store logins, the target logins, the plan and the question,
    in the order they happen. The question is answered ``answer``."""
    events: list[str] = []
    store: SecretStore = harness["store"]
    # The fake `estate` installed, wrapped below. Read from the namespace, as
    # `sopuli.cli` re-exports nothing.
    connect_target: Callable[..., Any] = vars(cli_module)["driver_for"]

    def opening(vault: Vault, **_: Any) -> SecretStore:
        events.append("store")
        return store

    class Recording:
        def __init__(self, driver: Any) -> None:
            self.driver = driver

        def connect(self, target: Any, credential: Any) -> Any:
            events.append("target")
            return self.driver.connect(target, credential)

    def showing(plan: Any, run: Any, *, noun: str) -> None:
        events.append("plan")

    def asking(question: str, **_: Any) -> bool:
        events.append("asked")
        if not answer:
            raise click.Abort
        return True

    monkeypatch.setattr("sopuli.cli.connect", opening)
    monkeypatch.setattr(
        "sopuli.cli.driver_for",
        lambda target, context: Recording(connect_target(target, context)),
    )
    monkeypatch.setattr("sopuli.cli._show_plan", showing)
    monkeypatch.setattr("sopuli.cli._can_prompt", lambda: True)
    monkeypatch.setattr("sopuli.cli._confirm", asking)
    return events


@pytest.mark.parametrize("argv", ASK_LAST)
@pytest.mark.parametrize("terminal", [True, False], ids=["profile", "no-terminal"])
def test_a_run_nobody_can_answer_is_refused_before_any_login(
    argv: list[str],
    terminal: bool,
    runner: CliRunner,
    write_config: Callable[[str], Path],
    estate: Harness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A profile with `confirm: false`, or no terminal, is refused before the
    run logs in to a store or a target (#1261)."""
    harness = estate()
    events = _recording(monkeypatch, harness, answer=True)
    monkeypatch.setattr("sopuli.cli._can_prompt", lambda: terminal)
    profile = ("--profile", "ci") if terminal else ()
    result = run(runner, argv, write_config(PROFILED), "--select", "tenant=alpha", *profile)

    assert isinstance(result.exception, RefusedError), result.output
    assert result.exception.exit_code == ExitCode.ABORTED
    assert events == []


@pytest.mark.parametrize(
    ("argv", "order"),
    [
        # The plan waits for the read, which fills in its stages, and comes
        # before the constraint reading's target login.
        pytest.param(
            ["creds", "generate", "--overwrite-pending"],
            ["store", "plan", "target", "asked"],
            id="generate",
        ),
        # The plan comes before every login. This estate requires no
        # encryption and no attribute, so rotate makes no target login before
        # the question.
        pytest.param(["creds", "rotate"], ["plan", "store", "asked"], id="rotate"),
    ],
)
def test_the_question_comes_after_the_logins(
    argv: list[str],
    order: list[str],
    runner: CliRunner,
    write_config: Callable[[str], Path],
    estate: Harness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The question comes after every login the plan-time checks make, so a
    refusal from one of them never follows a yes (#1261). A no changes
    nothing."""
    harness = estate()
    before = versions(harness)
    events = _recording(monkeypatch, harness, answer=False)
    result = run(runner, argv, write_config(CONFIG), "--select", "tenant=alpha")

    assert result.exit_code == ExitCode.ABORTED, result.output
    assert list(dict.fromkeys(events)) == order
    assert events.count("asked") == 1
    assert versions(harness) == before
    assert issued(harness) == []


@pytest.mark.parametrize("promote", [False, True], ids=["pending", "current"])
def test_a_refusal_the_read_decides_comes_before_the_question(
    promote: bool,
    runner: CliRunner,
    write_config: Callable[[str], Path],
    estate: Harness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A staged `pending` without `--overwrite-pending`, or under `--promote` a
    `current` without `--overwrite-current`, is refused before anybody is asked,
    not after a yes (#1261)."""
    harness = estate()
    before = versions(harness)
    events = _recording(monkeypatch, harness, answer=True)
    flags = ("--promote", "--overwrite-pending") if promote else ()
    result = run(
        runner, ["creds", "generate", *flags], write_config(CONFIG), "--select", "tenant=alpha"
    )

    assert isinstance(result.exception, RefusedError), result.output
    assert result.exception.exit_code == ExitCode.ABORTED
    expected = "--overwrite-current" if promote else "--overwrite-pending"
    assert expected in str(result.exception.hint)
    assert "asked" not in events
    assert versions(harness) == before
