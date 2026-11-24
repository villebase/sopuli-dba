"""Resolving the admin credential: P2's sources, at connect time.

``admin:`` is parsed by :mod:`sopuli.config.targets` and validated against its
target by :mod:`sopuli.config.references`. This module resolves it when a command
connects. It is the database half of what :mod:`sopuli.material` does for vault
material: turn a named source into a :class:`~sopuli.secrets.Secret`.

P2's bootstrap list, in its order of preference:

=============== ================================================================
``external``    a wallet, Kerberos, OS auth -- there is no material to resolve
``vault``       a whole SecretRef (§7), resolved through the target's store
``prompt``      interactive
``keyring``     ``entry:``, under the service ``sopuli`` in the OS keyring (#1417)
``env``         ``password_env:``, defaulting to ``SOPULI_DB_ADMIN_PASSWORD``
=============== ================================================================

**Here rather than in** :mod:`sopuli.config`, for the reason
:mod:`sopuli.material` gives at greater length: prompting and reading the
environment are I/O, and ``04-testing.md`` §4 makes the config layer I/O-free as
an architecture requirement rather than a test convenience. The file names a
location; this reads it, when something connects.

**Resolution is a function over a ref, never a method on one.** An
:class:`~sopuli.config.model.AdminCredential` that had been "resolved" would
have to hold the value, and the guarantee ends the moment somebody caches one.

**Every source arrives through a supplier the caller passes in.** ``env`` is a
mapping, ``prompt`` is a callable, ``vault`` is a callable over a ref. Three
consequences, and the first two are the reasons:

* a run that authenticates by wallet never builds a store client, because the
  ``vault`` branch is the only thing that calls one and a function is lazy;
* ``prompt=None`` is how "nobody is at a terminal" is expressed, so the refusal
  in :func:`_from_prompt` is reachable in a test without a pty;
* the ``vault`` branch has no implementation to wait for. Resolving a SecretRef
  against a stored document is :func:`sopuli.store.credentials.resolve`'s, and
  this module deliberately does not reimplement it -- Q7's "one rule for both
  layouts" would be two rules the day it did.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field

from sopuli import os_keyring
from sopuli.config.bindings import admin_store_in_file
from sopuli.config.errors import ROOT, ConfigError, KeyPath
from sopuli.config.expansion import declared_at, run_as_at
from sopuli.config.model import AdminAuth, AdminCredential, Config, ExpandedTarget, MaterialRef
from sopuli.config.secret_refs import SecretRef
from sopuli.config.targets import ADMIN_METHODS, ADMIN_PASSWORD_ENV, EXTERNAL
from sopuli.config.vault_env import DEFAULT_STORE_VARIABLE
from sopuli.driver.protocol import Credential
from sopuli.exit_codes import ExitCode
from sopuli.material import MaterialError
from sopuli.material import resolve as resolve_material
from sopuli.secrets import Secret

#: §6's username variable. Overrides a target's ``username:`` per execution
#: context, and is ignored under ``external`` -- see :func:`_username`.
ADMIN_USER_ENV = "SOPULI_DB_ADMIN_USER"

#: The config keys a credential is written under, for an error's location and words.
ADMIN_BLOCK = "admin"
RUN_AS_BLOCK = "run_as"
#: Not a key: the account came from the command line, so no key in the file is at fault.
AS_BLOCK = "--as"

VAULT = "vault"
PROMPT = "prompt"
ENV = "env"
KEYRING = "keyring"

#: The method whose material is an environment variable, and so the one P2
#: requires be "flagged in output as low-assurance". A set of one rather than
#: ``method == ENV`` at each call site, because what gets reported is
#: *assurance* and not *which method*: a second low-assurance source would
#: otherwise have to find every reporting site again.
LOW_ASSURANCE = frozenset({ENV})

#: Reads a §7 ref and returns its value. Supplied by the caller, because the
#: store it resolves against is authenticated well before this module is reached
#: and the store layer owns what a credential document looks like.
RefReader = Callable[[SecretRef], Secret]

#: Asks for one target's admin password, given the target and the username the
#: connection will actually use. Both, rather than a line of text, so that the
#: prompter can decide whether it has been asked this before -- see
#: :class:`PasswordPrompt`.
Prompter = Callable[[ExpandedTarget, "str | None"], Secret]

#: The admin credential sources that need nobody at a terminal, for a hint.
UNATTENDED_SOURCES = (
    "name a source that needs no one: "
    "`auth: { method: vault, secret: … }`, `auth: { method: keyring, entry: … }`, "
    f"`auth: {{ method: env }}` reading ${ADMIN_PASSWORD_ENV}, or `auth: external` "
    "with a wallet"
)

#: The same for `run_as:`, which has no `vault` method and never reads the
#: admin's variable (UC-3 §2).
RUN_AS_UNATTENDED_SOURCES = (
    "name a source that needs no one: `auth: { method: keyring, entry: … }`, "
    "`auth: { method: env, password_env: … }`, or `auth: external` with a wallet"
)

#: Shows a line and reads a password without echoing it. Returns a ``str``, and
#: that is deliberate: :func:`getpass.getpass` is the obvious implementation and
#: this makes it usable *as it is*, with :class:`PasswordPrompt` wrapping the
#: result exactly once. A contract returning :class:`~sopuli.secrets.Secret`
#: would put that wrapping in every supplier instead, which is invariant 2's own
#: argument against remembering to mask at a call site: a supplier that forgot
#: would put a bare ``str`` into :attr:`Resolved.credential`, where ``repr``
#: prints it in full.
#:
#: The module does not name :mod:`getpass` itself. Importing it here would put a
#: terminal read one import away from the config layer, and the CLI is where the
#: decision *whether there is a terminal* already lives.
Asker = Callable[[str], str]


class AdminCredentialError(ConfigError):
    """The named source for a target's admin credential held nothing usable.

    ``config`` and exit 9, matching :class:`~sopuli.material.MaterialError` and
    for its reasoning: the file is not wrong in a way the parser could have
    caught and the database has refused nothing -- what is incomplete is *this
    machine and this moment*, and the person reading the message is the one who
    fixes it.

    Distinct from the exit 6 the driver raises when Oracle rejects a credential.
    That one means "we sent it and it was not accepted"; this means "there was
    nothing to send".
    """


class NobodyToAskError(AdminCredentialError):
    """``auth: prompt`` on a run with no terminal.

    Exit 8 rather than 9, the distinction ``lock break`` already draws with
    :class:`~sopuli.safety.RefusedError`: the file is right, the invocation is
    right, and the run stopped because it needed a human and there was not one.
    A scheduler branching on 9 would send somebody to look at a config file that
    has nothing wrong with it.

    The exit code reaches the process only from a verb that changes something:
    :func:`~sopuli.safety.refuse_if_nobody_to_ask` raises it before the run
    connects (decision #481). A verb that only reads reports it as one target's
    finding, and the run exits 1. ``creds generate`` reads targets only for their
    password limits, and treats it as a caveat.
    """

    exit_code = ExitCode.ABORTED
    category = "policy"


@dataclass(frozen=True)
class Resolved:
    """One target's admin credential, and where it came from.

    Two halves, deliberately apart. :attr:`credential` is what the driver takes
    -- P1's :class:`~sopuli.driver.protocol.Credential`, which is a username, a
    secret, or neither. Everything else is *provenance*, which the driver has no
    use for and the run document does: P2 requires the environment source be
    flagged low-assurance wherever it is reported, and a flag that travelled
    inside the driver's input would have to be carried back out again.

    This module classifies and does not decide. Nothing here emits a warning or
    picks an exit code for the *reporting* of a low-assurance source: the command
    that connects knows whether this run produces a document, and it is the one that
    says so.
    """

    credential: Credential
    #: Which of :data:`~sopuli.config.targets.ADMIN_METHODS` produced it.
    method: str
    #: Where the material came from, in words, for the plan and the document --
    #: ``the environment variable SOPULI_DB_ADMIN_PASSWORD``. Never the value.
    source: str

    @property
    def low_assurance(self) -> bool:
        """P2: the environment source is supported and flagged, not refused."""
        return self.method in LOW_ASSURANCE


def prompt_key(target: ExpandedTarget, username: str | None) -> str:
    """What makes two targets share one prompt.

    Prompting per target for the same credential is a bad experience -- an
    estate of thirty-four generated targets would ask thirty-four times -- and
    caching across targets that only *look* alike is a worse bug. So the key is
    **what the configuration declares**, not what the credential turns out to be:

    * the **declaration site** -- ``target_sets.appdb`` for a generated target,
      ``targets[2]`` for an explicit one. One ``target_sets:`` entry is one
      operator writing one credential down once, and every target it generates
      is covered by that act. Two explicit targets are two acts and are asked
      twice, even where the blocks are identical, because the file gives no
      reason to believe they are the same credential;
    * the **effective username** -- what :func:`_username` resolved, so §6's
      ``SOPULI_DB_ADMIN_USER`` counts. That is what distinguishes generated
      targets from one another: ``username: C##SOPULI_SVC`` across a CDB
      resolves the same everywhere and is one credential, while ``username:
      sopuli_{tenant}`` resolves differently per target and is thirty-four.

    **Effective and not as-written.** Taking it from the file alone would get both
    halves wrong at once. The operator would be asked for one account's password
    while the connection used another, since the variable overrides ``username:`` --
    so the two differ exactly when it is set. And the key would separate targets the
    variable has just made identical: ``sopuli_{tenant}`` under
    ``SOPULI_DB_ADMIN_USER`` is one account on thirty-four databases, and would have
    been asked about thirty-four times. The variable is P3's layer 2 and the file is
    layer 4; "what the configuration declares" means the resolved value, not the
    lowest layer that had an opinion.

    Deliberately **not** the username alone, which is the tempting key and the
    unsafe one: two PDBs can hold same-named local accounts with different
    passwords, and a cache keyed on the name would send the first PDB's password
    to the second and read the resulting ORA-01017 as a rotation problem.

    The DSN is deliberately not in the key either. Targets generated from one
    entry with a literal username point at different databases *by design*, and
    including the DSN would defeat the whole cache. Where those databases really
    do hold different passwords the run fails at the second one with an
    authentication error naming the target -- diagnosable, and the file's own
    claim being wrong rather than this cache guessing.
    """
    # NUL, because it cannot appear in a key path or in an Oracle identifier and
    # so cannot be smuggled in by a username to make two distinct keys collide.
    return "\x00".join((str(declared_at(target, "admin")), username or ""))


@dataclass
class PasswordPrompt:
    """A :data:`Prompter` that asks once per declared credential.

    Mutable and stateful, unlike almost everything else here, and that is the
    point: the state *is* the answer to "have we asked for this one already".
    One instance lives for one run.

    :attr:`ask` is injected rather than being :func:`getpass.getpass` directly,
    which keeps this testable without a pty and keeps the terminal read at the
    CLI boundary where the decision about whether there *is* a terminal already
    lives.

    **This is where a typed password becomes a** :class:`~sopuli.secrets.Secret`,
    and it is the only place. The asker hands back a ``str`` because every
    terminal read does; wrapping it here means a supplier cannot forget to, and
    invariant 2's guarantee holds for the prompt source the way it holds for the
    other three -- structurally, rather than because each caller remembered.

    **An empty answer is refused here, and not cached.** Oracle has no empty
    password, so one can never authenticate, and sending it would get a ``DPY-4001``
    reported as ``connectivity`` -- which sends the reader to the listener for what
    is one keystroke at their own terminal -- and, on a password-authenticated admin
    account, possibly a failed login against its lockout counter. It is refused as
    an :class:`AdminCredentialError`, which is what an empty ``method: env``
    variable and an empty vault path already are: there was nothing to send. Not
    cached, so a later target sharing the credential asks again rather than
    inheriting the empty one.

    **Whitespace is an answer**, not an empty one. Oracle can hold a quoted
    password of spaces, and a refusal of one would be this tool deciding what
    the database may store.
    """

    ask: Asker
    _answers: dict[str, Secret] = field(default_factory=dict, repr=False)

    def __call__(self, target: ExpandedTarget, username: str | None) -> Secret:
        key = prompt_key(target, username)
        if key not in self._answers:
            answer = self.ask(self.line(target, username))
            if not answer:
                raise AdminCredentialError(
                    f"target {target.name!r} asked for its admin password, and the "
                    f"answer was empty",
                    at=_at(target, "auth"),
                    hint=(
                        "nothing was sent to the database -- an empty password can never "
                        "authenticate; run it again and type the password, or check that "
                        "a paste reached the hidden prompt"
                    ),
                )
            self._answers[key] = Secret(answer)
        return self._answers[key]

    def forget(self, target: ExpandedTarget, username: str | None) -> None:
        """Drop the answer for this credential, so it is asked again.

        `sql run` calls this when the database refused the typed password, so
        a refused password is never sent anywhere else (UC-3 §2).
        """
        self._answers.pop(prompt_key(target, username), None)

    @staticmethod
    def line(target: ExpandedTarget, username: str | None) -> str:
        """What the operator is asked, naming both halves of the answer.

        The account *and* the target, because an estate prompts for several and
        "Password:" on its own is a question nobody can answer correctly twice.

        ``username`` is the **effective** one, for the reason
        :func:`prompt_key` gives: being asked for ``C##SOPULI_SVC`` and then
        connecting as whatever ``SOPULI_DB_ADMIN_USER`` says is a question whose
        answer is wrong through no fault of the person answering it.
        """
        who = username or "the admin account"
        return f"password for {who} on {target.name}: "


def store_name(
    target: ExpandedTarget, ref: SecretRef, *, config: Config, env: Mapping[str, str]
) -> str | None:
    """Which store holds a target's admin credential, or ``None``.

    Pure, and here rather than in the CLI for the reason the rest of this module
    is here: *which* store is a question about the file, and *opening* one is
    I/O. The caller does the second.

    **The chain is `bindings._vault_for`'s, one link shorter**, and deliberately
    the same order. An admin credential belongs to a target rather than to an
    application, so the two middle links -- an ``applications:`` entry's
    ``vault:`` and an ``overrides:`` patch's -- have nothing to say about it:

    1. the ref's own prefix, ``vault-prod:ops/dba#password``. First because §7
       calls that an *explicit* vault, and because a resolved store contradicting
       the ref a reader can see is the worst of the available answers;
    2. the target's ``vault:``;
    3. ``defaults.vault``;
    4. the run's own -- ``SOPULI_VAULT``, then a profile's ``vault:``.

    **The run's layers come last, not first**, which looks like a precedence
    violation and is not. It is exactly what
    :func:`sopuli.config.binding_stores.complete` does for a binding, and for the
    reason its module note gives at length: those layers *fill holes and do not
    repoint arrows*. A target naming its own store is a statement about that
    database, and an exported ``SOPULI_VAULT`` -- a property of the shell a run
    started in -- must not silently redirect the credential that reaches a
    production database to a different vault. P3's ordering is satisfied because
    the run layers are only ever consulted where the file said nothing at all.

    ``None`` when no link answers, which is the operator's mistake the caller
    turns into a refusal: a target declaring ``method: vault`` with no store
    anywhere has named a credential nobody can fetch.
    """
    in_file = admin_store_in_file(target, ref, config)
    if in_file is not None:
        return in_file
    asked = env.get(DEFAULT_STORE_VARIABLE, "")
    if asked:
        return asked
    profile = config.active_profile
    return None if profile is None else profile.vault


def auth_at(target: ExpandedTarget) -> KeyPath:
    """The ``admin.auth`` key of a target: the line to edit to change its source."""
    return _at(target, "auth")


def needs_prompt(target: ExpandedTarget) -> bool:
    """Whether reaching this target will stop and ask for a password.

    Pure, and separate from :func:`resolve` on purpose. Invariant 4's shape is
    that a run which cannot succeed says so *before* it touches anything, and a
    run with ``auth: prompt`` and no terminal can never succeed -- but resolution
    itself belongs at connect time, so the check and the read cannot be the same
    call. This is the half a plan can ask, over the whole selected estate, while
    it is still deciding what to do.

    :func:`resolve` refuses on the same condition rather than trusting the plan
    to have asked, because the guard that must not be forgotten is the one
    nearest the pipe. The plan-phase caller is
    :func:`~sopuli.safety.refuse_if_nobody_to_ask`.
    """
    auth = _auth(target)
    return auth is not None and auth.method == PROMPT


def uses_keyring(target: ExpandedTarget) -> bool:
    """Whether this target's admin credential is read from the OS keyring.

    Pure, for :func:`needs_prompt`'s reason: a plan asks it over the whole
    selected estate before anything connects.
    """
    auth = _auth(target)
    return auth is not None and auth.method == KEYRING


def resolve(
    target: ExpandedTarget,
    *,
    env: Mapping[str, str],
    read_ref: RefReader | None = None,
    prompt: Prompter | None = None,
) -> Resolved:
    """The credential that reaches ``target``, from whichever source it names.

    ``env`` is passed in and never :data:`os.environ`, the arrangement
    :mod:`sopuli.material`, :mod:`sopuli.config.discovery` and
    :mod:`sopuli.settings.sources` already use: a test that had to set a real
    variable to check a rule is a test that cannot run beside another one.
    """
    auth = _auth(target)
    if auth is None:
        raise _no_source(target)
    return _resolve_auth(
        target,
        auth,
        block=ADMIN_BLOCK,
        username=_username(target, env=env),
        env=env,
        read_ref=read_ref,
        prompt=prompt,
    )


def _resolve_auth(
    target: ExpandedTarget,
    auth: AdminAuth,
    *,
    block: str,
    username: str | None,
    env: Mapping[str, str],
    read_ref: RefReader | None = None,
    prompt: Prompter | None = None,
) -> Resolved:
    """Work from one ``auth:`` block, whichever of ``admin:`` or ``run_as:`` wrote it.

    The one code path both :func:`resolve` and :func:`resolve_run_as` use, so a
    source is read one way for both. ``block`` is the key the block was written
    under, for the message and the location of an error.
    """
    if auth.method == EXTERNAL:
        # No username, and none read from the environment either: the wallet
        # supplies both halves, and `Credential.external` is what says so.
        return Resolved(
            credential=Credential(external=True),
            method=EXTERNAL,
            source="an external password store",
        )

    if auth.method == VAULT:
        secret = _read_ref(auth.secret, target=target, read_ref=read_ref)
        source = f"vault ref {auth.secret}"
    elif auth.method == PROMPT:
        secret, source = _from_prompt(target, username=username, prompt=prompt, block=block)
    elif auth.method == ENV:
        secret, source = _from_env(auth, target=target, env=env, block=block)
    elif auth.method == KEYRING:
        secret, source = _from_keyring(auth, target=target, env=env, block=block)
    else:  # pragma: no cover - `ADMIN_METHODS` is a closed set the builder checks
        raise AdminCredentialError(
            f"target {target.name!r} names an unknown {block} auth method {auth.method!r}",
            at=_at(target, "auth", "method", block=block),
        )

    return Resolved(
        credential=Credential(username=username, secret=secret),
        method=auth.method,
        source=source,
    )


def _declared_run_as(target: ExpandedTarget, as_user: str | None) -> AdminCredential | None:
    """What `sql run` connects as, before any source is read: ``--as``, else ``run_as:``."""
    if as_user is not None:
        return AdminCredential(username=as_user, auth=AdminAuth(method=PROMPT))
    return target.run_as


def resolve_run_as(
    target: ExpandedTarget,
    *,
    env: Mapping[str, str],
    prompt: Prompter | None,
    as_user: str | None,
) -> Resolved:
    """The credential `sql run` connects to ``target`` with (UC-3 §2).

    ``as_user``, from ``--as``, wins over any ``run_as:`` and means the named
    account with a prompt. Without it the target's ``run_as:`` is used, and
    without that this refuses and says both ways to fix it. There is no
    ``vault`` source: the config never names one for ``run_as:``.

    The admin's ``SOPULI_DB_ADMIN_USER`` does not apply here. It names the admin.
    """
    declared = _declared_run_as(target, as_user)
    if declared is None or declared.auth is None:
        raise _no_run_as(target)
    return _resolve_auth(
        target,
        declared.auth,
        block=AS_BLOCK if as_user is not None else RUN_AS_BLOCK,
        username=declared.username,
        env=env,
        prompt=prompt,
    )


@dataclass
class AskOncePerUser:
    """A :data:`Prompter` for `sql run`, which asks once for each run-as login.

    :class:`PasswordPrompt` asks once per declared *admin* credential. `sql run`
    connects as the run-as account instead, and two cases need their own key:

    * ``--as USER`` is declared nowhere in the file: it is one account the
      operator named once, so one password covers every target, and the key is
      the user name alone;
    * a ``run_as:`` with ``auth: prompt`` (``by_declaration=True``) is keyed by
      where the file declares it, and the user name. An inherited
      ``defaults.run_as`` is one act and is asked for once, however many targets
      take it. A ``run_as:`` written on each target is one act each, and two
      databases may hold different passwords for one name, so each is asked for
      and the first answer is not sent to the second (#1677).
    """

    prompt: Prompter
    by_declaration: bool = False
    _answers: dict[str, Secret] = field(default_factory=dict, repr=False)
    #: The target each key's password was asked for, which is the key the
    #: inner prompter cached it under.
    _asked_for: dict[str, ExpandedTarget] = field(default_factory=dict, repr=False)

    def _key(self, target: ExpandedTarget, username: str | None) -> str:
        if not self.by_declaration:
            return username or ""
        # NUL, as in :func:`prompt_key`, so a name cannot make two keys collide.
        return "\x00".join((str(run_as_at(target)), username or ""))

    def __call__(self, target: ExpandedTarget, username: str | None) -> Secret:
        key = self._key(target, username)
        if key not in self._answers:
            # The inner prompter keys on the `admin` declaration, which two
            # run-as declarations can share. Drop its answer for this target, so
            # that it asks for this one.
            forget(self.prompt, target, username)
            self._answers[key] = self.prompt(target, username)
            self._asked_for[key] = target
        return self._answers[key]

    def forget(self, target: ExpandedTarget, username: str | None) -> None:
        """Drop the answer, whichever target the database refused it on.

        The inner prompter is told to forget under the target it was asked
        for, so the next ask prompts again.
        """
        key = self._key(target, username)
        self._answers.pop(key, None)
        asked_for = self._asked_for.pop(key, target)
        forget(self.prompt, asked_for, username)


def forget(prompt: Prompter | None, target: ExpandedTarget, username: str | None) -> None:
    """Drop a typed password the database refused, where ``prompt`` keeps one.

    A prompter that caches nothing has nothing to drop.
    """
    drop = getattr(prompt, "forget", None)
    if drop is not None:
        drop(target, username)


def run_as_prompts(target: ExpandedTarget, as_user: str | None) -> bool:
    """Whether `sql run` asks for this target's password at the terminal:
    ``--as``, or a ``run_as:`` with ``auth: prompt``. Pure."""
    declared = _declared_run_as(target, as_user)
    return declared is not None and declared.auth is not None and declared.auth.method == PROMPT


def run_as_uses_keyring(target: ExpandedTarget, as_user: str | None) -> bool:
    """Whether `sql run` reads this target's password from the OS keyring. Pure."""
    declared = _declared_run_as(target, as_user)
    return declared is not None and declared.auth is not None and declared.auth.method == KEYRING


def run_as_user(target: ExpandedTarget, as_user: str | None) -> str:
    """The name `sql run` connects as, or ``"external"``. Pure, for the fingerprint."""
    declared = _declared_run_as(target, as_user)
    if declared is None or declared.auth is None:
        raise _no_run_as(target)
    if declared.auth.method == EXTERNAL:
        return EXTERNAL
    if declared.username is None:  # pragma: no cover - references refuses a `run_as` with none
        raise _no_run_as(target)
    return declared.username


def refuse_service_account(
    target: ExpandedTarget, as_user: str | None, *, env: Mapping[str, str] | None = None
) -> None:
    """`sql run` never connects as the account the tool itself uses (UC-3 §2).

    Refused with ``SOPULI-20010`` when the run-as name equals the admin's by
    ``upper()``, or when both are ``external`` on one ``dsn``, where one wallet
    entry would be both. ``env`` adds ``SOPULI_DB_ADMIN_USER``, which overrides
    the admin's written name. An ``external`` admin has no name to compare, so a
    run-as name is allowed there. That is the one gap, and the document says so.
    """
    # Here and not at the top: `sopuli.safety` imports this module.
    from sopuli.safety import ServiceAccountRefusedError

    who = run_as_user(target, as_user)
    admin = target.target.admin
    if admin is None:
        return
    if admin.auth is not None and admin.auth.method == EXTERNAL:
        if who == EXTERNAL:
            raise ServiceAccountRefusedError(
                f"target {target.name!r} would run statements through the same external "
                f"credential the tool uses for its own work",
                at=run_as_at(target),
                hint="name an account with `run_as: { username: …, auth: … }` or `--as USER`",
            )
        return
    from_variable = (env or {}).get(ADMIN_USER_ENV)
    admin_user = from_variable or admin.username
    if admin_user is not None and who != EXTERNAL and who.upper() == admin_user.upper():
        source = f"named by ${ADMIN_USER_ENV}" if from_variable else "named by `admin.username`"
        came_from = "`--as`" if as_user is not None else "`run_as.username`"
        raise ServiceAccountRefusedError(
            f"target {target.name!r} would run statements as {who!r} (from {came_from}), "
            f"the account the tool uses for its own work ({source})",
            at=ROOT if as_user is not None else run_as_at(target).key("username"),
            hint="name a personal or owner account with `run_as:` or `--as USER`",
        )


def refuse_session_user(
    target: ExpandedTarget, session_user: str, as_user: str | None, *, env: Mapping[str, str]
) -> None:
    """`sql run`'s second check, on the account the session actually reached (UC-3 §2).

    ``session_user`` is what the database says the run-as login became. It is
    refused with ``SOPULI-20010`` when it equals the admin's name by ``upper()``.
    An ``external`` admin has no name to compare, so nothing is checked there:
    the accepted gap of UC-3 §2. The tool never logs in as the admin to learn it.
    """
    from sopuli.safety import ServiceAccountRefusedError

    admin = target.target.admin
    if admin is None or (admin.auth is not None and admin.auth.method == EXTERNAL):
        return
    admin_user = _username(target, env=env)
    if admin_user is not None and session_user.upper() == admin_user.upper():
        raise ServiceAccountRefusedError(
            f"target {target.name!r}: the run-as login reached {session_user!r}, the "
            f"account the tool uses for its own work. No statement ran on any target",
            at=ROOT if as_user is not None else run_as_at(target),
            hint="name a personal or owner account with `run_as:` or `--as USER`",
        )


# ------------------------------------------------------------------ sources ---


def _from_prompt(
    target: ExpandedTarget,
    *,
    username: str | None,
    prompt: Prompter | None,
    block: str = ADMIN_BLOCK,
) -> tuple[Secret, str]:
    """``method: prompt`` -- and the refusal when there is nobody there.

    **A prompt never reads stdin**, which is how P5's "one stream, one reader"
    survives contact with this method. That rule reserves the pipe for at most
    one secret per run and ``--from-stdin`` (UC-1 §4) claims it on
    ``creds generate``; a prompt that fell back to stdin on finding no terminal
    would be a second reader of the same stream, taking the password meant for
    the *account* and sending it to the database as the DBA's.

    The refusal makes that impossible rather than merely discouraged. A prompter
    is supplied only when stdin is a terminal, and a terminal is not carrying a
    piped password -- so the two sources are mutually exclusive by construction
    and no ordering between them ever has to be defined.
    """
    if prompt is None:
        raise NobodyToAskError(
            f"target {target.name!r} asks for its {block} password interactively, "
            f"and there is nobody here to ask",
            at=_at(target, "auth", block=block),
            hint=(
                f"run it from a terminal, or "
                f"{RUN_AS_UNATTENDED_SOURCES if block != ADMIN_BLOCK else UNATTENDED_SOURCES}"
            ),
        )
    return prompt(target, username), "an interactive prompt"


def _from_env(
    auth: AdminAuth, *, target: ExpandedTarget, env: Mapping[str, str], block: str = ADMIN_BLOCK
) -> tuple[Secret, str]:
    """``method: env`` -- ``password_env:``, or §6's pair.

    Delegated to :func:`sopuli.material.resolve` rather than reading the mapping
    here, so that §6's "set but empty counts as unset" is decided in one place
    and worded once: a CI job that clears an inherited variable gets the same
    message as one that never set it, because it is the same situation described
    two ways.

    **Re-raised with a location**, which is the one thing the delegate cannot
    supply. :func:`sopuli.material.resolve` reports at
    :data:`~sopuli.config.errors.ROOT` because it is also used for a store's auth
    material and has no idea which target asked; here the key that named the variable
    is known, so the error can point at the line to edit instead of at the document.
    The message and hint are the delegate's own -- reworded here, they would be two
    descriptions of one rule.
    """
    name = auth.password_env or ADMIN_PASSWORD_ENV
    where = f"target {target.name!r} {block} credential"
    try:
        secret = resolve_material(MaterialRef(kind="env", location=name), env=env, where=where)
    except MaterialError as error:
        # Where `password_env:` was written, that is the key to point at. Where
        # it was not, the variable is a default and no such key exists -- naming
        # one would send the reader looking for a line that is not there.
        at = (
            _at(target, "auth", "password_env", block=block)
            if auth.password_env
            else _at(target, "auth", block=block)
        )
        raise AdminCredentialError(error.message, at=at, hint=error.hint) from error
    return secret, f"the environment variable {name}"


def _from_keyring(
    auth: AdminAuth, *, target: ExpandedTarget, env: Mapping[str, str], block: str = ADMIN_BLOCK
) -> tuple[Secret, str]:
    """``method: keyring`` -- one entry under the service ``sopuli`` (#1417).

    Read through :func:`sopuli.material.resolve`, so a keyring entry is read
    one way wherever it is named, and re-raised at ``entry:`` as
    :func:`_from_env` does. Not flagged low-assurance: see
    :class:`~sopuli.config.model.AdminAuth`.
    """
    entry = auth.entry
    if entry is None:  # pragma: no cover - `Method(required=("entry",))` guarantees one
        raise AdminCredentialError(
            f"target {target.name!r} {block} authenticates from the OS keyring and names no entry",
            at=_at(target, "auth", "entry", block=block),
        )
    where = f"target {target.name!r} {block} credential"
    try:
        secret = resolve_material(MaterialRef(kind=KEYRING, location=entry), env=env, where=where)
    except MaterialError as error:
        raise AdminCredentialError(
            error.message, at=_at(target, "auth", "entry", block=block), hint=error.hint
        ) from error
    return secret, os_keyring.describe(entry)


def _read_ref(
    ref: SecretRef | None, *, target: ExpandedTarget, read_ref: RefReader | None
) -> Secret:
    """Resolve ``method: vault``'s ref through the caller's store."""
    if ref is None:  # pragma: no cover - `Method(required=("secret",))` guarantees one
        raise AdminCredentialError(
            f"target {target.name!r} authenticates from a vault and names no ref",
            at=_at(target, "auth", "secret"),
            hint="there is no default admin path; write `secret:` on the auth block",
        )
    if read_ref is None:
        # Not an operator's mistake: the file is right and a caller failed to
        # supply the store it had already authenticated. Worded so that whoever
        # reads it in a bug report can tell those apart at a glance.
        raise AdminCredentialError(
            f"target {target.name!r} authenticates from a vault, and no store was "
            f"available here to read {str(ref)!r}",
            at=_at(target, "auth", "secret"),
            hint="the file is fine -- this is a caller that supplied no reader",
        )
    return read_ref(ref)


# ------------------------------------------------------------------ helpers ---


def _auth(target: ExpandedTarget) -> AdminAuth | None:
    admin = target.target.admin
    return None if admin is None else admin.auth


def _at(target: ExpandedTarget, *parts: str, block: str = ADMIN_BLOCK) -> KeyPath:
    """Where inside a target's ``admin:`` block something was written.

    :func:`~sopuli.config.expansion.declared_at` points at the target -- or at
    the ``overrides:`` entry that patched its ``admin:`` -- and the rest of the
    path is appended, so the result is the line to edit rather than the block
    containing it. The same helper ``config/references.py`` keeps for its own
    admin checks; a shared one would have to live somewhere both can import, and
    two callers is not yet a module.
    """
    if block == AS_BLOCK:
        # `--as` wrote nothing in the file, so no key is the line to edit.
        return ROOT
    at = run_as_at(target) if block == RUN_AS_BLOCK else declared_at(target, block)
    for part in parts:
        at = at.key(part)
    return at


def _username(target: ExpandedTarget, *, env: Mapping[str, str]) -> str | None:
    """Who connects: §6's variable, then the file, then nothing.

    P3's layering applied to one field -- the environment is layer 2 and the
    file is layer 4, so a variable set for this execution context wins.

    **Not consulted under** ``external``, and that asymmetry is deliberate.
    §3a *refuses* a ``username:`` written beside a wallet, because a file that
    appears to name the connecting account while the wallet names another is
    worth stopping for. The variable is the same claim from a different place --
    but it is ambient, set once for a whole run, and refusing a run because one
    target of thirty-four uses a wallet would make the variable unusable in a
    mixed estate. So the file is an error and the variable is ignored: the
    strict reading where somebody wrote it about *this* target, the permissive
    one where they did not.
    """
    declared = target.target.admin.username if target.target.admin is not None else None
    return env.get(ADMIN_USER_ENV) or declared


def _no_run_as(target: ExpandedTarget) -> AdminCredentialError:
    """Neither ``--as`` nor a ``run_as:`` says who `sql run` connects as.

    It never falls back to the admin: the admin is the tool's own account, and a
    statement run as it is the case `refuse_service_account` exists to stop.
    """
    return AdminCredentialError(
        f"target {target.name!r} has no account to run the statement as",
        at=declared_at(target, RUN_AS_BLOCK),
        hint=(
            "pass `--as USER`, which asks for that account's password, or declare "
            "`run_as: { username: …, auth: … }` on the target or in `defaults:`"
        ),
    )


def _no_source(target: ExpandedTarget) -> AdminCredentialError:
    """No ``admin.auth`` at all -- refused rather than guessed at.

    ``admin:`` is optional in the schema and ``auth:`` is optional inside it, so
    a target can reach here naming no source whatever. Falling back to §6's
    ``SOPULI_DB_ADMIN_PASSWORD`` when it happens to be set is the tempting
    reading of the variable table, and it is a guess: §6 calls that pair *the
    default for* ``method: env``, which is a statement about a declared method
    rather than about an absent one. A credential tool that authenticates from
    whatever variable it found lying in the environment, because the file said
    nothing, is doing the thing P2's bootstrap section exists to prevent.

    So it refuses, and the hint is the one line that fixes it. Refusing is also
    the reversible half: deciding later that a bare variable implies ``method:
    env`` only widens what works, while unpicking a silent fallback means
    breaking runs that had come to depend on it.
    """
    return AdminCredentialError(
        f"target {target.name!r} declares no admin credential, so there is no way "
        f"to authenticate to it",
        at=declared_at(target, "admin"),
        hint=(
            f"name one of {', '.join(sorted(ADMIN_METHODS))} under "
            f"`admin: {{ auth: … }}` -- `auth: {{ method: env }}` reads "
            f"${ADMIN_PASSWORD_ENV}"
        ),
    )
