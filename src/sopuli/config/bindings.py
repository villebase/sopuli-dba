"""*These accounts, in these targets, mastered by these secrets* (§1, §3, §7).

§1 says that sentence is what the whole config file exists to state, and calls
the account→secret mapping the safety-critical part of it. This is where the
sentence becomes a list: one :class:`~sopuli.config.model.Binding` per account
per target, each carrying the ref its password is mastered by.

Three things happen here, in this order, because each needs the one before it:

1. **Selection** -- which targets the application applies to
   (:mod:`sopuli.config.selection`).
2. **Patching** -- its ``overrides:`` are applied to the targets they match, in
   document order, so a broad rule can be narrowed by a later one.
3. **Rendering** -- the ref's ``{tokens}`` are expanded per account and target,
   which is the only step that can fail.

It is built at load, so a ref that cannot render is a config error rather than a
surprise at the first rotation. §10 is explicit that an unresolved
``{placeholder}`` is an error and never an empty string: a ref with `{tenant}`
still in it addresses a secret nobody wrote, and one with it replaced by nothing
addresses the *wrong* secret, which is worse.

**No vault is contacted and no value is read.** A binding is an address. What is
stored there -- whether anything is -- is the vault layer's question (P2), and
``config show --resolved`` answers this one offline precisely because the two are
separate.

A target no application selects simply has no bindings. That is a legitimate
state, not an oversight: §2's estate declares a CDB root for a use case that is
not designed yet, and the view that renders this shows it as unmanaged rather
than warning about it.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from sopuli.config.applications import ACCOUNT_TOKEN
from sopuli.config.errors import ROOT, ConfigError, KeyPath
from sopuli.config.model import (
    Application,
    Binding,
    Config,
    ExpandedTarget,
    Override,
    as_dict,
)
from sopuli.config.password_keys import PasswordKey, declared_password_key
from sopuli.config.products import refuse_a_container_clause
from sopuli.config.references import dangling
from sopuli.config.secret_refs import (
    FIELD_SEPARATOR,
    POINTER_SEPARATOR,
    QUALIFIER_SEPARATOR,
    VAULT_SEPARATOR,
    SecretRef,
    normalise_path,
    parse_secret_ref,
)
from sopuli.config.selection import matches, select
from sopuli.config.sharing import STAGE_COLLISION_HINT, StageCollision, colliding_stages
from sopuli.config.templates import PLACEHOLDER, substitute
from sopuli.config.vaults import (
    OCI_NAME,
    OCI_NAME_MAX,
    OCI_RESERVED_PREFIX,
    PAYLOAD_RULE_TYPES,
)
from sopuli.payload import stage_layout

#: What an unresolved token in a secret ref is measured against (§7).
_SCOPE = "a secret template resolves from the account, the target and the target's labels (§7)"

_APPLICATIONS = ROOT.key("applications")


def build_bindings(config: Config) -> tuple[Binding, ...]:
    """Every (account, target) the file declares, with its resolved ref.

    Ordered by application, then by estate order, then by the order the accounts
    are declared in -- all three of which are document order, so the result is
    stable enough to diff between runs.
    """
    bindings: list[Binding] = []
    where: dict[str | None, KeyPath] = {}
    for index, application in enumerate(config.applications):
        at = ROOT if application.is_inline else _APPLICATIONS.index(index)
        where[application.name] = at
        bindings.extend(_bind(config, application, at=at))
    # One user at two places first: its message names the user and the target,
    # which is the fault, where the rules below would name a password.
    _check_one_user_per_target(bindings, where=where)
    # Two accounts on one password next: where staging is emulated they would
    # also collide in `pending`, and this message names the actual fault.
    _check_one_account_per_password(bindings, where=where)
    _check_stages_do_not_collide(bindings, config, where=where)
    _check_one_policy_per_password(bindings, where=where)
    return tuple(bindings)


def _check_one_user_per_target(
    bindings: Sequence[Binding], *, where: Mapping[str | None, KeyPath]
) -> None:
    """One database user on one target is bound to one place (invariant 5).

    The database holds one password for the user. Two entries that bind it to
    two places give two documents: `creds generate` draws two passwords, one run
    rotates the user twice, and whichever document is applied second wins. The
    other application is locked out.

    Names are compared with ``upper()``, as the driver compares them, so
    ``acme_web_user`` and ``ACME_WEB_USER`` are one user. Targets are compared
    after expansion, so the rule sees every target an entry reaches. Each binding
    is compared with every earlier binding of the user, so the order of the
    entries does not matter.

    Two bindings at one place, in one spelling, hold one password and are
    allowed. Two spellings are refused even at one place: every later step keys
    on the name as written, so the tool would treat them as two accounts.

    Places are compared with stores as the file states them. A store that comes
    only from a profile or ``SOPULI_VAULT`` is not the store another entry names,
    so the pair is refused. The file cannot show that they are one place, and no
    later step compares them once the run has chosen the store. Naming the store
    in both entries settles it.

    A binding with no ref takes part too. Its place is "none", which is not the
    place of a binding that has a ref, so one entry with a ref and one without
    are two declarations of the user and are refused.

    One entry cannot bind a user twice on one target, because the duplicate-name
    rule refuses a name it declares twice. So this rule names two entries.
    """
    seen: dict[tuple[str, str], list[tuple[Binding, PasswordKey | None]]] = {}
    for binding in bindings:
        key = declared_password_key(binding)
        earlier = seen.setdefault((binding.target, binding.account.upper()), [])
        for other, other_key in earlier:
            if other.account != binding.account:
                raise ConfigError(
                    f"{other.account!r} and {binding.account!r} on target {binding.target!r} "
                    f"are one database user, spelled two ways in "
                    f"{_declared_in(other, binding)}",
                    at=where.get(binding.application, ROOT),
                    hint=(
                        "the database compares names in upper case, so spell the user the "
                        "same way in every entry, and give the entries the same ref"
                    ),
                )
            if other_key == key:
                continue
            raise ConfigError(
                f"{binding.account!r} on target {binding.target!r} is bound to two places, "
                f"in {_declared_in(other, binding)}: {_place(other)} and {_place(binding)}",
                at=where.get(binding.application, ROOT),
                hint=_one_place_hint(key, other_key),
            )
        earlier.append((binding, key))


def _place(binding: Binding) -> str:
    """Where a binding's password lives, for a message, or that it names none."""
    if binding.secret is None:
        return "no ref"
    return _address(binding, binding.secret)


def _one_place_hint(key: PasswordKey | None, other: PasswordKey | None) -> str:
    """What to change so that two bindings of one user are one place.

    Where only the store differs and one entry names none, the refs already
    match on the page, so the hint says which half is missing.
    """
    if (
        key is not None
        and other is not None
        and (key.path, key.place) == (other.path, other.place)
        and None in (key.store, other.store)
    ):
        return (
            "one entry names its store and the other leaves it to the run, which may "
            "choose another: name the same store in both entries"
        )
    return (
        "the database holds one password for the user, so declare it in one entry, "
        "or give both entries the same ref and the same store"
    )


def _check_one_account_per_password(
    bindings: Sequence[Binding], *, where: Mapping[str | None, KeyPath]
) -> None:
    """No two accounts resolve to one password, or to places that overlap.

    §10 refuses an entry whose ref cannot give its accounts distinct refs
    (``applications._require_distinguishable_accounts``). That rule sees one
    entry. Two entries can still put two accounts on the same field and pointer
    in the same document, for example by writing one literal ref in both. Then
    `creds generate` writes both passwords into one field, the last one wins, and
    one account's application reads the other account's password. The second
    rotation locks the first out.

    **Overlapping is the same fault.** A place is the field, then the pointer's
    segments; a ref with no field is the whole document. Where one account's
    place contains the other's, as ``apps/acme#DB`` contains
    ``apps/acme#DB/acme_api_user``, writing the first replaces the object that
    holds the second.

    It is about the password, not the stage. Where staging is emulated,
    ``_check_stages_do_not_collide`` would also refuse the file, because both
    accounts stage into one key in ``pending``, but its hint is about a bare
    ``#{account}``, which is a different mistake. So this runs first. Where a
    store stages natively, as OCI does, that rule does not apply and only this
    one refuses the file (decided in #841).

    **One account in two nested places is the same fault too.** An override or
    a second entry can give one account ``#DB`` on one target and
    ``#DB/acme_web_user`` on another. Those are two values, and writing one
    replaces the other. One account in one place is a shared password, which §7
    allows.

    Refused at load, as the policy rule below is. The error names the accounts,
    where they are declared, and the refs. It compares stores as the file states
    them, for the reason ``_check_one_policy_per_password`` gives. Where one
    store comes only from a profile or ``SOPULI_VAULT``, the file cannot show the
    pair. ``sopuli.generate.draw_once`` then draws each account its own value,
    and ``generate.group`` refuses a write that carries two values for one
    password, before anything is written.

    Accounts are compared as the file spells them. Two spellings of one Oracle
    user on one target never reach this rule: ``_check_one_user_per_target``
    refuses them first. On two targets they are two users, and this rule
    compares them as written.
    """
    documents: dict[tuple[str | None, str], dict[tuple[PasswordKey, str], Binding]] = {}
    for binding in bindings:
        key = declared_password_key(binding)
        if key is None:
            continue
        ref = binding.secret
        assert ref is not None
        seen = documents.setdefault((key.store, key.path), {})
        if (key, binding.account) in seen:
            # One account in one place on another target: a shared password.
            continue
        for (other_key, _), other in seen.items():
            if not key.overlaps(other_key):
                continue
            other_ref = other.secret
            assert other_ref is not None
            if key == other_key:
                fault = f"resolve to one password at {_address(binding, ref)}"
            else:
                fault = (
                    f"overlap at {_address(other, other_ref)} and {_address(binding, ref)}: "
                    "writing one password replaces the other"
                )
            declared = _declared_in(other, binding)
            if other.account == binding.account:
                # The places differ, or `seen` would have skipped this binding.
                message = f"{binding.account!r} ({declared}) has two places that {fault}"
            else:
                message = f"{other.account!r} and {binding.account!r} ({declared}) {fault}"
            raise ConfigError(
                message,
                at=where.get(binding.application, ROOT),
                hint=(
                    "each account needs one place of its own in the document, such as "
                    "path#FIELD/{account}: give the refs distinct, non-nested fields or pointers"
                ),
            )
        seen[(key, binding.account)] = binding


def _declared_in(first: Binding, second: Binding) -> str:
    """Where two bindings come from, for a message about the pair."""
    if first.application == second.application:
        return (
            "both in the inline application"
            if first.application is None
            else (f"both in entry {first.application!r}")
        )
    return f"entries {first.application!r} and {second.application!r}"


def _address(binding: Binding, ref: SecretRef) -> str:
    """``ref``, with the binding's store in front where the ref names none."""
    if ref.vault is not None or binding.vault is None:
        return str(ref)
    return f"{binding.vault}:{ref}"


def _check_one_policy_per_password(
    bindings: Sequence[Binding], *, where: Mapping[str | None, KeyPath]
) -> None:
    """Every binding that resolves to one password resolves to one policy.

    Two bindings resolve to one password when they are the same account and
    their refs address the same field and pointer in the same document of the
    same store. That is one account on several targets with no target label in
    its ref, which §7 allows and often intends. An override can still give one
    of those targets its own ``policy:``, or a second application entry can
    declare the account with another policy and the same ref. Then one stored
    password would have to follow two policies. ``creds generate`` would draw it
    against one of them, and ``creds check`` would report it against the other on
    every run.

    Refused at load, as a defect in the file, so every verb and
    ``config validate`` say so before anything is drawn (decided in #830). The
    error names the account, the ref with its store, and each policy with a
    target it governs. It points at the application entry: a binding does not
    record which override set its policy.

    **Only as the file states the stores**, as ``_check_stages_do_not_collide``
    is. A binding whose ``vault`` is still ``None`` gets one later from a profile
    or ``SOPULI_VAULT``, and the file alone cannot say which. Two such bindings
    with one ref are compared, because they will get the same store. One of them
    beside a binding that names a store is not, because the run may give it
    another. Checking again at run time would check only what the run's
    selectors kept, so the answer would depend on the selection.

    Two *different* accounts on one field never reach it:
    ``_check_one_account_per_password`` refuses them first.
    """
    seen: dict[tuple[str, PasswordKey], Binding] = {}
    for binding in bindings:
        key = declared_password_key(binding)
        if key is None:
            continue
        ref = binding.secret
        assert ref is not None
        first = seen.setdefault((binding.account, key), binding)
        if first.policy == binding.policy:
            continue
        address = _address(binding, ref)
        if first.target == binding.target:
            # Two entries on one target: the entries tell them apart.
            places = (
                f"on target {binding.target!r}, under two policies: {_policy(first)} from "
                f"entry {first.application!r} and {_policy(binding)} from entry "
                f"{binding.application!r}"
            )
        else:
            places = (
                f"on targets {first.target!r} and {binding.target!r}, under two policies: "
                f"{_policy(first)} on {first.target!r} and {_policy(binding)} on "
                f"{binding.target!r}"
            )
        raise ConfigError(
            f"{binding.account!r} has one password at {address} {places}",
            at=where.get(binding.application, ROOT),
            hint=(
                "one password cannot follow two policies: give these targets one policy, "
                "or give each target its own secret by putting a target label, such as "
                "{tenant}, in the ref"
            ),
        )


def _policy(binding: Binding) -> str:
    return "no policy" if binding.policy is None else repr(binding.policy)


def _check_stages_do_not_collide(
    bindings: Sequence[Binding], config: Config, *, where: Mapping[str | None, KeyPath]
) -> None:
    """No two accounts may stage into the same place in one document.

    ``_check_stageable`` refuses a ref with *nowhere* to stage. This refuses a
    set of refs that all have the **same** somewhere -- which is what
    ``path#{account}`` produces, because a field per account with no pointer
    below it leaves every account's ``pending`` at the document root. The merge
    then keeps whichever was written last: one account's new password lost, and
    the other's given to both.

    It cannot live beside ``_check_stageable``, which is called per binding with
    no view of its siblings. It is a property of the set, so it runs once every
    binding exists -- which is still load time, and still before any command has
    done anything (invariant 4). ``sopuli.generate.group`` also guards it at the
    write boundary, but that is one lock and one printed plan too late, and the
    wrong audience: this is a defect in the *file*, so it is what
    ``config validate`` should say.

    **Only on the store types in** :data:`~sopuli.config.vaults.PAYLOAD_RULE_TYPES`.
    OCI is one of them: a document that holds two accounts stages in payload
    fields there too (UC-1 §3), so its root ``pending`` is contended the same way.

    **Only where the store is known.** A binding whose ``vault`` is still ``None``
    is one C15 completes later from a profile or ``SOPULI_VAULT``, and its
    backend -- and therefore whether this rule applies at all -- is not knowable
    from the file alone. Those are left to ``generate.group``'s guard, which is
    the second reason that guard stays.
    """
    types = {vault.name: vault.type for vault in config.vaults}
    stageable = [
        binding
        for binding in bindings
        if binding.vault is not None and types.get(binding.vault) in PAYLOAD_RULE_TYPES
    ]
    for collision in colliding_stages(stageable):
        raise ConfigError(
            collision.description,
            at=where.get(_declared_by(stageable, collision), ROOT),
            hint=STAGE_COLLISION_HINT,
        )


def _declared_by(bindings: Sequence[Binding], collision: StageCollision) -> str | None:
    """Which application entry produced the second half of ``collision``.

    The *second* account of the pair, because that is the one whose arrival made
    it a collision -- and in the ordinary case both are in the same entry anyway,
    since one ``secret_template`` is what puts two accounts in one document.

    Matched on the **document as well as the account**, not on the name alone.
    One account may be declared by more than one application entry, each with its
    own ref, and only one of those entries is the one that collides; locating by
    name would then point at whichever entry mentions the account first and send
    an operator to a line that is fine.
    """
    return next(
        (
            binding.application
            for binding in bindings
            if binding.account == collision.accounts[1]
            and binding.vault == collision.vault
            and binding.secret is not None
            and normalise_path(binding.secret.path) == collision.path
        ),
        None,
    )


def _bind(config: Config, application: Application, *, at: KeyPath) -> list[Binding]:
    bound: list[Binding] = []

    for expanded in select(config, application.targets):
        patches = _patches_for(application, expanded)
        refuse_a_container_clause(expanded, application, patches, at=at)
        ref, where = _ref_for(application, patches, at=at)
        vault = _effective(application.vault, patches, key="vault")
        policy = _effective(application.policy, patches, key="policy")

        for account in application.accounts:
            secret = _render(ref, application, account, expanded, at=where)
            store = _vault_for(secret, vault, expanded, config)
            _check_store_declared(secret, config, at=where)
            _check_has_somewhere_to_resolve_from(secret, store, config, at=where)
            _check_stageable(secret, store, config, at=where)
            bound.append(
                Binding(
                    application=application.name,
                    account=account,
                    target=expanded.name,
                    secret=secret,
                    vault=store,
                    policy=policy if policy is not None else config.defaults.policy,
                )
            )
    return bound


def _check_store_declared(secret: SecretRef | None, config: Config, *, at: KeyPath) -> None:
    """A ref's own ``vault-name:`` prefix names a store like every other name does.

    :mod:`sopuli.config.references` resolves every *other* way a store gets named
    -- the target's ``vault:``, the entry's, an override's, a profile's,
    ``defaults.vault``, and the prefix on an ``admin.auth.secret``. The prefix on
    an **application's** ref was the one that went unchecked, because it is the
    only one that is not resolvable until the ref has been rendered: §7's tokens
    expand per account and target, and `check_references` runs before that on
    purpose (see :func:`~sopuli.config.loading.build_config`).

    So it is resolved here, against the same declared set and through the same
    :func:`~sopuli.config.references.dangling` message, because a second phrasing
    of "that name names nothing" would be a second thing to learn.

    This is the failure `references.py`'s own docstring describes: a dangling
    store name does not stay dangling. ``vault-prd:apps/acme/db#password`` is a
    ref the file accepts, a binding that resolves, and a rotation that discovers
    at the far end that there is no such store -- or, worse, a name that later
    *becomes* a store belonging to somebody else.
    """
    if secret is None or secret.vault is None:
        return
    dangling(
        secret.vault,
        {vault.name for vault in config.vaults},
        noun="vault",
        section="vaults",
        at=at,
    )


def _check_has_somewhere_to_resolve_from(
    secret: SecretRef | None, store: str | None, config: Config, *, at: KeyPath
) -> None:
    """A ref with no store, and no `vaults:` block to point one at later.

    ``store`` is `None` here means none of §3's chain named one -- not the ref's
    own prefix, not the entry, not an override, not the target, not
    ``defaults.vault``. That is not always a mistake: a profile's `vault:` is
    deliberately left out of the chain (`_vault_for`'s docstring), because which
    profile is active is a property of a *run* and bindings are built once at
    load, and the same is true of `SOPULI_VAULT` (P3, decision #10). Both can
    still complete this binding once a run picks one -- but only if the file declared
    somewhere for them to point *at*. `config show --resolved` already renders a
    `-` for this binding rather than a verdict, and the command that actually
    needs a store is where the exact answer belongs (invariant 4).

    What is refused here is narrower: `vaults:` declaring nothing at all. Then
    there is no name a profile or `SOPULI_VAULT` could select even in principle
    -- a store name resolves against what the file declared (invariant 5; see
    `references.py`'s own dangling-name rule) -- so no run of this file can ever
    rotate this account, and that is true regardless of profile or environment.
    Refusing here is `config validate` catching the case early, rather than
    every target discovering it separately at plan time.
    """
    if secret is None or store is not None or config.vaults:
        return
    raise ConfigError(
        "no vault is declared, and this binding names no store",
        at=at,
        hint=(
            "no `vaults:` entry exists for a profile or SOPULI_VAULT to select later -- "
            "declare one under `vaults:`, or name a store on the ref, the entry, an "
            "override, the target, or `defaults.vault`"
        ),
    )


def _check_stageable(
    secret: SecretRef | None, store: str | None, config: Config, *, at: KeyPath
) -> None:
    """A rendered ref must have somewhere to stage into (Q7).

    :func:`~sopuli.payload.stage_layout` refuses a ref naming a whole secret --
    nothing to put ``pending`` and ``previous`` beside -- and one whose field is a
    key the mirror rule generates, which would put the current stage and a
    staging sibling in one place. This check makes both refusals happen when the
    file is read, not at the first rotation. §1 calls the account→secret binding
    the safety-critical part, and invariant 4 wants a command that cannot succeed
    to fail before it has written anything.

    Here rather than in :mod:`sopuli.config.references` for two reasons, both of
    which turn on this being the rendered ref rather than the written one:

    * **The template question does not arise.** ``{account}`` and ``{tenant}`` are
      already substituted, so what is checked is what will reach the store --
      including the §7 case a written template cannot settle, a token whose value
      turns out to contain a ``#``.
    * **The store is known.** Which matters, because the rule is not universal.

    The store types are :data:`~sopuli.config.vaults.PAYLOAD_RULE_TYPES`. OCI
    is one, although it stages natively: a version's content holds the password
    beside the stamps that describe it (#1128 decision 3), so a rotated OCI ref
    names a field too. A store this layer has no capability row for, such as
    ``keyring``, is left alone. An OCI ref must also be an OCI secret name; see
    :func:`check_for_store`.
    """
    if secret is None or store is None:
        return
    # Every way a store can be named is resolved before this runs -- the five in
    # `references.py` and the ref's own prefix just above -- so a name with no
    # store behind it has already been refused. The `is None` arm is therefore
    # unreachable rather than a silent skip, and it stays because a lookup that
    # returns nothing must not decide a safety rule by falling through to it.
    declared = next((vault for vault in config.vaults if vault.name == store), None)
    if declared is None:
        return
    check_for_store(secret, declared.type, at=at)


def check_for_store(secret: SecretRef, store_type: str, *, at: KeyPath) -> None:
    """The rules a rotated ref must meet on a store of ``store_type``.

    Called at load for a binding whose store the file names, and by
    :func:`sopuli.config.binding_stores.complete` for one whose store the run
    supplies, so the two cannot disagree. Raises :class:`ConfigError`.
    """
    if store_type == "oci":
        check_oci_name(secret, at=at)
    if store_type in PAYLOAD_RULE_TYPES:
        stage_layout(secret, at=at)


def check_oci_name(secret: SecretRef, *, at: KeyPath) -> None:
    """A ref on an OCI store names one OCI secret, exactly (#1128 decision 1).

    ESO finds an OCI secret by name, so the name must be the one the operator
    wrote. Translating ``/`` into something OCI allows was rejected, because two
    different paths could then name one secret. Measured (``oci-name-rules``):
    letters, digits, ``-``, ``_`` and ``.``, at most 255 characters,
    case-sensitive.
    """
    name = secret.path
    if OCI_NAME.fullmatch(name) is None:
        raise ConfigError(
            f"{name!r} in the secret ref {secret} is not an OCI secret name",
            at=at,
            hint=(
                "an OCI secret name holds only letters, digits, `-`, `_` and `.`, "
                "with no `/`; write the name the secret has in the vault"
            ),
        )
    if len(name) > OCI_NAME_MAX:
        raise ConfigError(
            f"the OCI secret name in {secret} is {len(name)} characters, "
            f"longer than {OCI_NAME_MAX}",
            at=at,
            hint=f"OCI refuses a secret name longer than {OCI_NAME_MAX} characters",
        )
    if name.startswith(OCI_RESERVED_PREFIX):
        raise ConfigError(
            f"the secret ref {secret} names a secret starting with {OCI_RESERVED_PREFIX!r}",
            at=at,
            hint="the tool keeps its lock records under that prefix; choose another name",
        )


# ---------------------------------------------------------------- overrides ---


def _patches_for(application: Application, expanded: ExpandedTarget) -> list[tuple[int, Override]]:
    """The application's overrides that apply to this target, in document order.

    §3 calls them "patches applied to matching targets" -- plural, and applied,
    so all of them are. Later ones win key by key, which is what lets a broad
    rule be narrowed by a later exception rather than forcing every case to be
    written out separately.

    Each keeps its position in ``overrides:``, because a value's location is the
    line that wrote it and that line is the one worth reporting.
    """
    return [
        (position, override)
        for position, override in enumerate(application.overrides)
        if matches(expanded.target, override.where)
    ]


def _effective(base: str | None, patches: list[tuple[int, Override]], *, key: str) -> str | None:
    """The last patch that sets ``key``, or the entry's own value."""
    for _, override in reversed(patches):
        value = getattr(override, key)
        if value is not None:
            return str(value)
    return base


def _ref_for(
    application: Application, patches: list[tuple[int, Override]], *, at: KeyPath
) -> tuple[str | None, KeyPath]:
    """The ref that applies to this target, and the key it was written under.

    The location travels with the value because the two can come from different
    places: an override may set ``secret_template`` where the entry set
    ``secret``, and a failure reported against the entry would point at the one
    line that is not the problem. The same rule as
    :func:`~sopuli.config.expansion.declared_at` applies to a patched target.
    """
    for position, override in reversed(patches):
        if override.secret_ref is not None:
            key = "secret" if override.secret is not None else "secret_template"
            return override.secret_ref, at.key("overrides").index(position).key(key)

    key = "secret" if application.secret is not None else "secret_template"
    return application.secret_ref, at.key(key)


def _vault_for(
    secret: SecretRef | None, chosen: str | None, expanded: ExpandedTarget, config: Config
) -> str | None:
    """The ref's own prefix, else §3's chain: the entry's store, the target's,
    ``defaults.vault``.

    The prefix comes first because §7 calls ``vault-dev:path`` an *explicit*
    vault, and because the alternative is output that contradicts itself -- a
    ref reading ``vault-dev:...`` beside a resolved store of something else.

    This is the chain the reference writes, and only that chain. The `SOPULI_*`
    and command-line layers above it are P3's and belong to the precedence
    resolver (decision #10): a config file can be read without knowing what
    environment it will be read in.
    """
    if secret is not None and secret.vault is not None:
        return secret.vault
    if chosen is not None:
        return chosen
    if expanded.target.vault is not None:
        return expanded.target.vault
    return config.defaults.vault


# ---------------------------------------------------------------- rendering ---


def _render(
    ref: str | None,
    application: Application,
    account: str,
    expanded: ExpandedTarget,
    *,
    at: KeyPath,
) -> SecretRef | None:
    """Expand a ref's tokens for one account in one target.

    ``at`` is where this ref was written, which :func:`_ref_for` worked out --
    the entry's own key, or the override's if one supplied it.

    Absent stays absent: an application may declare no ref at all (§3), and this
    layer does not invent one.
    """
    if ref is None:
        return None
    tokens = _tokens(application, account, expanded)
    rendered = substitute(ref, tokens, at=at, source=_SCOPE)
    _refuse_a_separator_in_a_name(ref, tokens, expanded, at=at)
    _refuse_a_name_in_a_separators_place(ref, rendered, tokens, expanded, at=at)
    return parse_secret_ref(rendered, at=at)


#: What a name may not contain where a template uses it (decision #935).
_SEPARATORS = ("/", "#")


def _is_name(token: str, expanded: ExpandedTarget) -> bool:
    """Whether a placeholder stands for a name the database or the file chose.

    The account tokens are the ones :data:`~sopuli.config.applications.ACCOUNT_TOKEN`
    matches, so a new case variant is covered there and here at once. An
    application is a name, and so is a container, when the target has one: a label
    called ``container`` fills ``{container}`` on a target without one (see
    :func:`_tokens`), and a label is not a name. ``{target}``, ``{env}`` and the
    labels are values whoever writes the template also chose.
    """
    if ACCOUNT_TOKEN.fullmatch(f"{{{token}}}") or token == "application":
        return True
    return token == "container" and expanded.target.oracle.container is not None


def _refuse_a_separator_in_a_name(
    ref: str, tokens: Mapping[str, str], expanded: ExpandedTarget, *, at: KeyPath
) -> None:
    """Refuse a name with a ``/`` or ``#`` in a ref that uses it (decision #935).

    ``01-configuration.md`` §7 says why. Runs after substitution, so a misspelt
    token or a stray brace reports as itself, and every token the ref uses is
    then in ``tokens``.
    """
    for token in dict.fromkeys(PLACEHOLDER.findall(ref)):
        value = tokens[token]
        found = [separator for separator in _SEPARATORS if separator in value]
        if not found or not _is_name(token, expanded):
            continue
        raise ConfigError(
            f"{{{token}}} in secret ref {ref!r} is {value!r}, which contains "
            f"{' and '.join(f'`{separator}`' for separator in found)}",
            at=at,
            hint=(
                "a name goes into the ref as written, and a `/` or `#` in it changes where "
                "the password is stored. Declare it in an application entry of its own, "
                "with a ref that does not use this placeholder, or rename it where the "
                "database allows (a common user's `C##` cannot be)"
            ),
        )


def _spans(ref: str, tokens: Mapping[str, str]) -> list[tuple[str, int, int]]:
    """Where in the rendered ref each placeholder's value landed, as offsets.

    :func:`~sopuli.config.templates.substitute` renders each placeholder in
    place, so a value starts where its placeholder did, moved by the lengths
    the earlier placeholders gained or lost.
    """
    spans: list[tuple[str, int, int]] = []
    shift = 0
    for match in PLACEHOLDER.finditer(ref):
        value = tokens[match.group(1)]
        start = match.start() + shift
        spans.append((match.group(1), start, start + len(value)))
        shift += len(value) - (match.end() - match.start())
    return spans


def _structure(rendered: str) -> dict[int, str]:
    """Where a rendered ref's `:`, `@`, `=` and pointer `~` do a job, and what job.

    Found by :mod:`~sopuli.config.secret_refs`'s own rules. A qualifier is an `@`
    with an `=` after it, peeled from the end, and the parser refuses a second
    one. So every such `@` is marked, not only the last. A vault prefix is a `:`
    with no `/` or `#` before it, and the pointer starts at the first `/` after
    the `#`.
    """
    places: dict[int, str] = {}
    head = rendered
    while (at_sign := head.rfind(QUALIFIER_SEPARATOR)) != -1 and "=" in head[at_sign:]:
        places[at_sign] = "starts a version or stage qualifier"
        places[head.index("=", at_sign)] = "gives a version or stage qualifier its value"
        head = head[:at_sign]
    colon = head.find(VAULT_SEPARATOR)
    before = (POINTER_SEPARATOR, FIELD_SEPARATOR)
    if colon != -1 and not any(0 <= head.find(sign) < colon for sign in before):
        places[colon] = "names a vault"
    field = head.find(FIELD_SEPARATOR)
    pointer = head.find(POINTER_SEPARATOR, field) if field != -1 else -1
    if pointer != -1:
        for index in range(pointer, len(head)):
            if head[index] == "~":
                places[index] = "starts a JSON pointer escape"
    return places


def _refuse_a_name_in_a_separators_place(
    ref: str,
    rendered: str,
    tokens: Mapping[str, str],
    expanded: ExpandedTarget,
    *,
    at: KeyPath,
) -> None:
    """Refuse a name that brings a vault prefix, a qualifier or a pointer escape (#940).

    ``01-configuration.md`` §7 says why. A `:`, `@`, `=` or `~` is refused only
    where it does that job, so ``acme:web`` mid-path or ``acme~web`` in a path
    stay allowed. Two names that make a qualifier between them are caught too,
    because its `@` and its `=` each land in one of them.
    """
    places = _structure(rendered)
    if not places:
        return
    for token, start, end in _spans(ref, tokens):
        jobs = [(index, places[index]) for index in range(start, end) if index in places]
        if not jobs or not _is_name(token, expanded):
            continue
        index, job = jobs[0]
        raise ConfigError(
            f"{{{token}}} in secret ref {ref!r} is {tokens[token]!r}, whose "
            f"`{rendered[index]}` {job}",
            at=at,
            hint=(
                "a name goes into the ref as written, so a `:`, `@`, `=` or `~` in it can "
                "change where the password is stored. Declare it in an application entry "
                "of its own, with a ref that does not use this placeholder, or rename it "
                "where the database allows"
            ),
        )


def _tokens(application: Application, account: str, expanded: ExpandedTarget) -> dict[str, str]:
    """§7's token table, as a flat scope.

    Labels go in first and the built-ins overwrite them, so `{target}` means the
    target name even on an estate that labels something `target`. The built-ins
    are documented and a label is whatever somebody typed; the one that is
    specified wins.

    Two absences are deliberate. A target with no `environment` contributes no
    `{env}`, and one with no container no `{container}` -- so a template using
    either against a target that has neither fails to render, which §10 requires
    of any unresolved token. `{application}` is the documented exception: §7 says
    it is empty in the inline form, so it is present and empty rather than
    missing.
    """
    target = expanded.target
    tokens = dict(as_dict(target.labels))
    tokens.update(
        {
            "account": account,
            "account_lower": account.lower(),
            "account_upper": account.upper(),
            "target": target.name,
            "application": application.name or "",
        }
    )
    if target.environment is not None:
        tokens["env"] = target.environment
    if target.oracle.container is not None:
        tokens["container"] = target.oracle.container
    return tokens
