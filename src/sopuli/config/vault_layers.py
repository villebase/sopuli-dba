"""Merging P3's layers for one store (C13).

`00-principles.md` P3 puts one precedence chain over everything, and five of its
six layers reach a store:

.. code-block::

    2. Environment variable             SOPULI_VAULT__HCV_PROD__ADDR
    3. Profile block in config          profiles.ci.vaults.hcv-prod.addr
    4. Target/vault-level setting       vaults.hcv-prod.addr
    5. Top-level defaults in config     defaults.vaults.hcv-prod.addr

The third-party variables -- ``VAULT_ADDR`` and friends -- are also layer 2, ranked
below their ``SOPULI_*`` equivalent, as P3 says. **Layer 1 is one key wide**
(decision #422): ``--vault-addr`` hoists ``vaults.*.addr`` onto the command
line and nothing else does, so there is no ``--vault-mount`` beside it.
:func:`sopuli.config.vault_env.vault_cli_contributions` places it, on purpose --
which store an unnamed setting addresses is §6's question and it has one answer.

**The environment is collected next door**, in :mod:`sopuli.config.vault_env`,
which owns §6's spellings and the question the unnamed variables raise -- which
store is "the active" one. What arrives here is contributions, already addressed
to a store and a key, so this function is the place where the layers meet.

**The direction is the thing most likely to be got wrong.** A top-level
``vaults:`` entry *outranks* ``defaults.vaults:``, so the ``defaults:`` block
supplies keys the declaration did not write rather than replacing ones it did.
The word "patch" reads the other way and is right only for a profile, which is
layer 3 and above the declaration.

**Every layer is merged in one pass**, which is why the active profile has to be
known before this runs. Resolving 4 against 5 first and folding 3 in
afterwards would give the right *value* for an overridden key and the wrong
*provenance* for it -- and for ``tls.verify``, whose ratchet is the reason this
goes through the resolver at all, it would report the winner of the first pass
rather than the layer somebody has to go and edit.

The active profile is chosen by :func:`sopuli.config.profiles.select_profile` and
reaches here on :attr:`~sopuli.config.model.Config.active_profile`. A profile
that is declared and not active contributes nothing: §5 rule 1 is that exactly
one profile is active, so the others are inert text in the file.

**Not a second resolver.** :mod:`sopuli.settings` owns the merge rule, and every
key here goes through it -- which is the whole reason ``vaults.*.tls.verify``
ratchets instead of being overwritten. A hand-rolled "highest layer wins" would
have been three lines and would have got that one key silently wrong, because it
is the one key where highest-layer-wins is not the rule.

Two shape decisions the merge has to make, and they differ:

**``auth:`` is replaced whole.** Its keys are only meaningful together with a
``method``, so a key-by-key merge produces credentials nobody wrote --
``method: approle`` carrying a leftover ``token:`` from the declaration
authenticates as nobody. The layer that wrote an ``auth:`` block wrote all of it.

**``tls:`` is merged key by key.** Its keys are independent facts about one
connection, and one of them is under the safety ratchet. Replacing the block
whole would let a layer mentioning only ``ca_file`` drop a ``verify: true`` it
never spoke about, which is exactly the relaxation invariant 10 exists to stop.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import replace
from typing import Any
from urllib.parse import urlsplit

from sopuli.config.codes import (
    RELAXATION_DEFEATED,
    THIRD_PARTY_ADDR_OVERRIDES,
    THIRD_PARTY_ADDR_USERINFO,
    THIRD_PARTY_NAMESPACE_OVERRIDES,
    THIRD_PARTY_VARIABLE_UNAPPLIED,
)
from sopuli.config.errors import ROOT, ConfigError, KeyPath
from sopuli.config.model import Config, ConfigWarning, Vault, VaultAuth, VaultPatch, VaultTls
from sopuli.config.plain_http import PLAIN_HTTP_HINT, plain_http_scheme
from sopuli.config.vault_env import (
    NO_ENV,
    default_store,
    vault_cli_contributions,
    vault_env_contributions,
)
from sopuli.config.vaults import HASHICORP_KEYS, OCI_AUTH_METHODS, OCI_KEYS
from sopuli.settings import Contribution, Layer, Resolved, ratchet_note, resolve

#: One store's environment contributions, keyed by setting key -- what
#: :func:`~sopuli.config.vault_env.vault_env_contributions` produces for one
#: name. Empty for a store no variable mentioned, which is almost always all of
#: them.
EnvKeys = Mapping[str, Sequence[Contribution]]

#: The scalar keys of a vault entry, and the order the merged object takes them.
#: ``auth`` is absent because it is not a scalar; ``tls`` because its members are
#: merged individually. See the module note.
REACH_KEYS = ("addr", "mount", "kv_version", "namespace", "timeout_s", "merge_patch")

#: The members of ``tls:``, merged one at a time.
TLS_KEYS = ("ca_file", "ca_path", "client_cert", "client_key", "server_name", "verify")


def setting_name(key: str) -> str:
    """What a per-store setting is called in the registry.

    ``addr`` becomes ``vaults.*.addr``; ``tls.verify`` becomes
    ``vaults.*.tls.verify``. The ``*`` stands for the store, because a registry
    keyed by concrete store name would have to be built from a config -- and
    :data:`sopuli.settings.registry.SETTINGS` is a literal on purpose, so that the
    ratcheted set stays readable in one place without one.

    The concrete store is carried on the contribution's ``detail`` instead, which
    is where a location belongs anyway (``03-json-output.md``
    §``invocation.options``). ``sopuli/settings/sources.py`` already refers to
    ``vaults.*.tls.verify`` by exactly this spelling in the ``VAULT_SKIP_VERIFY``
    refusal, which is the same name arriving from the other end.
    """
    return f"vaults.*.{key}"


def apply_vault_layers(
    config: Config, *, env: Mapping[str, str] = NO_ENV, vault_addr: str | None = None
) -> tuple[tuple[Vault, ...], tuple[ConfigWarning, ...]]:
    """Every declared store with its layers merged in, and what was refused.

    A patch naming a store the file does not declare is **ignored here and
    refused elsewhere**: :mod:`sopuli.config.references` resolves every name in
    the file against what it declares, in one pass, with one message. Growing a
    second dangling-name error here would be a second thing to learn about the
    same mistake -- and nothing can proceed past that check either way.

    ``env`` defaults to empty rather than to ``os.environ``: this layer does no
    I/O and reads no ambient state, so a caller that wants the process's own
    environment says so (``04-testing.md`` §4). ``vault_addr`` is
    ``--vault-addr``'s value and defaults to ``None`` for the same reason -- the
    command line is the caller's to supply, not this layer's to find.
    """
    stores = [vault.name for vault in config.vaults]
    active = default_store(env, config.defaults.vault)
    from_env, env_warnings = vault_env_contributions(env, stores=stores, active=active)
    from_cli = vault_cli_contributions(vault_addr, stores=stores, active=active)

    by_name: dict[str, list[tuple[Layer, KeyPath, VaultPatch]]] = {}
    # Highest authority first, because `_highest` reads `auth:` off the front of
    # this list. The resolver sorts for itself; that one key does not go through
    # it, being replaced whole rather than merged.
    profile = config.active_profile
    if profile is not None:
        at = ROOT.key("profiles").key(profile.name).key("vaults")
        for patch in profile.vaults:
            by_name.setdefault(patch.name, []).append((Layer.PROFILE, at.key(patch.name), patch))
    for patch in config.defaults.vaults:
        by_name.setdefault(patch.name, []).append(
            (Layer.DEFAULTS, ROOT.key("defaults").key("vaults").key(patch.name), patch)
        )

    merged = []
    warnings: list[ConfigWarning] = list(env_warnings)
    for vault in config.vaults:
        # Layer 1 in front of layer 2, which is all the resolver needs: the two
        # are different layers, so it ranks them itself, and within a key the
        # list order only decides a tie that cannot happen between them.
        supplied = {
            key: [*from_cli.get(vault.name, {}).get(key, []), *contributions]
            for key, contributions in from_env.get(vault.name, {}).items()
        }
        for key, contributions in from_cli.get(vault.name, {}).items():
            supplied.setdefault(key, contributions)
        if vault.type == "oci":
            supplied, unapplied = _without_thirdparty(vault.name, supplied)
            warnings.extend(unapplied)
        if "addr" in supplied:
            supplied["addr"], dropped = _drop_userinfo(vault.name, supplied["addr"])
            warnings.extend(dropped)
        one, found = _merge(vault, by_name.get(vault.name, []), supplied)
        merged.append(one)
        warnings.extend(found)
    return tuple(merged), tuple(warnings)


def _without_thirdparty(
    name: str, supplied: dict[str, list[Contribution]]
) -> tuple[dict[str, list[Contribution]], list[ConfigWarning]]:
    """``supplied`` without HashiCorp's own variables, for an OCI store, and why.

    ``VAULT_ADDR``, ``VAULT_NAMESPACE`` and ``VAULT_CACERT`` are exported in
    every shell that has run `vault`, and they mean nothing to an OCI store. §6
    does not fail a run over another tool's variable: it warns that the variable
    was not applied, with ``SOPULI-W038``, and so does this (#1130). This tool's
    own ``SOPULI_*`` variables and ``--vault-addr`` stay, and
    :func:`_refuse_hashicorp_keys` refuses them.
    """
    kept: dict[str, list[Contribution]] = {}
    warnings = []
    for key, contributions in supplied.items():
        for one in contributions:
            if one.layer is not Layer.ENV_THIRDPARTY:
                kept.setdefault(key, []).append(one)
                continue
            warnings.append(
                ConfigWarning(
                    message=(
                        f"{one.location} is set and was not applied: the default store "
                        f"{name!r} is an OCI store, which reads no HashiCorp setting"
                    ),
                    # No `at`: the message names the variable.
                    at="",
                    hint="ignore this if the variable belongs to other work on this machine",
                    code=THIRD_PARTY_VARIABLE_UNAPPLIED,
                )
            )
    return kept, warnings


def _refuse_hashicorp_keys(
    vault: Vault, values: Mapping[str, Any], settings: Mapping[str, Resolved]
) -> None:
    """An OCI store reads none of HashiCorp's keys, from any layer (#1130).

    Checked on the merged values, so a profile, ``defaults.vaults``, a
    ``SOPULI_*`` variable or ``--vault-addr`` is refused as the file is, and the
    message names the layer that supplied the key. P3 refuses a key the tool
    would ignore. ``merge_patch`` has its own message, in
    :func:`_refuse_inert_merge_patch`.
    """
    if vault.type != "oci":
        return
    for key in HASHICORP_KEYS:
        if values.get(key) is None:
            continue
        answer = settings.get(key) or next(
            (one for name, one in settings.items() if name.startswith(f"{key}.")), None
        )
        given = "" if answer is None else f", from {answer.location},"
        raise ConfigError(
            f"vault {vault.name!r}: `{key}`{given} has no effect on a store of type 'oci'",
            at=ROOT,
            hint="it is a HashiCorp Vault key; remove it from this store",
        )


def _refuse_tls_on_oci(
    vault: Vault, patches: list[tuple[Layer, KeyPath, VaultPatch]], from_env: EnvKeys
) -> None:
    """An OCI store has no ``tls:`` block, from any layer (#1130).

    Its SDK verifies TLS itself. Checked before :func:`_merge_tls`, so that the
    message is this one and not one of that function's own refusals, and it
    names the layer that wrote the block.
    """
    if vault.type != "oci":
        return
    found = next((str(at.key("tls")) for _, at, patch in patches if patch.tls is not None), None)
    if found is None and vault.tls is not None:
        found = str(ROOT.key("vaults").key(vault.name).key("tls"))
    if found is None:
        found = next(
            (
                one.location
                for key, contributions in from_env.items()
                if key.startswith("tls.")
                for one in contributions
            ),
            None,
        )
    if found is not None:
        raise ConfigError(
            f"vault {vault.name!r}: `tls`, from {found}, has no effect on a store of type 'oci'",
            at=ROOT,
            hint="it is a HashiCorp Vault key; the OCI SDK verifies TLS itself",
        )


def _refuse_hashicorp_auth(vault: Vault, auth: VaultAuth | None, *, at: KeyPath) -> None:
    """An OCI store authenticates only with OCI's own methods (#1130).

    The other way round, an OCI method on a HashiCorp store, is refused when the
    store connects (:mod:`sopuli.store.hashicorp._auth`). This one is refused
    when the file is read, as the HashiCorp keys are, so a store whose ``type``
    was edited to ``oci`` does not keep an ``approle`` block that fails only at
    the first connection. ``at`` is the block in force, which a profile or
    ``defaults.vaults`` may have written.
    """
    if vault.type != "oci" or auth is None or auth.method in OCI_AUTH_METHODS:
        return
    raise ConfigError(
        f"auth method {auth.method!r} is a HashiCorp Vault method, and this is an OCI store",
        at=at,
        hint=f"an OCI store authenticates with one of: {', '.join(OCI_AUTH_METHODS)}",
    )


def _refuse_inert_merge_patch(vault: Vault, values: Mapping[str, Any]) -> None:
    """``merge_patch`` only means something on a HashiCorp KV v2 store.

    Anywhere else nothing reads it, and P3 says a key the tool would ignore is
    refused rather than accepted. Checked on the merged values, so a profile that
    writes it for an OCI store, or a layer that turns a store into KV v1, is
    refused as well.
    """
    if values.get("merge_patch") is None:
        return
    at = ROOT.key("vaults").key(vault.name).key("merge_patch")
    if vault.type != "hashicorp":
        raise ConfigError(
            f"`merge_patch` has no effect on a store of type {vault.type!r}",
            at=at,
            hint="it turns off HashiCorp KV v2's merge patch; remove it from this store",
        )
    if values.get("kv_version") == 1:
        raise ConfigError(
            "`merge_patch` has no effect on a KV v1 store",
            at=at,
            hint="KV v1 has no merge patch, so every write is already read-modify-write",
        )


#: What to do instead of a user name or password in ``addr``, for the refusal and
#: for ``SOPULI-W057``.
USERINFO_HINT = (
    "Vault does not read credentials from its address, so write the address with no "
    "`@` in it. A proxy that needs a credential reads it from HTTPS_PROXY. A `file` "
    "store's path may not hold an `@` either"
)


def _holds_at(address: str) -> bool:
    """Whether ``address`` holds an ``@`` after its scheme (#891).

    An ``@`` there may end a user name and password. **Not parsed, so it fails
    closed.** ``urlsplit`` ends the authority at the first ``/``, ``?`` or
    ``#``, so a password holding one would put the ``@`` outside the part it
    finds, and an address it cannot parse would hide the part entirely. An
    ``@`` in a path counts too, so a ``file`` store's path may not hold one.
    """
    _, separator, rest = address.partition("://")
    return "@" in (rest if separator else address)


def _without_userinfo(address: str) -> str | None:
    """``address`` without its user name and password, where that is all its ``@`` can be.

    Here the result is the address the run connects to, so a guess could send
    the token to another host: cutting
    ``https://vault.example.com/ui/@other.example.net`` at its ``@`` gives
    ``https://other.example.net``. So the cut is made only where the address
    has one ``@``, ``urlsplit`` puts it in the authority, and a host follows
    it. Otherwise ``None``, and the caller does not use the address.
    """
    if address.count("@") != 1:
        return None
    try:
        parts = urlsplit(address)
        host = parts.hostname
    except ValueError:
        return None
    if "@" not in parts.netloc or not host:
        return None
    scheme, _, rest = address.partition("://")
    return f"{scheme}://{rest.partition('@')[2]}"


def _refuse_userinfo(vault: Vault, answer: Resolved | None) -> None:
    """No address this tool was given may hold a user name or password (#891).

    Vault does not authenticate through the address, so one there is a proxy
    credential or a mistake, and ``config show``, ``--explain`` and the
    messages that name an address would print it. Every contribution is
    checked, not only the one that won, because the resolved setting keeps
    every layer's value, and an output may show the ones that lost.
    ``VAULT_ADDR`` arrives here already handled by :func:`_drop_userinfo`.

    The message names the layer and never the address.
    """
    if answer is None:
        return
    for one in answer.contributions:
        if _holds_at(str(one.value)):
            raise ConfigError(
                f"vault {vault.name!r}: the address {one.location} gives holds a user "
                f"name or password, before an `@`",
                at=ROOT,
                hint=USERINFO_HINT,
            )


def _drop_userinfo(
    name: str, contributions: Sequence[Contribution]
) -> tuple[list[Contribution], list[ConfigWarning]]:
    """``VAULT_ADDR`` without its user name and password, and a warning if it had an ``@``.

    The other layers are refused by :func:`_refuse_userinfo`. This one is another
    tool's variable, and §6 does not fail a run over it, so the run goes on
    and says so with ``SOPULI-W057``. Where :func:`_without_userinfo` finds a
    plain user name and password, the run uses the rest of the address. Where
    it cannot tell what the ``@`` ends, the variable is not applied at all, as
    when it has no store to apply to. Handled whether or not the variable wins,
    because the resolved setting keeps every layer's value, and an output may
    show the ones that lost.
    """
    kept = []
    warnings = []
    for one in contributions:
        if one.layer is not Layer.ENV_THIRDPARTY or not _holds_at(str(one.value)):
            kept.append(one)
            continue
        cut = _without_userinfo(str(one.value))
        if cut is None:
            message = (
                f"{one.location} holds an `@` that may not end a user name and password, "
                f"so this run did not apply it to vault {name!r}"
            )
        else:
            kept.append(replace(one, value=cut))
            message = (
                f"{one.location} holds a user name or password, before an `@`, and this "
                f"run dropped it: the address it gives vault {name!r} is {cut}"
            )
        warnings.append(
            ConfigWarning(
                message=message,
                # No `at`: the message names the variable.
                at="",
                hint=USERINFO_HINT,
                code=THIRD_PARTY_ADDR_USERINFO,
            )
        )
    return kept, warnings


def _refuse_plain_http(vault: Vault, answer: Resolved | None) -> None:
    """A HashiCorp store's address must be ``https://``, except to loopback.

    Checked on the merged address, so an address from the file, a profile,
    ``VAULT_ADDR`` or ``--vault-addr`` is refused the same way, and the message
    names the one that won. Only a HashiCorp store reads ``addr`` as a URL: a
    ``file`` store reads it as a path. The rule is
    :mod:`sopuli.config.plain_http`.
    """
    if vault.type != "hashicorp" or answer is None:
        return
    scheme = plain_http_scheme(answer.value)
    if scheme is None:
        return
    raise ConfigError(
        f"vault {vault.name!r}: the address {answer.detail} gives must use https://, "
        f"and this one uses {scheme}",
        at=ROOT,
        hint=PLAIN_HTTP_HINT,
    )


def _merge(
    vault: Vault, patches: list[tuple[Layer, KeyPath, VaultPatch]], from_env: EnvKeys
) -> tuple[Vault, list[ConfigWarning]]:
    """One store, resolved key by key. Returns it and any defeated relaxation.

    **Every store goes through the resolver, including one nobody patched**
    (decision #428). A single contribution resolves to itself, so skipping the
    resolver for that store would give the same *value*. It would lose the
    provenance, and a store with no layers has provenance worth reporting:
    ``[vaults.vault-dev.addr]`` is the answer "the file wrote it, here", and it is
    only distinguishable from "nobody wrote it" because the pair exists.

    :attr:`~sopuli.config.model.Vault.patched` does not depend on this. It names
    the keys some *other* layer supplied, which is the ``layer is not OBJECT``
    test below.
    """
    values: dict[str, Any] = {}
    patched: list[str] = []
    settings: dict[str, Resolved] = {}
    warnings: list[ConfigWarning] = []

    for key in REACH_KEYS:
        answer = _resolve_key(key, vault, patches, from_env, at=ROOT.key("vaults").key(vault.name))
        if answer is None:
            continue
        values[key] = answer.value
        settings[key] = answer
        if answer.layer is not Layer.OBJECT:
            patched.append(key)
    for key in OCI_KEYS:
        # Declaration only (unpatchable), so no patch or variable is passed and
        # the one contribution is the entry's own. Resolved anyway, so that
        # `config show` can say where it came from, as for every other key.
        oci_answer = _resolve_key(key, vault, [], {}, at=ROOT.key("vaults").key(vault.name))
        if oci_answer is not None:
            settings[key] = oci_answer
    # Before the address checks: on an OCI store the address is the fault, and
    # a message about its `@` or its scheme would send the operator to fix the
    # wrong thing first.
    _refuse_hashicorp_keys(vault, values, settings)
    _refuse_inert_merge_patch(vault, values)
    _refuse_userinfo(vault, settings.get("addr"))
    _refuse_plain_http(vault, settings.get("addr"))
    for overridden in (
        _addr_overridden(vault.name, settings.get("addr")),
        _namespace_overridden(vault.name, settings.get("namespace")),
    ):
        if overridden is not None:
            warnings.append(overridden)

    # Before the merge, for the same reason: `_merge_tls` has refusals of its
    # own, and on an OCI store the block is the fault.
    _refuse_tls_on_oci(vault, patches, from_env)
    tls, tls_patched, tls_settings, tls_warnings = _merge_tls(vault, patches, from_env)
    if tls is not None:
        values["tls"] = tls
    patched.extend(tls_patched)
    settings.update(tls_settings)
    warnings.extend(tls_warnings)

    auth = _highest(patch.auth for _, _, patch in patches)
    # `_highest` takes the front of the list, so the first patch with a block is
    # the layer that wrote the one in force.
    auth_at = next((at for _, at, patch in patches if patch.auth is not None), None)
    _refuse_hashicorp_auth(
        vault,
        auth or vault.auth,
        at=(auth_at or ROOT.key("vaults").key(vault.name)).key("auth"),
    )
    if auth is not None:
        # Whole-block replacement, so there is nothing to merge and nothing to
        # keep from the declaration. `replace` leaves the declaration's own block
        # in place when no layer wrote one.
        #
        # No `settings` entry, for the same reason: there is no `Resolved` to
        # report, one block having replaced another rather than a key having won.
        # `patched` names it, which is what the store's own table column reads.
        values["auth"] = auth
        patched.append("auth")

    return (
        replace(
            vault,
            patched=tuple(sorted(patched)),
            settings=tuple(sorted(settings.items())),
            **values,
        ),
        warnings,
    )


def _addr_overridden(name: str, answer: Resolved | None) -> ConfigWarning | None:
    """A warning when ``VAULT_ADDR`` moved a store away from the file's ``addr``.

    P3 puts ``VAULT_ADDR`` above the file (#865). A shell often keeps the
    variable from other work, and the run then sends its auth material to that
    address and writes there, so every command that loads the file warns. The
    variable this tool owns, ``SOPULI_VAULT_ADDR``, and ``--vault-addr`` do not
    warn: whoever set them meant this tool.

    Nothing to say when the file declares no ``addr`` for the store, or the
    two name the same server: see :func:`_same_address`.

    Neither address holds a user name or password by now:
    :func:`_drop_userinfo` cut the variable's, and :func:`_refuse_userinfo`
    refused the file's.
    """
    if answer is None or answer.layer is not Layer.ENV_THIRDPARTY:
        return None
    declared = _declared_under(answer)
    if declared is None or _same_address(declared.value, answer.value):
        return None
    return ConfigWarning(
        message=(
            f"{answer.detail} sets the address of vault {name!r} to {answer.value}, "
            f"not {declared.value}, which {declared.detail} declares"
        ),
        # No `at`: the message names both locations already.
        at="",
        hint=(
            f"unset {answer.detail} if it is left over from other work; to choose the "
            f"address for this tool on purpose, use SOPULI_VAULT_ADDR or --vault-addr"
        ),
        code=THIRD_PARTY_ADDR_OVERRIDES,
    )


def _namespace_overridden(name: str, answer: Resolved | None) -> ConfigWarning | None:
    """A warning when ``VAULT_NAMESPACE`` moved a store away from the file's ``namespace``.

    The same hazard as :func:`_addr_overridden` (#892): a namespace left over
    from other work sends this run's login and writes to another Vault
    Enterprise namespace. No ``SOPULI_*`` variable or flag sets a namespace, so
    the hint points at the file.

    **A file that declares no namespace still warns**, unlike the address. A
    store with no ``addr`` has no other address, but a store with no
    ``namespace`` uses the root namespace, and the variable moves it away from
    that. Nothing to say when the two differ only in ``/`` at either end, which
    Vault does not count.
    """
    if answer is None or answer.layer is not Layer.ENV_THIRDPARTY:
        return None
    declared = _declared_under(answer)
    if declared is not None and declared.value.strip("/") == answer.value.strip("/"):
        return None
    if declared is None:
        instead = "not the root namespace, which the file implies by declaring none"
    else:
        instead = f"not {declared.value!r}, which {declared.detail} declares"
    return ConfigWarning(
        message=(
            f"{answer.detail} sets the namespace of vault {name!r} to {answer.value!r}, {instead}"
        ),
        # No `at`: the message names both locations already.
        at="",
        hint=(
            f"unset {answer.detail} if it is left over from other work; to use that "
            f"namespace on purpose, declare it as the namespace of vault {name!r} in the "
            f"file, or in the profile this run uses"
        ),
        code=THIRD_PARTY_NAMESPACE_OVERRIDES,
    )


def _declared_under(answer: Resolved) -> Contribution | None:
    """The file's value under ``answer``, or ``None`` when the file declares none.

    The file's answer is its highest layer, which is the one an operator would
    edit.
    """
    return next((one for one in answer.contributions if one.layer in FILE_LAYERS), None)


#: The layers that are the config file, for :func:`_declared_under`.
FILE_LAYERS = frozenset({Layer.PROFILE, Layer.OBJECT, Layer.DEFAULTS})

#: The port a scheme implies, so ``https://v`` and ``https://v:443`` are one server.
DEFAULT_PORTS = {"http": 80, "https": 443}


def _same_address(first: str, second: str) -> bool:
    """Whether two addresses name the same server and path.

    Scheme and host are compared without case (``urlsplit`` lowers both), a
    missing port is the scheme's default, and a trailing ``/`` is ignored. An
    address that does not parse is compared as written.
    """
    try:
        one, two = urlsplit(first), urlsplit(second)
        ports = [
            url.port if url.port is not None else DEFAULT_PORTS.get(url.scheme)
            for url in (one, two)
        ]
    except ValueError:
        return first == second
    return (
        one.scheme == two.scheme
        and (one.hostname or "") == (two.hostname or "")
        and ports[0] == ports[1]
        and one.path.rstrip("/") == two.path.rstrip("/")
    )


def _merge_tls(
    vault: Vault, patches: list[tuple[Layer, KeyPath, VaultPatch]], from_env: EnvKeys
) -> tuple[VaultTls | None, list[str], dict[str, Resolved], list[ConfigWarning]]:
    """``tls:`` one member at a time, so ``verify`` can ratchet.

    ``None`` when no layer wrote a ``tls:`` block at all, which keeps "no block"
    distinct from "an empty block" -- the same distinction
    :class:`~sopuli.config.model.VaultTls` keeps between a missing ``verify`` and
    a written one. ``VAULT_CACERT`` counts as a layer writing one: it supplies
    ``tls.ca_file``, and a store whose only ``tls:`` key came from the
    environment still has a block.
    """
    wrote_tls = any(key.startswith("tls.") for key in from_env)
    if vault.tls is None and not wrote_tls and all(patch.tls is None for _, _, patch in patches):
        return None, [], {}, []

    values: dict[str, Any] = {}
    patched: list[str] = []
    settings: dict[str, Resolved] = {}
    warnings: list[ConfigWarning] = []
    for key in TLS_KEYS:
        answer = _resolve_key(
            f"tls.{key}", vault, patches, from_env, at=ROOT.key("vaults").key(vault.name)
        )
        if answer is None:
            continue
        values[key] = answer.value
        settings[f"tls.{key}"] = answer
        if answer.layer is not Layer.OBJECT:
            patched.append(f"tls.{key}")
        note = ratchet_note(answer)
        if note is not None:
            # A relaxation that lost is reported rather than swallowed
            # (`sopuli/settings/resolver.py`). Here it becomes a config warning
            # rather than a run diagnostic, because the merge happens while the
            # file is being read and `Config.warnings` is where a finding about
            # the file goes -- the boundary turns those into `diagnostics[]` for
            # every command that loads a config.
            warnings.append(
                ConfigWarning(
                    message=note,
                    # No `at`. Every other config warning needs one because its
                    # message describes a value; this one names *both* locations
                    # already -- the layer that asked and the one that held -- and
                    # a breadcrumb in front of it would repeat one of them a few
                    # words before the sentence says it again.
                    at="",
                    hint="invariant 10: a safety setting cannot be relaxed by any layer",
                    code=RELAXATION_DEFEATED,
                )
            )
    return VaultTls(**values), patched, settings, warnings


def _resolve_key(
    key: str,
    vault: Vault,
    patches: list[tuple[Layer, KeyPath, VaultPatch]],
    from_env: EnvKeys,
    *,
    at: KeyPath,
) -> Resolved | None:
    """One key across the layers that spoke, through the one resolver.

    The declaration contributes at :attr:`~sopuli.settings.registry.Layer.OBJECT`
    -- P3's layer 4, "target/vault-level setting" -- and a ``defaults:`` patch at
    layer 5. The environment contributes at layer 2, already addressed to
    this store by :mod:`sopuli.config.vault_env`. Which is higher is the
    resolver's business and not restated here.

    **The answer is renamed to the concrete store on the way out**
    (decision #428). :func:`setting_name` is what the registry has to be asked
    with -- ``vaults.*.tls.verify``, for the reason its own docstring gives --
    and it is not what a reader can be told: the ``*`` stands for every store at once and is
    not a key anybody can edit. Two things quote the name back.
    :func:`~sopuli.settings.ratchet_note` puts it in the sentence a defeated
    ``tls.verify`` produces -- which reaches an operator twice, as a warning on
    every command that loads the file and as the continuation line under this
    store's row in ``config show --explain``. Without the rename, the text
    ``vaults.*.tls.verify stays true`` would sit directly beneath a row named
    ``vaults.vault-dev.tls.verify``.

    Renamed **here** rather than in either view, because there are two of them and
    they must not spell one sentence two ways -- the argument
    :func:`~sopuli.settings.render_value` makes about a value appearing in a table
    and in a note three lines below it. The registry lookup is unaffected; only
    the label the answer carries changes.
    """
    contributions = list(from_env.get(key, ()))
    declared = _read(vault, key)
    if declared is not None:
        contributions.append(
            Contribution(layer=Layer.OBJECT, value=declared, detail=str(_at(at, key)))
        )
    for layer, where, patch in patches:
        value = _read(patch, key)
        if value is not None:
            contributions.append(
                Contribution(layer=layer, value=value, detail=str(_at(where, key)))
            )
    answer = resolve(setting_name(key), contributions)
    return None if answer is None else replace(answer, setting=str(_at(at, key)))


def _read(entry: Vault | VaultPatch, key: str) -> Any:
    """The value of ``addr`` or of ``tls.verify`` on either shape."""
    if not key.startswith("tls."):
        return getattr(entry, key)
    return None if entry.tls is None else getattr(entry.tls, key.removeprefix("tls."))


def _at(base: KeyPath, key: str) -> KeyPath:
    for part in key.split("."):
        base = base.key(part)
    return base


def _highest(blocks: Any) -> Any:
    """The first non-``None`` block, in the order the caller supplied.

    ``auth:`` only, and only because it is replaced whole. ``patches`` is built
    highest-authority-first, so "first" is "wins" -- and there is exactly one
    layer in it today, which is why this is three lines rather than a sort.
    """
    for block in blocks:
        if block is not None:
            return block
    return None
