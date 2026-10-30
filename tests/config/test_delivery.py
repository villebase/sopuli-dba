"""The `delivery:` block — UC-2 §6.

Tier 0, pure: everything builds from a dict, so there is no filesystem and no I/O.
Fixtures use the fictional vocabulary the provenance note requires.

One accept and one reject per rule, and the rejects assert on the *message*: a rule
that fires without saying which key is wrong has not finished its job.

Which keys a method's sub-block takes is a fact about the service behind the
method, so only methods whose keys are read have keys to test. `vault_wrapped:`,
`vault_path:`, `one_time_link:` and `onepassword_share:` have sections of their
own below; `smtp_encrypted:` is not read. What this layer owes every method is
the part common to all six: the method is one of the six, and the selected one
brought settings.
"""

from __future__ import annotations

from typing import Any

import pytest

from sopuli.config.codes import DELIVERY_UNSERVICEABLE, NOTIFY_UNSERVICEABLE
from sopuli.config.delivery import (
    DEFAULT_METHOD,
    DELIVERY_METHODS,
    build_delivery,
    unserviceable,
)
from sopuli.config.errors import ConfigError
from sopuli.config.loading import build_config


def document(**block: Any) -> dict[str, Any]:
    return {"version": 1, "delivery": block}


def built(**block: Any) -> Any:
    section = build_delivery(document(**block))
    assert section is not None
    return section


# --------------------------------------------------------------- declaring ---


def test_a_section_that_is_absent_is_none_rather_than_the_default() -> None:
    """An estate that configured no delivery has not silently chosen one. A reset
    with nowhere to deliver is a refusal for the verb to make, and a default
    materialised here would make that estate indistinguishable from one that asked
    for `vault_wrapped` by name."""
    assert build_delivery({"version": 1}) is None


def test_the_method_is_read_and_its_sub_block_is_required() -> None:
    section = built(method="smtp_encrypted", smtp_encrypted={"to": "acme"})

    assert section.method == "smtp_encrypted"
    assert not section.is_seen


def test_an_omitted_method_is_the_default() -> None:
    """§6.2: `vault_wrapped` works against a stock Vault, and every other unseen
    method needs infrastructure the tool does not create."""
    assert built(vault_wrapped={"ttl": "15m"}).method == DEFAULT_METHOD
    assert DEFAULT_METHOD == "vault_wrapped"


def test_manual_is_the_one_seen_method() -> None:
    """A path is seen because of what it does, not because a file said so."""
    assert built(method="manual", manual={"force_expire": True}).is_seen
    for method in DELIVERY_METHODS:
        if method != "manual":
            # Each method has its own required keys, so a sweep over the enum
            # has to carry them: `vault_wrapped` needs a `ttl`, `vault_path` a
            # `ttl` and a `prefix`, `one_time_link` a `base_url` and a `ttl`,
            # `onepassword_share` a vault, a `ttl` and a token, and an empty
            # block is a config error rather than an unseen delivery.
            settings: dict[str, Any] = {
                "vault_wrapped": {"ttl": "15m"},
                "vault_path": {"ttl": "8h", "prefix": "personal"},
                "one_time_link": link_block(),
                "onepassword_share": onepassword_block(),
            }.get(method, {})
            assert not built(method=method, **{method: settings}).is_seen


def test_the_enum_includes_a_method_with_no_tracking_issue() -> None:
    """`smtp_encrypted` has no issue of its own and is in the enum anyway. An enum
    listing only what somebody had written a ticket for would be a contract shaped
    by project bookkeeping (UC-2 §6.2)."""
    assert "smtp_encrypted" in DELIVERY_METHODS
    assert len(DELIVERY_METHODS) == 6


@pytest.mark.parametrize(
    "method",
    [
        {"method": "manual", "manual": {"force_expire": True}},
        {"method": "vault_wrapped", "vault_wrapped": {"ttl": "15m"}},
    ],
    ids=["manual", "vault_wrapped"],
)
def test_a_notify_block_is_read_whichever_built_method_is_selected(
    method: dict[str, Any],
) -> None:
    """`tests/config/test_notify.py` holds the notify block's grammar; what
    belongs here is that `delivery:` reaches it, and that it does so for each
    method this build serves, the seen one and the unseen one."""
    section = built(
        **method,
        notify={
            "method": "webhook",
            "webhook": {
                "url": {"env": "SOPULI_NOTIFY"},
                "template": "{account} on {target} has a new password waiting",
            },
        },
    )

    assert section.notify is not None
    assert section.notify.webhook is not None
    assert section.notify.webhook.url.location == "SOPULI_NOTIFY"


def test_a_notify_block_is_read_on_the_seen_path_too() -> None:
    """A notification is a property of the delivery as a whole, not of a method --
    so unlike a method's own sub-block it is read whichever method is selected.
    The tool does not author the message, so an estate on `manual` writes one that
    is true of `manual`."""
    section = built(
        method="manual",
        manual={"force_expire": True},
        notify={
            "method": "webhook",
            "webhook": {"url": {"env": "SOPULI_NOTIFY"}, "template": "{account} was reset"},
        },
    )

    assert section.notify is not None


# ---------------------------------------------------------------- refusing ---


def test_an_unknown_method_is_refused_and_lists_the_known_ones() -> None:
    with pytest.raises(ConfigError) as raised:
        build_delivery(document(method="carrier_pigeon", carrier_pigeon={}))
    message = str(raised.value)
    assert "delivery.method" in message
    assert "carrier_pigeon" in message
    assert "vault_wrapped" in message


def test_a_method_without_its_sub_block_is_refused_naming_the_method() -> None:
    """Half a configuration, and the half that was typed is the half that reads as
    done."""
    with pytest.raises(ConfigError) as raised:
        build_delivery(document(method="one_time_link"))
    message = str(raised.value)
    assert "one_time_link" in message
    assert "delivery.one_time_link" in message


def test_the_default_method_needs_its_block_too() -> None:
    """An omitted `method:` is `vault_wrapped`, and a default is not an excuse to
    skip the settings it needs."""
    with pytest.raises(ConfigError) as raised:
        build_delivery(document(notify={"method": "webhook"}))
    assert "vault_wrapped" in str(raised.value)


def test_a_sub_block_for_an_unselected_method_is_left_alone() -> None:
    """Keeping a configuration you are switching between is ordinary, and refusing
    it would make the file harder to edit without making a run safer -- nothing
    reads an unselected block. The opposite of §1's leftover `secret_template:`,
    where the stale key silently *governs*."""
    section = built(
        method="manual",
        manual={"force_expire": True},
        vault_wrapped={"ttl": "15m"},
    )

    assert section.method == "manual"


def test_an_unknown_key_in_the_block_is_refused() -> None:
    with pytest.raises(ConfigError) as raised:
        build_delivery(document(method="manual", manual={}, retries=3))
    assert "retries" in str(raised.value)


def test_a_sub_block_that_is_not_a_mapping_is_refused() -> None:
    with pytest.raises(ConfigError) as raised:
        build_delivery(document(method="manual", manual=["force_expire"]))
    assert "delivery.manual" in str(raised.value)


def test_a_notify_block_that_is_not_a_mapping_is_refused() -> None:
    with pytest.raises(ConfigError) as raised:
        build_delivery(document(method="manual", manual={}, notify="webhook"))
    assert "delivery.notify" in str(raised.value)


def test_the_block_is_a_mapping_not_a_list() -> None:
    with pytest.raises(ConfigError) as raised:
        build_delivery({"version": 1, "delivery": [{"method": "manual"}]})
    assert "delivery" in str(raised.value)


# --------------------------------------------- a method this build lacks ---


def test_an_unimplemented_method_warns_that_nothing_serves_it() -> None:
    """A `delivery:` block that validates silently reads as delivery being
    configured, and the operator would find out otherwise at the moment a password
    had already been drawn."""
    # The test is about the warning, not about which method is missing, so it
    # uses one this build does not implement.
    notice = unserviceable(built(method="smtp_encrypted", smtp_encrypted={}))

    assert notice is not None
    assert "smtp_encrypted" in notice
    assert "not implemented in this build" in notice


def test_an_implemented_method_warns_about_nothing() -> None:
    """`manual` is served, and the warning knows that: it would otherwise read
    *no delivery method is implemented* for every configured method, so an estate
    with a working seen path would be told nothing could hand a password over."""
    assert unserviceable(built(method="manual", manual={"force_expire": True})) is None


def test_no_block_means_nothing_to_warn_about() -> None:
    assert unserviceable(None) is None


# --------------------------------------------------------- through loading ---


def test_the_block_reaches_the_config() -> None:
    config = build_config(
        {
            "version": 1,
            "targets": [
                {
                    "name": "appdb-dev-alpha",
                    "type": "oracle",
                    "dsn": "db-dev.example.com:1521/ALPHA.pdb.example.com",
                }
            ],
            "delivery": {"method": "vault_wrapped", "vault_wrapped": {"ttl": "15m"}},
        }
    )

    assert config.delivery is not None
    assert config.delivery.method == "vault_wrapped"
    assert config.delivery.vault_wrapped is not None
    assert config.delivery.vault_wrapped.ttl == "15m"


def test_a_file_with_no_delivery_carries_none() -> None:
    assert build_config({"version": 1}).delivery is None


# ------------------------------------ the tool is never looser than the schema ---


def test_an_unselected_block_that_is_not_an_object_is_refused() -> None:
    """The published schema types all six method properties as objects, so
    `vault_wrapped: 15m` beside `method: manual` is refused by the schema.
    Accepting it here would invert §9b's claim that the schema is the incomplete
    check and the tool the complete one."""
    with pytest.raises(ConfigError) as raised:
        build_delivery(document(method="manual", manual={}, vault_wrapped="15m"))
    assert "delivery.vault_wrapped" in str(raised.value)


def test_an_unselected_block_is_still_left_alone_in_the_senses_that_matter() -> None:
    """Only the grammar widened. Its presence is not refused and its keys are not
    judged -- `tt1` is still accepted, because which keys a method takes is that
    method's own issue."""
    section = built(
        method="manual",
        manual={"force_expire": True},
        vault_wrapped={"tt1": "15m"},
    )

    assert section.method == "manual"


def test_every_method_block_is_checked_not_only_the_selected_one() -> None:
    for name in DELIVERY_METHODS:
        if name == "manual":
            continue
        with pytest.raises(ConfigError, match=f"delivery.{name}"):
            build_delivery(document(method="manual", manual={}, **{name: "not-an-object"}))


# ----------------------------------------------- the warning reaches the run ---


def test_the_warning_reaches_config_warnings_rather_than_only_the_helper() -> None:
    """The wire, not the function. `_delivery_warnings` could be dropped from the
    loader's return and every other test here would still pass -- which is the
    failure `Setting.inert_reason`'s docstring lists four instances of: a complete
    implementation with the one wire missing, found by somebody reading the code
    rather than by a test."""
    config = build_config(
        {
            "version": 1,
            "delivery": {"method": "smtp_encrypted", "smtp_encrypted": {}},
        }
    )

    found = [warning for warning in config.warnings if "not implemented" in warning.message]
    assert len(found) == 1
    assert found[0].at == "delivery.method"
    assert found[0].code == DELIVERY_UNSERVICEABLE
    assert found[0].hint is not None
    assert "nothing is wrong with the file" in found[0].hint


def test_a_channel_that_cannot_send_warns_with_its_own_code(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The notify channel's warning is not the method's: an estate can have one
    working and the other not, so a consumer must tell them apart by code."""
    from sopuli.notify.registry import Notifier

    missing = Notifier(
        module="sopuli.notify.webhook",
        extra="notify",
        provides=frozenset({"a_module_nobody_has_installed"}),
    )
    monkeypatch.setattr("sopuli.config.notify.NOTIFIERS", {"webhook": missing})
    webhook = {"url": {"env": "SOPULI_NOTIFY_WEBHOOK"}, "template": "{account} is ready"}
    config = build_config(
        {
            "version": 1,
            "delivery": {
                "method": "vault_wrapped",
                "vault_wrapped": {"ttl": "15m"},
                "notify": {"method": "webhook", "webhook": webhook},
            },
        }
    )

    [warning] = [one for one in config.warnings if one.at == "delivery.notify.method"]
    assert warning.code == NOTIFY_UNSERVICEABLE


def test_a_file_with_no_delivery_carries_no_such_warning() -> None:
    config = build_config({"version": 1})

    assert not [w for w in config.warnings if "no delivery method" in w.message]


# ---------------------------------------------------- `vault_wrapped:`'s keys ---


def test_the_ttl_is_required_rather_than_defaulted() -> None:
    """The argument `force_expire` makes one method over: a wrapping token's whole
    safety story is that it stops working, so how soon is not a number to inherit
    from a tool's default. A default would be an unreviewed value standing between
    a password and whoever finds the token afterwards."""
    with pytest.raises(ConfigError) as raised:
        build_delivery(document(method="vault_wrapped", vault_wrapped={}))

    assert "needs a `ttl`" in str(raised.value)
    assert "delivery.vault_wrapped.ttl" in str(raised.value)


def test_num_uses_is_refused_rather_than_ignored() -> None:
    """A response-wrapping token is single-use by construction, so the key can
    only describe a guarantee Vault is already making -- and accepting it
    silently would leave a file whose author believes the tool is enforcing
    something."""
    with pytest.raises(ConfigError) as raised:
        build_delivery(
            document(method="vault_wrapped", vault_wrapped={"ttl": "15m", "num_uses": 1})
        )

    assert "takes no `num_uses`" in str(raised.value)
    assert "single use by construction" in str(raised.value.hint or "")


@pytest.mark.parametrize("ttl", ["15", "15x", "0m", "-5m", "fifteen minutes", "15 m"])
def test_a_ttl_that_is_not_a_duration_is_refused_at_load(ttl: str) -> None:
    """Shape only, because Vault owns the grammar -- but shape *here*, so a typo
    is a config error rather than a 400 after a password has been drawn."""
    with pytest.raises(ConfigError, match="is not a duration"):
        build_delivery(document(method="vault_wrapped", vault_wrapped={"ttl": ttl}))


def test_an_empty_ttl_is_refused_by_the_field_before_the_shape() -> None:
    """Refused, and with the better message of the two: `must not be empty` says
    what to do, and `is not a duration` about an empty string would leave somebody
    looking for the unit they mistyped. Asserted so that tightening the pattern
    later does not quietly take the precise answer away."""
    with pytest.raises(ConfigError, match="must not be empty"):
        build_delivery(document(method="vault_wrapped", vault_wrapped={"ttl": ""}))


@pytest.mark.parametrize("ttl", ["15m", "900s", "1h", "90m"])
def test_the_durations_vault_actually_takes_are_accepted(ttl: str) -> None:
    section = built(method="vault_wrapped", vault_wrapped={"ttl": ttl})

    assert section.vault_wrapped is not None
    assert section.vault_wrapped.ttl == ttl


def test_the_store_is_optional_and_absence_means_the_chain() -> None:
    """Omitting `vault:` takes §3's chain -- the target's, then `defaults.vault` --
    which is the same resolution a secret ref walks. ``None`` rather than a
    materialised default, so a later layer can tell "not named here" from "named
    as this"."""
    section = built(method="vault_wrapped", vault_wrapped={"ttl": "15m"})

    assert section.vault_wrapped is not None
    assert section.vault_wrapped.vault is None


def test_the_store_can_be_named_on_the_method() -> None:
    """And it is not `reset_records.vault`. UC-2 §3.5 keeps the journal and the
    delivery target apart as two objects with two lifetimes, so an estate that
    wants them in one store says so twice rather than having one default to the
    other."""
    section = built(method="vault_wrapped", vault_wrapped={"ttl": "15m", "vault": "vault-handover"})

    assert section.vault_wrapped is not None
    assert section.vault_wrapped.vault == "vault-handover"


def test_an_unknown_key_in_the_wrapped_block_is_refused() -> None:
    """P3's "a typo in a credential tool must never be silently ignored", applied
    to the *selected* block now that it has keys of its own to typo -- which is
    the difference from the unselected one two tests down, whose keys stay
    unjudged on purpose."""
    with pytest.raises(ConfigError, match="delivery.vault_wrapped"):
        build_delivery(document(method="vault_wrapped", vault_wrapped={"ttl": "15m", "tt1": "x"}))


def test_the_block_is_not_read_when_another_method_is_selected() -> None:
    """`manual`'s rule, one method over: an unselected block is kept so somebody
    can switch between two configurations, and reading it either way would make a
    file start failing for a key the run never consults."""
    section = built(
        method="manual",
        manual={"force_expire": True},
        vault_wrapped={"num_uses": 1},
    )

    assert section.method == "manual"
    assert section.vault_wrapped is None


def test_vault_wrapped_is_served_by_this_build() -> None:
    """The warning that tells an estate nothing could deliver knows about
    `manual` and about this method, and `IMPLEMENTED` is one list so that
    `config validate` and the verb cannot disagree."""
    assert unserviceable(built(method="vault_wrapped", vault_wrapped={"ttl": "15m"})) is None


# ------------------------------------------------------- `vault_path:`'s keys ---


def path_block(**keys: Any) -> dict[str, Any]:
    return {"ttl": "8h", "prefix": "personal", **keys}


def test_the_path_block_is_read() -> None:
    section = built(method="vault_path", vault_path=path_block())

    assert section.vault_path is not None
    assert section.vault_path.ttl == "8h"
    assert section.vault_path.prefix == "personal"
    assert section.vault_path.vault is None
    assert not section.is_seen


def test_the_path_ttl_is_required_rather_than_defaulted() -> None:
    """The value at the path is a working password until Vault deletes it, and
    the ttl is when (decision #447). A default would be an unreviewed number."""
    with pytest.raises(ConfigError) as raised:
        build_delivery(document(method="vault_path", vault_path={"prefix": "personal"}))

    assert "needs a `ttl`" in str(raised.value)
    assert "delivery.vault_path.ttl" in str(raised.value)


@pytest.mark.parametrize("ttl", ["8", "8d", "0h", "eight hours"])
def test_a_path_ttl_that_is_not_a_duration_is_refused_at_load(ttl: str) -> None:
    with pytest.raises(ConfigError, match="is not a duration"):
        build_delivery(document(method="vault_path", vault_path=path_block(ttl=ttl)))


def test_the_prefix_is_required_because_the_policy_names_it() -> None:
    """The person's policy has to name the same prefix, so a default would be a
    path the file does not show."""
    with pytest.raises(ConfigError) as raised:
        build_delivery(document(method="vault_path", vault_path={"ttl": "8h"}))

    assert "needs a `prefix`" in str(raised.value)
    assert "delivery.vault_path.prefix" in str(raised.value)


def test_the_prefix_is_normalised() -> None:
    section = built(method="vault_path", vault_path=path_block(prefix="/acme//personal/"))

    assert section.vault_path is not None
    assert section.vault_path.prefix == "acme/personal"


@pytest.mark.parametrize("prefix", ["personal/../shared", "../personal", "personal/."])
def test_a_traversal_in_the_prefix_is_refused(prefix: str) -> None:
    """A `..` would put a live password outside the prefix the policy covers."""
    with pytest.raises(ConfigError, match="delivery.vault_path.prefix"):
        build_delivery(document(method="vault_path", vault_path=path_block(prefix=prefix)))


@pytest.mark.parametrize("prefix", ["team*", "per+sonal", "{{x}}"])
def test_a_prefix_with_a_vault_policy_wildcard_is_refused(prefix: str) -> None:
    """The person's policy repeats the prefix, and these characters are
    wildcards or a template there, so the policy would grant more than the tool
    writes."""
    with pytest.raises(ConfigError) as raised:
        build_delivery(document(method="vault_path", vault_path=path_block(prefix=prefix)))

    assert "delivery.vault_path.prefix" in str(raised.value)
    assert "Vault policy" in str(raised.value.hint or "")


def test_the_delivery_names_the_selected_method_s_store() -> None:
    wrapped = built(method="vault_wrapped", vault_wrapped={"ttl": "15m", "vault": "a"})
    path = built(method="vault_path", vault_path=path_block(vault="b"))

    assert (wrapped.vault, path.vault) == ("a", "b")
    assert built(method="manual", manual={"force_expire": True}).vault is None


def test_a_prefix_of_only_slashes_is_refused() -> None:
    with pytest.raises(ConfigError, match="needs a `prefix`"):
        build_delivery(document(method="vault_path", vault_path=path_block(prefix="//")))


def test_the_path_store_can_be_named_on_the_method() -> None:
    section = built(method="vault_path", vault_path=path_block(vault="vault-handover"))

    assert section.vault_path is not None
    assert section.vault_path.vault == "vault-handover"


def test_an_unknown_key_in_the_path_block_is_refused() -> None:
    with pytest.raises(ConfigError, match="delivery.vault_path"):
        build_delivery(document(method="vault_path", vault_path=path_block(identity_scoped=True)))


def test_the_path_block_is_not_read_when_another_method_is_selected() -> None:
    section = built(method="vault_wrapped", vault_wrapped={"ttl": "15m"}, vault_path={"tt1": 1})

    assert section.vault_path is None


def test_vault_path_is_served_by_this_build() -> None:
    """Through the loader, so `config.warnings` carries no W035 for it."""
    config = build_config(
        {"version": 1, "delivery": {"method": "vault_path", "vault_path": path_block()}}
    )

    assert not [warning for warning in config.warnings if warning.code == DELIVERY_UNSERVICEABLE]


# ---------------------------------------------------- `one_time_link:`'s keys ---


def link_block(**keys: Any) -> dict[str, Any]:
    return {"base_url": "https://yopass.example.com", "ttl": "1h", **keys}


def test_the_link_block_is_read() -> None:
    section = built(method="one_time_link", one_time_link=link_block())

    assert section.one_time_link is not None
    assert section.one_time_link.base_url == "https://yopass.example.com"
    assert section.one_time_link.ttl == "1h"
    assert section.one_time_link.split_key is False


def test_split_key_is_read() -> None:
    section = built(method="one_time_link", one_time_link=link_block(split_key=True))

    assert section.one_time_link is not None
    assert section.one_time_link.split_key is True


def test_split_key_must_be_a_boolean() -> None:
    with pytest.raises(ConfigError, match="delivery.one_time_link.split_key"):
        build_delivery(document(method="one_time_link", one_time_link=link_block(split_key="yes")))


@pytest.mark.parametrize("key", ["base_url", "ttl"])
def test_the_link_block_s_required_keys_are_required(key: str) -> None:
    block = link_block()
    del block[key]
    with pytest.raises(ConfigError) as raised:
        build_delivery(document(method="one_time_link", one_time_link=block))
    assert f"delivery.one_time_link.{key}" in str(raised.value)


def test_a_link_ttl_that_is_not_a_duration_is_refused_at_load() -> None:
    with pytest.raises(ConfigError, match="not a duration"):
        build_delivery(document(method="one_time_link", one_time_link=link_block(ttl="1d")))


@pytest.mark.parametrize(
    "url", ["http://yopass.example.com", "ftp://yopass.example.com", "yopass.example.com"]
)
def test_a_base_url_that_is_not_https_off_loopback_is_refused(url: str) -> None:
    """Decision #856's rule: the person's browser loads the page that reads the
    key from here."""
    with pytest.raises(ConfigError) as raised:
        build_delivery(document(method="one_time_link", one_time_link=link_block(base_url=url)))
    assert "delivery.one_time_link.base_url" in str(raised.value)
    assert "https://" in str(raised.value)


@pytest.mark.parametrize("url", ["http://127.0.0.1:1337", "http://localhost:1337"])
def test_plain_http_to_loopback_is_accepted(url: str) -> None:
    section = built(method="one_time_link", one_time_link=link_block(base_url=url))

    assert section.one_time_link is not None
    assert section.one_time_link.base_url == url


def test_a_trailing_slash_is_dropped() -> None:
    section = built(
        method="one_time_link", one_time_link=link_block(base_url="https://yopass.example.com/")
    )

    assert section.one_time_link is not None
    assert section.one_time_link.base_url == "https://yopass.example.com"


@pytest.mark.parametrize(
    "url", ["https://yopass.example.com/?a=b", "https://yopass.example.com/#/s/x"]
)
def test_a_base_url_with_a_query_or_a_fragment_is_refused(url: str) -> None:
    with pytest.raises(ConfigError, match="delivery.one_time_link.base_url"):
        build_delivery(document(method="one_time_link", one_time_link=link_block(base_url=url)))


@pytest.mark.parametrize("url", ["https://", "https:///yopass"])
def test_a_base_url_with_no_host_is_refused(url: str) -> None:
    with pytest.raises(ConfigError, match="names no host"):
        build_delivery(document(method="one_time_link", one_time_link=link_block(base_url=url)))


@pytest.mark.parametrize(
    "url",
    ["https://user:pw@yopass.example.com", "https://yopass.example.com@other.example.com"],
)
def test_a_base_url_with_a_user_or_a_password_is_refused_without_echoing_it(url: str) -> None:
    """Everything before the `#` goes into every link the person receives."""
    with pytest.raises(ConfigError, match="user name or a password") as raised:
        build_delivery(document(method="one_time_link", one_time_link=link_block(base_url=url)))
    assert "pw" not in str(raised.value)
    assert "other.example.com" not in str(raised.value)


def test_there_is_no_key_for_one_time() -> None:
    """The tool always asks for one-time (decision #445)."""
    with pytest.raises(ConfigError, match="one_time"):
        build_delivery(document(method="one_time_link", one_time_link=link_block(one_time=False)))


def test_the_link_block_is_not_read_when_another_method_is_selected() -> None:
    section = built(method="vault_wrapped", vault_wrapped={"ttl": "15m"}, one_time_link={"x": 1})

    assert section.one_time_link is None


def test_one_time_link_is_served_by_this_build() -> None:
    assert unserviceable(built(method="one_time_link", one_time_link=link_block())) is None


# ------------------------------------------------ `onepassword_share:`'s keys ---


def onepassword_block(**keys: Any) -> dict[str, Any]:
    return {
        "onepassword_vault": "acme-handover",
        "ttl": "24h",
        "token": {"env": "OP_SERVICE_ACCOUNT_TOKEN"},
        **keys,
    }


def test_the_onepassword_block_is_read() -> None:
    section = built(method="onepassword_share", onepassword_share=onepassword_block())

    settings = section.onepassword_share
    assert settings is not None
    assert settings.onepassword_vault == "acme-handover"
    assert settings.ttl == "24h"
    assert str(settings.token) == "env OP_SERVICE_ACCOUNT_TOKEN"
    # A 1Password vault is not a `vaults:` entry, so the store chain ignores it.
    assert section.vault is None


def test_the_vault_title_is_kept_as_written() -> None:
    """It is compared exactly with 1Password's titles, and a title may end in a
    space, so stripping it would make such a vault impossible to name."""
    block = onepassword_block(onepassword_vault="acme-handover ")
    section = built(method="onepassword_share", onepassword_share=block)

    assert section.onepassword_share is not None
    assert section.onepassword_share.onepassword_vault == "acme-handover "


@pytest.mark.parametrize("key", ["onepassword_vault", "ttl", "token"])
def test_the_onepassword_block_s_keys_are_required(key: str) -> None:
    block = onepassword_block()
    del block[key]
    with pytest.raises(ConfigError) as raised:
        build_delivery(document(method="onepassword_share", onepassword_share=block))
    assert f"delivery.onepassword_share.{key}" in str(raised.value)


@pytest.mark.parametrize("ttl", ["1h", "24h", "168h", "336h", "720h"])
def test_the_expiries_1password_offers_are_accepted(ttl: str) -> None:
    section = built(method="onepassword_share", onepassword_share=onepassword_block(ttl=ttl))

    assert section.onepassword_share is not None
    assert section.onepassword_share.ttl == ttl


@pytest.mark.parametrize("ttl", ["15m", "2h", "48h", "3600s"])
def test_an_expiry_1password_does_not_offer_is_refused_at_load(ttl: str) -> None:
    """1Password offers five expiries, so any other value would fail at the share,
    after a password had been drawn."""
    with pytest.raises(ConfigError, match="not an expiry 1Password offers") as raised:
        build_delivery(
            document(method="onepassword_share", onepassword_share=onepassword_block(ttl=ttl))
        )
    assert "`720h`" in str(raised.value)


def test_a_token_written_as_a_value_is_refused_without_echoing_it() -> None:
    """C9: the file names where the token is. It never holds the token."""
    block = onepassword_block(token="ops_acme_not_a_real_token")
    with pytest.raises(ConfigError, match="named, not written here") as raised:
        build_delivery(document(method="onepassword_share", onepassword_share=block))
    assert "ops_acme" not in str(raised.value)


def test_there_is_no_key_for_view_once() -> None:
    """The tool always asks for view-once (#446)."""
    block = onepassword_block(view_once=False)
    with pytest.raises(ConfigError, match="view_once"):
        build_delivery(document(method="onepassword_share", onepassword_share=block))


def test_the_onepassword_block_is_not_read_when_another_method_is_selected() -> None:
    section = built(method="vault_wrapped", vault_wrapped={"ttl": "15m"}, onepassword_share={})

    assert section.onepassword_share is None


def test_onepassword_share_still_warns_that_nothing_serves_it() -> None:
    """The keys are read, and the delivery is not built yet (TODO(#446)), so a
    clean parse must not read as a working delivery."""
    notice = unserviceable(built(method="onepassword_share", onepassword_share=onepassword_block()))

    assert notice is not None
    assert "not implemented in this build" in notice
