"""`delivery.notify:` — the low-trust channel, and what it may not carry (#442).

Tier 0, and that is the point rather than a convenience. UC-2 §6.1's rule is the
one binding rule of the delivery section, #442 asked for it "enforced, not
documented", and enforcing it in the config layer is what makes it testable
without a socket — and what makes it arrive *before* a password has been drawn
rather than after.
"""

from __future__ import annotations

from typing import Any

import pytest

from sopuli.config.errors import ROOT, ConfigError
from sopuli.config.notify import (
    NAMED_SECRETS,
    NOTIFY_METHODS,
    PLACEHOLDERS,
    build_notify,
    unserviceable,
)

AT = ROOT.key("delivery").key("notify")

URL: dict[str, Any] = {"env": "SOPULI_NOTIFY_WEBHOOK"}
MESSAGE = "{account} on {target} has a new password waiting"


def built(**webhook: Any) -> Any:
    settings: dict[str, Any] = {"url": URL, "template": MESSAGE}
    settings.update(webhook)
    return build_notify({"method": "webhook", "webhook": settings}, at=AT)


def refused(**webhook: Any) -> ConfigError:
    with pytest.raises(ConfigError) as raised:
        built(**webhook)
    return raised.value


# ------------------------------------------------------------- the grammar ---


def test_the_url_is_named_rather_than_written() -> None:
    """C9, and here it is doing real work rather than being applied uniformly: a
    chat incoming-webhook URL embeds its own credential, so a literal one is a
    credential in a file people commit."""
    section = built()

    assert section.webhook is not None
    assert section.webhook.url.kind == "env"
    assert section.webhook.url.location == "SOPULI_NOTIFY_WEBHOOK"


def test_a_literal_url_is_refused_as_material_rather_than_as_a_type() -> None:
    """`read_material`'s own message, which says the thing worth saying: material
    is named here, not written. "Must be a mapping" would read as a complaint
    about YAML rather than about a credential in a repository."""
    error = refused(url="https://chat.example.com/hooks/T00/B00/XXXX")

    assert "named, not written" in str(error)


def test_the_method_defaults_to_the_only_one_there_is() -> None:
    assert build_notify({"webhook": {"url": URL, "template": MESSAGE}}, at=AT).method == "webhook"


def test_a_selected_method_with_no_block_is_refused() -> None:
    with pytest.raises(ConfigError, match="has no `webhook:` block"):
        build_notify({"method": "webhook"}, at=AT)


@pytest.mark.parametrize("missing", ["url", "template"])
def test_both_keys_are_required(missing: str) -> None:
    """Neither is a default worth guessing at: a channel with no URL cannot post,
    and one with no template has nothing to say."""
    settings = {"url": URL, "template": MESSAGE}
    del settings[missing]

    with pytest.raises(ConfigError):
        build_notify({"method": "webhook", "webhook": settings}, at=AT)


def test_the_enum_holds_only_what_is_decided() -> None:
    """The opposite call from `DELIVERY_METHODS`, and the difference is real.
    UC-2 §6.2 *defines* six delivery methods, so listing only the ones with
    tickets would be a contract shaped by project bookkeeping. Nothing defines a
    set of notify channels -- §6.3 shows one and #442 sends `smtp` and `chat` to
    their own issues -- so inventing two values would publish a contract nobody
    has decided."""
    assert NOTIFY_METHODS == ("webhook",)


# ------------------------------------------------------------ §6.1's rule ---


@pytest.mark.parametrize("name", NAMED_SECRETS)
def test_a_template_naming_a_secret_is_refused_with_the_reason(name: str) -> None:
    """The half #442 asked to be "enforced, not documented" -- and refused at
    *load*, because a refusal at send time arrives after a password has been
    drawn."""
    error = refused(template=f"your password is {{{name}}}")

    assert f"may not reference {{{name}}}" in str(error)
    assert "6.1" in str(error.hint)
    assert "reach rather than value" in str(error.hint)


def test_an_unknown_placeholder_is_refused_rather_than_left_empty() -> None:
    """#442's own words. A message with a hole in it is one somebody has to go and
    diagnose, and the hole appears in front of the person being notified."""
    error = refused(template="hello {nobody}")

    assert "unknown placeholder {nobody}" in str(error)
    assert "{account}" in str(error.hint)


def test_the_guard_is_the_closed_set_and_not_the_list_of_names() -> None:
    """**The test that matters most in this file.** A blocklist would fail open on
    the next credential's name, so the enforcement has to be that everything
    outside `PLACEHOLDERS` is refused -- with `NAMED_SECRETS` only improving the
    message. Asserted with names nobody has listed, which is precisely the case a
    blocklist gets wrong."""
    for name in ("wrapping_token_v2", "pw", "otp", "retrieval_url", "unwrap_me"):
        assert name not in NAMED_SECRETS
        with pytest.raises(ConfigError, match="unknown placeholder"):
            built(template=f"take this: {{{name}}}")


def test_every_allowed_placeholder_renders_nothing_that_retrieves() -> None:
    """The closed set, asserted as a set rather than trusted to review: three
    facts about *who, where and when*, and nothing that fetches anything. A fourth
    is a decision, and this is where it gets argued for."""
    assert PLACEHOLDERS == ("account", "target", "expires_at")


def test_the_allowed_placeholders_are_accepted() -> None:
    assert built(template="{account}/{target} until {expires_at}") is not None


def test_a_literal_brace_is_not_a_placeholder() -> None:
    """`{{` is `str.format`'s own convention, and supporting it is why the walk
    uses `string.Formatter` rather than a regex: without it an estate whose
    message contains a brace meets a refusal about a placeholder it did not
    write."""
    assert built(template="{{ok}} for {account}") is not None


# ------------------------------------------------------- nothing sends yet ---


def test_a_configured_channel_says_it_cannot_send_yet() -> None:
    """E4/E5's shape. A block that validates clean reads as a channel that will
    send, and #442's part 2 is what opens the socket -- so until then the warning
    is what keeps silence from being read as a message going out."""
    notice = unserviceable(built())

    assert notice is not None
    assert "not implemented in this build" in notice
    assert "nothing will be sent" in notice


def test_no_notify_block_warns_about_nothing() -> None:
    assert unserviceable(None) is None
