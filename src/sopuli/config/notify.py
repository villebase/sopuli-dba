"""The `delivery.notify:` block: saying a password is ready (UC-2 §6.1, #442).

UC-2 §6.1 is the one binding rule of the whole delivery section:

    The channel that notifies may be low-trust. The channel that carries the
    secret may not. "Your new password is ready" may go anywhere; the password,
    or anything that retrieves it, may not.

**This module is where the second half is enforced**, and #442 asked for exactly
that — "the template can never reference the password itself, and that is
enforced, not documented." Enforced *here*, in the config layer, because the
alternative is finding out at send time, by which point a password has been drawn
and the run has something to lose.

**The enforcement is the closed set, not a list of forbidden words**, and the
difference is the whole reason this file is worth reading. A blocklist of
`password`, `wrap_token`, `item_link` would fail open on `{wrapping_token}`, on
`{pw}`, and on whatever the next method's credential gets called. So
:data:`PLACEHOLDERS` is closed and every other name is refused — and
:data:`NAMED_SECRETS` exists only to give a *better message* for the names
somebody would actually reach for. It adds no safety, and saying so keeps anybody
from later treating it as the guard and widening the allowed set to compensate.

**The tool does not author the message.** What is true of a hand-over differs by
path — a wrapping token is waiting in a vault, a `manual` password is with a DBA —
so a sentence the tool wrote would be wrong on one of them. The estate writes it,
which also means `notify:` needs no rule about which delivery methods it applies
to: all of them, with the estate's own words.
"""

from __future__ import annotations

from string import Formatter
from typing import Any

from sopuli.config.auth import read_material
from sopuli.config.errors import ConfigError, KeyPath
from sopuli.config.fields import choice, mapping, reject_unknown_keys, required_string
from sopuli.config.model import Notify, WebhookNotify

#: The methods this block may select. **One, and deliberately not padded out.**
#: `delivery.method` lists all six of UC-2 §6.2's values even where nobody has
#: written the code, because that section *defines* the set and an enum shaped by
#: which values had tickets would be a contract shaped by project bookkeeping.
#: Nothing defines a set of notify channels: §6.3 shows `webhook` and #442 says
#: `smtp` and `chat` get "their own issues if needed". Inventing two values to
#: make the enum look finished would publish a contract nobody has decided.
NOTIFY_METHODS = ("webhook",)

#: The methods this build can serve. Both halves of #442's split: part 1 reads and
#: refuses configuration, part 2 opens the socket. Until then a `notify:` block is
#: valid and inert, which `config validate` says out loud rather than leaving an
#: operator to conclude from silence that a message went out.
IMPLEMENTED: tuple[str, ...] = ()

WEBHOOK = "webhook"

#: The keys the block itself takes.
NOTIFY_KEYS = ("method", WEBHOOK)

#: `webhook:`'s own keys. Both required: a channel with no URL cannot post, and a
#: channel with no template has nothing to say, so neither is a default worth
#: guessing at.
WEBHOOK_KEYS = ("url", "template")

#: Every placeholder a template may use, and the closed set is the guard.
#:
#: All three are facts an estate's own audit log would hold anyway: **who** the
#: account is, **where** it lives, and **when** the hand-over stops working. None
#: retrieves anything, which is §6.1's test -- the rule is about reach rather than
#: about value.
#:
#: ``expires_at`` is worth having rather than minimal-by-reflex: "fetch this
#: within fifteen minutes" is the difference between a notification that helps and
#: one that makes somebody ask a DBA what the hurry is. It is empty for a method
#: with no expiry, which is a fact about the method rather than a missing value.
PLACEHOLDERS = ("account", "target", "expires_at")

#: Names that get a message about §6.1 instead of a message about spelling.
#:
#: **This is not the guard.** Every name outside :data:`PLACEHOLDERS` is refused
#: whether or not it appears here, and a reader who mistook this for the
#: enforcement would be one widening away from a hole. What it buys is that an
#: operator who wrote `{wrap_token}` -- a reasonable thing to want, and the exact
#: example #442 itself used before §6.1 settled the question -- is told *why* the
#: tool will not do it, rather than being told the word is misspelled.
NAMED_SECRETS = (
    "password",
    "secret",
    "token",
    "wrap_token",
    "wrapping_token",
    "item_link",
    "link",
    "credential",
)


def build_notify(raw: Any, *, at: KeyPath) -> Notify:
    """Normalise `delivery.notify:`.

    Called whichever delivery method is selected, which is the opposite of a
    method's own sub-block (`sopuli/config/delivery.py`): an unselected method's
    settings are never read because nothing consults them, and a notification is
    a property of the delivery as a whole.
    """
    block = mapping(raw, at=at)
    method = (
        choice(block["method"], allowed=NOTIFY_METHODS, at=at.key("method"), noun="notify method")
        if "method" in block
        else WEBHOOK
    )
    reject_unknown_keys(block, allowed=NOTIFY_KEYS, at=at)
    if method not in block:
        raise ConfigError(
            f"notify method {method!r} is selected and has no `{method}:` block",
            at=at.key(method),
            hint=(
                "a channel needs somewhere to post and something to say; write the block, "
                "or drop `notify:` if nothing should be sent"
            ),
        )
    return Notify(method=method, webhook=_build_webhook(block[WEBHOOK], at=at.key(WEBHOOK)))


def _build_webhook(raw: Any, *, at: KeyPath) -> WebhookNotify:
    """`webhook:`'s URL and message."""
    block = mapping(raw, at=at)
    reject_unknown_keys(block, allowed=WEBHOOK_KEYS, at=at)
    if "url" not in block:
        raise ConfigError(
            "`webhook` needs a `url`",
            at=at.key("url"),
            hint=(
                "and it is named rather than written: `{ env: SOPULI_NOTIFY_WEBHOOK }` or "
                "`{ file: /path }` (C9). A chat webhook URL carries its own credential, so "
                "a literal one here is a credential in a file people commit"
            ),
        )
    url = read_material(
        block["url"],
        at=at.key("url"),
        noun="a webhook URL",
        example="SOPULI_NOTIFY_WEBHOOK",
    )
    template = required_string(block, "template", at=at)
    check_template(template, at=at.key("template"))
    return WebhookNotify(url=url, template=template)


def check_template(template: str, *, at: KeyPath) -> None:
    """Refuse a template that cannot render, or that must not (§6.1).

    Two refusals out of one walk, because they are one condition read two ways: a
    name outside :data:`PLACEHOLDERS` cannot be filled, and *some* of those names
    cannot be filled for a reason worth saying out loud.

    ``{{`` and ``}}`` are literal braces, which is :class:`string.Formatter`'s own
    convention and is why the walk uses it rather than a regex. Without that an
    estate whose message contains a brace would meet a refusal about a placeholder
    it did not write.
    """
    for _, field, _, _ in Formatter().parse(template):
        if field is None:
            continue
        name = field.strip()
        if name in PLACEHOLDERS:
            continue
        if name.casefold() in NAMED_SECRETS:
            raise ConfigError(
                f"a notify template may not reference {{{name}}}",
                at=at,
                hint=(
                    "UC-2 6.1: the channel that notifies may be low-trust and the channel "
                    "that carries the secret may not -- and that covers the password *or "
                    "anything that retrieves it*, because the rule is about reach rather "
                    f"than value. Say that a password is ready and let the person fetch it: "
                    f"{_allowed()}"
                ),
            )
        raise ConfigError(
            f"unknown placeholder {{{name}}} in the notify template",
            at=at,
            hint=(
                f"{_allowed()}. An unknown name is refused rather than left empty, because a "
                "message with a hole in it is one somebody has to go and diagnose. Write "
                "`{{` for a literal brace"
            ),
        )


def unserviceable(notify: Notify | None) -> str | None:
    """Why a configured channel cannot send yet, or ``None`` when it could.

    E4/E5's shape, and the same argument `sopuli/config/delivery.py`'s twin makes:
    a block that validates clean reads as a channel that will send, and finding
    out otherwise once a password has changed is the failure that costs something.
    **No method is implemented yet** -- #442's part 1 reads and refuses
    configuration, and part 2 opens the socket.
    """
    if notify is None or notify.method in IMPLEMENTED:
        return None
    return (
        f"`delivery.notify.method: {notify.method}` is configured and is not implemented in "
        f"this build, so nothing will be sent when a password is delivered"
    )


def _allowed() -> str:
    """The placeholders a message may use, for a hint to list."""
    return "available: " + ", ".join(f"`{{{name}}}`" for name in PLACEHOLDERS)
