"""Posting a notification, with the HTTP call mocked (#442). Tier 0.

#442's acceptance asks for exactly this: "unit-tested with no network (the HTTP call
is mocked), including the refusal of a template that references the secret", and the
base install still shown to open no sockets. The template refusal is
`tests/config/test_notify.py`'s, because it happens at load; the install shape is
`tests/store/test_install_shape.py`'s, which now derives its exemptions from
`NOTIFIERS` as well.

What is left here is what a channel does with an answer, and the answers worth
having are the unhappy ones.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from sopuli.notify import webhook
from sopuli.notify.registry import (
    NOTIFIER_NOT_INSTALLED,
    NOTIFIERS,
    Notifier,
    NotifierNotInstalledError,
    resolve,
)
from sopuli.secrets import Secret
from sopuli.store import StoreError

#: A chat webhook's URL *is* its credential -- the path segments are the token --
#: which is C9's reason for the config key being a MaterialRef and this being a
#: `Secret`. Synthetic, for the reason #518's review gave about the wrapping token.
URL = Secret("https://chat.example.com/hooks/T00000/B00000/EXAMPLEEXAMPLEEXAMPLE")
MESSAGE = "acme_dev_alice on free-pdb has a new password waiting"


class Posted:
    """Records the one call, and answers however a test says."""

    def __init__(self, status: int = 204) -> None:
        self.status = status
        self.calls: list[tuple[str, Any, Any]] = []

    def __call__(self, url: str, *, json: Any = None, timeout: Any = None) -> httpx.Response:
        self.calls.append((url, json, timeout))
        return httpx.Response(status_code=self.status)


@pytest.fixture
def posted(monkeypatch: pytest.MonkeyPatch) -> Posted:
    recorder = Posted()
    monkeypatch.setattr("sopuli.notify.webhook.httpx.post", recorder)
    return recorder


# ------------------------------------------------------------ what it sends ---


def test_the_message_is_posted_to_the_url_with_a_deadline(posted: Posted) -> None:
    """A deadline on every request, which is ADR-005's reason for `httpx` and #83's
    for caring: UC-2 §3.3's advisory lock is still held while this runs, and a hung
    request is a lock nobody else can take."""
    webhook.send(URL, MESSAGE)

    url, body, timeout = posted.calls[0]
    assert url == URL.reveal()
    assert body == {"text": MESSAGE}
    assert timeout == webhook.TIMEOUT_S


def test_nothing_but_the_message_is_posted(posted: Posted) -> None:
    """Asserted as a closed set, so a field added later has to be argued for here.
    The body carries what §6.1 permits and nothing else -- there is no account
    object, no target, no metadata that would let a low-trust channel accumulate an
    estate's shape."""
    webhook.send(URL, MESSAGE)

    _, body, _ = posted.calls[0]
    assert set(body) == {"text"}


# ------------------------------------------------ and what it does not leak ---


def test_a_transport_failure_does_not_repeat_the_url(monkeypatch: pytest.MonkeyPatch) -> None:
    """**The test this file exists for.** `httpx` puts the URL in the message of
    several of its errors, and the URL is the credential -- so a warning built from
    `str(error)` would put a live chat webhook into `diagnostics[]`, a run document
    and whatever ingests them. The class name is carried instead."""

    def refuse(url: str, **rest: Any) -> httpx.Response:
        raise httpx.ConnectError(f"failed to connect to {url}")

    monkeypatch.setattr("sopuli.notify.webhook.httpx.post", refuse)

    with pytest.raises(StoreError) as raised:
        webhook.send(URL, MESSAGE)

    assert "could not be reached: ConnectError" in str(raised.value)
    assert "chat.example.com" not in str(raised.value)
    assert "EXAMPLEEXAMPLE" not in str(raised.value)
    assert raised.value.hint is not None
    assert "EXAMPLEEXAMPLE" not in raised.value.hint


@pytest.mark.parametrize("status", [400, 403, 404, 410, 500, 503])
def test_a_refused_post_is_reported_with_its_status(posted: Posted, status: int) -> None:
    """The status is what distinguishes a revoked webhook from a service having a
    bad day, and those send an operator to different places.

    Phrased as a cause rather than a sentence, which running it is what settled:
    `SOPULI-W026` says what happened and appends this, and the first draft produced
    "the notification could not be sent ... : the notification could not be sent:
    ConnectError"."""
    posted.status = status

    with pytest.raises(StoreError) as raised:
        webhook.send(URL, MESSAGE)

    assert f"refused it: HTTP {status}" in str(raised.value)
    assert "chat.example.com" not in str(raised.value)


@pytest.mark.parametrize("status", [200, 201, 202, 204])
def test_any_2xx_is_success(posted: Posted, status: int) -> None:
    """Chat services answer 200 with a body and 204 without; neither is a problem,
    and a channel that insisted on one of them would fail against half of them."""
    posted.status = status

    webhook.send(URL, MESSAGE)


# --------------------------------------------------- the extra, and E4 / E5 ---


def test_the_channel_resolves_to_its_module() -> None:
    assert resolve("webhook") is webhook


def test_a_missing_client_says_what_to_install(monkeypatch: pytest.MonkeyPatch) -> None:
    """E5: exit 9 and `category: config`, because a configured channel this machine
    cannot serve is a mismatch between a file and an install rather than a
    capability the tool lacks. The code is third in the series `SOPULI-20001` and
    `SOPULI-20002` started, for the same condition a third time."""

    def absent(name: str) -> Any:
        raise ModuleNotFoundError(f"No module named {'httpx'!r}", name="httpx")

    monkeypatch.setattr("sopuli.notify.registry.importlib.import_module", absent)

    with pytest.raises(NotifierNotInstalledError) as raised:
        resolve("webhook")

    assert "sopuli-dba[notify]" in str(raised.value.hint)
    assert raised.value.code == NOTIFIER_NOT_INSTALLED
    assert raised.value.category == "config"


def test_a_typo_in_our_own_import_path_re_raises_instead(monkeypatch: pytest.MonkeyPatch) -> None:
    """`missing_kind`'s whole reason for existing, and the first draft of the test
    above got it backwards -- it pointed `module` at a `sopuli.notify.*` that does
    not exist and expected an install line.

    That would be the expensive mistake ADR-006 names: sending somebody to `pip`
    forever over a typo of ours. Three failures arrive as one exception and only one
    of them has an install line as its answer, so this one propagates."""
    monkeypatch.setitem(
        NOTIFIERS,
        "webhook",
        Notifier(
            module="sopuli.notify.nothing_here", extra="notify", provides=frozenset({"httpx"})
        ),
    )

    with pytest.raises(ModuleNotFoundError):
        resolve("webhook")


def test_the_registered_channel_declares_the_client_it_needs() -> None:
    """`provides` is what lets a `ModuleNotFoundError` be read as "not installed"
    rather than as "we have a typo", and it is what `config validate` asks without
    importing anything."""
    assert NOTIFIERS["webhook"].provides == frozenset({"httpx"})
    assert NOTIFIERS["webhook"].extra == "notify"
    assert NOTIFIERS["webhook"].available is True
