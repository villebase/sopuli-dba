"""`one_time_link` delivery through a Yopass server (UC-2 §6.6, decision #445).

Tier 0 for the rules: what the server's `/config` allows, when the link is
split, and what a receipt carries. The HTTP calls go to an `httpx.MockTransport`
that answers as Yopass 16.0.1 does. Tier 1 at the end: the real container
answers, and what the person's browser would fetch decrypts to the password.

The decryption here uses `pysequoia`, the library that encrypted. That the
Yopass page, which decrypts with OpenPGP.js, reads the same message is checked
in the real run, not here.
"""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from typing import Any

import pytest

from sopuli.delivery.yopass import (
    DEFAULT_EXPIRATIONS,
    ServerPolicy,
    Yopass,
    YopassNotInstalledError,
    YopassRefusedError,
    link_base,
    refusal,
    splits,
    ttl_seconds,
)
from sopuli.exit_codes import ExitCode
from sopuli.secrets import Secret
from sopuli.store.protocol import StoreError

httpx = pytest.importorskip("httpx")
pysequoia = pytest.importorskip("pysequoia")

PASSWORD = "Correct#Horse9Battery"
BASE = "https://yopass.example.com"
SECRET_ID = "32kGY7o9KOnhJojy3zHURw"
DATE = "Tue, 27 Oct 2026 17:59:17 GMT"

#: What Yopass 16.0.1's `/config` answers with its default flags, measured on
#: the tier-1 container. Only the keys this method reads.
DEFAULT_CONFIG: dict[str, Any] = {
    "READ_ONLY": False,
    "REQUIRE_AUTH": False,
    "ALLOW_CUSTOM_EXPIRATION": False,
    "MIN_EXPIRATION": 60,
    "MAX_EXPIRATION": 7776000,
    "PREFETCH_SECRET": True,
    "DISABLE_ONE_CLICK_LINK": False,
}


class Server:
    """A Yopass that records what it was sent."""

    def __init__(self, config: dict[str, Any] | None = None, **answers: Any) -> None:
        self.config = {**DEFAULT_CONFIG, **(config or {})}
        self.create_status = answers.get("create_status", 200)
        self.create_body = answers.get("create_body", {"message": SECRET_ID})
        self.date: str | None = answers.get("date", DATE)
        self.requests: list[Any] = []

    def handle(self, request: Any) -> Any:
        self.requests.append(request)
        if request.url.path == "/config":
            return httpx.Response(200, json=self.config)
        if request.url.path == "/create/secret":
            headers = {"Date": self.date} if self.date else {}
            return httpx.Response(self.create_status, json=self.create_body, headers=headers)
        return httpx.Response(404, json={"message": "not found"})

    def factory(self, base_url: str) -> Any:
        return httpx.Client(base_url=base_url, transport=httpx.MockTransport(self.handle))

    @property
    def created(self) -> dict[str, Any]:
        [create] = [one for one in self.requests if one.url.path == "/create/secret"]
        body: dict[str, Any] = json.loads(create.content)
        return body


def backend(server: Server, **settings: Any) -> Yopass:
    return Yopass(
        base_url=settings.pop("base_url", BASE),
        ttl=settings.pop("ttl", "1h"),
        split_key=settings.pop("split_key", False),
        client_factory=server.factory,
    )


def decrypt(armored: str, key: str) -> str:
    plain: bytes = pysequoia.decrypt(armored.encode("ascii"), passwords=[key]).bytes
    return plain.decode("utf-8")


# ------------------------------------------------------------- the rules ---


def test_a_ttl_is_sent_in_seconds() -> None:
    assert ttl_seconds("1h") == 3600
    assert ttl_seconds("24h") == 86400
    assert ttl_seconds("90m") == 5400
    assert ttl_seconds("45s") == 45


def test_a_default_server_takes_an_hour_a_day_and_a_week_only() -> None:
    policy = ServerPolicy.from_config(DEFAULT_CONFIG)
    assert [policy.accepts(seconds) for seconds in DEFAULT_EXPIRATIONS] == [True, True, True]
    assert not policy.accepts(7200)
    assert refusal(policy, ttl="2h") is not None
    assert refusal(policy, ttl="1h") is None


def test_a_server_with_custom_expiry_takes_its_range() -> None:
    policy = ServerPolicy.from_config({**DEFAULT_CONFIG, "ALLOW_CUSTOM_EXPIRATION": True})
    assert policy.accepts(60)
    assert policy.accepts(7200)
    assert not policy.accepts(59)
    assert not policy.accepts(7776001)


def test_a_forced_expiration_is_the_only_one() -> None:
    policy = ServerPolicy.from_config({**DEFAULT_CONFIG, "FORCE_EXPIRATION": 86400})
    assert policy.accepts(86400)
    assert not policy.accepts(3600)
    message = refusal(policy, ttl="1h")
    assert message is not None
    assert "FORCE_EXPIRATION" in message


@pytest.mark.parametrize(
    ("setting", "named"),
    [({"READ_ONLY": True}, "READ_ONLY"), ({"REQUIRE_AUTH": True}, "REQUIRE_AUTH")],
)
def test_a_server_that_cannot_create_is_refused_by_name(
    setting: dict[str, Any], named: str
) -> None:
    message = refusal(ServerPolicy.from_config({**DEFAULT_CONFIG, **setting}), ttl="1h")
    assert message is not None
    assert named in message


def test_a_public_url_over_plain_http_off_loopback_is_refused() -> None:
    """Decision #856's rule, applied to the address the link carries."""
    policy = ServerPolicy.from_config({**DEFAULT_CONFIG, "PUBLIC_URL": "http://yopass.example.com"})
    message = refusal(policy, ttl="1h")
    assert message is not None
    assert "PUBLIC_URL" in message


def test_the_public_url_is_the_link_base_when_the_server_reports_one() -> None:
    public = ServerPolicy.from_config({**DEFAULT_CONFIG, "PUBLIC_URL": "https://read.example.com/"})
    assert link_base(public, base_url=BASE) == "https://read.example.com"
    assert link_base(ServerPolicy.from_config(DEFAULT_CONFIG), base_url=BASE) == BASE


@pytest.mark.parametrize(
    ("config", "split_key", "expected"),
    [
        ({}, False, False),
        ({}, True, True),
        ({"DISABLE_ONE_CLICK_LINK": True}, False, True),
        ({"PREFETCH_SECRET": False}, False, True),
    ],
    ids=["default", "split_key", "one-click-link-disabled", "no-prefetch"],
)
def test_when_the_link_and_the_key_are_split(
    config: dict[str, Any], split_key: bool, expected: bool
) -> None:
    policy = ServerPolicy.from_config({**DEFAULT_CONFIG, **config})
    assert splits(policy, split_key=split_key) is expected


def test_a_missing_prefetch_key_is_yopass_s_default_true() -> None:
    assert ServerPolicy.from_config({}).prefetch_secret is True


# ------------------------------------------------------------- delivering ---


def test_the_link_holds_the_id_and_a_key_that_decrypts_the_password() -> None:
    server = Server()
    receipt = backend(server).deliver(Secret(PASSWORD), account="ACME_DEV_ALICE", target="t")

    assert receipt.token is not None
    link = receipt.token.reveal()
    prefix = f"{BASE}/#/s/{SECRET_ID}/"
    assert link.startswith(prefix)
    key = link.removeprefix(prefix)
    assert len(key) == 22
    assert decrypt(server.created["message"], key) == PASSWORD
    assert receipt.id == SECRET_ID
    assert receipt.link is None


def test_the_secret_is_one_time_with_the_ttl_in_seconds() -> None:
    server = Server()
    backend(server, ttl="24h").deliver(Secret(PASSWORD), account="a", target="t")

    assert server.created["one_time"] is True
    assert server.created["expiration"] == 86400


def test_only_ciphertext_leaves_the_process() -> None:
    server = Server()
    backend(server).deliver(Secret(PASSWORD), account="a", target="t")

    for request in server.requests:
        assert PASSWORD.encode() not in request.content
    assert server.created["message"].startswith("-----BEGIN PGP MESSAGE-----")


def test_split_mode_returns_the_key_as_the_token_and_the_link_without_it() -> None:
    server = Server()
    receipt = backend(server, split_key=True).deliver(Secret(PASSWORD), account="a", target="t")

    assert receipt.link == f"{BASE}/#/s/{SECRET_ID}"
    assert receipt.token is not None
    key = receipt.token.reveal()
    assert key not in receipt.link
    assert decrypt(server.created["message"], key) == PASSWORD


def test_the_server_splits_when_it_hides_the_one_click_link() -> None:
    server = Server(config={"DISABLE_ONE_CLICK_LINK": True})
    receipt = backend(server).deliver(Secret(PASSWORD), account="a", target="t")

    assert receipt.link == f"{BASE}/#/s/{SECRET_ID}"


def test_the_token_is_a_secret_and_the_receipt_does_not_print_it() -> None:
    server = Server()
    receipt = backend(server).deliver(Secret(PASSWORD), account="a", target="t")

    assert receipt.token is not None
    assert str(receipt.token) == "***"
    assert receipt.token.reveal() not in repr(receipt)


def test_the_record_names_the_secret_and_cannot_read_it() -> None:
    server = Server()
    receipt = backend(server).deliver(Secret(PASSWORD), account="a", target="t")

    handover = receipt.reported()
    assert handover.id == SECRET_ID
    assert handover.accessor is None
    assert receipt.location == SECRET_ID


def test_expiry_is_the_server_s_date_plus_the_ttl() -> None:
    server = Server()
    receipt = backend(server).deliver(Secret(PASSWORD), account="a", target="t")

    assert receipt.expires_at == datetime(2026, 10, 27, 18, 59, 17, tzinfo=UTC)


@pytest.mark.parametrize("date", [None, "not a date"])
def test_without_a_usable_date_the_expiry_is_unknown(date: str | None) -> None:
    server = Server(date=date)
    receipt = backend(server).deliver(Secret(PASSWORD), account="a", target="t")

    assert receipt.expires_at is None


# ----------------------------------------------------------------- refusing ---


def test_preflight_refuses_with_exit_5_naming_the_server_and_the_setting() -> None:
    server = Server(config={"READ_ONLY": True})
    with pytest.raises(YopassRefusedError) as raised:
        backend(server).preflight(account="a", target="t")

    assert raised.value.exit_code == ExitCode.UNSUPPORTED_CAPABILITY
    assert BASE in str(raised.value)
    assert "READ_ONLY" in str(raised.value)
    assert not [one for one in server.requests if one.url.path == "/create/secret"]


def test_preflight_refuses_a_ttl_the_server_would_refuse() -> None:
    with pytest.raises(YopassRefusedError, match="ttl of 2h"):
        backend(Server(), ttl="2h").preflight(account="a", target="t")


def test_config_is_read_once_for_every_target() -> None:
    server = Server()
    yopass = backend(server)
    yopass.preflight(account="a", target="t1")
    yopass.preflight(account="a", target="t2")
    yopass.deliver(Secret(PASSWORD), account="a", target="t1")

    assert [one.url.path for one in server.requests].count("/config") == 1


def test_a_refused_create_names_the_server_s_message() -> None:
    server = Server(create_status=400, create_body={"message": "Invalid expiration specified"})
    with pytest.raises(StoreError) as raised:
        backend(server).deliver(Secret(PASSWORD), account="a", target="t")

    assert "HTTP 400" in str(raised.value)
    assert "Invalid expiration specified" in str(raised.value)


@pytest.mark.parametrize("body", [{}, {"message": ""}, {"message": "a/b"}, ["x"]])
def test_an_answer_with_no_usable_id_is_a_failure_not_an_empty_receipt(body: Any) -> None:
    """The caller would go on to change the password, and nobody could fetch it."""
    with pytest.raises(StoreError, match="no usable secret id"):
        backend(Server(create_body=body)).deliver(Secret(PASSWORD), account="a", target="t")


def test_an_unreachable_server_is_a_store_error() -> None:
    def refuse(request: Any) -> Any:
        raise httpx.ConnectError("refused", request=request)

    yopass = Yopass(
        base_url=BASE,
        ttl="1h",
        client_factory=lambda url: httpx.Client(
            base_url=url, transport=httpx.MockTransport(refuse)
        ),
    )
    with pytest.raises(StoreError, match="could not be reached: ConnectError"):
        yopass.preflight(account="a", target="t")


def test_without_pysequoia_preflight_names_the_extra(monkeypatch: pytest.MonkeyPatch) -> None:
    """ADR-006 rule 2: exit 9 and the install line, before a password is drawn."""
    monkeypatch.setitem(sys.modules, "pysequoia", None)
    with pytest.raises(YopassNotInstalledError) as raised:
        backend(Server()).preflight(account="a", target="t")

    assert raised.value.exit_code == ExitCode.CONFIG_INVALID
    assert "sopuli-dba[yopass]" in str(raised.value.hint)


# ------------------------------------------------- tier 1: the real server ---


def test_the_real_server_returns_ciphertext_the_key_decrypts_once(yopass_stack: Any) -> None:
    yopass = Yopass(base_url=yopass_stack.url, ttl="1h")
    yopass.preflight(account="ACME_DEV_ALICE", target="tier1")
    receipt = yopass.deliver(Secret(PASSWORD), account="ACME_DEV_ALICE", target="tier1")

    assert receipt.token is not None
    key = receipt.token.reveal().rsplit("/", 1)[1]
    fetched = yopass_stack.client.get(f"/secret/{receipt.id}")
    assert fetched.status_code == 200
    assert decrypt(fetched.json()["message"], key) == PASSWORD
    assert yopass_stack.client.get(f"/secret/{receipt.id}").status_code == 404
    assert receipt.expires_at is not None


def test_the_real_server_s_config_refuses_a_ttl_it_would_refuse(yopass_stack: Any) -> None:
    with pytest.raises(YopassRefusedError, match="1h, 24h or 168h"):
        Yopass(base_url=yopass_stack.url, ttl="2h").preflight(account="a", target="t")
