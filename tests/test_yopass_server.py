"""The Yopass side of `one_time_link` delivery (UC-2 §6.6), against the real container.

sopuli will encrypt a password with OpenPGP, send the ciphertext to Yopass as a
one-time secret, and hand over a link that carries the id and the key. Nothing
here runs sopuli's delivery code. These tests show that the server
`test/compose.yaml` runs behaves as the method relies on (decided in #445):

- `/config` reports the keys the plan-time checks read, with an unlicensed
  server's defaults;
- a one-time secret is returned once, and the next read answers 404;
- the status endpoint the web page calls first does not use up the read;
- the server refuses an expiration outside 1h, 1d and 1w, and a message that is
  not OpenPGP;
- whoever holds the id alone can delete the secret.

Plain HTTP calls, as the method will make them. Tier 1: it skips without the
container (`04-testing.md` §3).
"""

from __future__ import annotations

from typing import Any

import pytest

#: "not a password", encrypted by pysequoia 0.1.35 with the password
#: `sopuli-test-yopass-key`. The server checks only that it is OpenPGP armor.
CIPHERTEXT = """\
-----BEGIN PGP MESSAGE-----

wy4ECQMIkvISKrEWFDb/FQVnzE1tC9djj1zEyvY2B4UZecc4xQTGI2pFbK/W0/9H
0j8BSqM1YMQTtb1SKKv9l2i3zC/8iRiE7KckAEdDBAG/vCLy8QDtsDl176IIxjcg
lYEAaP1Es1mBLmQYFI+5dAM=
=dQ7+
-----END PGP MESSAGE-----
"""

ONE_HOUR = 3600


def _create(yopass_stack: Any, *, expiration: int = ONE_HOUR) -> Any:
    return yopass_stack.client.post(
        "/create/secret",
        json={"message": CIPHERTEXT, "expiration": expiration, "one_time": True},
    )


def _created_id(yopass_stack: Any) -> str:
    response = _create(yopass_stack)
    assert response.status_code == 200, response.text
    secret_id: str = response.json()["message"]
    return secret_id


def test_config_reports_the_keys_the_plan_time_checks_read(yopass_stack: Any) -> None:
    config = yopass_stack.client.get("/config").json()
    assert config["READ_ONLY"] is False
    assert config["REQUIRE_AUTH"] is False
    assert config["ALLOW_CUSTOM_EXPIRATION"] is False
    assert config["DISABLE_ONE_CLICK_LINK"] is False
    assert config["PREFETCH_SECRET"] is True
    # A server without --force-expiration or --public-url leaves the key out.
    assert "FORCE_EXPIRATION" not in config
    assert "PUBLIC_URL" not in config


def test_a_one_time_secret_is_returned_once(yopass_stack: Any) -> None:
    secret_id = _created_id(yopass_stack)

    first = yopass_stack.client.get(f"/secret/{secret_id}")
    assert first.status_code == 200
    assert first.json()["message"] == CIPHERTEXT

    assert yopass_stack.client.get(f"/secret/{secret_id}").status_code == 404


def test_the_status_check_does_not_use_up_the_read(yopass_stack: Any) -> None:
    secret_id = _created_id(yopass_stack)

    status = yopass_stack.client.get(f"/secret/{secret_id}/status")
    assert status.status_code == 200
    assert status.json()["oneTime"] is True

    assert yopass_stack.client.get(f"/secret/{secret_id}").status_code == 200


@pytest.mark.parametrize("seconds", [3600, 86400, 604800])
def test_the_default_server_accepts_an_hour_a_day_and_a_week(
    yopass_stack: Any, seconds: int
) -> None:
    response = _create(yopass_stack, expiration=seconds)
    assert response.status_code == 200
    # Removed at once, so a stack that runs for days does not collect secrets
    # that live for a week.
    yopass_stack.client.delete(f"/secret/{response.json()['message']}")


@pytest.mark.parametrize("seconds", [60, 7200])
def test_the_default_server_refuses_any_other_expiration(yopass_stack: Any, seconds: int) -> None:
    response = _create(yopass_stack, expiration=seconds)
    assert response.status_code == 400
    assert response.json()["message"] == "Invalid expiration specified"


def test_a_message_that_is_not_openpgp_is_refused(yopass_stack: Any) -> None:
    response = yopass_stack.client.post(
        "/create/secret",
        json={"message": "not a password", "expiration": ONE_HOUR, "one_time": True},
    )
    assert response.status_code == 400
    assert response.json()["message"] == "Message must be PGP encrypted"


def test_the_id_alone_deletes_the_secret(yopass_stack: Any) -> None:
    secret_id = _created_id(yopass_stack)

    assert yopass_stack.client.delete(f"/secret/{secret_id}").status_code == 204
    assert yopass_stack.client.get(f"/secret/{secret_id}").status_code == 404
