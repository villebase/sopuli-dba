"""`doctor`'s `keyring` section (#1417, decision 5).

Tier 0, against a fake `keyring` library, as `tests/test_os_keyring.py` is.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import jsonschema
import pytest

from sopuli import os_keyring
from sopuli.config.loading import build_config
from sopuli.keyring_survey import sources, survey
from sopuli.output.document import SCHEMA_VERSION
from sopuli.output.keyring_view import build, render

WINDOWS = "keyring.backends.Windows"

SCHEMAS = Path(__file__).parent.parent / "docs" / "schemas"
SCHEMA = SCHEMAS / f"sopuli-run-{SCHEMA_VERSION}.schema.json"


def backend(module: str = WINDOWS, **entries: str) -> Any:
    class Backend:
        priority = 5

        def __init__(self) -> None:
            self.entries = dict(entries)
            self.error: BaseException | None = None

        def get_password(self, service: str, user: str) -> str | None:
            if self.error is not None:
                raise self.error
            assert service == "sopuli"
            return self.entries.get(user)

    Backend.__module__ = module
    return Backend()


class Library:
    def __init__(self, found: Any) -> None:
        self.found = found

    def get_keyring(self) -> Any:
        return self.found


def config(**sections: Any) -> Any:
    return build_config({"version": 1, **sections})


VAULTS = {
    "vault-dev": {
        "type": "hashicorp",
        "addr": "https://vault-dev.example.com",
        "auth": {"method": "token", "token": {"keyring": "vault-dev"}},
    }
}

TARGET = {
    "name": "cdb-root-dev",
    "type": "oracle",
    "dsn": "db-dev.example.com:1521/CDBDEV.pdb.example.com",
    "admin": {"username": "C##SOPULI_SVC", "auth": {"method": "keyring", "entry": "cdb-root-dev"}},
}


def test_every_named_entry_is_found_with_its_key() -> None:
    found = sources(config(vaults=VAULTS, targets=[TARGET]))

    assert found == {
        "vault-dev": ["vaults.vault-dev.auth.token"],
        "cdb-root-dev": ["targets[0].admin.auth.entry"],
    }


def test_a_config_with_no_keyring_source_has_no_section() -> None:
    plain = {**TARGET, "admin": {"username": "C##SOPULI_SVC", "auth": {"method": "env"}}}

    assert survey(config(targets=[plain])) is None


def test_one_entry_named_by_a_target_set_is_listed_once() -> None:
    """Every generated target of a set shares the set's line."""
    target_set = {
        "type": "oracle",
        "for_each": {"env": {"dev": {"host": "db-dev"}, "test": {"host": "db-test"}}},
        "name": "cdb-{env}",
        "dsn": "{host}.example.com:1521/CDB.pdb.example.com",
        "admin": {"username": "C##SOPULI_SVC", "auth": {"method": "keyring", "entry": "cdb"}},
    }

    found = sources(config(target_sets={"cdbs": target_set}))

    assert found == {"cdb": ["target_sets.cdbs.admin.auth.entry"]}


def test_presence_is_reported_and_the_value_is_not(monkeypatch: pytest.MonkeyPatch) -> None:
    found = backend(**{"vault-dev": "hvs.example"})
    monkeypatch.setattr(os_keyring, "loader", lambda: Library(found))

    report = survey(config(vaults=VAULTS, targets=[TARGET]))

    assert report is not None
    section = build(report)
    assert section["backend"] == f"{WINDOWS}.Backend"
    assert [(one["entry"], one["present"]) for one in section["entries"]] == [
        ("vault-dev", True),
        ("cdb-root-dev", False),
    ]
    assert "hvs.example" not in json.dumps(section)
    assert "hvs.example" not in "\n".join(render(report))


def test_no_backend_leaves_every_entry_unread(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os_keyring, "loader", lambda: Library(backend("keyring.backends.fail")))

    report = survey(config(vaults=VAULTS))

    assert report is not None
    assert report.backend is None
    assert report.problem is not None
    assert report.problem.startswith("no OS keyring")
    assert [entry.present for entry in report.entries] == [None]


def test_a_failed_read_is_unread_with_its_reason(monkeypatch: pytest.MonkeyPatch) -> None:
    found = backend()
    found.error = OSError("the collection is locked")
    monkeypatch.setattr(os_keyring, "loader", lambda: Library(found))

    report = survey(config(vaults=VAULTS))

    assert report is not None
    assert report.entries[0].present is None
    assert report.entries[0].problem == "OSError: the collection is locked"
    assert "unread" in "\n".join(render(report))


def test_the_section_matches_the_run_schema(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os_keyring, "loader", lambda: Library(backend(**{"vault-dev": "x"})))
    report = survey(config(vaults=VAULTS, targets=[TARGET]))
    assert report is not None
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))

    jsonschema.validate(build(report), {"$defs": schema["$defs"], "$ref": "#/$defs/keyring_report"})
