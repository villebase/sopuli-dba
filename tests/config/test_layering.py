"""Several `--config` files, merged into one document (§9).

The rule is "deep merge for maps, replace for lists", and the asymmetry is the
whole subject. A mapping is a set of named settings and a later file adding one
must not delete the rest; a list is a whole answer, and merging two would produce
an estate that appears in no file -- a bad way to find out what the tool is about
to touch (invariant 5).

Merging happens on raw documents, after each file has been checked on its own.
That ordering is what keeps "this file is unreadable / unparseable / has no
version" pointing at a filename.
"""

from __future__ import annotations

import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from sopuli.config.errors import ConfigError
from sopuli.config.loading import load_config_from, load_documents, merge_documents, merge_layers

BASE = """
version: 1
vaults:
  vault-dev: { type: hashicorp, addr: "https://dev.example.com", kv_version: 2 }
targets:
  - name: cdb-root-dev
    type: oracle
    dsn: db-dev.example.com:1521/CDBDEV.pdb.example.com
"""


# ------------------------------------------------------------ merge rules ---


def test_a_later_document_wins_key_by_key() -> None:
    merged = merge_documents([{"version": 1, "a": "first"}, {"a": "second", "b": "new"}])

    assert merged == {"version": 1, "a": "second", "b": "new"}


def test_mappings_merge_rather_than_replace() -> None:
    """The reason the rule is not simply last-one-wins: an overlay that sets
    `vaults.vault-dev.addr` must not delete `vaults.vault-prod`."""
    merged = merge_documents(
        [
            {"vaults": {"dev": {"type": "hashicorp", "kv_version": 2}, "prod": {"type": "oci"}}},
            {"vaults": {"dev": {"addr": "https://elsewhere.example.com"}}},
        ]
    )

    assert merged["vaults"]["prod"] == {"type": "oci"}
    assert merged["vaults"]["dev"] == {
        "type": "hashicorp",
        "kv_version": 2,
        "addr": "https://elsewhere.example.com",
    }


def test_mappings_merge_at_every_depth() -> None:
    merged = merge_documents(
        [
            {"target_sets": {"appdb": {"for_each": {"env": {"dev": {"host": "a.example.com"}}}}}},
            {"target_sets": {"appdb": {"for_each": {"env": {"qa": {"host": "b.example.com"}}}}}},
        ]
    )

    assert sorted(merged["target_sets"]["appdb"]["for_each"]["env"]) == ["dev", "qa"]


def test_lists_are_replaced_whole() -> None:
    """Concatenating would build an estate that appears in no file, and
    `accounts:` is the list where that matters most (invariant 5)."""
    merged = merge_documents([{"accounts": ["acme_web_user"]}, {"accounts": ["acme_api_user"]}])

    assert merged["accounts"] == ["acme_api_user"]


def test_a_scalar_replaces_a_mapping_and_the_other_way_round() -> None:
    """Not a merge case at all: the types disagree, so the later file is simply
    the answer. Merging them would invent a third shape."""
    assert merge_documents([{"a": {"b": 1}}, {"a": "plain"}])["a"] == "plain"
    assert merge_documents([{"a": "plain"}, {"a": {"b": 1}}])["a"] == {"b": 1}


def test_merging_does_not_mutate_the_documents_it_was_given() -> None:
    """The loader hands these straight from the parser; a merge that edited them
    in place would make the second of two identical runs behave differently."""
    first: dict[str, Any] = {"vaults": {"dev": {"type": "hashicorp"}}}
    second: dict[str, Any] = {"vaults": {"dev": {"addr": "https://v.example.com"}}}

    merge_documents([first, second])

    assert first == {"vaults": {"dev": {"type": "hashicorp"}}}
    assert second == {"vaults": {"dev": {"addr": "https://v.example.com"}}}


def test_merging_nothing_is_an_empty_document() -> None:
    assert merge_documents([]) == {}


# -------------------------------------------------- the ratchet (#855) ---


def _safety(block: dict[str, Any]) -> dict[str, Any]:
    return {"defaults": {"safety": block}}


def test_a_later_file_cannot_relax_a_safety_setting() -> None:
    """Invariant 10 between files: each setting merges by its own shape."""
    merged, warnings = merge_layers(
        [
            _safety(
                {
                    "readonly": True,
                    "max_targets": 5,
                    "confirm_environments": ["prod"],
                    "delivery": {"allowed_methods": ["vault_wrapped"]},
                }
            ),
            _safety(
                {
                    "readonly": False,
                    "max_targets": 500,
                    "confirm_environments": ["dev"],
                    "delivery": {"allowed_methods": ["manual", "vault_wrapped"]},
                }
            ),
        ],
        names=["base.yaml", "local.yaml"],
    )

    assert merged["defaults"]["safety"] == {
        "readonly": True,
        "max_targets": 5,
        "confirm_environments": ["dev", "prod"],
        "delivery": {"allowed_methods": ["vault_wrapped"]},
    }
    # A union defeats nobody, so three of the four warn.
    assert [warning.code for warning in warnings] == ["SOPULI-W039"] * 3
    assert warnings[0].message == (
        "local.yaml asked for false; defaults.safety.readonly stays true (base.yaml) "
        "-- safety settings only ratchet toward safe"
    )


def test_a_later_file_can_tighten_a_safety_setting_without_a_warning() -> None:
    merged, warnings = merge_layers(
        [
            _safety({"readonly": False, "max_targets": 50}),
            _safety({"readonly": True, "max_targets": 5}),
        ]
    )

    assert merged["defaults"]["safety"] == {"readonly": True, "max_targets": 5}
    assert warnings == ()


def test_a_tie_names_the_earliest_file() -> None:
    """The file to edit, as "ties resolve downward" does between layers."""
    _, warnings = merge_layers(
        [_safety({"max_targets": 5}), _safety({"max_targets": 5}), _safety({"max_targets": 9})],
        names=["a.yaml", "b.yaml", "c.yaml"],
    )

    (warning,) = warnings
    assert warning.message.startswith(
        "c.yaml asked for 9; defaults.safety.max_targets stays 5 (a.yaml)"
    )


def test_disjoint_delivery_methods_between_files_are_refused() -> None:
    """The issue's own example: nothing could be delivered under both files."""
    with pytest.raises(ConfigError) as caught:
        merge_layers(
            [
                _safety({"delivery": {"allowed_methods": ["vault_wrapped"]}}),
                _safety({"delivery": {"allowed_methods": ["manual"]}}),
            ],
            names=["base.yaml", "local.yaml"],
        )

    assert "local.yaml allows manual; base.yaml allows vault_wrapped" in str(caught.value)
    # The key, so a profile's block is told from `defaults`.
    assert str(caught.value.at) == "defaults.safety.delivery.allowed_methods"


def test_break_expired_ratchets_toward_false() -> None:
    """Its safe value is `false`: it grants permission rather than withholding it."""
    merged, warnings = merge_layers(
        [
            {"profiles": {"ci": {"locking": {"break_expired": False}}}},
            {"profiles": {"ci": {"locking": {"break_expired": True}}}},
        ]
    )

    assert merged["profiles"]["ci"]["locking"]["break_expired"] is False
    assert len(warnings) == 1


@pytest.mark.parametrize(
    "owner",
    [
        ("profiles", "ci", "safety"),
        ("groups", "prod-dbs", "safety"),
        ("target_sets", "appdb", "safety"),
        ("target_sets", "appdb", "overrides", "appdb-prod", "safety"),
    ],
)
def test_every_mapping_that_holds_a_safety_block_ratchets(owner: tuple[str, ...]) -> None:
    def nested(value: bool) -> dict[str, Any]:
        node: dict[str, Any] = {"readonly": value}
        for key in reversed(owner):
            node = {key: node}
        return node

    merged, warnings = merge_layers([nested(True), nested(False)])

    node = merged
    for key in owner:
        node = node[key]
    assert node == {"readonly": True}
    assert len(warnings) == 1


@pytest.mark.parametrize(
    "owner",
    [
        ("vaults", "vault-dev"),
        ("defaults", "vaults", "vault-dev"),
        ("profiles", "ci", "vaults", "vault-dev"),
    ],
)
def test_tls_verify_ratchets_in_every_vault_entry(owner: tuple[str, ...]) -> None:
    def nested(value: bool) -> dict[str, Any]:
        node: dict[str, Any] = {"tls": {"verify": value}}
        for key in reversed(owner):
            node = {key: node}
        return node

    merged, warnings = merge_layers([nested(True), nested(False)])

    node = merged
    for key in owner:
        node = node[key]
    assert node == {"tls": {"verify": True}}
    assert len(warnings) == 1


def test_a_targets_list_is_still_replaced_whole() -> None:
    """A list is a whole answer (§9), safety blocks included. A floor a layered
    file must not lower belongs in `defaults.safety` or a group."""
    merged, warnings = merge_layers(
        [
            {"targets": [{"name": "appdb-prod", "safety": {"readonly": True}}]},
            {"targets": [{"name": "appdb-prod", "safety": {"readonly": False}}]},
        ]
    )

    assert merged["targets"] == [{"name": "appdb-prod", "safety": {"readonly": False}}]
    assert warnings == ()


def test_a_key_named_safety_elsewhere_is_not_ratcheted() -> None:
    """A `for_each` value is free text, and only a declared owner holds a block."""
    merged, warnings = merge_layers(
        [
            {"target_sets": {"appdb": {"for_each": {"env": {"safety": {"readonly": True}}}}}},
            {"target_sets": {"appdb": {"for_each": {"env": {"safety": {"readonly": False}}}}}},
        ]
    )

    assert merged["target_sets"]["appdb"]["for_each"]["env"]["safety"] == {"readonly": False}
    assert warnings == ()


@pytest.mark.parametrize("order", ["earlier", "later"])
def test_a_value_of_the_wrong_type_is_refused_with_its_file(order: str) -> None:
    """Validation sees only the merged value, so a wrong one in an earlier file
    would never be reported, and the ratchet would have nothing to compare."""
    wrong, right = _safety({"readonly": "yes"}), _safety({"readonly": False})
    documents = [wrong, right] if order == "earlier" else [right, wrong]
    names = ["floor.yaml", "local.yaml"]

    with pytest.raises(ConfigError) as caught:
        merge_layers(documents, names=names)

    label = names[documents.index(wrong)]
    assert caught.value.message == f"must be true or false, not a string, in {label}"
    assert str(caught.value.at) == "defaults.safety.readonly"


@pytest.mark.parametrize(
    "replacement",
    [
        {"target_sets": {"appdb": {"overrides": None}}},
        {"target_sets": {"appdb": "plain"}},
    ],
)
def test_a_later_file_cannot_erase_a_block_that_holds_a_safety_key(
    replacement: dict[str, Any],
) -> None:
    """Only one file wrote the key itself, so without this the setting would go
    with no ratchet and no warning."""
    floor = {
        "target_sets": {"appdb": {"overrides": {"appdb-prod": {"safety": {"readonly": True}}}}}
    }

    with pytest.raises(ConfigError) as caught:
        merge_layers([floor, replacement], names=["floor.yaml", "local.yaml"])

    assert caught.value.message.startswith("local.yaml replaces `target_sets.appdb")
    assert (
        "`target_sets.appdb.overrides.appdb-prod.safety.readonly` under it was set in floor.yaml"
    ) in caught.value.message


def test_ratcheting_across_three_files_does_not_mutate_the_last() -> None:
    """The last file's block is the one the result is built on. It is copied,
    so setting the safe value in the result leaves the caller's document alone."""
    first = _safety({"readonly": True})
    middle = {"defaults": {"policy": "app-standard"}}
    last = _safety({"readonly": False})

    merged, _ = merge_layers([first, middle, last])

    assert merged["defaults"]["safety"] == {"readonly": True}
    assert last == _safety({"readonly": False})


def test_ratcheting_does_not_mutate_the_documents_it_was_given() -> None:
    first = _safety({"readonly": True})
    second = _safety({"readonly": False})

    merge_layers([first, second])

    assert first == _safety({"readonly": True})
    assert second == _safety({"readonly": False})


# ------------------------------------------------------------- the loader ---


def test_layered_files_load_as_one_config(tmp_path: Path, write_at: WriteAt) -> None:
    base = write_at(tmp_path / "base.yaml", BASE)
    overlay = write_at(tmp_path / "overlay.yaml", "version: 1\nvaults:\n  extra: { type: file }\n")

    config = load_config_from([base, overlay])

    assert [vault.name for vault in config.vaults] == ["vault-dev", "extra"]
    assert config.expanded_targets[0].name == "cdb-root-dev"


def test_an_overlay_can_redirect_a_setting_without_restating_the_rest(
    tmp_path: Path, write_at: WriteAt
) -> None:
    """P3's rationale for layering at all: a shared config committed to a repo,
    redirected per execution context without editing it."""
    base = write_at(tmp_path / "base.yaml", BASE)
    overlay = write_at(
        tmp_path / "overlay.yaml",
        'version: 1\nvaults:\n  vault-dev: { addr: "https://ci.example.com" }\n',
    )

    (vault,) = load_config_from([base, overlay]).vaults

    assert vault.addr == "https://ci.example.com"
    assert vault.type == "hashicorp"
    assert vault.kv_version == 2


def test_a_defeated_relaxation_reaches_the_config_as_a_warning(
    tmp_path: Path, write_at: WriteAt
) -> None:
    base = write_at(tmp_path / "base.yaml", BASE + "defaults:\n  safety: { readonly: true }\n")
    local = write_at(
        tmp_path / "local.yaml", "version: 1\ndefaults:\n  safety: { readonly: false }\n"
    )

    config = load_config_from([base, local])

    assert config.defaults.safety is not None
    assert config.defaults.safety.readonly is True
    (warning,) = [one for one in config.warnings if one.code == "SOPULI-W039"]
    assert warning.message.startswith(f"{local} asked for false;")
    assert f"({base})" in warning.message


def test_every_layer_is_checked_as_a_file_first(tmp_path: Path, write_at: WriteAt) -> None:
    """A parse error in the second file names the second file. Merging first
    would leave a message about a document that exists on no disk."""
    good = write_at(tmp_path / "base.yaml", BASE)
    broken = write_at(tmp_path / "broken.yaml", "version: 1\nvaults: [unclosed\n")

    with pytest.raises(ConfigError) as caught:
        load_documents([good, broken])

    assert str(broken) in str(caught.value)


def test_every_layer_declares_its_own_version(tmp_path: Path, write_at: WriteAt) -> None:
    """§9a requires it because a file with no version cannot be migrated later,
    and that does not weaken when the file is one of several."""
    base = write_at(tmp_path / "base.yaml", BASE)
    fragment = write_at(tmp_path / "fragment.yaml", "vaults:\n  extra: { type: file }\n")

    with pytest.raises(ConfigError) as caught:
        load_config_from([base, fragment])

    rendered = str(caught.value)
    assert "does not declare a version" in rendered
    assert str(fragment) in rendered


def test_a_validation_error_over_layers_keeps_its_key_path(
    tmp_path: Path, write_at: WriteAt
) -> None:
    """With one file an error names it. With several it cannot: the value may
    have been written in one and overridden in another, and naming either would
    be a guess. The key path is what locates it instead.
    """
    base = write_at(tmp_path / "base.yaml", BASE)
    overlay = write_at(tmp_path / "overlay.yaml", "version: 1\nvaults:\n  extra: { type: nope }\n")

    with pytest.raises(ConfigError) as caught:
        load_config_from([base, overlay])

    rendered = str(caught.value)
    assert "vaults.extra.type" in rendered
    assert str(base) not in rendered


def test_one_layer_still_names_its_file(tmp_path: Path, write_at: WriteAt) -> None:
    """The common case must not lose anything to the general one."""
    only = write_at(tmp_path / "only.yaml", "version: 1\nvaults:\n  extra: { type: nope }\n")

    with pytest.raises(ConfigError) as caught:
        load_config_from([only])

    assert str(only) in str(caught.value)


def test_loading_no_files_at_all_is_refused() -> None:
    """Unreachable through the CLI, since discovery raises first. Held here so
    that a future caller assembling paths itself cannot get an empty config
    object out of an empty list."""
    with pytest.raises(ConfigError) as caught:
        load_config_from([])

    assert "no config file to load" in str(caught.value)


WriteAt = Callable[[Path, str], Path]


@pytest.fixture
def write_at() -> WriteAt:
    """Write a config file at an exact path, with permissions P4 accepts."""

    def write(path: Path, text: str) -> Path:
        path.write_text(text, encoding="utf-8")
        if sys.platform != "win32":
            path.chmod(0o600)
        return path

    return write
