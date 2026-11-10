"""The ``file`` store's entry point, which the registry names (#1372, #1415).

:func:`connect` is the contract :func:`sopuli.store.registry.connect` states
for every backend. The store itself is :class:`._store.FileStore`.

**Not for production** (#1415, decision 5): every run that opens a file store
says so with ``SOPULI-W069``, and ``doctor`` prints a line saying so. The
warning is added where the run opens its stores, in ``cli._stores_for``.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

# The client, imported here so that a machine without it fails at this
# module's import, which the registry turns into SOPULI-20001 and the install
# line (ADR-006 rule 2). The store's parts import it inside their functions,
# so without this a missing `pyrage` would surface as a bare
# ModuleNotFoundError from the middle of a run.
import pyrage  # noqa: F401

from sopuli.config.model import Vault
from sopuli.store.file._store import FileStore, open_store


def connect(vault: Vault, *, env: Mapping[str, str], token_file: Path | None = None) -> FileStore:
    """The file store ``vault`` declares, with its identity read.

    ``token_file`` is ``--vault-token-file``, a HashiCorp token. A file store
    is opened with its age identity, so it ignores the token, as an OCI store
    does.
    """
    return open_store(vault, env=env)


__all__ = ["FileStore", "connect"]
