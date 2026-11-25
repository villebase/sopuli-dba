"""Asking External Secrets Operator to read a promoted document at once (C18).

After ``creds apply`` or ``creds rotate`` promotes documents, each distinct
ExternalSecret that an application's ``kubernetes:`` block names for them is
annotated with ``force-sync``. ESO reads the vault again when that annotation
changes, rather than at its next ``refreshInterval``.

The tool runs ``kubectl`` with the operator's own kubeconfig. It holds no
cluster credential, and no secret is on the command line: the annotation is a
timestamp. ``kubectl`` is a prerequisite only for a config that has the block.

The refresh runs once, after every promotion of the run, so an ExternalSecret
that reads two documents is not refreshed between them. A failure is a warning
(``SOPULI-W078``), not a failed run: the databases and the vault are right, and
ESO catches up at its next refresh.
"""

from __future__ import annotations

import shutil
import subprocess
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import datetime

from sopuli.config.model import ExternalSecretRef

#: How long one ``kubectl`` call may take. A kubeconfig whose login needs a
#: person, such as an OIDC or cloud exec plugin, cannot prompt (stdin is
#: closed), so it fails or hangs, and this bounds the hang.
TIMEOUT_SECONDS = 30

#: Kept short in a message: kubectl's own error is the useful part.
_DETAIL_MAX = 300


@dataclass(frozen=True)
class Refresh:
    """What happened to one ExternalSecret. ``error`` is ``None`` on success."""

    external_secret: ExternalSecretRef
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None


Runner = Callable[[list[str]], "subprocess.CompletedProcess[str]"]


def describe(ref: ExternalSecretRef) -> str:
    """``namespace/name`` on ``context``, as messages and results name it."""
    return f"ExternalSecret {ref.namespace}/{ref.name} on context {ref.context}"


def command(kubectl: str, ref: ExternalSecretRef, stamp: str) -> list[str]:
    """The argument list. ``--context=`` and ``--namespace=`` are written with
    ``=`` so a value can never be read as another option."""
    return [
        kubectl,
        f"--context={ref.context}",
        f"--namespace={ref.namespace}",
        "annotate",
        "externalsecret",
        ref.name,
        f"force-sync={stamp}",
        "--overwrite",
    ]


def refresh_all(
    refs: Iterable[ExternalSecretRef],
    *,
    now: datetime,
    runner: Runner | None = None,
    which: Callable[[str], str | None] = shutil.which,
) -> list[Refresh]:
    """Annotate each ExternalSecret once, in a stable order."""
    distinct = sorted(set(refs), key=lambda ref: (ref.context, ref.namespace, ref.name))
    if not distinct:
        return []
    kubectl = which("kubectl")
    if kubectl is None:
        return [
            Refresh(ref, "kubectl was not found on PATH, so ESO was not asked to refresh")
            for ref in distinct
        ]
    stamp = str(int(now.timestamp()))
    run = runner if runner is not None else _run
    return [_refresh_one(run, command(kubectl, ref, stamp), ref) for ref in distinct]


def _refresh_one(run: Runner, argv: list[str], ref: ExternalSecretRef) -> Refresh:
    try:
        completed = run(argv)
    except subprocess.TimeoutExpired:
        return Refresh(ref, f"kubectl did not finish in {TIMEOUT_SECONDS} seconds")
    except OSError as error:
        return Refresh(ref, f"kubectl could not be started: {error.strerror or error}")
    if completed.returncode != 0:
        return Refresh(ref, f"kubectl exited {completed.returncode}: {_detail(completed)}")
    return Refresh(ref)


def _detail(completed: subprocess.CompletedProcess[str]) -> str:
    """kubectl's last line of error output, which is where it says what failed."""
    lines = [line.strip() for line in (completed.stderr or "").splitlines() if line.strip()]
    if not lines:
        return "no error output"
    last = lines[-1]
    return last if len(last) <= _DETAIL_MAX else last[: _DETAIL_MAX - 1] + "…"


def _run(argv: list[str]) -> subprocess.CompletedProcess[str]:
    """One kubectl call: no shell, stdin closed, output captured, bounded in time."""
    return subprocess.run(  # noqa: S603 - a fixed argument list, no shell
        argv,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=TIMEOUT_SECONDS,
        check=False,
    )
