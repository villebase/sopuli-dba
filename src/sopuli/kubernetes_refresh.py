"""Asking External Secrets Operator to read a promoted document at once (C18).

After ``creds apply`` or ``creds rotate`` promotes documents, or rolls one back,
each distinct ExternalSecret that an application's ``kubernetes:`` block names
for them is annotated with ``force-sync``. ESO reads the vault again when that
annotation changes, rather than at its next ``refreshInterval``.

The tool runs ``kubectl`` with the operator's own kubeconfig. It holds no
cluster credential, and no secret is on the command line: the annotation is a
timestamp. ``kubectl`` is a prerequisite only for a config that has the block.

The refresh runs once, after every promotion of the run, so an ExternalSecret
that reads two documents is not refreshed between them. A failure is a warning
(``SOPULI-W078``), not a failed run: the databases and the vault are right, and
ESO catches up at its next refresh.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime

from sopuli.config.model import ExternalSecretRef

#: How long one ``kubectl`` call may take. A kubeconfig whose login needs a
#: person, such as an OIDC or cloud exec plugin, cannot prompt (stdin is
#: closed), so it fails or hangs, and this bounds the hang. It is also the
#: only limit on a cluster that does not answer: kubectl's own
#: ``--request-timeout`` is not passed, because kubectl would then exit with
#: an error of its own, and a context that timed out could not be told apart
#: from one that refused, so the rest of its ExternalSecrets would each wait
#: again.
TIMEOUT_SECONDS = 30

#: Variables kubectl and its credential plugins never receive: the tool's own
#: settings and credentials. The rest of the environment is passed, because a
#: kubeconfig's exec plugin, such as a cloud CLI, reads its own variables from
#: it, as it would in the operator's shell.
_WITHHELD_PREFIXES = ("SOPULI_",)
_WITHHELD = frozenset({"VAULT_TOKEN"})

#: Kept short in a message: kubectl's own error is the useful part.
_DETAIL_MAX = 300


@dataclass(frozen=True)
class Refresh:
    """What happened to one ExternalSecret.

    ``error`` is ``None`` on success. ``attempted`` says whether kubectl was
    run for it at all: not where kubectl was not found, could not start, or an
    earlier call on the same context timed out.
    """

    external_secret: ExternalSecretRef
    error: str | None = None
    attempted: bool = True

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


def find_kubectl(path: str | None = None) -> str | None:
    """``kubectl`` from an absolute ``PATH`` entry, and never from anywhere else.

    Not :func:`shutil.which`: on Windows it looks in the current directory
    before ``PATH``, so a ``kubectl.exe`` in a checked-out repository would run
    with the operator's kubeconfig. An empty or relative ``PATH`` entry is
    skipped for the same reason.
    """
    entries = (os.environ.get("PATH", "") if path is None else path).split(os.pathsep)
    if sys.platform == "win32":
        extensions = [ext for ext in os.environ.get("PATHEXT", ".EXE").split(os.pathsep) if ext]
        names = [f"kubectl{ext.lower()}" for ext in extensions]
    else:
        names = ["kubectl"]
    for entry in entries:
        if not entry or not os.path.isabs(entry):
            continue
        for name in names:
            candidate = os.path.join(entry, name)
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                return candidate
    return None


def refresh_all(
    refs: Iterable[ExternalSecretRef],
    *,
    now: datetime,
    runner: Runner | None = None,
    find: Callable[[], str | None] = find_kubectl,
) -> list[Refresh]:
    """Annotate each ExternalSecret once, in a stable order.

    After a call times out, the others on the same context are not tried: the
    cluster did not answer, and each would wait out the same limit.
    """
    distinct = sorted(set(refs), key=lambda ref: (ref.context, ref.namespace, ref.name))
    if not distinct:
        return []
    kubectl = find()
    if kubectl is None:
        return [Refresh(ref, "kubectl was not found on PATH", attempted=False) for ref in distinct]
    # Microseconds, so two runs in one second still change the annotation, and
    # ESO sees each one.
    stamp = now.strftime("%Y%m%dT%H%M%S.%fZ")
    run = runner if runner is not None else _run
    results: list[Refresh] = []
    timed_out: set[str] = set()
    for ref in distinct:
        if ref.context in timed_out:
            results.append(
                Refresh(
                    ref,
                    "not tried: an earlier call on this context did not finish in "
                    f"{TIMEOUT_SECONDS} seconds",
                    attempted=False,
                )
            )
            continue
        result = _refresh_one(run, command(kubectl, ref, stamp), ref)
        if result.error is not None and result.error.startswith("kubectl did not finish"):
            timed_out.add(ref.context)
        results.append(result)
    return results


def _refresh_one(run: Runner, argv: list[str], ref: ExternalSecretRef) -> Refresh:
    try:
        completed = run(argv)
    except subprocess.TimeoutExpired:
        return Refresh(ref, f"kubectl did not finish in {TIMEOUT_SECONDS} seconds")
    except OSError as error:
        return Refresh(
            ref, f"kubectl could not be started: {error.strerror or error}", attempted=False
        )
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


def kubectl_environment(environ: Mapping[str, str]) -> dict[str, str]:
    """``environ`` without the tool's own settings and credentials.

    A credential in a variable of another name, such as an admin password a
    target names with ``password_env``, is passed: the operator's shell would
    pass it to kubectl too, and the tool cannot tell it from a cloud CLI's own
    setting.
    """
    return {
        name: value
        for name, value in environ.items()
        if name.upper() not in _WITHHELD and not name.upper().startswith(_WITHHELD_PREFIXES)
    }


def _run(argv: list[str]) -> subprocess.CompletedProcess[str]:
    """One kubectl call: no shell, stdin closed, bounded in time.

    Output goes to temporary files, not pipes. An exec credential plugin that
    kubectl starts can outlive kubectl and keep a pipe open, and then reading
    the pipe after the timeout would wait for the plugin. A file has no such
    wait, so the limit holds.
    """
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        process = subprocess.run(  # noqa: S603 - a fixed argument list, no shell
            argv,
            stdin=subprocess.DEVNULL,
            stdout=out,
            stderr=err,
            env=kubectl_environment(os.environ),
            timeout=TIMEOUT_SECONDS,
            check=False,
        )
        err.seek(0)
        stderr = err.read().decode("utf-8", errors="replace")
    return subprocess.CompletedProcess(argv, process.returncode, "", stderr)
