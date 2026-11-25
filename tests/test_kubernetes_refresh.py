"""Asking ESO to refresh an ExternalSecret after a promotion (C18).

Tier 0: kubectl is replaced by a recorder, so these check the command line the
tool builds and how it reads each way kubectl can fail.
"""

from __future__ import annotations

import os
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

from sopuli.config.model import ExternalSecretRef
from sopuli.kubernetes_refresh import (
    TIMEOUT_SECONDS,
    find_kubectl,
    kubectl_environment,
    refresh_all,
)

NOW = datetime(2026, 11, 25, 12, 0, 0, 123456, tzinfo=UTC)
STAMP = "20261125T120000.123456Z"
PROD = ExternalSecretRef("prod-cluster", "acme", "acme-db")
PROD_BETA = ExternalSecretRef("prod-cluster", "acme-beta", "acme-db")
TEST = ExternalSecretRef("test-cluster", "acme-alpha", "acme-db")


class Kubectl:
    """Records each argument list, and answers with ``returncode`` and ``stderr``."""

    def __init__(self, returncode: int = 0, stderr: str = "", raises: Exception | None = None):
        self.calls: list[list[str]] = []
        self.returncode = returncode
        self.stderr = stderr
        self.raises = raises

    def __call__(self, argv: list[str]) -> subprocess.CompletedProcess[str]:
        self.calls.append(argv)
        if self.raises is not None:
            raise self.raises
        return subprocess.CompletedProcess(argv, self.returncode, "", self.stderr)


def found() -> str:
    return "/usr/local/bin/kubectl"


def test_the_command_names_the_context_and_namespace_as_one_argument_each() -> None:
    kubectl = Kubectl()

    (result,) = refresh_all([PROD], now=NOW, runner=kubectl, find=found)

    assert result.ok
    assert result.attempted
    assert kubectl.calls == [
        [
            "/usr/local/bin/kubectl",
            "--context=prod-cluster",
            "--namespace=acme",
            "annotate",
            "externalsecret",
            "acme-db",
            f"force-sync={STAMP}",
            "--overwrite",
        ]
    ]


def test_each_external_secret_is_refreshed_once_in_a_stable_order() -> None:
    kubectl = Kubectl()

    results = refresh_all([TEST, PROD, TEST, PROD], now=NOW, runner=kubectl, find=found)

    assert [result.external_secret for result in results] == [PROD, TEST]
    assert len(kubectl.calls) == 2


def test_nothing_to_refresh_does_not_look_for_kubectl() -> None:
    def never() -> str:
        raise AssertionError("kubectl was looked for")

    assert refresh_all([], now=NOW, runner=Kubectl(), find=never) == []


def test_kubectl_missing_fails_each_refresh_and_runs_nothing() -> None:
    kubectl = Kubectl()

    results = refresh_all([PROD, TEST], now=NOW, runner=kubectl, find=lambda: None)

    assert kubectl.calls == []
    assert all(not result.ok and not result.attempted for result in results)
    assert all("not found on PATH" in (result.error or "") for result in results)


def test_a_non_zero_exit_reports_kubectls_last_line() -> None:
    stderr = (
        'Warning: something\nError from server (NotFound): externalsecrets "acme-db" not found\n'
    )
    kubectl = Kubectl(returncode=1, stderr=stderr)

    (result,) = refresh_all([PROD], now=NOW, runner=kubectl, find=found)

    assert result.attempted
    assert result.error == (
        'kubectl exited 1: Error from server (NotFound): externalsecrets "acme-db" not found'
    )


def test_a_timeout_is_a_failure_that_says_how_long() -> None:
    kubectl = Kubectl(raises=subprocess.TimeoutExpired(["kubectl"], TIMEOUT_SECONDS))

    (result,) = refresh_all([PROD], now=NOW, runner=kubectl, find=found)

    assert result.error == f"kubectl did not finish in {TIMEOUT_SECONDS} seconds"


def test_after_a_timeout_the_same_context_is_not_tried_again() -> None:
    """An unreachable cluster costs one timeout, not one per ExternalSecret."""
    calls: list[str] = []

    def runner(argv: list[str]) -> subprocess.CompletedProcess[str]:
        calls.append(argv[1])
        if argv[1] == "--context=prod-cluster":
            raise subprocess.TimeoutExpired(argv, TIMEOUT_SECONDS)
        return subprocess.CompletedProcess(argv, 0, "", "")

    results = refresh_all([PROD, PROD_BETA, TEST], now=NOW, runner=runner, find=found)

    assert calls == ["--context=prod-cluster", "--context=test-cluster"]
    assert [(result.ok, result.attempted) for result in results] == [
        (False, True),
        (False, False),
        (True, True),
    ]
    assert "not tried" in (results[1].error or "")


def test_kubectl_gets_the_environment_without_the_tools_own_credentials() -> None:
    environ = {
        "PATH": "/usr/bin",
        "KUBECONFIG": "/home/dba/.kube/config",
        "AWS_PROFILE": "prod",
        "SOPULI_VAULT_TOKEN": "hvs.secret",
        "SOPULI_DB_ADMIN_PASSWORD": "secret",
        "VAULT_TOKEN": "hvs.secret",
    }

    assert kubectl_environment(environ) == {
        "PATH": "/usr/bin",
        "KUBECONFIG": "/home/dba/.kube/config",
        "AWS_PROFILE": "prod",
    }


def test_kubectl_that_cannot_start_is_a_failure() -> None:
    kubectl = Kubectl(raises=PermissionError(13, "Permission denied"))

    (result,) = refresh_all([PROD], now=NOW, runner=kubectl, find=found)

    assert result.error == "kubectl could not be started: Permission denied"
    assert not result.attempted


def test_one_failure_does_not_stop_the_next_refresh() -> None:
    answers = iter([1, 0])

    def runner(argv: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(argv, next(answers), "", "error: no context")

    results = refresh_all([PROD, TEST], now=NOW, runner=runner, find=found)

    assert [result.ok for result in results] == [False, True]


# ------------------------------------------------------------ finding kubectl ---


def _kubectl_in(directory: Path) -> Path:
    name = "kubectl.exe" if sys.platform == "win32" else "kubectl"
    path = directory / name
    path.write_text("")
    path.chmod(0o755)
    return path


def test_kubectl_is_found_in_an_absolute_path_entry(tmp_path: Path) -> None:
    planted = _kubectl_in(tmp_path)

    assert find_kubectl(str(tmp_path)) == str(planted)


def test_the_current_directory_and_relative_entries_are_never_searched(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A kubectl in the working directory must not run in place of PATH's."""
    _kubectl_in(tmp_path)
    monkeypatch.chdir(tmp_path)

    assert find_kubectl(os.pathsep.join(["", ".", "relative/bin"])) is None
