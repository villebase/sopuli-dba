"""Asking ESO to refresh an ExternalSecret after a promotion (C18).

Tier 0: kubectl is replaced by a recorder, so these check the command line the
tool builds and how it reads each way kubectl can fail.
"""

from __future__ import annotations

import subprocess
from datetime import UTC, datetime

from sopuli.config.model import ExternalSecretRef
from sopuli.kubernetes_refresh import TIMEOUT_SECONDS, refresh_all

NOW = datetime(2026, 11, 25, 12, 0, tzinfo=UTC)
PROD = ExternalSecretRef("prod-cluster", "acme", "acme-db")
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


def found(_: str) -> str:
    return "/usr/local/bin/kubectl"


def test_the_command_names_the_context_and_namespace_as_one_argument_each() -> None:
    kubectl = Kubectl()

    (result,) = refresh_all([PROD], now=NOW, runner=kubectl, which=found)

    assert result.ok
    assert kubectl.calls == [
        [
            "/usr/local/bin/kubectl",
            "--context=prod-cluster",
            "--namespace=acme",
            "annotate",
            "externalsecret",
            "acme-db",
            f"force-sync={int(NOW.timestamp())}",
            "--overwrite",
        ]
    ]


def test_each_external_secret_is_refreshed_once_in_a_stable_order() -> None:
    kubectl = Kubectl()

    results = refresh_all([TEST, PROD, TEST, PROD], now=NOW, runner=kubectl, which=found)

    assert [result.external_secret for result in results] == [PROD, TEST]
    assert len(kubectl.calls) == 2


def test_nothing_to_refresh_does_not_look_for_kubectl() -> None:
    def never(_: str) -> str:
        raise AssertionError("kubectl was looked for")

    assert refresh_all([], now=NOW, runner=Kubectl(), which=never) == []


def test_kubectl_missing_fails_each_refresh_and_runs_nothing() -> None:
    kubectl = Kubectl()

    results = refresh_all([PROD, TEST], now=NOW, runner=kubectl, which=lambda _: None)

    assert kubectl.calls == []
    assert all(not result.ok for result in results)
    assert all("not found on PATH" in (result.error or "") for result in results)


def test_a_non_zero_exit_reports_kubectls_last_line() -> None:
    stderr = (
        'Warning: something\nError from server (NotFound): externalsecrets "acme-db" not found\n'
    )
    kubectl = Kubectl(returncode=1, stderr=stderr)

    (result,) = refresh_all([PROD], now=NOW, runner=kubectl, which=found)

    assert result.error == (
        'kubectl exited 1: Error from server (NotFound): externalsecrets "acme-db" not found'
    )


def test_a_timeout_is_a_failure_that_says_how_long() -> None:
    kubectl = Kubectl(raises=subprocess.TimeoutExpired(["kubectl"], TIMEOUT_SECONDS))

    (result,) = refresh_all([PROD], now=NOW, runner=kubectl, which=found)

    assert result.error == f"kubectl did not finish in {TIMEOUT_SECONDS} seconds"


def test_kubectl_that_cannot_start_is_a_failure() -> None:
    kubectl = Kubectl(raises=PermissionError(13, "Permission denied"))

    (result,) = refresh_all([PROD], now=NOW, runner=kubectl, which=found)

    assert result.error == "kubectl could not be started: Permission denied"


def test_one_failure_does_not_stop_the_next_refresh() -> None:
    answers = iter([1, 0])

    def runner(argv: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(argv, next(answers), "", "error: no context")

    results = refresh_all([PROD, TEST], now=NOW, runner=runner, which=found)

    assert [result.ok for result in results] == [False, True]
