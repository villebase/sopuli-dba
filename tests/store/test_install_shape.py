"""Rule 3: nothing in base opens a socket (ADR-006, ``04-testing.md`` §3).

**This is the only test in the suite that can see the boundary break.** The
developer environment is `sopuli-dba[all]`, so every other test passes whether or
not base is clean -- which is exactly how a convenient module-level ``import
httpx`` gets in and is discovered by a user rather than by CI.

What is asserted is ADR-006's own testable form of the property: in a base
install none of the clients the backends reach with is importable. Rather than
depending on how this machine happens to be installed, the clients are **blocked
at the import system** and every sopuli module outside a backend is imported
against that. The result is the same statement and it holds in either
environment.

The standard library's ``urllib`` and ``http.client`` are deliberately not
blocked. They are importable in every Python and no packaging rule changes that,
so the rule covers them by intent rather than by assertion: base code does not
reach the network, whatever it would reach it with.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

#: The clients the extras install, as ADR-006 names them: ``httpx``, the OCI SDK,
#: ``python-oracledb``, ``psycopg``, PyMySQL, PyNaCl, ``pysequoia`` and 1Password's SDK. Kept
#: here as a literal rather than derived from ``BACKENDS`` on purpose: this test is the check
#: *on* that table, and a check that reads its expectation out of the thing it is checking
#: would pass an empty table. The CI install-shape job's base cell lists the same names.
CLIENTS = (
    "httpx",
    "nacl",
    "oci",
    "onepassword",
    "oracledb",
    "psycopg",
    "pymysql",
    "pysequoia",
)

#: The driver packages exempt as a whole, for their own `provides` only. The
#: maintainer chose this for MariaDB, whose `password.py` imports PyNaCl at
#: module scope (#1296, option A). A literal, so another driver's package is
#: not exempted by being registered.
PACKAGE_EXEMPT = ("sopuli.driver.mariadb",)

#: A store the tool cannot reach from this interpreter, declared anyway. §3a's
#: promise in four lines: the file means the same thing on a machine that has the
#: backend and on one that does not.
CONFIG_NAMING_A_BACKEND = """version: 1
vaults:
  vault-prod:
    type: hashicorp
    mount: secret
"""

#: Run in a subprocess because the assertion is about what importing does from a
#: clean interpreter. This one is already several hundred sopuli modules deep by
#: the time it runs, so `sys.modules` here answers a different question.
PROBE = '''
import importlib
import json
import pkgutil
import sys

BLOCKED = {blocked!r}
#: The clients the module being imported may reach: a driver package's own
#: `provides`, while the second pass imports it, and nothing otherwise.
ALLOWED = set()


class Blocker:
    """Refuse the vendor clients the way a base install refuses them."""

    def find_spec(self, fullname, path=None, target=None):
        top = fullname.split(".")[0]
        if top in BLOCKED and top not in ALLOWED:
            raise ModuleNotFoundError(f"blocked by the install-shape test: {{fullname}}",
                                      name=fullname)
        return None


for name in list(sys.modules):
    if name.split(".")[0] in BLOCKED:
        del sys.modules[name]
sys.meta_path.insert(0, Blocker())

import sopuli
from sopuli.driver.registry import DRIVERS
from sopuli.notify.registry import NOTIFIERS
from sopuli.store.registry import BACKENDS

backends = (
    tuple(backend.module for backend in BACKENDS.values())
    + tuple(driver.module for driver in DRIVERS.values())
    + tuple(notifier.module for notifier in NOTIFIERS.values())
)

# The tests' own modules, planted into a sopuli package's path to show the
# walk refuses what it should. Empty for every other run.
for package, directory in {planted!r}.items():
    importlib.import_module(package).__path__.append(directory)

#: A driver package whose modules may import the clients its own extra
#: installs, and the clients. A module of it that the first pass reaches
#: through another module, as `sopuli.cli` reaches `roles`, has already
#: imported with every client blocked. It may not import another driver's
#: client (#1296). Every other driver's modules outside its session import
#: with all clients blocked.
packages = {{
    driver.module.rsplit(".", 1)[0]: frozenset(driver.provides)
    for driver in DRIVERS.values()
    if driver.module.rsplit(".", 1)[0] in {package_exempt!r}
}}


def _package(name):
    for package in packages:
        if name == package or name.startswith(package + "."):
            return package
    return None


imported = []
in_packages = []
for found in pkgutil.walk_packages(sopuli.__path__, "sopuli."):
    # Rule 1 puts the client import *inside* the backend module, so a backend is
    # the one place importing a client is correct. Everything else must not.
    # Drivers are backends for this purpose: `sopuli.driver.oracle` is
    # where `oracledb` may be imported, and nowhere above it. Notify channels are
    # too (E7): `sopuli.notify.webhook` is where `httpx` may be imported for
    # a notification. Listed from the registries rather than by hand, so a second
    # driver or channel inherits the exemption instead of failing this on the day
    # it is added.
    if any(found.name == module or found.name.startswith(module + ".") for module in backends):
        continue
    if _package(found.name) is not None and found.name not in packages:
        in_packages.append(found.name)
        continue
    importlib.import_module(found.name)
    imported.append(found.name)

# The second pass, after every other module has imported with all clients
# blocked: so a module outside a driver package that imports one of its
# modules has already failed the first pass.
before = set(sys.modules)
for name in in_packages:
    package = _package(name)
    ALLOWED.update(packages[package])
    loaded = set(sys.modules)
    try:
        importlib.import_module(name)
    except ModuleNotFoundError as error:
        # The driver's own client is not installed here, so the rest of the
        # module was not run and is not counted. Installing it is the extra's
        # business, not this rule's.
        if (error.name or "").split(".")[0] not in ALLOWED:
            raise
        continue
    finally:
        ALLOWED.clear()
    # The allowance is for the package's own modules. A sopuli module outside
    # it that loaded here, such as another driver's session, loaded with it.
    outside = sorted(
        new for new in set(sys.modules) - loaded
        if new.startswith("sopuli.") and _package(new) != package
    )
    if outside:
        raise AssertionError(
            f"{{name}} loaded {{', '.join(outside)}} with {{package}}'s clients allowed"
        )
    imported.append(name)
# Unload what the second pass loaded, the clients with it, so the command
# below imports each one again with every client blocked.
for name in set(sys.modules) - before:
    del sys.modules[name]
for name in list(sys.modules):
    if name.split(".")[0] in BLOCKED:
        del sys.modules[name]

# What the *walk* pulled in, before the command runs. `walk_packages` imports a
# package in order to enumerate it, so a backend whose client import survives the
# blocker lands in sys.modules here -- which says nothing about the command. Store
# backends never showed up only because httpx is blocked and their import fails;
# a driver package with no vendor import at module scope imports perfectly well.
# The question this test asks is what the *command* loaded, so the baseline is
# subtracted rather than assumed empty.
preloaded = {{name for name in sys.modules if name in backends}}

from click.testing import CliRunner

from sopuli.cli import cli

result = CliRunner().invoke(cli, ["--config", {config!r}, "config", "validate"])
print(json.dumps({{
    "modules": len(imported),
    "exit_code": result.exit_code,
    "output": result.output,
    "loaded_backends": [
        name for name in sys.modules if name in backends and name not in preloaded
    ],
}}))
'''


def _run(
    tmp_path: Path, config: str, planted: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    path = tmp_path / "sopuli.yaml"
    path.write_text(config, encoding="utf-8")
    if sys.platform != "win32":
        path.chmod(0o600)

    script = PROBE.format(
        blocked=set(CLIENTS),
        package_exempt=set(PACKAGE_EXEMPT),
        planted=planted or {},
        config=str(path),
    )
    return subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        check=False,
    )


def _probe(tmp_path: Path, config: str) -> dict[str, object]:
    finished = _run(tmp_path, config)
    assert finished.returncode == 0, finished.stderr
    return dict(json.loads(finished.stdout.strip().splitlines()[-1]))


def _plant(tmp_path: Path, package: str, name: str, source: str) -> dict[str, str]:
    """A module ``package.name`` holding ``source``, for the walk to find."""
    directory = tmp_path / "planted"
    directory.mkdir()
    (directory / f"{name}.py").write_text(source, encoding="utf-8")
    return {package: str(directory)}


@pytest.mark.parametrize(
    ("package", "name", "source", "refusal"),
    [
        # A shared module may import no client, not even MariaDB's.
        ("sopuli.driver.mysql_family", "zz_planted", "import nacl\n", "blocked by"),
        # The package's allowance is its own clients only.
        ("sopuli.driver.mariadb", "zz_planted", "import oracledb\n", "blocked by"),
        # Nor does it reach another driver's session, which has its own client.
        (
            "sopuli.driver.mariadb",
            "zz_planted",
            "import sopuli.driver.mysql.session\n",
            "loaded sopuli.driver.mysql.session",
        ),
        # A name that only starts with the package's is not in it.
        ("sopuli.driver", "mariadbzz", "import nacl\n", "blocked by"),
    ],
)
def test_the_walk_refuses_a_client_outside_its_allowance(
    tmp_path: Path, package: str, name: str, source: str, refusal: str
) -> None:
    finished = _run(tmp_path, "version: 1\n", _plant(tmp_path, package, name, source))

    assert finished.returncode != 0
    assert refusal in finished.stderr


def test_a_mariadb_module_may_import_its_own_clients(tmp_path: Path) -> None:
    """Option A of #1296: the walk imports it, with PyNaCl, and passes."""
    planted = _plant(tmp_path, "sopuli.driver.mariadb", "zz_planted", "import nacl\n")

    finished = _run(tmp_path, "version: 1\n", planted)

    assert finished.returncode == 0, finished.stderr


def test_base_imports_none_of_the_backend_clients(tmp_path: Path) -> None:
    """Every sopuli module outside a backend imports with the clients blocked.

    A module-level ``import httpx`` anywhere else fails this with the name of
    the module that did it, which is the diagnosis as well as the failure.
    """
    result = _probe(tmp_path, "version: 1\n")

    assert int(str(result["modules"])) > 20  # the walk found the package, not nothing


def test_the_offline_commands_still_work_with_no_client_installed(tmp_path: Path) -> None:
    """The half of the boundary that makes it honest rather than a trick.

    A config naming a backend validates with that backend uninstalled, because
    declaring a store is config and reaching one is not (§3a). This is the
    promise ADR-006 makes about what `pip install sopuli-dba` still does.
    """
    result = _probe(tmp_path, CONFIG_NAMING_A_BACKEND)

    assert result["exit_code"] == 0
    assert "0 targets" in str(result["output"])


def test_no_backend_module_is_loaded_by_an_offline_command(tmp_path: Path) -> None:
    """Rule 1 from the other side: the registry maps to module paths and imports
    on first use, so running a command that never connects must leave every
    backend module unimported."""
    result = _probe(tmp_path, CONFIG_NAMING_A_BACKEND)

    assert result["loaded_backends"] == []


# ------------------------------------------------- colour (decision #395) ---


def test_an_unimplemented_backend_nobody_configured_is_dimmed() -> None:
    """`file` and `keyring` are unimplemented on every run of this build.

    Colouring them would make every `doctor` look broken to somebody who
    configured none of them, which is the opposite of what the column is for.
    """
    from sopuli.install_shape import NOT_IMPLEMENTED, Component
    from sopuli.output.install_view import _status
    from sopuli.output.palette import Role
    from sopuli.output.table import Cell

    idle = Component(name="keyring", status=NOT_IMPLEMENTED, configured=())

    assert _status(idle) == Cell(NOT_IMPLEMENTED, Role.MUTED)


def test_an_unimplemented_backend_somebody_configured_is_not() -> None:
    """The same status, and the run's actual failure -- exit 9, and nothing
    anybody installs will fix it. The only place in this palette where a
    status's role depends on another column, and this is what it buys."""
    from sopuli.install_shape import NOT_IMPLEMENTED, Component
    from sopuli.output.install_view import _status
    from sopuli.output.palette import Role
    from sopuli.output.table import Cell

    asked_for = Component(name="keyring", status=NOT_IMPLEMENTED, configured=("vault-x",))

    assert _status(asked_for) == Cell(NOT_IMPLEMENTED, Role.BAD)
