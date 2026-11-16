"""sopuli-dba : what ODBC Driver 18 checks of a SQL Server's TLS certificate

#1549, the `mssql-client-tls` entry of docs/README.md. A SQL Server target's
config block needs TLS keys, and which ones depends on what pyodbc with ODBC
Driver 18 verifies. 06 measured only a server's own self-signed certificate.
This gives each server a certificate issued by a CA the probe creates, for
the server's container name and `localhost`, and measures each connection:

  TL1  Encrypt=yes, with the CA in no trust store
  TL2  Encrypt=yes, with the CA in the client's system trust store
  TL3  Encrypt=strict (TDS 8), with the CA in the system trust store
  TL4  Encrypt=yes, with the CA trusted, to a name the certificate does not
       hold (the server's IP address); and the same with
       HostNameInCertificate set to the container name
  TL5  ServerCertificate set to the server's certificate, with the CA in no
       trust store: Encrypt=yes, and Encrypt=strict
  TL6  ServerCertificate set to the CA's certificate: Encrypt=yes and strict
  TL7  TrustServerCertificate=yes: Encrypt=yes and strict
  TL8  Encrypt=no

A result is `encrypted` or `not encrypted`, from
sys.dm_exec_connections.encrypt_option, or `refused, <reason>`.

The client runs on Linux, in 06_client_library.Dockerfile's image, which
installs the CA in its system store for TL2 to TL4; and on Windows, where it
runs only the cases that need no change to the Windows certificate store
(TL1 and TL5 to TL8). The server is configured with mssql-conf's
network.tlscert and network.tlskey, and restarted; the probe sets both back
and restarts it again at the end.

The probe checks each result against the one RESULTS below records. A
difference, or a step that fails, makes it exit 1.

It MEASURES and decides nothing.

STATUS: run on 15.0.4510.2, 16.0.4325.4 and 17.0.5065.9, the
mcr.microsoft.com/mssql/server 2019-latest, 2022-latest and 2025-latest images
of test/compose.yaml profile mssql-matrix, as pulled on 2026-11-15, on
2026-11-16 (#1549). Clients: pyodbc 5.5.0 with ODBC Driver 18 for SQL Server
18.7.1.1, from Windows 11 (Python 3.13.12) and from Linux (06's image).
Five times; the first failed on 15.0.4510.2 and on Windows for reasons of
the probe's own, fixed since: the Windows client connects to 127.0.0.1,
because `localhost` resolves to ::1 there first and that connection is
refused. Up to the fourth, the Windows client's strict refusals were
labelled by their "SSL Provider" prefix; the message also carries 10054,
which the probe now looks for first. The results were the same every time a
case ran.

RESULTS -- the same on 15.0.4510.2 and 16.0.4325.4; 17.0.5065.9 where noted

  TL1  **Encrypt=yes checks the certificate's chain**: with the CA in no
       trust store it is refused, `certificate verify failed` (Linux) or an
       SSL provider error (Windows)
  TL2  with the CA in the system trust store, Encrypt=yes connects
       encrypted (Linux; the Windows store was not changed)
  TL3  **Encrypt=strict is refused on 15.0.4510.2 and 16.0.4325.4**, in
       every case and on both clients: the server resets the connection,
       10054 ("forcibly closed by the remote host"), also with the CA
       trusted. On 17.0.5065.9 it connects encrypted with the CA trusted
       (Linux)
  TL4  **Encrypt=yes checks the name** (Linux): with the CA trusted, a
       connection to an address the certificate does not hold is refused;
       with HostNameInCertificate set to a name it holds, it connects
  TL5  ServerCertificate set to the server's own certificate: refused with
       Encrypt=yes on every release. With Encrypt=strict it connects on
       17.0.5065.9 only, on both clients
  TL6  **ServerCertificate set to the CA's certificate never connects**,
       with Encrypt=yes or strict, on any release or client
  TL7  TrustServerCertificate=yes connects encrypted with Encrypt=yes, and
       does nothing for Encrypt=strict, which is refused
  TL8  Encrypt=no connects without encryption

HOW TO RUN, against the matrix (test/README.md), from the repo root, with
pyodbc 5.5.0 and cryptography in the Python that runs it, ODBC Driver 18 on
the machine, and 06's image built:

    python sql/mssql/10_client_tls_probe.py

It needs 02_client_hash_probe.py and 06_client_library_probe.py beside it.

THROWAWAY SERVERS ONLY. It writes a certificate and key into each server's
/var/opt/mssql/certs, sets network.tlscert and network.tlskey, and restarts
the server twice. It creates and drops the login sopuli_probe_tls.
"""

from __future__ import annotations

import datetime
import importlib.util
import ipaddress
import json
import os
import platform
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent


def _load(name: str, file: str) -> object:
    # The other probes' names start with a digit, so each is loaded by its path.
    spec = importlib.util.spec_from_file_location(name, HERE / file)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ch = _load("mssql_client_hash_probe", "02_client_hash_probe.py")
cl = _load("mssql_client_library_probe", "06_client_library_probe.py")

ACCOUNT = "sopuli_probe_tls"
#: A test password, not a credential.
GOOD = "Acme-Tls-pw1"
CERTS = "/var/opt/mssql/certs"
QUERY = "SELECT encrypt_option FROM sys.dm_exec_connections WHERE session_id = @@SPID"
#: The ODBC driver's reasons, shortened to what stays the same between runs.
REASONS = (
    ("(10054)", "connection reset, 10054"),
    ("certificate verify failed", "certificate verify failed"),
    ("17821", "17821"),
    ("Login timeout expired", "login timeout"),
    ("does not match", "name mismatch"),
    ("SSL Provider", "SSL provider error"),
)
_STATE = re.compile(r"\[(\w{5})\]")


# --------------------------------------------------------------- the client --


def connect(host: str, port: int, extra: str) -> str:
    import pyodbc  # type: ignore[import-not-found]

    pyodbc.pooling = False
    text = (
        f"Driver={{ODBC Driver 18 for SQL Server}};Server=tcp:{host},{port};"
        f"Database=master;Uid={ACCOUNT};Pwd={cl.braced(GOOD)};{extra}"
    )
    try:
        conn = pyodbc.connect(text, timeout=15)
    except Exception as exc:  # noqa: BLE001 - the result is the failure
        message = str(exc)
        for needle, reason in REASONS:
            if needle in message:
                return f"refused, {reason}"
        state = _STATE.findall(message)
        return f"refused, {state[0] if state else 'none'}: {message[-120:]}"
    try:
        cursor = conn.cursor()
        cursor.execute(QUERY)
        return "encrypted" if str(cursor.fetchone()[0]).upper() == "TRUE" else "not encrypted"
    finally:
        conn.close()


def measure(host: str, port: int, certs: Path) -> dict:
    """The cases that need the CA in no trust store."""
    # Braced, as the password is, so that a path with `;` or `}` stays one value.
    server_pem = cl.braced(str(certs / "server.pem"))
    ca_pem = cl.braced(str(certs / "ca.pem"))
    cases: dict[str, tuple[str, str]] = {
        "TL1 Encrypt=yes, CA not trusted": (host, "Encrypt=yes;"),
        "TL5 Encrypt=yes, ServerCertificate = server": (
            host, f"Encrypt=yes;ServerCertificate={server_pem};",
        ),
        "TL5 Encrypt=strict, ServerCertificate = server": (
            host, f"Encrypt=strict;ServerCertificate={server_pem};",
        ),
        "TL6 Encrypt=yes, ServerCertificate = CA": (
            host, f"Encrypt=yes;ServerCertificate={ca_pem};",
        ),
        "TL6 Encrypt=strict, ServerCertificate = CA": (
            host, f"Encrypt=strict;ServerCertificate={ca_pem};",
        ),
        "TL7 Encrypt=yes, TrustServerCertificate": (
            host, "Encrypt=yes;TrustServerCertificate=yes;",
        ),
        "TL7 Encrypt=strict, TrustServerCertificate": (
            host, "Encrypt=strict;TrustServerCertificate=yes;",
        ),
        "TL8 Encrypt=no": (host, "Encrypt=no;"),
    }  # fmt: skip
    return {label: connect(target, port, extra) for label, (target, extra) in cases.items()}


def measure_trusted(name: str, address: str, port: int) -> dict:
    """The cases that need the CA in the system trust store: Linux only."""
    cases: dict[str, tuple[str, str]] = {
        "TL2 Encrypt=yes, CA trusted": (name, "Encrypt=yes;"),
        "TL3 Encrypt=strict, CA trusted": (name, "Encrypt=strict;"),
        "TL4 Encrypt=yes, CA trusted, name not in certificate": (address, "Encrypt=yes;"),
        "TL4 Encrypt=yes, CA trusted, HostNameInCertificate": (
            address, f"Encrypt=yes;HostNameInCertificate={name};",
        ),
    }  # fmt: skip
    return {label: connect(target, port, extra) for label, (target, extra) in cases.items()}


def trust(ca: Path) -> None:
    """Install the CA in the Linux image's system store (run as root there)."""
    destination = Path("/usr/local/share/ca-certificates/sopuli-probe-ca.crt")
    destination.write_bytes(ca.read_bytes())
    subprocess.run(["update-ca-certificates"], capture_output=True, check=True)


# ------------------------------------------------------------ certificates --


def issue(directory: Path, names: list[str]) -> None:
    """A CA, and a server certificate it issues for `names`, as PEM files."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    now = datetime.datetime.now(datetime.UTC)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sopuli probe CA")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )  # fmt: skip
        .sign(ca_key, hashes.SHA256())
    )
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    server = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0])]))
        .issuer_name(ca_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=2))
        .add_extension(
            # The Windows client connects to 127.0.0.1: `localhost` resolves to
            # ::1 there first, and that connection is refused.
            x509.SubjectAlternativeName(
                [
                    *(x509.DNSName(name) for name in names),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                ]
            ),  # fmt: skip
            critical=False,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                key_cert_sign=False,
                crl_sign=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )  # fmt: skip
        .sign(ca_key, hashes.SHA256())
    )
    pem = serialization.Encoding.PEM
    (directory / "ca.pem").write_bytes(ca.public_bytes(pem))
    (directory / "server.pem").write_bytes(server.public_bytes(pem))
    (directory / "server.key").write_bytes(
        key.private_bytes(
            pem, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()
        )
    )


# ------------------------------------------------------------- the servers --


def docker(*args: str, check: bool = True) -> str:
    done = subprocess.run(
        ["docker", *args], capture_output=True, check=False,
        env={**os.environ, "MSYS_NO_PATHCONV": "1"},
    )  # fmt: skip
    if check and done.returncode != 0:
        raise ch.StepError(f"docker {' '.join(args[:3])}: {done.stderr.decode()[-300:]}")
    return done.stdout.decode("utf-8").strip()


def restart(service: str) -> None:
    name = ch.container(service)
    docker("restart", name)
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        try:
            ch.sa(service, "SELECT 1")
            return
        except ch.StepError:
            time.sleep(3)
    raise ch.StepError(f"{service} did not come back after a restart")


def configure(service: str, certs: Path) -> None:
    name = ch.container(service)
    docker("exec", "-u", "0", name, "mkdir", "-p", CERTS)
    for file in ("server.pem", "server.key"):
        docker("cp", str(certs / file), f"{name}:{CERTS}/{file}")
    docker("exec", "-u", "0", name, "chown", "-R", "mssql:", CERTS)
    docker("exec", "-u", "0", name, "chmod", "600", f"{CERTS}/server.key")
    mssql_conf = "/opt/mssql/bin/mssql-conf"
    docker("exec", "-u", "0", name, mssql_conf, "set", "network.tlscert", f"{CERTS}/server.pem")
    docker("exec", "-u", "0", name, mssql_conf, "set", "network.tlskey", f"{CERTS}/server.key")
    docker("exec", "-u", "0", name, "chown", "mssql:", "/var/opt/mssql/mssql.conf")
    restart(service)


def unconfigure(service: str) -> None:
    name = ch.container(service)
    mssql_conf = "/opt/mssql/bin/mssql-conf"
    for setting in ("network.tlscert", "network.tlskey"):
        docker("exec", "-u", "0", name, mssql_conf, "unset", setting, check=False)
    docker("exec", "-u", "0", name, "rm", "-rf", CERTS, check=False)
    restart(service)


def setup(service: str) -> str:
    teardown(service)
    ch.sa(
        service,
        f"CREATE LOGIN [{ACCOUNT}] WITH PASSWORD = {ch.quote(GOOD)}, CHECK_POLICY = OFF; "
        f"GRANT VIEW SERVER STATE TO [{ACCOUNT}]",
    )
    return ch.release(service)


def teardown(service: str) -> None:
    ch.sa(service, ch.drop_login(ACCOUNT))


def on_linux(service: str, certs: Path) -> dict:
    name = ch.container(service)
    # The address on the network the client joins, not on any other.
    network = f"{ch.PROJECT}_default"
    address = docker(
        "inspect", "-f", f'{{{{(index .NetworkSettings.Networks "{network}").IPAddress}}}}', name
    )
    ipaddress.ip_address(address)  # a refusal here is a step that failed
    output = docker(
        "run", "--rm", "--network", f"{ch.PROJECT}_default",
        "-v", f"{HERE}:/probe:ro", "-v", f"{certs}:/certs:ro", cl.IMAGE,
        "python", "-I", "/probe/10_client_tls_probe.py", "--client", name, address,
    )  # fmt: skip
    lines = output.splitlines()
    if not lines:
        raise ch.StepError(f"{service} on Linux: no results")
    return dict(json.loads(lines[-1]))


def probe(service: str) -> None:
    def body() -> None:
        release = setup(service)
        major = release.split(".")[0]
        print(f"\n== {service} {release}")
        with tempfile.TemporaryDirectory() as directory:
            certs = Path(directory)
            issue(certs, [ch.container(service), "localhost"])
            try:
                # Inside the try: a failure after mssql-conf has written the
                # settings must still set them back.
                configure(service, certs)
                variable = f"SOPULI_TEST_{service.upper().replace('-', '')}_PORT"
                port = int(os.environ.get(variable, cl.PORTS[service]))
                # Only a Windows host's answers are recorded; another host's
                # differ from nothing recorded, and say so.
                host = platform.system()
                recorded = RECORDED_WINDOWS.get(major, {}) if host == "Windows" else {}
                compare(service, host, measure("127.0.0.1", port, certs), recorded)
                linux = on_linux(service, certs)
                compare(service, "Linux", linux, RECORDED_LINUX.get(major, {}))
            finally:
                unconfigure(service)

    ch.cleaned(service, body, lambda: teardown(service))


def compare(service: str, where: str, results: dict, recorded: dict[str, str]) -> None:
    # Every label of either side, so a case the run left out is a difference too.
    for label in [*recorded, *(label for label in results if label not in recorded)]:
        got = results.get(label)
        print(f"{label} [{where}]: {got}")
        ch.check(f"{service} {where} {label}", got, recorded.get(label))


_RESET = "refused, connection reset, 10054"
#: The Windows client's answers on 2019 and 2022, which agree.
_WINDOWS_2019 = {
    "TL1 Encrypt=yes, CA not trusted": "refused, SSL provider error",
    "TL5 Encrypt=yes, ServerCertificate = server": "refused, SSL provider error",
    "TL5 Encrypt=strict, ServerCertificate = server": _RESET,
    "TL6 Encrypt=yes, ServerCertificate = CA": "refused, SSL provider error",
    "TL6 Encrypt=strict, ServerCertificate = CA": _RESET,
    "TL7 Encrypt=yes, TrustServerCertificate": "encrypted",
    "TL7 Encrypt=strict, TrustServerCertificate": _RESET,
    "TL8 Encrypt=no": "not encrypted",
}
#: The Linux client's answers on 2019 and 2022, which agree.
_LINUX_2019 = {
    "TL1 Encrypt=yes, CA not trusted": "refused, certificate verify failed",
    "TL5 Encrypt=yes, ServerCertificate = server": "refused, certificate verify failed",
    "TL5 Encrypt=strict, ServerCertificate = server": _RESET,
    "TL6 Encrypt=yes, ServerCertificate = CA": "refused, certificate verify failed",
    "TL6 Encrypt=strict, ServerCertificate = CA": _RESET,
    "TL7 Encrypt=yes, TrustServerCertificate": "encrypted",
    "TL7 Encrypt=strict, TrustServerCertificate": _RESET,
    "TL8 Encrypt=no": "not encrypted",
    "TL2 Encrypt=yes, CA trusted": "encrypted",
    "TL3 Encrypt=strict, CA trusted": _RESET,
    "TL4 Encrypt=yes, CA trusted, name not in certificate": "refused, certificate verify failed",
    "TL4 Encrypt=yes, CA trusted, HostNameInCertificate": "encrypted",
}
#: What the Windows client answered, by major release and label.
RECORDED_WINDOWS: dict[str, dict[str, str]] = {
    "15": _WINDOWS_2019,
    "16": _WINDOWS_2019,
    "17": {
        **_WINDOWS_2019,
        "TL5 Encrypt=strict, ServerCertificate = server": "encrypted",
        "TL6 Encrypt=strict, ServerCertificate = CA": "refused, SSL provider error",
        "TL7 Encrypt=strict, TrustServerCertificate": "refused, SSL provider error",
    },
}
#: What the Linux client answered, by major release and label.
RECORDED_LINUX: dict[str, dict[str, str]] = {
    "15": _LINUX_2019,
    "16": _LINUX_2019,
    "17": {
        **_LINUX_2019,
        "TL5 Encrypt=strict, ServerCertificate = server": "encrypted",
        "TL6 Encrypt=strict, ServerCertificate = CA": "refused, SSL provider error",
        "TL7 Encrypt=strict, TrustServerCertificate": "refused, certificate verify failed",
        "TL3 Encrypt=strict, CA trusted": "encrypted",
    },
}


def main() -> int:
    if sys.argv[1:2] == ["--client"]:
        # In the Linux image: measure with the CA in no store, then trust it
        # and measure the rest; print one JSON line.
        name, address = sys.argv[2], sys.argv[3]
        certs = Path("/certs")
        results = measure(name, 1433, certs)
        trust(certs / "ca.pem")
        results.update(measure_trusted(name, address, 1433))
        print(json.dumps(results))
        return 0
    print(cl.here())
    try:
        # 06's image, built as 06 builds it, so that the ODBC driver measured
        # is the one its Dockerfile names.
        cl.build()
    except ch.StepError as exc:
        print(f"STEP FAILED: {exc}")
        return 1
    return ch.run(probe)


if __name__ == "__main__":
    sys.exit(main())
