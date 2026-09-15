"""sopuli-dba : client-side reproduction of the 12C (T:) verifier   (#432)

Part 2 of #90's spike. Reads the output of ``06_verifier_reproduce.sql`` and,
for every stored ``T:``/``t:`` verifier, regenerates the digest from the
password with :func:`derive_12c` and compares it byte-for-byte. It derives
nothing secret: the input is a password the harness set on a throwaway account
and the verifier that account already stored, both emitted by the SQL probe.
This is the algorithm ``creds check --method hash`` would run against a vault
value and the account's own verifier.

Not product code and not a test -- a spike, run by hand against the tier-2
stack and left in the tree as the evidence behind the finding in
``docs/design/02-oracle-privileges.md`` §2. When ``--method hash`` is
implemented, :func:`derive_12c` is the reference to port, not this I/O.

THE DERIVATION (measured; parameters confirmed in #431):

    salt   = the last 16 bytes of the verifier (32 trailing hex characters)
    inter  = PBKDF2-HMAC-SHA512(password_utf8, salt || b"AUTH_PBKDF2_SPEEDY_KEY",
                                iterations=4096, dklen=64)
    digest = SHA-512(inter || salt)            # the first 64 bytes of the blob

  - The password is fed as its raw UTF-8 bytes, with no case folding and no
    Unicode normalisation -- the non-ASCII case reproduces on exactly the bytes
    the client sent (#431 measured those bytes as UTF-8 under an AL32UTF8
    database). No password containing ``"`` reaches here: invariant 11 rejects
    it before a driver would.
  - 4096 is the iteration count Oracle sends at logon as
    ``AUTH_PBKDF2_VGEN_COUNT`` on 26ai, 21c and 18c (#431). It is *not* stored
    in ``SPARE4``; a release that sent a different count would not reproduce
    here, which is why #431 read it from the wire rather than assuming it.

HOW TO RUN (from the repo root, against the tier-2 stack):

    docker exec -i -e NLS_LANG=AMERICAN_AMERICA.AL32UTF8 \
      sopuli-test-oracle-free-1 sqlplus -s / as sysdba \
      < sql/oracle/06_verifier_reproduce.sql \
      | python sql/oracle/06_verifier_reproduce.py

Exit status is 0 only if every verifier the probe emitted reproduced.
"""

from __future__ import annotations

import hashlib
import sys

#: The fixed suffix Oracle appends to the salt before the PBKDF2 pass. Not a
#: secret and not configurable -- it is part of the protocol, the same constant
#: hashcat's mode 12300 uses. Named here so the one magic string in the
#: derivation is spelled out once.
SPEEDY_KEY = b"AUTH_PBKDF2_SPEEDY_KEY"

#: Iterations Oracle uses to generate the stored verifier (#431). The session
#: key derivation count (AUTH_PBKDF2_SDER_COUNT = 3) is a different number for a
#: different purpose and is not used here.
ITERATIONS = 4096


def derive_12c(password: bytes, salt: bytes) -> bytes:
    """Regenerate the 64-byte 12C digest from a password and its 16-byte salt."""
    inter = hashlib.pbkdf2_hmac("sha512", password, salt + SPEEDY_KEY, ITERATIONS, 64)
    return hashlib.sha512(inter + salt).digest()


def twelve_c_verifiers(spare4: str) -> list[tuple[str, str, bytes]]:
    """Every 12C verifier in a ``SPARE4`` string, as ``(prefix, digest_hex, salt)``.

    The prefix is case-sensitive: a rollover window carries ``T:`` (the previous
    password) and ``t:`` (the current one), and telling them apart is the whole
    of question 2. ``S:`` (11G), ``H:`` (10G) and ``V:`` (the rollover marker)
    are not 12C verifiers and are skipped. A 12C blob is 160 hex characters: a
    128-hex (64-byte) digest followed by a 32-hex (16-byte) salt.
    """
    out: list[tuple[str, str, bytes]] = []
    for part in spare4.split(";"):
        prefix, value = part[:2], part[2:]
        if prefix in ("T:", "t:") and len(value) == 160:
            out.append((prefix, value[:128], bytes.fromhex(value[128:160])))
    return out


def main() -> int:
    static: list[tuple[str, bytes, str]] = []
    rollover_pw: dict[str, bytes] = {}
    rollover: list[tuple[str, str]] = []

    for raw in sys.stdin:
        line = raw.strip()
        if line.startswith("RESULT|"):
            _, label, pwhex, spare4 = line.split("|", 3)
            static.append((label, bytes.fromhex(pwhex), spare4))
        elif line.startswith("ROLLPW|"):
            _, which, pwhex = line.split("|", 2)
            rollover_pw[which] = bytes.fromhex(pwhex)
        elif line.startswith("ROLL|"):
            _, phase, spare4 = line.split("|", 2)
            rollover.append((phase, spare4))

    failures = 0

    print("== static passwords: does the stored T: reproduce byte-for-byte?")
    print(f"   {'label':<10} {'pw bytes':>8}  {'verifiers':>9}  result")
    for label, password, spare4 in static:
        verifiers = twelve_c_verifiers(spare4)
        if not verifiers:
            print(f"   {label:<10} {len(password):>8}  {'0':>9}  no T: (release has none)")
            continue
        ok = all(
            derive_12c(password, salt).hex().upper() == digest_hex.upper()
            for _prefix, digest_hex, salt in verifiers
        )
        failures += 0 if ok else 1
        verdict = "MATCH" if ok else "MISMATCH"
        print(f"   {label:<10} {len(password):>8}  {len(verifiers):>9}  {verdict}")

    if rollover:
        print("\n== rollover window: which verifier is current, which is previous?")
        print("   the probe rotated the account from ROLLPW|old to ROLLPW|new")
        for phase, spare4 in rollover:
            verifiers = twelve_c_verifiers(spare4)
            labelled = []
            for prefix, digest_hex, salt in verifiers:
                match = "unknown"
                for which, password in rollover_pw.items():
                    if derive_12c(password, salt).hex().upper() == digest_hex.upper():
                        match = which
                if match == "unknown":
                    failures += 1
                labelled.append(f"{prefix} = {match}")
            print(f"   {phase:<7} {len(verifiers)} verifier(s): {', '.join(labelled) or '(none)'}")

    print(f"\n{'ALL REPRODUCED' if failures == 0 else str(failures) + ' FAILED'}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
