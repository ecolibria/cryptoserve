#!/usr/bin/env python3
"""Release-smoke runner for the cryptoserve Python CLI.

Spawns ``python -m cryptoserve`` as a subprocess and asserts behavior across
help/version, scan/pqc/cbom/gate, encrypt/decrypt/hash, and the error
exit-code matrix. No network, no keychain writes, no vault writes.

Run::

    python sdk/python/scripts/release_smoke.py

Exit: ``0`` if every check passes, ``1`` if any check fails.

The companion checklist in ``docs/testing/release-smoke.md`` covers the
manual surfaces this runner can't reach (login, contexts, certs, backup).
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = ROOT / "pyproject.toml"
FIX = ROOT / "tests" / "fixtures" / "release-smoke"

# Colors. NO_COLOR honors the spec; CI/non-TTY auto-disables.
_TTY = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
_C = {
    "reset": "\x1b[0m", "dim": "\x1b[2m", "bold": "\x1b[1m",
    "green": "\x1b[32m", "red": "\x1b[31m",
    "yellow": "\x1b[33m", "cyan": "\x1b[36m",
}


def _paint(text: str, color: str) -> str:
    return f"{color}{text}{_C['reset']}" if _TTY else text


class Results:
    def __init__(self) -> None:
        self.passed = 0
        self.failed = 0
        self.failures: list[tuple[str, str]] = []


RESULTS = Results()


def check(label: str, predicate, detail: str = "") -> None:
    """Run ``predicate`` and record pass/fail. Exceptions count as failures."""
    try:
        ok = bool(predicate())
        err = ""
    except Exception as exc:  # noqa: BLE001 — runner sees ANY failure
        ok = False
        err = f"{type(exc).__name__}: {exc}"
    if ok:
        RESULTS.passed += 1
        print(f"  {_paint('ok', _C['green'])}   {label}")
    else:
        RESULTS.failed += 1
        msg = detail or err
        RESULTS.failures.append((label, msg))
        print(f"  {_paint('FAIL', _C['red'])} {label}")
        if msg:
            print(f"       {_paint(msg, _C['dim'])}")


def phase(name: str) -> None:
    print()
    print(_paint(name, _C["bold"] + _C["cyan"]))


def run(args: list[str], *, cwd: Path | None = None, timeout: int = 30) -> tuple[int, str, str]:
    """Spawn ``python -m cryptoserve <args>``. Returns (exit, stdout, stderr)."""
    env = {**os.environ, "NO_COLOR": "1", "FORCE_COLOR": "0", "PYTHONIOENCODING": "utf-8"}
    proc = subprocess.run(
        [sys.executable, "-m", "cryptoserve", *args],
        capture_output=True,
        text=True,
        cwd=str(cwd or ROOT),
        env=env,
        timeout=timeout,
        check=False,
    )
    return proc.returncode, proc.stdout, proc.stderr


def read_version_from_pyproject() -> str:
    """Read ``version = "..."`` from pyproject.toml.

    Avoids ``tomllib`` so the runner stays portable to Python 3.9/3.10
    contributors even though CI targets 3.11+.
    """
    text = PYPROJECT.read_text(encoding="utf-8")
    match = re.search(r'^version\s*=\s*"([^"]+)"', text, flags=re.MULTILINE)
    if not match:
        raise RuntimeError(f"could not find version in {PYPROJECT}")
    return match.group(1)


def parse_json_or_none(text: str):
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


# ---------------------------------------------------------------------------
# 0. Prerequisites
# ---------------------------------------------------------------------------

phase("0. Prerequisites")

check("pyproject.toml is present", lambda: PYPROJECT.exists())
check(
    "tests/fixtures/release-smoke/{benign,weak,pqc} present",
    lambda: all((FIX / d / "pyproject.toml").exists() for d in ("benign", "weak", "pqc")),
)

# Cheap import sanity — if the package is half-installed, every later phase
# fails with the same import error and floods the output. Catch it once.
ec, out, _err = run(["help"], timeout=20)
check("`python -m cryptoserve help` is invokable (exit 0)", lambda: ec == 0,
      f"exit={ec}")

# ---------------------------------------------------------------------------
# 1. Help & version
# ---------------------------------------------------------------------------

phase("1. Help and version")

EXPECTED_VERSION = read_version_from_pyproject()

v_ec, v_out, _ = run(["version"])
check("`version` exits 0", lambda: v_ec == 0, f"exit={v_ec}")
check(
    f"`version` reports {EXPECTED_VERSION} (matches pyproject.toml)",
    lambda: v_out.strip() == f"cryptoserve {EXPECTED_VERSION}",
    f"stdout={v_out.strip()!r}",
)

vf_ec, vf_out, _ = run(["--version"])
check("`--version` matches `version`", lambda: vf_out == v_out)

h_ec, h_out, _ = run(["help"])
check("`help` exits 0", lambda: h_ec == 0)

# Discovery-surface sections — every release must keep them in the help.
for section in ("SCANNING TOOLS", "SECURITY TOOLS", "OFFLINE TOOLS"):
    check(f'help mentions "{section}"', lambda s=section: s in h_out)

for cmd in ("scan", "pqc", "cbom", "gate", "encrypt", "decrypt", "hash-password", "contexts"):
    check(f'help lists "{cmd}"', lambda c=cmd: c in h_out)

# ---------------------------------------------------------------------------
# 2. Scan walkthrough (benign / weak / pqc)
# ---------------------------------------------------------------------------

phase("2. Scan (benign / weak / pqc)")

# `scan` delegates to the cryptoscan Go binary. The binary auto-downloads on
# first invocation; if the network is unavailable the rest of this phase
# will fail loudly rather than silently green-light the release.

def scan_json(fixture: str) -> dict | None:
    ec, out, _ = run(["scan", str(FIX / fixture), "--format", "json"], timeout=60)
    if ec != 0:
        return None
    # cryptoscan emits the JSON object as the first stdout line; the trailing
    # tip banner is plain text. Splitting on the first newline is robust.
    first_line = out.splitlines()[0] if out else ""
    return parse_json_or_none(first_line)


benign_j = scan_json("benign")
check("scan benign produces JSON", lambda: benign_j is not None)
check("scan benign has 0 findings",
      lambda: benign_j is not None and len(benign_j.get("findings", [])) == 0,
      f"findings={len(benign_j.get('findings', [])) if benign_j else 'n/a'}")

weak_j = scan_json("weak")
check("scan weak produces JSON", lambda: weak_j is not None)


def _weak_ids(prefix: str) -> bool:
    if not weak_j:
        return False
    return any(f.get("id", "").startswith(prefix) for f in weak_j.get("findings", []))


check("scan weak surfaces MD5-001", lambda: _weak_ids("MD5-"))
check("scan weak surfaces DES-001", lambda: _weak_ids("DES-"))
check("scan weak surfaces RSA-001", lambda: _weak_ids("RSA-"))
check(
    "scan weak surfaces quantumRisk=VULNERABLE",
    lambda: weak_j is not None and any(
        f.get("quantumRisk") == "VULNERABLE" for f in weak_j.get("findings", [])
    ),
)

pqc_j = scan_json("pqc")
check("scan pqc produces JSON", lambda: pqc_j is not None)
check(
    "scan pqc detects ML-KEM (quantumRisk=SAFE)",
    lambda: pqc_j is not None and any(
        f.get("id", "").startswith("PQC-MLKEM") and f.get("quantumRisk") == "SAFE"
        for f in pqc_j.get("findings", [])
    ),
)
check(
    "scan pqc detects ML-DSA (quantumRisk=SAFE)",
    lambda: pqc_j is not None and any(
        f.get("id", "").startswith("PQC-MLDSA") and f.get("quantumRisk") == "SAFE"
        for f in pqc_j.get("findings", [])
    ),
)

# ---------------------------------------------------------------------------
# 3. PQC analysis
# ---------------------------------------------------------------------------

phase("3. PQC analysis")

# The Python `pqc` command analyzes the running interpreter's imports — it
# does not take a path. Profile differentiation is the lever we can flex.

gen_ec, gen_out, _ = run(["pqc", "--profile", "general", "--format", "json"])
gen_j = parse_json_or_none(gen_out)
check("pqc general exits 0", lambda: gen_ec == 0)
check("pqc general is valid JSON", lambda: gen_j is not None)
check(
    "pqc general has quantum_readiness_score (0-100)",
    lambda: gen_j is not None
    and isinstance(gen_j.get("quantum_readiness_score"), (int, float))
    and 0 <= gen_j["quantum_readiness_score"] <= 100,
)
check(
    "pqc general reports overall_urgency",
    lambda: gen_j is not None
    and isinstance(gen_j.get("overall_urgency"), str)
    and len(gen_j["overall_urgency"]) > 0,
)
check(
    "pqc general surfaces SNDL assessment",
    lambda: gen_j is not None
    and isinstance(gen_j.get("sndl_assessment", {}).get("vulnerable"), bool),
)

ns_ec, ns_out, _ = run(["pqc", "--profile", "national_security", "--format", "json"])
ns_j = parse_json_or_none(ns_out)
check(
    "pqc national_security raises urgency vs general",
    lambda: ns_j is not None
    and gen_j is not None
    and ns_j.get("overall_urgency") in ("critical", "high"),
    f"ns_urgency={ns_j.get('overall_urgency') if ns_j else 'n/a'}",
)

# Unknown profile must not crash — text mode prints a notice + still emits
# something the runner can spot. Use JSON mode so stdout is a single shape.
bogus_ec, bogus_out, _ = run(["pqc", "--profile", "definitely-not-a-profile", "--format", "json"])
bogus_j = parse_json_or_none(bogus_out)
check("pqc unknown profile still emits JSON (no crash)", lambda: bogus_j is not None)

# ---------------------------------------------------------------------------
# 4. CBOM (json / cyclonedx / spdx)
# ---------------------------------------------------------------------------

phase("4. CBOM")

# CBOM mixes header text + JSON on stdout, so use `--output` to get a clean
# file we can parse. `--no-upload` keeps the runner offline.

def cbom_out(fmt: str) -> dict | None:
    # Write into a per-call tempdir so parallel checkouts / interrupted runs
    # never leave residue in the repo tree.
    with tempfile.TemporaryDirectory(prefix="cs-smoke-cbom-") as td:
        target = Path(td) / f"cbom-{fmt}.json"
        ec, _o, _e = run(
            ["cbom", str(FIX / "weak"), "--format", fmt, "--output", str(target), "--no-upload"],
            timeout=30,
        )
        if ec != 0 or not target.exists():
            return None
        return json.loads(target.read_text(encoding="utf-8"))


for fmt in ("json", "cyclonedx", "spdx"):
    cbom_j = cbom_out(fmt)
    check(f"cbom --format {fmt} produces parseable JSON", lambda j=cbom_j: j is not None)
    check(
        f"cbom --format {fmt} has components array",
        lambda j=cbom_j: j is not None and isinstance(j.get("components"), list),
    )
    check(
        f"cbom --format {fmt} stamps format={fmt}",
        lambda j=cbom_j, f=fmt: j is not None and j.get("format") == f,
    )

# ---------------------------------------------------------------------------
# 5. Gate — exit code matrix (0 pass, 1 fail, 2 error on missing path)
# ---------------------------------------------------------------------------

phase("5. Gate exit codes")

# Benign fixture has no crypto — permissive policy must pass.
pass_ec, pass_out, _ = run([
    "gate", str(FIX / "benign"), "--policy", "permissive", "--format", "json",
])
check("gate benign exits 0", lambda: pass_ec == 0, f"exit={pass_ec}")
pass_j = parse_json_or_none(pass_out)
check("gate benign reports passed=true", lambda: pass_j is not None and pass_j.get("passed") is True)

# Weak fixture has MD5 + DES + RSA-1024 — strict policy must fail.
fail_ec, fail_out, _ = run([
    "gate", str(FIX / "weak"), "--policy", "strict", "--format", "json",
])
check("gate weak (strict) exits 1", lambda: fail_ec == 1, f"exit={fail_ec}")
fail_j = parse_json_or_none(fail_out)
check("gate weak reports passed=false", lambda: fail_j is not None and fail_j.get("passed") is False)
check(
    "gate weak surfaces at least one violation",
    lambda: fail_j is not None and len(fail_j.get("violations", [])) > 0,
)

# Nonexistent path -> exit 2 (operator error, not policy failure). This is
# the same false-green that JS PR #38 closed; the Python fix lives in the
# same PR as this runner.
err_ec, _err_out, _ = run([
    "gate", str(FIX / "__missing__"), "--format", "json",
])
check("gate on missing path exits 2", lambda: err_ec == 2, f"exit={err_ec}")

# ---------------------------------------------------------------------------
# 6. Encrypt / decrypt roundtrip
# ---------------------------------------------------------------------------

phase("6. Encrypt / decrypt")

PW = "smoke-pw-do-not-use"
PLAINTEXT = "release-smoke roundtrip"

enc_ec, enc_out, enc_err = run(["encrypt", PLAINTEXT, "--password", PW])
check("encrypt exits 0", lambda: enc_ec == 0, enc_err)
blob = enc_out.strip()
check("encrypt produces non-empty blob", lambda: len(blob) > 0)
check(
    "encrypt blob differs from plaintext",
    lambda: len(blob) > 0 and PLAINTEXT not in blob,
)

dec_ec, dec_out, dec_err = run(["decrypt", blob, "--password", PW])
check("decrypt with correct pw exits 0", lambda: dec_ec == 0, dec_err)
check(
    "decrypt restores plaintext",
    lambda: dec_out.strip() == PLAINTEXT,
    f"got={dec_out.strip()!r}",
)

wrong_ec, _wrong_out, wrong_err = run(["decrypt", blob, "--password", "totally-wrong-pw"])
check("decrypt with wrong pw exits 1", lambda: wrong_ec == 1, f"exit={wrong_ec}")
check(
    "decrypt with wrong pw writes failure message",
    lambda: bool(re.search(r"fail|wrong|decryption", _wrong_out + wrong_err, re.IGNORECASE)),
)

# ---------------------------------------------------------------------------
# 7. Hash password (scrypt + pbkdf2)
# ---------------------------------------------------------------------------

phase("7. Hash password")

s_ec, s_out, s_err = run(["hash-password", "smoke-pw", "--algo", "scrypt"])
check("hash-password scrypt exits 0", lambda: s_ec == 0, s_err)
check(
    "hash-password scrypt output looks like a scrypt hash",
    lambda: s_out.strip().startswith("$scrypt$"),
    f"got={s_out.strip()[:40]!r}",
)

p_ec, p_out, p_err = run(["hash-password", "smoke-pw", "--algo", "pbkdf2"])
check("hash-password pbkdf2 exits 0", lambda: p_ec == 0, p_err)
check(
    "hash-password pbkdf2 output looks like a pbkdf2 hash",
    lambda: p_out.strip().startswith("$pbkdf2"),
    f"got={p_out.strip()[:40]!r}",
)

# ---------------------------------------------------------------------------
# 8. Error paths
# ---------------------------------------------------------------------------

phase("8. Error paths")

unk_ec, unk_out, _ = run(["frobnicate"])
check("unknown command exits 1", lambda: unk_ec == 1, f"exit={unk_ec}")
check(
    "unknown command falls back to help",
    lambda: "Usage: cryptoserve" in unk_out or "HELP" in unk_out,
)

# scan on a missing path — cryptoscan should signal an error via non-zero
# exit. (The binary writes to stderr; we just check the exit code so we
# stay resilient to wording.)
miss_ec, _miss_out, _miss_err = run(
    ["scan", str(FIX / "__does_not_exist__"), "--format", "json"], timeout=30,
)
check("scan on missing path exits non-zero", lambda: miss_ec != 0, f"exit={miss_ec}")

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

total = RESULTS.passed + RESULTS.failed
print()
print(_paint("-" * 60, _C["dim"]))
status = (
    _paint(f"PASS {RESULTS.passed}/{total}", _C["green"] + _C["bold"])
    if RESULTS.failed == 0
    else _paint(f"FAIL {RESULTS.failed}/{total}", _C["red"] + _C["bold"])
)
print(f"Release-smoke: {status}")

if RESULTS.failed:
    print()
    print(_paint("Failures:", _C["red"]))
    for label, msg in RESULTS.failures:
        print(f"  - {label}")
        if msg:
            print(f"      {_paint(msg, _C['dim'])}")
    sys.exit(1)

sys.exit(0)
