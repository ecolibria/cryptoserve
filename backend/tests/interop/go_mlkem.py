"""Locate, build and drive the Go crypto/mlkem helper for the ML-KEM interop check."""

import json
import os
import shutil
import subprocess
from collections.abc import Callable, Mapping
from pathlib import Path

import pytest

# Path to a prebuilt helper binary; when unset the helper is built with the Go toolchain on PATH.
HELPER_ENV = "CRYPTOSERVE_INTEROP_GO_HELPER"
# "1" turns the absence of either implementation into a failure instead of a skip.
REQUIRED_ENV = "CRYPTOSERVE_INTEROP_REQUIRED"

HELPER_SOURCE = Path(__file__).resolve().parent / "mlkem_go_helper"
BUILD_TIMEOUT_SECONDS = 300
CALL_TIMEOUT_SECONDS = 30


def locate_go_helper(
    build_dir: Path,
    environ: Mapping[str, str] | None = None,
    which: Callable[[str], str | None] = shutil.which,
) -> tuple[Path | None, str | None]:
    """Return (path, None) for a usable helper, or (None, reason) when it is absent."""
    environ = os.environ if environ is None else environ

    prebuilt = environ.get(HELPER_ENV)
    if prebuilt:
        if os.path.isfile(prebuilt) and os.access(prebuilt, os.X_OK):
            return Path(prebuilt), None
        return None, (
            f"{HELPER_ENV}={prebuilt} is not an executable file, "
            "so the second ML-KEM implementation (Go crypto/mlkem) is absent"
        )

    go = which("go")
    if go is None:
        return None, (
            f"the Go toolchain is not on PATH and {HELPER_ENV} is not set, "
            "so the second ML-KEM implementation (Go crypto/mlkem) is absent"
        )

    output = Path(build_dir) / "mlkem-go-helper"
    try:
        result = subprocess.run(
            [go, "build", "-o", str(output), "."],
            cwd=HELPER_SOURCE,
            # Build with the local toolchain only; an older Go must not download a newer one.
            env={**os.environ, "GOTOOLCHAIN": "local"},
            capture_output=True,
            text=True,
            timeout=BUILD_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return None, f"building the Go crypto/mlkem helper failed: {exc}"
    if result.returncode != 0:
        detail = (result.stderr.strip().splitlines() or ["no output"])[0]
        return None, f"building the Go crypto/mlkem helper failed (Go 1.24 or later is required): {detail}"
    return output, None


def on_absent(reason: str, environ: Mapping[str, str] | None = None) -> None:
    """Skip with the reason, or fail when the interop check is required."""
    environ = os.environ if environ is None else environ
    if environ.get(REQUIRED_ENV) == "1":
        pytest.fail(f"{reason} ({REQUIRED_ENV}=1 makes absence a failure)", pytrace=False)
    pytest.skip(reason)


class GoMLKEM768:
    """ML-KEM-768 from the Go standard library, one helper process per operation."""

    def __init__(self, path: Path):
        self.path = Path(path)

    def _call(self, *args: str) -> dict:
        result = subprocess.run(
            [str(self.path), *args],
            capture_output=True,
            text=True,
            timeout=CALL_TIMEOUT_SECONDS,
        )
        if result.returncode != 0:
            raise RuntimeError(f"mlkem-go-helper {args[0]} failed: {result.stderr.strip()}")
        return json.loads(result.stdout)

    def keygen(self) -> tuple[bytes, bytes]:
        """Return (encapsulation key, 64-byte d || z seed)."""
        out = self._call("keygen")
        return bytes.fromhex(out["encapsulationKey"]), bytes.fromhex(out["seed"])

    def encaps(self, encapsulation_key: bytes) -> tuple[bytes, bytes]:
        """Return (ciphertext, shared secret)."""
        out = self._call("encaps", encapsulation_key.hex())
        return bytes.fromhex(out["ciphertext"]), bytes.fromhex(out["sharedKey"])

    def decaps(self, seed: bytes, ciphertext: bytes) -> bytes:
        """Return the shared secret for ciphertext under the key expanded from seed."""
        out = self._call("decaps", seed.hex(), ciphertext.hex())
        return bytes.fromhex(out["sharedKey"])
