"""Cross-implementation interop check for ML-KEM-768 (NIST FIPS 203).

The server's ML-KEM-768 (liboqs, through app.core.hybrid_crypto.MLKEM) is
checked against a second implementation that is not derived from liboqs: the
Go standard library's crypto/mlkem (Go 1.24 and later), driven through the
helper in mlkem_go_helper/.

    Forward:  liboqs keygen -> Go encapsulate -> liboqs decapsulate
    Reverse:  Go keygen -> liboqs encapsulate -> Go decapsulate

Both directions must agree on the 32-byte shared secret. A tampered ciphertext
must not decapsulate to the encapsulated secret, so the check cannot pass by
never comparing.

When either implementation is absent the cross-implementation tests skip and
name what is missing. With CRYPTOSERVE_INTEROP_REQUIRED=1 (set by the interop
CI job) absence fails instead of skipping.

Run locally from backend/ with liboqs installed and Go 1.24 or later on PATH:

    CRYPTOSERVE_INTEROP_REQUIRED=1 pytest tests/interop -v -rs

The helper is built with the Go toolchain on PATH, or taken prebuilt from
CRYPTOSERVE_INTEROP_GO_HELPER.
"""

import os
import subprocess
import sys
from pathlib import Path

import pytest

from tests.interop.go_mlkem import (
    HELPER_ENV,
    REQUIRED_ENV,
    GoMLKEM768,
    locate_go_helper,
    on_absent,
)

ROUNDS = 8
PUBLIC_KEY_BYTES = 1184
CIPHERTEXT_BYTES = 1088
SHARED_SECRET_BYTES = 32

BACKEND_DIR = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="session")
def go_mlkem(tmp_path_factory) -> GoMLKEM768:
    """The second implementation: Go crypto/mlkem through the helper."""
    path, reason = locate_go_helper(tmp_path_factory.mktemp("mlkem-go-helper"))
    if path is None:
        on_absent(reason)
    return GoMLKEM768(path)


@pytest.fixture(scope="session")
def liboqs_mlkem():
    """The server's implementation: the MLKEM class the backend uses."""
    from app.core.hybrid_crypto import LIBOQS_AVAILABLE, MLKEM

    if not LIBOQS_AVAILABLE:
        on_absent("liboqs is not available to app.core.hybrid_crypto, so the server's ML-KEM implementation is absent")
    return MLKEM


def _tamper(ciphertext: bytes) -> bytes:
    flipped = bytearray(ciphertext)
    flipped[len(flipped) // 2] ^= 0x01
    return bytes(flipped)


class TestCrossImplementation:
    """liboqs and Go crypto/mlkem agree on ML-KEM-768 in both directions."""

    def test_liboqs_keygen_go_encaps_liboqs_decaps(self, go_mlkem, liboqs_mlkem):
        for _ in range(ROUNDS):
            receiver = liboqs_mlkem("ML-KEM-768")
            public_key = receiver.generate_keypair()
            assert len(public_key) == PUBLIC_KEY_BYTES

            ciphertext, go_secret = go_mlkem.encaps(public_key)
            assert len(ciphertext) == CIPHERTEXT_BYTES
            assert len(go_secret) == SHARED_SECRET_BYTES

            assert receiver.decap_secret(ciphertext) == go_secret

    def test_go_keygen_liboqs_encaps_go_decaps(self, go_mlkem, liboqs_mlkem):
        for _ in range(ROUNDS):
            encapsulation_key, seed = go_mlkem.keygen()
            assert len(encapsulation_key) == PUBLIC_KEY_BYTES

            ciphertext, oqs_secret = liboqs_mlkem("ML-KEM-768").encap_secret(encapsulation_key)
            assert len(ciphertext) == CIPHERTEXT_BYTES
            assert len(oqs_secret) == SHARED_SECRET_BYTES

            assert go_mlkem.decaps(seed, ciphertext) == oqs_secret

    def test_tampered_go_ciphertext_does_not_decapsulate_in_liboqs(self, go_mlkem, liboqs_mlkem):
        receiver = liboqs_mlkem("ML-KEM-768")
        ciphertext, go_secret = go_mlkem.encaps(receiver.generate_keypair())
        assert receiver.decap_secret(ciphertext) == go_secret

        recovered = receiver.decap_secret(_tamper(ciphertext))
        assert len(recovered) == SHARED_SECRET_BYTES
        assert recovered != go_secret

    def test_tampered_liboqs_ciphertext_does_not_decapsulate_in_go(self, go_mlkem, liboqs_mlkem):
        encapsulation_key, seed = go_mlkem.keygen()
        ciphertext, oqs_secret = liboqs_mlkem("ML-KEM-768").encap_secret(encapsulation_key)
        assert go_mlkem.decaps(seed, ciphertext) == oqs_secret

        recovered = go_mlkem.decaps(seed, _tamper(ciphertext))
        assert len(recovered) == SHARED_SECRET_BYTES
        assert recovered != oqs_secret

    def test_both_implementations_reject_a_1087_byte_ciphertext(self, go_mlkem, liboqs_mlkem):
        from app.core.hybrid_crypto import PQCError

        receiver = liboqs_mlkem("ML-KEM-768")
        ciphertext, _ = go_mlkem.encaps(receiver.generate_keypair())
        assert len(ciphertext[:-1]) == CIPHERTEXT_BYTES - 1
        with pytest.raises(PQCError, match="ciphertext"):
            receiver.decap_secret(ciphertext[:-1])

        encapsulation_key, seed = go_mlkem.keygen()
        ciphertext, _ = liboqs_mlkem("ML-KEM-768").encap_secret(encapsulation_key)
        with pytest.raises(RuntimeError, match="ciphertext length"):
            go_mlkem.decaps(seed, ciphertext[:-1])


class TestAbsencePath:
    """Absence of an implementation is reported as a skip or a failure, never a pass."""

    def test_no_go_toolchain_and_no_prebuilt_helper_is_absent(self, tmp_path):
        path, reason = locate_go_helper(tmp_path, environ={}, which=lambda _name: None)
        assert path is None
        assert "Go toolchain" in reason
        assert HELPER_ENV in reason

    def test_prebuilt_helper_that_does_not_exist_is_absent(self, tmp_path):
        missing = tmp_path / "no-such-helper"
        path, reason = locate_go_helper(tmp_path, environ={HELPER_ENV: str(missing)})
        assert path is None
        assert str(missing) in reason

    def test_absence_skips_with_the_reason(self):
        with pytest.raises(pytest.skip.Exception, match="Go crypto/mlkem is absent"):
            on_absent("Go crypto/mlkem is absent", environ={})

    def test_absence_fails_when_interop_is_required(self):
        with pytest.raises(pytest.fail.Exception, match="Go crypto/mlkem is absent"):
            on_absent("Go crypto/mlkem is absent", environ={REQUIRED_ENV: "1"})

    def _run_cross_tests_without_helper(self, tmp_path, required: bool) -> subprocess.CompletedProcess:
        env = {key: value for key, value in os.environ.items() if key != REQUIRED_ENV}
        # The tests read this run's output, so PYTEST_ADDOPTS is not inherited and the traceback style is
        # set here: an outer --tb=no would drop the ERRORS section, where a required run names the absent helper.
        env.pop("PYTEST_ADDOPTS", None)
        env[HELPER_ENV] = str(tmp_path / "no-such-helper")
        if required:
            env[REQUIRED_ENV] = "1"
        return subprocess.run(
            [
                sys.executable,
                "-m",
                "pytest",
                f"{Path(__file__).resolve()}::TestCrossImplementation",
                "-q",
                "-rs",
                "--tb=short",
                "-p",
                "no:cacheprovider",
            ],
            cwd=BACKEND_DIR,
            env=env,
            capture_output=True,
            text=True,
            timeout=300,
        )

    def test_cross_tests_skip_and_do_not_pass_when_helper_is_absent(self, tmp_path):
        result = self._run_cross_tests_without_helper(tmp_path, required=False)
        summary = result.stdout.strip().splitlines()[-1]
        assert result.returncode == 0, result.stdout
        assert "5 skipped" in summary, result.stdout
        assert "passed" not in summary, result.stdout
        assert HELPER_ENV in result.stdout

    def test_cross_tests_fail_when_helper_is_absent_and_required(self, tmp_path):
        result = self._run_cross_tests_without_helper(tmp_path, required=True)
        summary = result.stdout.strip().splitlines()[-1]
        assert result.returncode == 1, result.stdout
        assert "passed" not in summary, result.stdout
        assert "skipped" not in summary, result.stdout
        assert HELPER_ENV in result.stdout

    def test_cross_tests_ignore_pytest_addopts_from_the_outer_run(self, tmp_path, monkeypatch):
        monkeypatch.setenv("PYTEST_ADDOPTS", "--tb=no")
        result = self._run_cross_tests_without_helper(tmp_path, required=True)
        summary = result.stdout.strip().splitlines()[-1]
        assert result.returncode == 1, result.stdout
        assert "passed" not in summary, result.stdout
        assert "skipped" not in summary, result.stdout
        assert HELPER_ENV in result.stdout
