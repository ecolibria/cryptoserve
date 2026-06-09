"""Tests for CRYPTOSERVE_CLI_PREFIX honoring and banner suppression.

Covers issue #191:
  - When CRYPTOSERVE_CLI_PREFIX is set, command citations (Usage:/<verb> hints)
    render the host prefix instead of the bare `cryptoserve` binary name.
  - The compact banner is suppressed under non-TTY / --ci so an embedding CLI
    that spawns cryptoserve over a pipe does not leak the CRYPTOSERVE banner.
  - Importing the package produces no banner / stdout side effects.
"""

import os
import subprocess
import sys


SDK_DIR = os.path.join(os.path.dirname(__file__), "..")


def run_cli(*args, prefix=None):
    """Run the cryptoserve CLI (subprocess => non-TTY stdout) and return result."""
    env = dict(os.environ)
    # Ensure the source package is importable when running against the tree.
    env["PYTHONPATH"] = SDK_DIR + os.pathsep + env.get("PYTHONPATH", "")
    if prefix is not None:
        env["CRYPTOSERVE_CLI_PREFIX"] = prefix
    else:
        env.pop("CRYPTOSERVE_CLI_PREFIX", None)
    return subprocess.run(
        [sys.executable, "-m", "cryptoserve", *args],
        capture_output=True,
        text=True,
        cwd=SDK_DIR,
        env=env,
    )


# ---------------------------------------------------------------------------
# Requirement 1: prefix honoring in command citations
# ---------------------------------------------------------------------------

class TestPrefixHonoring:
    def test_help_renders_prefix(self):
        """With CRYPTOSERVE_CLI_PREFIX set, help usage shows the prefix."""
        result = run_cli("help", prefix="opena2a crypto")
        assert result.returncode == 0
        out = result.stdout
        assert "Usage: opena2a crypto <command> [options]" in out
        # representative verb citations are rebranded
        assert "opena2a crypto scan ." in out
        assert "opena2a crypto login" in out

    def test_help_no_bare_command_citations_when_prefixed(self):
        """No `cryptoserve <verb>` command citations leak when prefixed.

        The Python import snippet `from cryptoserve import CryptoServe` is a
        Python statement, not a CLI citation, and is allowed to remain.
        """
        import re

        result = run_cli("help", prefix="opena2a crypto")
        assert result.returncode == 0
        # A CLI citation is `cryptoserve ` followed by a verb / option / arg token
        # (e.g. `cryptoserve scan`, `cryptoserve <command>`). The Python import
        # snippet `from cryptoserve import ...` is NOT a citation.
        citation = re.compile(r"\bcryptoserve (?!import\b)[<\[\"'a-z-]")
        for line in result.stdout.splitlines():
            if "from cryptoserve import" in line or "import cryptoserve" in line:
                continue  # python import snippet, intentionally preserved
            assert not citation.search(line), f"leaked bare CLI citation: {line!r}"

    def test_default_is_native_cryptoserve(self):
        """Unset prefix => identical to historical `cryptoserve` citations."""
        result = run_cli("help")
        assert result.returncode == 0
        out = result.stdout
        assert "Usage: cryptoserve <command>" in out
        assert "cryptoserve scan ." in out
        assert "opena2a crypto" not in out

    def test_python_import_snippet_preserved_when_prefixed(self):
        """`from cryptoserve import CryptoServe` is never rebranded."""
        result = run_cli("help", prefix="opena2a crypto")
        assert result.returncode == 0
        assert "from cryptoserve import CryptoServe" in result.stdout
        assert "from opena2a crypto import" not in result.stdout

    def test_version_default_is_native(self):
        """`version` output keeps `cryptoserve <ver>` parity when unprefixed."""
        result = run_cli("version")
        assert result.returncode == 0
        assert result.stdout.strip().startswith("cryptoserve ")

    def test_version_honors_prefix(self):
        """`version` output is rebranded when the prefix is set."""
        result = run_cli("version", prefix="opena2a crypto")
        assert result.returncode == 0
        out = result.stdout.strip()
        assert out.startswith("opena2a crypto ")
        assert not out.startswith("cryptoserve ")

    def test_usage_error_renders_prefix(self):
        """A usage-error path (encrypt w/o password) rebrands its Usage line."""
        result = run_cli("encrypt", "hello", prefix="opena2a crypto")
        assert result.returncode == 1
        combined = result.stdout + result.stderr
        assert "opena2a crypto encrypt" in combined
        # bare binary citation must not appear in the Usage hint
        assert "Usage: cryptoserve encrypt" not in combined


# ---------------------------------------------------------------------------
# Requirement 2: banner suppression
# ---------------------------------------------------------------------------

class TestBannerSuppression:
    def test_no_banner_under_non_tty(self):
        """Subprocess stdout is non-TTY => no CRYPTOSERVE banner leaks."""
        result = run_cli("help")
        assert result.returncode == 0
        # The compact banner emits a line that is just the brand token.
        for line in result.stdout.splitlines():
            assert line.strip() != "CRYPTOSERVE"
            assert "CRYPTOSERVE > HELP" not in line
            assert "CRYPTOSERVE ›" not in line

    def test_compact_header_empty_when_non_tty(self, monkeypatch):
        """compact_header() returns '' when stdout is not a TTY."""
        from cryptoserve import _cli_style

        monkeypatch.setattr(_cli_style.sys.stdout, "isatty", lambda: False, raising=False)
        monkeypatch.setattr(_cli_style.sys, "argv", ["cryptoserve", "help"])
        assert _cli_style.compact_header("HELP") == ""
        assert _cli_style.compact_header() == ""

    def test_compact_header_empty_with_ci_flag(self, monkeypatch):
        """compact_header() returns '' when --ci is in argv (even on a TTY)."""
        from cryptoserve import _cli_style

        monkeypatch.setattr(_cli_style.sys.stdout, "isatty", lambda: True, raising=False)
        monkeypatch.setattr(_cli_style.sys, "argv", ["cryptoserve", "scan", "--ci"])
        assert _cli_style.compact_header("SCAN") == ""

    def test_compact_header_present_on_interactive_tty(self, monkeypatch):
        """compact_header() renders when stdout is a TTY and no --ci flag."""
        from cryptoserve import _cli_style

        monkeypatch.setattr(_cli_style.sys.stdout, "isatty", lambda: True, raising=False)
        monkeypatch.setattr(_cli_style.sys, "argv", ["cryptoserve", "help"])
        out = _cli_style.compact_header("HELP")
        assert out != ""
        assert "CRYPTOSERVE" in out
        assert "HELP" in out


# ---------------------------------------------------------------------------
# Requirement 2 (cont.): import has no banner / stdout side effects
# ---------------------------------------------------------------------------

class TestImportNoSideEffects:
    def test_import_produces_no_stdout(self):
        """`import cryptoserve` must print nothing."""
        env = dict(os.environ)
        env["PYTHONPATH"] = SDK_DIR + os.pathsep + env.get("PYTHONPATH", "")
        result = subprocess.run(
            [sys.executable, "-c", "import cryptoserve"],
            capture_output=True,
            text=True,
            cwd=SDK_DIR,
            env=env,
        )
        assert result.returncode == 0
        assert result.stdout == ""

    def test_import_cli_style_produces_no_stdout(self):
        """Importing the styling module must print nothing either."""
        env = dict(os.environ)
        env["PYTHONPATH"] = SDK_DIR + os.pathsep + env.get("PYTHONPATH", "")
        result = subprocess.run(
            [sys.executable, "-c", "import cryptoserve._cli_style"],
            capture_output=True,
            text=True,
            cwd=SDK_DIR,
            env=env,
        )
        assert result.returncode == 0
        assert result.stdout == ""
