"""
Binary manager for CryptoScan and CryptoDeps Go tools.

Downloads, caches, and executes Go binaries from GitHub releases.
Uses only stdlib (urllib.request) to avoid adding dependencies.
"""

import hashlib
import json
import os
import platform
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path
from typing import Optional
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError


TOOLS = {
    "cryptoscan": {
        "repo": "csnp/cryptoscan",
        "version": "v1.3.0",
        "binary_name": "cryptoscan",
    },
    "cryptodeps": {
        "repo": "csnp/qramm-cryptodeps",
        "version": "v1.2.2",
        "binary_name": "cryptodeps",
    },
}


def get_bin_dir() -> Path:
    """Return ~/.cryptoserve/bin/, creating it if needed."""
    bin_dir = Path.home() / ".cryptoserve" / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    return bin_dir


def _get_versions_path() -> Path:
    """Return path to versions.json tracking file."""
    return get_bin_dir() / "versions.json"


def _load_versions() -> dict:
    """Load the versions tracking file."""
    path = _get_versions_path()
    if path.exists():
        try:
            return json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            pass
    return {}


def _save_versions(versions: dict) -> None:
    """Save the versions tracking file."""
    path = _get_versions_path()
    path.write_text(json.dumps(versions, indent=2))


def _detect_platform() -> tuple[str, str]:
    """Detect OS and architecture.

    Returns:
        (os_name, arch) where os_name is darwin/linux/windows
        and arch is arm64/amd64.
    """
    system = platform.system().lower()
    if system not in ("darwin", "linux", "windows"):
        raise RuntimeError(f"Unsupported platform: {system}")

    machine = platform.machine().lower()
    if machine in ("arm64", "aarch64"):
        arch = "arm64"
    elif machine in ("x86_64", "amd64", "x64"):
        arch = "amd64"
    else:
        raise RuntimeError(f"Unsupported architecture: {machine}")

    return system, arch


def _build_asset_name(tool_name: str, version: str, os_name: str, arch: str) -> str:
    """Build the GitHub release asset filename.

    cryptodeps uses x86_64 instead of amd64 in asset names.
    """
    # Strip leading 'v' for asset name (e.g., v1.3.0 -> 1.3.0)
    ver = version.lstrip("v")

    # cryptodeps uses x86_64 in asset names
    asset_arch = arch
    if tool_name == "cryptodeps" and arch == "amd64":
        asset_arch = "x86_64"

    ext = "zip" if os_name == "windows" else "tar.gz"
    binary_name = TOOLS[tool_name]["binary_name"]
    return f"{binary_name}_{ver}_{os_name}_{asset_arch}.{ext}"


def _build_download_url(tool_name: str, version: str, asset_name: str) -> str:
    """Build the full GitHub release download URL."""
    repo = TOOLS[tool_name]["repo"]
    return f"https://github.com/{repo}/releases/download/{version}/{asset_name}"


def _download_file(url: str, dest: Path, label: str = "") -> None:
    """Download a file from URL to dest path with progress indication."""
    request = Request(url, headers={"User-Agent": "cryptoserve-cli"})
    try:
        with urlopen(request, timeout=60) as response:
            total = response.headers.get("Content-Length")
            if total:
                total = int(total)

            with open(dest, "wb") as f:
                downloaded = 0
                while True:
                    chunk = response.read(8192)
                    if not chunk:
                        break
                    f.write(chunk)
                    downloaded += len(chunk)
                    if total and sys.stderr.isatty():
                        pct = downloaded * 100 // total
                        sys.stderr.write(f"\r  {label} {pct}%")
                        sys.stderr.flush()

            if total and sys.stderr.isatty():
                sys.stderr.write("\r" + " " * 60 + "\r")
                sys.stderr.flush()

    except HTTPError as e:
        raise RuntimeError(
            f"Download failed: HTTP {e.code} for {url}"
        ) from e
    except URLError as e:
        raise RuntimeError(
            f"Download failed: {e.reason}. Check your internet connection."
        ) from e


def _verify_checksum(archive_path: Path, tool_name: str, version: str, asset_name: str) -> None:
    """Verify SHA256 checksum of downloaded archive against checksums.txt."""
    repo = TOOLS[tool_name]["repo"]
    checksums_url = f"https://github.com/{repo}/releases/download/{version}/checksums.txt"

    with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as tmp:
        tmp_path = Path(tmp.name)

    try:
        _download_file(checksums_url, tmp_path)
        checksums_text = tmp_path.read_text()
    except RuntimeError:
        # checksums.txt not available — skip verification with warning
        print("  Warning: checksums.txt not found, skipping verification", file=sys.stderr)
        return
    finally:
        tmp_path.unlink(missing_ok=True)

    # Parse checksums.txt: each line is "<hash>  <filename>" or "<hash> <filename>"
    expected_hash = None
    for line in checksums_text.strip().splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[1] == asset_name:
            expected_hash = parts[0].lower()
            break

    if expected_hash is None:
        print(f"  Warning: no checksum entry for {asset_name}", file=sys.stderr)
        return

    # Compute actual hash
    sha256 = hashlib.sha256()
    with open(archive_path, "rb") as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            sha256.update(chunk)

    actual_hash = sha256.hexdigest().lower()
    if actual_hash != expected_hash:
        archive_path.unlink(missing_ok=True)
        raise RuntimeError(
            f"Checksum mismatch for {asset_name}:\n"
            f"  expected: {expected_hash}\n"
            f"  got:      {actual_hash}\n"
            "The download may be corrupted. Try again with --update."
        )


def _extract_binary(archive_path: Path, binary_name: str, dest_dir: Path) -> Path:
    """Extract the binary from a tar.gz or zip archive."""
    archive_str = str(archive_path)

    if archive_str.endswith(".tar.gz") or archive_str.endswith(".tgz"):
        with tarfile.open(archive_path, "r:gz") as tar:
            # Find the binary in the archive
            for member in tar.getmembers():
                if os.path.basename(member.name) == binary_name:
                    # Extract to dest_dir
                    member.name = binary_name
                    tar.extract(member, dest_dir)
                    return dest_dir / binary_name

            raise RuntimeError(
                f"Binary '{binary_name}' not found in archive {archive_path.name}"
            )

    elif archive_str.endswith(".zip"):
        with zipfile.ZipFile(archive_path, "r") as zf:
            for name in zf.namelist():
                if os.path.basename(name) == binary_name or os.path.basename(name) == f"{binary_name}.exe":
                    target_name = os.path.basename(name)
                    with zf.open(name) as src, open(dest_dir / target_name, "wb") as dst:
                        shutil.copyfileobj(src, dst)
                    return dest_dir / target_name

            raise RuntimeError(
                f"Binary '{binary_name}' not found in archive {archive_path.name}"
            )
    else:
        raise RuntimeError(f"Unknown archive format: {archive_path.name}")


def get_binary_path(tool_name: str) -> Optional[Path]:
    """Return path to the binary if it exists and version matches, else None."""
    if tool_name not in TOOLS:
        raise ValueError(f"Unknown tool: {tool_name}. Available: {list(TOOLS.keys())}")

    tool = TOOLS[tool_name]
    bin_dir = get_bin_dir()
    binary_name = tool["binary_name"]

    # On Windows, binary has .exe extension
    if platform.system().lower() == "windows":
        binary_name += ".exe"

    binary_path = bin_dir / binary_name
    if not binary_path.exists():
        return None

    # Check version
    versions = _load_versions()
    installed_version = versions.get(tool_name)
    if installed_version != tool["version"]:
        return None

    return binary_path


def download_binary(tool_name: str, force: bool = False) -> Path:
    """Download the binary for a tool from GitHub releases.

    Args:
        tool_name: Name of the tool (cryptoscan or cryptodeps).
        force: If True, re-download even if already cached.

    Returns:
        Path to the downloaded binary.
    """
    if tool_name not in TOOLS:
        raise ValueError(f"Unknown tool: {tool_name}. Available: {list(TOOLS.keys())}")

    tool = TOOLS[tool_name]
    version = tool["version"]

    # Check if already installed (unless force)
    if not force:
        existing = get_binary_path(tool_name)
        if existing:
            return existing

    os_name, arch = _detect_platform()
    asset_name = _build_asset_name(tool_name, version, os_name, arch)
    url = _build_download_url(tool_name, version, asset_name)

    print(f"  Downloading {tool_name} {version} ({os_name}/{arch})...", file=sys.stderr)

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        archive_path = tmp_path / asset_name

        # Download
        _download_file(url, archive_path, label=f"Downloading {tool_name}...")

        # Verify checksum
        _verify_checksum(archive_path, tool_name, version, asset_name)

        # Extract
        binary_name = tool["binary_name"]
        if platform.system().lower() == "windows":
            binary_name += ".exe"

        extracted = _extract_binary(archive_path, tool["binary_name"], tmp_path)

        # Move to bin dir
        bin_dir = get_bin_dir()
        dest = bin_dir / binary_name
        shutil.move(str(extracted), str(dest))

        # chmod +x on unix
        if platform.system().lower() != "windows":
            dest.chmod(dest.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)

    # Track version
    versions = _load_versions()
    versions[tool_name] = version
    _save_versions(versions)

    print(f"  Installed {tool_name} {version} to {dest}", file=sys.stderr)
    return dest


def ensure_binary(tool_name: str) -> Path:
    """Ensure the binary is available, downloading if necessary.

    Returns:
        Path to the ready-to-use binary.
    """
    path = get_binary_path(tool_name)
    if path:
        return path
    return download_binary(tool_name)


def run_binary(tool_name: str, args: list[str]) -> int:
    """Run a tool binary with the given arguments.

    Downloads the binary on first use. Passes through stdio directly.

    Args:
        tool_name: Name of the tool (cryptoscan or cryptodeps).
        args: Command-line arguments to pass to the binary.

    Returns:
        Exit code from the binary.
    """
    binary = ensure_binary(tool_name)
    result = subprocess.run(
        [str(binary)] + args,
        stdin=sys.stdin,
        stdout=sys.stdout,
        stderr=sys.stderr,
    )
    return result.returncode
