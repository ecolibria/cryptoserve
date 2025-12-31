"""SDK package generator."""

import os
import shutil
import tempfile
import hashlib
from pathlib import Path

from app.config import get_settings
from app.models import Identity
from app.core.identity_manager import identity_manager

settings = get_settings()

# Get the templates directory relative to this file
TEMPLATES_DIR = Path(__file__).parent / "templates"


class SDKGenerator:
    """Generates personalized SDK packages."""

    def __init__(self):
        self.templates_dir = TEMPLATES_DIR

    def generate_python_sdk(self, identity: Identity, token: str) -> Path:
        """
        Generate a personalized Python SDK package.

        Returns the path to the generated wheel file.
        """
        # Create temporary directory for building
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            sdk_dir = temp_path / "cryptoserve"
            sdk_dir.mkdir()

            # Copy template files
            self._copy_template_files(sdk_dir)

            # Generate identity module
            self._generate_identity_module(sdk_dir, identity, token)

            # Generate setup.py
            identity_hash = hashlib.sha256(identity.id.encode()).hexdigest()[:8]
            self._generate_setup_py(temp_path, identity_hash)

            # Build wheel
            wheel_path = self._build_wheel(temp_path)

            # Move to output directory
            output_dir = Path(__file__).parent / "output"
            output_dir.mkdir(exist_ok=True)

            final_path = output_dir / wheel_path.name
            shutil.copy2(wheel_path, final_path)

            return final_path

    def _copy_template_files(self, target_dir: Path):
        """Copy SDK template files to target directory."""
        template_src = self.templates_dir / "python" / "cryptoserve"

        # Check if templates exist AND have actual Python files
        template_files = list(template_src.glob("*.py")) if template_src.exists() else []
        template_files = [f for f in template_files if f.name != "_identity.py"]

        if template_files:
            # Copy from template
            for file in template_files:
                shutil.copy2(file, target_dir / file.name)
        else:
            # Generate minimal SDK inline
            self._generate_minimal_sdk(target_dir)

    def _generate_minimal_sdk(self, target_dir: Path):
        """Generate minimal SDK files inline (when templates don't exist)."""
        # __init__.py
        init_content = '''"""CryptoServe SDK - Zero-config cryptographic operations."""

from cryptoserve.client import CryptoClient
from cryptoserve._identity import IDENTITY

__version__ = "0.1.0"

# Create singleton client
_client = None


def _get_client() -> CryptoClient:
    global _client
    if _client is None:
        _client = CryptoClient(
            server_url=IDENTITY["server_url"],
            token=IDENTITY["token"],
        )
    return _client


class crypto:
    """
    Main interface for CryptoServe.

    Usage:
        from cryptoserve import crypto

        ciphertext = crypto.encrypt(b"data", context="user-pii")
        plaintext = crypto.decrypt(ciphertext, context="user-pii")
    """

    @classmethod
    def encrypt(cls, plaintext: bytes | str, context: str) -> bytes:
        """Encrypt data."""
        if isinstance(plaintext, str):
            plaintext = plaintext.encode("utf-8")
        return _get_client().encrypt(plaintext, context)

    @classmethod
    def decrypt(cls, ciphertext: bytes, context: str) -> bytes:
        """Decrypt data."""
        return _get_client().decrypt(ciphertext, context)

    @classmethod
    def encrypt_string(cls, plaintext: str, context: str) -> str:
        """Encrypt string and return base64."""
        import base64
        ciphertext = cls.encrypt(plaintext.encode("utf-8"), context)
        return base64.b64encode(ciphertext).decode("ascii")

    @classmethod
    def decrypt_string(cls, ciphertext_b64: str, context: str) -> str:
        """Decrypt base64 string."""
        import base64
        ciphertext = base64.b64decode(ciphertext_b64)
        plaintext = cls.decrypt(ciphertext, context)
        return plaintext.decode("utf-8")
'''
        (target_dir / "__init__.py").write_text(init_content)

        # client.py
        client_content = '''"""CryptoServe API client."""

import base64
import requests


class CryptoServeError(Exception):
    """Base exception for CryptoServe errors."""
    pass


class AuthenticationError(CryptoServeError):
    """Authentication failed."""
    pass


class AuthorizationError(CryptoServeError):
    """Not authorized for this operation."""
    pass


class ContextNotFoundError(CryptoServeError):
    """Context does not exist."""
    pass


class CryptoClient:
    """Client for CryptoServe API."""

    def __init__(self, server_url: str, token: str):
        self.server_url = server_url.rstrip("/")
        self.token = token
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        })

    def encrypt(self, plaintext: bytes, context: str) -> bytes:
        """Encrypt data."""
        response = self.session.post(
            f"{self.server_url}/v1/crypto/encrypt",
            json={
                "plaintext": base64.b64encode(plaintext).decode("ascii"),
                "context": context,
            },
            timeout=30,
        )

        if response.status_code == 401:
            raise AuthenticationError("Invalid or expired identity token")
        elif response.status_code == 403:
            raise AuthorizationError(f"Not authorized for context: {context}")
        elif response.status_code == 400:
            data = response.json()
            raise ContextNotFoundError(data.get("detail", "Bad request"))
        elif response.status_code != 200:
            raise CryptoServeError(f"Server error: {response.status_code}")

        data = response.json()
        return base64.b64decode(data["ciphertext"])

    def decrypt(self, ciphertext: bytes, context: str) -> bytes:
        """Decrypt data."""
        response = self.session.post(
            f"{self.server_url}/v1/crypto/decrypt",
            json={
                "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
                "context": context,
            },
            timeout=30,
        )

        if response.status_code == 401:
            raise AuthenticationError("Invalid or expired identity token")
        elif response.status_code == 403:
            raise AuthorizationError(f"Not authorized for context: {context}")
        elif response.status_code == 400:
            data = response.json()
            raise CryptoServeError(data.get("detail", "Bad request"))
        elif response.status_code != 200:
            raise CryptoServeError(f"Server error: {response.status_code}")

        data = response.json()
        return base64.b64decode(data["plaintext"])
'''
        (target_dir / "client.py").write_text(client_content)

    def _generate_identity_module(self, target_dir: Path, identity: Identity, token: str):
        """Generate the _identity.py module with embedded credentials."""
        content = f'''"""
CryptoServe Identity - AUTO-GENERATED
DO NOT EDIT - This file contains your SDK credentials.
"""

IDENTITY = {{
    "server_url": "{settings.backend_url}",
    "token": "{token}",
    "identity_id": "{identity.id}",
    "identity_type": "{identity.type.value}",
    "name": "{identity.name}",
    "team": "{identity.team}",
    "environment": "{identity.environment}",
    "allowed_contexts": {identity.allowed_contexts},
    "created_at": "{identity.created_at.isoformat()}",
    "expires_at": "{identity.expires_at.isoformat()}",
}}
'''
        (target_dir / "_identity.py").write_text(content)

    def _generate_setup_py(self, temp_path: Path, identity_hash: str):
        """Generate pyproject.toml and setup.py for the package."""
        # Create pyproject.toml (required for modern pip)
        # Use + for local version identifier per PEP 440
        pyproject_content = f'''[build-system]
requires = ["setuptools>=69.0", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "cryptoserve"
version = "0.1.0+{identity_hash}"
description = "CryptoServe SDK - Zero-config cryptographic operations"
requires-python = ">=3.9"
dependencies = ["requests>=2.28.0"]

[tool.setuptools.packages.find]
where = ["."]
'''
        (temp_path / "pyproject.toml").write_text(pyproject_content)

        # Also create setup.py for compatibility
        setup_content = f'''"""CryptoServe SDK setup."""
from setuptools import setup, find_packages
setup(
    name="cryptoserve",
    version="0.1.0+{identity_hash}",
    packages=find_packages(),
    install_requires=["requests>=2.28.0"],
    python_requires=">=3.9",
)
'''
        (temp_path / "setup.py").write_text(setup_content)

    def _build_wheel(self, temp_path: Path) -> Path:
        """Build wheel package manually (no external tools required)."""
        import zipfile
        import sys

        # Create dist directory
        dist_dir = temp_path / "dist"
        dist_dir.mkdir(exist_ok=True)

        # Read version from pyproject.toml
        pyproject = (temp_path / "pyproject.toml").read_text()
        version_line = [l for l in pyproject.split("\n") if "version" in l][0]
        version = version_line.split('"')[1]  # Extract version from 'version = "0.1.0+hash"'

        # Wheel filename format: {distribution}-{version}-{python tag}-{abi tag}-{platform tag}.whl
        wheel_name = f"cryptoserve-{version}-py3-none-any.whl"
        wheel_path = dist_dir / wheel_name

        # Create wheel (it's just a zip file)
        with zipfile.ZipFile(wheel_path, "w", zipfile.ZIP_DEFLATED) as whl:
            # Add package files
            pkg_dir = temp_path / "cryptoserve"
            for py_file in pkg_dir.glob("*.py"):
                arcname = f"cryptoserve/{py_file.name}"
                whl.write(py_file, arcname)

            # Create METADATA
            metadata = f"""Metadata-Version: 2.1
Name: cryptoserve
Version: {version}
Summary: CryptoServe SDK - Zero-config cryptographic operations
Requires-Python: >=3.9
Requires-Dist: requests>=2.28.0
"""
            whl.writestr(f"cryptoserve-{version}.dist-info/METADATA", metadata)

            # Create WHEEL
            wheel_info = """Wheel-Version: 1.0
Generator: cryptoserve-sdk-generator
Root-Is-Purelib: true
Tag: py3-none-any
"""
            whl.writestr(f"cryptoserve-{version}.dist-info/WHEEL", wheel_info)

            # Create RECORD (list of files with hashes - simplified)
            record_lines = [
                f"cryptoserve/__init__.py,sha256=,",
                f"cryptoserve/client.py,sha256=,",
                f"cryptoserve/_identity.py,sha256=,",
                f"cryptoserve-{version}.dist-info/METADATA,sha256=,",
                f"cryptoserve-{version}.dist-info/WHEEL,sha256=,",
                f"cryptoserve-{version}.dist-info/RECORD,,",
            ]
            whl.writestr(f"cryptoserve-{version}.dist-info/RECORD", "\n".join(record_lines))

            # Create top_level.txt
            whl.writestr(f"cryptoserve-{version}.dist-info/top_level.txt", "cryptoserve\n")

        return wheel_path


# Singleton instance
sdk_generator = SDKGenerator()
