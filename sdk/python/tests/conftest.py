"""Pytest fixtures for SDK integration tests."""

import os
import pytest
import requests
from unittest.mock import MagicMock, patch

# Default test server configuration
TEST_SERVER_URL = os.environ.get("CRYPTOSERVE_TEST_SERVER", "http://localhost:8000")
TEST_TOKEN = os.environ.get("CRYPTOSERVE_TEST_TOKEN", "test-token")


@pytest.fixture
def server_url():
    """Get the test server URL."""
    return TEST_SERVER_URL


@pytest.fixture
def test_token():
    """Get a test authentication token."""
    return TEST_TOKEN


@pytest.fixture
def server_available(server_url):
    """Check if the test server is available."""
    try:
        response = requests.get(f"{server_url}/health", timeout=5)
        return response.status_code == 200
    except requests.RequestException:
        return False


@pytest.fixture
def mock_identity():
    """Mock identity for testing without server."""
    return {
        "identity_id": "test-identity-123",
        "name": "test-app",
        "token": "mock-jwt-token.payload.signature",
        "server_url": TEST_SERVER_URL,
        "team": "test-team",
    }


@pytest.fixture
def mock_credentials():
    """Mock application credentials for testing."""
    return {
        "app_id": "test-app-id",
        "access_token": "mock-access-token.payload.signature",
        "refresh_token": "mock-refresh-token",
        "server_url": TEST_SERVER_URL,
        "contexts": ["default", "user-pii"],
    }


@pytest.fixture
def mock_session_cookie():
    """Mock session cookie for testing registration."""
    return "mock-session-cookie"


@pytest.fixture
def mock_crypto_libraries():
    """Mock detected crypto libraries."""
    return [
        {
            "name": "cryptography",
            "version": "42.0.0",
            "category": "general",
            "algorithms": ["AES", "ChaCha20", "RSA", "ECDSA"],
            "quantum_risk": "high",
            "is_deprecated": False,
        },
        {
            "name": "hashlib",
            "version": None,
            "category": "hashing",
            "algorithms": ["SHA-256", "SHA-512", "SHA3-256"],
            "quantum_risk": "low",
            "is_deprecated": False,
        },
    ]


@pytest.fixture
def mock_cbom():
    """Mock CBOM response."""
    return {
        "id": "cbom_test_001",
        "version": "1.0",
        "format": "json",
        "components": [
            {
                "bom_ref": "crypto-lib-cryptography",
                "type": "library",
                "name": "cryptography",
                "quantum_risk": "high",
            }
        ],
        "summary": {
            "total_libraries": 1,
            "quantum_safe": 0,
            "quantum_vulnerable": 1,
        },
    }


@pytest.fixture
def mock_pqc_recommendations():
    """Mock PQC recommendations response."""
    return {
        "overall_urgency": "medium",
        "quantum_readiness_score": 45.0,
        "sndl_assessment": {
            "vulnerable": True,
            "risk_level": "medium",
        },
        "key_findings": [
            "RSA-2048 keys detected",
            "No PQC libraries in use",
        ],
        "next_steps": [
            "Evaluate ML-KEM-768 for key exchange",
            "Plan hybrid deployment",
        ],
        "kem_recommendations": [
            {
                "current_algorithm": "RSA-2048",
                "recommended_algorithm": "ML-KEM-768",
                "fips_standard": "FIPS 203",
            }
        ],
        "signature_recommendations": [],
        "migration_plan": [],
    }


@pytest.fixture
def patch_credentials(mock_credentials):
    """Patch credentials loading for tests."""
    with patch("cryptoserve._credentials.load_app_credentials", return_value=mock_credentials):
        with patch("cryptoserve._credentials.get_session_cookie", return_value="test-cookie"):
            with patch("cryptoserve._credentials.get_server_url", return_value=TEST_SERVER_URL):
                with patch("cryptoserve._credentials.get_api_url", return_value=f"{TEST_SERVER_URL}/api"):
                    yield


@pytest.fixture
def patch_no_credentials():
    """Patch credentials to simulate first-time registration."""
    with patch("cryptoserve._credentials.load_app_credentials", return_value=None):
        with patch("cryptoserve._credentials.get_session_cookie", return_value="test-cookie"):
            with patch("cryptoserve._credentials.get_server_url", return_value=TEST_SERVER_URL):
                with patch("cryptoserve._credentials.get_api_url", return_value=f"{TEST_SERVER_URL}/api"):
                    with patch("cryptoserve._credentials.save_app_credentials"):
                        yield
