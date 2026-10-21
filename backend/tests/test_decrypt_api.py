"""The decrypt routes answer a malformed hybrid ciphertext as a client error.

The ciphertexts are built in the serialized wire format with placeholder
contents, so these tests run without liboqs: the refusal happens while the
blob is parsed, before any ML-KEM operation.
"""

import base64
import json
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from fastapi import FastAPI

from app.api import crypto as crypto_api
from app.core.crypto_engine import crypto_engine, DecryptionError
from app.core.hybrid_crypto import HybridCiphertext, HybridMode
from app.core.rate_limiter import InMemoryBackend, RateLimiter, set_rate_limiter
from app.database import get_db
from app.models import Identity, IdentityType, IdentityStatus

# ML-KEM-768 ciphertext length in bytes (FIPS 203).
MLKEM_768_CIPHERTEXT_LEN = 1088


def _hybrid_blob() -> bytes:
    """A hybrid ciphertext in the serialized wire format, with placeholder contents."""
    return HybridCiphertext(
        mode=HybridMode.AES_MLKEM_768,
        classical_ciphertext=bytes(48),
        kem_ciphertext=bytes(MLKEM_768_CIPHERTEXT_LEN),
        nonce=bytes(12),
        key_id="placeholder-key-id",
    ).serialize()


def _truncated_inside_kem_ciphertext(blob: bytes) -> bytes:
    """Keep 2 + header_len + (kem_ct_len - 1) bytes: one byte short of the KEM ciphertext."""
    header_len = int.from_bytes(blob[:2], "big")
    header = json.loads(blob[2 : 2 + header_len])
    return blob[: 2 + header_len + header["kem_ct_len"] - 1]


def _with_header(header) -> bytes:
    """A blob whose header is the given JSON value, followed by the KEM ciphertext it claims."""
    header_json = json.dumps(header, separators=(",", ":")).encode()
    return len(header_json).to_bytes(2, "big") + header_json + bytes(MLKEM_768_CIPHERTEXT_LEN)


def _well_formed_header() -> dict:
    blob = _hybrid_blob()
    header_len = int.from_bytes(blob[:2], "big")
    return json.loads(blob[2 : 2 + header_len])


def _header_without(field: str) -> dict:
    header = _well_formed_header()
    del header[field]
    return header


def _header_with(field: str, value) -> dict:
    header = _well_formed_header()
    header[field] = value
    return header


@pytest.fixture
async def identity(db_session, test_user, test_context, test_tenant):
    identity = Identity(
        id="decrypt_api_identity",
        tenant_id=test_tenant.id,
        user_id=test_user.id,
        type=IdentityType.DEVELOPER,
        name="Decrypt API Identity",
        team="test",
        environment="development",
        allowed_contexts=["test-context"],
        status=IdentityStatus.ACTIVE,
        expires_at=datetime.now(timezone.utc) + timedelta(days=90),
    )
    db_session.add(identity)
    await db_session.commit()
    return identity


@pytest.fixture
async def crypto_client(db_session, identity):
    """The crypto routes, with the SDK identity check, the database and the rate limiter stubbed."""
    app = FastAPI()
    app.include_router(crypto_api.router)

    async def _db():
        yield db_session

    app.dependency_overrides[crypto_api.get_sdk_identity] = lambda: identity
    app.dependency_overrides[get_db] = _db
    # The routes consult the global rate limiter before decrypting. With REDIS_URL set
    # in the environment that limiter is the Redis one, so pin the in-memory backend:
    # these tests are about the decrypt routes, not about reaching a Redis server.
    set_rate_limiter(RateLimiter(backend=InMemoryBackend()))
    try:
        # An unhandled exception is answered 500 instead of being raised into the test.
        transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            yield client
    finally:
        set_rate_limiter(None)


class TestMalformedHybridCiphertext:
    """A client-supplied hybrid ciphertext that does not parse is a decryption failure."""

    @pytest.mark.parametrize(
        "blob",
        [
            pytest.param(_truncated_inside_kem_ciphertext(_hybrid_blob()), id="truncated-inside-kem-ciphertext"),
            pytest.param(_with_header(_header_without("mode")), id="header-without-mode"),
            pytest.param(_with_header(_header_with("mode", "AES-128-GCM+ML-KEM-512")), id="unknown-mode"),
            pytest.param(_with_header(_header_with("nonce", 12)), id="nonce-not-a-string"),
            pytest.param(_with_header(["kem_ct_len"]), id="header-not-an-object"),
        ],
    )
    async def test_engine_raises_decryption_error(self, db_session, identity, blob):
        assert crypto_engine._is_hybrid_ciphertext(blob)

        with pytest.raises(DecryptionError, match="Invalid hybrid ciphertext"):
            await crypto_engine.decrypt(
                db=db_session,
                packed_ciphertext=blob,
                context_name="test-context",
                identity=identity,
            )

    async def test_decrypt_route_answers_400(self, crypto_client):
        blob = _truncated_inside_kem_ciphertext(_hybrid_blob())

        response = await crypto_client.post(
            "/api/v1/crypto/decrypt",
            json={"ciphertext": base64.b64encode(blob).decode("ascii"), "context": "test-context"},
        )

        assert response.status_code == 400, response.text
        assert response.json()["detail"] == "Invalid hybrid ciphertext: Invalid ciphertext: KEM ciphertext truncated"

    async def test_batch_decrypt_route_reports_decryption_failed(self, crypto_client):
        blob = _truncated_inside_kem_ciphertext(_hybrid_blob())

        response = await crypto_client.post(
            "/api/v1/crypto/batch/decrypt",
            json={
                "context": "test-context",
                "items": [{"id": "truncated", "ciphertext": base64.b64encode(blob).decode("ascii")}],
            },
        )

        assert response.status_code == 200, response.text
        body = response.json()
        assert body["failed"] == 1
        assert body["results"] == [
            {"id": "truncated", "success": False, "plaintext": None, "error": "Decryption failed"}
        ]
