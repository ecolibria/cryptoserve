#!/usr/bin/env python3
"""
FastAPI Integration Example

Demonstrates integrating CryptoServe with a FastAPI web application.
"""

from typing import Optional
from datetime import datetime
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field, EmailStr

from cryptoserve import CryptoServe

# Initialize CryptoServe globally
crypto = CryptoServe(
    app_name="fastapi-example",
    team="examples",
    environment="development",
)


# Lifespan context manager for startup/shutdown
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: verify connection
    if not crypto.health_check():
        raise RuntimeError("CryptoServe not available")
    print("CryptoServe connected successfully")
    yield
    # Shutdown: cleanup
    print("Shutting down...")


app = FastAPI(
    title="CryptoServe FastAPI Example",
    description="Example API with field-level encryption using CryptoServe",
    version="1.0.0",
    lifespan=lifespan,
)


# =============================================================================
# Models
# =============================================================================


class UserCreate(BaseModel):
    """Request model for creating a user."""
    email: EmailStr
    name: str = Field(..., min_length=1, max_length=100)
    ssn: str = Field(..., pattern=r"^\d{3}-\d{2}-\d{4}$", description="SSN in XXX-XX-XXXX format")
    credit_card: Optional[str] = Field(None, pattern=r"^\d{16}$")


class UserResponse(BaseModel):
    """Response model for user data (encrypted fields masked)."""
    id: str
    email: str
    name: str
    ssn_encrypted: bool = True
    credit_card_encrypted: bool = False
    created_at: datetime


class UserPrivateResponse(BaseModel):
    """Response model with decrypted sensitive data."""
    id: str
    email: str
    name: str
    ssn: str
    credit_card: Optional[str]
    created_at: datetime


class DocumentCreate(BaseModel):
    """Request model for creating a document."""
    title: str
    content: str
    classification: str = Field("confidential", pattern="^(public|internal|confidential|secret)$")


class DocumentResponse(BaseModel):
    """Response model for document."""
    id: str
    title: str
    content_encrypted: bool = True
    classification: str
    signature: str
    created_at: datetime


class VerifyRequest(BaseModel):
    """Request model for signature verification."""
    document_id: str
    content: str
    signature: str


# =============================================================================
# Simulated Database
# =============================================================================


users_db: dict[str, dict] = {}
documents_db: dict[str, dict] = {}


# =============================================================================
# Dependencies
# =============================================================================


security = HTTPBearer()


async def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Verify JWT token (simplified for example)."""
    if credentials.credentials != "demo-token":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
        )
    return {"user_id": "demo-user"}


# =============================================================================
# User Endpoints
# =============================================================================


@app.post("/users", response_model=UserResponse, tags=["Users"])
async def create_user(user: UserCreate):
    """
    Create a new user with encrypted PII.

    Sensitive fields (SSN, credit card) are automatically encrypted
    before storage using CryptoServe.
    """
    import uuid

    user_id = f"user_{uuid.uuid4().hex[:8]}"

    # Encrypt sensitive fields
    encrypted_ssn = crypto.encrypt_string(user.ssn, context="user-pii")
    encrypted_cc = None
    if user.credit_card:
        encrypted_cc = crypto.encrypt_string(user.credit_card, context="payment-data")

    # Store in database
    users_db[user_id] = {
        "id": user_id,
        "email": user.email,
        "name": user.name,
        "ssn_encrypted": encrypted_ssn,
        "credit_card_encrypted": encrypted_cc,
        "created_at": datetime.utcnow(),
    }

    return UserResponse(
        id=user_id,
        email=user.email,
        name=user.name,
        ssn_encrypted=True,
        credit_card_encrypted=encrypted_cc is not None,
        created_at=users_db[user_id]["created_at"],
    )


@app.get("/users/{user_id}", response_model=UserResponse, tags=["Users"])
async def get_user(user_id: str):
    """Get user by ID (sensitive fields remain encrypted)."""
    if user_id not in users_db:
        raise HTTPException(status_code=404, detail="User not found")

    user = users_db[user_id]
    return UserResponse(
        id=user["id"],
        email=user["email"],
        name=user["name"],
        ssn_encrypted=True,
        credit_card_encrypted=user["credit_card_encrypted"] is not None,
        created_at=user["created_at"],
    )


@app.get("/users/{user_id}/private", response_model=UserPrivateResponse, tags=["Users"])
async def get_user_private(user_id: str, _: dict = Depends(verify_token)):
    """
    Get user with decrypted sensitive data.

    Requires authentication. Decrypts SSN and credit card for authorized access.
    """
    if user_id not in users_db:
        raise HTTPException(status_code=404, detail="User not found")

    user = users_db[user_id]

    # Decrypt sensitive fields
    ssn = crypto.decrypt_string(user["ssn_encrypted"], context="user-pii")
    credit_card = None
    if user["credit_card_encrypted"]:
        credit_card = crypto.decrypt_string(user["credit_card_encrypted"], context="payment-data")

    return UserPrivateResponse(
        id=user["id"],
        email=user["email"],
        name=user["name"],
        ssn=ssn,
        credit_card=credit_card,
        created_at=user["created_at"],
    )


# =============================================================================
# Document Endpoints
# =============================================================================


@app.post("/documents", response_model=DocumentResponse, tags=["Documents"])
async def create_document(doc: DocumentCreate, _: dict = Depends(verify_token)):
    """
    Create a signed and encrypted document.

    Content is encrypted and digitally signed for integrity verification.
    """
    import uuid

    doc_id = f"doc_{uuid.uuid4().hex[:8]}"

    # Encrypt content
    encrypted_content = crypto.encrypt_string(doc.content, context="documents")

    # Sign the original content for integrity
    signature = crypto.sign(doc.content.encode(), key_id="document-signing")

    documents_db[doc_id] = {
        "id": doc_id,
        "title": doc.title,
        "content_encrypted": encrypted_content,
        "classification": doc.classification,
        "signature": signature.hex(),
        "created_at": datetime.utcnow(),
    }

    return DocumentResponse(
        id=doc_id,
        title=doc.title,
        content_encrypted=True,
        classification=doc.classification,
        signature=signature.hex()[:32] + "...",
        created_at=documents_db[doc_id]["created_at"],
    )


@app.get("/documents/{doc_id}/content", tags=["Documents"])
async def get_document_content(doc_id: str, _: dict = Depends(verify_token)):
    """Get decrypted document content."""
    if doc_id not in documents_db:
        raise HTTPException(status_code=404, detail="Document not found")

    doc = documents_db[doc_id]
    content = crypto.decrypt_string(doc["content_encrypted"], context="documents")

    return {
        "id": doc["id"],
        "title": doc["title"],
        "content": content,
        "classification": doc["classification"],
    }


@app.post("/documents/verify", tags=["Documents"])
async def verify_document(req: VerifyRequest):
    """
    Verify document signature.

    Checks if the provided content matches the original signed document.
    """
    if req.document_id not in documents_db:
        raise HTTPException(status_code=404, detail="Document not found")

    doc = documents_db[req.document_id]

    # Verify signature
    is_valid = crypto.verify_signature(
        req.content.encode(),
        bytes.fromhex(doc["signature"]),
        key_id="document-signing"
    )

    return {
        "document_id": req.document_id,
        "signature_valid": is_valid,
        "message": "Document integrity verified" if is_valid else "Document has been modified",
    }


# =============================================================================
# Health Endpoint
# =============================================================================


@app.get("/health", tags=["Health"])
async def health_check():
    """Check service and CryptoServe health."""
    crypto_healthy = crypto.health_check()
    return {
        "status": "healthy" if crypto_healthy else "degraded",
        "cryptoserve": "connected" if crypto_healthy else "disconnected",
        "timestamp": datetime.utcnow().isoformat(),
    }


# =============================================================================
# Main
# =============================================================================


if __name__ == "__main__":
    import uvicorn

    print("CryptoServe FastAPI Integration Example")
    print("=" * 50)
    print("\nStarting server...")
    print("API docs: http://localhost:8080/docs")
    print("\nExample requests:")
    print("  curl -X POST http://localhost:8080/users \\")
    print('    -H "Content-Type: application/json" \\')
    print('    -d \'{"email":"john@example.com","name":"John","ssn":"123-45-6789"}\'')
    print()

    uvicorn.run(app, host="0.0.0.0", port=8080)
