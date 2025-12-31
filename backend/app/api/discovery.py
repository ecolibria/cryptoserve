"""Cryptographic Discovery API routes.

Provides binary scanning and cryptographic asset discovery.
"""

import base64
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import Identity
from app.core.binary_scanner import (
    BinaryScanner,
    ScanResult,
    CryptoFinding,
    ScannerError,
)
from app.api.crypto import get_sdk_identity

router = APIRouter(prefix="/api/v1/discovery", tags=["discovery"])

# Singleton scanner
binary_scanner = BinaryScanner()


class ScanRequest(BaseModel):
    """Binary scan request."""
    data: str = Field(..., description="Binary data to scan (base64 encoded)")
    filename: str | None = Field(default=None, description="Optional filename for context")
    include_entropy: bool = Field(default=True, description="Include entropy analysis")
    include_constants: bool = Field(default=True, description="Detect crypto constants")


class CryptoFindingResponse(BaseModel):
    """A cryptographic finding."""
    type: str = Field(..., description="Finding type (constant, entropy, pattern)")
    algorithm: str | None = Field(None, description="Detected algorithm if applicable")
    offset: int = Field(..., description="Byte offset in data")
    length: int = Field(..., description="Length of finding")
    confidence: float = Field(..., description="Confidence score 0.0-1.0")
    description: str
    severity: str = Field(..., description="Severity: info, low, medium, high, critical")
    cwe: str | None = Field(None, description="CWE identifier if applicable")
    recommendation: str | None = Field(None, description="Remediation recommendation")


class ScanResponse(BaseModel):
    """Binary scan response."""
    findings: list[CryptoFindingResponse]
    summary: dict
    scan_time_ms: float


class QuickScanResponse(BaseModel):
    """Quick scan summary response."""
    has_crypto: bool = Field(..., description="Whether cryptographic content was detected")
    algorithms_detected: list[str]
    risk_level: str = Field(..., description="Overall risk: none, low, medium, high")
    recommendation: str


@router.post("/scan", response_model=ScanResponse)
async def scan_binary(
    data: ScanRequest,
    identity: Annotated[Identity, Depends(get_sdk_identity)],
):
    """Scan binary data for cryptographic content.

    Detects:
    - Hardcoded cryptographic constants (S-boxes, IVs, magic numbers)
    - High-entropy regions (potential keys, random data)
    - Known weak algorithm patterns
    - Embedded certificates and keys

    Use for:
    - Security audits
    - Compliance checking (finding hardcoded secrets)
    - Cryptographic inventory
    """
    try:
        binary_data = base64.b64decode(data.data)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid base64 data",
        )

    try:
        result = binary_scanner.scan(
            data=binary_data,
            filename=data.filename,
            include_entropy=data.include_entropy,
            include_constants=data.include_constants,
        )
    except ScannerError as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

    return ScanResponse(
        findings=[
            CryptoFindingResponse(
                type=f.type,
                algorithm=f.algorithm,
                offset=f.offset,
                length=f.length,
                confidence=f.confidence,
                description=f.description,
                severity=f.severity,
                cwe=f.cwe,
                recommendation=f.recommendation,
            )
            for f in result.findings
        ],
        summary=result.summary,
        scan_time_ms=result.scan_time_ms,
    )


@router.post("/scan/quick", response_model=QuickScanResponse)
async def quick_scan(
    data: ScanRequest,
    identity: Annotated[Identity, Depends(get_sdk_identity)],
):
    """Quick scan for cryptographic content.

    Provides a fast yes/no answer on whether cryptographic content
    is present, with a risk assessment.
    """
    try:
        binary_data = base64.b64decode(data.data)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid base64 data",
        )

    try:
        result = binary_scanner.quick_scan(binary_data)
    except ScannerError as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

    return QuickScanResponse(
        has_crypto=result.has_crypto,
        algorithms_detected=result.algorithms_detected,
        risk_level=result.risk_level,
        recommendation=result.recommendation,
    )


@router.post("/scan/file")
async def scan_file(
    file: UploadFile = File(...),
    identity: Annotated[Identity, Depends(get_sdk_identity)] = None,
):
    """Scan an uploaded file for cryptographic content.

    Accepts any binary file and scans for:
    - Hardcoded keys and secrets
    - Cryptographic constants
    - Weak algorithms
    - Embedded certificates
    """
    if not identity:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)

    # Read file content
    content = await file.read()

    if len(content) > 50 * 1024 * 1024:  # 50MB limit
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="File too large (max 50MB)",
        )

    try:
        result = binary_scanner.scan(
            data=content,
            filename=file.filename,
            include_entropy=True,
            include_constants=True,
        )
    except ScannerError as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

    return {
        "filename": file.filename,
        "size_bytes": len(content),
        "findings": [
            {
                "type": f.type,
                "algorithm": f.algorithm,
                "offset": f.offset,
                "length": f.length,
                "confidence": f.confidence,
                "description": f.description,
                "severity": f.severity,
                "cwe": f.cwe,
                "recommendation": f.recommendation,
            }
            for f in result.findings
        ],
        "summary": result.summary,
        "scan_time_ms": result.scan_time_ms,
    }


@router.get("/algorithms")
async def list_detectable_algorithms(
    identity: Annotated[Identity, Depends(get_sdk_identity)],
):
    """List algorithms the scanner can detect.

    Returns the complete list of cryptographic algorithms
    and patterns the scanner can identify.
    """
    return binary_scanner.get_detectable_algorithms()
