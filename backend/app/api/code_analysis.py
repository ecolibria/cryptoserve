"""Code Analysis API routes.

Provides AST-based source code scanning for cryptographic detection.
"""

import base64
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File
from pydantic import BaseModel, Field

from app.models import User
from app.core.code_scanner import (
    CodeScanner,
    CodeScannerError,
    Language,
)
from app.auth.jwt import get_dashboard_or_sdk_user

router = APIRouter(prefix="/api/v1/code", tags=["code-analysis"])

# Singleton scanner
code_scanner = CodeScanner()


class CodeScanRequest(BaseModel):
    """Code scan request."""
    code: str = Field(..., description="Source code to analyze")
    language: str | None = Field(default=None, description="Language: python, javascript, go, java")
    filename: str | None = Field(default=None, description="Optional filename for context")


class CryptoUsageResponse(BaseModel):
    """A detected cryptographic usage."""
    algorithm: str
    category: str
    library: str
    function_call: str
    file_path: str
    line_number: int
    column: int
    confidence: float
    quantum_risk: str
    is_weak: bool
    weakness_reason: str | None = None
    recommendation: str | None = None
    cwe: str | None = None
    context: str | None = None


class CryptoFindingResponse(BaseModel):
    """A security finding."""
    severity: str
    title: str
    description: str
    file_path: str
    line_number: int
    algorithm: str | None = None
    cwe: str | None = None
    recommendation: str | None = None


class CBOMResponse(BaseModel):
    """Cryptographic Bill of Materials."""
    version: str
    scan_timestamp: str
    files_scanned: int
    algorithms: list[dict]
    libraries: list[dict]
    quantum_summary: dict
    findings_summary: dict


class CodeScanResponse(BaseModel):
    """Code scan response."""
    usages: list[CryptoUsageResponse]
    findings: list[CryptoFindingResponse]
    cbom: CBOMResponse
    files_scanned: int
    scan_time_ms: float


class DirectoryScanRequest(BaseModel):
    """Directory scan request."""
    path: str = Field(..., description="Directory path to scan")
    recursive: bool = Field(default=True, description="Scan subdirectories")
    exclude_patterns: list[str] | None = Field(
        default=None,
        description="Glob patterns to exclude (e.g., '**/node_modules/**')"
    )


class QuickAnalysisRequest(BaseModel):
    """Quick analysis request."""
    code: str = Field(..., description="Source code to analyze")
    language: str | None = Field(default=None, description="Language hint")


class QuickAnalysisResponse(BaseModel):
    """Quick analysis response."""
    has_crypto: bool = Field(..., description="Whether crypto operations were detected")
    algorithms: list[str] = Field(..., description="Algorithms detected")
    weak_algorithms: list[str] = Field(..., description="Weak/broken algorithms found")
    quantum_vulnerable: list[str] = Field(..., description="Quantum-vulnerable algorithms")
    risk_level: str = Field(..., description="Overall risk: none, low, medium, high, critical")
    recommendation: str


@router.post("/scan", response_model=CodeScanResponse)
async def scan_code(
    data: CodeScanRequest,
    user: Annotated[User, Depends(get_dashboard_or_sdk_user)],
):
    """Scan source code for cryptographic usage.

    Uses AST analysis (where supported) for accurate detection of:
    - Cryptographic library imports and usage
    - Algorithm identification (encryption, hashing, signing, KDF, MAC)
    - Weak/broken algorithm detection
    - Quantum vulnerability assessment
    - Generates a Cryptographic Bill of Materials (CBOM)

    Supported languages: Python (AST), JavaScript, TypeScript, Go, Java, C/C++
    """
    language = None
    if data.language:
        try:
            language = Language(data.language.lower())
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unsupported language: {data.language}. Use: python, javascript, go, java",
            )

    try:
        result = code_scanner.scan_code(
            code=data.code,
            language=language,
            filename=data.filename,
        )
    except CodeScannerError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    return CodeScanResponse(
        usages=[
            CryptoUsageResponse(
                algorithm=u.algorithm,
                category=u.category,
                library=u.library,
                function_call=u.function_call,
                file_path=u.file_path,
                line_number=u.line_number,
                column=u.column,
                confidence=u.confidence,
                quantum_risk=u.quantum_risk.value,
                is_weak=u.is_weak,
                weakness_reason=u.weakness_reason,
                recommendation=u.recommendation,
                cwe=u.cwe,
                context=u.context,
            )
            for u in result.usages
        ],
        findings=[
            CryptoFindingResponse(
                severity=f.severity.value,
                title=f.title,
                description=f.description,
                file_path=f.file_path,
                line_number=f.line_number,
                algorithm=f.algorithm,
                cwe=f.cwe,
                recommendation=f.recommendation,
            )
            for f in result.findings
        ],
        cbom=CBOMResponse(
            version=result.cbom.version,
            scan_timestamp=result.cbom.scan_timestamp,
            files_scanned=result.cbom.files_scanned,
            algorithms=result.cbom.algorithms,
            libraries=result.cbom.libraries,
            quantum_summary=result.cbom.quantum_summary,
            findings_summary=result.cbom.findings_summary,
        ),
        files_scanned=result.files_scanned,
        scan_time_ms=result.scan_time_ms,
    )


@router.post("/scan/quick", response_model=QuickAnalysisResponse)
async def quick_analysis(
    data: QuickAnalysisRequest,
    user: Annotated[User, Depends(get_dashboard_or_sdk_user)],
):
    """Quick code analysis for crypto detection.

    Returns a simple yes/no on crypto presence with risk assessment.
    Faster than full scan, ideal for CI/CD pipelines.
    """
    language = None
    if data.language:
        try:
            language = Language(data.language.lower())
        except ValueError:
            pass

    try:
        result = code_scanner.scan_code(code=data.code, language=language)
    except CodeScannerError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    algorithms = list(set(u.algorithm for u in result.usages))
    weak_algorithms = list(set(u.algorithm for u in result.usages if u.is_weak))
    quantum_vulnerable = list(set(
        u.algorithm for u in result.usages
        if u.quantum_risk.value in ["high", "critical"]
    ))

    # Determine risk level
    if any(f.severity.value == "critical" for f in result.findings):
        risk_level = "critical"
        recommendation = "Critical security issues found. Immediate remediation required."
    elif any(f.severity.value == "high" for f in result.findings):
        risk_level = "high"
        recommendation = "High-severity issues found. Replace weak algorithms."
    elif quantum_vulnerable:
        risk_level = "medium"
        recommendation = "Quantum-vulnerable algorithms detected. Plan migration to post-quantum."
    elif algorithms:
        risk_level = "low"
        recommendation = "Crypto usage detected. No immediate issues."
    else:
        risk_level = "none"
        recommendation = "No cryptographic operations detected."

    return QuickAnalysisResponse(
        has_crypto=len(algorithms) > 0,
        algorithms=algorithms,
        weak_algorithms=weak_algorithms,
        quantum_vulnerable=quantum_vulnerable,
        risk_level=risk_level,
        recommendation=recommendation,
    )


@router.post("/scan/file")
async def scan_file(
    file: UploadFile = File(...),
    user: Annotated[User, Depends(get_dashboard_or_sdk_user)] = None,
):
    """Scan an uploaded source file for cryptographic usage.

    Accepts any supported source file format.
    Automatically detects language from file extension.
    """
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)

    content = await file.read()

    if len(content) > 10 * 1024 * 1024:  # 10MB limit
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="File too large (max 10MB)",
        )

    try:
        code = content.decode("utf-8")
    except UnicodeDecodeError:
        try:
            code = content.decode("latin-1")
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Unable to decode file",
            )

    try:
        result = code_scanner.scan_code(code=code, filename=file.filename)
    except CodeScannerError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    return {
        "filename": file.filename,
        "size_bytes": len(content),
        "usages": [
            {
                "algorithm": u.algorithm,
                "category": u.category,
                "library": u.library,
                "line_number": u.line_number,
                "confidence": u.confidence,
                "quantum_risk": u.quantum_risk.value,
                "is_weak": u.is_weak,
                "weakness_reason": u.weakness_reason,
            }
            for u in result.usages
        ],
        "findings": [
            {
                "severity": f.severity.value,
                "title": f.title,
                "description": f.description,
                "line_number": f.line_number,
                "cwe": f.cwe,
            }
            for f in result.findings
        ],
        "cbom": {
            "algorithms": result.cbom.algorithms,
            "quantum_summary": result.cbom.quantum_summary,
            "findings_summary": result.cbom.findings_summary,
        },
        "scan_time_ms": result.scan_time_ms,
    }


@router.get("/languages")
async def list_supported_languages(
    user: Annotated[User, Depends(get_dashboard_or_sdk_user)],
):
    """List supported programming languages for code scanning."""
    return code_scanner.get_supported_languages()


@router.get("/algorithms")
async def list_detectable_algorithms(
    user: Annotated[User, Depends(get_dashboard_or_sdk_user)],
):
    """List all algorithms the scanner can detect.

    Includes classification info: category, quantum risk, weakness status.
    """
    return code_scanner.get_detectable_algorithms()


@router.post("/cbom", response_model=CBOMResponse)
async def generate_cbom(
    data: CodeScanRequest,
    user: Annotated[User, Depends(get_dashboard_or_sdk_user)],
):
    """Generate a Cryptographic Bill of Materials (CBOM).

    CBOM provides a complete inventory of:
    - All cryptographic algorithms in use
    - Libraries providing crypto functionality
    - Quantum vulnerability assessment
    - Security findings summary

    Use for:
    - Compliance audits (PCI-DSS, HIPAA, etc.)
    - Quantum readiness assessment
    - Cryptographic inventory management
    """
    language = None
    if data.language:
        try:
            language = Language(data.language.lower())
        except ValueError:
            pass

    try:
        result = code_scanner.scan_code(
            code=data.code,
            language=language,
            filename=data.filename,
        )
    except CodeScannerError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    return CBOMResponse(
        version=result.cbom.version,
        scan_timestamp=result.cbom.scan_timestamp,
        files_scanned=result.cbom.files_scanned,
        algorithms=result.cbom.algorithms,
        libraries=result.cbom.libraries,
        quantum_summary=result.cbom.quantum_summary,
        findings_summary=result.cbom.findings_summary,
    )
