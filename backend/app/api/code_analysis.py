"""Code Analysis API routes.

Provides AST-based source code scanning for cryptographic detection.
"""

import base64
import hashlib
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File
from pydantic import BaseModel, Field
from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import User, SecurityScan, SecurityFinding, ScanType, SeverityLevel, FindingStatus
from app.core.code_scanner import (
    CodeScanner,
    CodeScannerError,
    Language,
)
from app.auth.jwt import get_dashboard_or_sdk_user


def compute_finding_fingerprint(target_name: str, file_path: str | None, algorithm: str | None, title: str, line_number: int | None) -> str:
    """Compute a fingerprint for deduplication across scans."""
    data = f"{target_name}|{file_path or ''}|{algorithm or ''}|{title}|{line_number or ''}"
    return hashlib.sha256(data.encode()).hexdigest()[:32]

router = APIRouter(prefix="/api/v1/code", tags=["code-analysis"])

# Singleton scanner
code_scanner = CodeScanner()


class CodeScanRequest(BaseModel):
    """Code scan request."""
    code: str = Field(..., description="Source code to analyze")
    language: str | None = Field(default=None, description="Language: python, javascript, go, java")
    filename: str | None = Field(default=None, description="Optional filename for context")
    persist: bool = Field(default=False, description="Persist results to security dashboard")
    target_name: str | None = Field(default=None, description="Target name for dashboard (e.g., 'crypto-serve-backend')")


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
    db: AsyncSession = Depends(get_db),
):
    """Scan source code for cryptographic usage.

    Uses AST analysis (where supported) for accurate detection of:
    - Cryptographic library imports and usage
    - Algorithm identification (encryption, hashing, signing, KDF, MAC)
    - Weak/broken algorithm detection
    - Quantum vulnerability assessment
    - Generates a Cryptographic Bill of Materials (CBOM)

    Set persist=true to save results to the security dashboard.
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

    # Persist to SecurityScan/SecurityFinding tables if requested
    if data.persist:
        target_name = data.target_name or data.filename or "code-scan"

        # Count by severity
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in result.findings:
            sev = f.severity.value.lower()
            if sev in severity_counts:
                severity_counts[sev] += 1

        # Count quantum vulnerable/safe from usages
        quantum_vulnerable = sum(1 for u in result.usages if u.quantum_risk.value in ["high", "critical"])
        quantum_safe = sum(1 for u in result.usages if u.quantum_risk.value in ["none", "low"])

        # Find previous OPEN findings for this target to compare
        previous_findings_result = await db.execute(
            select(SecurityFinding)
            .join(SecurityScan)
            .where(
                and_(
                    SecurityScan.tenant_id == user.tenant_id,
                    SecurityScan.target_name == target_name,
                    SecurityScan.scan_type == ScanType.CODE,
                    SecurityFinding.status == FindingStatus.OPEN,
                )
            )
        )
        previous_findings = {f.fingerprint: f for f in previous_findings_result.scalars().all() if f.fingerprint}

        # Create SecurityScan record
        scan_record = SecurityScan(
            tenant_id=user.tenant_id,
            user_id=user.id,
            scan_type=ScanType.CODE,
            target_name=target_name,
            target_type=data.language or "auto",
            total_findings=len(result.findings),
            critical_count=severity_counts["critical"],
            high_count=severity_counts["high"],
            medium_count=severity_counts["medium"],
            low_count=severity_counts["low"],
            quantum_vulnerable_count=quantum_vulnerable,
            quantum_safe_count=quantum_safe,
            weak_crypto_count=sum(1 for u in result.usages if u.is_weak),
            results={
                "cbom": {
                    "algorithms": result.cbom.algorithms,
                    "libraries": result.cbom.libraries,
                    "quantum_summary": result.cbom.quantum_summary,
                },
                "files_scanned": result.files_scanned,
                "scan_time_ms": result.scan_time_ms,
            }
        )
        db.add(scan_record)
        await db.flush()

        # Track new fingerprints to identify resolved issues
        new_fingerprints = set()

        # Create SecurityFinding records for each finding
        for f in result.findings:
            sev_str = f.severity.value.lower()
            try:
                severity = SeverityLevel(sev_str)
            except ValueError:
                severity = SeverityLevel.LOW

            fingerprint = compute_finding_fingerprint(target_name, f.file_path, f.algorithm, f.title, f.line_number)
            new_fingerprints.add(fingerprint)

            # Check if this is a recurring finding
            is_new = fingerprint not in previous_findings
            first_seen_scan_id = scan_record.id if is_new else previous_findings.get(fingerprint, None) and previous_findings[fingerprint].first_seen_scan_id

            finding_record = SecurityFinding(
                scan_id=scan_record.id,
                severity=severity,
                title=f.title,
                description=f.description,
                file_path=f.file_path,
                line_number=f.line_number,
                algorithm=f.algorithm,
                cwe=f.cwe,
                recommendation=f.recommendation,
                fingerprint=fingerprint,
                is_new=is_new,
                first_seen_scan_id=first_seen_scan_id or scan_record.id,
            )
            db.add(finding_record)

        # Also create findings for quantum-vulnerable usages (skip if already in findings)
        for u in result.usages:
            if u.quantum_risk.value in ["high", "critical"]:
                qr = u.quantum_risk.value.lower()
                severity = SeverityLevel.HIGH if qr == "high" else SeverityLevel.MEDIUM

                title = f"Quantum Vulnerable: {u.algorithm.upper()}"
                fingerprint = compute_finding_fingerprint(target_name, u.file_path, u.algorithm, title, u.line_number)

                # Skip if this fingerprint was already created from result.findings
                if fingerprint in new_fingerprints:
                    continue

                new_fingerprints.add(fingerprint)

                is_new = fingerprint not in previous_findings

                finding_record = SecurityFinding(
                    scan_id=scan_record.id,
                    severity=severity,
                    title=title,
                    description=f"Algorithm {u.algorithm} is vulnerable to quantum computing attacks",
                    file_path=u.file_path,
                    line_number=u.line_number,
                    algorithm=u.algorithm,
                    library=u.library,
                    quantum_risk=u.quantum_risk.value,
                    is_weak=u.is_weak,
                    cwe=u.cwe,
                    recommendation=u.recommendation or "Plan migration to post-quantum algorithms (ML-KEM, ML-DSA)",
                    fingerprint=fingerprint,
                    is_new=is_new,
                    first_seen_scan_id=scan_record.id if is_new else None,
                )
                db.add(finding_record)

        # Auto-resolve findings that were in previous scan but not in this one
        now = datetime.now(timezone.utc)
        for fingerprint, old_finding in previous_findings.items():
            if fingerprint not in new_fingerprints:
                old_finding.status = FindingStatus.RESOLVED
                old_finding.status_reason = "Auto-resolved: not found in latest scan"
                old_finding.status_updated_at = now

        await db.commit()

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


class CBOMExportRequest(BaseModel):
    """Request for CBOM export in various formats."""
    code: str = Field(..., description="Source code to analyze")
    language: str | None = Field(default=None, description="Language hint")
    filename: str | None = Field(default=None, description="Optional filename")
    format: str = Field(default="json", description="Export format: json, cyclonedx, spdx")
    identity_name: str = Field(default="Code Scan", description="Application identity name")


class PQCRecommendationRequest(BaseModel):
    """Request for PQC migration recommendations."""
    code: str = Field(..., description="Source code to analyze")
    language: str | None = Field(default=None, description="Language hint")
    data_profile: str | None = Field(
        default=None,
        description="Data sensitivity profile: healthcare, national_security, financial, general, short_lived"
    )


@router.post("/cbom/export")
async def export_cbom(
    data: CBOMExportRequest,
    user: Annotated[User, Depends(get_dashboard_or_sdk_user)],
):
    """Export CBOM in various formats.

    Supports:
    - json: Native CBOM format with full crypto details
    - cyclonedx: CycloneDX 1.5 SBOM format with crypto extensions
    - spdx: SPDX 2.3 format with CBOM annotations

    These formats are suitable for:
    - Integration with SBOM tools
    - Compliance reporting
    - Security audits
    """
    from app.core.cbom import cbom_service
    from app.core.crypto_inventory import (
        CryptoInventory,
        DetectedLibrary,
        DetectedAlgorithm,
        InventorySource,
        QuantumRisk,
    )

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

    # Convert code scan result to CryptoInventory for CBOM generation
    libraries = []
    lib_map = {}
    for lib_data in result.cbom.libraries:
        lib_name = lib_data.get("name", "unknown")
        if lib_name not in lib_map:
            quantum_risk_str = lib_data.get("quantum_risk", "none")
            lib_map[lib_name] = DetectedLibrary(
                name=lib_name,
                version=lib_data.get("version"),
                category=lib_data.get("category", "general"),
                algorithms=lib_data.get("algorithms", []),
                quantum_risk=QuantumRisk(quantum_risk_str) if quantum_risk_str else QuantumRisk.NONE,
                source=InventorySource.CODE_SCAN,
                is_deprecated=lib_data.get("is_deprecated", False),
            )
            libraries.append(lib_map[lib_name])

    algorithms = []
    for usage in result.usages:
        algorithms.append(DetectedAlgorithm(
            name=usage.algorithm,
            category=usage.category,
            library=usage.library,
            quantum_risk=usage.quantum_risk,
            is_weak=usage.is_weak,
            source=InventorySource.CODE_SCAN,
            weakness_reason=usage.weakness_reason,
        ))

    inventory = CryptoInventory(
        identity_id=f"code-scan-{result.cbom.scan_timestamp}",
        identity_name=data.identity_name,
        scan_timestamp=result.cbom.scan_timestamp,
        libraries=libraries,
        algorithms=algorithms,
        secrets_detected=[],
        quantum_summary=result.cbom.quantum_summary,
        risk_summary={
            "deprecated_libraries": sum(1 for lib in libraries if lib.is_deprecated),
            "weak_algorithms": sum(1 for algo in algorithms if algo.is_weak),
        },
        source=InventorySource.CODE_SCAN,
    )

    # Generate full CBOM
    cbom = cbom_service.generate_cbom(
        inventory,
        scan_source="code_scanner",
    )

    # Export in requested format
    if data.format == "cyclonedx":
        return cbom_service.to_cyclonedx(cbom)
    elif data.format == "spdx":
        return cbom_service.to_spdx(cbom)
    else:
        return cbom_service.to_json(cbom)


@router.post("/recommendations")
async def get_pqc_recommendations(
    data: PQCRecommendationRequest,
    user: Annotated[User, Depends(get_dashboard_or_sdk_user)],
):
    """Get PQC migration recommendations based on code analysis.

    Returns:
    - SNDL (Store Now, Decrypt Later) risk assessment
    - KEM and signature algorithm recommendations
    - Migration plan with priority steps
    - Quantum readiness score

    Data profiles affect urgency calculations:
    - healthcare: 100 year protection (HIPAA records)
    - national_security: 75 year protection
    - financial: 25 year protection (PCI-DSS)
    - general: 10 year protection
    - short_lived: 1 year protection (session tokens)
    """
    from app.core.pqc_recommendations import pqc_recommendation_service
    from app.core.crypto_inventory import (
        CryptoInventory,
        DetectedLibrary,
        DetectedAlgorithm,
        InventorySource,
        QuantumRisk,
    )

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

    # Convert to CryptoInventory
    libraries = []
    lib_map = {}
    for lib_data in result.cbom.libraries:
        lib_name = lib_data.get("name", "unknown")
        if lib_name not in lib_map:
            quantum_risk_str = lib_data.get("quantum_risk", "none")
            lib_map[lib_name] = DetectedLibrary(
                name=lib_name,
                version=lib_data.get("version"),
                category=lib_data.get("category", "general"),
                algorithms=lib_data.get("algorithms", []),
                quantum_risk=QuantumRisk(quantum_risk_str) if quantum_risk_str else QuantumRisk.NONE,
                source=InventorySource.CODE_SCAN,
                is_deprecated=lib_data.get("is_deprecated", False),
            )
            libraries.append(lib_map[lib_name])

    algorithms = []
    for usage in result.usages:
        algorithms.append(DetectedAlgorithm(
            name=usage.algorithm,
            category=usage.category,
            library=usage.library,
            quantum_risk=usage.quantum_risk,
            is_weak=usage.is_weak,
            source=InventorySource.CODE_SCAN,
            weakness_reason=usage.weakness_reason,
        ))

    inventory = CryptoInventory(
        identity_id="code-scan",
        identity_name="Code Scan",
        scan_timestamp=result.cbom.scan_timestamp,
        libraries=libraries,
        algorithms=algorithms,
        secrets_detected=[],
        quantum_summary=result.cbom.quantum_summary,
        risk_summary={
            "deprecated_libraries": sum(1 for lib in libraries if lib.is_deprecated),
            "weak_algorithms": sum(1 for algo in algorithms if algo.is_weak),
        },
        source=InventorySource.CODE_SCAN,
    )

    # Get recommendations
    recommendations = pqc_recommendation_service.recommend(
        inventory,
        data_profile=data.data_profile,
    )

    return recommendations.to_dict()
