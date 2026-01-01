"""Crypto Inventory and Policy Enforcement API.

Endpoints for:
- Receiving crypto inventory reports from SDK
- Evaluating inventory against policies
- CI/CD deployment gate checks
- Admin overview of crypto usage across org
"""

from datetime import datetime, timezone
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import Identity
from app.models.crypto_inventory import (
    CryptoInventoryReport,
    CryptoLibraryUsage,
    EnforcementAction as DBEnforcementAction,
    ScanSource,
    QuantumRisk as DBQuantumRisk,
)
from app.core.crypto_inventory import (
    CryptoInventory,
    DetectedLibrary,
    DetectedAlgorithm,
    InventorySource,
    QuantumRisk,
)
from app.core.policy_enforcement import (
    policy_enforcement_service,
    EnforcementResult,
    EnforcementAction,
)
from app.core.cbom import cbom_service
from app.core.pqc_recommendations import (
    pqc_recommendation_service,
    DataProfile,
)

router = APIRouter(prefix="/api/v1/inventory", tags=["inventory"])


# =============================================================================
# Request/Response Models
# =============================================================================


class DetectedLibraryRequest(BaseModel):
    """A detected cryptographic library from SDK."""
    name: str
    version: str | None = None
    category: str
    algorithms: list[str] = Field(default_factory=list)
    quantum_risk: str = "none"
    is_deprecated: bool = False
    deprecation_reason: str | None = None


class InventoryReportRequest(BaseModel):
    """Inventory report from SDK initialization."""
    identity_id: str
    identity_name: str
    libraries: list[DetectedLibraryRequest] = Field(default_factory=list)
    algorithms: list[dict] = Field(default_factory=list)
    scan_source: str = "sdk_init"
    # Optional CI/CD metadata
    git_commit: str | None = None
    git_branch: str | None = None
    git_repo: str | None = None
    environment: str | None = None
    python_version: str | None = None


class CICDGateRequest(BaseModel):
    """CI/CD gate check request."""
    identity_id: str
    identity_name: str
    libraries: list[DetectedLibraryRequest] = Field(default_factory=list)
    # CI/CD specific fields
    git_commit: str
    git_branch: str
    git_repo: str | None = None
    environment: str = "production"
    fail_on: str = "violations"  # violations, warnings, none


class PolicyViolationResponse(BaseModel):
    """A policy violation in the response."""
    violation_type: str
    severity: str
    policy_name: str
    message: str
    details: dict[str, Any] = Field(default_factory=dict)
    library: str | None = None
    algorithm: str | None = None
    recommendation: str | None = None


class EnforcementResultResponse(BaseModel):
    """Policy enforcement result response."""
    report_id: int | None = None  # ID for tracking
    action: str  # allow, warn, block
    violations: list[PolicyViolationResponse]
    warnings: list[PolicyViolationResponse]
    info: list[PolicyViolationResponse]
    summary: dict[str, Any]
    evaluated_at: str
    identity_id: str | None = None
    identity_name: str | None = None
    quantum_readiness_score: float | None = None


class CICDGateResponse(BaseModel):
    """CI/CD gate response with pass/fail status."""
    passed: bool
    report_id: int
    action: str
    exit_code: int  # 0 = pass, 1 = blocked
    violations: list[PolicyViolationResponse]
    warnings: list[PolicyViolationResponse]
    message: str
    quantum_readiness_score: float
    # Links for CI output
    dashboard_url: str | None = None


# =============================================================================
# SDK Inventory Endpoint
# =============================================================================


@router.post("/report", response_model=EnforcementResultResponse)
async def report_inventory(
    request: InventoryReportRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """
    Receive and evaluate a crypto inventory report from SDK.

    This endpoint is called by the SDK during initialization when
    crypto detection is enabled.

    Returns policy enforcement results with:
    - violations: Blocking issues (deprecated libraries, weak algorithms)
    - warnings: Non-blocking concerns (quantum vulnerability)
    - info: Recommendations (add PQC support)
    """
    # Convert request to internal models
    libraries = [
        DetectedLibrary(
            name=lib.name,
            version=lib.version,
            category=lib.category,
            algorithms=lib.algorithms,
            quantum_risk=QuantumRisk(lib.quantum_risk),
            source=InventorySource(request.scan_source if request.scan_source in ["import_scan", "sdk_init"] else "import_scan"),
            is_deprecated=lib.is_deprecated,
            deprecation_reason=lib.deprecation_reason,
        )
        for lib in request.libraries
    ]

    # Build algorithms from libraries
    algorithms = [
        DetectedAlgorithm(
            name=algo,
            category=lib.category,
            library=lib.name,
            quantum_risk=QuantumRisk(lib.quantum_risk),
            is_weak=False,
            source=InventorySource("import_scan"),
        )
        for lib in request.libraries
        for algo in lib.algorithms
    ]

    # Build quantum summary
    quantum_safe = sum(1 for lib in libraries if lib.quantum_risk == QuantumRisk.NONE)
    quantum_vulnerable = sum(1 for lib in libraries if lib.quantum_risk in [QuantumRisk.HIGH, QuantumRisk.CRITICAL])
    has_pqc = any(lib.category == "pqc" for lib in libraries)
    deprecated_count = sum(1 for lib in libraries if lib.is_deprecated)

    quantum_summary = {
        "total_libraries": len(libraries),
        "quantum_safe": quantum_safe,
        "quantum_vulnerable": quantum_vulnerable,
        "has_pqc": has_pqc,
    }

    risk_summary = {
        "deprecated_libraries": deprecated_count,
        "weak_algorithms": sum(1 for algo in algorithms if algo.is_weak),
    }

    inventory = CryptoInventory(
        identity_id=request.identity_id,
        identity_name=request.identity_name,
        scan_timestamp=datetime.now(timezone.utc).isoformat(),
        libraries=libraries,
        algorithms=algorithms,
        secrets_detected=[],
        quantum_summary=quantum_summary,
        risk_summary=risk_summary,
        source=InventorySource("import_scan"),
    )

    # Evaluate against policies
    result = policy_enforcement_service.evaluate_inventory(inventory)

    # Get identity info for team/department
    identity_result = await db.execute(
        select(Identity).where(Identity.id == request.identity_id)
    )
    identity = identity_result.scalar_one_or_none()
    team = identity.team if identity else None

    # Store in database
    report = CryptoInventoryReport(
        identity_id=request.identity_id,
        identity_name=request.identity_name,
        team=team,
        scan_source=ScanSource.SDK_INIT,
        action=DBEnforcementAction(result.action.value),
        library_count=len(libraries),
        algorithm_count=len(algorithms),
        violation_count=len(result.violations),
        warning_count=len(result.warnings),
        quantum_safe_count=quantum_safe,
        quantum_vulnerable_count=quantum_vulnerable,
        has_pqc=has_pqc,
        deprecated_count=deprecated_count,
        libraries=[{"name": lib.name, "version": lib.version, "category": lib.category, "algorithms": lib.algorithms, "quantum_risk": lib.quantum_risk.value, "is_deprecated": lib.is_deprecated} for lib in libraries],
        algorithms=[{"name": algo.name, "category": algo.category, "library": algo.library} for algo in algorithms],
        violations=[{"type": v.violation_type.value, "severity": v.severity.value, "message": v.message, "library": v.library} for v in result.violations],
        warnings=[{"type": w.violation_type.value, "severity": w.severity.value, "message": w.message, "library": w.library} for w in result.warnings],
        environment=request.environment,
        python_version=request.python_version,
        git_commit=request.git_commit,
        git_branch=request.git_branch,
        git_repo=request.git_repo,
    )
    db.add(report)
    await db.commit()
    await db.refresh(report)

    # Update library usage aggregates
    await _update_library_usage(db, libraries, request.identity_id, team)

    # Convert to response
    response = _enforcement_result_to_response(result)
    response.report_id = report.id
    response.quantum_readiness_score = report.quantum_readiness_score
    return response


# =============================================================================
# CI/CD Gate Endpoint
# =============================================================================


@router.post("/gate", response_model=CICDGateResponse)
async def cicd_gate(
    request: CICDGateRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """
    CI/CD deployment gate check.

    This endpoint is designed for CI/CD pipelines to check crypto policy
    compliance before deployment. Returns a clear pass/fail with exit code.

    Usage in GitHub Actions:
        - name: Crypto Policy Gate
          run: |
            result=$(curl -X POST $CRYPTOSERVE_URL/api/v1/inventory/gate ...)
            exit_code=$(echo $result | jq -r '.exit_code')
            exit $exit_code

    Args:
        fail_on: What triggers failure
            - "violations": Fail on blocking violations only (deprecated, weak)
            - "warnings": Fail on warnings too (quantum vulnerability)
            - "none": Never fail (just report)
    """
    # Convert request to internal models
    libraries = [
        DetectedLibrary(
            name=lib.name,
            version=lib.version,
            category=lib.category,
            algorithms=lib.algorithms,
            quantum_risk=QuantumRisk(lib.quantum_risk),
            source=InventorySource("code_scan"),
            is_deprecated=lib.is_deprecated,
            deprecation_reason=lib.deprecation_reason,
        )
        for lib in request.libraries
    ]

    algorithms = [
        DetectedAlgorithm(
            name=algo,
            category=lib.category,
            library=lib.name,
            quantum_risk=QuantumRisk(lib.quantum_risk),
            is_weak=False,
            source=InventorySource("code_scan"),
        )
        for lib in request.libraries
        for algo in lib.algorithms
    ]

    # Calculate metrics
    quantum_safe = sum(1 for lib in libraries if lib.quantum_risk == QuantumRisk.NONE)
    quantum_vulnerable = sum(1 for lib in libraries if lib.quantum_risk in [QuantumRisk.HIGH, QuantumRisk.CRITICAL])
    has_pqc = any(lib.category == "pqc" for lib in libraries)
    deprecated_count = sum(1 for lib in libraries if lib.is_deprecated)

    inventory = CryptoInventory(
        identity_id=request.identity_id,
        identity_name=request.identity_name,
        scan_timestamp=datetime.now(timezone.utc).isoformat(),
        libraries=libraries,
        algorithms=algorithms,
        secrets_detected=[],
        quantum_summary={
            "total_libraries": len(libraries),
            "quantum_safe": quantum_safe,
            "quantum_vulnerable": quantum_vulnerable,
            "has_pqc": has_pqc,
        },
        risk_summary={"deprecated_libraries": deprecated_count, "weak_algorithms": 0},
        source=InventorySource("code_scan"),
    )

    # Evaluate against policies
    result = policy_enforcement_service.evaluate_inventory(inventory)

    # Get identity info
    identity_result = await db.execute(
        select(Identity).where(Identity.id == request.identity_id)
    )
    identity = identity_result.scalar_one_or_none()
    team = identity.team if identity else None

    # Determine pass/fail based on fail_on setting
    passed = True
    exit_code = 0

    if request.fail_on == "violations":
        if result.action == EnforcementAction.BLOCK:
            passed = False
            exit_code = 1
    elif request.fail_on == "warnings":
        if result.action in [EnforcementAction.BLOCK, EnforcementAction.WARN]:
            passed = False
            exit_code = 1
    # fail_on == "none" always passes

    # Store in database
    report = CryptoInventoryReport(
        identity_id=request.identity_id,
        identity_name=request.identity_name,
        team=team,
        scan_source=ScanSource.CICD_GATE,
        action=DBEnforcementAction(result.action.value),
        library_count=len(libraries),
        algorithm_count=len(algorithms),
        violation_count=len(result.violations),
        warning_count=len(result.warnings),
        quantum_safe_count=quantum_safe,
        quantum_vulnerable_count=quantum_vulnerable,
        has_pqc=has_pqc,
        deprecated_count=deprecated_count,
        libraries=[{"name": lib.name, "version": lib.version, "category": lib.category, "algorithms": lib.algorithms, "quantum_risk": lib.quantum_risk.value, "is_deprecated": lib.is_deprecated} for lib in libraries],
        algorithms=[{"name": algo.name, "category": algo.category, "library": algo.library} for algo in algorithms],
        violations=[{"type": v.violation_type.value, "severity": v.severity.value, "message": v.message, "library": v.library} for v in result.violations],
        warnings=[{"type": w.violation_type.value, "severity": w.severity.value, "message": w.message, "library": w.library} for w in result.warnings],
        environment=request.environment,
        git_commit=request.git_commit,
        git_branch=request.git_branch,
        git_repo=request.git_repo,
    )
    db.add(report)
    await db.commit()
    await db.refresh(report)

    # Build message
    if passed:
        if result.warnings:
            message = f"Passed with {len(result.warnings)} warning(s)"
        else:
            message = "All crypto policy checks passed"
    else:
        message = f"Blocked: {len(result.violations)} violation(s) found"

    return CICDGateResponse(
        passed=passed,
        report_id=report.id,
        action=result.action.value,
        exit_code=exit_code,
        violations=[
            PolicyViolationResponse(
                violation_type=v.violation_type.value,
                severity=v.severity.value,
                policy_name=v.policy_name,
                message=v.message,
                details=v.details,
                library=v.library,
                algorithm=v.algorithm,
                recommendation=v.recommendation,
            )
            for v in result.violations
        ],
        warnings=[
            PolicyViolationResponse(
                violation_type=v.violation_type.value,
                severity=v.severity.value,
                policy_name=v.policy_name,
                message=v.message,
                details=v.details,
                library=v.library,
                algorithm=v.algorithm,
                recommendation=v.recommendation,
            )
            for v in result.warnings
        ],
        message=message,
        quantum_readiness_score=report.quantum_readiness_score,
        dashboard_url=f"/dashboard/reports/{report.id}",
    )


# =============================================================================
# Policy Info Endpoint
# =============================================================================


@router.get("/policies", response_model=dict)
async def get_enforcement_policies():
    """
    Get summary of crypto inventory policies.

    Returns all policies used for evaluating detected crypto libraries
    and algorithms.
    """
    return policy_enforcement_service.get_policy_summary()


# =============================================================================
# History Endpoints
# =============================================================================


@router.get("/history/{identity_id}")
async def get_inventory_history(
    identity_id: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    limit: int = 10,
):
    """
    Get inventory report history for an identity.

    Returns recent scans with quantum readiness scores over time.
    """
    result = await db.execute(
        select(CryptoInventoryReport)
        .where(CryptoInventoryReport.identity_id == identity_id)
        .order_by(CryptoInventoryReport.scanned_at.desc())
        .limit(limit)
    )
    reports = result.scalars().all()

    return {
        "identity_id": identity_id,
        "total_reports": len(reports),
        "reports": [
            {
                "id": r.id,
                "scanned_at": r.scanned_at.isoformat(),
                "scan_source": r.scan_source.value,
                "action": r.action.value,
                "library_count": r.library_count,
                "violation_count": r.violation_count,
                "warning_count": r.warning_count,
                "quantum_readiness_score": r.quantum_readiness_score,
                "has_pqc": r.has_pqc,
                "git_commit": r.git_commit,
                "git_branch": r.git_branch,
            }
            for r in reports
        ],
    }


@router.get("/report/{report_id}")
async def get_inventory_report(
    report_id: int,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Get a specific inventory report by ID."""
    result = await db.execute(
        select(CryptoInventoryReport).where(CryptoInventoryReport.id == report_id)
    )
    report = result.scalar_one_or_none()

    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    return {
        "id": report.id,
        "identity_id": report.identity_id,
        "identity_name": report.identity_name,
        "team": report.team,
        "department": report.department,
        "scanned_at": report.scanned_at.isoformat(),
        "scan_source": report.scan_source.value,
        "action": report.action.value,
        "quantum_readiness_score": report.quantum_readiness_score,
        "libraries": report.libraries,
        "algorithms": report.algorithms,
        "violations": report.violations,
        "warnings": report.warnings,
        "metrics": {
            "library_count": report.library_count,
            "algorithm_count": report.algorithm_count,
            "violation_count": report.violation_count,
            "warning_count": report.warning_count,
            "quantum_safe_count": report.quantum_safe_count,
            "quantum_vulnerable_count": report.quantum_vulnerable_count,
            "has_pqc": report.has_pqc,
            "deprecated_count": report.deprecated_count,
        },
        "git": {
            "commit": report.git_commit,
            "branch": report.git_branch,
            "repo": report.git_repo,
        },
        "environment": report.environment,
        "python_version": report.python_version,
    }


# =============================================================================
# Helper Functions
# =============================================================================


def _enforcement_result_to_response(result: EnforcementResult) -> EnforcementResultResponse:
    """Convert EnforcementResult to response model."""
    return EnforcementResultResponse(
        action=result.action.value,
        violations=[
            PolicyViolationResponse(
                violation_type=v.violation_type.value,
                severity=v.severity.value,
                policy_name=v.policy_name,
                message=v.message,
                details=v.details,
                library=v.library,
                algorithm=v.algorithm,
                recommendation=v.recommendation,
            )
            for v in result.violations
        ],
        warnings=[
            PolicyViolationResponse(
                violation_type=v.violation_type.value,
                severity=v.severity.value,
                policy_name=v.policy_name,
                message=v.message,
                details=v.details,
                library=v.library,
                algorithm=v.algorithm,
                recommendation=v.recommendation,
            )
            for v in result.warnings
        ],
        info=[
            PolicyViolationResponse(
                violation_type=v.violation_type.value,
                severity=v.severity.value,
                policy_name=v.policy_name,
                message=v.message,
                details=v.details,
                library=v.library,
                algorithm=v.algorithm,
                recommendation=v.recommendation,
            )
            for v in result.info
        ],
        summary=result.summary,
        evaluated_at=result.evaluated_at,
        identity_id=result.identity_id,
        identity_name=result.identity_name,
    )


async def _update_library_usage(
    db: AsyncSession,
    libraries: list[DetectedLibrary],
    identity_id: str,
    team: str | None,
):
    """Update aggregate library usage stats."""
    for lib in libraries:
        # Check if library usage record exists
        result = await db.execute(
            select(CryptoLibraryUsage).where(
                CryptoLibraryUsage.library_name == lib.name,
                CryptoLibraryUsage.library_version == lib.version,
            )
        )
        usage = result.scalar_one_or_none()

        if usage:
            # Update existing record
            if identity_id not in usage.identity_ids:
                usage.identity_ids = usage.identity_ids + [identity_id]
                usage.app_count = len(set(usage.identity_ids))
            usage.last_seen_at = datetime.now(timezone.utc)
        else:
            # Create new record
            usage = CryptoLibraryUsage(
                library_name=lib.name,
                library_version=lib.version,
                category=lib.category,
                quantum_risk=DBQuantumRisk(lib.quantum_risk.value),
                is_deprecated=lib.is_deprecated,
                app_count=1,
                team_count=1 if team else 0,
                identity_ids=[identity_id],
            )
            db.add(usage)

    await db.commit()


# =============================================================================
# CBOM Export Endpoints
# =============================================================================


@router.get("/report/{report_id}/cbom")
async def export_cbom(
    report_id: int,
    db: Annotated[AsyncSession, Depends(get_db)],
    format: str = "json",
):
    """
    Export inventory report as CBOM (Cryptographic Bill of Materials).

    Supports multiple export formats:
    - json: Native CBOM JSON format with full crypto details
    - cyclonedx: CycloneDX 1.5 SBOM format with crypto extensions
    - spdx: SPDX 2.3 format with crypto annotations

    CBOM is like SBOM but focused on cryptographic components,
    enabling organizations to track and manage their crypto inventory.
    """
    result = await db.execute(
        select(CryptoInventoryReport).where(CryptoInventoryReport.id == report_id)
    )
    report = result.scalar_one_or_none()

    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    # Reconstruct inventory from stored data
    libraries = [
        DetectedLibrary(
            name=lib["name"],
            version=lib.get("version"),
            category=lib["category"],
            algorithms=lib.get("algorithms", []),
            quantum_risk=QuantumRisk(lib.get("quantum_risk", "none")),
            source=InventorySource.IMPORT_SCAN,
            is_deprecated=lib.get("is_deprecated", False),
        )
        for lib in report.libraries
    ]

    algorithms = [
        DetectedAlgorithm(
            name=algo["name"],
            category=algo["category"],
            library=algo["library"],
            quantum_risk=QuantumRisk("none"),
            is_weak=False,
            source=InventorySource.IMPORT_SCAN,
        )
        for algo in report.algorithms
    ]

    inventory = CryptoInventory(
        identity_id=report.identity_id,
        identity_name=report.identity_name,
        scan_timestamp=report.scanned_at.isoformat(),
        libraries=libraries,
        algorithms=algorithms,
        secrets_detected=[],
        quantum_summary={
            "total_libraries": report.library_count,
            "quantum_safe": report.quantum_safe_count,
            "quantum_vulnerable": report.quantum_vulnerable_count,
            "has_pqc": report.has_pqc,
        },
        risk_summary={
            "deprecated_libraries": report.deprecated_count,
            "weak_algorithms": 0,
        },
        source=InventorySource.IMPORT_SCAN,
    )

    # Generate CBOM
    cbom = cbom_service.generate_cbom(
        inventory=inventory,
        team=report.team,
        department=report.department,
        git_info={
            "commit": report.git_commit,
            "branch": report.git_branch,
            "repo": report.git_repo,
        },
        scan_source=report.scan_source.value,
    )

    # Export in requested format
    if format == "cyclonedx":
        return cbom_service.to_cyclonedx(cbom)
    elif format == "spdx":
        return cbom_service.to_spdx(cbom)
    else:
        return cbom_service.to_json(cbom)


# =============================================================================
# PQC Recommendations Endpoints
# =============================================================================


@router.get("/report/{report_id}/recommendations")
async def get_pqc_recommendations(
    report_id: int,
    db: Annotated[AsyncSession, Depends(get_db)],
    data_profile: str | None = None,
):
    """
    Get PQC (Post-Quantum Cryptography) migration recommendations.

    Analyzes the crypto inventory and provides:
    - SNDL (Store Now, Decrypt Later) risk assessment
    - Recommended PQC algorithms (ML-KEM, ML-DSA)
    - Step-by-step migration plan
    - Priority-ordered next steps

    Optional data_profile parameter for SNDL analysis:
    - national_security: 75-year confidentiality (CRITICAL urgency)
    - healthcare_records: Lifetime confidentiality (CRITICAL)
    - financial_long_term: 25-year confidentiality (HIGH)
    - intellectual_property: 20-year confidentiality (HIGH)
    - personal_data: 10-year confidentiality (MEDIUM) [default]
    - authentication_credentials: 1-year confidentiality (MEDIUM)
    - ephemeral_communications: Short-term (LOW)
    """
    result = await db.execute(
        select(CryptoInventoryReport).where(CryptoInventoryReport.id == report_id)
    )
    report = result.scalar_one_or_none()

    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    # Reconstruct inventory from stored data
    libraries = [
        DetectedLibrary(
            name=lib["name"],
            version=lib.get("version"),
            category=lib["category"],
            algorithms=lib.get("algorithms", []),
            quantum_risk=QuantumRisk(lib.get("quantum_risk", "none")),
            source=InventorySource.IMPORT_SCAN,
            is_deprecated=lib.get("is_deprecated", False),
        )
        for lib in report.libraries
    ]

    algorithms = [
        DetectedAlgorithm(
            name=algo["name"],
            category=algo["category"],
            library=algo["library"],
            quantum_risk=QuantumRisk("none"),
            is_weak=False,
            source=InventorySource.IMPORT_SCAN,
        )
        for algo in report.algorithms
    ]

    inventory = CryptoInventory(
        identity_id=report.identity_id,
        identity_name=report.identity_name,
        scan_timestamp=report.scanned_at.isoformat(),
        libraries=libraries,
        algorithms=algorithms,
        secrets_detected=[],
        quantum_summary={
            "total_libraries": report.library_count,
            "quantum_safe": report.quantum_safe_count,
            "quantum_vulnerable": report.quantum_vulnerable_count,
            "has_pqc": report.has_pqc,
        },
        risk_summary={
            "deprecated_libraries": report.deprecated_count,
            "weak_algorithms": 0,
        },
        source=InventorySource.IMPORT_SCAN,
    )

    # Parse data profile if provided
    profile = None
    if data_profile:
        try:
            profile = DataProfile(data_profile)
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid data_profile. Valid options: {[p.value for p in DataProfile]}"
            )

    # Generate recommendations
    recommendations = pqc_recommendation_service.recommend(inventory, profile)

    # Store recommendations in report for future reference
    report.pqc_recommendations = recommendations.to_dict()
    await db.commit()

    return recommendations.to_dict()


@router.get("/recommendations/algorithms")
async def get_pqc_algorithm_catalog():
    """
    Get catalog of recommended PQC algorithms.

    Returns the list of NIST-standardized post-quantum algorithms
    that CryptoServe recommends for migration:

    Key Encapsulation (KEMs):
    - ML-KEM-512/768/1024 (FIPS 203)

    Digital Signatures:
    - ML-DSA-44/65/87 (FIPS 204)
    - SLH-DSA-128f (FIPS 205)

    Use these as targets for your PQC migration plan.
    """
    from app.core.pqc_recommendations import PQC_ALGORITHMS

    return {
        "kem_algorithms": PQC_ALGORITHMS["kem"],
        "signature_algorithms": PQC_ALGORITHMS["signature"],
        "notes": [
            "ML-KEM-768 and ML-DSA-65 are recommended defaults (NIST Level 3)",
            "Use Level 5 algorithms for long-term secrets and high-security applications",
            "Consider hybrid modes (e.g., X25519Kyber768) for transition period",
        ],
    }


@router.get("/recommendations/data-profiles")
async def get_data_profiles():
    """
    Get available data sensitivity profiles for SNDL analysis.

    These profiles define how long data needs to remain confidential,
    which affects the urgency of PQC migration. Use these when
    calling /recommendations to get context-aware migration advice.
    """
    from app.core.pqc_recommendations import DATA_PROFILES, DataProfile as DP

    return {
        "profiles": [
            {
                "id": profile.value,
                "name": config["name"],
                "lifespan_years": config["lifespan_years"],
                "description": config["description"],
                "default_urgency": config["urgency"].value,
            }
            for profile, config in DATA_PROFILES.items()
        ],
        "usage": "Pass data_profile parameter to /report/{id}/recommendations",
    }
