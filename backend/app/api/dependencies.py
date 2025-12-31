"""Dependency Scanning API routes.

Scans package files (package.json, requirements.txt, etc.) for crypto dependencies.
"""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File
from pydantic import BaseModel, Field

from app.models import Identity
from app.core.dependency_scanner import (
    DependencyScanner,
    DependencyScannerError,
    PackageType,
)
from app.api.crypto import get_sdk_identity

router = APIRouter(prefix="/v1/dependencies", tags=["dependencies"])

# Singleton scanner
dependency_scanner = DependencyScanner()


class DependencyScanRequest(BaseModel):
    """Dependency scan request."""
    content: str = Field(..., description="Package file content")
    filename: str | None = Field(
        default=None,
        description="Filename for auto-detection (package.json, requirements.txt, go.mod, Cargo.toml)"
    )


class CryptoDependencyResponse(BaseModel):
    """A cryptographic dependency."""
    name: str
    version: str | None
    package_type: str
    category: str
    algorithms: list[str]
    quantum_risk: str
    is_deprecated: bool
    deprecation_reason: str | None = None
    recommended_replacement: str | None = None
    description: str | None = None


class DependencyScanResponse(BaseModel):
    """Dependency scan response."""
    dependencies: list[CryptoDependencyResponse]
    package_type: str
    total_packages: int
    crypto_packages: int
    quantum_vulnerable_count: int
    deprecated_count: int
    recommendations: list[str]


class QuickDependencyScanResponse(BaseModel):
    """Quick dependency scan response."""
    has_crypto: bool
    crypto_count: int
    quantum_vulnerable: bool
    deprecated_present: bool
    risk_level: str
    top_algorithms: list[str]
    recommendation: str


@router.post("/scan", response_model=DependencyScanResponse)
async def scan_dependencies(
    data: DependencyScanRequest,
    identity: Annotated[Identity, Depends(get_sdk_identity)],
):
    """Scan a package file for cryptographic dependencies.

    Detects crypto libraries in:
    - package.json (npm)
    - requirements.txt (PyPI)
    - go.mod (Go)
    - Cargo.toml (Rust)

    Returns:
    - All crypto dependencies found
    - Quantum vulnerability assessment
    - Deprecated package warnings
    - Recommendations for improvements
    """
    try:
        result = dependency_scanner.scan(
            content=data.content,
            filename=data.filename,
        )
    except DependencyScannerError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    return DependencyScanResponse(
        dependencies=[
            CryptoDependencyResponse(
                name=d.name,
                version=d.version,
                package_type=d.package_type.value,
                category=d.category,
                algorithms=d.algorithms,
                quantum_risk=d.quantum_risk.value,
                is_deprecated=d.is_deprecated,
                deprecation_reason=d.deprecation_reason,
                recommended_replacement=d.recommended_replacement,
                description=d.description,
            )
            for d in result.dependencies
        ],
        package_type=result.package_type.value,
        total_packages=result.total_packages,
        crypto_packages=result.crypto_packages,
        quantum_vulnerable_count=result.quantum_vulnerable_count,
        deprecated_count=result.deprecated_count,
        recommendations=result.recommendations,
    )


@router.post("/scan/quick", response_model=QuickDependencyScanResponse)
async def quick_dependency_scan(
    data: DependencyScanRequest,
    identity: Annotated[Identity, Depends(get_sdk_identity)],
):
    """Quick scan for crypto dependencies.

    Returns a simple summary ideal for CI/CD pipelines.
    """
    try:
        result = dependency_scanner.scan(
            content=data.content,
            filename=data.filename,
        )
    except DependencyScannerError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    # Collect top algorithms
    all_algorithms = set()
    for dep in result.dependencies:
        all_algorithms.update(dep.algorithms)
    top_algorithms = sorted(all_algorithms)[:5]

    # Determine risk level
    if result.deprecated_count > 0:
        risk_level = "high"
        recommendation = f"Found {result.deprecated_count} deprecated crypto packages. Replace immediately."
    elif result.quantum_vulnerable_count > 0:
        risk_level = "medium"
        recommendation = f"Found {result.quantum_vulnerable_count} quantum-vulnerable packages. Plan migration."
    elif result.crypto_packages > 0:
        risk_level = "low"
        recommendation = "Crypto dependencies look healthy."
    else:
        risk_level = "none"
        recommendation = "No known crypto dependencies detected."

    return QuickDependencyScanResponse(
        has_crypto=result.crypto_packages > 0,
        crypto_count=result.crypto_packages,
        quantum_vulnerable=result.quantum_vulnerable_count > 0,
        deprecated_present=result.deprecated_count > 0,
        risk_level=risk_level,
        top_algorithms=top_algorithms,
        recommendation=recommendation,
    )


@router.post("/scan/file")
async def scan_dependency_file(
    file: UploadFile = File(...),
    identity: Annotated[Identity, Depends(get_sdk_identity)] = None,
):
    """Scan an uploaded package file for crypto dependencies.

    Accepts: package.json, requirements.txt, go.mod, Cargo.toml
    """
    if not identity:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)

    content = await file.read()

    if len(content) > 1 * 1024 * 1024:  # 1MB limit
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="File too large (max 1MB)",
        )

    try:
        content_str = content.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="File must be UTF-8 encoded",
        )

    try:
        result = dependency_scanner.scan(
            content=content_str,
            filename=file.filename,
        )
    except DependencyScannerError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    return {
        "filename": file.filename,
        "package_type": result.package_type.value,
        "total_packages": result.total_packages,
        "crypto_packages": result.crypto_packages,
        "dependencies": [
            {
                "name": d.name,
                "version": d.version,
                "category": d.category,
                "algorithms": d.algorithms,
                "quantum_risk": d.quantum_risk.value,
                "is_deprecated": d.is_deprecated,
            }
            for d in result.dependencies
        ],
        "quantum_vulnerable_count": result.quantum_vulnerable_count,
        "deprecated_count": result.deprecated_count,
        "recommendations": result.recommendations,
    }


@router.get("/known-packages")
async def list_known_packages(
    package_type: str | None = None,
    identity: Annotated[Identity, Depends(get_sdk_identity)] = None,
):
    """List all known cryptographic packages.

    Returns the packages the scanner can detect, organized by ecosystem.

    Args:
        package_type: Filter by type (npm, pypi, go, cargo)
    """
    if not identity:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)

    pt = None
    if package_type:
        try:
            pt = PackageType(package_type.lower())
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid package type: {package_type}. Use: npm, pypi, go, cargo",
            )

    return dependency_scanner.get_known_packages(pt)


@router.get("/supported-formats")
async def list_supported_formats(
    identity: Annotated[Identity, Depends(get_sdk_identity)],
):
    """List supported package file formats."""
    return {
        "formats": [
            {"filename": "package.json", "ecosystem": "npm", "language": "JavaScript/TypeScript"},
            {"filename": "requirements.txt", "ecosystem": "pypi", "language": "Python"},
            {"filename": "go.mod", "ecosystem": "go", "language": "Go"},
            {"filename": "Cargo.toml", "ecosystem": "cargo", "language": "Rust"},
        ]
    }
