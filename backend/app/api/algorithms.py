"""Algorithm API routes.

Provides information about available cryptographic algorithms.
"""

from typing import Annotated

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel

from app.auth.jwt import get_current_user
from app.models import User
from app.core.crypto_registry import (
    crypto_registry,
    AlgorithmType,
    SecurityStatus,
)


router = APIRouter(prefix="/api/algorithms", tags=["algorithms"])


# =============================================================================
# Response Schemas
# =============================================================================

class AlgorithmResponse(BaseModel):
    """Algorithm information for API responses."""
    name: str
    family: str
    variant: str | None = None
    aliases: list[str] = []
    type: str
    use_cases: list[str] = []
    security_bits: int
    key_sizes: list[int] = []
    quantum_resistant: bool
    status: str
    replacement: str | None = None
    standards: list[str] = []
    hardware_acceleration: bool


class AlgorithmDetailResponse(AlgorithmResponse):
    """Detailed algorithm information."""
    block_size: int | None = None
    output_size: int | None = None
    quantum_security_bits: int | None = None
    deprecated_date: str | None = None
    vulnerabilities: list[str] = []
    compliance_frameworks: list[str] = []
    relative_speed: str
    memory_usage: str
    implementation_notes: list[str] = []
    common_mistakes: list[str] = []


class AlgorithmTypeInfo(BaseModel):
    """Information about an algorithm type."""
    value: str
    label: str
    description: str
    count: int


# =============================================================================
# API Endpoints
# =============================================================================

@router.get("", response_model=list[AlgorithmResponse])
async def list_algorithms(
    user: Annotated[User, Depends(get_current_user)],
    type: str | None = Query(None, description="Filter by algorithm type"),
    quantum_resistant: bool | None = Query(None, description="Filter by quantum resistance"),
    status: str | None = Query(None, description="Filter by security status"),
    min_security_bits: int | None = Query(None, description="Minimum security level in bits"),
):
    """List all available cryptographic algorithms.

    Supports filtering by type, quantum resistance, status, and security level.
    """
    # Parse filters
    algo_type = None
    if type:
        try:
            algo_type = AlgorithmType(type)
        except ValueError:
            pass

    sec_status = None
    if status:
        try:
            sec_status = SecurityStatus(status)
        except ValueError:
            pass

    algorithms = crypto_registry.search(
        algorithm_type=algo_type,
        quantum_resistant=quantum_resistant,
        status=sec_status,
        min_security_bits=min_security_bits,
    )

    return [
        AlgorithmResponse(
            name=algo.name,
            family=algo.family,
            variant=algo.variant,
            aliases=algo.aliases,
            type=algo.algorithm_type.value,
            use_cases=algo.use_cases,
            security_bits=algo.security_bits,
            key_sizes=algo.key_sizes,
            quantum_resistant=algo.quantum_resistant,
            status=algo.status.value,
            replacement=algo.replacement,
            standards=algo.standards,
            hardware_acceleration=algo.hardware_acceleration,
        )
        for algo in sorted(algorithms, key=lambda a: (a.algorithm_type.value, a.name))
    ]


@router.get("/types", response_model=list[AlgorithmTypeInfo])
async def list_algorithm_types(
    user: Annotated[User, Depends(get_current_user)],
):
    """List all algorithm types with descriptions."""
    type_descriptions = {
        AlgorithmType.SYMMETRIC_ENCRYPTION: "Symmetric encryption using shared secret keys",
        AlgorithmType.ASYMMETRIC_ENCRYPTION: "Public-key encryption for key exchange",
        AlgorithmType.HASH: "Cryptographic hash functions for data integrity",
        AlgorithmType.SIGNATURE: "Digital signatures for authentication",
        AlgorithmType.KEY_EXCHANGE: "Key agreement protocols",
        AlgorithmType.KEY_DERIVATION: "Key derivation functions",
        AlgorithmType.MAC: "Message authentication codes",
        AlgorithmType.AEAD: "Authenticated encryption with associated data",
    }

    type_labels = {
        AlgorithmType.SYMMETRIC_ENCRYPTION: "Symmetric Encryption",
        AlgorithmType.ASYMMETRIC_ENCRYPTION: "Asymmetric Encryption",
        AlgorithmType.HASH: "Hash Functions",
        AlgorithmType.SIGNATURE: "Digital Signatures",
        AlgorithmType.KEY_EXCHANGE: "Key Exchange",
        AlgorithmType.KEY_DERIVATION: "Key Derivation",
        AlgorithmType.MAC: "MAC",
        AlgorithmType.AEAD: "AEAD",
    }

    results = []
    for algo_type in AlgorithmType:
        count = len(crypto_registry.search(algorithm_type=algo_type))
        results.append(AlgorithmTypeInfo(
            value=algo_type.value,
            label=type_labels.get(algo_type, algo_type.value),
            description=type_descriptions.get(algo_type, ""),
            count=count,
        ))

    return results


@router.get("/recommended", response_model=list[AlgorithmResponse])
async def list_recommended_algorithms(
    user: Annotated[User, Depends(get_current_user)],
    type: str | None = Query(None, description="Filter by algorithm type"),
):
    """List recommended algorithms for production use."""
    algo_type = None
    if type:
        try:
            algo_type = AlgorithmType(type)
        except ValueError:
            pass

    algorithms = crypto_registry.search(
        algorithm_type=algo_type,
        status=SecurityStatus.RECOMMENDED,
    )

    return [
        AlgorithmResponse(
            name=algo.name,
            family=algo.family,
            variant=algo.variant,
            aliases=algo.aliases,
            type=algo.algorithm_type.value,
            use_cases=algo.use_cases,
            security_bits=algo.security_bits,
            key_sizes=algo.key_sizes,
            quantum_resistant=algo.quantum_resistant,
            status=algo.status.value,
            replacement=algo.replacement,
            standards=algo.standards,
            hardware_acceleration=algo.hardware_acceleration,
        )
        for algo in sorted(algorithms, key=lambda a: a.name)
    ]


@router.get("/quantum-resistant", response_model=list[AlgorithmResponse])
async def list_quantum_resistant_algorithms(
    user: Annotated[User, Depends(get_current_user)],
):
    """List all quantum-resistant (post-quantum) algorithms."""
    algorithms = crypto_registry.get_quantum_resistant()

    return [
        AlgorithmResponse(
            name=algo.name,
            family=algo.family,
            variant=algo.variant,
            aliases=algo.aliases,
            type=algo.algorithm_type.value,
            use_cases=algo.use_cases,
            security_bits=algo.security_bits,
            key_sizes=algo.key_sizes,
            quantum_resistant=algo.quantum_resistant,
            status=algo.status.value,
            replacement=algo.replacement,
            standards=algo.standards,
            hardware_acceleration=algo.hardware_acceleration,
        )
        for algo in sorted(algorithms, key=lambda a: a.name)
    ]


@router.get("/deprecated", response_model=list[AlgorithmResponse])
async def list_deprecated_algorithms(
    user: Annotated[User, Depends(get_current_user)],
):
    """List deprecated and broken algorithms that should be avoided."""
    algorithms = crypto_registry.get_deprecated()

    return [
        AlgorithmResponse(
            name=algo.name,
            family=algo.family,
            variant=algo.variant,
            aliases=algo.aliases,
            type=algo.algorithm_type.value,
            use_cases=algo.use_cases,
            security_bits=algo.security_bits,
            key_sizes=algo.key_sizes,
            quantum_resistant=algo.quantum_resistant,
            status=algo.status.value,
            replacement=algo.replacement,
            standards=algo.standards,
            hardware_acceleration=algo.hardware_acceleration,
        )
        for algo in sorted(algorithms, key=lambda a: a.name)
    ]


@router.get("/{name}", response_model=AlgorithmDetailResponse)
async def get_algorithm(
    name: str,
    user: Annotated[User, Depends(get_current_user)],
):
    """Get detailed information about a specific algorithm."""
    algo = crypto_registry.get(name)

    if not algo:
        from fastapi import HTTPException, status
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Algorithm not found: {name}",
        )

    return AlgorithmDetailResponse(
        name=algo.name,
        family=algo.family,
        variant=algo.variant,
        aliases=algo.aliases,
        type=algo.algorithm_type.value,
        use_cases=algo.use_cases,
        security_bits=algo.security_bits,
        key_sizes=algo.key_sizes,
        block_size=algo.block_size,
        output_size=algo.output_size,
        quantum_resistant=algo.quantum_resistant,
        quantum_security_bits=algo.quantum_security_bits,
        status=algo.status.value,
        deprecated_date=algo.deprecated_date,
        replacement=algo.replacement,
        vulnerabilities=algo.vulnerabilities,
        standards=algo.standards,
        compliance_frameworks=algo.compliance_frameworks,
        hardware_acceleration=algo.hardware_acceleration,
        relative_speed=algo.relative_speed,
        memory_usage=algo.memory_usage,
        implementation_notes=algo.implementation_notes,
        common_mistakes=algo.common_mistakes,
    )
