"""Policy API routes.

Provides policy management and evaluation.
"""

from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.auth.jwt import get_current_user
from app.models import User, Policy
from app.schemas.policy import (
    PolicyListResponse,
    PolicyResponse,
    PolicyCreate,
    PolicyUpdate,
    EvaluationRequest,
    EvaluationResponse,
    PolicyEvaluationResult,
)
from app.core.policy_engine import (
    PolicyEngine,
    EvaluationContext,
    PolicySeverity as EnginePolicySeverity,
    Policy as EnginePolicy,
)
from app.core.crypto_registry import crypto_registry

router = APIRouter(prefix="/api/policies", tags=["policies"])


# =============================================================================
# Helper Functions
# =============================================================================

def db_policy_to_engine_policy(db_policy: Policy) -> EnginePolicy:
    """Convert a database Policy to a PolicyEngine Policy."""
    return EnginePolicy(
        name=db_policy.name,
        description=db_policy.description or "",
        rule=db_policy.rule,
        severity=EnginePolicySeverity(db_policy.severity),
        message=db_policy.message,
        enabled=db_policy.enabled,
        contexts=db_policy.contexts or [],
        operations=db_policy.operations or [],
    )


def build_test_context(req: EvaluationRequest, algo_info: dict) -> EvaluationContext:
    """Build an EvaluationContext for testing from a request."""
    # Determine audit level based on sensitivity and frameworks
    audit_level = "standard"
    if req.sensitivity == "critical" or "HIPAA" in req.frameworks or "PCI-DSS" in req.frameworks:
        audit_level = "full"
    elif req.sensitivity == "high":
        audit_level = "detailed"
    elif req.sensitivity == "low":
        audit_level = "minimal"

    return EvaluationContext(
        algorithm={
            "name": algo_info["name"],
            "key_bits": algo_info["key_bits"],
            "quantum_resistant": algo_info["quantum_resistant"],
            "hardware_acceleration": algo_info.get("hardware_acceleration", False),
        },
        context={
            "name": req.context_name,
            "sensitivity": req.sensitivity,
            "pii": req.pii,
            "phi": req.phi,
            "pci": req.pci,
            "frameworks": req.frameworks,
            "protection_lifetime_years": req.protection_lifetime_years,
            "audit_level": audit_level,
            "frequency": "medium",
        },
        identity={
            "team": req.team,
        },
        operation=req.operation,
    )


# =============================================================================
# Read Endpoints
# =============================================================================

@router.get("", response_model=list[PolicyListResponse])
async def list_policies(
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
    enabled_only: bool = Query(False, description="Only return enabled policies"),
    severity: str | None = Query(None, description="Filter by severity (block, warn, info)"),
):
    """List all policies with optional filtering."""
    query = select(Policy).order_by(Policy.name)

    if enabled_only:
        query = query.where(Policy.enabled == True)

    if severity:
        query = query.where(Policy.severity == severity)

    result = await db.execute(query)
    policies = result.scalars().all()
    return policies


@router.get("/defaults")
async def list_default_policies(
    user: Annotated[User, Depends(get_current_user)],
):
    """List the built-in default policies.

    These are the hardcoded policies that ship with CryptoServe.
    """
    engine = PolicyEngine()
    engine.load_default_policies()

    return [
        {
            "name": p.name,
            "description": p.description,
            "rule": p.rule,
            "severity": p.severity.value,
            "message": p.message,
            "enabled": p.enabled,
            "contexts": p.contexts,
            "operations": p.operations,
        }
        for p in engine.policies
    ]


@router.get("/{name}", response_model=PolicyResponse)
async def get_policy(
    name: str,
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Get a specific policy by name."""
    result = await db.execute(select(Policy).where(Policy.name == name))
    policy = result.scalar_one_or_none()

    if not policy:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Policy not found: {name}",
        )

    return policy


# =============================================================================
# Policy Evaluation
# =============================================================================

@router.post("/evaluate", response_model=EvaluationResponse)
async def evaluate_policies(
    data: EvaluationRequest,
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
    include_defaults: bool = Query(True, description="Include default policies in evaluation"),
):
    """Evaluate policies against a test context.

    This endpoint is useful for testing how policies will behave
    before using them in production.
    """
    # Look up algorithm
    algo = crypto_registry.get(data.algorithm)
    if not algo:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown algorithm: {data.algorithm}. Use GET /api/algorithms for available options.",
        )

    algo_info = {
        "name": algo.name,
        "key_bits": algo.security_bits,
        "quantum_resistant": algo.quantum_resistant,
        "hardware_acceleration": algo.hardware_acceleration,
    }

    # Build evaluation context
    eval_context = build_test_context(data, algo_info)

    # Load policies
    engine = PolicyEngine()

    if include_defaults:
        engine.load_default_policies()

    # Load custom policies from database
    result = await db.execute(select(Policy).where(Policy.enabled == True))
    db_policies = result.scalars().all()
    for db_policy in db_policies:
        engine.add_policy(db_policy_to_engine_policy(db_policy))

    # Evaluate
    results = engine.evaluate(eval_context, raise_on_block=False)

    # Collect results
    blocking = 0
    warnings = 0
    infos = 0
    eval_results = []

    for r in results:
        eval_results.append(PolicyEvaluationResult(
            policy_name=r.policy_name,
            passed=r.passed,
            severity=r.severity.value,
            message=r.message if not r.passed else "",
            rule=r.details.get("rule", ""),
        ))

        if not r.passed:
            if r.severity == EnginePolicySeverity.BLOCK:
                blocking += 1
            elif r.severity == EnginePolicySeverity.WARN:
                warnings += 1
            else:
                infos += 1

    return EvaluationResponse(
        algorithm=data.algorithm,
        context=data.context_name,
        allowed=(blocking == 0),
        blocking_violations=blocking,
        warning_violations=warnings,
        info_violations=infos,
        results=eval_results,
    )


# =============================================================================
# Admin Helper
# =============================================================================

async def require_admin(
    user: Annotated[User, Depends(get_current_user)]
) -> User:
    """Verify user has admin privileges."""
    if not user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )
    return user


# =============================================================================
# Policy CRUD (Admin Only)
# =============================================================================

@router.post("", response_model=PolicyResponse, status_code=status.HTTP_201_CREATED)
async def create_policy(
    data: PolicyCreate,
    admin: Annotated[User, Depends(require_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Create a new custom policy (admin only)."""
    # Check for duplicate name
    existing = await db.execute(select(Policy).where(Policy.name == data.name))
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Policy with name '{data.name}' already exists",
        )

    # Validate rule syntax by trying to parse it
    try:
        engine = PolicyEngine()
        test_policy = EnginePolicy(
            name=data.name,
            description=data.description,
            rule=data.rule,
            severity=EnginePolicySeverity(data.severity.value),
            message=data.message,
            enabled=True,
            contexts=[],
            operations=[],
        )
        engine.add_policy(test_policy)
        # Try to evaluate to check syntax
        test_context = EvaluationContext(
            algorithm={"name": "AES-256-GCM", "key_bits": 256, "quantum_resistant": False},
            context={"name": "test", "sensitivity": "medium"},
            identity={"team": "test"},
            operation="encrypt",
        )
        engine.evaluate(test_context, raise_on_block=False)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid rule syntax: {str(e)}",
        )

    # Create policy
    policy = Policy(
        name=data.name,
        description=data.description,
        rule=data.rule,
        severity=data.severity.value,
        message=data.message,
        enabled=data.enabled,
        contexts=data.contexts,
        operations=data.operations,
        policy_metadata=data.policy_metadata,
        created_by=admin.github_username,
        created_at=datetime.now(timezone.utc),
    )
    db.add(policy)
    await db.commit()
    await db.refresh(policy)
    return policy


@router.put("/{name}", response_model=PolicyResponse)
async def update_policy(
    name: str,
    data: PolicyUpdate,
    admin: Annotated[User, Depends(require_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Update an existing policy (admin only)."""
    result = await db.execute(select(Policy).where(Policy.name == name))
    policy = result.scalar_one_or_none()

    if not policy:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Policy not found: {name}",
        )

    # Update fields if provided
    if data.description is not None:
        policy.description = data.description
    if data.rule is not None:
        # Validate rule syntax
        try:
            engine = PolicyEngine()
            test_policy = EnginePolicy(
                name=name,
                description="",
                rule=data.rule,
                severity=EnginePolicySeverity.WARN,
                message="test",
                enabled=True,
                contexts=[],
                operations=[],
            )
            engine.add_policy(test_policy)
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid rule syntax: {str(e)}",
            )
        policy.rule = data.rule
    if data.severity is not None:
        policy.severity = data.severity.value
    if data.message is not None:
        policy.message = data.message
    if data.enabled is not None:
        policy.enabled = data.enabled
    if data.contexts is not None:
        policy.contexts = data.contexts
    if data.operations is not None:
        policy.operations = data.operations
    if data.policy_metadata is not None:
        policy.policy_metadata = data.policy_metadata

    policy.updated_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(policy)
    return policy


@router.delete("/{name}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_policy(
    name: str,
    admin: Annotated[User, Depends(require_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Delete a custom policy (admin only)."""
    result = await db.execute(select(Policy).where(Policy.name == name))
    policy = result.scalar_one_or_none()

    if not policy:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Policy not found: {name}",
        )

    await db.delete(policy)
    await db.commit()
