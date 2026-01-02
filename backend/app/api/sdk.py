"""SDK download API routes."""

from fastapi import APIRouter, HTTPException, status, Header
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import Annotated

from app.database import get_session_maker
from app.models import Identity, Context
from app.core.identity_manager import identity_manager
from app.sdk_generator.generator import sdk_generator

router = APIRouter(prefix="/sdk", tags=["sdk"])

# Algorithm overhead info (nonce + tag sizes)
ALGORITHM_INFO = {
    "AES-128-GCM": {"speed": "very fast", "overhead_bytes": 28, "quantum_safe": False},
    "AES-256-GCM": {"speed": "fast", "overhead_bytes": 28, "quantum_safe": False},
    "ChaCha20-Poly1305": {"speed": "fast", "overhead_bytes": 28, "quantum_safe": False},
    "AES-256-GCM+ML-KEM-768": {"speed": "moderate", "overhead_bytes": 1120, "quantum_safe": True},
    "AES-256-GCM+ML-KEM-1024": {"speed": "moderate", "overhead_bytes": 1568, "quantum_safe": True},
}


@router.get("/download/{token}/python")
async def download_python_sdk(token: str):
    """Download personalized Python SDK."""
    async with get_session_maker()() as db:
        # Validate token and get identity
        identity = await identity_manager.get_identity_by_token(db, token)

        if not identity:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Invalid or expired token",
            )

        # Generate SDK
        try:
            wheel_path = sdk_generator.generate_python_sdk(identity, token)
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to generate SDK: {str(e)}",
            )

        return FileResponse(
            path=wheel_path,
            filename=wheel_path.name,
            media_type="application/octet-stream",
        )


@router.get("/info/{token}")
async def get_sdk_info(token: str):
    """Get identity info for a token (for SDK refresh)."""
    async with get_session_maker()() as db:
        identity = await identity_manager.get_identity_by_token(db, token)

        if not identity:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Invalid or expired token",
            )

        return {
            "identity_id": identity.id,
            "name": identity.name,
            "team": identity.team,
            "environment": identity.environment,
            "allowed_contexts": identity.allowed_contexts,
            "expires_at": identity.expires_at.isoformat(),
        }


async def _get_identity_from_auth(authorization: str) -> Identity:
    """Extract and validate identity from Authorization header."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid Authorization header",
        )
    token = authorization.replace("Bearer ", "")

    async with get_session_maker()() as db:
        identity = await identity_manager.get_identity_by_token(db, token)
        if not identity:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired token",
            )
        return identity


def _get_algorithm_info(algorithm: str) -> dict:
    """Get speed/overhead info for an algorithm."""
    return ALGORITHM_INFO.get(algorithm, {
        "speed": "unknown",
        "overhead_bytes": 0,
        "quantum_safe": "ML-KEM" in algorithm or "Kyber" in algorithm,
    })


@router.get("/contexts")
async def list_sdk_contexts(authorization: Annotated[str, Header()]):
    """List all contexts available to the SDK identity with algorithm details."""
    identity = await _get_identity_from_auth(authorization)

    async with get_session_maker()() as db:
        # Filter contexts by tenant for isolation
        result = await db.execute(
            select(Context).where(Context.tenant_id == identity.tenant_id)
        )
        all_contexts = result.scalars().all()

        # Filter to allowed contexts
        allowed = identity.allowed_contexts or []
        contexts = []
        for ctx in all_contexts:
            if ctx.name in allowed or "*" in allowed:
                algo_info = _get_algorithm_info(ctx.algorithm)
                contexts.append({
                    "name": ctx.name,
                    "display_name": ctx.display_name,
                    "algorithm": ctx.algorithm,
                    "speed": algo_info["speed"],
                    "overhead_bytes": algo_info["overhead_bytes"],
                    "quantum_safe": algo_info["quantum_safe"],
                    "compliance": ctx.compliance_tags or [],
                })
        return contexts


@router.get("/contexts/search")
async def search_sdk_contexts(
    authorization: Annotated[str, Header()],
    q: str = "",
):
    """Search contexts with smart matching.

    Matches against:
    - Context name (user-pii, payment-data)
    - Description text
    - Data examples (email, SSN, credit card)
    - Compliance tags (HIPAA, PCI-DSS, GDPR)

    Returns contexts sorted by relevance.
    """
    identity = await _get_identity_from_auth(authorization)
    query = q.lower().strip()

    async with get_session_maker()() as db:
        # Filter contexts by tenant for isolation
        result = await db.execute(
            select(Context).where(Context.tenant_id == identity.tenant_id)
        )
        all_contexts = result.scalars().all()

        # Filter to allowed contexts
        allowed = identity.allowed_contexts or []
        scored_contexts = []

        for ctx in all_contexts:
            if ctx.name not in allowed and "*" not in allowed:
                continue

            # Calculate relevance score
            score = 0
            matches = []

            # Exact name match (highest priority)
            if query and query == ctx.name.lower():
                score += 100
                matches.append("name (exact)")
            # Partial name match
            elif query and query in ctx.name.lower():
                score += 50
                matches.append("name")

            # Description match
            if query and query in (ctx.description or "").lower():
                score += 30
                matches.append("description")

            # Display name match
            if query and query in (ctx.display_name or "").lower():
                score += 25
                matches.append("display_name")

            # Data examples match
            for example in (ctx.data_examples or []):
                if query and query in example.lower():
                    score += 20
                    matches.append(f"example: {example}")
                    break

            # Compliance tags match
            for tag in (ctx.compliance_tags or []):
                if query and query in tag.lower():
                    score += 15
                    matches.append(f"compliance: {tag}")
                    break

            # If no query, show all (for listing)
            if not query:
                score = 1

            if score > 0:
                algo_info = _get_algorithm_info(ctx.algorithm)
                scored_contexts.append({
                    "name": ctx.name,
                    "display_name": ctx.display_name,
                    "description": ctx.description,
                    "algorithm": ctx.algorithm,
                    "speed": algo_info["speed"],
                    "overhead_bytes": algo_info["overhead_bytes"],
                    "quantum_safe": algo_info["quantum_safe"],
                    "compliance": ctx.compliance_tags or [],
                    "data_examples": ctx.data_examples or [],
                    "score": score,
                    "matches": matches if query else [],
                })

        # Sort by score (descending)
        scored_contexts.sort(key=lambda x: x["score"], reverse=True)

        return {
            "query": q,
            "total": len(scored_contexts),
            "contexts": scored_contexts,
        }


@router.get("/contexts/{context_name}")
async def get_sdk_context_info(
    context_name: str,
    authorization: Annotated[str, Header()],
):
    """Get detailed info about a specific context."""
    identity = await _get_identity_from_auth(authorization)

    # Check authorization
    allowed = identity.allowed_contexts or []
    if context_name not in allowed and "*" not in allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Not authorized for context '{context_name}'",
        )

    async with get_session_maker()() as db:
        # Filter by tenant for isolation
        result = await db.execute(
            select(Context).where(
                Context.name == context_name,
                Context.tenant_id == identity.tenant_id
            )
        )
        ctx = result.scalar_one_or_none()

        if not ctx:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Context '{context_name}' not found",
            )

        algo_info = _get_algorithm_info(ctx.algorithm)
        return {
            "name": ctx.name,
            "display_name": ctx.display_name,
            "description": ctx.description,
            "algorithm": ctx.algorithm,
            "speed": algo_info["speed"],
            "overhead_bytes": algo_info["overhead_bytes"],
            "quantum_safe": algo_info["quantum_safe"],
            "compliance": ctx.compliance_tags or [],
            "data_examples": ctx.data_examples or [],
        }
