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
        result = await db.execute(select(Context))
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
        result = await db.execute(
            select(Context).where(Context.name == context_name)
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
