"""Public API routes - no authentication required.

These endpoints are available to developers without logging in,
enabling better DX for SDK users and CLI tools.
"""

from typing import Optional
from fastapi import APIRouter, Query
from pydantic import BaseModel
from sqlalchemy import select

router = APIRouter(prefix="/api/public", tags=["public"])


# --- Schemas ---

class ContextRecommendationRequest(BaseModel):
    """Input for context recommendation."""
    data_type: str  # pii, financial, health, auth, business, general
    compliance: str  # none, soc2, hipaa, pci, gdpr, multiple
    threat_level: str  # standard, elevated, maximum, quantum
    performance: str  # realtime, interactive, batch


class ContextRecommendation(BaseModel):
    """Recommended context configuration."""
    context_name: str
    display_name: str
    description: str
    algorithm: str
    quantum_ready: bool
    compliance_tags: list[str]
    sensitivity: str
    key_rotation_days: int
    code_example: str
    rationale: list[str]


class AvailableContext(BaseModel):
    """Publicly available context info."""
    name: str
    display_name: str
    description: str
    algorithm: str
    compliance_tags: list[str]


# --- Context Recommendation Logic ---

def generate_recommendation(
    data_type: str,
    compliance: str,
    threat_level: str,
    performance: str,
) -> ContextRecommendation:
    """Generate context recommendation based on inputs."""
    rationale = []

    # Determine algorithm based on threat level and performance
    if threat_level == "quantum":
        algorithm = "KYBER-1024-AES-256-GCM"
        quantum_ready = True
        rationale.append("Quantum-resistant algorithm selected for future-proof protection")
    elif threat_level == "maximum":
        algorithm = "AES-256-GCM"
        quantum_ready = False
        rationale.append("AES-256 provides maximum classical security (256-bit)")
    elif performance == "realtime" and threat_level == "standard":
        algorithm = "ChaCha20-Poly1305"
        quantum_ready = False
        rationale.append("ChaCha20 selected for optimal real-time performance")
    else:
        algorithm = "AES-256-GCM"
        quantum_ready = False
        rationale.append("AES-256-GCM is the industry standard with hardware acceleration")

    # Override for compliance requirements
    if compliance in ["hipaa", "pci"]:
        algorithm = "AES-256-GCM"
        rationale.append(f"{compliance.upper()} compliance requires AES-256 encryption")

    # Generate context name based on data type
    context_mapping = {
        "pii": ("user-pii", "User Personal Data", "Personal identifiable information"),
        "financial": ("payment-data", "Payment Data", "Financial and payment card data"),
        "health": ("phi-records", "Health Records", "Protected health information (PHI)"),
        "auth": ("auth-secrets", "Auth Secrets", "Authentication credentials and tokens"),
        "business": ("business-confidential", "Business Confidential", "Sensitive business data"),
        "general": ("sensitive-data", "Sensitive Data", "General sensitive information"),
    }

    ctx_name, display_name, description = context_mapping.get(
        data_type, ("sensitive-data", "Sensitive Data", "General sensitive information")
    )

    # Determine sensitivity level
    sensitivity_map = {
        "pii": "high",
        "financial": "critical",
        "health": "critical",
        "auth": "critical",
        "business": "high",
        "general": "medium",
    }
    sensitivity = sensitivity_map.get(data_type, "medium")

    # Determine compliance tags
    compliance_tags = []
    if compliance == "soc2":
        compliance_tags = ["SOC2"]
        rationale.append("SOC 2 compliance tag added")
    elif compliance == "hipaa":
        compliance_tags = ["HIPAA"]
        rationale.append("HIPAA compliance requires strict PHI protection")
    elif compliance == "pci":
        compliance_tags = ["PCI-DSS"]
        rationale.append("PCI-DSS compliance for payment card data")
    elif compliance == "gdpr":
        compliance_tags = ["GDPR"]
        rationale.append("GDPR compliance for EU data protection")
    elif compliance == "multiple":
        compliance_tags = ["SOC2", "GDPR"]
        rationale.append("Multiple compliance frameworks applied")

    # Add data-type specific compliance
    if data_type == "health" and "HIPAA" not in compliance_tags:
        compliance_tags.append("HIPAA")
        rationale.append("HIPAA auto-added for health data")
    if data_type == "financial" and "PCI-DSS" not in compliance_tags:
        compliance_tags.append("PCI-DSS")
        rationale.append("PCI-DSS auto-added for financial data")

    # Determine key rotation
    if threat_level == "maximum" or sensitivity == "critical":
        key_rotation_days = 30
        rationale.append("30-day key rotation for critical data")
    elif threat_level == "elevated" or sensitivity == "high":
        key_rotation_days = 90
        rationale.append("90-day key rotation for high-sensitivity data")
    else:
        key_rotation_days = 365
        rationale.append("Annual key rotation for standard protection")

    # Generate code example
    code_example = f'''from cryptoserve import crypto

# Encrypt {data_type} data
ciphertext = crypto.encrypt(
    plaintext=b"sensitive data",
    context="{ctx_name}"
)

# Decrypt when needed
plaintext = crypto.decrypt(ciphertext, context="{ctx_name}")'''

    return ContextRecommendation(
        context_name=ctx_name,
        display_name=display_name,
        description=description,
        algorithm=algorithm,
        quantum_ready=quantum_ready,
        compliance_tags=compliance_tags,
        sensitivity=sensitivity,
        key_rotation_days=key_rotation_days,
        code_example=code_example,
        rationale=rationale,
    )


# --- Endpoints ---

@router.post("/context-wizard", response_model=ContextRecommendation)
async def get_context_recommendation(request: ContextRecommendationRequest):
    """
    Get a context recommendation based on data type, compliance, and security needs.

    No authentication required - available to all SDK users.
    """
    return generate_recommendation(
        data_type=request.data_type,
        compliance=request.compliance,
        threat_level=request.threat_level,
        performance=request.performance,
    )


@router.get("/context-wizard", response_model=ContextRecommendation)
async def get_context_recommendation_query(
    data_type: str = Query(..., description="Type of data: pii, financial, health, auth, business, general"),
    compliance: str = Query("none", description="Compliance framework: none, soc2, hipaa, pci, gdpr, multiple"),
    threat_level: str = Query("standard", description="Threat model: standard, elevated, maximum, quantum"),
    performance: str = Query("interactive", description="Performance needs: realtime, interactive, batch"),
):
    """
    Get a context recommendation via query parameters (GET-friendly for CLI/curl).

    No authentication required.

    Example:
        curl "https://api.cryptoserve.dev/api/public/context-wizard?data_type=pii&compliance=gdpr"
    """
    return generate_recommendation(
        data_type=data_type,
        compliance=compliance,
        threat_level=threat_level,
        performance=performance,
    )


@router.get("/algorithms")
async def list_public_algorithms():
    """
    List available encryption algorithms.

    No authentication required.
    """
    return {
        "symmetric": [
            {
                "name": "AES-256-GCM",
                "description": "Industry standard, hardware accelerated",
                "security_bits": 256,
                "quantum_resistant": False,
                "best_for": ["General purpose", "Compliance (HIPAA, PCI-DSS)"],
            },
            {
                "name": "ChaCha20-Poly1305",
                "description": "Fast software implementation, mobile-friendly",
                "security_bits": 256,
                "quantum_resistant": False,
                "best_for": ["Real-time applications", "Mobile devices"],
            },
        ],
        "quantum_resistant": [
            {
                "name": "KYBER-1024-AES-256-GCM",
                "description": "Hybrid post-quantum + classical encryption",
                "security_bits": 256,
                "quantum_resistant": True,
                "best_for": ["Long-term secrets", "Future-proof protection"],
            },
        ],
        "recommendation": "Use AES-256-GCM for most use cases. Consider ChaCha20 for real-time needs or KYBER hybrid for quantum resistance.",
    }


@router.get("/health")
async def public_health():
    """Public health check endpoint."""
    return {
        "status": "healthy",
        "service": "CryptoServe",
        "version": "1.0.0",
    }
