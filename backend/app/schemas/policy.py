"""Policy API schemas."""

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class PolicySeverity(str, Enum):
    """Policy enforcement severity levels."""
    BLOCK = "block"
    WARN = "warn"
    INFO = "info"


class PolicyCreate(BaseModel):
    """Schema for creating a policy."""
    name: str = Field(
        min_length=1,
        max_length=64,
        pattern=r"^[a-z0-9-]+$",
        description="Unique policy identifier (lowercase alphanumeric with hyphens)",
    )
    description: str = Field(
        default="",
        max_length=500,
        description="Human-readable description",
    )
    rule: str = Field(
        min_length=1,
        description="Rule expression to evaluate",
    )
    severity: PolicySeverity = Field(
        default=PolicySeverity.WARN,
        description="What to do when rule fails",
    )
    message: str = Field(
        min_length=1,
        max_length=500,
        description="Message shown when rule fails",
    )
    enabled: bool = Field(
        default=True,
        description="Whether policy is active",
    )
    contexts: list[str] = Field(
        default_factory=list,
        description="Contexts this policy applies to (empty = all)",
    )
    operations: list[str] = Field(
        default_factory=list,
        description="Operations this applies to: encrypt, decrypt (empty = all)",
    )
    policy_metadata: dict[str, Any] | None = Field(
        default=None,
        description="Additional policy metadata",
    )


class PolicyUpdate(BaseModel):
    """Schema for updating a policy (partial update)."""
    description: str | None = None
    rule: str | None = None
    severity: PolicySeverity | None = None
    message: str | None = None
    enabled: bool | None = None
    contexts: list[str] | None = None
    operations: list[str] | None = None
    policy_metadata: dict[str, Any] | None = None


class PolicyResponse(BaseModel):
    """Policy response schema."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    description: str | None
    rule: str
    severity: str
    message: str
    enabled: bool
    contexts: list[str] | None
    operations: list[str] | None
    policy_metadata: dict[str, Any] | None
    created_at: datetime
    updated_at: datetime | None
    created_by: str | None


class PolicyListResponse(BaseModel):
    """Simplified policy for list views."""

    model_config = ConfigDict(from_attributes=True)

    name: str
    description: str | None
    severity: str
    enabled: bool
    contexts: list[str] | None
    operations: list[str] | None
    created_at: datetime


class EvaluationRequest(BaseModel):
    """Request schema for policy evaluation (testing)."""
    algorithm: str = Field(
        description="Algorithm name to evaluate",
    )
    context_name: str = Field(
        default="general",
        description="Context name for evaluation",
    )
    sensitivity: str = Field(
        default="medium",
        description="Data sensitivity level",
    )
    pii: bool = Field(
        default=False,
        description="Whether data contains PII",
    )
    phi: bool = Field(
        default=False,
        description="Whether data contains PHI (health info)",
    )
    pci: bool = Field(
        default=False,
        description="Whether data contains PCI (payment card info)",
    )
    frameworks: list[str] = Field(
        default_factory=list,
        description="Compliance frameworks (e.g., HIPAA, PCI-DSS, GDPR)",
    )
    protection_lifetime_years: int = Field(
        default=5,
        description="How long data needs protection",
    )
    operation: str = Field(
        default="encrypt",
        description="Operation type: encrypt or decrypt",
    )
    team: str = Field(
        default="unknown",
        description="Team performing the operation",
    )


class PolicyEvaluationResult(BaseModel):
    """Result of evaluating a single policy."""
    policy_name: str
    passed: bool
    severity: str
    message: str
    rule: str


class EvaluationResponse(BaseModel):
    """Response schema for policy evaluation."""
    algorithm: str
    context: str
    allowed: bool
    blocking_violations: int
    warning_violations: int
    info_violations: int
    results: list[PolicyEvaluationResult]


class ViolationLogResponse(BaseModel):
    """Policy violation log response."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    policy_name: str
    severity: str
    message: str
    blocked: bool
    context_name: str
    operation: str
    identity_name: str | None
    team: str | None
    rule: str
    timestamp: datetime


class ViolationSummary(BaseModel):
    """Summary of policy violations."""
    total_violations: int
    blocked_count: int
    warning_count: int
    info_count: int
    by_policy: dict[str, int]
    by_context: dict[str, int]
    by_team: dict[str, int]
