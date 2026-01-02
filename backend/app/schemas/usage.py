"""Usage statistics schemas.

Provides aggregated usage metrics for contexts and operations.
"""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


def to_camel(string: str) -> str:
    """Convert snake_case to camelCase."""
    components = string.split("_")
    return components[0] + "".join(x.title() for x in components[1:])


class ContextUsageStats(BaseModel):
    """Usage statistics for a single context."""
    model_config = ConfigDict(
        from_attributes=True,
        alias_generator=to_camel,
        populate_by_name=True,
    )

    context_id: str = Field(description="Context name/ID")
    context_name: str = Field(description="Context display name")
    encrypt_calls: int = Field(default=0, description="Number of encrypt operations")
    decrypt_calls: int = Field(default=0, description="Number of decrypt operations")
    sign_calls: int = Field(default=0, description="Number of sign operations")
    verify_calls: int = Field(default=0, description="Number of verify operations")


class ErrorSummary(BaseModel):
    """Summary of errors for a context."""
    model_config = ConfigDict(
        from_attributes=True,
        alias_generator=to_camel,
        populate_by_name=True,
    )

    context_name: str = Field(description="Context where error occurred")
    error_type: str = Field(description="Type of error (e.g., DECRYPTION_FAILED)")
    count: int = Field(description="Number of occurrences")
    last_occurred: datetime = Field(description="Most recent occurrence")


class DailyUsageStats(BaseModel):
    """Daily aggregated usage statistics."""
    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
    )

    date: str = Field(description="Date in YYYY-MM-DD format")
    total_calls: int = Field(description="Total API calls on this date")


class UsagePeriod(BaseModel):
    """Time period for usage statistics."""
    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
    )

    start: datetime = Field(description="Period start time")
    end: datetime = Field(description="Period end time")


class UsageStatsResponse(BaseModel):
    """Complete usage statistics response."""
    model_config = ConfigDict(
        from_attributes=True,
        alias_generator=to_camel,
        populate_by_name=True,
    )

    org_id: str = Field(description="Organization/tenant ID")
    period: UsagePeriod = Field(description="Time period covered")
    total_calls: int = Field(description="Total API calls in period")
    by_context: list[ContextUsageStats] = Field(
        default_factory=list,
        description="Breakdown by context"
    )
    errors: list[ErrorSummary] = Field(
        default_factory=list,
        description="Error summary"
    )
    daily_breakdown: list[DailyUsageStats] = Field(
        default_factory=list,
        description="Daily usage breakdown"
    )


class UsageStatsRequest(BaseModel):
    """Request parameters for usage statistics."""
    start_date: datetime | None = Field(
        default=None,
        description="Start of period (defaults to 30 days ago)"
    )
    end_date: datetime | None = Field(
        default=None,
        description="End of period (defaults to now)"
    )
    context_ids: list[str] | None = Field(
        default=None,
        description="Filter by specific contexts"
    )
