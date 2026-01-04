"""Migration: Add expedited approval requests table.

This migration adds:
1. expedited_approval_requests table for tracking promotion approval workflow
2. Supports trust score calculation and audit trail

The approval requests table stores:
- Expedited promotion requests with justification
- Requester trust score (calculated from history)
- Approval status and approver information
- Follow-up tracking for compliance

Run with: python -m migrations.004_add_approval_requests
"""

import asyncio
import sys
from pathlib import Path

# Add backend directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from sqlalchemy import text
from app.database import get_engine


async def migrate():
    """Run migration to add expedited approval requests table."""
    engine = get_engine()

    async with engine.begin() as conn:
        # Check if expedited_approval_requests table exists
        result = await conn.execute(text("""
            SELECT name FROM sqlite_master
            WHERE type='table' AND name='expedited_approval_requests'
        """))
        if not result.fetchone():
            print("Creating expedited_approval_requests table...")
            await conn.execute(text("""
                CREATE TABLE expedited_approval_requests (
                    id VARCHAR(64) NOT NULL PRIMARY KEY,
                    request_id VARCHAR(20) NOT NULL UNIQUE,
                    tenant_id VARCHAR(64) NOT NULL,
                    application_id VARCHAR(64) NOT NULL,
                    application_name VARCHAR(256) NOT NULL,
                    priority VARCHAR(20) NOT NULL,
                    justification TEXT NOT NULL,
                    contexts JSON NOT NULL DEFAULT '[]',
                    thresholds_bypassed JSON NOT NULL DEFAULT '[]',
                    requester_user_id VARCHAR(64) NOT NULL,
                    requester_email VARCHAR(256) NOT NULL,
                    requester_trust_score REAL NOT NULL DEFAULT 1.0,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP,
                    status VARCHAR(20) NOT NULL DEFAULT 'pending',
                    approved_by_user_id VARCHAR(64),
                    approved_by_email VARCHAR(256),
                    approved_at TIMESTAMP,
                    approval_notes TEXT,
                    follow_up_required BOOLEAN NOT NULL DEFAULT FALSE,
                    follow_up_date TIMESTAMP,
                    follow_up_completed BOOLEAN NOT NULL DEFAULT FALSE,
                    FOREIGN KEY (tenant_id) REFERENCES tenants(id),
                    FOREIGN KEY (application_id) REFERENCES applications(id),
                    FOREIGN KEY (requester_user_id) REFERENCES users(id),
                    FOREIGN KEY (approved_by_user_id) REFERENCES users(id)
                )
            """))
            print("Created expedited_approval_requests table.")

            # Create indexes for common queries
            await conn.execute(text("""
                CREATE INDEX ix_approval_requests_tenant_id
                ON expedited_approval_requests(tenant_id)
            """))
            print("Created index on tenant_id.")

            await conn.execute(text("""
                CREATE INDEX ix_approval_requests_status
                ON expedited_approval_requests(status)
            """))
            print("Created index on status.")

            await conn.execute(text("""
                CREATE INDEX ix_approval_requests_requester
                ON expedited_approval_requests(requester_user_id)
            """))
            print("Created index on requester_user_id.")

            await conn.execute(text("""
                CREATE INDEX ix_approval_requests_application
                ON expedited_approval_requests(application_id)
            """))
            print("Created index on application_id.")

            await conn.execute(text("""
                CREATE INDEX ix_approval_requests_request_id
                ON expedited_approval_requests(request_id)
            """))
            print("Created index on request_id.")

        else:
            print("expedited_approval_requests table already exists.")

    print("\nMigration complete!")
    print("\nApproval workflow features are now available:")
    print("- Expedited promotion requests with trust score calculation")
    print("- Approval/rejection workflow with audit trail")
    print("- Follow-up tracking for compliance")


async def rollback():
    """Rollback migration by dropping expedited_approval_requests table."""
    engine = get_engine()

    async with engine.begin() as conn:
        print("Dropping expedited_approval_requests table...")
        await conn.execute(text("DROP TABLE IF EXISTS expedited_approval_requests"))
        print("Dropped expedited_approval_requests table.")

    print("\nRollback complete!")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--rollback", action="store_true", help="Rollback the migration")
    args = parser.parse_args()

    if args.rollback:
        asyncio.run(rollback())
    else:
        asyncio.run(migrate())
