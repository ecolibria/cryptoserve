"""Migration: Add user onboarding and invitation system.

This migration adds:
1. user_invitations table for email-based user invitations
2. Setup state tracking fields to organization_settings
3. Auto-provisioning configuration to organization_settings
4. Provisioning tracking fields to users table

The system supports:
- Email invitations with secure tokens and expiration
- Domain-based auto-provisioning
- GitHub organization-based auto-provisioning
- First admin automatic promotion
- Setup wizard state tracking

Run with: python -m migrations.005_add_user_onboarding
"""

import asyncio
import sys
from pathlib import Path

# Add backend directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from sqlalchemy import text
from app.database import get_engine


async def migrate():
    """Run migration to add user onboarding tables and columns."""
    engine = get_engine()

    async with engine.begin() as conn:
        # 1. Create user_invitations table
        result = await conn.execute(text("""
            SELECT name FROM sqlite_master
            WHERE type='table' AND name='user_invitations'
        """))
        if not result.fetchone():
            print("Creating user_invitations table...")
            await conn.execute(text("""
                CREATE TABLE user_invitations (
                    id VARCHAR(64) NOT NULL PRIMARY KEY,
                    tenant_id VARCHAR(64) NOT NULL,
                    email VARCHAR(255) NOT NULL,
                    role VARCHAR(50) NOT NULL DEFAULT 'developer',
                    token VARCHAR(64) NOT NULL UNIQUE,
                    status VARCHAR(16) NOT NULL DEFAULT 'pending',
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP NOT NULL,
                    accepted_at TIMESTAMP,
                    invited_by_id VARCHAR(64) NOT NULL,
                    accepted_by_user_id VARCHAR(64),
                    FOREIGN KEY (tenant_id) REFERENCES tenants(id),
                    FOREIGN KEY (invited_by_id) REFERENCES users(id),
                    FOREIGN KEY (accepted_by_user_id) REFERENCES users(id)
                )
            """))
            print("Created user_invitations table.")

            # Create indexes
            await conn.execute(text("""
                CREATE INDEX ix_invitations_tenant_id
                ON user_invitations(tenant_id)
            """))
            await conn.execute(text("""
                CREATE INDEX ix_invitations_email
                ON user_invitations(email)
            """))
            await conn.execute(text("""
                CREATE INDEX ix_invitations_token
                ON user_invitations(token)
            """))
            await conn.execute(text("""
                CREATE INDEX ix_invitations_tenant_status
                ON user_invitations(tenant_id, status)
            """))
            await conn.execute(text("""
                CREATE INDEX ix_invitations_email_status
                ON user_invitations(email, status)
            """))
            print("Created indexes on user_invitations.")
        else:
            print("user_invitations table already exists.")

        # 2. Add setup state columns to organization_settings
        # Check if setup_completed column exists
        result = await conn.execute(text("""
            PRAGMA table_info(organization_settings)
        """))
        columns = [row[1] for row in result.fetchall()]

        if "setup_completed" not in columns:
            print("Adding setup state columns to organization_settings...")
            await conn.execute(text("""
                ALTER TABLE organization_settings
                ADD COLUMN setup_completed BOOLEAN NOT NULL DEFAULT FALSE
            """))
            await conn.execute(text("""
                ALTER TABLE organization_settings
                ADD COLUMN setup_completed_at TIMESTAMP
            """))
            await conn.execute(text("""
                ALTER TABLE organization_settings
                ADD COLUMN setup_completed_by_id VARCHAR(64)
                REFERENCES users(id)
            """))
            print("Added setup state columns.")
        else:
            print("Setup state columns already exist.")

        # 3. Add auto-provisioning columns to organization_settings
        if "allowed_github_orgs" not in columns:
            print("Adding auto-provisioning columns to organization_settings...")
            await conn.execute(text("""
                ALTER TABLE organization_settings
                ADD COLUMN allowed_github_orgs TEXT NOT NULL DEFAULT '[]'
            """))
            await conn.execute(text("""
                ALTER TABLE organization_settings
                ADD COLUMN default_role VARCHAR(50) NOT NULL DEFAULT 'developer'
            """))
            await conn.execute(text("""
                ALTER TABLE organization_settings
                ADD COLUMN provisioning_mode VARCHAR(50) NOT NULL DEFAULT 'domain'
            """))
            print("Added auto-provisioning columns.")
        else:
            print("Auto-provisioning columns already exist.")

        # 4. Add provisioning tracking columns to users table
        result = await conn.execute(text("""
            PRAGMA table_info(users)
        """))
        user_columns = [row[1] for row in result.fetchall()]

        if "provisioning_source" not in user_columns:
            print("Adding provisioning tracking columns to users...")
            await conn.execute(text("""
                ALTER TABLE users
                ADD COLUMN provisioning_source VARCHAR(50)
            """))
            await conn.execute(text("""
                ALTER TABLE users
                ADD COLUMN invitation_id VARCHAR(64)
                REFERENCES user_invitations(id)
            """))
            print("Added provisioning tracking columns.")
        else:
            print("Provisioning tracking columns already exist.")

        # 5. Mark existing users as provisioned by 'first_user' if they're admins
        # or 'domain' if they're not admins (legacy users)
        await conn.execute(text("""
            UPDATE users
            SET provisioning_source = CASE
                WHEN is_admin = TRUE THEN 'first_user'
                ELSE 'domain'
            END
            WHERE provisioning_source IS NULL
        """))
        print("Updated existing users with provisioning_source.")

    print("\nMigration complete!")
    print("\nUser onboarding features are now available:")
    print("- Email invitation system with secure tokens")
    print("- Domain-based auto-provisioning")
    print("- GitHub organization auto-provisioning")
    print("- Setup wizard state tracking")
    print("- Provisioning source tracking for audit")


async def rollback():
    """Rollback migration by dropping added tables and columns."""
    engine = get_engine()

    async with engine.begin() as conn:
        print("Rolling back user onboarding migration...")

        # Drop user_invitations table
        print("Dropping user_invitations table...")
        await conn.execute(text("DROP TABLE IF EXISTS user_invitations"))
        print("Dropped user_invitations table.")

        # Note: SQLite doesn't support DROP COLUMN, so we can't easily rollback
        # the column additions to organization_settings and users tables.
        # In production, you would need to recreate the tables without these columns.
        print("\nNote: Column removals from organization_settings and users")
        print("tables are not supported in SQLite. Manual table recreation required.")

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
