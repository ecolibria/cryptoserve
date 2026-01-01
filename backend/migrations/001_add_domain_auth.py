"""Migration: Add domain-based authentication support.

This migration adds:
1. organization_settings table for domain-based access control
2. email_verified and email_domain columns to users table

Run with: python -m migrations.001_add_domain_auth
"""

import asyncio
import sys
from pathlib import Path

# Add backend directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from sqlalchemy import text
from app.database import get_engine, init_db


async def migrate():
    """Run migration to add domain-based auth support."""
    engine = get_engine()

    async with engine.begin() as conn:
        # Check if organization_settings table exists
        result = await conn.execute(text("""
            SELECT name FROM sqlite_master
            WHERE type='table' AND name='organization_settings'
        """))
        if not result.fetchone():
            print("Creating organization_settings table...")
            await conn.execute(text("""
                CREATE TABLE organization_settings (
                    id INTEGER NOT NULL PRIMARY KEY,
                    allowed_domains TEXT NOT NULL DEFAULT '[]',
                    require_domain_match BOOLEAN NOT NULL DEFAULT 1,
                    allow_any_github_user BOOLEAN NOT NULL DEFAULT 0,
                    admin_email VARCHAR(255),
                    organization_name VARCHAR(255),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """))
            print("Created organization_settings table.")
        else:
            print("organization_settings table already exists.")

        # Check if email_verified column exists in users table
        result = await conn.execute(text("PRAGMA table_info(users)"))
        columns = {row[1] for row in result.fetchall()}

        if "email_verified" not in columns:
            print("Adding email_verified column to users table...")
            await conn.execute(text("""
                ALTER TABLE users ADD COLUMN email_verified BOOLEAN NOT NULL DEFAULT 0
            """))
            print("Added email_verified column.")
        else:
            print("email_verified column already exists.")

        if "email_domain" not in columns:
            print("Adding email_domain column to users table...")
            await conn.execute(text("""
                ALTER TABLE users ADD COLUMN email_domain VARCHAR(255)
            """))
            print("Added email_domain column.")
        else:
            print("email_domain column already exists.")

    print("\nMigration complete!")
    print("\nNew features available:")
    print("- Domain-based access control via Admin > Settings")
    print("- First user to login becomes admin (or set ADMIN_EMAIL env var)")
    print("- Users from unauthorized domains see clear error message")


if __name__ == "__main__":
    asyncio.run(migrate())
