"""Migration: Add post-quantum cryptography key storage.

This migration adds:
1. pqc_keys table for storing ML-KEM and ML-DSA key pairs
2. key_type enum for KeyType (symmetric, pqc_kem, pqc_sig)

The PQC keys table stores:
- ML-KEM key pairs for hybrid encryption
- ML-DSA key pairs for post-quantum signatures
- Private keys are encrypted at rest using context-derived keys

Run with: python -m migrations.003_add_pqc_keys
"""

import asyncio
import sys
from pathlib import Path

# Add backend directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from sqlalchemy import text
from app.database import get_engine


async def migrate():
    """Run migration to add PQC key storage support."""
    engine = get_engine()

    async with engine.begin() as conn:
        # Check if pqc_keys table exists
        result = await conn.execute(text("""
            SELECT name FROM sqlite_master
            WHERE type='table' AND name='pqc_keys'
        """))
        if not result.fetchone():
            print("Creating pqc_keys table...")
            await conn.execute(text("""
                CREATE TABLE pqc_keys (
                    id VARCHAR(64) NOT NULL PRIMARY KEY,
                    context VARCHAR(64) NOT NULL,
                    key_type VARCHAR(16) NOT NULL DEFAULT 'pqc_kem',
                    algorithm VARCHAR(32) NOT NULL,
                    public_key BLOB NOT NULL,
                    encrypted_private_key BLOB NOT NULL,
                    private_key_nonce BLOB NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    status VARCHAR(16) NOT NULL DEFAULT 'active',
                    FOREIGN KEY (context) REFERENCES contexts(name)
                )
            """))
            print("Created pqc_keys table.")

            # Create index on context for faster lookups
            await conn.execute(text("""
                CREATE INDEX ix_pqc_keys_context ON pqc_keys(context)
            """))
            print("Created index on pqc_keys.context.")

            # Create index on status for filtering
            await conn.execute(text("""
                CREATE INDEX ix_pqc_keys_status ON pqc_keys(status)
            """))
            print("Created index on pqc_keys.status.")

        else:
            print("pqc_keys table already exists.")

    print("\nMigration complete!")
    print("\nPQC key storage is now available:")
    print("- ML-KEM key pairs for hybrid encryption (FIPS 203)")
    print("- ML-DSA key pairs for PQC signatures (FIPS 204)")
    print("- Private keys encrypted at rest using AES-256-GCM")


async def rollback():
    """Rollback migration by dropping pqc_keys table."""
    engine = get_engine()

    async with engine.begin() as conn:
        print("Dropping pqc_keys table...")
        await conn.execute(text("DROP TABLE IF EXISTS pqc_keys"))
        print("Dropped pqc_keys table.")

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
