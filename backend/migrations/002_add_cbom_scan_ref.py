"""Migration: Add scan_ref field for human-readable CBOM identifiers.

This migration adds:
1. scan_ref column to crypto_inventory_reports table
2. Generates CBOM-{uuid} format references for existing records
3. Creates unique index for lookup

Run with: python -m migrations.002_add_cbom_scan_ref
"""

import asyncio
import sys
import uuid
from pathlib import Path

# Add backend directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from sqlalchemy import text
from app.database import get_engine


def generate_scan_ref() -> str:
    """Generate a short, human-readable scan reference ID."""
    return f"CBOM-{uuid.uuid4().hex[:8].upper()}"


async def migrate():
    """Run migration to add scan_ref field."""
    engine = get_engine()

    async with engine.begin() as conn:
        # Check if scan_ref column exists
        result = await conn.execute(text("PRAGMA table_info(crypto_inventory_reports)"))
        columns = {row[1] for row in result.fetchall()}

        if "scan_ref" not in columns:
            print("Adding scan_ref column to crypto_inventory_reports table...")

            # Add the column (nullable first so we can populate existing rows)
            await conn.execute(text("""
                ALTER TABLE crypto_inventory_reports
                ADD COLUMN scan_ref VARCHAR(16)
            """))
            print("Added scan_ref column.")

            # Generate scan_ref for existing records
            result = await conn.execute(text("SELECT id FROM crypto_inventory_reports"))
            rows = result.fetchall()

            if rows:
                print(f"Generating scan_ref for {len(rows)} existing records...")
                for row in rows:
                    scan_ref = generate_scan_ref()
                    await conn.execute(
                        text("UPDATE crypto_inventory_reports SET scan_ref = :ref WHERE id = :id"),
                        {"ref": scan_ref, "id": row[0]}
                    )
                print("Updated existing records with scan_ref values.")

            # Create unique index
            print("Creating unique index on scan_ref...")
            await conn.execute(text("""
                CREATE UNIQUE INDEX IF NOT EXISTS ix_crypto_inventory_reports_scan_ref
                ON crypto_inventory_reports (scan_ref)
            """))
            print("Created unique index.")

        else:
            print("scan_ref column already exists.")

    print("\nMigration complete!")
    print("\nCBOM reports now have human-readable reference IDs like CBOM-A7B3C9D2")


if __name__ == "__main__":
    asyncio.run(migrate())
