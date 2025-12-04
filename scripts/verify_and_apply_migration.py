"""
Verify and apply migration 003 - Add api_key to agents table
"""

import sys
from pathlib import Path

# Add project paths
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.append(str(PROJECT_ROOT / "dbs"))

from connection import get_connection


def check_api_key_column():
    """Check if api_key column exists"""
    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("""
            SELECT COLUMN_NAME
            FROM INFORMATION_SCHEMA.COLUMNS
            WHERE TABLE_SCHEMA = 'ssh_guardian_v3'
            AND TABLE_NAME = 'agents'
            AND COLUMN_NAME = 'api_key'
        """)

        result = cursor.fetchone()
        return result is not None

    finally:
        cursor.close()
        conn.close()


def apply_migration():
    """Apply migration 003"""
    conn = get_connection()
    cursor = conn.cursor()

    try:
        print("Applying migration 003: Add api_key to agents table...")

        # Add api_key column
        cursor.execute("""
            ALTER TABLE agents
            ADD COLUMN api_key VARCHAR(100) UNIQUE AFTER agent_id
        """)

        # Add index
        cursor.execute("""
            ALTER TABLE agents
            ADD INDEX idx_api_key (api_key)
        """)

        conn.commit()
        print("✅ Migration 003 applied successfully")

    except Exception as e:
        conn.rollback()
        print(f"❌ Error applying migration: {e}")

    finally:
        cursor.close()
        conn.close()


if __name__ == "__main__":
    print("\n🔍 Checking if api_key column exists...")

    if check_api_key_column():
        print("✅ api_key column already exists")
    else:
        print("❌ api_key column missing")
        apply_migration()

    # Verify again
    print("\n🔍 Verifying...")
    if check_api_key_column():
        print("✅ api_key column confirmed")
    else:
        print("❌ api_key column still missing")

    print()
