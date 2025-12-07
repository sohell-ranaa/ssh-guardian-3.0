#!/usr/bin/env python3
"""
SSH Guardian v3.0 - Migration Verification
Verify that migration 025 was applied successfully
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from dbs.connection import get_connection

def verify_migration():
    """Verify migration 025 approval workflow columns"""

    print("🔍 Verifying Migration 025: Approval Workflow")
    print("=" * 60)

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # Get table structure
        print("\n📋 Checking ip_blocks table structure...")
        cursor.execute("DESCRIBE ip_blocks")
        columns = cursor.fetchall()

        # Check for approval workflow columns
        approval_columns = ['approval_status', 'approved_by', 'approved_at']
        found_columns = {col['Field'] for col in columns}

        print("\n✓ Existing columns in ip_blocks:")
        for col in columns:
            marker = "  🆕" if col['Field'] in approval_columns else "    "
            print(f"{marker} {col['Field']:25s} {col['Type']:30s} {col['Null']:5s} {col['Key']:5s} {col['Default'] or 'NULL'}")

        print("\n" + "=" * 60)
        print("📊 Verification Results:")
        print("=" * 60)

        all_found = True
        for col_name in approval_columns:
            if col_name in found_columns:
                print(f"✅ Column '{col_name}' exists")
            else:
                print(f"❌ Column '{col_name}' NOT FOUND")
                all_found = False

        # Check indexes
        print("\n📇 Checking indexes...")
        cursor.execute("SHOW INDEX FROM ip_blocks WHERE Key_name LIKE '%approval%'")
        indexes = cursor.fetchall()

        if indexes:
            print("\n✓ Approval-related indexes:")
            for idx in indexes:
                print(f"    - {idx['Key_name']}: {idx['Column_name']}")
        else:
            print("⚠️  No approval-related indexes found")

        # Check for sample data
        print("\n📈 Checking existing data...")
        cursor.execute("SELECT COUNT(*) as total FROM ip_blocks")
        count = cursor.fetchone()
        print(f"   Total ip_blocks records: {count['total']}")

        if count['total'] > 0:
            cursor.execute("""
                SELECT approval_status, COUNT(*) as count
                FROM ip_blocks
                GROUP BY approval_status
            """)
            status_counts = cursor.fetchall()
            print("\n   Approval status distribution:")
            for row in status_counts:
                print(f"      {row['approval_status']}: {row['count']}")

        print("\n" + "=" * 60)
        if all_found:
            print("✅ Migration 025 verification PASSED")
            print("=" * 60)
            return True
        else:
            print("❌ Migration 025 verification FAILED")
            print("=" * 60)
            return False

    except Exception as e:
        print(f"\n❌ Verification error: {e}")
        import traceback
        traceback.print_exc()
        return False

    finally:
        cursor.close()
        conn.close()


if __name__ == "__main__":
    success = verify_migration()
    sys.exit(0 if success else 1)
