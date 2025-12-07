#!/usr/bin/env python3
"""
SSH Guardian v3.0 - Direct Migration 025 Application
Applies approval workflow columns directly via Python
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from dbs.connection import get_connection

def apply_migration():
    """Apply migration 025 directly"""

    print("📝 Applying Migration 025: Approval Workflow")
    print("=" * 60)

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # Check if columns already exist
        cursor.execute("""
            SELECT COUNT(*) as count FROM INFORMATION_SCHEMA.COLUMNS
            WHERE TABLE_SCHEMA = DATABASE()
            AND TABLE_NAME = 'ip_blocks'
            AND COLUMN_NAME = 'approval_status'
        """)
        approval_status_exists = cursor.fetchone()['count'] > 0

        cursor.execute("""
            SELECT COUNT(*) as count FROM INFORMATION_SCHEMA.COLUMNS
            WHERE TABLE_SCHEMA = DATABASE()
            AND TABLE_NAME = 'ip_blocks'
            AND COLUMN_NAME = 'approved_by'
        """)
        approved_by_exists = cursor.fetchone()['count'] > 0

        cursor.execute("""
            SELECT COUNT(*) as count FROM INFORMATION_SCHEMA.COLUMNS
            WHERE TABLE_SCHEMA = DATABASE()
            AND TABLE_NAME = 'ip_blocks'
            AND COLUMN_NAME = 'approved_at'
        """)
        approved_at_exists = cursor.fetchone()['count'] > 0

        # Add approval_status column
        if not approval_status_exists:
            print("✓ Adding approval_status column...")
            cursor.execute("""
                ALTER TABLE ip_blocks
                ADD COLUMN approval_status ENUM('auto', 'pending', 'approved', 'rejected')
                DEFAULT 'auto'
                AFTER is_active
            """)
            print("  ✅ approval_status column added")
        else:
            print("  ⏭️  approval_status column already exists")

        # Add approved_by column
        if not approved_by_exists:
            print("✓ Adding approved_by column...")
            cursor.execute("""
                ALTER TABLE ip_blocks
                ADD COLUMN approved_by INT NULL
                AFTER approval_status
            """)
            print("  ✅ approved_by column added")
        else:
            print("  ⏭️  approved_by column already exists")

        # Add approved_at column
        if not approved_at_exists:
            print("✓ Adding approved_at column...")
            cursor.execute("""
                ALTER TABLE ip_blocks
                ADD COLUMN approved_at TIMESTAMP NULL
                AFTER approved_by
            """)
            print("  ✅ approved_at column added")
        else:
            print("  ⏭️  approved_at column already exists")

        # Add indexes
        print("\n✓ Adding indexes...")

        # Check and add idx_approval_pending
        cursor.execute("""
            SELECT COUNT(*) as count FROM INFORMATION_SCHEMA.STATISTICS
            WHERE TABLE_SCHEMA = DATABASE()
            AND TABLE_NAME = 'ip_blocks'
            AND INDEX_NAME = 'idx_approval_pending'
        """)
        if cursor.fetchone()['count'] == 0:
            cursor.execute("""
                CREATE INDEX idx_approval_pending
                ON ip_blocks(approval_status, is_active)
            """)
            print("  ✅ idx_approval_pending index added")
        else:
            print("  ⏭️  idx_approval_pending index already exists")

        # Check and add idx_approval_dashboard
        cursor.execute("""
            SELECT COUNT(*) as count FROM INFORMATION_SCHEMA.STATISTICS
            WHERE TABLE_SCHEMA = DATABASE()
            AND TABLE_NAME = 'ip_blocks'
            AND INDEX_NAME = 'idx_approval_dashboard'
        """)
        if cursor.fetchone()['count'] == 0:
            cursor.execute("""
                CREATE INDEX idx_approval_dashboard
                ON ip_blocks(approval_status, blocked_at)
            """)
            print("  ✅ idx_approval_dashboard index added")
        else:
            print("  ⏭️  idx_approval_dashboard index already exists")

        # Add foreign key if users table exists
        print("\n✓ Checking for users table...")
        cursor.execute("""
            SELECT COUNT(*) as count FROM INFORMATION_SCHEMA.TABLES
            WHERE TABLE_SCHEMA = DATABASE()
            AND TABLE_NAME = 'users'
        """)
        users_table_exists = cursor.fetchone()['count'] > 0

        if users_table_exists:
            # Check if FK already exists
            cursor.execute("""
                SELECT COUNT(*) as count FROM INFORMATION_SCHEMA.KEY_COLUMN_USAGE
                WHERE TABLE_SCHEMA = DATABASE()
                AND TABLE_NAME = 'ip_blocks'
                AND CONSTRAINT_NAME = 'fk_ip_blocks_approver'
            """)
            fk_exists = cursor.fetchone()['count'] > 0

            if not fk_exists:
                print("  ✓ Adding foreign key constraint...")
                cursor.execute("""
                    ALTER TABLE ip_blocks
                    ADD CONSTRAINT fk_ip_blocks_approver
                    FOREIGN KEY (approved_by) REFERENCES users(id) ON DELETE SET NULL
                """)
                print("  ✅ Foreign key added")
            else:
                print("  ⏭️  Foreign key already exists")
        else:
            print("  ⚠️  users table not found, skipping FK creation")

        # Update existing records
        print("\n✓ Updating existing records...")
        cursor.execute("""
            UPDATE ip_blocks
            SET approval_status = 'auto'
            WHERE approval_status IS NULL
        """)
        rows_updated = cursor.rowcount
        print(f"  ✅ Updated {rows_updated} records to approval_status='auto'")

        # Commit all changes
        conn.commit()

        print("\n" + "=" * 60)
        print("✅ Migration 025 applied successfully!")
        print("=" * 60)

        # Show final table structure
        print("\n📋 Updated ip_blocks table structure (approval columns):")
        cursor.execute("DESCRIBE ip_blocks")
        columns = cursor.fetchall()

        approval_cols = ['approval_status', 'approved_by', 'approved_at']
        for col in columns:
            if col['Field'] in approval_cols:
                print(f"  🆕 {col['Field']:25s} {col['Type']:35s} {col['Null']:5s} {col['Default'] or 'NULL'}")

        return True

    except Exception as e:
        print(f"\n❌ Migration failed: {e}")
        import traceback
        traceback.print_exc()
        conn.rollback()
        return False

    finally:
        cursor.close()
        conn.close()


if __name__ == "__main__":
    success = apply_migration()
    sys.exit(0 if success else 1)
