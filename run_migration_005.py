#!/usr/bin/env python3
"""
Run Migration 005: Add System Rule Flag
"""

import sys
import os

# Add dbs directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'dbs'))

from connection import get_connection

def run_migration():
    """Run the migration to add is_system_rule column"""

    print("=" * 70)
    print("Migration 005: Adding is_system_rule flag to blocking_rules")
    print("=" * 70)

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # Step 1: Add column
        print("\n1️⃣  Adding is_system_rule column...")
        cursor.execute("""
            ALTER TABLE blocking_rules
            ADD COLUMN is_system_rule TINYINT(1) NOT NULL DEFAULT 0
            COMMENT 'Flag indicating if this is a protected system rule (cannot be deleted)'
            AFTER is_enabled
        """)
        print("   ✅ Column added successfully")

        # Step 2: Mark first 6 rules as system rules
        print("\n2️⃣  Marking first 6 rules as system rules...")
        cursor.execute("""
            UPDATE blocking_rules
            SET is_system_rule = 1
            WHERE id <= 6
        """)
        affected = cursor.rowcount
        print(f"   ✅ {affected} rules marked as system rules")

        # Step 3: Add index
        print("\n3️⃣  Adding index on is_system_rule...")
        cursor.execute("""
            CREATE INDEX idx_is_system_rule ON blocking_rules(is_system_rule)
        """)
        print("   ✅ Index created successfully")

        # Commit changes
        conn.commit()
        print("\n4️⃣  Committing changes...")
        print("   ✅ Migration completed successfully")

        # Verification
        print("\n" + "=" * 70)
        print("Verification:")
        print("=" * 70)

        cursor.execute("""
            SELECT
                id,
                rule_name,
                is_system_rule,
                CASE
                    WHEN is_system_rule = 1 THEN 'PROTECTED (System Rule)'
                    ELSE 'User Rule (Can Delete)'
                END as protection_status
            FROM blocking_rules
            ORDER BY id
        """)

        rules = cursor.fetchall()
        print(f"\n{'ID':<5} {'Rule Name':<40} {'System':<8} {'Status':<30}")
        print("-" * 85)
        for rule in rules:
            print(f"{rule['id']:<5} {rule['rule_name']:<40} {rule['is_system_rule']:<8} {rule['protection_status']:<30}")

        # Summary
        print("\n" + "=" * 70)
        cursor.execute("""
            SELECT
                is_system_rule,
                COUNT(*) as rule_count,
                CASE
                    WHEN is_system_rule = 1 THEN 'System Rules (Protected)'
                    ELSE 'User Rules (Deletable)'
                END as rule_type
            FROM blocking_rules
            GROUP BY is_system_rule
        """)

        summary = cursor.fetchall()
        print("Summary:")
        print("-" * 70)
        for row in summary:
            print(f"  {row['rule_type']}: {row['rule_count']} rules")
        print("=" * 70)

        return True

    except Exception as e:
        conn.rollback()
        print(f"\n❌ Migration failed: {e}")
        import traceback
        traceback.print_exc()
        return False

    finally:
        cursor.close()
        conn.close()


if __name__ == "__main__":
    success = run_migration()
    sys.exit(0 if success else 1)
