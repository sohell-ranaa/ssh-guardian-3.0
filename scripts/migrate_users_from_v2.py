"""
Migrate users from SSH Guardian v2.0 to v3.0
Copies all users with their password hashes and settings
"""

import sys
from pathlib import Path
import mysql.connector

# Add project paths
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.append(str(PROJECT_ROOT / "dbs"))

# Import v3 connection
import connection as v3_connection


def get_v2_connection():
    """Direct connection to v2 database"""
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="123123",
        database="ssh_guardian_20",
        charset="utf8mb4"
    )


def migrate_users():
    """Migrate all users from v2 to v3"""

    # Get v2 users
    print("\n" + "=" * 80)
    print("📋 MIGRATING USERS FROM V2 TO V3")
    print("=" * 80)

    v2_conn = get_v2_connection()
    v2_cursor = v2_conn.cursor(dictionary=True)

    v2_cursor.execute("""
        SELECT
            email, password_hash, full_name, role_id,
            is_active, is_email_verified, last_login, created_at
        FROM users
        ORDER BY id
    """)
    v2_users = v2_cursor.fetchall()

    print(f"\n✅ Found {len(v2_users)} users in v2 database (ssh_guardian_20)")

    # Get v3 connection
    v3_conn = v3_connection.get_connection()
    v3_cursor = v3_conn.cursor(dictionary=True)

    # Track results
    migrated = 0
    skipped = 0
    errors = 0

    for user in v2_users:
        try:
            # Check if user already exists in v3
            v3_cursor.execute("SELECT id FROM users WHERE email = %s", (user['email'],))
            existing = v3_cursor.fetchone()

            if existing:
                print(f"⏭️  Skipped: {user['email']:40s} (already exists in v3)")
                skipped += 1
                continue

            # Insert user into v3
            v3_cursor.execute("""
                INSERT INTO users (
                    email, password_hash, full_name, role_id,
                    is_active, is_email_verified, last_login, created_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                user['email'],
                user['password_hash'],
                user['full_name'],
                user['role_id'],
                user['is_active'],
                user['is_email_verified'],
                user['last_login'],
                user['created_at']
            ))

            v3_conn.commit()

            status = "✅" if user['is_active'] else "🔒"
            print(f"{status} Migrated: {user['email']:40s} | {user['full_name']:25s} | Role {user['role_id']}")
            migrated += 1

        except Exception as e:
            print(f"❌ Error: {user['email']:40s} - {str(e)}")
            v3_conn.rollback()
            errors += 1

    # Close connections
    v2_cursor.close()
    v2_conn.close()
    v3_cursor.close()
    v3_conn.close()

    # Summary
    print("\n" + "=" * 80)
    print("📊 MIGRATION SUMMARY")
    print("=" * 80)
    print(f"✅ Migrated:  {migrated} users")
    print(f"⏭️  Skipped:   {skipped} users (already exist)")
    print(f"❌ Errors:    {errors} users")
    print("=" * 80)

    if migrated > 0:
        print("\n🎉 Users successfully migrated to v3.0!")
        print("   All password hashes preserved - users can login with existing passwords")

    return migrated > 0


if __name__ == "__main__":
    print("\n🔄 SSH Guardian v2.0 → v3.0 User Migration")

    try:
        success = migrate_users()

        if success:
            print("\n✅ Migration completed successfully!\n")
            sys.exit(0)
        else:
            print("\n⚠️  No new users to migrate\n")
            sys.exit(0)

    except Exception as e:
        print(f"\n❌ Migration failed: {e}\n")
        sys.exit(1)
