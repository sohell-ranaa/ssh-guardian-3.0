#!/usr/bin/env python3
"""
Delete all INVALID event type records from the database
Run this script to clean up existing invalid events
"""

import sys
from pathlib import Path

# Add project paths
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.append(str(PROJECT_ROOT / "dbs"))

from connection import get_connection

def delete_invalid_events():
    """Delete all events with event_type = 'invalid'"""

    conn = get_connection()
    cursor = conn.cursor()

    try:
        # First, check how many invalid records exist
        cursor.execute("SELECT COUNT(*) FROM auth_events WHERE event_type = 'invalid'")
        count = cursor.fetchone()[0]

        print(f"Found {count} invalid event records in the database")

        if count == 0:
            print("✅ No invalid events to delete")
            return

        # Ask for confirmation
        response = input(f"\nDo you want to delete {count} invalid event records? (yes/no): ")

        if response.lower() != 'yes':
            print("❌ Deletion cancelled")
            return

        # Delete the records
        print(f"\n🗑️  Deleting {count} invalid events...")
        cursor.execute("DELETE FROM auth_events WHERE event_type = 'invalid'")
        conn.commit()

        deleted = cursor.rowcount
        print(f"✅ Successfully deleted {deleted} invalid event records")

        # Verify deletion
        cursor.execute("SELECT COUNT(*) FROM auth_events WHERE event_type = 'invalid'")
        remaining = cursor.fetchone()[0]

        if remaining == 0:
            print("✅ Verification successful: No invalid events remaining")
        else:
            print(f"⚠️  Warning: {remaining} invalid events still remain")

    except Exception as e:
        conn.rollback()
        print(f"❌ Error deleting invalid events: {e}")
        raise

    finally:
        cursor.close()
        conn.close()


if __name__ == '__main__':
    print("=" * 60)
    print("SSH Guardian v3.0 - Delete Invalid Events")
    print("=" * 60)
    print()

    try:
        delete_invalid_events()
    except KeyboardInterrupt:
        print("\n\n❌ Operation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Fatal error: {e}")
        sys.exit(1)

    print()
    print("=" * 60)
    print("✅ Operation completed")
    print("=" * 60)
