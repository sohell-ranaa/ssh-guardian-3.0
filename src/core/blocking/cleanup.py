"""
SSH Guardian v3.0 - Block Cleanup
Handles cleanup of expired IP blocks
"""

import sys
from pathlib import Path

# Add project paths
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
sys.path.append(str(PROJECT_ROOT / "dbs"))

from connection import get_connection


def cleanup_expired_blocks():
    """
    Deactivate expired blocks (where unblock_at < NOW())

    Returns:
        int: Number of blocks cleaned up
    """
    try:
        conn = get_connection()
        cursor = conn.cursor()

        try:
            # Deactivate expired blocks
            cursor.execute("""
                UPDATE ip_blocks
                SET is_active = FALSE
                WHERE is_active = TRUE
                AND auto_unblock = TRUE
                AND unblock_at IS NOT NULL
                AND unblock_at <= NOW()
            """)

            count = cursor.rowcount
            conn.commit()

            if count > 0:
                print(f"🧹 Cleaned up {count} expired IP blocks")

            return count

        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        print(f"❌ Error cleaning up expired blocks: {e}")
        return 0
