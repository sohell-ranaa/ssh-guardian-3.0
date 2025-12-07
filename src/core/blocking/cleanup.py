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
from .ufw_sync import create_ufw_unblock_commands


def cleanup_expired_blocks():
    """
    Deactivate expired blocks (where unblock_at < NOW())
    Also creates UFW unblock commands for affected agents

    Returns:
        dict: {
            'blocks_cleaned': int,
            'ufw_commands_created': int
        }
    """
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            # First get the blocks that will expire (for UFW unblock commands)
            cursor.execute("""
                SELECT id, ip_address_text
                FROM ip_blocks
                WHERE is_active = TRUE
                AND auto_unblock = TRUE
                AND unblock_at IS NOT NULL
                AND unblock_at <= NOW()
            """)

            expiring_blocks = cursor.fetchall()

            if not expiring_blocks:
                return {'blocks_cleaned': 0, 'ufw_commands_created': 0}

            # Create UFW unblock commands for each expiring block
            ufw_commands_total = 0
            for block in expiring_blocks:
                ufw_result = create_ufw_unblock_commands(
                    ip_address=block['ip_address_text'],
                    block_id=block['id']
                )
                ufw_commands_total += ufw_result.get('commands_created', 0)

            # Now deactivate the expired blocks
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
                print(f"🧹 Cleaned up {count} expired IP blocks (UFW commands: {ufw_commands_total})")

            return {
                'blocks_cleaned': count,
                'ufw_commands_created': ufw_commands_total
            }

        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        print(f"❌ Error cleaning up expired blocks: {e}")
        return {'blocks_cleaned': 0, 'ufw_commands_created': 0}
