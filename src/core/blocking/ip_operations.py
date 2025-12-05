"""
SSH Guardian v3.0 - IP Blocking Operations
Handles blocking and unblocking of IP addresses
"""

import sys
import uuid
from pathlib import Path
from datetime import datetime, timedelta

# Add project paths
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
sys.path.append(str(PROJECT_ROOT / "dbs"))

from connection import get_connection, ip_to_binary


def block_ip(ip_address, block_reason, block_source='rule_based', blocking_rule_id=None,
             trigger_event_id=None, failed_attempts=0, threat_level=None,
             block_duration_minutes=1440, auto_unblock=True, created_by_user_id=None):
    """
    Block an IP address

    Args:
        ip_address (str): IP address to block
        block_reason (str): Reason for blocking
        block_source (str): manual, rule_based, ml_threshold, api_reputation, anomaly_detection
        blocking_rule_id (int): ID of rule that triggered block (if applicable)
        trigger_event_id (int): ID of event that triggered block
        failed_attempts (int): Number of failed attempts
        threat_level (str): Threat level assessment
        block_duration_minutes (int): How long to block (0 = permanent)
        auto_unblock (bool): Automatically unblock after duration
        created_by_user_id (int): User ID if manually blocked

    Returns:
        dict: {
            'success': bool,
            'block_id': int,
            'message': str
        }
    """
    try:
        # Convert IP to binary
        ip_binary = ip_to_binary(ip_address)

        # Calculate unblock time
        if block_duration_minutes > 0 and auto_unblock:
            unblock_at = datetime.now() + timedelta(minutes=block_duration_minutes)
        else:
            unblock_at = None

        conn = get_connection()
        cursor = conn.cursor()

        try:
            # Check if IP is already blocked and active
            cursor.execute("""
                SELECT id FROM ip_blocks
                WHERE ip_address_text = %s AND is_active = TRUE
            """, (ip_address,))

            existing_block = cursor.fetchone()

            if existing_block:
                return {
                    'success': False,
                    'block_id': existing_block[0],
                    'message': f'IP {ip_address} is already blocked'
                }

            # MUTUAL EXCLUSIVITY: Remove from whitelist if exists
            cursor.execute("""
                UPDATE ip_whitelist
                SET is_active = FALSE, updated_at = NOW()
                WHERE ip_address_text = %s AND is_active = TRUE
            """, (ip_address,))
            removed_from_whitelist = cursor.rowcount > 0

            # MUTUAL EXCLUSIVITY: Remove from watchlist if exists
            cursor.execute("""
                UPDATE ip_watchlist
                SET is_active = FALSE, updated_at = NOW()
                WHERE ip_address_text = %s AND is_active = TRUE
            """, (ip_address,))
            removed_from_watchlist = cursor.rowcount > 0

            # Insert block
            cursor.execute("""
                INSERT INTO ip_blocks (
                    ip_address,
                    ip_address_text,
                    block_reason,
                    block_source,
                    blocking_rule_id,
                    trigger_event_id,
                    failed_attempts,
                    threat_level,
                    is_active,
                    blocked_at,
                    unblock_at,
                    auto_unblock,
                    created_by_user_id
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s, TRUE, NOW(), %s, %s, %s
                )
            """, (
                ip_binary,
                ip_address,
                block_reason,
                block_source,
                blocking_rule_id,
                trigger_event_id,
                failed_attempts,
                threat_level,
                unblock_at,
                auto_unblock,
                created_by_user_id
            ))

            block_id = cursor.lastrowid

            # Log blocking action
            action_uuid = str(uuid.uuid4())
            cursor.execute("""
                INSERT INTO blocking_actions (
                    action_uuid,
                    ip_block_id,
                    ip_address_text,
                    action_type,
                    action_source,
                    reason,
                    performed_by_user_id,
                    triggered_by_rule_id,
                    triggered_by_event_id
                ) VALUES (
                    %s, %s, %s, 'blocked', %s, %s, %s, %s, %s
                )
            """, (
                action_uuid,
                block_id,
                ip_address,
                'rule' if block_source == 'rule_based' else 'manual',
                block_reason,
                created_by_user_id,
                blocking_rule_id,
                trigger_event_id
            ))

            # Update rule statistics if rule-based
            if blocking_rule_id:
                cursor.execute("""
                    UPDATE blocking_rules
                    SET times_triggered = times_triggered + 1,
                        ips_blocked_total = ips_blocked_total + 1,
                        last_triggered_at = NOW()
                    WHERE id = %s
                """, (blocking_rule_id,))

            conn.commit()

            # Build message with mutual exclusivity info
            msg = f'IP {ip_address} blocked successfully'
            if removed_from_whitelist:
                msg += ' (removed from whitelist)'
            if removed_from_watchlist:
                msg += ' (removed from watchlist)'

            print(f"🚫 Blocked IP: {ip_address} - {block_reason}")

            return {
                'success': True,
                'block_id': block_id,
                'message': msg,
                'unblock_at': unblock_at.isoformat() if unblock_at else None,
                'removed_from_whitelist': removed_from_whitelist,
                'removed_from_watchlist': removed_from_watchlist
            }

        except Exception as e:
            conn.rollback()
            raise e
        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        print(f"❌ Error blocking IP {ip_address}: {e}")
        return {
            'success': False,
            'block_id': None,
            'message': f'Failed to block IP: {str(e)}'
        }


def unblock_ip(ip_address, unblock_reason='Manual unblock', unblocked_by_user_id=None):
    """
    Unblock an IP address

    Returns:
        dict: {
            'success': bool,
            'message': str
        }
    """
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            # Find active block
            cursor.execute("""
                SELECT id FROM ip_blocks
                WHERE ip_address_text = %s AND is_active = TRUE
            """, (ip_address,))

            block = cursor.fetchone()

            if not block:
                return {
                    'success': False,
                    'message': f'No active block found for IP {ip_address}'
                }

            block_id = block['id']

            # Update block to inactive
            cursor.execute("""
                UPDATE ip_blocks
                SET is_active = FALSE,
                    manually_unblocked_at = NOW(),
                    unblocked_by_user_id = %s,
                    unblock_reason = %s
                WHERE id = %s
            """, (unblocked_by_user_id, unblock_reason, block_id))

            # Log unblock action
            action_uuid = str(uuid.uuid4())
            cursor.execute("""
                INSERT INTO blocking_actions (
                    action_uuid,
                    ip_block_id,
                    ip_address_text,
                    action_type,
                    action_source,
                    reason,
                    performed_by_user_id
                ) VALUES (
                    %s, %s, %s, 'unblocked', 'manual', %s, %s
                )
            """, (action_uuid, block_id, ip_address, unblock_reason, unblocked_by_user_id))

            conn.commit()

            print(f"✅ Unblocked IP: {ip_address} - {unblock_reason}")

            return {
                'success': True,
                'message': f'IP {ip_address} unblocked successfully'
            }

        except Exception as e:
            conn.rollback()
            raise e
        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        print(f"❌ Error unblocking IP {ip_address}: {e}")
        return {
            'success': False,
            'message': f'Failed to unblock IP: {str(e)}'
        }


def block_ip_manual(ip_address, reason, user_id=None, duration_minutes=1440):
    """Manually block an IP address"""
    return block_ip(
        ip_address=ip_address,
        block_reason=reason,
        block_source='manual',
        block_duration_minutes=duration_minutes,
        created_by_user_id=user_id
    )
