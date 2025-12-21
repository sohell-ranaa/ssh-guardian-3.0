"""
Notification Pane Routes - API endpoints for Facebook-style notification pane
Real-time notifications with read/unread status and quick actions
"""
import sys
from pathlib import Path
from flask import Blueprint, jsonify, request
from datetime import datetime

# Add database path
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
sys.path.append(str(PROJECT_ROOT / "dbs"))
sys.path.append(str(PROJECT_ROOT / "src" / "core"))

from connection import get_connection
from cache import get_cache, cache_key

notification_pane_routes = Blueprint('notification_pane', __name__)

# Cache TTLs
UNREAD_COUNT_TTL = 30   # 30 seconds for unread count (needs to be fresh)
RECENT_NOTIFS_TTL = 60  # 1 minute for recent notifications


def invalidate_pane_cache():
    """Invalidate notification pane caches"""
    cache = get_cache()
    cache.delete_pattern('notif_pane')


@notification_pane_routes.route('/unread-count', methods=['GET'])
def get_unread_count():
    """Get count of unread notifications for badge"""
    try:
        # Try cache first (short TTL)
        cache = get_cache()
        cache_k = cache_key('notif_pane', 'unread_count')
        cached = cache.get(cache_k)
        if cached is not None:
            return jsonify({
                'success': True,
                'data': {'count': cached},
                'from_cache': True
            })

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Count notifications that are not acknowledged as unread
        cursor.execute("""
            SELECT COUNT(*) as count
            FROM notifications
            WHERE is_acknowledged = 0
        """)

        result = cursor.fetchone()
        count = result['count'] if result else 0

        cursor.close()
        conn.close()

        # Cache the result
        cache.set(cache_k, count, UNREAD_COUNT_TTL)

        return jsonify({
            'success': True,
            'data': {'count': count},
            'from_cache': False
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


def derive_trigger_type(subject, message, is_security_alert):
    """Derive trigger type from notification content for categorization"""
    subject_lower = (subject or '').lower()
    message_lower = (message or '').lower()

    # Security alerts
    if 'brute force' in subject_lower or 'brute force' in message_lower:
        return 'brute_force_detected'
    if 'high risk' in subject_lower or 'suspicious' in subject_lower:
        return 'high_risk_detected'
    if 'failed auth' in subject_lower or 'failed login' in subject_lower:
        return 'failed_auth'
    if is_security_alert:
        return 'suspicious_activity'

    # IP blocking
    if 'blocked' in subject_lower and 'ip' in subject_lower:
        return 'ip_blocked'
    if 'unblocked' in subject_lower or 'removed' in subject_lower:
        return 'ip_unblocked'

    # System
    if 'agent' in subject_lower:
        return 'agent_status'
    if 'config' in subject_lower or 'updated' in subject_lower:
        return 'config_change'

    return 'system'


def derive_priority(subject, is_security_alert):
    """Derive priority from notification content"""
    subject_lower = (subject or '').lower()

    if 'critical' in subject_lower or 'urgent' in subject_lower:
        return 'critical'
    if 'high risk' in subject_lower or 'attack' in subject_lower:
        return 'high'
    if is_security_alert:
        return 'high'
    if 'blocked' in subject_lower:
        return 'normal'
    return 'low'


@notification_pane_routes.route('/recent', methods=['GET'])
def get_recent_notifications():
    """Get recent notifications for pane display (max 20)"""
    try:
        limit = min(int(request.args.get('limit', 20)), 50)
        unread_only = request.args.get('unread_only', 'false').lower() == 'true'

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Build query based on filter - using simplified schema
        if unread_only:
            cursor.execute("""
                SELECT
                    n.id,
                    n.channel,
                    n.recipient,
                    n.subject as message_title,
                    n.message as message_body,
                    n.status,
                    n.ip_address,
                    n.username,
                    n.is_security_alert,
                    n.ml_score,
                    n.ml_factors,
                    n.geo_data,
                    n.agent_id,
                    n.is_acknowledged as is_read,
                    n.acknowledged_at as read_at,
                    n.created_at,
                    nr.rule_name,
                    a.display_name as agent_name,
                    a.hostname as agent_hostname
                FROM notifications n
                LEFT JOIN notification_rules nr ON n.notification_rule_id = nr.id
                LEFT JOIN agents a ON n.agent_id = a.id
                WHERE n.is_acknowledged = 0
                ORDER BY n.created_at DESC
                LIMIT %s
            """, (limit,))
        else:
            cursor.execute("""
                SELECT
                    n.id,
                    n.channel,
                    n.recipient,
                    n.subject as message_title,
                    n.message as message_body,
                    n.status,
                    n.ip_address,
                    n.username,
                    n.is_security_alert,
                    n.ml_score,
                    n.ml_factors,
                    n.geo_data,
                    n.agent_id,
                    n.is_acknowledged as is_read,
                    n.acknowledged_at as read_at,
                    n.created_at,
                    nr.rule_name,
                    a.display_name as agent_name,
                    a.hostname as agent_hostname
                FROM notifications n
                LEFT JOIN notification_rules nr ON n.notification_rule_id = nr.id
                LEFT JOIN agents a ON n.agent_id = a.id
                ORDER BY n.created_at DESC
                LIMIT %s
            """, (limit,))

        notifications = cursor.fetchall()

        # Format timestamps and derive trigger_type/priority
        for notif in notifications:
            if notif.get('created_at'):
                notif['created_at'] = notif['created_at'].isoformat()
            if notif.get('read_at'):
                notif['read_at'] = notif['read_at'].isoformat()
            # Ensure is_read is boolean
            notif['is_read'] = bool(notif.get('is_read', False))
            # Derive trigger_type and priority for categorization
            is_security = bool(notif.get('is_security_alert', False))
            notif['trigger_type'] = derive_trigger_type(
                notif.get('message_title'),
                notif.get('message_body'),
                is_security
            )
            notif['priority'] = derive_priority(notif.get('message_title'), is_security)
            # Parse JSON fields
            if notif.get('ml_factors'):
                try:
                    import json
                    if isinstance(notif['ml_factors'], str):
                        notif['ml_factors'] = json.loads(notif['ml_factors'])
                except:
                    notif['ml_factors'] = []
            if notif.get('geo_data'):
                try:
                    import json
                    if isinstance(notif['geo_data'], str):
                        notif['geo_data'] = json.loads(notif['geo_data'])
                except:
                    notif['geo_data'] = {}
            # Set agent name
            notif['agent_name'] = notif.get('agent_name') or notif.get('agent_hostname') or None

        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'data': {
                'notifications': notifications,
                'count': len(notifications)
            }
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@notification_pane_routes.route('/<int:notif_id>/read', methods=['POST'])
def mark_as_read(notif_id):
    """Mark a single notification as read (set is_acknowledged = 1)"""
    try:
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            UPDATE notifications
            SET is_acknowledged = 1, acknowledged_at = NOW()
            WHERE id = %s AND is_acknowledged = 0
        """, (notif_id,))

        affected = cursor.rowcount
        conn.commit()

        cursor.close()
        conn.close()

        # Invalidate cache
        invalidate_pane_cache()

        return jsonify({
            'success': True,
            'data': {
                'marked_read': affected > 0,
                'notification_id': notif_id
            }
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@notification_pane_routes.route('/mark-all-read', methods=['POST'])
def mark_all_read():
    """Mark all notifications as read (set is_acknowledged = 1)"""
    try:
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            UPDATE notifications
            SET is_acknowledged = 1, acknowledged_at = NOW()
            WHERE is_acknowledged = 0
        """)

        affected = cursor.rowcount
        conn.commit()

        cursor.close()
        conn.close()

        # Invalidate cache
        invalidate_pane_cache()

        return jsonify({
            'success': True,
            'data': {
                'marked_read_count': affected
            },
            'message': f'Marked {affected} notifications as read'
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@notification_pane_routes.route('/<int:notif_id>/unread', methods=['POST'])
def mark_as_unread(notif_id):
    """Mark a notification as unread (set status to 'pending')"""
    try:
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            UPDATE notifications
            SET status = 'pending', sent_at = NULL
            WHERE id = %s
        """, (notif_id,))

        affected = cursor.rowcount
        conn.commit()

        cursor.close()
        conn.close()

        # Invalidate cache
        invalidate_pane_cache()

        return jsonify({
            'success': True,
            'data': {
                'marked_unread': affected > 0,
                'notification_id': notif_id
            }
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@notification_pane_routes.route('/<int:notif_id>', methods=['DELETE'])
def delete_notification(notif_id):
    """Delete a notification from the pane"""
    try:
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            DELETE FROM notifications WHERE id = %s
        """, (notif_id,))

        affected = cursor.rowcount
        conn.commit()

        cursor.close()
        conn.close()

        # Invalidate cache
        invalidate_pane_cache()

        if affected == 0:
            return jsonify({
                'success': False,
                'error': 'Notification not found'
            }), 404

        return jsonify({
            'success': True,
            'message': 'Notification deleted'
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@notification_pane_routes.route('/<int:notif_id>/action', methods=['POST'])
def execute_quick_action(notif_id):
    """Execute a quick action from notification (block IP, view event, etc.)"""
    try:
        data = request.get_json() or {}
        action = data.get('action')

        if not action:
            return jsonify({
                'success': False,
                'error': 'Action is required'
            }), 400

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Get the notification
        cursor.execute("""
            SELECT id, trigger_event_id, trigger_block_id, ip_address, trigger_type
            FROM notifications
            WHERE id = %s
        """, (notif_id,))

        notif = cursor.fetchone()

        if not notif:
            cursor.close()
            conn.close()
            return jsonify({
                'success': False,
                'error': 'Notification not found'
            }), 404

        result = {'action': action, 'notification_id': notif_id}

        if action == 'view_event':
            # Return event ID for navigation
            result['event_id'] = notif.get('trigger_event_id')
            result['redirect'] = f"#events-live?event={notif.get('trigger_event_id')}"

        elif action == 'block_ip':
            ip_address = notif.get('ip_address') or data.get('ip_address')
            if not ip_address:
                cursor.close()
                conn.close()
                return jsonify({
                    'success': False,
                    'error': 'No IP address associated with this notification'
                }), 400

            # Check if IP is already blocked
            cursor.execute("""
                SELECT id FROM ip_blocks WHERE ip_address = %s AND is_active = TRUE
            """, (ip_address,))

            existing = cursor.fetchone()
            if existing:
                result['already_blocked'] = True
                result['ip_address'] = ip_address
            else:
                # Add IP to block list
                cursor.execute("""
                    INSERT INTO ip_blocks (
                        ip_address, block_reason, block_type,
                        source, is_active, created_at
                    ) VALUES (
                        %s, %s, 'manual', 'notification_action', TRUE, NOW()
                    )
                """, (ip_address, f'Blocked via notification action (notification #{notif_id})'))
                conn.commit()
                result['blocked'] = True
                result['ip_address'] = ip_address

        elif action == 'whitelist_ip':
            ip_address = notif.get('ip_address') or data.get('ip_address')
            if not ip_address:
                cursor.close()
                conn.close()
                return jsonify({
                    'success': False,
                    'error': 'No IP address associated with this notification'
                }), 400

            # Add to whitelist
            cursor.execute("""
                INSERT IGNORE INTO ip_whitelist (ip_address, reason, created_at)
                VALUES (%s, %s, NOW())
            """, (ip_address, f'Whitelisted via notification action (notification #{notif_id})'))
            conn.commit()
            result['whitelisted'] = True
            result['ip_address'] = ip_address

        elif action == 'mark_read':
            cursor.execute("""
                UPDATE notifications
                SET status = 'sent', sent_at = NOW()
                WHERE id = %s
            """, (notif_id,))
            conn.commit()
            result['marked_read'] = True
            invalidate_pane_cache()

        else:
            cursor.close()
            conn.close()
            return jsonify({
                'success': False,
                'error': f'Unknown action: {action}'
            }), 400

        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'data': result
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@notification_pane_routes.route('/preferences', methods=['GET'])
def get_preferences():
    """Get user notification preferences"""
    try:
        # For now, return default preferences (can be extended for per-user later)
        return jsonify({
            'success': True,
            'data': {
                'show_in_pane': True,
                'sound_enabled': False,
                'desktop_notifications': False,
                'pane_max_items': 20,
                'auto_mark_read_seconds': 0,
                'poll_interval_seconds': 30
            }
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@notification_pane_routes.route('/preferences', methods=['PUT'])
def update_preferences():
    """Update user notification preferences"""
    try:
        data = request.get_json() or {}

        # For now, just acknowledge the update (can store in DB later)
        return jsonify({
            'success': True,
            'message': 'Preferences updated',
            'data': data
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
