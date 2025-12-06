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

        cursor.execute("""
            SELECT COUNT(*) as count
            FROM notifications
            WHERE is_read = FALSE OR is_read IS NULL
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


@notification_pane_routes.route('/recent', methods=['GET'])
def get_recent_notifications():
    """Get recent notifications for pane display (max 20)"""
    try:
        limit = min(int(request.args.get('limit', 20)), 50)

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT
                n.id,
                n.notification_uuid,
                n.trigger_type,
                n.trigger_event_id,
                n.trigger_block_id,
                n.message_title,
                n.message_body,
                n.priority,
                n.status,
                n.is_read,
                n.read_at,
                n.ip_address,
                n.created_at,
                nr.rule_name
            FROM notifications n
            LEFT JOIN notification_rules nr ON n.notification_rule_id = nr.id
            ORDER BY n.created_at DESC
            LIMIT %s
        """, (limit,))

        notifications = cursor.fetchall()

        # Format timestamps
        for notif in notifications:
            if notif['created_at']:
                notif['created_at'] = notif['created_at'].isoformat()
            if notif['read_at']:
                notif['read_at'] = notif['read_at'].isoformat()
            # Ensure is_read is boolean
            notif['is_read'] = bool(notif.get('is_read', False))

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
    """Mark a single notification as read"""
    try:
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            UPDATE notifications
            SET is_read = TRUE, read_at = NOW()
            WHERE id = %s AND (is_read = FALSE OR is_read IS NULL)
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
    """Mark all notifications as read"""
    try:
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            UPDATE notifications
            SET is_read = TRUE, read_at = NOW()
            WHERE is_read = FALSE OR is_read IS NULL
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
    """Mark a notification as unread"""
    try:
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            UPDATE notifications
            SET is_read = FALSE, read_at = NULL
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
                SET is_read = TRUE, read_at = NOW()
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
