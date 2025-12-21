"""
Notification History Routes - API endpoints for notification history/logs
Updated to match actual database schema (notifications table)
With Redis caching for improved performance
"""
import sys
import json
from pathlib import Path
from flask import Blueprint, jsonify, request

# Add database path
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
sys.path.append(str(PROJECT_ROOT / "dbs"))
sys.path.append(str(PROJECT_ROOT / "src" / "core"))

from connection import get_connection
from cache import get_cache, cache_key, cache_key_hash

notification_history_routes = Blueprint('notification_history', __name__)

# Cache TTLs
NOTIF_LIST_TTL = 300          # 5 minutes for paginated list
NOTIF_DETAIL_TTL = 600        # 10 minutes for single notification detail
NOTIF_STATS_TTL = 600         # 10 minutes for stats


def invalidate_notification_history_cache():
    """Invalidate all notification history caches"""
    cache = get_cache()
    cache.delete_pattern('notif_history')


def parse_json_field(value, default=None):
    """Safely parse JSON field"""
    if value is None:
        return default
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return default


@notification_history_routes.route('/list', methods=['GET'])
def list_notifications():
    """
    Get notification history with filtering and pagination
    Query params:
    - page: Page number (default 1)
    - per_page: Items per page (default 50, max 100)
    - status: Filter by status (pending, sent, failed)
    - channel: Filter by channel (telegram, email, webhook)
    - rule_id: Filter by notification rule ID
    - is_security_alert: Filter security alerts (true/false)
    - start_date: Filter from date (YYYY-MM-DD)
    - end_date: Filter to date (YYYY-MM-DD)
    - search: Search in subject/message
    - ip: Filter by IP address
    """
    try:
        page = int(request.args.get('page', 1))
        per_page = min(int(request.args.get('per_page', 50)), 100)
        status_filter = request.args.get('status', '').strip()
        channel_filter = request.args.get('channel', '').strip()
        rule_id_filter = request.args.get('rule_id', '').strip()
        is_security_alert = request.args.get('is_security_alert', '').strip()
        start_date = request.args.get('start_date', '').strip()
        end_date = request.args.get('end_date', '').strip()
        search = request.args.get('search', '').strip()
        ip_filter = request.args.get('ip', '').strip()
        limit = request.args.get('limit', '').strip()

        # Try cache first
        cache = get_cache()
        cache_params = {
            'page': page, 'per_page': per_page, 'status': status_filter,
            'channel': channel_filter, 'rule_id': rule_id_filter,
            'is_security_alert': is_security_alert,
            'start_date': start_date, 'end_date': end_date,
            'search': search, 'ip': ip_filter
        }
        cache_k = cache_key_hash('notif_history', 'list', cache_params)
        cached = cache.get(cache_k)
        if cached is not None:
            return jsonify({
                'success': True,
                'data': cached,
                'from_cache': True
            })

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Build query with filters
        where_clauses = []
        params = []

        if status_filter:
            where_clauses.append("n.status = %s")
            params.append(status_filter)

        if channel_filter:
            where_clauses.append("n.channel = %s")
            params.append(channel_filter)

        if rule_id_filter:
            where_clauses.append("n.notification_rule_id = %s")
            params.append(int(rule_id_filter))

        if is_security_alert:
            where_clauses.append("n.is_security_alert = %s")
            params.append(1 if is_security_alert.lower() == 'true' else 0)

        if start_date:
            where_clauses.append("DATE(n.created_at) >= %s")
            params.append(start_date)

        if end_date:
            where_clauses.append("DATE(n.created_at) <= %s")
            params.append(end_date)

        if search:
            where_clauses.append("(n.subject LIKE %s OR n.message LIKE %s)")
            params.append(f'%{search}%')
            params.append(f'%{search}%')

        if ip_filter:
            where_clauses.append("n.ip_address LIKE %s")
            params.append(f'%{ip_filter}%')

        where_sql = ""
        if where_clauses:
            where_sql = "WHERE " + " AND ".join(where_clauses)

        # Get total count
        count_query = f"""
            SELECT COUNT(*) as total
            FROM notifications n
            {where_sql}
        """
        cursor.execute(count_query, params)
        total = cursor.fetchone()['total']

        # Handle limit param for simplified queries
        if limit:
            per_page = min(int(limit), 100)
            page = 1

        # Get paginated results
        offset = (page - 1) * per_page
        query = f"""
            SELECT
                n.id, n.notification_rule_id, n.channel, n.recipient,
                n.subject, n.message, n.status, n.error_message,
                n.sent_at, n.created_at, n.ip_address, n.username,
                n.ml_score, n.ml_factors, n.geo_data, n.agent_id,
                n.is_acknowledged, n.acknowledged_by, n.acknowledged_at,
                n.action_taken, n.is_security_alert,
                nr.rule_name, a.hostname as agent_hostname
            FROM notifications n
            LEFT JOIN notification_rules nr ON n.notification_rule_id = nr.id
            LEFT JOIN agents a ON n.agent_id = a.id
            {where_sql}
            ORDER BY n.created_at DESC
            LIMIT %s OFFSET %s
        """
        params.extend([per_page, offset])

        cursor.execute(query, params)
        notifications = cursor.fetchall()

        # Format response
        for notif in notifications:
            if notif['created_at']:
                notif['created_at'] = notif['created_at'].isoformat()
            if notif['sent_at']:
                notif['sent_at'] = notif['sent_at'].isoformat()
            if notif['acknowledged_at']:
                notif['acknowledged_at'] = notif['acknowledged_at'].isoformat()
            # Parse JSON fields
            notif['ml_factors'] = parse_json_field(notif.get('ml_factors'), [])
            notif['geo_data'] = parse_json_field(notif.get('geo_data'), {})
            # Convert booleans
            notif['is_security_alert'] = bool(notif.get('is_security_alert'))
            notif['is_acknowledged'] = bool(notif.get('is_acknowledged'))

        cursor.close()
        conn.close()

        result_data = {
            'notifications': notifications,
            'total': total,
            'page': page,
            'per_page': per_page,
            'total_pages': (total + per_page - 1) // per_page if total > 0 else 0
        }

        # Cache the result
        cache.set(cache_k, result_data, NOTIF_LIST_TTL)

        return jsonify({
            'success': True,
            'data': result_data,
            'from_cache': False
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@notification_history_routes.route('/<int:notif_id>', methods=['GET'])
def get_notification(notif_id):
    """Get a specific notification by ID"""
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT
                n.id, n.notification_rule_id, n.channel, n.recipient,
                n.subject, n.message, n.status, n.error_message,
                n.sent_at, n.created_at, n.ip_address, n.username,
                n.ml_score, n.ml_factors, n.geo_data, n.agent_id,
                n.is_acknowledged, n.acknowledged_by, n.acknowledged_at,
                n.action_taken, n.is_security_alert,
                nr.rule_name, a.hostname as agent_hostname
            FROM notifications n
            LEFT JOIN notification_rules nr ON n.notification_rule_id = nr.id
            LEFT JOIN agents a ON n.agent_id = a.id
            WHERE n.id = %s
        """, (notif_id,))

        notif = cursor.fetchone()

        cursor.close()
        conn.close()

        if not notif:
            return jsonify({
                'success': False,
                'error': 'Notification not found'
            }), 404

        # Format timestamps
        if notif['created_at']:
            notif['created_at'] = notif['created_at'].isoformat()
        if notif['sent_at']:
            notif['sent_at'] = notif['sent_at'].isoformat()
        if notif['acknowledged_at']:
            notif['acknowledged_at'] = notif['acknowledged_at'].isoformat()
        # Parse JSON fields
        notif['ml_factors'] = parse_json_field(notif.get('ml_factors'), [])
        notif['geo_data'] = parse_json_field(notif.get('geo_data'), {})
        # Convert booleans
        notif['is_security_alert'] = bool(notif.get('is_security_alert'))
        notif['is_acknowledged'] = bool(notif.get('is_acknowledged'))

        return jsonify({
            'success': True,
            'data': notif
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@notification_history_routes.route('/stats', methods=['GET'])
def get_notification_stats():
    """Get notification statistics"""
    try:
        # Try cache first
        cache = get_cache()
        cache_k = cache_key('notif_history', 'stats')
        cached = cache.get(cache_k)
        if cached is not None:
            return jsonify({
                'success': True,
                'data': cached,
                'from_cache': True
            })

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Total notifications
        cursor.execute("SELECT COUNT(*) as total FROM notifications")
        total = cursor.fetchone()['total']

        # By status
        cursor.execute("""
            SELECT status, COUNT(*) as count
            FROM notifications
            GROUP BY status
        """)
        by_status = {row['status']: row['count'] for row in cursor.fetchall()}

        # Today's notifications
        cursor.execute("""
            SELECT COUNT(*) as today
            FROM notifications
            WHERE DATE(created_at) = CURDATE()
        """)
        today = cursor.fetchone()['today']

        # This week
        cursor.execute("""
            SELECT COUNT(*) as this_week
            FROM notifications
            WHERE created_at >= DATE_SUB(CURDATE(), INTERVAL 7 DAY)
        """)
        this_week = cursor.fetchone()['this_week']

        # By channel (last 30 days)
        cursor.execute("""
            SELECT channel, COUNT(*) as count
            FROM notifications
            WHERE created_at >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)
            GROUP BY channel
            ORDER BY count DESC
        """)
        by_channel = cursor.fetchall()

        # Security alerts count
        cursor.execute("""
            SELECT
                COUNT(*) as total_alerts,
                SUM(CASE WHEN is_acknowledged = 0 THEN 1 ELSE 0 END) as unacknowledged
            FROM notifications
            WHERE is_security_alert = 1
        """)
        alert_stats = cursor.fetchone()

        # Failed notifications (last 7 days)
        cursor.execute("""
            SELECT COUNT(*) as failed_count
            FROM notifications
            WHERE status = 'failed'
            AND created_at >= DATE_SUB(CURDATE(), INTERVAL 7 DAY)
        """)
        failed_recent = cursor.fetchone()['failed_count']

        # Daily trend (last 7 days)
        cursor.execute("""
            SELECT DATE(created_at) as date, COUNT(*) as count
            FROM notifications
            WHERE created_at >= DATE_SUB(CURDATE(), INTERVAL 7 DAY)
            GROUP BY DATE(created_at)
            ORDER BY date ASC
        """)
        daily_trend = []
        for row in cursor.fetchall():
            daily_trend.append({
                'date': row['date'].isoformat() if row['date'] else None,
                'count': row['count']
            })

        cursor.close()
        conn.close()

        stats_data = {
            'total': total,
            'today': today,
            'this_week': this_week,
            'by_status': by_status,
            'by_channel': by_channel,
            'security_alerts': {
                'total': alert_stats['total_alerts'] or 0,
                'unacknowledged': alert_stats['unacknowledged'] or 0
            },
            'failed_recent': failed_recent,
            'daily_trend': daily_trend
        }

        # Cache the result
        cache.set(cache_k, stats_data, NOTIF_STATS_TTL)

        return jsonify({
            'success': True,
            'data': stats_data,
            'from_cache': False
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@notification_history_routes.route('/channels', methods=['GET'])
def list_channels():
    """Get unique channels used in notifications"""
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT DISTINCT channel, COUNT(*) as count
            FROM notifications
            GROUP BY channel
            ORDER BY count DESC
        """)

        channels = cursor.fetchall()

        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'data': {'channels': channels}
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@notification_history_routes.route('/retry/<int:notif_id>', methods=['POST'])
def retry_notification(notif_id):
    """Retry a failed notification"""
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Get the notification
        cursor.execute("""
            SELECT * FROM notifications WHERE id = %s
        """, (notif_id,))
        notif = cursor.fetchone()

        if not notif:
            cursor.close()
            conn.close()
            return jsonify({
                'success': False,
                'error': 'Notification not found'
            }), 404

        if notif['status'] != 'failed':
            cursor.close()
            conn.close()
            return jsonify({
                'success': False,
                'error': 'Only failed notifications can be retried'
            }), 400

        # Update status to pending for retry
        cursor.execute("""
            UPDATE notifications
            SET status = 'pending', error_message = NULL
            WHERE id = %s
        """, (notif_id,))

        conn.commit()
        cursor.close()
        conn.close()

        invalidate_notification_history_cache()

        return jsonify({
            'success': True,
            'message': 'Notification queued for retry'
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@notification_history_routes.route('/acknowledge/<int:notif_id>', methods=['POST'])
def acknowledge_notification(notif_id):
    """Acknowledge a security alert notification"""
    try:
        data = request.get_json() or {}
        user_id = data.get('user_id')
        action_taken = data.get('action_taken', 'acknowledged')

        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            UPDATE notifications
            SET is_acknowledged = 1,
                acknowledged_by = %s,
                acknowledged_at = NOW(),
                action_taken = %s
            WHERE id = %s AND is_security_alert = 1
        """, (user_id, action_taken, notif_id))

        if cursor.rowcount == 0:
            cursor.close()
            conn.close()
            return jsonify({
                'success': False,
                'error': 'Notification not found or not a security alert'
            }), 404

        conn.commit()
        cursor.close()
        conn.close()

        invalidate_notification_history_cache()

        return jsonify({
            'success': True,
            'message': 'Alert acknowledged'
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@notification_history_routes.route('/clear', methods=['POST'])
def clear_old_notifications():
    """Clear old notifications (older than specified days)"""
    try:
        data = request.get_json() or {}
        days = int(data.get('days', 30))

        if days < 7:
            return jsonify({
                'success': False,
                'error': 'Minimum retention period is 7 days'
            }), 400

        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            DELETE FROM notifications
            WHERE created_at < DATE_SUB(NOW(), INTERVAL %s DAY)
            AND is_security_alert = 0
        """, (days,))

        deleted_count = cursor.rowcount
        conn.commit()

        cursor.close()
        conn.close()

        invalidate_notification_history_cache()

        return jsonify({
            'success': True,
            'message': f'Deleted {deleted_count} notifications older than {days} days',
            'data': {
                'deleted_count': deleted_count
            }
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@notification_history_routes.route('/export', methods=['GET'])
def export_notifications():
    """Export notifications as JSON (with same filters as list)"""
    try:
        status_filter = request.args.get('status', '').strip()
        channel_filter = request.args.get('channel', '').strip()
        start_date = request.args.get('start_date', '').strip()
        end_date = request.args.get('end_date', '').strip()
        limit = min(int(request.args.get('limit', 1000)), 10000)

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        where_clauses = []
        params = []

        if status_filter:
            where_clauses.append("n.status = %s")
            params.append(status_filter)

        if channel_filter:
            where_clauses.append("n.channel = %s")
            params.append(channel_filter)

        if start_date:
            where_clauses.append("DATE(n.created_at) >= %s")
            params.append(start_date)

        if end_date:
            where_clauses.append("DATE(n.created_at) <= %s")
            params.append(end_date)

        where_sql = ""
        if where_clauses:
            where_sql = "WHERE " + " AND ".join(where_clauses)

        query = f"""
            SELECT
                n.id, n.notification_rule_id, n.channel, n.subject,
                n.message, n.status, n.error_message, n.sent_at,
                n.created_at, n.ip_address, n.username,
                nr.rule_name
            FROM notifications n
            LEFT JOIN notification_rules nr ON n.notification_rule_id = nr.id
            {where_sql}
            ORDER BY n.created_at DESC
            LIMIT %s
        """
        params.append(limit)

        cursor.execute(query, params)
        notifications = cursor.fetchall()

        for notif in notifications:
            if notif['created_at']:
                notif['created_at'] = notif['created_at'].isoformat()
            if notif['sent_at']:
                notif['sent_at'] = notif['sent_at'].isoformat()

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
