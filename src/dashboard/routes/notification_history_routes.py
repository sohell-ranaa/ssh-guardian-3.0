"""
Notification History Routes - API endpoints for notification history/logs
Separate module for viewing sent notifications history
"""
import sys
from pathlib import Path
from flask import Blueprint, jsonify, request

# Add database path
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
sys.path.append(str(PROJECT_ROOT / "dbs"))

from connection import get_connection

notification_history_routes = Blueprint('notification_history', __name__)


@notification_history_routes.route('/list', methods=['GET'])
def list_notifications():
    """
    Get notification history with filtering and pagination
    Query params:
    - page: Page number (default 1)
    - per_page: Items per page (default 50, max 100)
    - status: Filter by status (pending, sent, failed, cancelled)
    - trigger_type: Filter by trigger type
    - priority: Filter by priority (low, normal, high, critical)
    - channel: Filter by channel (telegram, email, webhook)
    - rule_id: Filter by notification rule ID
    - start_date: Filter from date (YYYY-MM-DD)
    - end_date: Filter to date (YYYY-MM-DD)
    - search: Search in message title/body
    """
    try:
        page = int(request.args.get('page', 1))
        per_page = min(int(request.args.get('per_page', 50)), 100)
        status_filter = request.args.get('status', '').strip()
        trigger_type_filter = request.args.get('trigger_type', '').strip()
        priority_filter = request.args.get('priority', '').strip()
        channel_filter = request.args.get('channel', '').strip()
        rule_id_filter = request.args.get('rule_id', '').strip()
        start_date = request.args.get('start_date', '').strip()
        end_date = request.args.get('end_date', '').strip()
        search = request.args.get('search', '').strip()

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Build query with filters
        where_clauses = []
        params = []

        if status_filter:
            where_clauses.append("n.status = %s")
            params.append(status_filter)

        if trigger_type_filter:
            where_clauses.append("n.trigger_type = %s")
            params.append(trigger_type_filter)

        if priority_filter:
            where_clauses.append("n.priority = %s")
            params.append(priority_filter)

        if channel_filter:
            where_clauses.append("JSON_CONTAINS(n.channels, %s)")
            params.append(f'"{channel_filter}"')

        if rule_id_filter:
            where_clauses.append("n.notification_rule_id = %s")
            params.append(int(rule_id_filter))

        if start_date:
            where_clauses.append("DATE(n.created_at) >= %s")
            params.append(start_date)

        if end_date:
            where_clauses.append("DATE(n.created_at) <= %s")
            params.append(end_date)

        if search:
            where_clauses.append("(n.message_title LIKE %s OR n.message_body LIKE %s)")
            params.append(f'%{search}%')
            params.append(f'%{search}%')

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

        # Get paginated results
        offset = (page - 1) * per_page
        query = f"""
            SELECT
                n.id, n.notification_uuid, n.notification_rule_id,
                n.trigger_type, n.trigger_event_id, n.trigger_block_id,
                n.channels, n.message_title, n.message_body, n.message_format,
                n.priority, n.status, n.sent_at, n.failed_reason,
                n.retry_count, n.delivery_status, n.notification_metadata,
                n.created_at, n.updated_at,
                nr.rule_name
            FROM notifications n
            LEFT JOIN notification_rules nr ON n.notification_rule_id = nr.id
            {where_sql}
            ORDER BY n.created_at DESC
            LIMIT %s OFFSET %s
        """
        params.extend([per_page, offset])

        cursor.execute(query, params)
        notifications = cursor.fetchall()

        # Format timestamps
        for notif in notifications:
            if notif['created_at']:
                notif['created_at'] = notif['created_at'].isoformat()
            if notif['updated_at']:
                notif['updated_at'] = notif['updated_at'].isoformat()
            if notif['sent_at']:
                notif['sent_at'] = notif['sent_at'].isoformat()

        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'data': {
                'notifications': notifications,
                'total': total,
                'page': page,
                'per_page': per_page,
                'total_pages': (total + per_page - 1) // per_page if total > 0 else 0
            }
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
                n.id, n.notification_uuid, n.notification_rule_id,
                n.trigger_type, n.trigger_event_id, n.trigger_block_id,
                n.channels, n.message_title, n.message_body, n.message_format,
                n.priority, n.status, n.sent_at, n.failed_reason,
                n.retry_count, n.delivery_status, n.notification_metadata,
                n.created_at, n.updated_at,
                nr.rule_name
            FROM notifications n
            LEFT JOIN notification_rules nr ON n.notification_rule_id = nr.id
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
        if notif['updated_at']:
            notif['updated_at'] = notif['updated_at'].isoformat()
        if notif['sent_at']:
            notif['sent_at'] = notif['sent_at'].isoformat()

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

        # By trigger type (last 30 days)
        cursor.execute("""
            SELECT trigger_type, COUNT(*) as count
            FROM notifications
            WHERE created_at >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)
            GROUP BY trigger_type
            ORDER BY count DESC
        """)
        by_trigger_type = cursor.fetchall()

        # By priority (last 30 days)
        cursor.execute("""
            SELECT priority, COUNT(*) as count
            FROM notifications
            WHERE created_at >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)
            GROUP BY priority
            ORDER BY FIELD(priority, 'critical', 'high', 'normal', 'low')
        """)
        by_priority = cursor.fetchall()

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

        return jsonify({
            'success': True,
            'data': {
                'total': total,
                'today': today,
                'this_week': this_week,
                'by_status': by_status,
                'by_trigger_type': by_trigger_type,
                'by_priority': by_priority,
                'failed_recent': failed_recent,
                'daily_trend': daily_trend
            }
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@notification_history_routes.route('/trigger-types', methods=['GET'])
def list_trigger_types():
    """Get all unique trigger types for filtering"""
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT DISTINCT trigger_type, COUNT(*) as count
            FROM notifications
            GROUP BY trigger_type
            ORDER BY count DESC
        """)

        trigger_types = cursor.fetchall()

        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'data': {
                'trigger_types': trigger_types
            }
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
            SET status = 'pending', retry_count = retry_count + 1
            WHERE id = %s
        """, (notif_id,))

        conn.commit()
        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'message': 'Notification queued for retry'
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
        """, (days,))

        deleted_count = cursor.rowcount
        conn.commit()

        cursor.close()
        conn.close()

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
        trigger_type_filter = request.args.get('trigger_type', '').strip()
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

        if trigger_type_filter:
            where_clauses.append("n.trigger_type = %s")
            params.append(trigger_type_filter)

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
                n.id, n.notification_uuid, n.notification_rule_id,
                n.trigger_type, n.channels, n.message_title, n.message_body,
                n.priority, n.status, n.sent_at, n.failed_reason,
                n.created_at, nr.rule_name
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
