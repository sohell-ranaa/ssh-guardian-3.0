"""
Audit Routes - API endpoints for audit log management
"""
import sys
from pathlib import Path
from flask import Blueprint, jsonify, request

# Add database path
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
sys.path.append(str(PROJECT_ROOT / "dbs"))

from connection import get_connection

audit_routes = Blueprint('audit', __name__)


@audit_routes.route('/list', methods=['GET'])
def list_audit_logs():
    """
    Get audit logs with filtering and pagination
    Query params:
    - page: Page number (default 1)
    - per_page: Items per page (default 50, max 100)
    - action: Filter by action type
    - user_id: Filter by user ID
    - resource_type: Filter by resource type
    - start_date: Filter from date (YYYY-MM-DD)
    - end_date: Filter to date (YYYY-MM-DD)
    - search: Search in details
    """
    try:
        page = int(request.args.get('page', 1))
        per_page = min(int(request.args.get('per_page', 50)), 100)
        action_filter = request.args.get('action', '').strip()
        user_id_filter = request.args.get('user_id', '').strip()
        resource_type_filter = request.args.get('resource_type', '').strip()
        start_date = request.args.get('start_date', '').strip()
        end_date = request.args.get('end_date', '').strip()
        search = request.args.get('search', '').strip()

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Build query with filters
        where_clauses = []
        params = []

        if action_filter:
            where_clauses.append("a.action = %s")
            params.append(action_filter)

        if user_id_filter:
            where_clauses.append("a.user_id = %s")
            params.append(int(user_id_filter))

        if resource_type_filter:
            where_clauses.append("a.resource_type = %s")
            params.append(resource_type_filter)

        if start_date:
            where_clauses.append("DATE(a.created_at) >= %s")
            params.append(start_date)

        if end_date:
            where_clauses.append("DATE(a.created_at) <= %s")
            params.append(end_date)

        if search:
            where_clauses.append("(JSON_SEARCH(a.details, 'one', %s) IS NOT NULL OR a.ip_address LIKE %s)")
            params.append(f'%{search}%')
            params.append(f'%{search}%')

        where_sql = ""
        if where_clauses:
            where_sql = "WHERE " + " AND ".join(where_clauses)

        # Get total count
        count_query = f"""
            SELECT COUNT(*) as total
            FROM audit_logs a
            {where_sql}
        """
        cursor.execute(count_query, params)
        total = cursor.fetchone()['total']

        # Get paginated results
        offset = (page - 1) * per_page
        query = f"""
            SELECT
                a.id, a.user_id, a.action, a.resource_type, a.resource_id,
                a.details, a.ip_address, a.user_agent, a.created_at,
                u.email as user_email, u.full_name as user_name
            FROM audit_logs a
            LEFT JOIN users u ON a.user_id = u.id
            {where_sql}
            ORDER BY a.created_at DESC
            LIMIT %s OFFSET %s
        """
        params.extend([per_page, offset])

        cursor.execute(query, params)
        logs = cursor.fetchall()

        # Format timestamps and parse JSON
        for log in logs:
            if log['created_at']:
                log['created_at'] = log['created_at'].isoformat()
            # details is already JSON, no need to parse

        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'data': {
                'logs': logs,
                'total': total,
                'page': page,
                'per_page': per_page,
                'total_pages': (total + per_page - 1) // per_page
            }
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@audit_routes.route('/actions', methods=['GET'])
def list_action_types():
    """Get all unique action types for filtering"""
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT DISTINCT action, COUNT(*) as count
            FROM audit_logs
            GROUP BY action
            ORDER BY count DESC
        """)

        actions = cursor.fetchall()

        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'data': {
                'actions': actions
            }
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@audit_routes.route('/resource-types', methods=['GET'])
def list_resource_types():
    """Get all unique resource types for filtering"""
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT DISTINCT resource_type, COUNT(*) as count
            FROM audit_logs
            WHERE resource_type IS NOT NULL
            GROUP BY resource_type
            ORDER BY count DESC
        """)

        resource_types = cursor.fetchall()

        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'data': {
                'resource_types': resource_types
            }
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@audit_routes.route('/stats', methods=['GET'])
def get_audit_stats():
    """Get audit log statistics"""
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Total logs
        cursor.execute("SELECT COUNT(*) as total FROM audit_logs")
        total = cursor.fetchone()['total']

        # Logs today
        cursor.execute("""
            SELECT COUNT(*) as today
            FROM audit_logs
            WHERE DATE(created_at) = CURDATE()
        """)
        today = cursor.fetchone()['today']

        # Logs this week
        cursor.execute("""
            SELECT COUNT(*) as this_week
            FROM audit_logs
            WHERE created_at >= DATE_SUB(CURDATE(), INTERVAL 7 DAY)
        """)
        this_week = cursor.fetchone()['this_week']

        # Actions by type (last 30 days)
        cursor.execute("""
            SELECT action, COUNT(*) as count
            FROM audit_logs
            WHERE created_at >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)
            GROUP BY action
            ORDER BY count DESC
            LIMIT 10
        """)
        top_actions = cursor.fetchall()

        # Active users (last 7 days)
        cursor.execute("""
            SELECT COUNT(DISTINCT user_id) as active_users
            FROM audit_logs
            WHERE created_at >= DATE_SUB(CURDATE(), INTERVAL 7 DAY)
            AND user_id IS NOT NULL
        """)
        active_users = cursor.fetchone()['active_users']

        # Failed login attempts today
        cursor.execute("""
            SELECT COUNT(*) as failed_logins
            FROM audit_logs
            WHERE action = 'login_otp_failed'
            AND DATE(created_at) = CURDATE()
        """)
        failed_logins = cursor.fetchone()['failed_logins']

        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'data': {
                'total': total,
                'today': today,
                'this_week': this_week,
                'top_actions': top_actions,
                'active_users': active_users,
                'failed_logins_today': failed_logins
            }
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@audit_routes.route('/<int:log_id>', methods=['GET'])
def get_audit_log(log_id):
    """Get a specific audit log entry"""
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT
                a.id, a.user_id, a.action, a.resource_type, a.resource_id,
                a.details, a.ip_address, a.user_agent, a.created_at,
                u.email as user_email, u.full_name as user_name
            FROM audit_logs a
            LEFT JOIN users u ON a.user_id = u.id
            WHERE a.id = %s
        """, (log_id,))

        log = cursor.fetchone()

        cursor.close()
        conn.close()

        if not log:
            return jsonify({
                'success': False,
                'error': 'Audit log not found'
            }), 404

        if log['created_at']:
            log['created_at'] = log['created_at'].isoformat()

        return jsonify({
            'success': True,
            'data': log
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@audit_routes.route('/export', methods=['GET'])
def export_audit_logs():
    """Export audit logs as JSON (with same filters as list)"""
    try:
        action_filter = request.args.get('action', '').strip()
        user_id_filter = request.args.get('user_id', '').strip()
        start_date = request.args.get('start_date', '').strip()
        end_date = request.args.get('end_date', '').strip()
        limit = min(int(request.args.get('limit', 1000)), 10000)

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        where_clauses = []
        params = []

        if action_filter:
            where_clauses.append("a.action = %s")
            params.append(action_filter)

        if user_id_filter:
            where_clauses.append("a.user_id = %s")
            params.append(int(user_id_filter))

        if start_date:
            where_clauses.append("DATE(a.created_at) >= %s")
            params.append(start_date)

        if end_date:
            where_clauses.append("DATE(a.created_at) <= %s")
            params.append(end_date)

        where_sql = ""
        if where_clauses:
            where_sql = "WHERE " + " AND ".join(where_clauses)

        query = f"""
            SELECT
                a.id, a.user_id, a.action, a.resource_type, a.resource_id,
                a.details, a.ip_address, a.user_agent, a.created_at,
                u.email as user_email, u.full_name as user_name
            FROM audit_logs a
            LEFT JOIN users u ON a.user_id = u.id
            {where_sql}
            ORDER BY a.created_at DESC
            LIMIT %s
        """
        params.append(limit)

        cursor.execute(query, params)
        logs = cursor.fetchall()

        for log in logs:
            if log['created_at']:
                log['created_at'] = log['created_at'].isoformat()

        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'data': {
                'logs': logs,
                'count': len(logs)
            }
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
