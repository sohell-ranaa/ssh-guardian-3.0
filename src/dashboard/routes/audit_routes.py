"""
Audit Routes - API endpoints for audit log management
With Redis caching for improved performance
"""
import sys
from pathlib import Path
from flask import Blueprint, jsonify, request

# Add database path
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
sys.path.append(str(PROJECT_ROOT / "dbs"))
sys.path.append(str(PROJECT_ROOT / "src" / "core"))

from connection import get_connection
from cache import get_cache, cache_key, cache_key_hash

audit_routes = Blueprint('audit', __name__)

# Cache TTLs - OPTIMIZED FOR PERFORMANCE
AUDIT_LIST_TTL = 300          # 5 minutes for paginated list
AUDIT_ACTIONS_TTL = 1800      # 30 minutes for action types (rarely changes)
AUDIT_RESOURCES_TTL = 1800    # 30 minutes for resource types (rarely changes)
AUDIT_STATS_TTL = 600         # 10 minutes for stats
AUDIT_DETAIL_TTL = 900        # 15 minutes for single log detail


def invalidate_audit_cache():
    """Invalidate all audit log caches"""
    cache = get_cache()
    cache.delete_pattern('audit')


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

        # Try cache first
        cache = get_cache()
        cache_params = {
            'page': page, 'per_page': per_page, 'action': action_filter,
            'user_id': user_id_filter, 'resource_type': resource_type_filter,
            'start_date': start_date, 'end_date': end_date, 'search': search
        }
        cache_k = cache_key_hash('audit', 'list', cache_params)
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

        if action_filter:
            where_clauses.append("a.action = %s")
            params.append(action_filter)

        if user_id_filter:
            where_clauses.append("a.user_id = %s")
            params.append(int(user_id_filter))

        if resource_type_filter:
            where_clauses.append("a.entity_type = %s")
            params.append(resource_type_filter)

        if start_date:
            where_clauses.append("DATE(a.created_at) >= %s")
            params.append(start_date)

        if end_date:
            where_clauses.append("DATE(a.created_at) <= %s")
            params.append(end_date)

        if search:
            where_clauses.append("(JSON_SEARCH(a.old_values, 'one', %s) IS NOT NULL OR JSON_SEARCH(a.new_values, 'one', %s) IS NOT NULL OR a.ip_address LIKE %s)")
            params.append(f'%{search}%')
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
                a.id, a.user_id, a.action, a.entity_type as resource_type, a.entity_id as resource_id,
                a.old_values, a.new_values, a.ip_address, a.user_agent, a.created_at,
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

        result_data = {
            'logs': logs,
            'total': total,
            'page': page,
            'per_page': per_page,
            'total_pages': (total + per_page - 1) // per_page
        }

        # Cache the result
        cache.set(cache_k, result_data, AUDIT_LIST_TTL)

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


@audit_routes.route('/actions', methods=['GET'])
def list_action_types():
    """Get all unique action types for filtering"""
    try:
        # Try cache first
        cache = get_cache()
        cache_k = cache_key('audit', 'actions')
        cached = cache.get(cache_k)
        if cached is not None:
            return jsonify({
                'success': True,
                'data': {'actions': cached},
                'from_cache': True
            })

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

        # Cache the result
        cache.set(cache_k, actions, AUDIT_ACTIONS_TTL)

        return jsonify({
            'success': True,
            'data': {'actions': actions},
            'from_cache': False
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
        # Try cache first
        cache = get_cache()
        cache_k = cache_key('audit', 'resource_types')
        cached = cache.get(cache_k)
        if cached is not None:
            return jsonify({
                'success': True,
                'data': {'resource_types': cached},
                'from_cache': True
            })

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT DISTINCT entity_type as resource_type, COUNT(*) as count
            FROM audit_logs
            WHERE entity_type IS NOT NULL
            GROUP BY entity_type
            ORDER BY count DESC
        """)

        resource_types = cursor.fetchall()

        cursor.close()
        conn.close()

        # Cache the result
        cache.set(cache_k, resource_types, AUDIT_RESOURCES_TTL)

        return jsonify({
            'success': True,
            'data': {'resource_types': resource_types},
            'from_cache': False
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
        # Try cache first
        cache = get_cache()
        cache_k = cache_key('audit', 'stats')
        cached = cache.get(cache_k)
        if cached is not None:
            return jsonify({
                'success': True,
                'data': cached,
                'from_cache': True
            })

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

        stats_data = {
            'total': total,
            'today': today,
            'this_week': this_week,
            'top_actions': top_actions,
            'active_users': active_users,
            'failed_logins_today': failed_logins
        }

        # Cache the result
        cache.set(cache_k, stats_data, AUDIT_STATS_TTL)

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


@audit_routes.route('/<int:log_id>', methods=['GET'])
def get_audit_log(log_id):
    """Get a specific audit log entry"""
    try:
        # Try cache first
        cache = get_cache()
        cache_k = cache_key('audit', 'detail', str(log_id))
        cached = cache.get(cache_k)
        if cached is not None:
            return jsonify({
                'success': True,
                'data': cached,
                'from_cache': True
            })

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT
                a.id, a.user_id, a.action, a.entity_type as resource_type, a.entity_id as resource_id,
                a.old_values, a.new_values, a.ip_address, a.user_agent, a.created_at,
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

        # Cache the result
        cache.set(cache_k, log, AUDIT_DETAIL_TTL)

        return jsonify({
            'success': True,
            'data': log,
            'from_cache': False
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
                a.id, a.user_id, a.action, a.entity_type as resource_type, a.entity_id as resource_id,
                a.old_values, a.new_values, a.ip_address, a.user_agent, a.created_at,
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
