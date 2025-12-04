"""
SSH Guardian v3.0 - Blocking Actions Routes
API endpoints for viewing blocking action history
"""

from flask import Blueprint, jsonify, request
import sys
import os

# Add dbs directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../..', 'dbs'))
from connection import get_connection

actions_routes = Blueprint('actions_routes', __name__)


@actions_routes.route('/actions/list', methods=['GET'])
def list_actions():
    """
    Get list of blocking actions (audit log of block/unblock operations)

    Query Parameters:
    - limit: Number of actions (default: 50, max: 500)
    - offset: Offset for pagination (default: 0)
    - action_type: Filter by action type (blocked, unblocked, modified)
    - action_source: Filter by source (system, manual, rule, api)
    - ip_address: Filter by specific IP address
    """
    try:
        limit = min(int(request.args.get('limit', 50)), 500)
        offset = int(request.args.get('offset', 0))
        action_type = request.args.get('action_type')
        action_source = request.args.get('action_source')
        ip_address = request.args.get('ip_address')

        where_clauses = []
        params = []

        if action_type:
            where_clauses.append("ba.action_type = %s")
            params.append(action_type)

        if action_source:
            where_clauses.append("ba.action_source = %s")
            params.append(action_source)

        if ip_address:
            where_clauses.append("ba.ip_address_text = %s")
            params.append(ip_address)

        where_sql = " AND " + " AND ".join(where_clauses) if where_clauses else ""

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            # Get actions with related data
            query = f"""
                SELECT
                    ba.id,
                    ba.action_uuid,
                    ba.ip_address_text,
                    ba.action_type,
                    ba.action_source,
                    ba.reason,
                    ba.created_at,

                    -- User info
                    u.full_name as performed_by_name,
                    u.username as performed_by_username,

                    -- Rule info
                    br.rule_name as triggered_by_rule_name,

                    -- Block info
                    ib.block_reason as block_reason,
                    ib.block_source as block_source,

                    -- GeoIP info
                    geo.country_name,
                    geo.city

                FROM blocking_actions ba
                LEFT JOIN users u ON ba.performed_by_user_id = u.id
                LEFT JOIN blocking_rules br ON ba.triggered_by_rule_id = br.id
                LEFT JOIN ip_blocks ib ON ba.ip_block_id = ib.id
                LEFT JOIN ip_geolocation geo ON ba.ip_address_text = geo.ip_address_text

                WHERE 1=1 {where_sql}

                ORDER BY ba.created_at DESC
                LIMIT %s OFFSET %s
            """

            params.extend([limit, offset])
            cursor.execute(query, params)
            actions = cursor.fetchall()

            # Get total count
            count_query = f"""
                SELECT COUNT(*) as total
                FROM blocking_actions ba
                WHERE 1=1 {where_sql}
            """

            cursor.execute(count_query, params[:-2])
            total = cursor.fetchone()['total']

            # Format response
            formatted_actions = []
            for action in actions:
                formatted_action = {
                    'id': action['id'],
                    'action_uuid': action['action_uuid'],
                    'ip_address': action['ip_address_text'],
                    'action_type': action['action_type'],
                    'action_source': action['action_source'],
                    'reason': action['reason'],
                    'created_at': action['created_at'].isoformat() if action['created_at'] else None,
                    'performed_by': {
                        'name': action['performed_by_name'],
                        'username': action['performed_by_username']
                    } if action['performed_by_name'] else None,
                    'triggered_by_rule': action['triggered_by_rule_name'],
                    'block_info': {
                        'reason': action['block_reason'],
                        'source': action['block_source']
                    } if action['block_reason'] else None,
                    'location': {
                        'country': action['country_name'],
                        'city': action['city']
                    } if action['country_name'] else None
                }
                formatted_actions.append(formatted_action)

            return jsonify({
                'success': True,
                'actions': formatted_actions,
                'pagination': {
                    'total': total,
                    'limit': limit,
                    'offset': offset,
                    'has_more': (offset + limit) < total
                }
            }), 200

        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        print(f"❌ Error loading actions: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'success': False,
            'error': 'Failed to load blocking actions'
        }), 500


@actions_routes.route('/actions/stats', methods=['GET'])
def get_action_stats():
    """
    Get statistics about blocking actions
    """
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            # Get action counts by type
            cursor.execute("""
                SELECT
                    action_type,
                    COUNT(*) as count
                FROM blocking_actions
                WHERE created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)
                GROUP BY action_type
            """)
            action_types = cursor.fetchall()

            # Get action counts by source
            cursor.execute("""
                SELECT
                    action_source,
                    COUNT(*) as count
                FROM blocking_actions
                WHERE created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)
                GROUP BY action_source
            """)
            action_sources = cursor.fetchall()

            # Get recent activity
            cursor.execute("""
                SELECT
                    DATE(created_at) as date,
                    COUNT(*) as count
                FROM blocking_actions
                WHERE created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
                GROUP BY DATE(created_at)
                ORDER BY date DESC
            """)
            recent_activity = cursor.fetchall()

            # Get total counts
            cursor.execute("""
                SELECT
                    COUNT(*) as total_actions,
                    COUNT(DISTINCT ip_address_text) as unique_ips,
                    COUNT(CASE WHEN action_type = 'blocked' THEN 1 END) as total_blocks,
                    COUNT(CASE WHEN action_type = 'unblocked' THEN 1 END) as total_unblocks
                FROM blocking_actions
            """)
            totals = cursor.fetchone()

            return jsonify({
                'success': True,
                'action_types': {item['action_type']: item['count'] for item in action_types},
                'action_sources': {item['action_source']: item['count'] for item in action_sources},
                'recent_activity': [{'date': item['date'].isoformat(), 'count': item['count']} for item in recent_activity],
                'totals': totals
            }), 200

        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        print(f"❌ Error loading action stats: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to load action statistics'
        }), 500
