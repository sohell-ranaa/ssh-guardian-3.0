"""
IP Statistics Routes - API endpoints for IP statistics data
"""
import sys
from pathlib import Path
from flask import Blueprint, jsonify, request

# Add database path
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
sys.path.append(str(PROJECT_ROOT / "dbs"))

from connection import get_connection

ip_stats_routes = Blueprint('ip_stats', __name__)


@ip_stats_routes.route('/list', methods=['GET'])
def get_ip_statistics_list():
    """
    Get paginated list of IP statistics
    Query params:
    - page: Page number (default: 1)
    - limit: Items per page (default: 20)
    - sort: Sort field (default: last_seen)
    - order: Sort order (asc/desc, default: desc)
    - search: Search IP address
    - risk_level: Filter by risk level (high/medium/low)
    - blocked: Filter by blocked status (true/false)
    """
    try:
        # Get query parameters
        page = int(request.args.get('page', 1))
        limit = int(request.args.get('limit', 20))
        sort = request.args.get('sort', 'last_seen')
        order = request.args.get('order', 'desc').upper()
        search = request.args.get('search', '')
        risk_level = request.args.get('risk_level', '')
        blocked = request.args.get('blocked', '')

        # Validate parameters
        if order not in ['ASC', 'DESC']:
            order = 'DESC'

        allowed_sort_fields = ['ip_address_text', 'total_events', 'failed_events',
                               'avg_risk_score', 'times_blocked', 'last_seen']
        if sort not in allowed_sort_fields:
            sort = 'last_seen'

        offset = (page - 1) * limit

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Build WHERE clause
        where_conditions = []
        params = []

        if search:
            where_conditions.append("s.ip_address_text LIKE %s")
            params.append(f"%{search}%")

        if risk_level:
            if risk_level == 'high':
                where_conditions.append("s.avg_risk_score >= 70")
            elif risk_level == 'medium':
                where_conditions.append("s.avg_risk_score >= 40 AND s.avg_risk_score < 70")
            elif risk_level == 'low':
                where_conditions.append("s.avg_risk_score < 40")

        if blocked:
            if blocked.lower() == 'true':
                where_conditions.append("s.currently_blocked = 1")
            elif blocked.lower() == 'false':
                where_conditions.append("s.currently_blocked = 0")

        where_clause = ""
        if where_conditions:
            where_clause = "WHERE " + " AND ".join(where_conditions)

        # Get total count
        count_query = f"""
            SELECT COUNT(*) as total
            FROM ip_statistics s
            {where_clause}
        """
        cursor.execute(count_query, params)
        total_count = cursor.fetchone()['total']

        # Get data with pagination
        query = f"""
            SELECT
                s.*,
                g.country_name,
                g.country_code,
                g.city,
                t.abuseipdb_score,
                t.overall_threat_level
            FROM ip_statistics s
            LEFT JOIN ip_geolocation g ON s.geo_id = g.id
            LEFT JOIN ip_threat_intelligence t ON s.ip_address_text = t.ip_address_text
            {where_clause}
            ORDER BY s.{sort} {order}
            LIMIT %s OFFSET %s
        """

        query_params = params + [limit, offset]
        cursor.execute(query, query_params)
        stats = cursor.fetchall()

        # Format dates
        for stat in stats:
            if stat.get('last_blocked_at'):
                stat['last_blocked_at'] = stat['last_blocked_at'].isoformat()
            if stat.get('first_seen'):
                stat['first_seen'] = stat['first_seen'].isoformat()
            if stat.get('last_seen'):
                stat['last_seen'] = stat['last_seen'].isoformat()
            if stat.get('updated_at'):
                stat['updated_at'] = stat['updated_at'].isoformat()

        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'data': stats,
            'pagination': {
                'page': page,
                'limit': limit,
                'total': total_count,
                'pages': (total_count + limit - 1) // limit
            }
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@ip_stats_routes.route('/summary', methods=['GET'])
def get_ip_statistics_summary():
    """
    Get overall IP statistics summary
    """
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Get overall statistics
        cursor.execute("""
            SELECT
                COUNT(*) as total_ips,
                SUM(total_events) as total_events,
                SUM(failed_events) as total_failed_events,
                SUM(successful_events) as total_successful_events,
                SUM(times_blocked) as total_blocks,
                SUM(CASE WHEN currently_blocked = 1 THEN 1 ELSE 0 END) as currently_blocked_count,
                AVG(avg_risk_score) as overall_avg_risk_score,
                MAX(max_risk_score) as highest_risk_score
            FROM ip_statistics
        """)
        summary = cursor.fetchone()

        # Get risk level distribution
        cursor.execute("""
            SELECT
                CASE
                    WHEN avg_risk_score >= 70 THEN 'high'
                    WHEN avg_risk_score >= 40 THEN 'medium'
                    ELSE 'low'
                END as risk_level,
                COUNT(*) as count
            FROM ip_statistics
            WHERE avg_risk_score IS NOT NULL
            GROUP BY risk_level
        """)
        risk_distribution = {row['risk_level']: row['count'] for row in cursor.fetchall()}

        # Get top countries
        cursor.execute("""
            SELECT
                g.country_name,
                g.country_code,
                COUNT(*) as ip_count,
                SUM(s.failed_events) as total_failed_events
            FROM ip_statistics s
            LEFT JOIN ip_geolocation g ON s.geo_id = g.id
            WHERE g.country_name IS NOT NULL
            GROUP BY g.country_name, g.country_code
            ORDER BY total_failed_events DESC
            LIMIT 10
        """)
        top_countries = cursor.fetchall()

        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'data': {
                'summary': summary,
                'risk_distribution': risk_distribution,
                'top_countries': top_countries
            }
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@ip_stats_routes.route('/<ip_address>', methods=['GET'])
def get_ip_statistics_detail(ip_address):
    """
    Get detailed statistics for a specific IP address
    """
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Get IP statistics
        cursor.execute("""
            SELECT
                s.*,
                g.country_name,
                g.country_code,
                g.city,
                g.region,
                g.latitude,
                g.longitude,
                g.timezone,
                t.abuseipdb_score,
                t.overall_threat_level,
                t.abuseipdb_confidence
            FROM ip_statistics s
            LEFT JOIN ip_geolocation g ON s.geo_id = g.id
            LEFT JOIN ip_threat_intelligence t ON s.ip_address_text = t.ip_address_text
            WHERE s.ip_address_text = %s
        """, (ip_address,))

        stat = cursor.fetchone()

        if not stat:
            cursor.close()
            conn.close()
            return jsonify({
                'success': False,
                'error': 'IP address not found'
            }), 404

        # Format dates
        if stat.get('last_blocked_at'):
            stat['last_blocked_at'] = stat['last_blocked_at'].isoformat()
        if stat.get('first_seen'):
            stat['first_seen'] = stat['first_seen'].isoformat()
        if stat.get('last_seen'):
            stat['last_seen'] = stat['last_seen'].isoformat()
        if stat.get('updated_at'):
            stat['updated_at'] = stat['updated_at'].isoformat()

        # Get recent events for this IP
        cursor.execute("""
            SELECT
                event_type,
                username,
                server_name,
                port,
                event_timestamp,
                risk_score
            FROM ssh_events
            WHERE ip_address_text = %s
            ORDER BY event_timestamp DESC
            LIMIT 20
        """, (ip_address,))

        recent_events = cursor.fetchall()

        # Format event timestamps
        for event in recent_events:
            if event.get('event_timestamp'):
                event['event_timestamp'] = event['event_timestamp'].isoformat()

        # Get blocking history
        cursor.execute("""
            SELECT
                action_type,
                action_source,
                reason,
                created_at
            FROM blocking_actions
            WHERE ip_address_text = %s
            ORDER BY created_at DESC
            LIMIT 10
        """, (ip_address,))

        blocking_history = cursor.fetchall()

        # Format blocking history timestamps
        for action in blocking_history:
            if action.get('created_at'):
                action['created_at'] = action['created_at'].isoformat()

        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'data': {
                'statistics': stat,
                'recent_events': recent_events,
                'blocking_history': blocking_history
            }
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
