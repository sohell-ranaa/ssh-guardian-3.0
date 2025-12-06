"""
IP Statistics Routes - API endpoints for IP statistics data
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

ip_stats_routes = Blueprint('ip_stats', __name__)

# Cache TTLs - OPTIMIZED FOR PERFORMANCE (minimum 15 minutes)
IP_STATS_LIST_TTL = 900      # 15 minutes for paginated list
IP_STATS_SUMMARY_TTL = 1800  # 30 minutes for summary stats
IP_STATS_DETAIL_TTL = 1800   # 30 minutes for IP details


def invalidate_ip_stats_cache():
    """Invalidate all IP statistics caches"""
    cache = get_cache()
    cache.delete_pattern('ip_stats')


@ip_stats_routes.route('/list', methods=['GET'])
def get_ip_statistics_list():
    """
    Get paginated list of IP statistics with caching
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

        # Try cache first
        cache = get_cache()
        cache_params = {
            'page': page, 'limit': limit, 'sort': sort, 'order': order,
            'search': search, 'risk_level': risk_level, 'blocked': blocked
        }
        cache_k = cache_key_hash('ip_stats', 'list', cache_params)

        cached = cache.get(cache_k)
        if cached is not None:
            return jsonify({
                'success': True,
                'data': cached['data'],
                'pagination': cached['pagination'],
                'from_cache': True
            })

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

        # Format dates and convert Decimal fields
        for stat in stats:
            if stat.get('last_blocked_at'):
                stat['last_blocked_at'] = stat['last_blocked_at'].isoformat()
            if stat.get('first_seen'):
                stat['first_seen'] = stat['first_seen'].isoformat()
            if stat.get('last_seen'):
                stat['last_seen'] = stat['last_seen'].isoformat()
            if stat.get('updated_at'):
                stat['updated_at'] = stat['updated_at'].isoformat()
            # Convert Decimal fields
            if stat.get('avg_risk_score') is not None:
                stat['avg_risk_score'] = float(stat['avg_risk_score'])
            if stat.get('abuseipdb_score') is not None:
                stat['abuseipdb_score'] = int(stat['abuseipdb_score'])

        cursor.close()
        conn.close()

        pagination = {
            'page': page,
            'limit': limit,
            'total': total_count,
            'pages': (total_count + limit - 1) // limit
        }

        # Cache the result
        cache.set(cache_k, {'data': stats, 'pagination': pagination}, IP_STATS_LIST_TTL)

        return jsonify({
            'success': True,
            'data': stats,
            'pagination': pagination,
            'from_cache': False
        })

    except Exception as e:
        # Ensure connection is closed on error
        try:
            if 'cursor' in locals():
                cursor.close()
            if 'conn' in locals():
                conn.close()
        except:
            pass
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@ip_stats_routes.route('/summary', methods=['GET'])
def get_ip_statistics_summary():
    """
    Get overall IP statistics summary with caching
    """
    try:
        cache = get_cache()
        cache_k = cache_key('ip_stats', 'summary')

        # Try cache first
        cached = cache.get(cache_k)
        if cached is not None:
            return jsonify({
                'success': True,
                'data': cached,
                'from_cache': True
            })

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

        # Convert Decimal fields in summary
        if summary:
            for key in summary:
                if summary[key] is not None:
                    if key == 'overall_avg_risk_score':
                        summary[key] = float(summary[key])
                    elif isinstance(summary[key], (int, float)):
                        pass  # Keep as is
                    else:
                        summary[key] = int(summary[key])

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

        # Convert Decimal fields in top_countries
        for country in top_countries:
            if country.get('total_failed_events') is not None:
                country['total_failed_events'] = int(country['total_failed_events'])

        cursor.close()
        conn.close()

        data = {
            'summary': summary,
            'risk_distribution': risk_distribution,
            'top_countries': top_countries
        }

        # Cache the result
        cache.set(cache_k, data, IP_STATS_SUMMARY_TTL)

        return jsonify({
            'success': True,
            'data': data,
            'from_cache': False
        })

    except Exception as e:
        # Ensure connection is closed on error
        try:
            if 'cursor' in locals():
                cursor.close()
            if 'conn' in locals():
                conn.close()
        except:
            pass
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@ip_stats_routes.route('/<ip_address>', methods=['GET'])
def get_ip_statistics_detail(ip_address):
    """
    Get detailed statistics for a specific IP address with caching
    """
    try:
        cache = get_cache()
        cache_k = cache_key('ip_stats', 'detail', ip_address)

        # Try cache first
        cached = cache.get(cache_k)
        if cached is not None:
            return jsonify({
                'success': True,
                'data': cached,
                'from_cache': True
            })

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

        # Format dates and convert Decimal fields
        if stat.get('last_blocked_at'):
            stat['last_blocked_at'] = stat['last_blocked_at'].isoformat()
        if stat.get('first_seen'):
            stat['first_seen'] = stat['first_seen'].isoformat()
        if stat.get('last_seen'):
            stat['last_seen'] = stat['last_seen'].isoformat()
        if stat.get('updated_at'):
            stat['updated_at'] = stat['updated_at'].isoformat()
        # Convert Decimal fields
        if stat.get('latitude') is not None:
            stat['latitude'] = float(stat['latitude'])
        if stat.get('longitude') is not None:
            stat['longitude'] = float(stat['longitude'])
        if stat.get('avg_risk_score') is not None:
            stat['avg_risk_score'] = float(stat['avg_risk_score'])
        if stat.get('abuseipdb_score') is not None:
            stat['abuseipdb_score'] = int(stat['abuseipdb_score'])
        if stat.get('abuseipdb_confidence') is not None:
            stat['abuseipdb_confidence'] = float(stat['abuseipdb_confidence'])

        # Get recent events for this IP
        cursor.execute("""
            SELECT
                event_type,
                target_username as username,
                target_server as server_name,
                target_port as port,
                timestamp as event_timestamp
            FROM auth_events
            WHERE source_ip_text = %s
            ORDER BY timestamp DESC
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

        data = {
            'statistics': stat,
            'recent_events': recent_events,
            'blocking_history': blocking_history
        }

        # Cache the result
        cache.set(cache_k, data, IP_STATS_DETAIL_TTL)

        return jsonify({
            'success': True,
            'data': data,
            'from_cache': False
        })

    except Exception as e:
        # Ensure connection is closed on error
        try:
            if 'cursor' in locals():
                cursor.close()
            if 'conn' in locals():
                conn.close()
        except:
            pass
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
