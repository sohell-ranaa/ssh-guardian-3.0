"""
SSH Guardian v3.1 - IP Statistics Routes
API endpoints for IP statistics data with Redis caching
Updated for v3.1 schema (computed from auth_events + ip_geolocation)
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

# Cache TTLs
IP_STATS_LIST_TTL = 900
IP_STATS_SUMMARY_TTL = 1800
IP_STATS_DETAIL_TTL = 1800


def invalidate_ip_stats_cache():
    """Invalidate all IP statistics caches"""
    cache = get_cache()
    cache.delete_pattern('ip_stats')


@ip_stats_routes.route('/list', methods=['GET'])
def get_ip_statistics_list():
    """
    Get paginated list of IP statistics with caching
    v3.1: Computed from auth_events table with IP geolocation data
    """
    try:
        page = int(request.args.get('page', 1))
        limit = int(request.args.get('limit', 20))
        sort = request.args.get('sort', 'last_seen')
        order = request.args.get('order', 'desc').upper()
        search = request.args.get('search', '')
        risk_level = request.args.get('risk_level', '')
        blocked = request.args.get('blocked', '')

        if order not in ['ASC', 'DESC']:
            order = 'DESC'

        allowed_sort_fields = ['ip_address_text', 'total_events', 'failed_events',
                               'avg_risk_score', 'times_blocked', 'last_seen']
        if sort not in allowed_sort_fields:
            sort = 'last_seen'

        offset = (page - 1) * limit

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

        # v3.1: Build aggregated stats from auth_events with ML data from auth_events_ml
        base_query = """
            FROM (
                SELECT
                    ae.source_ip_text as ip_address_text,
                    COUNT(*) as total_events,
                    SUM(CASE WHEN ae.event_type = 'failed' THEN 1 ELSE 0 END) as failed_events,
                    SUM(CASE WHEN ae.event_type = 'successful' THEN 1 ELSE 0 END) as successful_events,
                    AVG(ml.risk_score) as avg_risk_score,
                    MAX(ml.risk_score) as max_risk_score,
                    MIN(ae.timestamp) as first_seen,
                    MAX(ae.timestamp) as last_seen,
                    ae.geo_id,
                    (SELECT COUNT(*) FROM ip_blocks ib WHERE ib.ip_address_text = ae.source_ip_text) as times_blocked,
                    (SELECT COUNT(*) > 0 FROM ip_blocks ib WHERE ib.ip_address_text = ae.source_ip_text AND ib.is_active = TRUE) as currently_blocked
                FROM auth_events ae
                LEFT JOIN auth_events_ml ml ON ae.id = ml.event_id
                GROUP BY ae.source_ip_text, ae.geo_id
            ) as s
            LEFT JOIN ip_geolocation g ON s.geo_id = g.id
        """

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
        count_query = f"SELECT COUNT(*) as total {base_query} {where_clause}"
        cursor.execute(count_query, params)
        total_count = cursor.fetchone()['total']

        # Get data with pagination
        query = f"""
            SELECT
                s.ip_address_text,
                s.total_events,
                s.failed_events,
                s.successful_events,
                s.avg_risk_score,
                s.max_risk_score,
                s.first_seen,
                s.last_seen,
                s.times_blocked,
                s.currently_blocked,
                g.country_name,
                g.country_code,
                g.city,
                g.abuseipdb_score,
                g.threat_level as overall_threat_level
            {base_query}
            {where_clause}
            ORDER BY s.{sort} {order}
            LIMIT %s OFFSET %s
        """

        query_params = params + [limit, offset]
        cursor.execute(query, query_params)
        stats = cursor.fetchall()

        # Format dates and convert Decimal fields
        for stat in stats:
            if stat.get('first_seen'):
                stat['first_seen'] = stat['first_seen'].isoformat()
            if stat.get('last_seen'):
                stat['last_seen'] = stat['last_seen'].isoformat()
            if stat.get('avg_risk_score') is not None:
                stat['avg_risk_score'] = float(stat['avg_risk_score'])
            if stat.get('max_risk_score') is not None:
                stat['max_risk_score'] = float(stat['max_risk_score'])
            if stat.get('abuseipdb_score') is not None:
                stat['abuseipdb_score'] = int(stat['abuseipdb_score'])
            stat['currently_blocked'] = bool(stat.get('currently_blocked'))

        cursor.close()
        conn.close()

        pagination = {
            'page': page,
            'limit': limit,
            'total': total_count,
            'pages': (total_count + limit - 1) // limit
        }

        cache.set(cache_k, {'data': stats, 'pagination': pagination}, IP_STATS_LIST_TTL)

        return jsonify({
            'success': True,
            'data': stats,
            'pagination': pagination,
            'from_cache': False
        })

    except Exception as e:
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
    """Get overall IP statistics summary with caching"""
    try:
        cache = get_cache()
        cache_k = cache_key('ip_stats', 'summary')

        cached = cache.get(cache_k)
        if cached is not None:
            return jsonify({
                'success': True,
                'data': cached,
                'from_cache': True
            })

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # v3.1: Compute from auth_events with ML data
        cursor.execute("""
            SELECT
                COUNT(DISTINCT ae.source_ip_text) as total_ips,
                COUNT(*) as total_events,
                SUM(CASE WHEN ae.event_type = 'failed' THEN 1 ELSE 0 END) as total_failed_events,
                SUM(CASE WHEN ae.event_type = 'successful' THEN 1 ELSE 0 END) as total_successful_events
            FROM auth_events ae
        """)
        event_summary = cursor.fetchone()

        # Get ML stats
        cursor.execute("""
            SELECT
                AVG(risk_score) as overall_avg_risk_score,
                MAX(risk_score) as highest_risk_score
            FROM auth_events_ml
        """)
        ml_summary = cursor.fetchone()

        # Get blocking stats
        cursor.execute("""
            SELECT
                COUNT(*) as total_blocks,
                SUM(is_active = 1) as currently_blocked_count
            FROM ip_blocks
        """)
        block_summary = cursor.fetchone()

        summary = {
            'total_ips': event_summary['total_ips'] or 0,
            'total_events': event_summary['total_events'] or 0,
            'total_failed_events': event_summary['total_failed_events'] or 0,
            'total_successful_events': event_summary['total_successful_events'] or 0,
            'total_blocks': block_summary['total_blocks'] or 0,
            'currently_blocked_count': int(block_summary['currently_blocked_count'] or 0),
            'overall_avg_risk_score': float(ml_summary['overall_avg_risk_score'] or 0),
            'highest_risk_score': float(ml_summary['highest_risk_score'] or 0)
        }

        # Get risk level distribution from ML data
        cursor.execute("""
            SELECT
                CASE
                    WHEN risk_score >= 70 THEN 'high'
                    WHEN risk_score >= 40 THEN 'medium'
                    ELSE 'low'
                END as risk_level,
                COUNT(DISTINCT event_id) as count
            FROM auth_events_ml
            WHERE risk_score IS NOT NULL
            GROUP BY risk_level
        """)
        risk_distribution = {row['risk_level']: row['count'] for row in cursor.fetchall()}

        # Get top countries
        cursor.execute("""
            SELECT
                g.country_name,
                g.country_code,
                COUNT(DISTINCT ae.source_ip_text) as ip_count,
                SUM(CASE WHEN ae.event_type = 'failed' THEN 1 ELSE 0 END) as total_failed_events
            FROM auth_events ae
            LEFT JOIN ip_geolocation g ON ae.geo_id = g.id
            WHERE g.country_name IS NOT NULL
            GROUP BY g.country_name, g.country_code
            ORDER BY total_failed_events DESC
            LIMIT 10
        """)
        top_countries = cursor.fetchall()

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

        cache.set(cache_k, data, IP_STATS_SUMMARY_TTL)

        return jsonify({
            'success': True,
            'data': data,
            'from_cache': False
        })

    except Exception as e:
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
    """Get detailed statistics for a specific IP address"""
    try:
        cache = get_cache()
        cache_k = cache_key('ip_stats', 'detail', ip_address)

        cached = cache.get(cache_k)
        if cached is not None:
            return jsonify({
                'success': True,
                'data': cached,
                'from_cache': True
            })

        conn = get_connection()
        cursor = conn.cursor(dictionary=True, buffered=True)

        # v3.1: Compute stats from auth_events with ML data
        # First get aggregated event stats (without geo grouping)
        cursor.execute("""
            SELECT
                ae.source_ip_text as ip_address_text,
                COUNT(*) as total_events,
                SUM(CASE WHEN ae.event_type = 'failed' THEN 1 ELSE 0 END) as failed_events,
                SUM(CASE WHEN ae.event_type = 'successful' THEN 1 ELSE 0 END) as successful_events,
                AVG(ml.risk_score) as avg_risk_score,
                MAX(ml.risk_score) as max_risk_score,
                MIN(ae.timestamp) as first_seen,
                MAX(ae.timestamp) as last_seen,
                MAX(ae.geo_id) as geo_id
            FROM auth_events ae
            LEFT JOIN auth_events_ml ml ON ae.id = ml.event_id
            WHERE ae.source_ip_text = %s
            GROUP BY ae.source_ip_text
        """, (ip_address,))

        stat = cursor.fetchone()

        if not stat:
            cursor.close()
            conn.close()
            return jsonify({
                'success': False,
                'error': 'IP address not found'
            }), 404

        # Get geo data separately using the geo_id
        geo_id = stat.get('geo_id')
        if geo_id:
            cursor.execute("""
                SELECT
                    country_name, country_code, city, region,
                    latitude, longitude, timezone, isp, asn,
                    is_proxy, is_vpn, is_tor,
                    abuseipdb_score, abuseipdb_reports,
                    threat_level as overall_threat_level
                FROM ip_geolocation
                WHERE id = %s
            """, (geo_id,))
            geo_data = cursor.fetchone()
            if geo_data:
                stat.update(geo_data)

        # Also try to get geo from ip_geolocation by IP address if not found
        if not stat.get('country_name'):
            cursor.execute("""
                SELECT
                    country_name, country_code, city, region,
                    latitude, longitude, timezone, isp, asn,
                    is_proxy, is_vpn, is_tor,
                    abuseipdb_score, abuseipdb_reports,
                    threat_level as overall_threat_level
                FROM ip_geolocation
                WHERE ip_address_text = %s
                LIMIT 1
            """, (ip_address,))
            geo_data = cursor.fetchone()
            if geo_data:
                stat.update(geo_data)

        # Get blocking info
        cursor.execute("""
            SELECT
                COUNT(*) as times_blocked,
                MAX(blocked_at) as last_blocked_at,
                SUM(is_active = 1) > 0 as currently_blocked
            FROM ip_blocks
            WHERE ip_address_text = %s
        """, (ip_address,))
        block_info = cursor.fetchone()
        stat['times_blocked'] = block_info['times_blocked'] or 0
        stat['last_blocked_at'] = block_info['last_blocked_at']
        stat['currently_blocked'] = bool(block_info['currently_blocked'])

        # Format dates and convert Decimal fields
        if stat.get('last_blocked_at'):
            stat['last_blocked_at'] = stat['last_blocked_at'].isoformat()
        if stat.get('first_seen'):
            stat['first_seen'] = stat['first_seen'].isoformat()
        if stat.get('last_seen'):
            stat['last_seen'] = stat['last_seen'].isoformat()
        if stat.get('latitude') is not None:
            stat['latitude'] = float(stat['latitude'])
        if stat.get('longitude') is not None:
            stat['longitude'] = float(stat['longitude'])
        if stat.get('avg_risk_score') is not None:
            stat['avg_risk_score'] = float(stat['avg_risk_score'])
        if stat.get('max_risk_score') is not None:
            stat['max_risk_score'] = float(stat['max_risk_score'])
        if stat.get('abuseipdb_score') is not None:
            stat['abuseipdb_score'] = int(stat['abuseipdb_score'])

        # Get recent events for this IP
        cursor.execute("""
            SELECT
                ae.event_type,
                ae.target_username as username,
                ae.agent_id,
                a.hostname as server_name,
                ae.timestamp as event_timestamp,
                ml.risk_score,
                ml.threat_type
            FROM auth_events ae
            LEFT JOIN auth_events_ml ml ON ae.id = ml.event_id
            LEFT JOIN agents a ON ae.agent_id = a.id
            WHERE ae.source_ip_text = %s
            ORDER BY ae.timestamp DESC
            LIMIT 20
        """, (ip_address,))

        recent_events = cursor.fetchall()

        for event in recent_events:
            if event.get('event_timestamp'):
                event['event_timestamp'] = event['event_timestamp'].isoformat()
            if event.get('risk_score') is not None:
                event['risk_score'] = float(event['risk_score'])

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

        cache.set(cache_k, data, IP_STATS_DETAIL_TTL)

        return jsonify({
            'success': True,
            'data': data,
            'from_cache': False
        })

    except Exception as e:
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


@ip_stats_routes.route('/top-attackers', methods=['GET'])
def get_top_attackers():
    """Get top attacking IPs based on failed attempts"""
    try:
        limit = int(request.args.get('limit', 20))
        period = request.args.get('period', '24h')

        cache = get_cache()
        cache_k = cache_key('ip_stats', 'top_attackers', period, str(limit))

        cached = cache.get(cache_k)
        if cached is not None:
            return jsonify({
                'success': True,
                'data': cached,
                'from_cache': True
            })

        # Calculate time filter
        time_filter = ""
        if period == '24h':
            time_filter = "AND ae.timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)"
        elif period == '7d':
            time_filter = "AND ae.timestamp >= DATE_SUB(NOW(), INTERVAL 7 DAY)"
        elif period == '30d':
            time_filter = "AND ae.timestamp >= DATE_SUB(NOW(), INTERVAL 30 DAY)"

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute(f"""
            SELECT
                ae.source_ip_text as ip_address,
                COUNT(*) as total_attempts,
                SUM(CASE WHEN ae.event_type = 'failed' THEN 1 ELSE 0 END) as failed_attempts,
                COUNT(DISTINCT ae.target_username) as unique_usernames,
                COUNT(DISTINCT ae.agent_id) as unique_servers,
                MAX(ml.risk_score) as max_risk_score,
                MAX(ae.timestamp) as last_seen,
                g.country_name,
                g.country_code,
                g.threat_level,
                g.abuseipdb_score,
                (SELECT is_active FROM ip_blocks WHERE ip_address_text = ae.source_ip_text ORDER BY blocked_at DESC LIMIT 1) as is_blocked
            FROM auth_events ae
            LEFT JOIN auth_events_ml ml ON ae.id = ml.event_id
            LEFT JOIN ip_geolocation g ON ae.geo_id = g.id
            WHERE ae.event_type = 'failed'
            {time_filter}
            GROUP BY ae.source_ip_text, ae.geo_id, g.country_name, g.country_code,
                     g.threat_level, g.abuseipdb_score
            ORDER BY failed_attempts DESC
            LIMIT %s
        """, (limit,))

        attackers = cursor.fetchall()

        for attacker in attackers:
            if attacker.get('last_seen'):
                attacker['last_seen'] = attacker['last_seen'].isoformat()
            if attacker.get('max_risk_score') is not None:
                attacker['max_risk_score'] = float(attacker['max_risk_score'])
            attacker['is_blocked'] = bool(attacker.get('is_blocked'))

        cursor.close()
        conn.close()

        cache.set(cache_k, attackers, IP_STATS_LIST_TTL)

        return jsonify({
            'success': True,
            'data': attackers,
            'period': period,
            'from_cache': False
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
