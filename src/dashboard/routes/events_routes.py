"""
SSH Guardian v3.0 - Events Dashboard Routes
Provides API endpoints for fetching and displaying auth events with enrichment data
Optimized with Redis caching for high performance
"""

from flask import Blueprint, jsonify, request
import sys
from pathlib import Path
from datetime import datetime

# Add project paths
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
sys.path.append(str(PROJECT_ROOT / "dbs"))
sys.path.append(str(PROJECT_ROOT / "src"))

from connection import get_connection
from core.cache import (
    get_cache, cache_key, cache_key_hash, CACHE_TTL,
    cached_events_list, cache_events_list,
    cached_events_count, cache_events_count,
    cached_stats, cache_stats
)

# Create Blueprint
events_routes = Blueprint('events_routes', __name__, url_prefix='/api/dashboard/events')


def _get_approximate_count(conn, where_sql: str, params: list, needs_threat_join: bool = False) -> int:
    """
    Get an approximate count for pagination.
    Uses table statistics for unfiltered queries, exact count for filtered.
    """
    cursor = conn.cursor(dictionary=True)
    try:
        if not where_sql or where_sql.strip() == "":
            # Unfiltered query - use table statistics (much faster)
            cursor.execute("""
                SELECT TABLE_ROWS as approx_count
                FROM information_schema.TABLES
                WHERE TABLE_SCHEMA = DATABASE()
                AND TABLE_NAME = 'auth_events'
            """)
            result = cursor.fetchone()
            if result and result['approx_count']:
                return int(result['approx_count'])

        # Filtered query - add threat intel join if filtering by threat level
        threat_join = ""
        if needs_threat_join:
            threat_join = "LEFT JOIN ip_threat_intelligence ti ON ae.source_ip_text = ti.ip_address_text"

        count_query = f"""
            SELECT COUNT(*) as total
            FROM auth_events ae
            {threat_join}
            WHERE 1=1 {where_sql}
        """
        cursor.execute(count_query, params)
        return cursor.fetchone()['total']
    finally:
        cursor.close()


@events_routes.route('/list', methods=['GET'])
def list_events():
    """
    Get list of auth events with enrichment data (GeoIP + Threat Intel)
    Optimized with Redis caching and efficient pagination.

    Query Parameters:
    - limit: Number of events to return (default: 50, max: 200)
    - offset: Offset for pagination (default: 0)
    - event_type: Filter by event type (failed, successful, invalid)
    - threat_level: Filter by threat level (clean, low, medium, high, critical)
    - search: Search by IP or username
    - nocache: Set to 1 to bypass cache
    """

    try:
        # Get query parameters
        limit = min(int(request.args.get('limit', 50)), 200)  # Reduced max limit
        offset = int(request.args.get('offset', 0))
        event_type = request.args.get('event_type')
        threat_level = request.args.get('threat_level')
        search = request.args.get('search', '').strip()
        agent_id = request.args.get('agent_id')
        nocache = request.args.get('nocache', '0') == '1'

        # Build filter dict for cache key
        filters = {
            'event_type': event_type,
            'threat_level': threat_level,
            'search': search if search else None,
            'agent_id': agent_id
        }
        # Remove None values for cleaner cache key
        filters = {k: v for k, v in filters.items() if v is not None}

        # Try cache first (unless nocache)
        cache = get_cache()
        if not nocache:
            cached_result = cached_events_list(limit, offset, filters)
            if cached_result:
                cached_result['from_cache'] = True
                return jsonify(cached_result), 200

        # Build WHERE clause
        where_clauses = []
        params = []
        needs_threat_join = False

        if event_type:
            where_clauses.append("ae.event_type = %s")
            params.append(event_type)

        if threat_level:
            # Use threat intel table for filtering
            where_clauses.append("ti.overall_threat_level = %s")
            params.append(threat_level)
            needs_threat_join = True

        if search:
            where_clauses.append("(ae.source_ip_text LIKE %s OR ae.target_username LIKE %s)")
            params.extend([f"%{search}%", f"%{search}%"])

        if agent_id:
            where_clauses.append("ae.agent_id = %s")
            params.append(agent_id)

        where_sql = " AND " + " AND ".join(where_clauses) if where_clauses else ""

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            # Step 1: Get base events with GeoIP (fast - uses indexed foreign key)
            # Add threat intel join only when filtering by threat level
            threat_join = ""
            if needs_threat_join:
                threat_join = "LEFT JOIN ip_threat_intelligence ti ON ae.source_ip_text = ti.ip_address_text"

            base_query = f"""
                SELECT
                    ae.id,
                    ae.event_uuid,
                    ae.timestamp,
                    ae.source_ip_text,
                    ae.target_username,
                    ae.event_type,
                    ae.auth_method,
                    ae.target_server,
                    ae.target_port,
                    ae.processing_status,
                    ae.ml_risk_score,
                    ae.ml_threat_type,
                    ae.is_anomaly,
                    ae.agent_id,

                    -- GeoIP data (indexed join on geo_id)
                    geo.country_code,
                    geo.country_name,
                    geo.city,
                    geo.region,
                    geo.latitude,
                    geo.longitude,
                    geo.isp,
                    geo.is_proxy,
                    geo.is_vpn,
                    geo.is_tor

                FROM auth_events ae
                LEFT JOIN ip_geolocation geo ON ae.geo_id = geo.id
                {threat_join}

                WHERE 1=1 {where_sql}

                ORDER BY ae.timestamp DESC
                LIMIT %s OFFSET %s
            """

            query_params = params + [limit, offset]
            cursor.execute(base_query, query_params)
            events = cursor.fetchall()

            # Step 2: Batch fetch threat intel and agent data for the IPs we got
            if events:
                # Get unique IPs and agent IDs
                unique_ips = list(set(e['source_ip_text'] for e in events if e['source_ip_text']))
                unique_agent_ids = list(set(e['agent_id'] for e in events if e['agent_id']))

                # Fetch threat intel in bulk
                threat_data = {}
                if unique_ips:
                    placeholders = ','.join(['%s'] * len(unique_ips))
                    cursor.execute(f"""
                        SELECT ip_address_text, overall_threat_level, threat_confidence,
                               abuseipdb_score, abuseipdb_reports,
                               virustotal_positives, virustotal_total,
                               shodan_ports, shodan_vulns
                        FROM ip_threat_intelligence
                        WHERE ip_address_text IN ({placeholders})
                    """, unique_ips)
                    for row in cursor.fetchall():
                        threat_data[row['ip_address_text']] = row

                # Fetch agent data in bulk
                agent_data = {}
                if unique_agent_ids:
                    placeholders = ','.join(['%s'] * len(unique_agent_ids))
                    cursor.execute(f"""
                        SELECT id, display_name, hostname
                        FROM agents
                        WHERE id IN ({placeholders})
                    """, unique_agent_ids)
                    for row in cursor.fetchall():
                        agent_data[row['id']] = row

                # Merge threat intel and agent data into events
                for event in events:
                    ip = event['source_ip_text']
                    agent_id = event['agent_id']

                    if ip in threat_data:
                        ti = threat_data[ip]
                        event['overall_threat_level'] = ti['overall_threat_level']
                        event['threat_confidence'] = ti['threat_confidence']
                        event['abuseipdb_score'] = ti['abuseipdb_score']
                        event['abuseipdb_reports'] = ti['abuseipdb_reports']
                        event['virustotal_positives'] = ti['virustotal_positives']
                        event['virustotal_total'] = ti['virustotal_total']
                        event['shodan_ports'] = ti['shodan_ports']
                        event['shodan_vulns'] = ti['shodan_vulns']
                    else:
                        event['overall_threat_level'] = None
                        event['threat_confidence'] = None
                        event['abuseipdb_score'] = None
                        event['abuseipdb_reports'] = None
                        event['virustotal_positives'] = None
                        event['virustotal_total'] = None
                        event['shodan_ports'] = None
                        event['shodan_vulns'] = None

                    if agent_id and agent_id in agent_data:
                        ag = agent_data[agent_id]
                        event['agent_name'] = ag['display_name']
                        event['agent_hostname'] = ag['hostname']
                    else:
                        event['agent_name'] = None
                        event['agent_hostname'] = None

            # Get count - use cached or approximate for better performance
            count_cache_key = cache_key_hash('events_count', filters=filters)
            total = cache.get(count_cache_key) if cache.enabled else None

            if total is None:
                total = _get_approximate_count(conn, where_sql, params, needs_threat_join)
                if cache.enabled:
                    cache.set(count_cache_key, total, CACHE_TTL['events_count'])

            # Format the response
            formatted_events = []
            for event in events:
                formatted_event = {
                    'id': event['id'],
                    'uuid': event['event_uuid'],
                    'timestamp': event['timestamp'].isoformat() if event['timestamp'] else None,
                    'ip': event['source_ip_text'],
                    'username': event['target_username'],
                    'event_type': event['event_type'],
                    'auth_method': event['auth_method'],
                    'server': event['target_server'],
                    'port': event['target_port'],
                    'processing_status': event['processing_status'],

                    # ML Results
                    'ml_risk_score': event['ml_risk_score'],
                    'ml_threat_type': event['ml_threat_type'],
                    'is_anomaly': bool(event['is_anomaly']) if event['is_anomaly'] is not None else None,

                    # GeoIP
                    'location': {
                        'country_code': event['country_code'],
                        'country': event['country_name'],
                        'city': event['city'],
                        'region': event['region'],
                        'latitude': float(event['latitude']) if event['latitude'] else None,
                        'longitude': float(event['longitude']) if event['longitude'] else None,
                        'isp': event['isp'],
                        'is_proxy': bool(event['is_proxy']) if event['is_proxy'] is not None else False,
                        'is_vpn': bool(event['is_vpn']) if event['is_vpn'] is not None else False,
                        'is_tor': bool(event['is_tor']) if event['is_tor'] is not None else False
                    } if event['country_name'] else None,

                    # Threat Intel
                    'threat': {
                        'level': event['overall_threat_level'],
                        'confidence': float(event['threat_confidence']) if event['threat_confidence'] else 0,
                        'abuseipdb_score': event['abuseipdb_score'],
                        'abuseipdb_reports': event['abuseipdb_reports'],
                        'virustotal_detections': f"{event['virustotal_positives'] or 0}/{event['virustotal_total'] or 0}",
                        'shodan_ports': event['shodan_ports'],
                        'shodan_vulns': event['shodan_vulns']
                    } if event['overall_threat_level'] else None,

                    # Agent
                    'agent': {
                        'name': event['agent_name'],
                        'hostname': event['agent_hostname']
                    } if event['agent_name'] else None
                }

                formatted_events.append(formatted_event)

            response_data = {
                'success': True,
                'events': formatted_events,
                'pagination': {
                    'total': total,
                    'limit': limit,
                    'offset': offset,
                    'has_more': (offset + limit) < total
                },
                'from_cache': False
            }

            # Cache the result
            cache_events_list(limit, offset, filters, response_data)

            return jsonify(response_data), 200

        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        print(f"❌ Error fetching events: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'success': False,
            'error': 'Failed to fetch events'
        }), 500


@events_routes.route('/stats', methods=['GET'])
def get_stats():
    """Get event statistics for dashboard - optimized with caching"""

    try:
        # Try cache first
        cache = get_cache()
        nocache = request.args.get('nocache', '0') == '1'

        if not nocache:
            cached_data = cached_stats()
            if cached_data:
                cached_data['from_cache'] = True
                return jsonify(cached_data), 200

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            # Total events - use approximate count
            cursor.execute("""
                SELECT TABLE_ROWS as total
                FROM information_schema.TABLES
                WHERE TABLE_SCHEMA = DATABASE()
                AND TABLE_NAME = 'auth_events'
            """)
            total_events = cursor.fetchone()['total'] or 0

            # Events by type - this query is fast with index
            cursor.execute("""
                SELECT
                    event_type,
                    COUNT(*) as count
                FROM auth_events
                GROUP BY event_type
            """)
            events_by_type = {row['event_type']: row['count'] for row in cursor.fetchall()}

            # Threat level distribution - limit to recent events for speed
            cursor.execute("""
                SELECT
                    ti.overall_threat_level as threat_level,
                    COUNT(DISTINCT ae.id) as count
                FROM auth_events ae
                JOIN ip_threat_intelligence ti ON ae.source_ip_text = ti.ip_address_text
                WHERE ae.timestamp >= DATE_SUB(NOW(), INTERVAL 7 DAY)
                GROUP BY ti.overall_threat_level
            """)
            threat_distribution = {row['threat_level']: row['count'] for row in cursor.fetchall()}

            # Recent events (last 24 hours) - use index
            cursor.execute("""
                SELECT COUNT(*) as count
                FROM auth_events
                WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
            """)
            recent_24h = cursor.fetchone()['count']

            # Top attacking IPs (failed events) - limit scope for speed
            cursor.execute("""
                SELECT
                    ae.source_ip_text,
                    COUNT(*) as attempts,
                    ti.overall_threat_level,
                    geo.country_name
                FROM auth_events ae
                LEFT JOIN ip_threat_intelligence ti ON ae.source_ip_text = ti.ip_address_text
                LEFT JOIN ip_geolocation geo ON ae.geo_id = geo.id
                WHERE ae.event_type = 'failed'
                AND ae.timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
                GROUP BY ae.source_ip_text, ti.overall_threat_level, geo.country_name
                ORDER BY attempts DESC
                LIMIT 10
            """)
            top_ips = cursor.fetchall()

            response_data = {
                'success': True,
                'stats': {
                    'total_events': total_events,
                    'events_by_type': events_by_type,
                    'threat_distribution': threat_distribution,
                    'recent_24h': recent_24h,
                    'top_attacking_ips': top_ips
                },
                'from_cache': False
            }

            # Cache the stats
            cache_stats(response_data)

            return jsonify(response_data), 200

        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        print(f"❌ Error fetching stats: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to fetch statistics'
        }), 500


@events_routes.route('/cache/clear', methods=['POST'])
def clear_cache():
    """Clear events cache - admin endpoint"""
    try:
        cache = get_cache()
        cache.invalidate_events()
        return jsonify({
            'success': True,
            'message': 'Events cache cleared'
        }), 200
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@events_routes.route('/cache/stats', methods=['GET'])
def cache_statistics():
    """Get cache statistics"""
    try:
        cache = get_cache()
        stats = cache.get_stats()
        return jsonify({
            'success': True,
            'cache': stats
        }), 200
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
