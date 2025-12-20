"""
SSH Guardian v3.1 - Events Dashboard Routes
API endpoints for fetching and displaying auth events with enrichment data
Updated for v3.1 schema:
- ML data in auth_events_ml table (joined via event_id)
- Threat data merged into ip_geolocation table
"""

from flask import Blueprint, jsonify, request
import sys
from pathlib import Path

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

events_routes = Blueprint('events_routes', __name__, url_prefix='/api/dashboard/events')


def _get_count(conn, where_sql: str, params: list) -> int:
    """Get count for pagination"""
    cursor = conn.cursor(dictionary=True)
    try:
        count_query = f"""
            SELECT COUNT(*) as total
            FROM auth_events ae
            LEFT JOIN ip_geolocation geo ON ae.geo_id = geo.id
            WHERE 1=1 {where_sql}
        """
        cursor.execute(count_query, params)
        return cursor.fetchone()['total']
    finally:
        cursor.close()


@events_routes.route('/list', methods=['GET'])
def list_events():
    """
    Get list of auth events with enrichment data (GeoIP + Threat Intel + ML)
    v3.1: ML data from auth_events_ml, threat data from ip_geolocation

    Query Parameters:
    - limit: Number of events to return (default: 50, max: 200)
    - offset: Offset for pagination (default: 0)
    - event_type: Filter by event type (failed, successful, invalid)
    - threat_level: Filter by threat level (clean, low, medium, high, critical)
    - search: Search by IP or username
    - time_range: Filter by time (today, yesterday, last_7_days, last_30_days, all_time)
    - nocache: Set to 1 to bypass cache
    """
    try:
        limit = min(int(request.args.get('limit', 50)), 200)
        offset = int(request.args.get('offset', 0))
        event_type = request.args.get('event_type')
        threat_level = request.args.get('threat_level')
        search = request.args.get('search', '').strip()
        ip_filter = request.args.get('ip', '').strip()
        agent_id = request.args.get('agent_id')
        time_range = request.args.get('time_range', 'last_30_days')
        nocache = request.args.get('nocache', '0') == '1'

        filters = {
            'event_type': event_type,
            'threat_level': threat_level,
            'search': search if search else None,
            'ip': ip_filter if ip_filter else None,
            'agent_id': agent_id,
            'time_range': time_range
        }
        filters = {k: v for k, v in filters.items() if v is not None}

        cache = get_cache()
        if not nocache:
            cached_result = cached_events_list(limit, offset, filters)
            if cached_result:
                cached_result['from_cache'] = True
                return jsonify(cached_result), 200

        where_clauses = []
        params = []

        if event_type:
            where_clauses.append("ae.event_type = %s")
            params.append(event_type)

        if threat_level:
            # v3.1: threat_level is in ip_geolocation table
            where_clauses.append("geo.threat_level = %s")
            params.append(threat_level)

        if search:
            where_clauses.append("(ae.target_username LIKE %s OR ae.source_ip_text LIKE %s)")
            params.extend([f"%{search}%", f"%{search}%"])

        if ip_filter:
            where_clauses.append("ae.source_ip_text LIKE %s")
            params.append(f"%{ip_filter}%")

        if agent_id:
            where_clauses.append("ae.agent_id = %s")
            params.append(agent_id)

        if time_range and time_range != 'all_time':
            if time_range == 'today':
                where_clauses.append("DATE(ae.timestamp) = CURDATE()")
            elif time_range == 'yesterday':
                where_clauses.append("DATE(ae.timestamp) = DATE_SUB(CURDATE(), INTERVAL 1 DAY)")
            elif time_range == 'last_7_days':
                where_clauses.append("ae.timestamp >= DATE_SUB(NOW(), INTERVAL 7 DAY)")
            elif time_range == 'last_30_days':
                where_clauses.append("ae.timestamp >= DATE_SUB(NOW(), INTERVAL 30 DAY)")

        where_sql = " AND " + " AND ".join(where_clauses) if where_clauses else ""

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            # v3.1: Join with auth_events_ml for ML data, threat data from ip_geolocation
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
                    ae.agent_id,
                    ae.failure_reason,

                    -- ML data from auth_events_ml (v3.1)
                    ml.risk_score as ml_risk_score,
                    ml.threat_type as ml_threat_type,
                    ml.is_anomaly,
                    ml.confidence as ml_confidence,

                    -- GeoIP + Threat data from ip_geolocation (v3.1)
                    geo.country_code,
                    geo.country_name,
                    geo.city,
                    geo.region,
                    geo.latitude,
                    geo.longitude,
                    geo.isp,
                    geo.is_proxy,
                    geo.is_vpn,
                    geo.is_tor,
                    geo.threat_level,
                    geo.abuseipdb_score,
                    geo.abuseipdb_reports,
                    geo.virustotal_positives,
                    geo.virustotal_total

                FROM auth_events ae
                LEFT JOIN ip_geolocation geo ON ae.geo_id = geo.id
                LEFT JOIN auth_events_ml ml ON ae.id = ml.event_id

                WHERE 1=1 {where_sql}

                ORDER BY ae.timestamp DESC
                LIMIT %s OFFSET %s
            """

            query_params = params + [limit, offset]
            cursor.execute(base_query, query_params)
            events = cursor.fetchall()

            # Fetch agent data for events
            if events:
                unique_agent_ids = list(set(e['agent_id'] for e in events if e['agent_id']))
                agent_data = {}
                if unique_agent_ids:
                    placeholders = ','.join(['%s'] * len(unique_agent_ids))
                    cursor.execute(f"""
                        SELECT id, agent_id, display_name, hostname
                        FROM agents
                        WHERE id IN ({placeholders})
                    """, unique_agent_ids)
                    for row in cursor.fetchall():
                        agent_data[row['id']] = row

                for event in events:
                    agent_id_val = event['agent_id']
                    if agent_id_val and agent_id_val in agent_data:
                        ag = agent_data[agent_id_val]
                        event['agent_name'] = ag['display_name'] or ag['hostname']
                        event['agent_hostname'] = ag['hostname']
                        event['agent_id_string'] = ag['agent_id']
                    else:
                        event['agent_name'] = None
                        event['agent_hostname'] = None
                        event['agent_id_string'] = None

            # Get count
            count_cache_key = cache_key_hash('events_count', filters=filters)
            total = cache.get(count_cache_key) if cache.enabled else None

            if total is None:
                total = _get_count(conn, where_sql, params)
                if cache.enabled:
                    cache.set(count_cache_key, total, CACHE_TTL.get('events_count', 15))

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
                    'failure_reason': event.get('failure_reason'),

                    # ML Results (v3.1: from auth_events_ml) - convert to 0-100 scale
                    'ml_risk_score': round(float(event['ml_risk_score']) * 100, 1) if event['ml_risk_score'] else None,
                    'ml_threat_type': event['ml_threat_type'],
                    'ml_confidence': round(float(event['ml_confidence']) * 100, 1) if event['ml_confidence'] else None,
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

                    # Threat Intel (v3.1: from ip_geolocation)
                    'threat': {
                        'level': event['threat_level'],
                        'abuseipdb_score': event['abuseipdb_score'],
                        'abuseipdb_reports': event['abuseipdb_reports'],
                        'virustotal_detections': f"{event['virustotal_positives'] or 0}/{event['virustotal_total'] or 0}"
                    } if event['threat_level'] or event['abuseipdb_score'] else None,

                    # Agent
                    'agent': {
                        'id': event['agent_id'],
                        'agent_id': event.get('agent_id_string'),
                        'name': event.get('agent_name'),
                        'hostname': event.get('agent_hostname')
                    } if event.get('agent_name') or event['agent_id'] else None
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

            cache_events_list(limit, offset, filters, response_data)

            return jsonify(response_data), 200

        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        print(f"Error fetching events: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'success': False,
            'error': 'Failed to fetch events'
        }), 500


@events_routes.route('/stats', methods=['GET'])
def get_stats():
    """Get event statistics for dashboard - v3.1 schema"""
    try:
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
            # Total events
            cursor.execute("""
                SELECT TABLE_ROWS as total
                FROM information_schema.TABLES
                WHERE TABLE_SCHEMA = DATABASE()
                AND TABLE_NAME = 'auth_events'
            """)
            total_events = cursor.fetchone()['total'] or 0

            # Events by type
            cursor.execute("""
                SELECT event_type, COUNT(*) as count
                FROM auth_events
                GROUP BY event_type
            """)
            events_by_type = {row['event_type']: row['count'] for row in cursor.fetchall()}

            # Threat level distribution (v3.1: from ip_geolocation)
            cursor.execute("""
                SELECT
                    geo.threat_level,
                    COUNT(DISTINCT ae.id) as count
                FROM auth_events ae
                JOIN ip_geolocation geo ON ae.geo_id = geo.id
                WHERE ae.timestamp >= DATE_SUB(NOW(), INTERVAL 7 DAY)
                AND geo.threat_level IS NOT NULL
                GROUP BY geo.threat_level
            """)
            threat_distribution = {row['threat_level']: row['count'] for row in cursor.fetchall()}

            # Recent events (last 24 hours)
            cursor.execute("""
                SELECT COUNT(*) as count
                FROM auth_events
                WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
            """)
            recent_24h = cursor.fetchone()['count']

            # Top attacking IPs (v3.1: threat_level from ip_geolocation)
            cursor.execute("""
                SELECT
                    ae.source_ip_text,
                    COUNT(*) as attempts,
                    geo.threat_level,
                    geo.country_name
                FROM auth_events ae
                LEFT JOIN ip_geolocation geo ON ae.geo_id = geo.id
                WHERE ae.event_type = 'failed'
                AND ae.timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
                GROUP BY ae.source_ip_text, geo.threat_level, geo.country_name
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

            cache_stats(response_data)

            return jsonify(response_data), 200

        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        print(f"Error fetching stats: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to fetch statistics'
        }), 500


@events_routes.route('/cache/clear', methods=['POST'])
def clear_cache():
    """Clear events cache"""
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


@events_routes.route('/timeline', methods=['GET'])
def get_timeline():
    """
    Get events timeline aggregated by time interval
    v3.1: ML data from auth_events_ml
    """
    try:
        interval = request.args.get('interval', 'day')
        days = min(int(request.args.get('days', 7)), 90)
        nocache = request.args.get('nocache', '0') == '1'

        if interval not in ['hour', 'day', 'week']:
            interval = 'day'

        if interval == 'hour' and days > 7:
            days = 7

        cache = get_cache()
        cache_key_str = f"timeline_{interval}_{days}"

        if not nocache and cache.enabled:
            cached_data = cache.get(cache_key_str)
            if cached_data:
                cached_data['from_cache'] = True
                return jsonify(cached_data), 200

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            if interval == 'hour':
                time_format = "DATE_FORMAT(ae.timestamp, '%Y-%m-%d %H:00:00')"
            elif interval == 'week':
                time_format = "YEARWEEK(ae.timestamp, 1)"
            else:
                time_format = "DATE(ae.timestamp)"

            # v3.1: ML data from auth_events_ml via LEFT JOIN
            query = f"""
                SELECT
                    {time_format} as time_period,
                    COUNT(*) as total_events,
                    SUM(CASE WHEN ae.event_type = 'failed' THEN 1 ELSE 0 END) as failed,
                    SUM(CASE WHEN ae.event_type = 'successful' THEN 1 ELSE 0 END) as successful,
                    SUM(CASE WHEN ae.event_type = 'invalid' THEN 1 ELSE 0 END) as invalid,
                    SUM(CASE WHEN ml.is_anomaly = 1 THEN 1 ELSE 0 END) as anomalies,
                    AVG(COALESCE(ml.risk_score, 0)) as avg_risk_score
                FROM auth_events ae
                LEFT JOIN auth_events_ml ml ON ae.id = ml.event_id
                WHERE ae.timestamp >= DATE_SUB(NOW(), INTERVAL %s DAY)
                GROUP BY {time_format}
                ORDER BY time_period DESC
                LIMIT 200
            """

            cursor.execute(query, (days,))
            timeline = cursor.fetchall()

            # Convert Decimal to float for JSON serialization
            for row in timeline:
                if row.get('avg_risk_score'):
                    row['avg_risk_score'] = float(row['avg_risk_score'])

            response_data = {
                'success': True,
                'data': {
                    'timeline': timeline,
                    'interval': interval,
                    'days': days
                },
                'from_cache': False
            }

            if cache.enabled:
                cache.set(cache_key_str, response_data, CACHE_TTL.get('events_timeline', 300))

            return jsonify(response_data), 200

        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        print(f"Error fetching timeline: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'success': False,
            'error': 'Failed to fetch timeline data'
        }), 500


@events_routes.route('/<int:event_id>', methods=['GET'])
def get_event(event_id):
    """Get a single event by ID with full enrichment data - v3.1 schema"""
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # v3.1: ML from auth_events_ml, threat from ip_geolocation
        cursor.execute("""
            SELECT
                ae.id,
                ae.event_uuid,
                ae.source_ip_text,
                ae.target_username,
                ae.event_type,
                ae.auth_method,
                ae.target_server,
                ae.target_port,
                ae.timestamp,
                ae.failure_reason,
                ae.agent_id,
                ml.risk_score as ml_risk_score,
                ml.threat_type as ml_threat_type,
                ml.is_anomaly,
                ml.confidence as ml_confidence,
                geo.country_code,
                geo.country_name,
                geo.city,
                geo.region,
                geo.isp,
                geo.latitude,
                geo.longitude,
                geo.is_proxy,
                geo.is_vpn,
                geo.is_tor,
                geo.threat_level,
                geo.abuseipdb_score,
                geo.abuseipdb_reports,
                geo.virustotal_positives,
                geo.virustotal_total
            FROM auth_events ae
            LEFT JOIN ip_geolocation geo ON ae.geo_id = geo.id
            LEFT JOIN auth_events_ml ml ON ae.id = ml.event_id
            WHERE ae.id = %s
        """, (event_id,))

        event = cursor.fetchone()

        if not event:
            cursor.close()
            conn.close()
            return jsonify({
                'success': False,
                'error': 'Event not found'
            }), 404

        # Fetch agent data
        agent_data = None
        if event['agent_id']:
            cursor.execute("""
                SELECT id, agent_id, display_name, hostname
                FROM agents
                WHERE id = %s
            """, (event['agent_id'],))
            agent_data = cursor.fetchone()

        cursor.close()
        conn.close()

        formatted_event = {
            'id': event['id'],
            'event_uuid': event['event_uuid'],
            'ip': event['source_ip_text'],
            'username': event['target_username'],
            'event_type': event['event_type'],
            'auth_method': event['auth_method'],
            'server': event['target_server'],
            'port': event['target_port'],
            'timestamp': event['timestamp'].isoformat() if event['timestamp'] else None,
            'failure_reason': event.get('failure_reason'),
            'ml_risk_score': round(float(event['ml_risk_score']) * 100, 1) if event['ml_risk_score'] else None,
            'ml_threat_type': event['ml_threat_type'],
            'ml_confidence': round(float(event['ml_confidence']) * 100, 1) if event['ml_confidence'] else None,
            'is_anomaly': bool(event['is_anomaly']) if event['is_anomaly'] is not None else False,
            'agent': {
                'id': agent_data['id'],
                'agent_id': agent_data['agent_id'],
                'name': agent_data['display_name'] or agent_data['hostname'],
                'hostname': agent_data['hostname']
            } if agent_data else None,
            'location': {
                'country_code': event['country_code'],
                'country': event['country_name'],
                'city': event['city'],
                'region': event['region'],
                'isp': event['isp'],
                'latitude': float(event['latitude']) if event['latitude'] else None,
                'longitude': float(event['longitude']) if event['longitude'] else None,
                'is_proxy': bool(event['is_proxy']) if event['is_proxy'] is not None else False,
                'is_vpn': bool(event['is_vpn']) if event['is_vpn'] is not None else False,
                'is_tor': bool(event['is_tor']) if event['is_tor'] is not None else False
            } if event['country_code'] else None,
            'threat': {
                'level': event['threat_level'],
                'abuseipdb_score': event['abuseipdb_score'],
                'abuseipdb_reports': event['abuseipdb_reports'],
                'virustotal_positives': event['virustotal_positives'],
                'virustotal_total': event['virustotal_total']
            } if event['threat_level'] or event['abuseipdb_score'] else None
        }

        return jsonify({
            'success': True,
            'data': formatted_event
        }), 200

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@events_routes.route('/grouped', methods=['GET'])
def list_events_grouped():
    """
    Get auth events grouped by IP address (unique IPs only)
    v3.1: threat_level from ip_geolocation
    """
    try:
        limit = min(int(request.args.get('limit', 50)), 100)
        offset = int(request.args.get('offset', 0))
        event_type = request.args.get('event_type')
        agent_id = request.args.get('agent_id')
        time_range = request.args.get('time_range', '24h')

        time_filters = {
            '1h': 'INTERVAL 1 HOUR',
            '6h': 'INTERVAL 6 HOUR',
            '24h': 'INTERVAL 24 HOUR',
            '7d': 'INTERVAL 7 DAY',
            '30d': 'INTERVAL 30 DAY'
        }
        time_interval = time_filters.get(time_range, 'INTERVAL 24 HOUR')

        where_clauses = [f"ae.timestamp >= DATE_SUB(NOW(), {time_interval})"]
        params = []

        if event_type:
            where_clauses.append("ae.event_type = %s")
            params.append(event_type)

        if agent_id:
            where_clauses.append("ae.agent_id = %s")
            params.append(agent_id)

        where_sql = " AND ".join(where_clauses)

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            # v3.1: Get max risk_score from auth_events_ml
            # Sort by last_activity (processed_at, fallback to created_at) to show most recently processed records first
            cursor.execute(f"""
                SELECT
                    ae.source_ip_text as ip_address,
                    COUNT(*) as event_count,
                    SUM(CASE WHEN ae.event_type = 'failed' THEN 1 ELSE 0 END) as failed_count,
                    SUM(CASE WHEN ae.event_type = 'successful' THEN 1 ELSE 0 END) as success_count,
                    MAX(ae.timestamp) as latest_timestamp,
                    MIN(ae.timestamp) as first_timestamp,
                    MAX(COALESCE(ae.processed_at, ae.created_at)) as last_activity,
                    COUNT(DISTINCT ae.target_username) as unique_users,
                    GROUP_CONCAT(DISTINCT ae.target_username ORDER BY ae.target_username SEPARATOR ', ') as usernames,
                    MAX(ml.risk_score) as max_risk_score,
                    MAX(ae.agent_id) as agent_id
                FROM auth_events ae
                LEFT JOIN auth_events_ml ml ON ae.id = ml.event_id
                WHERE {where_sql}
                GROUP BY ae.source_ip_text
                ORDER BY last_activity DESC
                LIMIT %s OFFSET %s
            """, params + [limit, offset])

            groups = cursor.fetchall()

            # Get total count
            cursor.execute(f"""
                SELECT COUNT(DISTINCT source_ip_text) as total
                FROM auth_events ae
                WHERE {where_sql}
            """, params)
            total_row = cursor.fetchone()
            total_groups = total_row['total'] if total_row else 0

            # Enrich with geo/threat data
            enriched_groups = []
            if groups:
                unique_ips = list(set(g['ip_address'] for g in groups if g['ip_address']))

                # v3.1: Get geo + threat from ip_geolocation
                geo_map = {}
                if unique_ips:
                    placeholders = ','.join(['%s'] * len(unique_ips))
                    cursor.execute(f"""
                        SELECT ip_address_text, country_code, country_name, city, isp,
                               is_proxy, is_vpn, is_tor, threat_level, abuseipdb_score, abuseipdb_reports
                        FROM ip_geolocation
                        WHERE ip_address_text IN ({placeholders})
                    """, unique_ips)
                    for row in cursor.fetchall():
                        geo_map[row['ip_address_text']] = row

                # Get agent info
                agent_ids = list(set(g['agent_id'] for g in groups if g['agent_id']))
                agent_map = {}
                if agent_ids:
                    placeholders = ','.join(['%s'] * len(agent_ids))
                    cursor.execute(f"""
                        SELECT id, agent_id, hostname FROM agents WHERE id IN ({placeholders})
                    """, agent_ids)
                    for row in cursor.fetchall():
                        agent_map[row['id']] = row

                for group in groups:
                    ip = group['ip_address']
                    geo = geo_map.get(ip, {})
                    agent = agent_map.get(group['agent_id'], {})

                    enriched_groups.append({
                        'ip_address': ip,
                        'event_count': group['event_count'],
                        'failed_count': group['failed_count'],
                        'success_count': group['success_count'],
                        'latest_timestamp': group['latest_timestamp'].isoformat() if group['latest_timestamp'] else None,
                        'first_timestamp': group['first_timestamp'].isoformat() if group['first_timestamp'] else None,
                        'last_activity': group['last_activity'].isoformat() if group['last_activity'] else None,
                        'unique_users': group['unique_users'],
                        'usernames': group['usernames'],
                        'max_risk_score': round(float(group['max_risk_score']) * 100, 1) if group['max_risk_score'] else None,
                        'location': {
                            'country_code': geo.get('country_code'),
                            'country_name': geo.get('country_name'),
                            'city': geo.get('city'),
                            'isp': geo.get('isp'),
                            'is_proxy': bool(geo.get('is_proxy')),
                            'is_vpn': bool(geo.get('is_vpn')),
                            'is_tor': bool(geo.get('is_tor'))
                        } if geo else None,
                        'threat': {
                            'level': geo.get('threat_level'),
                            'abuseipdb_score': geo.get('abuseipdb_score'),
                            'abuseipdb_reports': geo.get('abuseipdb_reports')
                        } if geo.get('threat_level') or geo.get('abuseipdb_score') else None,
                        'agent': {
                            'id': agent.get('id'),
                            'agent_id': agent.get('agent_id'),
                            'hostname': agent.get('hostname')
                        } if agent else None
                    })

            return jsonify({
                'success': True,
                'groups': enriched_groups,
                'pagination': {
                    'total': total_groups,
                    'limit': limit,
                    'offset': offset,
                    'has_more': offset + limit < total_groups
                }
            })

        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        print(f"Error in grouped events: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@events_routes.route('/by-ip', methods=['GET'])
def get_events_by_ip():
    """Get paginated events for a specific IP address - v3.1 schema"""
    try:
        ip_address = request.args.get('ip', '').strip()
        if not ip_address:
            return jsonify({'success': False, 'error': 'IP address is required'}), 400

        page = max(1, int(request.args.get('page', 1)))
        page_size = min(int(request.args.get('page_size', 20)), 100)
        event_type = request.args.get('event_type')
        time_range = request.args.get('time_range', '30d')

        time_filters = {
            '1h': 'INTERVAL 1 HOUR',
            '6h': 'INTERVAL 6 HOUR',
            '24h': 'INTERVAL 24 HOUR',
            '7d': 'INTERVAL 7 DAY',
            '30d': 'INTERVAL 30 DAY'
        }
        time_interval = time_filters.get(time_range, 'INTERVAL 30 DAY')

        where_clauses = [
            "ae.source_ip_text = %s",
            f"ae.timestamp >= DATE_SUB(NOW(), {time_interval})"
        ]
        params = [ip_address]

        if event_type:
            where_clauses.append("ae.event_type = %s")
            params.append(event_type)

        where_sql = " AND ".join(where_clauses)
        offset = (page - 1) * page_size

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            cursor.execute(f"""
                SELECT COUNT(*) as total
                FROM auth_events ae
                WHERE {where_sql}
            """, params)
            total = cursor.fetchone()['total']

            # v3.1: Get ML data from auth_events_ml
            # Sort by processed_at (or created_at as fallback) for most recently processed first
            cursor.execute(f"""
                SELECT
                    ae.id,
                    ae.timestamp,
                    ae.processed_at,
                    ae.created_at,
                    COALESCE(ae.processed_at, ae.created_at) as last_activity,
                    ae.source_ip_text as ip,
                    ae.target_username as username,
                    ae.event_type,
                    ae.auth_method,
                    ae.target_server as server,
                    ml.risk_score as ml_risk_score,
                    ae.agent_id,
                    a.hostname as agent_hostname
                FROM auth_events ae
                LEFT JOIN auth_events_ml ml ON ae.id = ml.event_id
                LEFT JOIN agents a ON ae.agent_id = a.id
                WHERE {where_sql}
                ORDER BY COALESCE(ae.processed_at, ae.created_at) DESC
                LIMIT %s OFFSET %s
            """, params + [page_size, offset])

            events = cursor.fetchall()

            for event in events:
                if event['timestamp']:
                    event['timestamp'] = event['timestamp'].isoformat()
                if event['processed_at']:
                    event['processed_at'] = event['processed_at'].isoformat()
                if event['created_at']:
                    event['created_at'] = event['created_at'].isoformat()
                if event['last_activity']:
                    event['last_activity'] = event['last_activity'].isoformat()
                if event['ml_risk_score']:
                    event['ml_risk_score'] = round(float(event['ml_risk_score']) * 100, 1)

            total_pages = (total + page_size - 1) // page_size

            return jsonify({
                'success': True,
                'events': events,
                'pagination': {
                    'total': total,
                    'page': page,
                    'page_size': page_size,
                    'total_pages': total_pages,
                    'has_next': page < total_pages,
                    'has_prev': page > 1
                }
            })

        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        print(f"Error fetching events by IP: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
