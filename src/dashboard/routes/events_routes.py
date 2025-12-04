"""
SSH Guardian v3.0 - Events Dashboard Routes
Provides API endpoints for fetching and displaying auth events with enrichment data
"""

from flask import Blueprint, jsonify, request
import sys
from pathlib import Path

# Add project paths
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
sys.path.append(str(PROJECT_ROOT / "dbs"))

from connection import get_connection

# Create Blueprint
events_routes = Blueprint('events_routes', __name__, url_prefix='/api/dashboard/events')


@events_routes.route('/list', methods=['GET'])
def list_events():
    """
    Get list of auth events with enrichment data (GeoIP + Threat Intel)

    Query Parameters:
    - limit: Number of events to return (default: 50, max: 500)
    - offset: Offset for pagination (default: 0)
    - event_type: Filter by event type (failed, successful, invalid)
    - threat_level: Filter by threat level (clean, low, medium, high, critical)
    - search: Search by IP or username
    """

    try:
        # Get query parameters
        limit = min(int(request.args.get('limit', 50)), 500)
        offset = int(request.args.get('offset', 0))
        event_type = request.args.get('event_type')
        threat_level = request.args.get('threat_level')
        search = request.args.get('search', '').strip()

        # Build WHERE clause
        where_clauses = []
        params = []

        if event_type:
            where_clauses.append("ae.event_type = %s")
            params.append(event_type)

        if threat_level:
            where_clauses.append("ti.overall_threat_level = %s")
            params.append(threat_level)

        if search:
            where_clauses.append("(ae.source_ip_text LIKE %s OR ae.target_username LIKE %s)")
            params.extend([f"%{search}%", f"%{search}%"])

        where_sql = " AND " + " AND ".join(where_clauses) if where_clauses else ""

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            # Get events with enrichment data
            query = f"""
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

                    -- GeoIP data
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

                    -- Threat Intelligence data
                    ti.overall_threat_level,
                    ti.threat_confidence,
                    ti.abuseipdb_score,
                    ti.abuseipdb_reports,
                    ti.virustotal_positives,
                    ti.virustotal_total,
                    ti.shodan_ports,
                    ti.shodan_vulns,

                    -- Agent info
                    ag.display_name as agent_name,
                    ag.hostname as agent_hostname

                FROM auth_events ae
                LEFT JOIN ip_geolocation geo ON ae.geo_id = geo.id
                LEFT JOIN ip_threat_intelligence ti ON ae.source_ip_text = ti.ip_address_text
                LEFT JOIN agents ag ON ae.agent_id = ag.id

                WHERE 1=1 {where_sql}

                ORDER BY ae.timestamp DESC
                LIMIT %s OFFSET %s
            """

            params.extend([limit, offset])
            cursor.execute(query, params)
            events = cursor.fetchall()

            # Get total count
            count_query = f"""
                SELECT COUNT(*) as total
                FROM auth_events ae
                LEFT JOIN ip_threat_intelligence ti ON ae.source_ip_text = ti.ip_address_text
                WHERE 1=1 {where_sql}
            """

            cursor.execute(count_query, params[:-2])  # Exclude limit and offset
            total = cursor.fetchone()['total']

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

            return jsonify({
                'success': True,
                'events': formatted_events,
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
        print(f"❌ Error fetching events: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'success': False,
            'error': 'Failed to fetch events'
        }), 500


@events_routes.route('/stats', methods=['GET'])
def get_stats():
    """Get event statistics for dashboard"""

    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            # Total events
            cursor.execute("SELECT COUNT(*) as total FROM auth_events")
            total_events = cursor.fetchone()['total']

            # Events by type
            cursor.execute("""
                SELECT
                    event_type,
                    COUNT(*) as count
                FROM auth_events
                GROUP BY event_type
            """)
            events_by_type = {row['event_type']: row['count'] for row in cursor.fetchall()}

            # Threat level distribution
            cursor.execute("""
                SELECT
                    ti.overall_threat_level as threat_level,
                    COUNT(DISTINCT ae.id) as count
                FROM auth_events ae
                JOIN ip_threat_intelligence ti ON ae.source_ip_text = ti.ip_address_text
                GROUP BY ti.overall_threat_level
            """)
            threat_distribution = {row['threat_level']: row['count'] for row in cursor.fetchall()}

            # Recent events (last 24 hours)
            cursor.execute("""
                SELECT COUNT(*) as count
                FROM auth_events
                WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
            """)
            recent_24h = cursor.fetchone()['count']

            # Top attacking IPs (failed events)
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
                GROUP BY ae.source_ip_text, ti.overall_threat_level, geo.country_name
                ORDER BY attempts DESC
                LIMIT 10
            """)
            top_ips = cursor.fetchall()

            return jsonify({
                'success': True,
                'stats': {
                    'total_events': total_events,
                    'events_by_type': events_by_type,
                    'threat_distribution': threat_distribution,
                    'recent_24h': recent_24h,
                    'top_attacking_ips': top_ips
                }
            }), 200

        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        print(f"❌ Error fetching stats: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to fetch statistics'
        }), 500
