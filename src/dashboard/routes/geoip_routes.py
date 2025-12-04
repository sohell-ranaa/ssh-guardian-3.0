"""
SSH Guardian v3.0 - GeoIP Lookup Routes
Handles IP geolocation lookups and statistics
"""

from flask import Blueprint, request, jsonify
import sys
from pathlib import Path

# Add project paths
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
sys.path.append(str(PROJECT_ROOT / "dbs"))
sys.path.append(str(PROJECT_ROOT / "src" / "core"))

from connection import get_connection
from geoip import GeoIPLookup

geoip_routes = Blueprint('geoip_routes', __name__)


@geoip_routes.route('/api/geoip/lookup/<ip_address>', methods=['GET'])
def lookup_ip(ip_address):
    """Lookup GeoIP information for an IP address"""
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT *
            FROM ip_geolocation
            WHERE ip_address_text = %s
        """, (ip_address,))

        result = cursor.fetchone()

        cursor.close()
        conn.close()

        if result:
            # Remove binary ip_address field (we have ip_address_text)
            if 'ip_address' in result:
                del result['ip_address']

            return jsonify({
                'success': True,
                'data': result
            })
        else:
            return jsonify({
                'success': False,
                'message': 'IP address not found in database'
            })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Lookup failed: {str(e)}'
        }), 500


@geoip_routes.route('/api/geoip/stats', methods=['GET'])
def get_stats():
    """Get GeoIP statistics"""
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Total IPs tracked
        cursor.execute("SELECT COUNT(*) as total FROM ip_geolocation")
        total = cursor.fetchone()['total']

        # Top countries
        cursor.execute("""
            SELECT country_code, country_name, COUNT(*) as count
            FROM ip_geolocation
            WHERE country_code IS NOT NULL
            GROUP BY country_code, country_name
            ORDER BY count DESC
            LIMIT 10
        """)
        top_countries = cursor.fetchall()

        # Proxy/VPN statistics
        cursor.execute("""
            SELECT
                SUM(is_proxy) as proxy_count,
                SUM(is_vpn) as vpn_count,
                SUM(is_tor) as tor_count,
                SUM(is_datacenter) as datacenter_count
            FROM ip_geolocation
        """)
        threat_stats = cursor.fetchone()

        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'stats': {
                'total_ips': total,
                'top_countries': top_countries,
                'threat_indicators': threat_stats
            }
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Failed to get stats: {str(e)}'
        }), 500


@geoip_routes.route('/api/geoip/recent', methods=['GET'])
def get_recent():
    """Get recently looked up IPs"""
    try:
        limit = request.args.get('limit', 50, type=int)

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT
                ip_address_text,
                country_code,
                country_name,
                city,
                asn_org,
                is_proxy,
                is_vpn,
                is_tor,
                last_seen
            FROM ip_geolocation
            ORDER BY last_seen DESC
            LIMIT %s
        """, (limit,))

        results = cursor.fetchall()

        # Format timestamps
        for row in results:
            if row['last_seen']:
                row['last_seen'] = row['last_seen'].isoformat()

        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'data': results,
            'total': len(results)
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Failed to get recent IPs: {str(e)}'
        }), 500


@geoip_routes.route('/api/geoip/enrich/<ip_address>', methods=['POST'])
def enrich_ip(ip_address):
    """Manually trigger GeoIP enrichment for an IP address"""
    try:
        # Perform GeoIP lookup
        geo_lookup = GeoIPLookup()
        geo_data = geo_lookup.lookup_ip(ip_address)

        if geo_data:
            # Remove binary ip_address field if present
            if isinstance(geo_data, dict) and 'ip_address' in geo_data:
                geo_data = geo_data.copy()
                del geo_data['ip_address']

            return jsonify({
                'success': True,
                'message': f'Successfully enriched IP {ip_address}'
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Failed to enrich IP address'
            }), 500

    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Enrichment failed: {str(e)}'
        }), 500
