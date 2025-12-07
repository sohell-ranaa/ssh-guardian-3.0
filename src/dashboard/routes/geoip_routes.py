"""
SSH Guardian v3.0 - GeoIP Lookup Routes
Handles IP geolocation lookups and statistics with Redis caching
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
from cache import get_cache, cache_key, get_ttl, should_cache

geoip_routes = Blueprint('geoip_routes', __name__)

# Cache TTLs - NOW LOADED FROM DATABASE via get_ttl()
# Fallback defaults only used if database unavailable
GEOIP_LOOKUP_TTL = 7200
GEOIP_STATS_TTL = 3600
GEOIP_RECENT_TTL = 1800
GEOIP_TOP_COUNTRIES_TTL = 7200


def invalidate_geoip_cache():
    """Invalidate all GeoIP-related caches"""
    cache = get_cache()
    cache.delete_pattern('geoip')


@geoip_routes.route('/api/geoip/lookup/<ip_address>', methods=['GET'])
def lookup_ip(ip_address):
    """Lookup GeoIP information for an IP address with caching"""
    try:
        cache = get_cache()
        cache_k = cache_key('geoip', 'lookup', ip_address)

        # Try cache first (if caching enabled)
        endpoint_key = 'geoip_lookup'
        if should_cache(endpoint_key):
            cached = cache.get(cache_k, endpoint_key)
            if cached is not None:
                return jsonify({
                    'success': True,
                    'data': cached,
                    'from_cache': True
                })

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

            # Convert datetime fields
            if result.get('first_seen'):
                result['first_seen'] = result['first_seen'].isoformat()
            if result.get('last_seen'):
                result['last_seen'] = result['last_seen'].isoformat()

            # Convert Decimal fields
            if result.get('latitude') is not None:
                result['latitude'] = float(result['latitude'])
            if result.get('longitude') is not None:
                result['longitude'] = float(result['longitude'])

            # Cache the result (if caching enabled)
            if should_cache(endpoint_key):
                ttl = get_ttl(endpoint_key=endpoint_key) or GEOIP_LOOKUP_TTL
                cache.set(cache_k, result, ttl)

            return jsonify({
                'success': True,
                'data': result,
                'from_cache': False
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
    """Get GeoIP statistics with caching"""
    try:
        cache = get_cache()
        cache_k = cache_key('geoip', 'stats')
        endpoint_key = 'geoip_stats'

        # Try cache first (with hit tracking)
        if should_cache(endpoint_key):
            cached = cache.get(cache_k, endpoint_key)
            if cached is not None:
                return jsonify({
                    'success': True,
                    'stats': cached,
                    'from_cache': True
                })

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

        # Convert Decimal to int for threat stats
        if threat_stats:
            for key in threat_stats:
                if threat_stats[key] is not None:
                    threat_stats[key] = int(threat_stats[key])

        stats = {
            'total_ips': total,
            'top_countries': top_countries,
            'threat_indicators': threat_stats
        }

        # Cache the result (if caching enabled)
        if should_cache(endpoint_key):
            ttl = get_ttl(endpoint_key=endpoint_key) or GEOIP_STATS_TTL
            cache.set(cache_k, stats, ttl)

        return jsonify({
            'success': True,
            'stats': stats,
            'from_cache': False
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Failed to get stats: {str(e)}'
        }), 500


@geoip_routes.route('/api/geoip/recent', methods=['GET'])
def get_recent():
    """Get recently looked up IPs with caching"""
    try:
        limit = request.args.get('limit', 50, type=int)

        cache = get_cache()
        cache_k = cache_key('geoip', 'recent', str(limit))

        # Try cache first
        cached = cache.get(cache_k)
        if cached is not None:
            return jsonify({
                'success': True,
                'data': cached['data'],
                'total': cached['total'],
                'from_cache': True
            })

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

        cache_data = {'data': results, 'total': len(results)}
        cache.set(cache_k, cache_data, GEOIP_RECENT_TTL)

        return jsonify({
            'success': True,
            'data': results,
            'total': len(results),
            'from_cache': False
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
            # Invalidate related caches
            cache = get_cache()
            cache.delete(cache_key('geoip', 'lookup', ip_address))
            cache.delete_pattern('geoip:stats')
            cache.delete_pattern('geoip:recent')

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
