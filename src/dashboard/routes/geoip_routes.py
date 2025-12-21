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
            # Not in database - fetch from API and save
            geo_lookup = GeoIPLookup()
            geo_data = geo_lookup.lookup_ip(ip_address)

            if geo_data:
                # Fetch the saved record from DB
                conn2 = get_connection()
                cursor2 = conn2.cursor(dictionary=True)
                cursor2.execute("""
                    SELECT * FROM ip_geolocation WHERE ip_address_text = %s
                """, (ip_address,))
                result = cursor2.fetchone()
                cursor2.close()
                conn2.close()

                if result:
                    if 'ip_address' in result:
                        del result['ip_address']
                    if result.get('first_seen'):
                        result['first_seen'] = result['first_seen'].isoformat()
                    if result.get('last_seen'):
                        result['last_seen'] = result['last_seen'].isoformat()
                    if result.get('latitude') is not None:
                        result['latitude'] = float(result['latitude'])
                    if result.get('longitude') is not None:
                        result['longitude'] = float(result['longitude'])

                    return jsonify({
                        'success': True,
                        'data': result,
                        'from_cache': False,
                        'freshly_fetched': True
                    })

            return jsonify({
                'success': False,
                'message': 'IP address not found and lookup failed'
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
    """Get IP geolocation records with pagination, search and filters"""
    try:
        # Pagination params
        page = request.args.get('page', 1, type=int)
        limit = request.args.get('limit', 20, type=int)
        offset = (page - 1) * limit

        # Filter params
        search = request.args.get('search', '').strip()
        filter_type = request.args.get('type', '').strip()

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Build WHERE clause
        where_parts = []
        params = []

        if search:
            where_parts.append("ip_address_text LIKE %s")
            params.append(f"%{search}%")

        if filter_type == 'proxy':
            where_parts.append("is_proxy = 1")
        elif filter_type == 'vpn':
            where_parts.append("is_vpn = 1")
        elif filter_type == 'tor':
            where_parts.append("is_tor = 1")

        where_clause = ""
        if where_parts:
            where_clause = "WHERE " + " AND ".join(where_parts)

        # Get total count
        cursor.execute(f"SELECT COUNT(*) as total FROM ip_geolocation {where_clause}", params)
        total = cursor.fetchone()['total']

        # Get data
        cursor.execute(f"""
            SELECT
                ip_address_text,
                country_code,
                country_name,
                city,
                isp,
                asn_org,
                is_proxy,
                is_vpn,
                is_tor,
                last_seen
            FROM ip_geolocation
            {where_clause}
            ORDER BY last_seen DESC
            LIMIT %s OFFSET %s
        """, params + [limit, offset])

        results = cursor.fetchall()

        # Format timestamps
        for row in results:
            if row['last_seen']:
                row['last_seen'] = row['last_seen'].isoformat()

        cursor.close()
        conn.close()

        total_pages = (total + limit - 1) // limit

        return jsonify({
            'success': True,
            'data': results,
            'pagination': {
                'page': page,
                'limit': limit,
                'total': total,
                'total_pages': total_pages,
                'has_prev': page > 1,
                'has_next': page < total_pages
            }
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Failed to get IPs: {str(e)}'
        }), 500


def is_private_ip(ip_address):
    """Check if an IP address is private/internal"""
    try:
        parts = ip_address.split('.')
        if len(parts) != 4:
            return False
        first, second = int(parts[0]), int(parts[1])
        # 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, 169.254.0.0/16
        if first == 10:
            return True
        if first == 172 and 16 <= second <= 31:
            return True
        if first == 192 and second == 168:
            return True
        if first == 127:
            return True
        if first == 169 and second == 254:
            return True
        return False
    except:
        return False


@geoip_routes.route('/api/geoip/enrich/<ip_address>', methods=['POST'])
def enrich_ip(ip_address):
    """Manually trigger GeoIP enrichment for an IP address"""
    try:
        # Check for private IP
        if is_private_ip(ip_address):
            return jsonify({
                'success': False,
                'error': 'Private IP addresses cannot be enriched from external APIs'
            }), 400

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
                'error': 'GeoIP lookup failed. The IP may be invalid or the API may be temporarily unavailable.'
            }), 500

    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Enrichment failed: {str(e)}'
        }), 500
