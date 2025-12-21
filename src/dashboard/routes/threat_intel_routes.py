"""
SSH Guardian v3.1 - Threat Intelligence Routes
Handles threat intelligence lookups and statistics with Redis caching
Updated for v3.1 schema (threat intel merged into ip_geolocation table)
"""

from flask import Blueprint, request, jsonify
import sys
from pathlib import Path

# Add project paths
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
sys.path.append(str(PROJECT_ROOT / "dbs"))
sys.path.append(str(PROJECT_ROOT / "src" / "core"))

from connection import get_connection
from threat_intel import ThreatIntelligence
from cache import get_cache, cache_key, get_ttl, should_cache

threat_intel_routes = Blueprint('threat_intel_routes', __name__)

# Cache TTLs
THREAT_LOOKUP_TTL = 7200
THREAT_STATS_TTL = 3600
THREAT_RECENT_TTL = 1800
THREAT_HIGH_RISK_TTL = 1800


def invalidate_threat_cache():
    """Invalidate all threat intelligence caches"""
    cache = get_cache()
    cache.delete_pattern('threat')


@threat_intel_routes.route('/api/threat-intel/lookup/<ip_address>', methods=['GET'])
def lookup_threat(ip_address):
    """Lookup threat intelligence for an IP address with caching"""
    conn = None
    cursor = None
    try:
        cache = get_cache()
        cache_k = cache_key('threat', 'lookup', ip_address)

        endpoint_key = 'threat_intel_lookup'
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

        # v3.1: Threat intel is now in ip_geolocation table
        cursor.execute("""
            SELECT
                ip_address_text,
                country_code,
                country_name,
                city,
                region,
                isp,
                asn,
                asn_org,
                latitude,
                longitude,
                is_proxy,
                is_vpn,
                is_tor,
                is_datacenter,
                is_hosting,
                abuseipdb_score,
                abuseipdb_reports,
                abuseipdb_last_reported,
                abuseipdb_checked_at,
                virustotal_positives,
                virustotal_total,
                virustotal_checked_at,
                shodan_ports,
                shodan_vulns,
                shodan_checked_at,
                greynoise_noise,
                greynoise_riot,
                greynoise_classification,
                greynoise_checked_at,
                threat_level,
                last_seen
            FROM ip_geolocation
            WHERE ip_address_text = %s
        """, (ip_address,))

        result = cursor.fetchone()

        if result:
            # Format timestamps
            for field in ['abuseipdb_last_reported', 'abuseipdb_checked_at',
                          'virustotal_checked_at', 'shodan_checked_at',
                          'greynoise_checked_at', 'last_seen']:
                if result.get(field):
                    result[field] = result[field].isoformat()

            # Convert Decimal fields
            # v3.1: threat_confidence replaced by threat_level (string)
            result['threat_confidence'] = result.get('threat_level')
            if result.get('latitude') is not None:
                result['latitude'] = float(result['latitude'])
            if result.get('longitude') is not None:
                result['longitude'] = float(result['longitude'])

            # Map to old API format for compatibility
            result['overall_threat_level'] = result.get('threat_level')

            if should_cache(endpoint_key):
                ttl = get_ttl(endpoint_key=endpoint_key) or THREAT_LOOKUP_TTL
                cache.set(cache_k, result, ttl)

            return jsonify({
                'success': True,
                'data': result,
                'from_cache': False
            })
        else:
            # Not in database - fetch from API and save
            threat_intel = ThreatIntelligence()
            threat_data = threat_intel.lookup_ip_threat(ip_address)

            if threat_data:
                # Fetch the saved record from DB
                conn2 = get_connection()
                cursor2 = conn2.cursor(dictionary=True)
                cursor2.execute("""
                    SELECT
                        ip_address_text,
                        country_code,
                        country_name,
                        city,
                        region,
                        isp,
                        asn,
                        asn_org,
                        is_proxy,
                        is_vpn,
                        is_tor,
                        is_datacenter,
                        abuseipdb_score,
                        abuseipdb_reports,
                        abuseipdb_last_reported,
                        virustotal_positives,
                        virustotal_total,
                        greynoise_noise,
                        greynoise_riot,
                        greynoise_classification,
                        greynoise_checked_at,
                        threat_level,
                        last_seen
                    FROM ip_geolocation
                    WHERE ip_address_text = %s
                """, (ip_address,))
                result = cursor2.fetchone()
                cursor2.close()
                conn2.close()

                if result:
                    for field in ['abuseipdb_last_reported', 'greynoise_checked_at', 'last_seen']:
                        if result.get(field):
                            result[field] = result[field].isoformat()
                    # v3.1: threat_confidence replaced by threat_level
                    result['threat_confidence'] = result.get('threat_level')
                    result['overall_threat_level'] = result.get('threat_level')

                    return jsonify({
                        'success': True,
                        'data': result,
                        'from_cache': False,
                        'freshly_fetched': True
                    })

            return jsonify({
                'success': False,
                'message': 'No threat intelligence data found and lookup failed'
            })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Lookup failed: {str(e)}'
        }), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@threat_intel_routes.route('/api/threat-intel/evaluate/<ip_address>', methods=['GET'])
def evaluate_ip_threat(ip_address):
    """
    Perform comprehensive threat evaluation combining:
    - ML model predictions (trained PKL model)
    - Threat intelligence (AbuseIPDB, VirusTotal, Shodan)
    - Network analysis (VPN, Proxy, TOR, Datacenter)
    - Geolocation risk
    - Behavioral patterns
    """
    try:
        # Import the unified evaluator
        from src.core.threat_evaluator import evaluate_ip_threat as do_evaluate

        # Get optional event context from query params
        event_data = {}
        if request.args.get('username'):
            event_data['username'] = request.args.get('username')
        if request.args.get('status'):
            event_data['status'] = request.args.get('status')

        # Perform evaluation
        result = do_evaluate(ip_address, event_data if event_data else None)

        return jsonify({
            'success': True,
            'evaluation': result
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Evaluation failed: {str(e)}'
        }), 500


@threat_intel_routes.route('/api/threat-intel/evaluate', methods=['POST'])
def evaluate_ip_threat_post():
    """
    POST version for comprehensive threat evaluation.
    Accepts event context in request body.
    """
    try:
        from src.core.threat_evaluator import evaluate_ip_threat as do_evaluate

        data = request.get_json() or {}
        ip_address = data.get('ip_address') or data.get('ip')

        if not ip_address:
            return jsonify({'success': False, 'error': 'ip_address is required'}), 400

        # Event context
        event_data = {
            'username': data.get('username'),
            'status': data.get('status'),
            'timestamp': data.get('timestamp')
        }
        event_data = {k: v for k, v in event_data.items() if v}

        result = do_evaluate(ip_address, event_data if event_data else None)

        return jsonify({
            'success': True,
            'evaluation': result
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Evaluation failed: {str(e)}'
        }), 500


@threat_intel_routes.route('/api/threat-intel/stats', methods=['GET'])
def get_threat_stats():
    """Get threat intelligence statistics with caching"""
    conn = None
    cursor = None
    try:
        cache = get_cache()
        cache_k = cache_key('threat', 'stats')
        endpoint_key = 'threat_intel_stats'

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

        # v3.1: Use ip_geolocation table
        # Total IPs tracked
        cursor.execute("SELECT COUNT(*) as total FROM ip_geolocation")
        total = cursor.fetchone()['total']

        # Threat level distribution
        cursor.execute("""
            SELECT threat_level as overall_threat_level, COUNT(*) as count
            FROM ip_geolocation
            WHERE threat_level IS NOT NULL
            GROUP BY threat_level
        """)
        threat_levels = cursor.fetchall()

        # High threat IPs
        cursor.execute("""
            SELECT COUNT(*) as count
            FROM ip_geolocation
            WHERE threat_level IN ('high', 'critical')
        """)
        high_threat_count = cursor.fetchone()['count']

        # AbuseIPDB statistics
        cursor.execute("""
            SELECT
                COUNT(*) as total_checked,
                AVG(abuseipdb_score) as avg_score,
                MAX(abuseipdb_score) as max_score,
                SUM(abuseipdb_reports) as total_reports
            FROM ip_geolocation
            WHERE abuseipdb_checked_at IS NOT NULL
        """)
        abuseipdb_stats = cursor.fetchone()

        # Convert Decimal fields
        if abuseipdb_stats:
            for key in abuseipdb_stats:
                if abuseipdb_stats[key] is not None:
                    abuseipdb_stats[key] = float(abuseipdb_stats[key])

        # Proxy/VPN/Tor statistics
        cursor.execute("""
            SELECT
                SUM(is_proxy = 1) as proxy_count,
                SUM(is_vpn = 1) as vpn_count,
                SUM(is_tor = 1) as tor_count,
                SUM(is_datacenter = 1) as datacenter_count
            FROM ip_geolocation
        """)
        classification_stats = cursor.fetchone()

        stats = {
            'total_ips': total,
            'threat_levels': threat_levels,
            'high_threat_count': high_threat_count,
            'abuseipdb': abuseipdb_stats,
            'classifications': {
                'proxy_count': int(classification_stats['proxy_count'] or 0),
                'vpn_count': int(classification_stats['vpn_count'] or 0),
                'tor_count': int(classification_stats['tor_count'] or 0),
                'datacenter_count': int(classification_stats['datacenter_count'] or 0)
            }
        }

        if should_cache(endpoint_key):
            ttl = get_ttl(endpoint_key=endpoint_key) or THREAT_STATS_TTL
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
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@threat_intel_routes.route('/api/threat-intel/recent', methods=['GET'])
def get_recent_threats():
    """Get recently checked threat intelligence with caching"""
    conn = None
    cursor = None
    try:
        limit = request.args.get('limit', 50, type=int)

        cache = get_cache()
        cache_k = cache_key('threat', 'recent', str(limit))

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

        # v3.1: Use ip_geolocation table with threat_level
        cursor.execute("""
            SELECT
                ip_address_text,
                threat_level as overall_threat_level,
                abuseipdb_score,
                abuseipdb_reports,
                virustotal_positives,
                virustotal_total,
                threat_level,
                is_proxy,
                is_vpn,
                is_tor,
                country_code,
                country_name,
                last_seen
            FROM ip_geolocation
            WHERE abuseipdb_score IS NOT NULL OR virustotal_positives IS NOT NULL
            ORDER BY last_seen DESC
            LIMIT %s
        """, (limit,))

        results = cursor.fetchall()

        for row in results:
            if row.get('last_seen'):
                row['updated_at'] = row['last_seen'].isoformat()
            # v3.1: threat_confidence replaced by threat_level
            row['threat_confidence'] = row.get('threat_level')

        cache_data = {'data': results, 'total': len(results)}
        cache.set(cache_k, cache_data, THREAT_RECENT_TTL)

        return jsonify({
            'success': True,
            'data': results,
            'total': len(results),
            'from_cache': False
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Failed to get recent threats: {str(e)}'
        }), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@threat_intel_routes.route('/api/threat-intel/high-risk', methods=['GET'])
def get_high_risk():
    """Get high-risk IPs with caching"""
    conn = None
    cursor = None
    try:
        limit = request.args.get('limit', 100, type=int)

        cache = get_cache()
        cache_k = cache_key('threat', 'high-risk', str(limit))

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

        # v3.1: Use ip_geolocation table
        cursor.execute("""
            SELECT
                ip_address_text,
                threat_level as overall_threat_level,
                abuseipdb_score,
                abuseipdb_reports,
                virustotal_positives,
                threat_level,
                is_tor,
                is_proxy,
                is_vpn,
                country_code,
                country_name,
                last_seen
            FROM ip_geolocation
            WHERE threat_level IN ('high', 'critical')
               OR abuseipdb_score >= 70
            ORDER BY abuseipdb_score DESC, last_seen DESC
            LIMIT %s
        """, (limit,))

        results = cursor.fetchall()

        for row in results:
            if row.get('last_seen'):
                row['updated_at'] = row['last_seen'].isoformat()
            # v3.1: threat_confidence replaced by threat_level
            row['threat_confidence'] = row.get('threat_level')

        cache_data = {'data': results, 'total': len(results)}
        cache.set(cache_k, cache_data, THREAT_HIGH_RISK_TTL)

        return jsonify({
            'success': True,
            'data': results,
            'total': len(results),
            'from_cache': False
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Failed to get high-risk IPs: {str(e)}'
        }), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


def is_private_ip(ip_address):
    """Check if an IP address is private/internal"""
    try:
        parts = ip_address.split('.')
        if len(parts) != 4:
            return False
        first, second = int(parts[0]), int(parts[1])
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


@threat_intel_routes.route('/api/threat-intel/enrich/<ip_address>', methods=['POST'])
def enrich_threat(ip_address):
    """Manually trigger threat intelligence enrichment for an IP address"""
    try:
        # Check for private IP
        if is_private_ip(ip_address):
            return jsonify({
                'success': False,
                'error': 'Private IP addresses cannot be checked against threat intelligence APIs'
            }), 400

        threat_intel = ThreatIntelligence()
        threat_data = threat_intel.lookup_ip_threat(ip_address)

        if threat_data:
            cache = get_cache()
            cache.delete(cache_key('threat', 'lookup', ip_address))
            cache.delete_pattern('threat:stats')
            cache.delete_pattern('threat:recent')
            cache.delete_pattern('threat:high-risk')

            return jsonify({
                'success': True,
                'message': f'Successfully enriched threat data for IP {ip_address}'
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Threat intelligence lookup failed. API keys may not be configured or rate limits may have been reached.'
            }), 500

    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Enrichment failed: {str(e)}'
        }), 500


@threat_intel_routes.route('/api/threat-intel/by-country', methods=['GET'])
def get_threats_by_country():
    """Get threat statistics grouped by country"""
    conn = None
    cursor = None
    try:
        cache = get_cache()
        cache_k = cache_key('threat', 'by_country')

        cached = cache.get(cache_k)
        if cached is not None:
            return jsonify({
                'success': True,
                'data': cached,
                'from_cache': True
            })

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT
                country_code,
                country_name,
                COUNT(*) as ip_count,
                AVG(abuseipdb_score) as avg_score,
                SUM(threat_level IN ('high', 'critical')) as high_threat_count
            FROM ip_geolocation
            WHERE country_code IS NOT NULL
            GROUP BY country_code, country_name
            ORDER BY ip_count DESC
            LIMIT 50
        """)

        results = cursor.fetchall()

        for row in results:
            if row.get('avg_score') is not None:
                row['avg_score'] = float(row['avg_score'])
            row['high_threat_count'] = int(row['high_threat_count'] or 0)

        cache.set(cache_k, results, THREAT_STATS_TTL)

        return jsonify({
            'success': True,
            'data': results,
            'from_cache': False
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Failed to get country stats: {str(e)}'
        }), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()
