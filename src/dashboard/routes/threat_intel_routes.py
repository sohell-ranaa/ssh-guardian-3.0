"""
SSH Guardian v3.0 - Threat Intelligence Routes
Handles threat intelligence lookups and statistics with Redis caching
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

# Cache TTLs - NOW LOADED FROM DATABASE via get_ttl()
# Fallback defaults only used if database unavailable
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

        # Try cache first (if caching enabled for this endpoint)
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

        cursor.execute("""
            SELECT *
            FROM ip_threat_intelligence
            WHERE ip_address_text = %s
        """, (ip_address,))

        result = cursor.fetchone()

        if result:
            # Remove binary ip_address field
            if 'ip_address' in result:
                del result['ip_address']

            # Format timestamps
            for field in ['abuseipdb_last_reported', 'abuseipdb_checked_at', 'shodan_last_update',
                          'shodan_checked_at', 'virustotal_checked_at', 'refresh_after',
                          'created_at', 'updated_at']:
                if result.get(field):
                    result[field] = result[field].isoformat()

            # Convert Decimal fields
            if result.get('threat_confidence') is not None:
                result['threat_confidence'] = float(result['threat_confidence'])

            # Cache the result (if caching enabled)
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
                    SELECT * FROM ip_threat_intelligence WHERE ip_address_text = %s
                """, (ip_address,))
                result = cursor2.fetchone()
                cursor2.close()
                conn2.close()

                if result:
                    if 'ip_address' in result:
                        del result['ip_address']
                    for field in ['abuseipdb_last_reported', 'abuseipdb_checked_at', 'shodan_last_update',
                                  'shodan_checked_at', 'virustotal_checked_at', 'refresh_after',
                                  'created_at', 'updated_at']:
                        if result.get(field):
                            result[field] = result[field].isoformat()
                    if result.get('threat_confidence') is not None:
                        result['threat_confidence'] = float(result['threat_confidence'])

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


@threat_intel_routes.route('/api/threat-intel/stats', methods=['GET'])
def get_threat_stats():
    """Get threat intelligence statistics with caching"""
    conn = None
    cursor = None
    try:
        cache = get_cache()
        cache_k = cache_key('threat', 'stats')
        endpoint_key = 'threat_intel_stats'

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
        cursor.execute("SELECT COUNT(*) as total FROM ip_threat_intelligence")
        total = cursor.fetchone()['total']

        # Threat level distribution
        cursor.execute("""
            SELECT overall_threat_level, COUNT(*) as count
            FROM ip_threat_intelligence
            GROUP BY overall_threat_level
        """)
        threat_levels = cursor.fetchall()

        # High threat IPs
        cursor.execute("""
            SELECT COUNT(*) as count
            FROM ip_threat_intelligence
            WHERE overall_threat_level IN ('high', 'critical')
        """)
        high_threat_count = cursor.fetchone()['count']

        # AbuseIPDB statistics
        cursor.execute("""
            SELECT
                COUNT(*) as total_checked,
                AVG(abuseipdb_score) as avg_score,
                MAX(abuseipdb_score) as max_score,
                SUM(abuseipdb_reports) as total_reports
            FROM ip_threat_intelligence
            WHERE abuseipdb_checked_at IS NOT NULL
        """)
        abuseipdb_stats = cursor.fetchone()

        # Convert Decimal fields
        if abuseipdb_stats:
            for key in abuseipdb_stats:
                if abuseipdb_stats[key] is not None:
                    abuseipdb_stats[key] = float(abuseipdb_stats[key])

        stats = {
            'total_ips': total,
            'threat_levels': threat_levels,
            'high_threat_count': high_threat_count,
            'abuseipdb': abuseipdb_stats
        }

        # Cache the result (if caching enabled)
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
                overall_threat_level,
                abuseipdb_score,
                abuseipdb_reports,
                virustotal_positives,
                virustotal_total,
                threat_confidence,
                updated_at
            FROM ip_threat_intelligence
            ORDER BY updated_at DESC
            LIMIT %s
        """, (limit,))

        results = cursor.fetchall()

        # Format timestamps and convert Decimal
        for row in results:
            if row['updated_at']:
                row['updated_at'] = row['updated_at'].isoformat()
            if row.get('threat_confidence') is not None:
                row['threat_confidence'] = float(row['threat_confidence'])

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
                overall_threat_level,
                abuseipdb_score,
                abuseipdb_reports,
                threat_confidence,
                updated_at
            FROM ip_threat_intelligence
            WHERE overall_threat_level IN ('high', 'critical')
            ORDER BY abuseipdb_score DESC, updated_at DESC
            LIMIT %s
        """, (limit,))

        results = cursor.fetchall()

        # Format timestamps and convert Decimal
        for row in results:
            if row['updated_at']:
                row['updated_at'] = row['updated_at'].isoformat()
            if row.get('threat_confidence') is not None:
                row['threat_confidence'] = float(row['threat_confidence'])

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


@threat_intel_routes.route('/api/threat-intel/enrich/<ip_address>', methods=['POST'])
def enrich_threat(ip_address):
    """Manually trigger threat intelligence enrichment for an IP address"""
    try:
        # Perform threat intelligence lookup
        threat_intel = ThreatIntelligence()
        threat_data = threat_intel.lookup_ip_threat(ip_address)

        if threat_data:
            # Invalidate related caches
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
                'error': 'Failed to enrich threat data'
            }), 500

    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Enrichment failed: {str(e)}'
        }), 500
