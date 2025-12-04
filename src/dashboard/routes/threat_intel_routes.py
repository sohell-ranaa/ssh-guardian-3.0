"""
SSH Guardian v3.0 - Threat Intelligence Routes
Handles threat intelligence lookups and statistics
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

threat_intel_routes = Blueprint('threat_intel_routes', __name__)


@threat_intel_routes.route('/api/threat-intel/lookup/<ip_address>', methods=['GET'])
def lookup_threat(ip_address):
    """Lookup threat intelligence for an IP address"""
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT *
            FROM ip_threat_intelligence
            WHERE ip_address_text = %s
        """, (ip_address,))

        result = cursor.fetchone()

        cursor.close()
        conn.close()

        if result:
            # Format timestamps
            for field in ['abuseipdb_last_reported', 'abuseipdb_checked_at', 'shodan_last_update',
                          'shodan_checked_at', 'virustotal_checked_at', 'refresh_after',
                          'created_at', 'updated_at']:
                if result.get(field):
                    result[field] = result[field].isoformat()

            return jsonify({
                'success': True,
                'data': result
            })
        else:
            return jsonify({
                'success': False,
                'message': 'No threat intelligence data found for this IP'
            })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Lookup failed: {str(e)}'
        }), 500


@threat_intel_routes.route('/api/threat-intel/stats', methods=['GET'])
def get_threat_stats():
    """Get threat intelligence statistics"""
    try:
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

        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'stats': {
                'total_ips': total,
                'threat_levels': threat_levels,
                'high_threat_count': high_threat_count,
                'abuseipdb': abuseipdb_stats
            }
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Failed to get stats: {str(e)}'
        }), 500


@threat_intel_routes.route('/api/threat-intel/recent', methods=['GET'])
def get_recent_threats():
    """Get recently checked threat intelligence"""
    try:
        limit = request.args.get('limit', 50, type=int)

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

        # Format timestamps
        for row in results:
            if row['updated_at']:
                row['updated_at'] = row['updated_at'].isoformat()

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
            'error': f'Failed to get recent threats: {str(e)}'
        }), 500


@threat_intel_routes.route('/api/threat-intel/high-risk', methods=['GET'])
def get_high_risk():
    """Get high-risk IPs"""
    try:
        limit = request.args.get('limit', 100, type=int)

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

        # Format timestamps
        for row in results:
            if row['updated_at']:
                row['updated_at'] = row['updated_at'].isoformat()

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
            'error': f'Failed to get high-risk IPs: {str(e)}'
        }), 500


@threat_intel_routes.route('/api/threat-intel/enrich/<ip_address>', methods=['POST'])
def enrich_threat(ip_address):
    """Manually trigger threat intelligence enrichment for an IP address"""
    try:
        # Perform threat intelligence lookup
        threat_intel = ThreatIntelligence()
        threat_data = threat_intel.lookup_ip_threat(ip_address)

        if threat_data:
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
