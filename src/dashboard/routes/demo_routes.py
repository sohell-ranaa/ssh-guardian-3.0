"""
SSH Guardian v3.0 - Demo API Routes
API endpoints for demonstration scenarios
"""

from flask import Blueprint, jsonify, request
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
sys.path.append(str(PROJECT_ROOT))
sys.path.append(str(PROJECT_ROOT / "dbs"))
sys.path.append(str(PROJECT_ROOT / "src"))

from src.core.auth import login_required
from src.simulation.demo_scenarios import (
    get_demo_scenarios,
    get_demo_scenario,
    run_demo_scenario,
    run_full_demo
)
from dbs.connection import get_connection

demo_routes = Blueprint('demo_routes', __name__)


def get_ip_history(ip_address: str) -> dict:
    """Get historical data for an IP from the database"""
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Get event count and types
        cursor.execute("""
            SELECT
                COUNT(*) as total_events,
                SUM(CASE WHEN event_type = 'failed' THEN 1 ELSE 0 END) as failed_attempts,
                SUM(CASE WHEN event_type = 'successful' THEN 1 ELSE 0 END) as successful_logins,
                COUNT(DISTINCT target_username) as unique_usernames,
                COUNT(DISTINCT target_server) as unique_servers,
                MIN(timestamp) as first_seen,
                MAX(timestamp) as last_seen,
                AVG(ml_risk_score) as avg_risk_score,
                SUM(CASE WHEN is_anomaly = 1 THEN 1 ELSE 0 END) as anomaly_count
            FROM auth_events
            WHERE source_ip_text = %s
        """, (ip_address,))
        stats = cursor.fetchone()

        # Get top targeted usernames
        cursor.execute("""
            SELECT target_username, COUNT(*) as attempts
            FROM auth_events
            WHERE source_ip_text = %s
            GROUP BY target_username
            ORDER BY attempts DESC
            LIMIT 5
        """, (ip_address,))
        top_usernames = cursor.fetchall()

        # Get similar threat IPs (same country/ISP)
        cursor.execute("""
            SELECT COUNT(DISTINCT ti.ip_address_text) as similar_threats
            FROM ip_threat_intelligence ti
            JOIN ip_geolocation g1 ON ti.ip_address_text = g1.ip_address_text
            JOIN ip_geolocation g2 ON g1.country_code = g2.country_code
            WHERE g2.ip_address_text = %s
            AND ti.overall_threat_level IN ('high', 'critical')
            AND ti.ip_address_text != %s
        """, (ip_address, ip_address))
        similar = cursor.fetchone()

        cursor.close()
        conn.close()

        return {
            'total_events': stats['total_events'] or 0,
            'failed_attempts': stats['failed_attempts'] or 0,
            'successful_logins': stats['successful_logins'] or 0,
            'unique_usernames': stats['unique_usernames'] or 0,
            'unique_servers': stats['unique_servers'] or 0,
            'first_seen': stats['first_seen'].isoformat() if stats['first_seen'] else None,
            'last_seen': stats['last_seen'].isoformat() if stats['last_seen'] else None,
            'avg_risk_score': round(float(stats['avg_risk_score']), 1) if stats['avg_risk_score'] else 0,
            'anomaly_count': stats['anomaly_count'] or 0,
            'top_usernames': top_usernames,
            'similar_threat_ips': similar['similar_threats'] if similar else 0
        }
    except Exception as e:
        print(f"[Demo] Error getting IP history: {e}")
        return {}


def generate_recommendations(ml: dict, threat: dict, geo: dict, history: dict) -> list:
    """Generate security recommendations based on analysis"""
    recommendations = []

    risk_score = ml.get('risk_score', 0) if ml else 0
    threat_level = threat.get('overall_threat_level', 'unknown') if threat else 'unknown'
    abuseipdb_score = threat.get('abuseipdb_score', 0) if threat else 0
    vt_positives = threat.get('virustotal_positives', 0) if threat else 0
    is_anomaly = ml.get('is_anomaly', False) if ml else False
    is_tor = geo.get('is_tor', False) if geo else False
    is_proxy = geo.get('is_proxy', False) if geo else False
    total_events = history.get('total_events', 0)
    failed_attempts = history.get('failed_attempts', 0)

    # Critical threat - immediate action
    if threat_level in ['high', 'critical'] or abuseipdb_score >= 80:
        recommendations.append({
            'priority': 'critical',
            'action': 'BLOCK IMMEDIATELY',
            'reason': f'Known malicious IP with AbuseIPDB score {abuseipdb_score}/100',
            'icon': '🚫'
        })

    # VirusTotal detections
    if vt_positives and vt_positives > 5:
        recommendations.append({
            'priority': 'high',
            'action': 'Add to permanent blocklist',
            'reason': f'Flagged by {vt_positives} security vendors on VirusTotal',
            'icon': '🔬'
        })

    # ML anomaly detection
    if is_anomaly:
        recommendations.append({
            'priority': 'high',
            'action': 'Investigate unusual behavior pattern',
            'reason': f'ML detected anomalous activity (confidence: {ml.get("confidence", 0)*100:.0f}%)',
            'icon': '🤖'
        })

    # High risk score
    if risk_score >= 70:
        recommendations.append({
            'priority': 'high',
            'action': 'Enable enhanced monitoring',
            'reason': f'High ML risk score: {risk_score}/100',
            'icon': '📊'
        })

    # Anonymization network
    if is_tor or is_proxy:
        network_type = 'Tor exit node' if is_tor else 'Proxy/VPN'
        recommendations.append({
            'priority': 'medium',
            'action': f'Review {network_type} access policy',
            'reason': 'Traffic from anonymization network detected',
            'icon': '🧅' if is_tor else '🔒'
        })

    # Brute force pattern
    if failed_attempts >= 10:
        recommendations.append({
            'priority': 'high',
            'action': 'Implement rate limiting',
            'reason': f'{failed_attempts} failed login attempts from this IP',
            'icon': '⚡'
        })

    # Multiple usernames targeted
    if history.get('unique_usernames', 0) >= 5:
        recommendations.append({
            'priority': 'medium',
            'action': 'Review targeted accounts',
            'reason': f'{history["unique_usernames"]} different usernames attempted',
            'icon': '👥'
        })

    # If no critical issues, provide positive feedback
    if not recommendations:
        if risk_score < 30:
            recommendations.append({
                'priority': 'low',
                'action': 'Continue monitoring',
                'reason': 'Low risk profile - appears to be normal activity',
                'icon': '✅'
            })
        else:
            recommendations.append({
                'priority': 'medium',
                'action': 'Monitor for pattern changes',
                'reason': 'Moderate risk - no immediate threat indicators',
                'icon': '👀'
            })

    return recommendations


@demo_routes.route('/scenarios', methods=['GET'])
@login_required
def list_scenarios():
    """Get all available demo scenarios"""
    try:
        scenarios = get_demo_scenarios()
        return jsonify({
            'success': True,
            'scenarios': scenarios,
            'count': len(scenarios)
        })
    except Exception as e:
        print(f"[Demo] Error listing scenarios: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@demo_routes.route('/scenario/<scenario_id>', methods=['GET'])
@login_required
def get_scenario_detail(scenario_id):
    """Get details for a specific demo scenario"""
    try:
        scenario = get_demo_scenario(scenario_id)
        if not scenario:
            return jsonify({'success': False, 'error': 'Scenario not found'}), 404

        return jsonify({
            'success': True,
            'scenario': {
                'id': scenario['id'],
                'name': scenario['name'],
                'description': scenario['description'],
                'severity': scenario['severity'],
                'category': scenario['category'],
                'ip': scenario['ip'],
                'expected_results': scenario['expected_results']
            }
        })
    except Exception as e:
        print(f"[Demo] Error getting scenario {scenario_id}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@demo_routes.route('/run/<scenario_id>', methods=['POST'])
@login_required
def execute_scenario(scenario_id):
    """Execute a single demo scenario"""
    try:
        result = run_demo_scenario(scenario_id, verbose=False)

        if result.get('success'):
            # Format response for UI
            actual = result.get('actual_results', {})
            ml = actual.get('ml', {})
            threat = actual.get('threat_intel', {}) or {}
            geo = actual.get('geoip', {}) or {}

            # Get historical analysis for the IP
            ip_address = result.get('ip')
            history = get_ip_history(ip_address)
            recommendations = generate_recommendations(ml, threat, geo, history)

            # Format geo data with proper field names for frontend
            geo_formatted = {}
            if geo:
                geo_formatted = {
                    'country': geo.get('country') or geo.get('country_name') or 'Unknown',
                    'country_code': geo.get('country_code'),
                    'city': geo.get('city') or 'Unknown',
                    'isp': geo.get('isp') or 'Unknown',
                    'is_tor': geo.get('is_tor', False),
                    'is_vpn': geo.get('is_vpn', False),
                    'is_proxy': geo.get('is_proxy', False),
                    'is_datacenter': geo.get('is_datacenter', False),
                    'latitude': float(geo.get('latitude')) if geo.get('latitude') else None,
                    'longitude': float(geo.get('longitude')) if geo.get('longitude') else None
                }

            response = {
                'success': True,
                'scenario_id': result.get('scenario_id'),
                'scenario_name': result.get('scenario_name'),
                'ip': ip_address,
                'event_id': result.get('event_id'),
                'event_type': result.get('event_type'),
                'expected': result.get('expected'),
                'results': {
                    'threat_intel': {
                        'abuseipdb_score': threat.get('abuseipdb_score'),
                        'abuseipdb_reports': threat.get('abuseipdb_reports', 0),
                        'abuseipdb_confidence': threat.get('abuseipdb_confidence'),
                        'virustotal_positives': threat.get('virustotal_positives'),
                        'virustotal_total': threat.get('virustotal_total'),
                        'threat_level': threat.get('overall_threat_level', 'unknown')
                    },
                    'ml': {
                        'risk_score': ml.get('risk_score'),
                        'threat_type': ml.get('threat_type'),
                        'confidence': ml.get('confidence'),
                        'is_anomaly': ml.get('is_anomaly'),
                        'ml_available': ml.get('ml_available', False)
                    },
                    'geo': geo_formatted,
                    'history': history,
                    'recommendations': recommendations
                }
            }
            return jsonify(response)
        else:
            return jsonify(result), 400

    except Exception as e:
        print(f"[Demo] Error executing scenario {scenario_id}: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500


@demo_routes.route('/run-all', methods=['POST'])
@login_required
def execute_all_scenarios():
    """Execute all demo scenarios (full demonstration)"""
    try:
        result = run_full_demo(verbose=False)

        if result.get('success'):
            # Format results for UI
            formatted_results = []
            for r in result.get('results', []):
                if r.get('success'):
                    actual = r.get('actual_results', {})
                    ml = actual.get('ml', {})
                    threat = actual.get('threat_intel', {})

                    formatted_results.append({
                        'scenario_id': r.get('scenario_id'),
                        'scenario_name': r.get('scenario_name'),
                        'ip': r.get('ip'),
                        'event_id': r.get('event_id'),
                        'success': True,
                        'results': {
                            'abuseipdb_score': threat.get('abuseipdb', {}).get('score') if threat else None,
                            'virustotal_positives': threat.get('virustotal', {}).get('positives') if threat else None,
                            'threat_level': threat.get('threat_level') if threat else None,
                            'risk_score': ml.get('risk_score'),
                            'is_anomaly': ml.get('is_anomaly'),
                            'ml_available': ml.get('ml_available', False)
                        }
                    })
                else:
                    formatted_results.append({
                        'scenario_id': r.get('scenario_id'),
                        'success': False,
                        'error': r.get('error')
                    })

            return jsonify({
                'success': True,
                'summary': result.get('summary'),
                'results': formatted_results,
                'timestamp': result.get('timestamp')
            })
        else:
            return jsonify(result), 400

    except Exception as e:
        print(f"[Demo] Error executing full demo: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500
