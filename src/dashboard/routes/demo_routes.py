"""
SSH Guardian v3.0 - Demo API Routes
API endpoints for demonstration scenarios
"""

from flask import Blueprint, jsonify, request
import sys
from pathlib import Path
from decimal import Decimal

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
from core.cache import get_cache
from src.ai.smart_recommendations import get_smart_recommendations

demo_routes = Blueprint('demo_routes', __name__)


def invalidate_events_cache():
    """Invalidate events cache so new demo events appear immediately"""
    try:
        cache = get_cache()
        cache.invalidate_events()
    except Exception as e:
        print(f"[Demo] Warning: Could not invalidate events cache: {e}")


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


def calculate_behavioral_score(history: dict, events_data: dict = None) -> dict:
    """
    Analyze attack pattern behavior

    Returns behavioral score 0-100 and pattern indicators
    """
    score = 0
    indicators = []

    # Convert Decimal values to int/float
    failed_attempts = int(history.get('failed_attempts') or 0)
    total_events = max(1, int(history.get('total_events') or 1))
    unique_usernames = int(history.get('unique_usernames') or 0)

    # Calculate duration in minutes
    first_seen = history.get('first_seen')
    last_seen = history.get('last_seen')
    duration_minutes = 1  # Default
    if first_seen and last_seen:
        from datetime import datetime
        try:
            first = datetime.fromisoformat(first_seen) if isinstance(first_seen, str) else first_seen
            last = datetime.fromisoformat(last_seen) if isinstance(last_seen, str) else last_seen
            duration_minutes = max(1, (last - first).total_seconds() / 60)
        except:
            duration_minutes = 1

    # Failure rate
    failure_rate = failed_attempts / total_events if total_events > 0 else 0
    if failure_rate > 0.95:
        score += 30
        indicators.append(f'Very high failure rate ({failure_rate*100:.0f}%)')
    elif failure_rate > 0.80:
        score += 20
        indicators.append(f'High failure rate ({failure_rate*100:.0f}%)')
    elif failure_rate > 0.50:
        score += 10
        indicators.append(f'Elevated failure rate ({failure_rate*100:.0f}%)')

    # Attack velocity (attempts per minute) - improved thresholds for low-velocity attacks
    velocity = failed_attempts / duration_minutes if duration_minutes > 0 else 0
    if velocity > 20:
        score += 30
        indicators.append(f'Rapid attempts ({velocity:.0f}/min)')
    elif velocity > 10:
        score += 20
        indicators.append(f'Fast attempts ({velocity:.0f}/min)')
    elif velocity > 5:
        score += 12
        indicators.append(f'Moderate velocity ({velocity:.1f}/min)')
    elif velocity > 1:
        score += 5
        indicators.append(f'Low velocity persistent ({velocity:.1f}/min)')
    elif velocity > 0 and failed_attempts >= 3:
        score += 3
        indicators.append(f'Slow persistent attack ({failed_attempts} attempts)')

    # Username diversity (credential stuffing / dictionary attack indicator)
    if unique_usernames > 10:
        score += 25
        indicators.append(f'Dictionary attack ({unique_usernames} usernames)')
    elif unique_usernames > 5:
        score += 15
        indicators.append(f'Username enumeration ({unique_usernames} usernames)')
    elif unique_usernames > 2:
        score += 8
        indicators.append(f'Multiple usernames targeted ({unique_usernames})')

    # Pattern matching against known attacks - improved with fallback patterns
    pattern_type = 'Unknown'
    if velocity > 15 and failure_rate > 0.90:
        pattern_type = 'Brute Force'
        score += 20
        indicators.append('Pattern matches known brute force')
    elif velocity > 10 and failure_rate > 0.85:
        pattern_type = 'Brute Force'
        score += 15
        indicators.append('Pattern matches brute force attack')
    elif unique_usernames > 10 and velocity > 5:
        pattern_type = 'Credential Stuffing'
        score += 18
        indicators.append('Pattern matches credential stuffing')
    elif unique_usernames > 5 and failure_rate > 0.95:
        pattern_type = 'Username Enumeration'
        score += 12
        indicators.append('Pattern matches username enumeration')
    elif total_events > 3 and duration_minutes < 5:
        pattern_type = 'Reconnaissance'
        score += 8
        indicators.append('Rapid reconnaissance pattern')
    # Fallback patterns for single-factor attacks
    elif failure_rate > 0.90 and failed_attempts >= 3:
        pattern_type = 'Targeted Attack'
        score += 12
        indicators.append('High failure rate targeted attack')
    elif failure_rate > 0.80 and failed_attempts >= 2:
        pattern_type = 'Suspicious Activity'
        score += 8
        indicators.append('Elevated failure rate suspicious activity')

    return {
        'score': min(100, score),
        'indicators': indicators,
        'pattern': pattern_type,
        'velocity': round(velocity, 1),
        'failure_rate': round(failure_rate * 100, 1),
        'duration_minutes': round(duration_minutes, 1),
        'unique_usernames': unique_usernames
    }


def calculate_geographic_risk_score(geo_data: dict, threat_intel: dict = None) -> dict:
    """
    Enhanced geographic risk with regional intelligence
    """
    score = 0
    factors = []

    # High-risk countries (known attack origins)
    high_risk_countries = ['RU', 'CN', 'KP', 'IR', 'BY', 'SY']
    elevated_risk_countries = ['VN', 'IN', 'BR', 'UA', 'TR']

    country_code = geo_data.get('country_code', '')
    country_name = geo_data.get('country', 'Unknown')

    if country_code in high_risk_countries:
        score += 40
        factors.append(f'High-risk country: {country_name}')
    elif country_code in elevated_risk_countries:
        score += 20
        factors.append(f'Elevated-risk region: {country_name}')

    # Anonymization networks (TOR = very high risk)
    if geo_data.get('is_tor'):
        score += 50
        factors.append('Tor Exit Node (anonymization network)')
    elif geo_data.get('is_proxy') or geo_data.get('is_vpn'):
        score += 30
        factors.append('VPN/Proxy detected (anonymization)')

    # Datacenter/hosting (often used for attacks)
    if geo_data.get('is_datacenter'):
        score += 25
        factors.append('Hosting/Datacenter IP (non-residential)')

    # Regional attack history (would need to query database in production)
    # For now, use simplified logic based on threat intel
    regional_threat_count = 0
    if threat_intel and threat_intel.get('abuseipdb_reports', 0) > 100:
        regional_threat_count = threat_intel.get('abuseipdb_reports', 0)
        if regional_threat_count > 1000:
            score += 20
            factors.append(f'Heavily reported IP ({regional_threat_count} reports)')
        elif regional_threat_count > 100:
            score += 10
            factors.append(f'Frequently reported IP ({regional_threat_count} reports)')

    return {
        'score': min(100, score),
        'factors': factors,
        'is_high_risk_region': country_code in high_risk_countries,
        'is_anonymized': geo_data.get('is_tor') or geo_data.get('is_proxy') or geo_data.get('is_vpn'),
        'regional_threat_count': regional_threat_count,
        'country': country_name,
        'country_code': country_code
    }


def calculate_composite_risk(threat_intel: dict, ml_analysis: dict, behavioral: dict, geographic: dict) -> dict:
    """
    Calculate weighted composite risk score using multi-factor analysis

    Weighted Risk Model:
    - Threat Intel Score × 0.35 (AbuseIPDB + VirusTotal)
    - ML Risk Score × 0.30 (Model prediction)
    - Behavioral Score × 0.25 (Attack pattern analysis)
    - Geographic Risk × 0.10 (Location-based risk)

    Returns:
        {
            'overall_score': 0-100,
            'breakdown': {...},
            'threat_level': 'CRITICAL|HIGH|MODERATE|LOW|CLEAN',
            'confidence': 0-100
        }
    """
    # Threat Intel Score (0-100)
    abuseipdb_score = float(threat_intel.get('abuseipdb_score', 0))
    vt_positives = float(threat_intel.get('virustotal_positives', 0))
    vt_total = max(1, float(threat_intel.get('virustotal_total', 70)))

    threat_score = (
        abuseipdb_score * 0.7 +
        (vt_positives / vt_total * 100) * 0.3
    )

    # ML Prediction Score (0-100)
    ml_score = float(ml_analysis.get('risk_score', 0))

    # Behavioral Score (0-100)
    behavioral_score = float(behavioral.get('score', 0))

    # Geographic Risk Score (0-100)
    geo_score = float(geographic.get('score', 0))

    # Weighted composite - rebalanced for better behavioral weight
    overall = (
        threat_score * 0.35 +
        ml_score * 0.25 +
        behavioral_score * 0.30 +
        geo_score * 0.10
    )

    # Determine threat level with nuanced thresholds
    if overall >= 85:
        level = 'CRITICAL'
    elif overall >= 70:
        level = 'HIGH'
    elif overall >= 40:
        level = 'MODERATE'
    elif overall >= 20:
        level = 'LOW'
    else:
        level = 'CLEAN'

    # Calculate confidence based on data availability and consistency
    confidence = 0
    factors_available = 0

    # Check data availability
    if abuseipdb_score > 0 or vt_positives > 0:
        confidence += 30
        factors_available += 1

    if ml_score > 0 and ml_analysis.get('ml_available'):
        ml_confidence = float(ml_analysis.get('confidence', 0))
        confidence += ml_confidence * 30  # ML provides 30% of confidence
        factors_available += 1

    if behavioral_score > 0:
        confidence += 25
        factors_available += 1

    if geo_score > 0:
        confidence += 15
        factors_available += 1

    # Boost confidence if multiple factors agree
    if factors_available >= 3:
        confidence = min(100, confidence * 1.1)
    elif factors_available >= 2:
        confidence = min(100, confidence * 1.05)

    return {
        'overall_score': round(overall, 1),
        'breakdown': {
            'threat_intel': {
                'score': round(threat_score, 1),
                'weight': 0.35,
                'weighted': round(threat_score * 0.35, 1),
                'abuseipdb': abuseipdb_score,
                'virustotal': round((vt_positives / vt_total * 100), 1)
            },
            'ml_prediction': {
                'score': round(ml_score, 1),
                'weight': 0.25,
                'weighted': round(ml_score * 0.25, 1),
                'confidence': ml_analysis.get('confidence', 0)
            },
            'behavioral': {
                'score': round(behavioral_score, 1),
                'weight': 0.30,
                'weighted': round(behavioral_score * 0.30, 1),
                'pattern': behavioral.get('pattern', 'Unknown'),
                'velocity': behavioral.get('velocity', 0),
                'failure_rate': behavioral.get('failure_rate', 0)
            },
            'geographic': {
                'score': round(geo_score, 1),
                'weight': 0.10,
                'weighted': round(geo_score * 0.10, 1),
                'is_high_risk': geographic.get('is_high_risk_region', False),
                'is_anonymized': geographic.get('is_anonymized', False)
            }
        },
        'threat_level': level,
        'confidence': round(confidence, 1),
        'factors_available': factors_available
    }


def generate_recommendations(ml: dict, threat: dict, geo: dict, history: dict, ip_address: str = None) -> list:
    """
    Generate simple, clear security recommendations.

    Each recommendation has:
    - priority: critical, high, medium, low
    - action: What to do (plain English)
    - reason: Why (simple explanation)
    - details: Key facts that support this recommendation
    """
    recommendations = []

    # Extract key metrics
    abuseipdb_score = int(threat.get('abuseipdb_score') or 0) if threat else 0
    vt_positives = int(threat.get('virustotal_positives') or 0) if threat else 0
    risk_score = float(ml.get('risk_score') or 0) if ml else 0.0
    is_anomaly = ml.get('is_anomaly', False) if ml else False

    is_tor = geo.get('is_tor', False) if geo else False
    is_proxy = geo.get('is_proxy', False) if geo else False
    is_vpn = geo.get('is_vpn', False) if geo else False
    country = geo.get('country', 'Unknown') if geo else 'Unknown'

    failed_attempts = int(history.get('failed_attempts') or 0)
    unique_usernames = int(history.get('unique_usernames') or 0)

    # HIGH PRIORITY: Bad reputation IP
    if abuseipdb_score >= 70:
        recommendations.append({
            'priority': 'critical' if abuseipdb_score >= 90 else 'high',
            'action': 'Block this IP',
            'reason': f'Bad reputation score: {abuseipdb_score}/100',
            'details': [
                f'AbuseIPDB: {abuseipdb_score}/100 (reported by security community)',
                f'This IP is known for malicious activity'
            ],
            'action_type': 'block_ip',
            'action_data': {'ip': ip_address, 'reason': f'AbuseIPDB {abuseipdb_score}/100'}
        })

    # HIGH PRIORITY: Malware source
    if vt_positives >= 5:
        recommendations.append({
            'priority': 'critical',
            'action': 'Block - Known malware source',
            'reason': f'{vt_positives} antivirus vendors flagged this IP',
            'details': [
                f'VirusTotal: {vt_positives} security vendors detected threats',
                'Associated with malware distribution'
            ],
            'action_type': 'block_ip',
            'action_data': {'ip': ip_address, 'reason': f'VirusTotal {vt_positives} detections'}
        })

    # HIGH PRIORITY: Brute force attack
    if failed_attempts >= 5:
        recommendations.append({
            'priority': 'high',
            'action': 'Block - Too many failed logins',
            'reason': f'{failed_attempts} failed login attempts',
            'details': [
                f'{failed_attempts} password guessing attempts detected',
                'This is a brute force attack pattern'
            ],
            'action_type': 'block_ip',
            'action_data': {'ip': ip_address, 'reason': f'{failed_attempts} failed attempts'}
        })

    # MEDIUM PRIORITY: Credential stuffing
    if unique_usernames >= 5:
        recommendations.append({
            'priority': 'high',
            'action': 'Block - Credential stuffing attack',
            'reason': f'Trying {unique_usernames} different usernames',
            'details': [
                f'{unique_usernames} different usernames attempted',
                'Testing stolen credentials from data breaches'
            ],
            'action_type': 'block_ip',
            'action_data': {'ip': ip_address, 'reason': f'{unique_usernames} usernames tried'}
        })

    # MEDIUM PRIORITY: Tor/VPN
    if is_tor:
        recommendations.append({
            'priority': 'medium',
            'action': 'Review - Tor exit node',
            'reason': 'Connection from Tor anonymity network',
            'details': [
                'Attacker is hiding their real IP',
                'Legitimate users rarely use Tor for SSH'
            ],
            'action_type': 'review',
            'action_data': {'ip': ip_address, 'network': 'tor'}
        })
    elif is_proxy or is_vpn:
        recommendations.append({
            'priority': 'low',
            'action': 'Monitor - VPN/Proxy connection',
            'reason': 'Connection via VPN or proxy',
            'details': [
                f'Country: {country}',
                'Could be hiding location, but many legitimate users use VPNs'
            ],
            'action_type': 'monitor',
            'action_data': {'ip': ip_address, 'network': 'vpn'}
        })

    # ML anomaly detection
    if is_anomaly and risk_score >= 60:
        recommendations.append({
            'priority': 'medium',
            'action': 'Investigate - Unusual behavior detected',
            'reason': f'ML flagged as anomaly (risk: {risk_score:.0f}/100)',
            'details': [
                f'Risk score: {risk_score:.0f}/100',
                f'Behavior pattern: {ml.get("threat_type", "suspicious")}'
            ],
            'action_type': 'investigate',
            'action_data': {'ip': ip_address}
        })

    # NO ISSUES: Clean IP
    if not recommendations:
        if abuseipdb_score < 20 and risk_score < 30:
            recommendations.append({
                'priority': 'low',
                'action': 'No action needed',
                'reason': 'This IP appears safe',
                'details': [
                    f'Clean reputation (AbuseIPDB: {abuseipdb_score}/100)',
                    'No suspicious patterns detected'
                ],
                'action_type': 'none',
                'action_data': None
            })
        else:
            recommendations.append({
                'priority': 'low',
                'action': 'Continue monitoring',
                'reason': 'Low risk - watching for changes',
                'details': [
                    f'Risk score: {risk_score:.0f}/100',
                    'No immediate threat, keep monitoring'
                ],
                'action_type': 'monitor',
                'action_data': {'ip': ip_address}
            })

    return recommendations


def generate_smart_recommendations(
    composite_risk: dict,
    behavioral_analysis: dict,
    threat_intel: dict,
    ml_analysis: dict,
    geo_data: dict,
    history: dict,
    ip_address: str
) -> list:
    """
    Generate simple, actionable recommendations based on threat analysis.

    Returns list of recommendations, each with:
    - priority: critical, high, medium, low
    - action: What to do (plain English)
    - reason: Why (simple explanation)
    - details: Supporting facts
    """
    recommendations = []

    # Get key metrics
    overall_score = composite_risk.get('overall_score', 0)
    abuseipdb_score = int(threat_intel.get('abuseipdb_score', 0))
    vt_positives = int(threat_intel.get('virustotal_positives', 0))
    ml_risk = float(ml_analysis.get('risk_score', 0))
    is_anomaly = ml_analysis.get('is_anomaly', False)

    velocity = behavioral_analysis.get('velocity', 0)
    pattern = behavioral_analysis.get('pattern', 'Unknown')
    unique_usernames = behavioral_analysis.get('unique_usernames', 0)

    is_tor = geo_data.get('is_tor', False)
    is_proxy = geo_data.get('is_proxy', False) or geo_data.get('is_vpn', False)
    country = geo_data.get('country', 'Unknown')

    failed_attempts = history.get('failed_attempts', 0)

    # =================================================================
    # CRITICAL: Active attack or very bad IP
    # =================================================================
    if overall_score >= 80 or abuseipdb_score >= 80:
        recommendations.append({
            'priority': 'critical',
            'action': 'Block IP immediately',
            'reason': 'Active threat detected' if overall_score >= 80 else f'Very bad reputation ({abuseipdb_score}/100)',
            'details': [
                f'Risk score: {overall_score:.0f}/100',
                f'AbuseIPDB: {abuseipdb_score}/100',
                f'Pattern: {pattern}' if pattern != 'Unknown' else None
            ],
            'action_type': 'block_ip',
            'action_data': {'ip': ip_address}
        })

    # =================================================================
    # HIGH: Known malware source
    # =================================================================
    if vt_positives >= 5:
        recommendations.append({
            'priority': 'critical' if vt_positives >= 10 else 'high',
            'action': 'Block - Malware infrastructure',
            'reason': f'{vt_positives} security vendors flagged this IP',
            'details': [
                f'VirusTotal: {vt_positives} detections',
                'Known for distributing malware'
            ],
            'action_type': 'block_ip',
            'action_data': {'ip': ip_address}
        })

    # =================================================================
    # HIGH: Rapid attack (DDoS-like)
    # =================================================================
    if velocity > 10:
        recommendations.append({
            'priority': 'high',
            'action': 'Block - Attack too fast',
            'reason': f'{velocity:.0f} attempts per minute',
            'details': [
                f'Velocity: {velocity:.0f}/min',
                'Automated attack tool or botnet'
            ],
            'action_type': 'block_ip',
            'action_data': {'ip': ip_address}
        })

    # =================================================================
    # HIGH: Brute force attack
    # =================================================================
    if failed_attempts >= 5 and 'block_ip' not in [r.get('action_type') for r in recommendations]:
        recommendations.append({
            'priority': 'high',
            'action': 'Block - Brute force attack',
            'reason': f'{failed_attempts} failed login attempts',
            'details': [
                f'{failed_attempts} password guessing attempts',
                'Classic brute force pattern'
            ],
            'action_type': 'block_ip',
            'action_data': {'ip': ip_address}
        })

    # =================================================================
    # HIGH: Credential stuffing
    # =================================================================
    if unique_usernames >= 5 and 'block_ip' not in [r.get('action_type') for r in recommendations]:
        recommendations.append({
            'priority': 'high',
            'action': 'Block - Credential stuffing',
            'reason': f'Trying {unique_usernames} different usernames',
            'details': [
                f'{unique_usernames} usernames attempted',
                'Testing stolen credentials'
            ],
            'action_type': 'block_ip',
            'action_data': {'ip': ip_address}
        })

    # =================================================================
    # MEDIUM: Tor exit node
    # =================================================================
    if is_tor:
        recommendations.append({
            'priority': 'medium',
            'action': 'Review - Tor connection',
            'reason': 'Attacker hiding behind Tor network',
            'details': [
                'Tor exit node detected',
                'Real IP address is hidden'
            ],
            'action_type': 'review',
            'action_data': {'ip': ip_address, 'network': 'tor'}
        })

    # =================================================================
    # LOW: VPN/Proxy (not necessarily malicious)
    # =================================================================
    elif is_proxy:
        recommendations.append({
            'priority': 'low',
            'action': 'Monitor - VPN/Proxy',
            'reason': 'Connection via VPN or proxy',
            'details': [
                f'Country: {country}',
                'Many legitimate users use VPNs'
            ],
            'action_type': 'monitor',
            'action_data': {'ip': ip_address}
        })

    # =================================================================
    # MEDIUM: ML anomaly
    # =================================================================
    if is_anomaly and ml_risk >= 50 and 'block_ip' not in [r.get('action_type') for r in recommendations]:
        recommendations.append({
            'priority': 'medium',
            'action': 'Investigate - Unusual behavior',
            'reason': f'ML detected anomaly (risk: {ml_risk:.0f}/100)',
            'details': [
                f'Risk score: {ml_risk:.0f}/100',
                f'Pattern: {pattern}'
            ],
            'action_type': 'investigate',
            'action_data': {'ip': ip_address}
        })

    # =================================================================
    # LOW: Clean IP
    # =================================================================
    if not recommendations:
        if overall_score < 30:
            recommendations.append({
                'priority': 'low',
                'action': 'No action needed',
                'reason': 'This IP appears safe',
                'details': [
                    f'Risk: {overall_score:.0f}/100 (Low)',
                    'No threats detected'
                ],
                'action_type': 'none',
                'action_data': None
            })
        else:
            recommendations.append({
                'priority': 'low',
                'action': 'Continue monitoring',
                'reason': 'Moderate risk - watching',
                'details': [
                    f'Risk: {overall_score:.0f}/100',
                    'Keep an eye on this IP'
                ],
                'action_type': 'monitor',
                'action_data': {'ip': ip_address}
            })

    # Clean up None values from details
    for rec in recommendations:
        if rec.get('details'):
            rec['details'] = [d for d in rec['details'] if d]

    # Sort by priority
    priority_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
    recommendations.sort(key=lambda x: priority_order.get(x.get('priority', 'low'), 4))

    return recommendations


@demo_routes.route('/refresh-ips', methods=['POST'])
@login_required
def refresh_ips():
    """Fetch fresh malicious IPs from external sources"""
    try:
        from simulation.ip_fetcher import fetch_and_save_all, get_pool_stats

        # Fetch from all sources
        result = fetch_and_save_all()

        # Get updated stats
        stats = get_pool_stats()

        return jsonify({
            'success': True,
            'fetched': result['total'],
            'sources': result['sources'],
            'pool_stats': stats,
            'timestamp': result['timestamp']
        })
    except Exception as e:
        print(f"[Demo] Error refreshing IPs: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500


@demo_routes.route('/ip-pool/stats', methods=['GET'])
@login_required
def ip_pool_stats():
    """Get statistics about the fresh IP pool"""
    try:
        from simulation.ip_fetcher import get_pool_stats
        stats = get_pool_stats()
        return jsonify({'success': True, **stats})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@demo_routes.route('/reference-ips', methods=['GET'])
@login_required
def get_reference_ips():
    """
    Get reference IPs in two categories: malicious and clean.
    Shows AbuseIPDB score beside each IP.
    """
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Get malicious IPs (high threat score)
        cursor.execute("""
            SELECT ip_address, threat_score
            FROM simulation_ip_pool
            WHERE ip_type = 'malicious' AND threat_score >= 50
            ORDER BY RAND()
            LIMIT 10
        """)
        malicious_rows = cursor.fetchall()

        # Get clean IPs (low threat score or trusted type)
        cursor.execute("""
            SELECT ip_address, threat_score
            FROM simulation_ip_pool
            WHERE ip_type = 'trusted' OR threat_score < 20
            ORDER BY RAND()
            LIMIT 10
        """)
        clean_rows = cursor.fetchall()

        # If no clean IPs in pool, use well-known clean IPs
        if not clean_rows:
            clean_rows = [
                {'ip_address': '8.8.8.8', 'threat_score': 0},
                {'ip_address': '1.1.1.1', 'threat_score': 0},
                {'ip_address': '208.67.222.222', 'threat_score': 0},
                {'ip_address': '9.9.9.9', 'threat_score': 0},
                {'ip_address': '64.6.64.6', 'threat_score': 0}
            ]

        cursor.close()
        conn.close()

        # Format response
        malicious = [{
            'ip': row['ip_address'],
            'abusedb_score': row['threat_score']
        } for row in malicious_rows]

        clean = [{
            'ip': row['ip_address'] if isinstance(row, dict) and 'ip_address' in row else row.get('ip_address', row.get('ip', '')),
            'abusedb_score': row.get('threat_score', 0)
        } for row in clean_rows]

        return jsonify({
            'success': True,
            'categories': {
                'malicious': malicious,
                'clean': clean
            },
            'total': len(malicious) + len(clean)
        })
    except Exception as e:
        print(f"[Demo] Error getting reference IPs: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500


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


@demo_routes.route('/scenarios/categorized', methods=['GET'])
@login_required
def list_scenarios_by_category():
    """
    Get scenarios organized by blocking mechanism.

    Categories:
    - ufw_blocking: Triggers SSH Guardian rules → UFW deny commands
    - fail2ban: Generates auth.log entries → fail2ban bans
    - baseline: Clean IPs for comparison
    """
    try:
        from src.simulation.demo_scenarios import get_scenarios_by_category
        categories = get_scenarios_by_category()

        return jsonify({
            'success': True,
            'categories': categories,
            'summary': {
                'ufw_blocking': len(categories.get('ufw_blocking', [])),
                'fail2ban': len(categories.get('fail2ban', [])),
                'baseline': len(categories.get('baseline', []))
            },
            'description': {
                'ufw_blocking': 'These scenarios trigger SSH Guardian blocking rules. When triggered, a UFW deny command is sent to the agent to block the IP.',
                'fail2ban': 'These scenarios generate auth.log entries that fail2ban detects. Fail2ban handles the blocking directly.',
                'baseline': 'Clean IPs for comparison - should NOT be blocked.'
            }
        })
    except Exception as e:
        print(f"[Demo] Error listing categorized scenarios: {e}")
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
    """Execute a single demo scenario with enhanced multi-factor analysis"""
    try:
        # Check for optional parameters
        data = request.get_json() or {}
        agent_id = data.get('agent_id')
        run_full_pipeline = data.get('run_full_pipeline', False)

        # Convert agent_id to int if provided
        if agent_id:
            agent_id = int(agent_id)

        result = run_demo_scenario(
            scenario_id,
            verbose=False,
            agent_id=agent_id,
            run_full_pipeline=run_full_pipeline
        )

        if result.get('success'):
            # Format response for UI
            actual = result.get('actual_results', {})
            ml = actual.get('ml', {})
            threat = actual.get('threat_intel', {}) or {}
            geo = actual.get('geoip', {}) or {}

            # Get historical analysis for the IP
            ip_address = result.get('ip')
            history = get_ip_history(ip_address)

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

            # Format threat intel data (handle both nested and flat structures)
            # Enrichment returns nested: {'abuseipdb': {'score': 100}, 'virustotal': {'positives': 4}}
            # Database cache returns flat: {'abuseipdb_score': 100, 'virustotal_positives': 4}
            abuseipdb_data = threat.get('abuseipdb', {}) if isinstance(threat.get('abuseipdb'), dict) else {}
            virustotal_data = threat.get('virustotal', {}) if isinstance(threat.get('virustotal'), dict) else {}

            threat_formatted = {
                'abuseipdb_score': float(
                    abuseipdb_data.get('score') or
                    threat.get('abuseipdb_score') or 0
                ),
                'abuseipdb_reports': int(
                    abuseipdb_data.get('reports') or
                    threat.get('abuseipdb_reports') or 0
                ),
                'abuseipdb_confidence': float(
                    abuseipdb_data.get('confidence') or
                    threat.get('abuseipdb_confidence') or 0
                ),
                'virustotal_positives': int(
                    virustotal_data.get('positives') or
                    threat.get('virustotal_positives') or 0
                ),
                'virustotal_total': int(
                    virustotal_data.get('total') or
                    threat.get('virustotal_total') or 70
                ),
                'threat_level': threat.get('threat_level') or threat.get('overall_threat_level', 'unknown')
            }

            # Calculate behavioral score
            behavioral_analysis = calculate_behavioral_score(history)

            # Calculate geographic risk score
            geographic_risk = calculate_geographic_risk_score(geo_formatted, threat_formatted)

            # Calculate composite risk using multi-factor analysis
            composite_risk = calculate_composite_risk(
                threat_formatted,
                ml,
                behavioral_analysis,
                geographic_risk
            )

            # Generate smart context-aware recommendations
            smart_recommendations = generate_smart_recommendations(
                composite_risk,
                behavioral_analysis,
                threat_formatted,
                ml,
                geo_formatted,
                history,
                ip_address
            )

            # Also generate traditional recommendations for backward compatibility
            basic_recommendations = generate_recommendations(ml, threat, geo, history, ip_address)

            # Merge recommendations (smart recommendations take priority)
            recommendations = smart_recommendations + basic_recommendations

            # Remove duplicates based on action type
            seen_actions = set()
            unique_recommendations = []
            for rec in recommendations:
                action_key = f"{rec.get('action_type', 'unknown')}_{rec.get('action', '')}"
                if action_key not in seen_actions:
                    seen_actions.add(action_key)
                    unique_recommendations.append(rec)

            # Limit to top recommendations
            recommendations = unique_recommendations[:8]

            # Get blocking result
            blocking_result = result.get('blocking', {}) or actual.get('blocking', {})

            # If blocked, add a recommendation showing the action taken
            if blocking_result.get('blocked'):
                triggered_rules = blocking_result.get('triggered_rules', [])
                duration = blocking_result.get('adjusted_duration', 0)
                duration_str = f"{duration} minutes" if duration < 60 else f"{duration // 60} hours" if duration < 1440 else f"{duration // 1440} days"

                # Add blocking action as top recommendation
                recommendations.insert(0, {
                    'urgency': 'immediate',
                    'priority': 'critical',
                    'action': 'IP BLOCKED',
                    'reason': f'Auto-blocked by rules: {", ".join(triggered_rules)}',
                    'why': [
                        f'Block duration: {duration_str}',
                        f'Block ID: {blocking_result.get("block_id")}',
                        f'Rules triggered: {", ".join(triggered_rules)}'
                    ],
                    'impact': 'IP is now blocked from accessing the system',
                    'confidence': 1.0,
                    'action_type': 'blocked',
                    'action_data': {
                        'block_id': blocking_result.get('block_id'),
                        'ip': ip_address,
                        'duration': duration,
                        'rules': triggered_rules
                    }
                })

            response = {
                'success': True,
                'scenario_id': result.get('scenario_id'),
                'scenario_name': result.get('scenario_name'),
                'ip': ip_address,
                'event_id': result.get('event_id'),
                'event_type': result.get('event_type'),
                'expected': result.get('expected'),
                # Pipeline integration
                'agent_id': result.get('agent_id'),
                'run_full_pipeline': result.get('run_full_pipeline', False),
                'pipeline_steps': result.get('pipeline_steps'),
                # Blocking result
                'blocking': blocking_result,
                # NEW: Composite risk assessment
                'composite_risk': composite_risk,
                # NEW: Enhanced analysis sections
                'behavioral_analysis': behavioral_analysis,
                'geographic_intelligence': geographic_risk,
                # Traditional results structure (for backward compatibility)
                'results': {
                    'threat_intel': threat_formatted,
                    'ml': {
                        'risk_score': float(ml.get('risk_score') or 0),
                        'threat_type': ml.get('threat_type'),
                        'confidence': float(ml.get('confidence') or 0),
                        'is_anomaly': ml.get('is_anomaly'),
                        'ml_available': ml.get('ml_available', False)
                    },
                    'geo': geo_formatted,
                    'history': history,
                    'recommendations': recommendations,
                    'blocking': blocking_result
                }
            }
            # Invalidate events cache so new demo events appear immediately in Live Events
            invalidate_events_cache()
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

            # Invalidate events cache so new demo events appear immediately in Live Events
            invalidate_events_cache()

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


@demo_routes.route('/ip-analysis/<ip_address>', methods=['GET'])
@login_required
def get_ip_analysis(ip_address):
    """
    Get comprehensive IP analysis with ML predictions, behavioral patterns,
    threat intelligence, and recommendations - same format as simulation results.

    This is used by the Live Events "View Details" action to show full analysis.
    """
    try:
        if not ip_address:
            return jsonify({'success': False, 'error': 'IP address required'}), 400

        # Get IP history from database
        history = get_ip_history(ip_address)

        # Get geolocation data
        geo = {}
        try:
            conn = get_connection()
            cursor = conn.cursor(dictionary=True)
            cursor.execute("""
                SELECT * FROM ip_geolocation
                WHERE ip_address_text = %s
                ORDER BY last_updated DESC
                LIMIT 1
            """, (ip_address,))
            geo_row = cursor.fetchone()
            if geo_row:
                geo = {
                    'country': geo_row.get('country') or geo_row.get('country_name') or 'Unknown',
                    'country_code': geo_row.get('country_code'),
                    'city': geo_row.get('city') or 'Unknown',
                    'region': geo_row.get('region') or geo_row.get('region_name'),
                    'isp': geo_row.get('isp') or geo_row.get('org') or 'Unknown',
                    'asn': geo_row.get('asn'),
                    'is_tor': bool(geo_row.get('is_tor')),
                    'is_vpn': bool(geo_row.get('is_vpn')),
                    'is_proxy': bool(geo_row.get('is_proxy')),
                    'is_datacenter': bool(geo_row.get('is_datacenter')),
                    'latitude': float(geo_row['latitude']) if geo_row.get('latitude') else None,
                    'longitude': float(geo_row['longitude']) if geo_row.get('longitude') else None,
                    'timezone': geo_row.get('timezone'),
                    'continent': geo_row.get('continent')
                }
            cursor.close()
            conn.close()
        except Exception as e:
            print(f"[IPAnalysis] Error getting geo data: {e}")

        # Get threat intelligence data
        threat = {}
        try:
            conn = get_connection()
            cursor = conn.cursor(dictionary=True)
            cursor.execute("""
                SELECT * FROM ip_threat_intelligence
                WHERE ip_address_text = %s
                ORDER BY last_updated DESC
                LIMIT 1
            """, (ip_address,))
            threat_row = cursor.fetchone()
            if threat_row:
                threat = {
                    'abuseipdb_score': float(threat_row.get('abuseipdb_score') or 0),
                    'abuseipdb_reports': int(threat_row.get('abuseipdb_reports') or 0),
                    'abuseipdb_confidence': float(threat_row.get('abuseipdb_confidence') or 0),
                    'virustotal_positives': int(threat_row.get('virustotal_positives') or 0),
                    'virustotal_total': int(threat_row.get('virustotal_total') or 70),
                    'overall_threat_level': threat_row.get('overall_threat_level', 'unknown')
                }
            cursor.close()
            conn.close()
        except Exception as e:
            print(f"[IPAnalysis] Error getting threat intel: {e}")

        # Get ML predictions for this IP (most recent event)
        ml = {'ml_available': False, 'risk_score': 0, 'confidence': 0, 'is_anomaly': False}
        try:
            conn = get_connection()
            cursor = conn.cursor(dictionary=True)
            cursor.execute("""
                SELECT ml_risk_score, ml_threat_type, ml_confidence, is_anomaly
                FROM auth_events
                WHERE source_ip_text = %s AND ml_risk_score IS NOT NULL
                ORDER BY timestamp DESC
                LIMIT 1
            """, (ip_address,))
            ml_row = cursor.fetchone()
            if ml_row:
                ml = {
                    'ml_available': True,
                    'risk_score': float(ml_row.get('ml_risk_score') or 0),
                    'threat_type': ml_row.get('ml_threat_type'),
                    'confidence': float(ml_row.get('ml_confidence') or 0),
                    'is_anomaly': bool(ml_row.get('is_anomaly'))
                }
            cursor.close()
            conn.close()
        except Exception as e:
            print(f"[IPAnalysis] Error getting ML data: {e}")

        # Calculate behavioral score
        behavioral_analysis = calculate_behavioral_score(history)

        # Calculate geographic risk score
        geographic_risk = calculate_geographic_risk_score(geo, threat)

        # Calculate composite risk using multi-factor analysis
        composite_risk = calculate_composite_risk(
            threat,
            ml,
            behavioral_analysis,
            geographic_risk
        )

        # Generate smart context-aware recommendations
        smart_recommendations = generate_smart_recommendations(
            composite_risk,
            behavioral_analysis,
            threat,
            ml,
            geo,
            history,
            ip_address
        )

        # Also generate traditional recommendations for backward compatibility
        basic_recommendations = generate_recommendations(ml, threat, geo, history, ip_address)

        # Merge recommendations (smart recommendations take priority)
        recommendations = smart_recommendations + basic_recommendations

        # Remove duplicates based on action type
        seen_actions = set()
        unique_recommendations = []
        for rec in recommendations:
            action_key = f"{rec.get('action_type', 'unknown')}_{rec.get('action', '')}"
            if action_key not in seen_actions:
                seen_actions.add(action_key)
                unique_recommendations.append(rec)

        # Limit to top recommendations
        recommendations = unique_recommendations[:8]

        return jsonify({
            'success': True,
            'ip': ip_address,
            'composite_risk': composite_risk,
            'behavioral_analysis': behavioral_analysis,
            'geographic_intelligence': geographic_risk,
            'results': {
                'threat_intel': threat,
                'ml': ml,
                'geo': geo,
                'history': history,
                'recommendations': recommendations
            }
        })

    except Exception as e:
        print(f"[IPAnalysis] Error analyzing IP {ip_address}: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500
