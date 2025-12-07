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
    """Generate security recommendations based on analysis

    Each recommendation includes:
    - priority: critical, high, medium, low
    - action: Short action title
    - reason: Data-driven explanation with specific metrics
    - icon: Visual indicator
    - action_type: Type of action (block_ip, add_blocklist, view_events, create_rule, navigate, info)
    - action_data: Data needed to perform the action (e.g., IP address, page URL, rule config)
    - evidence: Supporting data points that led to this recommendation
    """
    recommendations = []

    # Convert all numeric values to Python types immediately to avoid Decimal type issues
    threat_level = threat.get('overall_threat_level', 'unknown') if threat else 'unknown'
    abuseipdb_score = int(threat.get('abuseipdb_score') or 0) if threat else 0
    vt_positives = int(threat.get('virustotal_positives') or 0) if threat else 0

    is_anomaly = ml.get('is_anomaly', False) if ml else False
    ml_confidence = float(ml.get('confidence') or 0) if ml else 0.0
    risk_score = float(ml.get('risk_score') or 0) if ml else 0.0

    is_tor = geo.get('is_tor', False) if geo else False
    is_proxy = geo.get('is_proxy', False) if geo else False

    total_events = int(history.get('total_events') or 0)
    failed_attempts = int(history.get('failed_attempts') or 0)
    unique_usernames = int(history.get('unique_usernames') or 0)
    anomaly_count = int(history.get('anomaly_count') or 0)

    # Critical threat - immediate action
    if threat_level in ['high', 'critical'] or abuseipdb_score >= 80:
        recommendations.append({
            'priority': 'critical',
            'action': 'Block IP Immediately',
            'reason': f'Known malicious IP with AbuseIPDB score {abuseipdb_score}/100',
            'icon': '🚫',
            'action_type': 'block_ip',
            'ai_confidence': min(0.98, max(0.85, abuseipdb_score / 100)),  # Use threat intel score
            'action_data': {
                'ip': ip_address,
                'reason': f'Auto-block: AbuseIPDB {abuseipdb_score}/100, Threat Level: {threat_level}',
                'duration': 'permanent'
            },
            'evidence': [
                f'AbuseIPDB Score: {abuseipdb_score}/100',
                f'Threat Level: {threat_level.upper()}',
                f'Total Events from IP: {total_events}'
            ]
        })

    # VirusTotal detections
    if vt_positives and vt_positives > 5:
        recommendations.append({
            'priority': 'high',
            'action': 'Add to Permanent Blocklist',
            'reason': f'Flagged by {vt_positives} security vendors on VirusTotal',
            'icon': '🔬',
            'action_type': 'add_blocklist',
            'ai_confidence': min(0.92, 0.70 + (vt_positives / 70 * 0.25)),  # Scale with VT positives
            'action_data': {
                'ip': ip_address,
                'reason': f'VirusTotal: {vt_positives} vendors flagged this IP',
                'source': 'virustotal'
            },
            'evidence': [
                f'VirusTotal Detections: {vt_positives} vendors',
                f'AbuseIPDB Score: {abuseipdb_score}/100' if abuseipdb_score else None,
                f'Known for malicious activity'
            ]
        })

    # ML anomaly detection
    if is_anomaly:
        recommendations.append({
            'priority': 'high',
            'action': 'Investigate Anomaly',
            'reason': f'ML detected anomalous activity (confidence: {ml_confidence*100:.0f}%)',
            'icon': '🤖',
            'action_type': 'view_events',
            'ai_confidence': ml_confidence if ml_confidence > 0 else 0.78,  # Use ML confidence directly
            'action_data': {
                'ip': ip_address,
                'filter': 'anomaly',
                'page': 'events'
            },
            'evidence': [
                f'ML Confidence: {ml_confidence*100:.1f}%',
                f'Risk Score: {risk_score}/100',
                f'Anomalies from this IP: {anomaly_count}' if anomaly_count else 'First anomaly detected',
                f'Threat Type: {ml.get("threat_type", "Unknown")}' if ml.get('threat_type') else None
            ]
        })

    # High risk score
    if risk_score >= 70:
        recommendations.append({
            'priority': 'high',
            'action': 'Create Alert Rule',
            'reason': f'High ML risk score: {risk_score}/100',
            'icon': '📊',
            'action_type': 'create_rule',
            'ai_confidence': risk_score / 100,  # Use risk score directly
            'action_data': {
                'ip': ip_address,
                'rule_type': 'threshold',
                'threshold': 3,
                'window': '5m',
                'severity': 'high'
            },
            'evidence': [
                f'Risk Score: {risk_score}/100 (High)',
                f'ML Confidence: {ml_confidence*100:.1f}%',
                f'Failed Attempts: {failed_attempts}' if failed_attempts else None,
                f'Targeting {unique_usernames} usernames' if unique_usernames > 1 else None
            ]
        })

    # Anonymization network
    if is_tor or is_proxy:
        network_type = 'Tor exit node' if is_tor else 'Proxy/VPN'
        recommendations.append({
            'priority': 'medium',
            'action': f'Review {network_type} Policy',
            'reason': 'Traffic from anonymization network detected',
            'icon': '🧅' if is_tor else '🔒',
            'action_type': 'review_policy',
            'ai_confidence': 0.95 if is_tor else 0.72,  # TOR is more certain
            'action_data': {
                'network_type': network_type,
                'is_tor': is_tor,
                'is_proxy': is_proxy,
                'country': geo.get('country', 'Unknown') if geo else 'Unknown',
                'isp': geo.get('isp', 'Unknown') if geo else 'Unknown'
            },
            'evidence': [
                f'Network Type: {network_type}',
                f'ISP: {geo.get("isp", "Unknown")}' if geo else None,
                f'Country: {geo.get("country", "Unknown")}' if geo else None,
                'Consider blocking anonymization networks for sensitive systems'
            ]
        })

    # Brute force pattern
    if failed_attempts >= 10:
        rate = failed_attempts / max(1, (history.get('unique_servers', 1)))
        recommendations.append({
            'priority': 'high',
            'action': 'Enable Rate Limiting',
            'reason': f'{failed_attempts} failed login attempts from this IP',
            'icon': '⚡',
            'action_type': 'rate_limit',
            'ai_confidence': min(0.94, 0.70 + (min(failed_attempts, 50) / 50 * 0.24)),  # Scale with attempts
            'action_data': {
                'ip': ip_address,
                'failed_attempts': failed_attempts,
                'max_attempts': 5,
                'time_window': 60,
                'block_duration': 3600
            },
            'evidence': [
                f'Failed Attempts: {failed_attempts}',
                f'Attempts per server: ~{rate:.1f}',
                f'Unique Servers Targeted: {history.get("unique_servers", 1)}',
                f'Pattern: Brute force attack'
            ]
        })

    # Multiple usernames targeted
    if unique_usernames >= 5:
        recommendations.append({
            'priority': 'medium',
            'action': 'Review Targeted Accounts',
            'reason': f'{unique_usernames} different usernames attempted',
            'icon': '👥',
            'ai_confidence': min(0.82, 0.62 + (min(unique_usernames, 20) / 20 * 0.20)),  # Scale with diversity
            'action_type': 'view_events',
            'action_data': {
                'ip': ip_address,
                'filter': 'usernames',
                'page': 'ip-stats'
            },
            'evidence': [
                f'Unique Usernames: {unique_usernames}',
                f'Top targets: {", ".join([u["target_username"] for u in history.get("top_usernames", [])[:3]])}' if history.get('top_usernames') else None,
                f'Pattern: Username enumeration or credential stuffing'
            ]
        })

    # If no critical issues, provide positive feedback
    if not recommendations:
        if risk_score < 30:
            recommendations.append({
                'priority': 'low',
                'action': 'Continue Monitoring',
                'reason': 'Low risk profile - appears to be normal activity',
                'icon': '✅',
                'action_type': 'info',
                'ai_confidence': 0.65,  # Low confidence for benign activity
                'action_data': None,
                'evidence': [
                    f'Risk Score: {risk_score}/100 (Low)',
                    f'No threat intelligence flags',
                    f'Normal activity pattern'
                ]
            })
        else:
            recommendations.append({
                'priority': 'medium',
                'action': 'Monitor for Changes',
                'reason': 'Moderate risk - no immediate threat indicators',
                'icon': '👀',
                'action_type': 'view_events',
                'ai_confidence': risk_score / 100 if risk_score > 0 else 0.50,  # Use risk score
                'action_data': {
                    'ip': ip_address,
                    'page': 'events'
                },
                'evidence': [
                    f'Risk Score: {risk_score}/100 (Moderate)',
                    f'Total Events: {total_events}',
                    'Watch for pattern changes'
                ]
            })

    # Filter out None values from evidence lists
    for rec in recommendations:
        if rec.get('evidence'):
            rec['evidence'] = [e for e in rec['evidence'] if e]

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
    Generate context-aware recommendations with reasoning, urgency grouping, and clear impact

    Returns recommendations with:
    - urgency: immediate (5min), short_term (1hr), long_term (week)
    - priority: critical, high, medium, low
    - action: Clear action title
    - reason: Why this recommendation
    - why: List of specific reasons
    - impact: What happens if action is taken
    - risk_if_ignored: What happens if ignored
    - alternatives: Other approaches with trade-offs
    - confidence: AI confidence 0-1
    """
    recommendations = []
    overall_score = composite_risk.get('overall_score', 0)
    threat_level = composite_risk.get('threat_level', 'UNKNOWN')

    # Extract scores
    abuseipdb_score = int(threat_intel.get('abuseipdb_score', 0))
    vt_positives = int(threat_intel.get('virustotal_positives', 0))
    ml_risk = float(ml_analysis.get('risk_score', 0))
    is_anomaly = ml_analysis.get('is_anomaly', False)
    ml_confidence = float(ml_analysis.get('confidence', 0))

    # Behavioral metrics
    velocity = behavioral_analysis.get('velocity', 0)
    failure_rate = behavioral_analysis.get('failure_rate', 0)
    pattern = behavioral_analysis.get('pattern', 'Unknown')
    unique_usernames = behavioral_analysis.get('unique_usernames', 0)

    # Geographic
    is_tor = geo_data.get('is_tor', False)
    is_proxy = geo_data.get('is_proxy', False) or geo_data.get('is_vpn', False)
    country = geo_data.get('country', 'Unknown')

    # Historical
    failed_attempts = history.get('failed_attempts', 0)
    total_events = history.get('total_events', 0)

    # Helper to get subnet
    def get_subnet(ip):
        parts = ip.split('.')
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.0.0/16"
        return ip

    # IMMEDIATE ACTIONS (Next 5 minutes) - CRITICAL threats
    if overall_score >= 85 or (abuseipdb_score >= 80 and velocity > 10):
        # Active attack in progress - Block immediately
        recommendations.append({
            'urgency': 'immediate',
            'priority': 'critical',
            'action': 'Block IP Immediately',
            'reason': f'Active {pattern} attack in progress',
            'why': [
                f'{velocity} attempts per minute - attack ongoing',
                f'{failure_rate}% failure rate indicates malicious activity',
                f'Composite risk score: {overall_score}/100 (CRITICAL)',
                f'AbuseIPDB reputation: {abuseipdb_score}/100'
            ],
            'impact': 'Stops current attack immediately, prevents account compromise',
            'confidence': min(0.98, composite_risk.get('confidence', 90) / 100),
            'risk_if_ignored': 'HIGH - Account compromise likely within minutes',
            'action_type': 'block_ip',
            'action_data': {
                'ip': ip_address,
                'reason': f'Critical threat: {pattern} attack, AbuseIPDB {abuseipdb_score}/100',
                'duration': 'permanent'
            },
            'alternatives': [
                {
                    'action': 'Rate Limit Instead',
                    'impact': 'Slower mitigation, attack continues at reduced rate',
                    'when_to_use': 'If IP has some legitimate traffic mixed in'
                }
            ]
        })

    # High velocity brute force - Enable rate limiting
    if velocity > 10 or failed_attempts >= 20:
        subnet = get_subnet(ip_address)
        recommendations.append({
            'urgency': 'short_term' if overall_score < 85 else 'immediate',
            'priority': 'high',
            'action': 'Enable Rate Limiting',
            'reason': f'Prevent future attacks from subnet {subnet}',
            'why': [
                f'Current attack velocity: {velocity}/min',
                f'{failed_attempts} failed attempts detected',
                'Same subnet likely contains other compromised hosts',
                'Rate limiting prevents brute force escalation'
            ],
            'impact': f'Limits future attempts to 5 per minute from {subnet}',
            'confidence': min(0.94, 0.75 + (min(velocity, 30) / 30 * 0.19)),
            'risk_if_ignored': 'MEDIUM - Attack may resume or escalate',
            'recommended_config': {
                'max_attempts': 5,
                'time_window': '1 minute',
                'block_duration': '1 hour'
            },
            'action_type': 'rate_limit',
            'action_data': {
                'ip': ip_address,
                'subnet': subnet,
                'max_attempts': 5,
                'time_window': 60,
                'block_duration': 3600
            },
            'alternatives': [
                {
                    'action': 'Block Entire Subnet',
                    'impact': 'More aggressive, may block legitimate users in subnet',
                    'when_to_use': f'If entire {subnet} is known malicious'
                }
            ]
        })

    # Targeted accounts protection
    if unique_usernames >= 5:
        top_usernames = history.get('top_usernames', [])
        high_value_targets = [u['target_username'] for u in top_usernames if u['target_username'] in ['root', 'admin', 'administrator', 'postgres', 'mysql', 'oracle']][:3]

        if high_value_targets:
            recommendations.append({
                'urgency': 'short_term',
                'priority': 'high',
                'action': 'Protect Targeted Accounts',
                'reason': f'{len(high_value_targets)} high-value accounts under attack',
                'why': [
                    f'Accounts: {", ".join(high_value_targets)}',
                    'These accounts have elevated system privileges',
                    'Compromise would grant full system access',
                    f'{unique_usernames} total usernames targeted'
                ],
                'impact': 'Enables MFA and key-only auth for critical accounts',
                'confidence': 0.92,
                'risk_if_ignored': 'HIGH - Privileged account compromise',
                'affected_accounts': high_value_targets,
                'action_type': 'account_protection',
                'action_data': {
                    'accounts': high_value_targets,
                    'recommended_actions': ['Enable MFA', 'Require SSH keys', 'Disable password auth']
                },
                'alternatives': []
            })

    # ML anomaly detection
    if is_anomaly and ml_risk >= 60:
        recommendations.append({
            'urgency': 'short_term',
            'priority': 'high',
            'action': 'Create Alert Rule for Anomaly Pattern',
            'reason': f'ML detected {pattern} pattern with {ml_confidence*100:.0f}% confidence',
            'why': [
                f'ML risk score: {ml_risk}/100',
                f'Detection confidence: {ml_confidence*100:.0f}%',
                f'Pattern: {pattern}',
                'Early warning for similar future attacks'
            ],
            'impact': 'Auto-alerts on similar attack patterns before they escalate',
            'confidence': ml_confidence,
            'risk_if_ignored': 'MEDIUM - Future attacks may go undetected',
            'action_type': 'create_rule',
            'action_data': {
                'rule_type': 'ml_anomaly',
                'pattern': pattern,
                'threshold': 3,
                'window': '5m',
                'severity': 'high'
            },
            'alternatives': []
        })

    # TOR/Anonymization network policy
    if is_tor or is_proxy:
        network_type = 'Tor Exit Node' if is_tor else 'VPN/Proxy'
        recommendations.append({
            'urgency': 'long_term',
            'priority': 'medium',
            'action': f'Review {network_type} Access Policy',
            'reason': 'Traffic from anonymization network detected',
            'why': [
                f'Connection via {network_type}',
                '87% of SSH attacks originate from anonymization networks',
                'Legitimate users rarely access servers via Tor/VPN',
                'Creates attribution challenges for security teams'
            ],
            'impact': 'Blocks or requires additional auth for anonymized connections',
            'confidence': 0.95 if is_tor else 0.72,
            'risk_if_ignored': 'LOW - But creates ongoing blind spot',
            'action_type': 'geo_block',
            'action_data': {
                'network_type': network_type,
                'is_tor': is_tor,
                'country': country
            },
            'alternatives': [
                {
                    'action': 'Block All Tor/VPN',
                    'impact': 'Strongest security, may block legitimate privacy users',
                    'when_to_use': 'High-security production systems'
                },
                {
                    'action': 'Require Additional Auth',
                    'impact': 'MFA/2FA required for Tor/VPN connections',
                    'when_to_use': 'Balance security with user privacy'
                }
            ]
        })

    # VirusTotal detections
    if vt_positives >= 5:
        recommendations.append({
            'urgency': 'immediate' if vt_positives >= 10 else 'short_term',
            'priority': 'critical' if vt_positives >= 10 else 'high',
            'action': 'Add to Permanent Blocklist',
            'reason': f'Flagged by {vt_positives} security vendors',
            'why': [
                f'VirusTotal: {vt_positives}/{threat_intel.get("virustotal_total", 70)} vendors flagged',
                'IP associated with malware distribution',
                'Known malicious infrastructure',
                f'Also flagged by AbuseIPDB: {abuseipdb_score}/100'
            ],
            'impact': 'Permanent block, prevents all future access',
            'confidence': min(0.96, 0.70 + (vt_positives / 70 * 0.26)),
            'risk_if_ignored': 'HIGH - Known malicious IP remains accessible',
            'action_type': 'add_blocklist',
            'action_data': {
                'ip': ip_address,
                'reason': f'VirusTotal: {vt_positives} vendors flagged',
                'source': 'virustotal'
            },
            'alternatives': []
        })

    # Long-term hardening (if any attacks detected)
    if total_events >= 5 and overall_score >= 40:
        recommendations.append({
            'urgency': 'long_term',
            'priority': 'medium',
            'action': 'Strengthen SSH Authentication',
            'reason': 'Prevent future brute force and credential attacks',
            'why': [
                'Current configuration allows password-based authentication',
                'Brute force attacks can eventually succeed given enough time',
                'SSH keys provide cryptographic security',
                f'{failed_attempts} attacks already observed'
            ],
            'impact': 'Reduces brute force risk by 95%+',
            'confidence': 0.85,
            'risk_if_ignored': 'MEDIUM - Ongoing vulnerability to brute force',
            'recommended_changes': [
                'Disable password authentication (PasswordAuthentication no)',
                'Require SSH keys only (PubkeyAuthentication yes)',
                'Implement fail2ban or similar IDS',
                'Enable two-factor authentication where possible'
            ],
            'action_type': 'auth_hardening',
            'action_data': {
                'recommendations': ['disable_password_auth', 'require_ssh_keys', 'enable_fail2ban', 'enable_2fa']
            },
            'alternatives': []
        })

    # Low-risk baseline recommendation
    if overall_score < 30 and not recommendations:
        recommendations.append({
            'urgency': 'long_term',
            'priority': 'low',
            'action': 'Continue Monitoring',
            'reason': 'Low-risk activity detected - appears benign',
            'why': [
                f'Composite risk: {overall_score}/100 (Low)',
                f'Threat intel: {abuseipdb_score}/100 (Clean)',
                'No attack patterns detected',
                'Normal baseline activity'
            ],
            'impact': 'Maintain awareness without blocking legitimate activity',
            'confidence': 0.70,
            'risk_if_ignored': 'NONE - Low risk',
            'action_type': 'monitor',
            'action_data': None,
            'alternatives': []
        })

    # Sort by urgency first, then priority
    urgency_order = {'immediate': 0, 'short_term': 1, 'long_term': 2}
    priority_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}

    recommendations.sort(key=lambda x: (
        urgency_order.get(x.get('urgency', 'long_term'), 3),
        priority_order.get(x.get('priority', 'low'), 4)
    ))

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
