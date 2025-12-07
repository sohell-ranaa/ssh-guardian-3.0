"""
SSH Guardian v3.0 - Threat Combo Evaluator
Evaluates combined threat signals for blocking decisions
"""

import sys
from pathlib import Path

# Add project paths
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
sys.path.append(str(PROJECT_ROOT / "dbs"))

from connection import get_connection


def evaluate_threat_combo_rule(rule, ip_address, event_type=None):
    """
    Evaluate combined threat signals rule.

    Rule conditions:
    {
        "min_abuseipdb_score": 50,       # AbuseIPDB threshold
        "min_virustotal_positives": 5,   # VirusTotal threshold
        "min_shodan_vulns": 3,           # Shodan vulnerabilities threshold
        "is_tor": true,                  # Require Tor exit
        "is_proxy": true,                # Require proxy/VPN
        "require_failed_login": true     # Require failed login
    }

    Returns:
        dict: {
            'triggered': bool,
            'reason': str,
            'combo_factors': list,
            'abuseipdb_score': int,
            'virustotal_positives': int,
            'shodan_vulns': int
        }
    """
    try:
        conditions = rule['conditions']

        # Get thresholds
        min_abuseipdb = conditions.get('min_abuseipdb_score')
        min_vt = conditions.get('min_virustotal_positives')
        min_shodan = conditions.get('min_shodan_vulns')
        require_tor = conditions.get('is_tor', False)
        require_proxy = conditions.get('is_proxy', False)
        require_failed = conditions.get('require_failed_login', False)

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            # Get threat intelligence data
            cursor.execute("""
                SELECT abuseipdb_score, virustotal_positives, shodan_vulns
                FROM ip_threat_intelligence
                WHERE ip_address_text = %s
            """, (ip_address,))

            threat_data = cursor.fetchone()
            abuseipdb_score = int(threat_data['abuseipdb_score'] or 0) if threat_data else 0
            vt_positives = int(threat_data['virustotal_positives'] or 0) if threat_data else 0

            # Parse Shodan vulns (stored as JSON)
            shodan_vulns = 0
            if threat_data and threat_data.get('shodan_vulns'):
                try:
                    import json
                    vulns = json.loads(threat_data['shodan_vulns'])
                    shodan_vulns = len(vulns) if isinstance(vulns, list) else 0
                except:
                    shodan_vulns = 0

            # Get geo flags
            cursor.execute("""
                SELECT is_tor, is_proxy, is_vpn
                FROM ip_geolocation
                WHERE ip_address_text = %s
            """, (ip_address,))

            geo_data = cursor.fetchone()
            is_tor = geo_data and geo_data.get('is_tor', False)
            is_proxy = geo_data and (geo_data.get('is_proxy', False) or geo_data.get('is_vpn', False))

            # Check failed login if required
            if require_failed:
                if event_type != 'failed':
                    cursor.execute("""
                        SELECT COUNT(*) as fail_count
                        FROM auth_events
                        WHERE source_ip_text = %s
                        AND event_type = 'failed'
                        AND timestamp >= NOW() - INTERVAL 1 HOUR
                    """, (ip_address,))
                    result = cursor.fetchone()
                    if (result['fail_count'] or 0) == 0:
                        return {
                            'triggered': False,
                            'reason': 'No failed login attempts (required for combo rule)',
                            'combo_factors': [],
                            'abuseipdb_score': abuseipdb_score,
                            'virustotal_positives': vt_positives,
                            'shodan_vulns': shodan_vulns
                        }

            # Check combo conditions
            combo_factors = []
            all_conditions_met = True

            # AbuseIPDB check
            if min_abuseipdb is not None:
                if abuseipdb_score >= min_abuseipdb:
                    combo_factors.append(f"AbuseIPDB:{abuseipdb_score}")
                else:
                    all_conditions_met = False

            # VirusTotal check
            if min_vt is not None:
                if vt_positives >= min_vt:
                    combo_factors.append(f"VirusTotal:{vt_positives}")
                else:
                    all_conditions_met = False

            # Shodan check
            if min_shodan is not None:
                if shodan_vulns >= min_shodan:
                    combo_factors.append(f"Shodan:{shodan_vulns}vulns")
                else:
                    all_conditions_met = False

            # Tor check
            if require_tor:
                if is_tor:
                    combo_factors.append("Tor")
                else:
                    all_conditions_met = False

            # Proxy check
            if require_proxy:
                if is_proxy:
                    combo_factors.append("Proxy/VPN")
                else:
                    all_conditions_met = False

            if all_conditions_met and combo_factors:
                return {
                    'triggered': True,
                    'reason': f"Threat combo detected: {' + '.join(combo_factors)}",
                    'combo_factors': combo_factors,
                    'abuseipdb_score': abuseipdb_score,
                    'virustotal_positives': vt_positives,
                    'shodan_vulns': shodan_vulns
                }

            return {
                'triggered': False,
                'reason': f"Combo conditions not met. Present: {combo_factors}",
                'combo_factors': combo_factors,
                'abuseipdb_score': abuseipdb_score,
                'virustotal_positives': vt_positives,
                'shodan_vulns': shodan_vulns
            }

        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        print(f"Error evaluating threat combo rule: {e}")
        return {
            'triggered': False,
            'reason': f"Error: {str(e)}",
            'combo_factors': [],
            'abuseipdb_score': 0,
            'virustotal_positives': 0,
            'shodan_vulns': 0
        }


def evaluate_virustotal_rule(rule, ip_address):
    """
    Evaluate VirusTotal-only rule.

    Rule conditions:
    {
        "min_virustotal_positives": 5
    }
    """
    try:
        conditions = rule['conditions']
        min_positives = conditions.get('min_virustotal_positives', 5)

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            cursor.execute("""
                SELECT virustotal_positives
                FROM ip_threat_intelligence
                WHERE ip_address_text = %s
            """, (ip_address,))

            threat_data = cursor.fetchone()
            vt_positives = int(threat_data['virustotal_positives'] or 0) if threat_data else 0

            if vt_positives >= min_positives:
                return {
                    'triggered': True,
                    'reason': f"VirusTotal detected {vt_positives} security vendors flagged this IP",
                    'virustotal_positives': vt_positives
                }

            return {
                'triggered': False,
                'reason': f"VirusTotal: only {vt_positives}/{min_positives} positives",
                'virustotal_positives': vt_positives
            }

        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        print(f"Error evaluating VirusTotal rule: {e}")
        return {
            'triggered': False,
            'reason': f"Error: {str(e)}",
            'virustotal_positives': 0
        }


def evaluate_shodan_rule(rule, ip_address, event_type=None):
    """
    Evaluate Shodan vulnerabilities rule.

    Rule conditions:
    {
        "min_shodan_vulns": 3,
        "require_failed_login": true
    }
    """
    try:
        conditions = rule['conditions']
        min_vulns = conditions.get('min_shodan_vulns', 3)
        require_failed = conditions.get('require_failed_login', False)

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            cursor.execute("""
                SELECT shodan_vulns
                FROM ip_threat_intelligence
                WHERE ip_address_text = %s
            """, (ip_address,))

            threat_data = cursor.fetchone()

            # Parse Shodan vulns
            shodan_vulns = 0
            if threat_data and threat_data.get('shodan_vulns'):
                try:
                    import json
                    vulns = json.loads(threat_data['shodan_vulns'])
                    shodan_vulns = len(vulns) if isinstance(vulns, list) else 0
                except:
                    shodan_vulns = 0

            if shodan_vulns < min_vulns:
                return {
                    'triggered': False,
                    'reason': f"Shodan: only {shodan_vulns}/{min_vulns} vulnerabilities",
                    'shodan_vulns': shodan_vulns
                }

            # Check failed login if required
            if require_failed:
                if event_type != 'failed':
                    cursor.execute("""
                        SELECT COUNT(*) as fail_count
                        FROM auth_events
                        WHERE source_ip_text = %s
                        AND event_type = 'failed'
                        AND timestamp >= NOW() - INTERVAL 1 HOUR
                    """, (ip_address,))
                    result = cursor.fetchone()
                    if (result['fail_count'] or 0) == 0:
                        return {
                            'triggered': False,
                            'reason': f"Shodan: {shodan_vulns} vulns but no failed login",
                            'shodan_vulns': shodan_vulns
                        }

            return {
                'triggered': True,
                'reason': f"Shodan detected {shodan_vulns} known vulnerabilities on source IP",
                'shodan_vulns': shodan_vulns
            }

        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        print(f"Error evaluating Shodan rule: {e}")
        return {
            'triggered': False,
            'reason': f"Error: {str(e)}",
            'shodan_vulns': 0
        }
