"""
SSH Guardian v3.0 - Rule Evaluators
Individual rule evaluation functions
"""

import sys
from pathlib import Path
from datetime import datetime, timedelta

# Add project paths
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
sys.path.append(str(PROJECT_ROOT / "dbs"))

from connection import get_connection


def evaluate_brute_force_rule(rule, ip_address):
    """
    Evaluate brute force rule: X failed attempts in Y minutes

    Rule conditions format:
    {
        "failed_attempts": 5,
        "time_window_minutes": 10,
        "event_type": "failed"
    }

    Returns:
        dict: {
            'should_block': bool,
            'reason': str,
            'failed_attempts': int,
            'trigger_event_id': int or None
        }
    """
    try:
        conditions = rule['conditions']

        # Get parameters from rule
        threshold = conditions.get('failed_attempts', 5)
        time_window = conditions.get('time_window_minutes', 10)
        event_type = conditions.get('event_type', 'failed')

        # Calculate time window
        cutoff_time = datetime.now() - timedelta(minutes=time_window)

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            # Count failed attempts in time window
            cursor.execute("""
                SELECT
                    COUNT(*) as attempt_count,
                    MAX(id) as latest_event_id
                FROM auth_events
                WHERE source_ip_text = %s
                AND event_type = %s
                AND timestamp >= %s
            """, (ip_address, event_type, cutoff_time))

            result = cursor.fetchone()
            attempt_count = result['attempt_count']
            latest_event_id = result['latest_event_id']

            if attempt_count >= threshold:
                return {
                    'should_block': True,
                    'reason': f"{attempt_count} {event_type} attempts in {time_window} minutes (threshold: {threshold})",
                    'failed_attempts': attempt_count,
                    'trigger_event_id': latest_event_id
                }

            return {
                'should_block': False,
                'reason': f"Only {attempt_count}/{threshold} attempts",
                'failed_attempts': attempt_count,
                'trigger_event_id': None
            }

        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        print(f"❌ Error evaluating brute force rule: {e}")
        return {
            'should_block': False,
            'reason': f"Error: {str(e)}",
            'failed_attempts': 0,
            'trigger_event_id': None
        }


def evaluate_threat_threshold_rule(rule, ip_address, event_type=None):
    """
    Evaluate threat-based rule: Block based on AbuseIPDB score tiers

    Rule conditions format:
    {
        "min_abuseipdb_score": 90,      # Direct AbuseIPDB score threshold
        "min_threat_level": "high",      # OR threat level threshold
        "min_confidence": 0.5,
        "require_failed_login": false,   # Only block on failed login
        "min_failed_attempts": 1,        # Minimum fails required
        "block_on_success": false        # Block even on successful login
    }

    Returns:
        dict: {
            'should_block': bool,
            'reason': str,
            'threat_level': str,
            'confidence': float,
            'abuseipdb_score': int
        }
    """
    try:
        conditions = rule['conditions']

        # Get parameters
        min_abuseipdb_score = conditions.get('min_abuseipdb_score')
        min_threat_level = conditions.get('min_threat_level', 'high')
        min_confidence = conditions.get('min_confidence', 0.5)
        require_failed_login = conditions.get('require_failed_login', False)
        min_failed_attempts = conditions.get('min_failed_attempts', 1)
        block_on_success = conditions.get('block_on_success', False)

        # Threat level priority
        threat_priority = {
            'clean': 0,
            'low': 1,
            'medium': 2,
            'high': 3,
            'critical': 4
        }

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            # Get threat intelligence for IP
            cursor.execute("""
                SELECT
                    overall_threat_level,
                    threat_confidence,
                    abuseipdb_score,
                    virustotal_positives
                FROM ip_threat_intelligence
                WHERE ip_address_text = %s
            """, (ip_address,))

            threat_data = cursor.fetchone()

            if not threat_data:
                return {
                    'should_block': False,
                    'reason': 'No threat intelligence data available',
                    'threat_level': None,
                    'confidence': 0,
                    'abuseipdb_score': 0
                }

            current_threat = threat_data['overall_threat_level'] or 'clean'
            current_confidence = float(threat_data['threat_confidence'] or 0)
            abuseipdb_score = int(threat_data['abuseipdb_score'] or 0)

            # Check if failed login requirement is met
            if require_failed_login or min_failed_attempts > 1:
                cursor.execute("""
                    SELECT COUNT(*) as fail_count
                    FROM auth_events
                    WHERE source_ip_text = %s
                    AND event_type = 'failed'
                    AND timestamp >= NOW() - INTERVAL 1 HOUR
                """, (ip_address,))
                fail_result = cursor.fetchone()
                fail_count = fail_result['fail_count'] if fail_result else 0

                if fail_count < min_failed_attempts:
                    return {
                        'should_block': False,
                        'reason': f"Only {fail_count}/{min_failed_attempts} failed attempts required",
                        'threat_level': current_threat,
                        'confidence': current_confidence,
                        'abuseipdb_score': abuseipdb_score
                    }

            # Check AbuseIPDB score threshold (NEW - tiered blocking)
            if min_abuseipdb_score is not None:
                if abuseipdb_score >= min_abuseipdb_score:
                    # For critical scores (90+), block even on success
                    if abuseipdb_score >= 90 or block_on_success or event_type == 'failed':
                        return {
                            'should_block': True,
                            'reason': f"AbuseIPDB score {abuseipdb_score} >= {min_abuseipdb_score} threshold",
                            'threat_level': current_threat,
                            'confidence': current_confidence,
                            'abuseipdb_score': abuseipdb_score
                        }

            # Check threat level threshold (legacy)
            if (threat_priority.get(current_threat, 0) >= threat_priority.get(min_threat_level, 0) and
                current_confidence >= min_confidence):

                return {
                    'should_block': True,
                    'reason': f"Threat level '{current_threat}' (confidence: {current_confidence:.2f}) exceeds threshold '{min_threat_level}'",
                    'threat_level': current_threat,
                    'confidence': current_confidence,
                    'abuseipdb_score': abuseipdb_score
                }

            return {
                'should_block': False,
                'reason': f"AbuseIPDB score {abuseipdb_score} below threshold, threat level '{current_threat}'",
                'threat_level': current_threat,
                'confidence': current_confidence,
                'abuseipdb_score': abuseipdb_score
            }

        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        print(f"Error evaluating threat threshold rule: {e}")
        return {
            'should_block': False,
            'reason': f"Error: {str(e)}",
            'threat_level': None,
            'confidence': 0,
            'abuseipdb_score': 0
        }


def evaluate_high_risk_country_rule(rule, ip_address):
    """
    Evaluate high-risk country rule: Block IPs from specified countries after N failed attempts

    Rule conditions format:
    {
        "countries": ["CN", "RU", "KP", "IR", "BY"],
        "min_failed_attempts": 2
    }
    """
    try:
        conditions = rule['conditions']
        blocked_countries = conditions.get('countries', ['CN', 'RU', 'KP', 'IR', 'BY'])
        min_failed_attempts = conditions.get('min_failed_attempts', 2)

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            # Get country code for IP
            cursor.execute("""
                SELECT country_code, country_name
                FROM ip_geolocation
                WHERE ip_address_text = %s
            """, (ip_address,))

            geo_data = cursor.fetchone()

            if not geo_data or not geo_data['country_code']:
                return {
                    'should_block': False,
                    'reason': 'No geolocation data available',
                    'country_code': None,
                    'failed_attempts': 0
                }

            country_code = geo_data['country_code']

            if country_code not in blocked_countries:
                return {
                    'should_block': False,
                    'reason': f"Country {country_code} not in high-risk list",
                    'country_code': country_code,
                    'failed_attempts': 0
                }

            # Country is high-risk, check failed attempts
            cursor.execute("""
                SELECT COUNT(*) as fail_count
                FROM auth_events
                WHERE source_ip_text = %s
                AND event_type = 'failed'
                AND timestamp >= NOW() - INTERVAL 1 HOUR
            """, (ip_address,))

            fail_result = cursor.fetchone()
            fail_count = fail_result['fail_count'] if fail_result else 0

            if fail_count >= min_failed_attempts:
                return {
                    'should_block': True,
                    'reason': f"High-risk country {country_code} ({geo_data['country_name']}) with {fail_count} failed attempts",
                    'country_code': country_code,
                    'failed_attempts': fail_count
                }

            return {
                'should_block': False,
                'reason': f"High-risk country {country_code} but only {fail_count}/{min_failed_attempts} failed attempts",
                'country_code': country_code,
                'failed_attempts': fail_count
            }

        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        print(f"Error evaluating high-risk country rule: {e}")
        return {
            'should_block': False,
            'reason': f"Error: {str(e)}",
            'country_code': None,
            'failed_attempts': 0
        }


def evaluate_repeat_offender_rule(rule, ip_address):
    """
    Evaluate repeat offender rule: Escalate block duration for repeat offenders

    Rule conditions format:
    {
        "escalation": {
            "2": 2,       # 2nd offense = 2x duration
            "3": 10080,   # 3rd offense = 7 days fixed
            "4": 43200    # 4th+ offense = 30 days fixed
        }
    }

    Returns:
        dict: {
            'should_block': bool,
            'reason': str,
            'offense_count': int,
            'duration_multiplier': float,
            'fixed_duration': int or None
        }
    """
    try:
        conditions = rule['conditions']
        escalation = conditions.get('escalation', {'2': 2, '3': 10080, '4': 43200})

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            # Count previous blocks for this IP
            cursor.execute("""
                SELECT COUNT(*) as block_count
                FROM ip_blocks
                WHERE ip_address_text = %s
            """, (ip_address,))

            result = cursor.fetchone()
            previous_blocks = result['block_count'] if result else 0

            # Current offense number (this would be the next one)
            offense_number = previous_blocks + 1

            # Check escalation rules
            duration_multiplier = 1.0
            fixed_duration = None

            if str(offense_number) in escalation:
                value = escalation[str(offense_number)]
                if value > 100:  # Fixed duration in minutes
                    fixed_duration = value
                else:  # Multiplier
                    duration_multiplier = value
            elif offense_number >= 4:
                # 4th+ offense uses the "4" rule
                fixed_duration = escalation.get('4', 43200)

            return {
                'should_block': False,  # This rule doesn't trigger blocks, just modifies duration
                'reason': f"Offense #{offense_number}, multiplier={duration_multiplier}, fixed={fixed_duration}",
                'offense_count': offense_number,
                'duration_multiplier': duration_multiplier,
                'fixed_duration': fixed_duration
            }

        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        print(f"Error evaluating repeat offender rule: {e}")
        return {
            'should_block': False,
            'reason': f"Error: {str(e)}",
            'offense_count': 1,
            'duration_multiplier': 1.0,
            'fixed_duration': None
        }


def get_repeat_offender_duration(ip_address, base_duration):
    """
    Get adjusted block duration based on repeat offender status

    Args:
        ip_address: IP to check
        base_duration: Base duration in minutes from the rule

    Returns:
        int: Adjusted duration in minutes
    """
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            # Count previous blocks
            cursor.execute("""
                SELECT COUNT(*) as block_count
                FROM ip_blocks
                WHERE ip_address_text = %s
            """, (ip_address,))

            result = cursor.fetchone()
            previous_blocks = result['block_count'] if result else 0
            offense_number = previous_blocks + 1

            # Escalation rules (2nd = 2x, 3rd = 7 days, 4th+ = 30 days)
            if offense_number == 1:
                return base_duration
            elif offense_number == 2:
                return base_duration * 2
            elif offense_number == 3:
                return 10080  # 7 days
            else:
                return 43200  # 30 days

        finally:
            cursor.close()
            conn.close()

    except Exception:
        return base_duration
