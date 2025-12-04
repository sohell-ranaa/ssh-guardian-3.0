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


def evaluate_threat_threshold_rule(rule, ip_address):
    """
    Evaluate threat-based rule: Block if threat level >= threshold

    Rule conditions format:
    {
        "min_threat_level": "high",  # clean, low, medium, high, critical
        "min_confidence": 0.5,
        "sources": ["abuseipdb", "virustotal", "shodan"]
    }

    Returns:
        dict: {
            'should_block': bool,
            'reason': str,
            'threat_level': str,
            'confidence': float
        }
    """
    try:
        conditions = rule['conditions']

        # Get threat level threshold
        min_threat_level = conditions.get('min_threat_level', 'high')
        min_confidence = conditions.get('min_confidence', 0.5)

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

            if not threat_data or not threat_data['overall_threat_level']:
                return {
                    'should_block': False,
                    'reason': 'No threat intelligence data available',
                    'threat_level': None,
                    'confidence': 0
                }

            current_threat = threat_data['overall_threat_level']
            current_confidence = float(threat_data['threat_confidence'] or 0)

            # Check if threat level meets threshold
            if (threat_priority.get(current_threat, 0) >= threat_priority.get(min_threat_level, 0) and
                current_confidence >= min_confidence):

                return {
                    'should_block': True,
                    'reason': f"Threat level '{current_threat}' (confidence: {current_confidence:.2f}) exceeds threshold '{min_threat_level}'",
                    'threat_level': current_threat,
                    'confidence': current_confidence
                }

            return {
                'should_block': False,
                'reason': f"Threat level '{current_threat}' below threshold '{min_threat_level}'",
                'threat_level': current_threat,
                'confidence': current_confidence
            }

        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        print(f"❌ Error evaluating threat threshold rule: {e}")
        return {
            'should_block': False,
            'reason': f"Error: {str(e)}",
            'threat_level': None,
            'confidence': 0
        }
