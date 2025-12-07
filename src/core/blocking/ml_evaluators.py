"""
SSH Guardian v3.0 - ML-Specific Rule Evaluators
Machine Learning and behavioral analysis rule evaluation functions
"""

import sys
from pathlib import Path

# Add project paths
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
sys.path.append(str(PROJECT_ROOT / "dbs"))

from connection import get_connection


def evaluate_ml_threshold_rule(rule, ip_address, ml_result):
    """Evaluate ML threshold rule against ML prediction result.

    Rule conditions: min_risk_score, min_confidence, threat_types, requires_approval
    ML result: risk_score, confidence, threat_type, is_anomaly
    Returns: triggered, reason, requires_approval, risk_score, confidence
    """
    try:
        conditions = rule['conditions']
        min_risk_score = conditions.get('min_risk_score', 50)
        min_confidence = conditions.get('min_confidence', 0.5)
        threat_types = conditions.get('threat_types', [])
        requires_approval = conditions.get('requires_approval', False)

        risk_score = ml_result.get('risk_score', 0)
        confidence = ml_result.get('confidence', 0.0)
        threat_type = ml_result.get('threat_type', '')

        if risk_score < min_risk_score:
            return {'triggered': False, 'reason': f"Risk score {risk_score} below threshold {min_risk_score}",
                    'requires_approval': False, 'risk_score': risk_score, 'confidence': confidence}

        if confidence < min_confidence:
            return {'triggered': False, 'reason': f"Confidence {confidence:.2f} below threshold {min_confidence}",
                    'requires_approval': False, 'risk_score': risk_score, 'confidence': confidence}

        if threat_types and threat_type not in threat_types:
            return {'triggered': False, 'reason': f"Threat type '{threat_type}' not in allowed types",
                    'requires_approval': False, 'risk_score': risk_score, 'confidence': confidence}

        reason = f"ML detected risk score {risk_score} (confidence: {confidence:.2f})"
        if threat_type:
            reason += f", threat type: {threat_type}"

        return {'triggered': True, 'reason': reason, 'requires_approval': requires_approval,
                'risk_score': risk_score, 'confidence': confidence}

    except Exception as e:
        print(f"Error evaluating ML threshold rule: {e}")
        return {'triggered': False, 'reason': f"Error: {str(e)}", 'requires_approval': False,
                'risk_score': 0, 'confidence': 0.0}


def evaluate_credential_stuffing_rule(rule, ip_address):
    """Evaluate credential stuffing (same IP, many different usernames).

    Rule conditions: unique_usernames, time_window_minutes, requires_approval
    Returns: triggered, reason, requires_approval, unique_usernames, time_window
    """
    try:
        conditions = rule['conditions']
        threshold = conditions.get('unique_usernames', 10)
        time_window = conditions.get('time_window_minutes', 60)
        requires_approval = conditions.get('requires_approval', False)

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            cursor.execute("""
                SELECT COUNT(DISTINCT target_username) as unique_count
                FROM auth_events
                WHERE source_ip_text = %s
                AND event_type = 'failed'
                AND timestamp >= NOW() - INTERVAL %s MINUTE
            """, (ip_address, time_window))

            result = cursor.fetchone()
            unique_count = result['unique_count'] or 0

            if unique_count >= threshold:
                return {'triggered': True,
                        'reason': f"Credential stuffing detected: {unique_count} unique usernames in {time_window} minutes (threshold: {threshold})",
                        'requires_approval': requires_approval, 'unique_usernames': unique_count, 'time_window': time_window}

            return {'triggered': False, 'reason': f"Only {unique_count}/{threshold} unique usernames",
                    'requires_approval': False, 'unique_usernames': unique_count, 'time_window': time_window}

        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        print(f"Error evaluating credential stuffing rule: {e}")
        return {'triggered': False, 'reason': f"Error: {str(e)}", 'requires_approval': False,
                'unique_usernames': 0, 'time_window': 0}


def evaluate_anomaly_pattern_rule(rule, ip_address, ml_result):
    """Evaluate anomaly pattern rule.

    Rule conditions: anomaly_types (geo/time/velocity), min_confidence, requires_approval
    ML result: is_anomaly, anomaly_reasons, confidence
    Returns: triggered, reason, requires_approval, anomaly_types_matched
    """
    try:
        conditions = rule['conditions']
        required_anomaly_types = conditions.get('anomaly_types', [])
        min_confidence = conditions.get('min_confidence', 0.5)
        requires_approval = conditions.get('requires_approval', False)

        is_anomaly = ml_result.get('is_anomaly', False)
        anomaly_reasons = ml_result.get('anomaly_reasons', [])
        confidence = ml_result.get('confidence', 0.0)

        if not is_anomaly:
            return {'triggered': False, 'reason': 'No anomaly detected',
                    'requires_approval': False, 'anomaly_types_matched': []}

        if confidence < min_confidence:
            return {'triggered': False, 'reason': f"Anomaly confidence {confidence:.2f} below threshold {min_confidence}",
                    'requires_approval': False, 'anomaly_types_matched': []}

        if required_anomaly_types:
            matched_types = [atype for atype in anomaly_reasons if atype in required_anomaly_types]
            if not matched_types:
                return {'triggered': False, 'reason': f"Anomaly types {anomaly_reasons} do not match required types",
                        'requires_approval': False, 'anomaly_types_matched': []}

            return {'triggered': True, 'reason': f"Anomaly patterns detected: {', '.join(matched_types)} (confidence: {confidence:.2f})",
                    'requires_approval': requires_approval, 'anomaly_types_matched': matched_types}

        return {'triggered': True, 'reason': f"Anomaly detected: {', '.join(anomaly_reasons)} (confidence: {confidence:.2f})",
                'requires_approval': requires_approval, 'anomaly_types_matched': anomaly_reasons}

    except Exception as e:
        print(f"Error evaluating anomaly pattern rule: {e}")
        return {'triggered': False, 'reason': f"Error: {str(e)}",
                'requires_approval': False, 'anomaly_types_matched': []}


def evaluate_velocity_rule(rule, ip_address):
    """Evaluate velocity rule (too many events in short time) - DDoS detection.

    Rule conditions: max_events, time_window_seconds, requires_approval
    Returns: triggered, reason, requires_approval, event_count
    """
    try:
        conditions = rule['conditions']
        max_events = conditions.get('max_events', 20)  # Lowered default to 20 (aggressive)
        time_window = conditions.get('time_window_seconds', 60)
        requires_approval = conditions.get('requires_approval', False)

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            cursor.execute("""
                SELECT COUNT(*) as event_count
                FROM auth_events
                WHERE source_ip_text = %s
                AND timestamp >= NOW() - INTERVAL %s SECOND
            """, (ip_address, time_window))

            result = cursor.fetchone()
            event_count = result['event_count'] or 0

            if event_count >= max_events:
                return {'triggered': True,
                        'reason': f"DDoS/Velocity attack: {event_count} events in {time_window} seconds (limit: {max_events})",
                        'requires_approval': requires_approval, 'event_count': event_count}

            return {'triggered': False, 'reason': f"Only {event_count}/{max_events} events",
                    'requires_approval': False, 'event_count': event_count}

        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        print(f"Error evaluating velocity rule: {e}")
        return {'triggered': False, 'reason': f"Error: {str(e)}",
                'requires_approval': False, 'event_count': 0}


def evaluate_tor_detection_rule(rule, ip_address, event_type=None):
    """Evaluate Tor exit node detection rule.

    Rule conditions: is_tor, require_failed_login
    Returns: triggered, reason, is_tor
    """
    try:
        conditions = rule['conditions']
        require_failed_login = conditions.get('require_failed_login', True)

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            # Check if IP is Tor exit node
            cursor.execute("""
                SELECT is_tor
                FROM ip_geolocation
                WHERE ip_address_text = %s
            """, (ip_address,))

            geo_data = cursor.fetchone()
            is_tor = geo_data and geo_data.get('is_tor', False)

            if not is_tor:
                return {'triggered': False, 'reason': 'Not a Tor exit node',
                        'is_tor': False}

            # IP is Tor, check if failed login required
            if require_failed_login:
                if event_type != 'failed':
                    # Check recent failed logins
                    cursor.execute("""
                        SELECT COUNT(*) as fail_count
                        FROM auth_events
                        WHERE source_ip_text = %s
                        AND event_type = 'failed'
                        AND timestamp >= NOW() - INTERVAL 1 HOUR
                    """, (ip_address,))
                    result = cursor.fetchone()
                    if (result['fail_count'] or 0) == 0:
                        return {'triggered': False,
                                'reason': 'Tor exit but no failed login attempts',
                                'is_tor': True}

            return {'triggered': True,
                    'reason': f"Tor exit node detected with {'failed' if require_failed_login else 'any'} login attempt",
                    'is_tor': True}

        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        print(f"Error evaluating Tor detection rule: {e}")
        return {'triggered': False, 'reason': f"Error: {str(e)}", 'is_tor': False}


def evaluate_proxy_detection_rule(rule, ip_address):
    """Evaluate VPN/Proxy/Datacenter detection rule.

    Rule conditions: is_proxy_or_vpn, min_abuseipdb_score
    Returns: triggered, reason, is_proxy, is_vpn, is_datacenter, abuseipdb_score
    """
    try:
        conditions = rule['conditions']
        min_abuseipdb_score = conditions.get('min_abuseipdb_score', 30)

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            # Check geo flags
            cursor.execute("""
                SELECT is_proxy, is_vpn, is_datacenter
                FROM ip_geolocation
                WHERE ip_address_text = %s
            """, (ip_address,))

            geo_data = cursor.fetchone()
            is_proxy = geo_data and geo_data.get('is_proxy', False)
            is_vpn = geo_data and geo_data.get('is_vpn', False)
            is_datacenter = geo_data and geo_data.get('is_datacenter', False)

            if not (is_proxy or is_vpn or is_datacenter):
                return {'triggered': False, 'reason': 'Not a proxy/VPN/datacenter',
                        'is_proxy': False, 'is_vpn': False, 'is_datacenter': False, 'abuseipdb_score': 0}

            # Check AbuseIPDB score
            cursor.execute("""
                SELECT abuseipdb_score
                FROM ip_threat_intelligence
                WHERE ip_address_text = %s
            """, (ip_address,))

            threat_data = cursor.fetchone()
            abuseipdb_score = int(threat_data['abuseipdb_score'] or 0) if threat_data else 0

            if abuseipdb_score < min_abuseipdb_score:
                return {'triggered': False,
                        'reason': f"VPN/Proxy detected but AbuseIPDB score {abuseipdb_score} < {min_abuseipdb_score}",
                        'is_proxy': is_proxy, 'is_vpn': is_vpn, 'is_datacenter': is_datacenter,
                        'abuseipdb_score': abuseipdb_score}

            proxy_type = []
            if is_proxy:
                proxy_type.append('Proxy')
            if is_vpn:
                proxy_type.append('VPN')
            if is_datacenter:
                proxy_type.append('Datacenter')

            return {'triggered': True,
                    'reason': f"{'/'.join(proxy_type)} detected with AbuseIPDB score {abuseipdb_score}",
                    'is_proxy': is_proxy, 'is_vpn': is_vpn, 'is_datacenter': is_datacenter,
                    'abuseipdb_score': abuseipdb_score}

        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        print(f"Error evaluating proxy detection rule: {e}")
        return {'triggered': False, 'reason': f"Error: {str(e)}",
                'is_proxy': False, 'is_vpn': False, 'is_datacenter': False, 'abuseipdb_score': 0}


def evaluate_impossible_travel_rule(rule, ip_address, username=None):
    """Evaluate impossible travel detection rule.

    Rule conditions: max_distance_km, time_window_hours
    Returns: triggered, reason, distance_km, time_diff_hours
    """
    import math

    def haversine_distance(lat1, lon1, lat2, lon2):
        """Calculate distance between two points in km."""
        R = 6371  # Earth's radius in km
        lat1, lon1, lat2, lon2 = map(math.radians, [lat1, lon1, lat2, lon2])
        dlat = lat2 - lat1
        dlon = lon2 - lon1
        a = math.sin(dlat/2)**2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon/2)**2
        c = 2 * math.asin(math.sqrt(a))
        return R * c

    try:
        conditions = rule['conditions']
        max_distance_km = conditions.get('max_distance_km', 1000)
        time_window_hours = conditions.get('time_window_hours', 2)

        if not username:
            return {'triggered': False, 'reason': 'No username provided for travel check',
                    'distance_km': 0, 'time_diff_hours': 0}

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            # Get current location
            cursor.execute("""
                SELECT g.latitude, g.longitude, g.country_code, g.city
                FROM ip_geolocation g
                WHERE g.ip_address_text = %s
            """, (ip_address,))

            current_geo = cursor.fetchone()
            if not current_geo or not current_geo['latitude'] or not current_geo['longitude']:
                return {'triggered': False, 'reason': 'No current location data',
                        'distance_km': 0, 'time_diff_hours': 0}

            # Get user's last known location from baseline
            cursor.execute("""
                SELECT last_latitude, last_longitude, last_country_code, last_city, last_login_at
                FROM user_login_baselines
                WHERE username = %s
            """, (username,))

            baseline = cursor.fetchone()

            if not baseline or not baseline['last_latitude'] or not baseline['last_longitude']:
                # No baseline, create one
                cursor.execute("""
                    INSERT INTO user_login_baselines
                    (username, last_latitude, last_longitude, last_country_code, last_city, last_ip_text, last_login_at, login_count)
                    VALUES (%s, %s, %s, %s, %s, %s, NOW(), 1)
                    ON DUPLICATE KEY UPDATE
                        last_latitude = VALUES(last_latitude),
                        last_longitude = VALUES(last_longitude),
                        last_country_code = VALUES(last_country_code),
                        last_city = VALUES(last_city),
                        last_ip_text = VALUES(last_ip_text),
                        last_login_at = NOW(),
                        login_count = login_count + 1
                """, (username, current_geo['latitude'], current_geo['longitude'],
                      current_geo['country_code'], current_geo['city'], ip_address))
                conn.commit()

                return {'triggered': False, 'reason': 'First login for user - baseline created',
                        'distance_km': 0, 'time_diff_hours': 0}

            # Calculate distance
            distance_km = haversine_distance(
                float(baseline['last_latitude']), float(baseline['last_longitude']),
                float(current_geo['latitude']), float(current_geo['longitude'])
            )

            # Calculate time difference
            from datetime import datetime
            last_login = baseline['last_login_at']
            if last_login:
                time_diff = datetime.now() - last_login
                time_diff_hours = time_diff.total_seconds() / 3600
            else:
                time_diff_hours = 999  # No previous time

            # Update baseline with new location
            cursor.execute("""
                UPDATE user_login_baselines
                SET last_latitude = %s, last_longitude = %s, last_country_code = %s,
                    last_city = %s, last_ip_text = %s, last_login_at = NOW(), login_count = login_count + 1
                WHERE username = %s
            """, (current_geo['latitude'], current_geo['longitude'],
                  current_geo['country_code'], current_geo['city'], ip_address, username))
            conn.commit()

            # Check if impossible travel
            if distance_km > max_distance_km and time_diff_hours < time_window_hours:
                return {'triggered': True,
                        'reason': f"Impossible travel: {distance_km:.0f}km in {time_diff_hours:.1f}h "
                                  f"(from {baseline['last_city']}/{baseline['last_country_code']} "
                                  f"to {current_geo['city']}/{current_geo['country_code']})",
                        'distance_km': distance_km, 'time_diff_hours': time_diff_hours}

            return {'triggered': False,
                    'reason': f"Travel OK: {distance_km:.0f}km in {time_diff_hours:.1f}h",
                    'distance_km': distance_km, 'time_diff_hours': time_diff_hours}

        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        print(f"Error evaluating impossible travel rule: {e}")
        return {'triggered': False, 'reason': f"Error: {str(e)}",
                'distance_km': 0, 'time_diff_hours': 0}
