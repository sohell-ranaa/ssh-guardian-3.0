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

    Rule conditions: min_risk_score, min_confidence, threat_types, requires_approval, min_failed_attempts
    ML result: risk_score, confidence, threat_type, is_anomaly
    Returns: triggered, reason, requires_approval, risk_score, confidence
    """
    try:
        conditions = rule['conditions']
        min_risk_score = conditions.get('min_risk_score', 50)
        min_confidence = conditions.get('min_confidence', 0.5)
        threat_types = conditions.get('threat_types', [])
        requires_approval = conditions.get('requires_approval', False)
        min_failed_attempts = conditions.get('min_failed_attempts', 1)  # Default 1 for backwards compat

        risk_score = ml_result.get('risk_score', 0)
        confidence = ml_result.get('confidence', 0.0)
        threat_type = ml_result.get('threat_type', '')

        # Check minimum failed attempts requirement
        if min_failed_attempts > 1:
            conn = get_connection()
            cursor = conn.cursor(dictionary=True)
            try:
                cursor.execute("""
                    SELECT COUNT(*) as fail_count
                    FROM auth_events
                    WHERE source_ip_text = %s
                    AND event_type = 'failed'
                    AND timestamp >= NOW() - INTERVAL 24 HOUR
                """, (ip_address,))
                result = cursor.fetchone()
                fail_count = result['fail_count'] or 0

                if fail_count < min_failed_attempts:
                    return {'triggered': False,
                            'reason': f"Only {fail_count}/{min_failed_attempts} failed attempts (minimum not met)",
                            'requires_approval': False, 'risk_score': risk_score, 'confidence': confidence}
            finally:
                cursor.close()
                conn.close()

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

    Rule conditions:
        - unique_usernames: Minimum unique usernames to trigger (default 10)
        - time_window_minutes: Time window to check (default 60)
        - event_type: Filter by event type - 'failed', 'successful', or None for both (default None)
        - max_abuseipdb_score: Only trigger for clean IPs with score <= this value (default None = no filter)
        - off_hours: If true, only trigger during off-hours (default False)
        - requires_approval: Whether to require manual approval

    Returns: triggered, reason, requires_approval, unique_usernames, time_window
    """
    from datetime import datetime

    try:
        conditions = rule['conditions']
        threshold = conditions.get('unique_usernames', 10)
        time_window = conditions.get('time_window_minutes', 60)
        requires_approval = conditions.get('requires_approval', False)
        event_type_filter = conditions.get('event_type')  # 'failed', 'successful', or None
        max_abuse_score = conditions.get('max_abuseipdb_score')
        check_off_hours = conditions.get('off_hours', False)

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            # Check max_abuseipdb_score filter (for "clean IP only" rules)
            if max_abuse_score is not None:
                cursor.execute("""
                    SELECT abuseipdb_score FROM ip_threat_intelligence
                    WHERE ip_address_text = %s
                    ORDER BY last_seen DESC LIMIT 1
                """, (ip_address,))
                threat_row = cursor.fetchone()
                ip_abuse_score = threat_row['abuseipdb_score'] if threat_row and threat_row['abuseipdb_score'] else 0

                if ip_abuse_score > max_abuse_score:
                    return {
                        'triggered': False,
                        'reason': f"IP AbuseIPDB score ({ip_abuse_score}) exceeds max ({max_abuse_score}) - handled by bad-IP rules",
                        'requires_approval': False,
                        'unique_usernames': 0,
                        'time_window': time_window
                    }

            # Check off-hours filter
            if check_off_hours:
                now = datetime.now()
                current_hour = now.hour
                # Off-hours = before 6 AM or after 10 PM
                is_off_hours = current_hour < 6 or current_hour >= 22
                if not is_off_hours:
                    return {
                        'triggered': False,
                        'reason': f"Current time ({current_hour}:00) is during business hours - off_hours filter not met",
                        'requires_approval': False,
                        'unique_usernames': 0,
                        'time_window': time_window
                    }

            # Build query based on event_type filter
            if event_type_filter:
                cursor.execute("""
                    SELECT COUNT(DISTINCT target_username) as unique_count
                    FROM auth_events
                    WHERE source_ip_text = %s
                    AND event_type = %s
                    AND timestamp >= NOW() - INTERVAL %s MINUTE
                """, (ip_address, event_type_filter, time_window))
            else:
                # Count all events (both failed and successful)
                cursor.execute("""
                    SELECT COUNT(DISTINCT target_username) as unique_count
                    FROM auth_events
                    WHERE source_ip_text = %s
                    AND timestamp >= NOW() - INTERVAL %s MINUTE
                """, (ip_address, time_window))

            result = cursor.fetchone()
            unique_count = result['unique_count'] or 0

            if unique_count >= threshold:
                event_desc = f" ({event_type_filter} only)" if event_type_filter else ""
                off_hours_desc = " during off-hours" if check_off_hours else ""
                return {
                    'triggered': True,
                    'reason': f"Multi-user activity detected: {unique_count} unique usernames{event_desc}{off_hours_desc} in {time_window} minutes (threshold: {threshold})",
                    'requires_approval': requires_approval,
                    'unique_usernames': unique_count,
                    'time_window': time_window
                }

            return {
                'triggered': False,
                'reason': f"Only {unique_count}/{threshold} unique usernames",
                'requires_approval': False,
                'unique_usernames': unique_count,
                'time_window': time_window
            }

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


def evaluate_distributed_brute_force_rule(rule, ip_address, agent_id=None):
    """Evaluate distributed brute force (same server, many IPs, many usernames, slow frequency).

    This detects coordinated attacks where many different IPs try different usernames
    against the same server with slow frequency to avoid traditional rate limiting.

    Rule conditions:
        - unique_ips_threshold: Minimum unique IPs (default 5)
        - unique_usernames_threshold: Minimum unique usernames (default 10)
        - time_window_minutes: Time window to analyze (default 60)
        - max_attempts_per_ip: Max attempts per IP (slow = low number, default 3)
        - requires_approval: Whether to require manual approval

    Returns: triggered, reason, unique_ips, unique_usernames, pattern_score
    """
    try:
        conditions = rule['conditions']
        unique_ips_threshold = conditions.get('unique_ips_threshold', 5)
        unique_usernames_threshold = conditions.get('unique_usernames_threshold', 10)
        time_window = conditions.get('time_window_minutes', 60)
        max_attempts_per_ip = conditions.get('max_attempts_per_ip', 3)
        requires_approval = conditions.get('requires_approval', False)

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            # Build agent filter
            agent_filter = ""
            params = [time_window]
            if agent_id:
                agent_filter = "AND agent_id = %s"
                params.append(agent_id)

            # Get attack pattern metrics for the server
            cursor.execute(f"""
                SELECT
                    COUNT(DISTINCT source_ip_text) as unique_ips,
                    COUNT(DISTINCT target_username) as unique_usernames,
                    COUNT(*) as total_attempts,
                    COUNT(*) / NULLIF(COUNT(DISTINCT source_ip_text), 0) as avg_attempts_per_ip
                FROM auth_events
                WHERE event_type = 'failed'
                AND timestamp >= NOW() - INTERVAL %s MINUTE
                {agent_filter}
            """, params)

            result = cursor.fetchone()
            unique_ips = result['unique_ips'] or 0
            unique_usernames = result['unique_usernames'] or 0
            total_attempts = result['total_attempts'] or 0
            avg_attempts_per_ip = float(result['avg_attempts_per_ip'] or 0)

            # Calculate pattern score (higher = more likely distributed attack)
            pattern_score = 0
            if unique_ips >= unique_ips_threshold:
                pattern_score += 30
            if unique_usernames >= unique_usernames_threshold:
                pattern_score += 30
            if avg_attempts_per_ip <= max_attempts_per_ip and total_attempts > 10:
                pattern_score += 40  # Slow and steady attack pattern

            # Check with threat intelligence for coordinated attack indicators
            cursor.execute(f"""
                SELECT COUNT(DISTINCT ae.source_ip_text) as threat_ips
                FROM auth_events ae
                JOIN ip_threat_intelligence ti ON ae.source_ip_text = ti.ip_address_text
                WHERE ae.event_type = 'failed'
                AND ae.timestamp >= NOW() - INTERVAL %s MINUTE
                AND ti.abuseipdb_score >= 25
                {agent_filter}
            """, params)

            threat_result = cursor.fetchone()
            threat_ips = threat_result['threat_ips'] or 0
            if threat_ips >= 3:
                pattern_score += 20  # Multiple known threat IPs involved

            triggered = (unique_ips >= unique_ips_threshold and
                        unique_usernames >= unique_usernames_threshold and
                        avg_attempts_per_ip <= max_attempts_per_ip)

            if triggered:
                return {
                    'triggered': True,
                    'reason': f"Distributed brute force detected: {unique_ips} IPs, {unique_usernames} usernames, "
                              f"avg {avg_attempts_per_ip:.1f} attempts/IP (pattern score: {pattern_score})",
                    'requires_approval': requires_approval,
                    'unique_ips': unique_ips,
                    'unique_usernames': unique_usernames,
                    'pattern_score': pattern_score,
                    'threat_level': 'high' if pattern_score >= 80 else 'medium'
                }

            return {
                'triggered': False,
                'reason': f"Pattern not matched: {unique_ips} IPs, {unique_usernames} usernames",
                'requires_approval': False,
                'unique_ips': unique_ips,
                'unique_usernames': unique_usernames,
                'pattern_score': pattern_score
            }

        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        print(f"Error evaluating distributed brute force rule: {e}")
        return {'triggered': False, 'reason': f"Error: {str(e)}",
                'requires_approval': False, 'unique_ips': 0, 'unique_usernames': 0, 'pattern_score': 0}


def evaluate_account_takeover_rule(rule, ip_address, username=None):
    """Evaluate account takeover attempt (same username from multiple IPs/locations quickly).

    This detects when a username is being targeted from multiple different IPs
    or geographic locations in a short time - indicating credential testing or
    compromised credentials being sold/shared.

    Rule conditions:
        - unique_ips_threshold: Minimum unique IPs trying same username (default 3)
        - unique_countries_threshold: Minimum unique countries (default 2)
        - time_window_minutes: Time window to analyze (default 30)
        - check_threat_intel: Use AbuseIPDB to weight scoring (default true)
        - requires_approval: Whether to require manual approval

    Returns: triggered, reason, unique_ips, unique_countries, targeted_usernames
    """
    try:
        conditions = rule['conditions']
        unique_ips_threshold = conditions.get('unique_ips_threshold', 3)
        unique_countries_threshold = conditions.get('unique_countries_threshold', 2)
        time_window = conditions.get('time_window_minutes', 30)
        check_threat_intel = conditions.get('check_threat_intel', True)
        requires_approval = conditions.get('requires_approval', False)

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            # Find usernames being targeted from multiple IPs
            cursor.execute("""
                SELECT
                    ae.target_username,
                    COUNT(DISTINCT ae.source_ip_text) as unique_ips,
                    COUNT(DISTINCT g.country_code) as unique_countries,
                    COUNT(*) as attempt_count,
                    GROUP_CONCAT(DISTINCT g.country_code) as countries
                FROM auth_events ae
                LEFT JOIN ip_geolocation g ON ae.source_ip_text = g.ip_address_text
                WHERE ae.event_type = 'failed'
                AND ae.timestamp >= NOW() - INTERVAL %s MINUTE
                AND ae.target_username IS NOT NULL
                AND ae.target_username != ''
                GROUP BY ae.target_username
                HAVING unique_ips >= %s OR unique_countries >= %s
                ORDER BY unique_ips DESC
                LIMIT 10
            """, (time_window, unique_ips_threshold, unique_countries_threshold))

            targeted_users = cursor.fetchall()

            if not targeted_users:
                return {
                    'triggered': False,
                    'reason': 'No account takeover patterns detected',
                    'requires_approval': False,
                    'unique_ips': 0,
                    'unique_countries': 0,
                    'targeted_usernames': []
                }

            # Calculate threat score using threat intelligence
            threat_score = 0
            high_risk_usernames = []

            for user in targeted_users:
                user_threat_score = 0

                # Base score from IP diversity
                user_threat_score += min(user['unique_ips'] * 10, 40)

                # Geographic diversity bonus
                user_threat_score += min(user['unique_countries'] * 15, 30)

                if check_threat_intel:
                    # Check if attacking IPs have bad reputation
                    cursor.execute("""
                        SELECT AVG(ti.abuseipdb_score) as avg_score
                        FROM auth_events ae
                        JOIN ip_threat_intelligence ti ON ae.source_ip_text = ti.ip_address_text
                        WHERE ae.target_username = %s
                        AND ae.event_type = 'failed'
                        AND ae.timestamp >= NOW() - INTERVAL %s MINUTE
                    """, (user['target_username'], time_window))

                    ti_result = cursor.fetchone()
                    avg_abuse_score = float(ti_result['avg_score'] or 0)
                    if avg_abuse_score >= 30:
                        user_threat_score += 30

                if user_threat_score >= 50:
                    high_risk_usernames.append({
                        'username': user['target_username'],
                        'unique_ips': user['unique_ips'],
                        'countries': user['countries'],
                        'score': user_threat_score
                    })

                threat_score = max(threat_score, user_threat_score)

            if high_risk_usernames:
                top_target = high_risk_usernames[0]
                return {
                    'triggered': True,
                    'reason': f"Account takeover attempt: '{top_target['username']}' targeted from "
                              f"{top_target['unique_ips']} IPs across {top_target['countries']} "
                              f"(threat score: {top_target['score']})",
                    'requires_approval': requires_approval,
                    'unique_ips': top_target['unique_ips'],
                    'unique_countries': len(top_target['countries'].split(',')) if top_target['countries'] else 0,
                    'targeted_usernames': [u['username'] for u in high_risk_usernames],
                    'threat_level': 'critical' if threat_score >= 80 else 'high'
                }

            return {
                'triggered': False,
                'reason': f"Patterns found but below threat threshold",
                'requires_approval': False,
                'unique_ips': targeted_users[0]['unique_ips'] if targeted_users else 0,
                'unique_countries': targeted_users[0]['unique_countries'] if targeted_users else 0,
                'targeted_usernames': []
            }

        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        print(f"Error evaluating account takeover rule: {e}")
        return {'triggered': False, 'reason': f"Error: {str(e)}",
                'requires_approval': False, 'unique_ips': 0, 'unique_countries': 0, 'targeted_usernames': []}


def evaluate_off_hours_anomaly_rule(rule, ip_address, username=None, event_timestamp=None):
    """Evaluate out-of-work-time anomaly (login attempts outside business hours).

    This detects authentication attempts that occur outside normal business hours,
    which could indicate compromised credentials being used by attackers in different timezones.

    Rule conditions:
        - work_start_hour: Business start hour (default 8)
        - work_end_hour: Business end hour (default 18)
        - work_days: List of work days 0=Mon, 6=Sun (default [0,1,2,3,4])
        - min_off_hours_attempts: Minimum attempts outside hours to trigger (default 3)
        - event_type: Filter by event type - 'failed', 'successful', or None for both (default None)
        - max_abuseipdb_score: Only trigger for clean IPs with score <= this value (default None)
        - check_ip_reputation: If true, check IP reputation (default False)
        - check_user_baseline: Compare against user's normal login times (default true)
        - requires_approval: Whether to require manual approval

    Returns: triggered, reason, off_hours_attempts, is_weekend, hour_of_day
    """
    from datetime import datetime

    try:
        conditions = rule['conditions']
        work_start = conditions.get('work_start_hour', 8)
        work_end = conditions.get('work_end_hour', 18)
        work_days = conditions.get('work_days', [0, 1, 2, 3, 4])  # Mon-Fri
        min_attempts = conditions.get('min_off_hours_attempts', 3)
        event_type_filter = conditions.get('event_type')  # 'failed', 'successful', or None
        max_abuse_score = conditions.get('max_abuseipdb_score')
        check_ip_reputation = conditions.get('check_ip_reputation', False)
        check_baseline = conditions.get('check_user_baseline', True)
        requires_approval = conditions.get('requires_approval', False)

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            # Get the most recent event's timestamp to check if IT was during off-hours
            cursor.execute("""
                SELECT timestamp FROM auth_events
                WHERE source_ip_text = %s
                ORDER BY timestamp DESC LIMIT 1
            """, (ip_address,))
            latest_event = cursor.fetchone()

            if latest_event:
                event_time = latest_event['timestamp']
                current_hour = event_time.hour
                current_weekday = event_time.weekday()
            else:
                # Fall back to current time if no events found
                now = datetime.now()
                current_hour = now.hour
                current_weekday = now.weekday()

            is_work_day = current_weekday in work_days

            # Check max_abuseipdb_score filter (for "clean IP only" rules)
            if max_abuse_score is not None or check_ip_reputation:
                cursor.execute("""
                    SELECT abuseipdb_score FROM ip_threat_intelligence
                    WHERE ip_address_text = %s
                    ORDER BY last_seen DESC LIMIT 1
                """, (ip_address,))
                threat_row = cursor.fetchone()
                ip_abuse_score = threat_row['abuseipdb_score'] if threat_row and threat_row['abuseipdb_score'] else 0

                if max_abuse_score is not None and ip_abuse_score > max_abuse_score:
                    return {
                        'triggered': False,
                        'reason': f"IP AbuseIPDB score ({ip_abuse_score}) exceeds max ({max_abuse_score}) - handled by bad-IP rules",
                        'requires_approval': False,
                        'off_hours_attempts': 0,
                        'is_weekend': not is_work_day,
                        'hour_of_day': current_hour,
                        'anomaly_score': 0
                    }

            # For successful login alert during off-hours, trigger immediately if filter matches
            if event_type_filter == 'successful':
                # This is specifically for SCENARIO 2: Clean IP + Midnight Success = ALERT
                # Check if the MOST RECENTLY INSERTED event was during off-hours
                # ORDER BY id DESC gets the most recent INSERT, not the latest timestamp
                cursor.execute("""
                    SELECT timestamp
                    FROM auth_events
                    WHERE source_ip_text = %s
                    AND event_type = 'successful'
                    ORDER BY id DESC
                    LIMIT 1
                """, (ip_address,))
                result = cursor.fetchone()

                if result:
                    latest_event = result['timestamp']
                    event_hour = latest_event.hour
                    event_weekday = latest_event.weekday()

                    # Check if this specific event was during off-hours
                    is_off_hour = event_hour < work_start or event_hour >= work_end
                    is_weekend = event_weekday >= 5  # Sat=5, Sun=6

                    if is_off_hour or is_weekend:
                        # This event IS during off-hours - trigger alert
                        return {
                            'triggered': True,
                            'reason': f"Off-hours successful login detected at {event_hour}:00 (outside {work_start}:00-{work_end}:00)",
                            'requires_approval': requires_approval,
                            'off_hours_attempts': 1,
                            'is_weekend': is_weekend,
                            'hour_of_day': event_hour,
                            'anomaly_score': 1,
                            'threat_level': 'medium'
                        }

                # Event is during work hours OR no event found - no alert
                return {
                    'triggered': False,
                    'reason': f"Successful login during work hours or no events found",
                    'requires_approval': False,
                    'off_hours_attempts': 0,
                    'is_weekend': False,
                    'hour_of_day': current_hour,
                    'anomaly_score': 0
                }

            # Count recent off-hours attempts from this IP (for failed login detection)
            event_type_clause = "AND event_type = 'failed'" if not event_type_filter else f"AND event_type = '{event_type_filter}'"
            cursor.execute(f"""
                SELECT COUNT(*) as off_hours_count
                FROM auth_events
                WHERE source_ip_text = %s
                {event_type_clause}
                AND timestamp >= NOW() - INTERVAL 24 HOUR
                AND (
                    HOUR(timestamp) < %s OR HOUR(timestamp) >= %s
                    OR DAYOFWEEK(timestamp) IN (1, 7)
                )
            """, (ip_address, work_start, work_end))

            result = cursor.fetchone()
            off_hours_attempts = result['off_hours_count'] or 0

            # Check user baseline if username provided
            baseline_anomaly = False
            if check_baseline and username:
                cursor.execute("""
                    SELECT
                        AVG(HOUR(timestamp)) as avg_login_hour,
                        COUNT(*) as total_logins
                    FROM auth_events
                    WHERE target_username = %s
                    AND event_type = 'successful'
                    AND timestamp >= NOW() - INTERVAL 30 DAY
                """, (username,))

                baseline = cursor.fetchone()
                if baseline and baseline['total_logins'] and baseline['total_logins'] >= 5:
                    avg_hour = float(baseline['avg_login_hour'] or 12)
                    # If current hour is more than 6 hours from average, it's anomalous
                    hour_diff = abs(current_hour - avg_hour)
                    if hour_diff > 12:
                        hour_diff = 24 - hour_diff
                    baseline_anomaly = hour_diff >= 6

            # Check threat intelligence for the IP
            threat_multiplier = 1.0
            cursor.execute("""
                SELECT abuseipdb_score, virustotal_malicious
                FROM ip_threat_intelligence
                WHERE ip_address_text = %s
            """, (ip_address,))

            ti_data = cursor.fetchone()
            if ti_data:
                if (ti_data['abuseipdb_score'] or 0) >= 30:
                    threat_multiplier = 1.5
                if (ti_data['virustotal_malicious'] or 0) >= 2:
                    threat_multiplier = 2.0

            # Calculate final score
            anomaly_score = off_hours_attempts * threat_multiplier
            if baseline_anomaly:
                anomaly_score *= 1.5
            if not is_work_day:
                anomaly_score *= 1.3  # Weekend bonus

            triggered = (is_off_hours and off_hours_attempts >= min_attempts) or anomaly_score >= min_attempts * 2

            if triggered:
                time_desc = []
                if not is_work_day:
                    time_desc.append("weekend")
                if not is_work_hours:
                    time_desc.append(f"off-hours ({current_hour}:00)")
                if baseline_anomaly:
                    time_desc.append("unusual for user")

                return {
                    'triggered': True,
                    'reason': f"Off-hours anomaly: {off_hours_attempts} attempts during {', '.join(time_desc)} "
                              f"(anomaly score: {anomaly_score:.1f})",
                    'requires_approval': requires_approval,
                    'off_hours_attempts': off_hours_attempts,
                    'is_weekend': not is_work_day,
                    'hour_of_day': current_hour,
                    'anomaly_score': anomaly_score,
                    'threat_level': 'high' if anomaly_score >= min_attempts * 3 else 'medium'
                }

            return {
                'triggered': False,
                'reason': f"Within acceptable hours or below threshold ({off_hours_attempts} attempts)",
                'requires_approval': False,
                'off_hours_attempts': off_hours_attempts,
                'is_weekend': not is_work_day,
                'hour_of_day': current_hour,
                'anomaly_score': anomaly_score
            }

        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        print(f"Error evaluating off-hours anomaly rule: {e}")
        return {'triggered': False, 'reason': f"Error: {str(e)}",
                'requires_approval': False, 'off_hours_attempts': 0, 'is_weekend': False, 'hour_of_day': 0}


def evaluate_behavioral_analysis_rule(rule, ip_address, username=None, event_type=None, geo_data=None):
    """
    Evaluate behavioral analysis rule using the BehavioralAnalyzer.

    This is the PRIORITY ML rule that combines multiple behavioral signals:
    - Impossible travel detection
    - Unusual login time
    - New location/IP for user
    - Credential stuffing patterns
    - Success after failures (possible brute force success)

    Rule conditions:
        - min_risk_score: Minimum behavioral risk score to trigger (default 40)
        - min_confidence: Minimum confidence level (default 0.5)
        - priority_factors: List of factor types that auto-trigger block
        - block_method: 'ufw' for permanent, 'fail2ban' for temporary (default based on score)
        - requires_approval: Whether to require manual approval

    Returns: triggered, reason, risk_score, risk_factors, recommendations, block_method
    """
    try:
        conditions = rule['conditions']
        min_risk_score = conditions.get('min_risk_score', 40)
        min_confidence = conditions.get('min_confidence', 0.5)
        # Note: impossible_travel removed from default - should contribute to score, not auto-block
        priority_factors = conditions.get('priority_factors', ['credential_stuffing', 'brute_force'])
        requires_approval = conditions.get('requires_approval', False)

        if not username:
            return {
                'triggered': False,
                'reason': 'No username provided for behavioral analysis',
                'requires_approval': False,
                'risk_score': 0,
                'risk_factors': [],
                'recommendations': [],
                'block_method': 'none'
            }

        # Import and use BehavioralAnalyzer
        try:
            import sys
            from pathlib import Path
            PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
            sys.path.append(str(PROJECT_ROOT / "src" / "core"))
            from behavioral_analyzer import BehavioralAnalyzer

            analyzer = BehavioralAnalyzer()
            analysis = analyzer.analyze(
                ip_address=ip_address,
                username=username,
                event_type=event_type or 'failed',
                current_geo=geo_data
            )

            risk_score = analysis.get('risk_score', 0)
            confidence = analysis.get('confidence', 0.5)
            risk_factors = analysis.get('risk_factors', [])
            recommendations = analysis.get('recommendations', [])

            # Check for priority factors (immediate block)
            detected_types = [f.get('type') for f in risk_factors]
            has_priority_factor = any(pf in detected_types for pf in priority_factors)

            # Determine block method based on score
            if risk_score >= 80 or (has_priority_factor and risk_score >= 60):
                block_method = 'ufw'  # Permanent block for high-risk
            elif risk_score >= 60:
                block_method = 'fail2ban'  # Extended ban for medium-high risk
            elif risk_score >= min_risk_score:
                block_method = 'fail2ban'  # Standard ban
            else:
                block_method = 'none'

            # Check if should trigger
            if risk_score < min_risk_score:
                return {
                    'triggered': False,
                    'reason': f"Behavioral risk score {risk_score} below threshold {min_risk_score}",
                    'requires_approval': False,
                    'risk_score': risk_score,
                    'risk_factors': risk_factors,
                    'recommendations': recommendations,
                    'block_method': 'none',
                    'confidence': confidence
                }

            if confidence < min_confidence:
                return {
                    'triggered': False,
                    'reason': f"Confidence {confidence:.2f} below threshold {min_confidence}",
                    'requires_approval': False,
                    'risk_score': risk_score,
                    'risk_factors': risk_factors,
                    'recommendations': recommendations,
                    'block_method': 'none',
                    'confidence': confidence
                }

            # Build detailed reason
            factor_names = [f.get('title', f.get('type')) for f in risk_factors[:3]]
            reason = f"ML Behavioral Analysis: {risk_score} risk score"
            if factor_names:
                reason += f" ({', '.join(factor_names)})"
            reason += f" - confidence: {confidence:.2f}"

            # Determine threat level
            if risk_score >= 80:
                threat_level = 'critical'
            elif risk_score >= 60:
                threat_level = 'high'
            elif risk_score >= 40:
                threat_level = 'medium'
            else:
                threat_level = 'low'

            return {
                'triggered': True,
                'reason': reason,
                'requires_approval': requires_approval,
                'risk_score': risk_score,
                'risk_factors': risk_factors,
                'recommendations': recommendations,
                'block_method': block_method,
                'confidence': confidence,
                'threat_level': threat_level,
                'has_priority_factor': has_priority_factor,
                'detected_types': detected_types
            }

        except ImportError as e:
            print(f"BehavioralAnalyzer not available: {e}")
            return {
                'triggered': False,
                'reason': 'BehavioralAnalyzer module not available',
                'requires_approval': False,
                'risk_score': 0,
                'risk_factors': [],
                'recommendations': [],
                'block_method': 'none'
            }

    except Exception as e:
        print(f"Error evaluating behavioral analysis rule: {e}")
        return {
            'triggered': False,
            'reason': f"Error: {str(e)}",
            'requires_approval': False,
            'risk_score': 0,
            'risk_factors': [],
            'recommendations': [],
            'block_method': 'none'
        }


def evaluate_impossible_travel_rule(rule, ip_address, username=None):
    """Evaluate impossible travel detection rule.

    Rule conditions: max_distance_km, time_window_hours
    Returns: triggered, reason, distance_km, time_diff_hours
    """
    # Use shared haversine function from geoip
    try:
        import sys
        from pathlib import Path
        PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
        sys.path.append(str(PROJECT_ROOT / "src" / "core"))
        from geoip import haversine_distance
    except ImportError:
        # Fallback if geoip not available
        import math
        def haversine_distance(lat1, lon1, lat2, lon2):
            R = 6371
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
        max_abuse_score = conditions.get('max_abuseipdb_score')  # For "clean IP only" filter
        require_anomaly = conditions.get('require_anomaly', False)  # Require other anomalies
        min_risk_score = conditions.get('min_risk_score', 0)  # Minimum ML risk score

        if not username:
            return {'triggered': False, 'reason': 'No username provided for travel check',
                    'distance_km': 0, 'time_diff_hours': 0}

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            # Check max_abuseipdb_score filter (for "clean IP only" rules)
            if max_abuse_score is not None:
                cursor.execute("""
                    SELECT abuseipdb_score FROM ip_threat_intelligence
                    WHERE ip_address_text = %s
                    ORDER BY last_seen DESC LIMIT 1
                """, (ip_address,))
                threat_row = cursor.fetchone()
                ip_abuse_score = threat_row['abuseipdb_score'] if threat_row and threat_row['abuseipdb_score'] else 0

                if ip_abuse_score > max_abuse_score:
                    return {
                        'triggered': False,
                        'reason': f"IP AbuseIPDB score ({ip_abuse_score}) exceeds max ({max_abuse_score}) - handled by bad-IP rules",
                        'distance_km': 0,
                        'time_diff_hours': 0
                    }

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
            is_impossible_travel = distance_km > max_distance_km and time_diff_hours < time_window_hours

            if is_impossible_travel:
                # If require_anomaly or min_risk_score is set, check additional conditions
                if require_anomaly or min_risk_score > 0:
                    # Get IP's threat/anomaly score from threat intelligence
                    cursor.execute("""
                        SELECT abuseipdb_score, overall_threat_level
                        FROM ip_threat_intelligence
                        WHERE ip_address_text = %s
                    """, (ip_address,))
                    threat_data = cursor.fetchone()

                    # Calculate a combined risk score
                    ip_risk_score = 0
                    if threat_data:
                        abuse_score = threat_data.get('abuseipdb_score') or 0
                        threat_level = threat_data.get('overall_threat_level', 'clean')

                        # Base score from AbuseIPDB
                        ip_risk_score = abuse_score

                        # Boost for threat level
                        threat_boosts = {'low': 10, 'medium': 25, 'high': 40, 'critical': 60}
                        ip_risk_score += threat_boosts.get(threat_level, 0)

                    # Add impossible travel contribution
                    travel_risk = min(40, int(distance_km / 100))  # Up to 40 points for long distance
                    combined_risk = ip_risk_score + travel_risk

                    if min_risk_score > 0 and combined_risk < min_risk_score:
                        return {
                            'triggered': False,
                            'reason': f"Impossible travel detected but combined risk ({combined_risk}) below threshold ({min_risk_score})",
                            'distance_km': distance_km,
                            'time_diff_hours': time_diff_hours
                        }

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
