"""
SSH Guardian v3.0 - Rule Coordinator
Coordinates evaluation of multiple rules and triggers blocking
"""

import sys
import json
from pathlib import Path

# Add project paths
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
sys.path.append(str(PROJECT_ROOT / "dbs"))

from connection import get_connection
from .rule_evaluators import (
    evaluate_brute_force_rule,
    evaluate_threat_threshold_rule,
    evaluate_high_risk_country_rule,
    get_repeat_offender_duration
)
from .ml_evaluators import (
    evaluate_ml_threshold_rule,
    evaluate_credential_stuffing_rule,
    evaluate_anomaly_pattern_rule,
    evaluate_velocity_rule,
    evaluate_tor_detection_rule,
    evaluate_proxy_detection_rule,
    evaluate_impossible_travel_rule,
    evaluate_distributed_brute_force_rule,
    evaluate_account_takeover_rule,
    evaluate_off_hours_anomaly_rule,
    evaluate_behavioral_analysis_rule
)
from .threat_combo_evaluator import evaluate_threat_combo_rule
from .ip_operations import block_ip
from .alert_operations import create_security_alert


def evaluate_rules_for_ip(ip_address, ml_result=None, event_id=None, event_type=None, username=None):
    """
    Evaluate all enabled rules for an IP address

    Args:
        ip_address: IP to evaluate
        ml_result: Optional ML prediction result dict
        event_id: Optional trigger event ID
        event_type: 'failed' or 'successful'
        username: Target username for impossible travel detection

    Returns:
        list: List of rule evaluation results
    """
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    results = []

    try:
        # Get all enabled rules, ordered by priority
        cursor.execute("""
            SELECT
                id,
                rule_name,
                rule_type,
                action_type,
                priority,
                conditions,
                block_duration_minutes,
                auto_unblock
            FROM blocking_rules
            WHERE is_enabled = TRUE
            ORDER BY priority DESC, id ASC
        """)

        rules = cursor.fetchall()

        for rule in rules:
            # Parse JSON conditions
            rule['conditions'] = json.loads(rule['conditions']) if isinstance(rule['conditions'], str) else rule['conditions']

            # Evaluate based on rule type
            if rule['rule_type'] == 'brute_force':
                eval_result = evaluate_brute_force_rule(rule, ip_address)

            elif rule['rule_type'] == 'api_reputation':
                eval_result = evaluate_threat_threshold_rule(rule, ip_address, event_type)

            elif rule['rule_type'] == 'ml_threshold':
                if ml_result:
                    eval_result = evaluate_ml_threshold_rule(rule, ip_address, ml_result)
                    eval_result['should_block'] = eval_result.get('triggered', False)
                else:
                    eval_result = {'should_block': False, 'reason': 'No ML result available'}

            elif rule['rule_type'] == 'credential_stuffing':
                eval_result = evaluate_credential_stuffing_rule(rule, ip_address)
                eval_result['should_block'] = eval_result.get('triggered', False)

            elif rule['rule_type'] == 'anomaly_pattern':
                if ml_result:
                    eval_result = evaluate_anomaly_pattern_rule(rule, ip_address, ml_result)
                    eval_result['should_block'] = eval_result.get('triggered', False)
                else:
                    eval_result = {'should_block': False, 'reason': 'No ML result available'}

            elif rule['rule_type'] == 'velocity':
                eval_result = evaluate_velocity_rule(rule, ip_address)
                eval_result['should_block'] = eval_result.get('triggered', False)

            elif rule['rule_type'] == 'tor_detection':
                eval_result = evaluate_tor_detection_rule(rule, ip_address, event_type)
                eval_result['should_block'] = eval_result.get('triggered', False)

            elif rule['rule_type'] == 'proxy_detection':
                eval_result = evaluate_proxy_detection_rule(rule, ip_address)
                eval_result['should_block'] = eval_result.get('triggered', False)

            elif rule['rule_type'] == 'geo_restriction':
                eval_result = evaluate_high_risk_country_rule(rule, ip_address)

            elif rule['rule_type'] == 'geo_anomaly':
                eval_result = evaluate_impossible_travel_rule(rule, ip_address, username)
                eval_result['should_block'] = eval_result.get('triggered', False)

            elif rule['rule_type'] == 'threat_combo':
                eval_result = evaluate_threat_combo_rule(rule, ip_address, event_type)
                eval_result['should_block'] = eval_result.get('triggered', False)

            elif rule['rule_type'] == 'distributed_brute_force':
                # Distributed brute force: many IPs, many usernames, slow frequency
                eval_result = evaluate_distributed_brute_force_rule(rule, ip_address)
                eval_result['should_block'] = eval_result.get('triggered', False)

            elif rule['rule_type'] == 'account_takeover':
                # Account takeover: same username from multiple IPs/locations
                eval_result = evaluate_account_takeover_rule(rule, ip_address, username)
                eval_result['should_block'] = eval_result.get('triggered', False)

            elif rule['rule_type'] == 'off_hours_anomaly':
                # Off-hours anomaly: login attempts outside business hours
                eval_result = evaluate_off_hours_anomaly_rule(rule, ip_address, username)
                eval_result['should_block'] = eval_result.get('triggered', False)

            elif rule['rule_type'] == 'behavioral_analysis':
                # ML Behavioral Analysis (PRIORITY): comprehensive behavioral detection
                # This uses BehavioralAnalyzer for advanced pattern detection
                eval_result = evaluate_behavioral_analysis_rule(rule, ip_address, username, event_type)
                eval_result['should_block'] = eval_result.get('triggered', False)
                # Store block method preference for later use
                if eval_result.get('block_method') == 'ufw':
                    eval_result['force_ufw'] = True

            elif rule['rule_type'] == 'repeat_offender':
                # This is handled during block duration calculation
                eval_result = {'should_block': False, 'reason': 'Duration modifier only'}

            else:
                eval_result = {
                    'should_block': False,
                    'reason': f"Rule type '{rule['rule_type']}' not implemented"
                }

            eval_result['rule'] = rule
            eval_result['trigger_event_id'] = event_id
            results.append(eval_result)

        return results

    finally:
        cursor.close()
        conn.close()


def check_and_block_ip(ip_address, ml_result=None, event_id=None, event_type=None, username=None):
    """
    Check all rules for an IP and block if any rule triggers

    Args:
        ip_address: IP to evaluate and potentially block
        ml_result: Optional ML prediction result dict
        event_id: Optional trigger event ID
        event_type: 'failed' or 'successful'
        username: Target username for impossible travel

    Returns:
        dict: {
            'blocked': bool,
            'block_id': int or None,
            'triggered_rules': list,
            'message': str,
            'requires_approval': bool
        }
    """
    # Early check: Skip if IP is already blocked (by fail2ban, ML, or manual)
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("""
            SELECT id, block_source, blocked_at FROM ip_blocks
            WHERE ip_address_text = %s AND is_active = TRUE
        """, (ip_address,))
        existing_block = cursor.fetchone()
        if existing_block:
            return {
                'blocked': False,
                'block_id': existing_block['id'],
                'triggered_rules': [],
                'message': f'IP already blocked by {existing_block["block_source"]}',
                'requires_approval': False,
                'already_blocked': True
            }
    finally:
        cursor.close()
        conn.close()

    # Evaluate all rules
    eval_results = evaluate_rules_for_ip(ip_address, ml_result, event_id, event_type, username)

    triggered_rules = [r for r in eval_results if r.get('should_block')]

    if not triggered_rules:
        return {
            'blocked': False,
            'block_id': None,
            'triggered_rules': [],
            'message': 'No rules triggered',
            'requires_approval': False,
            'alerts_created': 0
        }

    # Separate rules by action_type: 'block' vs 'alert'
    block_rules = []
    alert_rules = []

    for r in triggered_rules:
        action_type = r['rule'].get('action_type', 'block')
        if action_type == 'alert':
            alert_rules.append(r)
        elif action_type == 'monitor':
            # Monitor-only: log but don't block or alert
            print(f"📊 Monitor: {r['rule']['rule_name']} triggered for {ip_address}")
        else:
            block_rules.append(r)

    # Process alerts (non-blocking)
    alerts_created = 0
    for alert_rule in alert_rules:
        rule = alert_rule['rule']
        alert_result = create_security_alert(
            ip_address=ip_address,
            alert_type=rule['rule_type'],
            title=f"{rule['rule_name']}: {alert_rule.get('reason', 'Suspicious activity detected')}",
            description=alert_rule.get('description', alert_rule.get('reason')),
            severity=alert_rule.get('threat_level', 'medium'),
            username=username,
            event_id=event_id,
            ml_score=alert_rule.get('ml_score', 0),
            ml_factors=alert_rule.get('risk_factors', [])
        )
        if alert_result.get('success'):
            alerts_created += 1

    # If no blocking rules, return with alert info
    if not block_rules:
        return {
            'blocked': False,
            'block_id': None,
            'triggered_rules': [r['rule']['rule_name'] for r in alert_rules],
            'message': f'Alert(s) created, no blocking rules triggered',
            'requires_approval': False,
            'alerts_created': alerts_created,
            'alert_only': True
        }

    # Prioritize ML behavioral analysis rule if triggered (highest priority)
    ml_behavioral_rules = [r for r in block_rules if r['rule']['rule_type'] == 'behavioral_analysis']
    if ml_behavioral_rules:
        # ML behavioral analysis takes priority
        rule_to_apply = ml_behavioral_rules[0]
    else:
        # Use highest priority rule
        rule_to_apply = block_rules[0]  # Already sorted by priority

    rule = rule_to_apply['rule']

    # Check if approval is required
    requires_approval = rule_to_apply.get('requires_approval', False)

    # Determine block source based on rule type
    rule_type = rule['rule_type']
    if rule_type == 'behavioral_analysis':
        # ML behavioral analysis - highest priority
        block_source = 'ml_behavioral'
    elif rule_type in ('ml_threshold', 'anomaly_pattern'):
        block_source = 'ml_threshold'
    elif rule_type == 'api_reputation':
        block_source = 'api_reputation'
    elif rule_type in ('geo_restriction', 'geo_anomaly'):
        block_source = 'anomaly_detection'
    elif rule_type == 'threat_combo':
        block_source = 'api_reputation'
    else:
        block_source = 'rule_based'

    # Get base duration from rule
    base_duration = rule['block_duration_minutes']

    # Apply repeat offender escalation
    adjusted_duration = get_repeat_offender_duration(ip_address, base_duration)

    # Check if ML behavioral analysis recommends permanent UFW block
    force_ufw = rule_to_apply.get('force_ufw', False)
    ml_risk_factors = rule_to_apply.get('risk_factors', [])

    # For behavioral analysis with critical threat level, override auto_unblock
    auto_unblock = rule['auto_unblock']
    if rule_type == 'behavioral_analysis':
        threat_level = rule_to_apply.get('threat_level', 'low')
        if threat_level == 'critical' or force_ufw:
            auto_unblock = False  # Permanent block for critical threats
            adjusted_duration = 0  # 0 = permanent

    # Block the IP
    block_result = block_ip(
        ip_address=ip_address,
        block_reason=rule_to_apply.get('reason', f'Rule {rule["rule_name"]} triggered'),
        block_source=block_source,
        blocking_rule_id=rule['id'],
        trigger_event_id=event_id or rule_to_apply.get('trigger_event_id'),
        failed_attempts=rule_to_apply.get('failed_attempts', 0),
        threat_level=rule_to_apply.get('threat_level'),
        block_duration_minutes=adjusted_duration,
        auto_unblock=auto_unblock
    )

    return {
        'blocked': block_result['success'],
        'block_id': block_result['block_id'],
        'triggered_rules': [r['rule']['rule_name'] for r in triggered_rules],
        'message': block_result['message'],
        'requires_approval': requires_approval,
        'ufw_commands_created': block_result.get('ufw_commands_created', 0),
        'base_duration': base_duration,
        'adjusted_duration': adjusted_duration,
        'ml_behavioral_analysis': {
            'risk_factors': ml_risk_factors,
            'recommendations': rule_to_apply.get('recommendations', []),
            'confidence': rule_to_apply.get('confidence', 0),
            'force_ufw': force_ufw
        } if rule_type == 'behavioral_analysis' else None
    }
