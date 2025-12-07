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
    evaluate_impossible_travel_rule
)
from .threat_combo_evaluator import evaluate_threat_combo_rule
from .ip_operations import block_ip


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
    # Evaluate all rules
    eval_results = evaluate_rules_for_ip(ip_address, ml_result, event_id, event_type, username)

    triggered_rules = [r for r in eval_results if r.get('should_block')]

    if not triggered_rules:
        return {
            'blocked': False,
            'block_id': None,
            'triggered_rules': [],
            'message': 'No rules triggered',
            'requires_approval': False
        }

    # Block based on highest priority rule
    rule_to_apply = triggered_rules[0]  # Already sorted by priority
    rule = rule_to_apply['rule']

    # Check if approval is required
    requires_approval = rule_to_apply.get('requires_approval', False)

    # Determine block source based on rule type
    rule_type = rule['rule_type']
    if rule_type in ('ml_threshold', 'anomaly_pattern'):
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
        auto_unblock=rule['auto_unblock']
    )

    return {
        'blocked': block_result['success'],
        'block_id': block_result['block_id'],
        'triggered_rules': [r['rule']['rule_name'] for r in triggered_rules],
        'message': block_result['message'],
        'requires_approval': requires_approval,
        'ufw_commands_created': block_result.get('ufw_commands_created', 0),
        'base_duration': base_duration,
        'adjusted_duration': adjusted_duration
    }
