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
from .rule_evaluators import evaluate_brute_force_rule, evaluate_threat_threshold_rule
from .ip_operations import block_ip


def evaluate_rules_for_ip(ip_address):
    """
    Evaluate all enabled rules for an IP address

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
                eval_result = evaluate_threat_threshold_rule(rule, ip_address)
            else:
                # Other rule types not implemented yet
                eval_result = {
                    'should_block': False,
                    'reason': f"Rule type '{rule['rule_type']}' not implemented"
                }

            eval_result['rule'] = rule
            results.append(eval_result)

        return results

    finally:
        cursor.close()
        conn.close()


def check_and_block_ip(ip_address):
    """
    Check all rules for an IP and block if any rule triggers

    Returns:
        dict: {
            'blocked': bool,
            'block_id': int or None,
            'triggered_rules': list,
            'message': str
        }
    """
    # Evaluate all rules
    eval_results = evaluate_rules_for_ip(ip_address)

    triggered_rules = [r for r in eval_results if r['should_block']]

    if not triggered_rules:
        return {
            'blocked': False,
            'block_id': None,
            'triggered_rules': [],
            'message': 'No rules triggered'
        }

    # Block based on highest priority rule
    rule_to_apply = triggered_rules[0]  # Already sorted by priority
    rule = rule_to_apply['rule']

    # Block the IP
    block_result = block_ip(
        ip_address=ip_address,
        block_reason=rule_to_apply['reason'],
        block_source='rule_based',
        blocking_rule_id=rule['id'],
        trigger_event_id=rule_to_apply.get('trigger_event_id'),
        failed_attempts=rule_to_apply.get('failed_attempts', 0),
        threat_level=rule_to_apply.get('threat_level'),
        block_duration_minutes=rule['block_duration_minutes'],
        auto_unblock=rule['auto_unblock']
    )

    return {
        'blocked': block_result['success'],
        'block_id': block_result['block_id'],
        'triggered_rules': [r['rule']['rule_name'] for r in triggered_rules],
        'message': block_result['message']
    }
