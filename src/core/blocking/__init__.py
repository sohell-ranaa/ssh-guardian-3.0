"""
SSH Guardian v3.0 - Blocking Engine Package
Modular IP blocking and rule evaluation system
"""

from .rule_evaluators import evaluate_brute_force_rule, evaluate_threat_threshold_rule
from .rule_coordinator import evaluate_rules_for_ip, check_and_block_ip
from .ip_operations import block_ip, unblock_ip, block_ip_manual
from .cleanup import cleanup_expired_blocks
from .ufw_sync import reconcile_ufw_with_ip_blocks

# Backwards compatibility - expose the original BlockingEngine class
class BlockingEngine:
    """
    Blocking Rules Engine (Legacy Interface)

    This class maintains backwards compatibility while delegating
    to modular functions.
    """

    @staticmethod
    def evaluate_brute_force_rule(rule, ip_address):
        return evaluate_brute_force_rule(rule, ip_address)

    @staticmethod
    def evaluate_threat_threshold_rule(rule, ip_address):
        return evaluate_threat_threshold_rule(rule, ip_address)

    @staticmethod
    def evaluate_rules_for_ip(ip_address):
        return evaluate_rules_for_ip(ip_address)

    @staticmethod
    def block_ip(ip_address, block_reason, block_source='rule_based', blocking_rule_id=None,
                 trigger_event_id=None, failed_attempts=0, threat_level=None,
                 block_duration_minutes=1440, auto_unblock=True, created_by_user_id=None):
        return block_ip(
            ip_address, block_reason, block_source, blocking_rule_id,
            trigger_event_id, failed_attempts, threat_level,
            block_duration_minutes, auto_unblock, created_by_user_id
        )

    @staticmethod
    def unblock_ip(ip_address, unblock_reason='Manual unblock', unblocked_by_user_id=None):
        return unblock_ip(ip_address, unblock_reason, unblocked_by_user_id)

    @staticmethod
    def check_and_block_ip(ip_address):
        return check_and_block_ip(ip_address)

    @staticmethod
    def cleanup_expired_blocks():
        return cleanup_expired_blocks()


__all__ = [
    'BlockingEngine',
    'evaluate_brute_force_rule',
    'evaluate_threat_threshold_rule',
    'evaluate_rules_for_ip',
    'check_and_block_ip',
    'block_ip',
    'unblock_ip',
    'block_ip_manual',
    'cleanup_expired_blocks',
    'reconcile_ufw_with_ip_blocks'
]
