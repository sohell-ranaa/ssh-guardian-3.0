"""
SSH Guardian v3.0 - Blocking Rules Engine (Wrapper)
This file maintains backwards compatibility by importing from the modular blocking package

For new code, import directly from the blocking package:
    from blocking import BlockingEngine, block_ip, unblock_ip, etc.

This wrapper file allows existing code to continue using:
    from blocking_engine import BlockingEngine
"""

# Import everything from the blocking package for backwards compatibility
from blocking import (
    BlockingEngine,
    evaluate_brute_force_rule,
    evaluate_threat_threshold_rule,
    evaluate_rules_for_ip,
    check_and_block_ip,
    block_ip,
    unblock_ip,
    block_ip_manual,
    cleanup_expired_blocks
)

# Expose convenience functions that were in the original file
__all__ = [
    'BlockingEngine',
    'evaluate_rules_for_ip',
    'check_and_block_ip',
    'block_ip_manual',
    'unblock_ip'
]
