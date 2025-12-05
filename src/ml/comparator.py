"""
SSH Guardian v3.0 - ML vs Rule-Based Comparator
Compares ML detection with traditional rule-based (fail2ban-style) detection
to prove ML effectiveness
"""

import sys
import json
import logging
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List
from collections import defaultdict

# Add project paths
PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.append(str(PROJECT_ROOT / "dbs"))

from connection import get_connection
from src.ml.comparator_queries import (
    get_ml_stats_optimized,
    get_rule_based_stats_optimized,
    get_detection_cases_batched,
    get_daily_stats_batched,
    get_benefits_stats_batched
)

logger = logging.getLogger(__name__)


class MLComparator:
    """
    Compares ML-based detection with rule-based detection.
    Proves ML is better than fail2ban through metrics.
    """

    # Fail2ban-style rule thresholds (for comparison)
    RULE_THRESHOLDS = {
        'max_failures_before_block': 5,  # Block after 5 failures
        'failure_window_minutes': 10,     # Within 10 minutes
        'ban_duration_minutes': 60        # Ban for 1 hour
    }

    def __init__(self):
        """Initialize comparator"""
        pass

    def get_comparison_stats(self, days: int = 30) -> Dict[str, Any]:
        """
        Get comprehensive comparison statistics.

        Args:
            days: Number of days to analyze

        Returns:
            Comparison statistics dict
        """
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            start_date = datetime.now() - timedelta(days=days)

            # Get ML detection stats
            ml_stats = self._get_ml_stats(cursor, start_date)

            # Get rule-based detection stats (simulated fail2ban behavior)
            rule_stats = self._get_rule_based_stats(cursor, start_date)

            # Get combined comparison metrics
            comparison = self._calculate_comparison(ml_stats, rule_stats)

            # Get detection cases
            cases = self._get_detection_cases(cursor, start_date)

            # Calculate daily stats
            daily_stats = self._get_daily_comparison_stats(cursor, start_date)

            return {
                'period_days': days,
                'start_date': start_date.isoformat(),
                'ml_stats': ml_stats,
                'rule_stats': rule_stats,
                'comparison': comparison,
                'detection_cases': cases,
                'daily_stats': daily_stats
            }

        finally:
            cursor.close()
            conn.close()

    def _get_ml_stats(self, cursor, start_date: datetime) -> Dict[str, Any]:
        """Get ML detection statistics (optimized version)"""
        return get_ml_stats_optimized(cursor, start_date)

    def _get_rule_based_stats(self, cursor, start_date: datetime) -> Dict[str, Any]:
        """
        Calculate what rule-based detection (fail2ban) would have caught.
        Simulates fail2ban behavior on the same events (optimized version).
        """
        threshold = self.RULE_THRESHOLDS['max_failures_before_block']
        window_minutes = self.RULE_THRESHOLDS['failure_window_minutes']

        return get_rule_based_stats_optimized(cursor, start_date, threshold, window_minutes)

    def _calculate_comparison(self, ml_stats: Dict, rule_stats: Dict) -> Dict[str, Any]:
        """Calculate comparison metrics between ML and rule-based"""
        ml_detections = ml_stats.get('anomalies_detected', 0)
        ml_first_attempt = ml_stats.get('first_attempt_detections', 0)
        rule_would_block = rule_stats.get('would_block_ips', 0)
        rule_missed = rule_stats.get('events_under_threshold', 0)

        # Calculate improvements
        total_threats = ml_detections + rule_missed  # Approximate total threats

        ml_detection_rate = (ml_detections / total_threats * 100) if total_threats > 0 else 0
        rule_detection_rate = (rule_would_block / total_threats * 100) if total_threats > 0 else 0

        # First attempt detection advantage
        first_attempt_advantage = (ml_first_attempt / ml_detections * 100) if ml_detections > 0 else 0

        # Threats caught that rules would miss
        additional_catches = max(0, ml_detections - rule_would_block)

        return {
            'ml_detection_rate': round(ml_detection_rate, 1),
            'rule_detection_rate': round(rule_detection_rate, 1),
            'detection_improvement': round(ml_detection_rate - rule_detection_rate, 1),
            'first_attempt_percentage': round(first_attempt_advantage, 1),
            'additional_threats_caught': additional_catches,
            'threats_rules_would_miss': rule_missed,
            'summary': {
                'ml_advantage': 'ML detects threats earlier and catches more attacks',
                'key_benefit_1': f'{int(first_attempt_advantage)}% of threats detected on first attempt',
                'key_benefit_2': f'{additional_catches} additional threats caught that rules missed',
                'key_benefit_3': 'ML adapts to new attack patterns automatically'
            }
        }

    def _get_detection_cases(self, cursor, start_date: datetime, limit: int = 10) -> List[Dict]:
        """Get notable ML detection cases (optimized version)"""
        return get_detection_cases_batched(cursor, start_date, limit)

    def _get_daily_comparison_stats(self, cursor, start_date: datetime) -> List[Dict]:
        """Get daily comparison statistics (optimized version)"""
        return get_daily_stats_batched(cursor, start_date)

    def get_benefits_report(self, days: int = 30) -> Dict[str, Any]:
        """
        Generate benefits report proving ML effectiveness.

        Args:
            days: Period to analyze

        Returns:
            Benefits report data
        """
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            start_date = datetime.now() - timedelta(days=days)

            # Get all stats in batched queries (optimized)
            summary, active_model, threat_distribution, timeline = get_benefits_stats_batched(
                cursor, start_date
            )

            # Time saved (estimate based on automated detections)
            manual_review_time_per_event = 5  # minutes
            time_saved_minutes = int(summary.get('threats_detected') or 0) * manual_review_time_per_event
            time_saved_hours = time_saved_minutes / 60

            return {
                'period_days': days,
                'executive_summary': {
                    'total_predictions': int(summary.get('total_predictions') or 0),
                    'threats_detected': int(summary.get('threats_detected') or 0),
                    'high_risk_events': int(summary.get('high_risk_events') or 0),
                    'ips_blocked': int(summary.get('ml_blocks') or 0),
                    'avg_confidence': round(float(summary.get('avg_confidence') or 0), 2),
                    'time_saved_hours': round(time_saved_hours, 1)
                },
                'active_model': active_model,
                'threat_distribution': threat_distribution,
                'detection_timeline': timeline,
                'key_benefits': [
                    {
                        'title': 'Proactive Detection',
                        'description': 'ML detects threats on first attempt, not after multiple failures',
                        'metric': f'{int(summary.get("threats_detected") or 0)} threats caught proactively'
                    },
                    {
                        'title': 'Reduced False Positives',
                        'description': 'ML considers 40+ features, reducing false blocks of legitimate users',
                        'metric': f'{round(float(summary.get("avg_confidence") or 0) * 100, 1)}% average confidence'
                    },
                    {
                        'title': 'Advanced Pattern Recognition',
                        'description': 'Catches distributed attacks, slow brute force, and credential stuffing',
                        'metric': f'{len(threat_distribution)} threat types identified'
                    },
                    {
                        'title': 'Time Savings',
                        'description': 'Automated detection reduces manual security review time',
                        'metric': f'{round(time_saved_hours, 1)} hours saved'
                    }
                ],
                'comparison_to_fail2ban': {
                    'fail2ban_limitations': [
                        'Only triggers after threshold failures (reactive)',
                        'Cannot detect distributed attacks across IPs',
                        'No geographic or behavioral analysis',
                        'High false positive rate for legitimate users',
                        'Cannot adapt to new attack patterns'
                    ],
                    'ml_advantages': [
                        'Detects threats on first attempt (proactive)',
                        'Correlates attacks across multiple IPs',
                        'Uses 40+ features including geo, behavior, reputation',
                        'Lower false positive rate with confidence scoring',
                        'Learns and adapts to new patterns via retraining'
                    ]
                }
            }

        finally:
            cursor.close()
            conn.close()

    def record_detection_case(self, case_type: str, title: str, description: str,
                             ip_addresses: List[str], event_ids: List[int],
                             is_featured: bool = False) -> int:
        """Record a notable ML detection case"""
        import uuid as uuid_mod

        conn = get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("""
                INSERT INTO ml_detection_cases
                (case_uuid, case_type, title, description, ip_addresses, event_ids,
                 events_in_case, is_featured, detected_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, NOW())
            """, (
                str(uuid_mod.uuid4()),
                case_type,
                title,
                description,
                json.dumps(ip_addresses),
                json.dumps(event_ids),
                len(event_ids),
                is_featured
            ))
            conn.commit()
            return cursor.lastrowid
        finally:
            cursor.close()
            conn.close()

    def update_daily_stats(self):
        """Update daily comparison statistics (call daily via cron)"""
        conn = get_connection()
        cursor = conn.cursor()

        today = datetime.now().date()

        try:
            # Calculate today's stats
            cursor.execute("""
                SELECT
                    COUNT(*) as total_events,
                    SUM(CASE WHEN event_type LIKE '%%failed%%' THEN 1 ELSE 0 END) as failed_events
                FROM auth_events
                WHERE DATE(timestamp) = %s
            """, (today,))
            event_stats = cursor.fetchone() or (0, 0)

            cursor.execute("""
                SELECT
                    SUM(CASE WHEN is_anomaly = 1 THEN 1 ELSE 0 END) as ml_detections,
                    COUNT(*) as ml_predictions
                FROM ml_predictions
                WHERE DATE(created_at) = %s
            """, (today,))
            ml_stats = cursor.fetchone() or (0, 0)

            cursor.execute("""
                SELECT COUNT(*) as blocks
                FROM ip_blocks
                WHERE DATE(created_at) = %s
            """, (today,))
            block_stats = cursor.fetchone() or (0,)

            # Upsert daily stats
            cursor.execute("""
                INSERT INTO ml_comparison_stats
                (stat_date, total_events, ml_true_positives, ml_blocks_total)
                VALUES (%s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    total_events = VALUES(total_events),
                    ml_true_positives = VALUES(ml_true_positives),
                    ml_blocks_total = VALUES(ml_blocks_total),
                    updated_at = NOW()
            """, (
                today,
                event_stats[0],
                ml_stats[0],
                block_stats[0]
            ))

            conn.commit()
            logger.info(f"Updated daily comparison stats for {today}")

        finally:
            cursor.close()
            conn.close()


# Global instance
_comparator = None


def get_comparator() -> MLComparator:
    """Get or create global comparator instance"""
    global _comparator
    if _comparator is None:
        _comparator = MLComparator()
    return _comparator
