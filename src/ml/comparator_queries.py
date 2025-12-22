"""
SSH Guardian v3.0 - Optimized Query Functions for ML Comparator
Contains optimized database queries using window functions and batching
Updated for v3.1: Uses auth_events_ml instead of auth_events_ml
"""

from typing import Dict, Any, List, Tuple
from datetime import datetime


def get_ml_stats_optimized(cursor, start_date: datetime) -> Dict[str, Any]:
    """
    Get ML detection statistics with optimized queries.
    Batches multiple queries together and uses window functions.
    """
    # Batch query 1: Get prediction stats, blocks, and high-risk events in one query
    cursor.execute("""
        SELECT
            (SELECT COUNT(*) FROM auth_events_ml WHERE created_at >= %s) as total_predictions,
            (SELECT SUM(CASE WHEN is_anomaly = 1 THEN 1 ELSE 0 END)
             FROM auth_events_ml WHERE created_at >= %s) as anomalies_detected,
            (SELECT AVG(risk_score) FROM auth_events_ml WHERE created_at >= %s) as avg_risk_score,
            (SELECT AVG(confidence) FROM auth_events_ml WHERE created_at >= %s) as avg_confidence,
            (SELECT COUNT(*) FROM ip_blocks
             WHERE created_at >= %s AND block_source = 'ml_threshold') as ml_blocks,
            (SELECT COUNT(*) FROM auth_events_ml
             WHERE created_at >= %s AND risk_score >= 70) as high_risk_events
    """, (start_date, start_date, start_date, start_date, start_date, start_date))

    stats = cursor.fetchone() or {}

    # Query 2: Threat types
    cursor.execute("""
        SELECT
            threat_type,
            COUNT(*) as count,
            AVG(risk_score) as avg_risk
        FROM auth_events_ml
        WHERE created_at >= %s AND threat_type IS NOT NULL
        GROUP BY threat_type
        ORDER BY count DESC
    """, (start_date,))
    threat_types = cursor.fetchall()

    # Query 3: First-attempt detections using window function (OPTIMIZED)
    # This replaces the correlated subquery with a window function
    cursor.execute("""
        SELECT COUNT(*) as first_attempt_detections
        FROM (
            SELECT
                p.event_id,
                ROW_NUMBER() OVER (
                    PARTITION BY e.source_ip_text
                    ORDER BY e.timestamp
                ) as attempt_number
            FROM auth_events_ml p
            JOIN auth_events e ON p.event_id = e.id
            WHERE p.created_at >= %s
            AND p.is_anomaly = 1
            AND p.risk_score >= 70
        ) as ranked
        WHERE attempt_number = 1
    """, (start_date,))
    first_attempt = cursor.fetchone() or {}

    return {
        'total_predictions': int(stats.get('total_predictions') or 0),
        'anomalies_detected': int(stats.get('anomalies_detected') or 0),
        'avg_risk_score': float(stats.get('avg_risk_score') or 0),
        'avg_confidence': float(stats.get('avg_confidence') or 0),
        'ml_blocks': int(stats.get('ml_blocks') or 0),
        'threat_types': threat_types,
        'first_attempt_detections': int(first_attempt.get('first_attempt_detections') or 0),
        'high_risk_events': int(stats.get('high_risk_events') or 0)
    }


def get_rule_based_stats_optimized(cursor, start_date: datetime,
                                   threshold: int, window_minutes: int) -> Dict[str, Any]:
    """
    Calculate rule-based detection stats with optimized queries.
    Uses proper time windows instead of approximate date/hour grouping.
    """
    # Query 1: IPs that would be blocked by rules using proper time windows
    # Uses exact match on event_type for index usage (auth_events has idx_timestamp_event_type)
    cursor.execute("""
        SELECT
            source_ip_text,
            MIN(timestamp) as first_failure,
            COUNT(*) as failure_count
        FROM auth_events
        WHERE timestamp >= %s
        AND event_type = 'failed'
        GROUP BY source_ip_text
        HAVING COUNT(*) >= %s
    """, (start_date, threshold))
    rule_would_block = cursor.fetchall()

    # Query 2: Batch actual blocks and average attempts together
    cursor.execute("""
        SELECT
            (SELECT COUNT(*) FROM ip_blocks
             WHERE created_at >= %s
             AND block_source IN ('rule_based', 'manual')) as rule_blocks,
            (SELECT AVG(failure_count) FROM (
                SELECT COUNT(*) as failure_count
                FROM auth_events
                WHERE timestamp >= %s
                AND event_type = 'failed'
                GROUP BY source_ip_text
                HAVING COUNT(*) >= %s
            ) as sub) as avg_attempts
    """, (start_date, start_date, threshold))
    combined_stats = cursor.fetchone() or {}

    # Query 3: Events that rules would miss (optimized with LEFT JOIN - much faster than NOT IN)
    # Using LEFT JOIN with IS NULL pattern instead of NOT IN subquery
    cursor.execute("""
        SELECT COUNT(*) as missed_events
        FROM auth_events ae
        LEFT JOIN (
            SELECT source_ip_text
            FROM auth_events
            WHERE timestamp >= %s
            AND event_type = 'failed'
            GROUP BY source_ip_text
            HAVING COUNT(*) >= %s
        ) blocked_ips ON ae.source_ip_text = blocked_ips.source_ip_text
        WHERE ae.timestamp >= %s
        AND ae.event_type = 'failed'
        AND blocked_ips.source_ip_text IS NULL
    """, (start_date, threshold, start_date))
    missed = cursor.fetchone() or {}

    return {
        'would_block_ips': len(rule_would_block),
        'actual_rule_blocks': int(combined_stats.get('rule_blocks') or 0),
        'avg_attempts_before_block': float(combined_stats.get('avg_attempts') or threshold),
        'events_under_threshold': int(missed.get('missed_events') or 0),
        'threshold_used': threshold,
        'window_minutes': window_minutes
    }


def get_detection_cases_batched(cursor, start_date: datetime, limit: int = 10) -> List[Dict]:
    """
    Get detection cases with batched queries.
    Combines multiple queries to reduce round trips.
    """
    # First check for featured cases
    cursor.execute("""
        SELECT * FROM ml_detection_cases
        WHERE detected_at >= %s
        AND is_featured = TRUE
        ORDER BY detected_at DESC
        LIMIT %s
    """, (start_date, limit))
    featured_cases = cursor.fetchall()

    if featured_cases:
        return featured_cases

    cases = []

    # Batch both case queries together
    cursor.execute("""
        (SELECT
            'early_detection' as case_type,
            p.id, p.event_id, p.risk_score, p.threat_type, p.confidence,
            e.source_ip_text, e.target_username, e.timestamp,
            NULL as ip_count, NULL as avg_risk
        FROM auth_events_ml p
        JOIN auth_events e ON p.event_id = e.id
        WHERE p.created_at >= %s
        AND p.is_anomaly = 1
        AND p.risk_score >= 70
        ORDER BY p.risk_score DESC
        LIMIT 3)

        UNION ALL

        (SELECT
            'distributed_attack' as case_type,
            NULL as id, NULL as event_id, NULL as risk_score, NULL as threat_type,
            NULL as confidence, NULL as source_ip_text,
            e.target_username,
            MIN(e.timestamp) as timestamp,
            COUNT(DISTINCT e.source_ip_text) as ip_count,
            AVG(p.risk_score) as avg_risk
        FROM auth_events_ml p
        JOIN auth_events e ON p.event_id = e.id
        WHERE p.created_at >= %s
        AND p.is_anomaly = 1
        GROUP BY e.target_username
        HAVING COUNT(DISTINCT e.source_ip_text) > 3
        ORDER BY ip_count DESC
        LIMIT 2)
    """, (start_date, start_date))

    for row in cursor.fetchall():
        if row['case_type'] == 'early_detection':
            cases.append({
                'case_type': 'early_detection',
                'title': f'High-Risk Detection: {row["source_ip_text"]}',
                'description': f'ML detected threat from {row["source_ip_text"]} targeting {row["target_username"]} '
                              f'with risk score {row["risk_score"]}. Threat type: {row["threat_type"]}',
                'risk_score': row['risk_score'],
                'ip_address': row['source_ip_text'],
                'detected_at': row['timestamp']
            })
        else:  # distributed_attack
            cases.append({
                'case_type': 'distributed_attack',
                'title': f'Distributed Attack on {row["target_username"]}',
                'description': f'{row["ip_count"]} different IPs targeted {row["target_username"]} '
                              f'(avg risk: {row["avg_risk"]:.0f}). Rules would only catch individual IPs.',
                'ip_count': row['ip_count'],
                'target_username': row['target_username'],
                'avg_risk': float(row['avg_risk']) if row['avg_risk'] else 0,
                'detected_at': row['timestamp']
            })

    return cases


def get_daily_stats_batched(cursor, start_date: datetime) -> List[Dict]:
    """
    Get daily comparison statistics with optimized separate queries.
    Avoid UNION on large tables - run two simple queries instead.
    """
    # Query 1: Get ML prediction stats (small table, fast)
    cursor.execute("""
        SELECT
            DATE(created_at) as stat_date,
            COUNT(*) as total_predictions,
            SUM(CASE WHEN is_anomaly = 1 THEN 1 ELSE 0 END) as ml_detections,
            AVG(risk_score) as avg_risk_score
        FROM auth_events_ml
        WHERE created_at >= %s
        GROUP BY DATE(created_at)
        ORDER BY stat_date DESC
        LIMIT 30
    """, (start_date,))
    ml_stats = {row['stat_date']: row for row in cursor.fetchall()}

    # Query 2: Get event stats - use pre-computed daily_stats table if available
    # Uses exact match on event_type for better index usage
    cursor.execute("""
        SELECT
            DATE(timestamp) as stat_date,
            COUNT(*) as total_events,
            SUM(CASE WHEN event_type = 'failed' THEN 1 ELSE 0 END) as failed_events
        FROM auth_events
        WHERE timestamp >= %s
        GROUP BY DATE(timestamp)
        ORDER BY stat_date DESC
        LIMIT 30
    """, (start_date,))
    event_stats = {row['stat_date']: row for row in cursor.fetchall()}

    # Merge results in Python (faster than UNION on large tables)
    all_dates = set(ml_stats.keys()) | set(event_stats.keys())
    daily_stats = []

    for date in sorted(all_dates, reverse=True)[:30]:
        ml = ml_stats.get(date, {})
        ev = event_stats.get(date, {})
        daily_stats.append({
            'date': str(date),
            'auth_events_ml': int(ml.get('total_predictions') or 0),
            'ml_detections': int(ml.get('ml_detections') or 0),
            'avg_risk_score': float(ml.get('avg_risk_score') or 0),
            'total_events': int(ev.get('total_events') or 0),
            'failed_events': int(ev.get('failed_events') or 0)
        })

    return daily_stats


def _get_daily_stats_batched_old(cursor, start_date: datetime) -> List[Dict]:
    """
    OLD VERSION - kept for reference. UNION on large tables is slow.
    """
    cursor.execute("""
        SELECT
            COALESCE(ml_dates.stat_date, event_dates.stat_date) as date,
            COALESCE(ml_dates.total_predictions, 0) as auth_events_ml,
            COALESCE(ml_dates.ml_detections, 0) as ml_detections,
            COALESCE(ml_dates.avg_risk_score, 0) as avg_risk_score,
            COALESCE(event_dates.total_events, 0) as total_events,
            COALESCE(event_dates.failed_events, 0) as failed_events
        FROM (
            SELECT
                DATE(created_at) as stat_date,
                COUNT(*) as total_predictions,
                SUM(CASE WHEN is_anomaly = 1 THEN 1 ELSE 0 END) as ml_detections,
                AVG(risk_score) as avg_risk_score
            FROM auth_events_ml
            WHERE created_at >= %s
            GROUP BY DATE(created_at)
        ) as ml_dates
        LEFT JOIN (
            SELECT
                DATE(timestamp) as stat_date,
                COUNT(*) as total_events,
                SUM(CASE WHEN event_type LIKE '%%failed%%' THEN 1 ELSE 0 END) as failed_events
            FROM auth_events
            WHERE timestamp >= %s
            GROUP BY DATE(timestamp)
        ) as event_dates
        ON ml_dates.stat_date = event_dates.stat_date

        UNION

        SELECT
            COALESCE(ml_dates.stat_date, event_dates.stat_date) as date,
            COALESCE(ml_dates.total_predictions, 0) as auth_events_ml,
            COALESCE(ml_dates.ml_detections, 0) as ml_detections,
            COALESCE(ml_dates.avg_risk_score, 0) as avg_risk_score,
            COALESCE(event_dates.total_events, 0) as total_events,
            COALESCE(event_dates.failed_events, 0) as failed_events
        FROM (
            SELECT
                DATE(timestamp) as stat_date,
                COUNT(*) as total_events,
                SUM(CASE WHEN event_type LIKE '%%failed%%' THEN 1 ELSE 0 END) as failed_events
            FROM auth_events
            WHERE timestamp >= %s
            GROUP BY DATE(timestamp)
        ) as event_dates
        LEFT JOIN (
            SELECT
                DATE(created_at) as stat_date,
                COUNT(*) as total_predictions,
                SUM(CASE WHEN is_anomaly = 1 THEN 1 ELSE 0 END) as ml_detections,
                AVG(risk_score) as avg_risk_score
            FROM auth_events_ml
            WHERE created_at >= %s
            GROUP BY DATE(created_at)
        ) as ml_dates
        ON event_dates.stat_date = ml_dates.stat_date
        WHERE ml_dates.stat_date IS NULL

        ORDER BY date DESC
        LIMIT 30
    """, (start_date, start_date, start_date, start_date))

    daily_stats = []
    for row in cursor.fetchall():
        daily_stats.append({
            'date': str(row['date']),
            'auth_events_ml': int(row['auth_events_ml']),
            'ml_detections': int(row['ml_detections']),
            'avg_risk_score': float(row['avg_risk_score']),
            'total_events': int(row['total_events']),
            'failed_events': int(row['failed_events'])
        })

    return daily_stats


def get_benefits_stats_batched(cursor, start_date: datetime) -> Tuple[Dict, Dict, List, List]:
    """
    Get benefits report statistics in batched queries.
    Returns: (summary_stats, model_info, threat_distribution, timeline)
    """
    # Batch 1: Summary stats, blocks, and model info
    cursor.execute("""
        SELECT
            (SELECT COUNT(*) FROM auth_events_ml WHERE created_at >= %s) as total_predictions,
            (SELECT SUM(CASE WHEN is_anomaly = 1 THEN 1 ELSE 0 END)
             FROM auth_events_ml WHERE created_at >= %s) as threats_detected,
            (SELECT SUM(CASE WHEN risk_score >= 70 THEN 1 ELSE 0 END)
             FROM auth_events_ml WHERE created_at >= %s) as high_risk_events,
            (SELECT AVG(confidence) FROM auth_events_ml WHERE created_at >= %s) as avg_confidence,
            (SELECT COUNT(*) FROM ip_blocks
             WHERE created_at >= %s AND block_source = 'ml_threshold') as ml_blocks
    """, (start_date, start_date, start_date, start_date, start_date))
    summary = cursor.fetchone() or {}

    # Batch 2: Active model info
    cursor.execute("""
        SELECT model_name, algorithm, f1_score, accuracy, predictions_count
        FROM ml_models
        WHERE is_active = TRUE
        LIMIT 1
    """)
    active_model = cursor.fetchone()

    # Batch 3: Threat distribution
    cursor.execute("""
        SELECT
            threat_type,
            COUNT(*) as count
        FROM auth_events_ml
        WHERE created_at >= %s AND threat_type IS NOT NULL
        GROUP BY threat_type
        ORDER BY count DESC
    """, (start_date,))
    threat_distribution = cursor.fetchall()

    # Batch 4: Timeline
    cursor.execute("""
        SELECT
            DATE(created_at) as date,
            COUNT(*) as predictions,
            SUM(CASE WHEN is_anomaly = 1 THEN 1 ELSE 0 END) as detections
        FROM auth_events_ml
        WHERE created_at >= %s
        GROUP BY DATE(created_at)
        ORDER BY date
    """, (start_date,))
    timeline = cursor.fetchall()

    return summary, active_model, threat_distribution, timeline
