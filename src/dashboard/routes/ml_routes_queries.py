"""
SSH Guardian v3.1 - ML Routes Optimized Queries
Optimized database queries to reduce round-trips and improve performance
Updated for v3.1 schema (ml_predictions → auth_events_ml)
"""

from typing import Dict, List, Any, Optional, Tuple


def get_overview_data(cursor) -> Dict[str, Any]:
    """
    Optimized overview query - combines multiple queries into 2 for better performance.
    v3.1: Uses auth_events_ml instead of ml_predictions

    Args:
        cursor: Database cursor (dictionary=True)

    Returns:
        Dict containing overview data structure
    """

    # Query 1: Combine all prediction and block statistics using CASE WHEN
    # v3.1: auth_events_ml instead of ml_predictions
    cursor.execute("""
        SELECT
            -- Today's prediction stats
            COUNT(CASE WHEN DATE(p.created_at) = CURDATE() THEN 1 END) as predictions_today,
            SUM(CASE WHEN DATE(p.created_at) = CURDATE() AND p.is_anomaly = 1 THEN 1 ELSE 0 END) as anomalies_today,
            AVG(CASE WHEN DATE(p.created_at) = CURDATE() THEN p.risk_score END) as avg_risk_today,
            AVG(CASE WHEN DATE(p.created_at) = CURDATE() THEN p.confidence END) as avg_confidence_today,
            SUM(CASE WHEN DATE(p.created_at) = CURDATE() AND p.risk_score >= 0.70 THEN 1 ELSE 0 END) as high_risk_today,

            -- Week's prediction stats
            COUNT(CASE WHEN p.created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY) THEN 1 END) as predictions_week,
            SUM(CASE WHEN p.created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY) AND p.is_anomaly = 1 THEN 1 ELSE 0 END) as anomalies_week,

            -- ML blocks today (from subquery)
            (SELECT COUNT(*) FROM ip_blocks
             WHERE DATE(blocked_at) = CURDATE() AND block_source = 'ml_threshold') as ml_blocks_today
        FROM auth_events_ml p
    """)
    stats = cursor.fetchone() or {}

    # Query 2: Get active model with ALL metrics
    cursor.execute("""
        SELECT m.*,
               cr.training_samples, cr.testing_samples, cr.feature_count,
               cr.confusion_matrix, cr.hyperparameters, cr.feature_importance,
               cr.specificity, cr.balanced_accuracy, cr.matthews_correlation,
               cr.training_time_seconds, cr.prediction_time_ms, cr.memory_usage_mb,
               cr.cv_mean, cr.cv_std, cr.cv_scores,
               cr.true_positives, cr.true_negatives, cr.false_positives, cr.false_negatives,
               tr.run_name, tr.total_events_generated, tr.benign_count, tr.malicious_count
        FROM ml_models m
        LEFT JOIN ml_comparison_results cr ON cr.model_name COLLATE utf8mb4_unicode_ci = m.model_name COLLATE utf8mb4_unicode_ci
        LEFT JOIN ml_training_runs tr ON cr.run_id = tr.id
        WHERE m.is_active = TRUE
        ORDER BY cr.id DESC
        LIMIT 1
    """)
    active_model_row = cursor.fetchone()

    # Query 3: Get model counts and threat types
    cursor.execute("""
        (
            SELECT 'model_counts' as type,
                   NULL as threat_type, NULL as count,
                   COUNT(*) as total_models,
                   SUM(CASE WHEN is_active = 1 THEN 1 ELSE 0 END) as production_models,
                   SUM(CASE WHEN status = 'candidate' THEN 1 ELSE 0 END) as candidate_models
            FROM ml_models
            LIMIT 1
        )
        UNION ALL
        (
            SELECT 'threat_type' as type,
                   p.threat_type,
                   COUNT(*) as count,
                   NULL, NULL, NULL
            FROM auth_events_ml p
            WHERE DATE(p.created_at) = CURDATE() AND p.threat_type IS NOT NULL
            GROUP BY p.threat_type
            ORDER BY count DESC
        )
    """)

    combined_results = cursor.fetchall()

    # Parse the combined results
    model_counts = {'total_models': 0, 'production_models': 0, 'candidate_models': 0}
    threat_types = []

    for row in combined_results:
        if row['type'] == 'model_counts':
            model_counts = {
                'total_models': int(row['total_models'] or 0),
                'production_models': int(row['production_models'] or 0),
                'candidate_models': int(row['candidate_models'] or 0)
            }
        elif row['type'] == 'threat_type':
            threat_types.append({
                'threat_type': row['threat_type'],
                'count': int(row['count'])
            })

    # Parse JSON fields if present
    import json
    confusion_matrix = None
    hyperparameters = None
    feature_importance = None
    cv_scores = None
    if active_model_row:
        for field_name in ['confusion_matrix', 'hyperparameters', 'feature_importance', 'cv_scores']:
            if active_model_row.get(field_name):
                try:
                    val = active_model_row[field_name]
                    parsed = json.loads(val) if isinstance(val, str) else val
                    if field_name == 'confusion_matrix':
                        confusion_matrix = parsed
                    elif field_name == 'hyperparameters':
                        hyperparameters = parsed
                    elif field_name == 'feature_importance':
                        feature_importance = parsed
                    elif field_name == 'cv_scores':
                        cv_scores = parsed
                except:
                    pass

    # Build the active model data with ALL metrics
    active_model_data = None
    if active_model_row:
        m = active_model_row
        active_model_data = {
            'id': m.get('id'),
            'name': m.get('model_name'),
            'algorithm': m.get('algorithm'),
            'version': m.get('version'),
            'status': m.get('status'),
            # Core metrics
            'accuracy': float(m['accuracy']) if m.get('accuracy') else None,
            'precision_score': float(m['precision_score']) if m.get('precision_score') else None,
            'recall_score': float(m['recall_score']) if m.get('recall_score') else None,
            'f1_score': float(m['f1_score']) if m.get('f1_score') else None,
            'auc_roc': float(m['auc_roc']) if m.get('auc_roc') else None,
            # Extended metrics from comparison_results
            'specificity': float(m['specificity']) if m.get('specificity') else None,
            'balanced_accuracy': float(m['balanced_accuracy']) if m.get('balanced_accuracy') else None,
            'matthews_correlation': float(m['matthews_correlation']) if m.get('matthews_correlation') else None,
            # Training info
            'training_samples': int(m['training_samples']) if m.get('training_samples') else None,
            'testing_samples': int(m['testing_samples']) if m.get('testing_samples') else None,
            'feature_count': int(m['feature_count']) if m.get('feature_count') else None,
            'training_time_seconds': float(m['training_time_seconds']) if m.get('training_time_seconds') else None,
            'prediction_time_ms': float(m['prediction_time_ms']) if m.get('prediction_time_ms') else None,
            'memory_usage_mb': float(m['memory_usage_mb']) if m.get('memory_usage_mb') else None,
            'cv_mean': float(m['cv_mean']) if m.get('cv_mean') else None,
            'cv_std': float(m['cv_std']) if m.get('cv_std') else None,
            # Training run info
            'run_name': m.get('run_name'),
            'total_events_generated': int(m['total_events_generated']) if m.get('total_events_generated') else None,
            'benign_count': int(m['benign_count']) if m.get('benign_count') else None,
            'malicious_count': int(m['malicious_count']) if m.get('malicious_count') else None,
            # Confusion matrix values
            'true_positives': int(m['true_positives']) if m.get('true_positives') else None,
            'true_negatives': int(m['true_negatives']) if m.get('true_negatives') else None,
            'false_positives': int(m['false_positives']) if m.get('false_positives') else None,
            'false_negatives': int(m['false_negatives']) if m.get('false_negatives') else None,
            'confusion_matrix': confusion_matrix,
            'hyperparameters': hyperparameters,
            'feature_importance': feature_importance,
            'cv_scores': cv_scores,
            # Usage
            'predictions_count': int(m['predictions_count']) if m.get('predictions_count') else 0,
            'created_at': m['created_at'].isoformat() if m.get('created_at') else None
        }

    # Build the overview data structure
    # v3.1: risk_score is now decimal(5,4) so 0.70 = 70%
    overview_data = {
        'today': {
            'predictions': int(stats.get('predictions_today') or 0),
            'anomalies': int(stats.get('anomalies_today') or 0),
            'avg_risk_score': round(float(stats.get('avg_risk_today') or 0) * 100, 1),  # Convert to percentage
            'avg_confidence': round(float(stats.get('avg_confidence_today') or 0), 2),
            'high_risk_events': int(stats.get('high_risk_today') or 0),
            'ml_blocks': int(stats.get('ml_blocks_today') or 0)
        },
        'week': {
            'predictions': int(stats.get('predictions_week') or 0),
            'anomalies': int(stats.get('anomalies_week') or 0)
        },
        'active_model': active_model_data,
        'models': model_counts,
        'threat_types': threat_types
    }

    return overview_data


def get_dashboard_summary_data(cursor) -> Dict[str, Any]:
    """
    Optimized dashboard summary - combines queries into 1 for better performance.
    v3.1: Uses auth_events_ml instead of ml_predictions

    Args:
        cursor: Database cursor (dictionary=True)

    Returns:
        Dict containing dashboard summary data
    """

    # v3.1: Use auth_events_ml instead of ml_predictions
    cursor.execute("""
        SELECT
            -- Today's predictions and stats
            COUNT(CASE WHEN DATE(p.created_at) = CURDATE() THEN 1 END) as predictions_today,
            SUM(CASE WHEN DATE(p.created_at) = CURDATE() AND p.is_anomaly = 1 THEN 1 ELSE 0 END) as threats_detected,
            SUM(CASE WHEN DATE(p.created_at) = CURDATE() AND p.risk_score >= 0.70 THEN 1 ELSE 0 END) as high_risk,
            AVG(CASE WHEN DATE(p.created_at) = CURDATE() THEN p.risk_score END) as avg_risk,

            -- Active model info (using subquery)
            (SELECT model_name FROM ml_models WHERE is_active = TRUE LIMIT 1) as model_name,
            (SELECT algorithm FROM ml_models WHERE is_active = TRUE LIMIT 1) as algorithm,
            (SELECT f1_score FROM ml_models WHERE is_active = TRUE LIMIT 1) as f1_score,
            (SELECT accuracy FROM ml_models WHERE is_active = TRUE LIMIT 1) as accuracy,

            -- ML blocks today
            (SELECT COUNT(*) FROM ip_blocks
             WHERE DATE(blocked_at) = CURDATE() AND block_source = 'ml_threshold') as ml_blocks_count
        FROM auth_events_ml p
    """)

    result = cursor.fetchone() or {}

    ml_summary = {
        'predictions_today': int(result.get('predictions_today') or 0),
        'threats_detected': int(result.get('threats_detected') or 0),
        'high_risk_events': int(result.get('high_risk') or 0),
        'avg_risk_score': round(float(result.get('avg_risk') or 0) * 100, 1),  # Convert to percentage
        'ips_blocked_by_ml': int(result.get('ml_blocks_count') or 0),
        'active_model': result.get('model_name'),
        'model_accuracy': round(float(result.get('accuracy') or 0) * 100, 1) if result.get('accuracy') else None
    }

    return ml_summary


def get_predictions_cursor_paginated(
    cursor,
    limit: int = 50,
    cursor_id: Optional[int] = None,
    anomaly_only: bool = False,
    min_risk: int = 0,
    ip_filter: Optional[str] = None
) -> Tuple[List[Dict[str, Any]], Optional[int]]:
    """
    Cursor-based pagination for predictions - more efficient than OFFSET.
    v3.1: Uses auth_events_ml instead of ml_predictions

    Args:
        cursor: Database cursor (dictionary=True)
        limit: Maximum number of results
        cursor_id: Last prediction ID from previous page (None for first page)
        anomaly_only: Filter for anomalies only
        min_risk: Minimum risk score filter (as percentage, e.g., 70 for 70%)
        ip_filter: Filter by IP address

    Returns:
        Tuple of (predictions list, next_cursor_id)
    """

    where_clauses = []
    params = []

    # Cursor-based filtering
    if cursor_id is not None:
        where_clauses.append("p.id < %s")
        params.append(cursor_id)

    if anomaly_only:
        where_clauses.append("p.is_anomaly = 1")

    # v3.1: risk_score is decimal(5,4), so 70% = 0.70
    if min_risk > 0:
        where_clauses.append("p.risk_score >= %s")
        params.append(min_risk / 100.0)

    if ip_filter:
        where_clauses.append("e.source_ip_text = %s")
        params.append(ip_filter)

    where_sql = "WHERE " + " AND ".join(where_clauses) if where_clauses else ""

    # Fetch limit + 1 to determine if there are more results
    params.append(limit + 1)

    # v3.1: auth_events_ml instead of ml_predictions
    cursor.execute(f"""
        SELECT
            p.id, p.event_id, p.model_id, p.risk_score, p.threat_type,
            p.confidence, p.is_anomaly, p.was_blocked, p.created_at,
            e.source_ip_text, e.target_username, e.event_type,
            m.model_name, m.algorithm
        FROM auth_events_ml p
        JOIN auth_events e ON p.event_id = e.id
        LEFT JOIN ml_models m ON p.model_id = m.id
        {where_sql}
        ORDER BY p.id DESC
        LIMIT %s
    """, params)

    predictions = cursor.fetchall()

    # Check if there are more results
    has_more = len(predictions) > limit
    if has_more:
        predictions = predictions[:limit]

    # Format results
    formatted = []
    for p in predictions:
        # v3.1: Convert risk_score from decimal to percentage
        risk_score_pct = round(float(p['risk_score'] or 0) * 100, 1)
        formatted.append({
            'id': p['id'],
            'event_id': p['event_id'],
            'risk_score': risk_score_pct,
            'threat_type': p['threat_type'],
            'confidence': round(float(p['confidence'] or 0) * 100, 1),
            'is_anomaly': bool(p['is_anomaly']),
            'was_blocked': bool(p['was_blocked']) if p['was_blocked'] is not None else False,
            'created_at': p['created_at'].isoformat() if p['created_at'] else None,
            'event': {
                'ip': p['source_ip_text'],
                'username': p['target_username'],
                'type': p['event_type']
            },
            'model': {
                'name': p['model_name'],
                'algorithm': p['algorithm']
            }
        })

    # Return next cursor (last id in current page) if there are more results
    next_cursor = predictions[-1]['id'] if has_more and predictions else None

    return formatted, next_cursor
