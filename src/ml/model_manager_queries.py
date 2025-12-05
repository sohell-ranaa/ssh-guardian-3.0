"""
SSH Guardian v3.0 - ML Model Manager Database Queries
Optimized database query functions for ML model operations
"""

import logging
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)


def log_prediction_with_stats(conn, event_id: int, model_id: int, risk_score: int,
                               threat_type: Optional[str], confidence: float,
                               is_anomaly: bool) -> bool:
    """
    Log ML prediction and update model statistics in a single transaction.

    Combines INSERT + UPDATE operations to reduce database round-trips.
    Uses a single transaction with two statements for atomicity and performance.

    Args:
        conn: Database connection object
        event_id: ID of the auth event being predicted
        model_id: ID of the ML model used
        risk_score: Risk score (0-100)
        threat_type: Type of threat detected (optional)
        confidence: Prediction confidence (0.0-1.0)
        is_anomaly: Whether event is classified as anomaly

    Returns:
        bool: True if successful, False otherwise
    """
    cursor = None
    try:
        cursor = conn.cursor()

        # Execute both queries in a single transaction
        # 1. Insert prediction record
        cursor.execute("""
            INSERT INTO ml_predictions
            (event_id, model_id, risk_score, threat_type, confidence, is_anomaly, created_at)
            VALUES (%s, %s, %s, %s, %s, %s, NOW())
        """, (event_id, model_id, risk_score, threat_type, confidence, is_anomaly))

        # 2. Update model statistics
        cursor.execute("""
            UPDATE ml_models
            SET predictions_made = predictions_made + 1,
                last_prediction_at = NOW()
            WHERE id = %s
        """, (model_id,))

        # Commit transaction
        conn.commit()
        return True

    except Exception as e:
        # Rollback on error
        if conn:
            conn.rollback()
        logger.debug(f"Failed to log prediction: {e}")
        return False

    finally:
        if cursor:
            cursor.close()


def get_active_model_info(conn) -> Optional[Dict[str, Any]]:
    """
    Get information about the currently active production model.

    Args:
        conn: Database connection object

    Returns:
        dict: Model info (id, model_name, algorithm, metrics) or None
    """
    cursor = None
    try:
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT id, model_name, algorithm, accuracy, f1_score
            FROM ml_models
            WHERE is_active = TRUE AND status = 'production'
            LIMIT 1
        """)

        return cursor.fetchone()

    except Exception as e:
        logger.debug(f"Failed to get active model info: {e}")
        return None

    finally:
        if cursor:
            cursor.close()
