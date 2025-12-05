"""
SSH Guardian v3.0 - ML Trainer Optimized Queries
Centralized database queries with optimizations for the ML trainer
"""

import sys
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple

# Add project paths
PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.append(str(PROJECT_ROOT / "dbs"))

from connection import get_connection


def fetch_training_data(data_start: datetime, data_end: datetime,
                        include_simulation: bool = True) -> List[Dict[str, Any]]:
    """
    Optimized query to fetch training data with geolocation and threat intelligence.

    Optimizations:
    - Single query with LEFT JOINs (indexed foreign keys)
    - Fetches all rows at once (no iteration)
    - Only selects needed columns

    Args:
        data_start: Start date for training data
        data_end: End date for training data
        include_simulation: Include simulation events

    Returns:
        List of event dictionaries with nested geo and threat data

    Raises:
        Exception: Database connection or query errors
    """
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # Optimized query - only fetch needed columns
        query = """
            SELECT
                ae.id, ae.timestamp, ae.event_type, ae.source_ip_text,
                ae.target_username, ae.target_server, ae.auth_method,
                ae.failure_reason, ae.source_type,
                g.country_code, g.city, g.latitude, g.longitude,
                g.is_proxy, g.is_vpn, g.is_tor, g.is_datacenter, g.asn,
                t.abuseipdb_score, t.virustotal_positives, t.overall_threat_level
            FROM auth_events ae
            LEFT JOIN ip_geolocation g ON ae.geo_id = g.id
            LEFT JOIN ip_threat_intelligence t ON ae.source_ip_text = t.ip_address_text
            WHERE ae.timestamp BETWEEN %s AND %s
        """

        params = [data_start, data_end]

        if not include_simulation:
            query += " AND ae.source_type != 'simulation'"

        query += " ORDER BY ae.timestamp"

        cursor.execute(query, params)
        events = cursor.fetchall()

        return events if events else []

    except Exception as e:
        raise Exception(f"Failed to fetch training data: {e}")
    finally:
        cursor.close()
        conn.close()


def batch_update_training_run(run_id: int, updates: Dict[str, Any]) -> None:
    """
    Batch update training run with multiple fields in a single query.

    Optimization: Reduces multiple UPDATE queries to a single operation.

    Args:
        run_id: Training run ID
        updates: Dictionary of field->value pairs to update

    Raises:
        Exception: Database errors
    """
    if not updates:
        return

    conn = get_connection()
    cursor = conn.cursor()

    try:
        # Build dynamic UPDATE query
        set_clauses = []
        params = []

        for field, value in updates.items():
            set_clauses.append(f"{field} = %s")
            params.append(value)

        params.append(run_id)

        query = f"""
            UPDATE ml_training_runs
            SET {', '.join(set_clauses)}
            WHERE id = %s
        """

        cursor.execute(query, params)
        conn.commit()

    except Exception as e:
        conn.rollback()
        raise Exception(f"Failed to update training run {run_id}: {e}")
    finally:
        cursor.close()
        conn.close()


def update_training_run_progress(run_id: int, status: str, progress: int,
                                  stage: str) -> None:
    """
    Update training run status and progress in a single query.

    Args:
        run_id: Training run ID
        status: Status string
        progress: Progress percentage
        stage: Current stage description

    Raises:
        Exception: Database errors
    """
    batch_update_training_run(run_id, {
        'status': status,
        'progress_percent': progress,
        'current_stage': stage
    })


def update_training_run_samples(run_id: int, total_samples: int) -> None:
    """
    Update sample counts in training run (80/20 split).

    Args:
        run_id: Training run ID
        total_samples: Total number of samples

    Raises:
        Exception: Database errors
    """
    training_samples = int(total_samples * 0.8)
    test_samples = total_samples - training_samples

    batch_update_training_run(run_id, {
        'total_samples': total_samples,
        'training_samples': training_samples,
        'test_samples': test_samples
    })


def complete_training_run(run_id: int, model_id: int) -> None:
    """
    Mark training run as completed with model ID.

    Args:
        run_id: Training run ID
        model_id: Associated model ID

    Raises:
        Exception: Database errors
    """
    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("""
            UPDATE ml_training_runs
            SET status = 'completed', progress_percent = 100,
                model_id = %s, completed_at = NOW(),
                duration_seconds = TIMESTAMPDIFF(SECOND, started_at, NOW())
            WHERE id = %s
        """, (model_id, run_id))
        conn.commit()
    except Exception as e:
        conn.rollback()
        raise Exception(f"Failed to complete training run {run_id}: {e}")
    finally:
        cursor.close()
        conn.close()


def fail_training_run(run_id: int, error_message: str) -> None:
    """
    Mark training run as failed with error message.

    Args:
        run_id: Training run ID
        error_message: Error description

    Raises:
        Exception: Database errors
    """
    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("""
            UPDATE ml_training_runs
            SET status = 'failed', error_message = %s,
                completed_at = NOW(),
                duration_seconds = TIMESTAMPDIFF(SECOND, started_at, NOW())
            WHERE id = %s
        """, (error_message, run_id))
        conn.commit()
    except Exception as e:
        conn.rollback()
        raise Exception(f"Failed to update training run {run_id}: {e}")
    finally:
        cursor.close()
        conn.close()


def promote_model_to_production(model_id: int) -> None:
    """
    Promote model to production, demoting current active model.

    Optimization: Uses a single transaction with two UPDATEs.

    Args:
        model_id: Model ID to promote

    Raises:
        Exception: Database errors
    """
    conn = get_connection()
    cursor = conn.cursor()

    try:
        # Demote current active model
        cursor.execute("""
            UPDATE ml_models
            SET is_active = FALSE, status = 'deprecated',
                deprecated_at = NOW()
            WHERE is_active = TRUE
        """)

        # Promote new model
        cursor.execute("""
            UPDATE ml_models
            SET is_active = TRUE, status = 'production',
                promoted_to_production_at = NOW()
            WHERE id = %s
        """, (model_id,))

        conn.commit()

    except Exception as e:
        conn.rollback()
        raise Exception(f"Failed to promote model {model_id}: {e}")
    finally:
        cursor.close()
        conn.close()
