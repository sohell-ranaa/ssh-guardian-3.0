"""
SSH Guardian v3.0 - ML Intelligence Routes
API endpoints for ML overview, training, models, comparison, and benefits
With Redis caching for improved performance
"""

from flask import Blueprint, jsonify, request
import sys
from pathlib import Path
from datetime import datetime, timedelta
import threading

# Add project paths
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
sys.path.append(str(PROJECT_ROOT / "dbs"))
sys.path.append(str(PROJECT_ROOT / "src"))
sys.path.append(str(PROJECT_ROOT / "src" / "core"))

from connection import get_connection
from cache import get_cache, cache_key, cache_key_hash
from src.dashboard.routes.ml_routes_queries import (
    get_overview_data,
    get_dashboard_summary_data,
    get_predictions_cursor_paginated
)

# Create Blueprint
ml_routes = Blueprint('ml_routes', __name__, url_prefix='/api/ml')

# Cache TTLs
ML_OVERVIEW_TTL = 30        # 30 seconds for overview
ML_MODELS_TTL = 60          # 1 minute for model list
ML_MODEL_DETAIL_TTL = 120   # 2 minutes for model details
ML_TRAINING_RUNS_TTL = 30   # 30 seconds for training runs
ML_TRAINING_DATA_TTL = 60   # 1 minute for training data stats
ML_PREDICTIONS_TTL = 30     # 30 seconds for predictions
ML_TIMELINE_TTL = 60        # 1 minute for timeline
ML_COMPARISON_TTL = 120     # 2 minutes for comparison
ML_BENEFITS_TTL = 120       # 2 minutes for benefits
ML_DASHBOARD_TTL = 30       # 30 seconds for dashboard summary


def invalidate_ml_cache():
    """Invalidate all ML-related caches"""
    cache = get_cache()
    cache.delete_pattern('ml')

# Training job tracking
_training_jobs = {}


def _get_ml_module():
    """Lazy load ML module"""
    try:
        from ml import get_model_manager, get_trainer
        return get_model_manager(), get_trainer()
    except Exception as e:
        print(f"ML module not available: {e}")
        return None, None


def _get_comparator():
    """Lazy load comparator"""
    try:
        from ml.comparator import get_comparator
        return get_comparator()
    except Exception as e:
        print(f"Comparator not available: {e}")
        return None


# ============================================================================
# OVERVIEW ENDPOINTS
# ============================================================================

@ml_routes.route('/overview', methods=['GET'])
def get_overview():
    """
    Get ML overview statistics for dashboard with caching

    Returns summary of predictions, active model, detection rates
    """
    try:
        cache = get_cache()
        cache_k = cache_key('ml', 'overview')

        # Try cache first
        cached = cache.get(cache_k)
        if cached is not None:
            return jsonify({
                'success': True,
                'overview': cached,
                'from_cache': True
            }), 200

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            # Use optimized query function (reduces 7 queries to 2)
            overview_data = get_overview_data(cursor)

            # Cache the result
            cache.set(cache_k, overview_data, ML_OVERVIEW_TTL)

            return jsonify({
                'success': True,
                'overview': overview_data,
                'from_cache': False
            }), 200

        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        print(f"Error getting ML overview: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500


@ml_routes.route('/predictions/timeline', methods=['GET'])
def get_predictions_timeline():
    """Get predictions over time for charts with caching"""
    try:
        days = int(request.args.get('days', 7))

        cache = get_cache()
        cache_k = cache_key('ml', 'predictions_timeline', str(days))

        # Try cache first
        cached = cache.get(cache_k)
        if cached is not None:
            return jsonify({
                'success': True,
                'timeline': cached,
                'from_cache': True
            }), 200

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            cursor.execute("""
                SELECT
                    DATE(created_at) as date,
                    COUNT(*) as predictions,
                    SUM(CASE WHEN is_anomaly = 1 THEN 1 ELSE 0 END) as anomalies,
                    AVG(risk_score) as avg_risk
                FROM ml_predictions
                WHERE created_at >= DATE_SUB(NOW(), INTERVAL %s DAY)
                GROUP BY DATE(created_at)
                ORDER BY date
            """, (days,))

            timeline = cursor.fetchall()

            # Format for charts
            formatted = [{
                'date': str(row['date']),
                'predictions': int(row['predictions']),
                'anomalies': int(row['anomalies'] or 0),
                'avg_risk': round(float(row['avg_risk'] or 0), 1)
            } for row in timeline]

            # Cache the result
            cache.set(cache_k, formatted, ML_TIMELINE_TTL)

            return jsonify({
                'success': True,
                'timeline': formatted,
                'from_cache': False
            }), 200

        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================================================
# MODEL MANAGEMENT ENDPOINTS
# ============================================================================

@ml_routes.route('/models', methods=['GET'])
def list_models():
    """Get all ML models with caching"""
    try:
        status_filter = request.args.get('status', '')

        cache = get_cache()
        cache_k = cache_key('ml', 'models', status_filter)

        # Try cache first
        cached = cache.get(cache_k)
        if cached is not None:
            return jsonify({
                'success': True,
                'models': cached['models'],
                'count': cached['count'],
                'from_cache': True
            }), 200

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            query = """
                SELECT
                    id, model_uuid, model_name, algorithm, version, status, is_active,
                    accuracy, precision_score, recall_score, f1_score, roc_auc,
                    training_samples, test_samples, predictions_made,
                    training_completed_at, promoted_to_production_at, created_at
                FROM ml_models
            """

            params = []
            if status_filter:
                query += " WHERE status = %s"
                params.append(status_filter)

            query += " ORDER BY created_at DESC"

            cursor.execute(query, params)
            models = cursor.fetchall()

            # Format for response
            formatted = []
            for m in models:
                formatted.append({
                    'id': m['id'],
                    'uuid': m['model_uuid'],
                    'name': m['model_name'],
                    'algorithm': m['algorithm'],
                    'version': m['version'],
                    'status': m['status'],
                    'is_active': bool(m['is_active']),
                    'metrics': {
                        'accuracy': float(m['accuracy']) if m['accuracy'] else None,
                        'precision': float(m['precision_score']) if m['precision_score'] else None,
                        'recall': float(m['recall_score']) if m['recall_score'] else None,
                        'f1_score': float(m['f1_score']) if m['f1_score'] else None,
                        'roc_auc': float(m['roc_auc']) if m['roc_auc'] else None
                    },
                    'training_samples': m['training_samples'],
                    'test_samples': m['test_samples'],
                    'predictions_made': m['predictions_made'],
                    'trained_at': m['training_completed_at'].isoformat() if m['training_completed_at'] else None,
                    'created_at': m['created_at'].isoformat() if m['created_at'] else None
                })

            # Cache the result
            cache_data = {'models': formatted, 'count': len(formatted)}
            cache.set(cache_k, cache_data, ML_MODELS_TTL)

            return jsonify({
                'success': True,
                'models': formatted,
                'count': len(formatted),
                'from_cache': False
            }), 200

        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@ml_routes.route('/models/<int:model_id>', methods=['GET'])
def get_model(model_id):
    """Get detailed model information"""
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            cursor.execute("""
                SELECT * FROM ml_models WHERE id = %s
            """, (model_id,))

            model = cursor.fetchone()
            if not model:
                return jsonify({'success': False, 'error': 'Model not found'}), 404

            # Parse JSON fields
            import json
            for field in ['hyperparameters', 'feature_names', 'confusion_matrix', 'feature_importance']:
                if model.get(field):
                    try:
                        model[field] = json.loads(model[field])
                    except Exception:
                        pass

            return jsonify({
                'success': True,
                'model': model
            }), 200

        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@ml_routes.route('/models/<int:model_id>/promote', methods=['POST'])
def promote_model(model_id):
    """Promote model to production"""
    try:
        _, trainer = _get_ml_module()
        if trainer:
            success = trainer.promote_model(model_id)
            if success:
                return jsonify({'success': True, 'message': 'Model promoted to production'}), 200
            else:
                return jsonify({'success': False, 'error': 'Failed to promote model'}), 500
        else:
            return jsonify({'success': False, 'error': 'ML module not available'}), 500

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@ml_routes.route('/models/<int:model_id>/deprecate', methods=['POST'])
def deprecate_model(model_id):
    """Deprecate a model"""
    try:
        _, trainer = _get_ml_module()
        if trainer:
            success = trainer.deprecate_model(model_id)
            if success:
                return jsonify({'success': True, 'message': 'Model deprecated'}), 200
            else:
                return jsonify({'success': False, 'error': 'Failed to deprecate model'}), 500
        else:
            return jsonify({'success': False, 'error': 'ML module not available'}), 500

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================================================
# TRAINING ENDPOINTS
# ============================================================================

@ml_routes.route('/training/runs', methods=['GET'])
def list_training_runs():
    """Get training history"""
    try:
        limit = int(request.args.get('limit', 20))

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            cursor.execute("""
                SELECT
                    tr.id, tr.run_uuid, tr.algorithm, tr.status, tr.progress_percent,
                    tr.current_stage, tr.total_samples, tr.training_samples, tr.test_samples,
                    tr.data_start_date, tr.data_end_date, tr.started_at, tr.completed_at,
                    tr.duration_seconds, tr.error_message,
                    m.model_name, m.f1_score
                FROM ml_training_runs tr
                LEFT JOIN ml_models m ON tr.model_id = m.id
                ORDER BY tr.created_at DESC
                LIMIT %s
            """, (limit,))

            runs = cursor.fetchall()

            formatted = []
            for run in runs:
                formatted.append({
                    'id': run['id'],
                    'uuid': run['run_uuid'],
                    'algorithm': run['algorithm'],
                    'status': run['status'],
                    'progress': run['progress_percent'],
                    'current_stage': run['current_stage'],
                    'samples': {
                        'total': run['total_samples'],
                        'training': run['training_samples'],
                        'test': run['test_samples']
                    },
                    'data_range': {
                        'start': str(run['data_start_date']) if run['data_start_date'] else None,
                        'end': str(run['data_end_date']) if run['data_end_date'] else None
                    },
                    'started_at': run['started_at'].isoformat() if run['started_at'] else None,
                    'completed_at': run['completed_at'].isoformat() if run['completed_at'] else None,
                    'duration_seconds': run['duration_seconds'],
                    'error': run['error_message'],
                    'result_model': {
                        'name': run['model_name'],
                        'f1_score': float(run['f1_score']) if run['f1_score'] else None
                    } if run['model_name'] else None
                })

            return jsonify({
                'success': True,
                'runs': formatted
            }), 200

        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@ml_routes.route('/training/start', methods=['POST'])
def start_training():
    """
    Start a new training job

    Request body:
    {
        "algorithm": "random_forest" | "xgboost" | "gradient_boosting" | "all",
        "data_start": "2024-01-01",
        "data_end": "2024-12-31",
        "include_simulation": true,
        "hyperparameters": {} (optional)
    }
    """
    try:
        data = request.get_json()

        algorithm = data.get('algorithm', 'random_forest')
        data_start_str = data.get('data_start')
        data_end_str = data.get('data_end')
        include_simulation = data.get('include_simulation', True)
        hyperparameters = data.get('hyperparameters')

        # Default to last 30 days if no dates specified
        if data_end_str:
            data_end = datetime.strptime(data_end_str, '%Y-%m-%d')
        else:
            data_end = datetime.now()

        if data_start_str:
            data_start = datetime.strptime(data_start_str, '%Y-%m-%d')
        else:
            data_start = data_end - timedelta(days=30)

        # Get trainer
        _, trainer = _get_ml_module()
        if not trainer:
            return jsonify({'success': False, 'error': 'ML training module not available'}), 500

        # Generate job ID
        import uuid
        job_id = str(uuid.uuid4())[:8]

        # Training callback to track progress
        def progress_callback(stage, progress, message):
            _training_jobs[job_id] = {
                'stage': stage,
                'progress': progress,
                'message': message,
                'updated_at': datetime.now().isoformat()
            }

        # Start training in background thread
        def run_training():
            try:
                if algorithm == 'all':
                    result = trainer.train_all_algorithms(
                        data_start=data_start,
                        data_end=data_end,
                        include_simulation=include_simulation,
                        callback=progress_callback
                    )
                else:
                    result = trainer.train(
                        algorithm=algorithm,
                        data_start=data_start,
                        data_end=data_end,
                        hyperparameters=hyperparameters,
                        include_simulation=include_simulation,
                        callback=progress_callback
                    )

                _training_jobs[job_id]['result'] = result
                _training_jobs[job_id]['stage'] = 'completed'
                _training_jobs[job_id]['progress'] = 100

            except Exception as e:
                _training_jobs[job_id]['error'] = str(e)
                _training_jobs[job_id]['stage'] = 'failed'

        # Start training thread
        _training_jobs[job_id] = {
            'stage': 'starting',
            'progress': 0,
            'message': 'Initializing training...',
            'algorithm': algorithm,
            'started_at': datetime.now().isoformat()
        }

        thread = threading.Thread(target=run_training)
        thread.daemon = True
        thread.start()

        return jsonify({
            'success': True,
            'message': 'Training started',
            'job_id': job_id,
            'algorithm': algorithm,
            'data_range': {
                'start': data_start.isoformat(),
                'end': data_end.isoformat()
            }
        }), 202

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500


@ml_routes.route('/training/status/<job_id>', methods=['GET'])
def get_training_status(job_id):
    """Get training job status"""
    if job_id in _training_jobs:
        return jsonify({
            'success': True,
            'job': _training_jobs[job_id]
        }), 200
    else:
        return jsonify({'success': False, 'error': 'Job not found'}), 404


@ml_routes.route('/training/config', methods=['GET'])
def get_training_config():
    """Get available training algorithms and default hyperparameters"""
    try:
        _, trainer = _get_ml_module()

        if trainer:
            algorithms = {}
            for algo, info in trainer.ALGORITHMS.items():
                algorithms[algo] = {
                    'name': info['name'],
                    'default_params': info['default_params']
                }
        else:
            # Fallback defaults
            algorithms = {
                'random_forest': {
                    'name': 'Random Forest',
                    'default_params': {'n_estimators': 100, 'max_depth': 15}
                },
                'gradient_boosting': {
                    'name': 'Gradient Boosting',
                    'default_params': {'n_estimators': 100, 'learning_rate': 0.1}
                },
                'xgboost': {
                    'name': 'XGBoost',
                    'default_params': {'n_estimators': 100, 'max_depth': 6}
                }
            }

        return jsonify({
            'success': True,
            'algorithms': algorithms,
            'train_test_split': '80/20',
            'note': 'Training uses 80% of data for training, 20% for testing'
        }), 200

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@ml_routes.route('/training/data-stats', methods=['GET'])
def get_training_data_stats():
    """Get statistics about available training data with caching"""
    conn = None
    cursor = None
    try:
        cache = get_cache()
        cache_k = cache_key('ml', 'training_data_stats')

        # Try cache first
        cached = cache.get(cache_k)
        if cached is not None:
            return jsonify({
                'success': True,
                'stats': cached,
                'from_cache': True
            }), 200

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Get overall event counts
        cursor.execute("""
            SELECT
                COUNT(*) as total_events,
                SUM(CASE WHEN event_type = 'failed' THEN 1 ELSE 0 END) as failed_events,
                SUM(CASE WHEN event_type = 'successful' THEN 1 ELSE 0 END) as success_events,
                COUNT(DISTINCT source_ip_text) as unique_ips,
                COUNT(DISTINCT target_username) as unique_usernames,
                MIN(timestamp) as earliest_event,
                MAX(timestamp) as latest_event
            FROM auth_events
        """)
        stats = cursor.fetchone() or {}

        # Get simulation vs real data breakdown
        cursor.execute("""
            SELECT
                SUM(CASE WHEN simulation_run_id IS NOT NULL THEN 1 ELSE 0 END) as simulation_events,
                SUM(CASE WHEN simulation_run_id IS NULL THEN 1 ELSE 0 END) as real_events
            FROM auth_events
        """)
        breakdown = cursor.fetchone() or {}

        # Get events by date (last 7 days)
        cursor.execute("""
            SELECT
                DATE(timestamp) as date,
                COUNT(*) as count
            FROM auth_events
            WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 7 DAY)
            GROUP BY DATE(timestamp)
            ORDER BY date DESC
        """)
        daily_events = cursor.fetchall()

        result = {
            'total_events': int(stats.get('total_events') or 0),
            'failed_events': int(stats.get('failed_events') or 0),
            'success_events': int(stats.get('success_events') or 0),
            'unique_ips': int(stats.get('unique_ips') or 0),
            'unique_usernames': int(stats.get('unique_usernames') or 0),
            'simulation_events': int(breakdown.get('simulation_events') or 0),
            'real_events': int(breakdown.get('real_events') or 0),
            'earliest_event': stats.get('earliest_event').isoformat() if stats.get('earliest_event') else None,
            'latest_event': stats.get('latest_event').isoformat() if stats.get('latest_event') else None,
            'daily_events': [{'date': str(d['date']), 'count': d['count']} for d in daily_events],
            'min_required': 100,
            'is_sufficient': int(stats.get('total_events') or 0) >= 100
        }

        # Cache the result
        cache.set(cache_k, result, ML_TRAINING_DATA_TTL)

        return jsonify({
            'success': True,
            'stats': result,
            'from_cache': False
        }), 200

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


# ============================================================================
# COMPARISON ENDPOINTS (ML vs Rule-Based)
# ============================================================================

@ml_routes.route('/comparison', methods=['GET'])
def get_comparison():
    """Get ML vs Rule-based comparison statistics with caching"""
    try:
        days = int(request.args.get('days', 30))

        cache = get_cache()
        cache_k = cache_key('ml', 'comparison', str(days))

        # Try cache first
        cached = cache.get(cache_k)
        if cached is not None:
            return jsonify({
                'success': True,
                'comparison': cached,
                'from_cache': True
            }), 200

        comparator = _get_comparator()
        if comparator:
            stats = comparator.get_comparison_stats(days=days)
            cache.set(cache_k, stats, ML_COMPARISON_TTL)
            return jsonify({
                'success': True,
                'comparison': stats,
                'from_cache': False
            }), 200
        else:
            return jsonify({'success': False, 'error': 'Comparator not available'}), 500

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500


@ml_routes.route('/comparison/daily', methods=['GET'])
def get_daily_comparison():
    """Get daily comparison statistics"""
    try:
        days = int(request.args.get('days', 30))

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            cursor.execute("""
                SELECT * FROM ml_comparison_stats
                WHERE stat_date >= DATE_SUB(CURDATE(), INTERVAL %s DAY)
                ORDER BY stat_date DESC
            """, (days,))

            stats = cursor.fetchall()

            return jsonify({
                'success': True,
                'daily_stats': stats
            }), 200

        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================================================
# BENEFITS REPORT ENDPOINTS
# ============================================================================

@ml_routes.route('/benefits', methods=['GET'])
def get_benefits():
    """Get ML benefits report with caching"""
    try:
        days = int(request.args.get('days', 30))

        cache = get_cache()
        cache_k = cache_key('ml', 'benefits', str(days))

        # Try cache first
        cached = cache.get(cache_k)
        if cached is not None:
            return jsonify({
                'success': True,
                'benefits': cached,
                'from_cache': True
            }), 200

        comparator = _get_comparator()
        if comparator:
            report = comparator.get_benefits_report(days=days)
            cache.set(cache_k, report, ML_BENEFITS_TTL)
            return jsonify({
                'success': True,
                'benefits': report,
                'from_cache': False
            }), 200
        else:
            return jsonify({'success': False, 'error': 'Benefits report not available'}), 500

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500


@ml_routes.route('/benefits/cases', methods=['GET'])
def get_detection_cases():
    """Get notable ML detection cases"""
    try:
        days = int(request.args.get('days', 30))
        limit = int(request.args.get('limit', 10))

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            cursor.execute("""
                SELECT * FROM ml_detection_cases
                WHERE detected_at >= DATE_SUB(NOW(), INTERVAL %s DAY)
                ORDER BY detected_at DESC
                LIMIT %s
            """, (days, limit))

            cases = cursor.fetchall()

            # Parse JSON fields
            import json
            for case in cases:
                for field in ['ip_addresses', 'event_ids']:
                    if case.get(field):
                        try:
                            case[field] = json.loads(case[field])
                        except Exception:
                            pass

            return jsonify({
                'success': True,
                'cases': cases
            }), 200

        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================================================
# PREDICTIONS ENDPOINTS
# ============================================================================

@ml_routes.route('/predictions', methods=['GET'])
def list_predictions():
    """Get recent ML predictions with cursor-based pagination"""
    try:
        limit = min(int(request.args.get('limit', 50)), 500)
        cursor_id = request.args.get('cursor')
        anomaly_only = request.args.get('anomaly_only', 'false').lower() == 'true'
        min_risk = int(request.args.get('min_risk', 0))

        # Convert cursor to int if provided
        cursor_id = int(cursor_id) if cursor_id else None

        conn = get_connection()
        db_cursor = conn.cursor(dictionary=True)

        try:
            # Use optimized cursor-based pagination (more efficient than OFFSET)
            predictions, next_cursor = get_predictions_cursor_paginated(
                db_cursor,
                limit=limit,
                cursor_id=cursor_id,
                anomaly_only=anomaly_only,
                min_risk=min_risk
            )

            return jsonify({
                'success': True,
                'predictions': predictions,
                'next_cursor': next_cursor,
                'has_more': next_cursor is not None
            }), 200

        finally:
            db_cursor.close()
            conn.close()

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@ml_routes.route('/predictions/<int:prediction_id>/feedback', methods=['POST'])
def submit_feedback(prediction_id):
    """
    Submit feedback on a prediction (for model improvement)

    Request body:
    {
        "feedback": "correct" | "false_positive" | "false_negative",
        "notes": "optional notes"
    }
    """
    try:
        data = request.get_json()
        feedback = data.get('feedback')
        notes = data.get('notes', '')

        if feedback not in ('correct', 'false_positive', 'false_negative'):
            return jsonify({'success': False, 'error': 'Invalid feedback value'}), 400

        conn = get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("""
                UPDATE ml_predictions
                SET manual_feedback = %s, feedback_notes = %s, feedback_at = NOW()
                WHERE id = %s
            """, (feedback, notes, prediction_id))

            conn.commit()

            return jsonify({
                'success': True,
                'message': 'Feedback submitted'
            }), 200

        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================================================
# DASHBOARD SUMMARY (for main dashboard)
# ============================================================================

@ml_routes.route('/dashboard-summary', methods=['GET'])
def get_dashboard_summary():
    """Get ML summary for main dashboard home page with caching"""
    try:
        cache = get_cache()
        cache_k = cache_key('ml', 'dashboard_summary')

        # Try cache first
        cached = cache.get(cache_k)
        if cached is not None:
            return jsonify({
                'success': True,
                'ml_summary': cached,
                'from_cache': True
            }), 200

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            # Use optimized query function (reduces 3 queries to 1)
            ml_summary = get_dashboard_summary_data(cursor)

            # Cache the result
            cache.set(cache_k, ml_summary, ML_DASHBOARD_TTL)

            return jsonify({
                'success': True,
                'ml_summary': ml_summary,
                'from_cache': False
            }), 200

        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
