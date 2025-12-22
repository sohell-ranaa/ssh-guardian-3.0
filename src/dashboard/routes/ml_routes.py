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
    Use ?refresh=1 to bypass cache
    """
    try:
        cache = get_cache()
        cache_k = cache_key('ml', 'overview')
        skip_cache = request.args.get('refresh') == '1'

        # Try cache first (unless refresh requested)
        if not skip_cache:
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
            # v3.1: Use auth_events_ml instead of ml_predictions
            cursor.execute("""
                SELECT
                    DATE(created_at) as date,
                    COUNT(*) as predictions,
                    SUM(CASE WHEN is_anomaly = 1 THEN 1 ELSE 0 END) as anomalies,
                    AVG(risk_score) as avg_risk
                FROM auth_events_ml
                WHERE created_at >= DATE_SUB(NOW(), INTERVAL %s DAY)
                GROUP BY DATE(created_at)
                ORDER BY date
            """, (days,))

            timeline = cursor.fetchall()

            # Format for charts
            # v3.1: risk_score is now decimal(5,4) so multiply by 100 for percentage
            formatted = [{
                'date': str(row['date']),
                'predictions': int(row['predictions']),
                'anomalies': int(row['anomalies'] or 0),
                'avg_risk': round(float(row['avg_risk'] or 0) * 100, 1)
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
    """Get all ML models with caching. Use ?refresh=1 to bypass cache"""
    try:
        status_filter = request.args.get('status', '')
        skip_cache = request.args.get('refresh') == '1'

        cache = get_cache()
        cache_k = cache_key('ml', 'models', status_filter)

        # Try cache first (unless refresh requested)
        if not skip_cache:
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
            # v3.1: Updated column names (auc_roc, predictions_count, promoted_at)
            query = """
                SELECT
                    id, model_uuid, model_name, algorithm, version, status, is_active,
                    accuracy, precision_score, recall_score, f1_score, auc_roc,
                    predictions_count, promoted_at, created_at
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
                        'roc_auc': float(m['auc_roc']) if m['auc_roc'] else None
                    },
                    'training_samples': None,  # v3.1: Not in this table
                    'test_samples': None,       # v3.1: Not in this table
                    'predictions_made': m['predictions_count'],
                    'trained_at': m['promoted_at'].isoformat() if m['promoted_at'] else None,
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
    """Get detailed model information - fetches from both ml_models and ml_comparison_results"""
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            # First get base model info
            cursor.execute("""
                SELECT * FROM ml_models WHERE id = %s
            """, (model_id,))

            model = cursor.fetchone()
            if not model:
                return jsonify({'success': False, 'error': 'Model not found'}), 404

            # Try to get detailed data from ml_comparison_results using model_name
            cursor.execute("""
                SELECT
                    cr.training_samples, cr.testing_samples, cr.feature_count,
                    cr.hyperparameters, cr.confusion_matrix,
                    cr.true_positives, cr.true_negatives, cr.false_positives, cr.false_negatives,
                    cr.specificity, cr.balanced_accuracy, cr.matthews_correlation,
                    cr.training_time_seconds, cr.prediction_time_ms, cr.memory_usage_mb,
                    cr.feature_importance, cr.cv_scores, cr.cv_mean, cr.cv_std,
                    cr.roc_auc as comparison_roc_auc,
                    tr.run_name, tr.total_events_generated, tr.benign_count, tr.malicious_count,
                    tr.started_at as training_started, tr.completed_at as training_completed
                FROM ml_comparison_results cr
                LEFT JOIN ml_training_runs tr ON cr.run_id = tr.id
                WHERE cr.model_name COLLATE utf8mb4_unicode_ci = %s COLLATE utf8mb4_unicode_ci
                ORDER BY cr.id DESC
                LIMIT 1
            """, (model.get('model_name'),))

            details = cursor.fetchone()

            import json

            # Merge detailed data into model response
            if details:
                for key, value in details.items():
                    if value is not None:
                        model[key] = value

            # Parse JSON fields
            json_fields = ['hyperparameters', 'feature_config', 'confusion_matrix',
                          'feature_importance', 'cv_scores']
            for field in json_fields:
                if model.get(field):
                    try:
                        if isinstance(model[field], str):
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
            # v3.1 schema: ml_training_runs has different columns
            cursor.execute("""
                SELECT
                    tr.id, tr.run_uuid, tr.run_name, tr.status,
                    tr.total_events_generated, tr.training_events, tr.testing_events,
                    tr.benign_count, tr.malicious_count,
                    tr.started_at, tr.completed_at, tr.error_message,
                    (SELECT MAX(f1_score) FROM ml_comparison_results WHERE run_id = tr.id) as best_f1,
                    (SELECT COUNT(*) FROM ml_comparison_results WHERE run_id = tr.id) as models_trained
                FROM ml_training_runs tr
                ORDER BY tr.started_at DESC
                LIMIT %s
            """, (limit,))

            runs = cursor.fetchall()

            formatted = []
            for run in runs:
                duration = None
                if run['started_at'] and run['completed_at']:
                    duration = (run['completed_at'] - run['started_at']).total_seconds()

                formatted.append({
                    'id': run['id'],
                    'uuid': run['run_uuid'],
                    'name': run['run_name'],
                    'status': run['status'],
                    'total_events': run['total_events_generated'],
                    'train_count': run['training_events'],
                    'test_count': run['testing_events'],
                    'benign_count': run['benign_count'],
                    'malicious_count': run['malicious_count'],
                    'started_at': run['started_at'].isoformat() if run['started_at'] else None,
                    'completed_at': run['completed_at'].isoformat() if run['completed_at'] else None,
                    'duration_seconds': duration,
                    'error': run['error_message'],
                    'best_f1': float(run['best_f1']) if run['best_f1'] else None,
                    'models_trained': run['models_trained'] or 0
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
        ip_filter = request.args.get('ip_filter')

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
                min_risk=min_risk,
                ip_filter=ip_filter
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
            # v3.1: auth_events_ml instead of ml_predictions
            cursor.execute("""
                UPDATE auth_events_ml
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


# ============================================================================
# TRAINING ITERATIONS ENDPOINTS (NEW - for thesis presentation)
# ============================================================================

@ml_routes.route('/training/iterations', methods=['GET'])
def get_training_iterations():
    """
    Get all training iterations with hyperparameters for timeline visualization
    Returns data formatted for Chart.js timeline
    """
    try:
        cache = get_cache()
        cache_k = cache_key('ml', 'training_iterations')

        cached = cache.get(cache_k)
        if cached is not None:
            return jsonify({
                'success': True,
                'iterations': cached,
                'from_cache': True
            }), 200

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            cursor.execute("""
                SELECT
                    i.id,
                    i.run_id,
                    i.iteration_number,
                    i.algorithm,
                    i.model_name,
                    i.hyperparameters,
                    ROUND(i.accuracy * 100, 2) as accuracy_pct,
                    ROUND(i.precision_score * 100, 2) as precision_pct,
                    ROUND(i.recall_score * 100, 2) as recall_pct,
                    ROUND(i.f1_score * 100, 4) as f1_pct,
                    ROUND(i.roc_auc * 100, 2) as auc_pct,
                    ROUND(i.specificity * 100, 2) as specificity_pct,
                    ROUND(i.balanced_accuracy * 100, 2) as balanced_acc_pct,
                    ROUND(i.matthews_correlation, 4) as matthews,
                    i.true_positives,
                    i.true_negatives,
                    i.false_positives,
                    i.false_negatives,
                    i.training_samples,
                    i.testing_samples,
                    ROUND(i.training_time_seconds, 1) as training_time,
                    ROUND(i.prediction_time_ms, 2) as prediction_time,
                    ROUND(i.memory_usage_mb, 1) as memory_mb,
                    i.is_best_iteration,
                    i.created_at,
                    r.run_name,
                    r.started_at as run_date
                FROM ml_training_iterations i
                LEFT JOIN ml_training_runs r ON i.run_id = r.id
                ORDER BY i.created_at DESC, i.f1_score DESC
                LIMIT 50
            """)
            iterations = cursor.fetchall()

            # Process for JSON serialization
            import json as json_module
            for it in iterations:
                if it['created_at']:
                    it['created_at'] = it['created_at'].isoformat()
                if it['run_date']:
                    it['run_date'] = it['run_date'].isoformat()
                if it['hyperparameters']:
                    if isinstance(it['hyperparameters'], str):
                        it['hyperparameters'] = json_module.loads(it['hyperparameters'])

            cache.set(cache_k, iterations, ML_TRAINING_RUNS_TTL)

            return jsonify({
                'success': True,
                'iterations': iterations,
                'from_cache': False
            }), 200

        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@ml_routes.route('/training/algorithm-comparison', methods=['GET'])
def get_algorithm_comparison():
    """
    Get aggregated comparison of Random Forest vs XGBoost vs LightGBM
    Returns best metrics for each algorithm
    """
    try:
        cache = get_cache()
        cache_k = cache_key('ml', 'algorithm_comparison')

        cached = cache.get(cache_k)
        if cached is not None:
            return jsonify({
                'success': True,
                'comparison': cached,
                'from_cache': True
            }), 200

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            cursor.execute("""
                SELECT
                    algorithm,
                    COUNT(*) as total_runs,
                    ROUND(MAX(accuracy) * 100, 2) as best_accuracy,
                    ROUND(MAX(f1_score) * 100, 4) as best_f1,
                    ROUND(MAX(roc_auc) * 100, 2) as best_auc,
                    ROUND(AVG(accuracy) * 100, 2) as avg_accuracy,
                    ROUND(AVG(f1_score) * 100, 4) as avg_f1,
                    ROUND(AVG(roc_auc) * 100, 2) as avg_auc,
                    ROUND(MIN(training_time_seconds), 1) as min_training_time,
                    ROUND(AVG(training_time_seconds), 1) as avg_training_time,
                    ROUND(AVG(memory_usage_mb), 1) as avg_memory
                FROM ml_training_iterations
                GROUP BY algorithm
                ORDER BY MAX(f1_score) DESC
            """)
            algorithms = cursor.fetchall()

            best_algo = algorithms[0]['algorithm'] if algorithms else None

            import json as json_module
            details = {}
            for algo in algorithms:
                cursor.execute("""
                    SELECT
                        model_name,
                        hyperparameters,
                        ROUND(accuracy * 100, 4) as accuracy,
                        ROUND(precision_score * 100, 4) as precision_score,
                        ROUND(recall_score * 100, 4) as recall_score,
                        ROUND(f1_score * 100, 4) as f1_score,
                        ROUND(roc_auc * 100, 4) as roc_auc,
                        true_positives,
                        true_negatives,
                        false_positives,
                        false_negatives,
                        training_samples,
                        testing_samples,
                        ROUND(training_time_seconds, 1) as training_time
                    FROM ml_training_iterations
                    WHERE algorithm = %s
                    ORDER BY f1_score DESC
                    LIMIT 1
                """, (algo['algorithm'],))
                best = cursor.fetchone()
                if best:
                    if best['hyperparameters']:
                        if isinstance(best['hyperparameters'], str):
                            best['hyperparameters'] = json_module.loads(best['hyperparameters'])
                    details[algo['algorithm']] = best

            result = {
                'algorithms': algorithms,
                'best_algorithm': best_algo,
                'details': details
            }

            cache.set(cache_k, result, ML_COMPARISON_TTL)

            return jsonify({
                'success': True,
                'comparison': result,
                'from_cache': False
            }), 200

        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@ml_routes.route('/training/stats', methods=['GET'])
def get_training_stats():
    """Get training data statistics for the training page header"""
    try:
        cache = get_cache()
        cache_k = cache_key('ml', 'training_stats')

        cached = cache.get(cache_k)
        if cached is not None:
            return jsonify({
                'success': True,
                'stats': cached,
                'from_cache': True
            }), 200

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            cursor.execute("""
                SELECT
                    (SELECT COUNT(*) FROM ml_training_data) as total_events,
                    (SELECT COUNT(*) FROM ml_training_data WHERE is_malicious = 1) as malicious_events,
                    (SELECT COUNT(*) FROM ml_training_data WHERE is_malicious = 0) as benign_events,
                    (SELECT training_events FROM ml_training_runs ORDER BY id DESC LIMIT 1) as training_samples,
                    (SELECT testing_events FROM ml_training_runs ORDER BY id DESC LIMIT 1) as testing_samples,
                    (SELECT COUNT(*) FROM ml_training_runs) as training_runs,
                    (SELECT COUNT(*) FROM ml_training_iterations) as iterations,
                    (SELECT ROUND(MAX(f1_score) * 100, 4) FROM ml_training_iterations) as best_f1
            """)
            stats = cursor.fetchone()

            cache.set(cache_k, stats, ML_TRAINING_DATA_TTL)

            return jsonify({
                'success': True,
                'stats': stats,
                'from_cache': False
            }), 200

        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================================================
# BENEFITS TREND ENDPOINTS (NEW - for thesis presentation)
# ============================================================================

@ml_routes.route('/benefits/trend', methods=['GET'])
def get_benefits_trend():
    """Get ML benefits improvement trend over time"""
    try:
        days = request.args.get('days', 30, type=int)

        cache = get_cache()
        cache_k = cache_key('ml', f'benefits_trend_{days}')

        cached = cache.get(cache_k)
        if cached is not None:
            return jsonify({
                'success': True,
                'trend': cached,
                'from_cache': True
            }), 200

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            cursor.execute("""
                SELECT
                    date,
                    total_events_analyzed,
                    threats_detected_ml,
                    high_risk_events,
                    first_attempt_detections,
                    threats_would_miss_fail2ban,
                    false_positives_prevented,
                    auto_escalations_to_ufw,
                    time_saved_minutes,
                    detection_improvement_pct
                FROM ml_benefits_metrics
                WHERE date >= DATE_SUB(CURDATE(), INTERVAL %s DAY)
                ORDER BY date ASC
            """, (days,))
            trend_data = cursor.fetchall()

            for row in trend_data:
                if row['date']:
                    row['date'] = row['date'].isoformat()

            if trend_data:
                summary = {
                    'total_events': sum(r['total_events_analyzed'] or 0 for r in trend_data),
                    'total_threats': sum(r['threats_detected_ml'] or 0 for r in trend_data),
                    'total_first_attempt': sum(r['first_attempt_detections'] or 0 for r in trend_data),
                    'total_would_miss': sum(r['threats_would_miss_fail2ban'] or 0 for r in trend_data),
                    'total_time_saved_hours': round(sum(r['time_saved_minutes'] or 0 for r in trend_data) / 60, 1),
                    'avg_improvement': round(sum(r['detection_improvement_pct'] or 0 for r in trend_data) / len(trend_data), 2)
                }
            else:
                summary = {'total_events': 0, 'total_threats': 0, 'total_first_attempt': 0, 'total_would_miss': 0, 'total_time_saved_hours': 0, 'avg_improvement': 0}

            result = {'data': trend_data, 'summary': summary, 'days': days}
            cache.set(cache_k, result, ML_BENEFITS_TTL)

            return jsonify({'success': True, 'trend': result, 'from_cache': False}), 200

        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@ml_routes.route('/benefits/cases', methods=['GET'])
def get_benefits_detection_cases():
    """Get notable ML detection case studies"""
    try:
        limit = request.args.get('limit', 10, type=int)
        days = request.args.get('days', 30, type=int)

        cache = get_cache()
        cache_k = cache_key('ml', f'detection_cases_{days}_{limit}')

        cached = cache.get(cache_k)
        if cached is not None:
            return jsonify({'success': True, 'cases': cached, 'from_cache': True}), 200

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            cursor.execute("""
                SELECT
                    scenario_type,
                    COUNT(*) as event_count,
                    COUNT(DISTINCT source_ip) as unique_ips,
                    AVG(CASE WHEN threat_level = 'critical' THEN 100
                             WHEN threat_level = 'high' THEN 75
                             WHEN threat_level = 'medium' THEN 50
                             ELSE 25 END) as avg_risk_score,
                    SUM(CASE WHEN is_tor = 1 THEN 1 ELSE 0 END) as tor_events,
                    SUM(CASE WHEN is_vpn = 1 THEN 1 ELSE 0 END) as vpn_events,
                    SUM(CASE WHEN is_datacenter = 1 THEN 1 ELSE 0 END) as datacenter_events,
                    COUNT(DISTINCT country_code) as countries_involved
                FROM ml_training_data
                WHERE is_malicious = 1
                  AND timestamp >= DATE_SUB(NOW(), INTERVAL %s DAY)
                GROUP BY scenario_type
                ORDER BY event_count DESC
                LIMIT %s
            """, (days, limit))
            scenarios = cursor.fetchall()

            case_templates = {
                'brute_force': {'title': 'Brute Force Attack Detection', 'why_fail2ban_missed': 'Fail2ban requires 5 failures before blocking. ML detected malicious intent on first attempt.', 'how_ml_detected': 'Analyzed IP reputation, geographic risk, timing patterns, and username targeting behavior.'},
                'distributed_brute_force': {'title': 'Distributed Attack Coordination', 'why_fail2ban_missed': 'Attack spread across multiple IPs, each below Fail2ban threshold.', 'how_ml_detected': 'Correlated patterns across IPs: similar timing, target usernames, and infrastructure sources.'},
                'credential_stuffing': {'title': 'Credential Stuffing Campaign', 'why_fail2ban_missed': 'Valid credentials used, no failed logins to trigger rules.', 'how_ml_detected': 'Detected abnormal login patterns, unusual geolocations, and automated behavior signatures.'},
                'password_spray': {'title': 'Password Spray Attack', 'why_fail2ban_missed': 'Single attempt per user stays below threshold.', 'how_ml_detected': 'Identified systematic targeting of multiple users with common passwords.'},
                'tor_exit_nodes': {'title': 'Tor Network Anonymized Attack', 'why_fail2ban_missed': 'IP changes with each attempt, evading IP-based blocking.', 'how_ml_detected': 'Tor exit node detection and behavioral pattern analysis regardless of IP.'},
                'datacenter_attacks': {'title': 'Cloud/Datacenter-Sourced Attack', 'why_fail2ban_missed': 'Legitimate-looking IPs from known cloud providers.', 'how_ml_detected': 'Datacenter IP identification combined with threat intelligence scoring.'}
            }

            cases = []
            for scenario in scenarios:
                template = case_templates.get(scenario['scenario_type'], {'title': f"{scenario['scenario_type'].replace('_', ' ').title()} Detection", 'why_fail2ban_missed': 'Attack pattern not matching static rules.', 'how_ml_detected': 'Multi-feature analysis including reputation, behavior, and context.'})
                cases.append({
                    'scenario_type': scenario['scenario_type'],
                    'title': template['title'],
                    'event_count': scenario['event_count'],
                    'unique_ips': scenario['unique_ips'],
                    'avg_risk_score': round(scenario['avg_risk_score'] or 0, 1),
                    'tor_events': scenario['tor_events'] or 0,
                    'vpn_events': scenario['vpn_events'] or 0,
                    'datacenter_events': scenario['datacenter_events'] or 0,
                    'countries_involved': scenario['countries_involved'] or 0,
                    'why_fail2ban_missed': template['why_fail2ban_missed'],
                    'how_ml_detected': template['how_ml_detected']
                })

            cache.set(cache_k, cases, ML_BENEFITS_TTL)
            return jsonify({'success': True, 'cases': cases, 'from_cache': False}), 200

        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
