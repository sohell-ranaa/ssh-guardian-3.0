"""ML Training API Routes"""
from flask import Blueprint, jsonify, request
import sys
from pathlib import Path
import pandas as pd

PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
sys.path.append(str(PROJECT_ROOT))
sys.path.append(str(PROJECT_ROOT / "src"))
sys.path.append(str(PROJECT_ROOT / "dbs"))

from connection import get_connection
from src.ml.model_trainer import get_trainer
from src.core.auth import login_required

ml_training_routes = Blueprint('ml_training', __name__, url_prefix='/api/ml/training')


@ml_training_routes.route('/data/prepare', methods=['POST'])
@login_required
def prepare_training_data():
    """Fetch and prepare training data from database"""
    try:
        data = request.get_json() or {}
        limit = data.get('limit', 10000)

        conn = get_connection()
        query = f"""
            SELECT
                e.event_type, e.target_username, e.target_port,
                e.timestamp, e.is_anomaly,
                t.abuseipdb_score, t.virustotal_positives, t.overall_threat_level,
                g.country_code, g.is_tor, g.is_proxy, g.is_vpn, g.is_datacenter
            FROM auth_events e
            LEFT JOIN ip_threat_intelligence t ON e.source_ip_text = t.ip_address_text
            LEFT JOIN ip_geolocation g ON e.source_ip_text = g.ip_address_text
            WHERE e.timestamp >= DATE_SUB(NOW(), INTERVAL 30 DAY)
            LIMIT {limit}
        """

        df = pd.read_sql(query, conn)
        conn.close()

        if len(df) < 100:
            return jsonify({'success': False, 'error': 'Insufficient data (need at least 100 records)'}), 400

        trainer = get_trainer()
        X, y, feature_names = trainer.prepare_training_data(df)

        return jsonify({
            'success': True,
            'samples': int(len(X)),
            'features': len(feature_names),
            'feature_names': feature_names,
            'malicious_ratio': float(y.sum() / len(y)),
            'benign_count': int((y == 0).sum()),
            'malicious_count': int((y == 1).sum())
        })

    except Exception as e:
        print(f"[ML] Error preparing data: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500


@ml_training_routes.route('/train', methods=['POST'])
@login_required
def train_models():
    """Train ML models"""
    try:
        data = request.get_json()
        model_types = data.get('model_types', ['random_forest', 'gradient_boosting', 'neural_network'])
        test_size = data.get('test_size', 0.2)
        limit = data.get('limit', 10000)

        # Fetch data
        conn = get_connection()
        query = f"""
            SELECT
                e.event_type, e.target_username, e.target_port,
                e.timestamp, e.is_anomaly,
                t.abuseipdb_score, t.virustotal_positives, t.overall_threat_level,
                g.country_code, g.is_tor, g.is_proxy, g.is_vpn, g.is_datacenter
            FROM auth_events e
            LEFT JOIN ip_threat_intelligence t ON e.source_ip_text = t.ip_address_text
            LEFT JOIN ip_geolocation g ON e.source_ip_text = g.ip_address_text
            WHERE e.timestamp >= DATE_SUB(NOW(), INTERVAL 30 DAY)
            LIMIT {limit}
        """
        df = pd.read_sql(query, conn)
        conn.close()

        trainer = get_trainer()
        X, y, feature_names = trainer.prepare_training_data(df)

        # Split data
        from sklearn.model_selection import train_test_split
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=test_size, random_state=42)

        # Train models
        results = []
        for model_type in model_types:
            result = trainer.train_model(model_type, X_train, y_train, X_test, y_test, feature_names)
            filepath = trainer.save_model(result)

            results.append({
                'model_type': model_type,
                'model_name': result['model_name'],
                'metrics': result['metrics'],
                'filepath': filepath,
                'trained_at': result['trained_at']
            })

        return jsonify({'success': True, 'models': results})

    except Exception as e:
        print(f"[ML] Training error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500


@ml_training_routes.route('/models/list', methods=['GET'])
@login_required
def list_models():
    """List all trained models"""
    try:
        trainer = get_trainer()
        models = trainer.list_models()
        return jsonify({'success': True, 'models': models})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@ml_training_routes.route('/models/compare', methods=['POST'])
@login_required
def compare_models():
    """Compare model performance"""
    try:
        data = request.get_json()
        model_versions = data.get('versions', [])

        trainer = get_trainer()
        all_models = trainer.list_models()

        # Filter by requested versions
        if model_versions:
            models_to_compare = [m for m in all_models if m['version'] in model_versions]
        else:
            models_to_compare = all_models[:5]  # Latest 5

        comparison = []
        for model_meta in models_to_compare:
            comparison.append({
                'model_name': model_meta['model_name'],
                'version': model_meta['version'],
                'test_accuracy': model_meta['metrics']['test']['accuracy'],
                'test_f1': model_meta['metrics']['test']['f1'],
                'test_recall': model_meta['metrics']['test']['recall'],
                'test_precision': model_meta['metrics']['test']['precision'],
                'cv_mean': model_meta['cross_val_mean'],
                'training_time': model_meta['training_time'],
                'trained_at': model_meta['trained_at']
            })

        return jsonify({'success': True, 'comparison': comparison})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
