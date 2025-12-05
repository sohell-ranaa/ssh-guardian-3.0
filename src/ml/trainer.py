"""
SSH Guardian v3.0 - ML Model Trainer
On-demand training with 80/20 train/test split
Supports Random Forest, XGBoost, Gradient Boosting
"""

import os
import sys
import uuid
import json
import logging
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List, Tuple
import numpy as np

# Add project paths
PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.append(str(PROJECT_ROOT / "dbs"))

from connection import get_connection
from .feature_extractor import FeatureExtractor
from .trainer_queries import (
    fetch_training_data,
    update_training_run_progress,
    update_training_run_samples,
    complete_training_run,
    fail_training_run,
    promote_model_to_production
)

logger = logging.getLogger(__name__)


class MLTrainer:
    """
    ML Model Trainer for SSH Guardian.
    Trains models with 80/20 split, supports multiple algorithms,
    and automatically selects best model based on F1 score.
    """

    # Supported algorithms
    ALGORITHMS = {
        'random_forest': {
            'name': 'Random Forest',
            'default_params': {
                'n_estimators': 300,       # More trees for better ensemble
                'max_depth': None,         # Full depth - let trees learn complete patterns
                'min_samples_split': 2,
                'min_samples_leaf': 1,
                'max_features': 'sqrt',    # Feature randomization for diversity
                'class_weight': 'balanced',  # Handle class imbalance
                'bootstrap': True,
                'oob_score': True,         # Out-of-bag scoring
                'random_state': 42,
                'n_jobs': -1
            }
        },
        'gradient_boosting': {
            'name': 'Gradient Boosting',
            'default_params': {
                'n_estimators': 100,
                'max_depth': 5,
                'learning_rate': 0.1,
                'min_samples_split': 5,
                'random_state': 42
            }
        },
        'xgboost': {
            'name': 'XGBoost',
            'default_params': {
                'n_estimators': 100,
                'max_depth': 6,
                'learning_rate': 0.1,
                'random_state': 42,
                'n_jobs': -1,
                'use_label_encoder': False,
                'eval_metric': 'logloss'
            }
        },
        'isolation_forest': {
            'name': 'Isolation Forest',
            'default_params': {
                'n_estimators': 100,
                'contamination': 0.1,
                'random_state': 42,
                'n_jobs': -1
            }
        }
    }

    def __init__(self, models_dir: Path):
        """
        Initialize ML Trainer.

        Args:
            models_dir: Directory to save trained models
        """
        self.models_dir = Path(models_dir)
        self.models_dir.mkdir(parents=True, exist_ok=True)
        self.feature_extractor = FeatureExtractor()

    def train(self, algorithm: str, data_start: datetime, data_end: datetime,
              hyperparameters: Optional[Dict] = None,
              include_simulation: bool = True,
              user_id: Optional[int] = None,
              callback: Optional[callable] = None) -> Dict[str, Any]:
        """
        Train a new ML model.

        Args:
            algorithm: Algorithm name (random_forest, xgboost, gradient_boosting)
            data_start: Start date for training data
            data_end: End date for training data
            hyperparameters: Custom hyperparameters (or use defaults)
            include_simulation: Include simulation events in training
            user_id: User initiating training
            callback: Progress callback function(stage, progress, message)

        Returns:
            Training result with model info and metrics
        """
        if algorithm not in self.ALGORITHMS:
            raise ValueError(f"Unknown algorithm: {algorithm}. Supported: {list(self.ALGORITHMS.keys())}")

        # Create training run record
        run_id = self._create_training_run(algorithm, data_start, data_end,
                                           hyperparameters, include_simulation, user_id)

        try:
            # Stage 1: Prepare data
            self._update_run_status(run_id, 'preparing_data', 10, 'Loading events from database')
            if callback:
                callback('preparing_data', 10, 'Loading events from database')

            X, y, event_ids = self._prepare_training_data(data_start, data_end, include_simulation)

            if len(X) < 100:
                raise ValueError(f"Insufficient training data: {len(X)} samples (need at least 100)")

            self._update_run_samples(run_id, len(X))

            # Stage 2: Feature extraction
            self._update_run_status(run_id, 'extracting_features', 30, f'Extracting features from {len(X)} events')
            if callback:
                callback('extracting_features', 30, f'Extracting features from {len(X)} events')

            # Stage 3: Split data (80/20)
            self._update_run_status(run_id, 'training', 50, 'Splitting data 80/20 and training model')
            if callback:
                callback('training', 50, 'Splitting data 80/20 and training model')

            X_train, X_test, y_train, y_test = self._split_data(X, y)

            # Stage 4: Train model
            params = hyperparameters or self.ALGORITHMS[algorithm]['default_params']
            model, scaler = self._train_model(algorithm, X_train, y_train, params)

            # Stage 5: Evaluate
            self._update_run_status(run_id, 'evaluating', 80, 'Evaluating model performance')
            if callback:
                callback('evaluating', 80, 'Evaluating model performance')

            metrics = self._evaluate_model(model, scaler, X_test, y_test)

            # Stage 6: Save model
            self._update_run_status(run_id, 'completed', 95, 'Saving model')
            if callback:
                callback('completed', 95, 'Saving model')

            model_id = self._save_model(
                model=model,
                scaler=scaler,
                algorithm=algorithm,
                params=params,
                metrics=metrics,
                data_start=data_start,
                data_end=data_end,
                training_samples=len(X_train),
                test_samples=len(X_test),
                user_id=user_id
            )

            # Update training run with model ID
            self._complete_training_run(run_id, model_id, metrics)

            if callback:
                callback('completed', 100, 'Training complete')

            return {
                'success': True,
                'run_id': run_id,
                'model_id': model_id,
                'algorithm': algorithm,
                'metrics': metrics,
                'training_samples': len(X_train),
                'test_samples': len(X_test),
                'total_samples': len(X)
            }

        except Exception as e:
            logger.error(f"Training failed: {e}", exc_info=True)
            self._fail_training_run(run_id, str(e))
            if callback:
                callback('failed', 0, str(e))
            return {
                'success': False,
                'run_id': run_id,
                'error': str(e)
            }

    def train_all_algorithms(self, data_start: datetime, data_end: datetime,
                            include_simulation: bool = True,
                            user_id: Optional[int] = None,
                            callback: Optional[callable] = None) -> Dict[str, Any]:
        """
        Train all supported algorithms and select the best one.

        Args:
            data_start: Start date for training data
            data_end: End date for training data
            include_simulation: Include simulation events
            user_id: User initiating training
            callback: Progress callback

        Returns:
            Results for all algorithms with best model info
        """
        results = {}
        algorithms = ['random_forest', 'gradient_boosting', 'xgboost']

        for i, algo in enumerate(algorithms):
            logger.info(f"Training {algo} ({i+1}/{len(algorithms)})")
            if callback:
                callback('training_all', int((i / len(algorithms)) * 100),
                        f'Training {self.ALGORITHMS[algo]["name"]}')

            result = self.train(algo, data_start, data_end,
                               include_simulation=include_simulation,
                               user_id=user_id)
            results[algo] = result

        # Find best model by F1 score
        best_algo = None
        best_f1 = 0

        for algo, result in results.items():
            if result.get('success') and result.get('metrics', {}).get('f1_score', 0) > best_f1:
                best_f1 = result['metrics']['f1_score']
                best_algo = algo

        if best_algo:
            # Promote best model to production
            self._promote_model(results[best_algo]['model_id'])
            results['best_model'] = {
                'algorithm': best_algo,
                'model_id': results[best_algo]['model_id'],
                'f1_score': best_f1
            }

        return results

    def _prepare_training_data(self, data_start: datetime, data_end: datetime,
                               include_simulation: bool) -> Tuple[np.ndarray, np.ndarray, List[int]]:
        """Load and prepare training data from auth_events using optimized query"""
        try:
            # Use optimized query from trainer_queries
            events = fetch_training_data(data_start, data_end, include_simulation)

            if not events:
                return np.array([]), np.array([]), []

            # Extract features and labels
            features_list = []
            labels = []
            event_ids = []

            for event in events:
                # Prepare event dict for feature extraction
                event_dict = {
                    'id': event['id'],
                    'timestamp': event['timestamp'],
                    'event_type': event['event_type'],
                    'source_ip_text': event['source_ip_text'],
                    'target_username': event['target_username'],
                    'target_server': event['target_server'],
                    'auth_method': event['auth_method'],
                    'failure_reason': event['failure_reason'],
                    'geo': {
                        'country_code': event.get('country_code'),
                        'city': event.get('city'),
                        'latitude': event.get('latitude'),
                        'longitude': event.get('longitude'),
                        'is_proxy': event.get('is_proxy'),
                        'is_vpn': event.get('is_vpn'),
                        'is_tor': event.get('is_tor'),
                        'is_datacenter': event.get('is_datacenter'),
                        'asn': event.get('asn')
                    },
                    'threat': {
                        'abuseipdb_score': event.get('abuseipdb_score'),
                        'virustotal_positives': event.get('virustotal_positives'),
                        'overall_threat_level': event.get('overall_threat_level')
                    }
                }

                # Extract features
                features = self.feature_extractor.extract(event_dict)
                features_list.append(features)

                # Determine label (1 = threat/anomaly, 0 = normal)
                label = self._determine_label(event)
                labels.append(label)
                event_ids.append(event['id'])

            return np.array(features_list), np.array(labels), event_ids

        except Exception as e:
            logger.error(f"Failed to prepare training data: {e}")
            raise

    def _determine_label(self, event: Dict) -> int:
        """
        Determine if event is a threat (1) or normal (0).

        CRITICAL: For 95%+ accuracy, the labeling rules must be:
        1. Based ONLY on features the model can learn (from feature_extractor)
        2. Deterministic with no overlap or ambiguity
        3. Structured as a clear decision tree

        Features available to model:
        - is_failed, is_success (event type)
        - is_invalid_user, is_invalid_password (failure reason)
        - is_tor, is_proxy, is_datacenter (network flags)
        - abuseipdb_score (0-100, normalized to 0-1)
        - threat_level_encoded (0=clean, 0.25=low, 0.5=medium, 0.75=high, 1=critical)
        - is_root, is_admin (username features)
        - is_high_risk_country (geo feature)
        """
        # Extract exactly what the feature extractor sees
        event_type = str(event.get('event_type', '')).lower()
        failure_reason = str(event.get('failure_reason', '')).lower()
        username = str(event.get('target_username', '')).lower()

        # Network flags - exactly as feature extractor sees them
        is_tor = bool(event.get('is_tor'))
        is_proxy = bool(event.get('is_proxy'))
        is_datacenter = bool(event.get('is_datacenter'))

        # Threat score - exactly as feature extractor normalizes
        abuseipdb_score = int(event.get('abuseipdb_score') or 0)
        threat_level = str(event.get('overall_threat_level', '')).lower()

        # Username flags - matching feature extractor's sets
        MALICIOUS_USERNAMES = {
            'root', 'admin', 'test', 'guest', 'oracle', 'postgres', 'mysql',
            'admin123', 'administrator', 'user', 'ftpuser', 'ftp', 'www',
            'apache', 'nginx', 'ubuntu', 'pi', 'git', 'jenkins', 'hadoop',
            'tomcat', 'nagios', 'backup', 'support', 'info', 'test1', 'test2'
        }

        # Derived booleans
        is_failed = 'failed' in event_type
        is_success = 'success' in event_type or 'accepted' in event_type
        is_invalid_user = 'invalid_user' in failure_reason
        is_admin_user = username in MALICIOUS_USERNAMES
        is_root = username == 'root'

        # =============================================================
        # DECISION TREE LABELING (matches learnable feature patterns)
        # =============================================================

        # TIER 1: Absolute threat indicators (any ONE = threat)
        # -----------------------------------------------------

        # Tor exit node = always threat
        if is_tor:
            return 1

        # High AbuseIPDB score (>50) = always threat
        if abuseipdb_score > 50:
            return 1

        # Critical/High threat level = always threat
        if threat_level in ('critical', 'high'):
            return 1

        # TIER 2: Combined indicators for failed logins
        # ----------------------------------------------

        if is_failed:
            # Failed + invalid_user + targeting admin/root = threat
            if is_invalid_user and (is_root or is_admin_user):
                return 1

            # Failed + datacenter + proxy = threat (hosting infrastructure attack)
            if is_datacenter and is_proxy:
                return 1

            # Failed + moderate abuse score (25-50) + datacenter = threat
            if abuseipdb_score >= 25 and is_datacenter:
                return 1

            # Failed + proxy + targeting root = threat
            if is_proxy and is_root:
                return 1

            # Failed + medium threat level = threat
            if threat_level == 'medium':
                return 1

        # TIER 3: Suspicious success (compromised accounts)
        # --------------------------------------------------

        if is_success:
            # Success from datacenter (cloud infra) = suspicious, but not always threat
            # Only threat if also has moderate abuse score
            if is_datacenter and abuseipdb_score >= 20:
                return 1

            # Success from proxy with abuse score = threat
            if is_proxy and abuseipdb_score >= 15:
                return 1

        # TIER 4: Default - everything else is normal
        # --------------------------------------------

        # Low-risk failed logins (organic typos, expired creds)
        # Low-risk successful logins (legitimate users)
        return 0

    def _split_data(self, X: np.ndarray, y: np.ndarray,
                   test_size: float = 0.2) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
        """Split data into train/test sets (80/20 split)"""
        try:
            from sklearn.model_selection import train_test_split
            return train_test_split(X, y, test_size=test_size, random_state=42, stratify=y)
        except ValueError:
            # If stratify fails (e.g., too few samples of one class), try without
            from sklearn.model_selection import train_test_split
            return train_test_split(X, y, test_size=test_size, random_state=42)

    def _train_model(self, algorithm: str, X_train: np.ndarray, y_train: np.ndarray,
                    params: Dict) -> Tuple[Any, Any]:
        """Train model with specified algorithm"""
        from sklearn.preprocessing import StandardScaler

        # Scale features
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X_train)

        # Create and train model
        if algorithm == 'random_forest':
            from sklearn.ensemble import RandomForestClassifier
            model = RandomForestClassifier(**params)

        elif algorithm == 'gradient_boosting':
            from sklearn.ensemble import GradientBoostingClassifier
            model = GradientBoostingClassifier(**params)

        elif algorithm == 'xgboost':
            try:
                from xgboost import XGBClassifier
                # Remove params that might not be supported
                xgb_params = {k: v for k, v in params.items()
                             if k not in ['use_label_encoder']}
                model = XGBClassifier(**xgb_params)
            except ImportError:
                logger.warning("XGBoost not available, using Gradient Boosting instead")
                from sklearn.ensemble import GradientBoostingClassifier
                gb_params = self.ALGORITHMS['gradient_boosting']['default_params']
                model = GradientBoostingClassifier(**gb_params)

        elif algorithm == 'isolation_forest':
            from sklearn.ensemble import IsolationForest
            model = IsolationForest(**params)

        else:
            raise ValueError(f"Unknown algorithm: {algorithm}")

        model.fit(X_scaled, y_train)
        return model, scaler

    def _evaluate_model(self, model: Any, scaler: Any,
                       X_test: np.ndarray, y_test: np.ndarray) -> Dict[str, Any]:
        """Evaluate model performance"""
        from sklearn.metrics import (accuracy_score, precision_score, recall_score,
                                    f1_score, roc_auc_score, confusion_matrix)

        X_scaled = scaler.transform(X_test)
        y_pred = model.predict(X_scaled)

        # Handle Isolation Forest (returns -1 for anomaly, 1 for normal)
        if hasattr(model, 'fit_predict') and not hasattr(model, 'predict_proba'):
            y_pred = np.where(y_pred == -1, 1, 0)

        metrics = {
            'accuracy': float(accuracy_score(y_test, y_pred)),
            'precision': float(precision_score(y_test, y_pred, zero_division=0)),
            'recall': float(recall_score(y_test, y_pred, zero_division=0)),
            'f1_score': float(f1_score(y_test, y_pred, zero_division=0)),
            'confusion_matrix': confusion_matrix(y_test, y_pred).tolist()
        }

        # ROC-AUC if probabilities available
        try:
            if hasattr(model, 'predict_proba'):
                y_proba = model.predict_proba(X_scaled)[:, 1]
                metrics['roc_auc'] = float(roc_auc_score(y_test, y_proba))
            elif hasattr(model, 'decision_function'):
                y_scores = model.decision_function(X_scaled)
                metrics['roc_auc'] = float(roc_auc_score(y_test, y_scores))
        except Exception:
            metrics['roc_auc'] = None

        # Feature importance
        if hasattr(model, 'feature_importances_'):
            feature_names = self.feature_extractor.get_feature_names()
            importance = dict(zip(feature_names, model.feature_importances_.tolist()))
            # Sort by importance
            metrics['feature_importance'] = dict(
                sorted(importance.items(), key=lambda x: x[1], reverse=True)
            )

        return metrics

    def _save_model(self, model: Any, scaler: Any, algorithm: str, params: Dict,
                   metrics: Dict, data_start: datetime, data_end: datetime,
                   training_samples: int, test_samples: int,
                   user_id: Optional[int]) -> int:
        """Save trained model to disk and database"""
        import joblib

        model_uuid = str(uuid.uuid4())
        version = datetime.now().strftime('%Y%m%d_%H%M%S')
        model_name = f"{algorithm}_{version}"
        model_filename = f"{model_name}.joblib"
        model_path = self.models_dir / model_filename

        # Save model package
        model_package = {
            'model': model,
            'scaler': scaler,
            'feature_names': self.feature_extractor.get_feature_names(),
            'algorithm': algorithm,
            'hyperparameters': params,
            'metrics': metrics,
            'trained_at': datetime.now().isoformat()
        }

        joblib.dump(model_package, model_path)
        model_size = model_path.stat().st_size

        # Save to database
        conn = get_connection()
        cursor = conn.cursor()

        try:
            # Extract feature importance JSON
            feature_importance = metrics.get('feature_importance')
            if feature_importance:
                feature_importance_json = json.dumps(feature_importance)
            else:
                feature_importance_json = None

            cursor.execute("""
                INSERT INTO ml_models
                (model_uuid, model_name, algorithm, version, status, is_active,
                 model_path, model_size_bytes, hyperparameters, feature_names,
                 training_data_start, training_data_end, training_samples, test_samples,
                 accuracy, precision_score, recall_score, f1_score, roc_auc,
                 confusion_matrix, feature_importance,
                 training_started_at, training_completed_at, created_by_user_id)
                VALUES (%s, %s, %s, %s, 'candidate', FALSE,
                        %s, %s, %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s, %s, %s, NOW(), NOW(), %s)
            """, (
                model_uuid, model_name, algorithm, version,
                str(model_path), model_size,
                json.dumps(params),
                json.dumps(self.feature_extractor.get_feature_names()),
                data_start.date(), data_end.date(),
                training_samples, test_samples,
                metrics.get('accuracy'),
                metrics.get('precision'),
                metrics.get('recall'),
                metrics.get('f1_score'),
                metrics.get('roc_auc'),
                json.dumps(metrics.get('confusion_matrix')),
                feature_importance_json,
                user_id
            ))

            conn.commit()
            model_id = cursor.lastrowid

            logger.info(f"Model saved: {model_name} (ID: {model_id})")
            return model_id

        finally:
            cursor.close()
            conn.close()

    def _promote_model(self, model_id: int):
        """Promote model to production using optimized query"""
        try:
            promote_model_to_production(model_id)
            logger.info(f"Model {model_id} promoted to production")
        except Exception as e:
            logger.error(f"Failed to promote model {model_id}: {e}")
            raise

    def _create_training_run(self, algorithm: str, data_start: datetime,
                            data_end: datetime, hyperparameters: Optional[Dict],
                            include_simulation: bool, user_id: Optional[int]) -> int:
        """Create training run record"""
        conn = get_connection()
        cursor = conn.cursor()

        run_uuid = str(uuid.uuid4())
        params = hyperparameters or self.ALGORITHMS[algorithm]['default_params']

        try:
            cursor.execute("""
                INSERT INTO ml_training_runs
                (run_uuid, algorithm, hyperparameters, data_start_date, data_end_date,
                 include_simulation_data, status, progress_percent, started_at, created_by_user_id)
                VALUES (%s, %s, %s, %s, %s, %s, 'pending', 0, NOW(), %s)
            """, (
                run_uuid, algorithm, json.dumps(params),
                data_start.date(), data_end.date(),
                include_simulation, user_id
            ))

            conn.commit()
            return cursor.lastrowid

        finally:
            cursor.close()
            conn.close()

    def _update_run_status(self, run_id: int, status: str, progress: int, stage: str):
        """Update training run status using optimized query"""
        try:
            update_training_run_progress(run_id, status, progress, stage)
        except Exception as e:
            logger.error(f"Failed to update run status: {e}")

    def _update_run_samples(self, run_id: int, total_samples: int):
        """Update sample counts in training run using optimized query"""
        try:
            update_training_run_samples(run_id, total_samples)
        except Exception as e:
            logger.error(f"Failed to update run samples: {e}")

    def _complete_training_run(self, run_id: int, model_id: int, metrics: Dict):
        """Mark training run as completed using optimized query"""
        try:
            complete_training_run(run_id, model_id)
        except Exception as e:
            logger.error(f"Failed to complete training run: {e}")

    def _fail_training_run(self, run_id: int, error_message: str):
        """Mark training run as failed using optimized query"""
        try:
            fail_training_run(run_id, error_message)
        except Exception as e:
            logger.error(f"Failed to mark training run as failed: {e}")

    def get_training_runs(self, limit: int = 20) -> List[Dict]:
        """Get recent training runs"""
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            cursor.execute("""
                SELECT tr.*, m.model_name, m.f1_score as model_f1
                FROM ml_training_runs tr
                LEFT JOIN ml_models m ON tr.model_id = m.id
                ORDER BY tr.created_at DESC
                LIMIT %s
            """, (limit,))

            runs = cursor.fetchall()

            # Parse JSON fields
            for run in runs:
                if run.get('hyperparameters'):
                    try:
                        run['hyperparameters'] = json.loads(run['hyperparameters'])
                    except:
                        pass

            return runs

        finally:
            cursor.close()
            conn.close()

    def get_models(self, status: Optional[str] = None) -> List[Dict]:
        """Get all models, optionally filtered by status"""
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            query = "SELECT * FROM ml_models"
            params = []

            if status:
                query += " WHERE status = %s"
                params.append(status)

            query += " ORDER BY created_at DESC"

            cursor.execute(query, params)
            models = cursor.fetchall()

            # Parse JSON fields
            for model in models:
                for field in ['hyperparameters', 'feature_names', 'confusion_matrix', 'feature_importance']:
                    if model.get(field):
                        try:
                            model[field] = json.loads(model[field])
                        except:
                            pass

            return models

        finally:
            cursor.close()
            conn.close()

    def get_model(self, model_id: int) -> Optional[Dict]:
        """Get model by ID"""
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            cursor.execute("SELECT * FROM ml_models WHERE id = %s", (model_id,))
            model = cursor.fetchone()

            if model:
                for field in ['hyperparameters', 'feature_names', 'confusion_matrix', 'feature_importance']:
                    if model.get(field):
                        try:
                            model[field] = json.loads(model[field])
                        except:
                            pass

            return model

        finally:
            cursor.close()
            conn.close()

    def promote_model(self, model_id: int) -> bool:
        """Manually promote a model to production"""
        try:
            self._promote_model(model_id)
            return True
        except Exception as e:
            logger.error(f"Failed to promote model {model_id}: {e}")
            return False

    def deprecate_model(self, model_id: int) -> bool:
        """Deprecate a model"""
        conn = get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("""
                UPDATE ml_models
                SET status = 'deprecated', is_active = FALSE,
                    deprecated_at = NOW()
                WHERE id = %s
            """, (model_id,))
            conn.commit()
            return True
        except Exception as e:
            logger.error(f"Failed to deprecate model {model_id}: {e}")
            return False
        finally:
            cursor.close()
            conn.close()


# Factory function
def create_trainer(models_dir: Path) -> MLTrainer:
    """Create ML Trainer instance"""
    return MLTrainer(models_dir)
