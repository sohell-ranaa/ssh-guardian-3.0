#!/usr/bin/env python3
"""
SSH Guardian v3.0 - ML Model Comparison Training
=================================================
Trains and compares 3 ML algorithms (Random Forest, XGBoost, LightGBM)
for academic justification of algorithm selection.

Features:
- Loads data from ml_training_data and ml_testing_data tables
- Extracts 50 features using FeatureExtractor
- Trains 3 models with identical data splits
- Computes 8+ metrics including confusion matrices
- Saves all results to ml_comparison_results table
- Generates thesis-ready comparison report

Author: SSH Guardian Team
"""

import os
import sys
import json
import uuid
import time
import logging
import pickle
import traceback
from datetime import datetime
from typing import Dict, List, Tuple, Any, Optional

import numpy as np
import psutil

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import mysql.connector
from mysql.connector import pooling

# ML Libraries
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix, classification_report,
    matthews_corrcoef, balanced_accuracy_score
)
from sklearn.model_selection import cross_val_score, RandomizedSearchCV

# XGBoost and LightGBM
try:
    from xgboost import XGBClassifier
    XGBOOST_AVAILABLE = True
except ImportError:
    XGBOOST_AVAILABLE = False
    print("Warning: XGBoost not installed. Run: pip install xgboost")

try:
    from lightgbm import LGBMClassifier
    LIGHTGBM_AVAILABLE = True
except ImportError:
    LIGHTGBM_AVAILABLE = False
    print("Warning: LightGBM not installed. Run: pip install lightgbm")

# ==================================================
# CONFIGURATION
# ==================================================

# Database config
DB_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': '123123',
    'database': 'ssh_guardian_v3_1',
    'pool_name': 'ml_training_pool',
    'pool_size': 5
}

# Model save directory
MODEL_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'ml_models')
os.makedirs(MODEL_DIR, exist_ok=True)

# Training configuration
BATCH_SIZE = 10000
N_JOBS = 1  # Use single core to reduce CPU usage
RANDOM_STATE = 42
CV_FOLDS = 5

# Hyperparameter tuning configuration
TUNING_ENABLED = True
N_ITER_SEARCH = 10  # Number of random parameter combinations to try
TUNING_CV_FOLDS = 3  # CV folds for hyperparameter search (faster)

# Model configurations with hyperparameter search spaces
MODEL_CONFIGS = {
    'random_forest': {
        'class': RandomForestClassifier,
        'default_params': {
            'class_weight': 'balanced',
            'bootstrap': True,
            'random_state': RANDOM_STATE,
            'n_jobs': N_JOBS
        },
        'param_distributions': {
            'n_estimators': [50, 100, 150, 200, 250],
            'max_depth': [5, 10, 15, 20, 25, 30, None],
            'min_samples_split': [2, 5, 10, 15, 20],
            'min_samples_leaf': [1, 2, 4, 6, 8],
            'max_features': ['sqrt', 'log2', 0.3, 0.5, 0.7]
        }
    },
    'xgboost': {
        'class': XGBClassifier if XGBOOST_AVAILABLE else None,
        'default_params': {
            'use_label_encoder': False,
            'eval_metric': 'logloss',
            'random_state': RANDOM_STATE,
            'n_jobs': N_JOBS
        },
        'param_distributions': {
            'n_estimators': [50, 100, 150, 200, 250],
            'max_depth': [3, 5, 7, 10, 12, 15],
            'learning_rate': [0.01, 0.05, 0.1, 0.15, 0.2],
            'subsample': [0.6, 0.7, 0.8, 0.9, 1.0],
            'colsample_bytree': [0.6, 0.7, 0.8, 0.9, 1.0],
            'min_child_weight': [1, 3, 5, 7],
            'gamma': [0, 0.1, 0.2, 0.3]
        }
    },
    'lightgbm': {
        'class': LGBMClassifier if LIGHTGBM_AVAILABLE else None,
        'default_params': {
            'class_weight': 'balanced',
            'random_state': RANDOM_STATE,
            'n_jobs': N_JOBS,
            'verbose': -1
        },
        'param_distributions': {
            'n_estimators': [50, 100, 150, 200, 250],
            'max_depth': [3, 5, 7, 10, 15, 20, -1],
            'learning_rate': [0.01, 0.05, 0.1, 0.15, 0.2],
            'num_leaves': [15, 31, 50, 70, 100],
            'subsample': [0.6, 0.7, 0.8, 0.9, 1.0],
            'colsample_bytree': [0.6, 0.7, 0.8, 0.9, 1.0],
            'min_child_samples': [5, 10, 20, 30, 50]
        }
    }
}

# 50 Feature names (from FeatureExtractor)
FEATURE_NAMES = [
    # Temporal (6)
    'hour_normalized', 'minute_normalized', 'day_of_week_normalized',
    'is_weekend', 'is_business_hours', 'is_night',
    # Event Type (5)
    'is_failed', 'is_success', 'is_invalid_user', 'is_invalid_password', 'failure_reason_encoded',
    # Geographic (6)
    'latitude_normalized', 'longitude_normalized', 'is_high_risk_country',
    'is_unknown_country', 'distance_from_previous', 'is_new_location',
    # Username (6)
    'is_root', 'is_admin_username', 'is_system_account',
    'username_entropy', 'username_length', 'username_has_numbers',
    # IP Behavior (9)
    'fails_last_hour', 'fails_last_10min', 'unique_users_tried',
    'unique_servers_hit', 'success_rate', 'hours_since_first_seen',
    'avg_interval_between_attempts', 'attempts_per_minute', 'is_first_time_ip',
    # Network Flags (5)
    'is_proxy', 'is_vpn', 'is_tor', 'is_datacenter', 'is_hosting',
    # Threat Reputation (3)
    'abuseipdb_score', 'virustotal_ratio', 'threat_level_encoded',
    # Pattern (2)
    'is_sequential_username', 'is_distributed_attack',
    # Advanced Detection (8)
    'travel_velocity_kmh', 'is_impossible_travel', 'success_after_failures',
    'is_brute_success', 'servers_accessed_10min', 'attempts_per_second',
    'is_greynoise_scanner', 'user_time_deviation_hours'
]

# High-risk countries
HIGH_RISK_COUNTRIES = {'CN', 'RU', 'KP', 'IR', 'VN', 'BR', 'IN', 'PK', 'NG', 'UA'}

# Admin usernames
ADMIN_USERNAMES = {'root', 'admin', 'administrator', 'sudo', 'superuser', 'sysadmin'}

# System accounts
SYSTEM_ACCOUNTS = {'daemon', 'bin', 'sys', 'sync', 'games', 'man', 'lp', 'mail',
                   'news', 'uucp', 'proxy', 'www-data', 'backup', 'nobody'}

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('/tmp/ml_training_comparison.log')
    ]
)
logger = logging.getLogger(__name__)


class FeatureExtractorSimple:
    """
    Simplified feature extractor for training data.
    Extracts 50 features from pre-computed event data.
    """

    def __init__(self):
        self.feature_names = FEATURE_NAMES

    def calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not text:
            return 0.0
        prob = [float(text.count(c)) / len(text) for c in set(text)]
        return -sum(p * np.log2(p) for p in prob if p > 0)

    def extract_features(self, event: Dict, ip_history: Dict = None) -> np.ndarray:
        """Extract 50 features from a single event."""
        features = np.zeros(50, dtype=np.float32)

        # ==================================================
        # TEMPORAL FEATURES (6)
        # ==================================================
        timestamp = event.get('timestamp')
        if timestamp:
            if isinstance(timestamp, str):
                timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))

            features[0] = timestamp.hour / 24.0  # hour_normalized
            features[1] = timestamp.minute / 60.0  # minute_normalized
            features[2] = timestamp.weekday() / 6.0  # day_of_week_normalized
            features[3] = 1.0 if timestamp.weekday() >= 5 else 0.0  # is_weekend
            features[4] = 1.0 if 9 <= timestamp.hour <= 17 else 0.0  # is_business_hours
            features[5] = 1.0 if timestamp.hour < 6 or timestamp.hour > 22 else 0.0  # is_night

        # ==================================================
        # EVENT TYPE FEATURES (5)
        # ==================================================
        event_type = event.get('event_type', '').lower()
        failure_reason = event.get('failure_reason', '') or ''

        features[6] = 1.0 if 'failed' in event_type else 0.0  # is_failed
        features[7] = 1.0 if 'success' in event_type else 0.0  # is_success
        features[8] = 1.0 if 'invalid_user' in failure_reason else 0.0  # is_invalid_user
        features[9] = 1.0 if 'invalid_password' in failure_reason else 0.0  # is_invalid_password

        # failure_reason_encoded
        reason_map = {'': 0, 'invalid_user': 0.4, 'invalid_password': 0.6,
                      'permission_denied': 0.7, 'connection_timeout': 0.3}
        features[10] = reason_map.get(failure_reason, 0.5)

        # ==================================================
        # GEOGRAPHIC FEATURES (6)
        # ==================================================
        lat = event.get('latitude', 0) or 0
        lon = event.get('longitude', 0) or 0
        country = event.get('country_code', '') or ''

        features[11] = float(lat) / 90.0  # latitude_normalized
        features[12] = float(lon) / 180.0  # longitude_normalized
        features[13] = 1.0 if country in HIGH_RISK_COUNTRIES else 0.0  # is_high_risk_country
        features[14] = 1.0 if not country else 0.0  # is_unknown_country
        features[15] = 0.0  # distance_from_previous (requires history)
        features[16] = 0.0  # is_new_location (requires history)

        # ==================================================
        # USERNAME FEATURES (6)
        # ==================================================
        username = event.get('target_username', '') or ''

        features[17] = 1.0 if username.lower() == 'root' else 0.0  # is_root
        features[18] = 1.0 if username.lower() in ADMIN_USERNAMES else 0.0  # is_admin_username
        features[19] = 1.0 if username.lower() in SYSTEM_ACCOUNTS else 0.0  # is_system_account
        features[20] = min(self.calculate_entropy(username) / 4.0, 1.0)  # username_entropy
        features[21] = min(len(username), 32) / 32.0  # username_length
        features[22] = 1.0 if any(c.isdigit() for c in username) else 0.0  # username_has_numbers

        # ==================================================
        # IP BEHAVIOR FEATURES (9)
        # ==================================================
        # These would normally come from IP history, using defaults for training
        features[23] = 0.0  # fails_last_hour
        features[24] = 0.0  # fails_last_10min
        features[25] = 0.0  # unique_users_tried
        features[26] = 0.0  # unique_servers_hit
        features[27] = 0.5  # success_rate
        features[28] = 0.5  # hours_since_first_seen
        features[29] = 0.5  # avg_interval_between_attempts
        features[30] = 0.0  # attempts_per_minute
        features[31] = 0.0  # is_first_time_ip

        # ==================================================
        # NETWORK FLAGS FEATURES (5)
        # ==================================================
        features[32] = float(event.get('is_proxy', 0) or 0)  # is_proxy
        features[33] = float(event.get('is_vpn', 0) or 0)  # is_vpn
        features[34] = float(event.get('is_tor', 0) or 0)  # is_tor
        features[35] = float(event.get('is_datacenter', 0) or 0)  # is_datacenter
        features[36] = float(event.get('is_hosting', 0) or 0)  # is_hosting

        # ==================================================
        # THREAT REPUTATION FEATURES (3)
        # ==================================================
        abuse_score = event.get('abuseipdb_score', 0) or 0
        vt_positives = event.get('virustotal_positives', 0) or 0
        vt_total = event.get('virustotal_total', 90) or 90
        threat_level = event.get('threat_level', 'clean') or 'clean'

        features[37] = float(abuse_score) / 100.0  # abuseipdb_score
        features[38] = float(vt_positives) / max(float(vt_total), 1)  # virustotal_ratio

        # threat_level_encoded
        level_map = {'clean': 0.0, 'low': 0.25, 'medium': 0.5, 'high': 0.75, 'critical': 1.0}
        features[39] = level_map.get(threat_level.lower(), 0.5)

        # ==================================================
        # PATTERN FEATURES (2)
        # ==================================================
        features[40] = 0.0  # is_sequential_username (requires pattern detection)
        features[41] = 0.0  # is_distributed_attack (requires pattern detection)

        # ==================================================
        # ADVANCED DETECTION FEATURES (8)
        # ==================================================
        features[42] = 0.0  # travel_velocity_kmh
        features[43] = 0.0  # is_impossible_travel

        # Simulate brute force detection based on scenario
        scenario = event.get('scenario_type', '')
        if 'brute' in scenario:
            features[44] = 0.8  # success_after_failures
            features[45] = 1.0  # is_brute_success
        else:
            features[44] = 0.0
            features[45] = 0.0

        if 'lateral' in scenario:
            features[46] = 0.8  # servers_accessed_10min
        else:
            features[46] = 0.0

        features[47] = 0.0  # attempts_per_second

        # GreyNoise classification
        greynoise = event.get('greynoise_classification', '') or ''
        if greynoise == 'malicious':
            features[48] = 1.0
        elif greynoise == 'benign':
            features[48] = -0.5
        else:
            features[48] = 0.0

        features[49] = 0.0  # user_time_deviation_hours

        return features


class ModelTrainer:
    """Trains and compares ML models."""

    def __init__(self):
        self.db_pool = None
        self.scaler = StandardScaler()
        self.feature_extractor = FeatureExtractorSimple()
        self.results = {}
        self.run_id = None

    def connect_db(self):
        """Create database connection pool."""
        try:
            self.db_pool = mysql.connector.pooling.MySQLConnectionPool(**DB_CONFIG)
            logger.info(f"Database pool created: {DB_CONFIG['database']}")
        except Exception as e:
            logger.error(f"Database connection failed: {e}")
            raise

    def get_connection(self):
        """Get a connection from the pool."""
        return self.db_pool.get_connection()

    def load_training_data(self) -> Tuple[np.ndarray, np.ndarray]:
        """Load and extract features from training data."""
        logger.info("Loading training data...")

        conn = self.get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            cursor.execute("SELECT COUNT(*) as cnt FROM ml_training_data")
            total = cursor.fetchone()['cnt']
            logger.info(f"Total training events: {total:,}")

            features_list = []
            labels_list = []
            offset = 0

            while offset < total:
                cursor.execute(f"""
                    SELECT * FROM ml_training_data
                    LIMIT {BATCH_SIZE} OFFSET {offset}
                """)

                batch = cursor.fetchall()
                for event in batch:
                    features = self.feature_extractor.extract_features(event)
                    features_list.append(features)
                    labels_list.append(event['is_malicious'])

                offset += BATCH_SIZE
                logger.info(f"  Loaded {min(offset, total):,}/{total:,} ({min(offset, total)/total*100:.1f}%)")

            X = np.array(features_list, dtype=np.float32)
            y = np.array(labels_list, dtype=np.int32)

            logger.info(f"Training data shape: {X.shape}")
            logger.info(f"Label distribution: 0={np.sum(y==0):,}, 1={np.sum(y==1):,}")

            return X, y

        finally:
            cursor.close()
            conn.close()

    def load_testing_data(self) -> Tuple[np.ndarray, np.ndarray]:
        """Load and extract features from testing data."""
        logger.info("Loading testing data...")

        conn = self.get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            cursor.execute("SELECT COUNT(*) as cnt FROM ml_testing_data")
            total = cursor.fetchone()['cnt']
            logger.info(f"Total testing events: {total:,}")

            features_list = []
            labels_list = []
            offset = 0

            while offset < total:
                cursor.execute(f"""
                    SELECT * FROM ml_testing_data
                    LIMIT {BATCH_SIZE} OFFSET {offset}
                """)

                batch = cursor.fetchall()
                for event in batch:
                    features = self.feature_extractor.extract_features(event)
                    features_list.append(features)
                    labels_list.append(event['is_malicious'])

                offset += BATCH_SIZE
                logger.info(f"  Loaded {min(offset, total):,}/{total:,} ({min(offset, total)/total*100:.1f}%)")

            X = np.array(features_list, dtype=np.float32)
            y = np.array(labels_list, dtype=np.int32)

            logger.info(f"Testing data shape: {X.shape}")
            logger.info(f"Label distribution: 0={np.sum(y==0):,}, 1={np.sum(y==1):,}")

            return X, y

        finally:
            cursor.close()
            conn.close()

    def train_model(self, name: str, X_train: np.ndarray, y_train: np.ndarray,
                    X_test: np.ndarray, y_test: np.ndarray) -> Dict:
        """Train a single model with hyperparameter tuning and compute all metrics."""

        config = MODEL_CONFIGS.get(name)
        if not config or not config['class']:
            logger.warning(f"Skipping {name} - not available")
            return None

        logger.info(f"\n{'='*60}")
        logger.info(f"Training: {name.upper()}")
        logger.info(f"{'='*60}")

        # Measure training time
        start_time = time.time()
        process = psutil.Process()
        mem_before = process.memory_info().rss / 1024 / 1024

        # Get default parameters and search space
        default_params = config['default_params'].copy()
        param_distributions = config['param_distributions']

        if TUNING_ENABLED:
            logger.info(f"Running RandomizedSearchCV with {N_ITER_SEARCH} iterations...")
            logger.info(f"Parameter search space: {list(param_distributions.keys())}")

            # Initialize base model with default params
            base_model = config['class'](**default_params)

            # RandomizedSearchCV
            search = RandomizedSearchCV(
                estimator=base_model,
                param_distributions=param_distributions,
                n_iter=N_ITER_SEARCH,
                cv=TUNING_CV_FOLDS,
                scoring='f1',
                n_jobs=N_JOBS,
                random_state=RANDOM_STATE,
                verbose=1,
                return_train_score=True
            )

            # Fit with hyperparameter search
            search.fit(X_train, y_train)

            # Get best model and parameters
            model = search.best_estimator_
            best_params = search.best_params_
            best_cv_score = search.best_score_

            logger.info(f"\nBest Parameters Found:")
            for param, value in best_params.items():
                logger.info(f"  {param}: {value}")
            logger.info(f"Best CV Score (F1): {best_cv_score:.4f}")

            # Combine default and best params for storage
            final_params = {**default_params, **best_params}

            # Get all CV results for analysis
            cv_results = {
                'mean_test_score': search.cv_results_['mean_test_score'].tolist(),
                'std_test_score': search.cv_results_['std_test_score'].tolist(),
                'params': [str(p) for p in search.cv_results_['params']],
                'rank_test_score': search.cv_results_['rank_test_score'].tolist()
            }
        else:
            # Use default parameters without tuning
            final_params = default_params
            model = config['class'](**final_params)
            model.fit(X_train, y_train)
            cv_results = None
            best_params = {}

        training_time = time.time() - start_time
        mem_after = process.memory_info().rss / 1024 / 1024
        memory_usage = mem_after - mem_before

        logger.info(f"\nTotal Training time: {training_time:.2f}s")

        # Predictions
        start_pred = time.time()
        y_pred = model.predict(X_test)
        y_prob = model.predict_proba(X_test)[:, 1]
        prediction_time = (time.time() - start_pred) * 1000 / len(X_test)  # ms per sample

        # Confusion Matrix
        cm = confusion_matrix(y_test, y_pred)
        tn, fp, fn, tp = cm.ravel()

        # Metrics
        accuracy = accuracy_score(y_test, y_pred)
        precision = precision_score(y_test, y_pred)
        recall = recall_score(y_test, y_pred)
        f1 = f1_score(y_test, y_pred)
        roc_auc = roc_auc_score(y_test, y_prob)
        specificity = tn / (tn + fp)
        balanced_acc = balanced_accuracy_score(y_test, y_pred)
        mcc = matthews_corrcoef(y_test, y_pred)

        # Final cross-validation on best model
        logger.info(f"Running final {CV_FOLDS}-fold cross-validation on best model...")
        cv_scores = cross_val_score(model, X_train, y_train, cv=CV_FOLDS, scoring='f1', n_jobs=N_JOBS)

        # Classification report
        class_report = classification_report(y_test, y_pred, output_dict=True)

        # Feature importance
        if hasattr(model, 'feature_importances_'):
            importance = model.feature_importances_
            feature_importance = [
                {'feature': feat_name, 'importance': float(imp)}
                for feat_name, imp in sorted(zip(FEATURE_NAMES, importance), key=lambda x: -x[1])
            ]
        else:
            feature_importance = []

        # Results
        result = {
            'model_name': f"{name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            'algorithm': name,
            'training_samples': len(X_train),
            'testing_samples': len(X_test),
            'feature_count': 50,
            'hyperparameters': final_params,
            'best_params': best_params,
            'tuning_enabled': TUNING_ENABLED,
            'n_iter_search': N_ITER_SEARCH if TUNING_ENABLED else 0,
            'accuracy': accuracy,
            'precision_score': precision,
            'recall_score': recall,
            'f1_score': f1,
            'roc_auc': roc_auc,
            'specificity': specificity,
            'balanced_accuracy': balanced_acc,
            'matthews_correlation': mcc,
            'true_positives': int(tp),
            'true_negatives': int(tn),
            'false_positives': int(fp),
            'false_negatives': int(fn),
            'confusion_matrix': cm.tolist(),
            'training_time_seconds': training_time,
            'prediction_time_ms': prediction_time,
            'memory_usage_mb': abs(memory_usage),
            'feature_importance': feature_importance[:20],  # Top 20
            'cv_scores': cv_scores.tolist(),
            'cv_mean': float(cv_scores.mean()),
            'cv_std': float(cv_scores.std()),
            'classification_report': class_report,
            'cv_search_results': cv_results,
            'model': model
        }

        # Print metrics
        logger.info(f"\n{'-'*40}")
        logger.info(f"FINAL METRICS for {name.upper()}:")
        logger.info(f"{'-'*40}")
        logger.info(f"  Accuracy:           {accuracy:.4f}")
        logger.info(f"  Precision:          {precision:.4f}")
        logger.info(f"  Recall:             {recall:.4f}")
        logger.info(f"  F1 Score:           {f1:.4f}")
        logger.info(f"  ROC AUC:            {roc_auc:.4f}")
        logger.info(f"  Specificity:        {specificity:.4f}")
        logger.info(f"  Balanced Accuracy:  {balanced_acc:.4f}")
        logger.info(f"  MCC:                {mcc:.4f}")
        logger.info(f"  CV F1 Mean:         {cv_scores.mean():.4f} (+/- {cv_scores.std():.4f})")
        logger.info(f"\n  Confusion Matrix:")
        logger.info(f"    TN={tn:,}  FP={fp:,}")
        logger.info(f"    FN={fn:,}  TP={tp:,}")
        logger.info(f"\n  Training Time:      {training_time:.2f}s")
        logger.info(f"  Prediction Time:    {prediction_time:.4f}ms/sample")
        logger.info(f"  Memory Usage:       {abs(memory_usage):.1f}MB")

        if TUNING_ENABLED and best_params:
            logger.info(f"\n  Best Hyperparameters:")
            for param, value in best_params.items():
                logger.info(f"    {param}: {value}")

        return result

    def save_model(self, result: Dict) -> str:
        """Save trained model to file."""
        model = result.pop('model', None)
        if model:
            model_path = os.path.join(MODEL_DIR, f"{result['model_name']}.pkl")
            with open(model_path, 'wb') as f:
                pickle.dump({
                    'model': model,
                    'scaler': self.scaler,
                    'feature_names': FEATURE_NAMES
                }, f)
            logger.info(f"Model saved: {model_path}")
            return model_path
        return ""

    def save_results_to_db(self, results: List[Dict]):
        """Save all results to ml_comparison_results table."""
        logger.info("\nSaving results to database...")

        conn = self.get_connection()
        cursor = conn.cursor()

        try:
            # Get run_id
            cursor.execute("SELECT id FROM ml_training_runs ORDER BY id DESC LIMIT 1")
            row = cursor.fetchone()
            run_id = row[0] if row else None

            # Determine best model by F1 score
            best_model = max(results, key=lambda x: x['f1_score'])

            for result in results:
                is_best = result == best_model

                # Prepare JSON fields
                hyperparams_json = json.dumps(self._make_serializable(result['hyperparameters']))
                confusion_json = json.dumps(result['confusion_matrix'])
                feature_imp_json = json.dumps(result['feature_importance'])
                cv_scores_json = json.dumps(result['cv_scores'])
                class_report_json = json.dumps(result['classification_report'])

                selection_reason = ""
                if is_best:
                    selection_reason = f"Best F1 Score ({result['f1_score']:.4f}) among all models. "
                    selection_reason += f"Balanced performance with {result['accuracy']:.4f} accuracy, "
                    selection_reason += f"{result['recall_score']:.4f} recall (threat detection), and "
                    selection_reason += f"{result['precision_score']:.4f} precision (low false positives)."

                cursor.execute("""
                    INSERT INTO ml_comparison_results (
                        run_id, model_name, algorithm, model_version, model_file_path,
                        training_samples, testing_samples, feature_count,
                        hyperparameters,
                        accuracy, precision_score, recall_score, f1_score, roc_auc,
                        true_positives, true_negatives, false_positives, false_negatives,
                        confusion_matrix,
                        specificity, balanced_accuracy, matthews_correlation,
                        training_time_seconds, prediction_time_ms, memory_usage_mb,
                        feature_importance, cv_scores, cv_mean, cv_std,
                        classification_report,
                        is_best_model, selection_reason
                    ) VALUES (
                        %s, %s, %s, %s, %s,
                        %s, %s, %s,
                        %s,
                        %s, %s, %s, %s, %s,
                        %s, %s, %s, %s,
                        %s,
                        %s, %s, %s,
                        %s, %s, %s,
                        %s, %s, %s, %s,
                        %s,
                        %s, %s
                    )
                """, (
                    run_id,
                    result['model_name'],
                    result['algorithm'],
                    '1.0.0',
                    result.get('model_file_path', ''),
                    result['training_samples'],
                    result['testing_samples'],
                    result['feature_count'],
                    hyperparams_json,
                    result['accuracy'],
                    result['precision_score'],
                    result['recall_score'],
                    result['f1_score'],
                    result['roc_auc'],
                    result['true_positives'],
                    result['true_negatives'],
                    result['false_positives'],
                    result['false_negatives'],
                    confusion_json,
                    result['specificity'],
                    result['balanced_accuracy'],
                    result['matthews_correlation'],
                    result['training_time_seconds'],
                    result['prediction_time_ms'],
                    result['memory_usage_mb'],
                    feature_imp_json,
                    cv_scores_json,
                    result['cv_mean'],
                    result['cv_std'],
                    class_report_json,
                    1 if is_best else 0,
                    selection_reason
                ))

                logger.info(f"  Saved: {result['algorithm']} {'[BEST]' if is_best else ''}")

            conn.commit()
            logger.info("All results saved to database!")

        except Exception as e:
            logger.error(f"Error saving results: {e}")
            conn.rollback()
            raise
        finally:
            cursor.close()
            conn.close()

    def _make_serializable(self, obj):
        """Convert numpy types to Python types for JSON serialization."""
        if isinstance(obj, dict):
            return {k: self._make_serializable(v) for k, v in obj.items()}
        elif isinstance(obj, (list, tuple)):
            return [self._make_serializable(v) for v in obj]
        elif isinstance(obj, np.integer):
            return int(obj)
        elif isinstance(obj, np.floating):
            return float(obj)
        elif isinstance(obj, np.ndarray):
            return obj.tolist()
        return obj

    def print_comparison_report(self, results: List[Dict]):
        """Print a formatted comparison report."""
        logger.info("\n")
        logger.info("=" * 80)
        logger.info("                    ML MODEL COMPARISON REPORT")
        logger.info("=" * 80)
        logger.info(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        logger.info(f"Training Samples: {results[0]['training_samples']:,}")
        logger.info(f"Testing Samples: {results[0]['testing_samples']:,}")
        logger.info(f"Features: {results[0]['feature_count']}")
        logger.info("=" * 80)

        # Comparison table
        header = f"{'Metric':<25} | " + " | ".join([f"{r['algorithm']:^15}" for r in results])
        logger.info("\n" + header)
        logger.info("-" * len(header))

        metrics = [
            ('Accuracy', 'accuracy'),
            ('Precision', 'precision_score'),
            ('Recall', 'recall_score'),
            ('F1 Score', 'f1_score'),
            ('ROC AUC', 'roc_auc'),
            ('Specificity', 'specificity'),
            ('Balanced Accuracy', 'balanced_accuracy'),
            ('MCC', 'matthews_correlation'),
            ('CV Mean (F1)', 'cv_mean'),
            ('CV Std', 'cv_std'),
            ('Training Time (s)', 'training_time_seconds'),
            ('Pred Time (ms)', 'prediction_time_ms'),
            ('Memory (MB)', 'memory_usage_mb'),
        ]

        for label, key in metrics:
            values = []
            for r in results:
                val = r.get(key, 0)
                if key in ['training_time_seconds']:
                    values.append(f"{val:^15.2f}")
                elif key in ['prediction_time_ms']:
                    values.append(f"{val:^15.4f}")
                elif key in ['memory_usage_mb']:
                    values.append(f"{val:^15.1f}")
                else:
                    values.append(f"{val:^15.4f}")
            logger.info(f"{label:<25} | " + " | ".join(values))

        # Confusion matrices
        logger.info("\n" + "=" * 80)
        logger.info("CONFUSION MATRICES")
        logger.info("=" * 80)

        for r in results:
            logger.info(f"\n{r['algorithm'].upper()}:")
            logger.info(f"  Predicted:    Benign    Malicious")
            logger.info(f"  Actual Benign:  {r['true_negatives']:>6,}     {r['false_positives']:>6,}")
            logger.info(f"  Actual Malicious: {r['false_negatives']:>6,}     {r['true_positives']:>6,}")

        # Best model
        best = max(results, key=lambda x: x['f1_score'])
        logger.info("\n" + "=" * 80)
        logger.info(f"BEST MODEL: {best['algorithm'].upper()}")
        logger.info("=" * 80)
        logger.info(f"F1 Score: {best['f1_score']:.4f}")
        logger.info(f"Justification: Achieved highest F1 score with balanced precision/recall.")
        logger.info(f"  - High recall ({best['recall_score']:.4f}) for threat detection")
        logger.info(f"  - Good precision ({best['precision_score']:.4f}) to minimize false positives")
        logger.info(f"  - Strong cross-validation consistency (CV std: {best['cv_std']:.4f})")

        # Top features
        if best.get('feature_importance'):
            logger.info("\nTop 10 Most Important Features:")
            for i, feat in enumerate(best['feature_importance'][:10], 1):
                logger.info(f"  {i:>2}. {feat['feature']:<30} {feat['importance']:.4f}")

        logger.info("\n" + "=" * 80)

    def run(self):
        """Run the full training pipeline."""
        try:
            self.connect_db()

            logger.info("=" * 60)
            logger.info("SSH GUARDIAN v3.0 - ML MODEL COMPARISON TRAINING")
            logger.info("=" * 60)
            logger.info(f"Models: Random Forest, XGBoost, LightGBM")
            logger.info(f"Features: 50")
            logger.info(f"CV Folds: {CV_FOLDS}")
            logger.info("=" * 60)

            # Load data
            X_train, y_train = self.load_training_data()
            X_test, y_test = self.load_testing_data()

            # Scale features
            logger.info("\nScaling features...")
            X_train_scaled = self.scaler.fit_transform(X_train)
            X_test_scaled = self.scaler.transform(X_test)

            # Train each model
            results = []
            for model_name in ['random_forest', 'xgboost', 'lightgbm']:
                result = self.train_model(model_name, X_train_scaled, y_train, X_test_scaled, y_test)
                if result:
                    # Save model
                    model_path = self.save_model(result)
                    result['model_file_path'] = model_path
                    results.append(result)

            # Save results to database
            self.save_results_to_db(results)

            # Print comparison report
            self.print_comparison_report(results)

            logger.info("\n" + "=" * 60)
            logger.info("TRAINING COMPLETE!")
            logger.info("=" * 60)

            return results

        except Exception as e:
            logger.error(f"Training failed: {e}")
            traceback.print_exc()
            raise


if __name__ == '__main__':
    trainer = ModelTrainer()
    trainer.run()
