"""
SSH Guardian v3.0 - ML Model Training Engine
Train, evaluate, and manage multiple ML models for threat detection
"""

import os
import json
import pickle
import joblib
import numpy as np
import pandas as pd
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Tuple
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, roc_auc_score, classification_report
)
import warnings
warnings.filterwarnings('ignore')

# Try to import xgboost
try:
    import xgboost as xgb
    XGBOOST_AVAILABLE = True
except ImportError:
    XGBOOST_AVAILABLE = False
    print("[ML] XGBoost not available, skipping XGBoost model")


class MLModelTrainer:
    """
    ML Model Training and Management System
    Supports multiple algorithms with training, evaluation, and versioning
    """

    def __init__(self, models_dir: str = None):
        self.models_dir = Path(models_dir) if models_dir else Path(__file__).parent / "models"
        self.models_dir.mkdir(exist_ok=True, parents=True)

        # Available model types
        self.model_types = {
            'random_forest': {
                'name': 'Random Forest',
                'class': RandomForestClassifier,
                'params': {
                    'n_estimators': 100,
                    'max_depth': 10,
                    'min_samples_split': 5,
                    'min_samples_leaf': 2,
                    'random_state': 42,
                    'n_jobs': -1
                }
            },
            'gradient_boosting': {
                'name': 'Gradient Boosting',
                'class': GradientBoostingClassifier,
                'params': {
                    'n_estimators': 100,
                    'learning_rate': 0.1,
                    'max_depth': 5,
                    'random_state': 42
                }
            },
            'neural_network': {
                'name': 'Neural Network (MLP)',
                'class': MLPClassifier,
                'params': {
                    'hidden_layer_sizes': (100, 50, 25),
                    'activation': 'relu',
                    'solver': 'adam',
                    'max_iter': 500,
                    'random_state': 42,
                    'early_stopping': True
                }
            }
        }

        if XGBOOST_AVAILABLE:
            self.model_types['xgboost'] = {
                'name': 'XGBoost',
                'class': xgb.XGBClassifier,
                'params': {
                    'n_estimators': 100,
                    'learning_rate': 0.1,
                    'max_depth': 5,
                    'random_state': 42,
                    'use_label_encoder': False,
                    'eval_metric': 'logloss'
                }
            }

        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()

    def prepare_training_data(
        self,
        events_data: pd.DataFrame
    ) -> Tuple[np.ndarray, np.ndarray, List[str]]:
        """
        Prepare training data from auth events

        Returns:
            X: Feature matrix
            y: Labels (0=benign, 1=malicious)
            feature_names: List of feature names
        """
        df = events_data.copy()

        # Feature engineering
        features = []
        feature_names = []

        # 1. Event type encoding (failed=1, successful=0)
        if 'event_type' in df.columns:
            features.append(df['event_type'].map({'failed': 1, 'successful': 0}).values.reshape(-1, 1))
            feature_names.append('event_type_encoded')

        # 2. AbuseIPDB score (normalized)
        if 'abuseipdb_score' in df.columns:
            abuse_scores = df['abuseipdb_score'].fillna(0).values.reshape(-1, 1) / 100.0
            features.append(abuse_scores)
            feature_names.append('abuseipdb_score_norm')

        # 3. VirusTotal positives (normalized)
        if 'virustotal_positives' in df.columns:
            vt_scores = df['virustotal_positives'].fillna(0).values.reshape(-1, 1) / 68.0
            features.append(vt_scores)
            feature_names.append('virustotal_score_norm')

        # 4. Geographic features
        if 'is_tor' in df.columns:
            features.append(df['is_tor'].fillna(0).astype(int).values.reshape(-1, 1))
            feature_names.append('is_tor')

        if 'is_proxy' in df.columns:
            features.append(df['is_proxy'].fillna(0).astype(int).values.reshape(-1, 1))
            feature_names.append('is_proxy')

        if 'is_vpn' in df.columns:
            features.append(df['is_vpn'].fillna(0).astype(int).values.reshape(-1, 1))
            feature_names.append('is_vpn')

        if 'is_datacenter' in df.columns:
            features.append(df['is_datacenter'].fillna(0).astype(int).values.reshape(-1, 1))
            feature_names.append('is_datacenter')

        # 5. Country risk (high-risk countries encoded)
        if 'country_code' in df.columns:
            high_risk_countries = ['CN', 'RU', 'KP', 'IR', 'BY']
            country_risk = df['country_code'].apply(
                lambda x: 1 if x in high_risk_countries else 0
            ).values.reshape(-1, 1)
            features.append(country_risk)
            feature_names.append('country_risk')

        # 6. Time-based features (hour of day)
        if 'timestamp' in df.columns:
            df['hour'] = pd.to_datetime(df['timestamp']).dt.hour
            # Encode as sin/cos for cyclical nature
            hour_sin = np.sin(2 * np.pi * df['hour'] / 24).values.reshape(-1, 1)
            hour_cos = np.cos(2 * np.pi * df['hour'] / 24).values.reshape(-1, 1)
            features.append(hour_sin)
            features.append(hour_cos)
            feature_names.extend(['hour_sin', 'hour_cos'])

        # 7. Username risk (common targets)
        if 'target_username' in df.columns:
            high_value_users = ['root', 'admin', 'administrator', 'ubuntu', 'ec2-user', 'test']
            username_risk = df['target_username'].apply(
                lambda x: 1 if x in high_value_users else 0
            ).values.reshape(-1, 1)
            features.append(username_risk)
            feature_names.append('username_risk')

        # 8. Port number (non-standard SSH ports)
        if 'target_port' in df.columns:
            port_risk = df['target_port'].apply(
                lambda x: 0 if x == 22 else 1
            ).values.reshape(-1, 1)
            features.append(port_risk)
            feature_names.append('non_standard_port')

        # Combine all features
        X = np.hstack(features)

        # Create labels based on threat indicators
        # Malicious if: failed login + (high abuse score OR anomaly OR threat intel positive)
        y = np.zeros(len(df))

        if 'is_anomaly' in df.columns:
            y = np.where(df['is_anomaly'] == 1, 1, y)

        if 'overall_threat_level' in df.columns:
            y = np.where(df['overall_threat_level'].isin(['high', 'critical']), 1, y)

        if 'abuseipdb_score' in df.columns:
            y = np.where((df['event_type'] == 'failed') & (df['abuseipdb_score'] > 50), 1, y)

        return X, y, feature_names

    def train_model(
        self,
        model_type: str,
        X_train: np.ndarray,
        y_train: np.ndarray,
        X_test: np.ndarray,
        y_test: np.ndarray,
        feature_names: List[str],
        model_params: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """
        Train a specific model type

        Returns:
            Dictionary with model, metrics, and metadata
        """
        if model_type not in self.model_types:
            raise ValueError(f"Unknown model type: {model_type}")

        model_config = self.model_types[model_type]
        params = model_params if model_params else model_config['params']

        print(f"[ML] Training {model_config['name']}...")

        # Initialize model
        model = model_config['class'](**params)

        # Scale features
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)

        # Train
        start_time = datetime.now()
        model.fit(X_train_scaled, y_train)
        training_time = (datetime.now() - start_time).total_seconds()

        # Predictions
        y_pred_train = model.predict(X_train_scaled)
        y_pred_test = model.predict(X_test_scaled)

        # Probabilities for ROC-AUC
        try:
            y_pred_proba_train = model.predict_proba(X_train_scaled)[:, 1]
            y_pred_proba_test = model.predict_proba(X_test_scaled)[:, 1]
        except:
            y_pred_proba_train = y_pred_train
            y_pred_proba_test = y_pred_test

        # Calculate metrics
        metrics = {
            'train': {
                'accuracy': float(accuracy_score(y_train, y_pred_train)),
                'precision': float(precision_score(y_train, y_pred_train, zero_division=0)),
                'recall': float(recall_score(y_train, y_pred_train, zero_division=0)),
                'f1': float(f1_score(y_train, y_pred_train, zero_division=0)),
                'roc_auc': float(roc_auc_score(y_train, y_pred_proba_train))
            },
            'test': {
                'accuracy': float(accuracy_score(y_test, y_pred_test)),
                'precision': float(precision_score(y_test, y_pred_test, zero_division=0)),
                'recall': float(recall_score(y_test, y_pred_test, zero_division=0)),
                'f1': float(f1_score(y_test, y_pred_test, zero_division=0)),
                'roc_auc': float(roc_auc_score(y_test, y_pred_proba_test))
            }
        }

        # Confusion matrix
        cm_test = confusion_matrix(y_test, y_pred_test)

        # Feature importance (if available)
        feature_importance = None
        if hasattr(model, 'feature_importances_'):
            importance = model.feature_importances_
            feature_importance = [
                {'feature': name, 'importance': float(imp)}
                for name, imp in sorted(zip(feature_names, importance), key=lambda x: x[1], reverse=True)
            ]

        # Cross-validation score
        cv_scores = cross_val_score(model, X_train_scaled, y_train, cv=5)

        result = {
            'model': model,
            'scaler': self.scaler,
            'model_type': model_type,
            'model_name': model_config['name'],
            'params': params,
            'metrics': metrics,
            'confusion_matrix': cm_test.tolist(),
            'feature_names': feature_names,
            'feature_importance': feature_importance,
            'training_time': training_time,
            'cross_val_scores': cv_scores.tolist(),
            'cross_val_mean': float(cv_scores.mean()),
            'cross_val_std': float(cv_scores.std()),
            'trained_at': datetime.now().isoformat(),
            'train_samples': int(len(y_train)),
            'test_samples': int(len(y_test))
        }

        print(f"[ML] ✓ {model_config['name']} trained successfully")
        print(f"[ML]   Test Accuracy: {metrics['test']['accuracy']:.3f}")
        print(f"[ML]   Test F1: {metrics['test']['f1']:.3f}")
        print(f"[ML]   Training time: {training_time:.2f}s")

        return result

    def save_model(self, model_result: Dict[str, Any], version: str = None) -> str:
        """Save trained model to disk"""
        if not version:
            version = datetime.now().strftime("%Y%m%d_%H%M%S")

        model_type = model_result['model_type']
        filename = f"{model_type}_v{version}.pkl"
        filepath = self.models_dir / filename

        # Save model and scaler
        save_data = {
            'model': model_result['model'],
            'scaler': model_result['scaler'],
            'model_type': model_type,
            'model_name': model_result['model_name'],
            'params': model_result['params'],
            'metrics': model_result['metrics'],
            'feature_names': model_result['feature_names'],
            'feature_importance': model_result['feature_importance'],
            'trained_at': model_result['trained_at'],
            'version': version
        }

        joblib.dump(save_data, filepath)

        # Save metadata separately
        metadata = {
            'model_type': model_type,
            'model_name': model_result['model_name'],
            'version': version,
            'filename': filename,
            'metrics': model_result['metrics'],
            'training_time': model_result['training_time'],
            'cross_val_mean': model_result['cross_val_mean'],
            'trained_at': model_result['trained_at'],
            'train_samples': model_result['train_samples'],
            'test_samples': model_result['test_samples']
        }

        metadata_file = self.models_dir / f"{model_type}_v{version}_metadata.json"
        with open(metadata_file, 'w') as f:
            json.dump(metadata, f, indent=2)

        print(f"[ML] Model saved: {filepath}")
        return str(filepath)

    def load_model(self, filepath: str) -> Dict[str, Any]:
        """Load a trained model from disk"""
        return joblib.load(filepath)

    def list_models(self) -> List[Dict[str, Any]]:
        """List all saved models"""
        models = []
        for metadata_file in self.models_dir.glob("*_metadata.json"):
            with open(metadata_file, 'r') as f:
                metadata = json.load(f)
                models.append(metadata)

        return sorted(models, key=lambda x: x['trained_at'], reverse=True)

    def predict(self, model_data: Dict[str, Any], X: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """
        Make predictions with a loaded model

        Returns:
            predictions: Binary predictions (0/1)
            probabilities: Probability scores
        """
        model = model_data['model']
        scaler = model_data['scaler']

        X_scaled = scaler.transform(X)
        predictions = model.predict(X_scaled)

        try:
            probabilities = model.predict_proba(X_scaled)[:, 1]
        except:
            probabilities = predictions.astype(float)

        return predictions, probabilities

    def compare_models(self, model_results: List[Dict[str, Any]]) -> pd.DataFrame:
        """Compare multiple trained models"""
        comparison = []

        for result in model_results:
            comparison.append({
                'Model': result['model_name'],
                'Type': result['model_type'],
                'Test Accuracy': result['metrics']['test']['accuracy'],
                'Test Precision': result['metrics']['test']['precision'],
                'Test Recall': result['metrics']['test']['recall'],
                'Test F1': result['metrics']['test']['f1'],
                'Test ROC-AUC': result['metrics']['test']['roc_auc'],
                'CV Mean': result['cross_val_mean'],
                'CV Std': result['cross_val_std'],
                'Training Time (s)': result['training_time'],
                'Trained At': result['trained_at']
            })

        return pd.DataFrame(comparison)


# Singleton instance
_trainer = None

def get_trainer() -> MLModelTrainer:
    """Get ML trainer singleton"""
    global _trainer
    if _trainer is None:
        _trainer = MLModelTrainer()
    return _trainer
