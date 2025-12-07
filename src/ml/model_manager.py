"""
SSH Guardian v3.0 - ML Model Manager
Loads, manages, and performs inference with trained ML models
"""

import os
import sys
import logging
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime
import numpy as np

# Add project paths
PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.append(str(PROJECT_ROOT / "dbs"))

from connection import get_connection
from .feature_extractor import FeatureExtractor
from .model_manager_queries import log_prediction_with_stats, get_active_model_info

logger = logging.getLogger(__name__)


class MLModelManager:
    """
    Manages ML models for SSH Guardian.
    Loads trained models, performs inference, and tracks predictions.
    """

    # Threat type classification thresholds
    THREAT_TYPES = {
        'brute_force': {'min_fails_10min': 0.1, 'min_fails_hour': 0.05},
        'credential_stuffing': {'min_unique_users': 0.1, 'max_fails_per_user': 0.5},
        'reconnaissance': {'is_invalid_user': 1, 'min_unique_users': 0.1},
        'distributed_attack': {'is_distributed': 1},
        'suspicious_access': {'is_high_risk': 1, 'is_night': 1},
        'anomaly': {'default': True}
    }

    def __init__(self, models_dir: Path):
        """
        Initialize ML Model Manager.

        Args:
            models_dir: Directory containing saved model files
        """
        self.models_dir = Path(models_dir)
        self.models = {}  # model_name -> model object
        self.scalers = {}  # model_name -> scaler object
        self.model_info = {}  # model_name -> metadata
        self.feature_extractor = FeatureExtractor()
        self.active_model_id = None

        # Load all available models
        self._load_models()

    def _load_models(self):
        """Load all trained models from disk"""
        logger.info("Loading ML models...")

        if not self.models_dir.exists():
            logger.warning(f"Models directory not found: {self.models_dir}")
            self.models_dir.mkdir(parents=True, exist_ok=True)
            return

        # Try to load joblib models
        try:
            import joblib
        except ImportError:
            logger.error("joblib not installed. ML models unavailable.")
            return

        # Look for model files
        model_patterns = ['*.pkl', '*.joblib']
        model_files = []
        for pattern in model_patterns:
            model_files.extend(list(self.models_dir.glob(pattern)))

        if not model_files:
            logger.warning("No model files found in production directory")
            return

        # Load each model
        for model_path in model_files:
            try:
                model_name = model_path.stem
                logger.info(f"  Loading {model_name}...")

                model_data = joblib.load(model_path)

                # Handle different model formats
                if isinstance(model_data, dict):
                    self.models[model_name] = model_data.get('model')
                    self.scalers[model_name] = model_data.get('scaler')
                    self.model_info[model_name] = {
                        'path': str(model_path),
                        'feature_names': model_data.get('feature_names', []),
                        'metrics': model_data.get('metrics', {}),
                        'loaded_at': datetime.now()
                    }
                else:
                    # Just the model object
                    self.models[model_name] = model_data
                    self.model_info[model_name] = {
                        'path': str(model_path),
                        'loaded_at': datetime.now()
                    }

                logger.info(f"  ✓ {model_name} loaded successfully")

            except Exception as e:
                logger.error(f"  ✗ Failed to load {model_path}: {e}")

        if self.models:
            logger.info(f"Loaded {len(self.models)} ML model(s)")
            # Get active model from database
            self._load_active_model_from_db()
        else:
            logger.warning("No ML models loaded. ML predictions unavailable.")

    def _load_active_model_from_db(self):
        """Load active model info from database"""
        try:
            conn = get_connection()
            active_model = get_active_model_info(conn)

            if active_model:
                self.active_model_id = active_model['id']
                logger.info(f"Active model from DB: {active_model['model_name']} (ID: {active_model['id']})")

            conn.close()
        except Exception as e:
            logger.debug(f"Could not load active model from DB: {e}")

    def predict(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform ML prediction on an event.

        Args:
            event: Event dict with fields like timestamp, source_ip_text, event_type, etc.

        Returns:
            Prediction result dict with keys:
            - ml_available: bool
            - risk_score: int (0-100)
            - threat_type: str
            - confidence: float (0.0-1.0)
            - is_anomaly: bool
            - model_used: str
        """
        if not self.models:
            return self._fallback_prediction(event)

        try:
            # Extract features
            features = self.feature_extractor.extract(event)
            features = features.reshape(1, -1)

            # Use ensemble prediction for best accuracy
            return self.ensemble_predict(event, features)

        except Exception as e:
            logger.error(f"ML prediction error: {e}", exc_info=True)
            return {
                'ml_available': False,
                'risk_score': 0,
                'threat_type': None,
                'confidence': 0.0,
                'is_anomaly': False,
                'model_used': 'error',
                'error': str(e)
            }

    def ensemble_predict(self, event: Dict, features: np.ndarray) -> Dict[str, Any]:
        """
        Use ensemble of all models for prediction.
        Combines predictions using weighted voting based on model performance.

        Args:
            event: Original event dict
            features: Pre-extracted feature array

        Returns:
            Ensemble prediction result
        """
        predictions = []
        probabilities = []
        model_weights = []

        for model_name, model in self.models.items():
            try:
                # Scale features if scaler available
                scaled_features = features
                if model_name in self.scalers and self.scalers[model_name] is not None:
                    scaled_features = self.scalers[model_name].transform(features)

                # Get prediction
                pred = model.predict(scaled_features)[0]
                predictions.append(pred)

                # Get probability if available
                if hasattr(model, 'predict_proba'):
                    proba = model.predict_proba(scaled_features)[0]
                    if len(proba) > 1:
                        probabilities.append(proba[1])  # Probability of positive class
                    else:
                        probabilities.append(float(pred))
                elif hasattr(model, 'decision_function'):
                    # For SVM-like models
                    decision = model.decision_function(scaled_features)[0]
                    prob = 1 / (1 + np.exp(-decision))  # Sigmoid
                    probabilities.append(prob)
                else:
                    probabilities.append(float(pred))

                # Model weight (default 1.0, or use F1 from info)
                weight = 1.0
                if model_name in self.model_info:
                    metrics = self.model_info[model_name].get('metrics', {})
                    if 'f1_score' in metrics:
                        weight = metrics['f1_score']
                model_weights.append(weight)

            except Exception as e:
                logger.debug(f"Model {model_name} prediction failed: {e}")
                continue

        if not predictions:
            return self._fallback_prediction(event)

        # Weighted ensemble
        weights = np.array(model_weights)
        weights = weights / weights.sum()  # Normalize

        # Weighted average for probability/risk score
        if probabilities:
            ensemble_probability = np.average(probabilities, weights=weights)
            risk_score = int(min(100, max(0, ensemble_probability * 100)))
        else:
            risk_score = int(np.average(predictions, weights=weights) * 100)

        # Majority vote for is_anomaly
        ensemble_prediction = int(np.round(np.average(predictions, weights=weights)))
        is_anomaly = ensemble_prediction == 1

        # Calculate confidence (based on agreement)
        if len(predictions) > 1:
            agreement = np.mean([1 if p == ensemble_prediction else 0 for p in predictions])
            confidence = agreement
        else:
            confidence = probabilities[0] if probabilities else 0.7

        # Determine threat type
        threat_type = self._classify_threat_type(event, features, risk_score, is_anomaly)

        # =============================================================
        # THREAT INTEL OVERRIDE - Known malicious IPs override ML
        # This ensures external threat intelligence is respected even
        # when ML model outputs lower scores due to feature dilution
        # UPDATED: More aggressive thresholds per user configuration
        # =============================================================
        threat_data = event.get('threat', {}) or {}
        geo_data = event.get('geo', {}) or {}
        abuseipdb_score = float(threat_data.get('abuseipdb_score') or 0)
        threat_level = str(threat_data.get('overall_threat_level', '') or '').lower()

        # VPN/Proxy/Datacenter detection - add +15 risk (aggressive)
        is_vpn = geo_data.get('is_vpn', False)
        is_proxy = geo_data.get('is_proxy', False)
        is_datacenter = geo_data.get('is_datacenter', False)
        if is_vpn or is_proxy or is_datacenter:
            risk_score = min(100, risk_score + 15)

        # Critical AbuseIPDB score (>=90) = ALWAYS BLOCK, minimum risk 90
        if abuseipdb_score >= 90:
            risk_score = max(risk_score, 90 + int((abuseipdb_score - 90) * 0.5))
            is_anomaly = True
            threat_type = threat_type or 'critical_abuse_score'
            confidence = max(confidence, 0.95)

        # High AbuseIPDB score (>=70) = minimum risk 70, force anomaly (lowered from 80)
        elif abuseipdb_score >= 70:
            risk_score = max(risk_score, 70 + int((abuseipdb_score - 70) * 0.5))
            is_anomaly = True
            threat_type = threat_type or 'known_malicious'
            confidence = max(confidence, 0.85)

        # Medium AbuseIPDB (50-70) = minimum risk 50
        elif abuseipdb_score >= 50:
            risk_score = max(risk_score, 50 + int((abuseipdb_score - 50) * 0.5))

        # Low-medium AbuseIPDB (25-50) = add partial risk
        elif abuseipdb_score >= 25:
            risk_score = min(100, risk_score + int(abuseipdb_score * 0.4))

        # Critical/High threat level override
        if threat_level == 'critical':
            risk_score = max(risk_score, 95)
            is_anomaly = True
            threat_type = threat_type or 'critical_threat'
            confidence = max(confidence, 0.95)
        elif threat_level == 'high':
            risk_score = max(risk_score, 75)
            is_anomaly = True
        elif threat_level == 'medium' and risk_score < 50:
            risk_score = max(risk_score, 50)
        # =============================================================

        # Log prediction to database
        self._log_prediction(event, risk_score, threat_type, confidence, is_anomaly)

        return {
            'ml_available': True,
            'risk_score': risk_score,
            'threat_type': threat_type,
            'confidence': round(confidence, 4),
            'is_anomaly': is_anomaly,
            'model_used': f'ensemble_{len(predictions)}_models',
            'predictions_count': len(predictions)
        }

    def _classify_threat_type(self, event: Dict, features: np.ndarray,
                             risk_score: int, is_anomaly: bool) -> Optional[str]:
        """
        Classify the threat type based on features and prediction.

        Args:
            event: Original event
            features: Feature array
            risk_score: ML risk score
            is_anomaly: Whether classified as anomaly

        Returns:
            Threat type string or None
        """
        if risk_score < 30 and not is_anomaly:
            return None  # Not a threat

        # Get feature names for indexing
        feature_names = self.feature_extractor.get_feature_names()

        def get_feature(name: str) -> float:
            try:
                idx = feature_names.index(name)
                return float(features[0, idx])
            except (ValueError, IndexError):
                return 0.0

        # Check patterns
        fails_10min = get_feature('fails_last_10min')
        fails_hour = get_feature('fails_last_hour')
        unique_users = get_feature('unique_users_tried')
        is_invalid_user = get_feature('is_invalid_user')
        is_distributed = get_feature('is_distributed_attack')
        is_high_risk = get_feature('is_high_risk_country')
        is_night = get_feature('is_night')

        # Brute force: rapid failures from same IP
        if fails_10min > 0.1 and fails_hour > 0.05:
            return 'brute_force'

        # Credential stuffing: many different usernames
        if unique_users > 0.1 and fails_hour > 0.05:
            return 'credential_stuffing'

        # Reconnaissance: invalid user probing
        if is_invalid_user > 0.5 and unique_users > 0.1:
            return 'reconnaissance'

        # Distributed attack
        if is_distributed > 0.5:
            return 'distributed_attack'

        # Suspicious access: high risk country + night
        if is_high_risk > 0.5 and is_night > 0.5:
            return 'suspicious_access'

        # Generic anomaly
        if is_anomaly:
            return 'anomaly'

        return None

    def _fallback_prediction(self, event: Dict) -> Dict[str, Any]:
        """
        Heuristic-based prediction when ML models unavailable.
        UPDATED: More aggressive thresholds per user configuration.

        Args:
            event: Event dict

        Returns:
            Basic risk assessment
        """
        risk_score = 0
        threat_type = None

        # Simple heuristics
        event_type = str(event.get('event_type', '')).lower()
        username = str(event.get('target_username', '')).lower()

        # Failed login baseline
        if 'failed' in event_type:
            risk_score += 25

        # Root/admin attempts
        if username in ('root', 'admin', 'administrator'):
            risk_score += 35

        # Invalid user
        if event.get('failure_reason') == 'invalid_user':
            risk_score += 25

        # Geographic risk - more aggressive for high-risk countries
        geo = event.get('geo', {}) or {}
        country_code = geo.get('country_code')
        if country_code in self.feature_extractor.HIGH_RISK_COUNTRIES:
            risk_score += 25  # Increased from 20

        # Proxy/VPN/Tor - more aggressive
        if geo.get('is_tor'):
            risk_score += 25  # Tor is high risk
        elif geo.get('is_proxy') or geo.get('is_vpn') or geo.get('is_datacenter'):
            risk_score += 15

        # Threat intel - tiered approach
        threat = event.get('threat', {}) or {}
        abuse_score = int(threat.get('abuseipdb_score', 0) or 0)

        if abuse_score >= 90:
            # Critical - force high risk
            risk_score = max(risk_score, 90)
            threat_type = 'critical_abuse_score'
        elif abuse_score >= 70:
            risk_score = max(risk_score, 70)
            threat_type = 'known_malicious'
        elif abuse_score >= 50:
            risk_score = max(risk_score, 50 + (abuse_score - 50) // 2)
        elif abuse_score >= 25:
            risk_score += int(abuse_score * 0.4)

        risk_score = min(100, risk_score)
        is_anomaly = risk_score >= 50  # Lowered threshold

        if risk_score >= 70 and not threat_type:
            threat_type = 'high_risk'
        elif risk_score >= 50 and not threat_type:
            threat_type = 'suspicious_activity'

        return {
            'ml_available': False,
            'risk_score': risk_score,
            'threat_type': threat_type,
            'confidence': 0.6,  # Slightly higher confidence for improved heuristics
            'is_anomaly': is_anomaly,
            'model_used': 'heuristic'
        }

    def _log_prediction(self, event: Dict, risk_score: int, threat_type: Optional[str],
                       confidence: float, is_anomaly: bool):
        """Log prediction to database for tracking"""
        if not self.active_model_id:
            return

        try:
            event_id = event.get('id')
            if not event_id:
                return

            conn = get_connection()

            # Use optimized combined query (INSERT + UPDATE in single transaction)
            log_prediction_with_stats(
                conn=conn,
                event_id=event_id,
                model_id=self.active_model_id,
                risk_score=risk_score,
                threat_type=threat_type,
                confidence=confidence,
                is_anomaly=is_anomaly
            )

            conn.close()

        except Exception as e:
            logger.debug(f"Failed to log prediction: {e}")

    def get_model_info(self) -> Dict[str, Any]:
        """Get information about loaded models"""
        return {
            'models_loaded': len(self.models),
            'model_names': list(self.models.keys()),
            'active_model_id': self.active_model_id,
            'feature_count': len(self.feature_extractor.get_feature_names())
        }

    def reload_models(self):
        """Reload all models from disk"""
        self.models.clear()
        self.scalers.clear()
        self.model_info.clear()
        self._load_models()

    def set_active_model(self, model_id: int):
        """Set the active model by database ID"""
        self.active_model_id = model_id


# Convenience function
def create_model_manager(models_dir: Path) -> MLModelManager:
    """Factory function to create ML Model Manager"""
    return MLModelManager(models_dir)
