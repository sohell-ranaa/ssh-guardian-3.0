"""
SSH Guardian v3.0 - Machine Learning Module
Provides ML-based threat detection and risk scoring
"""

from pathlib import Path

# Module version
__version__ = '1.0.0'

# Module root directory
ML_ROOT = Path(__file__).parent
MODELS_DIR = ML_ROOT / 'models' / 'production'

# Lazy imports for performance
_model_manager = None
_feature_extractor = None
_trainer = None


def get_model_manager():
    """
    Get or create the global ML Model Manager instance.

    Returns:
        MLModelManager instance
    """
    global _model_manager
    if _model_manager is None:
        from .model_manager import MLModelManager
        _model_manager = MLModelManager(MODELS_DIR)
    return _model_manager


def get_feature_extractor():
    """
    Get or create the global Feature Extractor instance.

    Returns:
        FeatureExtractor instance
    """
    global _feature_extractor
    if _feature_extractor is None:
        from .feature_extractor import FeatureExtractor
        _feature_extractor = FeatureExtractor()
    return _feature_extractor


def get_trainer():
    """
    Get or create the global ML Trainer instance.

    Returns:
        MLTrainer instance
    """
    global _trainer
    if _trainer is None:
        from .trainer import MLTrainer
        _trainer = MLTrainer(MODELS_DIR)
    return _trainer


def predict(event: dict) -> dict:
    """
    Convenience function for ML prediction.

    Args:
        event: Event data dict

    Returns:
        Prediction result with risk_score, threat_type, etc.
    """
    manager = get_model_manager()
    return manager.predict(event)


def extract_features(event: dict):
    """
    Convenience function for feature extraction.

    Args:
        event: Event data dict

    Returns:
        Feature array
    """
    extractor = get_feature_extractor()
    return extractor.extract(event)


# Export main classes
__all__ = [
    'get_model_manager',
    'get_feature_extractor',
    'get_trainer',
    'predict',
    'extract_features',
    'MODELS_DIR',
    'ML_ROOT'
]
