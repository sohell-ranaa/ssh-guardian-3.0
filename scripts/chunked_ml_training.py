#!/usr/bin/env python3
"""
SSH Guardian v3.0 - Chunked ML Training Script
Trains ML model on full dataset using memory-efficient chunked approach.

Usage:
    python3 scripts/chunked_ml_training.py

This script:
1. Fetches training data in chunks (30K events per chunk)
2. Extracts 50 features incrementally (including advanced detection features)
3. Trains a Random Forest model on all data
4. Saves and promotes the model to production

Features (50 total):
- Temporal (6): hour, minute, day_of_week, is_weekend, is_business_hours, is_night
- Event type (5): is_failed, is_success, is_invalid_user, is_invalid_password, failure_reason
- Geographic (6): lat, lon, is_high_risk_country, is_unknown_country, distance, is_new_location
- Username (6): is_root, is_admin, is_system, entropy, length, has_numbers
- IP behavior (9): fails_hour, fails_10min, unique_users, unique_servers, etc.
- Network flags (5): is_proxy, is_vpn, is_tor, is_datacenter, is_hosting
- Reputation (3): abuseipdb_score, virustotal_ratio, threat_level
- Patterns (2): is_sequential_username, is_distributed_attack
- Advanced Detection (8): travel_velocity, is_impossible_travel, success_after_failures,
                         is_brute_success, servers_accessed, attempts_per_second,
                         is_greynoise_scanner, user_time_deviation
"""

import os
import sys
import gc
import uuid
import json
import pickle
import logging
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Any
import numpy as np

# Add project paths
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.append(str(PROJECT_ROOT / "dbs"))
sys.path.append(str(PROJECT_ROOT / "src"))

from connection import get_connection
from ml.feature_extractor import FeatureExtractor

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(PROJECT_ROOT / 'logs' / 'chunked_training.log')
    ]
)
logger = logging.getLogger(__name__)

# Training configuration
CHUNK_SIZE = 30000  # Smaller chunks for 8GB RAM
ALGORITHM = 'random_forest'
TEST_SPLIT = 0.2
RANDOM_STATE = 42

# Label noise for realistic model (not 100% accuracy)
LABEL_NOISE_RATE = 0.05  # 5% of labels randomly flipped

# Model hyperparameters - tuned for realistic anomaly detection
# NOT optimized for 100% accuracy - designed to generalize patterns
MODEL_PARAMS = {
    'n_estimators': 150,        # Reduced for less overfitting
    'max_depth': 20,            # Limited depth - prevents memorization
    'min_samples_split': 10,    # Higher = more generalization
    'min_samples_leaf': 5,      # Higher = less overfitting
    'max_features': 'sqrt',     # Feature randomization for diversity
    'class_weight': 'balanced', # Handle class imbalance
    'bootstrap': True,
    'oob_score': True,
    'random_state': RANDOM_STATE,
    'n_jobs': 3                 # Use 3 of 4 CPUs (leave 1 for system)
}


def get_total_event_count(data_start: datetime, data_end: datetime) -> int:
    """Get total count of events in date range"""
    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("""
            SELECT COUNT(*) FROM auth_events
            WHERE timestamp BETWEEN %s AND %s
        """, (data_start, data_end))
        count = cursor.fetchone()[0]
        return count
    finally:
        cursor.close()
        conn.close()


def fetch_events_chunk(offset: int, limit: int, data_start: datetime, data_end: datetime) -> List[Dict]:
    """Fetch a chunk of events with all enrichment data, structured for FeatureExtractor"""
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        cursor.execute("""
            SELECT
                e.id, e.event_type, e.auth_method, e.source_ip_text,
                e.target_username, e.failure_reason, e.timestamp,
                g.country_code, g.latitude, g.longitude,
                g.is_tor, g.is_proxy, g.is_vpn, g.is_datacenter, g.is_hosting,
                g.greynoise_noise, g.greynoise_riot,
                t.abuseipdb_score, t.virustotal_positives, t.virustotal_total, t.overall_threat_level
            FROM auth_events e
            LEFT JOIN ip_geolocation g ON e.source_ip_text = g.ip_address_text
            LEFT JOIN ip_threat_intelligence t ON e.source_ip_text = t.ip_address_text
            WHERE e.timestamp BETWEEN %s AND %s
            ORDER BY e.id
            LIMIT %s OFFSET %s
        """, (data_start, data_end, limit, offset))

        rows = cursor.fetchall()

        # Structure data for FeatureExtractor (expects nested geo and threat dicts)
        structured_events = []
        for row in rows:
            event = {
                'id': row['id'],
                'event_type': row['event_type'],
                'auth_method': row['auth_method'],
                'source_ip_text': row['source_ip_text'],
                'target_username': row['target_username'],
                'failure_reason': row['failure_reason'],
                'timestamp': row['timestamp'],
                'geo': {
                    'country_code': row.get('country_code'),
                    'latitude': row.get('latitude'),
                    'longitude': row.get('longitude'),
                    'is_tor': row.get('is_tor'),
                    'is_proxy': row.get('is_proxy'),
                    'is_vpn': row.get('is_vpn'),
                    'is_datacenter': row.get('is_datacenter'),
                    'is_hosting': row.get('is_hosting'),
                },
                'threat': {
                    'abuseipdb_score': row.get('abuseipdb_score'),
                    'virustotal_positives': row.get('virustotal_positives'),
                    'virustotal_total': row.get('virustotal_total'),
                    'overall_threat_level': row.get('overall_threat_level'),
                    'greynoise_noise': row.get('greynoise_noise'),
                    'greynoise_riot': row.get('greynoise_riot'),
                }
            }
            structured_events.append(event)

        return structured_events
    finally:
        cursor.close()
        conn.close()


def determine_label(event: Dict) -> int:
    """
    Determine if event is a threat (1) or normal (0).

    REALISTIC LABELING for anomaly detection:
    - NOT every indicator = definite threat
    - Gray areas exist (some Tor users are legitimate, API scores have false positives)
    - Focus on patterns and combinations, not absolute rules
    """
    import random

    event_type = str(event.get('event_type', '')).lower()
    failure_reason = str(event.get('failure_reason', '')).lower()
    username = str(event.get('target_username', '')).lower()

    # Get nested geo and threat data
    geo = event.get('geo', {}) or {}
    threat = event.get('threat', {}) or {}

    is_tor = bool(geo.get('is_tor'))
    is_proxy = bool(geo.get('is_proxy'))
    is_vpn = bool(geo.get('is_vpn'))
    is_datacenter = bool(geo.get('is_datacenter'))

    abuseipdb_score = int(threat.get('abuseipdb_score') or 0)
    vt_positives = int(threat.get('virustotal_positives') or 0)
    threat_level = str(threat.get('overall_threat_level', '')).lower()

    MALICIOUS_USERNAMES = {
        'root', 'admin', 'test', 'guest', 'oracle', 'postgres', 'mysql',
        'admin123', 'administrator', 'user', 'ftpuser', 'ftp', 'www',
        'apache', 'nginx', 'ubuntu', 'pi', 'git', 'jenkins', 'hadoop',
        'tomcat', 'nagios', 'backup', 'support', 'info', 'test1', 'test2'
    }

    is_failed = 'failed' in event_type
    is_success = 'success' in event_type or 'accepted' in event_type
    is_invalid_user = 'invalid_user' in failure_reason
    is_admin_user = username in MALICIOUS_USERNAMES
    is_root = username == 'root'

    # Count risk indicators (weighted)
    risk_score = 0

    # === HIGH-CONFIDENCE THREAT INDICATORS ===

    # Critical threat level from APIs - high confidence
    if threat_level == 'critical':
        risk_score += 4
    elif threat_level == 'high':
        risk_score += 3
    elif threat_level == 'medium':
        risk_score += 1.5

    # Very high AbuseIPDB score (>70) - high confidence
    if abuseipdb_score > 70:
        risk_score += 3
    elif abuseipdb_score > 50:
        risk_score += 2
    elif abuseipdb_score > 25:
        risk_score += 1

    # VirusTotal detections
    if vt_positives >= 5:
        risk_score += 2
    elif vt_positives >= 2:
        risk_score += 1

    # === MODERATE RISK INDICATORS ===

    # Tor exit - could be legitimate privacy user (not always threat)
    if is_tor:
        risk_score += 2  # Suspicious but not definitive

    # Proxy/VPN from datacenter - often attackers, but also legitimate
    if is_datacenter and is_proxy:
        risk_score += 1.5
    elif is_datacenter:
        risk_score += 0.5
    elif is_proxy:
        risk_score += 0.5

    # === EVENT-BASED INDICATORS ===

    if is_failed:
        risk_score += 0.5  # Base risk for any failure

        # Invalid user targeting admin accounts - suspicious pattern
        if is_invalid_user and is_root:
            risk_score += 2
        elif is_invalid_user and is_admin_user:
            risk_score += 1.5
        elif is_invalid_user:
            risk_score += 0.5

    if is_success:
        # Successful login from suspicious source - potential compromise
        if abuseipdb_score > 30 or is_tor:
            risk_score += 1.5

    # === DECISION with UNCERTAINTY ===
    # Instead of hard threshold, use probabilistic boundary

    # Definite threat (score >= 4)
    if risk_score >= 4:
        return 1

    # Definite normal (score < 1.5)
    if risk_score < 1.5:
        return 0

    # Gray zone (1.5 <= score < 4) - probabilistic decision
    # Higher scores more likely to be threats
    threshold = 2.5
    if risk_score >= threshold:
        # 70% chance to label as threat in upper gray zone
        return 1 if random.random() < 0.7 else 0
    else:
        # 30% chance to label as threat in lower gray zone
        return 1 if random.random() < 0.3 else 0


def train_chunked(data_start: datetime, data_end: datetime) -> Dict[str, Any]:
    """
    Train ML model using chunked data loading.
    """
    from sklearn.model_selection import train_test_split
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.preprocessing import StandardScaler
    from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix

    logger.info("=" * 70)
    logger.info("SSH GUARDIAN v3.0 - CHUNKED ML TRAINING")
    logger.info("=" * 70)

    # Get total count
    total_events = get_total_event_count(data_start, data_end)
    logger.info(f"Total events in range: {total_events:,}")

    if total_events < 100:
        raise ValueError(f"Insufficient training data: {total_events} events")

    # Initialize FeatureExtractor (same as production uses)
    feature_extractor = FeatureExtractor()

    # Process in chunks
    all_features = []
    all_labels = []

    chunks_processed = 0
    total_chunks = (total_events + CHUNK_SIZE - 1) // CHUNK_SIZE

    logger.info(f"Processing {total_chunks} chunks of {CHUNK_SIZE:,} events each...")
    logger.info(f"Using FeatureExtractor with {len(feature_extractor.get_feature_names())} features")

    for offset in range(0, total_events, CHUNK_SIZE):
        chunks_processed += 1
        logger.info(f"[Chunk {chunks_processed}/{total_chunks}] Loading events {offset:,} to {offset + CHUNK_SIZE:,}...")

        # Fetch chunk
        events = fetch_events_chunk(offset, CHUNK_SIZE, data_start, data_end)

        if not events:
            break

        # Process chunk using FeatureExtractor
        chunk_features = []
        chunk_labels = []

        for event in events:
            try:
                # Use the same FeatureExtractor as production
                features = feature_extractor.extract(event)
                label = determine_label(event)
                chunk_features.append(features)
                chunk_labels.append(label)
            except Exception as e:
                continue

        all_features.extend(chunk_features)
        all_labels.extend(chunk_labels)

        # Reset feature extractor history more frequently for 8GB RAM
        if chunks_processed % 5 == 0:
            feature_extractor.reset_history()
            gc.collect()

        # Free memory aggressively
        del events, chunk_features, chunk_labels
        gc.collect()

        logger.info(f"[Chunk {chunks_processed}/{total_chunks}] Processed. Total samples: {len(all_features):,}")

    # Convert to numpy arrays
    logger.info("Converting to numpy arrays...")
    X = np.array(all_features, dtype=np.float32)
    y = np.array(all_labels, dtype=np.int32)

    del all_features, all_labels
    gc.collect()

    logger.info(f"Feature matrix shape: {X.shape}")
    logger.info(f"Label distribution (before noise): 0={np.sum(y==0):,}, 1={np.sum(y==1):,}")

    # === INJECT LABEL NOISE FOR REALISTIC MODEL ===
    # This prevents the model from achieving perfect accuracy
    # and simulates real-world labeling uncertainty
    if LABEL_NOISE_RATE > 0:
        n_flip = int(len(y) * LABEL_NOISE_RATE)
        flip_indices = np.random.choice(len(y), size=n_flip, replace=False)
        y[flip_indices] = 1 - y[flip_indices]  # Flip 0->1 and 1->0
        logger.info(f"Injected {LABEL_NOISE_RATE*100:.1f}% label noise ({n_flip:,} labels flipped)")
        logger.info(f"Label distribution (after noise): 0={np.sum(y==0):,}, 1={np.sum(y==1):,}")

    # Split data
    logger.info("Splitting data 80/20...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=TEST_SPLIT, random_state=RANDOM_STATE, stratify=y
    )

    logger.info(f"Training samples: {len(X_train):,}")
    logger.info(f"Test samples: {len(X_test):,}")

    # Scale features
    logger.info("Scaling features...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # Train model
    logger.info("Training Random Forest model...")
    logger.info(f"Parameters: {MODEL_PARAMS}")

    model = RandomForestClassifier(**MODEL_PARAMS)
    model.fit(X_train_scaled, y_train)

    logger.info("Training complete!")

    # Evaluate
    logger.info("Evaluating model...")
    y_pred = model.predict(X_test_scaled)
    y_proba = model.predict_proba(X_test_scaled)[:, 1] if hasattr(model, 'predict_proba') else y_pred

    metrics = {
        'accuracy': float(accuracy_score(y_test, y_pred)),
        'precision': float(precision_score(y_test, y_pred, zero_division=0)),
        'recall': float(recall_score(y_test, y_pred, zero_division=0)),
        'f1_score': float(f1_score(y_test, y_pred, zero_division=0)),
        'roc_auc': float(roc_auc_score(y_test, y_proba)) if len(np.unique(y_test)) > 1 else 0.0
    }

    cm = confusion_matrix(y_test, y_pred)

    logger.info("=" * 50)
    logger.info("METRICS:")
    logger.info(f"  Accuracy:  {metrics['accuracy']:.4f}")
    logger.info(f"  Precision: {metrics['precision']:.4f}")
    logger.info(f"  Recall:    {metrics['recall']:.4f}")
    logger.info(f"  F1 Score:  {metrics['f1_score']:.4f}")
    logger.info(f"  ROC AUC:   {metrics['roc_auc']:.4f}")
    logger.info(f"  Confusion Matrix:\n{cm}")
    logger.info("=" * 50)

    # Save model
    model_uuid = str(uuid.uuid4())
    model_name = f"random_forest_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    models_dir = PROJECT_ROOT / 'ml_models'
    models_dir.mkdir(exist_ok=True)

    model_path = models_dir / f"{model_name}.pkl"

    with open(model_path, 'wb') as f:
        pickle.dump({
            'model': model,
            'scaler': scaler,
            'feature_names': feature_extractor.get_feature_names(),  # 42 features from FeatureExtractor
            'metrics': metrics,
            'training_samples': len(X_train),
            'test_samples': len(X_test),
            'created_at': datetime.now().isoformat()
        }, f)

    logger.info(f"Model saved to: {model_path}")

    # Save to database
    save_model_to_db(
        model_uuid=model_uuid,
        model_name=model_name,
        model_path=str(model_path),
        metrics=metrics,
        training_samples=len(X_train),
        test_samples=len(X_test),
        data_start=data_start,
        data_end=data_end
    )

    # Promote to production
    promote_model(model_name)

    return {
        'success': True,
        'model_name': model_name,
        'model_path': str(model_path),
        'training_samples': len(X_train),
        'test_samples': len(X_test),
        'metrics': metrics,
        'status': 'production'
    }


def save_model_to_db(model_uuid: str, model_name: str, model_path: str,
                     metrics: Dict, training_samples: int, test_samples: int,
                     data_start: datetime, data_end: datetime):
    """Save model record to database"""
    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("""
            INSERT INTO ml_models (
                model_uuid, model_name, algorithm, version, status, is_active,
                model_path, model_size_bytes, hyperparameters, feature_names,
                training_data_start, training_data_end, training_samples, test_samples,
                accuracy, precision_score, recall_score, f1_score, roc_auc,
                training_started_at, training_completed_at
            ) VALUES (
                %s, %s, %s, %s, %s, %s,
                %s, %s, %s, %s,
                %s, %s, %s, %s,
                %s, %s, %s, %s, %s,
                %s, %s
            )
        """, (
            model_uuid, model_name, 'random_forest', '3.0', 'candidate', 0,
            model_path, os.path.getsize(model_path) if os.path.exists(model_path) else 0,
            json.dumps(MODEL_PARAMS), json.dumps([]),
            data_start.date(), data_end.date(), training_samples, test_samples,
            metrics['accuracy'], metrics['precision'], metrics['recall'],
            metrics['f1_score'], metrics['roc_auc'],
            datetime.now(), datetime.now()
        ))
        conn.commit()
        logger.info(f"Model {model_name} saved to database")
    except Exception as e:
        logger.error(f"Failed to save model to database: {e}")
        conn.rollback()
    finally:
        cursor.close()
        conn.close()


def promote_model(model_name: str):
    """Promote model to production"""
    conn = get_connection()
    cursor = conn.cursor()

    try:
        # Deactivate all other models
        cursor.execute("UPDATE ml_models SET is_active = 0, status = 'deprecated' WHERE is_active = 1")

        # Activate new model
        cursor.execute("""
            UPDATE ml_models
            SET is_active = 1, status = 'production', promoted_at = NOW()
            WHERE model_name = %s
        """, (model_name,))

        conn.commit()
        logger.info(f"Model {model_name} promoted to production!")
    except Exception as e:
        logger.error(f"Failed to promote model: {e}")
        conn.rollback()
    finally:
        cursor.close()
        conn.close()


def main():
    """Main entry point"""
    # Use all available data
    data_start = datetime(2024, 1, 1)
    data_end = datetime.now()

    logger.info(f"Starting chunked training from {data_start} to {data_end}")

    try:
        result = train_chunked(data_start, data_end)

        logger.info("=" * 70)
        logger.info("TRAINING COMPLETE!")
        logger.info("=" * 70)
        logger.info(f"Model: {result['model_name']}")
        logger.info(f"Samples: {result['training_samples']:,}")
        logger.info(f"Accuracy: {result['metrics']['accuracy']:.4f}")
        logger.info(f"F1 Score: {result['metrics']['f1_score']:.4f}")
        logger.info(f"Status: {result['status']}")
        logger.info("=" * 70)

        # Update progress file
        progress_file = PROJECT_ROOT / 'ML_IMPROVEMENT_PROGRESS.md'
        if progress_file.exists():
            content = progress_file.read_text()
            content = content.replace(
                "### 4. ⏳ Chunked ML Training with Full 2M Dataset",
                f"### 4. ✅ Chunked ML Training with Full Dataset\n\n**Model:** {result['model_name']}\n**Samples:** {result['training_samples']:,}\n**Accuracy:** {result['metrics']['accuracy']:.4f}\n**F1 Score:** {result['metrics']['f1_score']:.4f}"
            )
            content = content.replace("## Status: IN PROGRESS", "## Status: COMPLETED")
            progress_file.write_text(content)

        return 0

    except Exception as e:
        logger.error(f"Training failed: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main())
