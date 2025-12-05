-- ============================================================================
-- SSH Guardian v3.0 - ML Training & Prediction Tables
-- Version: 3.0.0
-- Date: 2025-12-05
-- Purpose: Database tables for ML model management, training, and predictions
-- ============================================================================

SET FOREIGN_KEY_CHECKS = 0;

-- ============================================================================
-- ML MODEL MANAGEMENT
-- ============================================================================

-- ----------------------------------------------------------------------------
-- ML Models (Production & Candidate Models)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ml_models (
    id INT AUTO_INCREMENT PRIMARY KEY,
    model_uuid CHAR(36) NOT NULL UNIQUE,
    model_name VARCHAR(100) NOT NULL,
    algorithm ENUM('random_forest', 'gradient_boosting', 'xgboost',
                   'isolation_forest', 'ensemble') NOT NULL,
    version VARCHAR(50) NOT NULL,

    -- Status
    status ENUM('training', 'candidate', 'production', 'deprecated', 'failed') DEFAULT 'training',
    is_active BOOLEAN DEFAULT FALSE COMMENT 'Currently used for predictions',

    -- File Info
    model_path VARCHAR(500) NOT NULL,
    model_size_bytes BIGINT NULL,

    -- Training Configuration
    hyperparameters JSON NOT NULL COMMENT 'Model hyperparameters',
    feature_names JSON NOT NULL COMMENT 'List of feature names used',
    training_data_start DATE NOT NULL,
    training_data_end DATE NOT NULL,
    training_samples INT NOT NULL COMMENT 'Number of training samples',
    test_samples INT NOT NULL COMMENT 'Number of test samples (80/20 split)',

    -- Performance Metrics
    accuracy DECIMAL(5,4) NULL COMMENT '0.0000 to 1.0000',
    precision_score DECIMAL(5,4) NULL,
    recall_score DECIMAL(5,4) NULL,
    f1_score DECIMAL(5,4) NULL,
    roc_auc DECIMAL(5,4) NULL,
    confusion_matrix JSON NULL COMMENT '[[TN, FP], [FN, TP]]',

    -- Feature Importance
    feature_importance JSON NULL COMMENT 'Feature name to importance mapping',

    -- Production Stats
    predictions_made BIGINT DEFAULT 0,
    avg_inference_time_ms DECIMAL(10,4) NULL,
    last_prediction_at TIMESTAMP NULL,

    -- Timestamps
    training_started_at TIMESTAMP NULL,
    training_completed_at TIMESTAMP NULL,
    promoted_to_production_at TIMESTAMP NULL,
    deprecated_at TIMESTAMP NULL,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    created_by_user_id INT NULL,

    KEY idx_algorithm (algorithm),
    KEY idx_status (status),
    KEY idx_is_active (is_active),
    KEY idx_created_at (created_at),
    KEY idx_f1_score (f1_score),

    FOREIGN KEY (created_by_user_id) REFERENCES users(id) ON DELETE SET NULL

) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
COMMENT='ML models registry with performance metrics';

-- ----------------------------------------------------------------------------
-- ML Training Runs (Training Job History)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ml_training_runs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    run_uuid CHAR(36) NOT NULL UNIQUE,

    -- Configuration
    algorithm ENUM('random_forest', 'gradient_boosting', 'xgboost',
                   'isolation_forest') NOT NULL,
    hyperparameters JSON NOT NULL COMMENT 'Training hyperparameters',

    -- Data Selection
    data_start_date DATE NOT NULL,
    data_end_date DATE NOT NULL,
    include_simulation_data BOOLEAN DEFAULT FALSE,
    total_samples INT NULL COMMENT 'Total data samples available',
    training_samples INT NULL COMMENT 'Samples used for training (80%)',
    test_samples INT NULL COMMENT 'Samples used for testing (20%)',

    -- Status
    status ENUM('pending', 'preparing_data', 'extracting_features', 'training',
                'evaluating', 'completed', 'failed', 'cancelled') DEFAULT 'pending',
    progress_percent TINYINT UNSIGNED DEFAULT 0,
    current_stage VARCHAR(100) NULL COMMENT 'Current processing stage',

    -- Results
    model_id INT NULL COMMENT 'FK to ml_models if training succeeded',
    training_log TEXT NULL COMMENT 'Detailed training log',
    error_message TEXT NULL,

    -- Timing
    started_at TIMESTAMP NULL,
    completed_at TIMESTAMP NULL,
    duration_seconds INT NULL,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_by_user_id INT NULL,

    KEY idx_status (status),
    KEY idx_algorithm (algorithm),
    KEY idx_created_at (created_at),

    FOREIGN KEY (model_id) REFERENCES ml_models(id) ON DELETE SET NULL,
    FOREIGN KEY (created_by_user_id) REFERENCES users(id) ON DELETE SET NULL

) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
COMMENT='ML training job history with progress tracking';

-- ----------------------------------------------------------------------------
-- ML Predictions (Prediction log for analysis)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ml_predictions (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,

    event_id BIGINT NOT NULL,
    model_id INT NOT NULL,

    -- Prediction Results
    risk_score TINYINT UNSIGNED NOT NULL COMMENT '0-100',
    threat_type VARCHAR(100) NULL COMMENT 'brute_force, credential_stuffing, etc.',
    confidence DECIMAL(5,4) NOT NULL COMMENT '0.0000-1.0000',
    is_anomaly BOOLEAN DEFAULT FALSE,

    -- Feature Snapshot (for debugging/analysis)
    features_snapshot JSON NULL,

    -- Performance
    inference_time_ms DECIMAL(10,4) NULL,

    -- Outcome (for accuracy tracking)
    was_blocked BOOLEAN DEFAULT FALSE,
    block_id INT NULL COMMENT 'FK to ip_blocks if blocked',

    -- Manual Feedback (for model improvement)
    manual_feedback ENUM('correct', 'false_positive', 'false_negative') NULL,
    feedback_at TIMESTAMP NULL,
    feedback_by_user_id INT NULL,
    feedback_notes TEXT NULL,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    KEY idx_event (event_id),
    KEY idx_model (model_id),
    KEY idx_risk_score (risk_score),
    KEY idx_is_anomaly (is_anomaly),
    KEY idx_created_at (created_at),
    KEY idx_feedback (manual_feedback),
    KEY idx_threat_type (threat_type),

    FOREIGN KEY (event_id) REFERENCES auth_events(id) ON DELETE CASCADE,
    FOREIGN KEY (model_id) REFERENCES ml_models(id) ON DELETE CASCADE,
    FOREIGN KEY (block_id) REFERENCES ip_blocks(id) ON DELETE SET NULL,
    FOREIGN KEY (feedback_by_user_id) REFERENCES users(id) ON DELETE SET NULL

) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
COMMENT='ML prediction log for accuracy tracking and analysis';

-- ----------------------------------------------------------------------------
-- ML Feature Statistics (For normalization & drift detection)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ml_feature_stats (
    id INT AUTO_INCREMENT PRIMARY KEY,

    model_id INT NOT NULL,
    feature_name VARCHAR(100) NOT NULL,

    -- Statistics at training time
    mean_value DECIMAL(15,6) NULL,
    std_value DECIMAL(15,6) NULL,
    min_value DECIMAL(15,6) NULL,
    max_value DECIMAL(15,6) NULL,
    median_value DECIMAL(15,6) NULL,
    percentile_25 DECIMAL(15,6) NULL,
    percentile_75 DECIMAL(15,6) NULL,

    -- Current statistics (for drift detection)
    current_mean DECIMAL(15,6) NULL,
    current_std DECIMAL(15,6) NULL,
    drift_score DECIMAL(5,4) NULL COMMENT 'Drift from training distribution',
    samples_since_training BIGINT DEFAULT 0,

    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    UNIQUE KEY idx_model_feature (model_id, feature_name),

    FOREIGN KEY (model_id) REFERENCES ml_models(id) ON DELETE CASCADE

) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
COMMENT='Feature statistics for normalization and drift detection';

-- ----------------------------------------------------------------------------
-- ML Comparison Stats (Rule-based vs ML-based detection stats)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ml_comparison_stats (
    id INT AUTO_INCREMENT PRIMARY KEY,

    stat_date DATE NOT NULL,

    -- Rule-based Detection (like fail2ban)
    rule_true_positives INT DEFAULT 0 COMMENT 'Threats correctly blocked by rules',
    rule_false_positives INT DEFAULT 0 COMMENT 'Legit users blocked by rules',
    rule_false_negatives INT DEFAULT 0 COMMENT 'Threats missed by rules',
    rule_blocks_total INT DEFAULT 0,
    rule_avg_attempts_before_block DECIMAL(10,2) NULL,

    -- ML-based Detection
    ml_true_positives INT DEFAULT 0 COMMENT 'Threats correctly flagged by ML',
    ml_false_positives INT DEFAULT 0 COMMENT 'Legit users flagged by ML',
    ml_false_negatives INT DEFAULT 0 COMMENT 'Threats missed by ML',
    ml_blocks_total INT DEFAULT 0,
    ml_first_attempt_detections INT DEFAULT 0 COMMENT 'Threats caught on first attempt',

    -- Combined Stats
    total_events INT DEFAULT 0,
    total_threats INT DEFAULT 0,
    total_blocks INT DEFAULT 0,

    -- Calculated Metrics (can be computed)
    rule_precision DECIMAL(5,4) NULL,
    rule_recall DECIMAL(5,4) NULL,
    ml_precision DECIMAL(5,4) NULL,
    ml_recall DECIMAL(5,4) NULL,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    UNIQUE KEY idx_stat_date (stat_date),
    KEY idx_created_at (created_at)

) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
COMMENT='Daily statistics comparing rule-based vs ML-based detection';

-- ----------------------------------------------------------------------------
-- ML Detection Cases (Example cases for benefits report)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ml_detection_cases (
    id INT AUTO_INCREMENT PRIMARY KEY,

    case_uuid CHAR(36) NOT NULL UNIQUE,
    case_type ENUM('ml_only_detection', 'early_detection', 'false_positive_prevention',
                   'distributed_attack', 'slow_attack', 'geographic_anomaly') NOT NULL,

    -- Case Details
    title VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,

    -- Related Data
    ip_addresses JSON NULL COMMENT 'IPs involved',
    event_ids JSON NULL COMMENT 'Related event IDs',
    block_id INT NULL,

    -- Metrics
    events_in_case INT DEFAULT 0,
    time_to_detection_seconds INT NULL,
    rule_would_have_detected BOOLEAN DEFAULT FALSE,
    rule_detection_delay_seconds INT NULL COMMENT 'How much later rules would detect',

    -- Visibility
    is_featured BOOLEAN DEFAULT FALSE COMMENT 'Show in benefits report',
    is_verified BOOLEAN DEFAULT FALSE COMMENT 'Manually verified case',

    detected_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    verified_by_user_id INT NULL,

    KEY idx_case_type (case_type),
    KEY idx_is_featured (is_featured),
    KEY idx_detected_at (detected_at),

    FOREIGN KEY (block_id) REFERENCES ip_blocks(id) ON DELETE SET NULL,
    FOREIGN KEY (verified_by_user_id) REFERENCES users(id) ON DELETE SET NULL

) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
COMMENT='Notable ML detection cases for benefits reporting';

-- ============================================================================
-- UPDATE EXISTING TABLES
-- ============================================================================

-- Add ml_prediction_id to ip_blocks for tracking ML-triggered blocks
ALTER TABLE ip_blocks
ADD COLUMN ml_prediction_id BIGINT NULL AFTER blocking_rule_id,
ADD KEY idx_ml_prediction (ml_prediction_id);

-- Note: Foreign key will be added after ml_predictions table exists
-- This is handled by the application layer

SET FOREIGN_KEY_CHECKS = 1;

-- ============================================================================
-- SCHEMA CREATION COMPLETE
-- ============================================================================
