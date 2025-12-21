-- Migration 033: User Behavioral Profiles for ML Anomaly Detection
-- Extends the existing user_login_baselines table and adds new profile table

-- Create user_behavioral_profiles table for ML-learned patterns
CREATE TABLE IF NOT EXISTS user_behavioral_profiles (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,

    -- Learned patterns (auto-populated by ML)
    typical_hours JSON COMMENT 'Hour distribution: {"0": count, "1": count, ..., "23": count}',
    typical_days JSON COMMENT 'Day distribution: {"Mon": count, "Tue": count, ...}',
    known_ips JSON COMMENT 'Known IPs: {"ip": count, ...}',
    known_countries JSON COMMENT 'Known countries: {"US": count, "UK": count, ...}',
    known_cities JSON COMMENT 'Known cities: {"New York": count, ...}',

    -- Statistics for ML
    login_count INT DEFAULT 0,
    successful_count INT DEFAULT 0,
    failed_count INT DEFAULT 0,
    avg_session_gap_hours FLOAT DEFAULT NULL COMMENT 'Average hours between logins',
    last_login_at TIMESTAMP NULL,

    -- Model state
    last_trained_at TIMESTAMP NULL,
    model_version INT DEFAULT 1,
    confidence_score FLOAT DEFAULT 0.0 COMMENT 'Confidence in learned patterns (0-1)',

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    INDEX idx_username (username),
    INDEX idx_last_login (last_login_at),
    INDEX idx_login_count (login_count)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Note: The new user_behavioral_profiles table handles ML-based patterns
-- user_login_baselines table remains for backward compatibility
