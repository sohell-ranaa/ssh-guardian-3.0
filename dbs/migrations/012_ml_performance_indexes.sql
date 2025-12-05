-- Migration: 012_ml_performance_indexes
-- Description: Add composite indexes to optimize ML prediction queries and analytics
-- Date: 2025-12-05
--
-- Background:
-- - ml_predictions table currently has 122 records but will grow to millions
-- - auth_events has 2M+ records
-- - Missing composite indexes for common ML query patterns
--
-- This migration adds performance indexes without modifying existing data

-- ============================================================================
-- ML Predictions Performance Indexes
-- ============================================================================

-- Index for anomaly timeline queries
-- Purpose: Optimize queries that filter by date range and anomaly status
-- Example query: SELECT * FROM ml_predictions WHERE created_at BETWEEN ? AND ? AND is_anomaly = true
-- Performance: Enables efficient time-series anomaly detection queries
CREATE INDEX IF NOT EXISTS idx_ml_predictions_created_anomaly
ON ml_predictions(created_at DESC, is_anomaly);

-- Index for risk score timeline queries
-- Purpose: Optimize queries that analyze risk scores over time
-- Example query: SELECT * FROM ml_predictions WHERE created_at BETWEEN ? AND ? AND risk_score > ?
-- Performance: Enables efficient time-series risk analysis and trending
CREATE INDEX IF NOT EXISTS idx_ml_predictions_created_risk
ON ml_predictions(created_at DESC, risk_score DESC);

-- Index for threat type analysis queries
-- Purpose: Optimize queries that analyze specific threat types over time
-- Example query: SELECT * FROM ml_predictions WHERE created_at BETWEEN ? AND ? AND threat_type = ?
-- Performance: Enables efficient threat pattern analysis and categorization
CREATE INDEX IF NOT EXISTS idx_ml_predictions_created_threat
ON ml_predictions(created_at DESC, threat_type);

-- Index for model-specific performance queries
-- Purpose: Optimize queries that analyze predictions from specific ML models
-- Example query: SELECT * FROM ml_predictions WHERE model_id = ? AND created_at BETWEEN ? AND ?
-- Performance: Enables efficient model performance monitoring and comparison
CREATE INDEX IF NOT EXISTS idx_ml_predictions_model_created
ON ml_predictions(model_id, created_at DESC);

-- ============================================================================
-- Verification Indexes (Add if missing)
-- ============================================================================

-- Index for auth_events geo_id lookups
-- Purpose: Optimize queries that join auth_events with geo_locations
-- Note: This index should already exist, but we verify with IF NOT EXISTS
CREATE INDEX IF NOT EXISTS idx_auth_events_geo_id
ON auth_events(geo_id);

-- Index for IP threat intelligence lookups
-- Purpose: Optimize queries that lookup threat intelligence by IP address
-- Note: This index should already exist, but we verify with IF NOT EXISTS
CREATE INDEX IF NOT EXISTS idx_ip_threat_intelligence_ip_address
ON ip_threat_intelligence(ip_address_text);

-- ============================================================================
-- Auth Events Composite Index for Rule-Based Detection Queries
-- ============================================================================

-- Index for failed event queries by IP and time
-- Purpose: Optimize ML vs Rule-based comparison queries that filter by event_type='failed'
-- Example query: SELECT source_ip_text, COUNT(*) FROM auth_events WHERE event_type='failed' AND timestamp >= ? GROUP BY source_ip_text
-- Performance: Reduces query time from 10+ seconds to <1 second on 2M+ rows
CREATE INDEX IF NOT EXISTS idx_event_type_timestamp_ip
ON auth_events(event_type, timestamp, source_ip_text);

-- ============================================================================
-- Migration Notes
-- ============================================================================
--
-- Performance Impact:
-- - Index creation on large tables may take time (especially auth_events with 2M+ records)
-- - All indexes use IF NOT EXISTS to prevent errors on re-runs
-- - DESC ordering on created_at optimizes recent-first queries (most common pattern)
-- - DESC ordering on risk_score optimizes high-risk-first queries
--
-- Estimated Index Sizes (for planning):
-- - ml_predictions indexes: ~1-5MB each (current), will grow with data
-- - auth_events indexes: ~50-100MB (with 2M records)
-- - ip_threat_intelligence indexes: ~10-50MB depending on data
--
-- Rollback:
-- To rollback this migration, drop the indexes:
-- DROP INDEX IF EXISTS idx_ml_predictions_created_anomaly;
-- DROP INDEX IF EXISTS idx_ml_predictions_created_risk;
-- DROP INDEX IF EXISTS idx_ml_predictions_created_threat;
-- DROP INDEX IF EXISTS idx_ml_predictions_model_created;
