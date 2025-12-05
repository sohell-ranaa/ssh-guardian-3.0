-- Migration 009: Performance Indexes for Events Analysis
-- Adds optimized indexes for the events-analysis dashboard page
-- These indexes significantly improve query performance for:
--   - Summary statistics
--   - Timeline aggregations
--   - Risk-based filtering
--   - Failure reason analysis

-- Index for ml_risk_score filtering (high/medium/low risk queries)
CREATE INDEX IF NOT EXISTS idx_ml_risk_score ON auth_events(ml_risk_score);

-- Composite index for timeline queries (timestamp + event_type for date grouping with type counts)
CREATE INDEX IF NOT EXISTS idx_timestamp_event_type ON auth_events(timestamp, event_type);

-- Composite index for failure reason analysis
CREATE INDEX IF NOT EXISTS idx_failure_reason_count ON auth_events(failure_reason);

-- Index for was_blocked filtering
CREATE INDEX IF NOT EXISTS idx_was_blocked ON auth_events(was_blocked);

-- Composite index for username analysis with event type
CREATE INDEX IF NOT EXISTS idx_username_event_type ON auth_events(target_username, event_type);

-- Index for auth_method analysis
CREATE INDEX IF NOT EXISTS idx_auth_method ON auth_events(auth_method);

-- Composite index for time-based risk analysis
CREATE INDEX IF NOT EXISTS idx_timestamp_risk ON auth_events(timestamp, ml_risk_score);

-- Note: Run ANALYZE TABLE after adding indexes to update statistics
-- ANALYZE TABLE auth_events;
