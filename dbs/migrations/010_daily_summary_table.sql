-- Migration 010: Daily Summary Table for Timeline Performance
-- Creates a pre-aggregated summary table for fast timeline queries
-- This dramatically improves performance for daily timeline views

-- Create the daily summary table
CREATE TABLE IF NOT EXISTS auth_events_daily_summary (
    summary_date DATE NOT NULL PRIMARY KEY,
    total_events INT UNSIGNED DEFAULT 0,
    failed_count INT UNSIGNED DEFAULT 0,
    successful_count INT UNSIGNED DEFAULT 0,
    invalid_count INT UNSIGNED DEFAULT 0,
    anomaly_count INT UNSIGNED DEFAULT 0,
    avg_risk_score DECIMAL(5,2) DEFAULT 0,
    unique_ips INT UNSIGNED DEFAULT 0,
    unique_usernames INT UNSIGNED DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_summary_date (summary_date)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Populate with historical data
INSERT INTO auth_events_daily_summary (
    summary_date,
    total_events,
    failed_count,
    successful_count,
    invalid_count,
    anomaly_count,
    avg_risk_score,
    unique_ips,
    unique_usernames
)
SELECT
    DATE(timestamp) as summary_date,
    COUNT(*) as total_events,
    SUM(event_type = 'failed') as failed_count,
    SUM(event_type = 'successful') as successful_count,
    SUM(event_type = 'invalid') as invalid_count,
    SUM(is_anomaly = 1) as anomaly_count,
    AVG(ml_risk_score) as avg_risk_score,
    COUNT(DISTINCT source_ip_text) as unique_ips,
    COUNT(DISTINCT target_username) as unique_usernames
FROM auth_events
WHERE timestamp IS NOT NULL
GROUP BY DATE(timestamp)
ON DUPLICATE KEY UPDATE
    total_events = VALUES(total_events),
    failed_count = VALUES(failed_count),
    successful_count = VALUES(successful_count),
    invalid_count = VALUES(invalid_count),
    anomaly_count = VALUES(anomaly_count),
    avg_risk_score = VALUES(avg_risk_score),
    unique_ips = VALUES(unique_ips),
    unique_usernames = VALUES(unique_usernames);

-- Create stored procedure to update today's summary
DELIMITER //
CREATE PROCEDURE IF NOT EXISTS update_daily_summary()
BEGIN
    INSERT INTO auth_events_daily_summary (
        summary_date,
        total_events,
        failed_count,
        successful_count,
        invalid_count,
        anomaly_count,
        avg_risk_score,
        unique_ips,
        unique_usernames
    )
    SELECT
        CURDATE() as summary_date,
        COUNT(*) as total_events,
        SUM(event_type = 'failed') as failed_count,
        SUM(event_type = 'successful') as successful_count,
        SUM(event_type = 'invalid') as invalid_count,
        SUM(is_anomaly = 1) as anomaly_count,
        AVG(ml_risk_score) as avg_risk_score,
        COUNT(DISTINCT source_ip_text) as unique_ips,
        COUNT(DISTINCT target_username) as unique_usernames
    FROM auth_events
    WHERE DATE(timestamp) = CURDATE()
    ON DUPLICATE KEY UPDATE
        total_events = VALUES(total_events),
        failed_count = VALUES(failed_count),
        successful_count = VALUES(successful_count),
        invalid_count = VALUES(invalid_count),
        anomaly_count = VALUES(anomaly_count),
        avg_risk_score = VALUES(avg_risk_score),
        unique_ips = VALUES(unique_ips),
        unique_usernames = VALUES(unique_usernames);
END //
DELIMITER ;

-- Create event to update summary every 5 minutes (requires EVENT scheduler enabled)
-- SET GLOBAL event_scheduler = ON;
-- CREATE EVENT IF NOT EXISTS update_daily_summary_event
-- ON SCHEDULE EVERY 5 MINUTE
-- DO CALL update_daily_summary();
