-- SSH Guardian v3.0 - Migration 004
-- Add agent_log_batches table for tracking batch uploads from agents
-- Created: 2025-12-04
-- Purpose: Track log batch submissions from remote agents for better monitoring

USE ssh_guardian_v3;

-- Create agent_log_batches table
CREATE TABLE IF NOT EXISTS agent_log_batches (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,

    batch_uuid CHAR(36) NOT NULL UNIQUE,
    agent_id INT NOT NULL,

    -- Batch Information
    batch_size INT NOT NULL COMMENT 'Number of log lines in batch',
    events_created INT DEFAULT 0 COMMENT 'Number of auth_events created',
    events_failed INT DEFAULT 0 COMMENT 'Number of logs that failed to parse',

    -- Processing
    processing_status ENUM('received', 'processing', 'completed', 'failed') DEFAULT 'received',
    processing_started_at TIMESTAMP NULL,
    processing_completed_at TIMESTAMP NULL,
    processing_duration_ms INT NULL COMMENT 'Processing time in milliseconds',

    -- Error Handling
    error_message TEXT NULL,
    failed_log_lines JSON NULL COMMENT 'Array of log lines that failed to parse',

    -- Metadata
    source_filename VARCHAR(255) NULL COMMENT 'Original log file name',
    log_date_range JSON NULL COMMENT 'Min/max timestamps in batch',
    upload_ip VARCHAR(45) NULL COMMENT 'IP address of agent during upload',

    -- Timestamps
    received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    -- Indexes
    KEY idx_agent (agent_id),
    KEY idx_status (processing_status),
    KEY idx_received_at (received_at),
    KEY idx_agent_status (agent_id, processing_status),

    FOREIGN KEY (agent_id) REFERENCES agents(id) ON DELETE CASCADE

) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
COMMENT='Tracks log batch uploads from remote agents';

-- Add batch_id reference to auth_events (optional, for traceability)
ALTER TABLE auth_events
ADD COLUMN agent_batch_id BIGINT NULL COMMENT 'FK to agent_log_batches if from agent batch' AFTER agent_id,
ADD KEY idx_agent_batch (agent_batch_id);

-- Verify changes
SELECT 'Migration 004 completed: agent_log_batches table created' AS status;
