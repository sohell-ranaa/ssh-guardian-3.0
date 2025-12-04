# SSH Guardian v3.0 - Database Design & Architecture

**Version:** 3.0.0
**Created:** 2025-12-04
**Status:** 🏗️ Design Complete, Ready for Implementation

---

## 🎯 Design Goals

1. **Unified Event Processing Pipeline**
   - Real SSH logs from agents
   - Synthetic logs from dashboard
   - Simulation data
   - All flow through same pipeline: Log → Parse → DB → ML → API Check → Action → Notify → Report

2. **Performance Optimized**
   - Binary IP storage (63% space savings)
   - Table partitioning by year
   - Composite indexes for common queries
   - Normalized data (no duplication)

3. **Data Integrity**
   - Foreign key constraints
   - Proper data types
   - Transaction support
   - Audit trails

4. **Scalability**
   - Connection pooling
   - Efficient indexes
   - Archival strategy
   - Cleanup procedures

---

## 🔗 Database Connection Information

### Connection Details

```yaml
Database System: MySQL 8.0+
Host: localhost
Port: 3306
Container: mysql_server (Docker)
Database Name: ssh_guardian_v3
Character Set: utf8mb4
Collation: utf8mb4_unicode_ci
```

### Credentials

```yaml
# Development Environment
Username: root
Password: 123123

# Production (MUST CHANGE)
Username: ssh_guardian_app
Password: <strong-generated-password>
Privileges: SELECT, INSERT, UPDATE, DELETE, EXECUTE
```

### Connection Pool Configuration

```yaml
Pool Name: ssh_guardian_v3_pool
Pool Size: 30 connections
Pool Reset: True (reset session on return)
Auto Commit: False (explicit transactions)
Connection Timeout: 10 seconds
Use C Extension: True (for performance)
```

### Network Configuration

```yaml
# MySQL Server (Docker)
Container Name: mysql_server
Internal Port: 3306
Exposed Port: 3306
Network: bridge
Max Connections: 500
Max Packet Size: 64MB
```

---

## 📊 Data Flow Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         DATA SOURCES                                 │
├─────────────────────────────────────────────────────────────────────┤
│  1. Real SSH Logs (from Agents)                                    │
│  2. Synthetic Logs (Dashboard Generator)                            │
│  3. Simulation Data (Attack Scenarios)                              │
└─────────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────────┐
│ STEP 1: LOG RECEPTION & PARSING                                     │
├─────────────────────────────────────────────────────────────────────┤
│ • Receive raw log lines                                             │
│ • Parse timestamp, IP, username, server, port                       │
│ • Validate format                                                   │
│ • Extract auth method and result                                    │
│ • Tag source (agent/synthetic/simulation)                           │
└─────────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────────┐
│ STEP 2: DATABASE STORAGE (auth_events)                              │
├─────────────────────────────────────────────────────────────────────┤
│ • Insert into auth_events table                                     │
│ • Generate UUID for tracking                                        │
│ • Convert IP to binary format                                       │
│ • Set processing_status = 'pending'                                 │
│ • Commit transaction                                                │
└─────────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────────┐
│ STEP 3: GEOIP LOOKUP                                                │
├─────────────────────────────────────────────────────────────────────┤
│ • Check ip_geolocation cache                                        │
│ • If not found, query GeoIP database                                │
│ • Store in ip_geolocation table                                     │
│ • Link to auth_event (geo_id)                                       │
│ • Update processing_status = 'geoip_complete'                       │
└─────────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────────┐
│ STEP 4: ML RISK ANALYSIS                                            │
├─────────────────────────────────────────────────────────────────────┤
│ • Feed features to ML model                                         │
│ • Calculate risk score (0-100)                                      │
│ • Detect threat type (brute_force, credential_stuffing, etc)       │
│ • Detect anomalies                                                  │
│ • Update auth_event with ML results                                 │
│ • Update processing_status = 'ml_complete'                          │
└─────────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────────┐
│ STEP 5: 3RD PARTY API CHECKS                                        │
├─────────────────────────────────────────────────────────────────────┤
│ • AbuseIPDB: Check IP reputation                                    │
│ • Shodan: Check if IP is scanner/bot                                │
│ • VirusTotal: Check if IP is malicious                              │
│ • Update ip_threat_intelligence table                               │
│ • Update processing_status = 'intel_complete'                       │
└─────────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────────┐
│ STEP 6: RULE EVALUATION & AUTO-BLOCKING                             │
├─────────────────────────────────────────────────────────────────────┤
│ • Evaluate blocking_rules                                           │
│ • Check if IP should be blocked:                                    │
│   - Brute force (X attempts in Y minutes)                           │
│   - ML risk score > threshold                                       │
│   - IP reputation < threshold                                       │
│   - Anomaly detected                                                │
│ • If block triggered:                                               │
│   - Insert into ip_blocks table                                     │
│   - Set unblock_at timestamp                                        │
│   - Create blocking_action record                                   │
└─────────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────────┐
│ STEP 7: NOTIFICATIONS                                               │
├─────────────────────────────────────────────────────────────────────┤
│ • Check notification_rules                                          │
│ • Create notification record in notifications table                 │
│ • Send to Telegram:                                                 │
│   - Critical: IP blocked (high risk)                                │
│   - Warning: Brute force detected                                   │
│   - Info: Anomaly detected                                          │
│ • Update notification status after send                             │
└─────────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────────┐
│ STEP 8: FINAL UPDATE & REPORTING                                    │
├─────────────────────────────────────────────────────────────────────┤
│ • Update auth_event processing_status = 'completed'                 │
│ • Update statistics tables:                                         │
│   - ip_statistics                                                   │
│   - daily_statistics                                                │
│   - agent_statistics                                                │
│ • Generate report entries if needed                                 │
│ • Commit all transactions                                           │
└─────────────────────────────────────────────────────────────────────┘
                              ↓
                    ✅ PIPELINE COMPLETE
```

---

## 🗄️ Database Schema Overview

### Core Tables (13 tables)

| # | Table Name | Purpose | Partition | Indexes |
|---|------------|---------|-----------|---------|
| 1 | **auth_events** | All SSH authentication events | By Year | 12 |
| 2 | **ip_geolocation** | Normalized GeoIP cache | No | 5 |
| 3 | **ip_threat_intelligence** | 3rd party API results | No | 6 |
| 4 | **ip_blocks** | Blocked IPs with rules | No | 8 |
| 5 | **blocking_rules** | Auto-blocking configuration | No | 3 |
| 6 | **blocking_actions** | Block/unblock history | By Year | 4 |
| 7 | **notifications** | Notification queue/history | By Month | 5 |
| 8 | **notification_rules** | Notification triggers | No | 2 |
| 9 | **agents** | Connected agents | No | 7 |
| 10 | **agent_heartbeats** | Agent health metrics | By Month | 3 |
| 11 | **log_sources** | Log source tracking | No | 3 |
| 12 | **daily_statistics** | Daily aggregated stats | No | 3 |
| 13 | **ip_statistics** | Per-IP statistics | No | 4 |

### Authentication Tables (5 tables)

| # | Table Name | Purpose |
|---|------------|---------|
| 14 | **users** | User accounts |
| 15 | **roles** | RBAC roles |
| 16 | **user_sessions** | Active sessions |
| 17 | **user_otps** | OTP codes |
| 18 | **audit_logs** | Security audit trail |

### Simulation Tables (4 tables)

| # | Table Name | Purpose |
|---|------------|---------|
| 19 | **simulation_runs** | Simulation executions |
| 20 | **simulation_templates** | Predefined scenarios |
| 21 | **simulation_logs** | Detailed sim logs |
| 22 | **simulation_ip_pool** | IP pool for sims |

### System Tables (2 tables)

| # | Table Name | Purpose |
|---|------------|---------|
| 23 | **system_config** | System configuration |
| 24 | **system_alerts** | System-wide alerts |

**Total: 24 tables**

---

## 📋 Table Definitions

### 1. auth_events (Core Event Table)

**Purpose:** Unified table for all SSH authentication events from all sources

```sql
CREATE TABLE auth_events (
    -- Primary Key
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    event_uuid CHAR(36) NOT NULL UNIQUE,

    -- Timing
    timestamp DATETIME(3) NOT NULL,
    processed_at DATETIME(3) NULL,

    -- Source Information
    source_type ENUM('agent', 'synthetic', 'simulation') NOT NULL,
    agent_id INT NULL,
    log_source_id INT NULL,
    simulation_run_id INT NULL,

    -- Event Type
    event_type ENUM('failed', 'successful', 'invalid') NOT NULL,
    auth_method ENUM('password', 'publickey', 'keyboard-interactive', 'none', 'other') NULL,

    -- IP Information (Binary + Text)
    source_ip VARBINARY(16) NOT NULL,
    source_ip_text VARCHAR(45) NOT NULL,
    source_port INT UNSIGNED NULL,
    geo_id INT NULL,

    -- Target Information
    target_server VARCHAR(255) NOT NULL,
    target_port INT UNSIGNED DEFAULT 22,
    target_username VARCHAR(255) NOT NULL,

    -- Event Details
    failure_reason ENUM('invalid_password', 'invalid_user', 'connection_refused',
                        'key_rejected', 'timeout', 'max_attempts', 'other') NULL,
    session_id VARCHAR(100) NULL,
    session_duration_sec INT UNSIGNED NULL,

    -- Processing Pipeline Status
    processing_status ENUM('pending', 'geoip_complete', 'ml_complete',
                          'intel_complete', 'completed', 'error') DEFAULT 'pending',
    processing_error TEXT NULL,

    -- ML Analysis Results
    ml_risk_score TINYINT UNSIGNED DEFAULT 0,
    ml_threat_type VARCHAR(100) NULL,
    ml_confidence DECIMAL(5,4) NULL,
    is_anomaly BOOLEAN DEFAULT FALSE,
    anomaly_reasons JSON NULL,

    -- Action Taken
    was_blocked BOOLEAN DEFAULT FALSE,
    block_id INT NULL,

    -- Raw Data
    raw_log_line TEXT NULL,
    additional_metadata JSON NULL,

    -- Timestamps
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    -- Indexes
    KEY idx_timestamp (timestamp),
    KEY idx_event_type (event_type),
    KEY idx_source_ip (source_ip),
    KEY idx_source_ip_text (source_ip_text),
    KEY idx_target_server (target_server),
    KEY idx_target_username (target_username),
    KEY idx_is_anomaly (is_anomaly),
    KEY idx_source_type (source_type),
    KEY idx_processing_status (processing_status),
    KEY idx_agent (agent_id),

    -- Composite indexes for pipeline
    KEY idx_ip_time (source_ip, timestamp),
    KEY idx_server_time (target_server, timestamp),
    KEY idx_pipeline (processing_status, created_at),

    -- Foreign Keys
    FOREIGN KEY (geo_id) REFERENCES ip_geolocation(id) ON DELETE SET NULL,
    FOREIGN KEY (agent_id) REFERENCES agents(id) ON DELETE SET NULL,
    FOREIGN KEY (log_source_id) REFERENCES log_sources(id) ON DELETE SET NULL,
    FOREIGN KEY (simulation_run_id) REFERENCES simulation_runs(id) ON DELETE CASCADE,
    FOREIGN KEY (block_id) REFERENCES ip_blocks(id) ON DELETE SET NULL

) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
PARTITION BY RANGE (YEAR(timestamp)) (
    PARTITION p2024 VALUES LESS THAN (2025),
    PARTITION p2025 VALUES LESS THAN (2026),
    PARTITION p2026 VALUES LESS THAN (2027),
    PARTITION pmax VALUES LESS THAN MAXVALUE
)
COMMENT='Unified SSH authentication events from all sources';
```

### 2. ip_geolocation (Normalized GeoIP Cache)

```sql
CREATE TABLE ip_geolocation (
    id INT AUTO_INCREMENT PRIMARY KEY,

    -- IP Address (Binary + Text)
    ip_address VARBINARY(16) NOT NULL UNIQUE,
    ip_address_text VARCHAR(45) NOT NULL UNIQUE,
    ip_version TINYINT NOT NULL COMMENT '4 or 6',

    -- Geographic Information
    country_code CHAR(2) NULL,
    country_name VARCHAR(100) NULL,
    region VARCHAR(100) NULL,
    city VARCHAR(100) NULL,
    postal_code VARCHAR(20) NULL,
    latitude DECIMAL(10,8) NULL,
    longitude DECIMAL(11,8) NULL,
    timezone VARCHAR(50) NULL,

    -- Network Information
    asn INT NULL,
    asn_org VARCHAR(255) NULL,
    isp VARCHAR(255) NULL,
    connection_type VARCHAR(50) NULL,

    -- Threat Indicators
    is_proxy BOOLEAN DEFAULT FALSE,
    is_vpn BOOLEAN DEFAULT FALSE,
    is_tor BOOLEAN DEFAULT FALSE,
    is_datacenter BOOLEAN DEFAULT FALSE,
    is_hosting BOOLEAN DEFAULT FALSE,

    -- Cache Management
    lookup_count INT DEFAULT 1,
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    cache_expires_at TIMESTAMP NULL,

    -- Indexes
    KEY idx_country (country_code),
    KEY idx_asn (asn),
    KEY idx_proxy_flags (is_proxy, is_vpn, is_tor),
    KEY idx_cache_expires (cache_expires_at)

) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
```

### 3. ip_threat_intelligence (3rd Party API Results)

```sql
CREATE TABLE ip_threat_intelligence (
    id INT AUTO_INCREMENT PRIMARY KEY,

    -- IP Reference
    ip_address_text VARCHAR(45) NOT NULL,
    geo_id INT NULL,

    -- AbuseIPDB Data
    abuseipdb_score INT NULL COMMENT '0-100',
    abuseipdb_confidence INT NULL,
    abuseipdb_reports INT NULL,
    abuseipdb_last_reported TIMESTAMP NULL,
    abuseipdb_categories JSON NULL,
    abuseipdb_checked_at TIMESTAMP NULL,

    -- Shodan Data
    shodan_ports JSON NULL,
    shodan_tags JSON NULL,
    shodan_vulns JSON NULL,
    shodan_last_update TIMESTAMP NULL,
    shodan_checked_at TIMESTAMP NULL,

    -- VirusTotal Data
    virustotal_positives INT NULL,
    virustotal_total INT NULL,
    virustotal_detected_urls JSON NULL,
    virustotal_checked_at TIMESTAMP NULL,

    -- Aggregated Threat Assessment
    overall_threat_level ENUM('clean', 'low', 'medium', 'high', 'critical') DEFAULT 'clean',
    threat_confidence DECIMAL(5,4) NULL,
    threat_categories JSON NULL,

    -- Cache Management
    needs_refresh BOOLEAN DEFAULT FALSE,
    refresh_after TIMESTAMP NULL,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    -- Indexes
    UNIQUE KEY idx_ip_unique (ip_address_text),
    KEY idx_geo (geo_id),
    KEY idx_threat_level (overall_threat_level),
    KEY idx_abuseipdb_score (abuseipdb_score),
    KEY idx_refresh (needs_refresh, refresh_after),

    FOREIGN KEY (geo_id) REFERENCES ip_geolocation(id) ON DELETE SET NULL

) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
```

### 4. ip_blocks (Active IP Blocks)

```sql
CREATE TABLE ip_blocks (
    id INT AUTO_INCREMENT PRIMARY KEY,

    -- IP Information
    ip_address VARBINARY(16) NOT NULL,
    ip_address_text VARCHAR(45) NOT NULL,
    ip_range_cidr VARCHAR(50) NULL COMMENT 'For CIDR range blocks',

    -- Block Details
    block_reason VARCHAR(500) NOT NULL,
    block_source ENUM('manual', 'rule_based', 'ml_threshold',
                     'api_reputation', 'anomaly_detection') NOT NULL,
    blocking_rule_id INT NULL,

    -- Trigger Information
    trigger_event_id BIGINT NULL COMMENT 'Event that triggered block',
    failed_attempts INT DEFAULT 0,
    risk_score TINYINT UNSIGNED NULL,
    threat_level VARCHAR(50) NULL,

    -- Status
    is_active BOOLEAN DEFAULT TRUE,
    blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    unblock_at TIMESTAMP NULL,
    auto_unblock BOOLEAN DEFAULT TRUE,

    -- Manual Management
    manually_unblocked_at TIMESTAMP NULL,
    unblocked_by_user_id INT NULL,
    unblock_reason VARCHAR(500) NULL,

    -- Simulation
    is_simulation BOOLEAN DEFAULT FALSE,
    simulation_run_id INT NULL,

    -- Metadata
    block_metadata JSON NULL,
    created_by_user_id INT NULL,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    -- Indexes
    KEY idx_ip_binary (ip_address),
    KEY idx_ip_text (ip_address_text),
    KEY idx_is_active (is_active),
    KEY idx_unblock_at (unblock_at),
    KEY idx_block_source (block_source),
    KEY idx_is_simulation (is_simulation),
    KEY idx_active_ip (is_active, ip_address),
    KEY idx_trigger_event (trigger_event_id),

    FOREIGN KEY (blocking_rule_id) REFERENCES blocking_rules(id) ON DELETE SET NULL,
    FOREIGN KEY (trigger_event_id) REFERENCES auth_events(id) ON DELETE SET NULL,
    FOREIGN KEY (simulation_run_id) REFERENCES simulation_runs(id) ON DELETE CASCADE,
    FOREIGN KEY (created_by_user_id) REFERENCES users(id) ON DELETE SET NULL,
    FOREIGN KEY (unblocked_by_user_id) REFERENCES users(id) ON DELETE SET NULL

) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
```

### 5. blocking_rules (Auto-blocking Configuration)

```sql
CREATE TABLE blocking_rules (
    id INT AUTO_INCREMENT PRIMARY KEY,

    -- Rule Identification
    rule_name VARCHAR(100) NOT NULL UNIQUE,
    rule_type ENUM('brute_force', 'ml_threshold', 'api_reputation',
                   'anomaly_pattern', 'geo_restriction', 'custom') NOT NULL,
    is_enabled BOOLEAN DEFAULT TRUE,
    priority INT DEFAULT 50 COMMENT 'Higher priority evaluated first',

    -- Rule Conditions (JSON for flexibility)
    conditions JSON NOT NULL,
    /*
    brute_force: {"failed_attempts": 5, "time_window_minutes": 10, "unique_usernames": 3}
    ml_threshold: {"min_risk_score": 80, "min_confidence": 0.75}
    api_reputation: {"abuseipdb_min_score": 80, "virustotal_min_positives": 3}
    anomaly_pattern: {"anomaly_types": ["geo_anomaly", "time_anomaly"]}
    geo_restriction: {"blocked_countries": ["CN", "RU"], "whitelist_ips": []}
    */

    -- Actions
    block_duration_minutes INT DEFAULT 1440 COMMENT '24 hours default',
    auto_unblock BOOLEAN DEFAULT TRUE,

    -- Notifications
    notify_on_trigger BOOLEAN DEFAULT TRUE,
    notification_channels JSON NULL COMMENT '["telegram", "email", "webhook"]',
    notification_message_template TEXT NULL,

    -- Statistics
    times_triggered INT DEFAULT 0,
    last_triggered_at TIMESTAMP NULL,
    ips_blocked_total INT DEFAULT 0,

    -- Metadata
    description TEXT NULL,
    created_by_user_id INT NULL,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    KEY idx_rule_type (rule_type),
    KEY idx_enabled_priority (is_enabled, priority),

    FOREIGN KEY (created_by_user_id) REFERENCES users(id) ON DELETE SET NULL

) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
```

---

## 🔧 Connection File Specification

**File:** `/home/rana-workspace/ssh_guardian_v3.0/dbs/connection.py`

**Features:**
- Connection pooling (30 connections)
- Automatic reconnection
- Transaction support
- Error handling
- Connection health checks
- IPv4/IPv6 binary conversion utilities

---

## 📊 Storage Estimates

### Expected Data Growth (1 year, 10 agents)

| Table | Daily Inserts | Size per Row | Monthly Size | Yearly Size |
|-------|---------------|--------------|--------------|-------------|
| auth_events | 50,000 | 500 bytes | 750 MB | 9 GB |
| ip_geolocation | 100 | 300 bytes | 9 MB | 108 MB |
| ip_threat_intelligence | 100 | 800 bytes | 24 MB | 288 MB |
| ip_blocks | 50 | 400 bytes | 600 KB | 7.2 MB |
| notifications | 200 | 300 bytes | 18 MB | 216 MB |
| agent_heartbeats | 28,800 | 200 bytes | 1.7 GB | 20 GB |
| **Total Estimated** | | | **2.5 GB/mo** | **30 GB/yr** |

With partitioning and archival: **~10 GB active data**

---

## 🎯 Next Steps

1. ✅ Design complete
2. Create connection.py file
3. Create schema SQL file
4. Create new database `ssh_guardian_v3`
5. Run schema creation
6. Insert seed data
7. Test connection
8. Test CRUD operations

---

**Status:** ✅ Design Complete - Ready for Implementation

**Last Updated:** 2025-12-04
