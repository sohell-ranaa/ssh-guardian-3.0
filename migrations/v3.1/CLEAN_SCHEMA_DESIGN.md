# SSH Guardian v3.1 - Clean Database Schema Design

## Design Principles
1. **Normalize properly** - No redundant data, proper relationships
2. **Use appropriate data types** - VARCHAR instead of restrictive ENUMs where values vary
3. **Clean foreign keys** - Proper ON DELETE behavior
4. **Remove legacy cruft** - No thesis tables, no duplicate firewall systems
5. **Consolidate where sensible** - Merge related config tables

---

## Core Domains

### 1. USER MANAGEMENT (4 tables)
| Table | Purpose | Records |
|-------|---------|---------|
| `roles` | User roles with permissions | 4 |
| `users` | User accounts | 7 |
| `user_sessions` | Active sessions | 14 |
| `user_otps` | One-time passwords | 25 |

### 2. AGENT MANAGEMENT (5 tables)
| Table | Purpose | Records |
|-------|---------|---------|
| `agents` | Registered agents | 3 |
| `agent_heartbeats` | Health pings (7-day retention) | ~4000 |
| `agent_log_batches` | Log upload batches (30-day retention) | ~1300 |
| `agent_ufw_state` | UFW firewall status | 2 |
| `agent_ufw_rules` | UFW rules per agent | 57 |
| `agent_ufw_commands` | Pending UFW commands | 327 |

### 3. IP INTELLIGENCE (2 tables)
| Table | Purpose | Records |
|-------|---------|---------|
| `ip_geolocation` | IP location + threat data (merged) | 32 |
| `ip_blocks` | Blocked IPs | 95 |

**Removed:** ip_watchlist, ip_whitelist, ip_reports, ip_block_events (audit goes to audit_logs)

### 4. AUTH EVENTS (3 tables)
| Table | Purpose | Records |
|-------|---------|---------|
| `auth_events` | SSH auth attempts | ~6000 |
| `auth_events_daily` | Daily aggregates | 181 |
| `auth_events_ml` | ML predictions for events | ~6000 |

### 5. BLOCKING SYSTEM (2 tables)
| Table | Purpose | Records |
|-------|---------|---------|
| `blocking_rules` | Auto-block rules | 8 |
| `blocking_actions` | Block/unblock history | 74 |

### 6. FAIL2BAN (2 tables)
| Table | Purpose | Records |
|-------|---------|---------|
| `fail2ban_state` | Current banned IPs per agent | 1 |
| `fail2ban_events` | Ban/unban events | 791 |

### 7. ML SYSTEM (2 tables)
| Table | Purpose | Records |
|-------|---------|---------|
| `ml_models` | Trained models | 10 |
| `ml_training_runs` | Training history | 9 |

### 8. SIMULATION (4 tables)
| Table | Purpose | Records |
|-------|---------|---------|
| `simulation_templates` | Attack templates | 4 |
| `simulation_runs` | Simulation executions | 20 |
| `simulation_ip_pool` | IPs used in simulations | 163 |
| `live_simulation_runs` | Live attack simulations | 32 |

### 9. SYSTEM CONFIG (4 tables)
| Table | Purpose | Records |
|-------|---------|---------|
| `system_settings` | All settings (consolidated) | ~57 |
| `integrations` | External integrations | 7 |
| `notification_rules` | Alert rules | 7 |
| `notifications` | Sent notifications | 3 |

### 10. AUDIT & LOGS (3 tables)
| Table | Purpose | Records |
|-------|---------|---------|
| `audit_logs` | System audit trail | 57 |
| `ufw_audit_log` | UFW change history | 321 |
| `log_sources` | Configured log sources | 3 |

### 11. UI SUPPORT (2 tables)
| Table | Purpose | Records |
|-------|---------|---------|
| `guide_steps` | Onboarding guide | 6 |
| `ufw_rule_templates` | Predefined UFW rules | 24 |

---

## TOTAL: 33 tables (down from 82)

## Tables REMOVED (49 tables):
- Empty tables (25)
- Thesis tables (3): thesis_metadata, thesis_sections, thesis_references
- Duplicate firewall: agent_firewall_*, firewall_rule_templates
- Redundant: ip_watchlist, ip_whitelist, ip_reports
- Merged: ip_threat_intelligence → ip_geolocation
- Merged: system_config, cache_settings → system_settings
- Merged: integration_config → integrations
- Renamed: ip_block_events → blocking_actions (consolidated)
- Removed: proactive_evaluations, fail2ban_ml_evaluations (merged into main tables)

---

## Key Schema Changes

### 1. Use VARCHAR instead of restrictive ENUMs
```sql
-- OLD: protocol ENUM('tcp', 'udp', 'any')
-- NEW: protocol VARCHAR(20) -- allows 'tcp (v6)', etc.

-- OLD: ufw_status ENUM('active', 'inactive', 'not_installed')
-- NEW: is_enabled BOOLEAN + status VARCHAR(20)
```

### 2. Proper NULL handling for optional FKs
```sql
-- All optional foreign keys are NULL, not 0
geo_id INT NULL REFERENCES ip_geolocation(id) ON DELETE SET NULL
```

### 3. Consolidated settings
```sql
-- One table for all settings with category field
system_settings (
    setting_key VARCHAR(100) PRIMARY KEY,
    setting_value TEXT,
    value_type VARCHAR(20), -- 'string', 'number', 'boolean', 'json'
    category VARCHAR(50),   -- 'general', 'security', 'cache', 'ml', etc.
    ...
)
```

### 4. Clean IP geolocation with threat data
```sql
-- Merged table with both geo and threat intelligence
ip_geolocation (
    ip_address VARBINARY(16),
    ip_address_text VARCHAR(45),
    -- Geo fields
    country_code, city, lat, lng, ...
    -- Threat fields (from ip_threat_intelligence)
    abuseipdb_score, virustotal_score, threat_level, ...
)
```
