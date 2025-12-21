# SSH Guardian v3.0 - Simulation Process Flow

This document describes the complete flow when a simulation is triggered, from injecting fake logs to blocking the threat.

---

## Process Flow Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        SIMULATION PROCESS FLOW                              │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│ STEP 1: USER TRIGGERS SIMULATION                                            │
│ Dashboard UI → simulation.js                                                │
├─────────────────────────────────────────────────────────────────────────────┤
│ • User selects scenario (e.g., "Bad Reputation Critical")                   │
│ • User clicks "Run Simulation"                                              │
│ • JS calls: POST /api/simulation/live/run                                   │
│   {scenario_id: "bad_reputation_critical", target_id: 1, event_count: 15}   │
└────────────────────────────────────────┬────────────────────────────────────┘
                                         ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ STEP 2: INJECT FAKE LOGS TO /var/log/auth.log                               │
│ live_simulation.py:48 → inject_local()                                      │
├─────────────────────────────────────────────────────────────────────────────┤
│ • Generates fake SSH log entries:                                           │
│   "Dec 19 14:30:45 server sshd[12345]: Failed password for root             │
│    from 185.220.101.1 port 54321 ssh2"                                      │
│ • Writes 15 lines to /var/log/auth.log                                      │
│ • Creates record in live_simulation_runs table (status: 'injected')         │
└────────────────────────────────────────┬────────────────────────────────────┘
                                         ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ STEP 3: AGENT DETECTS NEW LOG LINES                                         │
│ ssh_guardian_agent.py → LogCollector.collect_new_logs()                     │
├─────────────────────────────────────────────────────────────────────────────┤
│ • Agent polls /var/log/auth.log every 5 seconds                             │
│ • Tracks file position using inode + byte offset                            │
│ • Filters SSH-related lines (sshd, Failed password, etc.)                   │
│ • Collects new lines into batch                                             │
└────────────────────────────────────────┬────────────────────────────────────┘
                                         ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ STEP 4: AGENT SENDS LOGS TO DASHBOARD                                       │
│ ssh_guardian_agent.py → GuardianAPIClient.submit_log_batch()                │
├─────────────────────────────────────────────────────────────────────────────┤
│ POST /api/agents/logs                                                       │
│ Headers: X-API-Key: <agent_api_key>                                         │
│ Body: {                                                                     │
│   "batch_uuid": "xxx-xxx",                                                  │
│   "log_lines": ["Dec 19 14:30:45 server sshd[12345]: Failed..."],           │
│   "batch_size": 15,                                                         │
│   "source_filename": "/var/log/auth.log"                                    │
│ }                                                                           │
└────────────────────────────────────────┬────────────────────────────────────┘
                                         ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ STEP 5: DASHBOARD PROCESSES EACH LOG LINE                                   │
│ agents/logs.py → log_processor.py → process_log_line()                      │
├─────────────────────────────────────────────────────────────────────────────┤
│ For each log line:                                                          │
│ ┌─────────────────────────────────────────────────────────────────────────┐ │
│ │ 5a. PARSE LOG LINE                                                      │ │
│ │     Extract: IP (185.220.101.1), username (root), status (failed)       │ │
│ ├─────────────────────────────────────────────────────────────────────────┤ │
│ │ 5b. INSERT INTO auth_events                                             │ │
│ │     Creates event record with source_ip, username, event_type           │ │
│ ├─────────────────────────────────────────────────────────────────────────┤ │
│ │ 5c. ENRICHMENT PIPELINE → enrichment.py                                 │ │
│ │     • GeoIP lookup (country, city, ISP)                                 │ │
│ │     • Threat Intel (AbuseIPDB, VirusTotal, Shodan) → ip_geolocation     │ │
│ ├─────────────────────────────────────────────────────────────────────────┤ │
│ │ 5d. PROACTIVE THREAT EVALUATION → proactive_blocker.py                  │ │
│ │     • Checks blocking rules                                             │ │
│ │     • Evaluates threat level                                            │ │
│ │     • May trigger immediate block                                       │ │
│ └─────────────────────────────────────────────────────────────────────────┘ │
└────────────────────────────────────────┬────────────────────────────────────┘
                                         ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ STEP 6: UNIFIED THREAT EVALUATION                                           │
│ threat_evaluator.py → ThreatEvaluator.evaluate_ip()                         │
├─────────────────────────────────────────────────────────────────────────────┤
│ Combines 5 data sources into composite score:                               │
│                                                                             │
│ ┌──────────────────┬─────────┬──────────────────────────────────────────┐  │
│ │ Component        │ Weight  │ Data Source                              │  │
│ ├──────────────────┼─────────┼──────────────────────────────────────────┤  │
│ │ Threat Intel     │   30%   │ AbuseIPDB (90), VirusTotal, Shodan       │  │
│ │ ML Prediction    │   25%   │ Random Forest PKL model                  │  │
│ │ Behavioral       │   25%   │ Failed attempts, credential stuffing     │  │
│ │ Network          │   12%   │ TOR, VPN, Proxy, Datacenter flags        │  │
│ │ Geolocation      │    8%   │ High-risk country codes                  │  │
│ └──────────────────┴─────────┴──────────────────────────────────────────┘  │
│                                                                             │
│ Output: composite_score: 85, risk_level: "critical",                        │
│         recommended_action: "block_permanent"                               │
└────────────────────────────────────────┬────────────────────────────────────┘
                                         ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ STEP 7: BLOCKING DECISION                                                   │
│ blocking/proactive_blocker.py + blocking/rule_evaluators.py                 │
├─────────────────────────────────────────────────────────────────────────────┤
│ • Check blocking rules (e.g., "abuseipdb_critical_90")                      │
│ • If rule matches:                                                          │
│   - Create ip_blocks record                                                 │
│   - Queue UFW command for agent: "ufw deny from 185.220.101.1"              │
│   - Update agent_ufw_commands table                                         │
└────────────────────────────────────────┬────────────────────────────────────┘
                                         ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ STEP 8: AGENT APPLIES FIREWALL BLOCK                                        │
│ ssh_guardian_agent.py → FirewallManager.sync_rules()                        │
├─────────────────────────────────────────────────────────────────────────────┤
│ • Agent polls: GET /api/agents/ufw/commands?agent_id=xxx                    │
│ • Receives pending commands: [{action: "deny", ip: "185.220.101.1"}]        │
│ • Executes: sudo ufw deny from 185.220.101.1                                │
│ • Reports back: POST /api/agents/ufw/commands/{id}/ack                      │
└────────────────────────────────────────┬────────────────────────────────────┘
                                         ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ STEP 9: SIMULATION STATUS UPDATE                                            │
│ Dashboard polls: GET /api/simulation/live/{run_id}/status                   │
├─────────────────────────────────────────────────────────────────────────────┤
│ • Checks auth_events for detected events                                    │
│ • Checks fail2ban_events for bans                                           │
│ • Checks ip_blocks for blocks                                               │
│ • Updates simulation status: 'detected' → 'blocked' → 'completed'           │
│ • Returns timeline to UI                                                    │
└────────────────────────────────────────┬────────────────────────────────────┘
                                         ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ STEP 10: UI SHOWS RESULTS                                                   │
│ simulation.js → showSimulationResults()                                     │
├─────────────────────────────────────────────────────────────────────────────┤
│ • Displays threat evaluation scores                                         │
│ • Shows blocking factors (AbuseIPDB 90, TOR exit node, etc.)                │
│ • Shows timeline: Injected → Detected → Evaluated → Blocked                 │
│ • Displays recommendations                                                  │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Key Files Reference

| Step | File | Function |
|------|------|----------|
| 1 | `src/dashboard/static/js/modules/simulation.js` | `runDemoScenario()` |
| 2 | `src/dashboard/routes/simulation/live_simulation.py:48` | `inject_local()` |
| 3 | `src/dashboard/static/installer/ssh_guardian_agent.py:182` | `LogCollector.collect_new_logs()` |
| 4 | `src/dashboard/static/installer/ssh_guardian_agent.py:326` | `GuardianAPIClient.submit_log_batch()` |
| 5 | `src/dashboard/routes/agents/logs.py:29` | `submit_logs()` |
| 5 | `src/core/log_processor.py:114` | `process_log_line()` |
| 6 | `src/core/threat_evaluator.py:59` | `ThreatEvaluator.evaluate_ip()` |
| 7 | `src/core/blocking/proactive_blocker.py` | `evaluate_auth_event()` |
| 8 | `src/dashboard/static/installer/ssh_guardian_agent.py` | `FirewallManager.sync_rules()` |
| 9-10 | `src/dashboard/routes/simulation/live_simulation.py:348` | `get_simulation_status()` |

---

## API Endpoints Used

### Simulation Trigger
```
POST /api/simulation/live/run
{
  "scenario_id": "bad_reputation_critical",
  "target_id": 1,
  "event_count": 15,
  "source_ip": "185.220.101.1"
}
```

### Agent Log Submission
```
POST /api/agents/logs
Headers: X-API-Key: <agent_api_key>
{
  "batch_uuid": "xxx-xxx-xxx",
  "log_lines": ["Dec 19 14:30:45 server sshd[12345]: Failed password..."],
  "batch_size": 15
}
```

### Threat Evaluation
```
GET /api/threat-intel/evaluate/185.220.101.1

Response:
{
  "success": true,
  "evaluation": {
    "composite_score": 85,
    "risk_level": "critical",
    "recommended_action": "block_permanent",
    "components": {
      "threat_intel_score": 35,
      "ml_score": 75,
      "behavioral_score": 30,
      "network_score": 25,
      "geo_score": 20
    },
    "factors": [
      "Critical AbuseIPDB: 90/100",
      "TOR Exit Node",
      "ML High Risk: 75/100"
    ]
  }
}
```

### UFW Command Queue
```
GET /api/agents/ufw/commands?agent_id=xxx

Response:
{
  "commands": [
    {"id": 123, "action": "deny", "ip": "185.220.101.1"}
  ]
}
```

### Simulation Status
```
GET /api/simulation/live/{run_id}/status

Response:
{
  "status": "blocked",
  "events_detected": 15,
  "timeline": [
    {"step": "injected", "status": "completed", "time": "..."},
    {"step": "detected", "status": "completed", "time": "..."},
    {"step": "blocked", "status": "completed", "time": "..."}
  ]
}
```

---

## Database Tables Involved

| Table | Purpose |
|-------|---------|
| `live_simulation_runs` | Tracks simulation run status |
| `auth_events` | Stores parsed SSH events |
| `ip_geolocation` | Stores GeoIP + threat intel data |
| `ip_blocks` | Active IP blocks |
| `agent_ufw_commands` | Pending UFW commands for agents |
| `fail2ban_events` | fail2ban ban/unban events |
| `blocking_rules` | Configured blocking rules |

---

## Threat Evaluation Weights

```
┌──────────────────┬─────────┬────────────────────────────────────┐
│ Component        │ Weight  │ Description                        │
├──────────────────┼─────────┼────────────────────────────────────┤
│ Threat Intel     │   30%   │ AbuseIPDB, VirusTotal, Shodan      │
│ ML Prediction    │   25%   │ Random Forest classifier (PKL)     │
│ Behavioral       │   25%   │ Failed attempts, credential stuff  │
│ Network          │   12%   │ TOR, VPN, Proxy, Datacenter        │
│ Geolocation      │    8%   │ High-risk country codes            │
└──────────────────┴─────────┴────────────────────────────────────┘
```

---

## Risk Levels

| Score Range | Risk Level | Recommended Action |
|-------------|------------|-------------------|
| 80-100 | Critical | `block_permanent` |
| 60-79 | High | `block_temporary` |
| 40-59 | Medium | `monitor_closely` |
| 20-39 | Low | `monitor` |
| 0-19 | Minimal | `allow` |
