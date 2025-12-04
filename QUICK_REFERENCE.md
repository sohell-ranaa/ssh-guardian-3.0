# SSH Guardian v3.0 - Quick Reference Guide

**Last Updated:** 2025-12-04

---

## 🚀 Quick Start

### Activate Virtual Environment
```bash
source /home/rana-workspace/ssh_guardian_2.0/venv/bin/activate
```

### Start Dashboard Server
```bash
cd /home/rana-workspace/ssh_guardian_v3.0
python3 src/dashboard/server.py
```

**Access:** http://localhost:8081

### View Live Events Dashboard
1. Login to dashboard: http://localhost:8081
2. Navigate: **Auth Events** → **Live Events** (in sidebar)
3. Features:
   - Search by IP or username
   - Filter by event type (failed/successful/invalid)
   - Filter by threat level (clean/low/medium/high/critical)
   - View enriched data: GeoIP location, ISP, threat scores
   - Country flags, proxy/VPN/Tor indicators
   - Pagination support

---

## 📊 Database Operations

### Check Database Schema
```bash
python3 scripts/db_schema_check.py
```
- Shows all tables and columns
- Saves to `docs/CURRENT_DB_SCHEMA.txt`
- **Always check before writing queries**

### Database Statistics
```bash
python3 scripts/db_helper.py stats
```
- Row counts for all tables
- Recent activity summary
- Active agents and sessions

### View Recent Events
```bash
python3 scripts/db_helper.py events [N]
# Example: python3 scripts/db_helper.py events 10
```

### View Agents
```bash
python3 scripts/db_helper.py agents
```

### Custom Query
```bash
python3 scripts/db_helper.py query
```
- Interactive SQL query mode
- Type queries directly
- Type 'exit' to quit

---

## 🔑 API Operations

### Create Test Agent
```bash
python3 scripts/create_test_agent.py
```
- Creates agent with API key
- Outputs API key for testing
- Shows example curl command

### Test API Endpoint
```bash
# Health check
curl http://localhost:8081/api/events/health

# Submit event (replace API_KEY)
curl -X POST http://localhost:8081/api/events/submit \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_API_KEY" \
  -d '{
    "timestamp": "2025-12-04T10:30:45Z",
    "source_ip": "192.168.1.100",
    "username": "root",
    "status": "failed",
    "hostname": "test-server-01"
  }'
```

### Verify Events Submitted
```bash
python3 scripts/verify_event.py
```

### Test GeoIP Integration
```bash
python3 scripts/test_geoip.py
```
- Tests IP lookup functionality
- Verifies caching
- Shows enriched events with location data

### Test Threat Intelligence
```bash
python3 scripts/test_threat_intel.py
```
- Tests AbuseIPDB, VirusTotal, Shodan APIs
- Shows threat levels and scoring
- Verifies cache functionality

---

## 🗄️ Database Connection

**MySQL is in Docker** - Use Python scripts, not mysql CLI

**Connection Details:**
- Host: localhost
- Port: 3306
- Database: ssh_guardian_v3
- User: root
- Password: 123123
- Pool: 30 connections

**Reference:** `docs/DATABASE_CONNECTION.md`

---

## 📋 Important Table Schemas

### agents
- **display_name** (NOT agent_name)
- **api_key** - For API authentication
- **hostname** - Server hostname
- **status** - online, offline, maintenance, error, unknown
- **is_active** - Boolean active flag

### auth_events
- **event_type** - failed, successful, invalid (NOT status)
- **target_username** (NOT username)
- **target_server** (NOT hostname)
- **target_port** (NOT port)
- **raw_log_line** (NOT raw_log)
- **source_ip** - VARBINARY(16)
- **source_ip_text** - VARCHAR(45)

**Full schema:** `docs/CURRENT_DB_SCHEMA.txt`

---

## 📝 Common Scripts

```bash
# Database operations
python3 scripts/db_schema_check.py          # Check schema
python3 scripts/db_helper.py stats          # Database stats
python3 scripts/db_helper.py events         # Recent events
python3 scripts/db_helper.py agents         # List agents

# API operations
python3 scripts/create_test_agent.py        # Create agent
python3 scripts/verify_event.py             # Verify events

# Migrations
ls -la dbs/migrations/                      # List migrations
python3 scripts/verify_and_apply_migration.py  # Apply/verify migration
```

---

## 📚 Documentation Files

| File | Description |
|------|-------------|
| `docs/PROJECT_PLAN.md` | Project progress tracker |
| `docs/API_DOCUMENTATION.md` | API reference guide |
| `docs/DATABASE_CONNECTION.md` | DB connection details |
| `docs/CURRENT_DB_SCHEMA.txt` | Current table schemas |
| `docs/V3_DATABASE_DESIGN.md` | Database design doc |
| `docs/V2_DATABASE_REFERENCE.md` | V2 reference |
| `docs/V2_AUTH_SYSTEM_REFERENCE.md` | V2 auth reference |

---

## 🔧 Development Workflow

### Before Writing Code
1. Check database schema: `python3 scripts/db_schema_check.py`
2. Reference `docs/CURRENT_DB_SCHEMA.txt`
3. Use exact column names from schema

### Testing Changes
1. Test with curl or Python
2. Verify in database: `python3 scripts/db_helper.py stats`
3. Check logs in server console

### Database Changes
1. Create migration file in `dbs/migrations/`
2. Number sequentially (004_, 005_, etc.)
3. Apply and verify with Python script
4. Update schema reference: `python3 scripts/db_schema_check.py`

---

## ⚠️ Common Pitfalls

### ❌ Wrong Column Names
```python
# WRONG
cursor.execute("SELECT agent_name FROM agents")
cursor.execute("SELECT username FROM auth_events")

# CORRECT
cursor.execute("SELECT display_name FROM agents")
cursor.execute("SELECT target_username FROM auth_events")
```

### ❌ Using mysql CLI
```bash
# WRONG - Won't work (Docker MySQL)
mysql -u root -p ssh_guardian_v3

# CORRECT - Use Python scripts
python3 scripts/db_helper.py query
```

### ❌ Direct Schema Changes
```sql
-- WRONG - Don't modify directly
ALTER TABLE agents ADD COLUMN foo VARCHAR(100);

-- CORRECT - Create migration file
# Create dbs/migrations/004_add_foo.sql
# Then apply with Python script
```

---

## 🎯 Project Status

**Current Phase:** Phase 6 Complete ✅
**Progress:** 62/80+ tasks (77%)
**Next:** Phase 7 - Blocking Rules Engine

**Completed:**
- ✅ Database & Architecture
- ✅ Authentication System
- ✅ Dashboard UI
- ✅ Agent API Endpoint
- ✅ GeoIP & IP Intelligence
- ✅ Threat Intelligence (AbuseIPDB, VirusTotal, Shodan)
- ✅ Live Events Dashboard with Enriched Data

**Features Working:**
- Full enrichment pipeline: Event → GeoIP → Threat Intel → Dashboard
- Interactive events table with filtering and search
- Color-coded threat levels and country flags
- Proxy/VPN/Tor detection indicators

**Reference:** `docs/PROJECT_PLAN.md`

---

## 🆘 Troubleshooting

### Server Won't Start
```bash
# Check if port 8081 is in use
lsof -i :8081

# Check if MySQL is running
docker ps | grep mysql
```

### Connection Errors
```bash
# Test database connection
python3 scripts/db_helper.py stats

# Check .env file
cat .env | grep DB_
```

### API Not Working
```bash
# Check server is running
curl http://localhost:8081/api/events/health

# Verify agent exists
python3 scripts/db_helper.py agents

# Check API key
python3 scripts/create_test_agent.py
```

---

## 📞 Quick Commands Cheat Sheet

```bash
# Activate environment
source /home/rana-workspace/ssh_guardian_2.0/venv/bin/activate

# Start server
python3 src/dashboard/server.py

# Check schema
python3 scripts/db_schema_check.py

# DB stats
python3 scripts/db_helper.py stats

# Recent events
python3 scripts/db_helper.py events 10

# Create agent
python3 scripts/create_test_agent.py

# Test API health
curl http://localhost:8081/api/events/health

# View logs
tail -f logs/server.log  # (if logging to file)
```

---

## 🔗 Useful Paths

```
/home/rana-workspace/ssh_guardian_v3.0/
├── src/
│   ├── dashboard/          # Dashboard server
│   ├── api/               # API endpoints
│   └── core/              # Core modules
├── dbs/
│   ├── connection.py      # DB connection pool
│   └── migrations/        # SQL migration files
├── scripts/               # Utility scripts
├── docs/                  # Documentation
└── .env                   # Environment config
```
