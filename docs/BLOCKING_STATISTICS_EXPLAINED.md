# SSH Guardian v3.0 - Blocking Statistics Explained

## Date: December 6, 2025

---

## Understanding Blocking Statistics

### Problem Statement

**User Question:** "I ran simulation many times but in Blocking Rules I do not see any statistics like Triggered: 0 times, IPs Blocked: 0"

### Answer

The **Blocking Rules** page shows **rule-specific statistics**, not global blocking statistics. When you manually block IPs from the Simulation page, those blocks are created as **manual blocks** and don't increment individual rule counters.

---

## Two Types of IP Blocks

### 1. **Manual Blocks**
- **Source:** User-initiated blocks from Simulation page, IP Blocks page, or API
- **block_source:** `'manual'`
- **blocking_rule_id:** `NULL` (no rule associated)
- **Impact:** Creates IP block record but **does NOT increment rule statistics**

**Example:**
```javascript
// From Simulation page -> "Add to Blocklist" button
{
  "ip_address": "185.220.101.1",
  "reason": "Tor Exit Node Attack - Demo Scenario",
  "block_source": "manual",
  "blocking_rule_id": null  // No rule involved
}
```

### 2. **Rule-Based Blocks**
- **Source:** Automatic blocking triggered by evaluation of blocking rules
- **block_source:** `'rule_based'`
- **blocking_rule_id:** Set to the ID of the rule that triggered the block
- **Impact:** Creates IP block record AND **increments rule statistics**

**Example:**
```javascript
// Automatically triggered by "Brute Force Protection" rule
{
  "ip_address": "45.142.212.61",
  "reason": "Exceeded 5 failed attempts in 10 minutes",
  "block_source": "rule_based",
  "blocking_rule_id": 3  // Links to specific rule
}
```

---

## Rule Statistics Fields

Each blocking rule tracks:

| Field | Description | When Incremented |
|-------|-------------|------------------|
| `times_triggered` | How many times this rule evaluated to TRUE and triggered a block | When `block_ip()` is called with this `blocking_rule_id` |
| `ips_blocked_total` | How many unique IPs have been blocked by this rule | Same as above |
| `last_triggered_at` | Timestamp of last time this rule triggered | Same as above |

**Key Point:** These fields are ONLY updated when `blocking_rule_id` is provided to the `block_ip()` function.

---

## Where to See Your Simulation Blocks

### Option 1: **IP Management → Blocked IPs** (Recommended)

Navigate to: **IP Management → Blocked IPs** in the sidebar

This page shows:
- ✅ **All blocked IPs** (manual + automatic)
- ✅ Block source (manual, rule_based, api_reputation, etc.)
- ✅ Block reason
- ✅ When they were blocked
- ✅ Status (active/inactive)
- ✅ **Filter by source** - Select "Manual" to see only simulation blocks

**Steps:**
1. Open dashboard
2. Click **IP Management** in sidebar
3. Click **Blocked IPs**
4. Use filter: **All Sources → Manual**
5. See all your simulation blocks!

### Option 2: **Blocking Rules → Overall Statistics** (NEW)

The Blocking Rules page now shows a **summary statistics card** at the top:

- **Total Blocks (All Time)** - All blocks from all sources
- **Currently Active** - Active blocks right now
- **Manual Blocks** - Blocks from Simulation/manual actions
- **Rule-Based Blocks** - Blocks from automatic rules
- **Last 24 Hours** - Recent blocking activity

This helps you see the **big picture** of all blocking activity.

---

## Implementation Details

### Database Schema

**ip_blocks table:**
```sql
CREATE TABLE ip_blocks (
    id INT PRIMARY KEY AUTO_INCREMENT,
    ip_address_text VARCHAR(45),
    block_reason TEXT,
    block_source VARCHAR(50),           -- 'manual' or 'rule_based'
    blocking_rule_id INT NULL,          -- NULL for manual blocks
    trigger_event_id INT NULL,
    failed_attempts INT DEFAULT 0,
    threat_level VARCHAR(20),
    is_active BOOLEAN DEFAULT TRUE,
    blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ...
);
```

**blocking_rules table:**
```sql
CREATE TABLE blocking_rules (
    id INT PRIMARY KEY AUTO_INCREMENT,
    rule_name VARCHAR(255),
    times_triggered INT DEFAULT 0,      -- Incremented on rule-based blocks
    ips_blocked_total INT DEFAULT 0,    -- Incremented on rule-based blocks
    last_triggered_at TIMESTAMP NULL,   -- Updated on rule-based blocks
    ...
);
```

### Code Flow

**Manual Block (Simulation):**
```python
# simulation.html -> blockIPWithModal() -> /api/dashboard/blocking/manual
block_ip_manual(
    ip_address="185.220.101.1",
    reason="Tor Exit Node Attack",
    block_source='manual',
    blocking_rule_id=None  # No rule
)

# Result: ip_blocks record created, but blocking_rules NOT updated
```

**Automatic Rule-Based Block:**
```python
# evaluate_rules_for_ip() detects rule match
block_ip(
    ip_address="45.142.212.61",
    block_reason="Exceeded threshold",
    block_source='rule_based',
    blocking_rule_id=3  # Rule ID provided
)

# In ip_operations.py lines 150-158:
if blocking_rule_id:
    cursor.execute("""
        UPDATE blocking_rules
        SET times_triggered = times_triggered + 1,
            ips_blocked_total = ips_blocked_total + 1,
            last_triggered_at = NOW()
        WHERE id = %s
    """, (blocking_rule_id,))

# Result: Both ip_blocks AND blocking_rules updated
```

---

## API Endpoints

### Get Overall Statistics
**Endpoint:** `GET /api/dashboard/blocking/stats`

**Response:**
```json
{
  "success": true,
  "stats": {
    "total_blocks": 127,
    "active_blocks": 45,
    "blocks_by_source": {
      "manual": 89,           // <-- Your simulation blocks
      "rule_based": 32,
      "api_reputation": 6
    },
    "recent_24h": 15,
    "top_blocked_ips": [...]
  }
}
```

### Get All Blocked IPs
**Endpoint:** `GET /api/dashboard/blocking/blocks/list?block_source=manual`

**Response:**
```json
{
  "success": true,
  "blocks": [
    {
      "id": 124,
      "ip_address": "185.220.101.1",
      "reason": "Tor Exit Node Attack - Demo Scenario",
      "source": "manual",
      "is_active": true,
      "blocked_at": "2025-12-06T10:30:15Z"
    },
    ...
  ]
}
```

### Get Blocking Rules
**Endpoint:** `GET /api/dashboard/blocking/rules/list`

**Response:**
```json
{
  "success": true,
  "rules": [
    {
      "id": 1,
      "rule_name": "Brute Force Protection",
      "times_triggered": 0,      // <-- Only increments on automatic blocks
      "ips_blocked_total": 0,    // <-- Same here
      "last_triggered_at": null,
      "is_enabled": true
    }
  ]
}
```

---

## Common Misconceptions

### ❌ WRONG: "Blocking Rules shows all blocks"
**Reality:** Blocking Rules shows **rule-triggered blocks only**, not manual blocks.

### ❌ WRONG: "Simulation blocks don't work"
**Reality:** Simulation blocks work perfectly - they're stored in `ip_blocks` table with `block_source='manual'`.

### ❌ WRONG: "times_triggered should count all blocks"
**Reality:** `times_triggered` counts only automatic rule evaluations that resulted in blocks.

### ✅ CORRECT: "Manual blocks are separate from rule statistics"
**Why:** This is intentional design to distinguish between:
- **Proactive blocks** (rules automatically detecting threats)
- **Reactive blocks** (humans manually blocking IPs)

---

## How to Test Rule-Based Blocking

If you want to see rule statistics increment, you need to:

1. **Create a Blocking Rule**
   - Go to **Blocking Rules** page
   - Click **Create Rule**
   - Example: "Brute Force Protection"
     - Type: `brute_force`
     - Failed Attempts: `5`
     - Time Window: `10` minutes

2. **Trigger the Rule**
   - Create **actual failed login events** (not demo scenarios)
   - SSH to your server with wrong password 5+ times in 10 minutes
   - OR use the event generator to create real events

3. **Rule Evaluates Automatically**
   - The blocking engine runs periodically
   - Detects IP exceeds threshold
   - Calls `block_ip()` with `blocking_rule_id=1`
   - Rule statistics increment

4. **Check Statistics**
   - Refresh Blocking Rules page
   - See `times_triggered: 1`, `ips_blocked_total: 1`

---

## Summary

**Why you see "Triggered: 0 times, IPs Blocked: 0":**
- You're blocking IPs **manually** from Simulation page
- Manual blocks don't have a `blocking_rule_id`
- Rule statistics only count **automatic rule-triggered blocks**

**Where your simulation blocks are:**
- ✅ Stored in `ip_blocks` table with `block_source='manual'`
- ✅ Visible on **IP Blocks** page (filter by "Manual")
- ✅ Counted in **Overall Statistics** on Blocking Rules page
- ✅ Working correctly - they ARE blocking the IPs!

**To see rule statistics increment:**
- Create actual blocking rules
- Trigger them with real events (not demo scenarios)
- Or integrate demo scenarios with rule evaluation (Phase 2 enhancement)

---

## Future Enhancement Ideas

### Phase 2: Integrate Simulations with Rules

**Option 1:** Add "Trigger Rule Evaluation" checkbox to simulation
```javascript
// After running demo scenario
if (userSelectedTriggerRules) {
    await fetch('/api/blocking/evaluate', {
        method: 'POST',
        body: JSON.stringify({ ip_address: scenarioIP })
    });
    // This would evaluate rules and potentially increment stats
}
```

**Option 2:** Create "Simulation Rule" type
- Special rule that matches demo scenario IPs
- Auto-triggers during simulation runs
- Shows in rule statistics

**Option 3:** Separate "Simulation Statistics" section
- Track simulation-specific metrics
- Don't mix with production rule statistics
- Keep them separate for clarity

---

## Contact & Support

**Server Access:**
- Dashboard: https://ssh-guardian.rpu.solutions/dashboard
- Port: 8081
- Database: ssh_guardian_v3

**Relevant Files:**
- `/src/core/blocking/ip_operations.py` - Block IP logic (lines 150-158 for rule stats)
- `/src/dashboard/routes/blocking_routes.py` - API endpoints
- `/src/dashboard/templates/pages/rules.html` - Blocking Rules page with new stats card
- `/src/dashboard/static/js/modules/blocking_rules_page.js` - Frontend logic
- `/src/dashboard/templates/pages/ip_blocks.html` - Blocked IPs page

---

**🎯 TL;DR:**

Your simulation blocks ARE working and stored in the database. They just don't show in **individual rule statistics** because they're **manual blocks**, not **rule-triggered blocks**.

Check **IP Management → Blocked IPs** to see all your simulation blocks!

The new **Overall Statistics** card on Blocking Rules page now shows you the total count of manual blocks vs rule-based blocks.
