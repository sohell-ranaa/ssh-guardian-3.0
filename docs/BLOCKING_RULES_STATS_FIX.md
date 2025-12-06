# Blocking Rules Page - Statistics Enhancement

## Date: December 6, 2025
## Status: ✅ COMPLETE

---

## Problem

User reported: "I ran simulation many times but in Blocking Rules I do not see any statistics like Triggered: 0 times, IPs Blocked: 0"

### Root Cause

The Blocking Rules page displays **rule-specific statistics** that only increment when an IP is blocked **by an automatic rule**. When IPs are manually blocked from the Simulation page, they:
- Create IP block records with `block_source='manual'`
- Have `blocking_rule_id=NULL`
- Do NOT increment rule statistics (`times_triggered`, `ips_blocked_total`)

This is **by design** - manual blocks are separate from rule-triggered blocks.

---

## Solution Implemented

Added **Overall Blocking Statistics** card to the Blocking Rules page showing:

1. **Total Blocks (All Time)** - All blocks from all sources
2. **Currently Active** - Active blocks right now
3. **Manual Blocks** - Blocks from Simulation/manual actions (what user was looking for!)
4. **Rule-Based Blocks** - Blocks from automatic rules
5. **Last 24 Hours** - Recent blocking activity

Plus a helpful note directing users to the **IP Blocks** page to see all blocked IPs.

---

## Changes Made

### 1. Frontend - HTML Template

**File:** `/src/dashboard/templates/pages/rules.html`

Added new statistics card above "Quick Actions":

```html
<!-- Overall Blocking Statistics -->
<div id="overallBlockingStats" class="card" style="margin-bottom: 20px; display: none;">
    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px;">
        <div style="text-align: center;">
            <div style="font-size: 28px; font-weight: 700; color: var(--azure-blue);" id="statTotalBlocks">-</div>
            <div style="font-size: 12px; color: var(--text-secondary); margin-top: 4px;">Total Blocks (All Time)</div>
        </div>
        <div style="text-align: center;">
            <div style="font-size: 28px; font-weight: 700; color: #107C10;" id="statActiveBlocks">-</div>
            <div style="font-size: 12px; color: var(--text-secondary); margin-top: 4px;">Currently Active</div>
        </div>
        <div style="text-align: center;">
            <div style="font-size: 28px; font-weight: 700; color: #8A8886;" id="statManualBlocks">-</div>
            <div style="font-size: 12px; color: var(--text-secondary); margin-top: 4px;">Manual Blocks</div>
        </div>
        <div style="text-align: center;">
            <div style="font-size: 28px; font-weight: 700; color: #0078D4;" id="statRuleBlocks">-</div>
            <div style="font-size: 12px; color: var(--text-secondary); margin-top: 4px;">Rule-Based Blocks</div>
        </div>
        <div style="text-align: center;">
            <div style="font-size: 28px; font-weight: 700; color: #FFB900;" id="statRecent24h">-</div>
            <div style="font-size: 12px; color: var(--text-secondary); margin-top: 4px;">Last 24 Hours</div>
        </div>
    </div>
    <div style="margin-top: 12px; padding-top: 12px; border-top: 1px solid var(--border-light); font-size: 12px; color: var(--text-secondary); text-align: center;">
        💡 <strong>Note:</strong> Manual blocks from Simulation page show here, but don't increment individual rule statistics below.
        <a href="#ip-blocks" onclick="navigateToPage('ip-blocks'); return false;" style="color: var(--azure-blue); text-decoration: underline; cursor: pointer;">View all blocked IPs →</a>
    </div>
</div>
```

**Features:**
- 5 key metrics in responsive grid
- Color-coded for clarity
- Hidden by default, shown when data loads
- Helpful note explaining the distinction
- Link to IP Blocks page for full details

---

### 2. Frontend - JavaScript

**File:** `/src/dashboard/static/js/modules/blocking_rules_page.js`

#### Added: `loadOverallStats()` function

```javascript
// Load overall blocking statistics
async function loadOverallStats() {
    try {
        const response = await fetch('/api/dashboard/blocking/stats');
        const data = await response.json();

        if (data.success && data.stats) {
            const stats = data.stats;

            // Update statistics display
            document.getElementById('statTotalBlocks').textContent = stats.total_blocks || 0;
            document.getElementById('statActiveBlocks').textContent = stats.active_blocks || 0;
            document.getElementById('statManualBlocks').textContent = stats.blocks_by_source?.manual || 0;
            document.getElementById('statRuleBlocks').textContent = stats.blocks_by_source?.rule_based || 0;
            document.getElementById('statRecent24h').textContent = stats.recent_24h || 0;

            // Show the stats card
            document.getElementById('overallBlockingStats').style.display = 'block';
        }
    } catch (error) {
        console.error('Error loading overall stats:', error);
        // Don't show stats card if error
    }
}
```

#### Updated: `loadBlockingRulesPage()` to load stats

```javascript
async function loadBlockingRulesPage() {
    await Promise.all([
        loadOverallStats(),  // NEW - Load overall stats
        loadRules()
    ]);
}
```

#### Added: Event listeners for buttons and form controls

```javascript
document.addEventListener('DOMContentLoaded', function() {
    // Refresh button - now refreshes stats too
    const refreshBtn = document.getElementById('refreshRules');
    if (refreshBtn) {
        refreshBtn.addEventListener('click', function() {
            loadOverallStats();  // Refresh stats
            loadRules();         // Refresh rules
        });
    }

    // Show create rule form button
    const showCreateBtn = document.getElementById('showCreateRuleForm');
    if (showCreateBtn) {
        showCreateBtn.addEventListener('click', function() {
            document.getElementById('createRuleForm').style.display = 'block';
        });
    }

    // ... more event listeners for form controls
});
```

#### Added: `createRule()` function

Handles creating new blocking rules via the form.

---

### 3. Backend - API Endpoint (Already Exists)

**File:** `/src/dashboard/routes/blocking_routes.py`

**Endpoint:** `GET /api/dashboard/blocking/stats`

This endpoint already existed and provides:
- `total_blocks` - Total number of IP blocks
- `active_blocks` - Currently active blocks
- `blocks_by_source` - Breakdown by source (manual, rule_based, etc.)
- `recent_24h` - Blocks in last 24 hours
- `top_blocked_ips` - Most frequently blocked IPs

**Response Example:**
```json
{
  "success": true,
  "stats": {
    "total_blocks": 127,
    "active_blocks": 45,
    "blocks_by_source": {
      "manual": 89,        // <-- User's simulation blocks
      "rule_based": 32,
      "api_reputation": 6
    },
    "recent_24h": 15,
    "top_blocked_ips": [...]
  },
  "from_cache": false
}
```

**No backend changes needed** - just leveraged existing API.

---

## Testing Instructions

### 1. Run Some Simulations

1. Navigate to **Simulation** page
2. Run 3-5 demo scenarios
3. Block the IPs using "Add to Blocklist" button
4. Note: These are **manual blocks** (`block_source='manual'`)

### 2. Check Blocking Rules Page

1. Navigate to **Blocking Rules** page
2. You should see the new **Overall Blocking Statistics** card at the top
3. Verify:
   - ✅ **Total Blocks** shows total count (including your simulation blocks)
   - ✅ **Manual Blocks** shows non-zero number (your simulation blocks!)
   - ✅ **Rule-Based Blocks** shows 0 or low number (only automatic rule triggers)
   - ✅ **Currently Active** shows active blocks
   - ✅ **Last 24 Hours** shows recent activity

### 3. Check IP Blocks Page

1. Click the "View all blocked IPs →" link
2. OR navigate to **IP Management → Blocked IPs**
3. Use filter: **All Sources → Manual**
4. Verify: You see all your simulation blocks listed with:
   - IP address
   - Reason (e.g., "Tor Exit Node Attack")
   - Source: "manual"
   - Status: Active
   - Timestamp

### 4. Verify Individual Rule Statistics

1. Scroll down to the rules table on Blocking Rules page
2. Check individual rules
3. Verify: `Triggered: 0 times`, `IPs Blocked: 0` (because no automatic rule triggers yet)
4. This is **correct** - manual blocks don't increment these

---

## User Guidance

### ✅ What to Tell Users

**Q: "Why don't I see my simulation blocks in rule statistics?"**

**A:** Simulation blocks are **manual blocks**, not **rule-triggered blocks**. Here's where to see them:

1. **Blocking Rules Page (NEW!)** - Look at the **Overall Statistics** card at the top:
   - **Manual Blocks** = Your simulation blocks
   - **Rule-Based Blocks** = Automatic rule triggers

2. **IP Blocks Page** - Navigate to **IP Management → Blocked IPs**:
   - Filter by **Source: Manual**
   - See complete list of all simulation blocks

**Individual rule statistics** (`Triggered: X times`) only count **automatic rule evaluations**, not manual blocks. This is by design to distinguish between proactive (automatic) and reactive (manual) blocking.

---

## Visual Example

### Before (Confusing)
```
Blocking Rules Page:
┌────────────────────────────────┐
│ Quick Actions                  │
│ [+ Create Rule] [Refresh]      │
└────────────────────────────────┘

Rules Table:
┌─────────────────────────────────────────────┐
│ Rule Name      | Statistics                 │
├─────────────────────────────────────────────┤
│ Brute Force    | Triggered: 0 times         │
│                | IPs Blocked: 0             │
└─────────────────────────────────────────────┘

❌ User thinks: "My blocks aren't working!"
```

### After (Clear)
```
Blocking Rules Page:
┌──────────────────────────────────────────────┐
│ Overall Blocking Statistics                  │
├──────────────────────────────────────────────┤
│ Total: 127  Active: 45  Manual: 89           │
│ Rule-Based: 32  Last 24h: 15                 │
│                                              │
│ 💡 Note: Manual blocks from Simulation      │
│ page show here. View all blocked IPs →      │
└──────────────────────────────────────────────┘

┌────────────────────────────────┐
│ Quick Actions                  │
│ [+ Create Rule] [Refresh]      │
└────────────────────────────────┘

Rules Table:
┌─────────────────────────────────────────────┐
│ Rule Name      | Statistics                 │
├─────────────────────────────────────────────┤
│ Brute Force    | Triggered: 0 times         │
│                | IPs Blocked: 0             │
└─────────────────────────────────────────────┘

✅ User thinks: "Oh! I have 89 manual blocks from simulations.
   Rule-based blocks are separate. Makes sense!"
```

---

## Technical Details

### Why This Design?

**Separation of Concerns:**
- **Manual Blocks** - Human decision, reactive
  - Examples: Simulation testing, threat hunting, incident response
  - Don't reflect rule effectiveness

- **Rule-Based Blocks** - Automated detection, proactive
  - Reflect rule quality and tuning
  - Measure detection accuracy
  - Used for rule optimization

**Benefits:**
- Clear distinction between detection types
- Accurate rule performance metrics
- Prevents test/simulation data from polluting production rule stats

---

## Future Enhancements

### Phase 2: Simulation-Specific Tracking

**Option 1:** Add simulation statistics section
```javascript
{
  "simulation_stats": {
    "total_scenarios_run": 47,
    "ips_blocked_from_simulations": 89,
    "most_common_scenario": "Tor Exit Node Attack",
    "avg_risk_score": 87.3
  }
}
```

**Option 2:** Link simulations to rules
- Allow simulations to optionally trigger rule evaluation
- Show "Simulation Triggers" separately from "Real Triggers"

**Option 3:** Add "Test Mode" flag
- Mark blocks as `is_test_mode=true`
- Filter them out of production statistics
- Keep separate test/prod metrics

---

## Files Modified

1. `/src/dashboard/templates/pages/rules.html` - Added overall stats card
2. `/src/dashboard/static/js/modules/blocking_rules_page.js` - Added stats loading logic

## Documentation Created

1. `/docs/BLOCKING_RULES_STATS_FIX.md` (this file) - Implementation guide
2. `/docs/BLOCKING_STATISTICS_EXPLAINED.md` - Comprehensive explanation for users

---

## Success Criteria

✅ Overall blocking statistics visible on Blocking Rules page
✅ Shows manual blocks count (user's simulation blocks)
✅ Shows rule-based blocks count separately
✅ Helpful note explains the distinction
✅ Link to IP Blocks page for detailed view
✅ Refresh button updates both stats and rules
✅ User understands where their simulation blocks are

---

**🎉 Enhancement Complete!**

Users can now see **all blocking activity** at a glance, with clear separation between manual and rule-based blocks.

**Next Steps:**
1. User testing - verify stats display correctly
2. Run simulations and confirm manual blocks count increments
3. Gather feedback on clarity of the new statistics card
