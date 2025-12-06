# Events Live Page - Updates

## Changes Made

### ✅ 1. Added Seconds to Timestamps

**Location:** `src/dashboard/static/js/modules/events_live_page.js` (lines 600-629)

**Changes:**
- Updated `formatTimestamp()` function to include seconds
- Works with TimeSettings module
- Falls back to browser locale with seconds if TimeSettings unavailable

**Display Format:**
- Before: `12/06/2025 15:30`
- After: `12/06/2025 15:30:45`

### ✅ 2. Added Overview Statistics Section

**Location:** `src/dashboard/templates/pages/events_live.html` (lines 18-43)

**Features:**
- 5 key metrics displayed at the top
- Responsive grid layout
- Color-coded statistics
- Updates based on filtered results

**Metrics:**
1. **Total Events** - Total number of events shown
2. **Failed** - Failed authentication attempts (red)
3. **Successful** - Successful authentications (green)
4. **Unique IPs** - Number of unique IP addresses
5. **High Threat** - Events with high/critical threat level (dark red)

### ✅ 3. Added IP Filter (Text Input)

**Location:** `src/dashboard/templates/pages/events_live.html` (line 51-52)

**Features:**
- Separate text input for IP filtering
- Search/filter by partial IP address
- Press Enter to apply filter
- Independent from username search

**Usage:**
```
Filter by IP: [192.168.1._____] (Enter to search)
```

### ✅ 4. Added Server Filter (Dropdown)

**Location:** `src/dashboard/templates/pages/events_live.html` (lines 54-57)

**Features:**
- Dropdown populated dynamically from events
- Shows unique server hostnames
- Auto-populated on page load
- "All Servers" option to clear filter

**Populated by:** `populateServerFilter()` function in JS

### ✅ 5. Updated Backend to Support New Filters

**Location:** `src/dashboard/routes/events_routes.py` (lines 81-141)

**Changes:**
- Added `ip` query parameter support
- Added `server` query parameter support
- Updated WHERE clause construction
- Updated cache key to include new filters

**API Parameters:**
```
GET /api/dashboard/events/list?
  limit=50
  &offset=0
  &search=username      (username search)
  &ip=192.168.1        (IP filter)
  &server=hostname     (server filter)
  &event_type=failed
  &threat_level=high
  &agent_id=10
```

### ✅ 6. Overview Updates with Filters

**Location:** `src/dashboard/static/js/modules/events_live_page.js` (lines 527-562)

**Function:** `updateOverviewStats(events)`

**Behavior:**
- Calculates stats from currently filtered events
- Updates in real-time when filters change
- Shows statistics relevant to current view only
- Counts unique IPs, event types, threat levels

## File Changes Summary

| File | Changes | Lines |
|------|---------|-------|
| `events_live.html` | Added overview section, IP filter, server filter | 18-88 |
| `events_live_page.js` | Updated timestamp format, added filters, overview stats | 527-896 |
| `events_routes.py` | Added IP & server filter support | 81-141 |

## Features

### Filter Combinations

All filters work together:
```
Search: "admin"           (username contains "admin")
IP Filter: "192.168"      (IP starts with "192.168")
Server: "web-server-01"   (specific server)
Event Type: "failed"      (failed attempts only)
Threat Level: "high"      (high threat only)
Agent: "Agent 10"         (from specific agent)
```

### Overview Statistics Behavior

The overview section updates based on ALL active filters:

**Example:**
- Filter: IP = "192.168.1.100", Event Type = "failed"
- Overview shows: Only statistics for failed events from that specific IP
- Total Events: 15 (15 failed attempts from that IP)
- Failed: 15
- Successful: 0
- Unique IPs: 1
- High Threat: 8

### Timestamp Display

**With seconds enabled:**
```
Time Column:
┌──────────────────────┐
│ 2025-12-06 15:30:45 │
│ 2025-12-06 15:30:42 │
│ 2025-12-06 15:30:39 │
└──────────────────────┘
```

Better precision for:
- Analyzing attack patterns
- Identifying rapid-fire attempts
- Troubleshooting timing issues

## UI Layout

### Overview Section
```
┌─────────────────────────────────────────────────────────────┐
│ Overview                                                     │
├─────────────┬─────────────┬─────────────┬─────────────┬─────┤
│ Total       │ Failed      │ Successful  │ Unique IPs  │ High│
│ Events      │             │             │             │Threa│
│ 1,234       │ 987         │ 247         │ 156         │ 89  │
└─────────────┴─────────────┴─────────────┴─────────────┴─────┘
```

### Filters Section
```
┌─────────────────────────────────────────────────────────────┐
│ [Search username...]  [Filter by IP...]  [All Servers ▼]   │
│ [All Event Types ▼]   [All Threat Levels ▼]  [All Agents ▼]│
│ [▶ Live]  [↻ Refresh]                                       │
└─────────────────────────────────────────────────────────────┘
```

## Testing

### Test New Filters

1. **IP Filter:**
   ```
   Enter: 192.168
   Press Enter
   → Shows only events from IPs starting with "192.168"
   → Overview updates to show stats for those IPs only
   ```

2. **Server Filter:**
   ```
   Select: "web-server-01"
   → Shows only events from that server
   → Overview updates accordingly
   ```

3. **Combined Filters:**
   ```
   IP: 192.168.1.100
   Server: web-server-01
   Event Type: failed
   → Shows failed events from that IP on that server
   → Overview shows precise statistics
   ```

### Test Timestamp Seconds

1. Navigate to Events Live page
2. Check Time column
3. Verify seconds are displayed
4. Verify format matches: `YYYY-MM-DD HH:MM:SS`

### Test Overview

1. Load page without filters
   → Overview shows all events statistics

2. Apply Event Type filter: "failed"
   → Total Events decreases
   → Failed count equals Total
   → Successful becomes 0

3. Add IP filter: "192.168"
   → All stats update to filtered subset
   → Unique IPs shows only matching IPs

## API Examples

### Filter by IP
```bash
curl 'http://localhost:8081/api/dashboard/events/list?ip=192.168.1'
```

### Filter by Server
```bash
curl 'http://localhost:8081/api/dashboard/events/list?server=web-server-01'
```

### Combined Filters
```bash
curl 'http://localhost:8081/api/dashboard/events/list?ip=192.168&server=web-01&event_type=failed'
```

## Browser Compatibility

| Feature | Chrome | Firefox | Safari | Edge |
|---------|--------|---------|--------|------|
| Overview Stats | ✅ | ✅ | ✅ | ✅ |
| IP Filter | ✅ | ✅ | ✅ | ✅ |
| Server Filter | ✅ | ✅ | ✅ | ✅ |
| Timestamp Seconds | ✅ | ✅ | ✅ | ✅ |

## Performance

**Overview Calculation:**
- Runs on client-side
- No additional API calls
- Uses already-loaded events data
- Updates instantly when filters change

**Server Filter Population:**
- Single API call on page load
- Fetches last 1000 events to get servers
- Cached in dropdown
- No performance impact on filtering

## Notes

### Filter Independence

- **Username Search** (`eventSearch`) - Filters by username only
- **IP Filter** (`ipFilter`) - Filters by IP address only
- Both can be used simultaneously
- Both use LIKE query (partial matching)

### Server Filter

- Populated from actual event data
- Shows only servers that have events
- Sorted alphabetically
- Updates when page loads

### Overview Statistics

- **Real-time** - Updates with every filter change
- **Accurate** - Calculated from visible results
- **Fast** - Client-side calculation
- **Responsive** - Adapts to any filter combination

## Summary

**What Was Added:**
- ✅ Seconds to timestamps (HH:MM:SS format)
- ✅ Overview statistics section (5 metrics)
- ✅ IP filter (text input)
- ✅ Server filter (dropdown)
- ✅ Backend support for new filters
- ✅ Overview updates with filters

**What Was NOT Changed:**
- ❌ Existing functionality (all preserved)
- ❌ Event table structure
- ❌ Pagination
- ❌ Other page features
- ❌ Auto-refresh behavior

**Status:** ✅ Complete and ready to use!

**Access:** https://ssh-guardian.rpu.solutions/dashboard#events-live
