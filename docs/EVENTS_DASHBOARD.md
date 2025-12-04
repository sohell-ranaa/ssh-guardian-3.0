# SSH Guardian v3.0 - Events Dashboard Documentation

**Last Updated:** 2025-12-04

---

## Overview

The Live Events Dashboard displays SSH authentication events enriched with GeoIP location data and threat intelligence from multiple sources (AbuseIPDB, VirusTotal, Shodan).

---

## Features

### 📊 Real-time Event Display
- Table view of authentication events with full enrichment data
- Automatic loading when page is accessed
- Manual refresh capability

### 🔍 Filtering & Search
- **Search**: Filter by IP address or username
- **Event Type Filter**: failed, successful, invalid
- **Threat Level Filter**: clean, low, medium, high, critical

### 📄 Pagination
- 50 events per page (configurable)
- Previous/Next navigation
- Shows total count and current range

### 🎨 Visual Indicators
- **Color-coded threat badges**: Green (clean), Blue (low), Orange (medium), Red (high), Dark red (critical)
- **Event status colors**: Red (failed), Green (successful), Orange (invalid)
- **Country flags**: Emoji flags for each country
- **Security indicators**: 🔒 Proxy, 🔐 VPN, 🧅 Tor

---

## Data Displayed

### Event Information
- **Timestamp**: Date and time of event
- **IP Address**: Source IP with security flags
- **Location**: Country flag + City, Country
- **ISP**: Internet Service Provider name
- **Username**: Target username attempted
- **Status**: Failed/Successful/Invalid
- **Server**: Target server hostname
- **Auth Method**: password, publickey, etc.

### GeoIP Enrichment
- Country code, name
- City, region
- Latitude/longitude
- ISP and ASN
- Proxy/VPN/Tor/Datacenter detection

### Threat Intelligence
- **Overall threat level**: clean, low, medium, high, critical
- **Confidence score**: 0.0-1.0
- **AbuseIPDB**: Abuse score (0-100), report count
- **VirusTotal**: Detections (e.g., 0/95)
- **Shodan**: Open ports, vulnerabilities

---

## API Endpoints

### GET /api/dashboard/events/list

Fetch events with enrichment data.

**Query Parameters:**
- `limit` (int): Number of events (default: 50, max: 500)
- `offset` (int): Pagination offset (default: 0)
- `event_type` (string): Filter by type (failed, successful, invalid)
- `threat_level` (string): Filter by threat (clean, low, medium, high, critical)
- `search` (string): Search IP or username

**Response:**
```json
{
  "success": true,
  "events": [
    {
      "id": 5,
      "uuid": "91985126-ff79-4c9d-9efa-e78f2231c25c",
      "timestamp": "2025-12-04T12:00:00",
      "ip": "1.1.1.1",
      "username": "admin",
      "event_type": "failed",
      "auth_method": "password",
      "server": "test-server",
      "port": 22,
      "processing_status": "intel_complete",
      "location": {
        "country_code": "HK",
        "country": "Hong Kong",
        "city": "Hong Kong",
        "region": "Central and Western District",
        "latitude": 22.3193,
        "longitude": 114.1693,
        "isp": "Cloudflare, Inc",
        "is_proxy": false,
        "is_vpn": false,
        "is_tor": false
      },
      "threat": {
        "level": "clean",
        "confidence": 0.1,
        "abuseipdb_score": 0,
        "abuseipdb_reports": 458,
        "virustotal_detections": "0/95",
        "shodan_ports": "[80, 443]",
        "shodan_vulns": "[]"
      },
      "agent": {
        "name": "Test Agent 01",
        "hostname": "test-server-01"
      }
    }
  ],
  "pagination": {
    "total": 5,
    "limit": 50,
    "offset": 0,
    "has_more": false
  }
}
```

### GET /api/dashboard/events/stats

Get event statistics.

**Response:**
```json
{
  "success": true,
  "stats": {
    "total_events": 5,
    "events_by_type": {
      "failed": 4,
      "successful": 1
    },
    "threat_distribution": {
      "clean": 3,
      "low": 1,
      "medium": 1
    },
    "recent_24h": 5,
    "top_attacking_ips": [
      {
        "source_ip_text": "192.168.1.100",
        "attempts": 15,
        "overall_threat_level": "medium",
        "country_name": "United States"
      }
    ]
  }
}
```

---

## Implementation Details

### Files Created

1. **src/dashboard/routes/events_routes.py** (270 lines)
   - Events API routes
   - Database queries with JOINs
   - Filtering and pagination logic
   - Separate file, doesn't affect other routes

2. **Dashboard UI** (Added to templates/dashboard.html)
   - Live Events page section
   - Filter controls
   - Events table
   - JavaScript for data fetching and rendering

3. **Server Integration** (src/dashboard/server.py)
   - Registered events_routes blueprint

### Database Schema Used

The API queries join multiple tables:

```sql
SELECT
    ae.*,
    geo.country_code, geo.country_name, geo.city, geo.isp, geo.is_proxy, geo.is_vpn, geo.is_tor,
    ti.overall_threat_level, ti.threat_confidence, ti.abuseipdb_score, ti.virustotal_positives,
    ag.display_name as agent_name, ag.hostname as agent_hostname
FROM auth_events ae
LEFT JOIN ip_geolocation geo ON ae.geo_id = geo.id
LEFT JOIN ip_threat_intelligence ti ON ae.source_ip_text = ti.ip_address_text
LEFT JOIN agents ag ON ae.agent_id = ag.id
ORDER BY ae.timestamp DESC
```

### JavaScript Functions

- `loadEvents()`: Fetch and display events
- `getThreatBadge(level)`: Generate threat badge HTML
- `getStatusBadge(status)`: Generate status badge HTML
- `getFlagEmoji(countryCode)`: Convert country code to emoji flag
- `formatTimestamp(timestamp)`: Format ISO date to local time
- `showPage(pageName)`: Handle page navigation

---

## Usage Example

### Access Dashboard
1. Navigate to http://localhost:8081
2. Login with credentials
3. Click **Auth Events** in sidebar
4. Click **Live Events**

### Filter Events
```
Search: "192.168"
Event Type: "failed"
Threat Level: "medium"
Click "Refresh"
```

### View Details
Each row shows:
- Time: 12/4/2025, 12:00:00 PM
- IP: 1.1.1.1 (with flags if proxy/VPN/Tor)
- Location: 🇭🇰 Hong Kong, HK + ISP
- Username: admin
- Status: failed (red)
- Threat: CLEAN (green badge) + Abuse: 0 | VT: 0/95
- Details: Server: test-server, Method: password

---

## Testing

### Test with curl

```bash
# List events
curl http://localhost:8081/api/dashboard/events/list?limit=5

# Filter by threat level
curl "http://localhost:8081/api/dashboard/events/list?threat_level=clean&limit=10"

# Search IP
curl "http://localhost:8081/api/dashboard/events/list?search=1.1.1.1"

# Get statistics
curl http://localhost:8081/api/dashboard/events/stats
```

### Test in Browser
1. Open http://localhost:8081 and login
2. Navigate to Live Events page
3. Try filters and search
4. Check browser console for any errors
5. Verify all enrichment data displays

---

## Enrichment Pipeline

Full end-to-end flow:

```
1. Event Submitted
   ↓ (via /api/events/submit)

2. Event Stored in auth_events
   ↓ (processing_status: pending)

3. GeoIP Enrichment
   ↓ (lookup IP, store in ip_geolocation)
   ↓ (update geo_id, processing_status: geoip_complete)

4. Threat Intelligence Enrichment
   ↓ (check AbuseIPDB, VirusTotal, Shodan)
   ↓ (store in ip_threat_intelligence)
   ↓ (processing_status: intel_complete)

5. Display in Dashboard
   ↓ (JOIN all tables)
   ↓ (show enriched data)
```

---

## Configuration

### Page Size
Default: 50 events per page

To change, edit in `dashboard.html`:
```javascript
const pageSize = 50;  // Change to desired value
```

### API Timeout
Default: Browser default (usually 30s)

To add timeout in fetch:
```javascript
const response = await fetch(url, {
    signal: AbortSignal.timeout(10000)  // 10 second timeout
});
```

---

## Future Enhancements

Planned features (Phase 8+):

1. **Real-time Updates**
   - WebSocket/SSE for live event streaming
   - Auto-refresh without page reload
   - New event notifications

2. **Event Details Modal**
   - Click row to see full details
   - Raw log line display
   - Full threat intelligence report

3. **Visualizations**
   - Geographic map of attacks
   - Timeline chart
   - Attack pattern graphs

4. **Export**
   - CSV export
   - JSON export
   - PDF reports

---

## Troubleshooting

### Events Not Loading

Check:
```bash
# Verify API is accessible
curl http://localhost:8081/api/dashboard/events/list

# Check database connection
python3 scripts/db_helper.py stats

# Check server logs
# (Look at running server console output)
```

### No Enrichment Data

```bash
# Verify GeoIP data exists
python3 -c "
from dbs.connection import get_connection
conn = get_connection()
cursor = conn.cursor()
cursor.execute('SELECT COUNT(*) FROM ip_geolocation')
print('GeoIP records:', cursor.fetchone()[0])
cursor.execute('SELECT COUNT(*) FROM ip_threat_intelligence')
print('Threat intel records:', cursor.fetchone()[0])
"
```

### Filters Not Working

Check browser console for JavaScript errors:
1. Open browser DevTools (F12)
2. Go to Console tab
3. Look for errors when clicking filters
4. Check Network tab for failed API requests

---

## Performance Considerations

- **Database Indexes**: Ensure indexes on:
  - `auth_events.timestamp` (for ORDER BY)
  - `auth_events.source_ip_text` (for JOINs)
  - `auth_events.event_type` (for filtering)
  - `ip_threat_intelligence.overall_threat_level` (for filtering)

- **Caching**:
  - GeoIP: 30-day cache
  - Threat Intel: 7-day cache
  - Reduces API calls significantly

- **Pagination**:
  - Limit max page size to 500
  - Use offset-based pagination
  - Consider cursor-based pagination for large datasets

---

## Security Notes

- Events API requires authentication (session-based)
- No API key needed for dashboard routes (internal use)
- Agent API uses separate API key authentication
- All queries use parameterized statements (SQL injection safe)
- No user input directly in SQL queries

---

## Support

For issues or questions:
1. Check server console logs
2. Review `docs/PROJECT_PLAN.md`
3. Check `QUICK_REFERENCE.md`
4. Verify database schema: `python3 scripts/db_schema_check.py`
