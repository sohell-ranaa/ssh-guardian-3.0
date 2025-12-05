# Event Actions API Documentation

API endpoints for Events Live page actionable functions (whitelist, watchlist, notes, reports).

**Base URL:** `/api/dashboard/event-actions`

---

## Whitelist Actions

### 1. Add IP to Whitelist
**Endpoint:** `POST /api/dashboard/event-actions/whitelist`

Add an IP address to the whitelist to bypass security checks.

**Request Body:**
```json
{
  "ip_address": "192.168.1.100",
  "reason": "Trusted server",
  "expires_minutes": 1440  // Optional, default: no expiration
}
```

**Response (201 Created):**
```json
{
  "success": true,
  "whitelist_id": 123,
  "message": "IP 192.168.1.100 added to whitelist"
}
```

**Validations:**
- IP address format must be valid (IPv4 or IPv6)
- IP cannot already be whitelisted

---

### 2. Remove from Whitelist
**Endpoint:** `DELETE /api/dashboard/event-actions/whitelist/<ip_address>`

Remove an IP address from the whitelist.

**Response (200 OK):**
```json
{
  "success": true,
  "message": "IP 192.168.1.100 removed from whitelist"
}
```

---

### 3. Check Whitelist Status
**Endpoint:** `GET /api/dashboard/event-actions/whitelist/check/<ip_address>`

Check if an IP address is currently whitelisted.

**Response (200 OK):**
```json
{
  "success": true,
  "is_whitelisted": true,
  "whitelist_info": {
    "id": 123,
    "reason": "Trusted server",
    "expires_at": "2025-12-06T15:30:00",
    "created_at": "2025-12-05T15:30:00"
  },
  "from_cache": false
}
```

---

## Watchlist Actions

### 4. Add IP to Watchlist
**Endpoint:** `POST /api/dashboard/event-actions/watchlist`

Add an IP address to the watchlist for monitoring.

**Request Body:**
```json
{
  "ip_address": "192.168.1.100",
  "reason": "Suspicious activity",
  "watch_level": "medium",  // low, medium, high, critical
  "notify_on_activity": true,
  "event_id": 12345  // Optional
}
```

**Response (201 Created):**
```json
{
  "success": true,
  "watchlist_id": 456,
  "message": "IP 192.168.1.100 added to watchlist with medium level"
}
```

**Validations:**
- IP address format must be valid
- Watch level must be one of: low, medium, high, critical
- IP cannot already be on watchlist

---

### 5. Remove from Watchlist
**Endpoint:** `DELETE /api/dashboard/event-actions/watchlist/<ip_address>`

Remove an IP address from the watchlist.

**Response (200 OK):**
```json
{
  "success": true,
  "message": "IP 192.168.1.100 removed from watchlist"
}
```

---

### 6. Check Watchlist Status
**Endpoint:** `GET /api/dashboard/event-actions/watchlist/check/<ip_address>`

Check if an IP address is on the watchlist.

**Response (200 OK):**
```json
{
  "success": true,
  "is_watched": true,
  "watchlist_info": {
    "id": 456,
    "reason": "Suspicious activity",
    "level": "medium",
    "notify_on_activity": true,
    "expires_at": null,
    "created_at": "2025-12-05T15:30:00"
  },
  "from_cache": false
}
```

---

## Notes Actions

### 7. Add Note
**Endpoint:** `POST /api/dashboard/event-actions/notes`

Add a note to an event or IP address.

**Request Body (Event Note):**
```json
{
  "note_type": "event",
  "event_id": 12345,
  "note_content": "This is a suspicious event"
}
```

**Request Body (IP Note):**
```json
{
  "note_type": "ip",
  "ip_address": "192.168.1.100",
  "note_content": "Known botnet IP"
}
```

**Response (201 Created):**
```json
{
  "success": true,
  "note_id": 789,
  "note_uuid": "550e8400-e29b-41d4-a716-446655440000",
  "message": "Event note added successfully"
}
```

**Validations:**
- note_type must be "event" or "ip"
- If event note: event_id is required
- If IP note: ip_address is required and must be valid format

---

### 8. Get Notes
**Endpoint:** `GET /api/dashboard/event-actions/notes/<note_type>/<id_or_ip>`

Get all notes for an event or IP address.

**Examples:**
- `/api/dashboard/event-actions/notes/event/12345`
- `/api/dashboard/event-actions/notes/ip/192.168.1.100`

**Response (200 OK):**
```json
{
  "success": true,
  "notes": [
    {
      "id": 789,
      "note_uuid": "550e8400-e29b-41d4-a716-446655440000",
      "content": "This is a suspicious event",
      "is_pinned": false,
      "created_at": "2025-12-05T15:30:00",
      "updated_at": "2025-12-05T15:30:00"
    }
  ],
  "count": 1,
  "from_cache": false
}
```

---

### 9. Delete Note
**Endpoint:** `DELETE /api/dashboard/event-actions/notes/<note_id>`

Delete a note by ID.

**Response (200 OK):**
```json
{
  "success": true,
  "message": "Note deleted successfully"
}
```

---

## Report Actions

### 10. Report IP
**Endpoint:** `POST /api/dashboard/event-actions/report`

Submit an IP report for internal tracking.

**Request Body:**
```json
{
  "ip_address": "192.168.1.100",
  "report_service": "abuseipdb",  // abuseipdb, manual, internal
  "report_categories": ["ssh", "brute-force"],
  "report_comment": "Multiple failed login attempts",
  "event_id": 12345  // Optional
}
```

**Response (201 Created):**
```json
{
  "success": true,
  "report_id": 321,
  "report_uuid": "550e8400-e29b-41d4-a716-446655440000",
  "message": "IP 192.168.1.100 report submitted to abuseipdb"
}
```

**Validations:**
- IP address format must be valid
- report_service must be one of: abuseipdb, manual, internal

---

### 11. Get Report History
**Endpoint:** `GET /api/dashboard/event-actions/report/<ip_address>/history`

Get all reports submitted for an IP address.

**Response (200 OK):**
```json
{
  "success": true,
  "reports": [
    {
      "id": 321,
      "report_uuid": "550e8400-e29b-41d4-a716-446655440000",
      "service": "abuseipdb",
      "categories": ["ssh", "brute-force"],
      "comment": "Multiple failed login attempts",
      "status": "pending",
      "external_report_id": null,
      "created_at": "2025-12-05T15:30:00",
      "updated_at": "2025-12-05T15:30:00"
    }
  ],
  "count": 1,
  "from_cache": false
}
```

---

## Quick Info

### 12. Get IP Status
**Endpoint:** `GET /api/dashboard/event-actions/ip-status/<ip_address>`

Get combined status for an IP address (blocked, whitelisted, watched, notes count, reports count).

**Response (200 OK):**
```json
{
  "success": true,
  "ip_address": "192.168.1.100",
  "is_blocked": false,
  "is_whitelisted": true,
  "is_watched": false,
  "notes_count": 3,
  "reports_count": 1,
  "from_cache": false
}
```

---

## Error Responses

All endpoints return consistent error responses:

**400 Bad Request:**
```json
{
  "success": false,
  "error": "Missing required field: ip_address"
}
```

**404 Not Found:**
```json
{
  "success": false,
  "error": "IP not found in whitelist or already removed"
}
```

**500 Internal Server Error:**
```json
{
  "success": false,
  "error": "Failed to add IP to whitelist"
}
```

---

## Caching

- All GET endpoints support Redis caching with 15-minute TTL
- Cache is automatically invalidated on POST/DELETE operations
- Responses include `from_cache: true/false` field

---

## Database Tables

The API interacts with these tables:
- `ip_whitelist` - Trusted IP addresses
- `ip_watchlist` - Monitored IP addresses
- `event_notes` - Notes for events and IPs
- `ip_reports` - IP abuse reports

See migration: `013_event_actions_tables.sql`

---

## Implementation Notes

1. **IP Validation:** All endpoints validate IP format (IPv4/IPv6) using `is_valid_ip()`
2. **UUID Generation:** Notes and reports use UUIDs for unique identification
3. **Soft Deletes:** Whitelist and watchlist use `is_active` flag instead of hard deletes
4. **Cache Invalidation:** All write operations invalidate related caches
5. **User Tracking:** `created_by_user_id` is prepared but currently set to NULL (TODO: session integration)

---

## Next Steps

- Integrate user session for `created_by_user_id` tracking
- Add external API integration for AbuseIPDB report submission
- Implement email notifications for watchlist activity
- Add bulk operations for whitelist/watchlist management
