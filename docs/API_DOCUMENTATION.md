# SSH Guardian v3.0 - API Documentation

**Last Updated:** 2025-12-04
**Version:** 3.0.0

---

## Overview

The SSH Guardian API allows agents to submit SSH authentication events for monitoring and analysis.

**Base URL:** `http://localhost:8081/api`

---

## Authentication

All API endpoints (except `/health`) require API key authentication.

**Header:**
```
X-API-Key: <your-api-key>
```

### Getting an API Key

Run the agent creation script:
```bash
python3 scripts/create_test_agent.py
```

This will output your API key and agent details.

---

## Endpoints

### 1. Health Check

**Endpoint:** `GET /api/events/health`

**Description:** Check if the API is running

**Authentication:** Not required

**Response:**
```json
{
  "status": "healthy",
  "service": "SSH Guardian Events API",
  "version": "3.0.0"
}
```

**Example:**
```bash
curl http://localhost:8081/api/events/health
```

---

### 2. Submit Single Event

**Endpoint:** `POST /api/events/submit`

**Description:** Submit a single SSH authentication event

**Authentication:** Required (X-API-Key header)

**Request Body:**
```json
{
  "timestamp": "2025-12-04T10:30:45Z",
  "source_ip": "192.168.1.100",
  "username": "root",
  "auth_method": "password",
  "status": "failed",
  "port": 22,
  "protocol": "ssh2",
  "raw_log": "Dec  4 10:30:45 server01 sshd[12345]: Failed password for root from 192.168.1.100 port 54321 ssh2",
  "hostname": "test-server-01"
}
```

**Required Fields:**
- `timestamp` (string, ISO 8601 format)
- `source_ip` (string, IPv4 or IPv6)
- `username` (string)
- `status` (string, "success" or "failed")

**Optional Fields:**
- `auth_method` (string, default: "password")
- `port` (integer, default: 22)
- `protocol` (string, default: "ssh2")
- `raw_log` (string, original log line)
- `hostname` (string, server hostname)

**Response (Success - 201):**
```json
{
  "success": true,
  "event_id": 2,
  "event_uuid": "7f9f9d1c-6bd7-45ab-9608-3230550b75d1",
  "message": "Event received and queued for processing",
  "agent": "Test Agent 01"
}
```

**Response (Error - 400):**
```json
{
  "error": "Missing required fields",
  "missing": ["timestamp", "source_ip"]
}
```

**Response (Error - 401):**
```json
{
  "error": "API key required"
}
```

**Example:**
```bash
curl -X POST http://localhost:8081/api/events/submit \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_API_KEY_HERE" \
  -d '{
    "timestamp": "2025-12-04T10:30:45Z",
    "source_ip": "192.168.1.100",
    "username": "root",
    "auth_method": "password",
    "status": "failed",
    "port": 22,
    "protocol": "ssh2",
    "raw_log": "Dec  4 10:30:45 server01 sshd[12345]: Failed password for root from 192.168.1.100 port 54321 ssh2",
    "hostname": "test-server-01"
  }'
```

---

### 3. Submit Batch Events

**Endpoint:** `POST /api/events/submit/batch`

**Description:** Submit multiple events in a single request

**Authentication:** Required (X-API-Key header)

**Request Body:**
```json
{
  "events": [
    {
      "timestamp": "2025-12-04T10:30:45Z",
      "source_ip": "192.168.1.100",
      "username": "root",
      "status": "failed"
    },
    {
      "timestamp": "2025-12-04T10:30:50Z",
      "source_ip": "192.168.1.101",
      "username": "admin",
      "status": "failed"
    }
  ]
}
```

**Limits:**
- Maximum 100 events per batch

**Response (Success - 201):**
```json
{
  "success": true,
  "received": 2,
  "processed": 2,
  "failed": 0,
  "event_uuids": [
    "uuid-1",
    "uuid-2"
  ]
}
```

**Example:**
```bash
curl -X POST http://localhost:8081/api/events/submit/batch \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_API_KEY_HERE" \
  -d '{
    "events": [
      {
        "timestamp": "2025-12-04T10:30:45Z",
        "source_ip": "192.168.1.100",
        "username": "root",
        "status": "failed"
      },
      {
        "timestamp": "2025-12-04T10:30:50Z",
        "source_ip": "192.168.1.101",
        "username": "admin",
        "status": "failed"
      }
    ]
  }'
```

---

## Event Status Values

- `success` - Authentication succeeded
- `failed` - Authentication failed

---

## Authentication Methods

- `password` - Password authentication
- `publickey` - Public key authentication
- `keyboard-interactive` - Keyboard-interactive authentication
- `none` - No authentication
- `other` - Other authentication methods

---

## Error Codes

| Code | Description |
|------|-------------|
| 400 | Bad Request - Missing or invalid fields |
| 401 | Unauthorized - Invalid or missing API key |
| 500 | Internal Server Error |

---

## Rate Limiting

Currently not implemented. Future implementation will include:
- Per-agent rate limits
- Burst handling
- Rate limit headers in responses

---

## Testing

### 1. Create Test Agent
```bash
source /home/rana-workspace/ssh_guardian_2.0/venv/bin/activate
python3 scripts/create_test_agent.py
```

### 2. Test API Health
```bash
curl http://localhost:8081/api/events/health
```

### 3. Submit Test Event
```bash
# Save your API key from step 1
export API_KEY="your-api-key-here"

curl -X POST http://localhost:8081/api/events/submit \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d '{
    "timestamp": "2025-12-04T10:30:45Z",
    "source_ip": "192.168.1.100",
    "username": "root",
    "status": "failed",
    "hostname": "test-server-01"
  }'
```

### 4. Verify Events in Database
```bash
python3 scripts/verify_event.py
```

---

## Integration Examples

### Python Agent Example

```python
import requests
import json
from datetime import datetime

API_KEY = "your-api-key-here"
API_URL = "http://localhost:8081/api/events/submit"

def send_event(source_ip, username, status, raw_log):
    """Send SSH event to Guardian API"""

    payload = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "source_ip": source_ip,
        "username": username,
        "status": status,
        "auth_method": "password",
        "port": 22,
        "protocol": "ssh2",
        "raw_log": raw_log,
        "hostname": "my-server"
    }

    headers = {
        "Content-Type": "application/json",
        "X-API-Key": API_KEY
    }

    response = requests.post(API_URL, json=payload, headers=headers)

    if response.status_code == 201:
        print(f"✅ Event sent: {response.json()['event_uuid']}")
    else:
        print(f"❌ Error: {response.json()['error']}")

    return response

# Example usage
send_event(
    source_ip="192.168.1.100",
    username="root",
    status="failed",
    raw_log="Dec  4 10:30:45 server sshd[12345]: Failed password for root from 192.168.1.100"
)
```

### Bash Script Example

```bash
#!/bin/bash

API_KEY="your-api-key-here"
API_URL="http://localhost:8081/api/events/submit"
HOSTNAME=$(hostname)

# Parse SSH log and send event
send_event() {
    local ip=$1
    local user=$2
    local status=$3
    local log_line=$4

    timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

    curl -X POST "$API_URL" \
        -H "Content-Type: application/json" \
        -H "X-API-Key: $API_KEY" \
        -d "{
            \"timestamp\": \"$timestamp\",
            \"source_ip\": \"$ip\",
            \"username\": \"$user\",
            \"status\": \"$status\",
            \"hostname\": \"$HOSTNAME\",
            \"raw_log\": \"$log_line\"
        }"
}

# Example: Monitor auth.log and send events
tail -f /var/log/auth.log | while read line; do
    if echo "$line" | grep -q "Failed password"; then
        ip=$(echo "$line" | grep -oP 'from \K[\d.]+')
        user=$(echo "$line" | grep -oP 'for \K\w+')
        send_event "$ip" "$user" "failed" "$line"
    fi
done
```

---

## Next Steps

1. Implement batch processing optimization
2. Add rate limiting
3. Add event validation rules
4. Implement webhook notifications
5. Add API metrics and monitoring

---

## Support

For issues or questions:
- Check logs: Server console output
- Verify agent: `python3 scripts/verify_event.py`
- Database check: Query `auth_events` table
