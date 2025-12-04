# SSH Guardian v3.0 - Block Status Control Guide

## 📊 Understanding Block Status

### Active Block (is_active = TRUE)
**IP is currently blocked and cannot access the system**

Characteristics:
- ✅ Block is enforced
- ✅ IP is denied access
- ✅ Shows in "Active Blocks" filter
- ✅ Has "Unblock" button in dashboard

### Inactive Block (is_active = FALSE)
**IP is no longer blocked, but record is kept for audit/history**

Characteristics:
- ❌ Block is not enforced
- ✅ IP can access the system again
- ✅ Shows in "Inactive Blocks" filter
- ✅ No action button (already unblocked)
- ℹ️  Kept for historical/compliance purposes

---

## 🔄 How Blocks Become Inactive

### 1. Manual Unblock (Immediate)
**Dashboard Method:**
```
Security → IP Management → Blocked IPs
→ Find active block
→ Click "Unblock" button
→ Confirm
→ Block instantly becomes inactive
```

**API Method:**
```bash
curl -X POST http://localhost:8081/api/dashboard/blocking/blocks/unblock \
  -H "Content-Type: application/json" \
  -d '{
    "ip_address": "192.168.1.100",
    "reason": "False positive"
  }'
```

**Python Method:**
```python
from blocking_engine import unblock_ip

result = unblock_ip(
    ip_address="192.168.1.100",
    reason="False positive",
    user_id=1
)
```

### 2. Auto-Unblock (Scheduled)
**Blocks expire automatically when:**
- `auto_unblock = TRUE`
- Current time >= `unblock_at` time

**Requires cleanup service running:**
```bash
# Run once
python3 scripts/cleanup_expired_blocks.py

# Run as daemon (every 5 minutes)
python3 scripts/cleanup_expired_blocks.py --daemon

# Run as daemon (custom interval)
python3 scripts/cleanup_expired_blocks.py --daemon --interval 10
```

### 3. Permanent Blocks (Never Auto-Expire)
**Configuration:**
```json
{
  "duration_minutes": 0,
  "auto_unblock": false
}
```

These blocks:
- Stay active forever
- `unblock_at` is NULL
- Require manual unblock
- Used for known malicious IPs

---

## 🎛️ Block Duration Control

### When Creating a Block

**Short Duration (1 hour):**
```json
{"duration_minutes": 60}
```

**Standard Duration (24 hours) - DEFAULT:**
```json
{"duration_minutes": 1440}
```

**Long Duration (1 week):**
```json
{"duration_minutes": 10080}
```

**Permanent Block:**
```json
{
  "duration_minutes": 0,
  "auto_unblock": false
}
```

### Block Duration Examples

| Duration | Minutes | Use Case |
|----------|---------|----------|
| 15 minutes | 15 | Testing/Temporary |
| 1 hour | 60 | Warning block |
| 6 hours | 360 | Suspicious activity |
| 24 hours | 1440 | **Default** - Failed attempts |
| 48 hours | 2880 | High threat level |
| 1 week | 10080 | Persistent attacks |
| Permanent | 0 | Known malicious IP |

---

## 📋 Your Current Blocks (Example)

```
Block #3 - ACTIVE ✅
  IP: 198.51.100.50
  Status: Currently blocking
  Unblock at: 2025-12-05 13:31:03
  Reason: Blocked from Live Events - failed attempt
  → Will auto-unblock tomorrow

Block #2 - INACTIVE ❌
  IP: 192.168.100.50
  Status: No longer blocking
  Unblocked: Manually via API
  Reason: "Test unblock from API"
  → Was unblocked before expiry time

Block #1 - INACTIVE ❌
  IP: 203.0.113.100
  Status: No longer blocking
  Unblocked: Manually via dashboard
  Reason: "Test unblock"
  → Was unblocked before expiry time
```

---

## 🔧 Cleanup Service Setup

### Script Location
```
scripts/cleanup_expired_blocks.py
```

### Usage

**Run Once (Manual Cleanup):**
```bash
python3 scripts/cleanup_expired_blocks.py
```

**Run as Daemon (Automatic):**
```bash
# Every 5 minutes (default)
python3 scripts/cleanup_expired_blocks.py --daemon

# Every 10 minutes
python3 scripts/cleanup_expired_blocks.py --daemon --interval 10

# Every 30 minutes
python3 scripts/cleanup_expired_blocks.py --daemon --interval 30
```

**Run as System Service (systemd):**

Create `/etc/systemd/system/ssh-guardian-cleanup.service`:
```ini
[Unit]
Description=SSH Guardian Block Cleanup Service
After=network.target mysql.service

[Service]
Type=simple
User=your-user
WorkingDirectory=/home/rana-workspace/ssh_guardian_v3.0
ExecStart=/home/rana-workspace/ssh_guardian_2.0/venv/bin/python3 scripts/cleanup_expired_blocks.py --daemon --interval 5
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl enable ssh-guardian-cleanup
sudo systemctl start ssh-guardian-cleanup
sudo systemctl status ssh-guardian-cleanup
```

### Cron Job (Alternative)

Run every 5 minutes:
```bash
crontab -e
```

Add:
```
*/5 * * * * cd /home/rana-workspace/ssh_guardian_v3.0 && /home/rana-workspace/ssh_guardian_2.0/venv/bin/python3 scripts/cleanup_expired_blocks.py >> /var/log/ssh-guardian-cleanup.log 2>&1
```

---

## 📊 Monitoring Block Status

### Dashboard Filters

**View Only Active Blocks:**
```
Security → IP Management → Blocked IPs
→ Status Filter: "Active"
→ Shows only currently enforced blocks
```

**View Only Inactive Blocks:**
```
Security → IP Management → Blocked IPs
→ Status Filter: "Inactive"
→ Shows historical/unblocked IPs
```

**View All Blocks:**
```
Security → IP Management → Blocked IPs
→ Status Filter: "All Status"
→ Shows everything
```

### API Monitoring

**Get Active Blocks Count:**
```bash
curl -s http://localhost:8081/api/dashboard/blocking/stats | jq '.stats.active_blocks'
```

**Get All Blocks:**
```bash
curl -s "http://localhost:8081/api/dashboard/blocking/blocks/list?is_active=true"
```

**Check Specific IP:**
```bash
curl -s http://localhost:8081/api/dashboard/blocking/blocks/check/192.168.1.100
```

### Database Query

**Check block status directly:**
```sql
SELECT
    ip_address_text,
    is_active,
    blocked_at,
    unblock_at,
    block_reason,
    unblock_reason
FROM ip_blocks
WHERE ip_address_text = '192.168.1.100';
```

**Count active vs inactive:**
```sql
SELECT
    is_active,
    COUNT(*) as count
FROM ip_blocks
GROUP BY is_active;
```

**Find expired but not cleaned up:**
```sql
SELECT
    ip_address_text,
    blocked_at,
    unblock_at
FROM ip_blocks
WHERE is_active = TRUE
AND auto_unblock = TRUE
AND unblock_at <= NOW();
```

---

## 🎯 Best Practices

### 1. Regular Cleanup
- Run cleanup service as daemon
- Check cleanup logs regularly
- Monitor for expired blocks

### 2. Block Duration Strategy
- **Failed logins:** 24 hours
- **Brute force attacks:** 48 hours
- **High threat IPs:** 1 week
- **Known malicious:** Permanent

### 3. Review Inactive Blocks
- Check for patterns
- Identify false positives
- Adjust rules accordingly

### 4. Audit Trail
- All blocks kept in database
- All actions logged in `blocking_actions`
- Use for compliance reporting

### 5. Manual Override
- Always allow manual unblock
- Document unblock reasons
- Review manual unblocks regularly

---

## ⚠️ Common Issues

### Issue: Blocks Not Auto-Expiring
**Cause:** Cleanup service not running

**Solution:**
```bash
# Check if service is running
ps aux | grep cleanup_expired_blocks

# Start service
python3 scripts/cleanup_expired_blocks.py --daemon &
```

### Issue: Too Many Inactive Blocks
**Cause:** Historical records accumulating

**Solution:**
```sql
-- Delete old inactive blocks (optional)
DELETE FROM ip_blocks
WHERE is_active = FALSE
AND blocked_at < DATE_SUB(NOW(), INTERVAL 30 DAY);
```

### Issue: Block Expired But Still Active
**Cause:** Cleanup hasn't run yet

**Solution:**
```bash
# Run cleanup manually
python3 scripts/cleanup_expired_blocks.py
```

---

## 📈 Statistics

**View blocking statistics:**
```
Dashboard → Security → Blocking Rules → View Stats
```

Or via API:
```bash
curl -s http://localhost:8081/api/dashboard/blocking/stats | jq
```

Returns:
- Total blocks (all time)
- Active blocks (currently enforced)
- Blocks by source (manual, rule_based, api_reputation)
- Recent 24h blocks
- Top blocked IPs

---

## 🔐 Security Considerations

1. **Inactive Blocks Are Not Enforced**
   - IP can access system again
   - Only kept for audit purposes
   - Can be safely deleted after retention period

2. **Manual Unblock Requires Permission**
   - Only authorized users should unblock
   - All unblocks are logged
   - Reason field is mandatory for audit

3. **Cleanup Service Security**
   - Only deactivates expired blocks
   - Never deletes block records
   - Preserves audit trail

4. **Rate Limiting**
   - Repeated blocks of same IP tracked
   - Pattern analysis possible
   - Can identify persistent attackers

---

## 📝 Summary

**Active = Currently Blocking ✅**
- IP is denied access
- Block is enforced
- Can be manually unblocked
- Auto-expires at `unblock_at` time

**Inactive = No Longer Blocking ❌**
- IP can access system
- Block is not enforced
- Record kept for history
- Result of manual unblock or expiration

**Control Methods:**
1. Manual unblock (immediate)
2. Auto-unblock (scheduled, requires cleanup service)
3. Duration settings (when creating block)
4. Permanent blocks (never expire)

**Cleanup Service:**
- Required for auto-unblock to work
- Runs periodically (default: 5 minutes)
- Can be daemon or cron job
- Logs all cleanup actions
