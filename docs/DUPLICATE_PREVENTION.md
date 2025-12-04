# SSH Guardian v3.0 - Duplicate Block Prevention

## ✅ System Already Prevents Duplicates!

The blocking system **already prevents duplicate active blocks** for the same IP address. This document explains how it works and the improvements made.

---

## 🔒 How Duplicate Prevention Works

### 1. Application-Level Check (blocking_engine.py:298-311)

```python
# Check if IP is already blocked and active
cursor.execute("""
    SELECT id FROM ip_blocks
    WHERE ip_address_text = %s AND is_active = TRUE
""", (ip_address,))

existing_block = cursor.fetchone()

if existing_block:
    return {
        'success': False,
        'block_id': existing_block[0],
        'message': f'IP {ip_address} is already blocked'
    }
```

**What this does:**
- Before creating a new block, checks if IP is already actively blocked
- If active block exists, returns error message
- Prevents duplicate active blocks at application level

---

## 📋 Understanding "Duplicate" vs "Historical" Blocks

### ❌ NOT a Duplicate (This is Normal):
```
IP: 198.51.100.50
  - Block #3: INACTIVE (2025-12-04) - Old block, expired/unblocked
  - Block #4: ACTIVE   (2025-12-04) - New block, currently enforced

Status: ✅ ALLOWED - Only one is active
Reason: Historical records are kept for audit purposes
```

### ⚠️ TRUE Duplicate (This is Prevented):
```
IP: 198.51.100.50
  - Block #3: ACTIVE (2025-12-04)
  - Block #4: ACTIVE (2025-12-04)

Status: ❌ PREVENTED - System blocks this
Reason: Only one active block per IP is allowed
```

---

## 🆕 Improvements Made

### 1. Better UI Feedback ✅

**Before:**
```
User tries to block already-blocked IP
→ Generic error: "Failed to block IP"
```

**After:**
```javascript
User tries to block already-blocked IP
→ Dialog: "⚠️ IP 198.51.100.50 is already blocked!"
          "Block ID: 4"
          "Would you like to view blocked IPs?"
→ If YES: Navigate to Blocked IPs page
```

### 2. Default Filter: Active Only ✅

**Before:**
- Shows ALL blocks (active + inactive)
- User sees "duplicates" (actually historical records)
- Confusing UI

**After:**
- Defaults to "Active Only" filter
- Only shows currently blocked IPs
- Clean, focused view
- User can change to "All Status" to see history

### 3. Database-Level Constraint (Optional)

**SQL to add unique constraint:**
```sql
ALTER TABLE ip_blocks
ADD CONSTRAINT unique_active_ip
UNIQUE (ip_address_text, is_active);
```

**What this does:**
- Enforces at database level: only one active block per IP
- Prevents any application bugs from creating duplicates
- MySQL will reject INSERT if constraint violated

**Note:** Not applied by default to maintain backward compatibility.

---

## 🧪 Testing Duplicate Prevention

### Test 1: Try to Block Already-Blocked IP

```bash
# Block an IP
curl -X POST http://localhost:8081/api/dashboard/blocking/blocks/manual \
  -H "Content-Type: application/json" \
  -d '{"ip_address": "198.51.100.50", "reason": "First block", "duration_minutes": 1440}'

# Response: Success, Block ID: 4

# Try to block same IP again
curl -X POST http://localhost:8081/api/dashboard/blocking/blocks/manual \
  -H "Content-Type: application/json" \
  -d '{"ip_address": "198.51.100.50", "reason": "Second block", "duration_minutes": 1440}'

# Response: {
#   "success": false,
#   "block_id": 4,
#   "message": "IP 198.51.100.50 is already blocked"
# }
```

✅ **Result:** System correctly prevents duplicate

### Test 2: Unblock and Re-Block

```bash
# Unblock IP
curl -X POST http://localhost:8081/api/dashboard/blocking/blocks/unblock \
  -H "Content-Type: application/json" \
  -d '{"ip_address": "198.51.100.50", "reason": "Test"}'

# Response: Success (Block #4 becomes inactive)

# Block same IP again (now allowed)
curl -X POST http://localhost:8081/api/dashboard/blocking/blocks/manual \
  -H "Content-Type: application/json" \
  -d '{"ip_address": "198.51.100.50", "reason": "New block", "duration_minutes": 60}'

# Response: Success, Block ID: 5 (new block)
```

✅ **Result:** System allows re-blocking after unblock

### Test 3: View Blocks with Filter

```bash
# View only active blocks
curl -s "http://localhost:8081/api/dashboard/blocking/blocks/list?is_active=true"

# View all blocks (including inactive)
curl -s "http://localhost:8081/api/dashboard/blocking/blocks/list"
```

---

## 🎯 Best Practices

### 1. Use Active Filter by Default
```
Dashboard → Blocked IPs → Filter: "Active Only"
```
Shows only currently enforced blocks

### 2. View History When Needed
```
Dashboard → Blocked IPs → Filter: "All Status"
```
Shows all blocks including historical

### 3. Understand Block Lifecycle
```
Create Block → ACTIVE
   ↓
Manual Unblock OR Auto-Expire → INACTIVE (kept for audit)
   ↓
Can Block Again → New ACTIVE block (new ID)
```

### 4. Check Before Blocking
```javascript
// API automatically checks, but you can also:
GET /api/dashboard/blocking/blocks/check/192.168.1.100

// Returns:
{
  "is_blocked": true,  // IP is currently blocked
  "block_info": { ... } // Details of active block
}
```

---

## 📊 Current System State

### Your Blocks (Example):
```
Total blocks: 4
Active blocks: 1
Inactive blocks: 3

Active:
  - 198.51.100.50 (Block #4)

Inactive (Historical):
  - 198.51.100.50 (Block #3) - Previous block
  - 192.168.100.50 (Block #2)
  - 203.0.113.100 (Block #1)
```

**Analysis:**
- ✅ Only 1 active block per IP
- ✅ No true duplicates
- ✅ System working correctly
- ℹ️  Historical records preserved for audit

---

## 🔧 Technical Implementation

### Files Modified:

**1. src/dashboard/templates/dashboard.html**
- Enhanced `quickBlock()` function with duplicate detection
- Added navigation to Blocked IPs page on duplicate
- Changed default filter to "Active Only"

**2. src/core/blocking_engine.py** (Already Had This)
- Line 298-311: Duplicate check before insert
- Returns error if active block exists

**3. src/dashboard/routes/blocking_routes.py** (Already Had This)
- Uses `block_ip_manual()` which calls blocking_engine
- Inherits duplicate prevention automatically

---

## ❓ FAQ

### Q: Why do I see the same IP multiple times?
**A:** Those are historical records. Filter by "Active Only" to see current blocks.

### Q: Can I block an IP that was previously blocked?
**A:** Yes! After unblocking, you can block again. Each block gets a new ID.

### Q: Why keep inactive blocks?
**A:** For audit trail, compliance, and pattern analysis. Shows history of blocking decisions.

### Q: Can I delete old inactive blocks?
**A:** Yes, but not recommended. Better to filter them out in the UI.

```sql
-- If you really want to delete old inactive blocks:
DELETE FROM ip_blocks
WHERE is_active = FALSE
AND blocked_at < DATE_SUB(NOW(), INTERVAL 90 DAY);
```

### Q: What happens if I try to block an active block via UI?
**A:** Dashboard shows warning dialog:
```
⚠️ IP is already blocked!
Block ID: X
Would you like to view blocked IPs?
```

### Q: How do I extend an existing block?
**A:** Currently, you must:
1. Unblock the IP
2. Block it again with new duration

**Future enhancement:** Add "Extend Block" button.

---

## 🎨 UI Improvements Summary

### Before:
- ❌ Generic error for duplicates
- ❌ Shows all blocks by default (confusing)
- ❌ No guidance on what to do

### After:
- ✅ Clear duplicate warning with block ID
- ✅ Defaults to "Active Only" filter
- ✅ Offers to navigate to Blocked IPs page
- ✅ Better user experience

---

## 🚀 Optional: Add Database Constraint

If you want **extra safety** at database level:

```bash
# Connect to MySQL
mysql -u root -p ssh_guardian_v3

# Add constraint
ALTER TABLE ip_blocks
ADD CONSTRAINT unique_active_ip
UNIQUE (ip_address_text, is_active);

# Test
INSERT INTO ip_blocks (ip_address, ip_address_text, is_active, ...)
VALUES (INET6_ATON('1.2.3.4'), '1.2.3.4', TRUE, ...);

INSERT INTO ip_blocks (ip_address, ip_address_text, is_active, ...)
VALUES (INET6_ATON('1.2.3.4'), '1.2.3.4', TRUE, ...);
-- ERROR: Duplicate entry '1.2.3.4-1' for key 'unique_active_ip'
```

**Trade-off:**
- ✅ Extra safety
- ❌ Can't have multiple active blocks for same IP (already prevented by app)
- ❌ May cause issues if app logic changes

---

## ✅ Conclusion

The system **already prevents duplicate active blocks** at the application level. The improvements made:

1. ✅ Better UI feedback for duplicate attempts
2. ✅ Default filter shows only active blocks
3. ✅ Clear user guidance when duplicates detected
4. ✅ Optional database constraint for extra safety

**No action required** - system is working correctly! Historical blocks are normal and expected.
