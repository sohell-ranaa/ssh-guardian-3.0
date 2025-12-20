# Alert Only Scenarios - Complete Journey (All 6)

## Overview
Alert Only scenarios test SSH Guardian's ability to detect **behavioral anomalies** in SUCCESSFUL logins. They trigger alerts but do NOT block IPs.

**Key Difference from Blocking Scenarios:**
- Log template: `Accepted password/publickey` (success, not failure)
- Action: Alert notification only
- No entry in `ip_blocks` table

---

## Scenario 1: Alert: Unusual Login Time

### Card Display
```
Name: Alert: Unusual Login Time
Badge: ⚠️ NO BLOCK (orange)
Severity: 🟡 medium
IP: 73.162.0.1
```

### What Gets Injected
```
Dec 20 03:30:00 server sshd[45678]: Accepted password for dev.user from 73.162.0.1 port 52341 ssh2
```
- **1 event** at forced time **3:30 AM**
- User: `dev.user`
- Auth: password (successful)

### ML Detection
| Factor | Score | Reason |
|--------|-------|--------|
| unusual_time | 31 | 3:30 AM login vs learned 9am-5pm pattern |

### Baseline Created
```python
{
    "user": "dev.user",
    "baseline_hours": [9, 10, 11, 12, 13, 14, 15, 16, 17]  # 9am-5pm
}
```

### Expected Outcome
```
✅ Login ALLOWED
⚠️ Alert sent: "Unusual login time detected for dev.user"
❌ IP NOT blocked
```

### Real-World Meaning
Employee working late, traveling across timezones, or attacker using stolen credentials at odd hours.

---

## Scenario 2: Alert: New Location

### Card Display
```
Name: Alert: New Location
Badge: ⚠️ NO BLOCK (orange)
Severity: 🟡 medium
IP: 82.132.234.1 (UK)
```

### What Gets Injected
```
Dec 20 14:30:00 server sshd[45679]: Accepted password for engineer from 82.132.234.1 port 52342 ssh2
```
- **1 event** from UK IP
- User: `engineer`
- Auth: password (successful)

### ML Detection
| Factor | Score | Reason |
|--------|-------|--------|
| new_location | 38 | First login from UK (baseline: US only) |

### Baseline Created
```python
{
    "user": "engineer",
    "baseline_countries": ["US"]
}
```

### Expected Outcome
```
✅ Login ALLOWED
⚠️ Alert sent: "New location detected for engineer: United Kingdom"
❌ IP NOT blocked
```

### Real-World Meaning
Business travel, vacation abroad, or attacker in different country with valid credentials.

---

## Scenario 3: Alert: First Time IP

### Card Display
```
Name: Alert: First Time IP
Badge: ⚠️ NO BLOCK (orange)
Severity: 🟢 low
IP: 98.217.55.12
```

### What Gets Injected
```
Dec 20 10:15:00 server sshd[45680]: Accepted password for analyst from 98.217.55.12 port 52343 ssh2
```
- **1 event** from new IP (same country, same ISP)
- User: `analyst`
- Auth: password (successful)

### ML Detection
| Factor | Score | Reason |
|--------|-------|--------|
| new_ip_for_user | 10 | First time from this IP, same country |

### Baseline Created
```python
{
    "user": "analyst",
    "baseline_ips": ["98.217.50.1", "98.217.50.2"]
}
```

### Expected Outcome
```
✅ Login ALLOWED
⚠️ Alert sent: "First login from new IP for analyst"
❌ IP NOT blocked
```

### Real-World Meaning
User at coffee shop, changed ISP, or working from friend's house. Low risk - same geographic area.

---

## Scenario 4: Alert: Weekend Login

### Card Display
```
Name: Alert: Weekend Login
Badge: ⚠️ NO BLOCK (orange)
Severity: 🟢 low
IP: 73.162.50.1
```

### What Gets Injected
```
Dec 21 14:00:00 server sshd[45681]: Accepted password for pm_lead from 73.162.50.1 port 52344 ssh2
```
- **1 event** on Saturday at 2pm
- User: `pm_lead`
- Auth: password (successful)
- **Note:** Day forced to Saturday

### ML Detection
| Factor | Score | Reason |
|--------|-------|--------|
| unusual_time | 8 | Weekend login, user has weekday-only pattern |

### Baseline Created
```python
{
    "user": "pm_lead",
    "baseline_days": ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]
}
```

### Expected Outcome
```
✅ Login ALLOWED
⚠️ Alert sent: "Weekend login detected for pm_lead"
❌ IP NOT blocked
```

### Real-World Meaning
Employee catching up on work over weekend. Known IP, just unusual day.

---

## Scenario 5: Alert: Elevated Risk Score

### Card Display
```
Name: Alert: Elevated Risk Score
Badge: ⚠️ NO BLOCK (orange)
Severity: 🟡 medium
IP: 104.28.5.100 (Cloud/CDN IP)
```

### What Gets Injected
```
Dec 20 18:45:00 server sshd[45682]: Accepted publickey for sysadmin from 104.28.5.100 port 52345 ssh2
```
- **1 event** at 6:45 PM from cloud provider IP
- User: `sysadmin`
- Auth: publickey (successful)

### ML Detection
| Factor | Score | Reason |
|--------|-------|--------|
| new_ip_for_user | 10 | First time from this IP |
| unusual_time | 10 | 6:45 PM vs typical 9am-5pm |
| cloud_provider_ip | 15 | IP belongs to cloud provider |
| **TOTAL** | **35** | Multiple minor anomalies combined |

### Expected Outcome
```
✅ Login ALLOWED
⚠️ Alert sent: "Elevated ML risk score (35) for sysadmin"
❌ IP NOT blocked (score below 50 threshold)
```

### Real-World Meaning
Sysadmin accessing from cloud shell, VPS, or working late. Multiple minor flags but authenticated successfully.

---

## Scenario 6: Alert: Root from New Location

### Card Display
```
Name: Alert: Root from New Location
Badge: ⚠️ NO BLOCK (orange)
Severity: 🔴 high
IP: 206.47.0.1 (Canada)
```

### What Gets Injected
```
Dec 20 11:30:00 server sshd[45683]: Accepted publickey for root from 206.47.0.1 port 52346 ssh2
```
- **1 event** from Canada (user baseline: US only)
- User: `root` (privileged!)
- Auth: publickey (successful)

### ML Detection
| Factor | Score | Reason |
|--------|-------|--------|
| privileged_account | 15 | Root account access |
| new_location | 20 | First login from Canada (baseline: US) |
| **TOTAL** | **35** | Privileged + new location |

### Baseline Created
```python
{
    "user": "root",
    "baseline_countries": ["US"]
}
```

### Expected Outcome
```
✅ Login ALLOWED (valid SSH key)
🚨 HIGH PRIORITY Alert: "Root login from new location: Canada"
❌ IP NOT blocked
```

### Real-World Meaning
Sysadmin traveling to Canada, or attacker with stolen SSH private key. HIGH priority for security team review.

---

## Common Flow for All Alert-Only Scenarios

```
User clicks scenario card
        ↓
POST /api/live-sim/live/run
        ↓
Backend: Inject SUCCESSFUL login to auth.log
        ↓
Agent: Detect event → Send to dashboard
        ↓
Dashboard: Enrich with GeoIP + Threat Intel
        ↓
ML Engine: Analyze against user baseline
        ↓
ML Engine: Calculate anomaly score
        ↓
Notification System: Send alert (Telegram/Email/Webhook)
        ↓
Frontend: Show results
        ↓
Result: "⚠️ Alert Created - IP NOT Blocked"
```

---

## Results Card Display (All Alert-Only)

```
┌─────────────────────────────────────────────┐
│  ⚠️ SIMULATION COMPLETE                     │
│     Behavioral anomaly detected             │
├─────────────────────────────────────────────┤
│  IP: [scenario IP]                          │
│  Scenario: [scenario name]                  │
├─────────────────────────────────────────────┤
│  ML Analysis:                               │
│    Risk Score: [8-38]/100                   │
│    Anomaly: [unusual_time/new_location/etc] │
│    Decision: ALLOW (with alert)             │
├─────────────────────────────────────────────┤
│  ⚠️ Alert Created                           │
│     Notification sent to configured channels│
│     IP allowed - behavioral anomaly logged  │
└─────────────────────────────────────────────┘
```

---

## Summary Table

| # | Scenario | IP | User | Anomaly Type | Score | Severity |
|---|----------|-----|------|--------------|-------|----------|
| 1 | Unusual Login Time | 73.162.0.1 | dev.user | 3:30 AM login | 31 | medium |
| 2 | New Location | 82.132.234.1 | engineer | UK (baseline: US) | 38 | medium |
| 3 | First Time IP | 98.217.55.12 | analyst | New IP, same country | 10 | low |
| 4 | Weekend Login | 73.162.50.1 | pm_lead | Saturday login | 8 | low |
| 5 | Elevated Risk | 104.28.5.100 | sysadmin | Multiple minor flags | 35 | medium |
| 6 | Root New Location | 206.47.0.1 | root | Root + Canada | 35 | high |

**All scenarios:** Login ALLOWED ✅ | Alert Sent ⚠️ | IP NOT Blocked ❌
