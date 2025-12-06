# SSH Guardian v3.0 - Backend Revamp Complete

## Date: December 6, 2025

---

## Summary

Successfully implemented enhanced multi-factor threat analysis backend for simulation page revamp.

---

## New Backend Functions Added

### 1. `calculate_behavioral_score(history, events_data)`
**Location:** `/src/dashboard/routes/demo_routes.py` lines 106-194

**Purpose:** Analyze attack pattern behavior based on historical data

**Returns:**
```python
{
    'score': 0-100,               # Behavioral risk score
    'indicators': [...],           # List of detected indicators
    'pattern': 'Brute Force|Credential Stuffing|Username Enumeration|Reconnaissance',
    'velocity': float,             # Attacks per minute
    'failure_rate': float,         # Percentage of failed attempts
    'duration_minutes': float,
    'unique_usernames': int
}
```

**Scoring Logic:**
- Failure rate > 95%: +30 points
- Velocity > 20/min: +30 points
- Username diversity > 10: +25 points
- Pattern matching: +5-15 points

---

### 2. `calculate_geographic_risk_score(geo_data, threat_intel)`
**Location:** `/src/dashboard/routes/demo_routes.py` lines 197-251

**Purpose:** Enhanced geographic risk assessment with regional intelligence

**Returns:**
```python
{
    'score': 0-100,                # Geographic risk score
    'factors': [...],               # Risk factors list
    'is_high_risk_region': bool,
    'is_anonymized': bool,
    'regional_threat_count': int,
    'country': str,
    'country_code': str
}
```

**Scoring Logic:**
- High-risk countries (RU, CN, KP, IR, BY, SY): +40 points
- Tor Exit Node: +50 points
- VPN/Proxy: +30 points
- Datacenter/Hosting IP: +25 points
- Heavily reported IP (>1000 reports): +20 points

---

### 3. `calculate_composite_risk(threat_intel, ml_analysis, behavioral, geographic)`
**Location:** `/src/dashboard/routes/demo_routes.py` lines 254-374

**Purpose:** Multi-factor weighted risk scoring system

**Weighted Model:**
- **Threat Intel Score × 0.35** (AbuseIPDB 70% + VirusTotal 30%)
- **ML Risk Score × 0.30** (Model prediction)
- **Behavioral Score × 0.25** (Attack pattern analysis)
- **Geographic Risk × 0.10** (Location-based risk)

**Returns:**
```python
{
    'overall_score': 0-100,
    'breakdown': {
        'threat_intel': {'score': X, 'weight': 0.35, 'weighted': Y, ...},
        'ml_prediction': {...},
        'behavioral': {...},
        'geographic': {...}
    },
    'threat_level': 'CRITICAL|HIGH|MODERATE|LOW|CLEAN',
    'confidence': 0-100,
    'factors_available': int
}
```

**Threat Level Thresholds:**
- CRITICAL: ≥85
- HIGH: ≥70
- MODERATE: ≥40
- LOW: ≥20
- CLEAN: <20

---

### 4. `generate_smart_recommendations(composite_risk, behavioral_analysis, threat_intel, ml_analysis, geo_data, history, ip_address)`
**Location:** `/src/dashboard/routes/demo_routes.py` lines 611-915

**Purpose:** Context-aware recommendations with reasoning, urgency grouping, and clear impact

**Returns:** List of recommendations with:

```python
{
    'urgency': 'immediate|short_term|long_term',  # Time grouping
    'priority': 'critical|high|medium|low',
    'action': str,                                 # Clear action title
    'reason': str,                                # Why this recommendation
    'why': [...],                                 # List of specific reasons
    'impact': str,                                # What happens if action taken
    'confidence': 0-1,                            # AI confidence
    'risk_if_ignored': str,                       # What happens if ignored
    'action_type': str,                           # Type of action
    'action_data': {...},                         # Data for execution
    'alternatives': [...]                         # Other approaches
}
```

**Urgency Levels:**
- **immediate** (5 minutes): Critical threats, active attacks
- **short_term** (1 hour): High priority, preventive actions
- **long_term** (1 week): Hardening, policy improvements

**Recommendation Types:**
1. Block IP Immediately (Critical - velocity > 10, score ≥ 85)
2. Enable Rate Limiting (High velocity or ≥20 failed attempts)
3. Protect Targeted Accounts (≥5 unique usernames)
4. Create Alert Rule (ML anomaly + risk ≥ 60)
5. Review Tor/VPN Policy (Anonymization detected)
6. Add to Permanent Blocklist (VirusTotal ≥ 5 detections)
7. Strengthen SSH Authentication (Total events ≥ 5, score ≥ 40)
8. Continue Monitoring (Low risk < 30)

---

## Updated API Endpoint

### `/api/demo/run/<scenario_id>` (POST)
**Location:** `/src/dashboard/routes/demo_routes.py` lines 960-1085

**New Response Structure:**

```json
{
    "success": true,
    "scenario_id": "...",
    "scenario_name": "...",
    "ip": "...",
    "event_id": "...",
    "event_type": "...",
    "expected": {...},

    // NEW: Composite risk assessment
    "composite_risk": {
        "overall_score": 87.3,
        "threat_level": "CRITICAL",
        "confidence": 94.2,
        "breakdown": {
            "threat_intel": {...},
            "ml_prediction": {...},
            "behavioral": {...},
            "geographic": {...}
        }
    },

    // NEW: Enhanced analysis sections
    "behavioral_analysis": {
        "score": 73,
        "indicators": [...],
        "pattern": "Brute Force",
        "velocity": 28.4,
        "failure_rate": 95.2
    },

    "geographic_intelligence": {
        "score": 90,
        "factors": [...],
        "is_high_risk_region": true,
        "is_anonymized": true
    },

    // Traditional results (backward compatible)
    "results": {
        "threat_intel": {...},
        "ml": {...},
        "geo": {...},
        "history": {...},
        "recommendations": [...]  // Enhanced with urgency + why + impact
    }
}
```

---

## Key Improvements

### 1. **Accurate Analysis**
- ✅ Multi-factor weighted scoring instead of simple thresholds
- ✅ Treats different metrics appropriately (AbuseIPDB ≠ ML risk score)
- ✅ Behavioral pattern detection (velocity, failure rate, username diversity)
- ✅ Geographic risk intelligence

### 2. **Context-Aware Recommendations**
- ✅ Each recommendation includes WHY (specific reasons)
- ✅ Clear IMPACT statement
- ✅ RISK_IF_IGNORED warnings
- ✅ ALTERNATIVES with trade-offs
- ✅ Time-based urgency grouping (immediate/short/long-term)

### 3. **Proper Prioritization**
- ✅ Sorted by urgency first, then priority
- ✅ Immediate actions appear first
- ✅ Long-term hardening appears last
- ✅ Not just "all critical = equal"

### 4. **Data-Driven Confidence**
- ✅ AI confidence based on actual metrics
- ✅ Scales with threat level
- ✅ Multiple data sources boost confidence
- ✅ No hardcoded values

---

## Testing

### Test Scenarios:

**Geographic Anomaly (218.92.0.107 - China):**
```bash
curl -X POST http://localhost:8081/api/demo/run/geographic_anomaly
```

**Expected New Fields:**
- `composite_risk.overall_score`: 40-60 (MODERATE)
- `behavioral_analysis.pattern`: "Reconnaissance" or "Unknown"
- `geographic_intelligence.is_high_risk_region`: true
- Recommendations: 3-5 with varied urgency levels

**Tor Exit Attack (185.220.101.1):**
```bash
curl -X POST http://localhost:8081/api/demo/run/tor_exit_attack
```

**Expected New Fields:**
- `composite_risk.overall_score`: 85+ (CRITICAL)
- `behavioral_analysis.pattern`: "Brute Force"
- `geographic_intelligence.is_anonymized`: true
- Recommendations: "Block IP Immediately" with urgency="immediate"

---

## Files Modified

1. `/src/dashboard/routes/demo_routes.py`
   - Added: `calculate_behavioral_score()` (lines 106-194)
   - Added: `calculate_geographic_risk_score()` (lines 197-251)
   - Added: `calculate_composite_risk()` (lines 254-374)
   - Added: `generate_smart_recommendations()` (lines 611-915)
   - Modified: `execute_scenario()` (lines 960-1085)

---

## Next Steps - Frontend Revamp

### Phase 3-5: Frontend Implementation (Pending)

1. **Restructure simulation.html to 3-tab layout**
   - Tab 1: Scenarios (Demo + Custom Simulation combined)
   - Tab 2: Analysis (Multi-factor risk display)
   - Tab 3: Results (Grouped recommendations)

2. **Build Analysis Tab**
   - Overall Threat Assessment card
   - Risk Breakdown with weighted components
   - Behavioral Analysis section
   - Geographic Intelligence section
   - Historical Context timeline

3. **Build Results Tab**
   - Immediate Actions (Next 5 min)
   - Short-Term Actions (Next hour)
   - Long-Term Hardening (This week)
   - Each recommendation shows: why, impact, risk_if_ignored, alternatives

4. **Auto-Tab Switching**
   - After scenario runs, auto-switch to Analysis tab
   - Store results globally for tab navigation

---

## Server Status

- ✅ **Running:** Port 8081
- ✅ **Backend Complete:** All analysis functions implemented
- ✅ **API Enhanced:** Returns composite_risk + behavioral_analysis + geographic_intelligence
- ✅ **Access:** https://ssh-guardian.rpu.solutions/dashboard
- ✅ **Logs:** `/home/rana-workspace/ssh_guardian_v3.0/dashboard.log`

---

**Backend implementation complete. Ready for frontend tab interface development.**
