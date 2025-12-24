"""
SSH Guardian v3.0 - Demo Scenarios (8 Core Test Scenarios)

USAGE MODES:
1. DEFAULT MODE  - Run scenario and see result immediately
2. GUIDED MODE   - Step-by-step with explanations and verification

SCENARIO CATEGORIES:
├── BASELINE (No Action)
│   └── 1. Clean Daytime Success
│
├── ALERT ONLY (Monitor, No Block)
│   ├── 2. Clean Midnight Success (off-hours)
│   ├── 4. Clean Multi-User (credential stuffing watch)
│   └── 7. Private IP Insider (internal threat)
│
├── FAIL2BAN BLOCK (Temporary 24h)
│   ├── 3. Clean 5 Failed (brute force)
│   └── 8. Bad IP 5 Failed (bad reputation)
│
├── FAIL2BAN BLOCK (Temporary 6h)
│   └── 5. Clean Multi-User Night (suspicious activity)
│
└── UFW BLOCK (Permanent 30 days)
    └── 6. Clean Persistent Attacker
"""

import sys
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime
import random

PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.append(str(PROJECT_ROOT / "dbs"))
sys.path.append(str(PROJECT_ROOT / "src"))


# =============================================================================
# SCENARIO DEFINITIONS
# =============================================================================

DEMO_SCENARIOS = {

    # =========================================================================
    # CATEGORY: BASELINE (No Action Expected)
    # =========================================================================

    "clean_daytime_success": {
        "id": "clean_daytime_success",
        "name": "1. Clean Daytime Success",
        "short_name": "Daytime Login",
        "category": "baseline",
        "category_label": "No Action",
        "action_type": "none",
        "icon": "✅",
        "color": "green",

        # What it tests
        "description": "Normal login during business hours from clean IP",
        "test_purpose": "Verify system does NOT trigger false positives for normal activity",

        # Technical details
        "trigger": "Clean IP (AbuseIPDB 0) + successful login + daytime (6 AM - 10 PM)",
        "expected_result": "NO alert, NO block",
        "block_duration": None,
        "rule_id": None,
        "rule_name": None,

        # How to verify
        "verification_steps": [
            "Check notifications table - should have NO new entries",
            "Check ip_blocks table - IP should NOT be blocked",
            "Check fail2ban status - IP should NOT be banned"
        ],

        # Simulation config
        "severity": "low",
        "ip": "8.8.8.8",
        "alternate_ips": ["1.1.1.1", "208.67.222.222"],
        "abuseipdb_score": 0,
        "log_template": "Dec {day} {time} server sshd[{pid}]: Accepted password for {username} from {ip} port {port} ssh2",
        "usernames": ["john.smith", "alice.johnson"],
        "custom_time": "10:30:00",
        "event_count": 1,

        # Guided mode hints
        "before_run": "This tests that normal logins don't trigger alerts",
        "after_run": "Verify no notifications were created - this is the baseline",
    },

    # =========================================================================
    # CATEGORY: ALERT ONLY (Monitor but Don't Block)
    # =========================================================================

    "clean_midnight_success": {
        "id": "clean_midnight_success",
        "name": "2. Clean Midnight Success",
        "short_name": "Night Login",
        "category": "alert_only",
        "category_label": "Alert Only",
        "action_type": "alert",
        "icon": "🔔",
        "color": "yellow",

        "description": "Successful login at 3 AM from clean IP",
        "test_purpose": "Verify off-hours detection creates alert but doesn't block clean IPs",

        "trigger": "Clean IP + successful login + off-hours (10 PM - 6 AM)",
        "expected_result": "Alert created, NO block",
        "block_duration": None,
        "rule_id": 19,
        "rule_name": "Off-Hours Successful Login Alert",

        "verification_steps": [
            "Check notifications table - should have 'Off-Hours' alert",
            "Check ip_blocks table - IP should NOT be blocked",
            "Alert should show time anomaly reason"
        ],

        "severity": "medium",
        "ip": "8.8.8.8",
        "alternate_ips": ["1.1.1.1"],
        "abuseipdb_score": 0,
        "log_template": "Dec {day} {time} server sshd[{pid}]: Accepted password for {username} from {ip} port {port} ssh2",
        "usernames": ["john.smith", "dev.user"],
        "custom_time": "03:00:00",
        "event_count": 1,

        "before_run": "This tests off-hours detection (10 PM - 6 AM)",
        "after_run": "Check for alert with 'Off-Hours' in the title - no block should occur",
    },

    "clean_multi_user": {
        "id": "clean_multi_user",
        "name": "4. Clean Multi-User",
        "short_name": "Multi-User",
        "category": "alert_only",
        "category_label": "Alert Only",
        "action_type": "alert",
        "icon": "👥",
        "color": "yellow",

        "description": "3 different users login from same clean IP",
        "test_purpose": "Detect potential credential stuffing success without blocking legitimate shared IPs",

        "trigger": "Clean IP + 3+ unique usernames succeed in 1 hour",
        "expected_result": "Alert created, NO block",
        "block_duration": None,
        "rule_id": 14,
        "rule_name": "Multi-User Same IP Alert",

        "verification_steps": [
            "Check notifications table - should have 'Multi-User' alert",
            "Check ip_blocks table - IP should NOT be blocked",
            "Alert should list the usernames involved"
        ],

        "severity": "medium",
        "ip": "73.162.0.1",
        "alternate_ips": ["24.48.0.1"],
        "abuseipdb_score": 0,
        "log_template": "Dec {day} {time} server sshd[{pid}]: Accepted password for {username} from {ip} port {port} ssh2",
        "usernames": ["john.smith", "alice.johnson", "bob.wilson"],
        "custom_time": "14:00:00",
        "event_count": 3,

        "before_run": "This tests multi-user detection (possible credential stuffing)",
        "after_run": "Check for 'Multi-User' alert - no block because it's daytime",
    },

    "private_ip_insider": {
        "id": "private_ip_insider",
        "name": "7. Private IP Insider",
        "short_name": "Insider Threat",
        "category": "alert_only",
        "category_label": "Alert Only",
        "action_type": "alert",
        "icon": "🏢",
        "color": "orange",

        "description": "Internal IP with brute force at 3 AM",
        "test_purpose": "Detect insider threats from private/internal IPs without blocking",

        "trigger": "Private IP (192.168.x.x, 10.x.x.x) + 5 failed logins + night",
        "expected_result": "Alert created, NO block (never block internal IPs)",
        "block_duration": None,
        "rule_id": None,
        "rule_name": "Private IP Behavioral Alert",

        "verification_steps": [
            "Check notifications table - should have insider threat alert",
            "Check ip_blocks table - private IP should NEVER be blocked",
            "Alert should indicate internal network origin"
        ],

        "severity": "high",
        "ip": "192.168.1.100",
        "alternate_ips": ["10.0.0.50", "172.16.0.25"],
        "abuseipdb_score": 0,
        "is_private_ip": True,
        "log_template": "Dec {day} {time} server sshd[{pid}]: Failed password for {username} from {ip} port {port} ssh2",
        "usernames": ["root", "admin", "deploy"],
        "custom_time": "03:00:00",
        "event_count": 5,

        "before_run": "This tests insider threat detection (private IPs are never blocked)",
        "after_run": "Alert should be created but NO block - internal IPs are monitored only",
    },

    # =========================================================================
    # CATEGORY: FAIL2BAN BLOCK (Temporary 24 hours)
    # =========================================================================

    "clean_5_failed": {
        "id": "clean_5_failed",
        "name": "3. Clean 5 Failed",
        "short_name": "Brute Force",
        "category": "fail2ban_block",
        "category_label": "Fail2ban 24h",
        "action_type": "block",
        "icon": "🔒",
        "color": "red",

        "description": "5 failed login attempts from clean IP",
        "test_purpose": "Block brute force attacks even from previously clean IPs",

        "trigger": "Clean IP + 5 failed logins in 1 hour",
        "expected_result": "IP blocked via fail2ban for 24 hours",
        "block_duration": "24 hours",
        "rule_id": 12,
        "rule_name": "Failed Login Block (5 attempts)",

        "verification_steps": [
            "Check ip_blocks table - IP should be blocked with 24h duration",
            "Run: sudo fail2ban-client status sshd - IP should be banned",
            "Block reason should mention 'brute force'"
        ],

        "severity": "high",
        "ip": "91.240.118.172",
        "alternate_ips": ["45.227.254.0", "193.56.28.103"],
        "abuseipdb_score": 0,
        "log_template": "Dec {day} {time} server sshd[{pid}]: Failed password for {username} from {ip} port {port} ssh2",
        "usernames": ["root", "admin", "user", "postgres", "mysql"],
        "event_count": 5,

        "before_run": "This tests fail2ban blocking for brute force attacks",
        "after_run": "Check fail2ban status - IP should be banned for 24 hours",
    },

    "bad_ip_5_failed": {
        "id": "bad_ip_5_failed",
        "name": "8. Bad IP 5 Failed",
        "short_name": "Bad IP Attack",
        "category": "fail2ban_block",
        "category_label": "Fail2ban 24h",
        "action_type": "block",
        "icon": "☠️",
        "color": "red",

        "description": "5 failed logins from bad reputation IP (AbuseIPDB 25+)",
        "test_purpose": "Faster blocking for IPs with bad reputation",

        "trigger": "Bad IP (AbuseIPDB 25+) + 5 failed logins",
        "expected_result": "IP blocked via fail2ban for 24 hours",
        "block_duration": "24 hours",
        "rule_id": 17,
        "rule_name": "Bad IP Failed Attempts Block",

        "verification_steps": [
            "Check ip_blocks table - IP should be blocked",
            "Run: sudo fail2ban-client status sshd - IP should be banned",
            "Block reason should mention 'bad reputation'"
        ],

        "severity": "high",
        "ip": "185.220.101.1",
        "alternate_ips": ["45.142.212.61"],
        "abuseipdb_score": 30,
        "log_template": "Dec {day} {time} server sshd[{pid}]: Failed password for {username} from {ip} port {port} ssh2",
        "usernames": ["root", "admin", "user", "postgres", "mysql"],
        "event_count": 5,

        "before_run": "This tests blocking of known bad IPs (Tor exit nodes, known attackers)",
        "after_run": "IP should be blocked - bad reputation + failed attempts = confirmed attack",
    },

    # =========================================================================
    # CATEGORY: FAIL2BAN BLOCK (Temporary 6 hours)
    # =========================================================================

    "clean_multi_user_night": {
        "id": "clean_multi_user_night",
        "name": "5. Clean Multi-User Night",
        "short_name": "Night Stuffing",
        "category": "credential_stuffing",
        "category_label": "Fail2ban 6h",
        "action_type": "block",
        "icon": "🌙",
        "color": "purple",

        "description": "3 different users login from same IP at 2 AM",
        "test_purpose": "Block suspicious multi-user activity during off-hours",

        "trigger": "Clean IP + 3+ users succeed + off-hours (10 PM - 6 AM)",
        "expected_result": "Alert created AND 6-hour temporary block",
        "block_duration": "6 hours",
        "rule_id": 20,
        "rule_name": "Multi-User Off-Hours Block",

        "verification_steps": [
            "Check notifications table - should have alert",
            "Check ip_blocks table - IP blocked for 6 hours",
            "Both alert AND block should occur"
        ],

        "severity": "high",
        "ip": "73.162.0.2",
        "alternate_ips": ["24.48.0.2"],
        "abuseipdb_score": 0,
        "log_template": "Dec {day} {time} server sshd[{pid}]: Accepted password for {username} from {ip} port {port} ssh2",
        "usernames": ["john.smith", "alice.johnson", "bob.wilson"],
        "custom_time": "02:00:00",
        "event_count": 3,

        "before_run": "This tests credential stuffing at night (suspicious + off-hours = block)",
        "after_run": "Both alert AND 6-hour block should be created",
    },

    # =========================================================================
    # CATEGORY: UFW BLOCK (Permanent 30 days)
    # =========================================================================

    "clean_10_failed_24h": {
        "id": "clean_10_failed_24h",
        "name": "6. Clean Persistent Attacker",
        "short_name": "UFW Block",
        "category": "ufw_block",
        "category_label": "UFW 30 days",
        "action_type": "block",
        "icon": "🛡️",
        "color": "darkred",

        "description": "10+ failed logins over 24 hours",
        "test_purpose": "Permanent block for persistent attackers",

        "trigger": "Any IP + 10+ failed logins in 24 hours",
        "expected_result": "IP blocked via UFW for 30 days (permanent)",
        "block_duration": "30 days",
        "rule_id": 13,
        "rule_name": "Persistent Attacker UFW Block",

        "verification_steps": [
            "Check ip_blocks table - IP blocked with UFW method",
            "Run: sudo ufw status - IP should have DENY rule",
            "Block should NOT auto-expire (manual removal needed)"
        ],

        "severity": "critical",
        "ip": "9.9.9.9",
        "alternate_ips": ["8.8.9.9", "8.8.9.8"],
        "abuseipdb_score": 0,
        "log_template": "Dec {day} {time} server sshd[{pid}]: Failed password for {username} from {ip} port {port} ssh2",
        "usernames": ["root", "admin", "user", "postgres", "mysql", "oracle", "test", "ftp", "www", "nginx"],
        "event_count": 10,

        "before_run": "This tests permanent UFW blocking for persistent attackers",
        "after_run": "Check UFW status - IP should be permanently blocked",
    },
}


# =============================================================================
# SCENARIO GROUPS FOR UI
# =============================================================================

SCENARIO_GROUPS = {
    "baseline": {
        "label": "Baseline (No Action)",
        "description": "Normal activity that should NOT trigger any alerts or blocks",
        "icon": "✅",
        "color": "green",
        "scenarios": ["clean_daytime_success"]
    },
    "alert_only": {
        "label": "Alert Only (Monitor)",
        "description": "Suspicious activity that creates alerts but doesn't block",
        "icon": "🔔",
        "color": "yellow",
        "scenarios": ["clean_midnight_success", "clean_multi_user", "private_ip_insider"]
    },
    "fail2ban": {
        "label": "Fail2ban Block (Temporary)",
        "description": "Attacks blocked via fail2ban (auto-expires)",
        "icon": "🔒",
        "color": "red",
        "scenarios": ["clean_5_failed", "clean_multi_user_night", "bad_ip_5_failed"]
    },
    "ufw": {
        "label": "UFW Block (Permanent)",
        "description": "Persistent attackers blocked via UFW firewall",
        "icon": "🛡️",
        "color": "darkred",
        "scenarios": ["clean_10_failed_24h"]
    }
}


# =============================================================================
# USAGE MODES
# =============================================================================

def get_scenario_for_mode(scenario_id: str, mode: str = "default") -> Dict:
    """
    Get scenario with mode-specific presentation.

    Modes:
    - default: Run immediately, show result
    - guided: Step-by-step with explanations
    """
    scenario = DEMO_SCENARIOS.get(scenario_id)
    if not scenario:
        return None

    result = {**scenario}

    if mode == "guided":
        result["show_before_hint"] = True
        result["show_verification"] = True
        result["show_after_hint"] = True
    else:
        result["show_before_hint"] = False
        result["show_verification"] = False
        result["show_after_hint"] = False

    return result


def get_scenarios_grouped() -> Dict:
    """Get scenarios organized by group for UI display"""
    result = {}
    for group_id, group in SCENARIO_GROUPS.items():
        result[group_id] = {
            **group,
            "scenarios": [DEMO_SCENARIOS[sid] for sid in group["scenarios"] if sid in DEMO_SCENARIOS]
        }
    return result


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def get_scenarios_by_category() -> Dict[str, List[Dict]]:
    """Get scenarios organized by blocking category"""
    categories = {}
    for scenario in DEMO_SCENARIOS.values():
        cat = scenario.get("category", "unknown")
        if cat not in categories:
            categories[cat] = []
        categories[cat].append(scenario)
    return categories


def get_demo_scenarios(use_fresh_ips: bool = True) -> List[Dict]:
    """Get list of all demo scenarios for UI"""
    scenarios = []
    for scenario_id, scenario in DEMO_SCENARIOS.items():
        ip = get_rotated_ip(scenario_id) if use_fresh_ips else scenario["ip"]
        scenario_data = {
            "id": scenario["id"],
            "name": scenario["name"],
            "short_name": scenario.get("short_name", scenario["name"]),
            "description": scenario["description"],
            "test_purpose": scenario.get("test_purpose", ""),
            "severity": scenario["severity"],
            "category": scenario.get("category", "unknown"),
            "category_label": scenario.get("category_label", ""),
            "icon": scenario.get("icon", ""),
            "color": scenario.get("color", "gray"),
            "ip": ip or scenario["ip"],
            "trigger": scenario.get("trigger", ""),
            "expected_result": scenario.get("expected_result", ""),
            "block_duration": scenario.get("block_duration"),
            "rule_name": scenario.get("rule_name", ""),
            "action_type": scenario.get("action_type", "block"),
            "is_private_ip": scenario.get("is_private_ip", False),
            "event_count": scenario.get("event_count", 1),
            "usernames": scenario.get("usernames", ["root"]),
            "log_template": scenario.get("log_template", ""),
            "verification_steps": scenario.get("verification_steps", []),
            "before_run": scenario.get("before_run", ""),
            "after_run": scenario.get("after_run", ""),
        }
        scenarios.append(scenario_data)
    return scenarios


def get_demo_scenario(scenario_id: str) -> Optional[Dict]:
    """Get a specific demo scenario"""
    return DEMO_SCENARIOS.get(scenario_id)


def get_rotated_ip(scenario_id: str) -> str:
    """Get IP for scenario with optional rotation"""
    scenario = DEMO_SCENARIOS.get(scenario_id)
    if not scenario:
        return None

    # Baseline and alert scenarios use fixed IPs
    if scenario.get('category') in ['baseline', 'alert_only', 'private_ip']:
        return scenario['ip']

    # Clean IP scenarios use fixed IPs to ensure filters work
    if scenario.get('abuseipdb_score', 100) <= 20:
        if scenario.get('alternate_ips'):
            all_ips = [scenario['ip']] + scenario['alternate_ips']
            return random.choice(all_ips)
        return scenario['ip']

    # Try fresh IP pool for BAD IP scenarios only
    try:
        from simulation.ip_fetcher import get_fresh_ip
        fresh_ip = get_fresh_ip('brute_force')
        if fresh_ip:
            return fresh_ip
    except Exception:
        pass

    # Fallback to random alternate
    if scenario.get('alternate_ips'):
        all_ips = [scenario['ip']] + scenario['alternate_ips']
        return random.choice(all_ips)

    return scenario['ip']


def generate_demo_log(scenario_id: str, custom_ip: str = None) -> Optional[str]:
    """Generate a log line for a demo scenario"""
    scenario = DEMO_SCENARIOS.get(scenario_id)
    if not scenario:
        return None

    now = datetime.now()
    ip_to_use = custom_ip if custom_ip else get_rotated_ip(scenario_id)

    template = scenario.get("log_template", "")
    if not template:
        return None

    usernames = scenario.get('usernames', ['root', 'admin', 'user'])
    time_str = scenario.get('custom_time', now.strftime("%H:%M:%S"))

    log = template.format(
        day=now.day,
        time=time_str,
        pid=random.randint(10000, 99999),
        ip=ip_to_use,
        port=random.randint(40000, 65000),
        username=random.choice(usernames) if '{username}' in template else ''
    )
    return log


def run_demo_scenario(scenario_id: str, verbose: bool = False,
                      agent_id: int = None, mode: str = "default") -> Dict:
    """
    Execute a demo scenario.

    Args:
        scenario_id: ID of scenario to run
        verbose: Print detailed output
        agent_id: Target agent for blocking
        mode: "default" or "guided"
    """
    from core.log_processor import process_log_line

    scenario = DEMO_SCENARIOS.get(scenario_id)
    if not scenario:
        return {"success": False, "error": f"Unknown scenario: {scenario_id}"}

    # Default to first active agent
    if agent_id is None:
        try:
            from connection import get_connection
            conn = get_connection()
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT id FROM agents WHERE is_active = TRUE LIMIT 1")
            agent_row = cursor.fetchone()
            if agent_row:
                agent_id = agent_row['id']
            cursor.close()
            conn.close()
        except Exception:
            pass

    if verbose or mode == "guided":
        print(f"\n{'='*60}")
        print(f"{scenario.get('icon', '')} SCENARIO: {scenario['name']}")
        print(f"{'='*60}")
        print(f"Purpose: {scenario.get('test_purpose', scenario['description'])}")
        print(f"Trigger: {scenario.get('trigger', 'N/A')}")
        print(f"Expected: {scenario.get('expected_result', 'N/A')}")
        if mode == "guided" and scenario.get('before_run'):
            print(f"\n💡 {scenario['before_run']}")
        print(f"{'='*60}")

    event_count = scenario.get('event_count', 1)
    rotated_ip = get_rotated_ip(scenario_id)

    if verbose:
        print(f"\nUsing IP: {rotated_ip}")
        print(f"Generating {event_count} events...")

    # Process events
    result = None
    cumulative_blocking = {'blocked': False, 'triggered_rules': [], 'alerts_created': 0}

    for i in range(event_count):
        log_line = generate_demo_log(scenario_id, custom_ip=rotated_ip)
        if verbose:
            print(f"  [{i+1}] {log_line}")

        result = process_log_line(
            log_line,
            source_type='agent' if agent_id else 'simulation',
            agent_id=agent_id,
            skip_blocking=False,
            skip_learning=True,
            skip_notifications=True
        )

        if result and result.get('success'):
            enrichment = result.get('enrichment', {})
            blocking_result = enrichment.get('blocking', {})
            proactive_block = result.get('proactive_block', {})

            if blocking_result.get('blocked'):
                cumulative_blocking['blocked'] = True
                if blocking_result.get('triggered_rules'):
                    for rule in blocking_result['triggered_rules']:
                        if rule not in cumulative_blocking['triggered_rules']:
                            cumulative_blocking['triggered_rules'].append(rule)
            if blocking_result.get('alerts_created', 0) > 0:
                cumulative_blocking['alerts_created'] += blocking_result.get('alerts_created', 0)

            if proactive_block and proactive_block.get('should_block'):
                cumulative_blocking['blocked'] = True
                cumulative_blocking['proactive'] = True

    # Show guided mode hints
    if mode == "guided" and scenario.get('after_run'):
        print(f"\n✅ {scenario['after_run']}")
        if scenario.get('verification_steps'):
            print("\n📋 Verification Steps:")
            for step in scenario['verification_steps']:
                print(f"   • {step}")

    if result and result.get('success'):
        enrichment = result.get('enrichment', {})
        return {
            "success": True,
            "scenario_id": scenario_id,
            "scenario_name": scenario["name"],
            "ip": rotated_ip,
            "event_count": event_count,
            "event_id": result.get('event_id'),
            "is_private_ip": enrichment.get('is_private_ip', False),
            "blocking": cumulative_blocking,
            "expected_result": scenario.get("expected_result"),
            "verification_steps": scenario.get("verification_steps", []),
        }
    else:
        return {"success": False, "error": result.get('error') if result else "No result"}


def run_full_demo(verbose: bool = True, mode: str = "default") -> Dict:
    """Run all 8 demo scenarios."""
    results = []
    summary = {"total": len(DEMO_SCENARIOS), "successful": 0, "blocked": 0, "alerts": 0}

    if verbose:
        print("\n" + "=" * 60)
        print("🚀 SSH GUARDIAN v3.0 - FULL DEMO (8 SCENARIOS)")
        print("=" * 60)
        print("\nScenario Categories:")
        for group_id, group in SCENARIO_GROUPS.items():
            print(f"  {group['icon']} {group['label']}: {len(group['scenarios'])} scenarios")
        print("=" * 60)

    for scenario_id in DEMO_SCENARIOS:
        result = run_demo_scenario(scenario_id, verbose=verbose, mode=mode)
        results.append(result)

        if result.get('success'):
            summary['successful'] += 1
            if result.get('blocking', {}).get('blocked'):
                summary['blocked'] += 1
            if result.get('blocking', {}).get('alerts_created', 0) > 0:
                summary['alerts'] += 1

    if verbose:
        print("\n" + "=" * 60)
        print(f"📊 SUMMARY")
        print(f"   Scenarios: {summary['successful']}/{summary['total']} successful")
        print(f"   Blocks: {summary['blocked']}")
        print(f"   Alerts: {summary['alerts']}")
        print("=" * 60)

    return {"success": True, "summary": summary, "results": results}


# =============================================================================
# QUICK REFERENCE
# =============================================================================

def print_quick_reference():
    """Print quick reference guide for all scenarios"""
    print("""
╔══════════════════════════════════════════════════════════════════════════════╗
║                    SSH GUARDIAN v3.0 - SCENARIO REFERENCE                    ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║  ✅ BASELINE (No Action)                                                     ║
║  ├─ 1. clean_daytime_success    Normal login, daytime     → NO action       ║
║                                                                              ║
║  🔔 ALERT ONLY (Monitor)                                                     ║
║  ├─ 2. clean_midnight_success   Night login (3 AM)        → Alert only      ║
║  ├─ 4. clean_multi_user         3 users, daytime          → Alert only      ║
║  └─ 7. private_ip_insider       Internal IP, brute force  → Alert only      ║
║                                                                              ║
║  🔒 FAIL2BAN (Temporary Block)                                               ║
║  ├─ 3. clean_5_failed           5 failed logins           → Block 24h       ║
║  ├─ 5. clean_multi_user_night   3 users at night          → Block 6h        ║
║  └─ 8. bad_ip_5_failed          Bad IP + 5 failed         → Block 24h       ║
║                                                                              ║
║  🛡️  UFW (Permanent Block)                                                   ║
║  └─ 6. clean_10_failed_24h      10+ failed in 24h         → Block 30 days   ║
║                                                                              ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  USAGE:                                                                      ║
║  • Default Mode:  run_demo_scenario("clean_5_failed")                        ║
║  • Guided Mode:   run_demo_scenario("clean_5_failed", mode="guided")         ║
║  • Run All:       run_full_demo()                                            ║
╚══════════════════════════════════════════════════════════════════════════════╝
    """)
