"""
Test Blocking Rules Engine
"""

import sys
from pathlib import Path
import json

# Add project paths
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.append(str(PROJECT_ROOT / "dbs"))
sys.path.append(str(PROJECT_ROOT / "src" / "core"))

from connection import get_connection
from blocking_engine import BlockingEngine, block_ip_manual, unblock_ip


def test_create_brute_force_rule():
    """Create a brute force detection rule"""
    print("\n" + "="*70)
    print("TEST: Create Brute Force Rule")
    print("="*70)

    conn = get_connection()
    cursor = conn.cursor()

    try:
        # Create brute force rule: 5 failed attempts in 10 minutes
        cursor.execute("""
            INSERT INTO blocking_rules (
                rule_name,
                rule_type,
                is_enabled,
                priority,
                conditions,
                block_duration_minutes,
                auto_unblock,
                notify_on_trigger,
                description
            ) VALUES (
                'Brute Force Protection',
                'brute_force',
                TRUE,
                100,
                %s,
                1440,
                TRUE,
                TRUE,
                'Block IPs with 5+ failed login attempts in 10 minutes'
            )
        """, (json.dumps({
            'failed_attempts': 5,
            'time_window_minutes': 10,
            'event_type': 'failed'
        }),))

        rule_id = cursor.lastrowid
        conn.commit()

        print(f"✅ Created brute force rule (ID: {rule_id})")
        print(f"   Condition: 5 failed attempts in 10 minutes")
        print(f"   Block duration: 1440 minutes (24 hours)")
        print(f"   Auto-unblock: Yes")

        return rule_id

    except Exception as e:
        print(f"❌ Error creating rule: {e}")
        return None
    finally:
        cursor.close()
        conn.close()


def test_create_threat_rule():
    """Create a threat-based blocking rule"""
    print("\n" + "="*70)
    print("TEST: Create Threat-Based Rule")
    print("="*70)

    conn = get_connection()
    cursor = conn.cursor()

    try:
        # Create threat-based rule: Block high/critical threat IPs
        cursor.execute("""
            INSERT INTO blocking_rules (
                rule_name,
                rule_type,
                is_enabled,
                priority,
                conditions,
                block_duration_minutes,
                auto_unblock,
                notify_on_trigger,
                description
            ) VALUES (
                'High Threat Auto-Block',
                'api_reputation',
                TRUE,
                90,
                %s,
                2880,
                TRUE,
                TRUE,
                'Automatically block IPs with high or critical threat level'
            )
        """, (json.dumps({
            'min_threat_level': 'high',
            'min_confidence': 0.5,
            'sources': ['abuseipdb', 'virustotal', 'shodan']
        }),))

        rule_id = cursor.lastrowid
        conn.commit()

        print(f"✅ Created threat-based rule (ID: {rule_id})")
        print(f"   Condition: Threat level >= high, confidence >= 0.5")
        print(f"   Block duration: 2880 minutes (48 hours)")
        print(f"   Auto-unblock: Yes")

        return rule_id

    except Exception as e:
        print(f"❌ Error creating rule: {e}")
        return None
    finally:
        cursor.close()
        conn.close()


def test_simulate_brute_force():
    """Simulate brute force attack by creating multiple failed events"""
    print("\n" + "="*70)
    print("TEST: Simulate Brute Force Attack")
    print("="*70)

    test_ip = "198.51.100.50"  # Test IP
    print(f"Simulating 6 failed attempts from {test_ip}...")

    conn = get_connection()
    cursor = conn.cursor()

    try:
        # Create 6 failed login attempts
        for i in range(6):
            cursor.execute("""
                INSERT INTO auth_events (
                    event_uuid,
                    timestamp,
                    source_type,
                    event_type,
                    source_ip,
                    source_ip_text,
                    target_server,
                    target_username,
                    auth_method
                ) VALUES (
                    UUID(), NOW(), 'agent', 'failed',
                    INET6_ATON(%s), %s, 'test-server', 'root', 'password'
                )
            """, (test_ip, test_ip))

        conn.commit()
        print(f"✅ Created 6 failed login events for {test_ip}")

        return test_ip

    except Exception as e:
        print(f"❌ Error creating events: {e}")
        return None
    finally:
        cursor.close()
        conn.close()


def test_evaluate_rules(ip_address):
    """Test rule evaluation for an IP"""
    print("\n" + "="*70)
    print(f"TEST: Evaluate Rules for {ip_address}")
    print("="*70)

    try:
        results = BlockingEngine.evaluate_rules_for_ip(ip_address)

        print(f"\n📋 Evaluated {len(results)} rules:\n")

        for result in results:
            rule = result['rule']
            print(f"Rule: {rule['rule_name']} ({rule['rule_type']})")
            print(f"  Priority: {rule['priority']}")
            print(f"  Should Block: {'YES' if result['should_block'] else 'NO'}")
            print(f"  Reason: {result['reason']}")
            print()

        return results

    except Exception as e:
        print(f"❌ Error evaluating rules: {e}")
        return []


def test_auto_block(ip_address):
    """Test automatic blocking based on rules"""
    print("\n" + "="*70)
    print(f"TEST: Auto-Block {ip_address}")
    print("="*70)

    try:
        result = BlockingEngine.check_and_block_ip(ip_address)

        if result['blocked']:
            print(f"🚫 IP {ip_address} BLOCKED")
            print(f"   Block ID: {result['block_id']}")
            print(f"   Triggered Rules: {', '.join(result['triggered_rules'])}")
            print(f"   Message: {result['message']}")
        else:
            print(f"✅ IP {ip_address} NOT blocked")
            print(f"   Message: {result['message']}")

        return result

    except Exception as e:
        print(f"❌ Error auto-blocking: {e}")
        return None


def test_manual_block():
    """Test manual IP blocking"""
    print("\n" + "="*70)
    print("TEST: Manual IP Block")
    print("="*70)

    test_ip = "203.0.113.100"  # Test IP
    print(f"Manually blocking {test_ip}...")

    try:
        result = block_ip_manual(
            ip_address=test_ip,
            reason="Manual block for testing",
            duration_minutes=60
        )

        if result['success']:
            print(f"✅ Manually blocked {test_ip}")
            print(f"   Block ID: {result['block_id']}")
            print(f"   Unblock at: {result['unblock_at']}")
        else:
            print(f"❌ Failed to block: {result['message']}")

        return test_ip if result['success'] else None

    except Exception as e:
        print(f"❌ Error: {e}")
        return None


def test_manual_unblock(ip_address):
    """Test manual IP unblocking"""
    print("\n" + "="*70)
    print(f"TEST: Manual IP Unblock")
    print("="*70)

    print(f"Manually unblocking {ip_address}...")

    try:
        result = unblock_ip(
            ip_address=ip_address,
            reason="Test unblock"
        )

        if result['success']:
            print(f"✅ {result['message']}")
        else:
            print(f"❌ {result['message']}")

        return result['success']

    except Exception as e:
        print(f"❌ Error: {e}")
        return False


def test_check_block_status(ip_address):
    """Check if IP is blocked"""
    print("\n" + "="*70)
    print(f"TEST: Check Block Status for {ip_address}")
    print("="*70)

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        cursor.execute("""
            SELECT
                id,
                block_reason,
                block_source,
                blocked_at,
                unblock_at,
                is_active
            FROM ip_blocks
            WHERE ip_address_text = %s
            ORDER BY blocked_at DESC
            LIMIT 1
        """, (ip_address,))

        block = cursor.fetchone()

        if block:
            print(f"\n📊 Block Information:")
            print(f"   Block ID: {block['id']}")
            print(f"   Reason: {block['block_reason']}")
            print(f"   Source: {block['block_source']}")
            print(f"   Blocked at: {block['blocked_at']}")
            print(f"   Unblock at: {block['unblock_at']}")
            print(f"   Active: {'YES' if block['is_active'] else 'NO'}")
        else:
            print(f"ℹ️  No block record found for {ip_address}")

        return block

    finally:
        cursor.close()
        conn.close()


def show_blocking_stats():
    """Show blocking statistics"""
    print("\n" + "="*70)
    print("Blocking Statistics")
    print("="*70)

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # Total blocks
        cursor.execute("SELECT COUNT(*) as count FROM ip_blocks")
        total = cursor.fetchone()['count']

        # Active blocks
        cursor.execute("SELECT COUNT(*) as count FROM ip_blocks WHERE is_active = TRUE")
        active = cursor.fetchone()['count']

        # Total rules
        cursor.execute("SELECT COUNT(*) as count FROM blocking_rules")
        total_rules = cursor.fetchone()['count']

        # Enabled rules
        cursor.execute("SELECT COUNT(*) as count FROM blocking_rules WHERE is_enabled = TRUE")
        enabled_rules = cursor.fetchone()['count']

        print(f"\n📊 Statistics:")
        print(f"   Total Blocks: {total}")
        print(f"   Active Blocks: {active}")
        print(f"   Total Rules: {total_rules}")
        print(f"   Enabled Rules: {enabled_rules}")

    finally:
        cursor.close()
        conn.close()


def main():
    """Run all tests"""
    print("\n" + "="*70)
    print("🧪 SSH Guardian v3.0 - Blocking Engine Tests")
    print("="*70)

    # Show initial stats
    show_blocking_stats()

    # Create rules
    brute_force_rule_id = test_create_brute_force_rule()
    threat_rule_id = test_create_threat_rule()

    # Simulate brute force attack
    test_ip = test_simulate_brute_force()

    if test_ip:
        # Evaluate rules for the test IP
        test_evaluate_rules(test_ip)

        # Try to auto-block based on rules
        test_auto_block(test_ip)

        # Check block status
        test_check_block_status(test_ip)

    # Test manual blocking
    manual_ip = test_manual_block()

    if manual_ip:
        # Check status
        test_check_block_status(manual_ip)

        # Unblock
        test_manual_unblock(manual_ip)

        # Check status again
        test_check_block_status(manual_ip)

    # Show final stats
    show_blocking_stats()

    print("\n" + "="*70)
    print("✅ All tests complete!")
    print("="*70 + "\n")


if __name__ == "__main__":
    main()
