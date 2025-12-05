#!/usr/bin/env python3
"""
Populate sample blocking actions data for testing
"""
import sys
import os
from pathlib import Path
from datetime import datetime, timedelta
import uuid
import random

# Add dbs directory to path
PROJECT_ROOT = Path(__file__).parent
sys.path.append(str(PROJECT_ROOT / "dbs"))

from connection import get_connection

def populate_sample_actions():
    """Populate blocking actions table with sample data"""

    # Sample IPs and locations
    sample_ips = [
        ('192.168.1.100', 'United States', 'New York'),
        ('10.0.0.50', 'China', 'Beijing'),
        ('172.16.0.25', 'Russia', 'Moscow'),
        ('203.0.113.42', 'Germany', 'Berlin'),
        ('198.51.100.33', 'United Kingdom', 'London'),
        ('185.220.101.55', 'France', 'Paris'),
        ('45.142.120.10', 'Netherlands', 'Amsterdam'),
        ('91.203.4.92', 'Ukraine', 'Kyiv'),
        ('104.244.42.65', 'Brazil', 'São Paulo'),
        ('118.25.6.39', 'Japan', 'Tokyo')
    ]

    action_types = ['blocked', 'unblocked', 'blocked', 'blocked', 'modified']
    action_sources = ['system', 'manual', 'rule', 'api', 'manual']

    reasons = [
        'Brute force attack detected - 5 failed attempts in 10 minutes',
        'Manually blocked by administrator',
        'Triggered blocking rule: Excessive failed logins',
        'API reputation check failed - known malicious IP',
        'Suspicious activity pattern detected',
        'Manually unblocked after verification',
        'False positive - legitimate user',
        'Multiple authentication failures',
        'Port scanning activity detected',
        'DDoS attack attempt'
    ]

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # Check if we already have data
        cursor.execute("SELECT COUNT(*) as count FROM blocking_actions")
        existing_count = cursor.fetchone()['count']

        if existing_count > 0:
            print(f"⚠️  Found {existing_count} existing blocking actions")
            print(f"✅ Adding more sample data...")

        # Get user IDs for manual actions
        cursor.execute("SELECT id FROM users LIMIT 1")
        user_result = cursor.fetchone()
        user_id = user_result['id'] if user_result else None

        # Get rule IDs
        cursor.execute("SELECT id FROM blocking_rules LIMIT 1")
        rule_result = cursor.fetchone()
        rule_id = rule_result['id'] if rule_result else None

        # Create sample ip_blocks first
        print("📝 Creating sample IP blocks...")
        ip_block_ids = {}

        for ip, country, city in sample_ips:
            # Check if IP already blocked
            cursor.execute("SELECT id FROM ip_blocks WHERE ip_address_text = %s", (ip,))
            existing_block = cursor.fetchone()

            if existing_block:
                ip_block_ids[ip] = existing_block['id']
                print(f"  ✓ IP block already exists for {ip}")
            else:
                # Create IP block
                block_data = {
                    'ip_address_text': ip,
                    'block_reason': random.choice(reasons),
                    'block_source': random.choice(['manual', 'rule_based', 'api_reputation']),
                    'is_active': random.choice([True, True, False]),  # More active than inactive
                    'blocked_at': datetime.now() - timedelta(days=random.randint(0, 30)),
                    'auto_unblock': random.choice([True, False])
                }

                cursor.execute("""
                    INSERT INTO ip_blocks
                    (ip_address_text, block_reason, block_source, is_active, blocked_at, auto_unblock)
                    VALUES (%(ip_address_text)s, %(block_reason)s, %(block_source)s,
                            %(is_active)s, %(blocked_at)s, %(auto_unblock)s)
                """, block_data)

                ip_block_ids[ip] = cursor.lastrowid
                print(f"  ✓ Created IP block for {ip}")

        conn.commit()

        # Create GeoIP entries
        print("\n🌍 Creating GeoIP entries...")
        for ip, country, city in sample_ips:
            cursor.execute("SELECT id FROM ip_geolocation WHERE ip_address_text = %s", (ip,))
            if not cursor.fetchone():
                cursor.execute("""
                    INSERT INTO ip_geolocation
                    (ip_address_text, country_name, country_code, city)
                    VALUES (%s, %s, %s, %s)
                """, (ip, country, country[:2].upper(), city))
                print(f"  ✓ Created GeoIP entry for {ip} - {city}, {country}")

        conn.commit()

        # Now create blocking actions
        print("\n📊 Creating blocking actions...")
        actions_created = 0

        for i in range(20):  # Create 20 sample actions
            ip, country, city = random.choice(sample_ips)
            action_type = random.choice(action_types)
            action_source = random.choice(action_sources)

            action_data = {
                'action_uuid': str(uuid.uuid4()),
                'ip_block_id': ip_block_ids.get(ip),
                'ip_address_text': ip,
                'action_type': action_type,
                'action_source': action_source,
                'reason': random.choice(reasons),
                'performed_by_user_id': user_id if action_source == 'manual' else None,
                'triggered_by_rule_id': rule_id if action_source == 'rule' else None,
                'created_at': datetime.now() - timedelta(days=random.randint(0, 30),
                                                         hours=random.randint(0, 23),
                                                         minutes=random.randint(0, 59))
            }

            cursor.execute("""
                INSERT INTO blocking_actions
                (action_uuid, ip_block_id, ip_address_text, action_type, action_source,
                 reason, performed_by_user_id, triggered_by_rule_id, created_at)
                VALUES (%(action_uuid)s, %(ip_block_id)s, %(ip_address_text)s,
                        %(action_type)s, %(action_source)s, %(reason)s,
                        %(performed_by_user_id)s, %(triggered_by_rule_id)s, %(created_at)s)
            """, action_data)

            actions_created += 1

        conn.commit()

        print(f"\n✅ Successfully created {actions_created} blocking actions!")
        print(f"\n📍 View them at: http://31.220.94.187:8081/dashboard#actions")

        # Show summary
        cursor.execute("""
            SELECT
                action_type,
                COUNT(*) as count
            FROM blocking_actions
            GROUP BY action_type
        """)

        print("\n📈 Summary by Action Type:")
        for row in cursor.fetchall():
            print(f"  - {row['action_type']}: {row['count']}")

        cursor.execute("""
            SELECT
                action_source,
                COUNT(*) as count
            FROM blocking_actions
            GROUP BY action_source
        """)

        print("\n📈 Summary by Action Source:")
        for row in cursor.fetchall():
            print(f"  - {row['action_source']}: {row['count']}")

    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        conn.rollback()
    finally:
        cursor.close()
        conn.close()

if __name__ == '__main__':
    print("=" * 70)
    print("🔧 SSH GUARDIAN v3.0 - POPULATE BLOCKING ACTIONS DATA")
    print("=" * 70)
    populate_sample_actions()
