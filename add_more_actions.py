#!/usr/bin/env python3
"""
Add more blocking actions using existing IP blocks
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

def add_more_actions():
    """Add more blocking actions using existing data"""

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
        'DDoS attack attempt',
        'Automated scanning detected',
        'SQL injection attempt blocked',
        'Cross-site scripting (XSS) detected',
        'Invalid authentication tokens',
        'Rate limit exceeded'
    ]

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # Get existing IP blocks
        cursor.execute("SELECT id, ip_address_text FROM ip_blocks LIMIT 10")
        ip_blocks = cursor.fetchall()

        if not ip_blocks:
            print("❌ No IP blocks found. Please create some IP blocks first.")
            return

        print(f"✅ Found {len(ip_blocks)} IP blocks to use")

        # Get user ID
        cursor.execute("SELECT id FROM users LIMIT 1")
        user_result = cursor.fetchone()
        user_id = user_result['id'] if user_result else None

        # Get rule ID
        cursor.execute("SELECT id FROM blocking_rules LIMIT 1")
        rule_result = cursor.fetchone()
        rule_id = rule_result['id'] if rule_result else None

        # Create 15 more actions
        actions_created = 0

        for i in range(15):
            ip_block = random.choice(ip_blocks)
            action_type = random.choice(action_types)
            action_source = random.choice(action_sources)

            action_data = {
                'action_uuid': str(uuid.uuid4()),
                'ip_block_id': ip_block['id'],
                'ip_address_text': ip_block['ip_address_text'],
                'action_type': action_type,
                'action_source': action_source,
                'reason': random.choice(reasons),
                'performed_by_user_id': user_id if action_source == 'manual' else None,
                'triggered_by_rule_id': rule_id if action_source == 'rule' else None,
                'created_at': datetime.now() - timedelta(
                    days=random.randint(0, 15),
                    hours=random.randint(0, 23),
                    minutes=random.randint(0, 59)
                )
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
            print(f"  ✓ Action {actions_created}: {action_type.upper()} - {ip_block['ip_address_text']}")

        conn.commit()

        print(f"\n✅ Successfully created {actions_created} new blocking actions!")
        print(f"📍 View them at: http://31.220.94.187:8081/dashboard#actions")

        # Show summary
        cursor.execute("SELECT COUNT(*) as total FROM blocking_actions")
        total = cursor.fetchone()['total']
        print(f"\n📊 Total blocking actions in database: {total}")

        cursor.execute("""
            SELECT
                action_type,
                COUNT(*) as count
            FROM blocking_actions
            GROUP BY action_type
        """)

        print("\n📈 Summary by Action Type:")
        for row in cursor.fetchall():
            print(f"  - {row['action_type'].upper()}: {row['count']}")

        cursor.execute("""
            SELECT
                action_source,
                COUNT(*) as count
            FROM blocking_actions
            GROUP BY action_source
        """)

        print("\n📈 Summary by Action Source:")
        for row in cursor.fetchall():
            print(f"  - {row['action_source'].upper()}: {row['count']}")

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
    print("📊 ADDING MORE BLOCKING ACTIONS")
    print("=" * 70)
    add_more_actions()
