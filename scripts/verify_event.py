"""
Verify test event was saved to database
"""

import sys
from pathlib import Path

# Add project paths
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.append(str(PROJECT_ROOT / "dbs"))

from connection import get_connection


def verify_event():
    """Check if events were saved"""
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        cursor.execute("""
            SELECT
                id,
                event_uuid,
                timestamp,
                source_type,
                source_ip_text,
                target_username,
                event_type,
                auth_method,
                target_server,
                target_port,
                agent_id,
                raw_log_line
            FROM auth_events
            ORDER BY id DESC
            LIMIT 5
        """)

        events = cursor.fetchall()

        if not events:
            print("❌ No events found in database")
            return

        print("=" * 70)
        print(f"✅ Found {len(events)} event(s) in database")
        print("=" * 70)

        for event in events:
            print(f"\nEvent ID: {event['id']}")
            print(f"UUID: {event['event_uuid']}")
            print(f"Time: {event['timestamp']}")
            print(f"Source: {event['source_type']}")
            print(f"IP: {event['source_ip_text']}")
            print(f"User: {event['target_username']}")
            print(f"Status: {event['event_type']}")
            print(f"Method: {event['auth_method']}")
            print(f"Server: {event['target_server']}")
            print(f"Port: {event['target_port']}")
            print(f"Agent ID: {event['agent_id']}")
            print(f"Raw Log: {event['raw_log_line'][:80] if event['raw_log_line'] else 'N/A'}...")
            print("-" * 70)

    finally:
        cursor.close()
        conn.close()


if __name__ == "__main__":
    print("\n🔍 SSH Guardian v3.0 - Verify Events\n")
    verify_event()
    print()
