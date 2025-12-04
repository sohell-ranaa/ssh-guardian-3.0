"""
Create a test agent for API testing
"""

import sys
import secrets
from pathlib import Path

# Add project paths
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.append(str(PROJECT_ROOT / "dbs"))

from connection import get_connection


def create_test_agent():
    """Create a test agent with API key"""

    # Generate secure API key
    api_key = secrets.token_urlsafe(32)

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # Check if test agent already exists
        cursor.execute("SELECT id, api_key FROM agents WHERE hostname = 'test-server-01'")
        existing = cursor.fetchone()

        if existing:
            print("=" * 70)
            print("⚠️  TEST AGENT ALREADY EXISTS")
            print("=" * 70)
            print(f"Agent ID:  {existing['id']}")
            print(f"API Key:   {existing['api_key']}")
            print("=" * 70)
            return existing['api_key']

        # Generate UUIDs
        import uuid
        agent_uuid = str(uuid.uuid4())
        agent_id_str = f"agent-{secrets.token_hex(8)}"

        # Create test agent
        cursor.execute("""
            INSERT INTO agents (
                agent_uuid,
                agent_id,
                api_key,
                hostname,
                display_name,
                agent_type,
                ip_address_primary,
                environment,
                status,
                health_status,
                version,
                heartbeat_interval_sec,
                consecutive_missed_heartbeats,
                total_events_sent,
                total_uptime_seconds,
                restart_count,
                is_active,
                is_approved,
                created_at,
                updated_at
            ) VALUES (
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW(), NOW()
            )
        """, (
            agent_uuid,
            agent_id_str,
            api_key,
            'test-server-01',
            'Test Agent 01',
            'primary',
            '127.0.0.1',
            'development',
            'online',
            'healthy',
            '1.0.0',
            60,
            0,
            0,
            0,
            0,
            True,
            True
        ))

        agent_id = cursor.lastrowid
        conn.commit()

        print("=" * 70)
        print("✅ TEST AGENT CREATED SUCCESSFULLY")
        print("=" * 70)
        print(f"Agent ID:       {agent_id}")
        print(f"Agent Name:     test-agent-01")
        print(f"Hostname:       test-server-01")
        print(f"API Key:        {api_key}")
        print("=" * 70)
        print("\n📝 Use this API key in the X-API-Key header:")
        print(f"\n   X-API-Key: {api_key}")
        print("\n🔗 API Endpoint:")
        print("   POST http://localhost:8081/api/events/submit")
        print("=" * 70)

        return api_key

    except Exception as e:
        conn.rollback()
        print(f"❌ Error creating agent: {e}")
        return None

    finally:
        cursor.close()
        conn.close()


if __name__ == "__main__":
    print("\n🤖 SSH Guardian v3.0 - Create Test Agent\n")
    create_test_agent()
    print()
