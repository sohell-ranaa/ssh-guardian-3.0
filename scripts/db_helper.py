#!/usr/bin/env python3
"""
Database Helper - Quick database operations without mysql CLI
"""

import sys
from pathlib import Path

# Add project paths
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.append(str(PROJECT_ROOT / "dbs"))

from connection import get_connection


def run_query(query, params=None, fetch='all'):
    """Run a query and return results"""
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        cursor.execute(query, params or ())

        if fetch == 'one':
            return cursor.fetchone()
        elif fetch == 'all':
            return cursor.fetchall()
        elif fetch == 'none':
            conn.commit()
            return cursor.lastrowid
        else:
            return cursor.fetchall()
    except Exception as e:
        print(f"❌ Query error: {e}")
        return None
    finally:
        cursor.close()
        conn.close()


def show_table_count(table):
    """Show row count for a table"""
    result = run_query(f"SELECT COUNT(*) as count FROM {table}", fetch='one')
    if result:
        print(f"  {table}: {result['count']} rows")


def show_stats():
    """Show database statistics"""
    print("\n" + "="*60)
    print("SSH Guardian v3.0 - Database Statistics")
    print("="*60)

    tables = [
        'auth_events',
        'agents',
        'ip_geolocation',
        'ip_blocks',
        'users',
        'user_sessions',
        'blocking_rules',
        'notifications'
    ]

    print("\nTable Row Counts:")
    for table in tables:
        show_table_count(table)

    print("\nRecent Activity:")

    # Recent events
    events = run_query("""
        SELECT COUNT(*) as count, MAX(timestamp) as latest
        FROM auth_events
        WHERE timestamp > DATE_SUB(NOW(), INTERVAL 1 HOUR)
    """, fetch='one')

    if events:
        print(f"  Events (last hour): {events['count']}")
        print(f"  Latest event: {events['latest']}")

    # Active agents
    agents = run_query("""
        SELECT COUNT(*) as count
        FROM agents
        WHERE is_active = TRUE
    """, fetch='one')

    if agents:
        print(f"  Active agents: {agents['count']}")

    # Active sessions
    sessions = run_query("""
        SELECT COUNT(*) as count
        FROM user_sessions
        WHERE expires_at > NOW()
    """, fetch='one')

    if sessions:
        print(f"  Active sessions: {sessions['count']}")

    print("\n" + "="*60 + "\n")


def show_recent_events(limit=5):
    """Show recent auth events"""
    print("\n" + "="*60)
    print(f"Recent {limit} Auth Events")
    print("="*60)

    events = run_query(f"""
        SELECT
            id,
            event_uuid,
            timestamp,
            source_ip_text,
            target_username,
            event_type,
            auth_method,
            target_server
        FROM auth_events
        ORDER BY id DESC
        LIMIT {limit}
    """)

    if not events:
        print("No events found")
        return

    for event in events:
        print(f"\nID: {event['id']}")
        print(f"  Time: {event['timestamp']}")
        print(f"  IP: {event['source_ip_text']}")
        print(f"  User: {event['target_username']}")
        print(f"  Status: {event['event_type']}")
        print(f"  Method: {event['auth_method']}")
        print(f"  Server: {event['target_server']}")
        print("-"*60)

    print()


def show_agents():
    """Show all agents"""
    print("\n" + "="*60)
    print("Agents")
    print("="*60)

    agents = run_query("""
        SELECT
            id,
            display_name,
            hostname,
            status,
            environment,
            is_active,
            last_heartbeat,
            total_events_sent
        FROM agents
        ORDER BY id
    """)

    if not agents:
        print("No agents found")
        return

    for agent in agents:
        status_emoji = "✅" if agent['is_active'] else "❌"
        print(f"\n{status_emoji} ID: {agent['id']} - {agent['display_name']}")
        print(f"  Hostname: {agent['hostname']}")
        print(f"  Status: {agent['status']}")
        print(f"  Environment: {agent['environment']}")
        print(f"  Events sent: {agent['total_events_sent']}")
        print(f"  Last heartbeat: {agent['last_heartbeat']}")
        print("-"*60)

    print()


def custom_query():
    """Interactive query mode"""
    print("\n" + "="*60)
    print("Custom Query Mode")
    print("="*60)
    print("Enter SQL query (or 'exit' to quit):")
    print()

    while True:
        try:
            query = input("SQL> ").strip()

            if query.lower() == 'exit':
                break

            if not query:
                continue

            results = run_query(query)

            if results is None:
                continue

            if isinstance(results, int):
                print(f"✅ Rows affected: {results}")
            elif isinstance(results, list):
                if len(results) == 0:
                    print("No results")
                else:
                    print(f"\nResults ({len(results)} rows):")
                    for i, row in enumerate(results, 1):
                        print(f"\nRow {i}:")
                        for key, val in row.items():
                            print(f"  {key}: {val}")
            else:
                print(f"Result: {results}")

            print()

        except KeyboardInterrupt:
            print("\n")
            break
        except Exception as e:
            print(f"❌ Error: {e}")


def main():
    if len(sys.argv) > 1:
        command = sys.argv[1]

        if command == 'stats':
            show_stats()
        elif command == 'events':
            limit = int(sys.argv[2]) if len(sys.argv) > 2 else 5
            show_recent_events(limit)
        elif command == 'agents':
            show_agents()
        elif command == 'query':
            custom_query()
        else:
            print(f"Unknown command: {command}")
            print("\nUsage:")
            print("  python3 scripts/db_helper.py stats          # Show statistics")
            print("  python3 scripts/db_helper.py events [N]     # Show recent N events")
            print("  python3 scripts/db_helper.py agents         # Show all agents")
            print("  python3 scripts/db_helper.py query          # Interactive query mode")
    else:
        # Default: show stats
        show_stats()


if __name__ == "__main__":
    main()
