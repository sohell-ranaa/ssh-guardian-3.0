#!/usr/bin/env python3
"""
Populate IP Statistics table with sample data from existing IP blocks
"""
import sys
import os
from pathlib import Path
from datetime import datetime, timedelta
import random

# Add dbs directory to path
PROJECT_ROOT = Path(__file__).parent
sys.path.append(str(PROJECT_ROOT / "dbs"))

from connection import get_connection

def populate_ip_statistics():
    """Populate ip_statistics table with data based on existing ip_blocks"""

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # Get existing IP blocks
        cursor.execute("""
            SELECT
                b.ip_address_text,
                b.is_active as currently_blocked,
                b.blocked_at,
                g.id as geo_id
            FROM ip_blocks b
            LEFT JOIN ip_geolocation g ON b.ip_address_text = g.ip_address_text
            WHERE b.ip_address_text IS NOT NULL
        """)
        ip_blocks = cursor.fetchall()

        if not ip_blocks:
            print("❌ No IP blocks found. Please create some IP blocks first.")
            return

        print(f"✅ Found {len(ip_blocks)} IP blocks to create statistics for")

        # Check how many already exist in ip_statistics
        cursor.execute("SELECT COUNT(*) as count FROM ip_statistics")
        existing_count = cursor.fetchone()['count']

        if existing_count > 0:
            print(f"⚠️  Found {existing_count} existing IP statistics entries")
            print(f"✅ Will add statistics for new IPs only...")

        stats_created = 0
        stats_updated = 0

        for ip_block in ip_blocks:
            ip_address = ip_block['ip_address_text']

            # Check if this IP already has statistics
            cursor.execute("""
                SELECT id FROM ip_statistics
                WHERE ip_address_text = %s
            """, (ip_address,))

            existing_stat = cursor.fetchone()

            if existing_stat:
                stats_updated += 1
                continue

            # Generate sample statistics for this IP
            total_events = random.randint(5, 500)
            failed_events = random.randint(3, int(total_events * 0.9))
            successful_events = random.randint(0, int(total_events * 0.3))
            invalid_events = total_events - failed_events - successful_events

            # Calculate risk score based on failure rate
            failure_rate = failed_events / total_events if total_events > 0 else 0
            avg_risk_score = min(100, int(failure_rate * 100 + random.randint(0, 20)))
            max_risk_score = min(100, avg_risk_score + random.randint(0, 15))

            # Calculate times blocked
            times_blocked = random.randint(1, 5) if ip_block['currently_blocked'] else random.randint(0, 3)

            # Create timestamps
            first_seen = datetime.now() - timedelta(days=random.randint(1, 90))
            last_seen = datetime.now() - timedelta(hours=random.randint(0, 48))
            last_blocked_at = ip_block['blocked_at'] if ip_block['blocked_at'] else None

            stat_data = {
                'ip_address_text': ip_address,
                'geo_id': ip_block['geo_id'],
                'total_events': total_events,
                'failed_events': failed_events,
                'successful_events': successful_events,
                'invalid_events': invalid_events,
                'unique_servers': random.randint(1, 5),
                'unique_usernames': random.randint(1, 20),
                'avg_risk_score': avg_risk_score,
                'max_risk_score': max_risk_score,
                'anomaly_count': random.randint(0, 10),
                'times_blocked': times_blocked,
                'currently_blocked': 1 if ip_block['currently_blocked'] else 0,
                'last_blocked_at': last_blocked_at,
                'first_seen': first_seen,
                'last_seen': last_seen
            }

            cursor.execute("""
                INSERT INTO ip_statistics
                (ip_address_text, geo_id, total_events, failed_events, successful_events,
                 invalid_events, unique_servers, unique_usernames, avg_risk_score, max_risk_score,
                 anomaly_count, times_blocked, currently_blocked, last_blocked_at, first_seen, last_seen)
                VALUES (%(ip_address_text)s, %(geo_id)s, %(total_events)s, %(failed_events)s,
                        %(successful_events)s, %(invalid_events)s, %(unique_servers)s,
                        %(unique_usernames)s, %(avg_risk_score)s, %(max_risk_score)s,
                        %(anomaly_count)s, %(times_blocked)s, %(currently_blocked)s,
                        %(last_blocked_at)s, %(first_seen)s, %(last_seen)s)
            """, stat_data)

            stats_created += 1
            print(f"  ✓ Created statistics for {ip_address} (risk: {avg_risk_score}, events: {total_events})")

        conn.commit()

        print(f"\n{'='*70}")
        print(f"✅ Successfully created {stats_created} IP statistics entries!")
        if stats_updated > 0:
            print(f"⏭️  Skipped {stats_updated} IPs that already had statistics")

        # Show summary
        cursor.execute("SELECT COUNT(*) as total FROM ip_statistics")
        total = cursor.fetchone()['total']
        print(f"\n📊 Total IP statistics in database: {total}")

        cursor.execute("""
            SELECT
                CASE
                    WHEN avg_risk_score >= 70 THEN 'High Risk'
                    WHEN avg_risk_score >= 40 THEN 'Medium Risk'
                    ELSE 'Low Risk'
                END as risk_level,
                COUNT(*) as count
            FROM ip_statistics
            WHERE avg_risk_score IS NOT NULL
            GROUP BY risk_level
        """)

        print(f"\n📈 Risk Distribution:")
        for row in cursor.fetchall():
            print(f"  - {row['risk_level']}: {row['count']}")

        cursor.execute("""
            SELECT
                SUM(total_events) as total_events,
                SUM(failed_events) as failed_events,
                SUM(currently_blocked) as blocked_count
            FROM ip_statistics
        """)

        summary = cursor.fetchone()
        print(f"\n📈 Overall Statistics:")
        print(f"  - Total Events: {summary['total_events']:,}")
        print(f"  - Failed Events: {summary['failed_events']:,}")
        print(f"  - Currently Blocked: {summary['blocked_count']}")

        print(f"\n{'='*70}")
        print(f"📍 View statistics at: http://31.220.94.187:8081/dashboard#ip-stats")
        print(f"{'='*70}")

    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        conn.rollback()
    finally:
        cursor.close()
        conn.close()

if __name__ == '__main__':
    print("="*70)
    print("📊 POPULATING IP STATISTICS TABLE")
    print("="*70)
    populate_ip_statistics()
