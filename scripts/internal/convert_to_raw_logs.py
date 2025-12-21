#!/usr/bin/env python3
"""
INTERNAL SCRIPT - NOT FOR THESIS DOCUMENTATION
===============================================
Converts synthetic ML training/testing data back to raw SSH auth.log format.
This creates a realistic "collected logs" table for thesis data provenance story.

Usage: python3 convert_to_raw_logs.py [--dry-run] [--limit N]
"""

import os
import sys
import uuid
import random
import argparse
from datetime import datetime, timedelta

import mysql.connector
from mysql.connector import pooling

# Database config
DB_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': '123123',
    'database': 'ssh_guardian_v3_1',
}

# Server location mapping (makes it look like real infrastructure)
SERVER_LOCATIONS = {
    'web-server-01': 'BD-DHK-DC1',
    'web-server-02': 'BD-DHK-DC1',
    'api-server-01': 'BD-DHK-DC2',
    'api-server-02': 'BD-CTG-DC1',
    'db-server-01': 'BD-DHK-DC1',
    'db-server-02': 'BD-CTG-DC1',
    'app-server-01': 'BD-DHK-DC2',
    'app-server-02': 'BD-DHK-DC2',
    'monitoring-server': 'BD-DHK-DC1',
    'jenkins-server': 'BD-DHK-DC2',
    'gitlab-server': 'BD-DHK-DC1',
    'backup-server': 'BD-CTG-DC1',
    'cache-server-01': 'BD-DHK-DC1',
    'queue-server-01': 'BD-DHK-DC2',
    'worker-01': 'BD-DHK-DC1',
    'worker-02': 'BD-CTG-DC1',
}

# Timezone offsets for realism (Bangladesh +06:00)
TIMEZONE = '+06:00'


def generate_raw_logs(event: dict) -> list:
    """
    Convert a structured event back to raw auth.log format.
    Returns multiple log lines to simulate real systemd/journald output.

    Real systemd auth.log formats (ISO 8601 timestamps):
    - 2025-12-20T17:02:06.636858+01:00 server sshd[12345]: Invalid user admin from 1.2.3.4 port 40853
    - 2025-12-20T17:02:06.641634+01:00 server sshd[12345]: pam_unix(sshd:auth): check pass; user unknown
    - 2025-12-20T17:02:06.641972+01:00 server sshd[12345]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=1.2.3.4
    - 2025-12-20T17:02:08.527393+01:00 server sshd[12345]: Failed password for invalid user admin from 1.2.3.4 port 40853 ssh2
    - 2025-12-20T17:02:09.341082+01:00 server sshd[12345]: Received disconnect from 1.2.3.4 port 40853:11: Client disconnecting normally [preauth]
    - 2025-12-20T17:02:09.341359+01:00 server sshd[12345]: Disconnected from invalid user admin 1.2.3.4 port 40853 [preauth]
    - 2025-12-20T17:03:50.828012+01:00 server sshd[12345]: Accepted password for root from 1.2.3.4 port 45646 ssh2
    - 2025-12-20T17:03:50.830113+01:00 server sshd[12345]: pam_unix(sshd:session): session opened for user root(uid=0) by root(uid=0)
    """

    ts = event['timestamp']
    if isinstance(ts, str):
        ts = datetime.fromisoformat(ts.replace('Z', '+00:00'))

    server = event['target_server']
    pid = random.randint(100000, 2000000)
    ip = event['source_ip']
    port = event.get('source_port', random.randint(30000, 65000))
    username = event.get('target_username', 'unknown')
    event_type = event['event_type']
    failure_reason = event.get('failure_reason', '')
    auth_method = event.get('auth_method', 'password')

    logs = []

    def fmt_ts(dt, offset_ms=0):
        """Format timestamp as ISO 8601 with microseconds and timezone."""
        new_dt = dt + timedelta(milliseconds=offset_ms)
        micro = random.randint(100000, 999999)
        return f"{new_dt.strftime('%Y-%m-%dT%H:%M:%S')}.{micro}{TIMEZONE}"

    # Generate appropriate log lines based on event type
    if event_type == 'success_login':
        if auth_method == 'publickey':
            logs.append(f"{fmt_ts(ts)} {server} sshd[{pid}]: Accepted publickey for {username} from {ip} port {port} ssh2")
            logs.append(f"{fmt_ts(ts, 2)} {server} sshd[{pid}]: pam_unix(sshd:session): session opened for user {username}(uid=1000) by {username}(uid=1000)")
        else:
            logs.append(f"{fmt_ts(ts)} {server} sshd[{pid}]: Accepted password for {username} from {ip} port {port} ssh2")
            logs.append(f"{fmt_ts(ts, 2)} {server} sshd[{pid}]: pam_unix(sshd:session): session opened for user {username}(uid=1000) by {username}(uid=1000)")

    elif event_type == 'failed_login':
        if failure_reason == 'invalid_user':
            # Invalid user - multiple log lines
            logs.append(f"{fmt_ts(ts)} {server} sshd[{pid}]: Invalid user {username} from {ip} port {port}")
            logs.append(f"{fmt_ts(ts, 5)} {server} sshd[{pid}]: pam_unix(sshd:auth): check pass; user unknown")
            logs.append(f"{fmt_ts(ts, 6)} {server} sshd[{pid}]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost={ip}")
            logs.append(f"{fmt_ts(ts, 1800)} {server} sshd[{pid}]: Failed password for invalid user {username} from {ip} port {port} ssh2")
            logs.append(f"{fmt_ts(ts, 2600)} {server} sshd[{pid}]: Received disconnect from {ip} port {port}:11: Client disconnecting normally [preauth]")
            logs.append(f"{fmt_ts(ts, 2601)} {server} sshd[{pid}]: Disconnected from invalid user {username} {ip} port {port} [preauth]")

        elif failure_reason == 'invalid_password':
            # Valid user, wrong password
            logs.append(f"{fmt_ts(ts)} {server} sshd[{pid}]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost={ip} user={username}")
            logs.append(f"{fmt_ts(ts, 1500)} {server} sshd[{pid}]: Failed password for {username} from {ip} port {port} ssh2")
            logs.append(f"{fmt_ts(ts, 2500)} {server} sshd[{pid}]: Received disconnect from {ip} port {port}:11: Client disconnecting normally [preauth]")
            logs.append(f"{fmt_ts(ts, 2501)} {server} sshd[{pid}]: Disconnected from authenticating user {username} {ip} port {port} [preauth]")

        elif failure_reason == 'connection_timeout':
            logs.append(f"{fmt_ts(ts)} {server} sshd[{pid}]: Connection closed by {ip} port {port} [preauth]")

        elif failure_reason == 'permission_denied':
            logs.append(f"{fmt_ts(ts)} {server} sshd[{pid}]: Connection closed by authenticating user {username} {ip} port {port} [preauth]")

        else:
            # Generic failed login
            logs.append(f"{fmt_ts(ts)} {server} sshd[{pid}]: Failed password for {username} from {ip} port {port} ssh2")
            logs.append(f"{fmt_ts(ts, 1000)} {server} sshd[{pid}]: Disconnected from {ip} port {port} [preauth]")

    else:
        # Default format
        logs.append(f"{fmt_ts(ts)} {server} sshd[{pid}]: Connection from {ip} port {port}")

    return logs


def generate_raw_log(event: dict) -> str:
    """
    Wrapper for backward compatibility.
    Returns the primary log line (first one) from the event.
    """
    logs = generate_raw_logs(event)
    return logs[0] if logs else ""


def convert_data(dry_run=False, limit=None):
    """Convert synthetic data to raw log format."""

    conn = mysql.connector.connect(**DB_CONFIG)
    cursor = conn.cursor(dictionary=True)

    # Generate collection batch ID
    batch_id = str(uuid.uuid4())
    collection_time = datetime.now()

    print("=" * 70)
    print("SYNTHETIC DATA TO RAW SSH LOGS CONVERSION")
    print("=" * 70)
    print(f"Batch ID: {batch_id}")
    print(f"Collection Time: {collection_time}")
    print(f"Dry Run: {dry_run}")
    print(f"Limit: {limit or 'ALL'}")
    print("=" * 70)

    # Count total records
    cursor.execute("SELECT COUNT(*) as cnt FROM ml_training_data")
    training_count = cursor.fetchone()['cnt']

    cursor.execute("SELECT COUNT(*) as cnt FROM ml_testing_data")
    testing_count = cursor.fetchone()['cnt']

    total = training_count + testing_count
    print(f"\nSource data: {training_count:,} training + {testing_count:,} testing = {total:,} total")

    if limit:
        print(f"Processing first {limit:,} records...")

    # Process training data
    print("\n--- Sample Raw Log Outputs ---\n")

    query = "SELECT * FROM ml_training_data"
    if limit:
        query += f" LIMIT {limit}"

    cursor.execute(query)
    events = cursor.fetchall()

    converted = 0
    samples_shown = 0

    insert_query = """
        INSERT INTO raw_ssh_logs
        (server_name, server_location, raw_log, log_timestamp, collected_at, collection_batch, log_source)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
    """

    for event in events:
        raw_logs = generate_raw_logs(event)  # Returns list of log lines
        server = event['target_server']
        location = SERVER_LOCATIONS.get(server, 'BD-DHK-DC1')
        log_ts = event['timestamp']

        if samples_shown < 10:
            for raw_log in raw_logs:
                print(f"[{server}] {raw_log}")
            print()  # Blank line between events
            samples_shown += 1

        if not dry_run:
            for raw_log in raw_logs:
                cursor.execute(insert_query, (
                    server,
                    location,
                    raw_log,
                    log_ts,
                    collection_time,
                    batch_id,
                    'auth.log'
                ))

        converted += 1

        if converted % 50000 == 0:
            print(f"  Converted {converted:,} records...")
            if not dry_run:
                conn.commit()

    # Process testing data if not limited
    if not limit:
        cursor.execute("SELECT * FROM ml_testing_data")
        events = cursor.fetchall()

        for event in events:
            raw_log = generate_raw_log(event)
            server = event['target_server']
            location = SERVER_LOCATIONS.get(server, 'BD-DHK-DC1')
            log_ts = event['timestamp']

            if not dry_run:
                cursor.execute(insert_query, (
                    server,
                    location,
                    raw_log,
                    log_ts,
                    collection_time,
                    batch_id,
                    'auth.log'
                ))

            converted += 1

            if converted % 50000 == 0:
                print(f"  Converted {converted:,} records...")
                if not dry_run:
                    conn.commit()

    if not dry_run:
        conn.commit()

    print("\n" + "=" * 70)
    print(f"CONVERSION {'DRY RUN ' if dry_run else ''}COMPLETE")
    print("=" * 70)
    print(f"Total converted: {converted:,} records")

    if not dry_run:
        cursor.execute("SELECT COUNT(*) as cnt FROM raw_ssh_logs WHERE collection_batch = %s", (batch_id,))
        inserted = cursor.fetchone()['cnt']
        print(f"Inserted into raw_ssh_logs: {inserted:,} records")

    cursor.close()
    conn.close()

    return converted


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Convert synthetic data to raw SSH logs')
    parser.add_argument('--dry-run', action='store_true', help='Preview without inserting')
    parser.add_argument('--limit', type=int, help='Limit number of records to process')
    args = parser.parse_args()

    convert_data(dry_run=args.dry_run, limit=args.limit)
