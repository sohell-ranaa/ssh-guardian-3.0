#!/usr/bin/env python3
"""
SSH Guardian v3.0 - SSH Log Collection Script
==============================================
Collects SSH authentication logs from multiple production servers
for machine learning training dataset creation.

This script connects to configured servers via SSH, retrieves auth.log
entries, and stores them in the raw_ssh_logs database table for
subsequent processing and analysis.

Data Collection Methodology:
----------------------------
1. Secure SSH connection to each production server
2. Extract auth.log entries within specified date range
3. Transfer logs to central collection database
4. Maintain collection metadata for audit trail

Servers Configuration:
----------------------
Servers are organized by datacenter location:
- BD-DHK-DC1: Primary datacenter (Dhaka)
- BD-DHK-DC2: Secondary datacenter (Dhaka)
- BD-CTG-DC1: Disaster recovery site (Chittagong)

Usage:
------
    python3 collect_ssh_logs.py --servers config/servers.yaml
    python3 collect_ssh_logs.py --server web-server-01 --days 30
    python3 collect_ssh_logs.py --all --start-date 2024-10-01 --end-date 2024-12-15

Author: SSH Guardian Research Team
Date: December 2024
"""

import os
import sys
import uuid
import yaml
import logging
import argparse
import paramiko
from datetime import datetime, timedelta
from typing import List, Dict, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

import mysql.connector
from mysql.connector import pooling

# ==================================================
# CONFIGURATION
# ==================================================

# Database configuration
DB_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': '********',  # Redacted for security
    'database': 'ssh_guardian_v3_1',
    'pool_name': 'collection_pool',
    'pool_size': 5
}

# Server inventory - Production servers for log collection
# Credentials stored in secure vault, not in code
SERVER_INVENTORY = {
    'BD-DHK-DC1': {
        'description': 'Primary Datacenter - Dhaka',
        'servers': [
            {'name': 'web-server-01', 'ip': '10.1.1.11', 'log_path': '/var/log/auth.log'},
            {'name': 'web-server-02', 'ip': '10.1.1.12', 'log_path': '/var/log/auth.log'},
            {'name': 'db-server-01', 'ip': '10.1.1.21', 'log_path': '/var/log/auth.log'},
            {'name': 'monitoring-server', 'ip': '10.1.1.31', 'log_path': '/var/log/auth.log'},
            {'name': 'gitlab-server', 'ip': '10.1.1.41', 'log_path': '/var/log/auth.log'},
            {'name': 'cache-server-01', 'ip': '10.1.1.51', 'log_path': '/var/log/auth.log'},
            {'name': 'worker-01', 'ip': '10.1.1.61', 'log_path': '/var/log/auth.log'},
        ]
    },
    'BD-DHK-DC2': {
        'description': 'Secondary Datacenter - Dhaka',
        'servers': [
            {'name': 'api-server-01', 'ip': '10.2.1.11', 'log_path': '/var/log/auth.log'},
            {'name': 'app-server-01', 'ip': '10.2.1.21', 'log_path': '/var/log/auth.log'},
            {'name': 'app-server-02', 'ip': '10.2.1.22', 'log_path': '/var/log/auth.log'},
            {'name': 'jenkins-server', 'ip': '10.2.1.31', 'log_path': '/var/log/auth.log'},
            {'name': 'queue-server-01', 'ip': '10.2.1.41', 'log_path': '/var/log/auth.log'},
        ]
    },
    'BD-CTG-DC1': {
        'description': 'DR Site - Chittagong',
        'servers': [
            {'name': 'api-server-02', 'ip': '10.3.1.11', 'log_path': '/var/log/auth.log'},
            {'name': 'db-server-02', 'ip': '10.3.1.21', 'log_path': '/var/log/auth.log'},
            {'name': 'backup-server', 'ip': '10.3.1.31', 'log_path': '/var/log/auth.log'},
            {'name': 'worker-02', 'ip': '10.3.1.41', 'log_path': '/var/log/auth.log'},
        ]
    }
}

# SSH connection settings
SSH_CONFIG = {
    'username': 'log_collector',
    'key_file': '/root/.ssh/log_collector_key',
    'port': 22,
    'timeout': 30,
    'banner_timeout': 30
}

# Logging configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('/var/log/ssh_guardian/log_collection.log')
    ]
)
logger = logging.getLogger(__name__)


class SSHLogCollector:
    """
    Collects SSH authentication logs from production servers.

    This class handles secure connections to multiple servers,
    retrieves auth.log entries, and stores them for ML processing.
    """

    def __init__(self, db_config: Dict):
        self.db_pool = None
        self.batch_id = str(uuid.uuid4())
        self.collection_time = datetime.now()
        self.stats = {
            'servers_processed': 0,
            'servers_failed': 0,
            'total_logs': 0,
            'errors': []
        }
        self._init_db(db_config)

    def _init_db(self, config: Dict):
        """Initialize database connection pool."""
        try:
            self.db_pool = mysql.connector.pooling.MySQLConnectionPool(**config)
            logger.info("Database connection pool initialized")
        except Exception as e:
            logger.error(f"Database connection failed: {e}")
            raise

    def get_connection(self):
        """Get a connection from the pool."""
        return self.db_pool.get_connection()

    def connect_to_server(self, server_info: Dict, location: str) -> Optional[paramiko.SSHClient]:
        """
        Establish SSH connection to a server.

        Args:
            server_info: Server configuration dict
            location: Datacenter location code

        Returns:
            SSHClient if successful, None otherwise
        """
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            logger.info(f"Connecting to {server_info['name']} ({server_info['ip']})...")

            # Load private key
            private_key = paramiko.RSAKey.from_private_key_file(SSH_CONFIG['key_file'])

            client.connect(
                hostname=server_info['ip'],
                port=SSH_CONFIG['port'],
                username=SSH_CONFIG['username'],
                pkey=private_key,
                timeout=SSH_CONFIG['timeout'],
                banner_timeout=SSH_CONFIG['banner_timeout']
            )

            logger.info(f"Connected to {server_info['name']}")
            return client

        except paramiko.AuthenticationException:
            logger.error(f"Authentication failed for {server_info['name']}")
        except paramiko.SSHException as e:
            logger.error(f"SSH error for {server_info['name']}: {e}")
        except Exception as e:
            logger.error(f"Connection failed for {server_info['name']}: {e}")

        return None

    def collect_logs_from_server(
        self,
        server_info: Dict,
        location: str,
        start_date: datetime,
        end_date: datetime
    ) -> int:
        """
        Collect SSH logs from a single server.

        Args:
            server_info: Server configuration
            location: Datacenter location
            start_date: Start of collection period
            end_date: End of collection period

        Returns:
            Number of log entries collected
        """
        client = self.connect_to_server(server_info, location)
        if not client:
            self.stats['servers_failed'] += 1
            return 0

        try:
            log_path = server_info['log_path']
            server_name = server_info['name']

            # Build command to extract logs within date range
            # Uses journalctl for systemd systems or grep for traditional auth.log
            cmd = f"""
            if command -v journalctl &> /dev/null; then
                journalctl -u sshd --since "{start_date.strftime('%Y-%m-%d')}" \\
                          --until "{end_date.strftime('%Y-%m-%d')}" --no-pager
            else
                cat {log_path} {log_path}.1 2>/dev/null | \\
                grep -E "sshd\\[[0-9]+\\]:" | head -100000
            fi
            """

            stdin, stdout, stderr = client.exec_command(cmd, timeout=120)
            logs = stdout.read().decode('utf-8', errors='ignore')
            errors = stderr.read().decode('utf-8', errors='ignore')

            if errors:
                logger.warning(f"Stderr from {server_name}: {errors[:200]}")

            # Parse and store logs
            log_lines = [line.strip() for line in logs.split('\n') if line.strip()]
            logger.info(f"Retrieved {len(log_lines):,} log entries from {server_name}")

            # Insert into database
            self._store_logs(log_lines, server_name, location)

            self.stats['servers_processed'] += 1
            self.stats['total_logs'] += len(log_lines)

            return len(log_lines)

        except Exception as e:
            logger.error(f"Error collecting logs from {server_info['name']}: {e}")
            self.stats['errors'].append({
                'server': server_info['name'],
                'error': str(e)
            })
            self.stats['servers_failed'] += 1
            return 0

        finally:
            client.close()

    def _store_logs(self, log_lines: List[str], server_name: str, location: str):
        """Store collected logs in database."""
        conn = self.get_connection()
        cursor = conn.cursor()

        try:
            insert_query = """
                INSERT INTO raw_ssh_logs
                (server_name, server_location, raw_log, log_timestamp,
                 collected_at, collection_batch, log_source)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """

            for log_line in log_lines:
                # Parse timestamp from log line
                log_ts = self._parse_log_timestamp(log_line)

                cursor.execute(insert_query, (
                    server_name,
                    location,
                    log_line,
                    log_ts,
                    self.collection_time,
                    self.batch_id,
                    'auth.log'
                ))

            conn.commit()
            logger.info(f"Stored {len(log_lines):,} logs from {server_name}")

        except Exception as e:
            logger.error(f"Database insert error: {e}")
            conn.rollback()
            raise

        finally:
            cursor.close()
            conn.close()

    def _parse_log_timestamp(self, log_line: str) -> datetime:
        """
        Parse timestamp from auth.log line.

        Format: "Dec 21 03:15:42 server sshd[12345]: ..."
        """
        try:
            parts = log_line.split()
            if len(parts) >= 3:
                month_str = parts[0]
                day = int(parts[1])
                time_str = parts[2]

                month_map = {
                    'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4,
                    'May': 5, 'Jun': 6, 'Jul': 7, 'Aug': 8,
                    'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12
                }
                month = month_map.get(month_str, 1)

                # Assume current year if not specified
                year = datetime.now().year

                hour, minute, second = map(int, time_str.split(':'))

                return datetime(year, month, day, hour, minute, second)

        except Exception:
            pass

        return datetime.now()

    def collect_all(
        self,
        start_date: datetime,
        end_date: datetime,
        parallel: bool = True,
        max_workers: int = 4
    ):
        """
        Collect logs from all configured servers.

        Args:
            start_date: Start of collection period
            end_date: End of collection period
            parallel: Whether to collect in parallel
            max_workers: Max concurrent connections
        """
        logger.info("=" * 70)
        logger.info("SSH GUARDIAN - LOG COLLECTION")
        logger.info("=" * 70)
        logger.info(f"Batch ID: {self.batch_id}")
        logger.info(f"Collection Period: {start_date.date()} to {end_date.date()}")
        logger.info(f"Parallel Collection: {parallel}")
        logger.info("=" * 70)

        all_servers = []
        for location, dc_info in SERVER_INVENTORY.items():
            for server in dc_info['servers']:
                all_servers.append((server, location))

        logger.info(f"\nTotal servers to collect from: {len(all_servers)}")

        if parallel:
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {
                    executor.submit(
                        self.collect_logs_from_server,
                        server, location, start_date, end_date
                    ): server['name']
                    for server, location in all_servers
                }

                for future in as_completed(futures):
                    server_name = futures[future]
                    try:
                        count = future.result()
                        logger.info(f"Completed: {server_name} ({count:,} logs)")
                    except Exception as e:
                        logger.error(f"Failed: {server_name} - {e}")
        else:
            for server, location in all_servers:
                self.collect_logs_from_server(server, location, start_date, end_date)

        self._print_summary()

    def _print_summary(self):
        """Print collection summary."""
        logger.info("\n" + "=" * 70)
        logger.info("COLLECTION SUMMARY")
        logger.info("=" * 70)
        logger.info(f"Batch ID: {self.batch_id}")
        logger.info(f"Servers Processed: {self.stats['servers_processed']}")
        logger.info(f"Servers Failed: {self.stats['servers_failed']}")
        logger.info(f"Total Logs Collected: {self.stats['total_logs']:,}")
        logger.info(f"Collection Time: {datetime.now() - self.collection_time}")

        if self.stats['errors']:
            logger.warning(f"\nErrors ({len(self.stats['errors'])}):")
            for err in self.stats['errors'][:5]:
                logger.warning(f"  - {err['server']}: {err['error']}")

        logger.info("=" * 70)


def main():
    parser = argparse.ArgumentParser(
        description='SSH Guardian Log Collection Script',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Collect from all servers for last 30 days:
    python3 collect_ssh_logs.py --all --days 30

  Collect from specific server:
    python3 collect_ssh_logs.py --server web-server-01 --days 7

  Collect with date range:
    python3 collect_ssh_logs.py --all --start-date 2024-10-01 --end-date 2024-12-15
        """
    )

    parser.add_argument('--all', action='store_true', help='Collect from all servers')
    parser.add_argument('--server', type=str, help='Specific server to collect from')
    parser.add_argument('--days', type=int, default=30, help='Number of days to collect')
    parser.add_argument('--start-date', type=str, help='Start date (YYYY-MM-DD)')
    parser.add_argument('--end-date', type=str, help='End date (YYYY-MM-DD)')
    parser.add_argument('--parallel', action='store_true', default=True, help='Parallel collection')
    parser.add_argument('--workers', type=int, default=4, help='Max parallel workers')

    args = parser.parse_args()

    # Determine date range
    if args.start_date and args.end_date:
        start_date = datetime.strptime(args.start_date, '%Y-%m-%d')
        end_date = datetime.strptime(args.end_date, '%Y-%m-%d')
    else:
        end_date = datetime.now()
        start_date = end_date - timedelta(days=args.days)

    # Initialize collector
    collector = SSHLogCollector(DB_CONFIG)

    # Run collection
    if args.all:
        collector.collect_all(start_date, end_date, args.parallel, args.workers)
    elif args.server:
        # Find server in inventory
        for location, dc_info in SERVER_INVENTORY.items():
            for server in dc_info['servers']:
                if server['name'] == args.server:
                    collector.collect_logs_from_server(server, location, start_date, end_date)
                    collector._print_summary()
                    return
        logger.error(f"Server not found: {args.server}")
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
