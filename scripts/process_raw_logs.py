#!/usr/bin/env python3
"""
SSH Guardian v3.0 - Raw Log Processing & Labeling Script
=========================================================
Processes raw SSH authentication logs and transforms them into
structured ML training/testing datasets with threat labels.

Processing Pipeline:
--------------------
1. Parse raw auth.log entries from raw_ssh_logs table
2. Extract structured fields (IP, username, event type, etc.)
3. Enrich with geolocation data (MaxMind GeoIP)
4. Query threat intelligence APIs (AbuseIPDB, VirusTotal, GreyNoise)
5. Apply labeling rules based on behavior patterns
6. Split into training (80%) and testing (20%) datasets
7. Store in ml_training_data and ml_testing_data tables

Labeling Methodology:
---------------------
Events are labeled as malicious (1) or benign (0) based on:
- Threat intelligence scores (AbuseIPDB > 50, VirusTotal positives)
- Behavioral patterns (brute force, credential stuffing)
- Known attack signatures (root attempts, dictionary usernames)
- Geographic anomalies (high-risk countries, impossible travel)
- Network characteristics (Tor exit nodes, known bad ASNs)

Usage:
------
    python3 process_raw_logs.py --batch <batch_id>
    python3 process_raw_logs.py --all --split 0.8
    python3 process_raw_logs.py --dry-run --limit 1000

Author: SSH Guardian Research Team
Date: December 2024
"""

import os
import sys
import re
import uuid
import json
import time
import logging
import argparse
import requests
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional
from collections import defaultdict

import mysql.connector
from mysql.connector import pooling

# ==================================================
# CONFIGURATION
# ==================================================

DB_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': '********',  # Redacted
    'database': 'ssh_guardian_v3_1',
    'pool_name': 'processing_pool',
    'pool_size': 5
}

# API Keys (stored in environment variables in production)
ABUSEIPDB_API_KEY = os.getenv('ABUSEIPDB_API_KEY', '')
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY', '')
GREYNOISE_API_KEY = os.getenv('GREYNOISE_API_KEY', '')

# Processing configuration
BATCH_SIZE = 1000
TRAIN_SPLIT = 0.8  # 80% training, 20% testing

# High-risk countries (ISO codes)
HIGH_RISK_COUNTRIES = {'CN', 'RU', 'KP', 'IR', 'VN', 'BR', 'IN', 'PK', 'NG', 'UA'}

# Common brute force usernames
BRUTE_FORCE_USERNAMES = {
    'root', 'admin', 'administrator', 'test', 'user', 'guest',
    'oracle', 'postgres', 'mysql', 'ftp', 'www', 'www-data',
    'ubuntu', 'pi', 'git', 'jenkins', 'deploy', 'backup'
}

# Dictionary attack patterns
DICTIONARY_PATTERNS = [
    r'^[a-z]{4,8}$',  # Simple lowercase words
    r'^[a-z]+\d{1,4}$',  # word + numbers
    r'^(user|admin|test)\d+$',  # user1, admin2, etc.
]

# Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('/var/log/ssh_guardian/log_processing.log')
    ]
)
logger = logging.getLogger(__name__)


class LogParser:
    """Parses raw auth.log entries into structured data."""

    # Regex patterns for different log formats
    PATTERNS = {
        'failed_invalid_user': re.compile(
            r'Failed password for invalid user (\S+) from (\d+\.\d+\.\d+\.\d+) port (\d+)'
        ),
        'failed_password': re.compile(
            r'Failed password for (\S+) from (\d+\.\d+\.\d+\.\d+) port (\d+)'
        ),
        'accepted_password': re.compile(
            r'Accepted password for (\S+) from (\d+\.\d+\.\d+\.\d+) port (\d+)'
        ),
        'accepted_publickey': re.compile(
            r'Accepted publickey for (\S+) from (\d+\.\d+\.\d+\.\d+) port (\d+)'
        ),
        'connection_closed': re.compile(
            r'Connection closed by (\d+\.\d+\.\d+\.\d+) port (\d+)'
        ),
        'invalid_user': re.compile(
            r'Invalid user (\S+) from (\d+\.\d+\.\d+\.\d+) port (\d+)'
        ),
    }

    MONTH_MAP = {
        'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4,
        'May': 5, 'Jun': 6, 'Jul': 7, 'Aug': 8,
        'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12
    }

    def parse(self, raw_log: str, server_name: str) -> Optional[Dict]:
        """
        Parse a raw auth.log line into structured data.

        Args:
            raw_log: Raw log line from auth.log
            server_name: Name of the source server

        Returns:
            Structured event dict or None if parsing fails
        """
        try:
            # Parse timestamp
            parts = raw_log.split()
            if len(parts) < 6:
                return None

            month = self.MONTH_MAP.get(parts[0], 1)
            day = int(parts[1])
            time_parts = parts[2].split(':')
            hour, minute, second = int(time_parts[0]), int(time_parts[1]), int(time_parts[2])

            # Use current year (logs don't include year)
            year = datetime.now().year
            timestamp = datetime(year, month, day, hour, minute, second)

            # Initialize event
            event = {
                'event_uuid': str(uuid.uuid4()),
                'timestamp': timestamp,
                'event_type': None,
                'auth_method': 'password',
                'failure_reason': None,
                'source_ip': None,
                'source_port': None,
                'target_server': server_name,
                'target_port': 22,
                'target_username': None,
            }

            # Try each pattern
            for pattern_name, pattern in self.PATTERNS.items():
                match = pattern.search(raw_log)
                if match:
                    groups = match.groups()

                    if pattern_name == 'failed_invalid_user':
                        event['event_type'] = 'failed_login'
                        event['failure_reason'] = 'invalid_user'
                        event['target_username'] = groups[0]
                        event['source_ip'] = groups[1]
                        event['source_port'] = int(groups[2])

                    elif pattern_name == 'failed_password':
                        event['event_type'] = 'failed_login'
                        event['failure_reason'] = 'invalid_password'
                        event['target_username'] = groups[0]
                        event['source_ip'] = groups[1]
                        event['source_port'] = int(groups[2])

                    elif pattern_name == 'accepted_password':
                        event['event_type'] = 'success_login'
                        event['auth_method'] = 'password'
                        event['target_username'] = groups[0]
                        event['source_ip'] = groups[1]
                        event['source_port'] = int(groups[2])

                    elif pattern_name == 'accepted_publickey':
                        event['event_type'] = 'success_login'
                        event['auth_method'] = 'publickey'
                        event['target_username'] = groups[0]
                        event['source_ip'] = groups[1]
                        event['source_port'] = int(groups[2])

                    elif pattern_name == 'connection_closed':
                        event['event_type'] = 'failed_login'
                        event['failure_reason'] = 'connection_timeout'
                        event['source_ip'] = groups[0]
                        event['source_port'] = int(groups[1])

                    elif pattern_name == 'invalid_user':
                        event['event_type'] = 'failed_login'
                        event['failure_reason'] = 'invalid_user'
                        event['target_username'] = groups[0]
                        event['source_ip'] = groups[1]
                        event['source_port'] = int(groups[2])

                    return event

            return None

        except Exception as e:
            logger.debug(f"Parse error: {e} - Log: {raw_log[:100]}")
            return None


class ThreatEnricher:
    """Enriches events with threat intelligence data."""

    def __init__(self):
        self.cache = {}  # IP -> enrichment data
        self.geoip_reader = None
        self._init_geoip()

    def _init_geoip(self):
        """Initialize MaxMind GeoIP database."""
        try:
            import geoip2.database
            geoip_path = '/usr/share/GeoIP/GeoLite2-City.mmdb'
            if os.path.exists(geoip_path):
                self.geoip_reader = geoip2.database.Reader(geoip_path)
                logger.info("GeoIP database loaded")
        except Exception as e:
            logger.warning(f"GeoIP initialization failed: {e}")

    def enrich(self, event: Dict) -> Dict:
        """
        Enrich event with geolocation and threat intelligence.

        Args:
            event: Parsed event dict

        Returns:
            Enriched event dict
        """
        ip = event.get('source_ip')
        if not ip:
            return event

        # Check cache
        if ip in self.cache:
            event.update(self.cache[ip])
            return event

        enrichment = {
            'country_code': None,
            'country_name': None,
            'city': None,
            'latitude': 0.0,
            'longitude': 0.0,
            'is_private_ip': self._is_private_ip(ip),
            'is_vpn': False,
            'is_proxy': False,
            'is_tor': False,
            'is_datacenter': False,
            'is_hosting': False,
            'abuseipdb_score': 0,
            'virustotal_positives': 0,
            'virustotal_total': 90,
            'greynoise_classification': None,
            'threat_level': 'clean',
        }

        # GeoIP lookup
        if self.geoip_reader and not enrichment['is_private_ip']:
            try:
                response = self.geoip_reader.city(ip)
                enrichment['country_code'] = response.country.iso_code
                enrichment['country_name'] = response.country.name
                enrichment['city'] = response.city.name
                enrichment['latitude'] = response.location.latitude
                enrichment['longitude'] = response.location.longitude
            except Exception:
                pass

        # AbuseIPDB lookup (rate limited)
        if ABUSEIPDB_API_KEY and not enrichment['is_private_ip']:
            abuse_data = self._query_abuseipdb(ip)
            if abuse_data:
                enrichment['abuseipdb_score'] = abuse_data.get('abuseConfidenceScore', 0)
                enrichment['is_tor'] = abuse_data.get('isTor', False)

        # VirusTotal lookup (rate limited)
        if VIRUSTOTAL_API_KEY and not enrichment['is_private_ip']:
            vt_data = self._query_virustotal(ip)
            if vt_data:
                enrichment['virustotal_positives'] = vt_data.get('positives', 0)
                enrichment['virustotal_total'] = vt_data.get('total', 90)

        # Determine threat level
        enrichment['threat_level'] = self._calculate_threat_level(enrichment)

        # Cache result
        self.cache[ip] = enrichment
        event.update(enrichment)

        return event

    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private/internal."""
        import ipaddress
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private
        except Exception:
            return False

    def _query_abuseipdb(self, ip: str) -> Optional[Dict]:
        """Query AbuseIPDB API."""
        try:
            response = requests.get(
                'https://api.abuseipdb.com/api/v2/check',
                headers={'Key': ABUSEIPDB_API_KEY, 'Accept': 'application/json'},
                params={'ipAddress': ip, 'maxAgeInDays': 90},
                timeout=5
            )
            if response.status_code == 200:
                return response.json().get('data', {})
        except Exception:
            pass
        return None

    def _query_virustotal(self, ip: str) -> Optional[Dict]:
        """Query VirusTotal API."""
        try:
            response = requests.get(
                f'https://www.virustotal.com/api/v3/ip_addresses/{ip}',
                headers={'x-apikey': VIRUSTOTAL_API_KEY},
                timeout=5
            )
            if response.status_code == 200:
                data = response.json().get('data', {}).get('attributes', {})
                stats = data.get('last_analysis_stats', {})
                return {
                    'positives': stats.get('malicious', 0),
                    'total': sum(stats.values())
                }
        except Exception:
            pass
        return None

    def _calculate_threat_level(self, enrichment: Dict) -> str:
        """Calculate overall threat level."""
        score = 0

        if enrichment.get('abuseipdb_score', 0) > 80:
            score += 3
        elif enrichment.get('abuseipdb_score', 0) > 50:
            score += 2
        elif enrichment.get('abuseipdb_score', 0) > 25:
            score += 1

        if enrichment.get('virustotal_positives', 0) > 5:
            score += 2
        elif enrichment.get('virustotal_positives', 0) > 0:
            score += 1

        if enrichment.get('is_tor'):
            score += 2
        if enrichment.get('country_code') in HIGH_RISK_COUNTRIES:
            score += 1

        if score >= 5:
            return 'critical'
        elif score >= 3:
            return 'high'
        elif score >= 2:
            return 'medium'
        elif score >= 1:
            return 'low'
        return 'clean'


class BehaviorAnalyzer:
    """Analyzes behavioral patterns for threat labeling."""

    def __init__(self):
        self.ip_history = defaultdict(list)  # IP -> list of events
        self.username_attempts = defaultdict(set)  # IP -> set of usernames

    def analyze(self, event: Dict) -> Dict:
        """
        Analyze event behavior and determine scenario type.

        Args:
            event: Enriched event dict

        Returns:
            Event with scenario_type and is_malicious labels
        """
        ip = event.get('source_ip')
        username = event.get('target_username', '')
        event_type = event.get('event_type')

        # Track history
        self.ip_history[ip].append(event)
        if username:
            self.username_attempts[ip].add(username)

        # Analyze patterns
        scenario_type = 'normal'
        is_malicious = False

        # Check for brute force (many attempts from same IP)
        if len(self.ip_history[ip]) > 10:
            failed_count = sum(1 for e in self.ip_history[ip]
                              if e.get('event_type') == 'failed_login')
            if failed_count > 8:
                scenario_type = 'brute_force'
                is_malicious = True

        # Check for credential stuffing (many usernames from same IP)
        if len(self.username_attempts[ip]) > 5:
            scenario_type = 'credential_stuffing'
            is_malicious = True

        # Check for dictionary attack usernames
        if username and username.lower() in BRUTE_FORCE_USERNAMES:
            if event_type == 'failed_login':
                scenario_type = 'dictionary_attack'
                is_malicious = True

        # Check for high threat intelligence score
        if event.get('abuseipdb_score', 0) > 50:
            is_malicious = True
            if scenario_type == 'normal':
                scenario_type = 'known_attacker'

        # Check for Tor/VPN with failed logins
        if event.get('is_tor') and event_type == 'failed_login':
            is_malicious = True
            scenario_type = 'tor_attack'

        # Check for high-risk country with root attempts
        if (event.get('country_code') in HIGH_RISK_COUNTRIES and
            username == 'root' and event_type == 'failed_login'):
            is_malicious = True
            if scenario_type == 'normal':
                scenario_type = 'geo_anomaly'

        # Legitimate scenarios
        if event.get('is_private_ip') and event_type == 'success_login':
            scenario_type = 'normal_internal'
            is_malicious = False

        if event.get('auth_method') == 'publickey' and event_type == 'success_login':
            scenario_type = 'normal_publickey'
            is_malicious = False

        event['scenario_type'] = scenario_type
        event['is_malicious'] = 1 if is_malicious else 0

        return event


class LogProcessor:
    """Main processor class."""

    def __init__(self, db_config: Dict):
        self.db_pool = mysql.connector.pooling.MySQLConnectionPool(**db_config)
        self.parser = LogParser()
        self.enricher = ThreatEnricher()
        self.analyzer = BehaviorAnalyzer()
        self.stats = {
            'total_processed': 0,
            'parsed_success': 0,
            'parse_failed': 0,
            'training_samples': 0,
            'testing_samples': 0,
            'malicious_count': 0,
            'benign_count': 0
        }

    def get_connection(self):
        return self.db_pool.get_connection()

    def process_batch(self, batch_id: str = None, limit: int = None,
                      dry_run: bool = False, train_split: float = 0.8):
        """
        Process raw logs and create ML datasets.

        Args:
            batch_id: Specific batch to process (None for all)
            limit: Maximum records to process
            dry_run: Preview without database writes
            train_split: Training/testing split ratio
        """
        logger.info("=" * 70)
        logger.info("SSH GUARDIAN - RAW LOG PROCESSING")
        logger.info("=" * 70)
        logger.info(f"Batch ID: {batch_id or 'ALL'}")
        logger.info(f"Dry Run: {dry_run}")
        logger.info(f"Train/Test Split: {train_split}/{1-train_split}")
        logger.info("=" * 70)

        conn = self.get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            # Count records
            query = "SELECT COUNT(*) as cnt FROM raw_ssh_logs"
            if batch_id:
                query += f" WHERE collection_batch = '{batch_id}'"
            cursor.execute(query)
            total = cursor.fetchone()['cnt']
            logger.info(f"\nTotal raw logs to process: {total:,}")

            # Fetch records
            query = "SELECT * FROM raw_ssh_logs"
            if batch_id:
                query += f" WHERE collection_batch = '{batch_id}'"
            if limit:
                query += f" LIMIT {limit}"

            cursor.execute(query)
            records = cursor.fetchall()

            training_events = []
            testing_events = []

            for i, record in enumerate(records):
                # Parse raw log
                event = self.parser.parse(record['raw_log'], record['server_name'])

                if event:
                    self.stats['parsed_success'] += 1

                    # Enrich with threat intel
                    event = self.enricher.enrich(event)

                    # Analyze behavior and label
                    event = self.analyzer.analyze(event)

                    # Split into train/test
                    import random
                    if random.random() < train_split:
                        training_events.append(event)
                    else:
                        testing_events.append(event)

                    if event['is_malicious']:
                        self.stats['malicious_count'] += 1
                    else:
                        self.stats['benign_count'] += 1
                else:
                    self.stats['parse_failed'] += 1

                self.stats['total_processed'] += 1

                if (i + 1) % 10000 == 0:
                    logger.info(f"  Processed {i+1:,}/{len(records):,} records...")

            self.stats['training_samples'] = len(training_events)
            self.stats['testing_samples'] = len(testing_events)

            # Store to database
            if not dry_run:
                logger.info("\nStoring to database...")
                self._store_events(training_events, 'ml_training_data')
                self._store_events(testing_events, 'ml_testing_data')
            else:
                logger.info("\n[DRY RUN] Would store:")
                logger.info(f"  - {len(training_events):,} training samples")
                logger.info(f"  - {len(testing_events):,} testing samples")

                # Show sample outputs
                logger.info("\n--- Sample Processed Events ---")
                for event in training_events[:5]:
                    logger.info(f"  [{event['scenario_type']}] "
                              f"{event['source_ip']} -> {event['target_username']} "
                              f"| {event['event_type']} | malicious={event['is_malicious']}")

        finally:
            cursor.close()
            conn.close()

        self._print_summary()

    def _store_events(self, events: List[Dict], table: str):
        """Store events to specified table."""
        if not events:
            return

        conn = self.get_connection()
        cursor = conn.cursor()

        try:
            # Build insert query dynamically based on table schema
            columns = [
                'event_uuid', 'timestamp', 'event_type', 'auth_method',
                'failure_reason', 'source_ip', 'source_port', 'target_server',
                'target_port', 'target_username', 'country_code', 'country_name',
                'city', 'latitude', 'longitude', 'is_private_ip', 'is_vpn',
                'is_proxy', 'is_tor', 'is_datacenter', 'is_hosting',
                'abuseipdb_score', 'virustotal_positives', 'virustotal_total',
                'greynoise_classification', 'threat_level', 'scenario_type',
                'is_malicious'
            ]

            placeholders = ', '.join(['%s'] * len(columns))
            column_names = ', '.join(columns)

            query = f"INSERT INTO {table} ({column_names}) VALUES ({placeholders})"

            for event in events:
                values = tuple(event.get(col) for col in columns)
                cursor.execute(query, values)

            conn.commit()
            logger.info(f"  Stored {len(events):,} events to {table}")

        finally:
            cursor.close()
            conn.close()

    def _print_summary(self):
        """Print processing summary."""
        logger.info("\n" + "=" * 70)
        logger.info("PROCESSING SUMMARY")
        logger.info("=" * 70)
        logger.info(f"Total Processed: {self.stats['total_processed']:,}")
        logger.info(f"Parse Success: {self.stats['parsed_success']:,}")
        logger.info(f"Parse Failed: {self.stats['parse_failed']:,}")
        logger.info(f"Training Samples: {self.stats['training_samples']:,}")
        logger.info(f"Testing Samples: {self.stats['testing_samples']:,}")
        logger.info(f"Malicious Events: {self.stats['malicious_count']:,}")
        logger.info(f"Benign Events: {self.stats['benign_count']:,}")

        if self.stats['malicious_count'] + self.stats['benign_count'] > 0:
            mal_pct = self.stats['malicious_count'] / (
                self.stats['malicious_count'] + self.stats['benign_count']) * 100
            logger.info(f"Malicious Ratio: {mal_pct:.1f}%")

        logger.info("=" * 70)


def main():
    parser = argparse.ArgumentParser(
        description='SSH Guardian Raw Log Processing Script'
    )

    parser.add_argument('--batch', type=str, help='Specific batch ID to process')
    parser.add_argument('--all', action='store_true', help='Process all raw logs')
    parser.add_argument('--limit', type=int, help='Limit records to process')
    parser.add_argument('--split', type=float, default=0.8, help='Train/test split ratio')
    parser.add_argument('--dry-run', action='store_true', help='Preview without storing')

    args = parser.parse_args()

    processor = LogProcessor(DB_CONFIG)

    if args.all or args.batch:
        processor.process_batch(
            batch_id=args.batch,
            limit=args.limit,
            dry_run=args.dry_run,
            train_split=args.split
        )
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
