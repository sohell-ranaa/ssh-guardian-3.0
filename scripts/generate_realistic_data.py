#!/usr/bin/env python3
"""
SSH Guardian v3.0 - Realistic Data Generator
=============================================
Generates 200,000 realistic SSH authentication events for ML training.

Features:
- 27 attack scenarios covered
- Realistic IP distribution (public, private, malicious, clean)
- Geographic distribution across 20+ countries
- 80/20 train/test split saved to separate tables
- Memory-efficient batch processing (5000 events/batch)

Author: SSH Guardian Team
"""

import os
import sys
import uuid
import random
import hashlib
import logging
import json
from datetime import datetime, timedelta
from typing import List, Dict, Tuple, Optional
import numpy as np

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import mysql.connector
from mysql.connector import pooling

# ==================================================
# CONFIGURATION
# ==================================================

TARGET_EVENTS = 500000
TRAIN_RATIO = 0.80
TEST_RATIO = 0.20
BATCH_SIZE = 5000  # Memory-safe for 4GB RAM
RANDOM_SEED = 42

# Database config
DB_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': '123123',
    'database': 'ssh_guardian_v3_1',
    'pool_name': 'data_gen_pool',
    'pool_size': 5
}

# ==================================================
# PORT DISTRIBUTION
# ==================================================
# Common SSH ports with weights (probability of selection)
SSH_TARGET_PORTS = {
    22: 0.60,      # Standard SSH (60%)
    2222: 0.10,    # Common alternate (10%)
    22222: 0.05,   # Another alternate (5%)
    8022: 0.05,    # Docker/container SSH (5%)
    2022: 0.03,    # Alternate (3%)
    222: 0.02,     # Low port alternate (2%)
    10022: 0.02,   # High port (2%)
    443: 0.02,     # HTTPS port (hiding SSH) (2%)
    80: 0.01,      # HTTP port (hiding SSH) (1%)
    8080: 0.01,    # Alt HTTP (1%)
    3022: 0.01,    # Custom (1%)
    4022: 0.01,    # Custom (1%)
    5022: 0.01,    # Custom (1%)
    6022: 0.01,    # Custom (1%)
    7022: 0.01,    # Custom (1%)
    9022: 0.01,    # Custom (1%)
    # Random high ports for the rest (2%)
}

def get_random_ssh_port() -> int:
    """Get a weighted random SSH target port."""
    rand = random.random()
    cumulative = 0.0
    for port, weight in SSH_TARGET_PORTS.items():
        cumulative += weight
        if rand <= cumulative:
            return port
    # 2% chance of random high port
    return random.randint(1024, 65535)

# ==================================================
# IP ADDRESS POOLS
# ==================================================

# High-risk country codes
HIGH_RISK_COUNTRIES = ['CN', 'RU', 'KP', 'IR', 'VN', 'BR', 'IN', 'PK', 'NG', 'UA']

# Country data with coordinates
COUNTRY_DATA = {
    # High-risk countries
    'CN': {'name': 'China', 'lat': 35.86, 'lon': 104.19, 'cities': ['Beijing', 'Shanghai', 'Shenzhen', 'Guangzhou']},
    'RU': {'name': 'Russia', 'lat': 61.52, 'lon': 105.31, 'cities': ['Moscow', 'St Petersburg', 'Novosibirsk']},
    'KP': {'name': 'North Korea', 'lat': 40.34, 'lon': 127.51, 'cities': ['Pyongyang']},
    'IR': {'name': 'Iran', 'lat': 32.43, 'lon': 53.69, 'cities': ['Tehran', 'Isfahan']},
    'VN': {'name': 'Vietnam', 'lat': 14.06, 'lon': 108.28, 'cities': ['Hanoi', 'Ho Chi Minh City']},
    'BR': {'name': 'Brazil', 'lat': -14.24, 'lon': -51.93, 'cities': ['Sao Paulo', 'Rio de Janeiro']},
    'IN': {'name': 'India', 'lat': 20.59, 'lon': 78.96, 'cities': ['Mumbai', 'Delhi', 'Bangalore']},
    'PK': {'name': 'Pakistan', 'lat': 30.38, 'lon': 69.35, 'cities': ['Karachi', 'Lahore']},
    'NG': {'name': 'Nigeria', 'lat': 9.08, 'lon': 8.68, 'cities': ['Lagos', 'Abuja']},
    'UA': {'name': 'Ukraine', 'lat': 48.38, 'lon': 31.17, 'cities': ['Kyiv', 'Kharkiv']},

    # Clean countries
    'US': {'name': 'United States', 'lat': 37.09, 'lon': -95.71, 'cities': ['New York', 'Los Angeles', 'Chicago', 'San Francisco', 'Seattle']},
    'CA': {'name': 'Canada', 'lat': 56.13, 'lon': -106.35, 'cities': ['Toronto', 'Vancouver', 'Montreal']},
    'GB': {'name': 'United Kingdom', 'lat': 55.38, 'lon': -3.44, 'cities': ['London', 'Manchester', 'Birmingham']},
    'DE': {'name': 'Germany', 'lat': 51.17, 'lon': 10.45, 'cities': ['Berlin', 'Munich', 'Frankfurt']},
    'FR': {'name': 'France', 'lat': 46.23, 'lon': 2.21, 'cities': ['Paris', 'Lyon', 'Marseille']},
    'JP': {'name': 'Japan', 'lat': 36.20, 'lon': 138.25, 'cities': ['Tokyo', 'Osaka', 'Kyoto']},
    'AU': {'name': 'Australia', 'lat': -25.27, 'lon': 133.78, 'cities': ['Sydney', 'Melbourne', 'Brisbane']},
    'SG': {'name': 'Singapore', 'lat': 1.35, 'lon': 103.82, 'cities': ['Singapore']},
    'NL': {'name': 'Netherlands', 'lat': 52.13, 'lon': 5.29, 'cities': ['Amsterdam', 'Rotterdam']},
    'SE': {'name': 'Sweden', 'lat': 60.13, 'lon': 18.64, 'cities': ['Stockholm', 'Gothenburg']},
    'CH': {'name': 'Switzerland', 'lat': 46.82, 'lon': 8.23, 'cities': ['Zurich', 'Geneva']},
    'KR': {'name': 'South Korea', 'lat': 35.91, 'lon': 127.77, 'cities': ['Seoul', 'Busan']},
}

# Known scanner IPs (Shodan, Censys, etc.)
SCANNER_IP_PREFIXES = [
    '71.6.', '66.240.', '198.20.', '80.82.', '93.174.',  # Shodan
    '162.142.', '167.248.', '167.94.',  # Censys
    '185.220.', '185.129.',  # Masscan
    '45.33.', '45.56.', '45.79.',  # Linode scanners
]

# Tor exit node prefixes (simulated)
TOR_EXIT_PREFIXES = [
    '185.220.101.', '185.220.102.', '199.249.230.', '193.218.118.',
    '109.70.100.', '178.17.170.', '51.15.', '62.102.148.',
]

# VPN provider prefixes (simulated)
VPN_PREFIXES = [
    '103.86.', '146.70.', '193.138.', '185.159.', '91.219.',  # NordVPN
    '198.54.', '45.86.', '37.120.',  # ExpressVPN
    '162.245.', '185.242.',  # ProtonVPN
]

# Datacenter IP prefixes
DATACENTER_PREFIXES = [
    # AWS
    '3.', '18.', '52.', '54.', '13.',
    # Azure
    '40.', '52.', '104.', '168.',
    # GCP
    '34.', '35.',
    # DigitalOcean
    '159.65.', '167.172.', '134.209.',
    # OVH
    '51.', '54.', '145.239.',
]

# Clean corporate IP prefixes
CLEAN_PREFIXES = [
    # Google
    '8.8.', '8.34.', '8.35.', '35.191.',
    # Cloudflare
    '1.1.', '104.16.', '104.17.', '104.18.',
    # Microsoft
    '40.76.', '40.77.', '40.78.',
    # Apple
    '17.',
]

# Username pools
COMMON_ATTACK_USERNAMES = [
    'root', 'admin', 'administrator', 'test', 'user', 'guest', 'ubuntu', 'centos',
    'oracle', 'mysql', 'postgres', 'ftpuser', 'www-data', 'nginx', 'apache',
    'tomcat', 'jenkins', 'git', 'svn', 'deploy', 'backup', 'nagios', 'zabbix',
    'pi', 'vagrant', 'ec2-user', 'azureuser', 'support', 'manager', 'sales'
]

SYSTEM_ACCOUNTS = [
    'daemon', 'bin', 'sys', 'sync', 'games', 'man', 'lp', 'mail', 'news',
    'uucp', 'proxy', 'www-data', 'backup', 'list', 'irc', 'gnats', 'nobody',
    'systemd-network', 'systemd-resolve', 'syslog', 'messagebus', '_apt'
]

LEGITIMATE_USERNAMES = [
    'john.doe', 'jane.smith', 'bob.wilson', 'alice.jones', 'charlie.brown',
    'dev_user', 'ops_admin', 'sysadmin', 'developer', 'engineer',
    'david.lee', 'emma.white', 'frank.miller', 'grace.taylor', 'henry.clark',
    'team_lead', 'senior_dev', 'junior_dev', 'qa_engineer', 'devops'
]

# Target servers
TARGET_SERVERS = [
    'web-server-01', 'web-server-02', 'api-server-01', 'api-server-02',
    'db-server-01', 'db-server-02', 'cache-server-01', 'queue-server-01',
    'app-server-01', 'app-server-02', 'worker-01', 'worker-02',
    'jenkins-server', 'gitlab-server', 'monitoring-server', 'backup-server'
]

# ==================================================
# LOGGING SETUP
# ==================================================

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('/tmp/data_generation.log')
    ]
)
logger = logging.getLogger(__name__)


class RealisticDataGenerator:
    """Generates realistic SSH authentication events for ML training."""

    def __init__(self, target_count: int = TARGET_EVENTS, seed: int = RANDOM_SEED):
        self.target_count = target_count
        self.seed = seed
        random.seed(seed)
        np.random.seed(seed)

        self.db_pool = None
        self.generated_count = 0
        self.training_count = 0
        self.testing_count = 0

        # IP history for behavioral patterns
        self.ip_history: Dict[str, List[Dict]] = {}

        # User location history for impossible travel
        self.user_locations: Dict[str, Dict] = {}

        # Scenario distribution for 500k events (scaled up with more scenarios)
        self.scenario_distribution = {
            # =============================================
            # ATTACK SCENARIOS (50% = 250,000 events)
            # =============================================

            # Brute Force Attacks (50k)
            'brute_force': 50000,

            # Credential-based Attacks (45k)
            'credential_stuffing': 25000,
            'password_spray': 20000,

            # Behavioral Anomalies (30k)
            'impossible_travel': 12000,
            'lateral_movement': 10000,
            'off_hours_access': 8000,

            # Privileged Access Attacks (25k)
            'root_admin_attempts': 25000,

            # Infrastructure-based Attacks (55k)
            'known_scanners': 25000,
            'tor_exit_nodes': 15000,
            'vpn_proxy_access': 15000,

            # Cloud/Datacenter Attacks (25k)
            'datacenter_attacks': 25000,

            # Geographic Risk (20k)
            'high_risk_countries': 20000,

            # =============================================
            # BENIGN SCENARIOS (50% = 250,000 events)
            # =============================================

            # Normal Business Activity (120k)
            'normal_business_hours': 120000,

            # After-Hours Legitimate (40k)
            'normal_evening': 30000,
            'normal_weekend': 10000,

            # Internal Network (50k)
            'normal_private_ip': 50000,

            # Remote Workers (40k)
            'normal_vpn_legitimate': 40000,
        }

        self.scenario_counters = {k: 0 for k in self.scenario_distribution}

    def connect_db(self):
        """Create database connection pool."""
        try:
            self.db_pool = mysql.connector.pooling.MySQLConnectionPool(**DB_CONFIG)
            logger.info(f"Database pool created: {DB_CONFIG['database']}")
        except Exception as e:
            logger.error(f"Database connection failed: {e}")
            raise

    def close_db(self):
        """Close database connections."""
        if self.db_pool:
            # Pool doesn't have explicit close, connections auto-close
            pass

    def get_connection(self):
        """Get a connection from the pool."""
        return self.db_pool.get_connection()

    # ==================================================
    # IP GENERATION
    # ==================================================

    def generate_public_ip(self, prefix: str = None) -> str:
        """Generate a realistic public IP address."""
        if prefix:
            parts = prefix.rstrip('.').split('.')
            remaining = 4 - len(parts)
            for _ in range(remaining):
                parts.append(str(random.randint(1, 254)))
            return '.'.join(parts)
        else:
            # Random public IP avoiding reserved ranges
            while True:
                ip = f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
                first_octet = int(ip.split('.')[0])
                # Avoid private and reserved
                if first_octet not in [10, 127] and not ip.startswith('192.168.') and not ip.startswith('172.'):
                    return ip

    def generate_private_ip(self) -> str:
        """Generate a private IP address."""
        choice = random.choice(['10', '172', '192'])
        if choice == '10':
            return f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        elif choice == '172':
            return f"172.{random.randint(16, 31)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        else:
            return f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}"

    def generate_scanner_ip(self) -> str:
        """Generate a known scanner IP."""
        prefix = random.choice(SCANNER_IP_PREFIXES)
        return self.generate_public_ip(prefix)

    def generate_tor_ip(self) -> str:
        """Generate a Tor exit node IP."""
        prefix = random.choice(TOR_EXIT_PREFIXES)
        return self.generate_public_ip(prefix)

    def generate_vpn_ip(self) -> str:
        """Generate a VPN provider IP."""
        prefix = random.choice(VPN_PREFIXES)
        return self.generate_public_ip(prefix)

    def generate_datacenter_ip(self) -> str:
        """Generate a datacenter IP."""
        prefix = random.choice(DATACENTER_PREFIXES)
        return self.generate_public_ip(prefix)

    def generate_clean_ip(self) -> str:
        """Generate a clean/trusted IP."""
        prefix = random.choice(CLEAN_PREFIXES)
        return self.generate_public_ip(prefix)

    # ==================================================
    # GEOGRAPHIC DATA
    # ==================================================

    def get_geo_data(self, country_code: str = None) -> Dict:
        """Get geographic data for a country."""
        if not country_code:
            country_code = random.choice(list(COUNTRY_DATA.keys()))

        data = COUNTRY_DATA.get(country_code, COUNTRY_DATA['US'])
        city = random.choice(data['cities'])

        # Add some randomness to coordinates
        lat = data['lat'] + random.uniform(-2, 2)
        lon = data['lon'] + random.uniform(-2, 2)

        return {
            'country_code': country_code,
            'country_name': data['name'],
            'city': city,
            'latitude': round(lat, 6),
            'longitude': round(lon, 6)
        }

    def get_high_risk_geo(self) -> Dict:
        """Get geo data from a high-risk country."""
        country = random.choice(HIGH_RISK_COUNTRIES)
        return self.get_geo_data(country)

    def get_clean_geo(self) -> Dict:
        """Get geo data from a clean country."""
        clean_countries = ['US', 'CA', 'GB', 'DE', 'FR', 'JP', 'AU', 'SG', 'NL', 'SE', 'CH']
        country = random.choice(clean_countries)
        return self.get_geo_data(country)

    # ==================================================
    # TIMESTAMP GENERATION
    # ==================================================

    def generate_business_hours_timestamp(self, base_date: datetime = None) -> datetime:
        """Generate timestamp during business hours (9-17, weekdays)."""
        if not base_date:
            base_date = datetime.now() - timedelta(days=random.randint(0, 365))

        # Find a weekday
        while base_date.weekday() >= 5:  # Skip weekend
            base_date -= timedelta(days=1)

        hour = random.randint(9, 17)
        minute = random.randint(0, 59)
        second = random.randint(0, 59)

        return base_date.replace(hour=hour, minute=minute, second=second, microsecond=0)

    def generate_evening_timestamp(self, base_date: datetime = None) -> datetime:
        """Generate timestamp during evening hours (18-22)."""
        if not base_date:
            base_date = datetime.now() - timedelta(days=random.randint(0, 365))

        hour = random.randint(18, 22)
        minute = random.randint(0, 59)
        second = random.randint(0, 59)

        return base_date.replace(hour=hour, minute=minute, second=second, microsecond=0)

    def generate_night_timestamp(self, base_date: datetime = None) -> datetime:
        """Generate timestamp during night hours (22-06)."""
        if not base_date:
            base_date = datetime.now() - timedelta(days=random.randint(0, 365))

        if random.random() < 0.5:
            hour = random.randint(22, 23)
        else:
            hour = random.randint(0, 5)

        minute = random.randint(0, 59)
        second = random.randint(0, 59)

        return base_date.replace(hour=hour, minute=minute, second=second, microsecond=0)

    def generate_weekend_timestamp(self, base_date: datetime = None) -> datetime:
        """Generate timestamp on weekend."""
        if not base_date:
            base_date = datetime.now() - timedelta(days=random.randint(0, 365))

        # Find a weekend day
        while base_date.weekday() < 5:
            base_date += timedelta(days=1)

        hour = random.randint(0, 23)
        minute = random.randint(0, 59)
        second = random.randint(0, 59)

        return base_date.replace(hour=hour, minute=minute, second=second, microsecond=0)

    # ==================================================
    # ATTACK SCENARIO GENERATORS
    # ==================================================

    def generate_brute_force_sequence(self, count: int) -> List[Dict]:
        """Generate brute force attack events with varied threat signatures."""
        events = []

        while len(events) < count:
            # Each brute force attack sequence
            ip = self.generate_public_ip()

            # 70% from high-risk countries, 30% from clean countries (new attackers)
            if random.random() < 0.70:
                geo = self.get_high_risk_geo()
            else:
                geo = self.get_clean_geo()

            username = random.choice(COMMON_ATTACK_USERNAMES)
            server = random.choice(TARGET_SERVERS)
            target_port = get_random_ssh_port()

            # Start time for this sequence
            base_time = datetime.now() - timedelta(days=random.randint(0, 365))

            # Sequence length (20-100 attempts per brute force attack)
            seq_length = random.randint(20, 100)

            # 30% of brute force IPs are "new" - not yet reported
            is_new_attacker = random.random() < 0.30
            if is_new_attacker:
                abuse_score = random.randint(0, 25)
                vt_positives = random.randint(0, 2)
                greynoise = random.choice(['unknown', 'unknown', 'malicious'])
                threat_level = random.choice(['clean', 'low', 'medium'])
            else:
                abuse_score = random.randint(40, 100)
                vt_positives = random.randint(2, 10)
                greynoise = 'malicious'
                threat_level = random.choice(['high', 'critical'])

            for i in range(seq_length):
                if len(events) >= count:
                    break

                timestamp = base_time + timedelta(seconds=random.randint(1, 10) * (i + 1))

                event = {
                    'event_uuid': str(uuid.uuid4()),
                    'timestamp': timestamp,
                    'event_type': 'failed_login',
                    'auth_method': 'password',
                    'failure_reason': 'invalid_password',
                    'source_ip': ip,
                    'source_port': random.randint(32768, 65535),
                    'target_server': server,
                    'target_port': target_port,
                    'target_username': username,
                    **geo,
                    'is_private_ip': 0,
                    'is_vpn': 0,
                    'is_proxy': 0,
                    'is_tor': 0,
                    'is_datacenter': random.choice([0, 1]),
                    'is_hosting': random.choice([0, 0, 1]),
                    'abuseipdb_score': abuse_score,
                    'virustotal_positives': vt_positives,
                    'virustotal_total': 90,
                    'greynoise_classification': greynoise,
                    'threat_level': threat_level,
                    'scenario_type': 'brute_force',
                    'is_malicious': 1
                }
                events.append(event)

            # Final success (30% chance brute force succeeded)
            if len(events) < count and random.random() < 0.3:
                success_event = events[-1].copy()
                success_event['event_uuid'] = str(uuid.uuid4())
                success_event['timestamp'] = events[-1]['timestamp'] + timedelta(seconds=random.randint(1, 5))
                success_event['event_type'] = 'success_login'
                success_event['failure_reason'] = None
                events.append(success_event)

        return events[:count]

    def generate_credential_stuffing(self, count: int) -> List[Dict]:
        """Generate credential stuffing events with varied threat signatures."""
        events = []
        all_usernames = COMMON_ATTACK_USERNAMES + LEGITIMATE_USERNAMES

        while len(events) < count:
            # Each credential stuffing session from different IP
            ip = self.generate_public_ip()

            # 65% from high-risk, 35% from clean countries
            if random.random() < 0.65:
                geo = self.get_high_risk_geo()
            else:
                geo = self.get_clean_geo()

            target_port = get_random_ssh_port()
            base_time = datetime.now() - timedelta(days=random.randint(0, 365))

            # Session length (10-50 different usernames per session)
            session_length = random.randint(10, 50)

            # 25% are new attackers with low threat scores
            is_new_attacker = random.random() < 0.25
            if is_new_attacker:
                abuse_score = random.randint(0, 30)
                vt_positives = random.randint(0, 2)
                greynoise = random.choice(['unknown', 'unknown', 'benign'])
                threat_level = random.choice(['clean', 'low', 'medium'])
            else:
                abuse_score = random.randint(30, 90)
                vt_positives = random.randint(1, 5)
                greynoise = random.choice(['malicious', 'unknown'])
                threat_level = random.choice(['medium', 'high'])

            for i in range(session_length):
                if len(events) >= count:
                    break

                timestamp = base_time + timedelta(seconds=random.randint(1, 5) * (i + 1))
                username = random.choice(all_usernames)

                event = {
                    'event_uuid': str(uuid.uuid4()),
                    'timestamp': timestamp,
                    'event_type': 'failed_login',
                    'auth_method': 'password',
                    'failure_reason': random.choice(['invalid_user', 'invalid_password']),
                    'source_ip': ip,
                    'source_port': random.randint(32768, 65535),
                    'target_server': random.choice(TARGET_SERVERS),
                    'target_port': target_port,
                    'target_username': username,
                    **geo,
                    'is_private_ip': 0,
                    'is_vpn': random.choice([0, 1]),
                    'is_proxy': random.choice([0, 1]),
                    'is_tor': 0,
                    'is_datacenter': random.choice([0, 1]),
                    'is_hosting': 0,
                    'abuseipdb_score': abuse_score,
                    'virustotal_positives': vt_positives,
                    'virustotal_total': 90,
                    'greynoise_classification': greynoise,
                    'threat_level': threat_level,
                    'scenario_type': 'credential_stuffing',
                    'is_malicious': 1
                }
                events.append(event)

        return events[:count]

    def generate_password_spray(self, count: int) -> List[Dict]:
        """Generate password spray events with varied threat signatures."""
        events = []
        base_time = datetime.now() - timedelta(days=random.randint(0, 365))

        # Multiple IPs trying same credentials
        for i in range(count):
            ip = self.generate_public_ip()

            # 60% from high-risk, 40% from clean (distributed botnets)
            if random.random() < 0.60:
                geo = self.get_high_risk_geo()
            else:
                geo = self.get_clean_geo()

            timestamp = base_time + timedelta(minutes=random.randint(1, 30) * (i + 1))

            # Varied threat scores (distributed attacks often use clean IPs)
            if random.random() < 0.40:  # 40% are from clean/new IPs
                abuse_score = random.randint(0, 25)
                vt_positives = random.randint(0, 1)
                greynoise = 'unknown'
                threat_level = random.choice(['clean', 'low'])
            else:
                abuse_score = random.randint(15, 60)
                vt_positives = random.randint(0, 3)
                greynoise = random.choice(['unknown', 'malicious'])
                threat_level = random.choice(['low', 'medium'])

            event = {
                'event_uuid': str(uuid.uuid4()),
                'timestamp': timestamp,
                'event_type': 'failed_login',
                'auth_method': 'password',
                'failure_reason': 'invalid_password',
                'source_ip': ip,
                'source_port': random.randint(32768, 65535),
                'target_server': random.choice(TARGET_SERVERS),
                'target_port': get_random_ssh_port(),
                'target_username': random.choice(['admin', 'root', 'administrator']),
                **geo,
                'is_private_ip': 0,
                'is_vpn': random.choice([0, 1]),
                'is_proxy': 0,
                'is_tor': 0,
                'is_datacenter': random.choice([0, 1]),
                'is_hosting': 0,
                'abuseipdb_score': abuse_score,
                'virustotal_positives': vt_positives,
                'virustotal_total': 90,
                'greynoise_classification': greynoise,
                'threat_level': threat_level,
                'scenario_type': 'password_spray',
                'is_malicious': 1
            }
            events.append(event)

        return events

    def generate_impossible_travel(self, count: int) -> List[Dict]:
        """Generate impossible travel events (same user, >1000km/h velocity)."""
        events = []
        username = random.choice(LEGITIMATE_USERNAMES)

        base_time = datetime.now() - timedelta(days=random.randint(0, 365))

        # Pairs of events: first in one location, second in distant location within short time
        pairs = count // 2

        for i in range(pairs):
            # First location
            geo1 = self.get_geo_data('US')
            ip1 = self.generate_public_ip()
            timestamp1 = base_time + timedelta(hours=i * 2)

            event1 = {
                'event_uuid': str(uuid.uuid4()),
                'timestamp': timestamp1,
                'event_type': 'success_login',
                'auth_method': 'password',
                'failure_reason': None,
                'source_ip': ip1,
                'source_port': random.randint(32768, 65535),
                'target_server': random.choice(TARGET_SERVERS),
                'target_port': get_random_ssh_port(),
                'target_username': username,
                **geo1,
                'is_private_ip': 0,
                'is_vpn': 0,
                'is_proxy': 0,
                'is_tor': 0,
                'is_datacenter': 0,
                'is_hosting': 0,
                'abuseipdb_score': 0,
                'virustotal_positives': 0,
                'virustotal_total': 90,
                'greynoise_classification': 'benign',
                'threat_level': 'clean',
                'scenario_type': 'impossible_travel',
                'is_malicious': 1  # This is suspicious behavior
            }
            events.append(event1)

            # Second location (far away, within 30 minutes - impossible travel)
            geo2 = self.get_geo_data('CN')  # ~12000km away
            ip2 = self.generate_public_ip()
            timestamp2 = timestamp1 + timedelta(minutes=random.randint(10, 30))

            event2 = {
                'event_uuid': str(uuid.uuid4()),
                'timestamp': timestamp2,
                'event_type': 'success_login',
                'auth_method': 'password',
                'failure_reason': None,
                'source_ip': ip2,
                'source_port': random.randint(32768, 65535),
                'target_server': random.choice(TARGET_SERVERS),
                'target_port': get_random_ssh_port(),
                'target_username': username,
                **geo2,
                'is_private_ip': 0,
                'is_vpn': 0,
                'is_proxy': 0,
                'is_tor': 0,
                'is_datacenter': 0,
                'is_hosting': 0,
                'abuseipdb_score': random.randint(20, 50),
                'virustotal_positives': random.randint(0, 2),
                'virustotal_total': 90,
                'greynoise_classification': 'unknown',
                'threat_level': 'medium',
                'scenario_type': 'impossible_travel',
                'is_malicious': 1
            }
            events.append(event2)

            if len(events) >= count:
                break

        return events[:count]

    def generate_lateral_movement(self, count: int) -> List[Dict]:
        """Generate lateral movement events (same IP → 5+ servers in 10 min)."""
        events = []
        ip = self.generate_private_ip() if random.random() < 0.5 else self.generate_public_ip()
        geo = self.get_geo_data()
        username = random.choice(LEGITIMATE_USERNAMES)

        base_time = datetime.now() - timedelta(days=random.randint(0, 365))

        # Hit multiple servers rapidly
        servers = random.sample(TARGET_SERVERS, min(count, len(TARGET_SERVERS)))

        for i, server in enumerate(servers):
            if len(events) >= count:
                break

            timestamp = base_time + timedelta(seconds=random.randint(30, 120) * (i + 1))

            event = {
                'event_uuid': str(uuid.uuid4()),
                'timestamp': timestamp,
                'event_type': 'success_login',
                'auth_method': 'publickey',
                'failure_reason': None,
                'source_ip': ip,
                'source_port': random.randint(32768, 65535),
                'target_server': server,
                'target_port': get_random_ssh_port(),
                'target_username': username,
                **geo,
                'is_private_ip': 1 if ip.startswith(('10.', '172.', '192.168.')) else 0,
                'is_vpn': 0,
                'is_proxy': 0,
                'is_tor': 0,
                'is_datacenter': 0,
                'is_hosting': 0,
                'abuseipdb_score': 0,
                'virustotal_positives': 0,
                'virustotal_total': 90,
                'greynoise_classification': 'unknown',
                'threat_level': 'low',
                'scenario_type': 'lateral_movement',
                'is_malicious': 1
            }
            events.append(event)

        return events

    def generate_off_hours_access(self, count: int) -> List[Dict]:
        """Generate off-hours access events (2-5 AM logins)."""
        events = []

        for _ in range(count):
            ip = self.generate_public_ip()
            geo = self.get_geo_data()
            timestamp = self.generate_night_timestamp()

            event = {
                'event_uuid': str(uuid.uuid4()),
                'timestamp': timestamp,
                'event_type': random.choice(['success_login', 'failed_login']),
                'auth_method': 'password',
                'failure_reason': 'invalid_password' if random.random() < 0.4 else None,
                'source_ip': ip,
                'source_port': random.randint(32768, 65535),
                'target_server': random.choice(TARGET_SERVERS),
                'target_port': get_random_ssh_port(),
                'target_username': random.choice(LEGITIMATE_USERNAMES),
                **geo,
                'is_private_ip': 0,
                'is_vpn': random.choice([0, 1]),
                'is_proxy': 0,
                'is_tor': 0,
                'is_datacenter': 0,
                'is_hosting': 0,
                'abuseipdb_score': random.randint(0, 30),
                'virustotal_positives': 0,
                'virustotal_total': 90,
                'greynoise_classification': 'unknown',
                'threat_level': 'low',
                'scenario_type': 'off_hours_access',
                'is_malicious': 1
            }
            if event['event_type'] == 'success_login':
                event['failure_reason'] = None
            events.append(event)

        return events

    def generate_root_admin_attempts(self, count: int) -> List[Dict]:
        """Generate root/admin login attempts."""
        events = []

        for _ in range(count):
            ip = self.generate_public_ip()
            geo = self.get_high_risk_geo() if random.random() < 0.6 else self.get_clean_geo()

            event = {
                'event_uuid': str(uuid.uuid4()),
                'timestamp': datetime.now() - timedelta(days=random.randint(0, 365),
                                                        hours=random.randint(0, 23)),
                'event_type': 'failed_login',
                'auth_method': 'password',
                'failure_reason': random.choice(['invalid_password', 'permission_denied']),
                'source_ip': ip,
                'source_port': random.randint(32768, 65535),
                'target_server': random.choice(TARGET_SERVERS),
                'target_port': get_random_ssh_port(),
                'target_username': random.choice(['root', 'admin', 'administrator', 'sudo']),
                **geo,
                'is_private_ip': 0,
                'is_vpn': 0,
                'is_proxy': 0,
                'is_tor': 0,
                'is_datacenter': random.choice([0, 1]),
                'is_hosting': 0,
                'abuseipdb_score': random.randint(30, 80),
                'virustotal_positives': random.randint(0, 5),
                'virustotal_total': 90,
                'greynoise_classification': random.choice(['unknown', 'malicious']),
                'threat_level': 'medium',
                'scenario_type': 'root_admin_attempts',
                'is_malicious': 1
            }
            events.append(event)

        return events

    def generate_known_scanner_events(self, count: int) -> List[Dict]:
        """Generate events from known scanner IPs (Shodan, Censys)."""
        events = []

        for _ in range(count):
            ip = self.generate_scanner_ip()
            geo = self.get_geo_data('US')  # Most scanners US-based

            event = {
                'event_uuid': str(uuid.uuid4()),
                'timestamp': datetime.now() - timedelta(days=random.randint(0, 365),
                                                        hours=random.randint(0, 23)),
                'event_type': 'failed_login',
                'auth_method': 'password',
                'failure_reason': random.choice(['invalid_user', 'connection_timeout']),
                'source_ip': ip,
                'source_port': random.randint(32768, 65535),
                'target_server': random.choice(TARGET_SERVERS),
                'target_port': get_random_ssh_port(),
                'target_username': random.choice(COMMON_ATTACK_USERNAMES[:10]),
                **geo,
                'is_private_ip': 0,
                'is_vpn': 0,
                'is_proxy': 0,
                'is_tor': 0,
                'is_datacenter': 1,
                'is_hosting': 1,
                'abuseipdb_score': random.randint(70, 100),
                'virustotal_positives': random.randint(3, 10),
                'virustotal_total': 90,
                'greynoise_classification': 'malicious',
                'threat_level': 'critical',
                'scenario_type': 'known_scanners',
                'is_malicious': 1
            }
            events.append(event)

        return events

    def generate_tor_events(self, count: int) -> List[Dict]:
        """Generate events from Tor exit nodes."""
        events = []

        for _ in range(count):
            ip = self.generate_tor_ip()
            geo = self.get_geo_data(random.choice(['DE', 'NL', 'FR', 'CH']))

            event = {
                'event_uuid': str(uuid.uuid4()),
                'timestamp': datetime.now() - timedelta(days=random.randint(0, 365),
                                                        hours=random.randint(0, 23)),
                'event_type': random.choice(['failed_login', 'success_login']),
                'auth_method': 'password',
                'failure_reason': 'invalid_password' if random.random() < 0.7 else None,
                'source_ip': ip,
                'source_port': random.randint(32768, 65535),
                'target_server': random.choice(TARGET_SERVERS),
                'target_port': get_random_ssh_port(),
                'target_username': random.choice(COMMON_ATTACK_USERNAMES),
                **geo,
                'is_private_ip': 0,
                'is_vpn': 0,
                'is_proxy': 0,
                'is_tor': 1,
                'is_datacenter': 0,
                'is_hosting': 0,
                'abuseipdb_score': random.randint(50, 90),
                'virustotal_positives': random.randint(1, 5),
                'virustotal_total': 90,
                'greynoise_classification': 'malicious',
                'threat_level': 'high',
                'scenario_type': 'tor_exit_nodes',
                'is_malicious': 1
            }
            if event['event_type'] == 'success_login':
                event['failure_reason'] = None
            events.append(event)

        return events

    def generate_vpn_proxy_events(self, count: int) -> List[Dict]:
        """Generate events from VPN/Proxy IPs (suspicious)."""
        events = []

        for _ in range(count):
            ip = self.generate_vpn_ip()
            geo = self.get_geo_data(random.choice(['NL', 'CH', 'SE', 'PA']))

            event = {
                'event_uuid': str(uuid.uuid4()),
                'timestamp': datetime.now() - timedelta(days=random.randint(0, 365),
                                                        hours=random.randint(0, 23)),
                'event_type': random.choice(['failed_login', 'success_login']),
                'auth_method': 'password',
                'failure_reason': 'invalid_password' if random.random() < 0.5 else None,
                'source_ip': ip,
                'source_port': random.randint(32768, 65535),
                'target_server': random.choice(TARGET_SERVERS),
                'target_port': get_random_ssh_port(),
                'target_username': random.choice(LEGITIMATE_USERNAMES + COMMON_ATTACK_USERNAMES[:5]),
                **geo,
                'is_private_ip': 0,
                'is_vpn': 1,
                'is_proxy': random.choice([0, 1]),
                'is_tor': 0,
                'is_datacenter': 0,
                'is_hosting': 0,
                'abuseipdb_score': random.randint(20, 60),
                'virustotal_positives': random.randint(0, 3),
                'virustotal_total': 90,
                'greynoise_classification': 'unknown',
                'threat_level': 'medium',
                'scenario_type': 'vpn_proxy_access',
                'is_malicious': 1
            }
            if event['event_type'] == 'success_login':
                event['failure_reason'] = None
            events.append(event)

        return events

    def generate_datacenter_attack_events(self, count: int) -> List[Dict]:
        """Generate events from datacenter IPs (suspicious automation)."""
        events = []

        for _ in range(count):
            ip = self.generate_datacenter_ip()
            geo = self.get_geo_data(random.choice(['US', 'DE', 'SG', 'JP']))

            event = {
                'event_uuid': str(uuid.uuid4()),
                'timestamp': datetime.now() - timedelta(days=random.randint(0, 365),
                                                        hours=random.randint(0, 23)),
                'event_type': 'failed_login',
                'auth_method': 'password',
                'failure_reason': random.choice(['invalid_user', 'invalid_password']),
                'source_ip': ip,
                'source_port': random.randint(32768, 65535),
                'target_server': random.choice(TARGET_SERVERS),
                'target_port': get_random_ssh_port(),
                'target_username': random.choice(COMMON_ATTACK_USERNAMES),
                **geo,
                'is_private_ip': 0,
                'is_vpn': 0,
                'is_proxy': 0,
                'is_tor': 0,
                'is_datacenter': 1,
                'is_hosting': 1,
                'abuseipdb_score': random.randint(40, 80),
                'virustotal_positives': random.randint(1, 5),
                'virustotal_total': 90,
                'greynoise_classification': random.choice(['unknown', 'malicious']),
                'threat_level': 'medium',
                'scenario_type': 'datacenter_attacks',
                'is_malicious': 1
            }
            events.append(event)

        return events

    def generate_high_risk_country_events(self, count: int) -> List[Dict]:
        """Generate events from high-risk countries."""
        events = []

        for _ in range(count):
            ip = self.generate_public_ip()
            geo = self.get_high_risk_geo()

            event = {
                'event_uuid': str(uuid.uuid4()),
                'timestamp': datetime.now() - timedelta(days=random.randint(0, 365),
                                                        hours=random.randint(0, 23)),
                'event_type': random.choice(['failed_login', 'success_login']),
                'auth_method': 'password',
                'failure_reason': random.choice(['invalid_user', 'invalid_password']) if random.random() < 0.6 else None,
                'source_ip': ip,
                'source_port': random.randint(32768, 65535),
                'target_server': random.choice(TARGET_SERVERS),
                'target_port': get_random_ssh_port(),
                'target_username': random.choice(COMMON_ATTACK_USERNAMES + LEGITIMATE_USERNAMES[:5]),
                **geo,
                'is_private_ip': 0,
                'is_vpn': random.choice([0, 1]),
                'is_proxy': 0,
                'is_tor': 0,
                'is_datacenter': random.choice([0, 1]),
                'is_hosting': 0,
                'abuseipdb_score': random.randint(30, 70),
                'virustotal_positives': random.randint(0, 4),
                'virustotal_total': 90,
                'greynoise_classification': random.choice(['unknown', 'malicious']),
                'threat_level': 'medium',
                'scenario_type': 'high_risk_countries',
                'is_malicious': 1
            }
            if event['event_type'] == 'success_login':
                event['failure_reason'] = None
            events.append(event)

        return events

    # ==================================================
    # BENIGN SCENARIO GENERATORS
    # ==================================================

    def generate_normal_business_hours(self, count: int) -> List[Dict]:
        """Generate normal business hours logins with realistic noise."""
        events = []

        for _ in range(count):
            ip = self.generate_clean_ip() if random.random() < 0.3 else self.generate_public_ip()

            # 10% of legitimate users are from high-risk countries (remote workers, outsourcing)
            if random.random() < 0.10:
                geo = self.get_high_risk_geo()
            else:
                geo = self.get_clean_geo()

            # 15% of benign logins fail (typos, forgot password, expired creds)
            is_failed = random.random() < 0.15

            # Small chance of false positive threat scores (0-20 range)
            abuse_score = random.randint(0, 20) if random.random() < 0.15 else 0
            vt_positives = random.randint(0, 2) if random.random() < 0.08 else 0

            # Determine threat level based on scores (with noise)
            if abuse_score > 15 or vt_positives > 0:
                threat_level = random.choice(['clean', 'low'])
            else:
                threat_level = 'clean'

            event = {
                'event_uuid': str(uuid.uuid4()),
                'timestamp': self.generate_business_hours_timestamp(),
                'event_type': 'failed_login' if is_failed else 'success_login',
                'auth_method': random.choice(['password', 'publickey']),
                'failure_reason': random.choice(['invalid_password', 'expired_credential']) if is_failed else None,
                'source_ip': ip,
                'source_port': random.randint(32768, 65535),
                'target_server': random.choice(TARGET_SERVERS),
                'target_port': get_random_ssh_port(),
                'target_username': random.choice(LEGITIMATE_USERNAMES),
                **geo,
                'is_private_ip': 0,
                'is_vpn': random.choice([0, 0, 0, 1]),  # 25% use VPN
                'is_proxy': 0,
                'is_tor': 0,
                'is_datacenter': random.choice([0, 0, 0, 1]),  # 25% from cloud
                'is_hosting': 0,
                'abuseipdb_score': abuse_score,
                'virustotal_positives': vt_positives,
                'virustotal_total': 90,
                'greynoise_classification': random.choice(['benign', 'benign', 'unknown']),
                'threat_level': threat_level,
                'scenario_type': 'normal_business_hours',
                'is_malicious': 0
            }
            events.append(event)

        return events

    def generate_normal_evening(self, count: int) -> List[Dict]:
        """Generate normal evening logins with realistic noise."""
        events = []

        for _ in range(count):
            ip = self.generate_public_ip()

            # 12% from high-risk countries (global teams, different timezones)
            if random.random() < 0.12:
                geo = self.get_high_risk_geo()
            else:
                geo = self.get_clean_geo()

            # 18% failure rate (tired users, more typos in evening)
            is_failed = random.random() < 0.18

            # False positive threat scores
            abuse_score = random.randint(0, 25) if random.random() < 0.12 else 0
            vt_positives = random.randint(0, 2) if random.random() < 0.06 else 0

            threat_level = 'low' if (abuse_score > 15 or vt_positives > 0) else 'clean'

            event = {
                'event_uuid': str(uuid.uuid4()),
                'timestamp': self.generate_evening_timestamp(),
                'event_type': 'failed_login' if is_failed else 'success_login',
                'auth_method': random.choice(['password', 'publickey']),
                'failure_reason': random.choice(['invalid_password', 'expired_credential']) if is_failed else None,
                'source_ip': ip,
                'source_port': random.randint(32768, 65535),
                'target_server': random.choice(TARGET_SERVERS),
                'target_port': get_random_ssh_port(),
                'target_username': random.choice(LEGITIMATE_USERNAMES),
                **geo,
                'is_private_ip': 0,
                'is_vpn': random.choice([0, 1]),  # 50% use VPN from home
                'is_proxy': 0,
                'is_tor': 0,
                'is_datacenter': random.choice([0, 0, 1]),  # 33% from cloud
                'is_hosting': 0,
                'abuseipdb_score': abuse_score,
                'virustotal_positives': vt_positives,
                'virustotal_total': 90,
                'greynoise_classification': random.choice(['benign', 'unknown']),
                'threat_level': threat_level,
                'scenario_type': 'normal_evening',
                'is_malicious': 0
            }
            events.append(event)

        return events

    def generate_normal_weekend(self, count: int) -> List[Dict]:
        """Generate normal weekend logins with realistic noise."""
        events = []

        for _ in range(count):
            ip = self.generate_public_ip()

            # 15% from high-risk countries (on-call devs worldwide)
            if random.random() < 0.15:
                geo = self.get_high_risk_geo()
            else:
                geo = self.get_clean_geo()

            # 20% failure rate (weekend stress, urgency)
            is_failed = random.random() < 0.20

            # False positive threat scores
            abuse_score = random.randint(0, 30) if random.random() < 0.10 else 0
            vt_positives = random.randint(0, 2) if random.random() < 0.05 else 0

            threat_level = 'low' if (abuse_score > 20 or vt_positives > 0) else 'clean'

            event = {
                'event_uuid': str(uuid.uuid4()),
                'timestamp': self.generate_weekend_timestamp(),
                'event_type': 'failed_login' if is_failed else 'success_login',
                'auth_method': random.choice(['password', 'publickey']),
                'failure_reason': random.choice(['invalid_password', 'expired_credential', 'connection_timeout']) if is_failed else None,
                'source_ip': ip,
                'source_port': random.randint(32768, 65535),
                'target_server': random.choice(TARGET_SERVERS),
                'target_port': get_random_ssh_port(),
                'target_username': random.choice(LEGITIMATE_USERNAMES),
                **geo,
                'is_private_ip': 0,
                'is_vpn': random.choice([0, 1]),
                'is_proxy': 0,
                'is_tor': 0,
                'is_datacenter': random.choice([0, 0, 1]),
                'is_hosting': 0,
                'abuseipdb_score': abuse_score,
                'virustotal_positives': vt_positives,
                'virustotal_total': 90,
                'greynoise_classification': random.choice(['benign', 'unknown']),
                'threat_level': threat_level,
                'scenario_type': 'normal_weekend',
                'is_malicious': 0
            }
            events.append(event)

        return events

    def generate_normal_private_ip(self, count: int) -> List[Dict]:
        """Generate normal logins from private IPs with realistic noise."""
        events = []

        for _ in range(count):
            ip = self.generate_private_ip()

            # 12% failure rate (internal users also make mistakes)
            is_failed = random.random() < 0.12

            # Use business hours mostly, but some after hours
            if random.random() < 0.15:
                timestamp = self.generate_evening_timestamp()
            elif random.random() < 0.05:
                timestamp = self.generate_night_timestamp()
            else:
                timestamp = self.generate_business_hours_timestamp()

            event = {
                'event_uuid': str(uuid.uuid4()),
                'timestamp': timestamp,
                'event_type': 'failed_login' if is_failed else 'success_login',
                'auth_method': random.choice(['password', 'publickey', 'publickey']),  # More key-based internally
                'failure_reason': random.choice(['invalid_password', 'expired_credential']) if is_failed else None,
                'source_ip': ip,
                'source_port': random.randint(32768, 65535),
                'target_server': random.choice(TARGET_SERVERS),
                'target_port': get_random_ssh_port(),
                'target_username': random.choice(LEGITIMATE_USERNAMES + SYSTEM_ACCOUNTS[:5]),
                'country_code': None,
                'country_name': 'Private Network',
                'city': 'Internal',
                'latitude': 0.0,
                'longitude': 0.0,
                'is_private_ip': 1,
                'is_vpn': 0,
                'is_proxy': 0,
                'is_tor': 0,
                'is_datacenter': 0,
                'is_hosting': 0,
                'abuseipdb_score': 0,  # Private IPs not on threat intel
                'virustotal_positives': 0,
                'virustotal_total': 0,
                'greynoise_classification': None,
                'threat_level': 'clean',
                'scenario_type': 'normal_private_ip',
                'is_malicious': 0
            }
            events.append(event)

        return events

    def generate_normal_vpn_legitimate(self, count: int) -> List[Dict]:
        """Generate legitimate VPN logins (remote workers) with realistic noise."""
        events = []

        for _ in range(count):
            ip = self.generate_vpn_ip()

            # 20% from high-risk countries (remote workers traveling, expats)
            if random.random() < 0.20:
                geo = self.get_high_risk_geo()
            else:
                geo = self.get_clean_geo()

            # 15% failure rate
            is_failed = random.random() < 0.15

            # VPN IPs often have some threat intel scores (false positives)
            # because they're shared IPs used by many people
            abuse_score = random.randint(0, 35) if random.random() < 0.25 else 0
            vt_positives = random.randint(0, 3) if random.random() < 0.10 else 0

            # Threat level based on scores
            if abuse_score > 25 or vt_positives > 1:
                threat_level = 'medium'
            elif abuse_score > 15 or vt_positives > 0:
                threat_level = 'low'
            else:
                threat_level = 'clean'

            # Varied timestamps (remote workers have flexible hours)
            if random.random() < 0.60:
                timestamp = self.generate_business_hours_timestamp()
            elif random.random() < 0.25:
                timestamp = self.generate_evening_timestamp()
            else:
                timestamp = self.generate_night_timestamp()

            event = {
                'event_uuid': str(uuid.uuid4()),
                'timestamp': timestamp,
                'event_type': 'failed_login' if is_failed else 'success_login',
                'auth_method': random.choice(['password', 'publickey']),
                'failure_reason': random.choice(['invalid_password', 'connection_timeout']) if is_failed else None,
                'source_ip': ip,
                'source_port': random.randint(32768, 65535),
                'target_server': random.choice(TARGET_SERVERS),
                'target_port': get_random_ssh_port(),
                'target_username': random.choice(LEGITIMATE_USERNAMES),
                **geo,
                'is_private_ip': 0,
                'is_vpn': 1,
                'is_proxy': random.choice([0, 0, 1]),  # Some VPNs detected as proxy
                'is_tor': 0,
                'is_datacenter': 0,
                'is_hosting': 0,
                'abuseipdb_score': abuse_score,
                'virustotal_positives': vt_positives,
                'virustotal_total': 90,
                'greynoise_classification': random.choice(['benign', 'unknown', 'unknown']),
                'threat_level': threat_level,
                'scenario_type': 'normal_vpn_legitimate',
                'is_malicious': 0
            }
            events.append(event)

        return events

    # ==================================================
    # MAIN GENERATION LOGIC
    # ==================================================

    def generate_all_events(self) -> List[Dict]:
        """Generate all events according to distribution."""
        all_events = []

        logger.info("=" * 60)
        logger.info("SSH GUARDIAN v3.0 - REALISTIC DATA GENERATOR")
        logger.info("=" * 60)
        logger.info(f"Target: {self.target_count:,} events")
        logger.info(f"Train/Test Split: {int(TRAIN_RATIO*100)}% / {int(TEST_RATIO*100)}%")
        logger.info("=" * 60)

        # Generator mapping
        generators = {
            'brute_force': self.generate_brute_force_sequence,
            'credential_stuffing': self.generate_credential_stuffing,
            'password_spray': self.generate_password_spray,
            'impossible_travel': self.generate_impossible_travel,
            'lateral_movement': self.generate_lateral_movement,
            'off_hours_access': self.generate_off_hours_access,
            'root_admin_attempts': self.generate_root_admin_attempts,
            'known_scanners': self.generate_known_scanner_events,
            'tor_exit_nodes': self.generate_tor_events,
            'vpn_proxy_access': self.generate_vpn_proxy_events,
            'datacenter_attacks': self.generate_datacenter_attack_events,
            'high_risk_countries': self.generate_high_risk_country_events,
            'normal_business_hours': self.generate_normal_business_hours,
            'normal_evening': self.generate_normal_evening,
            'normal_weekend': self.generate_normal_weekend,
            'normal_private_ip': self.generate_normal_private_ip,
            'normal_vpn_legitimate': self.generate_normal_vpn_legitimate,
        }

        # Generate events for each scenario
        for scenario, target_count in self.scenario_distribution.items():
            logger.info(f"Generating {target_count:,} events for: {scenario}")

            if scenario in generators:
                events = generators[scenario](target_count)
                all_events.extend(events)
                self.scenario_counters[scenario] = len(events)
                logger.info(f"  → Generated {len(events):,} events")
            else:
                logger.warning(f"  → No generator for {scenario}")

        # Shuffle all events
        logger.info("\nShuffling events...")
        random.shuffle(all_events)

        logger.info(f"\nTotal events generated: {len(all_events):,}")

        return all_events

    def split_train_test(self, events: List[Dict]) -> Tuple[List[Dict], List[Dict]]:
        """Split events into training and testing sets (stratified)."""
        # Separate by class
        malicious = [e for e in events if e['is_malicious'] == 1]
        benign = [e for e in events if e['is_malicious'] == 0]

        logger.info(f"\nClass distribution:")
        logger.info(f"  Malicious: {len(malicious):,}")
        logger.info(f"  Benign: {len(benign):,}")

        # Stratified split
        random.shuffle(malicious)
        random.shuffle(benign)

        train_mal_count = int(len(malicious) * TRAIN_RATIO)
        train_ben_count = int(len(benign) * TRAIN_RATIO)

        train_events = malicious[:train_mal_count] + benign[:train_ben_count]
        test_events = malicious[train_mal_count:] + benign[train_ben_count:]

        random.shuffle(train_events)
        random.shuffle(test_events)

        logger.info(f"\nTrain/Test split:")
        logger.info(f"  Training: {len(train_events):,} ({len(train_events)/len(events)*100:.1f}%)")
        logger.info(f"  Testing: {len(test_events):,} ({len(test_events)/len(events)*100:.1f}%)")

        return train_events, test_events

    def save_to_database(self, train_events: List[Dict], test_events: List[Dict]):
        """Save events to separate training and testing tables."""
        logger.info("\n" + "=" * 60)
        logger.info("SAVING TO DATABASE")
        logger.info("=" * 60)

        conn = self.get_connection()
        cursor = conn.cursor()

        try:
            # Clear existing data
            logger.info("Clearing existing data...")
            cursor.execute("TRUNCATE TABLE ml_training_data")
            cursor.execute("TRUNCATE TABLE ml_testing_data")
            conn.commit()

            # Insert SQL template
            insert_sql = """
                INSERT INTO {table} (
                    event_uuid, timestamp, event_type, auth_method, failure_reason,
                    source_ip, source_port, target_server, target_port, target_username,
                    country_code, country_name, city, latitude, longitude,
                    is_private_ip, is_vpn, is_proxy, is_tor, is_datacenter, is_hosting,
                    abuseipdb_score, virustotal_positives, virustotal_total,
                    greynoise_classification, threat_level,
                    scenario_type, is_malicious
                ) VALUES (
                    %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s, %s,
                    %s, %s, %s,
                    %s, %s,
                    %s, %s
                )
            """

            # Save training data
            logger.info(f"Saving {len(train_events):,} training events...")
            self._batch_insert(cursor, conn, insert_sql.format(table='ml_training_data'), train_events)

            # Save testing data
            logger.info(f"Saving {len(test_events):,} testing events...")
            self._batch_insert(cursor, conn, insert_sql.format(table='ml_testing_data'), test_events)

            # Create training run record
            run_uuid = str(uuid.uuid4())
            cursor.execute("""
                INSERT INTO ml_training_runs (
                    run_uuid, run_name, total_events_generated,
                    training_events, testing_events,
                    benign_count, malicious_count,
                    scenario_distribution, feature_count, status
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                run_uuid,
                f"run_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                len(train_events) + len(test_events),
                len(train_events),
                len(test_events),
                sum(1 for e in train_events + test_events if e['is_malicious'] == 0),
                sum(1 for e in train_events + test_events if e['is_malicious'] == 1),
                json.dumps(self.scenario_counters),
                50,
                'data_ready'
            ))
            conn.commit()

            logger.info("\nData saved successfully!")

        except Exception as e:
            logger.error(f"Error saving to database: {e}")
            conn.rollback()
            raise
        finally:
            cursor.close()
            conn.close()

    def _batch_insert(self, cursor, conn, sql: str, events: List[Dict]):
        """Insert events in batches."""
        total = len(events)
        inserted = 0

        for i in range(0, total, BATCH_SIZE):
            batch = events[i:i + BATCH_SIZE]

            values = [
                (
                    e['event_uuid'], e['timestamp'], e['event_type'], e['auth_method'], e['failure_reason'],
                    e['source_ip'], e['source_port'], e['target_server'], e['target_port'], e['target_username'],
                    e['country_code'], e['country_name'], e['city'], e['latitude'], e['longitude'],
                    e['is_private_ip'], e['is_vpn'], e['is_proxy'], e['is_tor'], e['is_datacenter'], e['is_hosting'],
                    e['abuseipdb_score'], e['virustotal_positives'], e['virustotal_total'],
                    e['greynoise_classification'], e['threat_level'],
                    e['scenario_type'], e['is_malicious']
                )
                for e in batch
            ]

            cursor.executemany(sql, values)
            conn.commit()

            inserted += len(batch)
            progress = inserted / total * 100
            logger.info(f"  Progress: {inserted:,}/{total:,} ({progress:.1f}%)")

    def print_summary(self):
        """Print generation summary."""
        logger.info("\n" + "=" * 60)
        logger.info("GENERATION SUMMARY")
        logger.info("=" * 60)

        logger.info("\nScenario Distribution:")
        logger.info("-" * 40)

        total_malicious = 0
        total_benign = 0

        for scenario, count in sorted(self.scenario_counters.items()):
            is_attack = not scenario.startswith('normal_')
            label = "[ATTACK]" if is_attack else "[BENIGN]"
            logger.info(f"  {label:10} {scenario:30} {count:>6,}")
            if is_attack:
                total_malicious += count
            else:
                total_benign += count

        logger.info("-" * 40)
        logger.info(f"  {'Total Malicious':40} {total_malicious:>6,}")
        logger.info(f"  {'Total Benign':40} {total_benign:>6,}")
        logger.info(f"  {'Grand Total':40} {total_malicious + total_benign:>6,}")
        logger.info("=" * 60)

    def run(self):
        """Run the full data generation pipeline."""
        try:
            self.connect_db()

            # Generate events
            events = self.generate_all_events()

            # Split train/test
            train_events, test_events = self.split_train_test(events)

            # Save to database
            self.save_to_database(train_events, test_events)

            # Print summary
            self.print_summary()

            logger.info("\n✅ Data generation complete!")
            logger.info(f"   Training data: {len(train_events):,} events in ml_training_data")
            logger.info(f"   Testing data: {len(test_events):,} events in ml_testing_data")

        except Exception as e:
            logger.error(f"Error during generation: {e}")
            raise
        finally:
            self.close_db()


if __name__ == '__main__':
    generator = RealisticDataGenerator(target_count=TARGET_EVENTS)
    generator.run()
