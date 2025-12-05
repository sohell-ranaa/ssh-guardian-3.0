"""
SSH Guardian v3.0 - Bulk Training Data Generator
Generates 50,000+ diverse auth events for proper ML training
"""

import uuid
import random
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict
import ipaddress

PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.append(str(PROJECT_ROOT / "dbs"))

from connection import get_connection


class BulkDataGenerator:
    """Generate diverse training data for ML models"""

    # Realistic username distributions
    COMMON_ATTACK_USERS = ['root', 'admin', 'administrator', 'test', 'guest', 'user', 'ubuntu', 'oracle', 'postgres', 'mysql', 'ftp', 'www', 'nginx', 'apache', 'tomcat', 'jenkins', 'git', 'backup', 'support', 'info']
    DICTIONARY_USERS = ['john', 'mike', 'david', 'james', 'alex', 'admin1', 'test1', 'user1', 'guest1', 'demo', 'temp', 'scanner', 'scan', 'ftpuser', 'webmaster', 'postmaster', 'sales', 'marketing', 'hr', 'finance']
    LEGITIMATE_USERS = ['deploy', 'ansible', 'terraform', 'ci', 'jenkins_deploy', 'svc_account', 'monitoring', 'nagios', 'zabbix', 'prometheus']

    # Country codes with risk levels
    HIGH_RISK_COUNTRIES = ['CN', 'RU', 'KP', 'IR', 'VN', 'BR', 'IN', 'PK', 'UA', 'RO']
    MEDIUM_RISK_COUNTRIES = ['TR', 'ID', 'TH', 'PH', 'MX', 'AR', 'CO', 'EG', 'NG', 'ZA']
    LOW_RISK_COUNTRIES = ['US', 'GB', 'DE', 'FR', 'CA', 'AU', 'JP', 'NL', 'SE', 'CH', 'SG', 'NZ']

    # Servers to target
    SERVERS = ['prod-web-01', 'prod-web-02', 'prod-db-01', 'staging-app-01', 'dev-server-01', 'bastion-01', 'jump-host', 'api-gateway', 'mail-server', 'backup-server']

    def __init__(self):
        self.conn = None

    def generate_dataset(self, target_count: int = 50000, days_back: int = 90) -> Dict:
        """
        Generate a diverse dataset of auth events.

        Args:
            target_count: Number of events to generate
            days_back: Spread events over this many days

        Returns:
            Summary of generated data
        """
        print(f"Generating {target_count:,} events over {days_back} days...")

        self.conn = get_connection()
        cursor = self.conn.cursor()

        # Distribution of event types (realistic attack patterns)
        distributions = {
            'brute_force_attacks': int(target_count * 0.25),      # 25% brute force
            'distributed_attacks': int(target_count * 0.15),      # 15% distributed
            'credential_stuffing': int(target_count * 0.10),      # 10% credential stuffing
            'reconnaissance': int(target_count * 0.08),           # 8% recon
            'slow_attacks': int(target_count * 0.05),             # 5% slow/stealthy
            'legitimate_failed': int(target_count * 0.12),        # 12% legit failures (typos)
            'legitimate_success': int(target_count * 0.20),       # 20% legit success
            'suspicious_success': int(target_count * 0.05),       # 5% suspicious success (compromised)
        }

        start_time = datetime.now() - timedelta(days=days_back)
        events_generated = 0
        batch_size = 1000
        batch = []

        try:
            # Generate each category
            for category, count in distributions.items():
                print(f"  Generating {count:,} {category} events...")

                for i in range(count):
                    event = self._generate_event(category, start_time, days_back)
                    batch.append(event)

                    if len(batch) >= batch_size:
                        self._insert_batch(cursor, batch)
                        self.conn.commit()  # Commit after each batch to preserve progress
                        events_generated += len(batch)
                        batch = []
                        print(f"    Inserted {events_generated:,} events...")

            # Insert remaining
            if batch:
                self._insert_batch(cursor, batch)
                events_generated += len(batch)

            self.conn.commit()
            print(f"Successfully generated {events_generated:,} events")

            return {
                'success': True,
                'events_generated': events_generated,
                'distributions': distributions
            }

        except Exception as e:
            self.conn.rollback()
            print(f"Error: {e}")
            return {'success': False, 'error': str(e)}
        finally:
            cursor.close()
            self.conn.close()

    def _generate_event(self, category: str, start_time: datetime, days_back: int) -> Dict:
        """Generate a single event based on category"""

        # Random timestamp within range
        random_seconds = random.randint(0, days_back * 24 * 3600)
        timestamp = start_time + timedelta(seconds=random_seconds)

        # Base event
        event = {
            'event_uuid': str(uuid.uuid4()),
            'timestamp': timestamp,
            'target_server': random.choice(self.SERVERS),
            'auth_method': random.choice(['password', 'password', 'password', 'publickey', 'keyboard-interactive']),
            'source_type': 'synthetic',
            'processing_status': 'completed'
        }

        if category == 'brute_force_attacks':
            event.update(self._generate_brute_force())
        elif category == 'distributed_attacks':
            event.update(self._generate_distributed())
        elif category == 'credential_stuffing':
            event.update(self._generate_credential_stuffing())
        elif category == 'reconnaissance':
            event.update(self._generate_reconnaissance())
        elif category == 'slow_attacks':
            event.update(self._generate_slow_attack())
        elif category == 'legitimate_failed':
            event.update(self._generate_legitimate_failed())
        elif category == 'legitimate_success':
            event.update(self._generate_legitimate_success())
        elif category == 'suspicious_success':
            event.update(self._generate_suspicious_success())

        return event

    def _generate_brute_force(self) -> Dict:
        """Single IP hammering with common usernames"""
        return {
            'event_type': 'failed',
            'source_ip': self._random_ip(risk='high'),
            'target_username': random.choice(self.COMMON_ATTACK_USERS),
            'failure_reason': random.choice(['invalid_password', 'invalid_password', 'invalid_user']),
            'country_code': random.choice(self.HIGH_RISK_COUNTRIES),
            'is_proxy': random.random() < 0.3,
            'is_vpn': random.random() < 0.2,
            'is_tor': random.random() < 0.15,
            'is_datacenter': random.random() < 0.6,
            'abuseipdb_score': random.randint(40, 100),
            'threat_level': random.choice(['high', 'critical', 'high', 'medium'])
        }

    def _generate_distributed(self) -> Dict:
        """Multiple IPs, same target"""
        return {
            'event_type': 'failed',
            'source_ip': self._random_ip(risk='mixed'),
            'target_username': random.choice(['root', 'admin', 'administrator']),
            'failure_reason': 'invalid_password',
            'country_code': random.choice(self.HIGH_RISK_COUNTRIES + self.MEDIUM_RISK_COUNTRIES),
            'is_proxy': random.random() < 0.4,
            'is_vpn': random.random() < 0.3,
            'is_tor': random.random() < 0.1,
            'is_datacenter': random.random() < 0.7,
            'abuseipdb_score': random.randint(20, 80),
            'threat_level': random.choice(['medium', 'high', 'medium'])
        }

    def _generate_credential_stuffing(self) -> Dict:
        """Trying leaked credential patterns"""
        return {
            'event_type': 'failed',
            'source_ip': self._random_ip(risk='medium'),
            'target_username': random.choice(self.DICTIONARY_USERS + self.COMMON_ATTACK_USERS[:5]),
            'failure_reason': 'invalid_password',
            'country_code': random.choice(self.HIGH_RISK_COUNTRIES + self.MEDIUM_RISK_COUNTRIES),
            'is_proxy': random.random() < 0.5,
            'is_vpn': random.random() < 0.4,
            'is_tor': random.random() < 0.05,
            'is_datacenter': random.random() < 0.5,
            'abuseipdb_score': random.randint(10, 60),
            'threat_level': random.choice(['low', 'medium', 'medium'])
        }

    def _generate_reconnaissance(self) -> Dict:
        """Scanning for valid usernames"""
        return {
            'event_type': 'failed',
            'source_ip': self._random_ip(risk='medium'),
            'target_username': random.choice(self.DICTIONARY_USERS + ['scan' + str(i) for i in range(1, 20)]),
            'failure_reason': 'invalid_user',
            'country_code': random.choice(self.HIGH_RISK_COUNTRIES + self.MEDIUM_RISK_COUNTRIES),
            'is_proxy': random.random() < 0.3,
            'is_vpn': random.random() < 0.2,
            'is_tor': random.random() < 0.2,
            'is_datacenter': random.random() < 0.8,
            'abuseipdb_score': random.randint(30, 90),
            'threat_level': random.choice(['medium', 'high'])
        }

    def _generate_slow_attack(self) -> Dict:
        """Slow, stealthy attack evading rate limits"""
        return {
            'event_type': 'failed',
            'source_ip': self._random_ip(risk='low'),  # Clean-looking IPs
            'target_username': random.choice(self.COMMON_ATTACK_USERS[:5]),
            'failure_reason': random.choice(['invalid_password', 'invalid_user']),
            'country_code': random.choice(self.LOW_RISK_COUNTRIES),  # Blend in
            'is_proxy': random.random() < 0.1,
            'is_vpn': random.random() < 0.3,
            'is_tor': False,
            'is_datacenter': random.random() < 0.2,
            'abuseipdb_score': random.randint(0, 20),  # Low reputation score
            'threat_level': random.choice(['low', 'unknown', 'low'])
        }

    def _generate_legitimate_failed(self) -> Dict:
        """Real users making mistakes (typos, expired passwords)"""
        # Valid enum values: invalid_password, invalid_user, connection_refused, key_rejected, timeout, max_attempts, other
        return {
            'event_type': 'failed',
            'source_ip': self._random_ip(risk='clean'),
            'target_username': random.choice(self.LEGITIMATE_USERS),
            'failure_reason': random.choice(['invalid_password', 'invalid_password', 'key_rejected', 'timeout']),
            'country_code': random.choice(self.LOW_RISK_COUNTRIES),
            'is_proxy': False,
            'is_vpn': random.random() < 0.1,  # Some legit VPN use
            'is_tor': False,
            'is_datacenter': random.random() < 0.3,  # Cloud offices
            'abuseipdb_score': random.randint(0, 5),
            'threat_level': random.choice(['unknown', 'low', 'unknown'])
        }

    def _generate_legitimate_success(self) -> Dict:
        """Normal successful logins"""
        return {
            'event_type': 'successful',
            'source_ip': self._random_ip(risk='clean'),
            'target_username': random.choice(self.LEGITIMATE_USERS),
            'failure_reason': None,
            'country_code': random.choice(self.LOW_RISK_COUNTRIES),
            'is_proxy': False,
            'is_vpn': random.random() < 0.15,
            'is_tor': False,
            'is_datacenter': random.random() < 0.4,
            'abuseipdb_score': random.randint(0, 3),
            'threat_level': 'unknown'
        }

    def _generate_suspicious_success(self) -> Dict:
        """Successful login but suspicious (compromised account)"""
        return {
            'event_type': 'successful',
            'source_ip': self._random_ip(risk='high'),
            'target_username': random.choice(self.LEGITIMATE_USERS + self.COMMON_ATTACK_USERS[:3]),
            'failure_reason': None,
            'country_code': random.choice(self.HIGH_RISK_COUNTRIES),
            'is_proxy': random.random() < 0.4,
            'is_vpn': random.random() < 0.3,
            'is_tor': random.random() < 0.1,
            'is_datacenter': random.random() < 0.5,
            'abuseipdb_score': random.randint(20, 70),
            'threat_level': random.choice(['medium', 'high', 'low'])
        }

    def _random_ip(self, risk: str = 'mixed') -> str:
        """Generate random IP based on risk profile"""
        if risk == 'high':
            # More likely to be in suspicious ranges
            prefixes = ['45.', '185.', '91.', '193.', '195.', '77.', '89.', '176.', '178.', '188.']
        elif risk == 'medium':
            prefixes = ['103.', '104.', '146.', '151.', '162.', '167.', '172.', '198.', '199.', '200.']
        elif risk == 'low':
            prefixes = ['8.', '13.', '35.', '52.', '54.', '99.', '100.', '142.', '157.', '216.']
        elif risk == 'clean':
            prefixes = ['10.', '192.168.', '172.16.', '34.', '35.', '52.']  # AWS/GCP ranges
        else:
            prefixes = ['']

        prefix = random.choice(prefixes)
        if prefix in ['10.', '192.168.', '172.16.']:
            # Private ranges
            if prefix == '10.':
                return f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
            elif prefix == '192.168.':
                return f"192.168.{random.randint(0,255)}.{random.randint(1,254)}"
            else:
                return f"172.{random.randint(16,31)}.{random.randint(0,255)}.{random.randint(1,254)}"
        else:
            return f"{prefix}{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

    def _insert_batch(self, cursor, batch: List[Dict]):
        """Insert batch of events with proper enrichment linking"""
        for event in batch:
            # Convert IP to binary format
            ip_binary = self._ip_to_binary(event['source_ip'])

            # First, insert geo data and get the ID
            geo_id = self._insert_geo_data(cursor, event)

            # Insert threat intelligence data
            self._insert_threat_intel(cursor, event)

            cursor.execute("""
                INSERT INTO auth_events
                (event_uuid, timestamp, event_type, source_ip, source_ip_text, target_username,
                 target_server, auth_method, failure_reason, source_type, processing_status,
                 geo_id, ml_risk_score, ml_threat_type)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                event['event_uuid'],
                event['timestamp'],
                event['event_type'],
                ip_binary,
                event['source_ip'],
                event['target_username'],
                event['target_server'],
                event['auth_method'],
                event.get('failure_reason'),
                event['source_type'],
                event['processing_status'],
                geo_id,  # Link to geo data
                None,  # ml_risk_score - will be calculated during training
                None   # ml_threat_type
            ))

    def _ip_to_binary(self, ip_str: str) -> bytes:
        """Convert IP address string to binary format"""
        try:
            # Handle private IPs that might have been generated
            ip = ipaddress.ip_address(ip_str)
            return ip.packed
        except ValueError:
            # Fallback for any invalid IPs
            return ipaddress.ip_address('0.0.0.0').packed

    def _insert_geo_data(self, cursor, event: Dict) -> int:
        """Insert associated geo data and return the geo_id"""
        ip_binary = self._ip_to_binary(event['source_ip'])

        # Check if geo record already exists
        cursor.execute("""
            SELECT id FROM ip_geolocation WHERE ip_address_text = %s
        """, (event['source_ip'],))
        existing = cursor.fetchone()

        if existing:
            return existing[0]

        try:
            cursor.execute("""
                INSERT INTO ip_geolocation
                (ip_address, ip_address_text, ip_version, country_code, is_proxy, is_vpn, is_tor, is_datacenter,
                 latitude, longitude)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                ip_binary,
                event['source_ip'],
                4,  # IPv4
                event.get('country_code', 'XX'),
                1 if event.get('is_proxy') else 0,
                1 if event.get('is_vpn') else 0,
                1 if event.get('is_tor') else 0,
                1 if event.get('is_datacenter') else 0,
                round(random.uniform(-90, 90), 8),
                round(random.uniform(-180, 180), 8)
            ))
            return cursor.lastrowid
        except Exception:
            # If insert fails, try to get existing
            cursor.execute("""
                SELECT id FROM ip_geolocation WHERE ip_address_text = %s
            """, (event['source_ip'],))
            result = cursor.fetchone()
            return result[0] if result else None

    def _insert_threat_intel(self, cursor, event: Dict):
        """Insert threat intelligence data for the IP"""
        # Check if threat intel already exists
        cursor.execute("""
            SELECT id FROM ip_threat_intelligence WHERE ip_address_text = %s
        """, (event['source_ip'],))
        if cursor.fetchone():
            return  # Already exists

        try:
            # Map threat levels to valid ENUM values
            threat_level = event.get('threat_level', 'unknown')
            # Valid ENUM: 'clean','low','medium','high','critical'
            threat_level_map = {
                'unknown': 'low',
                'clean': 'clean',
                'low': 'low',
                'medium': 'medium',
                'high': 'high',
                'critical': 'critical'
            }
            threat_level = threat_level_map.get(threat_level, 'low')

            abuseipdb_score = event.get('abuseipdb_score', 0)

            cursor.execute("""
                INSERT INTO ip_threat_intelligence
                (ip_address_text, abuseipdb_score, overall_threat_level, created_at, updated_at)
                VALUES (%s, %s, %s, NOW(), NOW())
            """, (
                event['source_ip'],
                abuseipdb_score,
                threat_level
            ))
        except Exception as e:
            pass  # Ignore duplicate key errors


def generate_training_data(count: int = 50000, days: int = 90):
    """Main entry point for bulk data generation"""
    generator = BulkDataGenerator()
    return generator.generate_dataset(target_count=count, days_back=days)


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Generate bulk training data')
    parser.add_argument('--count', type=int, default=50000, help='Number of events to generate')
    parser.add_argument('--days', type=int, default=90, help='Days to spread events over')
    args = parser.parse_args()

    result = generate_training_data(args.count, args.days)
    print(f"\nResult: {result}")
