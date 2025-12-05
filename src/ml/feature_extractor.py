"""
SSH Guardian v3.0 - Feature Extractor
Extracts 40+ features from SSH authentication events for ML prediction
"""

import numpy as np
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from collections import defaultdict
import math
import sys
from pathlib import Path

# Add project paths
PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.append(str(PROJECT_ROOT / "dbs"))

from connection import get_connection


class FeatureExtractor:
    """
    Extracts comprehensive features from SSH events for ML prediction.
    Designed for high-accuracy threat detection with 40+ features.
    """

    # High-risk indicators
    MALICIOUS_USERNAMES = {
        'root', 'admin', 'test', 'guest', 'oracle', 'postgres', 'mysql',
        'admin123', 'administrator', 'user', 'ftpuser', 'ftp', 'www',
        'apache', 'nginx', 'ubuntu', 'pi', 'git', 'jenkins', 'hadoop',
        'tomcat', 'nagios', 'backup', 'support', 'info', 'test1', 'test2'
    }

    SYSTEM_ACCOUNTS = {
        'root', 'daemon', 'bin', 'sys', 'sync', 'games', 'man', 'lp',
        'mail', 'news', 'uucp', 'proxy', 'www-data', 'backup', 'list',
        'irc', 'gnats', 'nobody', 'systemd-network', 'systemd-resolve'
    }

    HIGH_RISK_COUNTRIES = {
        'CN', 'RU', 'KP', 'IR', 'VN', 'UA', 'PK', 'IN', 'BR', 'ID'
    }

    def __init__(self):
        """Initialize the feature extractor"""
        # IP history tracking (in-memory for session)
        self.ip_history = defaultdict(lambda: {
            'failed_attempts': [],
            'successful_logins': [],
            'unique_usernames': set(),
            'unique_servers': set(),
            'first_seen': None,
            'last_seen': None,
            'last_location': None
        })

    def extract(self, event: Dict) -> np.ndarray:
        """
        Extract all features from an event.

        Args:
            event: Event dict with keys like timestamp, source_ip_text, event_type, etc.

        Returns:
            numpy array of shape (42,) with extracted features
        """
        features = []

        # Parse timestamp
        timestamp = self._parse_timestamp(event.get('timestamp'))

        # === TEMPORAL FEATURES (6) ===
        features.extend(self._extract_temporal_features(timestamp))

        # === EVENT TYPE FEATURES (5) ===
        features.extend(self._extract_event_features(event))

        # === GEOGRAPHIC FEATURES (6) ===
        features.extend(self._extract_geo_features(event))

        # === USERNAME FEATURES (6) ===
        features.extend(self._extract_username_features(event))

        # === IP BEHAVIOR FEATURES (9) ===
        features.extend(self._extract_ip_behavior_features(event, timestamp))

        # === NETWORK FLAGS FEATURES (5) ===
        features.extend(self._extract_network_features(event))

        # === THREAT REPUTATION FEATURES (3) ===
        features.extend(self._extract_reputation_features(event))

        # === PATTERN FEATURES (2) ===
        features.extend(self._extract_pattern_features(event, timestamp))

        # Update history for future predictions
        self._update_history(event, timestamp)

        return np.array(features, dtype=np.float32)

    def _parse_timestamp(self, ts) -> datetime:
        """Parse timestamp from various formats"""
        if isinstance(ts, datetime):
            return ts
        if isinstance(ts, str):
            try:
                return datetime.fromisoformat(ts.replace('Z', '+00:00'))
            except:
                pass
        return datetime.now()

    def _extract_temporal_features(self, timestamp: datetime) -> List[float]:
        """
        Extract temporal features (6 features)
        - hour, minute, day_of_week, is_weekend, is_business_hours, is_night
        """
        hour = timestamp.hour
        minute = timestamp.minute
        day_of_week = timestamp.weekday()
        is_weekend = 1 if day_of_week >= 5 else 0
        is_business_hours = 1 if 9 <= hour <= 17 and not is_weekend else 0
        is_night = 1 if hour < 6 or hour > 22 else 0

        return [
            hour / 24.0,  # Normalized hour
            minute / 60.0,  # Normalized minute
            day_of_week / 6.0,  # Normalized day
            is_weekend,
            is_business_hours,
            is_night
        ]

    def _extract_event_features(self, event: Dict) -> List[float]:
        """
        Extract event type features (5 features)
        - is_failed, is_success, is_invalid_user, is_invalid_password, failure_reason_encoded
        """
        event_type = str(event.get('event_type', '')).lower()
        failure_reason = str(event.get('failure_reason', '')).lower()

        is_failed = 1 if 'failed' in event_type else 0
        is_success = 1 if 'success' in event_type or 'accepted' in event_type else 0
        is_invalid_user = 1 if 'invalid_user' in failure_reason or 'invalid user' in failure_reason else 0
        is_invalid_password = 1 if 'invalid_password' in failure_reason or 'password' in failure_reason else 0

        # Encode failure reason
        reason_map = {
            'invalid_user': 0.2,
            'invalid_password': 0.4,
            'connection_refused': 0.6,
            'key_rejected': 0.3,
            'timeout': 0.1,
            'max_attempts': 0.8
        }
        failure_encoded = reason_map.get(event.get('failure_reason', ''), 0.0)

        return [is_failed, is_success, is_invalid_user, is_invalid_password, failure_encoded]

    def _extract_geo_features(self, event: Dict) -> List[float]:
        """
        Extract geographic features (6 features)
        - latitude, longitude, is_high_risk_country, is_unknown_country, distance_from_baseline, is_new_location
        """
        geo = event.get('geo', {}) or {}

        latitude = float(geo.get('latitude', 0) or 0) / 90.0  # Normalized
        longitude = float(geo.get('longitude', 0) or 0) / 180.0  # Normalized

        country_code = geo.get('country_code', '') or ''
        is_high_risk = 1 if country_code in self.HIGH_RISK_COUNTRIES else 0
        is_unknown = 1 if not country_code or country_code == 'Unknown' else 0

        # Distance from previous location (impossible travel detection)
        source_ip = event.get('source_ip_text', '')
        last_loc = self.ip_history[source_ip].get('last_location')

        distance = 0.0
        is_new_location = 0
        if last_loc and geo.get('latitude') and geo.get('longitude'):
            distance = self._haversine_distance(
                last_loc[0], last_loc[1],
                float(geo.get('latitude')), float(geo.get('longitude'))
            ) / 20000.0  # Normalize by max Earth distance
            is_new_location = 1 if distance > 0.1 else 0  # > 2000km

        return [latitude, longitude, is_high_risk, is_unknown, distance, is_new_location]

    def _extract_username_features(self, event: Dict) -> List[float]:
        """
        Extract username features (6 features)
        - is_root, is_admin, is_system_account, username_entropy, username_length, has_numbers
        """
        username = str(event.get('target_username', '') or '').lower()

        is_root = 1 if username == 'root' else 0
        is_admin = 1 if username in self.MALICIOUS_USERNAMES else 0
        is_system = 1 if username in self.SYSTEM_ACCOUNTS else 0
        entropy = self._calculate_entropy(username) / 4.0  # Normalize
        length = min(len(username), 32) / 32.0  # Normalized, cap at 32
        has_numbers = 1 if any(c.isdigit() for c in username) else 0

        return [is_root, is_admin, is_system, entropy, length, has_numbers]

    def _extract_ip_behavior_features(self, event: Dict, timestamp: datetime) -> List[float]:
        """
        Extract IP behavior features (9 features)
        - fails_last_hour, fails_last_10min, unique_users_tried, unique_servers_hit,
        - success_rate, hours_since_first_seen, avg_interval, attempts_per_minute, is_first_time
        """
        source_ip = event.get('source_ip_text', '')
        history = self.ip_history[source_ip]

        # Count recent failures
        recent_fails_hour = len([t for t in history['failed_attempts']
                                if (timestamp - t).total_seconds() < 3600])
        recent_fails_10min = len([t for t in history['failed_attempts']
                                 if (timestamp - t).total_seconds() < 600])

        # Normalize (cap at reasonable max)
        fails_hour = min(recent_fails_hour, 100) / 100.0
        fails_10min = min(recent_fails_10min, 50) / 50.0

        # Unique targets
        unique_users = min(len(history['unique_usernames']), 50) / 50.0
        unique_servers = min(len(history['unique_servers']), 20) / 20.0

        # Success rate
        total = len(history['failed_attempts']) + len(history['successful_logins'])
        success_rate = len(history['successful_logins']) / total if total > 0 else 0.5

        # Time since first seen
        if history['first_seen']:
            hours_since_first = (timestamp - history['first_seen']).total_seconds() / 3600.0
            hours_since_first = min(hours_since_first, 168) / 168.0  # Cap at 1 week
        else:
            hours_since_first = 0.0

        # Average interval between attempts
        avg_interval = 0.0
        if len(history['failed_attempts']) > 1:
            times = sorted(history['failed_attempts'])
            intervals = [(times[i] - times[i-1]).total_seconds() for i in range(1, len(times))]
            avg_interval = min(np.mean(intervals), 3600) / 3600.0  # Cap at 1 hour

        # Attempts per minute
        if recent_fails_10min > 0:
            attempts_per_min = recent_fails_10min / 10.0
        else:
            attempts_per_min = 0.0

        # Is this the first time seeing this IP?
        is_first_time = 1 if not history['first_seen'] else 0

        return [
            fails_hour, fails_10min, unique_users, unique_servers,
            success_rate, hours_since_first, avg_interval, attempts_per_min, is_first_time
        ]

    def _extract_network_features(self, event: Dict) -> List[float]:
        """
        Extract network flags features (5 features)
        - is_proxy, is_vpn, is_tor, is_datacenter, is_hosting
        """
        geo = event.get('geo', {}) or {}

        return [
            1 if geo.get('is_proxy') else 0,
            1 if geo.get('is_vpn') else 0,
            1 if geo.get('is_tor') else 0,
            1 if geo.get('is_datacenter') else 0,
            1 if geo.get('is_hosting') else 0
        ]

    def _extract_reputation_features(self, event: Dict) -> List[float]:
        """
        Extract threat reputation features (3 features)
        - abuseipdb_score, virustotal_ratio, threat_level_encoded
        """
        threat = event.get('threat', {}) or {}

        # AbuseIPDB score (0-100)
        abuse_score = float(threat.get('abuseipdb_score', 0) or 0) / 100.0

        # VirusTotal ratio
        vt_pos = int(threat.get('virustotal_positives', 0) or 0)
        vt_total = int(threat.get('virustotal_total', 0) or 0)
        vt_ratio = vt_pos / vt_total if vt_total > 0 else 0.0

        # Threat level encoding
        threat_level = str(threat.get('overall_threat_level', '') or '').lower()
        level_map = {
            'clean': 0.0,
            'low': 0.25,
            'medium': 0.5,
            'high': 0.75,
            'critical': 1.0
        }
        threat_encoded = level_map.get(threat_level, 0.5)

        return [abuse_score, vt_ratio, threat_encoded]

    def _extract_pattern_features(self, event: Dict, timestamp: datetime) -> List[float]:
        """
        Extract pattern features (2 features)
        - is_sequential_username, is_distributed_attack
        """
        source_ip = event.get('source_ip_text', '')
        username = str(event.get('target_username', '') or '')
        history = self.ip_history[source_ip]

        # Sequential username pattern (user1, user2, user3)
        is_sequential = 0
        if username and len(username) > 1:
            if username[-1].isdigit() and username[:-1].isalpha():
                is_sequential = 1

        # Distributed attack pattern (many servers, many IPs)
        recent_fails = len([t for t in history['failed_attempts']
                          if (timestamp - t).total_seconds() < 3600])
        unique_servers = len(history['unique_servers'])
        is_distributed = 1 if unique_servers > 3 and recent_fails > 5 else 0

        return [is_sequential, is_distributed]

    def _update_history(self, event: Dict, timestamp: datetime):
        """Update IP history for future predictions"""
        source_ip = event.get('source_ip_text', '')
        if not source_ip:
            return

        history = self.ip_history[source_ip]

        # Update timestamps
        if not history['first_seen']:
            history['first_seen'] = timestamp
        history['last_seen'] = timestamp

        # Track attempts
        event_type = str(event.get('event_type', '')).lower()
        if 'failed' in event_type:
            history['failed_attempts'].append(timestamp)
            # Keep only last 24 hours
            cutoff = timestamp - timedelta(hours=24)
            history['failed_attempts'] = [t for t in history['failed_attempts'] if t > cutoff]
        elif 'success' in event_type or 'accepted' in event_type:
            history['successful_logins'].append(timestamp)
            history['successful_logins'] = [t for t in history['successful_logins']
                                           if t > timestamp - timedelta(hours=24)]

        # Track unique targets
        username = event.get('target_username')
        if username:
            history['unique_usernames'].add(username)

        server = event.get('target_server')
        if server:
            history['unique_servers'].add(server)

        # Track location
        geo = event.get('geo', {}) or {}
        if geo.get('latitude') and geo.get('longitude'):
            history['last_location'] = (float(geo['latitude']), float(geo['longitude']))

    def _haversine_distance(self, lat1: float, lon1: float, lat2: float, lon2: float) -> float:
        """Calculate distance between two points in km"""
        lat1, lon1, lat2, lon2 = map(math.radians, [lat1, lon1, lat2, lon2])
        dlat = lat2 - lat1
        dlon = lon2 - lon1

        a = math.sin(dlat/2)**2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon/2)**2
        c = 2 * math.asin(math.sqrt(a))
        return 6371 * c  # Earth radius in km

    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of a string"""
        if not text:
            return 0.0

        from collections import Counter
        counts = Counter(text)
        length = len(text)

        entropy = -sum((count/length) * math.log2(count/length)
                      for count in counts.values())
        return entropy

    def get_feature_names(self) -> List[str]:
        """Return list of all feature names (42 features)"""
        return [
            # Temporal (6)
            'hour_normalized', 'minute_normalized', 'day_of_week_normalized',
            'is_weekend', 'is_business_hours', 'is_night',

            # Event type (5)
            'is_failed', 'is_success', 'is_invalid_user', 'is_invalid_password',
            'failure_reason_encoded',

            # Geographic (6)
            'latitude_normalized', 'longitude_normalized', 'is_high_risk_country',
            'is_unknown_country', 'distance_from_previous', 'is_new_location',

            # Username (6)
            'is_root', 'is_admin_username', 'is_system_account', 'username_entropy',
            'username_length', 'username_has_numbers',

            # IP behavior (9)
            'fails_last_hour', 'fails_last_10min', 'unique_users_tried',
            'unique_servers_hit', 'success_rate', 'hours_since_first_seen',
            'avg_interval_between_attempts', 'attempts_per_minute', 'is_first_time_ip',

            # Network flags (5)
            'is_proxy', 'is_vpn', 'is_tor', 'is_datacenter', 'is_hosting',

            # Reputation (3)
            'abuseipdb_score', 'virustotal_ratio', 'threat_level_encoded',

            # Patterns (2)
            'is_sequential_username', 'is_distributed_attack'
        ]

    def reset_history(self):
        """Reset IP history (useful for batch processing)"""
        self.ip_history.clear()

    def get_statistics(self) -> Dict:
        """Get statistics about tracked IPs"""
        return {
            'total_ips_tracked': len(self.ip_history),
            'ips_with_failures': sum(1 for h in self.ip_history.values() if h['failed_attempts']),
            'ips_with_successes': sum(1 for h in self.ip_history.values() if h['successful_logins'])
        }
