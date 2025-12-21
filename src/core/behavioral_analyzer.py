"""
SSH Guardian v3.0 - Behavioral Analyzer
Detects anomalies in user login patterns:
- Impossible travel (different geo in short time)
- Unusual login times
- New IP/location for user
- Authentication pattern changes
- Credential stuffing patterns
"""

import sys
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
import json

PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.append(str(PROJECT_ROOT / "dbs"))
sys.path.append(str(PROJECT_ROOT / "src" / "core"))

from connection import get_connection
from geoip import haversine_distance  # Shared utility


class BehavioralAnalyzer:
    """Analyzes user and IP behavioral patterns to detect anomalies"""

    # Speed thresholds for impossible travel (km/h)
    MAX_HUMAN_SPEED_KMH = 1000  # Max reasonable travel speed (airplane)
    SUSPICIOUS_SPEED_KMH = 500  # Speed that raises suspicion

    # Time windows
    RECENT_HISTORY_HOURS = 24
    BASELINE_HISTORY_DAYS = 30

    # Risk score weights
    WEIGHTS = {
        'impossible_travel': 40,
        'new_location': 20,
        'unusual_time': 15,
        'new_ip_for_user': 15,
        'rapid_attempts': 20,
        'credential_stuffing': 25,
        'brute_force': 30,
        'account_enumeration': 20,
        'success_after_failures': 15,
        'geo_mismatch': 10
    }

    def __init__(self):
        self.analysis_results = {}
        self.risk_factors = []
        self.risk_score = 0

    def analyze(self, ip_address: str, username: str, event_type: str,
                current_geo: Dict = None, timestamp: datetime = None) -> Dict:
        """
        Perform comprehensive behavioral analysis

        Returns dict with:
        - risk_score: 0-100 composite behavioral risk
        - risk_factors: list of detected anomalies with explanations
        - recommendations: suggested actions
        - confidence: how confident we are in the analysis
        """
        self.risk_factors = []
        self.risk_score = 0
        timestamp = timestamp or datetime.now()

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            # Get user's historical login patterns
            user_history = self._get_user_history(cursor, username)

            # Get IP's historical activity
            ip_history = self._get_ip_history(cursor, ip_address)

            # Get recent events for this IP-user combination
            ip_user_history = self._get_ip_user_history(cursor, ip_address, username)

            # 1. Check for impossible travel
            if current_geo and user_history:
                travel_result = self._check_impossible_travel(
                    cursor, username, current_geo, timestamp
                )
                if travel_result['detected']:
                    self.risk_factors.append(travel_result)
                    self.risk_score += travel_result['score']

            # 2. Check for new location for user
            if current_geo and user_history:
                location_result = self._check_new_location(
                    user_history, current_geo
                )
                if location_result['detected']:
                    self.risk_factors.append(location_result)
                    self.risk_score += location_result['score']

            # 3. Check for unusual login time
            time_result = self._check_unusual_time(user_history, timestamp)
            if time_result['detected']:
                self.risk_factors.append(time_result)
                self.risk_score += time_result['score']

            # 4. Check if this is a new IP for the user
            if user_history:
                new_ip_result = self._check_new_ip_for_user(
                    user_history, ip_address
                )
                if new_ip_result['detected']:
                    self.risk_factors.append(new_ip_result)
                    self.risk_score += new_ip_result['score']

            # 5. Check for rapid login attempts (brute force indicator)
            rapid_result = self._check_rapid_attempts(cursor, ip_address, username)
            if rapid_result['detected']:
                self.risk_factors.append(rapid_result)
                self.risk_score += rapid_result['score']

            # 6. Check for credential stuffing pattern
            stuffing_result = self._check_credential_stuffing(cursor, ip_address)
            if stuffing_result['detected']:
                self.risk_factors.append(stuffing_result)
                self.risk_score += stuffing_result['score']

            # 7. Check for success after multiple failures
            if event_type == 'successful':
                success_result = self._check_success_after_failures(
                    cursor, ip_address, username
                )
                if success_result['detected']:
                    self.risk_factors.append(success_result)
                    self.risk_score += success_result['score']

            # 8. Check geographic mismatch patterns
            if current_geo:
                geo_result = self._check_geo_mismatch(
                    cursor, username, current_geo
                )
                if geo_result['detected']:
                    self.risk_factors.append(geo_result)
                    self.risk_score += geo_result['score']

            # Cap score at 100
            self.risk_score = min(100, self.risk_score)

            # Calculate confidence based on available data
            confidence = self._calculate_confidence(user_history, ip_history)

            # Generate recommendations
            recommendations = self._generate_recommendations()

            return {
                'risk_score': self.risk_score,
                'risk_factors': self.risk_factors,
                'recommendations': recommendations,
                'confidence': confidence,
                'analysis_timestamp': timestamp.isoformat(),
                'user_baseline': {
                    'total_logins': user_history.get('total_logins', 0) if user_history else 0,
                    'known_locations': user_history.get('known_locations', []) if user_history else [],
                    'known_ips': user_history.get('known_ips', []) if user_history else [],
                    'typical_hours': user_history.get('typical_hours', []) if user_history else []
                }
            }

        finally:
            cursor.close()
            conn.close()

    def _get_user_history(self, cursor, username: str) -> Optional[Dict]:
        """Get user's historical login patterns"""
        # Get basic stats
        cursor.execute("""
            SELECT
                COUNT(*) as total_logins,
                SUM(event_type = 'successful') as successful_logins,
                SUM(event_type = 'failed') as failed_logins,
                MIN(timestamp) as first_seen,
                MAX(timestamp) as last_seen
            FROM auth_events
            WHERE target_username = %s
            AND timestamp >= DATE_SUB(NOW(), INTERVAL %s DAY)
        """, (username, self.BASELINE_HISTORY_DAYS))
        stats = cursor.fetchone()

        if not stats or stats['total_logins'] == 0:
            return None

        # Get known locations
        cursor.execute("""
            SELECT DISTINCT
                g.country_code, g.country_name, g.city,
                g.latitude, g.longitude
            FROM auth_events ae
            JOIN ip_geolocation g ON ae.geo_id = g.id
            WHERE ae.target_username = %s
            AND ae.event_type = 'successful'
            AND ae.timestamp >= DATE_SUB(NOW(), INTERVAL %s DAY)
        """, (username, self.BASELINE_HISTORY_DAYS))
        known_locations = cursor.fetchall()

        # Get known IPs
        cursor.execute("""
            SELECT DISTINCT source_ip_text
            FROM auth_events
            WHERE target_username = %s
            AND event_type = 'successful'
            AND timestamp >= DATE_SUB(NOW(), INTERVAL %s DAY)
        """, (username, self.BASELINE_HISTORY_DAYS))
        known_ips = [row['source_ip_text'] for row in cursor.fetchall()]

        # Get typical login hours
        cursor.execute("""
            SELECT HOUR(timestamp) as login_hour, COUNT(*) as count
            FROM auth_events
            WHERE target_username = %s
            AND event_type = 'successful'
            AND timestamp >= DATE_SUB(NOW(), INTERVAL %s DAY)
            GROUP BY HOUR(timestamp)
            ORDER BY count DESC
        """, (username, self.BASELINE_HISTORY_DAYS))
        hour_distribution = cursor.fetchall()
        typical_hours = [row['login_hour'] for row in hour_distribution[:8]]  # Top 8 hours

        return {
            'total_logins': stats['total_logins'],
            'successful_logins': stats['successful_logins'] or 0,
            'failed_logins': stats['failed_logins'] or 0,
            'first_seen': stats['first_seen'],
            'last_seen': stats['last_seen'],
            'known_locations': known_locations,
            'known_ips': known_ips,
            'typical_hours': typical_hours
        }

    def _get_ip_history(self, cursor, ip_address: str) -> Optional[Dict]:
        """Get IP's historical activity"""
        cursor.execute("""
            SELECT
                COUNT(*) as total_events,
                SUM(event_type = 'successful') as successful_logins,
                SUM(event_type = 'failed') as failed_logins,
                COUNT(DISTINCT target_username) as unique_users,
                MIN(timestamp) as first_seen,
                MAX(timestamp) as last_seen
            FROM auth_events
            WHERE source_ip_text = %s
            AND timestamp >= DATE_SUB(NOW(), INTERVAL %s DAY)
        """, (ip_address, self.BASELINE_HISTORY_DAYS))
        return cursor.fetchone()

    def _get_ip_user_history(self, cursor, ip_address: str, username: str) -> List[Dict]:
        """Get recent events for specific IP-user combination"""
        cursor.execute("""
            SELECT
                ae.event_type, ae.timestamp,
                g.country_code, g.city, g.latitude, g.longitude
            FROM auth_events ae
            LEFT JOIN ip_geolocation g ON ae.geo_id = g.id
            WHERE ae.source_ip_text = %s AND ae.target_username = %s
            AND ae.timestamp >= DATE_SUB(NOW(), INTERVAL %s HOUR)
            ORDER BY ae.timestamp DESC
            LIMIT 50
        """, (ip_address, username, self.RECENT_HISTORY_HOURS))
        return cursor.fetchall()

    def _check_impossible_travel(self, cursor, username: str,
                                  current_geo: Dict, timestamp: datetime) -> Dict:
        """
        Check for impossible travel - login from distant location in short time
        """
        result = {
            'type': 'impossible_travel',
            'detected': False,
            'score': 0,
            'title': 'Impossible Travel Detected',
            'description': '',
            'details': {}
        }

        # Get user's last successful login with geo
        cursor.execute("""
            SELECT
                ae.timestamp, ae.source_ip_text,
                g.country_code, g.country_name, g.city,
                g.latitude, g.longitude
            FROM auth_events ae
            JOIN ip_geolocation g ON ae.geo_id = g.id
            WHERE ae.target_username = %s
            AND ae.event_type = 'successful'
            AND ae.timestamp < %s
            AND g.latitude IS NOT NULL
            ORDER BY ae.timestamp DESC
            LIMIT 1
        """, (username, timestamp))

        last_login = cursor.fetchone()

        if not last_login:
            return result

        current_lat = current_geo.get('latitude')
        current_lon = current_geo.get('longitude')

        if not current_lat or not current_lon:
            return result

        last_lat = float(last_login['latitude'])
        last_lon = float(last_login['longitude'])

        # Calculate distance using shared utility
        distance_km = haversine_distance(
            last_lat, last_lon, float(current_lat), float(current_lon)
        )

        # Calculate time difference
        time_diff = timestamp - last_login['timestamp']
        hours_diff = time_diff.total_seconds() / 3600

        if hours_diff <= 0:
            return result

        # Calculate required speed
        required_speed = distance_km / hours_diff

        # Check if travel is impossible
        if required_speed > self.MAX_HUMAN_SPEED_KMH:
            result['detected'] = True
            result['score'] = self.WEIGHTS['impossible_travel']
            result['description'] = (
                f"Login from {current_geo.get('city', 'Unknown')}, "
                f"{current_geo.get('country_name', 'Unknown')} "
                f"occurred {hours_diff:.1f} hours after login from "
                f"{last_login['city']}, {last_login['country_name']}. "
                f"Distance: {distance_km:.0f} km would require traveling at "
                f"{required_speed:.0f} km/h - physically impossible."
            )
            result['details'] = {
                'previous_location': {
                    'city': last_login['city'],
                    'country': last_login['country_name'],
                    'country_code': last_login['country_code'],
                    'ip': last_login['source_ip_text'],
                    'timestamp': last_login['timestamp'].isoformat()
                },
                'current_location': {
                    'city': current_geo.get('city'),
                    'country': current_geo.get('country_name'),
                    'country_code': current_geo.get('country_code')
                },
                'distance_km': round(distance_km, 1),
                'time_diff_hours': round(hours_diff, 2),
                'required_speed_kmh': round(required_speed, 0),
                'max_possible_speed_kmh': self.MAX_HUMAN_SPEED_KMH
            }
        elif required_speed > self.SUSPICIOUS_SPEED_KMH:
            result['detected'] = True
            result['score'] = int(self.WEIGHTS['impossible_travel'] * 0.5)
            result['title'] = 'Suspicious Travel Speed'
            result['description'] = (
                f"Login locations suggest travel at {required_speed:.0f} km/h - "
                f"unusually fast but theoretically possible."
            )
            result['details'] = {
                'distance_km': round(distance_km, 1),
                'time_diff_hours': round(hours_diff, 2),
                'required_speed_kmh': round(required_speed, 0)
            }

        return result

    def _check_new_location(self, user_history: Dict, current_geo: Dict) -> Dict:
        """Check if login is from a new/unknown location for this user"""
        result = {
            'type': 'new_location',
            'detected': False,
            'score': 0,
            'title': 'Login from New Location',
            'description': '',
            'details': {}
        }

        known_locations = user_history.get('known_locations', [])
        if not known_locations:
            return result

        current_country = current_geo.get('country_code')
        current_city = current_geo.get('city')

        # Check if country is known
        known_countries = set(loc['country_code'] for loc in known_locations if loc.get('country_code'))
        known_cities = set(loc['city'] for loc in known_locations if loc.get('city'))

        if current_country and current_country not in known_countries:
            result['detected'] = True
            result['score'] = self.WEIGHTS['new_location']
            result['description'] = (
                f"First login from {current_geo.get('country_name', current_country)}. "
                f"User previously logged in from: {', '.join(known_countries)}."
            )
            result['details'] = {
                'new_country': current_geo.get('country_name'),
                'new_country_code': current_country,
                'known_countries': list(known_countries),
                'is_first_from_country': True
            }
        elif current_city and current_city not in known_cities:
            result['detected'] = True
            result['score'] = int(self.WEIGHTS['new_location'] * 0.5)
            result['description'] = (
                f"First login from {current_city}, {current_geo.get('country_name')}. "
                f"Known cities: {', '.join(list(known_cities)[:5])}."
            )
            result['details'] = {
                'new_city': current_city,
                'known_cities': list(known_cities)[:10],
                'is_first_from_city': True
            }

        return result

    def _check_unusual_time(self, user_history: Dict, timestamp: datetime) -> Dict:
        """Check if login time is unusual for this user"""
        result = {
            'type': 'unusual_time',
            'detected': False,
            'score': 0,
            'title': 'Unusual Login Time',
            'description': '',
            'details': {}
        }

        if not user_history:
            return result

        typical_hours = user_history.get('typical_hours', [])
        if not typical_hours:
            return result

        current_hour = timestamp.hour

        # Check if current hour is outside typical hours
        if current_hour not in typical_hours:
            # Calculate how far from typical hours
            min_distance = min(
                min(abs(current_hour - h), 24 - abs(current_hour - h))
                for h in typical_hours
            ) if typical_hours else 12

            if min_distance >= 4:  # 4+ hours from typical login time
                result['detected'] = True
                result['score'] = self.WEIGHTS['unusual_time']
                result['description'] = (
                    f"Login at {timestamp.strftime('%H:%M')} is unusual. "
                    f"User typically logs in during hours: "
                    f"{', '.join(f'{h}:00' for h in sorted(typical_hours)[:5])}."
                )
                result['details'] = {
                    'login_hour': current_hour,
                    'typical_hours': typical_hours,
                    'hours_from_typical': min_distance
                }

        return result

    def _check_new_ip_for_user(self, user_history: Dict, ip_address: str) -> Dict:
        """Check if this is a new IP for the user"""
        result = {
            'type': 'new_ip_for_user',
            'detected': False,
            'score': 0,
            'title': 'Login from New IP Address',
            'description': '',
            'details': {}
        }

        known_ips = user_history.get('known_ips', [])

        if ip_address not in known_ips:
            result['detected'] = True
            total_known = len(known_ips)

            if total_known == 0:
                result['score'] = int(self.WEIGHTS['new_ip_for_user'] * 0.3)
                result['description'] = "First recorded login for this user."
            else:
                result['score'] = self.WEIGHTS['new_ip_for_user']
                result['description'] = (
                    f"First login from IP {ip_address}. "
                    f"User has {total_known} known IP(s)."
                )

            result['details'] = {
                'new_ip': ip_address,
                'known_ip_count': total_known,
                'sample_known_ips': known_ips[:5]
            }

        return result

    def _check_rapid_attempts(self, cursor, ip_address: str, username: str) -> Dict:
        """Check for rapid login attempts (brute force indicator)"""
        result = {
            'type': 'rapid_attempts',
            'detected': False,
            'score': 0,
            'title': 'Rapid Login Attempts',
            'description': '',
            'details': {}
        }

        # Check attempts in last 5 minutes
        cursor.execute("""
            SELECT COUNT(*) as attempts,
                   SUM(event_type = 'failed') as failed
            FROM auth_events
            WHERE source_ip_text = %s
            AND timestamp >= DATE_SUB(NOW(), INTERVAL 5 MINUTE)
        """, (ip_address,))

        recent = cursor.fetchone()

        if recent['attempts'] >= 10:
            result['detected'] = True
            fail_rate = (recent['failed'] or 0) / recent['attempts'] * 100

            if fail_rate > 80:
                result['score'] = self.WEIGHTS['brute_force']
                result['title'] = 'Brute Force Attack Detected'
                result['description'] = (
                    f"{recent['attempts']} login attempts in 5 minutes "
                    f"with {fail_rate:.0f}% failure rate. "
                    f"Classic brute force attack pattern."
                )
            else:
                result['score'] = self.WEIGHTS['rapid_attempts']
                result['description'] = (
                    f"{recent['attempts']} login attempts in 5 minutes "
                    f"is abnormally high activity."
                )

            result['details'] = {
                'attempts_5min': recent['attempts'],
                'failed_attempts': recent['failed'] or 0,
                'failure_rate': round(fail_rate, 1),
                'threshold': 10
            }

        return result

    def _check_credential_stuffing(self, cursor, ip_address: str) -> Dict:
        """Check for credential stuffing pattern (many users, low success)"""
        result = {
            'type': 'credential_stuffing',
            'detected': False,
            'score': 0,
            'title': 'Credential Stuffing Pattern',
            'description': '',
            'details': {}
        }

        # Check last hour
        cursor.execute("""
            SELECT
                COUNT(DISTINCT target_username) as unique_users,
                COUNT(*) as total_attempts,
                SUM(event_type = 'successful') as successes
            FROM auth_events
            WHERE source_ip_text = %s
            AND timestamp >= DATE_SUB(NOW(), INTERVAL 1 HOUR)
        """, (ip_address,))

        stats = cursor.fetchone()

        unique_users = stats['unique_users'] or 0
        total = stats['total_attempts'] or 0
        successes = stats['successes'] or 0

        # Credential stuffing: many users, few successes
        if unique_users >= 5 and total >= 10:
            success_rate = (successes / total * 100) if total > 0 else 0

            if success_rate < 20:  # Low success rate across many users
                result['detected'] = True
                result['score'] = self.WEIGHTS['credential_stuffing']
                result['description'] = (
                    f"IP attempted login to {unique_users} different usernames "
                    f"in the last hour with only {success_rate:.0f}% success rate. "
                    f"This pattern indicates credential stuffing attack."
                )
                result['details'] = {
                    'unique_usernames': unique_users,
                    'total_attempts': total,
                    'successful': successes,
                    'success_rate': round(success_rate, 1)
                }

        return result

    def _check_success_after_failures(self, cursor, ip_address: str, username: str) -> Dict:
        """Check if successful login came after multiple failures"""
        result = {
            'type': 'success_after_failures',
            'detected': False,
            'score': 0,
            'title': 'Success After Multiple Failures',
            'description': '',
            'details': {}
        }

        # Count recent failures before this success
        cursor.execute("""
            SELECT COUNT(*) as failed_attempts
            FROM auth_events
            WHERE source_ip_text = %s
            AND target_username = %s
            AND event_type = 'failed'
            AND timestamp >= DATE_SUB(NOW(), INTERVAL 1 HOUR)
        """, (ip_address, username))

        failures = cursor.fetchone()['failed_attempts'] or 0

        if failures >= 3:
            result['detected'] = True
            if failures >= 10:
                result['score'] = self.WEIGHTS['success_after_failures']
                result['description'] = (
                    f"Successful login after {failures} failed attempts. "
                    f"This may indicate a successful brute force or "
                    f"password guessing attack."
                )
            else:
                result['score'] = int(self.WEIGHTS['success_after_failures'] * 0.6)
                result['description'] = (
                    f"Successful login after {failures} failed attempts. "
                    f"Could indicate password recovery or attack."
                )

            result['details'] = {
                'prior_failures': failures,
                'time_window': '1 hour'
            }

        return result

    def _check_geo_mismatch(self, cursor, username: str, current_geo: Dict) -> Dict:
        """Check for geographic mismatch with user's typical pattern"""
        result = {
            'type': 'geo_mismatch',
            'detected': False,
            'score': 0,
            'title': 'Geographic Pattern Mismatch',
            'description': '',
            'details': {}
        }

        # Get user's most common login country
        cursor.execute("""
            SELECT g.country_code, g.country_name, COUNT(*) as login_count
            FROM auth_events ae
            JOIN ip_geolocation g ON ae.geo_id = g.id
            WHERE ae.target_username = %s
            AND ae.event_type = 'successful'
            AND ae.timestamp >= DATE_SUB(NOW(), INTERVAL 90 DAY)
            GROUP BY g.country_code, g.country_name
            ORDER BY login_count DESC
            LIMIT 3
        """, (username,))

        common_countries = cursor.fetchall()

        if not common_countries:
            return result

        current_country = current_geo.get('country_code')
        primary_country = common_countries[0]['country_code']
        primary_count = common_countries[0]['login_count']

        # Check if current country differs from primary
        if current_country and current_country != primary_country:
            # Calculate what percentage of logins are from primary
            total_logins = sum(c['login_count'] for c in common_countries)
            primary_pct = (primary_count / total_logins * 100) if total_logins > 0 else 0

            if primary_pct >= 90:  # User almost always logs in from one country
                result['detected'] = True
                result['score'] = self.WEIGHTS['geo_mismatch']
                result['description'] = (
                    f"Login from {current_geo.get('country_name')} is unusual. "
                    f"User logs in from {common_countries[0]['country_name']} "
                    f"{primary_pct:.0f}% of the time."
                )
                result['details'] = {
                    'current_country': current_geo.get('country_name'),
                    'primary_country': common_countries[0]['country_name'],
                    'primary_country_percentage': round(primary_pct, 1),
                    'common_countries': [
                        {'country': c['country_name'], 'logins': c['login_count']}
                        for c in common_countries
                    ]
                }

        return result

    def _calculate_confidence(self, user_history: Dict, ip_history: Dict) -> float:
        """Calculate confidence level based on available historical data"""
        confidence = 0.5  # Base confidence

        if user_history:
            total_logins = user_history.get('total_logins', 0)
            if total_logins >= 100:
                confidence += 0.3
            elif total_logins >= 30:
                confidence += 0.2
            elif total_logins >= 10:
                confidence += 0.1

        if ip_history:
            if ip_history.get('total_events', 0) >= 10:
                confidence += 0.1

        return min(1.0, confidence)

    def _generate_recommendations(self) -> List[str]:
        """Generate actionable recommendations based on findings"""
        recommendations = []

        risk_types = [f['type'] for f in self.risk_factors]

        if 'impossible_travel' in risk_types:
            recommendations.append(
                "CRITICAL: Verify user identity immediately. "
                "Consider forcing password reset and enabling MFA."
            )

        if 'credential_stuffing' in risk_types or 'brute_force' in risk_types:
            recommendations.append(
                "Block this IP immediately. "
                "Review all accounts that received login attempts."
            )

        if 'new_location' in risk_types:
            recommendations.append(
                "Send verification email to user confirming login location."
            )

        if 'success_after_failures' in risk_types:
            recommendations.append(
                "Verify this login was legitimate. "
                "Check for signs of account compromise."
            )

        if 'unusual_time' in risk_types:
            recommendations.append(
                "Flag for review if combined with other anomalies."
            )

        if not recommendations:
            if self.risk_score < 20:
                recommendations.append("No immediate action required.")
            else:
                recommendations.append("Monitor for additional suspicious activity.")

        return recommendations

    # NOTE: _haversine_distance has been removed - using shared geoip.haversine_distance instead


def analyze_behavioral_risk(ip_address: str, username: str,
                           event_type: str, geo_data: Dict = None) -> Dict:
    """Convenience function to perform behavioral analysis"""
    analyzer = BehavioralAnalyzer()
    return analyzer.analyze(ip_address, username, event_type, geo_data)
