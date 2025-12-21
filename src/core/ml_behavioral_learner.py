"""
SSH Guardian v3.0 - ML Behavioral Learner
Auto-learns user behavioral patterns from successful logins.
Tracks login times, locations, IPs to build user profiles.
"""

import json
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Optional, List, Tuple

PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.append(str(PROJECT_ROOT / "dbs"))

from connection import get_connection


class MLBehavioralLearner:
    """
    Auto-learns user behavioral patterns from login events.
    Builds profiles that can be used to detect anomalies.
    """

    # Minimum logins before profile is considered reliable
    MIN_LOGINS_FOR_CONFIDENCE = 10

    # Maximum items to track per category
    MAX_IPS_TRACKED = 50
    MAX_CITIES_TRACKED = 20
    MAX_COUNTRIES_TRACKED = 10

    def __init__(self, verbose: bool = False):
        self.verbose = verbose

    def _log(self, msg: str):
        if self.verbose:
            print(f"[MLLearner] {msg}")

    def get_user_profile(self, username: str) -> Optional[Dict]:
        """
        Get learned behavioral profile for a user.
        Returns None if user has no profile yet.
        """
        if not username:
            return None

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            cursor.execute("""
                SELECT
                    username,
                    typical_hours,
                    typical_days,
                    known_ips,
                    known_countries,
                    known_cities,
                    login_count,
                    successful_count,
                    failed_count,
                    avg_session_gap_hours,
                    last_login_at,
                    confidence_score
                FROM user_behavioral_profiles
                WHERE username = %s
            """, (username,))

            row = cursor.fetchone()
            if not row:
                return None

            # Parse JSON fields
            profile = {
                'username': row['username'],
                'typical_hours': json.loads(row['typical_hours']) if row['typical_hours'] else {},
                'typical_days': json.loads(row['typical_days']) if row['typical_days'] else {},
                'known_ips': json.loads(row['known_ips']) if row['known_ips'] else {},
                'known_countries': json.loads(row['known_countries']) if row['known_countries'] else {},
                'known_cities': json.loads(row['known_cities']) if row['known_cities'] else {},
                'login_count': row['login_count'] or 0,
                'successful_count': row['successful_count'] or 0,
                'failed_count': row['failed_count'] or 0,
                'avg_session_gap_hours': row['avg_session_gap_hours'],
                'last_login_at': row['last_login_at'],
                'confidence_score': row['confidence_score'] or 0.0
            }

            return profile

        except Exception as e:
            self._log(f"Error getting profile for {username}: {e}")
            return None
        finally:
            cursor.close()
            conn.close()

    def learn_from_login(self, username: str, login_data: Dict) -> bool:
        """
        Update user profile with a new login event.
        Call this for each successful login to build the profile.

        login_data should contain:
            - hour: int (0-23)
            - day_of_week: int (0=Mon, 6=Sun) or str ('Monday', 'Tuesday', ...)
            - ip_address: str
            - country: str (country code like 'US', 'UK')
            - city: str (optional)
            - is_successful: bool
            - timestamp: datetime (optional)
        """
        if not username:
            return False

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            # Get existing profile or create new one
            cursor.execute("""
                SELECT * FROM user_behavioral_profiles WHERE username = %s
            """, (username,))
            existing = cursor.fetchone()

            # Parse existing data
            if existing:
                typical_hours = json.loads(existing['typical_hours']) if existing['typical_hours'] else {}
                typical_days = json.loads(existing['typical_days']) if existing['typical_days'] else {}
                known_ips = json.loads(existing['known_ips']) if existing['known_ips'] else {}
                known_countries = json.loads(existing['known_countries']) if existing['known_countries'] else {}
                known_cities = json.loads(existing['known_cities']) if existing['known_cities'] else {}
                login_count = existing['login_count'] or 0
                successful_count = existing['successful_count'] or 0
                failed_count = existing['failed_count'] or 0
                last_login_at = existing['last_login_at']
            else:
                typical_hours = {}
                typical_days = {}
                known_ips = {}
                known_countries = {}
                known_cities = {}
                login_count = 0
                successful_count = 0
                failed_count = 0
                last_login_at = None

            # Extract data from login
            hour = login_data.get('hour', datetime.now().hour)
            day = login_data.get('day_of_week', datetime.now().weekday())
            ip_address = login_data.get('ip_address', '')
            country = login_data.get('country', 'Unknown')
            city = login_data.get('city', 'Unknown')
            is_successful = login_data.get('is_successful', True)
            timestamp = login_data.get('timestamp', datetime.now())

            # Convert day to string if needed
            day_names = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']
            if isinstance(day, int):
                day_str = day_names[day % 7]
            else:
                day_str = str(day)[:3]

            # Update hour distribution
            hour_key = str(hour)
            typical_hours[hour_key] = typical_hours.get(hour_key, 0) + 1

            # Update day distribution
            typical_days[day_str] = typical_days.get(day_str, 0) + 1

            # Update known IPs (limit size)
            if ip_address:
                known_ips[ip_address] = known_ips.get(ip_address, 0) + 1
                if len(known_ips) > self.MAX_IPS_TRACKED:
                    # Remove least frequent
                    sorted_ips = sorted(known_ips.items(), key=lambda x: x[1], reverse=True)
                    known_ips = dict(sorted_ips[:self.MAX_IPS_TRACKED])

            # Update known countries
            if country and country != 'Unknown':
                known_countries[country] = known_countries.get(country, 0) + 1

            # Update known cities
            if city and city != 'Unknown':
                known_cities[city] = known_cities.get(city, 0) + 1
                if len(known_cities) > self.MAX_CITIES_TRACKED:
                    sorted_cities = sorted(known_cities.items(), key=lambda x: x[1], reverse=True)
                    known_cities = dict(sorted_cities[:self.MAX_CITIES_TRACKED])

            # Update counts
            login_count += 1
            if is_successful:
                successful_count += 1
            else:
                failed_count += 1

            # Calculate session gap
            avg_gap = None
            if last_login_at:
                gap_hours = (timestamp - last_login_at).total_seconds() / 3600
                if existing and existing.get('avg_session_gap_hours'):
                    # Running average
                    old_avg = existing['avg_session_gap_hours']
                    avg_gap = (old_avg * (login_count - 1) + gap_hours) / login_count
                else:
                    avg_gap = gap_hours

            # Calculate confidence score
            confidence = min(1.0, login_count / 100)  # Max out at 100 logins

            # Upsert profile
            if existing:
                cursor.execute("""
                    UPDATE user_behavioral_profiles SET
                        typical_hours = %s,
                        typical_days = %s,
                        known_ips = %s,
                        known_countries = %s,
                        known_cities = %s,
                        login_count = %s,
                        successful_count = %s,
                        failed_count = %s,
                        avg_session_gap_hours = %s,
                        last_login_at = %s,
                        confidence_score = %s,
                        updated_at = NOW()
                    WHERE username = %s
                """, (
                    json.dumps(typical_hours),
                    json.dumps(typical_days),
                    json.dumps(known_ips),
                    json.dumps(known_countries),
                    json.dumps(known_cities),
                    login_count,
                    successful_count,
                    failed_count,
                    avg_gap,
                    timestamp,
                    confidence,
                    username
                ))
            else:
                cursor.execute("""
                    INSERT INTO user_behavioral_profiles
                    (username, typical_hours, typical_days, known_ips, known_countries,
                     known_cities, login_count, successful_count, failed_count,
                     avg_session_gap_hours, last_login_at, confidence_score)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (
                    username,
                    json.dumps(typical_hours),
                    json.dumps(typical_days),
                    json.dumps(known_ips),
                    json.dumps(known_countries),
                    json.dumps(known_cities),
                    login_count,
                    successful_count,
                    failed_count,
                    avg_gap,
                    timestamp,
                    confidence
                ))

            conn.commit()
            self._log(f"Updated profile for {username}: {login_count} logins, confidence={confidence:.2f}")
            return True

        except Exception as e:
            self._log(f"Error updating profile for {username}: {e}")
            conn.rollback()
            return False
        finally:
            cursor.close()
            conn.close()

    def calculate_time_deviation(self, username: str, login_hour: int) -> float:
        """
        Calculate how unusual this login time is for the user.
        Returns a value from 0.0 (normal) to 1.0 (very unusual).
        """
        profile = self.get_user_profile(username)
        if not profile or not profile['typical_hours']:
            return 0.0  # No baseline, can't determine deviation

        if profile['login_count'] < self.MIN_LOGINS_FOR_CONFIDENCE:
            return 0.0  # Not enough data

        typical_hours = profile['typical_hours']
        total_logins = sum(typical_hours.values())

        if total_logins == 0:
            return 0.0

        hour_key = str(login_hour)
        hour_frequency = typical_hours.get(hour_key, 0) / total_logins

        # If this hour has high frequency, deviation is low
        # If this hour has zero or low frequency, deviation is high
        if hour_frequency >= 0.1:  # 10% or more of logins at this hour
            return 0.0
        elif hour_frequency >= 0.05:  # 5-10%
            return 0.3
        elif hour_frequency > 0:  # Some logins at this hour
            return 0.5
        else:  # Never logged in at this hour
            return 0.9

    def calculate_location_novelty(self, username: str, country: str, city: str = None) -> float:
        """
        Calculate how novel this location is for the user.
        Returns 0.0 (known location) to 1.0 (completely new).
        """
        profile = self.get_user_profile(username)
        if not profile:
            return 0.0  # No baseline

        if profile['login_count'] < self.MIN_LOGINS_FOR_CONFIDENCE:
            return 0.0  # Not enough data

        known_countries = profile['known_countries']
        known_cities = profile['known_cities']

        # Check country
        country_novelty = 0.0
        if country and country not in known_countries:
            country_novelty = 0.8  # New country is significant

        # Check city
        city_novelty = 0.0
        if city and city not in known_cities:
            if country in known_countries:
                city_novelty = 0.3  # New city in known country
            else:
                city_novelty = 0.5  # New city in new country

        return max(country_novelty, city_novelty)

    def calculate_ip_novelty(self, username: str, ip_address: str) -> float:
        """
        Calculate how novel this IP is for the user.
        Returns 0.0 (known IP) to 1.0 (never seen).
        """
        profile = self.get_user_profile(username)
        if not profile:
            return 0.0

        if profile['login_count'] < self.MIN_LOGINS_FOR_CONFIDENCE:
            return 0.0

        known_ips = profile['known_ips']

        if ip_address in known_ips:
            # Known IP - check frequency
            total = sum(known_ips.values())
            freq = known_ips[ip_address] / total if total > 0 else 0
            if freq >= 0.3:  # Primary IP
                return 0.0
            elif freq >= 0.1:  # Regular IP
                return 0.1
            else:  # Rarely used IP
                return 0.2
        else:
            # Completely new IP
            return 0.7

    def calculate_day_deviation(self, username: str, day_of_week: int) -> float:
        """
        Calculate how unusual this day is for the user.
        day_of_week: 0=Monday, 6=Sunday
        """
        profile = self.get_user_profile(username)
        if not profile or not profile['typical_days']:
            return 0.0

        if profile['login_count'] < self.MIN_LOGINS_FOR_CONFIDENCE:
            return 0.0

        day_names = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']
        day_str = day_names[day_of_week % 7]

        typical_days = profile['typical_days']
        total = sum(typical_days.values())

        if total == 0:
            return 0.0

        day_frequency = typical_days.get(day_str, 0) / total

        if day_frequency >= 0.1:
            return 0.0
        elif day_frequency > 0:
            return 0.3
        else:
            return 0.6  # Never logged in on this day


def seed_simulation_profiles():
    """
    Seed behavioral profiles for simulation testing.
    Creates baseline data for test users.
    """
    learner = MLBehavioralLearner(verbose=True)

    # Simulation user profiles
    profiles = {
        'dev.user': {
            'typical_hours': {str(h): 10 for h in range(9, 18)},  # 9am-5pm
            'typical_days': {'Mon': 20, 'Tue': 20, 'Wed': 20, 'Thu': 20, 'Fri': 20},
            'known_ips': {'73.162.0.1': 50, '98.217.50.1': 30},
            'known_countries': {'US': 100},
            'known_cities': {'San Francisco': 60, 'New York': 40},
            'login_count': 100
        },
        'engineer': {
            'typical_hours': {str(h): 8 for h in range(8, 19)},  # 8am-6pm
            'typical_days': {'Mon': 18, 'Tue': 18, 'Wed': 18, 'Thu': 18, 'Fri': 18, 'Sat': 5, 'Sun': 5},
            'known_ips': {'98.217.50.1': 60, '24.48.0.1': 40},
            'known_countries': {'US': 100},
            'known_cities': {'Austin': 100},
            'login_count': 100
        },
        'analyst': {
            'typical_hours': {str(h): 12 for h in range(9, 17)},  # 9am-5pm
            'typical_days': {'Mon': 20, 'Tue': 20, 'Wed': 20, 'Thu': 20, 'Fri': 20},
            'known_ips': {'98.217.50.1': 50, '98.217.50.2': 50},
            'known_countries': {'US': 100},
            'known_cities': {'Chicago': 100},
            'login_count': 100
        },
        'pm_lead': {
            'typical_hours': {str(h): 12 for h in range(9, 17)},  # 9am-5pm weekdays only
            'typical_days': {'Mon': 20, 'Tue': 20, 'Wed': 20, 'Thu': 20, 'Fri': 20},
            'known_ips': {'73.162.50.1': 80, '24.48.100.1': 20},
            'known_countries': {'US': 100},
            'known_cities': {'Seattle': 100},
            'login_count': 100
        },
        'sysadmin': {
            'typical_hours': {str(h): 10 for h in range(9, 17)},
            'typical_days': {'Mon': 18, 'Tue': 18, 'Wed': 18, 'Thu': 18, 'Fri': 18, 'Sat': 5, 'Sun': 5},
            'known_ips': {'10.0.0.1': 40, '192.168.1.1': 40, '98.217.50.1': 20},
            'known_countries': {'US': 100},
            'known_cities': {'Denver': 100},
            'login_count': 100
        },
        'root': {
            'typical_hours': {str(h): 10 for h in range(9, 18)},
            'typical_days': {'Mon': 20, 'Tue': 20, 'Wed': 20, 'Thu': 20, 'Fri': 20},
            'known_ips': {'10.0.0.1': 70, '192.168.1.100': 30},
            'known_countries': {'US': 100},
            'known_cities': {'New York': 100},
            'login_count': 100
        }
    }

    conn = get_connection()
    cursor = conn.cursor()

    try:
        for username, profile_data in profiles.items():
            cursor.execute("""
                INSERT INTO user_behavioral_profiles
                (username, typical_hours, typical_days, known_ips, known_countries,
                 known_cities, login_count, successful_count, confidence_score)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    typical_hours = VALUES(typical_hours),
                    typical_days = VALUES(typical_days),
                    known_ips = VALUES(known_ips),
                    known_countries = VALUES(known_countries),
                    known_cities = VALUES(known_cities),
                    login_count = VALUES(login_count),
                    successful_count = VALUES(successful_count),
                    confidence_score = VALUES(confidence_score)
            """, (
                username,
                json.dumps(profile_data['typical_hours']),
                json.dumps(profile_data['typical_days']),
                json.dumps(profile_data['known_ips']),
                json.dumps(profile_data['known_countries']),
                json.dumps(profile_data['known_cities']),
                profile_data['login_count'],
                profile_data['login_count'],  # successful = total for baseline
                1.0  # Full confidence for seeded data
            ))
            print(f"Seeded profile for: {username}")

        conn.commit()
        print(f"Successfully seeded {len(profiles)} simulation profiles")
        return True

    except Exception as e:
        print(f"Error seeding profiles: {e}")
        conn.rollback()
        return False
    finally:
        cursor.close()
        conn.close()


if __name__ == "__main__":
    # When run directly, seed simulation profiles
    seed_simulation_profiles()
