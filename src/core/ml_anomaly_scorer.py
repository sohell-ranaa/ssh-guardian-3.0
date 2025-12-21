"""
SSH Guardian v3.0 - ML Anomaly Scorer
Scores login events for behavioral anomalies using learned user profiles.
Combines multiple deviation factors into a composite anomaly score.
"""

import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.append(str(PROJECT_ROOT / "dbs"))
sys.path.append(str(PROJECT_ROOT / "src"))

from core.ml_behavioral_learner import MLBehavioralLearner
from core.auto_trust_learner import is_ip_trusted


class MLAnomalyScorer:
    """
    Scores login events for behavioral anomalies.
    Uses learned user profiles to detect deviations from normal behavior.
    """

    # Anomaly threshold - score >= this triggers alert
    # Lowered to 30 to catch single-factor anomalies (unusual time alone, new location alone)
    ANOMALY_THRESHOLD = 30

    # Feature weights for composite score (increased for more sensitive detection)
    WEIGHTS = {
        'time_deviation': 35,      # Unusual login time
        'location_novelty': 40,    # New country/city
        'ip_novelty': 25,          # New IP address
        'day_deviation': 20,       # Unusual day of week
        'session_gap': 10          # Unusual gap since last login
    }

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.learner = MLBehavioralLearner(verbose=verbose)

    def _log(self, msg: str):
        if self.verbose:
            print(f"[MLScorer] {msg}")

    def score_login(self, login_data: Dict) -> Dict:
        """
        Score a login event for anomalies.

        Args:
            login_data: Dict containing:
                - username: str
                - hour: int (0-23)
                - day_of_week: int (0=Mon, 6=Sun)
                - ip_address: str
                - country: str
                - city: str (optional)
                - timestamp: datetime (optional)

        Returns:
            Dict with:
                - anomaly_score: int (0-100)
                - is_anomaly: bool
                - factors: List of detected anomaly factors
                - details: Dict with individual scores
        """
        username = login_data.get('username', '')
        ip_address = login_data.get('ip_address', '')

        if not username:
            return {
                'anomaly_score': 0,
                'is_anomaly': False,
                'factors': [],
                'details': {},
                'message': 'No username provided'
            }

        # Check if IP is trusted - skip anomaly detection for trusted sources
        if ip_address:
            is_trusted, trust_reason = is_ip_trusted(ip_address)
            if is_trusted:
                self._log(f"IP {ip_address} is trusted - skipping anomaly detection")
                return {
                    'anomaly_score': 0,
                    'is_anomaly': False,
                    'factors': ['trusted_source'],
                    'details': {'trust_reason': trust_reason},
                    'message': f'Trusted source: {trust_reason}'
                }

        # Get user profile
        profile = self.learner.get_user_profile(username)

        if not profile:
            self._log(f"No profile for {username} - first time user")
            return {
                'anomaly_score': 0,
                'is_anomaly': False,
                'factors': ['first_time_user'],
                'details': {'message': 'First time user, building baseline'},
                'message': 'New user - building baseline'
            }

        if profile['login_count'] < 10:
            self._log(f"Profile for {username} has only {profile['login_count']} logins - insufficient data")
            return {
                'anomaly_score': 0,
                'is_anomaly': False,
                'factors': ['insufficient_baseline'],
                'details': {'login_count': profile['login_count']},
                'message': f"Building baseline ({profile['login_count']}/10 logins)"
            }

        # Calculate individual deviation scores
        hour = login_data.get('hour', datetime.now().hour)
        day = login_data.get('day_of_week', datetime.now().weekday())
        ip_address = login_data.get('ip_address', '')
        country = login_data.get('country', '')
        city = login_data.get('city', '')

        # Get deviations (each returns 0.0 to 1.0)
        time_dev = self.learner.calculate_time_deviation(username, hour)
        location_nov = self.learner.calculate_location_novelty(username, country, city)
        ip_nov = self.learner.calculate_ip_novelty(username, ip_address)
        day_dev = self.learner.calculate_day_deviation(username, day)

        # Session gap deviation (simplified)
        session_gap_dev = 0.0
        if profile.get('avg_session_gap_hours') and login_data.get('timestamp'):
            if profile.get('last_login_at'):
                current_gap = (login_data['timestamp'] - profile['last_login_at']).total_seconds() / 3600
                avg_gap = profile['avg_session_gap_hours']
                if avg_gap > 0:
                    gap_ratio = current_gap / avg_gap
                    if gap_ratio > 5:  # 5x longer than usual
                        session_gap_dev = 0.5
                    elif gap_ratio > 10:  # 10x longer
                        session_gap_dev = 0.8

        # Calculate weighted composite score
        weighted_scores = {
            'time_deviation': time_dev * self.WEIGHTS['time_deviation'],
            'location_novelty': location_nov * self.WEIGHTS['location_novelty'],
            'ip_novelty': ip_nov * self.WEIGHTS['ip_novelty'],
            'day_deviation': day_dev * self.WEIGHTS['day_deviation'],
            'session_gap': session_gap_dev * self.WEIGHTS['session_gap']
        }

        # Use maximum weighted score approach for single-factor anomalies
        # This ensures a single high deviation can trigger an alert
        max_weighted = max(weighted_scores.values()) if weighted_scores else 0
        sum_weighted = sum(weighted_scores.values())

        # Score is the higher of: max single factor OR average of all factors
        # This allows both single-factor and multi-factor detection
        avg_score = (sum_weighted / sum(self.WEIGHTS.values())) * 100
        max_score = max_weighted  # Direct use since weights are already scaled to ~100
        anomaly_score = int(max(avg_score, max_score))
        anomaly_score = min(100, max(0, anomaly_score))

        # Determine factors that contributed
        factors = []
        factor_details = []

        if time_dev >= 0.5:
            factors.append('unusual_time')
            factor_details.append(f"Login at {hour}:00 is unusual (deviation: {time_dev:.1%})")

        if location_nov >= 0.5:
            factors.append('new_location')
            loc_str = f"{city}, {country}" if city else country
            factor_details.append(f"New location: {loc_str}")

        if ip_nov >= 0.5:
            factors.append('new_ip')
            factor_details.append(f"First time from IP: {ip_address}")

        if day_dev >= 0.5:
            day_names = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
            factors.append('unusual_day')
            factor_details.append(f"Login on {day_names[day]} is unusual")

        if session_gap_dev >= 0.5:
            factors.append('unusual_gap')
            factor_details.append("Unusual time gap since last login")

        is_anomaly = anomaly_score >= self.ANOMALY_THRESHOLD

        result = {
            'anomaly_score': anomaly_score,
            'is_anomaly': is_anomaly,
            'factors': factors,
            'factor_details': factor_details,
            'details': {
                'time_deviation': round(time_dev, 2),
                'location_novelty': round(location_nov, 2),
                'ip_novelty': round(ip_nov, 2),
                'day_deviation': round(day_dev, 2),
                'session_gap_deviation': round(session_gap_dev, 2),
                'weighted_scores': {k: round(v, 1) for k, v in weighted_scores.items()},
                'profile_confidence': profile.get('confidence_score', 0),
                'profile_login_count': profile.get('login_count', 0)
            },
            'message': self._build_message(factors, factor_details, anomaly_score)
        }

        self._log(f"Scored {username}: {anomaly_score}/100, anomaly={is_anomaly}, factors={factors}")

        return result

    def _build_message(self, factors: List[str], details: List[str], score: int) -> str:
        """Build human-readable message from factors."""
        if not factors:
            return "Login matches normal patterns"

        if score >= 70:
            severity = "High-risk"
        elif score >= 50:
            severity = "Suspicious"
        else:
            severity = "Minor"

        msg = f"{severity} behavioral anomaly detected"
        if details:
            msg += ": " + "; ".join(details)

        return msg

    def get_anomaly_type(self, factors: List[str]) -> str:
        """
        Determine the primary anomaly type from factors.
        Used for notification categorization.
        """
        if not factors:
            return 'normal'

        # Priority order for anomaly type
        if 'new_location' in factors:
            return 'new_location'
        if 'unusual_time' in factors:
            return 'unusual_time'
        if 'unusual_day' in factors:
            return 'unusual_day'
        if 'new_ip' in factors:
            return 'new_ip'
        if 'unusual_gap' in factors:
            return 'unusual_gap'

        return 'behavioral_anomaly'


def test_scorer():
    """Test the anomaly scorer with sample data."""
    scorer = MLAnomalyScorer(verbose=True)

    # First, ensure profiles are seeded
    from core.ml_behavioral_learner import seed_simulation_profiles
    seed_simulation_profiles()

    # Test cases
    tests = [
        {
            'name': 'Normal login for dev.user',
            'data': {
                'username': 'dev.user',
                'hour': 10,  # Normal work hours
                'day_of_week': 1,  # Tuesday
                'ip_address': '73.162.0.1',  # Known IP
                'country': 'US',
                'city': 'San Francisco'
            }
        },
        {
            'name': 'Unusual time for dev.user (3 AM)',
            'data': {
                'username': 'dev.user',
                'hour': 3,  # 3 AM - unusual
                'day_of_week': 1,
                'ip_address': '73.162.0.1',
                'country': 'US',
                'city': 'San Francisco'
            }
        },
        {
            'name': 'New location for dev.user (UK)',
            'data': {
                'username': 'dev.user',
                'hour': 10,
                'day_of_week': 1,
                'ip_address': '82.132.234.1',  # UK IP
                'country': 'UK',
                'city': 'London'
            }
        },
        {
            'name': 'Weekend login for pm_lead',
            'data': {
                'username': 'pm_lead',
                'hour': 14,  # 2 PM
                'day_of_week': 5,  # Saturday
                'ip_address': '73.162.50.1',
                'country': 'US',
                'city': 'Seattle'
            }
        }
    ]

    print("\n" + "="*60)
    print("ML ANOMALY SCORER TEST RESULTS")
    print("="*60)

    for test in tests:
        print(f"\n--- {test['name']} ---")
        result = scorer.score_login(test['data'])
        print(f"  Score: {result['anomaly_score']}/100")
        print(f"  Is Anomaly: {result['is_anomaly']}")
        print(f"  Factors: {result['factors']}")
        print(f"  Message: {result['message']}")


if __name__ == "__main__":
    test_scorer()
