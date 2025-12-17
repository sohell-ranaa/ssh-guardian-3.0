"""
SSH Guardian v3.0 - Proactive Threat Blocker
Analyzes incoming auth events in real-time and blocks threats BEFORE fail2ban threshold.

This enhances fail2ban by:
1. Blocking known bad IPs on FIRST attempt (not waiting for 5 failures)
2. Using threat intelligence (AbuseIPDB, Tor, VPN detection)
3. Detecting patterns fail2ban can't see (credential stuffing, slow attacks)
4. Escalating high-risk IPs to permanent UFW blocks

Decision Matrix:
┌─────────────────────────────────────────────────────────────────┐
│  Threat Score  │  Action                                        │
├─────────────────────────────────────────────────────────────────┤
│  0-30          │  No action - let fail2ban handle normally      │
│  30-60         │  Monitor closely - log warning                 │
│  60-80         │  PRE-EMPTIVE BLOCK via fail2ban (extended ban) │
│  80-100        │  PERMANENT BLOCK via UFW                       │
└─────────────────────────────────────────────────────────────────┘
"""

import sys
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, Optional, List, Tuple
import logging

# Add project paths
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
sys.path.append(str(PROJECT_ROOT / "dbs"))
sys.path.append(str(PROJECT_ROOT / "src" / "core"))

from connection import get_connection

# Configuration
PROACTIVE_BLOCKING_ENABLED = True  # Master switch
BLOCK_THRESHOLD_UFW = 80           # Score >= this → permanent UFW block
BLOCK_THRESHOLD_FAIL2BAN = 60      # Score >= this → extended fail2ban ban
WARNING_THRESHOLD = 30             # Score >= this → log warning

# High-risk indicators and their scores
THREAT_SCORES = {
    'tor_exit_node': 25,
    'vpn_proxy': 10,
    'abuseipdb_critical': 30,      # AbuseIPDB >= 80%
    'abuseipdb_high': 20,          # AbuseIPDB >= 50%
    'abuseipdb_medium': 10,        # AbuseIPDB >= 25%
    'virustotal_malicious': 25,
    'high_risk_country': 10,
    'repeat_offender_3plus': 25,
    'repeat_offender_2': 15,
    'credential_stuffing': 20,     # Multiple usernames from same IP
    'brute_force_velocity': 15,    # High velocity attacks
    'time_anomaly': 5,             # Off-hours attack
    'root_attempt': 10,            # Trying to login as root
    'invalid_user': 5,             # Unknown username
}


class ProactiveBlocker:
    """
    Real-time threat analysis and proactive blocking.
    Call evaluate_event() for each incoming auth event.
    """

    def __init__(self):
        self.enabled = PROACTIVE_BLOCKING_ENABLED
        self._cache = {}  # Simple in-memory cache for enrichment data

    def evaluate_event(self, event: Dict) -> Dict:
        """
        Evaluate an incoming auth event and decide on action.

        Args:
            event: {
                'source_ip': str,
                'username': str,
                'event_type': str ('failed', 'success', 'invalid_user'),
                'timestamp': str or datetime,
                'hostname': str (optional)
            }

        Returns:
            {
                'should_block': bool,
                'block_method': str ('none', 'fail2ban', 'ufw'),
                'threat_score': int (0-100),
                'risk_level': str ('low', 'medium', 'high', 'critical'),
                'factors': list of str,
                'action_taken': str
            }
        """
        if not self.enabled:
            return self._no_action_result()

        ip = event.get('source_ip')
        if not ip:
            return self._no_action_result()

        # Skip private IPs
        if self._is_private_ip(ip):
            return self._no_action_result()

        score = 0
        factors = []

        # 1. Get enrichment data (cached or fresh)
        enrichment = self._get_enrichment(ip)

        # 2. Score based on threat intelligence
        if enrichment:
            # Tor exit node
            if enrichment.get('is_tor'):
                score += THREAT_SCORES['tor_exit_node']
                factors.append('Tor exit node')

            # VPN/Proxy
            if enrichment.get('is_vpn') or enrichment.get('is_proxy'):
                score += THREAT_SCORES['vpn_proxy']
                factors.append('VPN/Proxy')

            # AbuseIPDB score
            abuse_score = enrichment.get('abuseipdb_score', 0)
            if abuse_score >= 80:
                score += THREAT_SCORES['abuseipdb_critical']
                factors.append(f'AbuseIPDB: {abuse_score}% (critical)')
            elif abuse_score >= 50:
                score += THREAT_SCORES['abuseipdb_high']
                factors.append(f'AbuseIPDB: {abuse_score}% (high)')
            elif abuse_score >= 25:
                score += THREAT_SCORES['abuseipdb_medium']
                factors.append(f'AbuseIPDB: {abuse_score}%')

            # VirusTotal
            if enrichment.get('virustotal_malicious', 0) > 0:
                score += THREAT_SCORES['virustotal_malicious']
                factors.append(f"VirusTotal: {enrichment['virustotal_malicious']} detections")

            # High-risk country
            if enrichment.get('is_high_risk_country'):
                score += THREAT_SCORES['high_risk_country']
                factors.append(f"High-risk country: {enrichment.get('country_code', 'Unknown')}")

        # 3. Score based on behavioral analysis
        behavior = self._analyze_behavior(ip, event)

        # Repeat offender
        if behavior['previous_bans'] >= 3:
            score += THREAT_SCORES['repeat_offender_3plus']
            factors.append(f"Repeat offender ({behavior['previous_bans']} bans)")
        elif behavior['previous_bans'] >= 2:
            score += THREAT_SCORES['repeat_offender_2']
            factors.append(f"{behavior['previous_bans']} previous bans")

        # Credential stuffing (multiple usernames)
        if behavior['unique_usernames'] >= 3:
            score += THREAT_SCORES['credential_stuffing']
            factors.append(f"Credential stuffing ({behavior['unique_usernames']} usernames)")

        # Velocity (many attempts in short time)
        if behavior['recent_attempts'] >= 10:
            score += THREAT_SCORES['brute_force_velocity']
            factors.append(f"High velocity ({behavior['recent_attempts']} attempts/5min)")

        # 4. Score based on event details
        username = event.get('username', '').lower()
        event_type = event.get('event_type', '')

        if username == 'root':
            score += THREAT_SCORES['root_attempt']
            factors.append('Root login attempt')

        if event_type == 'invalid_user':
            score += THREAT_SCORES['invalid_user']
            factors.append('Invalid username')

        # Time anomaly (off business hours: 22:00 - 06:00)
        hour = datetime.now().hour
        if hour < 6 or hour >= 22:
            score += THREAT_SCORES['time_anomaly']
            factors.append('Off-hours activity')

        # Cap score at 100
        score = min(score, 100)

        # Determine action
        result = self._determine_action(ip, score, factors)

        # Log the evaluation
        self._log_evaluation(ip, event, result)

        return result

    def _determine_action(self, ip: str, score: int, factors: List[str]) -> Dict:
        """Determine blocking action based on score."""

        if score >= BLOCK_THRESHOLD_UFW:
            # Critical threat - permanent UFW block
            success = self._block_via_ufw(ip, score, factors)
            return {
                'should_block': True,
                'block_method': 'ufw',
                'threat_score': score,
                'risk_level': 'critical',
                'factors': factors,
                'action_taken': 'Blocked via UFW (permanent)' if success else 'UFW block failed'
            }

        elif score >= BLOCK_THRESHOLD_FAIL2BAN:
            # High threat - extended fail2ban ban
            success = self._block_via_fail2ban(ip, score, factors, bantime=86400)  # 24h
            return {
                'should_block': True,
                'block_method': 'fail2ban',
                'threat_score': score,
                'risk_level': 'high',
                'factors': factors,
                'action_taken': 'Pre-emptive block via fail2ban (24h)' if success else 'Fail2ban block failed'
            }

        elif score >= WARNING_THRESHOLD:
            # Medium threat - warning only
            logging.warning(f"⚠️ Medium threat: {ip} (score={score}, factors={factors})")
            return {
                'should_block': False,
                'block_method': 'none',
                'threat_score': score,
                'risk_level': 'medium',
                'factors': factors,
                'action_taken': 'Warning logged - monitoring'
            }

        else:
            # Low threat - no action
            return {
                'should_block': False,
                'block_method': 'none',
                'threat_score': score,
                'risk_level': 'low',
                'factors': factors,
                'action_taken': 'No action - standard fail2ban handling'
            }

    def _get_enrichment(self, ip: str) -> Optional[Dict]:
        """Get enrichment data from cache or database."""
        # Check cache first (5 min TTL)
        cache_key = f"enrich_{ip}"
        if cache_key in self._cache:
            cached, timestamp = self._cache[cache_key]
            if datetime.now() - timestamp < timedelta(minutes=5):
                return cached

        conn = None
        cursor = None
        try:
            conn = get_connection()
            cursor = conn.cursor(dictionary=True)

            cursor.execute("""
                SELECT abuseipdb_score, virustotal_malicious, is_tor, is_vpn,
                       is_proxy, country_code, is_high_risk_country
                FROM ip_enrichment
                WHERE ip_address = %s
                  AND enriched_at >= NOW() - INTERVAL 24 HOUR
            """, (ip,))

            result = cursor.fetchone()

            if result:
                self._cache[cache_key] = (result, datetime.now())

            return result
        except Exception as e:
            logging.error(f"Error getting enrichment for {ip}: {e}")
            return None
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()

    def _analyze_behavior(self, ip: str, event: Dict) -> Dict:
        """Analyze behavioral patterns for this IP."""
        behavior = {
            'previous_bans': 0,
            'unique_usernames': 0,
            'recent_attempts': 0,
            'recent_failures': 0
        }

        conn = None
        cursor = None
        try:
            conn = get_connection()
            cursor = conn.cursor(dictionary=True)

            # Previous bans
            cursor.execute("""
                SELECT COUNT(*) as count FROM fail2ban_events
                WHERE ip_address = %s AND action = 'ban'
            """, (ip,))
            result = cursor.fetchone()
            behavior['previous_bans'] = result['count'] if result else 0

            # Unique usernames in last hour
            cursor.execute("""
                SELECT COUNT(DISTINCT username) as count FROM auth_events
                WHERE source_ip = %s AND timestamp >= NOW() - INTERVAL 1 HOUR
            """, (ip,))
            result = cursor.fetchone()
            behavior['unique_usernames'] = result['count'] if result else 0

            # Recent attempts (last 5 min)
            cursor.execute("""
                SELECT COUNT(*) as count FROM auth_events
                WHERE source_ip = %s AND timestamp >= NOW() - INTERVAL 5 MINUTE
            """, (ip,))
            result = cursor.fetchone()
            behavior['recent_attempts'] = result['count'] if result else 0

        except Exception as e:
            logging.error(f"Error analyzing behavior for {ip}: {e}")
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()

        return behavior

    def _block_via_ufw(self, ip: str, score: int, factors: List[str]) -> bool:
        """Block IP permanently via UFW."""
        try:
            from blocking.ip_operations import block_ip

            reason = f"Proactive block: score={score}, {', '.join(factors[:3])}"
            result = block_ip(
                ip_address=ip,
                block_reason=reason,
                block_source='rule_based',
                auto_unblock=False
            )

            if result.get('success'):
                logging.info(f"🛡️ PROACTIVE UFW BLOCK: {ip} (score={score})")
                return True
            return False

        except Exception as e:
            logging.error(f"Error blocking {ip} via UFW: {e}")
            return False

    def _block_via_fail2ban(self, ip: str, score: int, factors: List[str], bantime: int = 86400) -> bool:
        """Block IP via fail2ban with extended duration."""
        try:
            from blocking.ip_operations import block_ip

            reason = f"Proactive block: score={score}, {', '.join(factors[:3])}"
            result = block_ip(
                ip_address=ip,
                block_reason=reason,
                block_source='fail2ban',
                block_duration_minutes=bantime // 60,
                auto_unblock=True
            )

            if result.get('success'):
                logging.info(f"🛡️ PROACTIVE FAIL2BAN BLOCK: {ip} (score={score}, {bantime}s)")
                return True
            return False

        except Exception as e:
            logging.error(f"Error blocking {ip} via fail2ban: {e}")
            return False

    def _log_evaluation(self, ip: str, event: Dict, result: Dict):
        """Log the proactive evaluation."""
        conn = None
        cursor = None
        try:
            conn = get_connection()
            cursor = conn.cursor()

            cursor.execute("""
                INSERT INTO proactive_evaluations (
                    ip_address, username, event_type, threat_score,
                    risk_level, action_taken, factors_json, evaluated_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, NOW())
            """, (
                ip,
                event.get('username', ''),
                event.get('event_type', ''),
                result['threat_score'],
                result['risk_level'],
                result['action_taken'],
                str(result['factors'])
            ))

            conn.commit()
        except Exception as e:
            # Table might not exist yet
            pass
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()

    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private/local."""
        if ip.startswith('10.') or ip.startswith('192.168.') or ip.startswith('127.'):
            return True
        if ip.startswith('172.'):
            second_octet = int(ip.split('.')[1])
            if 16 <= second_octet <= 31:
                return True
        return False

    def _no_action_result(self) -> Dict:
        """Return a no-action result."""
        return {
            'should_block': False,
            'block_method': 'none',
            'threat_score': 0,
            'risk_level': 'low',
            'factors': [],
            'action_taken': 'No action'
        }


# Singleton instance
_blocker = None

def get_proactive_blocker() -> ProactiveBlocker:
    """Get singleton blocker instance."""
    global _blocker
    if _blocker is None:
        _blocker = ProactiveBlocker()
    return _blocker


def evaluate_auth_event(event: Dict) -> Dict:
    """
    Convenience function to evaluate an auth event.
    Call this from log_processor.py when events are received.
    """
    blocker = get_proactive_blocker()
    return blocker.evaluate_event(event)
