"""
SSH Guardian v3.0 - Fail2ban ML Evaluator
Analyzes fail2ban bans using ML and threat intelligence to determine:
1. Whether to auto-escalate to UFW permanent block
2. Optimal ban duration based on threat level
3. Threat scoring and recommendations
"""

import sys
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple

# Add project paths
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
sys.path.append(str(PROJECT_ROOT / "dbs"))
sys.path.append(str(PROJECT_ROOT / "src" / "core"))

from connection import get_connection

# Try to import enrichment
try:
    from enrichment import EventEnricher
except ImportError:
    EventEnricher = None

# Try to import blocking operations
try:
    from blocking.ip_operations import block_ip
except ImportError:
    block_ip = None


class Fail2banMLEvaluator:
    """
    Evaluates fail2ban bans using ML and threat intelligence.

    Threat Scoring Factors:
    - AbuseIPDB confidence score (0-100)
    - VirusTotal detections
    - Tor exit node status
    - VPN/Proxy detection
    - Geographic risk (high-risk countries)
    - Historical behavior (repeat offender)
    - Time anomaly (attacks during unusual hours)
    - Velocity (burst of attempts)
    """

    # Thresholds for auto-escalation
    AUTO_ESCALATE_SCORE = 75      # Auto-block via UFW if score >= this
    HIGH_RISK_SCORE = 50          # Extended ban duration
    REPEAT_OFFENDER_THRESHOLD = 3 # Auto-escalate after this many bans

    # Ban duration tiers (seconds)
    BAN_DURATION_LOW = 3600       # 1 hour - low risk
    BAN_DURATION_MEDIUM = 21600   # 6 hours - medium risk
    BAN_DURATION_HIGH = 86400     # 24 hours - high risk
    BAN_DURATION_PERMANENT = -1   # Escalate to UFW

    def __init__(self):
        self.enricher = EventEnricher() if EventEnricher else None

    def evaluate_ban(self, ip_address: str, failures: int = 0,
                     jail: str = 'sshd', agent_id: int = None) -> Dict:
        """
        Evaluate a fail2ban ban and determine appropriate response.

        Returns:
            {
                'threat_score': int (0-100),
                'risk_level': str ('low', 'medium', 'high', 'critical'),
                'recommended_action': str ('standard_ban', 'extended_ban', 'escalate_to_ufw'),
                'recommended_duration': int (seconds, -1 for permanent),
                'auto_escalated': bool,
                'factors': list of str,
                'analysis': dict (detailed analysis data)
            }
        """
        result = {
            'threat_score': 0,
            'risk_level': 'low',
            'recommended_action': 'standard_ban',
            'recommended_duration': self.BAN_DURATION_LOW,
            'auto_escalated': False,
            'factors': [],
            'analysis': {}
        }

        score = 0
        factors = []

        # 1. Check repeat offender status
        repeat_count = self._get_repeat_count(ip_address)
        if repeat_count >= self.REPEAT_OFFENDER_THRESHOLD:
            score += 30
            factors.append(f'Repeat offender ({repeat_count} previous bans)')
        elif repeat_count > 0:
            score += repeat_count * 8
            factors.append(f'{repeat_count} previous ban(s)')

        # 2. Factor in failure count
        if failures >= 10:
            score += 15
            factors.append(f'High failure count ({failures})')
        elif failures >= 5:
            score += 8
            factors.append(f'{failures} failures')

        # 3. Get enrichment data if available
        enrichment = self._get_enrichment(ip_address)
        if enrichment:
            result['analysis']['enrichment'] = enrichment

            # AbuseIPDB score
            abuse_score = enrichment.get('abuseipdb_score', 0)
            if abuse_score >= 80:
                score += 25
                factors.append(f'AbuseIPDB: {abuse_score}% (critical)')
            elif abuse_score >= 50:
                score += 15
                factors.append(f'AbuseIPDB: {abuse_score}% (high)')
            elif abuse_score >= 25:
                score += 8
                factors.append(f'AbuseIPDB: {abuse_score}%')

            # Tor exit node
            if enrichment.get('is_tor_exit'):
                score += 20
                factors.append('Tor exit node')

            # VPN/Proxy
            if enrichment.get('is_vpn') or enrichment.get('is_proxy'):
                score += 10
                factors.append('VPN/Proxy detected')

            # High-risk country
            if enrichment.get('is_high_risk_country'):
                score += 10
                factors.append(f"High-risk country: {enrichment.get('country', 'Unknown')}")

            # VirusTotal detections
            vt_detections = enrichment.get('virustotal_detections', 0)
            if vt_detections > 0:
                score += min(vt_detections * 5, 20)
                factors.append(f'VirusTotal: {vt_detections} detections')

        # 4. Time anomaly check
        if self._is_time_anomaly():
            score += 5
            factors.append('Unusual time pattern')

        # Cap score at 100
        score = min(score, 100)

        # Determine risk level and action
        if score >= self.AUTO_ESCALATE_SCORE:
            result['risk_level'] = 'critical'
            result['recommended_action'] = 'escalate_to_ufw'
            result['recommended_duration'] = self.BAN_DURATION_PERMANENT

            # Auto-escalate if enabled
            if self._should_auto_escalate(ip_address, score, repeat_count):
                escalated = self._escalate_to_ufw(ip_address, score, factors)
                result['auto_escalated'] = escalated
                if escalated:
                    factors.append('AUTO-ESCALATED to UFW')

        elif score >= self.HIGH_RISK_SCORE:
            result['risk_level'] = 'high'
            result['recommended_action'] = 'extended_ban'
            result['recommended_duration'] = self.BAN_DURATION_HIGH
        elif score >= 30:
            result['risk_level'] = 'medium'
            result['recommended_action'] = 'extended_ban'
            result['recommended_duration'] = self.BAN_DURATION_MEDIUM
        else:
            result['risk_level'] = 'low'
            result['recommended_action'] = 'standard_ban'
            result['recommended_duration'] = self.BAN_DURATION_LOW

        result['threat_score'] = score
        result['factors'] = factors

        # Log the evaluation
        self._log_evaluation(ip_address, result)

        return result

    def _get_repeat_count(self, ip_address: str) -> int:
        """Get number of times this IP has been banned before."""
        conn = None
        cursor = None
        try:
            conn = get_connection()
            cursor = conn.cursor(dictionary=True)

            cursor.execute("""
                SELECT COUNT(*) as count FROM fail2ban_events
                WHERE ip_address = %s AND action = 'ban'
            """, (ip_address,))

            result = cursor.fetchone()
            return result['count'] if result else 0
        except Exception as e:
            print(f"Error getting repeat count: {e}")
            return 0
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()

    def _get_enrichment(self, ip_address: str) -> Optional[Dict]:
        """Get enrichment data for IP."""
        if not self.enricher:
            return None

        conn = None
        cursor = None
        try:
            # Check cached enrichment first
            conn = get_connection()
            cursor = conn.cursor(dictionary=True)

            cursor.execute("""
                SELECT abuseipdb_score, abuseipdb_reports,
                       virustotal_malicious, is_tor, is_vpn, is_proxy,
                       country_code, is_high_risk_country
                FROM ip_enrichment
                WHERE ip_address = %s
                  AND enriched_at >= NOW() - INTERVAL 24 HOUR
            """, (ip_address,))

            cached = cursor.fetchone()

            if cached:
                return {
                    'abuseipdb_score': cached.get('abuseipdb_score', 0),
                    'abuseipdb_reports': cached.get('abuseipdb_reports', 0),
                    'virustotal_detections': cached.get('virustotal_malicious', 0),
                    'is_tor_exit': cached.get('is_tor', False),
                    'is_vpn': cached.get('is_vpn', False),
                    'is_proxy': cached.get('is_proxy', False),
                    'country': cached.get('country_code', 'Unknown'),
                    'is_high_risk_country': cached.get('is_high_risk_country', False)
                }

            # Trigger async enrichment for future lookups
            self.enricher.enrich_ip_background(ip_address)
            return None

        except Exception as e:
            print(f"Error getting enrichment: {e}")
            return None
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()

    def _is_time_anomaly(self) -> bool:
        """Check if current time is unusual for attacks (business hours)."""
        hour = datetime.now().hour
        # Most legitimate traffic is during business hours (8-18)
        # Attacks often happen during off-hours
        return hour < 6 or hour > 22

    def _should_auto_escalate(self, ip_address: str, score: int, repeat_count: int) -> bool:
        """Determine if IP should be auto-escalated to UFW."""
        # Auto-escalate if:
        # 1. Score is very high (>= 85)
        # 2. Repeat offender with high score
        # 3. Known bad actor indicators

        if score >= 85:
            return True

        if repeat_count >= self.REPEAT_OFFENDER_THRESHOLD and score >= 60:
            return True

        return False

    def _escalate_to_ufw(self, ip_address: str, score: int, factors: list) -> bool:
        """Escalate ban to permanent UFW block."""
        if not block_ip:
            print(f"Cannot escalate {ip_address} - block_ip not available")
            return False

        try:
            reason = f"Auto-escalated: score={score}, factors={', '.join(factors[:3])}"

            result = block_ip(
                ip_address=ip_address,
                block_reason=reason,
                block_source='rule_based',  # Mark as rule-based for UFW
                auto_unblock=False  # Permanent block
            )

            if result.get('success'):
                print(f"Auto-escalated {ip_address} to UFW (score={score})")
                return True
            else:
                print(f"Failed to escalate {ip_address}: {result.get('message')}")
                return False

        except Exception as e:
            print(f"Error escalating to UFW: {e}")
            return False

    def _log_evaluation(self, ip_address: str, result: Dict):
        """Log the ML evaluation for dashboard visibility."""
        conn = None
        cursor = None
        try:
            conn = get_connection()
            cursor = conn.cursor()

            # Store in a lightweight log table (create if not exists handled by migration)
            cursor.execute("""
                INSERT INTO fail2ban_ml_evaluations (
                    ip_address, threat_score, risk_level,
                    recommended_action, auto_escalated,
                    factors_json, evaluated_at
                ) VALUES (%s, %s, %s, %s, %s, %s, NOW())
            """, (
                ip_address,
                result['threat_score'],
                result['risk_level'],
                result['recommended_action'],
                result['auto_escalated'],
                str(result['factors'])
            ))

            conn.commit()
        except Exception as e:
            # Table might not exist - that's okay for now
            pass
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()


# Singleton instance
_evaluator = None

def get_evaluator() -> Fail2banMLEvaluator:
    """Get singleton evaluator instance."""
    global _evaluator
    if _evaluator is None:
        _evaluator = Fail2banMLEvaluator()
    return _evaluator


def evaluate_fail2ban_ban(ip_address: str, failures: int = 0,
                          jail: str = 'sshd', agent_id: int = None) -> Dict:
    """
    Convenience function to evaluate a fail2ban ban.
    Called from fail2ban.py when a ban is received.
    """
    evaluator = get_evaluator()
    return evaluator.evaluate_ban(ip_address, failures, jail, agent_id)
