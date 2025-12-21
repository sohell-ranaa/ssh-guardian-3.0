"""
SSH Guardian v3.0 - Auto Trust Learner
Automatically learns and trusts IPs/networks based on login patterns.
"""

import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import ipaddress

PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.append(str(PROJECT_ROOT / "dbs"))

from connection import get_connection


class AutoTrustLearner:
    """
    Automatically learns trusted IPs and networks from login patterns.

    Trust criteria:
    - Minimum successful logins
    - Minimum days of activity
    - Low failure rate
    - Consistent user(s)
    """

    # Thresholds for auto-trust (relaxed for practical use)
    MIN_SUCCESSFUL_LOGINS = 3      # At least 3 successful logins
    MIN_DAYS_ACTIVE = 1            # Active for at least 1 day
    MAX_FAILURE_RATE = 0.3         # Less than 30% failure rate
    TRUST_SCORE_THRESHOLD = 50     # Score >= 50 to auto-trust

    # Network aggregation
    MIN_IPS_FOR_NETWORK = 2        # At least 2 IPs from same /24 to trust network

    def __init__(self, verbose: bool = False):
        self.verbose = verbose

    def _log(self, msg: str):
        if self.verbose:
            print(f"[AutoTrust] {msg}")

    def calculate_trust_score(self, ip_stats: Dict) -> float:
        """
        Calculate trust score (0-100) based on IP statistics.

        Factors:
        - Successful login count (max 30 points)
        - Days active (max 25 points)
        - Failure rate (max 25 points)
        - User consistency (max 20 points)
        """
        score = 0.0

        successful = ip_stats.get('successful_logins', 0)
        failed = ip_stats.get('failed_logins', 0)
        days_active = ip_stats.get('days_active', 0)
        unique_users = ip_stats.get('unique_users', 1)
        total = successful + failed

        # Successful logins (max 30 points)
        # 5 logins = 10 points, 10 = 20, 20+ = 30
        if successful >= 20:
            score += 30
        elif successful >= 10:
            score += 20
        elif successful >= 5:
            score += 10
        elif successful >= 3:
            score += 5

        # Days active (max 25 points)
        # 3 days = 10, 7 days = 15, 14+ days = 25
        if days_active >= 14:
            score += 25
        elif days_active >= 7:
            score += 15
        elif days_active >= 3:
            score += 10
        elif days_active >= 1:
            score += 5

        # Low failure rate (max 25 points)
        # 0% = 25, <5% = 20, <10% = 15, <20% = 10
        if total > 0:
            failure_rate = failed / total
            if failure_rate == 0:
                score += 25
            elif failure_rate < 0.05:
                score += 20
            elif failure_rate < 0.10:
                score += 15
            elif failure_rate < 0.20:
                score += 10
        else:
            score += 25  # No data = assume good

        # User consistency (max 20 points)
        # 1 user = 20, 2 users = 15, 3+ users = 10
        # (Multiple users from same IP could be shared workstation - still trusted)
        if unique_users == 1:
            score += 20
        elif unique_users == 2:
            score += 15
        elif unique_users <= 5:
            score += 10
        else:
            score += 5  # Many users - less trusted but not zero

        return min(100.0, score)

    def analyze_ip(self, ip_address: str) -> Dict:
        """Analyze an IP address and return trust statistics."""
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            # Get login statistics for this IP
            cursor.execute("""
                SELECT
                    COUNT(*) as total_events,
                    SUM(event_type = 'successful') as successful_logins,
                    SUM(event_type = 'failed') as failed_logins,
                    COUNT(DISTINCT target_username) as unique_users,
                    COUNT(DISTINCT DATE(timestamp)) as days_active,
                    MIN(timestamp) as first_seen,
                    MAX(timestamp) as last_seen,
                    GROUP_CONCAT(DISTINCT target_username) as usernames
                FROM auth_events
                WHERE source_ip_text = %s
                AND timestamp >= DATE_SUB(NOW(), INTERVAL 30 DAY)
            """, (ip_address,))

            stats = cursor.fetchone()

            if not stats or stats['total_events'] == 0:
                return {
                    'ip_address': ip_address,
                    'successful_logins': 0,
                    'failed_logins': 0,
                    'unique_users': 0,
                    'days_active': 0,
                    'trust_score': 0,
                    'should_trust': False
                }

            result = {
                'ip_address': ip_address,
                'successful_logins': stats['successful_logins'] or 0,
                'failed_logins': stats['failed_logins'] or 0,
                'unique_users': stats['unique_users'] or 0,
                'days_active': stats['days_active'] or 0,
                'first_seen': stats['first_seen'],
                'last_seen': stats['last_seen'],
                'usernames': stats['usernames']
            }

            # Calculate trust score
            result['trust_score'] = self.calculate_trust_score(result)

            # Determine if should auto-trust
            result['should_trust'] = (
                result['trust_score'] >= self.TRUST_SCORE_THRESHOLD and
                result['successful_logins'] >= self.MIN_SUCCESSFUL_LOGINS and
                result['days_active'] >= self.MIN_DAYS_ACTIVE
            )

            return result

        finally:
            cursor.close()
            conn.close()

    def update_trusted_source(self, ip_address: str, stats: Dict) -> bool:
        """Update or create trusted_sources record for an IP."""
        conn = get_connection()
        cursor = conn.cursor()

        try:
            # Check if already exists
            cursor.execute(
                "SELECT id, is_manually_trusted FROM trusted_sources WHERE ip_address = %s",
                (ip_address,)
            )
            existing = cursor.fetchone()

            trust_score = stats['trust_score']
            should_trust = stats['should_trust']

            if existing:
                # Don't override manual trust
                if existing[1]:  # is_manually_trusted
                    return True

                cursor.execute("""
                    UPDATE trusted_sources SET
                        trust_score = %s,
                        successful_logins = %s,
                        failed_logins = %s,
                        unique_users = %s,
                        days_active = %s,
                        first_seen_at = %s,
                        last_seen_at = %s,
                        is_auto_trusted = %s,
                        trusted_at = IF(%s AND trusted_at IS NULL, NOW(), trusted_at),
                        trust_reason = IF(%s, 'Auto-learned from login patterns', trust_reason)
                    WHERE ip_address = %s
                """, (
                    trust_score,
                    stats['successful_logins'],
                    stats['failed_logins'],
                    stats['unique_users'],
                    stats['days_active'],
                    stats.get('first_seen'),
                    stats.get('last_seen'),
                    should_trust,
                    should_trust,
                    should_trust,
                    ip_address
                ))
            else:
                cursor.execute("""
                    INSERT INTO trusted_sources (
                        source_type, ip_address, trust_score,
                        successful_logins, failed_logins, unique_users,
                        days_active, first_seen_at, last_seen_at,
                        is_auto_trusted, trusted_at, trust_reason
                    ) VALUES (
                        'ip', %s, %s, %s, %s, %s, %s, %s, %s, %s,
                        IF(%s, NOW(), NULL),
                        IF(%s, 'Auto-learned from login patterns', NULL)
                    )
                """, (
                    ip_address, trust_score,
                    stats['successful_logins'], stats['failed_logins'],
                    stats['unique_users'], stats['days_active'],
                    stats.get('first_seen'), stats.get('last_seen'),
                    should_trust, should_trust, should_trust
                ))

            conn.commit()
            self._log(f"Updated trust for {ip_address}: score={trust_score:.1f}, trusted={should_trust}")
            return True

        except Exception as e:
            conn.rollback()
            self._log(f"Error updating trust for {ip_address}: {e}")
            return False
        finally:
            cursor.close()
            conn.close()

    def detect_trusted_networks(self) -> List[Dict]:
        """
        Detect networks where multiple IPs are trusted.
        If 2+ IPs from same /24 are trusted, trust the whole /24.
        """
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        networks_to_trust = []

        try:
            # Get all trusted IPs
            cursor.execute("""
                SELECT ip_address, trust_score
                FROM trusted_sources
                WHERE source_type = 'ip'
                AND is_auto_trusted = TRUE
                AND ip_address IS NOT NULL
            """)

            trusted_ips = cursor.fetchall()

            # Group by /24 network
            network_ips = {}
            for row in trusted_ips:
                try:
                    ip = ipaddress.ip_address(row['ip_address'])
                    if ip.version == 4:
                        network = ipaddress.ip_network(f"{ip}/24", strict=False)
                        network_str = str(network)
                        if network_str not in network_ips:
                            network_ips[network_str] = []
                        network_ips[network_str].append({
                            'ip': row['ip_address'],
                            'score': row['trust_score']
                        })
                except ValueError:
                    continue

            # Check which networks qualify
            for network_cidr, ips in network_ips.items():
                if len(ips) >= self.MIN_IPS_FOR_NETWORK:
                    avg_score = sum(ip['score'] for ip in ips) / len(ips)
                    networks_to_trust.append({
                        'network_cidr': network_cidr,
                        'ip_count': len(ips),
                        'avg_trust_score': avg_score,
                        'ips': [ip['ip'] for ip in ips]
                    })

            # Add trusted networks to database
            for network in networks_to_trust:
                cursor.execute("""
                    INSERT INTO trusted_sources (
                        source_type, network_cidr, trust_score,
                        is_auto_trusted, trusted_at, trust_reason
                    ) VALUES ('network', %s, %s, TRUE, NOW(), %s)
                    ON DUPLICATE KEY UPDATE
                        trust_score = VALUES(trust_score),
                        is_auto_trusted = TRUE,
                        trust_reason = VALUES(trust_reason)
                """, (
                    network['network_cidr'],
                    network['avg_trust_score'],
                    f"Auto-learned: {network['ip_count']} trusted IPs in this network"
                ))

            conn.commit()
            return networks_to_trust

        finally:
            cursor.close()
            conn.close()

    def is_trusted(self, ip_address: str) -> Tuple[bool, Optional[str]]:
        """
        Check if an IP is trusted (directly or via network).

        Returns:
            (is_trusted, reason)
        """
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            # Check direct IP trust
            cursor.execute("""
                SELECT trust_score, trust_reason, is_auto_trusted, is_manually_trusted
                FROM trusted_sources
                WHERE source_type = 'ip' AND ip_address = %s
                AND (is_auto_trusted = TRUE OR is_manually_trusted = TRUE)
            """, (ip_address,))

            direct = cursor.fetchone()
            if direct:
                reason = "manually trusted" if direct['is_manually_trusted'] else "auto-trusted"
                return True, f"IP {reason}: {direct['trust_reason']}"

            # Check network trust
            try:
                ip = ipaddress.ip_address(ip_address)
                if ip.version == 4:
                    # Check /24 network
                    network_24 = str(ipaddress.ip_network(f"{ip}/24", strict=False))
                    cursor.execute("""
                        SELECT trust_score, trust_reason
                        FROM trusted_sources
                        WHERE source_type = 'network' AND network_cidr = %s
                        AND (is_auto_trusted = TRUE OR is_manually_trusted = TRUE)
                    """, (network_24,))

                    network = cursor.fetchone()
                    if network:
                        return True, f"Network trusted: {network['trust_reason']}"
            except ValueError:
                pass

            return False, None

        finally:
            cursor.close()
            conn.close()

    def learn_from_all_events(self) -> Dict:
        """
        Analyze all IPs with successful logins and update trust scores.
        Run this periodically to keep trust database updated.
        """
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        results = {
            'ips_analyzed': 0,
            'newly_trusted': 0,
            'networks_trusted': 0,
            'errors': 0
        }

        try:
            # Get all IPs with successful logins in last 30 days
            cursor.execute("""
                SELECT DISTINCT source_ip_text as ip_address
                FROM auth_events
                WHERE event_type = 'successful'
                AND timestamp >= DATE_SUB(NOW(), INTERVAL 30 DAY)
                AND source_ip_text IS NOT NULL
                AND source_ip_text != ''
            """)

            ips = cursor.fetchall()
            cursor.close()
            conn.close()

            for row in ips:
                ip = row['ip_address']
                try:
                    # Analyze IP
                    stats = self.analyze_ip(ip)
                    results['ips_analyzed'] += 1

                    # Check if newly trusted
                    was_trusted, _ = self.is_trusted(ip)

                    # Update database
                    self.update_trusted_source(ip, stats)

                    # Check if now trusted
                    if not was_trusted and stats['should_trust']:
                        results['newly_trusted'] += 1
                        self._log(f"Newly trusted: {ip} (score={stats['trust_score']:.1f})")

                except Exception as e:
                    results['errors'] += 1
                    self._log(f"Error analyzing {ip}: {e}")

            # Detect and trust networks
            networks = self.detect_trusted_networks()
            results['networks_trusted'] = len(networks)
            for net in networks:
                self._log(f"Trusted network: {net['network_cidr']} ({net['ip_count']} IPs)")

            return results

        except Exception as e:
            self._log(f"Error in learn_from_all_events: {e}")
            results['errors'] += 1
            return results


def is_ip_trusted(ip_address: str) -> Tuple[bool, Optional[str]]:
    """Convenience function to check if IP is trusted."""
    learner = AutoTrustLearner()
    return learner.is_trusted(ip_address)


def run_trust_learning(verbose: bool = True) -> Dict:
    """Run the trust learning process."""
    learner = AutoTrustLearner(verbose=verbose)
    return learner.learn_from_all_events()
