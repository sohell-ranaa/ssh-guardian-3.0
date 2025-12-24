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
import json
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, Optional, List, Tuple
import logging

# Add project paths
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
sys.path.append(str(PROJECT_ROOT / "dbs"))
sys.path.append(str(PROJECT_ROOT / "src" / "core"))

from connection import get_connection

# Import unified ThreatEvaluator
try:
    from threat_evaluator import evaluate_ip_threat
    THREAT_EVALUATOR_AVAILABLE = True
except ImportError:
    THREAT_EVALUATOR_AVAILABLE = False

# Import BehavioralAnalyzer for ML-first blocking
try:
    from behavioral_analyzer import BehavioralAnalyzer
    BEHAVIORAL_ANALYZER_AVAILABLE = True
except ImportError:
    BEHAVIORAL_ANALYZER_AVAILABLE = False

# Configuration
PROACTIVE_BLOCKING_ENABLED = True  # Master switch
BLOCK_THRESHOLD_UFW = 80           # Score >= this → permanent UFW block
BLOCK_THRESHOLD_FAIL2BAN = 60      # Score >= this → extended fail2ban ban
WARNING_THRESHOLD = 30             # Score >= this → log warning
USE_UNIFIED_EVALUATOR = True       # Use ThreatEvaluator for scoring
USE_BEHAVIORAL_ANALYZER = True     # Prioritize ML behavioral analysis

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
    'greynoise_scanner': 15,       # GreyNoise noise=True (known internet scanner)
    'greynoise_benign': -20,       # GreyNoise riot=True (known benign service - reduces score)
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

        # Skip private IPs early
        if self._is_private_ip(ip):
            return self._no_action_result()

        # PRIORITY: ML Behavioral Analysis first (most advanced detection)
        if USE_BEHAVIORAL_ANALYZER and BEHAVIORAL_ANALYZER_AVAILABLE:
            behavioral_result = self._evaluate_with_behavioral_analyzer(ip, event)
            if behavioral_result.get('should_block'):
                return behavioral_result

        # Use unified ThreatEvaluator if available
        if USE_UNIFIED_EVALUATOR and THREAT_EVALUATOR_AVAILABLE:
            return self._evaluate_with_unified(ip, event)

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

            # GreyNoise - Known scanner (adds to threat score)
            if enrichment.get('greynoise_noise'):
                score += THREAT_SCORES['greynoise_scanner']
                factors.append('GreyNoise: Known internet scanner')

            # GreyNoise - Benign service (reduces threat score)
            if enrichment.get('greynoise_riot'):
                score += THREAT_SCORES['greynoise_benign']  # This is negative
                factors.append('GreyNoise: Benign service (reduced threat)')

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

    def _evaluate_with_behavioral_analyzer(self, ip: str, event: Dict) -> Dict:
        """
        PRIORITY ML evaluation using BehavioralAnalyzer.

        This method runs FIRST and can short-circuit to block high-risk threats
        based on behavioral patterns that rule-based systems can't detect:
        - Impossible travel
        - Credential stuffing
        - Success after brute force
        - Unusual login times/locations for specific users

        Decision Matrix for Behavioral Analysis:
        ┌─────────────────────────────────────────────────────────────────────┐
        │  Behavioral Score │  Action                                         │
        ├─────────────────────────────────────────────────────────────────────┤
        │  80-100 + priority│  IMMEDIATE UFW BLOCK (permanent)                │
        │  60-79            │  EXTENDED FAIL2BAN BLOCK (48h)                  │
        │  40-59            │  STANDARD FAIL2BAN BLOCK (24h)                  │
        │  0-39             │  Pass to next evaluator (ThreatEvaluator)       │
        └─────────────────────────────────────────────────────────────────────┘
        """
        try:
            username = event.get('username')
            event_type = event.get('event_type', 'failed')

            if not username:
                # Can't do behavioral analysis without username
                return {'should_block': False}

            # Get geo data for the IP
            geo_data = self._get_geo_for_behavioral(ip)

            # Run behavioral analysis
            analyzer = BehavioralAnalyzer()
            analysis = analyzer.analyze(
                ip_address=ip,
                username=username,
                event_type=event_type,
                current_geo=geo_data,
                timestamp=datetime.now()
            )

            risk_score = analysis.get('risk_score', 0)
            confidence = analysis.get('confidence', 0.5)
            risk_factors = analysis.get('risk_factors', [])
            recommendations = analysis.get('recommendations', [])

            # Check for priority factors (immediate block regardless of total score)
            # Note: impossible_travel removed - it should contribute to score, not auto-block
            # (user could be using VPN, legitimate travel, etc.)
            priority_types = ['credential_stuffing', 'brute_force']
            detected_types = [f.get('type') for f in risk_factors]
            has_priority_factor = any(pt in detected_types for pt in priority_types)

            # Build human-readable factors list
            factor_descriptions = [
                f"{f.get('title', f.get('type'))}: +{f.get('score', 0)}"
                for f in risk_factors[:5]
            ]

            # Determine action based on behavioral score
            if risk_score >= 80 or (has_priority_factor and risk_score >= 60):
                # CRITICAL: Permanent UFW block
                success = self._block_via_ufw(ip, risk_score, factor_descriptions)
                result = {
                    'should_block': True,
                    'block_method': 'ufw',
                    'threat_score': risk_score,
                    'risk_level': 'critical',
                    'factors': factor_descriptions,
                    'action_taken': 'ML BEHAVIORAL: Permanent UFW block' if success else 'UFW block failed',
                    'ml_analysis': {
                        'source': 'BehavioralAnalyzer',
                        'risk_factors': risk_factors,
                        'recommendations': recommendations,
                        'confidence': confidence,
                        'has_priority_factor': has_priority_factor,
                        'detected_types': detected_types
                    }
                }
                self._log_evaluation(ip, event, result)
                self._create_notification(
                    ip, risk_score, factor_descriptions, 'ufw',
                    f"ML Behavioral: {ip} blocked permanently (score: {risk_score})"
                )
                return result

            elif risk_score >= 60:
                # HIGH: Extended fail2ban block (48h)
                success = self._block_via_fail2ban(ip, risk_score, factor_descriptions, bantime=172800)
                result = {
                    'should_block': True,
                    'block_method': 'fail2ban',
                    'threat_score': risk_score,
                    'risk_level': 'high',
                    'factors': factor_descriptions,
                    'action_taken': 'ML BEHAVIORAL: Extended fail2ban block (48h)' if success else 'Block failed',
                    'ml_analysis': {
                        'source': 'BehavioralAnalyzer',
                        'risk_factors': risk_factors,
                        'recommendations': recommendations,
                        'confidence': confidence
                    }
                }
                self._log_evaluation(ip, event, result)
                return result

            elif risk_score >= 40:
                # MEDIUM (40-59): Alert only - no blocking
                # This score range indicates suspicious but not confirmed threat
                # Skip alert for clean IPs (AbuseIPDB < 20) - likely ML false positive
                enrichment = self._get_enrichment(ip)
                abuseipdb_score = enrichment.get('abuseipdb_score') if enrichment else None
                is_clean_ip = abuseipdb_score is not None and abuseipdb_score < 20

                if is_clean_ip:
                    print(f"⏭️  Skipping medium-risk alert for clean IP {ip} (AbuseIPDB: {abuseipdb_score}, behavioral: {risk_score})")
                else:
                    try:
                        from .alert_operations import create_security_alert
                        create_security_alert(
                            ip_address=ip,
                            alert_type='behavioral_anomaly',
                            title=f'Medium Risk Activity Detected (score: {risk_score})',
                            description=f"Behavioral analysis detected medium-risk activity. Factors: {', '.join(factor_descriptions[:3])}",
                            severity='medium',
                            username=event.get('target_username'),
                            ml_score=int(risk_score),
                            ml_factors=risk_factors[:5]
                        )
                    except Exception as alert_err:
                        print(f"Failed to create medium-risk alert: {alert_err}")

                result = {
                    'should_block': False,  # Changed: Don't block at 40-59
                    'block_method': 'none',
                    'threat_score': risk_score,
                    'risk_level': 'medium',
                    'factors': factor_descriptions,
                    'action_taken': 'ML BEHAVIORAL: Alert created (monitoring)',
                    'ml_analysis': {
                        'source': 'BehavioralAnalyzer',
                        'risk_factors': risk_factors,
                        'recommendations': recommendations,
                        'confidence': confidence
                    }
                }
                self._log_evaluation(ip, event, result)
                return result

            # Below 40: Low risk - create alert only if notable factors exist
            if risk_score >= 20 and risk_factors:
                # Import alert_operations to create behavioral alert
                try:
                    from .alert_operations import create_security_alert

                    # Get username from event
                    username = event.get('username', 'unknown')

                    # Determine alert type from factors
                    alert_type = 'behavioral_anomaly'
                    for factor in risk_factors:
                        factor_type = factor.get('type', '')
                        if factor_type in ['unusual_time', 'new_location', 'new_ip', 'weekend_login']:
                            alert_type = factor_type
                            break

                    # Get geo data for the alert
                    geo_data = self._get_geo_for_behavioral(ip)

                    create_security_alert(
                        ip_address=ip,
                        alert_type=alert_type,
                        title=f"Behavioral Anomaly Detected",
                        description=f"User: {username}\nAnomaly Score: {risk_score}/100\n\nFactors:\n" + "; ".join(factor_descriptions),
                        severity='medium' if risk_score >= 30 else 'low',
                        username=username,
                        ml_score=risk_score,
                        ml_factors=factor_descriptions,
                        geo_data=geo_data
                    )
                    print(f"  [ML Behavioral] Alert created for {ip} (score: {risk_score})")
                except Exception as alert_err:
                    print(f"  [ML Behavioral] Warning: Could not create alert: {alert_err}")

            # Pass to next evaluator (no block)
            return {
                'should_block': False,
                'threat_score': risk_score,
                'ml_analysis': {
                    'source': 'BehavioralAnalyzer',
                    'risk_factors': risk_factors,
                    'confidence': confidence
                }
            }

        except Exception as e:
            logging.error(f"[ProactiveBlocker] Behavioral analysis error: {e}")
            return {'should_block': False}

    def _get_geo_for_behavioral(self, ip: str) -> Optional[Dict]:
        """Get geo data for behavioral analysis."""
        conn = None
        cursor = None
        try:
            conn = get_connection()
            cursor = conn.cursor(dictionary=True)
            cursor.execute("""
                SELECT latitude, longitude, country_code, country_name, city
                FROM ip_geolocation
                WHERE ip_address_text = %s
            """, (ip,))
            return cursor.fetchone()
        except Exception as e:
            logging.error(f"Error getting geo for {ip}: {e}")
            return None
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()

    def _evaluate_with_unified(self, ip: str, event: Dict) -> Dict:
        """
        Use unified ThreatEvaluator for comprehensive scoring.
        This combines ML, threat intel, behavioral, network, and geo analysis.
        """
        try:
            # Build event context for evaluator
            event_context = {
                'username': event.get('username'),
                'status': event.get('event_type'),
                'timestamp': event.get('timestamp'),
            }

            # Run unified evaluation
            evaluation = evaluate_ip_threat(ip, event_context)

            score = evaluation.get('composite_score', 0)
            risk_level = evaluation.get('risk_level', 'low')
            factors = evaluation.get('factors', [])
            recommended_action = evaluation.get('recommended_action', 'allow')

            # Determine blocking action based on unified score
            if score >= BLOCK_THRESHOLD_UFW:
                success = self._block_via_ufw(ip, score, factors)
                return {
                    'should_block': True,
                    'block_method': 'ufw',
                    'threat_score': score,
                    'risk_level': risk_level,
                    'factors': factors,
                    'action_taken': 'Blocked via UFW (permanent)' if success else 'UFW block failed',
                    'evaluation': evaluation
                }

            elif score >= BLOCK_THRESHOLD_FAIL2BAN:
                success = self._block_via_fail2ban(ip, score, factors, bantime=86400)
                return {
                    'should_block': True,
                    'block_method': 'fail2ban',
                    'threat_score': score,
                    'risk_level': risk_level,
                    'factors': factors,
                    'action_taken': 'Pre-emptive block via fail2ban (24h)' if success else 'Fail2ban block failed',
                    'evaluation': evaluation
                }

            elif score >= WARNING_THRESHOLD:
                logging.warning(f"⚠️ Medium threat: {ip} (score={score})")
                return {
                    'should_block': False,
                    'block_method': 'none',
                    'threat_score': score,
                    'risk_level': risk_level,
                    'factors': factors,
                    'action_taken': 'Warning logged - monitoring',
                    'evaluation': evaluation
                }

            else:
                return {
                    'should_block': False,
                    'block_method': 'none',
                    'threat_score': score,
                    'risk_level': risk_level,
                    'factors': factors,
                    'action_taken': 'No action - standard fail2ban handling',
                    'evaluation': evaluation
                }

        except Exception as e:
            logging.error(f"[ProactiveBlocker] Unified evaluation error: {e}")
            # Fall back to legacy scoring
            return self._legacy_evaluate(ip, event)

    def _legacy_evaluate(self, ip: str, event: Dict) -> Dict:
        """Legacy scoring method as fallback."""
        # Skip private IPs
        if self._is_private_ip(ip):
            return self._no_action_result()

        score = 0
        factors = []

        # Basic enrichment check
        enrichment = self._get_enrichment(ip)
        if enrichment:
            abuse_score = enrichment.get('abuseipdb_score', 0)
            if abuse_score >= 80:
                score += 30
                factors.append(f'AbuseIPDB: {abuse_score}%')
            if enrichment.get('is_tor'):
                score += 25
                factors.append('Tor exit node')

        result = self._determine_action(ip, score, factors)
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

            # Query from ip_geolocation table (v3.1 schema) with GreyNoise fields
            cursor.execute("""
                SELECT abuseipdb_score, virustotal_positives as virustotal_malicious,
                       is_tor, is_vpn, is_proxy, country_code,
                       CASE WHEN country_code IN ('CN', 'RU', 'KP', 'IR', 'VN', 'IN', 'BR', 'PK', 'ID', 'NG')
                            THEN 1 ELSE 0 END as is_high_risk_country,
                       greynoise_noise, greynoise_riot, greynoise_classification
                FROM ip_geolocation
                WHERE ip_address_text = %s
                  AND last_seen >= NOW() - INTERVAL 24 HOUR
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

            # Previous bans (event_type = 'ban' in current schema)
            cursor.execute("""
                SELECT COUNT(*) as count FROM fail2ban_events
                WHERE ip_address = %s AND event_type = 'ban'
            """, (ip,))
            result = cursor.fetchone()
            behavior['previous_bans'] = result['count'] if result else 0

            # Unique usernames in last hour (check both possible column names)
            try:
                cursor.execute("""
                    SELECT COUNT(DISTINCT COALESCE(username, target_username)) as count FROM auth_events
                    WHERE source_ip_text = %s AND timestamp >= NOW() - INTERVAL 1 HOUR
                """, (ip,))
                result = cursor.fetchone()
                behavior['unique_usernames'] = result['count'] if result else 0
            except:
                behavior['unique_usernames'] = 0

            # Recent attempts (last 5 min)
            try:
                cursor.execute("""
                    SELECT COUNT(*) as count FROM auth_events
                    WHERE source_ip_text = %s AND timestamp >= NOW() - INTERVAL 5 MINUTE
                """, (ip,))
                result = cursor.fetchone()
                behavior['recent_attempts'] = result['count'] if result else 0
            except:
                behavior['recent_attempts'] = 0

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
                # Create notification for auto-block
                self._create_notification(
                    ip, score, factors, 'ufw',
                    f"Auto-blocked {ip} via UFW (score: {score})"
                )
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
                # Create notification for auto-block
                self._create_notification(
                    ip, score, factors, 'fail2ban',
                    f"Auto-blocked {ip} via Fail2ban for {bantime//3600}h (score: {score})"
                )
                return True
            return False

        except Exception as e:
            logging.error(f"Error blocking {ip} via fail2ban: {e}")
            return False

    def _create_notification(self, ip: str, score: int, factors: List[str], method: str, message: str):
        """Create a notification for auto-blocking action."""
        import uuid as uuid_module
        conn = None
        cursor = None
        try:
            conn = get_connection()
            cursor = conn.cursor()

            priority = 'critical' if method == 'ufw' else 'high'
            notification_uuid = str(uuid_module.uuid4())

            cursor.execute("""
                INSERT INTO notifications (
                    notification_uuid, trigger_type, message_title, message_body,
                    message_format, priority, status, channels, created_at
                ) VALUES (%s, %s, %s, %s, %s, %s, 'pending', '["dashboard"]', NOW())
            """, (
                notification_uuid,
                'auto_block',
                f"Auto-Block: {ip}",
                json.dumps({
                    'message': message,
                    'ip_address': ip,
                    'threat_score': score,
                    'factors': factors[:5],
                    'block_method': method
                }),
                'json',
                priority
            ))

            conn.commit()
            logging.info(f"📢 Notification created for auto-block: {ip}")

        except Exception as e:
            logging.error(f"Error creating notification: {e}")
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()

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
