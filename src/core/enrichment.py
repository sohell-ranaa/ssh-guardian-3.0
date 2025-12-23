"""
SSH Guardian v3.0 - Event Enrichment Pipeline
Unified enrichment for all events (GeoIP, Threat Intel, ML Prediction)
"""

import sys
from pathlib import Path
from typing import Dict, Optional, List, Tuple
from datetime import datetime

# Add project paths
PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.append(str(PROJECT_ROOT / "dbs"))
sys.path.append(str(PROJECT_ROOT / "src"))

from connection import get_connection

# Notification thresholds
HIGH_RISK_THRESHOLD = 70  # ML risk score threshold for high_risk_detected (realistic: prevents noise)
BEHAVIORAL_ANOMALY_THRESHOLD = 60  # Behavioral anomaly score threshold for notifications
ANOMALY_NOTIFICATION = True  # Send notification when ML anomaly detected

# Risk score adjustments (tuned for realistic alerting)
NIGHT_TIME_RISK_BOOST = 10  # +10 for logins between 10PM-6AM (reduced from 20)
HIGH_RISK_COUNTRY_BOOST = 20  # +20 for high-risk countries on first fail (reduced from 25)
VPN_PROXY_RISK_BOOST = 10  # +10 for VPN/proxy IPs (reduced from 15)

# High-risk countries
HIGH_RISK_COUNTRIES = {'CN', 'RU', 'KP', 'IR', 'BY'}

# Night time hours (10PM - 6AM)
NIGHT_START_HOUR = 22  # 10 PM
NIGHT_END_HOUR = 6     # 6 AM


def is_night_time(timestamp: datetime = None) -> bool:
    """Check if the given timestamp (or current time) is during night hours (10PM-6AM)"""
    if timestamp is None:
        timestamp = datetime.now()
    hour = timestamp.hour
    return hour >= NIGHT_START_HOUR or hour < NIGHT_END_HOUR


def calculate_risk_adjustments(
    geo_data: Optional[Dict],
    event_type: str,
    timestamp: datetime = None
) -> Tuple[int, List[str]]:
    """
    Calculate risk score adjustments based on contextual factors.

    Args:
        geo_data: Geolocation data dict
        event_type: 'failed' or 'successful'
        timestamp: Event timestamp (defaults to now)

    Returns:
        Tuple of (total_adjustment, list of reasons)
    """
    adjustment = 0
    reasons = []

    # Night-time adjustment (+20)
    if is_night_time(timestamp):
        adjustment += NIGHT_TIME_RISK_BOOST
        reasons.append(f"night_time_login:+{NIGHT_TIME_RISK_BOOST}")

    if geo_data:
        country_code = geo_data.get('country_code')

        # High-risk country adjustment (+25 on first fail)
        if country_code in HIGH_RISK_COUNTRIES and event_type == 'failed':
            adjustment += HIGH_RISK_COUNTRY_BOOST
            reasons.append(f"high_risk_country_{country_code}:+{HIGH_RISK_COUNTRY_BOOST}")

        # VPN/Proxy adjustment (+15)
        is_vpn = geo_data.get('is_vpn', False)
        is_proxy = geo_data.get('is_proxy', False)
        is_datacenter = geo_data.get('is_datacenter', False)
        if is_vpn or is_proxy or is_datacenter:
            adjustment += VPN_PROXY_RISK_BOOST
            network_type = 'vpn' if is_vpn else ('proxy' if is_proxy else 'datacenter')
            reasons.append(f"{network_type}_detected:+{VPN_PROXY_RISK_BOOST}")

    return adjustment, reasons


class EventEnricher:
    """
    Unified event enrichment pipeline.
    Processes events through GeoIP, ML Prediction, and Threat Intelligence.
    """

    def __init__(self, verbose: bool = True):
        """
        Initialize the event enricher.

        Args:
            verbose: Whether to print progress messages
        """
        self.verbose = verbose
        self._geoip_module = None
        self._threat_intel_module = None
        self._ml_manager = None
        self._notification_module = None
        self._behavioral_scorer = None
        self._behavioral_learner = None

    def _log(self, message: str):
        """Print message if verbose mode enabled"""
        if self.verbose:
            print(message)

    def _get_geoip_module(self):
        """Lazy load GeoIP module"""
        if self._geoip_module is None:
            try:
                from core.geoip import enrich_event as geoip_enrich
                self._geoip_module = geoip_enrich
            except ImportError:
                self._log("⚠️  GeoIP module not available")
                self._geoip_module = False
        return self._geoip_module

    def _get_threat_intel_module(self):
        """Lazy load Threat Intelligence module"""
        if self._threat_intel_module is None:
            try:
                from core.threat_intel import check_ip_threat
                self._threat_intel_module = check_ip_threat
            except ImportError:
                self._log("⚠️  Threat Intel module not available")
                self._threat_intel_module = False
        return self._threat_intel_module

    def _get_ml_manager(self):
        """Lazy load ML Model Manager"""
        if self._ml_manager is None:
            try:
                from ml import get_model_manager
                self._ml_manager = get_model_manager()
            except ImportError:
                self._log("⚠️  ML module not available")
                self._ml_manager = False
            except Exception as e:
                self._log(f"⚠️  ML module error: {e}")
                self._ml_manager = False
        return self._ml_manager

    def _get_notification_module(self):
        """Lazy load Notification Dispatcher"""
        if self._notification_module is None:
            try:
                from core.notification_dispatcher import notify_high_risk, notify_anomaly
                self._notification_module = {
                    'high_risk': notify_high_risk,
                    'anomaly': notify_anomaly
                }
            except ImportError as e:
                self._log(f"⚠️  Notification module not available: {e}")
                self._notification_module = False
            except Exception as e:
                self._log(f"⚠️  Notification module error: {e}")
                self._notification_module = False
        return self._notification_module

    def _get_behavioral_modules(self):
        """Lazy load ML Behavioral Scorer and Learner"""
        if self._behavioral_scorer is None:
            try:
                from core.ml_anomaly_scorer import MLAnomalyScorer
                from core.ml_behavioral_learner import MLBehavioralLearner
                self._behavioral_scorer = MLAnomalyScorer(verbose=self.verbose)
                self._behavioral_learner = MLBehavioralLearner(verbose=self.verbose)
            except ImportError as e:
                self._log(f"⚠️  Behavioral ML modules not available: {e}")
                self._behavioral_scorer = False
                self._behavioral_learner = False
            except Exception as e:
                self._log(f"⚠️  Behavioral ML module error: {e}")
                self._behavioral_scorer = False
                self._behavioral_learner = False
        return self._behavioral_scorer, self._behavioral_learner

    def _is_private_ip(self, ip: str) -> bool:
        """
        Check if IP is a private/local network address.
        Private IPs should use behavioral analysis only (skip GeoIP, ThreatIntel).

        RFC 1918 ranges:
        - 10.0.0.0/8 (10.x.x.x)
        - 172.16.0.0/12 (172.16.x.x - 172.31.x.x)
        - 192.168.0.0/16 (192.168.x.x)
        - 127.0.0.0/8 (loopback)
        """
        if not ip:
            return False

        # Check common private ranges
        if ip.startswith('10.') or ip.startswith('192.168.') or ip.startswith('127.'):
            return True

        # Check 172.16.0.0/12 range (172.16.x.x - 172.31.x.x)
        if ip.startswith('172.'):
            try:
                second_octet = int(ip.split('.')[1])
                if 16 <= second_octet <= 31:
                    return True
            except (IndexError, ValueError):
                pass

        return False

    def _enrich_private_ip_event(self, event_id: int, source_ip: str,
                                  skip_blocking: bool = False,
                                  skip_learning: bool = False) -> Dict:
        """
        Behavioral-only enrichment for private network IPs.

        For private IPs (192.168.x.x, 10.x.x.x, etc.), we skip:
        - GeoIP lookups (no useful data)
        - Threat Intelligence (AbuseIPDB, VirusTotal)
        - Impossible Travel detection (requires geo coordinates)

        We still perform:
        - Login time anomaly detection
        - Rapid attempt detection
        - Brute force counting
        - Success after failures detection
        - User baseline tracking
        """
        self._log(f"\n🏠 Private IP detected: {source_ip} - Using behavioral analysis only")

        result = {
            'event_id': event_id,
            'source_ip': source_ip,
            'is_private_ip': True,
            'enrichment_type': 'behavioral_only',
            'geoip': None,  # Skipped for private IPs
            'threat_intel': None,  # Skipped for private IPs
            'ml': None,
            'success': True,
            'errors': []
        }

        # Get event data
        event_data = self._get_event_data(event_id)
        if not event_data:
            result['success'] = False
            result['errors'].append('Event not found')
            return result

        target_username = event_data.get('target_username')
        event_type = event_data.get('event_type', 'unknown')
        event_timestamp = event_data.get('timestamp', datetime.now())

        # Perform behavioral analysis for private IP
        behavioral_result = self._analyze_private_ip_behavior(
            event_id, source_ip, target_username, event_type, event_timestamp
        )
        result['behavioral'] = behavioral_result
        result['ml'] = {
            'risk_score': behavioral_result.get('risk_score', 0),
            'threat_type': behavioral_result.get('threat_type'),
            'is_anomaly': behavioral_result.get('is_anomaly', False),
            'confidence': behavioral_result.get('confidence', 0.5),
            'ml_available': True,
            'private_ip_mode': True
        }

        # Update auth_events with behavioral results
        self._update_ml_results(
            event_id,
            behavioral_result.get('risk_score', 0),
            behavioral_result.get('threat_type'),
            behavioral_result.get('confidence', 0.5),
            behavioral_result.get('is_anomaly', False)
        )

        # Handle blocking decision for private IPs
        if not skip_blocking and behavioral_result.get('risk_score', 0) >= 60:
            try:
                from core.blocking.rule_coordinator import check_and_block_ip
                blocking_result = check_and_block_ip(
                    ip_address=source_ip,
                    ml_result=result['ml'],
                    event_id=event_id,
                    event_type=event_type,
                    username=target_username
                )
                result['blocking'] = blocking_result
                if blocking_result.get('blocked'):
                    self._log(f"🚫 Private IP {source_ip} blocked (behavioral): {blocking_result.get('triggered_rules')}")
            except Exception as e:
                self._log(f"⚠️  Blocking error for private IP: {e}")
                result['errors'].append(f"Blocking error: {str(e)}")

        # Send notifications if high risk
        risk_score = behavioral_result.get('risk_score', 0)
        if risk_score >= HIGH_RISK_THRESHOLD:
            notif_module = self._get_notification_module()
            if notif_module and 'high_risk' in notif_module:
                try:
                    notif_module['high_risk'](
                        event_id=event_id,
                        ip_address=source_ip,
                        risk_score=risk_score,
                        threat_type=behavioral_result.get('threat_type', 'behavioral_anomaly'),
                        geo_data=None,  # No geo for private IP
                        threat_data=None,
                        verbose=self.verbose
                    )
                    self._log(f"🔔 High risk notification sent for private IP")
                except Exception as e:
                    self._log(f"❌ Notification error: {e}")

        # Update behavioral profile (learning) for private IPs too
        if event_type == 'successful' and target_username and not skip_learning:
            behavioral_scorer, behavioral_learner = self._get_behavioral_modules()
            if behavioral_learner:
                try:
                    login_data = {
                        'hour': event_timestamp.hour if hasattr(event_timestamp, 'hour') else datetime.now().hour,
                        'day_of_week': event_timestamp.weekday() if hasattr(event_timestamp, 'weekday') else datetime.now().weekday(),
                        'ip_address': source_ip,
                        'country': 'PRIVATE',  # Mark as private network
                        'city': 'LOCAL',
                        'is_successful': True,
                        'timestamp': event_timestamp if isinstance(event_timestamp, datetime) else datetime.now()
                    }
                    behavioral_learner.learn_from_login(target_username, login_data)
                    self._log(f"📚 Updated behavioral profile for {target_username} (private IP)")
                except Exception as e:
                    self._log(f"⚠️  Profile learning error: {e}")

        # Mark as completed
        self._update_processing_status(event_id, 'completed')
        self._log(f"✅ Private IP enrichment complete (behavioral score: {behavioral_result.get('risk_score', 0)})")

        return result

    def _analyze_private_ip_behavior(self, event_id: int, source_ip: str,
                                      username: str, event_type: str,
                                      timestamp: datetime) -> Dict:
        """
        Behavioral analysis specifically for private network IPs.

        Checks performed:
        - Login time anomaly (unusual hours: before 6AM or after 10PM)
        - New IP for this user
        - Rapid attempts (brute force indicator)
        - Success after multiple failures
        - Off-hours weekend login
        """
        result = {
            'risk_score': 0,
            'is_anomaly': False,
            'threat_type': None,
            'confidence': 0.5,
            'factors': [],
            'factor_details': []
        }

        if not username:
            return result

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            risk_score = 0
            factors = []
            factor_details = []

            # 1. Check login time anomaly (unusual hours: 10PM - 6AM = +25 risk)
            hour = timestamp.hour if hasattr(timestamp, 'hour') else datetime.now().hour
            if hour >= NIGHT_START_HOUR or hour < NIGHT_END_HOUR:
                risk_score += 25
                factors.append('unusual_login_time')
                factor_details.append({
                    'factor': 'unusual_login_time',
                    'description': f'Login at {hour}:00 (outside 6AM-10PM)',
                    'weight': 25
                })
                self._log(f"⏰ Unusual login time: {hour}:00 (+25 risk)")

            # 2. Check if this is a new private IP for this user (+15 risk)
            cursor.execute("""
                SELECT COUNT(*) as count FROM auth_events
                WHERE target_username = %s AND source_ip_text = %s
                AND event_type = 'successful'
                AND id < %s
            """, (username, source_ip, event_id))
            prev_logins = cursor.fetchone()

            if prev_logins and prev_logins['count'] == 0:
                risk_score += 15
                factors.append('new_ip_for_user')
                factor_details.append({
                    'factor': 'new_ip_for_user',
                    'description': f'First login from {source_ip}',
                    'weight': 15
                })
                self._log(f"🆕 New private IP for user: {source_ip} (+15 risk)")

            # 3. Check rapid attempts (10+ attempts in 5 minutes = +20 risk)
            cursor.execute("""
                SELECT COUNT(*) as count FROM auth_events
                WHERE source_ip_text = %s
                AND timestamp >= DATE_SUB(NOW(), INTERVAL 5 MINUTE)
                AND id <= %s
            """, (source_ip, event_id))
            rapid = cursor.fetchone()

            if rapid and rapid['count'] >= 10:
                risk_score += 20
                factors.append('rapid_attempts')
                factor_details.append({
                    'factor': 'rapid_attempts',
                    'description': f'{rapid["count"]} attempts in 5 minutes',
                    'weight': 20
                })
                self._log(f"⚡ Rapid attempts: {rapid['count']} in 5 min (+20 risk)")

            # 4. Check success after failures (3+ failures then success = +15 risk)
            if event_type == 'successful':
                cursor.execute("""
                    SELECT COUNT(*) as count FROM auth_events
                    WHERE source_ip_text = %s AND event_type = 'failed'
                    AND timestamp >= DATE_SUB(NOW(), INTERVAL 1 HOUR)
                    AND id < %s
                """, (source_ip, event_id))
                failures = cursor.fetchone()

                if failures and failures['count'] >= 3:
                    risk_score += 15
                    factors.append('success_after_failures')
                    factor_details.append({
                        'factor': 'success_after_failures',
                        'description': f'Success after {failures["count"]} failures',
                        'weight': 15
                    })
                    self._log(f"🔓 Success after {failures['count']} failures (+15 risk)")

            # 5. Check off-hours weekend login (+10 risk)
            day_of_week = timestamp.weekday() if hasattr(timestamp, 'weekday') else datetime.now().weekday()
            if day_of_week >= 5:  # Saturday = 5, Sunday = 6
                risk_score += 10
                factors.append('weekend_login')
                factor_details.append({
                    'factor': 'weekend_login',
                    'description': 'Login on weekend',
                    'weight': 10
                })
                self._log(f"📅 Weekend login (+10 risk)")

            # 6. Check brute force pattern (20+ failed attempts from this IP = +30 risk)
            cursor.execute("""
                SELECT COUNT(*) as count FROM auth_events
                WHERE source_ip_text = %s AND event_type = 'failed'
                AND timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
            """, (source_ip,))
            brute_force = cursor.fetchone()

            if brute_force and brute_force['count'] >= 20:
                risk_score += 30
                factors.append('brute_force_pattern')
                factor_details.append({
                    'factor': 'brute_force_pattern',
                    'description': f'{brute_force["count"]} failures in 24h',
                    'weight': 30
                })
                self._log(f"🔨 Brute force pattern: {brute_force['count']} failures (+30 risk)")

            # Cap at 100
            risk_score = min(risk_score, 100)

            # Determine anomaly and threat type
            is_anomaly = risk_score >= 40
            threat_type = None
            if 'brute_force_pattern' in factors:
                threat_type = 'brute_force'
            elif 'rapid_attempts' in factors:
                threat_type = 'rapid_attack'
            elif 'success_after_failures' in factors:
                threat_type = 'credential_compromise'
            elif 'unusual_login_time' in factors:
                threat_type = 'time_anomaly'
            elif is_anomaly:
                threat_type = 'behavioral_anomaly'

            result = {
                'risk_score': risk_score,
                'is_anomaly': is_anomaly,
                'threat_type': threat_type,
                'confidence': min(0.5 + (len(factors) * 0.1), 0.95),
                'factors': factors,
                'factor_details': factor_details
            }

            return result

        except Exception as e:
            self._log(f"⚠️  Behavioral analysis error: {e}")
            result['errors'] = [str(e)]
            return result
        finally:
            cursor.close()
            conn.close()

    def _check_new_location(self, username: str, geo_data: Dict, source_ip: str) -> Tuple[bool, Optional[Dict]]:
        """
        Check if this is a new/unusual location for the user.

        Args:
            username: Target username
            geo_data: Current login geolocation data
            source_ip: Source IP address

        Returns:
            Tuple of (is_new_location, previous_location_data)
        """
        if not username or not geo_data:
            return False, None

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            # Get user's baseline location
            cursor.execute("""
                SELECT last_country_code, last_city, last_latitude, last_longitude,
                       last_ip_text, last_login_at, login_count
                FROM user_login_baselines
                WHERE username = %s
            """, (username,))

            baseline = cursor.fetchone()

            current_country = geo_data.get('country_code')
            current_city = geo_data.get('city')

            if not baseline:
                # First login for this user - create baseline
                cursor.execute("""
                    INSERT INTO user_login_baselines
                    (username, last_latitude, last_longitude, last_country_code,
                     last_city, last_ip_text, last_login_at, login_count)
                    VALUES (%s, %s, %s, %s, %s, %s, NOW(), 1)
                """, (
                    username,
                    geo_data.get('latitude'),
                    geo_data.get('longitude'),
                    current_country,
                    current_city,
                    source_ip
                ))
                conn.commit()
                return False, None  # Not a new location, just first login

            # Check if location is different
            prev_country = baseline.get('last_country_code')
            prev_city = baseline.get('last_city')

            is_new_location = False
            if prev_country and current_country and prev_country != current_country:
                is_new_location = True
            elif prev_city and current_city and prev_city != current_city:
                is_new_location = True

            # Update baseline with current login
            cursor.execute("""
                UPDATE user_login_baselines
                SET last_latitude = %s,
                    last_longitude = %s,
                    last_country_code = %s,
                    last_city = %s,
                    last_ip_text = %s,
                    last_login_at = NOW(),
                    login_count = login_count + 1
                WHERE username = %s
            """, (
                geo_data.get('latitude'),
                geo_data.get('longitude'),
                current_country,
                current_city,
                source_ip,
                username
            ))
            conn.commit()

            return is_new_location, baseline

        except Exception as e:
            self._log(f"⚠️  Error checking new location: {e}")
            return False, None
        finally:
            cursor.close()
            conn.close()

    def enrich_event(self, event_id: int, source_ip: str,
                     skip_geoip: bool = False,
                     skip_ml: bool = False,
                     skip_threat_intel: bool = False,
                     skip_blocking: bool = False,
                     skip_learning: bool = False,
                     skip_notifications: bool = False) -> Dict:
        """
        Full enrichment pipeline for a single event.

        Pipeline:
        1. GeoIP lookup → geo_id, location data
        2. ML prediction → ml_risk_score, ml_threat_type, is_anomaly
        3. Threat Intel → threat level from external APIs
        4. Update processing_status = 'completed'

        Args:
            event_id: auth_events.id
            source_ip: IP address to enrich
            skip_geoip: Skip GeoIP enrichment
            skip_ml: Skip ML prediction
            skip_threat_intel: Skip threat intelligence
            skip_blocking: Skip auto-blocking (analysis only mode)
            skip_learning: Skip behavioral profile learning (for simulation)
            skip_notifications: Skip sending notifications (for simulation)

        Returns:
            Dict with enrichment results
        """
        self._log(f"\n🔄 Enriching event {event_id} (IP: {source_ip})")

        # PRIVATE IP CHECK - Branch to behavioral-only analysis
        # Private IPs (192.168.x, 10.x, 172.16-31.x) skip GeoIP/ThreatIntel
        if self._is_private_ip(source_ip):
            return self._enrich_private_ip_event(
                event_id=event_id,
                source_ip=source_ip,
                skip_blocking=skip_blocking,
                skip_learning=skip_learning
            )

        result = {
            'event_id': event_id,
            'source_ip': source_ip,
            'geoip': None,
            'ml': None,
            'threat_intel': None,
            'success': True,
            'errors': []
        }

        # Get event data for ML
        event_data = self._get_event_data(event_id)
        if not event_data:
            result['success'] = False
            result['errors'].append('Event not found')
            return result

        # Step 1: GeoIP Enrichment (PUBLIC IPs only)
        geo_data = None
        if not skip_geoip:
            try:
                geoip_module = self._get_geoip_module()
                if geoip_module:
                    self._log(f"🌍 GeoIP lookup for {source_ip}...")
                    geo_id = geoip_module(event_id, source_ip)
                    # Get full geo data for result
                    geo_data = self._get_geo_data(source_ip)
                    result['geoip'] = {
                        'geo_id': geo_id,
                        'country': geo_data.get('country_name') if geo_data else None,
                        'country_code': geo_data.get('country_code') if geo_data else None,
                        'city': geo_data.get('city') if geo_data else None,
                        'isp': geo_data.get('isp') if geo_data else None,
                        'is_tor': geo_data.get('is_tor') if geo_data else False,
                        'is_vpn': geo_data.get('is_vpn') if geo_data else False,
                        'is_proxy': geo_data.get('is_proxy') if geo_data else False,
                        'is_datacenter': geo_data.get('is_datacenter') if geo_data else False,
                        'latitude': geo_data.get('latitude') if geo_data else None,
                        'longitude': geo_data.get('longitude') if geo_data else None
                    }
                    if geo_id:
                        self._log(f"✅ GeoIP complete (geo_id: {geo_id})")
                        self._update_processing_status(event_id, 'geoip_complete')
            except Exception as e:
                error_msg = f"GeoIP error: {str(e)}"
                self._log(f"❌ {error_msg}")
                result['errors'].append(error_msg)

        # Step 2: ML Prediction
        if not skip_ml:
            try:
                ml_manager = self._get_ml_manager()
                if ml_manager:
                    self._log(f"🤖 ML prediction for event {event_id}...")

                    # Get geo data for ML features
                    geo_data = self._get_geo_data(source_ip)
                    threat_data = self._get_threat_data(source_ip)

                    # Add geo/threat data to event
                    enriched_event = {**event_data}
                    if geo_data:
                        enriched_event['geo'] = geo_data
                    if threat_data:
                        enriched_event['threat'] = threat_data

                    # Get ML prediction
                    ml_result = ml_manager.predict(enriched_event)
                    result['ml'] = ml_result

                    if ml_result.get('ml_available', False):
                        # Get base risk score from ML
                        base_risk_score = ml_result.get('risk_score', 0)
                        event_type = event_data.get('event_type', 'unknown')
                        event_timestamp = event_data.get('timestamp')
                        target_username = event_data.get('target_username')

                        # Calculate risk adjustments
                        risk_adjustment, adjustment_reasons = calculate_risk_adjustments(
                            geo_data=geo_data,
                            event_type=event_type,
                            timestamp=event_timestamp
                        )

                        # Apply adjustments to risk score (cap at 100)
                        adjusted_risk_score = min(base_risk_score + risk_adjustment, 100)

                        if risk_adjustment > 0:
                            self._log(f"📊 Risk adjustments applied: {adjustment_reasons} (+{risk_adjustment})")
                            ml_result['risk_score'] = adjusted_risk_score
                            ml_result['risk_adjustments'] = adjustment_reasons
                            ml_result['base_risk_score'] = base_risk_score

                        # Update auth_events with ML results (using adjusted score)
                        self._update_ml_results(
                            event_id,
                            adjusted_risk_score,
                            ml_result.get('threat_type'),
                            ml_result.get('confidence', 0),
                            ml_result.get('is_anomaly', False)
                        )
                        self._log(f"✅ ML complete (risk: {adjusted_risk_score}, type: {ml_result.get('threat_type')})")
                        self._update_processing_status(event_id, 'ml_complete')

                        # Trigger rule evaluation for potential auto-blocking
                        risk_score = adjusted_risk_score
                        is_anomaly = ml_result.get('is_anomaly', False)
                        threat_type = ml_result.get('threat_type')
                        confidence = ml_result.get('confidence', 0)

                        # Evaluate blocking rules (unless skip_blocking=True for analysis-only mode)
                        if skip_blocking:
                            self._log(f"⏭️  Skipping blocking (analysis-only mode)")
                            result['blocking'] = {
                                'blocked': False,
                                'skipped': True,
                                'message': 'Blocking skipped (analysis-only mode)'
                            }
                        else:
                            # ALWAYS evaluate blocking rules - rules decide themselves whether to block
                            # Rules like abuseipdb_critical_90 should block regardless of ML score
                            try:
                                from core.blocking.rule_coordinator import check_and_block_ip
                                blocking_result = check_and_block_ip(
                                    ip_address=source_ip,
                                    ml_result=ml_result,
                                    event_id=event_id,
                                    event_type=event_type,
                                    username=target_username
                                )
                                result['blocking'] = blocking_result
                                if blocking_result.get('blocked'):
                                    self._log(f"🚫 IP {source_ip} auto-blocked: {blocking_result.get('triggered_rules')}")
                                elif not blocking_result.get('success', True) and 'already blocked' in blocking_result.get('message', '').lower():
                                    self._log(f"⚠️  IP {source_ip} already blocked (block_id: {blocking_result.get('block_id')})")
                            except Exception as e:
                                self._log(f"⚠️  Rule evaluation error: {e}")
                                result['errors'].append(f"Rule evaluation error: {str(e)}")

                        # Send notifications (skip for simulations)
                        if skip_notifications:
                            self._log(f"⏭️  Skipping notifications (simulation mode)")
                        else:
                            notif_module = self._get_notification_module()
                            if notif_module:
                                # Send high_risk notification if score >= threshold (70)
                                if risk_score >= HIGH_RISK_THRESHOLD:
                                    self._log(f"🔔 Triggering high_risk notification (score: {risk_score})")
                                    try:
                                        notif_module['high_risk'](
                                            event_id=event_id,
                                            ip_address=source_ip,
                                            risk_score=risk_score,
                                            threat_type=threat_type,
                                            geo_data=geo_data,
                                            threat_data=threat_data,
                                            verbose=self.verbose
                                        )
                                    except Exception as e:
                                        self._log(f"❌ High risk notification error: {e}")

                                # Send ML anomaly notification only for significant anomalies
                                # Must meet BEHAVIORAL_ANOMALY_THRESHOLD (60) and be below HIGH_RISK_THRESHOLD (70)
                                # Skip if risk_score >= 70 (already handled by high_risk above)
                                if ANOMALY_NOTIFICATION and is_anomaly and risk_score >= BEHAVIORAL_ANOMALY_THRESHOLD and risk_score < HIGH_RISK_THRESHOLD:
                                    self._log(f"🔔 Triggering anomaly notification (score: {risk_score})")
                                    try:
                                        notif_module['anomaly'](
                                            event_id=event_id,
                                            ip_address=source_ip,
                                            risk_score=risk_score,
                                            threat_type=threat_type,
                                            confidence=confidence,
                                            geo_data=geo_data,
                                            verbose=self.verbose
                                        )
                                    except Exception as e:
                                        self._log(f"❌ Anomaly notification error: {e}")
                                elif is_anomaly and risk_score < BEHAVIORAL_ANOMALY_THRESHOLD:
                                    self._log(f"ℹ️  ML anomaly below threshold ({risk_score} < {BEHAVIORAL_ANOMALY_THRESHOLD}), no notification")

                            # Check for new location on successful logins (allow + notify)
                            if event_type == 'successful' and target_username and geo_data:
                                is_new_location, prev_location = self._check_new_location(
                                    target_username, geo_data, source_ip
                                )
                                if is_new_location:
                                    result['new_location'] = {
                                        'detected': True,
                                        'previous': prev_location,
                                        'current': {
                                            'country_code': geo_data.get('country_code'),
                                            'city': geo_data.get('city')
                                        }
                                    }
                                    self._log(f"🌍 New location detected for {target_username}: {geo_data.get('city')}, {geo_data.get('country_code')}")

                                    # Send new location notification
                                    if 'new_location' in notif_module:
                                        try:
                                            notif_module['new_location'](
                                                event_id=event_id,
                                                ip_address=source_ip,
                                                username=target_username,
                                                current_location=geo_data,
                                                previous_location=prev_location,
                                                verbose=self.verbose
                                            )
                                        except Exception as e:
                                            self._log(f"❌ New location notification error: {e}")
            except Exception as e:
                error_msg = f"ML error: {str(e)}"
                self._log(f"❌ {error_msg}")
                result['errors'].append(error_msg)

        # Step 3: Threat Intelligence
        if not skip_threat_intel:
            try:
                threat_module = self._get_threat_intel_module()
                if threat_module:
                    self._log(f"🔍 Threat Intel lookup for {source_ip}...")
                    threat_data = threat_module(source_ip)
                    result['threat_intel'] = threat_data

                    if threat_data:
                        threat_level = threat_data.get('threat_level', 'unknown')
                        self._log(f"✅ Threat Intel complete (level: {threat_level})")
                        self._update_processing_status(event_id, 'intel_complete')
            except Exception as e:
                error_msg = f"Threat Intel error: {str(e)}"
                self._log(f"❌ {error_msg}")
                result['errors'].append(error_msg)

        # Step 3.5: ML Behavioral Analysis (alert-only, no blocking)
        # Detects unusual login patterns based on learned user behavior
        try:
            behavioral_scorer, behavioral_learner = self._get_behavioral_modules()
            target_username = event_data.get('target_username')
            event_type = event_data.get('event_type', 'unknown')
            event_timestamp = event_data.get('timestamp', datetime.now())

            if behavioral_scorer and behavioral_learner and target_username:
                self._log(f"🧠 ML Behavioral analysis for {target_username}...")

                # Build login data for behavioral scoring
                login_data = {
                    'username': target_username,
                    'hour': event_timestamp.hour if hasattr(event_timestamp, 'hour') else datetime.now().hour,
                    'day_of_week': event_timestamp.weekday() if hasattr(event_timestamp, 'weekday') else datetime.now().weekday(),
                    'ip_address': source_ip,
                    'country': geo_data.get('country_code', '') if geo_data else '',
                    'city': geo_data.get('city', '') if geo_data else '',
                    'timestamp': event_timestamp if isinstance(event_timestamp, datetime) else datetime.now()
                }

                # Score the login for anomalies
                behavioral_result = behavioral_scorer.score_login(login_data)
                result['behavioral_ml'] = behavioral_result

                if behavioral_result.get('is_anomaly'):
                    anomaly_score = behavioral_result.get('anomaly_score', 0)
                    factors = behavioral_result.get('factors', [])
                    anomaly_type = behavioral_scorer.get_anomaly_type(factors)

                    self._log(f"🚨 Behavioral anomaly detected: score={anomaly_score}, type={anomaly_type}, factors={factors}")

                    # Send notification for behavioral anomaly (ALERT ONLY - no blocking)
                    # Only notify if score >= BEHAVIORAL_ANOMALY_THRESHOLD and not skipping notifications
                    if skip_notifications:
                        self._log(f"⏭️  Skipping behavioral notification (simulation mode)")
                    elif anomaly_score < BEHAVIORAL_ANOMALY_THRESHOLD:
                        self._log(f"ℹ️  Behavioral anomaly below threshold ({anomaly_score} < {BEHAVIORAL_ANOMALY_THRESHOLD}), no notification")
                    else:
                        notif_module = self._get_notification_module()
                        if notif_module and 'anomaly' in notif_module:
                            try:
                                notif_module['anomaly'](
                                    event_id=event_id,
                                    ip_address=source_ip,
                                    risk_score=anomaly_score,
                                    threat_type=anomaly_type,
                                    confidence=behavioral_result.get('details', {}).get('profile_confidence', 0),
                                    geo_data=geo_data,
                                    username=target_username,
                                    anomaly_factors=factors,
                                    anomaly_details=behavioral_result.get('factor_details', []),
                                    verbose=self.verbose
                                )
                                self._log(f"✅ Behavioral anomaly notification sent")
                            except Exception as e:
                                self._log(f"❌ Behavioral anomaly notification error: {e}")
                else:
                    self._log(f"✅ Behavioral analysis: normal (score={behavioral_result.get('anomaly_score', 0)})")

                # Update user profile with successful logins (learning)
                # Skip learning during simulation to prevent profile contamination
                if event_type == 'successful' and not skip_learning:
                    login_learn_data = {
                        'hour': login_data['hour'],
                        'day_of_week': login_data['day_of_week'],
                        'ip_address': source_ip,
                        'country': login_data['country'],
                        'city': login_data['city'],
                        'is_successful': True,
                        'timestamp': login_data['timestamp']
                    }
                    behavioral_learner.learn_from_login(target_username, login_learn_data)
                    self._log(f"📚 Updated behavioral profile for {target_username}")
                elif skip_learning:
                    self._log(f"⏭️  Skipping profile learning (simulation mode)")

        except Exception as e:
            self._log(f"⚠️  Behavioral ML error: {e}")
            result['errors'].append(f"Behavioral ML error: {str(e)}")

        # Step 4: Rule-based blocking (runs even when ML is not available)
        # This ensures threat intel and pattern-based rules can trigger blocks
        if not skip_blocking and 'blocking' not in result:
            try:
                from core.blocking.rule_coordinator import check_and_block_ip

                # Build ML result from available data if ML didn't run
                ml_result_for_blocking = result.get('ml', {})
                if not ml_result_for_blocking:
                    ml_result_for_blocking = {
                        'risk_score': 0,
                        'threat_type': None,
                        'is_anomaly': False,
                        'confidence': 0
                    }

                event_type = event_data.get('event_type', 'unknown')
                target_username = event_data.get('target_username')

                blocking_result = check_and_block_ip(
                    ip_address=source_ip,
                    ml_result=ml_result_for_blocking,
                    event_id=event_id,
                    event_type=event_type,
                    username=target_username
                )
                result['blocking'] = blocking_result

                if blocking_result.get('blocked'):
                    self._log(f"🚫 IP {source_ip} blocked by rules: {blocking_result.get('triggered_rules')}")
                elif blocking_result.get('already_blocked'):
                    self._log(f"⚠️  IP {source_ip} already blocked")
            except Exception as e:
                self._log(f"⚠️  Rule-based blocking error: {e}")
                result['errors'].append(f"Rule-based blocking error: {str(e)}")

        # Final: Mark as completed
        self._update_processing_status(event_id, 'completed')
        self._log(f"✅ Enrichment complete for event {event_id}")

        return result

    def enrich_batch(self, event_ids: List[int]) -> List[Dict]:
        """
        Enrich multiple events.

        Args:
            event_ids: List of event IDs to enrich

        Returns:
            List of enrichment results
        """
        results = []
        for event_id in event_ids:
            # Get IP for event
            ip = self._get_event_ip(event_id)
            if ip:
                result = self.enrich_event(event_id, ip)
                results.append(result)
            else:
                results.append({
                    'event_id': event_id,
                    'success': False,
                    'errors': ['Event not found or no IP']
                })
        return results

    def _get_event_data(self, event_id: int) -> Optional[Dict]:
        """Get event data from database"""
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            cursor.execute("""
                SELECT
                    id, event_uuid, timestamp, source_type, event_type,
                    auth_method, source_ip_text, target_server, target_username,
                    failure_reason, geo_id
                FROM auth_events
                WHERE id = %s
            """, (event_id,))

            return cursor.fetchone()
        finally:
            cursor.close()
            conn.close()

    def _get_event_ip(self, event_id: int) -> Optional[str]:
        """Get IP address for an event"""
        conn = get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("""
                SELECT source_ip_text FROM auth_events WHERE id = %s
            """, (event_id,))

            result = cursor.fetchone()
            return result[0] if result else None
        finally:
            cursor.close()
            conn.close()

    def _get_geo_data(self, source_ip: str) -> Optional[Dict]:
        """Get cached geo data for IP"""
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            cursor.execute("""
                SELECT
                    country_code, country_name, city, latitude, longitude,
                    is_proxy, is_vpn, is_tor, is_datacenter, is_hosting, asn, isp
                FROM ip_geolocation
                WHERE ip_address_text = %s
            """, (source_ip,))

            return cursor.fetchone()
        finally:
            cursor.close()
            conn.close()

    def _get_threat_data(self, source_ip: str) -> Optional[Dict]:
        """Get cached threat intel data for IP"""
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            cursor.execute("""
                SELECT
                    abuseipdb_score, abuseipdb_confidence, abuseipdb_reports,
                    virustotal_positives, virustotal_total,
                    overall_threat_level, threat_confidence
                FROM ip_threat_intelligence
                WHERE ip_address_text = %s
            """, (source_ip,))

            return cursor.fetchone()
        finally:
            cursor.close()
            conn.close()

    def _update_processing_status(self, event_id: int, status: str):
        """Update event processing status"""
        conn = get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("""
                UPDATE auth_events
                SET processing_status = %s,
                    processed_at = CASE WHEN %s = 'completed' THEN NOW() ELSE processed_at END
                WHERE id = %s
            """, (status, status, event_id))
            conn.commit()
        finally:
            cursor.close()
            conn.close()

    def _update_ml_results(self, event_id: int, risk_score: int,
                          threat_type: Optional[str], confidence: float,
                          is_anomaly: bool):
        """Update event with ML prediction results"""
        conn = get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("""
                UPDATE auth_events
                SET ml_risk_score = %s,
                    ml_threat_type = %s,
                    ml_confidence = %s,
                    is_anomaly = %s
                WHERE id = %s
            """, (risk_score, threat_type, confidence, is_anomaly, event_id))
            conn.commit()
        finally:
            cursor.close()
            conn.close()


# Global enricher instance
_enricher = None


def get_enricher(verbose: bool = True) -> EventEnricher:
    """Get or create the global enricher instance"""
    global _enricher
    if _enricher is None:
        _enricher = EventEnricher(verbose=verbose)
    return _enricher


def enrich_event(event_id: int, source_ip: str, verbose: bool = True,
                 skip_blocking: bool = False, skip_learning: bool = False,
                 skip_notifications: bool = False) -> Dict:
    """
    Convenience function to enrich a single event.

    Args:
        event_id: auth_events.id
        source_ip: IP address
        verbose: Print progress
        skip_blocking: Skip auto-blocking (analysis only mode)
        skip_learning: Skip behavioral profile learning (for simulation)
        skip_notifications: Skip sending notifications (for simulation)

    Returns:
        Enrichment result dict
    """
    enricher = get_enricher(verbose=verbose)
    return enricher.enrich_event(
        event_id, source_ip,
        skip_blocking=skip_blocking,
        skip_learning=skip_learning,
        skip_notifications=skip_notifications
    )


def enrich_batch(event_ids: List[int], verbose: bool = True) -> List[Dict]:
    """
    Convenience function to enrich multiple events.

    Args:
        event_ids: List of auth_events.id
        verbose: Print progress

    Returns:
        List of enrichment results
    """
    enricher = get_enricher(verbose=verbose)
    return enricher.enrich_batch(event_ids)
