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
HIGH_RISK_THRESHOLD = 50  # ML risk score threshold for high_risk_detected (lowered from 60)
ANOMALY_NOTIFICATION = True  # Send notification when anomaly detected

# Risk score adjustments (added for aggressive blocking)
NIGHT_TIME_RISK_BOOST = 20  # +20 for logins between 10PM-6AM
HIGH_RISK_COUNTRY_BOOST = 25  # +25 for high-risk countries on first fail
VPN_PROXY_RISK_BOOST = 15  # +15 for VPN/proxy IPs

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
                from core.notification_dispatcher import notify_high_risk, notify_anomaly, notify_new_location
                self._notification_module = {
                    'high_risk': notify_high_risk,
                    'anomaly': notify_anomaly,
                    'new_location': notify_new_location
                }
            except ImportError:
                self._log("⚠️  Notification module not available")
                self._notification_module = False
            except Exception as e:
                self._log(f"⚠️  Notification module error: {e}")
                self._notification_module = False
        return self._notification_module

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
                     skip_blocking: bool = False) -> Dict:
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

        Returns:
            Dict with enrichment results
        """
        self._log(f"\n🔄 Enriching event {event_id} (IP: {source_ip})")

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

        # Step 1: GeoIP Enrichment
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

                        notif_module = self._get_notification_module()
                        if notif_module:
                            # Send high_risk notification if score >= threshold
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

                            # Send anomaly notification if anomaly detected
                            if ANOMALY_NOTIFICATION and is_anomaly:
                                self._log(f"🔔 Triggering anomaly notification")
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
                 skip_blocking: bool = False) -> Dict:
    """
    Convenience function to enrich a single event.

    Args:
        event_id: auth_events.id
        source_ip: IP address
        verbose: Print progress
        skip_blocking: Skip auto-blocking (analysis only mode)

    Returns:
        Enrichment result dict
    """
    enricher = get_enricher(verbose=verbose)
    return enricher.enrich_event(event_id, source_ip, skip_blocking=skip_blocking)


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
