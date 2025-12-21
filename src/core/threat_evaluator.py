"""
SSH Guardian v3.0 - Unified Threat Evaluator
Combines ML model predictions, threat intelligence, network analysis,
geolocation, and behavioral patterns into a comprehensive risk score.
"""

import sys
import json
import logging
import math
from pathlib import Path
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta

# Add project paths
PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.append(str(PROJECT_ROOT / "dbs"))
sys.path.append(str(PROJECT_ROOT / "src"))

from connection import get_connection

logger = logging.getLogger(__name__)


# High-risk countries (based on common attack sources)
HIGH_RISK_COUNTRIES = {'CN', 'RU', 'KP', 'IR', 'VN', 'IN', 'BR', 'PK', 'ID', 'NG'}
MEDIUM_RISK_COUNTRIES = {'UA', 'RO', 'BG', 'TH', 'PH', 'MY', 'BD', 'EG', 'TR', 'MX'}


class ThreatEvaluator:
    """
    Unified threat evaluation combining multiple data sources:
    - ML Model predictions (trained Random Forest)
    - Threat Intelligence (AbuseIPDB, VirusTotal, Shodan)
    - Network Analysis (VPN, Proxy, TOR, Datacenter)
    - Geolocation Risk
    - Behavioral Patterns (login attempts, timing, patterns)
    """

    def __init__(self):
        self.ml_manager = None
        self.threat_intel = None
        self._init_modules()

    def _init_modules(self):
        """Initialize ML and threat intel modules"""
        try:
            from ml import get_model_manager
            self.ml_manager = get_model_manager()
            logger.info("[ThreatEvaluator] ML Model Manager loaded")
        except Exception as e:
            logger.warning(f"[ThreatEvaluator] ML module not available: {e}")

        try:
            from threat_intel import ThreatIntelligence
            self.threat_intel = ThreatIntelligence()
            logger.info("[ThreatEvaluator] Threat Intelligence module loaded")
        except Exception as e:
            logger.warning(f"[ThreatEvaluator] Threat Intel module not available: {e}")

    def evaluate_ip(self, ip_address: str, event_data: Dict = None) -> Dict[str, Any]:
        """
        Perform comprehensive threat evaluation for an IP address.

        Args:
            ip_address: IP to evaluate
            event_data: Optional event context (username, timestamp, etc.)

        Returns:
            Comprehensive evaluation with scores and factors
        """
        result = {
            'ip_address': ip_address,
            'evaluated_at': datetime.now().isoformat(),
            'composite_score': 0,
            'risk_level': 'low',
            'recommended_action': 'allow',
            'confidence': 0.0,
            'factors': [],
            'components': {
                'ml_score': 0,
                'threat_intel_score': 0,
                'network_score': 0,
                'geo_score': 0,
                'behavioral_score': 0
            },
            'details': {}
        }

        try:
            # 1. Fetch Threat Intelligence
            ti_result = self._evaluate_threat_intel(ip_address)
            result['components']['threat_intel_score'] = ti_result['score']
            result['factors'].extend(ti_result['factors'])
            result['details']['threat_intel'] = ti_result['details']

            # 2. ML Model Prediction
            ml_result = self._evaluate_ml(ip_address, event_data, ti_result['details'])
            result['components']['ml_score'] = ml_result['score']
            result['factors'].extend(ml_result['factors'])
            result['details']['ml'] = ml_result['details']

            # 3. Network Analysis
            net_result = self._evaluate_network(ti_result['details'])
            result['components']['network_score'] = net_result['score']
            result['factors'].extend(net_result['factors'])
            result['details']['network'] = net_result['details']

            # 4. Geolocation Risk
            geo_result = self._evaluate_geolocation(ti_result['details'])
            result['components']['geo_score'] = geo_result['score']
            result['factors'].extend(geo_result['factors'])
            result['details']['geolocation'] = geo_result['details']

            # 5. Behavioral Analysis (if event history available)
            beh_result = self._evaluate_behavior(ip_address, event_data)
            result['components']['behavioral_score'] = beh_result['score']
            result['factors'].extend(beh_result['factors'])
            result['details']['behavioral'] = beh_result['details']

            # 6. Specialized Detectors (Impossible Travel, Brute Force Success, Lateral Movement)
            detected_threats = self._run_specialized_detectors(
                ip_address, event_data, ti_result['details'], geo_result['details']
            )
            result['details']['specialized_detectors'] = detected_threats

            # Calculate composite score (weighted average + detector boosts)
            result['composite_score'] = self._calculate_composite_score(
                result['components'], detected_threats
            )
            result['risk_level'] = self._get_risk_level(result['composite_score'])
            result['recommended_action'] = self._get_recommended_action(result['composite_score'])
            result['confidence'] = self._calculate_confidence(result['components'])

            # Store evaluation in database
            self._store_evaluation(result)

        except Exception as e:
            logger.error(f"[ThreatEvaluator] Error evaluating {ip_address}: {e}")
            result['error'] = str(e)

        return result

    def _evaluate_threat_intel(self, ip_address: str) -> Dict:
        """Evaluate threat intelligence from external APIs"""
        score = 0
        factors = []
        details = {}

        try:
            # Try to get cached data first
            conn = get_connection()
            cursor = conn.cursor(dictionary=True)
            cursor.execute("""
                SELECT
                    abuseipdb_score, abuseipdb_reports,
                    virustotal_positives, virustotal_total,
                    shodan_ports, shodan_vulns,
                    is_proxy, is_vpn, is_tor, is_datacenter, is_hosting,
                    threat_level, country_code, country_name, isp, asn_org
                FROM ip_geolocation
                WHERE ip_address_text = %s
                AND last_seen >= DATE_SUB(NOW(), INTERVAL 7 DAY)
            """, (ip_address,))
            cached = cursor.fetchone()
            cursor.close()
            conn.close()

            if cached:
                details = dict(cached)
            elif self.threat_intel:
                # Fetch fresh data
                ti_data = self.threat_intel.lookup_ip_threat(ip_address)
                if ti_data:
                    details = {
                        'abuseipdb_score': ti_data.get('abuseipdb', {}).get('score', 0),
                        'abuseipdb_reports': ti_data.get('abuseipdb', {}).get('reports', 0),
                        'virustotal_positives': ti_data.get('virustotal', {}).get('positives', 0),
                        'virustotal_total': ti_data.get('virustotal', {}).get('total', 0),
                        'shodan_vulns': len(ti_data.get('shodan', {}).get('vulns', [])),
                        'is_proxy': ti_data.get('is_proxy', False),
                        'is_vpn': ti_data.get('is_vpn', False),
                        'is_tor': ti_data.get('is_tor', False),
                        'is_datacenter': ti_data.get('is_datacenter', False),
                        'threat_level': ti_data.get('threat_level', 'unknown'),
                        'country_code': ti_data.get('country_code'),
                        'country_name': ti_data.get('country_name'),
                        'isp': ti_data.get('isp'),
                    }

            # Score based on AbuseIPDB (max 55 points)
            abuse_score_raw = details.get('abuseipdb_score') or 0
            abuse_score = int(abuse_score_raw) if abuse_score_raw else 0
            if abuse_score >= 95:
                score += 55
                factors.append(f'Critical AbuseIPDB: {abuse_score}/100')
            elif abuse_score >= 90:
                score += 45
                factors.append(f'Critical AbuseIPDB: {abuse_score}/100')
            elif abuse_score >= 75:
                score += 35
                factors.append(f'High AbuseIPDB: {abuse_score}/100')
            elif abuse_score >= 50:
                score += 25
                factors.append(f'Elevated AbuseIPDB: {abuse_score}/100')
            elif abuse_score >= 25:
                score += 15
                factors.append(f'Moderate AbuseIPDB: {abuse_score}/100')

            # Score based on VirusTotal (max 30 points)
            vt_raw = details.get('virustotal_positives') or 0
            vt_positives = int(vt_raw) if vt_raw else 0
            if vt_positives >= 10:
                score += 30
                factors.append(f'{vt_positives} VirusTotal detections')
            elif vt_positives >= 5:
                score += 20
                factors.append(f'{vt_positives} VirusTotal detections')
            elif vt_positives >= 1:
                score += 10
                factors.append(f'{vt_positives} VirusTotal detection(s)')

            # Score based on Shodan vulnerabilities (max 15 points)
            vulns_raw = details.get('shodan_vulns') or 0
            vulns = int(vulns_raw) if vulns_raw else 0
            if vulns >= 5:
                score += 15
                factors.append(f'{vulns} Shodan vulnerabilities')
            elif vulns >= 1:
                score += 8
                factors.append(f'{vulns} Shodan vulnerability')

            # Report count adds significant weight for confirmed bad actors
            reports_raw = details.get('abuseipdb_reports') or 0
            reports = int(reports_raw) if reports_raw else 0
            if reports >= 500:
                score += 20
                factors.append(f'{reports} abuse reports')
            elif reports >= 100:
                score += 15
                factors.append(f'{reports} abuse reports')
            elif reports >= 50:
                score += 8

        except Exception as e:
            logger.error(f"[ThreatEvaluator] Threat intel error: {e}")

        return {'score': min(score, 100), 'factors': factors, 'details': details}

    def _evaluate_ml(self, ip_address: str, event_data: Dict, ti_details: Dict) -> Dict:
        """Get ML model prediction - uses MAX of ML and heuristic scores"""
        score = 0
        factors = []
        details = {}

        # Always calculate heuristic score as baseline
        heuristic_score = self._heuristic_ml_score(ti_details)

        try:
            if self.ml_manager:
                # Build event for ML prediction
                ml_event = event_data.copy() if event_data else {}
                ml_event['source_ip'] = ip_address

                # Add threat intel context
                ml_event['abuseipdb_score'] = ti_details.get('abuseipdb_score', 0)
                ml_event['is_vpn'] = ti_details.get('is_vpn', False)
                ml_event['is_proxy'] = ti_details.get('is_proxy', False)
                ml_event['is_tor'] = ti_details.get('is_tor', False)
                ml_event['is_datacenter'] = ti_details.get('is_datacenter', False)
                ml_event['threat_level'] = ti_details.get('threat_level', 'unknown')

                # Get prediction
                prediction = self.ml_manager.predict(ml_event)

                if prediction.get('ml_available'):
                    ml_score = prediction.get('risk_score', 0)
                    ml_confidence = prediction.get('confidence', 0)

                    # Use MAX of ML score and heuristic (ML may not capture all threat intel signals)
                    score = max(ml_score, heuristic_score)

                    details = {
                        'ml_score': ml_score,
                        'heuristic_score': heuristic_score,
                        'risk_score': score,
                        'threat_type': prediction.get('threat_type'),
                        'confidence': ml_confidence,
                        'is_anomaly': prediction.get('is_anomaly', False),
                        'model_used': prediction.get('model_used'),
                        'used_heuristic': score == heuristic_score and heuristic_score > ml_score
                    }

                    if prediction.get('is_anomaly'):
                        factors.append(f"ML Anomaly: {prediction.get('threat_type', 'unknown')}")

                    if score >= 75:
                        factors.append(f"High Risk Score: {score}/100")
                    elif score >= 50:
                        factors.append(f"Elevated Risk: {score}/100")
                else:
                    # ML not available - use heuristic
                    score = heuristic_score
                    details = {'heuristic': True, 'risk_score': score}
                    if score >= 50:
                        factors.append(f"Heuristic Risk: {score}/100")
            else:
                # ML not loaded - use heuristic
                score = heuristic_score
                details = {'heuristic': True, 'risk_score': score}

        except Exception as e:
            logger.error(f"[ThreatEvaluator] ML prediction error: {e}")
            score = heuristic_score
            details = {'error': str(e), 'heuristic': True}

        return {'score': min(score, 100), 'factors': factors, 'details': details}

    def _heuristic_ml_score(self, ti_details: Dict) -> int:
        """Calculate heuristic score when ML is unavailable"""
        score = 0

        abuse_raw = ti_details.get('abuseipdb_score') or 0
        abuse = int(abuse_raw) if abuse_raw else 0
        score += int(abuse * 0.4)  # Up to 40 points

        vt_raw = ti_details.get('virustotal_positives') or 0
        vt = int(vt_raw) if vt_raw else 0
        score += min(30, vt * 3)  # Up to 30 points

        if ti_details.get('is_tor'):
            score += 20
        elif ti_details.get('is_proxy'):
            score += 15
        elif ti_details.get('is_vpn'):
            score += 10
        elif ti_details.get('is_datacenter'):
            score += 10

        return min(score, 100)

    def _evaluate_network(self, ti_details: Dict) -> Dict:
        """Evaluate network characteristics"""
        score = 0
        factors = []
        details = {
            'is_tor': ti_details.get('is_tor', False),
            'is_proxy': ti_details.get('is_proxy', False),
            'is_vpn': ti_details.get('is_vpn', False),
            'is_datacenter': ti_details.get('is_datacenter', False),
            'is_hosting': ti_details.get('is_hosting', False),
            'isp': ti_details.get('isp'),
            'asn': ti_details.get('asn_org')
        }

        if ti_details.get('is_tor'):
            score += 25
            factors.append('TOR Exit Node')
        if ti_details.get('is_proxy'):
            score += 20
            factors.append('Known Proxy')
        if ti_details.get('is_vpn'):
            score += 15
            factors.append('VPN Service')
        if ti_details.get('is_datacenter') or ti_details.get('is_hosting'):
            score += 10
            factors.append('Datacenter/Hosting IP')

        return {'score': min(score, 100), 'factors': factors, 'details': details}

    def _evaluate_geolocation(self, ti_details: Dict) -> Dict:
        """Evaluate geographic risk"""
        score = 0
        factors = []
        country_code = ti_details.get('country_code', '')
        country_name = ti_details.get('country_name', 'Unknown')

        details = {
            'country_code': country_code,
            'country_name': country_name
        }

        if country_code in HIGH_RISK_COUNTRIES:
            score = 20
            factors.append(f'High-risk country: {country_name}')
        elif country_code in MEDIUM_RISK_COUNTRIES:
            score = 10
            factors.append(f'Medium-risk country: {country_name}')

        return {'score': score, 'factors': factors, 'details': details}

    def _evaluate_behavior(self, ip_address: str, event_data: Dict = None) -> Dict:
        """
        Evaluate behavioral patterns using advanced BehavioralAnalyzer.
        Detects: impossible travel, time anomalies, new locations, credential stuffing, etc.
        """
        score = 0
        factors = []
        details = {}

        try:
            # Use advanced BehavioralAnalyzer if event_data contains username
            username = event_data.get('username') if event_data else None
            event_type = event_data.get('status', 'failed') if event_data else 'failed'

            if username:
                try:
                    from behavioral_analyzer import BehavioralAnalyzer
                    analyzer = BehavioralAnalyzer()

                    # Get geo data for current event
                    geo_data = self._get_geo_for_ip(ip_address)

                    # Run comprehensive behavioral analysis
                    analysis = analyzer.analyze(
                        ip_address=ip_address,
                        username=username,
                        event_type=event_type,
                        current_geo=geo_data
                    )

                    # Extract score and factors from analysis
                    score = analysis.get('risk_score', 0)
                    details['behavioral_analysis'] = analysis

                    # Convert risk_factors to simple factor strings
                    for rf in analysis.get('risk_factors', []):
                        factor_type = rf.get('type', 'unknown')
                        factor_title = rf.get('title', factor_type)
                        factor_score = rf.get('score', 0)
                        factors.append(f"{factor_title} (+{factor_score})")

                        # Store detailed breakdown
                        if 'risk_factors_detail' not in details:
                            details['risk_factors_detail'] = []
                        details['risk_factors_detail'].append(rf)

                    # Store recommendations
                    details['recommendations'] = analysis.get('recommendations', [])
                    details['confidence'] = analysis.get('confidence', 0.5)
                    details['user_baseline'] = analysis.get('user_baseline', {})

                except ImportError:
                    logger.debug("[ThreatEvaluator] BehavioralAnalyzer not available, using fallback")
                    score, factors, details = self._fallback_behavioral_analysis(ip_address)
                except Exception as e:
                    logger.warning(f"[ThreatEvaluator] BehavioralAnalyzer error: {e}, using fallback")
                    score, factors, details = self._fallback_behavioral_analysis(ip_address)
            else:
                # No username - use fallback analysis
                score, factors, details = self._fallback_behavioral_analysis(ip_address)

        except Exception as e:
            logger.error(f"[ThreatEvaluator] Behavioral analysis error: {e}")

        return {'score': min(score, 100), 'factors': factors, 'details': details}

    def _get_geo_for_ip(self, ip_address: str) -> Dict:
        """Get geo data for an IP address"""
        try:
            conn = get_connection()
            cursor = conn.cursor(dictionary=True)
            cursor.execute("""
                SELECT country_code, country_name, city, region, latitude, longitude
                FROM ip_geolocation
                WHERE ip_address_text = %s
                LIMIT 1
            """, (ip_address,))
            result = cursor.fetchone()
            cursor.close()
            conn.close()
            return result or {}
        except Exception:
            return {}

    def _fallback_behavioral_analysis(self, ip_address: str) -> tuple:
        """Fallback behavioral analysis when BehavioralAnalyzer is not available"""
        score = 0
        factors = []
        details = {}

        try:
            conn = get_connection()
            cursor = conn.cursor(dictionary=True)

            # Get recent activity for this IP
            cursor.execute("""
                SELECT
                    COUNT(*) as total_events,
                    SUM(CASE WHEN event_type = 'failed' THEN 1 ELSE 0 END) as failed_attempts,
                    COUNT(DISTINCT target_username) as unique_usernames,
                    MIN(timestamp) as first_seen,
                    MAX(timestamp) as last_seen,
                    SUM(CASE WHEN target_username = 'root' THEN 1 ELSE 0 END) as root_attempts
                FROM auth_events
                WHERE source_ip_text = %s
                AND timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
            """, (ip_address,))
            stats = cursor.fetchone()

            if stats and stats['total_events']:
                details = {
                    'total_events_24h': stats['total_events'],
                    'failed_attempts': stats['failed_attempts'] or 0,
                    'unique_usernames': stats['unique_usernames'] or 0,
                    'root_attempts': stats['root_attempts'] or 0,
                    'first_seen': stats['first_seen'].isoformat() if stats['first_seen'] else None,
                    'last_seen': stats['last_seen'].isoformat() if stats['last_seen'] else None
                }

                failed = stats['failed_attempts'] or 0
                usernames = stats['unique_usernames'] or 0

                # High failed attempt count
                if failed >= 50:
                    score += 30
                    factors.append(f'{failed} failed attempts (24h)')
                elif failed >= 20:
                    score += 20
                    factors.append(f'{failed} failed attempts (24h)')
                elif failed >= 10:
                    score += 10
                    factors.append(f'{failed} failed attempts (24h)')

                # Credential stuffing indicator
                if usernames >= 10:
                    score += 20
                    factors.append(f'Credential stuffing: {usernames} usernames')
                elif usernames >= 5:
                    score += 10
                    factors.append(f'Multiple usernames: {usernames}')

                # Root targeting
                if stats['root_attempts'] >= 5:
                    score += 15
                    factors.append(f'{stats["root_attempts"]} root login attempts')

            # Check for existing blocks
            cursor.execute("""
                SELECT COUNT(*) as block_count
                FROM ip_blocks
                WHERE ip_address_text = %s
            """, (ip_address,))
            blocks = cursor.fetchone()
            if blocks and blocks['block_count'] > 0:
                score += 10
                factors.append('Previously blocked')
                details['previously_blocked'] = True

            cursor.close()
            conn.close()

        except Exception as e:
            logger.error(f"[ThreatEvaluator] Fallback behavioral analysis error: {e}")

        return score, factors, details

    # === SPECIALIZED DETECTORS (Phase 3) ===

    def _run_specialized_detectors(self, ip_address: str, event_data: Dict,
                                    ti_details: Dict, geo_details: Dict) -> Dict:
        """
        Run all specialized detectors and collect results.
        Returns dict with detector results and total score boost.
        """
        detections = []
        total_boost = 0

        username = event_data.get('username') if event_data else None
        event_type = event_data.get('status', '') if event_data else ''

        # Build geo dict from ti_details
        geo = {
            'latitude': ti_details.get('latitude') or geo_details.get('latitude'),
            'longitude': ti_details.get('longitude') or geo_details.get('longitude'),
            'country_name': ti_details.get('country_name') or geo_details.get('country_name'),
            'city': ti_details.get('city') or geo_details.get('city')
        }

        # 1. Impossible Travel Detection
        travel_result = self._detect_impossible_travel(ip_address, username, geo)
        if travel_result.get('detected'):
            detections.append(travel_result)
            total_boost += travel_result.get('score_boost', 0)

        # 2. Brute Force Success Detection
        brute_result = self._detect_brute_force_success(ip_address, event_type)
        if brute_result.get('detected'):
            detections.append(brute_result)
            total_boost += brute_result.get('score_boost', 0)

        # 3. Lateral Movement Detection
        lateral_result = self._detect_lateral_movement(ip_address)
        if lateral_result.get('detected'):
            detections.append(lateral_result)
            total_boost += lateral_result.get('score_boost', 0)

        return {
            'detections': detections,
            'total_boost': total_boost,
            'threat_types': [d.get('threat_type') for d in detections if d.get('threat_type')]
        }

    def _detect_impossible_travel(self, ip_address: str, username: str, geo: Dict) -> Dict:
        """
        Detect impossible travel based on velocity.
        If a user logs in from two locations faster than physically possible,
        it indicates compromised credentials.

        Returns:
            dict with: detected, score_boost, threat_type, details
        """
        if not username or not geo.get('latitude') or not geo.get('longitude'):
            return {'detected': False}

        try:
            conn = get_connection()
            cursor = conn.cursor(dictionary=True)

            # Get last successful login for this username from a different IP
            cursor.execute("""
                SELECT
                    ae.source_ip_text,
                    ae.timestamp,
                    ig.latitude,
                    ig.longitude,
                    ig.country_name,
                    ig.city
                FROM auth_events ae
                LEFT JOIN ip_geolocation ig ON ae.source_ip_text = ig.ip_address_text
                WHERE ae.target_username = %s
                AND ae.source_ip_text != %s
                AND ae.event_type LIKE '%%success%%'
                AND ae.timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
                AND ig.latitude IS NOT NULL
                ORDER BY ae.timestamp DESC
                LIMIT 1
            """, (username, ip_address))

            prev_login = cursor.fetchone()
            cursor.close()
            conn.close()

            if not prev_login:
                return {'detected': False}

            prev_lat = float(prev_login.get('latitude', 0))
            prev_lon = float(prev_login.get('longitude', 0))
            curr_lat = float(geo.get('latitude', 0))
            curr_lon = float(geo.get('longitude', 0))

            if prev_lat == 0 or prev_lon == 0:
                return {'detected': False}

            # Calculate distance using haversine
            distance_km = self._haversine_distance(prev_lat, prev_lon, curr_lat, curr_lon)

            # Calculate time difference
            prev_time = prev_login.get('timestamp')
            if not prev_time:
                return {'detected': False}

            time_diff_hours = (datetime.now() - prev_time).total_seconds() / 3600.0

            if time_diff_hours <= 0.001:  # Less than 3.6 seconds
                return {'detected': False}

            velocity_kmh = distance_km / time_diff_hours

            # > 1000 km/h is impossible (faster than commercial jet cruising speed)
            if velocity_kmh > 1000 and distance_km > 500:  # At least 500km apart
                prev_loc = f"{prev_login.get('city', 'Unknown')}, {prev_login.get('country_name', 'Unknown')}"
                curr_loc = f"{geo.get('city', 'Unknown')}, {geo.get('country_name', 'Unknown')}"

                return {
                    'detected': True,
                    'score_boost': 40,
                    'threat_type': 'impossible_travel',
                    'details': {
                        'distance_km': round(distance_km, 1),
                        'time_hours': round(time_diff_hours, 2),
                        'velocity_kmh': round(velocity_kmh, 0),
                        'from_location': prev_loc,
                        'to_location': curr_loc,
                        'previous_ip': prev_login.get('source_ip_text')
                    }
                }

        except Exception as e:
            logger.error(f"[ThreatEvaluator] Impossible travel detection error: {e}")

        return {'detected': False}

    def _detect_brute_force_success(self, ip_address: str, event_type: str) -> Dict:
        """
        Detect successful login after many failures.
        This indicates a successful brute force attack.

        Returns:
            dict with: detected, score_boost, threat_type, details
        """
        if not event_type or 'success' not in event_type.lower():
            return {'detected': False}

        try:
            conn = get_connection()
            cursor = conn.cursor(dictionary=True)

            # Count recent failures from this IP before this success
            cursor.execute("""
                SELECT
                    COUNT(*) as failure_count,
                    COUNT(DISTINCT target_username) as unique_usernames,
                    MIN(timestamp) as first_failure
                FROM auth_events
                WHERE source_ip_text = %s
                AND event_type LIKE '%%failed%%'
                AND timestamp >= DATE_SUB(NOW(), INTERVAL 1 HOUR)
            """, (ip_address,))

            stats = cursor.fetchone()
            cursor.close()
            conn.close()

            if not stats:
                return {'detected': False}

            failure_count = stats.get('failure_count', 0) or 0
            unique_usernames = stats.get('unique_usernames', 0) or 0

            # Brute force success: 10+ failures followed by success
            if failure_count >= 10:
                return {
                    'detected': True,
                    'score_boost': 35 if failure_count >= 50 else 25,
                    'threat_type': 'brute_force_success',
                    'details': {
                        'failures_before_success': failure_count,
                        'unique_usernames_tried': unique_usernames,
                        'first_failure': stats.get('first_failure').isoformat() if stats.get('first_failure') else None
                    }
                }

        except Exception as e:
            logger.error(f"[ThreatEvaluator] Brute force success detection error: {e}")

        return {'detected': False}

    def _detect_lateral_movement(self, ip_address: str) -> Dict:
        """
        Detect same IP accessing multiple servers in short time.
        This indicates lateral movement in a network.

        Returns:
            dict with: detected, score_boost, threat_type, details
        """
        try:
            conn = get_connection()
            cursor = conn.cursor(dictionary=True)

            # Count unique servers accessed by this IP in last 10 minutes
            cursor.execute("""
                SELECT
                    COUNT(DISTINCT target_server) as server_count,
                    GROUP_CONCAT(DISTINCT target_server SEPARATOR ', ') as servers,
                    COUNT(*) as total_attempts
                FROM auth_events
                WHERE source_ip_text = %s
                AND timestamp >= DATE_SUB(NOW(), INTERVAL 10 MINUTE)
                AND target_server IS NOT NULL
            """, (ip_address,))

            stats = cursor.fetchone()
            cursor.close()
            conn.close()

            if not stats:
                return {'detected': False}

            server_count = stats.get('server_count', 0) or 0
            total_attempts = stats.get('total_attempts', 0) or 0

            # Lateral movement: accessing 5+ servers in 10 minutes
            if server_count >= 5:
                return {
                    'detected': True,
                    'score_boost': 30 if server_count >= 10 else 20,
                    'threat_type': 'lateral_movement',
                    'details': {
                        'servers_accessed': server_count,
                        'total_attempts': total_attempts,
                        'server_list': stats.get('servers', '')[:200]  # Limit length
                    }
                }

        except Exception as e:
            logger.error(f"[ThreatEvaluator] Lateral movement detection error: {e}")

        return {'detected': False}

    def _haversine_distance(self, lat1: float, lon1: float, lat2: float, lon2: float) -> float:
        """Calculate distance between two points in km using Haversine formula"""
        lat1, lon1, lat2, lon2 = map(math.radians, [lat1, lon1, lat2, lon2])
        dlat = lat2 - lat1
        dlon = lon2 - lon1

        a = math.sin(dlat/2)**2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon/2)**2
        c = 2 * math.asin(math.sqrt(a))
        return 6371 * c  # Earth radius in km

    def _calculate_composite_score(self, components: Dict, detected_threats: Dict = None) -> int:
        """
        Calculate weighted composite score with critical threat boost and specialized detector boosts.

        If any major component is very high, boost the final score to ensure
        critical threats aren't diluted by low scores in other components.
        Specialized detectors add additional boosts for specific threat patterns.
        """
        weights = {
            'threat_intel_score': 0.35,  # 35% - External reputation (primary signal)
            'ml_score': 0.30,            # 30% - ML/heuristic prediction
            'behavioral_score': 0.20,    # 20% - Observed behavior
            'network_score': 0.10,       # 10% - Network characteristics
            'geo_score': 0.05            # 5%  - Geographic risk
        }

        # Calculate weighted average
        weighted_total = 0
        for key, weight in weights.items():
            weighted_total += components.get(key, 0) * weight

        # Critical threat boost: if threat_intel or ml_score is very high,
        # ensure the composite reflects the severity
        ti_score = components.get('threat_intel_score', 0)
        ml_score = components.get('ml_score', 0)
        max_major = max(ti_score, ml_score)

        # If a major component is critical (>=80), use higher of weighted vs boosted
        if max_major >= 80:
            # Boost: at least 70% of max major score
            boosted = max_major * 0.85
            weighted_total = max(weighted_total, boosted)
        elif max_major >= 60:
            # High threat: at least 60% of max major score
            boosted = max_major * 0.75
            weighted_total = max(weighted_total, boosted)

        # Add specialized detector boosts
        if detected_threats:
            detector_boost = detected_threats.get('total_boost', 0)
            weighted_total += detector_boost

            # Log detected threats for visibility
            threat_types = detected_threats.get('threat_types', [])
            if threat_types:
                logger.info(f"[ThreatEvaluator] Specialized detectors triggered: {threat_types}, boost: +{detector_boost}")

        return int(min(weighted_total, 100))

    def _calculate_confidence(self, components: Dict) -> float:
        """Calculate confidence based on data availability"""
        available = sum(1 for v in components.values() if v > 0)
        return round(available / len(components), 2)

    def _get_risk_level(self, score: int) -> str:
        """Convert score to risk level"""
        if score >= 80:
            return 'critical'
        elif score >= 60:
            return 'high'
        elif score >= 40:
            return 'medium'
        elif score >= 20:
            return 'low'
        return 'minimal'

    def _get_recommended_action(self, score: int) -> str:
        """Get recommended action based on score"""
        if score >= 80:
            return 'block_permanent'
        elif score >= 60:
            return 'block_temporary'
        elif score >= 40:
            return 'monitor_closely'
        elif score >= 20:
            return 'monitor'
        return 'allow'

    def _store_evaluation(self, result: Dict):
        """Store evaluation in ip_geolocation table (reuses existing table)"""
        try:
            conn = get_connection()
            cursor = conn.cursor()

            # Update existing ip_geolocation record with evaluation scores
            # The threat_level field stores the risk level from evaluation
            cursor.execute("""
                UPDATE ip_geolocation
                SET threat_level = %s,
                    last_seen = NOW()
                WHERE ip_address_text = %s
            """, (
                result['risk_level'],
                result['ip_address']
            ))

            conn.commit()
            cursor.close()
            conn.close()
            logger.debug(f"[ThreatEvaluator] Updated ip_geolocation for {result['ip_address']}")
        except Exception as e:
            logger.debug(f"[ThreatEvaluator] Could not update ip_geolocation: {e}")

    def store_ml_result_for_event(self, event_id: int, evaluation: Dict) -> bool:
        """
        Store ML evaluation result in auth_events_ml table for a specific event.

        Args:
            event_id: The auth_events.id
            evaluation: Result from evaluate_ip()

        Returns:
            True if stored successfully
        """
        try:
            conn = get_connection()
            cursor = conn.cursor()

            # Get ML details from evaluation
            ml_details = evaluation.get('details', {}).get('ml', {})
            composite_score = evaluation.get('composite_score', 0)
            risk_level = evaluation.get('risk_level', 'minimal')

            # Convert to decimal (0-1 scale for risk_score)
            risk_score = composite_score / 100.0

            # Determine threat type based on factors
            factors = evaluation.get('factors', [])
            threat_type = 'normal'
            if composite_score >= 80:
                threat_type = 'critical_threat'
            elif composite_score >= 60:
                threat_type = 'high_threat'
            elif composite_score >= 40:
                threat_type = 'medium_threat'
            elif any('brute' in f.lower() for f in factors):
                threat_type = 'brute_force'
            elif any('credential' in f.lower() for f in factors):
                threat_type = 'credential_stuffing'

            # Check if record already exists
            cursor.execute("SELECT id FROM auth_events_ml WHERE event_id = %s", (event_id,))
            existing = cursor.fetchone()

            # Prepare features JSON
            features_json = json.dumps(evaluation.get('components', {}))

            if existing:
                # Update existing record
                cursor.execute("""
                    UPDATE auth_events_ml
                    SET risk_score = %s,
                        threat_type = %s,
                        confidence = %s,
                        is_anomaly = %s,
                        features_snapshot = %s
                    WHERE event_id = %s
                """, (
                    risk_score,
                    threat_type,
                    ml_details.get('confidence', 0.8),
                    1 if composite_score >= 60 else 0,
                    features_json,
                    event_id
                ))
            else:
                # Insert new record
                cursor.execute("""
                    INSERT INTO auth_events_ml
                    (event_id, model_id, risk_score, threat_type, confidence, is_anomaly, features_snapshot)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                """, (
                    event_id,
                    1,  # Default model_id
                    risk_score,
                    threat_type,
                    ml_details.get('confidence', 0.8),
                    1 if composite_score >= 60 else 0,
                    features_json
                ))

            conn.commit()
            cursor.close()
            conn.close()
            logger.debug(f"[ThreatEvaluator] Stored ML result for event {event_id}: score={risk_score}")
            return True

        except Exception as e:
            logger.error(f"[ThreatEvaluator] Error storing ML result for event {event_id}: {e}")
            return False


# Singleton instance
_evaluator = None

def get_threat_evaluator() -> ThreatEvaluator:
    """Get singleton ThreatEvaluator instance"""
    global _evaluator
    if _evaluator is None:
        _evaluator = ThreatEvaluator()
    return _evaluator


def evaluate_ip_threat(ip_address: str, event_data: Dict = None) -> Dict[str, Any]:
    """Convenience function to evaluate an IP"""
    evaluator = get_threat_evaluator()
    return evaluator.evaluate_ip(ip_address, event_data)


def evaluate_and_store_for_event(event_id: int, ip_address: str, event_data: Dict = None) -> Dict[str, Any]:
    """
    Evaluate IP threat and store result in auth_events_ml.

    Args:
        event_id: The auth_events.id to associate with
        ip_address: IP to evaluate
        event_data: Optional event context

    Returns:
        Evaluation result dict
    """
    evaluator = get_threat_evaluator()
    evaluation = evaluator.evaluate_ip(ip_address, event_data)

    # Store in auth_events_ml
    evaluator.store_ml_result_for_event(event_id, evaluation)

    return evaluation
