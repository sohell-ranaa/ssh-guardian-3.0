"""
SSH Guardian v3.1 - Threat Intelligence Module
Integrates with AbuseIPDB, VirusTotal, and Shodan for IP reputation checking
Updated for v3.1 schema (threat intel merged into ip_geolocation table)
"""

import sys
from pathlib import Path
import os
import requests
import time
from datetime import datetime, timedelta
from dotenv import load_dotenv
import json

# Add project paths
PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.append(str(PROJECT_ROOT / "dbs"))

from connection import get_connection
from integrations_config import get_integration_config_value

# Load environment variables
load_dotenv(PROJECT_ROOT / ".env")


def _get_api_key_from_db(integration_type: str) -> str:
    """Load API key from database integrations table (v3.1 schema)."""
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT credentials FROM integrations
            WHERE integration_type = %s
        """, (integration_type,))
        row = cursor.fetchone()
        cursor.close()
        conn.close()
        if row and row.get('credentials'):
            creds = row['credentials']
            if isinstance(creds, str):
                creds = json.loads(creds)
            return creds.get('api_key')
        return None
    except Exception:
        return None


class ThreatIntelligence:
    """
    Threat Intelligence API integrations

    Supported services:
    - AbuseIPDB: IP reputation and abuse reports
    - VirusTotal: IP reputation and detected URLs
    - Shodan: Open ports and vulnerabilities
    """

    # API Configuration - Try env vars first, then database
    ABUSEIPDB_API_KEY = os.getenv('ABUSEIPDB_API_KEY') or _get_api_key_from_db('abuseipdb')
    VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY') or _get_api_key_from_db('virustotal')
    SHODAN_API_KEY = os.getenv('SHODAN_API_KEY') or _get_api_key_from_db('shodan')

    # Rate limits (per day)
    ABUSEIPDB_RATE_LIMIT = int(os.getenv('ABUSEIPDB_RATE_LIMIT_PER_DAY', 1000))
    VIRUSTOTAL_RATE_LIMIT = int(os.getenv('VIRUSTOTAL_RATE_LIMIT_PER_DAY', 250))

    # Cache duration
    CACHE_DURATION_DAYS = 7  # Refresh threat intel every 7 days

    # API Endpoints
    ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
    VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    SHODAN_URL = "https://api.shodan.io/shodan/host/{ip}"
    GREYNOISE_COMMUNITY_URL = "https://api.greynoise.io/v3/community/{ip}"
    GREYNOISE_ENTERPRISE_URL = "https://api.greynoise.io/v2/noise/context/{ip}"

    @staticmethod
    def check_abuseipdb(ip_address):
        """
        Check IP reputation on AbuseIPDB

        Returns:
            dict: AbuseIPDB data or None
        """

        if not ThreatIntelligence.ABUSEIPDB_API_KEY:
            print("⚠️  AbuseIPDB API key not configured")
            return None

        try:
            headers = {
                'Key': ThreatIntelligence.ABUSEIPDB_API_KEY,
                'Accept': 'application/json'
            }

            params = {
                'ipAddress': ip_address,
                'maxAgeInDays': 90,
                'verbose': True
            }

            print(f"🔍 Checking AbuseIPDB for {ip_address}...")

            response = requests.get(
                ThreatIntelligence.ABUSEIPDB_URL,
                headers=headers,
                params=params,
                timeout=10
            )

            if response.status_code == 200:
                data = response.json().get('data', {})

                result = {
                    'score': data.get('abuseConfidenceScore', 0),
                    'confidence': data.get('abuseConfidenceScore', 0),
                    'reports': data.get('totalReports', 0),
                    'last_reported': data.get('lastReportedAt'),
                    'categories': data.get('reports', []),
                    'checked_at': datetime.now()
                }

                print(f"✅ AbuseIPDB: Score {result['score']}, Reports {result['reports']}")
                return result

            elif response.status_code == 429:
                print("⚠️  AbuseIPDB rate limit exceeded")
                return None

            else:
                print(f"❌ AbuseIPDB error: HTTP {response.status_code}")
                return None

        except Exception as e:
            print(f"❌ AbuseIPDB lookup failed: {e}")
            return None

    @staticmethod
    def check_virustotal(ip_address):
        """
        Check IP reputation on VirusTotal

        Returns:
            dict: VirusTotal data or None
        """

        if not ThreatIntelligence.VIRUSTOTAL_API_KEY:
            print("⚠️  VirusTotal API key not configured")
            return None

        try:
            headers = {
                'x-apikey': ThreatIntelligence.VIRUSTOTAL_API_KEY
            }

            url = ThreatIntelligence.VIRUSTOTAL_URL.format(ip=ip_address)

            print(f"🔍 Checking VirusTotal for {ip_address}...")

            response = requests.get(
                url,
                headers=headers,
                timeout=10
            )

            if response.status_code == 200:
                data = response.json().get('data', {})
                attributes = data.get('attributes', {})
                stats = attributes.get('last_analysis_stats', {})

                result = {
                    'positives': stats.get('malicious', 0),
                    'total': sum(stats.values()),
                    'detected_urls': attributes.get('last_https_certificate', {}),
                    'checked_at': datetime.now()
                }

                print(f"✅ VirusTotal: {result['positives']}/{result['total']} detections")
                return result

            elif response.status_code == 429:
                print("⚠️  VirusTotal rate limit exceeded")
                return None

            elif response.status_code == 404:
                print("ℹ️  IP not found in VirusTotal database")
                return {
                    'positives': 0,
                    'total': 0,
                    'detected_urls': {},
                    'checked_at': datetime.now()
                }

            else:
                print(f"❌ VirusTotal error: HTTP {response.status_code}")
                return None

        except Exception as e:
            print(f"❌ VirusTotal lookup failed: {e}")
            return None

    @staticmethod
    def check_shodan(ip_address):
        """
        Check IP information on Shodan

        Returns:
            dict: Shodan data or None
        """

        if not ThreatIntelligence.SHODAN_API_KEY:
            print("⚠️  Shodan API key not configured")
            return None

        try:
            url = ThreatIntelligence.SHODAN_URL.format(ip=ip_address)
            params = {'key': ThreatIntelligence.SHODAN_API_KEY}

            print(f"🔍 Checking Shodan for {ip_address}...")

            response = requests.get(
                url,
                params=params,
                timeout=10
            )

            if response.status_code == 200:
                data = response.json()

                result = {
                    'ports': data.get('ports', []),
                    'tags': data.get('tags', []),
                    'vulns': data.get('vulns', []),
                    'last_update': data.get('last_update'),
                    'checked_at': datetime.now()
                }

                print(f"✅ Shodan: {len(result['ports'])} ports, {len(result['vulns'])} vulnerabilities")
                return result

            elif response.status_code == 404:
                print("ℹ️  IP not found in Shodan database")
                return {
                    'ports': [],
                    'tags': [],
                    'vulns': [],
                    'last_update': None,
                    'checked_at': datetime.now()
                }

            else:
                print(f"❌ Shodan error: HTTP {response.status_code}")
                return None

        except Exception as e:
            print(f"❌ Shodan lookup failed: {e}")
            return None

    @staticmethod
    def check_greynoise(ip_address):
        """
        Check IP against GreyNoise to determine if it's internet noise or targeted attack.
        Uses Community API (free, 100/day) or Enterprise API if key configured.

        Returns:
            dict: GreyNoise data or None
            - noise: True if IP is a known internet scanner
            - riot: True if IP belongs to a known benign service (e.g., Google, Microsoft)
            - classification: 'benign', 'malicious', or 'unknown'
        """
        try:
            # Check if enterprise API key is configured
            api_key = _get_api_key_from_db('greynoise')
            use_community = get_integration_config_value('greynoise', 'use_community_api')

            if api_key and use_community != 'true':
                # Use Enterprise API
                url = ThreatIntelligence.GREYNOISE_ENTERPRISE_URL.format(ip=ip_address)
                headers = {'key': api_key, 'Accept': 'application/json'}
            else:
                # Use Community API (free, no key required)
                url = ThreatIntelligence.GREYNOISE_COMMUNITY_URL.format(ip=ip_address)
                headers = {'Accept': 'application/json'}
                if api_key:
                    headers['key'] = api_key

            print(f"🔍 Checking GreyNoise for {ip_address}...")

            response = requests.get(url, headers=headers, timeout=10)

            if response.status_code == 200:
                data = response.json()

                result = {
                    'noise': data.get('noise', False),
                    'riot': data.get('riot', False),
                    'classification': data.get('classification', 'unknown'),
                    'name': data.get('name', ''),  # For RIOT IPs (e.g., "Google")
                    'link': data.get('link', ''),
                    'last_seen': data.get('last_seen'),
                    'message': data.get('message', ''),
                    'checked_at': datetime.now()
                }

                status = []
                if result['noise']:
                    status.append('Internet Scanner')
                if result['riot']:
                    status.append(f"Known Service: {result['name']}")
                if result['classification'] == 'malicious':
                    status.append('Malicious')

                print(f"✅ GreyNoise: {', '.join(status) if status else 'Unknown/Clean'}")
                return result

            elif response.status_code == 404:
                # IP not found in GreyNoise database - this is normal for most IPs
                print("ℹ️  IP not found in GreyNoise database (not a known scanner)")
                return {
                    'noise': False,
                    'riot': False,
                    'classification': 'unknown',
                    'name': '',
                    'link': '',
                    'last_seen': None,
                    'message': 'IP not observed',
                    'checked_at': datetime.now()
                }

            elif response.status_code == 429:
                print("⚠️  GreyNoise rate limit exceeded")
                return None

            else:
                print(f"❌ GreyNoise error: HTTP {response.status_code}")
                return None

        except Exception as e:
            print(f"❌ GreyNoise lookup failed: {e}")
            return None

    @staticmethod
    def calculate_threat_level(abuseipdb_data, virustotal_data, shodan_data):
        """
        Calculate overall threat level based on all sources

        Returns:
            tuple: (threat_level, confidence)
        """

        threat_score = 0
        confidence_factors = []

        # AbuseIPDB scoring (0-100)
        if abuseipdb_data:
            abuse_score = abuseipdb_data.get('score', 0)
            threat_score += abuse_score

            if abuse_score > 0:
                confidence_factors.append(0.4)  # High confidence for abuse reports

        # VirusTotal scoring
        if virustotal_data:
            vt_positives = virustotal_data.get('positives', 0)
            vt_total = virustotal_data.get('total', 1)

            if vt_total > 0:
                vt_percentage = (vt_positives / vt_total) * 100
                threat_score += vt_percentage * 0.5  # Weight VirusTotal at 50%

                if vt_positives > 0:
                    confidence_factors.append(0.3)

        # Shodan scoring (presence of vulnerabilities)
        if shodan_data:
            vulns = shodan_data.get('vulns', [])
            if len(vulns) > 0:
                threat_score += min(len(vulns) * 10, 30)  # Max 30 points for vulns
                confidence_factors.append(0.2)

        # Calculate average threat score
        avg_threat_score = threat_score / 1.5  # Normalize

        # Determine threat level
        if avg_threat_score >= 75:
            threat_level = 'critical'
        elif avg_threat_score >= 50:
            threat_level = 'high'
        elif avg_threat_score >= 25:
            threat_level = 'medium'
        elif avg_threat_score > 0:
            threat_level = 'low'
        else:
            threat_level = 'clean'

        # Calculate confidence (0.0-1.0)
        confidence = sum(confidence_factors) if confidence_factors else 0.1
        confidence = min(confidence, 1.0)

        return threat_level, confidence

    @staticmethod
    def lookup_ip_threat(ip_address):
        """
        Comprehensive threat intelligence lookup

        Args:
            ip_address (str): IP address to check

        Returns:
            dict: Combined threat intelligence data
        """

        print(f"\n🔍 Threat Intelligence Lookup: {ip_address}")
        print("="*70)

        # Check cache first
        cached_data = ThreatIntelligence._get_from_cache(ip_address)
        if cached_data:
            print(f"✅ Cache hit - data from {cached_data.get('updated_at')}")
            return cached_data

        # Perform lookups (with delays to respect rate limits)
        abuseipdb_data = ThreatIntelligence.check_abuseipdb(ip_address)
        time.sleep(1)  # Rate limiting delay

        virustotal_data = ThreatIntelligence.check_virustotal(ip_address)
        time.sleep(1)

        shodan_data = ThreatIntelligence.check_shodan(ip_address)
        time.sleep(0.5)

        # GreyNoise lookup (helps distinguish scanners from targeted attacks)
        greynoise_data = ThreatIntelligence.check_greynoise(ip_address)

        # Calculate overall threat
        threat_level, confidence = ThreatIntelligence.calculate_threat_level(
            abuseipdb_data,
            virustotal_data,
            shodan_data
        )

        # Adjust threat level based on GreyNoise data
        if greynoise_data:
            if greynoise_data.get('riot'):
                # Known benign service (Google, Microsoft, etc.) - lower threat
                if threat_level in ['medium', 'high']:
                    threat_level = 'low'
                    print(f"ℹ️  GreyNoise RIOT: Known benign service, lowering threat level")
            elif greynoise_data.get('noise') and greynoise_data.get('classification') == 'malicious':
                # Known malicious scanner - raise threat
                if threat_level in ['clean', 'low', 'medium']:
                    threat_level = 'high'
                    confidence = max(confidence, 0.7)
                    print(f"⚠️  GreyNoise: Known malicious scanner, raising threat level")

        print(f"\n📊 Overall Threat Level: {threat_level.upper()} (confidence: {confidence:.2f})")
        print("="*70)

        # Prepare data for storage
        threat_data = {
            'ip_address_text': ip_address,
            'abuseipdb': abuseipdb_data,
            'virustotal': virustotal_data,
            'shodan': shodan_data,
            'greynoise': greynoise_data,
            'threat_level': threat_level,
            'confidence': confidence
        }

        # Save to cache
        ThreatIntelligence._save_to_cache(threat_data)

        return threat_data

    @staticmethod
    def _get_from_cache(ip_address):
        """Check if threat intelligence is in cache (v3.1: using ip_geolocation table)"""

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            # v3.1: Threat intel is now merged into ip_geolocation table
            cursor.execute("""
                SELECT
                    ip_address_text,
                    abuseipdb_score,
                    abuseipdb_reports,
                    abuseipdb_last_reported,
                    abuseipdb_checked_at,
                    virustotal_positives,
                    virustotal_total,
                    virustotal_checked_at,
                    shodan_ports,
                    shodan_vulns,
                    shodan_checked_at,
                    threat_level,
                    last_seen as updated_at
                FROM ip_geolocation
                WHERE ip_address_text = %s
                AND abuseipdb_checked_at IS NOT NULL
                AND abuseipdb_checked_at > DATE_SUB(NOW(), INTERVAL 7 DAY)
            """, (ip_address,))

            cached = cursor.fetchone()
            return cached

        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def _save_to_cache(threat_data):
        """Save threat intelligence to cache (writes to both ip_geolocation and ip_threat_intelligence)"""

        conn = get_connection()
        cursor = conn.cursor()

        try:
            # Extract data (use 'or {}' to handle None values)
            ip = threat_data['ip_address_text']
            abuseipdb = threat_data.get('abuseipdb') or {}
            virustotal = threat_data.get('virustotal') or {}
            shodan = threat_data.get('shodan') or {}
            greynoise = threat_data.get('greynoise') or {}

            # Also save to ip_threat_intelligence table (for compatibility with other modules)
            cursor.execute("SELECT id FROM ip_threat_intelligence WHERE ip_address_text = %s", (ip,))
            ti_exists = cursor.fetchone()

            if ti_exists:
                cursor.execute("""
                    UPDATE ip_threat_intelligence SET
                        abuseipdb_score = %s,
                        abuseipdb_confidence = %s,
                        abuseipdb_reports = %s,
                        abuseipdb_last_reported = %s,
                        abuseipdb_checked_at = %s,
                        virustotal_positives = %s,
                        virustotal_total = %s,
                        virustotal_checked_at = %s,
                        shodan_ports = %s,
                        shodan_vulns = %s,
                        shodan_checked_at = %s,
                        overall_threat_level = %s,
                        threat_confidence = %s,
                        last_seen = NOW()
                    WHERE ip_address_text = %s
                """, (
                    abuseipdb.get('score'),
                    abuseipdb.get('confidence'),
                    abuseipdb.get('reports'),
                    abuseipdb.get('last_reported'),
                    abuseipdb.get('checked_at'),
                    virustotal.get('positives'),
                    virustotal.get('total'),
                    virustotal.get('checked_at'),
                    json.dumps(shodan.get('ports', [])) if shodan else None,
                    json.dumps(shodan.get('vulns', [])) if shodan else None,
                    shodan.get('checked_at'),
                    threat_data.get('threat_level', 'clean'),
                    threat_data.get('confidence', 0),
                    ip
                ))
            else:
                cursor.execute("""
                    INSERT INTO ip_threat_intelligence (
                        ip_address_text,
                        abuseipdb_score, abuseipdb_confidence, abuseipdb_reports,
                        abuseipdb_last_reported, abuseipdb_checked_at,
                        virustotal_positives, virustotal_total, virustotal_checked_at,
                        shodan_ports, shodan_vulns, shodan_checked_at,
                        overall_threat_level, threat_confidence
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (
                    ip,
                    abuseipdb.get('score'),
                    abuseipdb.get('confidence'),
                    abuseipdb.get('reports'),
                    abuseipdb.get('last_reported'),
                    abuseipdb.get('checked_at'),
                    virustotal.get('positives'),
                    virustotal.get('total'),
                    virustotal.get('checked_at'),
                    json.dumps(shodan.get('ports', [])) if shodan else None,
                    json.dumps(shodan.get('vulns', [])) if shodan else None,
                    shodan.get('checked_at'),
                    threat_data.get('threat_level', 'clean'),
                    threat_data.get('confidence', 0)
                ))

            # v3.1: Threat intel is now merged into ip_geolocation table
            # First check if IP exists
            cursor.execute("SELECT id FROM ip_geolocation WHERE ip_address_text = %s", (ip,))
            existing = cursor.fetchone()

            if existing:
                # Update existing record
                cursor.execute("""
                    UPDATE ip_geolocation SET
                        abuseipdb_score = %s,
                        abuseipdb_reports = %s,
                        abuseipdb_last_reported = %s,
                        abuseipdb_checked_at = %s,
                        virustotal_positives = %s,
                        virustotal_total = %s,
                        virustotal_checked_at = %s,
                        shodan_ports = %s,
                        shodan_vulns = %s,
                        shodan_checked_at = %s,
                        greynoise_noise = %s,
                        greynoise_riot = %s,
                        greynoise_classification = %s,
                        greynoise_checked_at = %s,
                        threat_level = %s,
                        last_seen = NOW()
                    WHERE ip_address_text = %s
                """, (
                    abuseipdb.get('score') if abuseipdb else None,
                    abuseipdb.get('reports') if abuseipdb else None,
                    abuseipdb.get('last_reported') if abuseipdb else None,
                    abuseipdb.get('checked_at') if abuseipdb else None,
                    virustotal.get('positives') if virustotal else None,
                    virustotal.get('total') if virustotal else None,
                    virustotal.get('checked_at') if virustotal else None,
                    json.dumps(shodan.get('ports', [])) if shodan else None,
                    json.dumps(shodan.get('vulns', [])) if shodan else None,
                    shodan.get('checked_at') if shodan else None,
                    greynoise.get('noise') if greynoise else None,
                    greynoise.get('riot') if greynoise else None,
                    greynoise.get('classification') if greynoise else None,
                    greynoise.get('checked_at') if greynoise else None,
                    threat_data['threat_level'],
                    ip
                ))
            else:
                # Insert new record with basic geolocation placeholder
                import socket
                import struct
                ip_binary = socket.inet_aton(ip) if '.' in ip else socket.inet_pton(socket.AF_INET6, ip)

                cursor.execute("""
                    INSERT INTO ip_geolocation (
                        ip_address, ip_address_text, ip_version,
                        abuseipdb_score, abuseipdb_reports, abuseipdb_last_reported, abuseipdb_checked_at,
                        virustotal_positives, virustotal_total, virustotal_checked_at,
                        shodan_ports, shodan_vulns, shodan_checked_at,
                        greynoise_noise, greynoise_riot, greynoise_classification, greynoise_checked_at,
                        threat_level, last_seen
                    ) VALUES (
                        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW()
                    )
                """, (
                    ip_binary,
                    ip,
                    4 if '.' in ip else 6,
                    abuseipdb.get('score') if abuseipdb else None,
                    abuseipdb.get('reports') if abuseipdb else None,
                    abuseipdb.get('last_reported') if abuseipdb else None,
                    abuseipdb.get('checked_at') if abuseipdb else None,
                    virustotal.get('positives') if virustotal else None,
                    virustotal.get('total') if virustotal else None,
                    virustotal.get('checked_at') if virustotal else None,
                    json.dumps(shodan.get('ports', [])) if shodan else None,
                    json.dumps(shodan.get('vulns', [])) if shodan else None,
                    shodan.get('checked_at') if shodan else None,
                    greynoise.get('noise') if greynoise else None,
                    greynoise.get('riot') if greynoise else None,
                    greynoise.get('classification') if greynoise else None,
                    greynoise.get('checked_at') if greynoise else None,
                    threat_data['threat_level']
                ))

            conn.commit()
            print(f"💾 Threat intelligence cached for {ip}")

        except Exception as e:
            conn.rollback()
            print(f"❌ Failed to cache threat data: {e}")
        finally:
            cursor.close()
            conn.close()


# Convenience function
def check_ip_threat(ip_address):
    """Convenience function for threat intelligence lookup"""
    return ThreatIntelligence.lookup_ip_threat(ip_address)
