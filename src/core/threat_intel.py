"""
SSH Guardian v3.0 - Threat Intelligence Module
Integrates with AbuseIPDB, VirusTotal, and Shodan for IP reputation checking
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

# Load environment variables
load_dotenv(PROJECT_ROOT / ".env")


def _get_api_key_from_db(integration_id: str) -> str:
    """Load API key from database integration_config table."""
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT config_value FROM integration_config
            WHERE integration_id = %s AND config_key = 'api_key'
        """, (integration_id,))
        row = cursor.fetchone()
        cursor.close()
        conn.close()
        return row.get('config_value') if row else None
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

        # Calculate overall threat
        threat_level, confidence = ThreatIntelligence.calculate_threat_level(
            abuseipdb_data,
            virustotal_data,
            shodan_data
        )

        print(f"\n📊 Overall Threat Level: {threat_level.upper()} (confidence: {confidence:.2f})")
        print("="*70)

        # Prepare data for storage
        threat_data = {
            'ip_address_text': ip_address,
            'abuseipdb': abuseipdb_data,
            'virustotal': virustotal_data,
            'shodan': shodan_data,
            'threat_level': threat_level,
            'confidence': confidence
        }

        # Save to cache
        ThreatIntelligence._save_to_cache(threat_data)

        return threat_data

    @staticmethod
    def _get_from_cache(ip_address):
        """Check if threat intelligence is in cache"""

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            cursor.execute("""
                SELECT *
                FROM ip_threat_intelligence
                WHERE ip_address_text = %s
                AND (needs_refresh = FALSE OR refresh_after > NOW())
            """, (ip_address,))

            cached = cursor.fetchone()
            return cached

        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def _save_to_cache(threat_data):
        """Save threat intelligence to cache"""

        conn = get_connection()
        cursor = conn.cursor()

        try:
            # Calculate refresh date
            refresh_after = datetime.now() + timedelta(days=ThreatIntelligence.CACHE_DURATION_DAYS)

            # Extract data
            ip = threat_data['ip_address_text']
            abuseipdb = threat_data.get('abuseipdb', {})
            virustotal = threat_data.get('virustotal', {})
            shodan = threat_data.get('shodan', {})

            cursor.execute("""
                INSERT INTO ip_threat_intelligence (
                    ip_address_text,
                    abuseipdb_score,
                    abuseipdb_confidence,
                    abuseipdb_reports,
                    abuseipdb_checked_at,
                    virustotal_positives,
                    virustotal_total,
                    virustotal_checked_at,
                    shodan_ports,
                    shodan_tags,
                    shodan_vulns,
                    shodan_checked_at,
                    overall_threat_level,
                    threat_confidence,
                    needs_refresh,
                    refresh_after
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, FALSE, %s
                )
                ON DUPLICATE KEY UPDATE
                    abuseipdb_score = VALUES(abuseipdb_score),
                    abuseipdb_confidence = VALUES(abuseipdb_confidence),
                    abuseipdb_reports = VALUES(abuseipdb_reports),
                    abuseipdb_checked_at = VALUES(abuseipdb_checked_at),
                    virustotal_positives = VALUES(virustotal_positives),
                    virustotal_total = VALUES(virustotal_total),
                    virustotal_checked_at = VALUES(virustotal_checked_at),
                    shodan_ports = VALUES(shodan_ports),
                    shodan_tags = VALUES(shodan_tags),
                    shodan_vulns = VALUES(shodan_vulns),
                    shodan_checked_at = VALUES(shodan_checked_at),
                    overall_threat_level = VALUES(overall_threat_level),
                    threat_confidence = VALUES(threat_confidence),
                    needs_refresh = FALSE,
                    refresh_after = VALUES(refresh_after),
                    updated_at = NOW()
            """, (
                ip,
                abuseipdb.get('score') if abuseipdb else None,
                abuseipdb.get('confidence') if abuseipdb else None,
                abuseipdb.get('reports') if abuseipdb else None,
                abuseipdb.get('checked_at') if abuseipdb else None,
                virustotal.get('positives') if virustotal else None,
                virustotal.get('total') if virustotal else None,
                virustotal.get('checked_at') if virustotal else None,
                json.dumps(shodan.get('ports', [])) if shodan else None,
                json.dumps(shodan.get('tags', [])) if shodan else None,
                json.dumps(shodan.get('vulns', [])) if shodan else None,
                shodan.get('checked_at') if shodan else None,
                threat_data['threat_level'],
                threat_data['confidence'],
                refresh_after
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
