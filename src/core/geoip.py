"""
SSH Guardian v3.0 - GeoIP Lookup Module
Provides IP geolocation enrichment using IP-API.com (free tier)
"""

import sys
from pathlib import Path
import socket
import requests
from datetime import datetime, timedelta
import time

# Add project paths
PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.append(str(PROJECT_ROOT / "dbs"))

from connection import get_connection, ip_to_binary


class GeoIPLookup:
    """
    GeoIP lookup service using IP-API.com

    Features:
    - Free tier: 45 requests/minute
    - No API key required
    - Returns comprehensive geolocation data
    - Built-in caching to avoid duplicate lookups
    """

    API_URL = "http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,proxy,hosting"
    CACHE_DURATION_DAYS = 30  # Cache GeoIP data for 30 days
    RATE_LIMIT_DELAY = 1.5  # Delay between requests (40 requests/min to be safe)

    @staticmethod
    def lookup_ip(ip_address):
        """
        Lookup geolocation for an IP address

        Args:
            ip_address (str): IP address to lookup

        Returns:
            dict: GeoIP data or None if lookup fails
        """

        # Check if it's a valid IP
        try:
            # Validate IP format
            socket.inet_aton(ip_address) if '.' in ip_address else socket.inet_pton(socket.AF_INET6, ip_address)
        except socket.error:
            print(f"❌ Invalid IP address: {ip_address}")
            return None

        # Check cache first
        cached_data = GeoIPLookup._get_from_cache(ip_address)
        if cached_data:
            print(f"✅ GeoIP cache hit for {ip_address}")
            return cached_data

        # Fetch from API
        print(f"🌐 Fetching GeoIP data for {ip_address}...")

        try:
            # Rate limiting
            time.sleep(GeoIPLookup.RATE_LIMIT_DELAY)

            response = requests.get(
                GeoIPLookup.API_URL.format(ip=ip_address),
                timeout=5
            )

            if response.status_code != 200:
                print(f"❌ GeoIP API error: HTTP {response.status_code}")
                return None

            data = response.json()

            if data.get('status') == 'fail':
                print(f"❌ GeoIP lookup failed: {data.get('message', 'Unknown error')}")
                return None

            # Parse response
            geo_data = GeoIPLookup._parse_response(ip_address, data)

            # Save to cache
            GeoIPLookup._save_to_cache(geo_data)

            print(f"✅ GeoIP data retrieved: {geo_data['city']}, {geo_data['country_name']}")

            return geo_data

        except requests.RequestException as e:
            print(f"❌ GeoIP API request failed: {e}")
            return None
        except Exception as e:
            print(f"❌ GeoIP lookup error: {e}")
            return None

    @staticmethod
    def _parse_response(ip_address, data):
        """Parse API response into database format"""

        # Detect IP version
        ip_version = 4 if '.' in ip_address else 6

        # Convert IP to binary
        ip_binary = ip_to_binary(ip_address)

        # Extract ASN number from 'as' field (format: "AS15169 Google LLC")
        asn = None
        asn_org = None
        if data.get('as'):
            parts = data['as'].split(' ', 1)
            if parts[0].startswith('AS'):
                try:
                    asn = int(parts[0][2:])
                    asn_org = parts[1] if len(parts) > 1 else None
                except ValueError:
                    pass

        # Calculate cache expiration
        cache_expires_at = datetime.now() + timedelta(days=GeoIPLookup.CACHE_DURATION_DAYS)

        return {
            'ip_address': ip_binary,
            'ip_address_text': ip_address,
            'ip_version': ip_version,
            'country_code': data.get('countryCode'),
            'country_name': data.get('country'),
            'region': data.get('regionName'),
            'city': data.get('city'),
            'postal_code': data.get('zip'),
            'latitude': data.get('lat'),
            'longitude': data.get('lon'),
            'timezone': data.get('timezone'),
            'asn': asn,
            'asn_org': asn_org or data.get('org'),
            'isp': data.get('isp'),
            'connection_type': None,  # Not provided by IP-API
            'is_proxy': data.get('proxy', False),
            'is_vpn': False,  # Not provided by IP-API free tier
            'is_tor': False,  # Not provided by IP-API free tier
            'is_datacenter': False,  # Inferred from hosting flag
            'is_hosting': data.get('hosting', False),
            'lookup_count': 1,
            'cache_expires_at': cache_expires_at
        }

    @staticmethod
    def _get_from_cache(ip_address):
        """Check if IP geolocation is in cache"""

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            cursor.execute("""
                SELECT
                    id,
                    ip_address,
                    ip_address_text,
                    ip_version,
                    country_code,
                    country_name,
                    region,
                    city,
                    postal_code,
                    latitude,
                    longitude,
                    timezone,
                    asn,
                    asn_org,
                    isp,
                    connection_type,
                    is_proxy,
                    is_vpn,
                    is_tor,
                    is_datacenter,
                    is_hosting,
                    lookup_count,
                    cache_expires_at
                FROM ip_geolocation
                WHERE ip_address_text = %s
                AND (cache_expires_at IS NULL OR cache_expires_at > NOW())
            """, (ip_address,))

            cached = cursor.fetchone()

            if cached:
                # Update lookup count and last_seen
                cursor.execute("""
                    UPDATE ip_geolocation
                    SET lookup_count = lookup_count + 1,
                        last_seen = NOW()
                    WHERE id = %s
                """, (cached['id'],))
                conn.commit()

                return cached

            return None

        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def _save_to_cache(geo_data):
        """Save GeoIP data to cache"""

        conn = get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("""
                INSERT INTO ip_geolocation (
                    ip_address,
                    ip_address_text,
                    ip_version,
                    country_code,
                    country_name,
                    region,
                    city,
                    postal_code,
                    latitude,
                    longitude,
                    timezone,
                    asn,
                    asn_org,
                    isp,
                    connection_type,
                    is_proxy,
                    is_vpn,
                    is_tor,
                    is_datacenter,
                    is_hosting,
                    lookup_count,
                    cache_expires_at
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                )
                ON DUPLICATE KEY UPDATE
                    lookup_count = lookup_count + 1,
                    last_seen = NOW()
            """, (
                geo_data['ip_address'],
                geo_data['ip_address_text'],
                geo_data['ip_version'],
                geo_data['country_code'],
                geo_data['country_name'],
                geo_data['region'],
                geo_data['city'],
                geo_data['postal_code'],
                geo_data['latitude'],
                geo_data['longitude'],
                geo_data['timezone'],
                geo_data['asn'],
                geo_data['asn_org'],
                geo_data['isp'],
                geo_data['connection_type'],
                geo_data['is_proxy'],
                geo_data['is_vpn'],
                geo_data['is_tor'],
                geo_data['is_datacenter'],
                geo_data['is_hosting'],
                geo_data['lookup_count'],
                geo_data['cache_expires_at']
            ))

            geo_id = cursor.lastrowid
            conn.commit()

            print(f"💾 Cached GeoIP data (ID: {geo_id})")

            return geo_id

        except Exception as e:
            conn.rollback()
            print(f"❌ Failed to cache GeoIP data: {e}")
            return None
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def enrich_event_with_geoip(event_id, ip_address):
        """
        Enrich an auth_event with GeoIP data

        Args:
            event_id (int): auth_events.id
            ip_address (str): IP address to lookup

        Returns:
            int: geo_id if successful, None otherwise
        """

        # Lookup GeoIP data
        geo_data = GeoIPLookup.lookup_ip(ip_address)

        if not geo_data:
            print(f"❌ Could not enrich event {event_id} - GeoIP lookup failed")
            return None

        # Get geo_id
        geo_id = geo_data.get('id')

        if not geo_id:
            # If data was just cached, get the ID
            conn = get_connection()
            cursor = conn.cursor(dictionary=True)

            try:
                cursor.execute("""
                    SELECT id FROM ip_geolocation
                    WHERE ip_address_text = %s
                """, (ip_address,))

                result = cursor.fetchone()
                geo_id = result['id'] if result else None

            finally:
                cursor.close()
                conn.close()

        if not geo_id:
            print(f"❌ Could not find geo_id for {ip_address}")
            return None

        # Update auth_event with geo_id
        conn = get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("""
                UPDATE auth_events
                SET geo_id = %s,
                    processing_status = CASE
                        WHEN processing_status = 'pending' THEN 'geoip_complete'
                        ELSE processing_status
                    END
                WHERE id = %s
            """, (geo_id, event_id))

            conn.commit()

            print(f"✅ Event {event_id} enriched with GeoIP data (geo_id: {geo_id})")

            return geo_id

        except Exception as e:
            conn.rollback()
            print(f"❌ Failed to enrich event {event_id}: {e}")
            return None
        finally:
            cursor.close()
            conn.close()


# Utility functions for easy import
def lookup_ip(ip_address):
    """Convenience function for IP lookup"""
    return GeoIPLookup.lookup_ip(ip_address)


def enrich_event(event_id, ip_address):
    """Convenience function for event enrichment"""
    return GeoIPLookup.enrich_event_with_geoip(event_id, ip_address)
