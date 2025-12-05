"""
SSH Guardian v3.0 - IP Information Routes
API endpoints for IP geolocation with provider selection
Supports: FreeIPAPI, IP-API
"""

from flask import Blueprint, jsonify
import sys
from pathlib import Path
import requests

# Add project paths
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
sys.path.append(str(PROJECT_ROOT / "dbs"))
sys.path.append(str(PROJECT_ROOT / "src" / "core"))

from cache import get_cache, cache_key
from integrations_config import get_integration_config_value

# Create Blueprint
ip_info_routes = Blueprint('ip_info_routes', __name__, url_prefix='/api/dashboard/ip-info')

# Provider URLs
FREEIPAPI_BASE_URL = "https://freeipapi.com/api/json"
IPAPI_BASE_URL = "http://ip-api.com/json"

# Cache TTL - 24 hours for IP geolocation (doesn't change frequently)
IP_INFO_TTL = 86400


def get_primary_provider():
    """Determine which GeoIP provider to use as primary"""
    try:
        # Check FreeIPAPI settings
        freeipapi_primary = get_integration_config_value('freeipapi', 'use_as_primary')
        freeipapi_enabled = get_integration_config_value('freeipapi', 'enabled')

        # Check IP-API settings
        ipapi_primary = get_integration_config_value('ipapi', 'use_as_primary')
        ipapi_enabled = get_integration_config_value('ipapi', 'enabled')

        # If IP-API is set as primary and enabled, use it
        if ipapi_primary == 'true' and ipapi_enabled == 'true':
            return 'ipapi'
        # If FreeIPAPI is primary and enabled, use it
        elif freeipapi_primary == 'true' and freeipapi_enabled == 'true':
            return 'freeipapi'
        # If only one is enabled, use that one
        elif freeipapi_enabled == 'true':
            return 'freeipapi'
        elif ipapi_enabled == 'true':
            return 'ipapi'
        # Default to FreeIPAPI
        return 'freeipapi'
    except Exception:
        return 'freeipapi'


def fetch_from_freeipapi(ip_address):
    """Fetch IP info from FreeIPAPI"""
    response = requests.get(
        f"{FREEIPAPI_BASE_URL}/{ip_address}",
        timeout=10,
        allow_redirects=True
    )

    if response.status_code == 200:
        data = response.json()
        return {
            'success': True,
            'provider': 'freeipapi',
            'ip_address': data.get('ipAddress', ip_address),
            'ip_version': data.get('ipVersion', 4),
            'country': data.get('countryName', 'Unknown'),
            'country_code': data.get('countryCode', 'N/A'),
            'city': data.get('cityName', 'Unknown'),
            'region': data.get('regionName', 'Unknown'),
            'latitude': data.get('latitude', 0),
            'longitude': data.get('longitude', 0),
            'timezone': data.get('timeZones', ['N/A'])[0] if data.get('timeZones') else 'N/A',
            'isp': data.get('asnOrganization', 'Unknown'),
            'asn': data.get('asn', 'N/A'),
            'is_proxy': data.get('isProxy', False),
            'continent': data.get('continent', 'Unknown'),
            'continent_code': data.get('continentCode', 'N/A'),
            'zip_code': data.get('zipCode', 'N/A'),
            'is_private': False,
            'from_cache': False
        }
    return None


def fetch_from_ipapi(ip_address):
    """Fetch IP info from IP-API"""
    response = requests.get(
        f"{IPAPI_BASE_URL}/{ip_address}",
        timeout=10
    )

    if response.status_code == 200:
        data = response.json()
        if data.get('status') == 'success':
            return {
                'success': True,
                'provider': 'ipapi',
                'ip_address': data.get('query', ip_address),
                'ip_version': 4,
                'country': data.get('country', 'Unknown'),
                'country_code': data.get('countryCode', 'N/A'),
                'city': data.get('city', 'Unknown'),
                'region': data.get('regionName', 'Unknown'),
                'latitude': data.get('lat', 0),
                'longitude': data.get('lon', 0),
                'timezone': data.get('timezone', 'N/A'),
                'isp': data.get('isp', 'Unknown'),
                'asn': data.get('as', 'N/A').split(' ')[0] if data.get('as') else 'N/A',
                'is_proxy': data.get('proxy', False),
                'continent': 'N/A',
                'continent_code': 'N/A',
                'zip_code': data.get('zip', 'N/A'),
                'is_private': False,
                'from_cache': False
            }
    return None


def is_valid_ip(ip_address):
    """Validate IP address format"""
    import re
    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    ipv6_pattern = r'^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$'

    if re.match(ipv4_pattern, ip_address):
        parts = ip_address.split('.')
        return all(0 <= int(part) <= 255 for part in parts)
    elif re.match(ipv6_pattern, ip_address):
        return True
    return False


def is_private_ip(ip_address):
    """Check if IP is private/internal"""
    import ipaddress
    try:
        ip = ipaddress.ip_address(ip_address)
        return ip.is_private or ip.is_loopback or ip.is_reserved
    except ValueError:
        return False


@ip_info_routes.route('/lookup/<ip_address>', methods=['GET'])
def lookup_ip(ip_address):
    """
    Get detailed IP information from FreeIPAPI

    Returns:
    {
        "success": true,
        "ip_address": "1.1.1.1",
        "ip_version": 4,
        "country": "Australia",
        "country_code": "AU",
        "city": "Sydney",
        "region": "New South Wales",
        "latitude": -33.8688,
        "longitude": 151.209,
        "timezone": "Australia/Sydney",
        "isp": "Cloudflare, Inc.",
        "asn": "13335",
        "is_proxy": false,
        "continent": "Oceania"
    }
    """
    try:
        # Validate IP format
        if not is_valid_ip(ip_address):
            return jsonify({
                'success': False,
                'error': 'Invalid IP address format'
            }), 400

        # Check if private IP
        if is_private_ip(ip_address):
            return jsonify({
                'success': True,
                'ip_address': ip_address,
                'is_private': True,
                'country': 'Private Network',
                'country_code': 'N/A',
                'city': 'Internal',
                'region': 'N/A',
                'latitude': 0,
                'longitude': 0,
                'timezone': 'N/A',
                'isp': 'Private Network',
                'asn': 'N/A',
                'is_proxy': False,
                'continent': 'N/A',
                'from_cache': False
            }), 200

        # Check cache first
        cache = get_cache()
        cache_k = cache_key('ip_info', 'lookup', ip_address)

        cached = cache.get(cache_k)
        if cached is not None:
            cached['from_cache'] = True
            return jsonify(cached), 200

        # Determine which provider to use
        provider = get_primary_provider()

        # Fetch from selected provider with fallback
        try:
            result = None

            if provider == 'freeipapi':
                result = fetch_from_freeipapi(ip_address)
                # Fallback to IP-API if FreeIPAPI fails
                if result is None:
                    result = fetch_from_ipapi(ip_address)
            else:  # ipapi
                result = fetch_from_ipapi(ip_address)
                # Fallback to FreeIPAPI if IP-API fails
                if result is None:
                    result = fetch_from_freeipapi(ip_address)

            if result:
                # Cache the result
                cache.set(cache_k, result, IP_INFO_TTL)
                return jsonify(result), 200
            else:
                return jsonify({
                    'success': False,
                    'error': 'All GeoIP providers failed'
                }), 502

        except requests.RequestException as e:
            print(f"Error fetching IP info: {e}")
            return jsonify({
                'success': False,
                'error': 'Failed to fetch IP information from external API'
            }), 502

    except Exception as e:
        print(f"Error in IP lookup: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'success': False,
            'error': 'Internal server error'
        }), 500


@ip_info_routes.route('/bulk', methods=['POST'])
def bulk_lookup():
    """
    Bulk IP lookup (up to 10 IPs at a time)

    Request JSON:
    {
        "ip_addresses": ["1.1.1.1", "8.8.8.8"]
    }
    """
    from flask import request

    try:
        data = request.get_json()

        if not data or 'ip_addresses' not in data:
            return jsonify({
                'success': False,
                'error': 'Missing ip_addresses field'
            }), 400

        ip_addresses = data['ip_addresses']

        if not isinstance(ip_addresses, list):
            return jsonify({
                'success': False,
                'error': 'ip_addresses must be a list'
            }), 400

        # Limit to 10 IPs
        if len(ip_addresses) > 10:
            return jsonify({
                'success': False,
                'error': 'Maximum 10 IP addresses per request'
            }), 400

        results = {}
        cache = get_cache()

        for ip in ip_addresses:
            if not is_valid_ip(ip):
                results[ip] = {'success': False, 'error': 'Invalid IP format'}
                continue

            # Check cache
            cache_k = cache_key('ip_info', 'lookup', ip)
            cached = cache.get(cache_k)

            if cached is not None:
                cached['from_cache'] = True
                results[ip] = cached
            elif is_private_ip(ip):
                results[ip] = {
                    'success': True,
                    'ip_address': ip,
                    'is_private': True,
                    'country': 'Private Network',
                    'country_code': 'N/A',
                    'city': 'Internal',
                    'from_cache': False
                }
            else:
                # Fetch from API
                try:
                    response = requests.get(
                        f"{FREEIPAPI_BASE_URL}/{ip}",
                        timeout=5,
                        allow_redirects=True
                    )

                    if response.status_code == 200:
                        api_data = response.json()
                        result = {
                            'success': True,
                            'ip_address': api_data.get('ipAddress', ip),
                            'country': api_data.get('countryName', 'Unknown'),
                            'country_code': api_data.get('countryCode', 'N/A'),
                            'city': api_data.get('cityName', 'Unknown'),
                            'region': api_data.get('regionName', 'Unknown'),
                            'isp': api_data.get('asnOrganization', 'Unknown'),
                            'is_proxy': api_data.get('isProxy', False),
                            'is_private': False,
                            'from_cache': False
                        }
                        # Cache it
                        cache.set(cache_k, result, IP_INFO_TTL)
                        results[ip] = result
                    else:
                        results[ip] = {'success': False, 'error': 'API error'}

                except requests.RequestException:
                    results[ip] = {'success': False, 'error': 'Request failed'}

        return jsonify({
            'success': True,
            'results': results,
            'count': len(results)
        }), 200

    except Exception as e:
        print(f"Error in bulk IP lookup: {e}")
        return jsonify({
            'success': False,
            'error': 'Internal server error'
        }), 500


@ip_info_routes.route('/provider', methods=['GET'])
def get_provider_info():
    """
    Get current GeoIP provider configuration

    Returns:
    {
        "success": true,
        "primary_provider": "freeipapi",
        "providers": {
            "freeipapi": { "enabled": true, "is_primary": true },
            "ipapi": { "enabled": true, "is_primary": false }
        }
    }
    """
    try:
        freeipapi_enabled = get_integration_config_value('freeipapi', 'enabled') == 'true'
        freeipapi_primary = get_integration_config_value('freeipapi', 'use_as_primary') == 'true'

        ipapi_enabled = get_integration_config_value('ipapi', 'enabled') == 'true'
        ipapi_primary = get_integration_config_value('ipapi', 'use_as_primary') == 'true'

        primary = get_primary_provider()

        return jsonify({
            'success': True,
            'primary_provider': primary,
            'providers': {
                'freeipapi': {
                    'name': 'FreeIPAPI',
                    'enabled': freeipapi_enabled,
                    'is_primary': freeipapi_primary,
                    'features': ['ASN', 'Proxy Detection', 'Timezone', 'Continent']
                },
                'ipapi': {
                    'name': 'IP-API',
                    'enabled': ipapi_enabled,
                    'is_primary': ipapi_primary,
                    'features': ['ISP', 'Organization', 'Timezone']
                }
            }
        }), 200

    except Exception as e:
        print(f"Error getting provider info: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to get provider info'
        }), 500
