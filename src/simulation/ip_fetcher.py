"""
SSH Guardian v3.0 - IP Fetcher
Fetches fresh malicious IPs from external threat intelligence sources.
Sources: AbuseIPDB, Blocklist.de
"""

import sys
import requests
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Optional

PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.append(str(PROJECT_ROOT / "dbs"))

from connection import get_connection


# IP Categories for scenarios
CATEGORY_MAPPING = {
    'SSH': 'brute_force',
    'Brute-Force': 'brute_force',
    'DDoS Attack': 'ddos_botnet',
    'Port Scan': 'scanner',
    'Web Attack': 'credential_stuffing',
    'Hacking': 'botnet',
    'Spam': 'spam',
    'VoIP': 'voip',
    'Tor': 'tor_exit'
}


def fetch_from_blocklist_de() -> List[Dict]:
    """
    Fetch SSH attackers from Blocklist.de (free, no API key).
    Returns list of IPs with category 'brute_force'.
    """
    ips = []
    try:
        # SSH attackers list
        url = "https://lists.blocklist.de/lists/ssh.txt"
        response = requests.get(url, timeout=10)

        if response.status_code == 200:
            lines = response.text.strip().split('\n')
            for line in lines[:100]:  # Limit to 100 IPs
                ip = line.strip()
                if ip and not ip.startswith('#'):
                    ips.append({
                        'ip': ip,
                        'category': 'brute_force',
                        'source': 'blocklist_de',
                        'threat_score': 75  # Default high score for blocklist
                    })
    except Exception as e:
        print(f"[IP Fetcher] Blocklist.de error: {e}")

    return ips


def fetch_from_abuseipdb(api_key: str, limit: int = 50) -> List[Dict]:
    """
    Fetch top reported IPs from AbuseIPDB.
    Requires API key.
    """
    ips = []
    try:
        url = "https://api.abuseipdb.com/api/v2/blacklist"
        headers = {
            'Key': api_key,
            'Accept': 'application/json'
        }
        params = {
            'confidenceMinimum': 75,
            'limit': limit
        }

        response = requests.get(url, headers=headers, params=params, timeout=15)

        if response.status_code == 200:
            data = response.json()
            for item in data.get('data', []):
                ip = item.get('ipAddress')
                score = item.get('abuseConfidenceScore', 0)

                # Categorize based on score
                if score >= 90:
                    category = 'tor_exit'  # Very high abuse = likely tor/proxy
                elif score >= 75:
                    category = 'brute_force'
                else:
                    category = 'scanner'

                ips.append({
                    'ip': ip,
                    'category': category,
                    'source': 'abuseipdb',
                    'threat_score': score
                })
        elif response.status_code == 429:
            print("[IP Fetcher] AbuseIPDB rate limit reached")
        else:
            print(f"[IP Fetcher] AbuseIPDB error: {response.status_code}")

    except Exception as e:
        print(f"[IP Fetcher] AbuseIPDB error: {e}")

    return ips


def get_abuseipdb_key() -> Optional[str]:
    """Get AbuseIPDB API key from database."""
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT api_key FROM integrations
            WHERE name = 'abuseipdb' AND is_active = TRUE
        """)
        row = cursor.fetchone()
        cursor.close()
        conn.close()
        return row.get('api_key') if row else None
    except:
        return None


def save_ips_to_pool(ips: List[Dict]) -> int:
    """Save fetched IPs to simulation_ip_pool table.

    Table schema uses:
    - pool_type (enum: 'malicious','trusted','random','geo_specific')
    - reputation_score (int)
    - is_tor, is_vpn, is_proxy (tinyint)
    - source, notes (varchar/text)
    """
    if not ips:
        return 0

    conn = get_connection()
    cursor = conn.cursor()
    saved = 0

    # Map categories to ip_type and flags
    CATEGORY_TO_POOL = {
        'brute_force': ('malicious', False, False, False),
        'tor_exit': ('malicious', True, False, False),
        'scanner': ('malicious', False, False, False),
        'ddos_botnet': ('malicious', False, False, False),
        'botnet': ('malicious', False, False, False),
        'credential_stuffing': ('malicious', False, False, False),
    }

    try:
        for ip_data in ips:
            try:
                category = ip_data.get('category', 'brute_force')
                ip_type, is_tor, is_vpn, is_proxy = CATEGORY_TO_POOL.get(category, ('malicious', False, False, False))

                # High abuse score = treat as TOR
                if ip_data.get('threat_score', 0) >= 90:
                    is_tor = True

                cursor.execute("""
                    INSERT INTO simulation_ip_pool
                    (ip_address, ip_type, threat_score)
                    VALUES (%s, %s, %s)
                    ON DUPLICATE KEY UPDATE
                    threat_score = VALUES(threat_score)
                """, (
                    ip_data['ip'],
                    ip_type,
                    ip_data.get('threat_score', 75)
                ))
                saved += 1
            except Exception as e:
                continue

        conn.commit()
    finally:
        cursor.close()
        conn.close()

    return saved


def fetch_and_save_all() -> Dict:
    """
    Fetch IPs from all sources and save to database.
    Returns summary of fetched IPs.
    """
    results = {
        'success': True,
        'sources': {},
        'total': 0,
        'timestamp': datetime.now().isoformat()
    }

    # Fetch from Blocklist.de (no API key needed)
    blocklist_ips = fetch_from_blocklist_de()
    if blocklist_ips:
        saved = save_ips_to_pool(blocklist_ips)
        results['sources']['blocklist_de'] = {
            'fetched': len(blocklist_ips),
            'saved': saved
        }
        results['total'] += saved

    # Fetch from AbuseIPDB (if API key available)
    api_key = get_abuseipdb_key()
    if api_key:
        abuseipdb_ips = fetch_from_abuseipdb(api_key)
        if abuseipdb_ips:
            saved = save_ips_to_pool(abuseipdb_ips)
            results['sources']['abuseipdb'] = {
                'fetched': len(abuseipdb_ips),
                'saved': saved
            }
            results['total'] += saved
    else:
        results['sources']['abuseipdb'] = {
            'fetched': 0,
            'saved': 0,
            'error': 'No API key configured'
        }

    return results


def get_fresh_ip(category: str = None) -> Optional[str]:
    """
    Get a fresh IP from the pool for a given category.
    Falls back to any available malicious IP if category not found.

    Category mapping:
    - 'brute_force', 'scanner', 'ddos_botnet', 'botnet' -> ip_type='malicious'
    - 'tor_exit' -> ip_type='malicious' (with high threat_score)
    """
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        if category == 'tor_exit':
            # TOR exit nodes (high threat score)
            cursor.execute("""
                SELECT ip_address FROM simulation_ip_pool
                WHERE ip_type = 'malicious' AND threat_score >= 90
                ORDER BY RAND() LIMIT 1
            """)
        elif category:
            # Any malicious IP
            cursor.execute("""
                SELECT ip_address FROM simulation_ip_pool
                WHERE ip_type = 'malicious'
                ORDER BY RAND() LIMIT 1
            """)
        else:
            # Any malicious IP
            cursor.execute("""
                SELECT ip_address FROM simulation_ip_pool
                WHERE ip_type = 'malicious'
                ORDER BY RAND() LIMIT 1
            """)

        row = cursor.fetchone()

        # Fall back to any malicious IP if specific category not found
        if not row and category:
            cursor.execute("""
                SELECT ip_address FROM simulation_ip_pool
                WHERE ip_type = 'malicious'
                ORDER BY RAND() LIMIT 1
            """)
            row = cursor.fetchone()

        return row['ip_address'] if row else None
    finally:
        cursor.close()
        conn.close()


def get_pool_stats() -> Dict:
    """Get statistics about the IP pool."""
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        cursor.execute("""
            SELECT
                ip_type,
                COUNT(*) as count,
                AVG(threat_score) as avg_score,
                MAX(created_at) as last_update
            FROM simulation_ip_pool
            WHERE ip_type = 'malicious'
            GROUP BY ip_type
        """)

        stats = cursor.fetchall()

        cursor.execute("SELECT COUNT(*) as total FROM simulation_ip_pool WHERE ip_type = 'malicious'")
        total = cursor.fetchone()

        return {
            'total_ips': total['total'] if total else 0,
            'by_type': stats,
            'last_refresh': stats[0]['last_update'].isoformat() if stats and stats[0].get('last_update') else None
        }
    finally:
        cursor.close()
        conn.close()
