"""
Test GeoIP Integration
"""

import sys
from pathlib import Path

# Add project paths
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.append(str(PROJECT_ROOT / "dbs"))
sys.path.append(str(PROJECT_ROOT / "src" / "core"))

from geoip import GeoIPLookup, lookup_ip, enrich_event
from connection import get_connection


def test_ip_lookup():
    """Test basic IP lookup"""
    print("\n" + "="*70)
    print("TEST 1: Basic IP Lookup")
    print("="*70)

    test_ips = [
        "8.8.8.8",          # Google DNS
        "1.1.1.1",          # Cloudflare DNS
        "192.168.1.1",      # Private IP (should fail gracefully)
    ]

    for ip in test_ips:
        print(f"\n🔍 Looking up: {ip}")
        result = lookup_ip(ip)

        if result:
            print(f"   ✅ Country: {result.get('country_name')} ({result.get('country_code')})")
            print(f"   📍 City: {result.get('city')}, {result.get('region')}")
            print(f"   🌐 Coordinates: {result.get('latitude')}, {result.get('longitude')}")
            print(f"   🏢 ISP: {result.get('isp')}")
            print(f"   🔢 ASN: AS{result.get('asn')} - {result.get('asn_org')}")
            print(f"   🔒 Proxy: {result.get('is_proxy')}, Hosting: {result.get('is_hosting')}")
        else:
            print(f"   ❌ Lookup failed")


def test_cache():
    """Test caching functionality"""
    print("\n" + "="*70)
    print("TEST 2: Cache Testing")
    print("="*70)

    test_ip = "8.8.8.8"

    print(f"\n🔍 First lookup (should fetch from API): {test_ip}")
    result1 = lookup_ip(test_ip)

    print(f"\n🔍 Second lookup (should use cache): {test_ip}")
    result2 = lookup_ip(test_ip)

    if result1 and result2:
        print(f"\n✅ Both lookups successful")
        print(f"   First lookup count: {result1.get('lookup_count', 'N/A')}")
        print(f"   Second lookup count: {result2.get('lookup_count', 'N/A')}")
    else:
        print(f"\n❌ Cache test failed")


def test_event_enrichment():
    """Test enriching auth_events with GeoIP"""
    print("\n" + "="*70)
    print("TEST 3: Event Enrichment")
    print("="*70)

    # Find a recent event without GeoIP data
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        cursor.execute("""
            SELECT id, source_ip_text, geo_id, processing_status
            FROM auth_events
            WHERE geo_id IS NULL
            ORDER BY id DESC
            LIMIT 1
        """)

        event = cursor.fetchone()

        if not event:
            print("\n⚠️  No events found without GeoIP data")
            print("   Create a test event first using the API")
            return

        print(f"\n📋 Event ID: {event['id']}")
        print(f"   IP: {event['source_ip_text']}")
        print(f"   Current geo_id: {event['geo_id']}")
        print(f"   Processing status: {event['processing_status']}")

        print(f"\n🌍 Enriching event with GeoIP data...")
        geo_id = enrich_event(event['id'], event['source_ip_text'])

        if geo_id:
            # Verify enrichment
            cursor.execute("""
                SELECT
                    e.id,
                    e.source_ip_text,
                    e.geo_id,
                    e.processing_status,
                    g.country_name,
                    g.city,
                    g.isp
                FROM auth_events e
                LEFT JOIN ip_geolocation g ON e.geo_id = g.id
                WHERE e.id = %s
            """, (event['id'],))

            enriched = cursor.fetchone()

            print(f"\n✅ Event enriched successfully!")
            print(f"   geo_id: {enriched['geo_id']}")
            print(f"   Processing status: {enriched['processing_status']}")
            print(f"   Location: {enriched['city']}, {enriched['country_name']}")
            print(f"   ISP: {enriched['isp']}")
        else:
            print(f"\n❌ Enrichment failed")

    finally:
        cursor.close()
        conn.close()


def show_geoip_stats():
    """Show GeoIP statistics"""
    print("\n" + "="*70)
    print("GeoIP Cache Statistics")
    print("="*70)

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # Total cached IPs
        cursor.execute("SELECT COUNT(*) as count FROM ip_geolocation")
        total = cursor.fetchone()['count']

        print(f"\n📊 Total cached IPs: {total}")

        # Recent lookups
        cursor.execute("""
            SELECT
                ip_address_text,
                country_name,
                city,
                lookup_count,
                last_seen
            FROM ip_geolocation
            ORDER BY last_seen DESC
            LIMIT 5
        """)

        recent = cursor.fetchall()

        if recent:
            print(f"\n📋 Recent Lookups:")
            for row in recent:
                print(f"   {row['ip_address_text']:<15} | {row['city']}, {row['country_name']:<20} | Lookups: {row['lookup_count']} | Last: {row['last_seen']}")

        # Events with GeoIP
        cursor.execute("""
            SELECT COUNT(*) as count
            FROM auth_events
            WHERE geo_id IS NOT NULL
        """)
        enriched_count = cursor.fetchone()['count']

        cursor.execute("SELECT COUNT(*) as count FROM auth_events")
        total_events = cursor.fetchone()['count']

        print(f"\n📈 Events with GeoIP: {enriched_count} / {total_events}")

        if total_events > 0:
            percentage = (enriched_count / total_events) * 100
            print(f"   Coverage: {percentage:.1f}%")

    finally:
        cursor.close()
        conn.close()

    print("\n" + "="*70 + "\n")


def main():
    """Run all tests"""
    print("\n" + "="*70)
    print("🧪 SSH Guardian v3.0 - GeoIP Integration Tests")
    print("="*70)

    # Show current stats
    show_geoip_stats()

    # Run tests
    test_ip_lookup()
    test_cache()
    test_event_enrichment()

    # Show updated stats
    show_geoip_stats()


if __name__ == "__main__":
    main()
