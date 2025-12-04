"""
Test Threat Intelligence Integration
"""

import sys
from pathlib import Path

# Add project paths
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.append(str(PROJECT_ROOT / "dbs"))
sys.path.append(str(PROJECT_ROOT / "src" / "core"))

from threat_intel import ThreatIntelligence, check_ip_threat
from connection import get_connection


def test_threat_lookup():
    """Test threat intelligence lookup"""
    print("\n" + "="*70)
    print("TEST: Threat Intelligence Lookup")
    print("="*70)

    # Test with known malicious IPs and clean IPs
    test_ips = [
        ("8.8.8.8", "Google DNS - Expected: Clean"),
        ("1.1.1.1", "Cloudflare DNS - Expected: Clean"),
    ]

    for ip, description in test_ips:
        print(f"\n\n{'='*70}")
        print(f"Testing: {ip} ({description})")
        print('='*70)

        result = check_ip_threat(ip)

        if result:
            print(f"\n✅ Threat Intelligence Retrieved:")
            print(f"   IP: {ip}")
            print(f"   Threat Level: {result.get('threat_level', 'N/A').upper()}")
            print(f"   Confidence: {result.get('confidence', 0):.2f}")

            # AbuseIPDB
            abuseipdb = result.get('abuseipdb', {})
            if abuseipdb:
                print(f"\n   AbuseIPDB:")
                print(f"     Score: {abuseipdb.get('score', 0)}")
                print(f"     Reports: {abuseipdb.get('reports', 0)}")

            # VirusTotal
            virustotal = result.get('virustotal', {})
            if virustotal:
                print(f"\n   VirusTotal:")
                print(f"     Detections: {virustotal.get('positives', 0)}/{virustotal.get('total', 0)}")

            # Shodan
            shodan = result.get('shodan', {})
            if shodan:
                print(f"\n   Shodan:")
                print(f"     Open Ports: {len(shodan.get('ports', []))}")
                print(f"     Vulnerabilities: {len(shodan.get('vulns', []))}")

        else:
            print(f"\n❌ Lookup failed")


def show_threat_stats():
    """Show threat intelligence statistics"""
    print("\n" + "="*70)
    print("Threat Intelligence Cache Statistics")
    print("="*70)

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # Total cached IPs
        cursor.execute("SELECT COUNT(*) as count FROM ip_threat_intelligence")
        total = cursor.fetchone()['count']

        print(f"\n📊 Total cached IPs: {total}")

        # Threat level distribution
        cursor.execute("""
            SELECT
                overall_threat_level,
                COUNT(*) as count
            FROM ip_threat_intelligence
            GROUP BY overall_threat_level
            ORDER BY count DESC
        """)

        distribution = cursor.fetchall()

        if distribution:
            print(f"\n📋 Threat Level Distribution:")
            for row in distribution:
                print(f"   {row['overall_threat_level']}: {row['count']}")

        # Recent checks
        cursor.execute("""
            SELECT
                ip_address_text,
                overall_threat_level,
                abuseipdb_score,
                virustotal_positives,
                updated_at
            FROM ip_threat_intelligence
            ORDER BY updated_at DESC
            LIMIT 5
        """)

        recent = cursor.fetchall()

        if recent:
            print(f"\n📋 Recent Threat Checks:")
            for row in recent:
                print(f"   {row['ip_address_text']:<15} | Threat: {row['overall_threat_level']:<8} | "
                      f"Abuse: {row['abuseipdb_score'] or 0:>3} | VT: {row['virustotal_positives'] or 0:>2} | "
                      f"Checked: {row['updated_at']}")

    finally:
        cursor.close()
        conn.close()

    print("\n" + "="*70 + "\n")


def main():
    """Run all tests"""
    print("\n" + "="*70)
    print("🧪 SSH Guardian v3.0 - Threat Intelligence Tests")
    print("="*70)

    # Show current stats
    show_threat_stats()

    # Run tests
    test_threat_lookup()

    # Show updated stats
    show_threat_stats()


if __name__ == "__main__":
    main()
