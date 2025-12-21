"""
SSH Guardian v3.0 - Demo Anomaly Scenarios
Creates realistic test data demonstrating behavioral anomaly detection
"""

import sys
from pathlib import Path
from datetime import datetime, timedelta
import random
import uuid

PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.append(str(PROJECT_ROOT / "dbs"))
sys.path.append(str(PROJECT_ROOT / "src" / "core"))

from connection import get_connection, ip_to_binary

# Real public IPs with different geographic locations
SCENARIO_IPS = {
    # Normal user locations (US East Coast)
    'home_office': {
        'ip': '24.48.0.1',  # Comcast Boston
        'city': 'Boston',
        'country': 'United States',
        'country_code': 'US',
        'lat': 42.3601,
        'lon': -71.0589,
        'isp': 'Comcast Cable',
        'asn': 7922
    },
    'work_vpn': {
        'ip': '8.8.4.4',  # Google DNS (example corporate)
        'city': 'Mountain View',
        'country': 'United States',
        'country_code': 'US',
        'lat': 37.3861,
        'lon': -122.0839,
        'isp': 'Google LLC',
        'asn': 15169
    },
    # Anomaly locations
    'russia_attacker': {
        'ip': '185.220.101.1',  # Known Tor exit
        'city': 'Moscow',
        'country': 'Russia',
        'country_code': 'RU',
        'lat': 55.7558,
        'lon': 37.6173,
        'isp': 'LLC Baxet',
        'asn': 41722,
        'is_tor': True
    },
    'china_datacenter': {
        'ip': '116.31.127.1',
        'city': 'Shenzhen',
        'country': 'China',
        'country_code': 'CN',
        'lat': 22.5431,
        'lon': 114.0579,
        'isp': 'Chinanet',
        'asn': 4134,
        'is_datacenter': True
    },
    'germany_office': {
        'ip': '77.88.8.8',  # Yandex DNS (example European)
        'city': 'Berlin',
        'country': 'Germany',
        'country_code': 'DE',
        'lat': 52.5200,
        'lon': 13.4050,
        'isp': 'Deutsche Telekom',
        'asn': 3320
    },
    'brazil_unusual': {
        'ip': '200.160.2.3',
        'city': 'São Paulo',
        'country': 'Brazil',
        'country_code': 'BR',
        'lat': -23.5505,
        'lon': -46.6333,
        'isp': 'Telefonica Brasil',
        'asn': 27699
    },
    'india_proxy': {
        'ip': '103.21.244.1',
        'city': 'Mumbai',
        'country': 'India',
        'country_code': 'IN',
        'lat': 19.0760,
        'lon': 72.8777,
        'isp': 'DigitalOcean',
        'asn': 14061,
        'is_proxy': True,
        'is_hosting': True
    }
}

# Test users
TEST_USERS = [
    'john.smith',      # Normal US user - will have impossible travel anomaly
    'alice.johnson',   # Normal user - will have time anomaly
    'admin',           # Admin account - will have credential stuffing attempt
    'developer',       # Dev account - will have new location anomaly
    'sarah.wilson',    # Normal user - will have success after failures
]


def ensure_geo_data(cursor, ip_info: dict) -> int:
    """Ensure IP geo data exists and return geo_id"""
    ip = ip_info['ip']

    # Check if exists
    cursor.execute("SELECT id FROM ip_geolocation WHERE ip_address_text = %s", (ip,))
    existing = cursor.fetchone()
    if existing:
        return existing['id']

    # Insert new geo data
    ip_binary = ip_to_binary(ip)
    cursor.execute("""
        INSERT INTO ip_geolocation (
            ip_address, ip_address_text, ip_version,
            country_code, country_name, city, region,
            latitude, longitude, isp, asn,
            is_proxy, is_vpn, is_tor, is_datacenter, is_hosting,
            abuseipdb_score, threat_level
        ) VALUES (
            %s, %s, 4,
            %s, %s, %s, %s,
            %s, %s, %s, %s,
            %s, %s, %s, %s, %s,
            %s, %s
        )
    """, (
        ip_binary, ip,
        ip_info.get('country_code'), ip_info.get('country'),
        ip_info.get('city'), ip_info.get('city'),
        ip_info.get('lat'), ip_info.get('lon'),
        ip_info.get('isp'), ip_info.get('asn'),
        ip_info.get('is_proxy', False), ip_info.get('is_vpn', False),
        ip_info.get('is_tor', False), ip_info.get('is_datacenter', False),
        ip_info.get('is_hosting', False),
        ip_info.get('abuseipdb_score', 0),
        ip_info.get('threat_level', 'low')
    ))

    return cursor.lastrowid


def create_auth_event(cursor, ip_info: dict, username: str,
                      event_type: str, timestamp: datetime,
                      agent_id: int = 13) -> int:
    """Create an auth event"""
    geo_id = ensure_geo_data(cursor, ip_info)
    event_uuid = str(uuid.uuid4())
    ip = ip_info['ip']
    ip_binary = ip_to_binary(ip)

    cursor.execute("""
        INSERT INTO auth_events (
            event_uuid, timestamp, source_type, agent_id,
            event_type, auth_method,
            source_ip, source_ip_text, geo_id,
            target_server, target_username,
            failure_reason, processing_status
        ) VALUES (
            %s, %s, 'synthetic', %s,
            %s, 'password',
            %s, %s, %s,
            'demo-server', %s,
            %s, 'completed'
        )
    """, (
        event_uuid, timestamp, agent_id,
        event_type,
        ip_binary, ip, geo_id,
        username,
        'invalid_password' if event_type == 'failed' else None
    ))

    return cursor.lastrowid


def create_scenario_1_impossible_travel(cursor, conn):
    """
    Scenario 1: Impossible Travel Detection
    User 'john.smith' logs in from Boston, then 2 hours later from Moscow
    Distance: ~7,500 km, would require 3,750 km/h travel
    """
    print("\n📍 Creating Scenario 1: Impossible Travel for john.smith")

    username = 'john.smith'
    now = datetime.now()

    # Create baseline: 30 days of normal logins from Boston
    print("   Creating 30-day baseline from Boston...")
    for days_ago in range(30, 0, -1):
        # 1-2 logins per day at normal business hours (9am-6pm)
        for _ in range(random.randint(1, 2)):
            hour = random.randint(9, 17)
            login_time = now - timedelta(days=days_ago, hours=random.randint(0, 8))
            login_time = login_time.replace(hour=hour)
            create_auth_event(
                cursor, SCENARIO_IPS['home_office'],
                username, 'successful', login_time
            )
    conn.commit()

    # Recent login from Boston (2 hours ago)
    boston_login = now - timedelta(hours=2)
    event_id = create_auth_event(
        cursor, SCENARIO_IPS['home_office'],
        username, 'successful', boston_login
    )
    print(f"   ✓ Boston login at {boston_login.strftime('%H:%M')}")
    conn.commit()

    # Anomalous login from Moscow (NOW) - IMPOSSIBLE TRAVEL
    moscow_ip = SCENARIO_IPS['russia_attacker'].copy()
    moscow_ip['abuseipdb_score'] = 85
    moscow_ip['threat_level'] = 'high'
    event_id = create_auth_event(
        cursor, moscow_ip,
        username, 'successful', now
    )
    print(f"   ⚠️  Moscow login at {now.strftime('%H:%M')} - IMPOSSIBLE TRAVEL!")
    print(f"      Boston → Moscow = ~7,500 km in 2 hours = 3,750 km/h")
    conn.commit()

    return event_id


def create_scenario_2_time_anomaly(cursor, conn):
    """
    Scenario 2: Unusual Login Time
    User 'alice.johnson' typically logs in 9am-5pm, suddenly logs in at 3am
    """
    print("\n🕐 Creating Scenario 2: Time Anomaly for alice.johnson")

    username = 'alice.johnson'
    now = datetime.now()

    # Create baseline: 30 days of logins during business hours only
    print("   Creating baseline of business-hour logins...")
    for days_ago in range(30, 0, -1):
        # Always between 9am-5pm
        hour = random.randint(9, 16)
        login_time = now - timedelta(days=days_ago)
        login_time = login_time.replace(hour=hour, minute=random.randint(0, 59))
        create_auth_event(
            cursor, SCENARIO_IPS['work_vpn'],
            username, 'successful', login_time
        )
    conn.commit()

    # Anomalous login at 3am
    anomaly_time = now.replace(hour=3, minute=17)
    if anomaly_time > now:
        anomaly_time -= timedelta(days=1)

    event_id = create_auth_event(
        cursor, SCENARIO_IPS['work_vpn'],
        username, 'successful', anomaly_time
    )
    print(f"   ✓ Normal hours: 9am-5pm")
    print(f"   ⚠️  Anomalous login at {anomaly_time.strftime('%H:%M')} - UNUSUAL TIME!")
    conn.commit()

    return event_id


def create_scenario_3_credential_stuffing(cursor, conn):
    """
    Scenario 3: Credential Stuffing Attack
    IP tries multiple usernames rapidly with low success rate
    """
    print("\n🔐 Creating Scenario 3: Credential Stuffing Attack")

    attack_ip = SCENARIO_IPS['china_datacenter'].copy()
    attack_ip['abuseipdb_score'] = 95
    attack_ip['threat_level'] = 'critical'
    now = datetime.now()

    # Try 50 different usernames in last hour
    usernames_tried = [
        'admin', 'root', 'administrator', 'test', 'user', 'guest',
        'postgres', 'mysql', 'oracle', 'backup', 'ftp', 'mail',
        'info', 'support', 'sales', 'marketing', 'hr', 'finance',
        'dev', 'developer', 'qa', 'staging', 'production', 'deploy',
        'jenkins', 'gitlab', 'docker', 'ubuntu', 'centos', 'debian',
        'webmaster', 'postmaster', 'hostmaster', 'abuse', 'security',
        'john', 'jane', 'mike', 'sarah', 'david', 'emma', 'james',
        'mary', 'robert', 'linda', 'william', 'elizabeth', 'richard'
    ]

    print(f"   Simulating attack from {attack_ip['ip']} ({attack_ip['city']}, {attack_ip['country']})")

    for i, username in enumerate(usernames_tried):
        attempt_time = now - timedelta(minutes=random.randint(1, 55))
        # 96% failure rate (only 2 succeed out of 50)
        event_type = 'successful' if username in ['guest', 'test'] else 'failed'
        create_auth_event(cursor, attack_ip, username, event_type, attempt_time)

    conn.commit()
    print(f"   ⚠️  {len(usernames_tried)} usernames tried, 2 succeeded (4% success rate)")
    print(f"      Pattern: Credential stuffing attack!")


def create_scenario_4_new_location(cursor, conn):
    """
    Scenario 4: Login from New Location
    Developer always logs in from US, suddenly logs in from Brazil
    """
    print("\n🌍 Creating Scenario 4: New Location for developer")

    username = 'developer'
    now = datetime.now()

    # Create baseline: All logins from US locations
    print("   Creating US-only login baseline...")
    us_locations = ['home_office', 'work_vpn']
    for days_ago in range(60, 0, -1):
        location = random.choice(us_locations)
        login_time = now - timedelta(days=days_ago)
        create_auth_event(
            cursor, SCENARIO_IPS[location],
            username, 'successful', login_time
        )
    conn.commit()

    # Anomalous login from Brazil
    event_id = create_auth_event(
        cursor, SCENARIO_IPS['brazil_unusual'],
        username, 'successful', now
    )
    print(f"   ✓ 60 days of US-only logins (Boston, Mountain View)")
    print(f"   ⚠️  First-ever login from São Paulo, Brazil - NEW LOCATION!")
    conn.commit()

    return event_id


def create_scenario_5_success_after_failures(cursor, conn):
    """
    Scenario 5: Successful Login After Multiple Failures
    Someone finally cracks sarah.wilson's password after 15 failed attempts
    """
    print("\n🔓 Creating Scenario 5: Success After Failures for sarah.wilson")

    username = 'sarah.wilson'
    now = datetime.now()
    attack_ip = SCENARIO_IPS['india_proxy'].copy()
    attack_ip['abuseipdb_score'] = 70
    attack_ip['threat_level'] = 'high'

    # Create some legitimate history first
    print("   Creating legitimate login history...")
    for days_ago in range(30, 0, -1):
        login_time = now - timedelta(days=days_ago)
        create_auth_event(
            cursor, SCENARIO_IPS['home_office'],
            username, 'successful', login_time
        )
    conn.commit()

    # Failed attempts from attacker IP (15 failures in last 30 minutes)
    print("   Simulating brute force attack...")
    for i in range(15):
        attempt_time = now - timedelta(minutes=30-i*2)
        create_auth_event(cursor, attack_ip, username, 'failed', attempt_time)
    conn.commit()

    # Finally successful!
    event_id = create_auth_event(
        cursor, attack_ip,
        username, 'successful', now
    )
    print(f"   ⚠️  15 failed attempts followed by SUCCESS - COMPROMISED!")
    print(f"      Attack source: {attack_ip['ip']} ({attack_ip['city']}, {attack_ip['country']})")
    conn.commit()

    return event_id


def create_scenario_6_combined_anomalies(cursor, conn):
    """
    Scenario 6: Multiple Anomalies Combined
    New IP + New Location + Unusual Time = Very Suspicious
    """
    print("\n💀 Creating Scenario 6: Multiple Anomalies for admin")

    username = 'admin'
    now = datetime.now()

    # Create strict baseline: Only from home_office, only 10am-4pm
    print("   Creating strict baseline for admin account...")
    for days_ago in range(90, 0, -1):
        hour = random.randint(10, 15)
        login_time = now - timedelta(days=days_ago)
        login_time = login_time.replace(hour=hour)
        create_auth_event(
            cursor, SCENARIO_IPS['home_office'],
            username, 'successful', login_time
        )
    conn.commit()

    # Attack: New IP + New Country + 2am login
    attack_time = now.replace(hour=2, minute=33)
    if attack_time > now:
        attack_time -= timedelta(days=1)

    attack_ip = SCENARIO_IPS['russia_attacker'].copy()
    attack_ip['abuseipdb_score'] = 100
    attack_ip['threat_level'] = 'critical'

    event_id = create_auth_event(
        cursor, attack_ip,
        username, 'successful', attack_time
    )

    print(f"   ✓ 90-day baseline: Boston only, 10am-4pm only")
    print(f"   ⚠️  MULTIPLE ANOMALIES DETECTED:")
    print(f"      - New IP: {attack_ip['ip']}")
    print(f"      - New Country: Russia (Tor exit node)")
    print(f"      - Unusual Time: 2:33 AM")
    print(f"      - AbuseIPDB: 100/100")
    conn.commit()

    return event_id


def run_all_scenarios():
    """Run all demo scenarios"""
    print("=" * 70)
    print("🧪 SSH GUARDIAN - BEHAVIORAL ANOMALY DEMO SCENARIOS")
    print("=" * 70)

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # Run all scenarios
        create_scenario_1_impossible_travel(cursor, conn)
        create_scenario_2_time_anomaly(cursor, conn)
        create_scenario_3_credential_stuffing(cursor, conn)
        create_scenario_4_new_location(cursor, conn)
        create_scenario_5_success_after_failures(cursor, conn)
        create_scenario_6_combined_anomalies(cursor, conn)

        print("\n" + "=" * 70)
        print("✅ All scenarios created successfully!")
        print("=" * 70)
        print("\nTest these in the dashboard:")
        print("  • john.smith    - Impossible travel (Boston → Moscow)")
        print("  • alice.johnson - Time anomaly (3am login)")
        print("  • developer     - New location (US → Brazil)")
        print("  • sarah.wilson  - Success after 15 failures")
        print("  • admin         - Multiple anomalies combined")
        print("\nIPs to check:")
        for name, info in SCENARIO_IPS.items():
            print(f"  • {info['ip']:18} - {info['city']}, {info['country']}")

    except Exception as e:
        conn.rollback()
        print(f"\n❌ Error: {e}")
        raise
    finally:
        cursor.close()
        conn.close()


if __name__ == "__main__":
    run_all_scenarios()
