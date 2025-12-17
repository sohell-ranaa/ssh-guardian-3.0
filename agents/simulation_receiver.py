#!/usr/bin/env python3
"""
SSH Guardian v3.0 - Simulation Receiver
Lightweight HTTP server that receives attack simulation commands from the dashboard
and writes fake auth.log entries to trigger fail2ban and SSH Guardian agent.

Usage:
    python3 simulation_receiver.py --api-key YOUR_API_KEY [--port 5001] [--log-file /var/log/auth.log]

Environment Variables:
    SIM_RECEIVER_API_KEY - API key for authentication
    SIM_RECEIVER_PORT - Port to listen on (default: 5001)
    SIM_RECEIVER_LOG_FILE - Path to auth.log (default: /var/log/auth.log)
"""

import os
import sys
import json
import random
import socket
import argparse
import logging
from datetime import datetime
from functools import wraps

try:
    from flask import Flask, request, jsonify
except ImportError:
    print("Error: Flask is required. Install with: pip3 install flask")
    sys.exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [SimReceiver] %(levelname)s: %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Configuration (set via environment or command line)
CONFIG = {
    'api_key': os.getenv('SIM_RECEIVER_API_KEY', ''),
    'port': int(os.getenv('SIM_RECEIVER_PORT', 5001)),
    'log_file': os.getenv('SIM_RECEIVER_LOG_FILE', '/var/log/auth.log'),
    'hostname': socket.gethostname()
}

# Last injection tracking
LAST_INJECTION = {
    'time': None,
    'scenario_id': None,
    'ip': None,
    'count': 0
}

# ============================================================================
# DEMO SCENARIOS (Embedded from demo_scenarios.py for self-contained operation)
# ============================================================================
DEMO_SCENARIOS = {
    # CRITICAL TIER - AbuseIPDB >= 90
    "abuseipdb_critical": {
        "id": "abuseipdb_critical",
        "name": "AbuseIPDB Critical (90+)",
        "ip": "185.220.101.1",
        "alternate_ips": ["185.220.101.2", "185.220.101.54", "193.56.28.103"],
        "log_template": "sshd[{pid}]: Failed password for root from {ip} port {port} ssh2"
    },
    "tor_exit_attack": {
        "id": "tor_exit_attack",
        "name": "Tor Exit Node + Failed Login",
        "ip": "185.220.101.1",
        "alternate_ips": ["185.220.101.2", "185.220.101.3", "185.220.102.1"],
        "log_template": "sshd[{pid}]: Failed password for root from {ip} port {port} ssh2"
    },
    # HIGH TIER - AbuseIPDB >= 70
    "abuseipdb_high": {
        "id": "abuseipdb_high",
        "name": "AbuseIPDB High (70+)",
        "ip": "45.142.212.61",
        "alternate_ips": ["185.220.101.1", "193.56.28.103"],
        "log_template": "sshd[{pid}]: Failed password for admin from {ip} port {port} ssh2"
    },
    # BRUTE FORCE - 5 fails in 10 minutes
    "brute_force_5_fails": {
        "id": "brute_force_5_fails",
        "name": "Brute Force (5 fails/10min)",
        "ip": "91.240.118.172",
        "alternate_ips": ["45.142.212.61", "193.56.28.103"],
        "log_template": "sshd[{pid}]: Failed password for root from {ip} port {port} ssh2"
    },
    # CREDENTIAL STUFFING - 5 unique usernames
    "credential_stuffing": {
        "id": "credential_stuffing",
        "name": "Credential Stuffing (5 users)",
        "ip": "45.227.254.0",
        "alternate_ips": ["193.56.28.103", "185.220.101.1"],
        "log_template": "sshd[{pid}]: Failed password for invalid user {username} from {ip} port {port} ssh2",
        "rotate_usernames": True
    },
    # DDoS/VELOCITY - 20 events per minute
    "ddos_velocity": {
        "id": "ddos_velocity",
        "name": "DDoS/Velocity (20 events/min)",
        "ip": "185.156.73.0",
        "alternate_ips": ["91.240.118.172", "193.56.28.103"],
        "log_template": "sshd[{pid}]: Failed password for invalid user admin from {ip} port {port} ssh2"
    },
    # VPN/PROXY + SCORE >= 30
    "vpn_proxy_attack": {
        "id": "vpn_proxy_attack",
        "name": "VPN/Proxy + Score 30+",
        "ip": "103.216.221.19",
        "alternate_ips": ["45.142.212.61", "91.240.118.172"],
        "log_template": "sshd[{pid}]: Failed password for admin from {ip} port {port} ssh2"
    },
    # HIGH-RISK COUNTRY + 2 FAILS
    "high_risk_country": {
        "id": "high_risk_country",
        "name": "High-Risk Country + 2 Fails",
        "ip": "218.92.0.107",
        "alternate_ips": ["39.96.0.0", "45.142.212.61"],
        "log_template": "sshd[{pid}]: Failed password for root from {ip} port {port} ssh2"
    },
    # THREAT COMBO - Combined Signals
    "threat_combo_tor": {
        "id": "threat_combo_tor",
        "name": "Threat Combo (Abuse 50 + Tor)",
        "ip": "185.220.101.54",
        "alternate_ips": ["185.220.101.1", "185.220.102.1"],
        "log_template": "sshd[{pid}]: Failed password for root from {ip} port {port} ssh2"
    },
    "virustotal_5_vendors": {
        "id": "virustotal_5_vendors",
        "name": "VirusTotal 5+ Vendors",
        "ip": "193.56.28.103",
        "alternate_ips": ["45.142.212.61", "185.156.73.0"],
        "log_template": "sshd[{pid}]: Failed password for invalid user oracle from {ip} port {port} ssh2"
    },
    # IMPOSSIBLE TRAVEL
    "impossible_travel": {
        "id": "impossible_travel",
        "name": "Impossible Travel (1000km/2hr)",
        "ip": "39.96.0.0",
        "alternate_ips": ["218.92.0.107", "45.142.212.61"],
        "log_template": "sshd[{pid}]: Failed password for admin from {ip} port {port} ssh2"
    },
    # MEDIUM TIER - AbuseIPDB >= 50
    "abuseipdb_medium": {
        "id": "abuseipdb_medium",
        "name": "AbuseIPDB Medium (50+)",
        "ip": "162.142.125.0",
        "alternate_ips": ["91.240.118.172", "185.220.101.1"],
        "log_template": "sshd[{pid}]: Failed password for invalid user test from {ip} port {port} ssh2"
    },
    # DATACENTER/HOSTING IP
    "datacenter_attack": {
        "id": "datacenter_attack",
        "name": "Datacenter IP Attack",
        "ip": "167.172.248.37",
        "alternate_ips": ["206.189.156.201", "159.89.133.246"],
        "log_template": "sshd[{pid}]: Failed password for root from {ip} port {port} ssh2"
    },
    # NIGHT-TIME LOGIN
    "night_time_login": {
        "id": "night_time_login",
        "name": "Night-Time Login (10PM-6AM)",
        "ip": "45.142.212.61",
        "alternate_ips": ["193.56.28.103", "91.240.118.172"],
        "log_template": "sshd[{pid}]: Failed password for admin from {ip} port {port} ssh2"
    },
    # CLEAN BASELINE
    "clean_baseline": {
        "id": "clean_baseline",
        "name": "Clean IP Baseline",
        "ip": "8.8.8.8",
        "alternate_ips": ["8.8.4.4", "1.1.1.1"],
        "log_template": "sshd[{pid}]: Accepted publickey for deploy from {ip} port {port} ssh2"
    },
    # REPEAT OFFENDER
    "repeat_offender": {
        "id": "repeat_offender",
        "name": "Repeat Offender (Escalation)",
        "ip": "185.156.73.0",
        "alternate_ips": ["193.56.28.103", "45.142.212.61"],
        "log_template": "sshd[{pid}]: Failed password for root from {ip} port {port} ssh2"
    }
}

# Username list for credential stuffing scenarios
USERNAMES = ['admin', 'root', 'user', 'oracle', 'postgres', 'mysql', 'test', 'ubuntu', 'deploy', 'guest', 'ftp', 'www-data']


# ============================================================================
# AUTHENTICATION
# ============================================================================
def require_api_key(f):
    """Decorator to require API key authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key') or request.args.get('api_key')
        if not api_key:
            return jsonify({'success': False, 'error': 'API key required'}), 401
        if api_key != CONFIG['api_key']:
            logger.warning(f"Invalid API key attempt from {request.remote_addr}")
            return jsonify({'success': False, 'error': 'Invalid API key'}), 403
        return f(*args, **kwargs)
    return decorated_function


# ============================================================================
# LOG GENERATION
# ============================================================================
def generate_auth_log_entries(scenario_id: str, event_count: int = 15, use_alternate_ip: bool = False) -> dict:
    """
    Generate auth.log formatted entries for a given scenario.

    Returns:
        dict with 'success', 'entries', 'ip_used', 'count'
    """
    scenario = DEMO_SCENARIOS.get(scenario_id)
    if not scenario:
        return {'success': False, 'error': f'Unknown scenario: {scenario_id}'}

    # Select IP (main or alternate)
    if use_alternate_ip and scenario.get('alternate_ips'):
        ip = random.choice(scenario['alternate_ips'])
    else:
        ip = scenario['ip']

    template = scenario['log_template']
    hostname = CONFIG['hostname']
    entries = []

    now = datetime.now()
    month = now.strftime('%b')
    day = now.day

    for i in range(event_count):
        # Generate timestamp with small offsets (1-3 seconds apart for realism)
        time_offset = i * random.randint(1, 3)
        event_time = datetime.fromtimestamp(now.timestamp() + time_offset)
        time_str = event_time.strftime('%H:%M:%S')

        # For credential stuffing, rotate usernames
        username = USERNAMES[i % len(USERNAMES)] if scenario.get('rotate_usernames') else 'root'

        # Format the log entry
        entry = f"{month} {day:2d} {time_str} {hostname} " + template.format(
            pid=random.randint(10000, 99999),
            ip=ip,
            port=random.randint(40000, 65000),
            username=username
        )
        entries.append(entry)

    return {
        'success': True,
        'entries': entries,
        'ip_used': ip,
        'count': len(entries),
        'scenario_name': scenario['name']
    }


def write_to_auth_log(entries: list) -> dict:
    """
    Append entries to auth.log file.

    Returns:
        dict with 'success', 'lines_written', 'log_file'
    """
    log_file = CONFIG['log_file']

    try:
        with open(log_file, 'a') as f:
            for entry in entries:
                f.write(entry + '\n')

        logger.info(f"Wrote {len(entries)} entries to {log_file}")
        return {
            'success': True,
            'lines_written': len(entries),
            'log_file': log_file
        }
    except PermissionError:
        logger.error(f"Permission denied writing to {log_file}")
        return {
            'success': False,
            'error': f'Permission denied: {log_file}. Run with sudo or check permissions.'
        }
    except Exception as e:
        logger.error(f"Error writing to {log_file}: {e}")
        return {
            'success': False,
            'error': str(e)
        }


# ============================================================================
# API ENDPOINTS
# ============================================================================
@app.route('/api/simulation/health', methods=['GET'])
def health_check():
    """Health check endpoint (no auth required)"""
    return jsonify({
        'success': True,
        'status': 'running',
        'hostname': CONFIG['hostname'],
        'port': CONFIG['port'],
        'log_file': CONFIG['log_file'],
        'last_injection': LAST_INJECTION,
        'scenarios_available': len(DEMO_SCENARIOS)
    })


@app.route('/api/simulation/scenarios', methods=['GET'])
@require_api_key
def list_scenarios():
    """List all available scenarios"""
    scenarios = []
    for sid, scenario in DEMO_SCENARIOS.items():
        scenarios.append({
            'id': sid,
            'name': scenario['name'],
            'ip': scenario['ip'],
            'alternate_ips': scenario.get('alternate_ips', [])
        })
    return jsonify({
        'success': True,
        'scenarios': scenarios,
        'count': len(scenarios)
    })


@app.route('/api/simulation/inject', methods=['POST'])
@require_api_key
def inject_attack():
    """
    Main endpoint to inject attack simulation into auth.log.

    Request Body:
        scenario_id: str - ID of the scenario to run (required)
        event_count: int - Number of log entries to generate (default: 15)
        use_alternate_ip: bool - Use alternate IP instead of main (default: False)

    Response:
        success: bool
        scenario_id: str
        scenario_name: str
        ip_used: str
        lines_written: int
        log_file: str
    """
    global LAST_INJECTION

    data = request.get_json() or {}
    scenario_id = data.get('scenario_id')
    event_count = data.get('event_count', 15)
    use_alternate_ip = data.get('use_alternate_ip', False)

    if not scenario_id:
        return jsonify({'success': False, 'error': 'scenario_id is required'}), 400

    # Validate event count
    event_count = max(1, min(50, int(event_count)))  # Limit 1-50

    logger.info(f"Injection request: scenario={scenario_id}, count={event_count}, from={request.remote_addr}")

    # Generate log entries
    gen_result = generate_auth_log_entries(scenario_id, event_count, use_alternate_ip)
    if not gen_result['success']:
        return jsonify(gen_result), 400

    # Write to auth.log
    write_result = write_to_auth_log(gen_result['entries'])
    if not write_result['success']:
        return jsonify(write_result), 500

    # Update tracking
    LAST_INJECTION = {
        'time': datetime.now().isoformat(),
        'scenario_id': scenario_id,
        'ip': gen_result['ip_used'],
        'count': gen_result['count']
    }

    return jsonify({
        'success': True,
        'scenario_id': scenario_id,
        'scenario_name': gen_result['scenario_name'],
        'ip_used': gen_result['ip_used'],
        'lines_written': write_result['lines_written'],
        'log_file': write_result['log_file'],
        'injected_at': LAST_INJECTION['time']
    })


@app.route('/api/simulation/test-write', methods=['POST'])
@require_api_key
def test_write():
    """
    Test write access to auth.log without actually writing attack entries.
    Writes a harmless test message.
    """
    log_file = CONFIG['log_file']
    test_entry = f"{datetime.now().strftime('%b %d %H:%M:%S')} {CONFIG['hostname']} ssh_guardian_sim[0]: Test write from simulation receiver"

    try:
        with open(log_file, 'a') as f:
            f.write(test_entry + '\n')

        return jsonify({
            'success': True,
            'message': 'Write test successful',
            'log_file': log_file
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e),
            'log_file': log_file
        }), 500


# ============================================================================
# STATUS & SELF-TEST
# ============================================================================
def print_status_banner(host, port, api_key, log_file):
    """Print a clear status banner showing configuration"""
    api_key_preview = api_key[:8] + '...' + api_key[-4:] if len(api_key) > 12 else '***'

    print()
    print("=" * 70)
    print("  SSH GUARDIAN v3.0 - SIMULATION RECEIVER")
    print("=" * 70)
    print()
    print(f"  Status:        \033[92m● RUNNING\033[0m")
    print(f"  Host:          {host}")
    print(f"  Port:          {port}")
    print(f"  Hostname:      {CONFIG['hostname']}")
    print(f"  Log File:      {log_file}")
    print(f"  API Key:       {api_key_preview}")
    print(f"  Scenarios:     {len(DEMO_SCENARIOS)} available")
    print()
    print("-" * 70)
    print("  ENDPOINTS:")
    print(f"    Health Check:   http://{host}:{port}/api/simulation/health")
    print(f"    Inject Attack:  http://{host}:{port}/api/simulation/inject")
    print(f"    Test Write:     http://{host}:{port}/api/simulation/test-write")
    print("-" * 70)
    print()


def run_self_test(api_key, port):
    """Run self-test to verify API key and connectivity"""
    import urllib.request
    import urllib.error

    print()
    print("=" * 70)
    print("  SELF-TEST MODE")
    print("=" * 70)
    print()

    tests_passed = 0
    tests_total = 3

    # Test 1: Check API key format
    print(f"  [1/3] API Key Format Check...")
    if api_key and len(api_key) >= 32:
        print(f"        \033[92m✓ PASS\033[0m - API key is properly formatted ({len(api_key)} chars)")
        tests_passed += 1
    else:
        print(f"        \033[91m✗ FAIL\033[0m - API key is missing or too short (got {len(api_key) if api_key else 0} chars, need 32+)")
        print(f"        → Check your API key from the dashboard")

    # Test 2: Check log file write access
    print(f"  [2/3] Log File Write Access...")
    log_file = CONFIG['log_file']
    if os.path.exists(log_file):
        if os.access(log_file, os.W_OK):
            print(f"        \033[92m✓ PASS\033[0m - Can write to {log_file}")
            tests_passed += 1
        else:
            print(f"        \033[91m✗ FAIL\033[0m - No write permission to {log_file}")
            print(f"        → Run with sudo or fix permissions: sudo chmod a+w {log_file}")
    else:
        # Try to create parent dir check
        parent_dir = os.path.dirname(log_file)
        if os.access(parent_dir, os.W_OK):
            print(f"        \033[93m⚠ WARN\033[0m - File doesn't exist but directory is writable")
            tests_passed += 1
        else:
            print(f"        \033[91m✗ FAIL\033[0m - Cannot create {log_file}")
            print(f"        → Run with sudo or check directory permissions")

    # Test 3: Check if port is available
    print(f"  [3/3] Port Availability Check...")
    try:
        test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        test_socket.settimeout(1)
        result = test_socket.connect_ex(('127.0.0.1', port))
        test_socket.close()

        if result != 0:
            print(f"        \033[92m✓ PASS\033[0m - Port {port} is available")
            tests_passed += 1
        else:
            print(f"        \033[91m✗ FAIL\033[0m - Port {port} is already in use")
            print(f"        → Stop the existing process or use a different port with --port")
    except Exception as e:
        print(f"        \033[93m⚠ WARN\033[0m - Could not check port: {e}")
        tests_passed += 1

    print()
    print("-" * 70)
    if tests_passed == tests_total:
        print(f"  \033[92mAll {tests_total} tests passed!\033[0m Configuration is correct.")
        print(f"  The receiver is ready to accept simulation commands.")
    else:
        print(f"  \033[91m{tests_total - tests_passed} of {tests_total} tests failed.\033[0m Fix the issues above.")
    print("-" * 70)
    print()
    print("  API Key Usage:")
    print("  → In dashboard: Go to Simulation > Manage > Enable agent > enter this key")
    print("  → The key shown here must EXACTLY match the key in the dashboard")
    print()

    return tests_passed == tests_total


def verify_api_key_match(api_key):
    """Show the full API key for verification"""
    print()
    print("=" * 70)
    print("  API KEY VERIFICATION")
    print("=" * 70)
    print()
    print("  Your configured API key is:")
    print()
    print(f"  \033[96m{api_key}\033[0m")
    print()
    print("  Copy this key and paste it in the SSH Guardian dashboard:")
    print("  Simulation > Manage Targets > Enable Simulation on your agent")
    print()
    print("  If you're getting 'Invalid API key' errors, ensure:")
    print("  1. The key above matches EXACTLY what's in the dashboard")
    print("  2. No extra spaces before or after the key")
    print("  3. The key hasn't been regenerated in the dashboard")
    print()
    print("=" * 70)
    print()


# ============================================================================
# MAIN
# ============================================================================
def main():
    parser = argparse.ArgumentParser(
        description='SSH Guardian Simulation Receiver',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Start receiver:
    python3 simulation_receiver.py --api-key YOUR_API_KEY

  Run self-test:
    python3 simulation_receiver.py --api-key YOUR_API_KEY --test

  Show API key for verification:
    python3 simulation_receiver.py --api-key YOUR_API_KEY --show-key

  Custom port and log file:
    python3 simulation_receiver.py --api-key YOUR_API_KEY --port 5002 --log-file /tmp/test.log
        """
    )
    parser.add_argument('--api-key', '-k', help='API key for authentication (or set SIM_RECEIVER_API_KEY)')
    parser.add_argument('--port', '-p', type=int, default=5001, help='Port to listen on (default: 5001)')
    parser.add_argument('--log-file', '-l', default='/var/log/auth.log', help='Path to auth.log')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to (default: 0.0.0.0)')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    parser.add_argument('--test', '-t', action='store_true', help='Run self-test and exit')
    parser.add_argument('--show-key', '-s', action='store_true', help='Show full API key for verification')
    parser.add_argument('--status', action='store_true', help='Show status and exit')

    args = parser.parse_args()

    # Update config from arguments
    if args.api_key:
        CONFIG['api_key'] = args.api_key
    if args.port:
        CONFIG['port'] = args.port
    if args.log_file:
        CONFIG['log_file'] = args.log_file

    # Validate API key is set
    if not CONFIG['api_key']:
        print("\033[91mError: API key is required.\033[0m")
        print()
        print("Set via --api-key or SIM_RECEIVER_API_KEY environment variable.")
        print("Get your API key from SSH Guardian dashboard:")
        print("  Simulation > Manage Targets > Enable Simulation > Copy the generated key")
        print()
        sys.exit(1)

    # Show key mode
    if args.show_key:
        verify_api_key_match(CONFIG['api_key'])
        sys.exit(0)

    # Self-test mode
    if args.test:
        success = run_self_test(CONFIG['api_key'], CONFIG['port'])
        sys.exit(0 if success else 1)

    # Status mode
    if args.status:
        print_status_banner(args.host, CONFIG['port'], CONFIG['api_key'], CONFIG['log_file'])
        sys.exit(0)

    # Check log file accessibility (warning only)
    log_file = CONFIG['log_file']
    if not os.path.exists(log_file):
        logger.warning(f"Log file does not exist: {log_file}. Will create on first write.")
    else:
        if not os.access(log_file, os.W_OK):
            logger.warning(f"No write access to {log_file}. Run with sudo or check permissions.")

    # Print status banner
    print_status_banner(args.host, CONFIG['port'], CONFIG['api_key'], CONFIG['log_file'])

    # Start server
    logger.info("Starting Flask server...")
    app.run(host=args.host, port=CONFIG['port'], debug=args.debug)


if __name__ == '__main__':
    main()
