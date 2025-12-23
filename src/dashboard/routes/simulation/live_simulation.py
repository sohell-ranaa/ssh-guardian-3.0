"""
SSH Guardian v3.0 - Live Attack Simulation
API endpoints for running live attack simulations against target servers
Supports both local (same machine) and remote (via HTTP) simulation
"""

import json
import os
import random
import socket
import requests
from datetime import datetime
from flask import request, jsonify
import sys
from pathlib import Path

# Add project paths
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent.parent
sys.path.append(str(PROJECT_ROOT / "dbs"))
sys.path.append(str(PROJECT_ROOT / "src"))

from connection import get_connection
from . import live_sim_routes
from src.core.auth import login_required
from src.simulation.demo_scenarios import DEMO_SCENARIOS, get_demo_scenarios

# Usernames for credential stuffing scenarios
USERNAMES = ['admin', 'root', 'user', 'oracle', 'postgres', 'mysql', 'test', 'ubuntu', 'deploy', 'guest', 'ftp', 'www-data']


def is_local_target(ip_address: str) -> bool:
    """Check if target IP is local (same machine as dashboard)"""
    local_ips = ['127.0.0.1', 'localhost', '::1']

    # Add machine's own IPs
    try:
        hostname = socket.gethostname()
        local_ips.append(socket.gethostbyname(hostname))
        # Get all IPs for this host
        for info in socket.getaddrinfo(hostname, None):
            local_ips.append(info[4][0])
    except:
        pass

    return ip_address in local_ips


def inject_local(scenario_id: str, event_count: int, use_alternate_ip: bool, log_file: str = '/var/log/auth.log', override_ip: str = None, action_type: str = 'attack', override_username: str = None, auth_type: str = 'password', auth_result: str = 'Failed', event_time: str = None) -> dict:
    """
    Inject attack simulation directly to local auth.log file.
    Used when dashboard and agent are on the same machine.

    Args:
        override_ip: If provided, use this IP instead of scenario's default IP
        override_username: If provided, use this username instead of scenario's default
        auth_type: password, publickey, keyboard-interactive
        auth_result: Accepted or Failed
        action_type: 'baseline' (create normal profile), 'normal' (test normal login), 'attack' (run attack)
        event_time: Time string in HH:MM format (e.g., '02:00' for 2am). If provided, uses this time instead of current.
    """
    scenario = DEMO_SCENARIOS.get(scenario_id)
    if not scenario:
        return {'success': False, 'error': f'Unknown scenario: {scenario_id}'}

    # Select IP - prefer override_ip (from frontend card), then alternate, then scenario default
    if override_ip:
        ip = override_ip
    elif use_alternate_ip and scenario.get('alternate_ips'):
        ip = random.choice(scenario['alternate_ips'])
    else:
        ip = scenario['ip']

    hostname = socket.gethostname()
    entries = []
    now = datetime.now()
    month = now.strftime('%b')
    day = now.day

    # Get username - prefer override from frontend, fallback to scenario default
    username = override_username if override_username else scenario.get('username', 'root')

    if action_type == 'baseline':
        # BASELINE: Generate 15 normal successful logins during business hours (9am-5pm)
        # This builds the behavioral profile for the user
        event_count = 15
        baseline_ip = '10.0.0.50'  # Internal/trusted IP for baseline

        for i in range(event_count):
            # Business hours: 9am to 5pm, spread over past days
            base_hour = 9 + (i % 8)  # 9, 10, 11, 12, 13, 14, 15, 16
            base_minute = random.randint(0, 59)
            base_second = random.randint(0, 59)
            time_str = f"{base_hour:02d}:{base_minute:02d}:{base_second:02d}"

            # Spread events over past few days
            days_ago = i // 3
            event_day = max(1, day - days_ago)

            entry = f"{month} {event_day:2d} {time_str} {hostname} sshd[{random.randint(10000, 99999)}]: Accepted password for {username} from {baseline_ip} port {random.randint(40000, 65000)} ssh2"
            entries.append(entry)

    elif action_type == 'normal':
        # NORMAL: Generate 1-2 normal successful logins (matching baseline pattern)
        event_count = 2
        baseline_ip = '10.0.0.50'  # Same trusted IP as baseline

        for i in range(event_count):
            # Current business hours
            current_hour = now.hour
            if current_hour < 9:
                current_hour = 9
            elif current_hour > 17:
                current_hour = 14
            time_str = f"{current_hour:02d}:{random.randint(0, 59):02d}:{random.randint(0, 59):02d}"

            entry = f"{month} {day:2d} {time_str} {hostname} sshd[{random.randint(10000, 99999)}]: Accepted password for {username} from {baseline_ip} port {random.randint(40000, 65000)} ssh2"
            entries.append(entry)

    else:
        # ATTACK: Use user-provided auth_type and auth_result to build log entry
        # Build template dynamically based on user selections
        log_template = f"sshd[{{pid}}]: {auth_result} {auth_type} for {{username}} from {{ip}} port {{port}} ssh2"

        for i in range(event_count):
            # Generate timestamp - use custom event_time if provided
            if event_time:
                # Parse HH:MM format and use today's date with that time
                try:
                    hour, minute = map(int, event_time.split(':'))
                    time_offset = i * random.randint(1, 3)  # Small offset for multiple events
                    time_str = f"{hour:02d}:{minute:02d}:{time_offset:02d}"
                except:
                    time_str = now.strftime('%H:%M:%S')
            else:
                time_offset = i * random.randint(1, 3)
                event_ts = datetime.fromtimestamp(now.timestamp() + time_offset)
                time_str = event_ts.strftime('%H:%M:%S')

            # For credential stuffing, rotate usernames
            attack_username = USERNAMES[i % len(USERNAMES)] if scenario.get('rotate_usernames') else username

            # Format the log entry
            entry = f"{month} {day:2d} {time_str} {hostname} " + log_template.format(
                pid=random.randint(10000, 99999),
                ip=ip,
                port=random.randint(40000, 65000),
                username=attack_username,
                day=day,
                time=time_str,
                hostname=hostname
            )
            entries.append(entry)

    # Write to auth.log
    try:
        with open(log_file, 'a') as f:
            for entry in entries:
                f.write(entry + '\n')

        return {
            'success': True,
            'ip_used': ip if action_type == 'attack' else '10.0.0.50',
            'lines_written': len(entries),
            'log_file': log_file,
            'injected_at': datetime.now().isoformat(),
            'local': True,
            'action_type': action_type
        }
    except PermissionError:
        return {'success': False, 'error': f'Permission denied writing to {log_file}. Run dashboard with sudo or check permissions.'}
    except Exception as e:
        return {'success': False, 'error': str(e)}


@live_sim_routes.route('/live/scenarios', methods=['GET'])
@login_required
def list_live_scenarios():
    """Get list of scenarios available for live simulation"""
    try:
        scenarios = get_demo_scenarios(use_fresh_ips=False)
        return jsonify({
            'success': True,
            'scenarios': scenarios,
            'count': len(scenarios)
        })
    except Exception as e:
        print(f"[LiveSim] Error listing scenarios: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@live_sim_routes.route('/live/run', methods=['POST'])
@login_required
def run_live_simulation():
    """
    Run a live attack simulation against a target server.

    Request Body:
        target_id: int - ID of the target server
        scenario_id: str - ID of the scenario (from DEMO_SCENARIOS)
        event_count: int - Number of events to inject (default: 15)
        use_alternate_ip: bool - Use alternate IP (default: False)

    Flow:
        1. Validate target and scenario
        2. Check if target is local or remote
        3. Local: Write directly to auth.log
        4. Remote: Send HTTP request to simulation receiver
        5. Create simulation_run record
        6. Return run_id for status tracking
    """
    try:
        data = request.get_json() or {}
        target_id = data.get('target_id')
        scenario_id = data.get('scenario_id')
        source_ip = data.get('source_ip')  # IP passed from frontend (from scenario card)
        username_override = data.get('username')  # Username override from frontend
        auth_type = data.get('auth_type', 'password')  # password, publickey, keyboard-interactive
        auth_result = data.get('auth_result', 'Failed')  # Accepted or Failed
        use_alternate_ip = data.get('use_alternate_ip', False)
        action_type = data.get('action_type', 'attack')  # 'baseline', 'normal', or 'attack'
        event_time = data.get('event_time')  # HH:MM format for custom time (e.g., '02:00' for 2am)

        if not target_id:
            return jsonify({'success': False, 'error': 'target_id is required'}), 400
        if not scenario_id:
            return jsonify({'success': False, 'error': 'scenario_id is required'}), 400

        # Get scenario details
        scenario = DEMO_SCENARIOS.get(scenario_id)
        if not scenario:
            return jsonify({'success': False, 'error': f'Unknown scenario: {scenario_id}'}), 400

        # Use scenario's event_count if frontend doesn't provide one, fallback to 15
        event_count = data.get('event_count') or scenario.get('event_count', 15)

        # Use the IP passed from frontend (exact IP shown on card), fallback to scenario default
        if not source_ip:
            source_ip = scenario.get('ip')

        # Get target server details
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT id, name, ip_address, port, api_key, is_active, agent_id
            FROM simulation_targets
            WHERE id = %s
        """, (target_id,))

        target = cursor.fetchone()

        if not target:
            cursor.close()
            conn.close()
            return jsonify({'success': False, 'error': 'Target not found'}), 404

        if not target['is_active']:
            cursor.close()
            conn.close()
            return jsonify({'success': False, 'error': 'Target is not active'}), 400

        # Create simulation run record
        import uuid as uuid_module
        run_uuid = str(uuid_module.uuid4())
        # source_ip is already set from request or scenario fallback
        cursor.execute("""
            INSERT INTO live_simulation_runs
            (run_uuid, target_id, scenario_id, scenario_name, source_ip, event_count, status, agent_id)
            VALUES (%s, %s, %s, %s, %s, %s, 'pending', %s)
        """, (run_uuid, target_id, scenario_id, scenario['name'], source_ip, event_count, target.get('agent_id', 0)))

        run_id = cursor.lastrowid
        conn.commit()

        # Check if target is local (same machine) or remote
        is_local = is_local_target(target['ip_address'])

        if is_local:
            # LOCAL: Write directly to auth.log with the exact IP and username from frontend
            print(f"[LiveSim] Local target detected ({target['ip_address']}), action={action_type}, injecting IP {source_ip}, user {username_override or 'default'}, auth={auth_type}/{auth_result}, time={event_time or 'now'} to auth.log")
            result = inject_local(scenario_id, event_count, use_alternate_ip, override_ip=source_ip, action_type=action_type, override_username=username_override, auth_type=auth_type, auth_result=auth_result, event_time=event_time)

            if result.get('success'):
                cursor.execute("""
                    UPDATE live_simulation_runs
                    SET status = 'injected',
                        source_ip = %s,
                        injected_at = NOW()
                    WHERE id = %s
                """, (result.get('ip_used', source_ip), run_id))
                conn.commit()
                cursor.close()
                conn.close()

                return jsonify({
                    'success': True,
                    'run_id': run_id,
                    'target_name': target['name'],
                    'scenario_id': scenario_id,
                    'scenario_name': scenario['name'],
                    'ip_used': result.get('ip_used'),
                    'lines_written': result.get('lines_written'),
                    'status': 'injected',
                    'local': True,
                    'message': f"Local injection: {result.get('lines_written', event_count)} events written to {result.get('log_file')}"
                })
            else:
                cursor.execute("""
                    UPDATE live_simulation_runs
                    SET status = 'failed', error_message = %s, completed_at = NOW()
                    WHERE id = %s
                """, (result.get('error', 'Local injection failed'), run_id))
                conn.commit()
                cursor.close()
                conn.close()
                return jsonify({'success': False, 'run_id': run_id, 'error': result.get('error')}), 500

        # REMOTE: Send HTTP request to simulation receiver
        receiver_url = f"http://{target['ip_address']}:{target['port']}/api/simulation/inject"

        try:
            response = requests.post(
                receiver_url,
                headers={
                    'X-API-Key': target['api_key'],
                    'Content-Type': 'application/json'
                },
                json={
                    'scenario_id': scenario_id,
                    'event_count': event_count,
                    'use_alternate_ip': use_alternate_ip,
                    'action_type': action_type
                },
                timeout=30
            )

            result = response.json()

            if result.get('success'):
                # Update run with injection details
                cursor.execute("""
                    UPDATE live_simulation_runs
                    SET status = 'injected',
                        source_ip = %s,
                        injected_at = NOW()
                    WHERE id = %s
                """, (result.get('ip_used', source_ip), run_id))
                conn.commit()

                cursor.close()
                conn.close()

                return jsonify({
                    'success': True,
                    'run_id': run_id,
                    'target_name': target['name'],
                    'scenario_id': scenario_id,
                    'scenario_name': scenario['name'],
                    'ip_used': result.get('ip_used'),
                    'lines_written': result.get('lines_written'),
                    'status': 'injected',
                    'message': f"Injected {result.get('lines_written', event_count)} events to {target['name']}"
                })
            else:
                # Update run as failed
                cursor.execute("""
                    UPDATE live_simulation_runs
                    SET status = 'failed',
                        error_message = %s,
                        completed_at = NOW()
                    WHERE id = %s
                """, (result.get('error', 'Unknown error'), run_id))
                conn.commit()
                cursor.close()
                conn.close()

                return jsonify({
                    'success': False,
                    'run_id': run_id,
                    'error': result.get('error', 'Injection failed')
                }), 500

        except requests.exceptions.ConnectionError:
            error_msg = f"Cannot connect to {target['ip_address']}:{target['port']} - is receiver running?"
            cursor.execute("""
                UPDATE live_simulation_runs
                SET status = 'failed', error_message = %s, completed_at = NOW()
                WHERE id = %s
            """, (error_msg, run_id))
            conn.commit()
            cursor.close()
            conn.close()
            return jsonify({'success': False, 'run_id': run_id, 'error': error_msg}), 500

        except requests.exceptions.Timeout:
            error_msg = 'Connection timeout'
            cursor.execute("""
                UPDATE live_simulation_runs
                SET status = 'failed', error_message = %s, completed_at = NOW()
                WHERE id = %s
            """, (error_msg, run_id))
            conn.commit()
            cursor.close()
            conn.close()
            return jsonify({'success': False, 'run_id': run_id, 'error': error_msg}), 500

    except Exception as e:
        print(f"[LiveSim] Error running simulation: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500


@live_sim_routes.route('/live/<int:run_id>/status', methods=['GET'])
@login_required
def get_simulation_status(run_id):
    """
    Get current status of a simulation run.

    Checks:
    - Run record status
    - fail2ban events for the source IP
    - auth_events from the target agent
    - ip_blocks for the source IP
    """
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Get run details
        cursor.execute("""
            SELECT
                sr.*,
                st.name as target_name,
                st.agent_id
            FROM live_simulation_runs sr
            JOIN simulation_targets st ON sr.target_id = st.id
            WHERE sr.id = %s
        """, (run_id,))

        run = cursor.fetchone()

        if not run:
            cursor.close()
            conn.close()
            return jsonify({'success': False, 'error': 'Run not found'}), 404

        source_ip = run['source_ip']
        agent_id = run.get('agent_id')

        # Check for auth_events from this IP since injection
        events_detected = 0
        if run.get('injected_at'):
            cursor.execute("""
                SELECT COUNT(*) as count
                FROM auth_events
                WHERE source_ip_text = %s
                AND timestamp >= %s
            """, (source_ip, run['injected_at']))

            result = cursor.fetchone()
            events_detected = result['count'] if result else 0

            # Update events_detected count
            if events_detected > run.get('events_detected', 0):
                cursor.execute("""
                    UPDATE live_simulation_runs
                    SET events_detected = %s,
                        detected_at = COALESCE(detected_at, NOW()),
                        status = CASE WHEN status = 'injected' THEN 'detected' ELSE status END
                    WHERE id = %s
                """, (events_detected, run_id))
                conn.commit()

        # Check for fail2ban blocks
        fail2ban_block = None
        cursor.execute("""
            SELECT id, created_at
            FROM fail2ban_events
            WHERE ip_address = %s
            AND event_type = 'ban'
            AND created_at >= %s
            ORDER BY created_at DESC
            LIMIT 1
        """, (source_ip, run.get('injected_at') or run['created_at']))

        fb_result = cursor.fetchone()
        if fb_result:
            fail2ban_block = {
                'id': fb_result['id'],
                'blocked_at': fb_result['created_at'].isoformat() if fb_result['created_at'] else None
            }

        # Check for ML/manual blocks
        ip_block = None
        cursor.execute("""
            SELECT id, block_source, blocked_at, block_reason
            FROM ip_blocks
            WHERE ip_address_text = %s
            AND is_active = TRUE
            AND blocked_at >= %s
            ORDER BY blocked_at DESC
            LIMIT 1
        """, (source_ip, run.get('injected_at') or run['created_at']))

        block_result = cursor.fetchone()
        if block_result:
            ip_block = {
                'id': block_result['id'],
                'source': block_result['block_source'],
                'reason': block_result['block_reason'],
                'blocked_at': block_result['blocked_at'].isoformat() if block_result['blocked_at'] else None
            }

        # Update status if blocked
        if (fail2ban_block or ip_block) and run['status'] not in ('blocked', 'completed', 'failed'):
            cursor.execute("""
                UPDATE live_simulation_runs
                SET status = 'blocked',
                    blocked_at = NOW(),
                    fail2ban_block_id = %s,
                    ml_block_id = %s
                WHERE id = %s
            """, (
                fail2ban_block['id'] if fail2ban_block else None,
                ip_block['id'] if ip_block else None,
                run_id
            ))
            conn.commit()

            # Refresh run data
            cursor.execute("SELECT * FROM live_simulation_runs WHERE id = %s", (run_id,))
            run = cursor.fetchone()

        # Auto-complete detected simulations after wait period if no block occurred
        # This handles baseline/normal scenarios that shouldn't trigger blocks
        elif run['status'] == 'detected' and events_detected >= run.get('event_count', 1):
            # If detected and all events processed, wait 5 seconds then mark complete
            from datetime import datetime, timedelta
            detected_at = run.get('detected_at')
            if detected_at:
                # If more than 5 seconds since detection and no block, mark as completed
                if datetime.now() - detected_at > timedelta(seconds=5):
                    cursor.execute("""
                        UPDATE live_simulation_runs
                        SET status = 'completed', completed_at = NOW()
                        WHERE id = %s AND status = 'detected'
                    """, (run_id,))
                    conn.commit()
                    # Refresh run data
                    cursor.execute("SELECT * FROM live_simulation_runs WHERE id = %s", (run_id,))
                    run = cursor.fetchone()

        cursor.close()
        conn.close()

        # Build timeline
        timeline = []

        timeline.append({
            'step': 'created',
            'status': 'completed',
            'time': run['created_at'].isoformat() if run.get('created_at') else None,
            'message': 'Simulation created'
        })

        if run.get('injected_at'):
            timeline.append({
                'step': 'injected',
                'status': 'completed',
                'time': run['injected_at'].isoformat(),
                'message': f"Injected {run['event_count']} events to auth.log"
            })

        if run.get('detected_at') or events_detected > 0:
            timeline.append({
                'step': 'detected',
                'status': 'completed',
                'time': run['detected_at'].isoformat() if run.get('detected_at') else None,
                'message': f"Detected {events_detected} events in dashboard"
            })
        elif run['status'] == 'injected':
            timeline.append({
                'step': 'detected',
                'status': 'pending',
                'time': None,
                'message': 'Waiting for agent to report events...'
            })

        if fail2ban_block:
            timeline.append({
                'step': 'fail2ban_block',
                'status': 'completed',
                'time': fail2ban_block['blocked_at'],
                'message': 'fail2ban blocked the IP'
            })

        if ip_block:
            timeline.append({
                'step': 'ip_block',
                'status': 'completed',
                'time': ip_block['blocked_at'],
                'message': f"IP blocked ({ip_block['source']})"
            })

        if run['status'] == 'blocked' or (fail2ban_block or ip_block):
            timeline.append({
                'step': 'completed',
                'status': 'completed',
                'time': run.get('blocked_at', run.get('completed_at')),
                'message': 'Simulation complete - attack detected and blocked!'
            })
        elif run['status'] == 'completed':
            timeline.append({
                'step': 'completed',
                'status': 'completed',
                'time': run.get('completed_at'),
                'message': 'Simulation complete - events processed (no block triggered)'
            })
        elif run['status'] == 'failed':
            timeline.append({
                'step': 'failed',
                'status': 'failed',
                'time': run.get('completed_at'),
                'message': run.get('error_message', 'Simulation failed')
            })

        # Format dates in run
        for key in ['created_at', 'injected_at', 'detected_at', 'blocked_at', 'completed_at']:
            if run.get(key):
                run[key] = run[key].isoformat()

        return jsonify({
            'success': True,
            'run_id': run_id,
            'status': run['status'],
            'target_name': run.get('target_name'),
            'scenario_id': run['scenario_id'],
            'scenario_name': run['scenario_name'],
            'source_ip': source_ip,
            'events_detected': events_detected,
            'fail2ban_block': fail2ban_block,
            'ip_block': ip_block,
            'is_complete': run['status'] in ('blocked', 'completed', 'failed'),
            'timeline': timeline,
            'run': run
        })

    except Exception as e:
        print(f"[LiveSim] Error getting status for run {run_id}: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500


@live_sim_routes.route('/live/history', methods=['GET'])
@login_required
def get_simulation_history():
    """Get history of simulation runs"""
    try:
        limit = request.args.get('limit', 20, type=int)
        offset = request.args.get('offset', 0, type=int)

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT
                sr.*,
                st.name as target_name
            FROM live_simulation_runs sr
            JOIN simulation_targets st ON sr.target_id = st.id
            ORDER BY sr.created_at DESC
            LIMIT %s OFFSET %s
        """, (limit, offset))

        runs = cursor.fetchall()

        # Format dates
        for run in runs:
            for key in ['created_at', 'injected_at', 'detected_at', 'blocked_at', 'completed_at']:
                if run.get(key):
                    run[key] = run[key].isoformat()

        # Get total count
        cursor.execute("SELECT COUNT(*) as count FROM live_simulation_runs")
        total = cursor.fetchone()['count']

        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'runs': runs,
            'count': len(runs),
            'total': total,
            'limit': limit,
            'offset': offset
        })

    except Exception as e:
        print(f"[LiveSim] Error getting history: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@live_sim_routes.route('/live/<int:run_id>/complete', methods=['POST'])
@login_required
def mark_simulation_complete(run_id):
    """Manually mark a simulation as complete"""
    try:
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            UPDATE live_simulation_runs
            SET status = 'completed',
                completed_at = NOW()
            WHERE id = %s
            AND status NOT IN ('completed', 'failed')
        """, (run_id,))

        if cursor.rowcount == 0:
            cursor.close()
            conn.close()
            return jsonify({'success': False, 'error': 'Run not found or already completed'}), 404

        conn.commit()
        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'message': 'Simulation marked as complete'
        })

    except Exception as e:
        print(f"[LiveSim] Error completing run {run_id}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500
