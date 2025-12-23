"""
SSH Guardian v3.1 - Fail2ban Integration Routes
Receives ban/unban reports from fail2ban actions on agent servers
Updated for v3.1 database schema
"""

import sys
from datetime import datetime, timedelta
from flask import request, jsonify
from pathlib import Path

# Add project paths
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent.parent
sys.path.append(str(PROJECT_ROOT / "dbs"))
sys.path.append(str(PROJECT_ROOT / "src" / "core"))

from connection import get_connection, ip_to_binary
from . import agent_routes

# Import blocking operations
try:
    from blocking.ip_operations import block_ip, unblock_ip
except ImportError:
    sys.path.insert(0, str(PROJECT_ROOT / "src" / "core"))
    from blocking.ip_operations import block_ip, unblock_ip

# Import enrichment for ML analysis
try:
    from enrichment import EventEnricher
except ImportError:
    EventEnricher = None

# Import ML evaluator for threat scoring
try:
    from blocking.fail2ban_ml_evaluator import evaluate_fail2ban_ban
except ImportError:
    evaluate_fail2ban_ban = None

# Import block events logging
try:
    from routes.block_events_routes import log_block_event
except ImportError:
    log_block_event = None


def verify_api_key_simple():
    """
    Simple API key verification for fail2ban actions.
    Accepts API key in header or JSON body (fail2ban curl limitation).
    Returns agent dict if valid, None otherwise.
    """
    api_key = request.headers.get('X-API-Key')

    # Also check JSON body for api_key (fail2ban convenience)
    if not api_key and request.is_json:
        api_key = request.json.get('api_key')

    if not api_key:
        return None

    conn = None
    cursor = None
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT id, agent_id, hostname, is_active, is_approved
            FROM agents
            WHERE api_key = %s
        """, (api_key,))

        agent = cursor.fetchone()

        if agent and agent['is_active'] and agent['is_approved']:
            return agent
        return None

    except Exception as e:
        print(f"Auth error: {e}")
        return None
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@agent_routes.route('/agents/fail2ban/ban', methods=['POST'])
def report_fail2ban_ban():
    """
    Receive ban report from fail2ban action.

    Expected JSON:
    {
        "ip": "1.2.3.4",
        "jail": "sshd",
        "agent_id": "agent-uuid",
        "action": "ban",
        "failures": 5,
        "bantime": 3600
    }
    """
    try:
        # Verify API key
        agent = verify_api_key_simple()
        if not agent:
            return jsonify({
                'success': False,
                'error': 'Invalid or missing API key'
            }), 401

        data = request.json
        if not data:
            return jsonify({
                'success': False,
                'error': 'No JSON data provided'
            }), 400

        ip_address = data.get('ip')
        jail = data.get('jail', 'sshd')
        failures = data.get('failures', 0)
        bantime = data.get('bantime', 3600)  # Default 1 hour

        if not ip_address:
            return jsonify({
                'success': False,
                'error': 'IP address is required'
            }), 400

        # Convert bantime (seconds) to minutes
        duration_minutes = max(1, bantime // 60)

        # Block the IP using existing function
        # Use 'fail2ban' as block_source to distinguish from ML/manual blocks
        result = block_ip(
            ip_address=ip_address,
            block_reason=f'fail2ban/{jail}: {failures} failures',
            block_source='fail2ban',
            failed_attempts=failures,
            block_duration_minutes=duration_minutes,
            auto_unblock=True
        )

        if result['success']:
            # Log the fail2ban ban event
            conn = get_connection()
            cursor = conn.cursor()

            try:
                # v3.1: event_type instead of action, timestamp instead of reported_at
                cursor.execute("""
                    INSERT INTO fail2ban_events (
                        agent_id, event_type, ip_address, jail_name,
                        failures, bantime_seconds, timestamp
                    ) VALUES (%s, 'ban', %s, %s, %s, %s, NOW())
                """, (agent['id'], ip_address, jail, failures, bantime))
                conn.commit()
            except Exception as e:
                print(f"Note: Could not log fail2ban event: {e}")
            finally:
                cursor.close()
                conn.close()

            # Trigger async enrichment if available
            if EventEnricher:
                try:
                    enricher = EventEnricher()
                    # Create a minimal event dict for enrichment
                    event_data = {
                        'source_ip': ip_address,
                        'event_type': 'failed',
                        'username': 'unknown',
                        'timestamp': datetime.now().strftime('%Y-%m-%dT%H:%M:%S+08:00')
                    }
                    # Run enrichment async (non-blocking)
                    enricher.enrich_ip_background(ip_address)
                except Exception as e:
                    print(f"Enrichment skipped: {e}")

            # Run ML threat evaluation
            ml_evaluation = None
            if evaluate_fail2ban_ban:
                try:
                    ml_evaluation = evaluate_fail2ban_ban(
                        ip_address=ip_address,
                        failures=failures,
                        jail=jail,
                        agent_id=agent['id']
                    )
                    if ml_evaluation.get('auto_escalated'):
                        print(f"AUTO-ESCALATED {ip_address} to UFW (score={ml_evaluation.get('threat_score')})")
                except Exception as e:
                    print(f"ML evaluation skipped: {e}")

            print(f"fail2ban ban: {ip_address} (jail={jail}, failures={failures})")

            response_data = {
                'success': True,
                'message': f'Ban recorded for {ip_address}',
                'block_id': result.get('block_id'),
                'source': 'fail2ban'
            }

            # Include ML evaluation results if available
            if ml_evaluation:
                response_data['ml_evaluation'] = {
                    'threat_score': ml_evaluation.get('threat_score', 0),
                    'risk_level': ml_evaluation.get('risk_level', 'unknown'),
                    'auto_escalated': ml_evaluation.get('auto_escalated', False)
                }

            return jsonify(response_data)
        else:
            # IP might already be blocked
            return jsonify({
                'success': True,
                'message': result.get('message', 'IP already blocked'),
                'already_blocked': True
            })

    except Exception as e:
        print(f"fail2ban ban error: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@agent_routes.route('/agents/fail2ban/unban', methods=['POST'])
def report_fail2ban_unban():
    """
    Receive unban report from fail2ban action.

    Expected JSON:
    {
        "ip": "1.2.3.4",
        "jail": "sshd",
        "agent_id": "agent-uuid",
        "action": "unban"
    }
    """
    try:
        # Verify API key
        agent = verify_api_key_simple()
        if not agent:
            return jsonify({
                'success': False,
                'error': 'Invalid or missing API key'
            }), 401

        data = request.json
        if not data:
            return jsonify({
                'success': False,
                'error': 'No JSON data provided'
            }), 400

        ip_address = data.get('ip')
        jail = data.get('jail', 'sshd')

        if not ip_address:
            return jsonify({
                'success': False,
                'error': 'IP address is required'
            }), 400

        # Check if this IP was blocked by fail2ban (not ML or manual)
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            cursor.execute("""
                SELECT id, block_source FROM ip_blocks
                WHERE ip_address_text = %s AND is_active = TRUE
            """, (ip_address,))

            block = cursor.fetchone()

            if block:
                # Only auto-unblock if it was blocked by fail2ban
                # ML and manual blocks should persist until dashboard unblocks
                if block['block_source'] == 'fail2ban':
                    result = unblock_ip(
                        ip_address=ip_address,
                        unblock_reason=f'fail2ban/{jail}: Auto-unban after bantime expired'
                    )

                    # Log the unban event
                    # v3.1: event_type instead of action, timestamp instead of reported_at
                    cursor.execute("""
                        INSERT INTO fail2ban_events (
                            agent_id, event_type, ip_address, jail_name,
                            failures, bantime_seconds, timestamp
                        ) VALUES (%s, 'unban', %s, %s, 0, 0, NOW())
                    """, (agent['id'], ip_address, jail))
                    conn.commit()

                    print(f"fail2ban unban: {ip_address} (jail={jail})")

                    return jsonify({
                        'success': True,
                        'message': f'Unban recorded for {ip_address}',
                        'source': 'fail2ban'
                    })
                else:
                    # IP was blocked by ML/manual - don't auto-unblock
                    print(f"fail2ban unban skipped: {ip_address} blocked by {block['block_source']}")
                    return jsonify({
                        'success': True,
                        'message': f'IP {ip_address} blocked by {block["block_source"]}, not auto-unblocking',
                        'skipped': True,
                        'block_source': block['block_source']
                    })
            else:
                # No active block found - might have been manually unblocked
                return jsonify({
                    'success': True,
                    'message': f'No active block for {ip_address}',
                    'no_block': True
                })

        except Exception as e:
            print(f"Note: fail2ban unban error: {e}")
            raise
        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        print(f"fail2ban unban error: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@agent_routes.route('/agents/fail2ban/pending-unbans', methods=['GET'])
def get_pending_fail2ban_unbans():
    """
    Get pending unban commands for an agent.
    When dashboard admin manually unblocks an IP that was blocked by fail2ban,
    the agent needs to know to run `fail2ban-client unbanip`.

    v3.1: Uses blocking_actions to track manual unblocks instead of ip_blocks columns
    """
    try:
        # Verify API key
        agent = verify_api_key_simple()
        if not agent:
            return jsonify({
                'success': False,
                'error': 'Invalid or missing API key'
            }), 401

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            # v3.1: Find recent manual unblocks of fail2ban IPs from blocking_actions
            cursor.execute("""
                SELECT DISTINCT ba.ip_address_text
                FROM blocking_actions ba
                WHERE ba.action_source = 'fail2ban'
                  AND ba.action_type = 'unblock'
                  AND ba.created_at >= DATE_SUB(NOW(), INTERVAL 1 HOUR)
                  AND ba.agent_id = %s
                ORDER BY ba.created_at DESC
                LIMIT 10
            """, (agent['id'],))

            pending = cursor.fetchall()

            commands = []
            for block in pending:
                commands.append({
                    'ip': block['ip_address_text'],
                    'jail': 'sshd',  # Default jail
                    'action': 'unban'
                })

            return jsonify({
                'success': True,
                'commands': commands,
                'count': len(commands)
            })

        except Exception as e:
            print(f"Note: pending-unbans query: {e}")
            return jsonify({
                'success': True,
                'commands': [],
                'count': 0
            })
        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@agent_routes.route('/agents/fail2ban/sync', methods=['POST'])
def sync_fail2ban_status():
    """
    Receive current fail2ban ban status from agent.
    Agent periodically sends list of currently banned IPs.
    This is the LIVE state - what fail2ban is currently enforcing.

    Expected JSON:
    {
        "agent_id": "agent-uuid",
        "hostname": "server1",
        "bans": [
            {"ip": "1.2.3.4", "jail": "sshd", "failures": 5, "bantime": 3600},
            ...
        ]
    }

    v3.1: Uses fail2ban_state instead of agent_fail2ban_state
    """
    try:
        # Verify API key
        agent = verify_api_key_simple()
        if not agent:
            return jsonify({
                'success': False,
                'error': 'Invalid or missing API key'
            }), 401

        data = request.json
        if not data:
            return jsonify({
                'success': False,
                'error': 'No JSON data provided'
            }), 400

        bans = data.get('bans', [])
        agent_db_id = agent['id']
        hostname = data.get('hostname', agent['hostname'])

        conn = get_connection()
        cursor = conn.cursor(dictionary=True, buffered=True)

        try:
            # STEP 1: Update fail2ban_state with LIVE data from agent
            # v3.1: Table renamed from agent_fail2ban_state to fail2ban_state

            # Clear old state for this agent
            cursor.execute("DELETE FROM fail2ban_state WHERE agent_id = %s", (agent_db_id,))

            # Insert current bans
            for ban in bans:
                ip = ban.get('ip')
                jail = ban.get('jail', 'sshd')
                failures = ban.get('failures', 0)
                bantime = ban.get('bantime', 0)
                banned_at = ban.get('banned_at') or ban.get('timestamp')

                if not ip:
                    continue

                cursor.execute("""
                    INSERT INTO fail2ban_state
                    (agent_id, ip_address, jail_name, banned_at, bantime_seconds, failures, last_sync)
                    VALUES (%s, %s, %s, %s, %s, %s, NOW())
                """, (agent_db_id, ip, jail, banned_at or datetime.now(), bantime, failures))

            # STEP 2: Update ip_blocks for history (Blocked IPs table)
            current_ips = set(b.get('ip') for b in bans if b.get('ip'))

            for ban in bans:
                ip = ban.get('ip')
                jail = ban.get('jail', 'sshd')
                banned_at = ban.get('banned_at') or ban.get('timestamp')

                if not ip:
                    continue

                ip_binary = ip_to_binary(ip)

                # Check if exists in ip_blocks
                cursor.execute(
                    "SELECT id, is_active FROM ip_blocks "
                    "WHERE ip_address_text = %s AND block_source = 'fail2ban' "
                    "ORDER BY blocked_at DESC LIMIT 1",
                    (ip,)
                )
                existing = cursor.fetchone()

                if existing and existing['is_active']:
                    pass  # Already active, nothing to do
                elif existing:
                    # Reactivate - clear unblocked_at as well
                    cursor.execute(
                        "UPDATE ip_blocks SET is_active = TRUE, blocked_at = %s, "
                        "unblocked_at = NULL, unblock_reason = NULL, agent_id = %s "
                        "WHERE id = %s",
                        (banned_at or datetime.now(), agent_db_id, existing['id'])
                    )
                    # Log block event (reactivation)
                    if log_block_event:
                        log_block_event(
                            ip_address=ip,
                            event_type='block',
                            block_source='fail2ban',
                            agent_id=agent_db_id,
                            reason=f'Reactivated - fail2ban jail: {jail}',
                            jail_name=jail,
                            failures=ban.get('failures', 0),
                            bantime_seconds=ban.get('bantime', 0),
                            triggered_by='agent_sync'
                        )
                else:
                    # Insert new
                    cursor.execute(
                        "INSERT INTO ip_blocks "
                        "(ip_address, ip_address_text, block_source, block_reason, is_active, blocked_at, agent_id) "
                        "VALUES (%s, %s, 'fail2ban', %s, TRUE, %s, %s)",
                        (ip_binary, ip, f'fail2ban jail: {jail} (agent: {hostname})',
                         banned_at or datetime.now(), agent_db_id)
                    )
                    # Log block event (new)
                    if log_block_event:
                        log_block_event(
                            ip_address=ip,
                            event_type='block',
                            block_source='fail2ban',
                            agent_id=agent_db_id,
                            reason=f'New fail2ban ban - jail: {jail}',
                            jail_name=jail,
                            failures=ban.get('failures', 0),
                            bantime_seconds=ban.get('bantime', 0),
                            triggered_by='agent_sync'
                        )

            # STEP 3: Deactivate IPs no longer in fail2ban
            cursor.execute(
                "SELECT id, ip_address_text FROM ip_blocks "
                "WHERE agent_id = %s AND block_source = 'fail2ban' AND is_active = TRUE",
                (agent_db_id,)
            )
            active_blocks = cursor.fetchall()
            auto_unbanned = 0

            for row in active_blocks:
                if row['ip_address_text'] not in current_ips:
                    cursor.execute(
                        "UPDATE ip_blocks SET is_active = FALSE, "
                        "unblocked_at = NOW(), unblock_reason = 'Auto-expired in fail2ban' WHERE id = %s",
                        (row['id'],)
                    )
                    # Log unban event for history
                    # v3.1: event_type instead of action, timestamp instead of reported_at
                    cursor.execute(
                        "INSERT INTO fail2ban_events "
                        "(agent_id, event_type, ip_address, jail_name, failures, bantime_seconds, timestamp) "
                        "VALUES (%s, 'unban', %s, 'sshd', 0, 0, NOW())",
                        (agent_db_id, row['ip_address_text'])
                    )
                    # Log unblock event to block events table
                    if log_block_event:
                        log_block_event(
                            ip_address=row['ip_address_text'],
                            event_type='unblock',
                            block_source='fail2ban',
                            agent_id=agent_db_id,
                            reason='Auto-expired in fail2ban',
                            triggered_by='agent_sync'
                        )
                    auto_unbanned += 1

            if auto_unbanned > 0:
                print(f"Auto-unbanned {auto_unbanned} expired fail2ban bans for agent {agent_db_id}")

            conn.commit()

            return jsonify({
                'success': True,
                'message': 'Fail2ban sync complete',
                'total_bans': len(bans),
                'auto_unbanned': auto_unbanned
            })

        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        print(f"Fail2ban sync error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@agent_routes.route('/agents/<int:agent_id>/fail2ban/live', methods=['GET'])
def get_live_fail2ban_bans(agent_id):
    """
    Get LIVE fail2ban bans for an agent.
    For local agent: fetches directly from fail2ban-client
    For remote agents: reads from fail2ban_state table (synced by agent)
    """
    import subprocess
    import socket

    conn = None
    cursor = None
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Get agent info
        cursor.execute("SELECT hostname, agent_id as agent_uuid, ip_address FROM agents WHERE id = %s", (agent_id,))
        agent = cursor.fetchone()

        if not agent:
            return jsonify({'success': False, 'error': 'Agent not found'}), 404

        result = []
        is_local = False

        # Check if this is the local machine
        local_hostname = socket.gethostname()
        agent_ip = agent.get('ip_address', '')
        if agent['hostname'] == local_hostname or agent_ip in ('127.0.0.1', 'localhost', ''):
            is_local = True

        if is_local:
            # Fetch from fail2ban-client for accurate "currently banned" list
            # Then use sqlite for timing info
            import sqlite3 as sqlite
            import time

            f2b_db_path = '/var/lib/fail2ban/fail2ban.sqlite3'
            now_ts = int(time.time())

            # First, get the list of CURRENTLY banned IPs from fail2ban-client
            currently_banned = set()
            try:
                jail_result = subprocess.run(
                    ['sudo', 'fail2ban-client', 'status', 'sshd'],
                    capture_output=True, text=True, timeout=10
                )
                if jail_result.returncode == 0:
                    for line in jail_result.stdout.split('\n'):
                        if 'Banned IP list:' in line:
                            ip_str = line.split(':')[1].strip() if ':' in line else ''
                            currently_banned = set(ip.strip() for ip in ip_str.split() if ip.strip())
            except Exception as e:
                print(f"[Fail2ban] Error getting banned list: {e}")

            try:
                f2b_conn = sqlite.connect(f2b_db_path)
                f2b_conn.row_factory = sqlite.Row
                f2b_cursor = f2b_conn.cursor()

                # Query bans with timing info
                f2b_cursor.execute("""
                    SELECT
                        ip,
                        jail,
                        timeofban,
                        bantime,
                        bancount,
                        (timeofban + bantime) as expires_ts
                    FROM bans
                    ORDER BY timeofban DESC
                """)

                for row in f2b_cursor.fetchall():
                    ip = row['ip']
                    # Only include IPs that are CURRENTLY banned according to fail2ban-client
                    if ip not in currently_banned:
                        continue

                    remaining_sec = row['expires_ts'] - now_ts
                    # If fail2ban-client says it's banned, it's not expired
                    # (fail2ban may have extended the ban or timing is off)
                    is_expired = False

                    result.append({
                        'ip_address': ip,
                        'jail_name': row['jail'],
                        'banned_at': datetime.fromtimestamp(row['timeofban']).isoformat() + '+08:00',
                        'bantime_seconds': row['bantime'],
                        'expires_at': datetime.fromtimestamp(row['expires_ts']).isoformat() + '+08:00',
                        'remaining_seconds': max(0, remaining_sec),
                        'remaining_minutes': max(0, remaining_sec // 60),
                        'is_expired': is_expired,
                        'ban_count': row['bancount'],
                        'failures': 0,
                        'last_sync': datetime.now().isoformat() + '+08:00',
                        'agent_hostname': agent['hostname'],
                        'agent_id': agent_id,
                        'agent_uuid': agent['agent_uuid'],
                        'source': 'live'
                    })

                # Add any IPs from fail2ban-client that aren't in sqlite (edge case)
                sqlite_ips = set(r['ip_address'] for r in result)
                for ip in currently_banned:
                    if ip not in sqlite_ips:
                        result.append({
                            'ip_address': ip,
                            'jail_name': 'sshd',
                            'banned_at': datetime.now().isoformat() + '+08:00',
                            'bantime_seconds': 3600,
                            'remaining_seconds': 0,
                            'remaining_minutes': 0,
                            'is_expired': False,
                            'ban_count': 1,
                            'failures': 0,
                            'agent_hostname': agent['hostname'],
                            'agent_id': agent_id,
                            'agent_uuid': agent['agent_uuid'],
                            'source': 'live'
                        })

                f2b_conn.close()

            except Exception as e:
                print(f"[Fail2ban] Error reading sqlite db: {e}")
                # Fallback to fail2ban-client
                try:
                    jail_result = subprocess.run(
                        ['sudo', 'fail2ban-client', 'status', 'sshd'],
                        capture_output=True, text=True, timeout=10
                    )
                    if jail_result.returncode == 0:
                        for line in jail_result.stdout.split('\n'):
                            if 'Banned IP list:' in line:
                                ip_str = line.split(':')[1].strip() if ':' in line else ''
                                banned_ips = [ip.strip() for ip in ip_str.split() if ip.strip()]
                                for ip in banned_ips:
                                    result.append({
                                        'ip_address': ip,
                                        'jail_name': 'sshd',
                                        'banned_at': datetime.now().isoformat() + '+08:00',
                                        'bantime_seconds': 3600,
                                        'remaining_seconds': 0,
                                        'remaining_minutes': 0,
                                        'is_expired': False,
                                        'ban_count': 1,
                                        'failures': 0,
                                        'agent_hostname': agent['hostname'],
                                        'agent_id': agent_id,
                                        'agent_uuid': agent['agent_uuid'],
                                        'source': 'live-fallback'
                                    })
                except Exception as fallback_err:
                    print(f"[Fail2ban] Fallback also failed: {fallback_err}")

        else:
            # Remote agent - read from fail2ban_state table
            cursor.execute("""
                SELECT
                    ip_address,
                    jail_name,
                    banned_at,
                    bantime_seconds,
                    failures,
                    last_sync
                FROM fail2ban_state
                WHERE agent_id = %s
                ORDER BY banned_at DESC
            """, (agent_id,))

            bans = cursor.fetchall()
            for ban in bans:
                result.append({
                    'ip_address': ban['ip_address'],
                    'jail_name': ban['jail_name'],
                    'banned_at': ban['banned_at'].isoformat() if ban['banned_at'] else None,
                    'bantime_seconds': ban['bantime_seconds'],
                    'failures': ban['failures'],
                    'last_sync': ban['last_sync'].isoformat() if ban['last_sync'] else None,
                    'agent_hostname': agent['hostname'],
                    'agent_id': agent_id,
                    'agent_uuid': agent['agent_uuid'],
                    'source': 'database'
                })

        return jsonify({
            'success': True,
            'bans': result,
            'total': len(result),
            'agent_hostname': agent['hostname'],
            'is_local': is_local
        })

    except Exception as e:
        print(f"Error getting live fail2ban bans: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@agent_routes.route('/agents/fail2ban/history', methods=['GET'])
def get_fail2ban_history():
    """
    Get fail2ban events history with filtering support.
    Used by the Live Events Fail2ban History tab.

    v3.1: event_type instead of action, timestamp instead of reported_at
    """
    page = request.args.get('page', 1, type=int)
    page_size = min(request.args.get('page_size', 50, type=int), 100)
    ip = request.args.get('ip', '').strip()
    jail = request.args.get('jail', '').strip()
    event_type = request.args.get('event_type', '').strip() or request.args.get('action', '').strip()  # Support both
    agent_id = request.args.get('agent_id', type=int)
    time_range = request.args.get('time_range', '7d')

    conn = None
    cursor = None
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Build WHERE clause
        where_clauses = []
        params = []

        # Time range filter
        time_filters = {
            '24h': 'INTERVAL 24 HOUR',
            '7d': 'INTERVAL 7 DAY',
            '30d': 'INTERVAL 30 DAY'
        }
        time_interval = time_filters.get(time_range, 'INTERVAL 7 DAY')
        where_clauses.append(f"fe.timestamp >= DATE_SUB(NOW(), {time_interval})")

        if ip:
            where_clauses.append("fe.ip_address LIKE %s")
            params.append(f"%{ip}%")

        if jail:
            where_clauses.append("fe.jail_name = %s")
            params.append(jail)

        if event_type:
            where_clauses.append("fe.event_type = %s")
            params.append(event_type)

        if agent_id:
            where_clauses.append("fe.agent_id = %s")
            params.append(agent_id)

        where_sql = " AND ".join(where_clauses) if where_clauses else "1=1"

        # Get total count
        cursor.execute(f"""
            SELECT COUNT(*) as total FROM fail2ban_events fe WHERE {where_sql}
        """, params)
        total = cursor.fetchone()['total']

        # Get events with agent info
        offset = (page - 1) * page_size
        # v3.1: event_type instead of action, timestamp instead of reported_at
        cursor.execute(f"""
            SELECT
                fe.id, fe.ip_address, fe.jail_name, fe.event_type,
                fe.bantime_seconds, fe.failures, fe.timestamp,
                fe.agent_id, a.hostname as agent_hostname
            FROM fail2ban_events fe
            LEFT JOIN agents a ON fe.agent_id = a.id
            WHERE {where_sql}
            ORDER BY fe.timestamp DESC
            LIMIT %s OFFSET %s
        """, params + [page_size, offset])

        events = cursor.fetchall()

        # Format timestamps and add backwards compatibility
        for event in events:
            if event.get('timestamp'):
                event['timestamp'] = event['timestamp'].isoformat()
                event['reported_at'] = event['timestamp']  # Backwards compatibility
            # Backwards compatibility for action field
            event['action'] = event.get('event_type')

        return jsonify({
            'success': True,
            'events': events,
            'total': total,
            'page': page,
            'page_size': page_size,
            'pages': (total + page_size - 1) // page_size
        })

    except Exception as e:
        print(f"Error fetching fail2ban history: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@agent_routes.route('/agents/fail2ban/events', methods=['GET'])
def get_fail2ban_events():
    """
    Get fail2ban events for a specific IP address.

    v3.1: event_type instead of action, timestamp instead of reported_at
    """
    ip = request.args.get('ip')
    limit = request.args.get('limit', 10, type=int)

    if not ip:
        return jsonify({'success': False, 'error': 'IP address required'}), 400

    conn = None
    cursor = None
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # v3.1: event_type instead of action, timestamp instead of reported_at
        cursor.execute("""
            SELECT id, ip_address, jail_name, event_type, bantime_seconds,
                   failures, timestamp
            FROM fail2ban_events
            WHERE ip_address = %s
            ORDER BY timestamp DESC
            LIMIT %s
        """, (ip, limit))

        events = cursor.fetchall()

        # Convert datetime objects to ISO format and add backwards compatibility
        for event in events:
            if event.get('timestamp'):
                event['timestamp'] = event['timestamp'].isoformat()
                event['reported_at'] = event['timestamp']  # Backwards compatibility
            event['action'] = event.get('event_type')  # Backwards compatibility

        return jsonify({
            'success': True,
            'events': events
        })

    except Exception as e:
        print(f"Error fetching fail2ban events: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@agent_routes.route('/agents/<int:agent_id>/fail2ban/command', methods=['POST'])
def execute_fail2ban_command(agent_id):
    """
    Execute a fail2ban command immediately via subprocess.
    Logs the action to fail2ban_events for history tracking.

    Expected JSON:
    {
        "command_type": "unban",
        "ip_address": "1.2.3.4",
        "jail_name": "sshd"
    }
    """
    import subprocess

    try:
        data = request.json
        if not data:
            return jsonify({'success': False, 'error': 'No JSON data provided'}), 400

        command_type = data.get('command_type')
        ip_address = data.get('ip_address')
        jail_name = data.get('jail_name', 'sshd')
        bantime = data.get('bantime_seconds', 600)

        if command_type not in ['ban', 'unban']:
            return jsonify({'success': False, 'error': 'Invalid command_type'}), 400

        if not ip_address:
            return jsonify({'success': False, 'error': 'IP address required'}), 400

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            # Verify agent exists
            cursor.execute("SELECT id, hostname, ip_address FROM agents WHERE id = %s", (agent_id,))
            agent = cursor.fetchone()
            if not agent:
                return jsonify({'success': False, 'error': 'Agent not found'}), 404

            # Execute command directly via subprocess
            executed = False
            result_message = ''

            try:
                if command_type == 'unban':
                    cmd = ['sudo', 'fail2ban-client', 'set', jail_name, 'unbanip', ip_address]
                else:
                    cmd = ['sudo', 'fail2ban-client', 'set', jail_name, 'banip', ip_address]

                print(f"[Fail2ban] Executing: {' '.join(cmd)}")
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)

                if result.returncode == 0:
                    executed = True
                    result_message = f'Successfully {command_type}ned {ip_address}'

                    # Update fail2ban_state
                    if command_type == 'unban':
                        cursor.execute("DELETE FROM fail2ban_state WHERE agent_id = %s AND ip_address = %s",
                                      (agent_id, ip_address))
                        # Mark ip_blocks as inactive
                        cursor.execute("""
                            UPDATE ip_blocks SET is_active = FALSE, unblock_reason = 'Manual unban from dashboard'
                            WHERE ip_address_text = %s AND block_source = 'fail2ban' AND is_active = TRUE
                        """, (ip_address,))

                    # Log event to fail2ban_events for history
                    cursor.execute("""
                        INSERT INTO fail2ban_events
                        (agent_id, event_type, ip_address, jail_name, failures, bantime_seconds, timestamp)
                        VALUES (%s, %s, %s, %s, 0, %s, NOW())
                    """, (agent_id, command_type, ip_address, jail_name, bantime if command_type == 'ban' else 0))

                    conn.commit()
                    print(f"[Fail2ban] Executed {command_type} for {ip_address}: {result_message}")
                else:
                    result_message = result.stderr.strip() if result.stderr else 'Command failed'
                    # Check if IP already not banned (common case)
                    if 'not banned' in result_message.lower() or 'not in' in result_message.lower():
                        executed = True
                        result_message = f'{ip_address} is not currently banned'
                        # Still clean up state just in case
                        cursor.execute("DELETE FROM fail2ban_state WHERE agent_id = %s AND ip_address = %s",
                                      (agent_id, ip_address))
                        conn.commit()
                    print(f"[Fail2ban] Command result: {result_message}")

            except subprocess.TimeoutExpired:
                result_message = 'Command timed out after 10 seconds'
            except FileNotFoundError:
                result_message = 'fail2ban-client not found on this server'
            except PermissionError:
                result_message = 'Permission denied - check sudo permissions'
            except Exception as e:
                result_message = str(e)

            return jsonify({
                'success': executed,
                'executed': executed,
                'message': result_message,
                'ip_address': ip_address,
                'command_type': command_type
            })

        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        print(f"Error executing fail2ban command: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500


@agent_routes.route('/agents/fail2ban/commands/poll', methods=['GET'])
def poll_fail2ban_commands():
    """
    Agent polls for pending fail2ban commands.
    Returns pending commands and marks them as 'sent'.
    """
    try:
        agent = verify_api_key_simple()
        if not agent:
            return jsonify({'success': False, 'error': 'Invalid API key'}), 401

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            # Get pending commands for this agent
            cursor.execute("""
                SELECT id, command_uuid, command_type, ip_address, jail_name, bantime_seconds
                FROM fail2ban_commands
                WHERE agent_id = %s AND status = 'pending'
                ORDER BY created_at ASC
                LIMIT 10
            """, (agent['id'],))

            commands = cursor.fetchall()

            # Mark as sent
            if commands:
                ids = [c['id'] for c in commands]
                cursor.execute(f"""
                    UPDATE fail2ban_commands
                    SET status = 'sent', sent_at = NOW()
                    WHERE id IN ({','.join(['%s'] * len(ids))})
                """, ids)
                conn.commit()

            return jsonify({
                'success': True,
                'commands': commands,
                'count': len(commands)
            })

        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        print(f"Error polling fail2ban commands: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@agent_routes.route('/agents/fail2ban/commands/complete', methods=['POST'])
def complete_fail2ban_command():
    """
    Agent reports command completion.
    Also logs the event to fail2ban_events for history.
    """
    try:
        agent = verify_api_key_simple()
        if not agent:
            return jsonify({'success': False, 'error': 'Invalid API key'}), 401

        data = request.json
        if not data:
            return jsonify({'success': False, 'error': 'No JSON data'}), 400

        command_uuid = data.get('command_uuid')
        success = data.get('success', True)
        result_message = data.get('result_message', '')

        if not command_uuid:
            return jsonify({'success': False, 'error': 'command_uuid required'}), 400

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            # Get command details
            cursor.execute("""
                SELECT id, command_type, ip_address, jail_name
                FROM fail2ban_commands
                WHERE command_uuid = %s AND agent_id = %s
            """, (command_uuid, agent['id']))

            command = cursor.fetchone()
            if not command:
                return jsonify({'success': False, 'error': 'Command not found'}), 404

            # Update command status
            new_status = 'completed' if success else 'failed'
            cursor.execute("""
                UPDATE fail2ban_commands
                SET status = %s, result_message = %s, completed_at = NOW()
                WHERE id = %s
            """, (new_status, result_message, command['id']))

            # Log event to history if successful
            if success:
                cursor.execute("""
                    INSERT INTO fail2ban_events
                    (agent_id, event_type, ip_address, jail_name, failures, bantime_seconds, timestamp)
                    VALUES (%s, %s, %s, %s, 0, 0, NOW())
                """, (agent['id'], command['command_type'], command['ip_address'], command['jail_name']))

                # If unban, also remove from fail2ban_state
                if command['command_type'] == 'unban':
                    cursor.execute("""
                        DELETE FROM fail2ban_state
                        WHERE agent_id = %s AND ip_address = %s
                    """, (agent['id'], command['ip_address']))

                    # Also mark ip_blocks as inactive if it was a fail2ban block
                    cursor.execute("""
                        UPDATE ip_blocks
                        SET is_active = FALSE, unblock_reason = 'Manual unban from dashboard'
                        WHERE ip_address_text = %s AND block_source = 'fail2ban' AND is_active = TRUE
                    """, (command['ip_address'],))

            conn.commit()

            print(f"[Fail2ban] Command {command_uuid} completed: {new_status}")

            return jsonify({
                'success': True,
                'message': f'Command marked as {new_status}'
            })

        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        print(f"Error completing fail2ban command: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@agent_routes.route('/agents/fail2ban/stats', methods=['GET'])
def get_fail2ban_stats():
    """
    Get fail2ban statistics summary.
    """
    conn = None
    cursor = None
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Total active bans
        cursor.execute("SELECT COUNT(*) as total FROM fail2ban_state")
        total_bans = cursor.fetchone()['total']

        # Bans by jail
        cursor.execute("""
            SELECT jail_name, COUNT(*) as count
            FROM fail2ban_state
            GROUP BY jail_name
            ORDER BY count DESC
        """)
        by_jail = cursor.fetchall()

        # Recent events (24h)
        cursor.execute("""
            SELECT event_type, COUNT(*) as count
            FROM fail2ban_events
            WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
            GROUP BY event_type
        """)
        recent_events = {row['event_type']: row['count'] for row in cursor.fetchall()}

        # Top banned IPs
        cursor.execute("""
            SELECT ip_address, COUNT(*) as ban_count
            FROM fail2ban_events
            WHERE event_type = 'ban'
              AND timestamp >= DATE_SUB(NOW(), INTERVAL 7 DAY)
            GROUP BY ip_address
            ORDER BY ban_count DESC
            LIMIT 10
        """)
        top_ips = cursor.fetchall()

        return jsonify({
            'success': True,
            'stats': {
                'total_active_bans': total_bans,
                'by_jail': by_jail,
                'recent_24h': recent_events,
                'top_banned_ips': top_ips
            }
        })

    except Exception as e:
        print(f"Error fetching fail2ban stats: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@agent_routes.route('/agents/fail2ban/grouped', methods=['GET'])
def get_fail2ban_grouped():
    """
    Get fail2ban events grouped by IP address (like SSH events/grouped).
    Returns aggregated data with geo enrichment for the Live Events page.
    """
    try:
        limit = min(int(request.args.get('limit', 50)), 100)
        offset = int(request.args.get('offset', 0))
        action = request.args.get('action', '').strip()
        agent_id = request.args.get('agent_id')
        time_range = request.args.get('time_range', '7d')
        ip_filter = request.args.get('ip', '').strip()

        time_filters = {
            '24h': 'INTERVAL 24 HOUR',
            '7d': 'INTERVAL 7 DAY',
            '30d': 'INTERVAL 30 DAY'
        }
        time_interval = time_filters.get(time_range, 'INTERVAL 7 DAY')

        where_clauses = [f"fe.timestamp >= DATE_SUB(NOW(), {time_interval})"]
        params = []

        if action:
            where_clauses.append("fe.event_type = %s")
            params.append(action)

        if agent_id:
            where_clauses.append("fe.agent_id = %s")
            params.append(agent_id)

        if ip_filter:
            where_clauses.append("fe.ip_address LIKE %s")
            params.append(f"%{ip_filter}%")

        where_sql = " AND ".join(where_clauses)

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            # Get grouped fail2ban events by IP
            cursor.execute(f"""
                SELECT
                    fe.ip_address,
                    COUNT(*) as event_count,
                    SUM(CASE WHEN fe.event_type = 'ban' THEN 1 ELSE 0 END) as ban_count,
                    SUM(CASE WHEN fe.event_type = 'unban' THEN 1 ELSE 0 END) as unban_count,
                    MAX(fe.failures) as max_failures,
                    SUM(fe.failures) as total_failures,
                    MAX(fe.bantime_seconds) as max_bantime,
                    MAX(fe.timestamp) as latest_timestamp,
                    MIN(fe.timestamp) as first_timestamp,
                    GROUP_CONCAT(DISTINCT fe.jail_name) as jails,
                    MAX(fe.agent_id) as agent_id
                FROM fail2ban_events fe
                WHERE {where_sql}
                GROUP BY fe.ip_address
                ORDER BY latest_timestamp DESC
                LIMIT %s OFFSET %s
            """, params + [limit, offset])

            groups = cursor.fetchall()

            # Get total count
            cursor.execute(f"""
                SELECT COUNT(DISTINCT ip_address) as total
                FROM fail2ban_events fe
                WHERE {where_sql}
            """, params)
            total_row = cursor.fetchone()
            total_groups = total_row['total'] if total_row else 0

            # Enrich with geo/threat data
            enriched_groups = []
            if groups:
                unique_ips = list(set(g['ip_address'] for g in groups if g['ip_address']))

                # Get geo + threat from ip_geolocation
                geo_map = {}
                if unique_ips:
                    placeholders = ','.join(['%s'] * len(unique_ips))
                    cursor.execute(f"""
                        SELECT ip_address_text, country_code, country_name, city, isp,
                               is_proxy, is_vpn, is_tor, threat_level, abuseipdb_score, abuseipdb_reports,
                               greynoise_noise, greynoise_riot, greynoise_classification
                        FROM ip_geolocation
                        WHERE ip_address_text IN ({placeholders})
                    """, unique_ips)
                    for row in cursor.fetchall():
                        geo_map[row['ip_address_text']] = row

                # Get agent info
                agent_ids = list(set(g['agent_id'] for g in groups if g['agent_id']))
                agent_map = {}
                if agent_ids:
                    placeholders = ','.join(['%s'] * len(agent_ids))
                    cursor.execute(f"""
                        SELECT id, agent_id, hostname FROM agents WHERE id IN ({placeholders})
                    """, agent_ids)
                    for row in cursor.fetchall():
                        agent_map[row['id']] = row

                for group in groups:
                    ip = group['ip_address']
                    geo = geo_map.get(ip, {})
                    agent = agent_map.get(group['agent_id'], {})

                    # Calculate risk score based on fail2ban data
                    # Convert to float to avoid Decimal type issues from MySQL
                    ban_count = int(group['ban_count'] or 0)
                    total_failures = int(group['total_failures'] or 0)
                    abuse_score = float(geo.get('abuseipdb_score') or 0)
                    greynoise_noise = geo.get('greynoise_noise', False)
                    greynoise_riot = geo.get('greynoise_riot', False)
                    risk_score = min(100, (
                        ban_count * 15 +
                        total_failures * 2 +
                        abuse_score * 0.5 +
                        (20 if geo.get('is_tor') else 0) +
                        (10 if geo.get('is_vpn') else 0) +
                        (15 if greynoise_noise else 0) +  # GreyNoise scanner adds risk
                        (-15 if greynoise_riot else 0)    # GreyNoise benign reduces risk
                    ))

                    enriched_groups.append({
                        'ip_address': ip,
                        'event_count': group['event_count'],
                        'ban_count': group['ban_count'] or 0,
                        'unban_count': group['unban_count'] or 0,
                        'total_failures': group['total_failures'] or 0,
                        'max_bantime': group['max_bantime'],
                        'jails': group['jails'],
                        'latest_timestamp': group['latest_timestamp'].isoformat() if group['latest_timestamp'] else None,
                        'first_timestamp': group['first_timestamp'].isoformat() if group['first_timestamp'] else None,
                        'max_risk_score': risk_score,
                        'location': {
                            'country_code': geo.get('country_code'),
                            'country_name': geo.get('country_name'),
                            'city': geo.get('city'),
                            'isp': geo.get('isp'),
                            'is_tor': geo.get('is_tor'),
                            'is_vpn': geo.get('is_vpn'),
                            'is_proxy': geo.get('is_proxy')
                        },
                        'threat': {
                            'level': geo.get('threat_level'),
                            'abuseipdb_score': geo.get('abuseipdb_score'),
                            'abuseipdb_reports': geo.get('abuseipdb_reports'),
                            'greynoise_noise': geo.get('greynoise_noise'),
                            'greynoise_riot': geo.get('greynoise_riot'),
                            'greynoise_classification': geo.get('greynoise_classification')
                        },
                        'agent': {
                            'id': group['agent_id'],
                            'hostname': agent.get('hostname')
                        }
                    })

            return jsonify({
                'success': True,
                'groups': enriched_groups,
                'pagination': {
                    'total': total_groups,
                    'limit': limit,
                    'offset': offset,
                    'has_more': offset + limit < total_groups
                }
            })

        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        print(f"Error fetching grouped fail2ban: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500


@agent_routes.route('/agents/fail2ban/by-ip', methods=['GET'])
def get_fail2ban_by_ip():
    """
    Get fail2ban events for a specific IP address (for modal history).
    """
    ip = request.args.get('ip')
    if not ip:
        return jsonify({'success': False, 'error': 'IP required'}), 400

    page = int(request.args.get('page', 1))
    page_size = min(int(request.args.get('page_size', 100)), 200)
    time_range = request.args.get('time_range', '30d')

    time_filters = {
        '24h': 'INTERVAL 24 HOUR',
        '7d': 'INTERVAL 7 DAY',
        '30d': 'INTERVAL 30 DAY'
    }
    time_interval = time_filters.get(time_range, 'INTERVAL 30 DAY')

    conn = None
    cursor = None
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Get events for this IP
        cursor.execute(f"""
            SELECT fe.*, a.hostname as agent_hostname
            FROM fail2ban_events fe
            LEFT JOIN agents a ON fe.agent_id = a.id
            WHERE fe.ip_address = %s
              AND fe.timestamp >= DATE_SUB(NOW(), {time_interval})
            ORDER BY fe.timestamp DESC
            LIMIT %s OFFSET %s
        """, (ip, page_size, (page - 1) * page_size))

        events = cursor.fetchall()

        # Get total count
        cursor.execute(f"""
            SELECT COUNT(*) as total
            FROM fail2ban_events
            WHERE ip_address = %s
              AND timestamp >= DATE_SUB(NOW(), {time_interval})
        """, (ip,))
        total = cursor.fetchone()['total']

        # Format timestamps
        for event in events:
            if event.get('timestamp'):
                event['timestamp'] = event['timestamp'].isoformat()

        return jsonify({
            'success': True,
            'events': events,
            'pagination': {
                'page': page,
                'page_size': page_size,
                'total': total,
                'total_pages': (total + page_size - 1) // page_size,
                'has_prev': page > 1,
                'has_next': page * page_size < total
            }
        })

    except Exception as e:
        print(f"Error fetching fail2ban by IP: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()
