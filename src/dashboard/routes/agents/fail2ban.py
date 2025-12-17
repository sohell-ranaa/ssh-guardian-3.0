"""
SSH Guardian v3.0 - Fail2ban Integration Routes
Receives ban/unban reports from fail2ban actions on agent servers
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
                cursor.execute("""
                    INSERT INTO fail2ban_events (
                        agent_id, ip_address, jail_name, action,
                        failures, bantime_seconds, reported_at
                    ) VALUES (%s, %s, %s, 'ban', %s, %s, NOW())
                """, (agent['id'], ip_address, jail, failures, bantime))
                conn.commit()
            except Exception as e:
                # Table might not exist yet, that's okay
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
                        'timestamp': datetime.now().isoformat()
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
                        print(f"🚨 AUTO-ESCALATED {ip_address} to UFW (score={ml_evaluation.get('threat_score')})")
                except Exception as e:
                    print(f"ML evaluation skipped: {e}")

            print(f"🔒 fail2ban ban: {ip_address} (jail={jail}, failures={failures})")

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
        print(f"❌ fail2ban ban error: {e}")
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
                    cursor.execute("""
                        INSERT INTO fail2ban_events (
                            agent_id, ip_address, jail_name, action,
                            failures, bantime_seconds, reported_at
                        ) VALUES (%s, %s, %s, 'unban', 0, 0, NOW())
                    """, (agent['id'], ip_address, jail))
                    conn.commit()

                    print(f"🔓 fail2ban unban: {ip_address} (jail={jail})")

                    return jsonify({
                        'success': True,
                        'message': f'Unban recorded for {ip_address}',
                        'source': 'fail2ban'
                    })
                else:
                    # IP was blocked by ML/manual - don't auto-unblock
                    print(f"⚠️ fail2ban unban skipped: {ip_address} blocked by {block['block_source']}")
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
        print(f"❌ fail2ban unban error: {e}")
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
            # Find fail2ban blocks that were manually unblocked from dashboard
            # and haven't been synced to fail2ban yet
            cursor.execute("""
                SELECT id, ip_address_text, unblock_reason
                FROM ip_blocks
                WHERE block_source = 'fail2ban'
                  AND is_active = FALSE
                  AND manually_unblocked_at IS NOT NULL
                  AND fail2ban_sync_status = 'pending'
                ORDER BY manually_unblocked_at ASC
                LIMIT 10
            """)

            pending = cursor.fetchall()

            commands = []
            for block in pending:
                commands.append({
                    'id': block['id'],
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
            # Column might not exist yet
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


@agent_routes.route('/agents/fail2ban/unban-result', methods=['POST'])
def report_fail2ban_unban_result():
    """
    Report result of fail2ban unban command execution.
    Called by agent after running `fail2ban-client unbanip`.
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
        block_id = data.get('id')
        success = data.get('success', False)
        message = data.get('message', '')

        if not block_id:
            return jsonify({
                'success': False,
                'error': 'Block ID required'
            }), 400

        conn = get_connection()
        cursor = conn.cursor()

        try:
            status = 'synced' if success else 'failed'
            cursor.execute("""
                UPDATE ip_blocks
                SET fail2ban_sync_status = %s,
                    fail2ban_sync_message = %s,
                    fail2ban_synced_at = NOW()
                WHERE id = %s
            """, (status, message, block_id))
            conn.commit()

            return jsonify({
                'success': True,
                'message': f'Unban result recorded: {status}'
            })

        except Exception as e:
            print(f"Note: unban-result update: {e}")
            return jsonify({
                'success': True,
                'message': 'Result noted (column may not exist)'
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

    Expected JSON:
    {
        "agent_id": "agent-uuid",
        "hostname": "server1",
        "bans": [
            {"ip": "1.2.3.4", "jail": "sshd", "action": "ban"},
            ...
        ]
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

        bans = data.get('bans', [])
        agent_db_id = agent['id']
        hostname = data.get('hostname', agent['hostname'])

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            synced_count = 0
            new_count = 0

            for ban in bans:
                ip = ban.get('ip')
                jail = ban.get('jail', 'sshd')

                if not ip:
                    continue

                ip_binary = ip_to_binary(ip)

                # Check if this ban already exists and is active
                cursor.execute("""
                    SELECT id, is_active FROM ip_blocks
                    WHERE ip_address_text = %s
                      AND block_source = 'fail2ban'
                    ORDER BY blocked_at DESC
                    LIMIT 1
                """, (ip,))

                existing = cursor.fetchone()

                if existing and existing['is_active']:
                    # Already recorded and active, skip
                    synced_count += 1
                else:
                    # Insert new ban record
                    cursor.execute("""
                        INSERT INTO ip_blocks
                        (ip_address, ip_address_text, block_source, block_reason,
                         is_active, blocked_at)
                        VALUES (%s, %s, 'fail2ban', %s, TRUE, NOW())
                    """, (ip_binary, ip, f'fail2ban jail: {jail} (agent: {hostname})'))
                    new_count += 1

                    # Also create fail2ban_events record
                    cursor.execute("""
                        INSERT INTO fail2ban_events
                        (agent_id, ip_address, jail_name, action, failures, bantime_seconds, reported_at)
                        VALUES (%s, %s, %s, 'ban', 5, 0, NOW())
                    """, (agent_db_id, ip, jail))

            conn.commit()

            return jsonify({
                'success': True,
                'message': f'Fail2ban sync complete',
                'synced': synced_count,
                'new': new_count,
                'total_bans': len(bans)
            })

        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        print(f"❌ Fail2ban sync error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
