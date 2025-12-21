"""
SSH Guardian v3.0 - Full Pipeline Simulation Routes
API endpoints for end-to-end attack simulation with agent targeting
"""

import uuid
import json
import time
from datetime import datetime, timedelta
from flask import Blueprint, jsonify, request
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
sys.path.append(str(PROJECT_ROOT))
sys.path.append(str(PROJECT_ROOT / "dbs"))
sys.path.append(str(PROJECT_ROOT / "src"))

from dbs.connection import get_connection
from src.core.auth import login_required

pipeline_simulation_routes = Blueprint('pipeline_simulation_routes', __name__)


def get_active_agents():
    """Get list of active agents"""
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT id, hostname, display_name, is_active, last_heartbeat
            FROM agents
            WHERE is_active = TRUE
            ORDER BY display_name, hostname
        """)
        agents = cursor.fetchall()
        cursor.close()
        conn.close()

        # Format for display
        for agent in agents:
            if agent.get('last_heartbeat'):
                agent['last_heartbeat'] = agent['last_heartbeat'].isoformat()

        return agents
    except Exception as e:
        print(f"[PipelineSim] Error getting agents: {e}")
        return []


def create_attack_events(agent_id: int, attack_type: str, source_ip: str,
                         target_username: str = "root", count: int = 15):
    """Create attack events directly in auth_events table for a specific agent"""
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Get agent hostname
        cursor.execute("SELECT hostname FROM agents WHERE id = %s", (agent_id,))
        agent = cursor.fetchone()
        if not agent:
            return {'success': False, 'error': 'Agent not found'}

        hostname = agent['hostname']
        event_ids = []

        # Generate events
        base_time = datetime.now()

        for i in range(count):
            event_uuid = str(uuid.uuid4())
            timestamp = base_time + timedelta(seconds=i * 4)  # 4 seconds apart

            # Determine failure reason based on attack type
            if attack_type == 'brute_force':
                failure_reason = 'invalid_password'
                username = target_username
            elif attack_type == 'credential_stuffing':
                failure_reason = 'invalid_password'
                usernames = ['admin', 'root', 'user', 'test', 'deploy', 'ubuntu']
                username = usernames[i % len(usernames)]
            elif attack_type == 'reconnaissance':
                failure_reason = 'invalid_user'
                usernames = ['hacker', 'test123', 'admin123', 'ftp', 'oracle', 'mysql']
                username = usernames[i % len(usernames)]
            else:
                failure_reason = 'invalid_password'
                username = target_username

            cursor.execute("""
                INSERT INTO auth_events
                (event_uuid, timestamp, source_type, event_type, auth_method,
                 source_ip_text, target_server, target_username, failure_reason,
                 agent_id, processing_status, is_simulation, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
            """, (
                event_uuid, timestamp, 'sshd', 'failed', 'password',
                source_ip, hostname, username, failure_reason,
                agent_id, 'pending', True
            ))

            event_ids.append(cursor.lastrowid)

        conn.commit()
        cursor.close()
        conn.close()

        return {
            'success': True,
            'event_ids': event_ids,
            'count': len(event_ids),
            'source_ip': source_ip,
            'agent_hostname': hostname
        }

    except Exception as e:
        print(f"[PipelineSim] Error creating events: {e}")
        return {'success': False, 'error': str(e)}


def run_enrichment(event_ids: list):
    """Run enrichment pipeline on events"""
    try:
        from core.enrichment import enrich_event

        results = []
        for event_id in event_ids:
            # Get event IP
            conn = get_connection()
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT source_ip_text FROM auth_events WHERE id = %s", (event_id,))
            event = cursor.fetchone()
            cursor.close()
            conn.close()

            if event:
                result = enrich_event(event_id, event['source_ip_text'], verbose=False)
                results.append({
                    'event_id': event_id,
                    'success': result.get('success', False),
                    'ml': result.get('ml', {}),
                    'blocking': result.get('blocking', {})
                })

        return {'success': True, 'results': results}

    except Exception as e:
        print(f"[PipelineSim] Error running enrichment: {e}")
        return {'success': False, 'error': str(e)}


def verify_ml_detection(event_ids: list):
    """Verify ML detection results"""
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        placeholders = ','.join(['%s'] * len(event_ids))
        cursor.execute(f"""
            SELECT id, ml_risk_score, ml_threat_type, ml_confidence, is_anomaly, processing_status
            FROM auth_events
            WHERE id IN ({placeholders})
        """, tuple(event_ids))

        events = cursor.fetchall()
        cursor.close()
        conn.close()

        # Calculate summary
        ml_analyzed = sum(1 for e in events if e.get('ml_risk_score') is not None)
        high_risk = sum(1 for e in events if (e.get('ml_risk_score') or 0) >= 60)
        anomalies = sum(1 for e in events if e.get('is_anomaly'))

        avg_risk = 0
        if ml_analyzed > 0:
            avg_risk = sum(float(e.get('ml_risk_score') or 0) for e in events) / ml_analyzed

        # Get most common threat type
        threat_types = [e.get('ml_threat_type') for e in events if e.get('ml_threat_type')]
        most_common_type = max(set(threat_types), key=threat_types.count) if threat_types else None

        return {
            'success': True,
            'total_events': len(events),
            'ml_analyzed': ml_analyzed,
            'high_risk_count': high_risk,
            'anomaly_count': anomalies,
            'avg_risk_score': round(avg_risk, 1),
            'threat_type': most_common_type,
            'events': events
        }

    except Exception as e:
        print(f"[PipelineSim] Error verifying ML: {e}")
        return {'success': False, 'error': str(e)}


def verify_ip_blocked(ip_address: str):
    """Verify if IP was blocked"""
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT id, ip_address_text, block_reason, blocked_at, is_active,
                   risk_score, threat_type, unblock_at
            FROM ip_blocks
            WHERE ip_address_text = %s AND is_active = TRUE
            ORDER BY blocked_at DESC
            LIMIT 1
        """, (ip_address,))

        block = cursor.fetchone()
        cursor.close()
        conn.close()

        if block:
            if block.get('blocked_at'):
                block['blocked_at'] = block['blocked_at'].isoformat()
            if block.get('unblock_at'):
                block['unblock_at'] = block['unblock_at'].isoformat()

            return {
                'success': True,
                'is_blocked': True,
                'block_id': block['id'],
                'reason': block.get('block_reason'),
                'risk_score': block.get('risk_score'),
                'threat_type': block.get('threat_type'),
                'blocked_at': block.get('blocked_at'),
                'unblock_at': block.get('unblock_at')
            }
        else:
            return {
                'success': True,
                'is_blocked': False,
                'message': 'IP not blocked (may not have met threshold)'
            }

    except Exception as e:
        print(f"[PipelineSim] Error verifying block: {e}")
        return {'success': False, 'error': str(e)}


def verify_ufw_command(ip_address: str, agent_id: int):
    """Verify UFW command was created"""
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT id, agent_id, command_uuid, command_type, params_json,
                   status, created_at, sent_at, executed_at, result_message
            FROM agent_ufw_commands
            WHERE JSON_EXTRACT(params_json, '$.ip') = %s
              AND agent_id = %s
              AND command_type = 'deny_from'
            ORDER BY created_at DESC
            LIMIT 1
        """, (ip_address, agent_id))

        command = cursor.fetchone()
        cursor.close()
        conn.close()

        if command:
            if command.get('created_at'):
                command['created_at'] = command['created_at'].isoformat()
            if command.get('sent_at'):
                command['sent_at'] = command['sent_at'].isoformat()
            if command.get('executed_at'):
                command['executed_at'] = command['executed_at'].isoformat()
            if command.get('params_json'):
                try:
                    command['params'] = json.loads(command['params_json'])
                except:
                    pass

            return {
                'success': True,
                'command_exists': True,
                'command_id': command['id'],
                'command_uuid': command['command_uuid'],
                'status': command['status'],
                'created_at': command.get('created_at'),
                'executed_at': command.get('executed_at'),
                'result': command.get('result_message')
            }
        else:
            return {
                'success': True,
                'command_exists': False,
                'message': 'No UFW command created (IP may not have been blocked)'
            }

    except Exception as e:
        print(f"[PipelineSim] Error verifying UFW: {e}")
        return {'success': False, 'error': str(e)}


def verify_notification(event_ids: list):
    """Verify notifications were sent"""
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        placeholders = ','.join(['%s'] * len(event_ids))
        cursor.execute(f"""
            SELECT id, trigger_type, trigger_event_id, channels, status,
                   sent_at, response_data
            FROM notifications
            WHERE trigger_event_id IN ({placeholders})
            ORDER BY sent_at DESC
        """, tuple(event_ids))

        notifications = cursor.fetchall()
        cursor.close()
        conn.close()

        for notif in notifications:
            if notif.get('sent_at'):
                notif['sent_at'] = notif['sent_at'].isoformat()
            if notif.get('channels'):
                try:
                    notif['channels'] = json.loads(notif['channels'])
                except:
                    pass
            if notif.get('response_data'):
                try:
                    notif['response_data'] = json.loads(notif['response_data'])
                except:
                    pass

        return {
            'success': True,
            'notification_count': len(notifications),
            'notifications': notifications
        }

    except Exception as e:
        print(f"[PipelineSim] Error verifying notifications: {e}")
        return {'success': False, 'error': str(e)}


@pipeline_simulation_routes.route('/agents', methods=['GET'])
@login_required
def list_agents():
    """Get list of active agents for simulation targeting"""
    agents = get_active_agents()
    return jsonify({
        'success': True,
        'agents': agents,
        'count': len(agents)
    })


@pipeline_simulation_routes.route('/attack-types', methods=['GET'])
@login_required
def list_attack_types():
    """Get available attack types for simulation"""
    attack_types = [
        {
            'id': 'brute_force',
            'name': 'Brute Force Attack',
            'description': '15 rapid failed login attempts targeting root user',
            'severity': 'critical',
            'expected_risk': '85+',
            'expected_block': True
        },
        {
            'id': 'credential_stuffing',
            'name': 'Credential Stuffing',
            'description': 'Multiple usernames with 3 attempts each',
            'severity': 'high',
            'expected_risk': '80+',
            'expected_block': True
        },
        {
            'id': 'reconnaissance',
            'name': 'Reconnaissance Scan',
            'description': 'Probing with invalid usernames',
            'severity': 'high',
            'expected_risk': '70+',
            'expected_block': True
        }
    ]
    return jsonify({
        'success': True,
        'attack_types': attack_types
    })


@pipeline_simulation_routes.route('/run', methods=['POST'])
@login_required
def run_full_pipeline():
    """
    Run full pipeline simulation for a specific agent.

    Flow:
    1. Create attack events for agent
    2. Run enrichment pipeline (GeoIP, ML, Threat Intel)
    3. Verify ML detection results
    4. Verify IP blocking
    5. Verify UFW command creation
    6. Verify notification sent

    Returns step-by-step results for UI visualization.
    """
    try:
        data = request.get_json()

        agent_id = data.get('agent_id')
        attack_type = data.get('attack_type', 'brute_force')
        source_ip = data.get('source_ip', '185.220.101.42')  # Default Tor exit node
        event_count = data.get('event_count', 15)

        if not agent_id:
            return jsonify({'success': False, 'error': 'agent_id is required'}), 400

        results = {
            'simulation_id': str(uuid.uuid4()),
            'agent_id': agent_id,
            'attack_type': attack_type,
            'source_ip': source_ip,
            'started_at': datetime.now().isoformat(),
            'steps': {}
        }

        # Step 1: Create attack events
        print(f"[PipelineSim] Step 1: Creating {event_count} attack events...")
        event_result = create_attack_events(
            agent_id=agent_id,
            attack_type=attack_type,
            source_ip=source_ip,
            count=event_count
        )
        results['steps']['create_events'] = {
            'status': 'success' if event_result['success'] else 'failed',
            'message': f"Created {event_result.get('count', 0)} events" if event_result['success'] else event_result.get('error'),
            'event_ids': event_result.get('event_ids', []),
            'agent_hostname': event_result.get('agent_hostname')
        }

        if not event_result['success']:
            results['completed_at'] = datetime.now().isoformat()
            return jsonify(results)

        event_ids = event_result['event_ids']

        # Step 2: Run enrichment pipeline
        print(f"[PipelineSim] Step 2: Running enrichment pipeline...")
        enrich_result = run_enrichment(event_ids)
        results['steps']['enrichment'] = {
            'status': 'success' if enrich_result['success'] else 'failed',
            'message': 'Enrichment pipeline completed' if enrich_result['success'] else enrich_result.get('error'),
            'events_processed': len(enrich_result.get('results', []))
        }

        # Step 3: Verify ML detection
        print(f"[PipelineSim] Step 3: Verifying ML detection...")
        ml_result = verify_ml_detection(event_ids)
        results['steps']['ml_detection'] = {
            'status': 'success' if ml_result['success'] else 'failed',
            'ml_analyzed': ml_result.get('ml_analyzed', 0),
            'high_risk_count': ml_result.get('high_risk_count', 0),
            'anomaly_count': ml_result.get('anomaly_count', 0),
            'avg_risk_score': ml_result.get('avg_risk_score', 0),
            'threat_type': ml_result.get('threat_type'),
            'message': f"ML analyzed {ml_result.get('ml_analyzed', 0)} events, avg risk: {ml_result.get('avg_risk_score', 0)}"
        }

        # Step 4: Verify IP blocking
        print(f"[PipelineSim] Step 4: Verifying IP blocking...")
        block_result = verify_ip_blocked(source_ip)
        results['steps']['ip_blocking'] = {
            'status': 'success' if block_result.get('is_blocked') else 'skipped',
            'is_blocked': block_result.get('is_blocked', False),
            'block_id': block_result.get('block_id'),
            'reason': block_result.get('reason'),
            'risk_score': block_result.get('risk_score'),
            'message': f"IP blocked (block_id: {block_result.get('block_id')})" if block_result.get('is_blocked') else block_result.get('message', 'Not blocked')
        }

        # Step 5: Verify UFW command
        print(f"[PipelineSim] Step 5: Verifying UFW command...")
        ufw_result = verify_ufw_command(source_ip, agent_id)
        results['steps']['ufw_command'] = {
            'status': 'success' if ufw_result.get('command_exists') else 'skipped',
            'command_exists': ufw_result.get('command_exists', False),
            'command_id': ufw_result.get('command_id'),
            'command_status': ufw_result.get('status'),
            'message': f"UFW deny command created (status: {ufw_result.get('status')})" if ufw_result.get('command_exists') else ufw_result.get('message', 'No command')
        }

        # Step 6: Verify notification
        print(f"[PipelineSim] Step 6: Verifying notifications...")
        notif_result = verify_notification(event_ids)
        results['steps']['notification'] = {
            'status': 'success' if notif_result.get('notification_count', 0) > 0 else 'skipped',
            'count': notif_result.get('notification_count', 0),
            'notifications': notif_result.get('notifications', []),
            'message': f"Sent {notif_result.get('notification_count', 0)} notification(s)" if notif_result.get('notification_count', 0) > 0 else 'No notifications sent'
        }

        results['completed_at'] = datetime.now().isoformat()
        results['success'] = True

        # Calculate overall success
        steps_passed = sum(1 for step in results['steps'].values() if step['status'] == 'success')
        results['steps_passed'] = steps_passed
        results['steps_total'] = 6

        print(f"[PipelineSim] Simulation complete: {steps_passed}/6 steps passed")

        return jsonify(results)

    except Exception as e:
        print(f"[PipelineSim] Error running simulation: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500


@pipeline_simulation_routes.route('/status/<simulation_id>', methods=['GET'])
@login_required
def get_simulation_status(simulation_id):
    """Get status of a running simulation (for future async support)"""
    # For now, simulations are synchronous
    return jsonify({
        'success': True,
        'simulation_id': simulation_id,
        'status': 'completed',
        'message': 'Simulations run synchronously'
    })


@pipeline_simulation_routes.route('/cleanup/<ip_address>', methods=['DELETE'])
@login_required
def cleanup_simulation(ip_address):
    """Cleanup simulation data - unblock IP and remove UFW command"""
    try:
        conn = get_connection()
        cursor = conn.cursor()

        # Remove from ip_blocks
        cursor.execute("""
            UPDATE ip_blocks SET is_active = FALSE
            WHERE ip_address_text = %s AND is_simulation = TRUE
        """, (ip_address,))
        blocks_removed = cursor.rowcount

        # Create UFW delete command for all agents that have deny command
        cursor.execute("""
            SELECT DISTINCT agent_id FROM agent_ufw_commands
            WHERE JSON_EXTRACT(params_json, '$.ip') = %s
            AND command_type = 'deny_from'
        """, (ip_address,))

        agents = cursor.fetchall()
        ufw_commands_created = 0

        for agent in agents:
            ufw_cmd = f"ufw delete deny from {ip_address}"
            cursor.execute("""
                INSERT INTO agent_ufw_commands
                (agent_id, command_uuid, command_type, params_json, ufw_command, status, created_at)
                VALUES (%s, %s, 'delete_deny_from', %s, %s, 'pending', NOW())
            """, (agent[0], str(uuid.uuid4()), json.dumps({'ip': ip_address}), ufw_cmd))
            ufw_commands_created += 1

        conn.commit()
        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'ip_address': ip_address,
            'blocks_removed': blocks_removed,
            'ufw_unblock_commands': ufw_commands_created,
            'message': f'Cleaned up {blocks_removed} block(s), created {ufw_commands_created} UFW unblock command(s)'
        })

    except Exception as e:
        print(f"[PipelineSim] Error cleaning up: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500
