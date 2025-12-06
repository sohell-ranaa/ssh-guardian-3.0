"""
SSH Guardian v3.0 - Agent Firewall Routes
Handles firewall rules synchronization and command management
"""

from flask import request, jsonify
import json
import uuid
import sys
from pathlib import Path
from datetime import datetime

# Add project paths
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent.parent
sys.path.append(str(PROJECT_ROOT / "dbs"))
sys.path.append(str(PROJECT_ROOT / "src" / "core"))

from connection import get_connection
from cache import get_cache, cache_key
from auth import AuditLogger
from . import agent_routes
from .auth import require_api_key


def get_current_user_id():
    """Get current user ID from request context"""
    if hasattr(request, 'current_user') and request.current_user:
        return request.current_user.get('user_id') or request.current_user.get('id')
    return None

# Cache TTLs
FIREWALL_CACHE_TTL = 60  # 1 minute


# ============================================================================
# FIREWALL SYNC ENDPOINT
# ============================================================================

@agent_routes.route('/agents/firewall/sync', methods=['POST'])
@require_api_key
def sync_firewall_rules():
    """
    Receive firewall rules from an agent and store them.
    This is called periodically by the agent to sync its iptables state.
    """
    try:
        data = request.get_json()

        agent_id = data.get('agent_id')
        hostname = data.get('hostname')
        firewall_data = data.get('firewall_data', {})

        if not agent_id:
            return jsonify({'success': False, 'error': 'Agent ID required'}), 400

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Get the agent's database ID
        cursor.execute(
            "SELECT id FROM agents WHERE agent_id = %s OR agent_uuid = %s",
            (agent_id, agent_id)
        )
        agent_row = cursor.fetchone()

        if not agent_row:
            cursor.close()
            conn.close()
            return jsonify({'success': False, 'error': 'Agent not found'}), 404

        db_agent_id = agent_row['id']

        # Store or update firewall state
        cursor.execute("""
            INSERT INTO agent_firewall_state
                (agent_id, firewall_data, status_json, rules_count, port_forwards_count, last_sync)
            VALUES (%s, %s, %s, %s, %s, NOW())
            ON DUPLICATE KEY UPDATE
                firewall_data = VALUES(firewall_data),
                status_json = VALUES(status_json),
                rules_count = VALUES(rules_count),
                port_forwards_count = VALUES(port_forwards_count),
                last_sync = NOW()
        """, (
            db_agent_id,
            json.dumps(firewall_data.get('rules', {})),
            json.dumps(firewall_data.get('status', {})),
            firewall_data.get('status', {}).get('total_rules', 0),
            firewall_data.get('status', {}).get('port_forwards_count', 0)
        ))

        # Store individual rules for querying
        _store_firewall_rules(cursor, db_agent_id, firewall_data)

        # Store port forwards
        _store_port_forwards(cursor, db_agent_id, firewall_data.get('port_forwards', []))

        # Store network interfaces
        _store_network_interfaces(cursor, db_agent_id, firewall_data.get('interfaces', []))

        conn.commit()

        # Invalidate cache
        cache = get_cache()
        cache.delete_pattern(f'firewall:{db_agent_id}')

        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'message': 'Firewall state synced',
            'rules_count': firewall_data.get('status', {}).get('total_rules', 0)
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


def _store_firewall_rules(cursor, agent_id: int, firewall_data: dict):
    """Store parsed firewall rules for querying"""
    # Clear existing rules for this agent
    cursor.execute("DELETE FROM agent_firewall_rules WHERE agent_id = %s", (agent_id,))

    rules_data = firewall_data.get('rules', {})

    for table_name, rules in rules_data.items():
        for rule in rules:
            cursor.execute("""
                INSERT INTO agent_firewall_rules
                    (agent_id, table_name, chain, rule_num, target, protocol,
                     source_ip, destination_ip, in_interface, out_interface,
                     ports, options, raw_rule, packets_count, bytes_count)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                agent_id,
                table_name,
                rule.get('chain', ''),
                rule.get('rule_num', 0),
                rule.get('target', ''),
                rule.get('protocol', 'all'),
                rule.get('source', '0.0.0.0/0'),
                rule.get('destination', '0.0.0.0/0'),
                rule.get('in_interface', ''),
                rule.get('out_interface', ''),
                rule.get('ports', ''),
                rule.get('options', ''),
                rule.get('raw_rule', ''),
                rule.get('packets_count', 0),
                rule.get('bytes_count', 0)
            ))


def _store_port_forwards(cursor, agent_id: int, port_forwards: list):
    """Store port forwarding rules"""
    cursor.execute("DELETE FROM agent_port_forwards WHERE agent_id = %s", (agent_id,))

    for pf in port_forwards:
        cursor.execute("""
            INSERT INTO agent_port_forwards
                (agent_id, external_port, internal_ip, internal_port,
                 protocol, interface, is_enabled, description)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            agent_id,
            pf.get('external_port'),
            pf.get('internal_ip'),
            pf.get('internal_port'),
            pf.get('protocol', 'tcp'),
            pf.get('interface', ''),
            pf.get('enabled', True),
            pf.get('description', '')
        ))


def _store_network_interfaces(cursor, agent_id: int, interfaces: list):
    """Store network interface information"""
    cursor.execute("DELETE FROM agent_network_interfaces WHERE agent_id = %s", (agent_id,))

    for iface in interfaces:
        addresses = json.dumps(iface.get('addresses', []))
        cursor.execute("""
            INSERT INTO agent_network_interfaces
                (agent_id, interface_name, state, mac_address, addresses_json)
            VALUES (%s, %s, %s, %s, %s)
        """, (
            agent_id,
            iface.get('name', ''),
            iface.get('state', 'unknown'),
            iface.get('mac', ''),
            addresses
        ))


# ============================================================================
# FIREWALL COMMANDS ENDPOINT
# ============================================================================

@agent_routes.route('/agents/firewall/commands', methods=['GET'])
@require_api_key
def get_pending_commands():
    """
    Get pending firewall commands for an agent.
    The agent polls this endpoint to receive commands to execute.
    """
    try:
        agent_id = request.args.get('agent_id')

        if not agent_id:
            return jsonify({'success': False, 'error': 'Agent ID required'}), 400

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Get the agent's database ID
        cursor.execute(
            "SELECT id FROM agents WHERE agent_id = %s OR agent_uuid = %s",
            (agent_id, agent_id)
        )
        agent_row = cursor.fetchone()

        if not agent_row:
            cursor.close()
            conn.close()
            return jsonify({'success': False, 'error': 'Agent not found'}), 404

        db_agent_id = agent_row['id']

        # Get pending commands
        cursor.execute("""
            SELECT id, command_uuid, action, params_json, created_at
            FROM agent_firewall_commands
            WHERE agent_id = %s AND status = 'pending'
            ORDER BY created_at ASC
            LIMIT 10
        """, (db_agent_id,))

        commands = cursor.fetchall()

        # Mark commands as sent
        if commands:
            command_ids = [c['id'] for c in commands]
            placeholders = ','.join(['%s'] * len(command_ids))
            cursor.execute(f"""
                UPDATE agent_firewall_commands
                SET status = 'sent', sent_at = NOW()
                WHERE id IN ({placeholders})
            """, command_ids)
            conn.commit()

        cursor.close()
        conn.close()

        # Format commands for agent
        formatted_commands = []
        for cmd in commands:
            formatted_commands.append({
                'id': cmd['command_uuid'],
                'action': cmd['action'],
                'params': json.loads(cmd['params_json']) if cmd['params_json'] else {},
                'created_at': cmd['created_at'].isoformat() if cmd['created_at'] else None
            })

        return jsonify({
            'success': True,
            'commands': formatted_commands
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@agent_routes.route('/agents/firewall/command-result', methods=['POST'])
@require_api_key
def report_command_result():
    """
    Receive the result of a firewall command execution from an agent.
    """
    try:
        data = request.get_json()

        agent_id = data.get('agent_id')
        command_id = data.get('command_id')
        success = data.get('success', False)
        message = data.get('message', '')

        if not agent_id or not command_id:
            return jsonify({'success': False, 'error': 'Agent ID and command ID required'}), 400

        conn = get_connection()
        cursor = conn.cursor()

        # Update command status
        cursor.execute("""
            UPDATE agent_firewall_commands
            SET status = %s,
                result_message = %s,
                executed_at = NOW()
            WHERE command_uuid = %s
        """, (
            'completed' if success else 'failed',
            message,
            command_id
        ))

        conn.commit()
        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'message': 'Command result recorded'
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================================================
# DASHBOARD API ENDPOINTS
# ============================================================================

@agent_routes.route('/agents/<int:agent_id>/firewall', methods=['GET'])
def get_agent_firewall(agent_id):
    """Get firewall state for an agent (dashboard endpoint)"""
    try:
        cache = get_cache()
        cache_k = cache_key('firewall', str(agent_id), 'state')

        # Try cache first
        cached = cache.get(cache_k)
        if cached is not None:
            cached['from_cache'] = True
            return jsonify(cached)

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Get firewall state
        cursor.execute("""
            SELECT * FROM agent_firewall_state
            WHERE agent_id = %s
        """, (agent_id,))
        state = cursor.fetchone()

        if not state:
            cursor.close()
            conn.close()
            return jsonify({
                'success': True,
                'has_data': False,
                'message': 'No firewall data available for this agent'
            })

        # Get rules grouped by table and chain
        cursor.execute("""
            SELECT * FROM agent_firewall_rules
            WHERE agent_id = %s
            ORDER BY table_name, chain, rule_num
        """, (agent_id,))
        rules = cursor.fetchall()

        # Get port forwards
        cursor.execute("""
            SELECT * FROM agent_port_forwards
            WHERE agent_id = %s
        """, (agent_id,))
        port_forwards = cursor.fetchall()

        # Get network interfaces
        cursor.execute("""
            SELECT * FROM agent_network_interfaces
            WHERE agent_id = %s
        """, (agent_id,))
        interfaces = cursor.fetchall()

        # Get recent commands
        cursor.execute("""
            SELECT * FROM agent_firewall_commands
            WHERE agent_id = %s
            ORDER BY created_at DESC
            LIMIT 20
        """, (agent_id,))
        commands = cursor.fetchall()

        cursor.close()
        conn.close()

        # Parse JSON fields
        if state.get('status_json'):
            state['status'] = json.loads(state['status_json'])

        for iface in interfaces:
            if iface.get('addresses_json'):
                iface['addresses'] = json.loads(iface['addresses_json'])

        for cmd in commands:
            if cmd.get('params_json'):
                cmd['params'] = json.loads(cmd['params_json'])
            # Format timestamps
            for field in ['created_at', 'sent_at', 'executed_at']:
                if cmd.get(field):
                    cmd[field] = cmd[field].isoformat()

        # Format state timestamps
        if state.get('last_sync'):
            state['last_sync'] = state['last_sync'].isoformat()

        # Organize rules by table and chain
        rules_organized = {}
        for rule in rules:
            table = rule['table_name']
            chain = rule['chain']
            if table not in rules_organized:
                rules_organized[table] = {}
            if chain not in rules_organized[table]:
                rules_organized[table][chain] = []
            rules_organized[table][chain].append(rule)

        result = {
            'success': True,
            'has_data': True,
            'state': state,
            'rules': rules_organized,
            'rules_flat': rules,
            'port_forwards': port_forwards,
            'interfaces': interfaces,
            'recent_commands': commands,
            'from_cache': False
        }

        # Cache the result
        cache.set(cache_k, result, FIREWALL_CACHE_TTL)

        return jsonify(result)

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@agent_routes.route('/agents/<int:agent_id>/firewall/command', methods=['POST'])
def create_firewall_command(agent_id):
    """Create a new firewall command to be executed by the agent"""
    try:
        data = request.get_json()

        action = data.get('action')
        params = data.get('params', {})

        if not action:
            return jsonify({'success': False, 'error': 'Action required'}), 400

        # Validate action
        valid_actions = [
            'add_rule', 'delete_rule', 'delete_rule_by_spec',
            'add_port_forward', 'remove_port_forward',
            'set_policy', 'flush_chain', 'save_rules'
        ]

        if action not in valid_actions:
            return jsonify({
                'success': False,
                'error': f'Invalid action. Valid actions: {", ".join(valid_actions)}'
            }), 400

        conn = get_connection()
        cursor = conn.cursor()

        command_uuid = str(uuid.uuid4())

        cursor.execute("""
            INSERT INTO agent_firewall_commands
                (agent_id, command_uuid, action, params_json, status, created_at)
            VALUES (%s, %s, %s, %s, 'pending', NOW())
        """, (
            agent_id,
            command_uuid,
            action,
            json.dumps(params)
        ))

        conn.commit()
        cursor.close()
        conn.close()

        # Invalidate cache
        cache = get_cache()
        cache.delete_pattern(f'firewall:{agent_id}')

        # Audit log for firewall commands
        AuditLogger.log_action(
            user_id=get_current_user_id(),
            action='firewall_command_created',
            resource_type='firewall',
            resource_id=str(agent_id),
            details={'command_id': command_uuid, 'action': action, 'params': params},
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent')
        )

        return jsonify({
            'success': True,
            'message': 'Command created',
            'command_id': command_uuid
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@agent_routes.route('/agents/<int:agent_id>/firewall/request-sync', methods=['POST'])
def request_firewall_sync(agent_id):
    """
    Request the agent to sync its firewall rules.
    This creates a special 'sync_now' command that the agent will process.
    """
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Check if agent exists and is online
        cursor.execute("""
            SELECT id, agent_id, status, is_approved
            FROM agents WHERE id = %s
        """, (agent_id,))
        agent = cursor.fetchone()

        if not agent:
            cursor.close()
            conn.close()
            return jsonify({'success': False, 'error': 'Agent not found'}), 404

        if agent['status'] != 'online':
            cursor.close()
            conn.close()
            return jsonify({
                'success': False,
                'error': 'Agent is offline. It will sync when it comes back online.'
            }), 400

        if not agent['is_approved']:
            cursor.close()
            conn.close()
            return jsonify({
                'success': False,
                'error': 'Agent is not approved. Please approve the agent first.'
            }), 403

        # Create a sync_now command
        command_uuid = str(uuid.uuid4())

        cursor.execute("""
            INSERT INTO agent_firewall_commands
                (agent_id, command_uuid, action, params_json, status, created_at)
            VALUES (%s, %s, 'sync_now', '{}', 'pending', NOW())
        """, (agent_id, command_uuid))

        conn.commit()
        cursor.close()
        conn.close()

        # Invalidate cache
        cache = get_cache()
        cache.delete_pattern(f'firewall:{agent_id}')

        # Audit log
        AuditLogger.log_action(
            user_id=get_current_user_id(),
            action='firewall_sync_requested',
            resource_type='firewall',
            resource_id=str(agent_id),
            details={'command_id': command_uuid},
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent')
        )

        return jsonify({
            'success': True,
            'message': 'Sync request sent to agent',
            'command_id': command_uuid
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@agent_routes.route('/agents/<int:agent_id>/firewall/rules', methods=['GET'])
def get_firewall_rules(agent_id):
    """Get firewall rules for an agent with filtering options"""
    try:
        table = request.args.get('table')
        chain = request.args.get('chain')
        target = request.args.get('target')

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        query = "SELECT * FROM agent_firewall_rules WHERE agent_id = %s"
        params = [agent_id]

        if table:
            query += " AND table_name = %s"
            params.append(table)

        if chain:
            query += " AND chain = %s"
            params.append(chain)

        if target:
            query += " AND target = %s"
            params.append(target)

        query += " ORDER BY table_name, chain, rule_num"

        cursor.execute(query, params)
        rules = cursor.fetchall()

        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'rules': rules,
            'total': len(rules)
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@agent_routes.route('/agents/<int:agent_id>/firewall/port-forwards', methods=['GET'])
def get_port_forwards(agent_id):
    """Get port forwards for an agent"""
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT * FROM agent_port_forwards
            WHERE agent_id = %s
            ORDER BY external_port
        """, (agent_id,))
        port_forwards = cursor.fetchall()

        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'port_forwards': port_forwards,
            'total': len(port_forwards)
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@agent_routes.route('/agents/<int:agent_id>/firewall/commands', methods=['GET'])
def get_command_history(agent_id):
    """Get firewall command history for an agent"""
    try:
        limit = request.args.get('limit', 50, type=int)
        status = request.args.get('status')

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        query = """
            SELECT * FROM agent_firewall_commands
            WHERE agent_id = %s
        """
        params = [agent_id]

        if status:
            query += " AND status = %s"
            params.append(status)

        query += " ORDER BY created_at DESC LIMIT %s"
        params.append(limit)

        cursor.execute(query, params)
        commands = cursor.fetchall()

        cursor.close()
        conn.close()

        # Format timestamps and parse JSON
        for cmd in commands:
            if cmd.get('params_json'):
                cmd['params'] = json.loads(cmd['params_json'])
            for field in ['created_at', 'sent_at', 'executed_at']:
                if cmd.get(field):
                    cmd[field] = cmd[field].isoformat()

        return jsonify({
            'success': True,
            'commands': commands,
            'total': len(commands)
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================================================
# EXTENDED SYNC ENDPOINT (listening ports, users, suggestions)
# ============================================================================

@agent_routes.route('/agents/firewall/sync-extended', methods=['POST'])
@require_api_key
def sync_extended_data():
    """
    Receive extended system data from an agent including:
    - Listening ports
    - System users
    - Active connections
    - Command history
    - Protected ports
    """
    try:
        data = request.get_json()

        agent_id = data.get('agent_id')
        if not agent_id:
            return jsonify({'success': False, 'error': 'Agent ID required'}), 400

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Get the agent's database ID
        cursor.execute(
            "SELECT id FROM agents WHERE agent_id = %s OR agent_uuid = %s",
            (agent_id, agent_id)
        )
        agent_row = cursor.fetchone()

        if not agent_row:
            cursor.close()
            conn.close()
            return jsonify({'success': False, 'error': 'Agent not found'}), 404

        db_agent_id = agent_row['id']

        # Store listening ports
        listening_ports = data.get('listening_ports', [])
        _store_listening_ports(cursor, db_agent_id, listening_ports)

        # Store system users
        system_users = data.get('system_users', [])
        _store_system_users(cursor, db_agent_id, system_users)

        # Store active connections (sampling - only store last sync)
        active_connections = data.get('active_connections', [])
        _store_active_connections(cursor, db_agent_id, active_connections)

        # Store command history
        command_history = data.get('command_history', [])
        _store_command_history(cursor, db_agent_id, command_history)

        # Store protected ports
        protected_ports = data.get('protected_ports', [])
        _store_protected_ports(cursor, db_agent_id, protected_ports)

        # Generate and store rule suggestions
        suggestions = data.get('suggestions', [])
        _store_suggestions(cursor, db_agent_id, suggestions)

        # Update counts in firewall state
        cursor.execute("""
            UPDATE agent_firewall_state
            SET listening_ports_count = %s,
                users_count = %s,
                active_connections_count = %s,
                suggestions_count = %s,
                extended_data_json = %s
            WHERE agent_id = %s
        """, (
            len(listening_ports),
            len([u for u in system_users if u.get('is_login_enabled')]),
            len(active_connections),
            len(suggestions),
            json.dumps({'collected_at': data.get('collected_at')}),
            db_agent_id
        ))

        conn.commit()

        # Invalidate cache
        cache = get_cache()
        cache.delete_pattern(f'firewall:{db_agent_id}')

        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'message': 'Extended data synced',
            'counts': {
                'listening_ports': len(listening_ports),
                'users': len(system_users),
                'connections': len(active_connections),
                'suggestions': len(suggestions)
            }
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


def _store_listening_ports(cursor, agent_id: int, ports: list):
    """Store listening ports for an agent"""
    cursor.execute("DELETE FROM agent_listening_ports WHERE agent_id = %s", (agent_id,))

    for port in ports:
        cursor.execute("""
            INSERT INTO agent_listening_ports
                (agent_id, port, protocol, address, state, pid, process_name,
                 user, is_protected, last_seen)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
        """, (
            agent_id,
            port.get('port'),
            port.get('protocol', 'tcp'),
            port.get('address', '0.0.0.0'),
            port.get('state', 'LISTEN'),
            port.get('pid', 0),
            port.get('process_name', ''),
            port.get('user', ''),
            port.get('is_protected', False)
        ))


def _store_system_users(cursor, agent_id: int, users: list):
    """Store system users for an agent"""
    cursor.execute("DELETE FROM agent_system_users WHERE agent_id = %s", (agent_id,))

    for user in users:
        cursor.execute("""
            INSERT INTO agent_system_users
                (agent_id, username, uid, gid, home_dir, shell,
                 is_system_user, is_login_enabled, last_login, groups_json, last_seen)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
        """, (
            agent_id,
            user.get('username'),
            user.get('uid', 0),
            user.get('gid', 0),
            user.get('home_dir', ''),
            user.get('shell', ''),
            user.get('is_system_user', False),
            user.get('is_login_enabled', True),
            user.get('last_login'),
            json.dumps(user.get('groups', []))
        ))


def _store_active_connections(cursor, agent_id: int, connections: list):
    """Store active connections snapshot"""
    cursor.execute("DELETE FROM agent_active_connections WHERE agent_id = %s", (agent_id,))

    for conn_item in connections[:500]:  # Limit to 500 to prevent huge inserts
        cursor.execute("""
            INSERT INTO agent_active_connections
                (agent_id, protocol, state, local_address, local_port,
                 remote_address, remote_port, process_name, pid, recorded_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
        """, (
            agent_id,
            conn_item.get('protocol', 'tcp'),
            conn_item.get('state', 'ESTAB'),
            conn_item.get('local_address', ''),
            conn_item.get('local_port', 0),
            conn_item.get('remote_address', ''),
            conn_item.get('remote_port', 0),
            conn_item.get('process', ''),
            conn_item.get('pid', 0)
        ))


def _store_command_history(cursor, agent_id: int, history: list):
    """Store command history (only new entries)"""
    for entry in history[:100]:  # Limit to 100 most recent
        # Check if already exists
        cursor.execute("""
            SELECT id FROM agent_command_history
            WHERE agent_id = %s AND command = %s AND user = %s
            LIMIT 1
        """, (
            agent_id,
            entry.get('command', '')[:1000],  # Limit command length
            entry.get('user', 'unknown')
        ))

        if not cursor.fetchone():
            cursor.execute("""
                INSERT INTO agent_command_history
                    (agent_id, command, user, working_dir, exit_code, command_timestamp)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (
                agent_id,
                entry.get('command', '')[:1000],
                entry.get('user', 'unknown'),
                entry.get('working_dir', '~'),
                entry.get('exit_code'),
                entry.get('timestamp')
            ))


def _store_protected_ports(cursor, agent_id: int, protected: list):
    """Store protected ports configuration"""
    cursor.execute(
        "DELETE FROM agent_protected_ports WHERE agent_id = %s AND is_custom = FALSE",
        (agent_id,)
    )

    for port in protected:
        cursor.execute("""
            INSERT INTO agent_protected_ports
                (agent_id, port, service_name, reason, is_listening, is_custom)
            VALUES (%s, %s, %s, %s, %s, FALSE)
            ON DUPLICATE KEY UPDATE
                service_name = VALUES(service_name),
                reason = VALUES(reason),
                is_listening = VALUES(is_listening)
        """, (
            agent_id,
            port.get('port'),
            port.get('service', 'Unknown'),
            port.get('reason', 'Detected service'),
            port.get('is_listening', False)
        ))


def _store_suggestions(cursor, agent_id: int, suggestions: list):
    """Store firewall rule suggestions"""
    # Expire old pending suggestions
    cursor.execute("""
        UPDATE firewall_suggestions
        SET status = 'expired'
        WHERE agent_id = %s AND status = 'pending'
        AND created_at < DATE_SUB(NOW(), INTERVAL 7 DAY)
    """, (agent_id,))

    for suggestion in suggestions:
        # Check if similar suggestion already exists
        cursor.execute("""
            SELECT id FROM firewall_suggestions
            WHERE agent_id = %s AND suggestion_type = %s AND title = %s
            AND status = 'pending'
            LIMIT 1
        """, (
            agent_id,
            suggestion.get('type', 'unknown'),
            suggestion.get('title', '')
        ))

        if not cursor.fetchone():
            cursor.execute("""
                INSERT INTO firewall_suggestions
                    (agent_id, suggestion_type, priority, title, description,
                     rule_json, iptables_cmd, recommendation, auto_apply)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                agent_id,
                suggestion.get('type', 'unknown'),
                suggestion.get('priority', 'medium'),
                suggestion.get('title', ''),
                suggestion.get('description', ''),
                json.dumps(suggestion.get('rule')) if suggestion.get('rule') else None,
                suggestion.get('iptables_cmd'),
                suggestion.get('recommendation'),
                suggestion.get('auto_apply', False)
            ))


# ============================================================================
# EXTENDED DATA ENDPOINTS
# ============================================================================

@agent_routes.route('/agents/<int:agent_id>/listening-ports', methods=['GET'])
def get_listening_ports(agent_id):
    """Get listening ports for an agent"""
    try:
        protected_only = request.args.get('protected_only', 'false').lower() == 'true'

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        query = """
            SELECT * FROM agent_listening_ports
            WHERE agent_id = %s
        """
        params = [agent_id]

        if protected_only:
            query += " AND is_protected = TRUE"

        query += " ORDER BY port"

        cursor.execute(query, params)
        ports = cursor.fetchall()

        # Format timestamps
        for port in ports:
            if port.get('last_seen'):
                port['last_seen'] = port['last_seen'].isoformat()
            if port.get('created_at'):
                port['created_at'] = port['created_at'].isoformat()

        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'ports': ports,
            'total': len(ports),
            'protected_count': len([p for p in ports if p.get('is_protected')])
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@agent_routes.route('/agents/<int:agent_id>/system-users', methods=['GET'])
def get_system_users(agent_id):
    """Get system users for an agent"""
    try:
        login_enabled_only = request.args.get('login_enabled', 'false').lower() == 'true'

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        query = """
            SELECT * FROM agent_system_users
            WHERE agent_id = %s
        """
        params = [agent_id]

        if login_enabled_only:
            query += " AND is_login_enabled = TRUE"

        query += " ORDER BY uid"

        cursor.execute(query, params)
        users = cursor.fetchall()

        # Parse groups JSON
        for user in users:
            if user.get('groups_json'):
                user['groups'] = json.loads(user['groups_json'])
            if user.get('last_login'):
                user['last_login'] = user['last_login'].isoformat() if hasattr(user['last_login'], 'isoformat') else str(user['last_login'])
            if user.get('last_seen'):
                user['last_seen'] = user['last_seen'].isoformat()

        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'users': users,
            'total': len(users),
            'login_enabled_count': len([u for u in users if u.get('is_login_enabled')])
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@agent_routes.route('/agents/<int:agent_id>/active-connections', methods=['GET'])
def get_active_connections(agent_id):
    """Get active connections for an agent"""
    try:
        limit = request.args.get('limit', 100, type=int)

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT * FROM agent_active_connections
            WHERE agent_id = %s
            ORDER BY recorded_at DESC
            LIMIT %s
        """, (agent_id, limit))
        connections = cursor.fetchall()

        # Group by remote IP
        ip_counts = {}
        for conn_item in connections:
            remote_ip = conn_item.get('remote_address', '')
            ip_counts[remote_ip] = ip_counts.get(remote_ip, 0) + 1
            if conn_item.get('recorded_at'):
                conn_item['recorded_at'] = conn_item['recorded_at'].isoformat()

        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'connections': connections,
            'total': len(connections),
            'unique_ips': len(ip_counts),
            'ip_counts': dict(sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:20])
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@agent_routes.route('/agents/<int:agent_id>/shell-history', methods=['GET'])
def get_shell_history(agent_id):
    """Get shell command history for an agent"""
    try:
        limit = request.args.get('limit', 100, type=int)
        user = request.args.get('user')

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        query = """
            SELECT * FROM agent_command_history
            WHERE agent_id = %s
        """
        params = [agent_id]

        if user:
            query += " AND user = %s"
            params.append(user)

        query += " ORDER BY command_timestamp DESC LIMIT %s"
        params.append(limit)

        cursor.execute(query, params)
        history = cursor.fetchall()

        # Format timestamps
        for entry in history:
            if entry.get('command_timestamp'):
                entry['command_timestamp'] = entry['command_timestamp'].isoformat() if hasattr(entry['command_timestamp'], 'isoformat') else str(entry['command_timestamp'])
            if entry.get('recorded_at'):
                entry['recorded_at'] = entry['recorded_at'].isoformat()

        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'history': history,
            'total': len(history)
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@agent_routes.route('/agents/<int:agent_id>/suggestions', methods=['GET'])
def get_suggestions(agent_id):
    """Get firewall rule suggestions for an agent"""
    try:
        status = request.args.get('status', 'pending')
        priority = request.args.get('priority')

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        query = """
            SELECT * FROM firewall_suggestions
            WHERE agent_id = %s
        """
        params = [agent_id]

        if status:
            query += " AND status = %s"
            params.append(status)

        if priority:
            query += " AND priority = %s"
            params.append(priority)

        query += " ORDER BY FIELD(priority, 'high', 'medium', 'low'), created_at DESC"

        cursor.execute(query, params)
        suggestions = cursor.fetchall()

        # Parse JSON and format timestamps
        for suggestion in suggestions:
            if suggestion.get('rule_json'):
                suggestion['rule'] = json.loads(suggestion['rule_json'])
            for field in ['created_at', 'updated_at', 'applied_at', 'dismissed_at']:
                if suggestion.get(field):
                    suggestion[field] = suggestion[field].isoformat()

        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'suggestions': suggestions,
            'total': len(suggestions),
            'high_priority': len([s for s in suggestions if s.get('priority') == 'high'])
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@agent_routes.route('/agents/<int:agent_id>/suggestions/<int:suggestion_id>/apply', methods=['POST'])
def apply_suggestion(agent_id, suggestion_id):
    """Apply a firewall rule suggestion"""
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Get the suggestion
        cursor.execute("""
            SELECT * FROM firewall_suggestions
            WHERE id = %s AND agent_id = %s AND status = 'pending'
        """, (suggestion_id, agent_id))
        suggestion = cursor.fetchone()

        if not suggestion:
            cursor.close()
            conn.close()
            return jsonify({'success': False, 'error': 'Suggestion not found or not pending'}), 404

        # Create a firewall command from the suggestion
        rule = json.loads(suggestion['rule_json']) if suggestion.get('rule_json') else {}

        action = 'add_rule'
        if suggestion['suggestion_type'] == 'block_ip':
            action = 'add_rule'
        elif suggestion['suggestion_type'] == 'policy':
            action = 'set_policy'

        command_uuid = str(uuid.uuid4())

        cursor.execute("""
            INSERT INTO agent_firewall_commands
                (agent_id, command_uuid, action, params_json, status, created_at)
            VALUES (%s, %s, %s, %s, 'pending', NOW())
        """, (
            agent_id,
            command_uuid,
            action,
            json.dumps(rule)
        ))

        # Mark suggestion as applied
        cursor.execute("""
            UPDATE firewall_suggestions
            SET status = 'applied', applied_at = NOW()
            WHERE id = %s
        """, (suggestion_id,))

        conn.commit()
        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'message': 'Suggestion applied',
            'command_id': command_uuid
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@agent_routes.route('/agents/<int:agent_id>/suggestions/<int:suggestion_id>/dismiss', methods=['POST'])
def dismiss_suggestion(agent_id, suggestion_id):
    """Dismiss a firewall rule suggestion"""
    try:
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            UPDATE firewall_suggestions
            SET status = 'dismissed', dismissed_at = NOW()
            WHERE id = %s AND agent_id = %s AND status = 'pending'
        """, (suggestion_id, agent_id))

        if cursor.rowcount == 0:
            cursor.close()
            conn.close()
            return jsonify({'success': False, 'error': 'Suggestion not found or not pending'}), 404

        conn.commit()
        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'message': 'Suggestion dismissed'
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@agent_routes.route('/agents/<int:agent_id>/protected-ports', methods=['GET'])
def get_protected_ports(agent_id):
    """Get protected ports for an agent"""
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT * FROM agent_protected_ports
            WHERE agent_id = %s
            ORDER BY port
        """, (agent_id,))
        ports = cursor.fetchall()

        for port in ports:
            if port.get('created_at'):
                port['created_at'] = port['created_at'].isoformat()

        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'protected_ports': ports,
            'total': len(ports)
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@agent_routes.route('/agents/<int:agent_id>/protected-ports', methods=['POST'])
def add_protected_port(agent_id):
    """Add a custom protected port"""
    try:
        data = request.get_json()

        port = data.get('port')
        service_name = data.get('service_name', 'Custom')
        reason = data.get('reason', 'Manually added')

        if not port:
            return jsonify({'success': False, 'error': 'Port is required'}), 400

        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO agent_protected_ports
                (agent_id, port, service_name, reason, is_listening, is_custom)
            VALUES (%s, %s, %s, %s, FALSE, TRUE)
            ON DUPLICATE KEY UPDATE
                service_name = VALUES(service_name),
                reason = VALUES(reason),
                is_custom = TRUE
        """, (agent_id, port, service_name, reason))

        conn.commit()
        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'message': f'Port {port} added to protected list'
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@agent_routes.route('/agents/<int:agent_id>/protected-ports/<int:port>', methods=['DELETE'])
def remove_protected_port(agent_id, port):
    """Remove a custom protected port"""
    try:
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            DELETE FROM agent_protected_ports
            WHERE agent_id = %s AND port = %s AND is_custom = TRUE
        """, (agent_id, port))

        if cursor.rowcount == 0:
            cursor.close()
            conn.close()
            return jsonify({'success': False, 'error': 'Port not found or is system protected'}), 404

        conn.commit()
        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'message': f'Port {port} removed from protected list'
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@agent_routes.route('/agents/<int:agent_id>/security-overview', methods=['GET'])
def get_security_overview(agent_id):
    """Get comprehensive security overview for an agent"""
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Get agent info
        cursor.execute("SELECT * FROM agents WHERE id = %s", (agent_id,))
        agent = cursor.fetchone()

        if not agent:
            cursor.close()
            conn.close()
            return jsonify({'success': False, 'error': 'Agent not found'}), 404

        # Get firewall state
        cursor.execute("SELECT * FROM agent_firewall_state WHERE agent_id = %s", (agent_id,))
        firewall_state = cursor.fetchone()

        # Get counts
        cursor.execute("SELECT COUNT(*) as count FROM agent_listening_ports WHERE agent_id = %s", (agent_id,))
        listening_ports_count = cursor.fetchone()['count']

        cursor.execute("SELECT COUNT(*) as count FROM agent_listening_ports WHERE agent_id = %s AND is_protected = TRUE", (agent_id,))
        protected_ports_count = cursor.fetchone()['count']

        cursor.execute("SELECT COUNT(*) as count FROM agent_system_users WHERE agent_id = %s AND is_login_enabled = TRUE", (agent_id,))
        login_users_count = cursor.fetchone()['count']

        cursor.execute("SELECT COUNT(*) as count FROM agent_active_connections WHERE agent_id = %s", (agent_id,))
        connections_count = cursor.fetchone()['count']

        cursor.execute("SELECT COUNT(*) as count FROM firewall_suggestions WHERE agent_id = %s AND status = 'pending'", (agent_id,))
        pending_suggestions = cursor.fetchone()['count']

        cursor.execute("SELECT COUNT(*) as count FROM firewall_suggestions WHERE agent_id = %s AND status = 'pending' AND priority = 'high'", (agent_id,))
        high_priority_suggestions = cursor.fetchone()['count']

        cursor.execute("SELECT COUNT(*) as count FROM agent_firewall_commands WHERE agent_id = %s AND status = 'pending'", (agent_id,))
        pending_commands = cursor.fetchone()['count']

        cursor.close()
        conn.close()

        # Format timestamps
        if firewall_state and firewall_state.get('last_sync'):
            firewall_state['last_sync'] = firewall_state['last_sync'].isoformat()

        return jsonify({
            'success': True,
            'agent': {
                'id': agent['id'],
                'hostname': agent.get('hostname'),
                'agent_id': agent.get('agent_id') or agent.get('agent_uuid')
            },
            'firewall': {
                'rules_count': firewall_state.get('rules_count', 0) if firewall_state else 0,
                'port_forwards_count': firewall_state.get('port_forwards_count', 0) if firewall_state else 0,
                'last_sync': firewall_state.get('last_sync') if firewall_state else None
            },
            'ports': {
                'listening': listening_ports_count,
                'protected': protected_ports_count
            },
            'users': {
                'login_enabled': login_users_count
            },
            'connections': {
                'active': connections_count
            },
            'suggestions': {
                'pending': pending_suggestions,
                'high_priority': high_priority_suggestions
            },
            'commands': {
                'pending': pending_commands
            }
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
