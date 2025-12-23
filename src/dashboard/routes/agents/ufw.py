"""
SSH Guardian v3.0 - Agent UFW Routes
Handles UFW (Uncomplicated Firewall) synchronization and management
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

# Import block events logging
try:
    from routes.block_events_routes import log_block_event
except ImportError:
    log_block_event = None


def get_current_user_id():
    """Get current user ID from request context"""
    if hasattr(request, 'current_user') and request.current_user:
        return request.current_user.get('user_id') or request.current_user.get('id')
    return None


# Cache TTLs
UFW_CACHE_TTL = 60  # 1 minute


# ============================================================================
# UFW SYNC ENDPOINT (Agent -> Server)
# ============================================================================

@agent_routes.route('/agents/ufw/sync', methods=['POST'])
@require_api_key
def sync_ufw_rules():
    """
    Receive UFW rules from an agent and store them.
    This is called periodically by the agent to sync its UFW state.
    """
    conn = None
    cursor = None
    try:
        data = request.get_json()

        agent_id = data.get('agent_id')
        hostname = data.get('hostname')
        ufw_data = data.get('ufw_data', {})

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
            return jsonify({'success': False, 'error': 'Agent not found'}), 404

        db_agent_id = agent_row['id']

        # Extract status and rules - handle both flat and nested formats
        # Flat format (from direct sync): ufw_data.ufw_status, ufw_data.default_incoming, etc.
        # Nested format (legacy): ufw_data.status.status, ufw_data.status.default_incoming, etc.
        status_data = ufw_data.get('status', {})

        # Get ufw_status - check flat format first, then nested
        ufw_status = ufw_data.get('ufw_status') or status_data.get('status', 'inactive')
        default_incoming = ufw_data.get('default_incoming') or status_data.get('default_incoming', 'deny')
        default_outgoing = ufw_data.get('default_outgoing') or status_data.get('default_outgoing', 'allow')
        default_routed = status_data.get('default_routed', 'disabled')
        logging_level = status_data.get('logging_level', 'low')
        ipv6_enabled = status_data.get('ipv6_enabled', True)
        ufw_version = status_data.get('ufw_version', '')

        rules = ufw_data.get('rules', [])
        listening_ports = ufw_data.get('listening_ports', [])
        protected_ports = ufw_data.get('protected_ports', [])

        # Store or update UFW state
        cursor.execute("""
            INSERT INTO agent_ufw_state
                (agent_id, ufw_status, default_incoming, default_outgoing, default_routed,
                 logging_level, ipv6_enabled, rules_count, ufw_version, last_sync)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
            ON DUPLICATE KEY UPDATE
                ufw_status = VALUES(ufw_status),
                default_incoming = VALUES(default_incoming),
                default_outgoing = VALUES(default_outgoing),
                default_routed = VALUES(default_routed),
                logging_level = VALUES(logging_level),
                ipv6_enabled = VALUES(ipv6_enabled),
                rules_count = VALUES(rules_count),
                ufw_version = VALUES(ufw_version),
                last_sync = NOW()
        """, (
            db_agent_id,
            ufw_status,
            default_incoming,
            default_outgoing,
            default_routed,
            logging_level,
            ipv6_enabled,
            len(rules),
            ufw_version
        ))

        # Store individual rules
        _store_ufw_rules(cursor, db_agent_id, rules)

        # Store listening ports
        _store_listening_ports(cursor, db_agent_id, listening_ports)

        # Store protected ports
        _store_protected_ports(cursor, db_agent_id, protected_ports)

        conn.commit()

        # Invalidate cache
        cache = get_cache()
        cache.delete_pattern(f'ufw:{db_agent_id}')
        cache.delete_pattern('blocking')  # Also invalidate blocking cache

        # Reconcile ip_blocks with actual UFW rules
        # This marks IPs as unblocked if they were removed from UFW externally
        try:
            from blocking import reconcile_ufw_with_ip_blocks
            reconcile_result = reconcile_ufw_with_ip_blocks(db_agent_id)
            reconciled_count = reconcile_result.get('reconciled_count', 0)
        except Exception as reconcile_err:
            print(f"⚠️  UFW reconciliation error: {reconcile_err}")
            reconciled_count = 0

        return jsonify({
            'success': True,
            'message': 'UFW state synced',
            'rules_count': len(rules),
            'ufw_status': ufw_status,
            'reconciled_count': reconciled_count
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


def _store_ufw_rules(cursor, agent_id: int, rules: list):
    """Store UFW rules for querying, preserving timestamps for existing blocked IPs"""

    # First, get existing DENY rules with their created_at timestamps
    # to preserve the original block time
    cursor.execute("""
        SELECT from_ip, created_at FROM agent_ufw_rules
        WHERE agent_id = %s AND action = 'DENY' AND from_ip IS NOT NULL
          AND from_ip != '' AND from_ip != 'Anywhere'
    """, (agent_id,))
    existing_blocks = {row['from_ip']: row['created_at'] for row in cursor.fetchall()}

    # Clear existing rules for this agent
    cursor.execute("DELETE FROM agent_ufw_rules WHERE agent_id = %s", (agent_id,))

    for rule in rules:
        action = rule.get('action', 'ALLOW')
        from_ip = rule.get('from_ip', 'Anywhere')

        # Preserve original created_at for existing DENY rules (blocked IPs)
        preserved_time = None
        if action == 'DENY' and from_ip and from_ip not in ('', 'Anywhere'):
            preserved_time = existing_blocks.get(from_ip)

        if preserved_time:
            # Use preserved timestamp for existing blocked IP
            cursor.execute("""
                INSERT INTO agent_ufw_rules
                    (agent_id, rule_index, action, direction, from_ip, from_port,
                     to_ip, to_port, protocol, interface, comment, is_v6, raw_rule, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                agent_id,
                rule.get('rule_index', 0),
                action,
                rule.get('direction', 'IN'),
                from_ip,
                rule.get('from_port', ''),
                rule.get('to_ip', 'Anywhere'),
                rule.get('to_port', ''),
                rule.get('protocol', ''),
                rule.get('interface', ''),
                rule.get('comment', ''),
                rule.get('ipv6', False) or rule.get('is_v6', False),
                rule.get('raw_rule', ''),
                preserved_time
            ))
        else:
            # New rule - use default (NOW())
            cursor.execute("""
                INSERT INTO agent_ufw_rules
                    (agent_id, rule_index, action, direction, from_ip, from_port,
                     to_ip, to_port, protocol, interface, comment, is_v6, raw_rule)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                agent_id,
                rule.get('rule_index', 0),
                action,
                rule.get('direction', 'IN'),
                from_ip,
                rule.get('from_port', ''),
                rule.get('to_ip', 'Anywhere'),
                rule.get('to_port', ''),
                rule.get('protocol', ''),
                rule.get('interface', ''),
                rule.get('comment', ''),
                rule.get('ipv6', False) or rule.get('is_v6', False),
                rule.get('raw_rule', '')
            ))


def _store_listening_ports(cursor, agent_id: int, ports: list):
    """Store listening ports for an agent (v3.1: table removed, skip)"""
    return  # Table not in v3.1 schema
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


def _store_protected_ports(cursor, agent_id: int, protected: list):
    """Store protected ports configuration (v3.1: table removed, skip)"""
    return  # Table not in v3.1 schema
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


# ============================================================================
# UFW COMMANDS ENDPOINT (Server -> Agent)
# ============================================================================

@agent_routes.route('/agents/ufw/commands', methods=['GET'])
@require_api_key
def get_pending_ufw_commands():
    """
    Get pending UFW commands for an agent.
    The agent polls this endpoint to receive commands to execute.
    """
    conn = None
    cursor = None
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
            return jsonify({'success': False, 'error': 'Agent not found'}), 404

        db_agent_id = agent_row['id']

        # Get pending commands
        cursor.execute("""
            SELECT id, command_uuid, command_type, params, ufw_command, created_at
            FROM agent_ufw_commands
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
                UPDATE agent_ufw_commands
                SET status = 'sent', sent_at = NOW()
                WHERE id IN ({placeholders})
            """, command_ids)
            conn.commit()

        # Format commands for agent
        formatted_commands = []
        for cmd in commands:
            # params is already JSON type in v3.1 schema - may be dict or string
            params_val = cmd.get('params') or {}
            if isinstance(params_val, str):
                params_val = json.loads(params_val) if params_val else {}
            formatted_commands.append({
                'id': cmd['command_uuid'],
                'command_type': cmd['command_type'],
                'action': cmd['command_type'],  # Alias for compatibility
                'params': params_val,
                'ufw_command': cmd['ufw_command'],
                'created_at': cmd['created_at'].isoformat() if cmd['created_at'] else None
            })

        return jsonify({
            'success': True,
            'commands': formatted_commands
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@agent_routes.route('/agents/ufw/command-result', methods=['POST'])
@require_api_key
def report_ufw_command_result():
    """
    Receive the result of a UFW command execution from an agent.
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
            UPDATE agent_ufw_commands
            SET status = %s,
                result_message = %s,
                executed_at = NOW()
            WHERE command_uuid = %s
        """, (
            'completed' if success else 'failed',
            message,
            command_id
        ))

        # Also log to audit table
        cursor.execute("""
            INSERT INTO ufw_audit_log
                (agent_id, command_type, command_uuid, status, result_message)
            SELECT agent_id, command_type, command_uuid, %s, %s
            FROM agent_ufw_commands WHERE command_uuid = %s
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

@agent_routes.route('/agents/<int:agent_id>/ufw/live', methods=['GET'])
def get_live_ufw_data(agent_id):
    """
    Get LIVE UFW data directly from the agent.
    For local machines: runs 'ufw status numbered' directly
    For remote agents: reads from agent_ufw_state/rules tables (synced by agent)
    """
    import subprocess
    import socket

    conn = None
    cursor = None
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Verify agent exists and get its info
        cursor.execute("""
            SELECT id, hostname, agent_id, ip_address
            FROM agents WHERE id = %s
        """, (agent_id,))
        agent = cursor.fetchone()

        if not agent:
            return jsonify({'success': False, 'error': 'Agent not found'}), 404

        # Check if this is the local machine
        local_hostname = socket.gethostname()
        agent_hostname = agent.get('hostname', '')
        agent_ip = agent.get('ip_address', '')
        is_local = (
            agent_hostname == local_hostname or
            agent_ip in ('127.0.0.1', '::1', 'localhost') or
            agent_hostname == 'localhost'
        )

        rules = []
        state = {
            'ufw_status': 'inactive',
            'default_incoming': 'deny',
            'default_outgoing': 'allow',
            'last_sync': datetime.now().isoformat()
        }

        if is_local:
            # Get UFW status directly from local machine
            try:
                result = subprocess.run(
                    ['sudo', 'ufw', 'status', 'numbered'],
                    capture_output=True, text=True, timeout=10
                )

                if result.returncode == 0:
                    output = result.stdout
                    lines = output.strip().split('\n')

                    # Parse status
                    for line in lines:
                        if line.startswith('Status:'):
                            status = line.split(':')[1].strip().lower()
                            state['ufw_status'] = status
                        elif 'Default:' in line:
                            # Parse default policies
                            if 'deny (incoming)' in line.lower():
                                state['default_incoming'] = 'deny'
                            elif 'allow (incoming)' in line.lower():
                                state['default_incoming'] = 'allow'
                            if 'allow (outgoing)' in line.lower():
                                state['default_outgoing'] = 'allow'
                            elif 'deny (outgoing)' in line.lower():
                                state['default_outgoing'] = 'deny'

                    # Parse rules
                    # UFW format: [ 1] To                         Action      From
                    # Example:    [ 1] 22/tcp                     ALLOW IN    Anywhere
                    # Example:    [ 2] Anywhere                   DENY IN     192.168.1.1
                    import re
                    rule_pattern = re.compile(r'\[\s*(\d+)\]\s+(.+)')

                    for line in lines:
                        match = rule_pattern.match(line.strip())
                        if match:
                            rule_index = int(match.group(1))
                            rule_text = match.group(2).strip()

                            # Parse the rule text using regex
                            # Pattern: <to> <action> <direction> <from>
                            # Where to/from can be port, IP, or "Anywhere"
                            rule_match = re.match(
                                r'^(\S+(?:\s+\(v6\))?)\s+(ALLOW|DENY|REJECT|LIMIT)\s+(IN|OUT)\s+(.+)$',
                                rule_text, re.IGNORECASE
                            )

                            action = 'ALLOW'
                            direction = 'IN'
                            to_port = ''
                            protocol = ''
                            from_ip = 'Anywhere'
                            is_v6 = '(v6)' in rule_text

                            if rule_match:
                                to_field = rule_match.group(1).replace('(v6)', '').strip()
                                action = rule_match.group(2).upper()
                                direction = rule_match.group(3).upper()
                                from_field = rule_match.group(4).strip()

                                # Parse 'to' field - can be port, port/proto, or "Anywhere"
                                if to_field.lower() != 'anywhere':
                                    if '/' in to_field:
                                        parts = to_field.split('/')
                                        to_port = parts[0]
                                        protocol = parts[1].lower() if len(parts) > 1 else ''
                                    elif to_field.isdigit():
                                        to_port = to_field
                                    else:
                                        to_port = to_field

                                # Parse 'from' field - can be IP, CIDR, or "Anywhere"
                                from_clean = from_field.replace('(v6)', '').strip()
                                if from_clean.lower() != 'anywhere':
                                    from_ip = from_clean
                            else:
                                # Fallback: simple split parsing
                                parts = rule_text.split()
                                for i, part in enumerate(parts):
                                    if part.upper() in ('ALLOW', 'DENY', 'REJECT', 'LIMIT'):
                                        action = part.upper()
                                        if i > 0:
                                            to_part = parts[0].replace('(v6)', '').strip()
                                            if to_part.lower() != 'anywhere':
                                                if '/' in to_part:
                                                    to_port, protocol = to_part.split('/', 1)
                                                    protocol = protocol.lower()
                                                elif to_part.isdigit():
                                                    to_port = to_part
                                        if i + 1 < len(parts) and parts[i + 1].upper() in ('IN', 'OUT'):
                                            direction = parts[i + 1].upper()
                                            if i + 2 < len(parts):
                                                from_part = parts[i + 2].replace('(v6)', '').strip()
                                                if from_part.lower() != 'anywhere':
                                                    from_ip = from_part
                                        break

                            rules.append({
                                'rule_index': rule_index,
                                'action': action,
                                'direction': direction,
                                'to_port': to_port,
                                'protocol': protocol,
                                'from_ip': from_ip,
                                'is_v6': is_v6,
                                'raw_rule': rule_text
                            })

            except subprocess.TimeoutExpired:
                print("[UFW Live] Timeout running ufw status")
            except Exception as e:
                print(f"[UFW Live] Error running ufw status: {e}")
                # Fall back to database
                is_local = False

        if not is_local:
            # Get from database (synced by remote agent)
            cursor.execute("""
                SELECT * FROM agent_ufw_state
                WHERE agent_id = %s
            """, (agent_id,))
            db_state = cursor.fetchone()

            if db_state:
                state = {
                    'ufw_status': db_state.get('ufw_status', 'inactive'),
                    'default_incoming': db_state.get('default_incoming', 'deny'),
                    'default_outgoing': db_state.get('default_outgoing', 'allow'),
                    'last_sync': db_state['last_sync'].isoformat() if db_state.get('last_sync') else None
                }

            cursor.execute("""
                SELECT * FROM agent_ufw_rules
                WHERE agent_id = %s
                ORDER BY rule_index ASC
            """, (agent_id,))
            rules = cursor.fetchall()

        if not rules and not is_local:
            return jsonify({
                'success': True,
                'has_data': False,
                'message': 'No UFW data available - waiting for agent sync',
                'agent_hostname': agent.get('hostname')
            })

        # Count allow/deny rules
        allow_count = sum(1 for r in rules if r.get('action') == 'ALLOW')
        deny_count = sum(1 for r in rules if r.get('action') in ('DENY', 'REJECT'))

        return jsonify({
            'success': True,
            'has_data': True,
            'agent_hostname': agent.get('hostname'),
            'state': state,
            'rules': rules,
            'listening_ports': [],
            'total_rules': len(rules),
            'allow_count': allow_count,
            'deny_count': deny_count,
            'source': 'live' if is_local else 'database'
        })

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@agent_routes.route('/agents/<int:agent_id>/ufw', methods=['GET'])
def get_agent_ufw(agent_id):
    """Get UFW state for an agent (dashboard endpoint) - includes templates and command history"""
    try:
        # Check for force refresh parameter
        force_refresh = request.args.get('force', '').lower() in ('true', '1', 'yes')

        cache = get_cache()
        cache_k = cache_key('ufw', str(agent_id), 'state')

        # Try cache first (unless force refresh)
        if not force_refresh:
            cached = cache.get(cache_k)
            if cached is not None:
                cached['from_cache'] = True
                return jsonify(cached)

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Get UFW state
        cursor.execute("""
            SELECT * FROM agent_ufw_state
            WHERE agent_id = %s
        """, (agent_id,))
        state = cursor.fetchone()

        if not state:
            cursor.close()
            conn.close()
            return jsonify({
                'success': True,
                'has_data': False,
                'message': 'No UFW data available for this agent'
            })

        # Get rules
        cursor.execute("""
            SELECT * FROM agent_ufw_rules
            WHERE agent_id = %s
            ORDER BY rule_index
        """, (agent_id,))
        rules = cursor.fetchall()

        # Listening ports and protected ports tables removed in v3.1
        listening_ports = []
        protected_ports = []

        # Get recent commands
        cursor.execute("""
            SELECT * FROM agent_ufw_commands
            WHERE agent_id = %s
            ORDER BY created_at DESC
            LIMIT 20
        """, (agent_id,))
        commands = cursor.fetchall()

        # Get rule templates
        cursor.execute("""
            SELECT * FROM ufw_rule_templates
            ORDER BY category, display_order, template_name
        """)
        templates = cursor.fetchall()

        cursor.close()
        conn.close()

        # Format timestamps
        if state.get('last_sync'):
            state['last_sync'] = state['last_sync'].isoformat()
        if state.get('created_at'):
            state['created_at'] = state['created_at'].isoformat()
        if state.get('updated_at'):
            state['updated_at'] = state['updated_at'].isoformat()

        for cmd in commands:
            # params is already JSON type in v3.1 schema
            params_val = cmd.get('params')
            if params_val and isinstance(params_val, str):
                cmd['params'] = json.loads(params_val)
            for field in ['created_at', 'sent_at', 'executed_at']:
                if cmd.get(field):
                    cmd[field] = cmd[field].isoformat()

        for port in listening_ports:
            if port.get('last_seen'):
                port['last_seen'] = port['last_seen'].isoformat()

        for tpl in templates:
            if tpl.get('created_at'):
                tpl['created_at'] = tpl['created_at'].isoformat()

        result = {
            'success': True,
            'has_data': True,
            'state': state,
            'rules': rules,
            'listening_ports': listening_ports,
            'protected_ports': protected_ports,
            'recent_commands': commands,
            'templates': templates,
            'from_cache': False
        }

        # Cache the result
        cache.set(cache_k, result, UFW_CACHE_TTL)

        return jsonify(result)

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@agent_routes.route('/agents/<int:agent_id>/ufw/command', methods=['POST'])
def create_ufw_command(agent_id):
    """Create a new UFW command to be executed by the agent"""
    try:
        data = request.get_json()

        command_type = data.get('command_type') or data.get('action')
        params = data.get('params', {})
        ufw_command = data.get('ufw_command', '')

        if not command_type:
            return jsonify({'success': False, 'error': 'Command type required'}), 400

        # Validate command type
        valid_commands = [
            'allow', 'deny', 'reject', 'limit', 'delete', 'delete_by_rule',
            'enable', 'disable', 'reset', 'reload', 'default', 'logging',
            'sync_now', 'raw'
        ]

        if command_type not in valid_commands:
            return jsonify({
                'success': False,
                'error': f'Invalid command type. Valid types: {", ".join(valid_commands)}'
            }), 400

        # Build UFW command string if not provided
        if not ufw_command:
            ufw_command = _build_ufw_command(command_type, params)

        conn = get_connection()
        cursor = conn.cursor()

        command_uuid = str(uuid.uuid4())

        cursor.execute("""
            INSERT INTO agent_ufw_commands
                (agent_id, command_uuid, command_type, params, ufw_command, status, created_at, created_by)
            VALUES (%s, %s, %s, %s, %s, 'pending', NOW(), %s)
        """, (
            agent_id,
            command_uuid,
            command_type,
            json.dumps(params),
            ufw_command,
            get_current_user_id()
        ))

        conn.commit()
        cursor.close()
        conn.close()

        # If this is an IP block (deny from IP), also create an ip_blocks record
        # so the IP appears in "Currently Blocked IPs"
        block_id = None
        from_ip = params.get('from_ip')
        is_escalation = data.get('from_fail2ban', False) or data.get('escalation', False)

        if command_type == 'deny' and from_ip and from_ip.lower() not in ['anywhere', 'any', '']:
            escalation_text = ' (escalated from Fail2ban)' if is_escalation else ''
            try:
                from blocking_engine import block_ip_manual
                block_result = block_ip_manual(
                    ip_address=from_ip,
                    reason=f'UFW block from dashboard{escalation_text}',
                    user_id=get_current_user_id(),
                    duration_minutes=0,  # Permanent (UFW blocks don't auto-expire)
                    agent_id=agent_id
                )
                if block_result.get('success'):
                    block_id = block_result.get('block_id')
            except Exception as block_err:
                # Log but don't fail - UFW command is already created
                print(f"Warning: Failed to create ip_blocks record for UFW deny: {block_err}")

            # Log block event - track escalations properly
            if log_block_event:
                event_type = 'escalate' if is_escalation else 'block'
                reason = 'Escalated from Fail2ban to permanent UFW block' if is_escalation else 'UFW deny rule from dashboard'
                log_block_event(
                    ip_address=from_ip,
                    event_type=event_type,
                    block_source='ufw',
                    agent_id=agent_id,
                    reason=reason,
                    triggered_by='dashboard_manual',
                    user_id=get_current_user_id()
                )

            # If escalating from fail2ban, also unban from fail2ban
            if is_escalation and from_ip:
                try:
                    unban_conn = get_connection()
                    unban_cursor = unban_conn.cursor()
                    unban_uuid = str(uuid.uuid4())
                    unban_cursor.execute("""
                        INSERT INTO fail2ban_commands
                            (agent_id, command_uuid, command_type, ip_address, jail_name, status, created_at)
                        VALUES (%s, %s, 'unban', %s, 'sshd', 'pending', NOW())
                    """, (agent_id, unban_uuid, from_ip))
                    unban_conn.commit()
                    unban_cursor.close()
                    unban_conn.close()
                    print(f"Queued fail2ban unban for {from_ip} after UFW escalation")
                except Exception as unban_err:
                    print(f"Warning: Failed to queue fail2ban unban after UFW escalation: {unban_err}")

        # Log delete command as unblock
        if command_type in ('delete', 'delete_by_rule') and from_ip and log_block_event:
            log_block_event(
                ip_address=from_ip,
                event_type='unblock',
                block_source='ufw',
                agent_id=agent_id,
                reason='UFW rule deleted from dashboard',
                triggered_by='dashboard_manual',
                user_id=get_current_user_id()
            )

        # Invalidate cache
        cache = get_cache()
        cache.delete_pattern(f'ufw:{agent_id}')
        cache.delete_pattern('blocking')  # Also invalidate blocking cache

        # Audit log
        AuditLogger.log_action(
            user_id=get_current_user_id(),
            action='ufw_command_created',
            resource_type='ufw',
            resource_id=str(agent_id),
            details={'command_id': command_uuid, 'command_type': command_type, 'params': params},
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent')
        )

        return jsonify({
            'success': True,
            'message': 'UFW command created',
            'command_id': command_uuid,
            'ufw_command': ufw_command,
            'block_id': block_id
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


def _build_ufw_command(command_type: str, params: dict) -> str:
    """Build UFW command string from type and params"""
    port = params.get('port', '')
    protocol = params.get('protocol', '')
    from_ip = params.get('from_ip') or params.get('from', '')
    to_ip = params.get('to_ip') or params.get('to', '')

    if command_type == 'allow':
        if from_ip and from_ip.lower() not in ['anywhere', 'any']:
            if port:
                return f"ufw allow from {from_ip} to any port {port}" + (f" proto {protocol}" if protocol else "")
            return f"ufw allow from {from_ip}"
        if port:
            return f"ufw allow {port}" + (f"/{protocol}" if protocol else "")
        return "ufw allow"

    elif command_type == 'deny':
        if from_ip and from_ip.lower() not in ['anywhere', 'any']:
            if port:
                return f"ufw deny from {from_ip} to any port {port}" + (f" proto {protocol}" if protocol else "")
            return f"ufw deny from {from_ip}"
        if port:
            return f"ufw deny {port}" + (f"/{protocol}" if protocol else "")
        return "ufw deny"

    elif command_type == 'reject':
        if port:
            return f"ufw reject {port}" + (f"/{protocol}" if protocol else "")
        return "ufw reject"

    elif command_type == 'limit':
        if port:
            return f"ufw limit {port}/{protocol or 'tcp'}"
        return "ufw limit"

    elif command_type == 'delete':
        rule_num = params.get('rule_number') or params.get('rule_index')
        if rule_num:
            return f"ufw --force delete {rule_num}"
        return "ufw delete"

    elif command_type == 'enable':
        return "ufw --force enable"

    elif command_type == 'disable':
        return "ufw --force disable"

    elif command_type == 'reset':
        return "ufw --force reset"

    elif command_type == 'reload':
        return "ufw reload"

    elif command_type == 'default':
        direction = params.get('direction', 'incoming')
        policy = params.get('policy', 'deny')
        return f"ufw default {policy} {direction}"

    elif command_type == 'logging':
        level = params.get('level', 'low')
        return f"ufw logging {level}"

    elif command_type == 'sync_now':
        return "# Sync request"

    elif command_type == 'raw':
        return params.get('command', '')

    return ""


@agent_routes.route('/agents/<int:agent_id>/ufw/request-sync', methods=['POST'])
def request_ufw_sync(agent_id):
    """Request the agent to sync its UFW rules immediately"""
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

        # Create a sync_now command
        command_uuid = str(uuid.uuid4())

        cursor.execute("""
            INSERT INTO agent_ufw_commands
                (agent_id, command_uuid, command_type, params, ufw_command, status, created_at)
            VALUES (%s, %s, 'sync_now', '{}', '# Sync request', 'pending', NOW())
        """, (agent_id, command_uuid))

        conn.commit()
        cursor.close()
        conn.close()

        # Invalidate cache
        cache = get_cache()
        cache.delete_pattern(f'ufw:{agent_id}')

        return jsonify({
            'success': True,
            'message': 'Sync request sent to agent',
            'command_id': command_uuid
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@agent_routes.route('/agents/<int:agent_id>/ufw/rules', methods=['GET'])
def get_ufw_rules(agent_id):
    """Get UFW rules for an agent with filtering options"""
    try:
        action = request.args.get('action')
        direction = request.args.get('direction')

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        query = "SELECT * FROM agent_ufw_rules WHERE agent_id = %s"
        params = [agent_id]

        if action:
            query += " AND action = %s"
            params.append(action.upper())

        if direction:
            query += " AND direction = %s"
            params.append(direction.upper())

        query += " ORDER BY rule_index"

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


@agent_routes.route('/agents/<int:agent_id>/ufw/commands', methods=['GET'])
def get_ufw_command_history(agent_id):
    """Get UFW command history for an agent"""
    try:
        limit = request.args.get('limit', 50, type=int)
        status = request.args.get('status')

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        query = """
            SELECT * FROM agent_ufw_commands
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
            # params is already JSON type in v3.1 schema
            params_val = cmd.get('params')
            if params_val and isinstance(params_val, str):
                cmd['params'] = json.loads(params_val)
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


@agent_routes.route('/agents/<int:agent_id>/ufw/templates', methods=['GET'])
def get_ufw_templates(agent_id):
    """Get UFW rule templates"""
    try:
        category = request.args.get('category')

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        query = "SELECT * FROM ufw_rule_templates"
        params = []

        if category:
            query += " WHERE category = %s"
            params.append(category)

        query += " ORDER BY category, display_order, template_name"

        cursor.execute(query, params)
        templates = cursor.fetchall()

        cursor.close()
        conn.close()

        # Format timestamps
        for tpl in templates:
            if tpl.get('created_at'):
                tpl['created_at'] = tpl['created_at'].isoformat()

        return jsonify({
            'success': True,
            'templates': templates,
            'total': len(templates)
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@agent_routes.route('/agents/<int:agent_id>/ufw/reorder', methods=['POST'])
def reorder_ufw_rules(agent_id):
    """
    Reorder UFW rules by moving a rule from one position to another.
    UFW doesn't have native reorder, so we delete the rule and re-add it at the new position.
    """
    try:
        data = request.get_json()
        from_index = data.get('from_index')
        to_index = data.get('to_index')

        if from_index is None or to_index is None:
            return jsonify({'success': False, 'error': 'from_index and to_index required'}), 400

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Get the rule at from_index
        cursor.execute("""
            SELECT * FROM agent_ufw_rules
            WHERE agent_id = %s AND rule_index = %s
        """, (agent_id, from_index))
        rule = cursor.fetchone()

        if not rule:
            cursor.close()
            conn.close()
            return jsonify({'success': False, 'error': f'Rule #{from_index} not found'}), 404

        # Create a reorder command sequence
        # 1. Delete the rule at from_index
        # 2. Insert it at to_index position
        command_uuid = str(uuid.uuid4())

        # For UFW, we need to:
        # - Delete the rule by number (from bottom to avoid index shift if moving up)
        # - Re-add the rule at the new position using 'insert'

        # Build the UFW command for reinserting
        port = rule.get('to_port', '')
        protocol = rule.get('protocol', '')
        from_ip = rule.get('from_ip', 'Anywhere')
        action = rule.get('action', 'ALLOW').lower()

        # Build insert command
        insert_cmd = f"ufw insert {to_index} {action}"
        if from_ip and from_ip.lower() not in ['anywhere', 'any']:
            insert_cmd += f" from {from_ip}"
        if port:
            insert_cmd += f" to any port {port}"
            if protocol:
                insert_cmd += f" proto {protocol}"
        elif not from_ip or from_ip.lower() in ['anywhere', 'any']:
            insert_cmd += f" from any"

        # Create delete command
        delete_cmd = f"ufw --force delete {from_index}"

        # Store as a compound reorder command
        reorder_params = {
            'from_index': from_index,
            'to_index': to_index,
            'delete_cmd': delete_cmd,
            'insert_cmd': insert_cmd,
            'original_rule': {
                'action': rule.get('action'),
                'port': port,
                'protocol': protocol,
                'from_ip': from_ip
            }
        }

        cursor.execute("""
            INSERT INTO agent_ufw_commands
                (agent_id, command_uuid, command_type, params, ufw_command, status, created_at, created_by)
            VALUES (%s, %s, 'reorder', %s, %s, 'pending', NOW(), %s)
        """, (
            agent_id,
            command_uuid,
            json.dumps(reorder_params),
            f"{delete_cmd} && {insert_cmd}",
            get_current_user_id()
        ))

        conn.commit()
        cursor.close()
        conn.close()

        # Invalidate cache
        cache = get_cache()
        cache.delete_pattern(f'ufw:{agent_id}')

        # Audit log
        AuditLogger.log_action(
            user_id=get_current_user_id(),
            action='ufw_reorder',
            resource_type='ufw',
            resource_id=str(agent_id),
            details={'from_index': from_index, 'to_index': to_index, 'command_id': command_uuid},
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent')
        )

        return jsonify({
            'success': True,
            'message': f'Reorder command queued: move rule #{from_index} to position #{to_index}',
            'command_id': command_uuid
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@agent_routes.route('/agents/<int:agent_id>/ufw/quick-action', methods=['POST'])
def ufw_quick_action(agent_id):
    """
    Execute a quick UFW action (allow/deny port, block IP, etc.)
    For local machines: executes command directly via subprocess
    For remote agents: queues command for agent to pick up
    """
    import subprocess
    import socket

    try:
        data = request.get_json()

        action_type = data.get('action_type')  # allow_port, deny_port, block_ip, allow_ip, limit_port
        port = data.get('port')
        protocol = data.get('protocol', 'tcp')
        ip = data.get('ip')

        if not action_type:
            return jsonify({'success': False, 'error': 'Action type required'}), 400

        command_type = None
        params = {}

        if action_type == 'allow_port':
            if not port:
                return jsonify({'success': False, 'error': 'Port required'}), 400
            command_type = 'allow'
            params = {'port': port, 'protocol': protocol}

        elif action_type == 'deny_port':
            if not port:
                return jsonify({'success': False, 'error': 'Port required'}), 400
            command_type = 'deny'
            params = {'port': port, 'protocol': protocol}

        elif action_type == 'block_ip':
            if not ip:
                return jsonify({'success': False, 'error': 'IP address required'}), 400
            command_type = 'deny'
            params = {'from_ip': ip}
            if port:
                params['port'] = port
                params['protocol'] = protocol

        elif action_type == 'allow_ip':
            if not ip:
                return jsonify({'success': False, 'error': 'IP address required'}), 400
            command_type = 'allow'
            params = {'from_ip': ip}
            if port:
                params['port'] = port
                params['protocol'] = protocol

        elif action_type == 'limit_port':
            if not port:
                return jsonify({'success': False, 'error': 'Port required'}), 400
            command_type = 'limit'
            params = {'port': port, 'protocol': protocol}

        elif action_type == 'delete_rule':
            rule_number = data.get('rule_number')
            if not rule_number:
                return jsonify({'success': False, 'error': 'Rule number required'}), 400
            command_type = 'delete'
            params = {'rule_number': rule_number}

        elif action_type == 'enable':
            command_type = 'enable'

        elif action_type == 'disable':
            command_type = 'disable'

        else:
            return jsonify({'success': False, 'error': f'Unknown action type: {action_type}'}), 400

        # Build UFW command
        ufw_command = _build_ufw_command(command_type, params)
        command_uuid = str(uuid.uuid4())

        # Check if this is a local machine
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT id, hostname, agent_id, ip_address
            FROM agents WHERE id = %s
        """, (agent_id,))
        agent = cursor.fetchone()

        if not agent:
            cursor.close()
            conn.close()
            return jsonify({'success': False, 'error': 'Agent not found'}), 404

        local_hostname = socket.gethostname()
        agent_hostname = agent.get('hostname', '')
        agent_ip = agent.get('ip_address', '')
        is_local = (
            agent_hostname == local_hostname or
            agent_ip in ('127.0.0.1', '::1', 'localhost') or
            agent_hostname == 'localhost'
        )

        executed = False
        result_message = ''

        if is_local:
            # Execute directly on local machine
            try:
                # Build the actual shell command
                shell_cmd = f"sudo {ufw_command}"
                if command_type == 'delete':
                    shell_cmd = f"sudo ufw --force delete {params.get('rule_number')}"
                elif command_type in ('enable', 'disable'):
                    shell_cmd = f"echo 'y' | sudo ufw {command_type}"

                result = subprocess.run(
                    shell_cmd,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=15
                )

                executed = result.returncode == 0
                result_message = result.stdout.strip() if executed else result.stderr.strip()

                # Log to database for history
                cursor.execute("""
                    INSERT INTO agent_ufw_commands
                        (agent_id, command_uuid, command_type, params, ufw_command, status,
                         result_message, executed_at, created_at, created_by)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, NOW(), NOW(), %s)
                """, (
                    agent_id,
                    command_uuid,
                    command_type,
                    json.dumps(params),
                    ufw_command,
                    'completed' if executed else 'failed',
                    result_message,
                    get_current_user_id()
                ))

            except subprocess.TimeoutExpired:
                result_message = 'Command timed out'
                executed = False
            except Exception as e:
                result_message = str(e)
                executed = False
        else:
            # Queue for remote agent
            cursor.execute("""
                INSERT INTO agent_ufw_commands
                    (agent_id, command_uuid, command_type, params, ufw_command, status, created_at, created_by)
                VALUES (%s, %s, %s, %s, %s, 'pending', NOW(), %s)
            """, (
                agent_id,
                command_uuid,
                command_type,
                json.dumps(params),
                ufw_command,
                get_current_user_id()
            ))
            result_message = 'Command queued for agent'

        conn.commit()

        # If this is an IP block (block_ip action), also create an ip_blocks record
        block_id = None
        is_escalation = data.get('from_fail2ban', False) or data.get('escalation', False)

        if action_type == 'block_ip' and ip and (executed or not is_local):
            try:
                from blocking_engine import block_ip_manual
                block_result = block_ip_manual(
                    ip_address=ip,
                    reason='UFW block from dashboard',
                    user_id=get_current_user_id(),
                    duration_minutes=0,
                    agent_id=agent_id
                )
                if block_result.get('success'):
                    block_id = block_result.get('block_id')
            except Exception as block_err:
                print(f"Warning: Failed to create ip_blocks record: {block_err}")

            if log_block_event:
                event_type = 'escalate' if is_escalation else 'block'
                reason = 'Escalated from Fail2ban to permanent UFW block' if is_escalation else 'UFW block from dashboard'
                log_block_event(
                    ip_address=ip,
                    event_type=event_type,
                    block_source='ufw',
                    agent_id=agent_id,
                    reason=reason,
                    triggered_by='dashboard_manual',
                    user_id=get_current_user_id()
                )

            # If escalating from fail2ban, also unban from fail2ban
            if is_escalation and ip:
                try:
                    # Queue fail2ban unban command for the agent
                    unban_conn = get_connection()
                    unban_cursor = unban_conn.cursor()
                    unban_uuid = str(uuid.uuid4())
                    unban_cursor.execute("""
                        INSERT INTO fail2ban_commands
                            (agent_id, command_uuid, command_type, ip_address, jail_name, status, created_at)
                        VALUES (%s, %s, 'unban', %s, 'sshd', 'pending', NOW())
                    """, (agent_id, unban_uuid, ip))
                    unban_conn.commit()
                    unban_cursor.close()
                    unban_conn.close()
                    print(f"Queued fail2ban unban for {ip} after UFW escalation")
                except Exception as unban_err:
                    print(f"Warning: Failed to queue fail2ban unban after UFW escalation: {unban_err}")

        cursor.close()
        conn.close()

        # Invalidate cache
        cache = get_cache()
        cache.delete_pattern(f'ufw:{agent_id}')
        cache.delete_pattern('blocking')
        if is_escalation:
            cache.delete_pattern(f'fail2ban:{agent_id}')

        # Audit log
        AuditLogger.log_action(
            user_id=get_current_user_id(),
            action='ufw_quick_action',
            resource_type='ufw',
            resource_id=str(agent_id),
            details={
                'action_type': action_type,
                'command_id': command_uuid,
                'ufw_command': ufw_command,
                'executed': executed,
                'is_local': is_local
            },
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent')
        )

        if is_local:
            return jsonify({
                'success': executed,
                'executed': True,
                'message': result_message or ('Command executed successfully' if executed else 'Command failed'),
                'command_id': command_uuid,
                'ufw_command': ufw_command,
                'block_id': block_id
            })
        else:
            return jsonify({
                'success': True,
                'executed': False,
                'message': f'UFW command queued: {ufw_command}',
                'command_id': command_uuid,
                'ufw_command': ufw_command,
                'block_id': block_id
            })

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500
