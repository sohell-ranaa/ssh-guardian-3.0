"""
SSH Guardian v3.0 - Simulation Target Server Management
API endpoints for managing servers that can receive live attack simulations
"""

import uuid
import socket
import requests
from flask import request, jsonify
import sys
from pathlib import Path

# Add project paths
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent.parent
sys.path.append(str(PROJECT_ROOT / "dbs"))

from connection import get_connection
from . import live_sim_routes
from src.core.auth import login_required


def is_local_ip(ip_address: str) -> bool:
    """Check if IP is local (same machine as dashboard)"""
    local_ips = ['127.0.0.1', 'localhost', '::1']
    try:
        hostname = socket.gethostname()
        local_ips.append(socket.gethostbyname(hostname))
        for info in socket.getaddrinfo(hostname, None):
            local_ips.append(info[4][0])
    except:
        pass
    return ip_address in local_ips


@live_sim_routes.route('/targets', methods=['GET'])
@login_required
def list_targets():
    """Get all simulation target servers"""
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT
                st.id,
                st.name,
                st.description,
                st.ip_address,
                st.port,
                st.agent_id,
                st.is_active,
                st.last_tested_at,
                st.test_status,
                st.created_at,
                st.updated_at,
                a.hostname as agent_hostname
            FROM simulation_targets st
            LEFT JOIN agents a ON st.agent_id = a.id
            ORDER BY st.name
        """)

        targets = cursor.fetchall()

        # Format datetime fields
        for target in targets:
            if target.get('last_tested_at'):
                target['last_tested_at'] = target['last_tested_at'].isoformat()
            if target.get('created_at'):
                target['created_at'] = target['created_at'].isoformat()
            if target.get('updated_at'):
                target['updated_at'] = target['updated_at'].isoformat()

        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'targets': targets,
            'count': len(targets)
        })

    except Exception as e:
        print(f"[SimTargets] Error listing targets: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@live_sim_routes.route('/targets', methods=['POST'])
@login_required
def add_target():
    """Add a new simulation target server"""
    try:
        data = request.get_json()

        name = data.get('name', '').strip()
        ip_address = data.get('ip_address', '').strip()
        port = data.get('port', 5001)
        description = data.get('description', '').strip()
        agent_id = data.get('agent_id')  # Optional link to existing agent

        if not name or not ip_address:
            return jsonify({
                'success': False,
                'error': 'Name and IP address are required'
            }), 400

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Check for duplicate name
        cursor.execute("SELECT id FROM simulation_targets WHERE name = %s", (name,))
        if cursor.fetchone():
            cursor.close()
            conn.close()
            return jsonify({
                'success': False,
                'error': f'A target with name "{name}" already exists'
            }), 400

        # Check for duplicate IP:port combination
        cursor.execute(
            "SELECT id, name FROM simulation_targets WHERE ip_address = %s AND port = %s",
            (ip_address, port)
        )
        existing = cursor.fetchone()
        if existing:
            cursor.close()
            conn.close()
            return jsonify({
                'success': False,
                'error': f'A target with IP {ip_address}:{port} already exists ("{existing["name"]}")'
            }), 400

        # Generate API key for this target
        api_key = str(uuid.uuid4())

        cursor.execute("""
            INSERT INTO simulation_targets
            (name, description, ip_address, port, api_key, agent_id)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (name, description, ip_address, port, api_key, agent_id))

        target_id = cursor.lastrowid
        conn.commit()
        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'message': 'Target added successfully',
            'target_id': target_id,
            'api_key': api_key,
            'note': 'Save this API key - use it when installing the simulation receiver on the target server'
        }), 201

    except Exception as e:
        print(f"[SimTargets] Error adding target: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@live_sim_routes.route('/targets/<int:target_id>', methods=['GET'])
@login_required
def get_target(target_id):
    """Get details for a specific target server"""
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT
                st.*,
                a.hostname as agent_hostname
            FROM simulation_targets st
            LEFT JOIN agents a ON st.agent_id = a.id
            WHERE st.id = %s
        """, (target_id,))

        target = cursor.fetchone()
        cursor.close()
        conn.close()

        if not target:
            return jsonify({'success': False, 'error': 'Target not found'}), 404

        # Format datetime fields
        if target.get('last_tested_at'):
            target['last_tested_at'] = target['last_tested_at'].isoformat()
        if target.get('created_at'):
            target['created_at'] = target['created_at'].isoformat()
        if target.get('updated_at'):
            target['updated_at'] = target['updated_at'].isoformat()

        return jsonify({
            'success': True,
            'target': target
        })

    except Exception as e:
        print(f"[SimTargets] Error getting target {target_id}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@live_sim_routes.route('/targets/<int:target_id>', methods=['PUT'])
@login_required
def update_target(target_id):
    """Update a target server"""
    try:
        data = request.get_json()

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Check if target exists
        cursor.execute("SELECT * FROM simulation_targets WHERE id = %s", (target_id,))
        current = cursor.fetchone()
        if not current:
            cursor.close()
            conn.close()
            return jsonify({'success': False, 'error': 'Target not found'}), 404

        # Check for duplicate name (if changing)
        if 'name' in data and data['name'].strip() != current['name']:
            cursor.execute(
                "SELECT id FROM simulation_targets WHERE name = %s AND id != %s",
                (data['name'].strip(), target_id)
            )
            if cursor.fetchone():
                cursor.close()
                conn.close()
                return jsonify({
                    'success': False,
                    'error': f'A target with name "{data["name"]}" already exists'
                }), 400

        # Check for duplicate IP:port (if changing either)
        new_ip = data.get('ip_address', current['ip_address']).strip() if 'ip_address' in data else current['ip_address']
        new_port = data.get('port', current['port'])

        if new_ip != current['ip_address'] or new_port != current['port']:
            cursor.execute(
                "SELECT id, name FROM simulation_targets WHERE ip_address = %s AND port = %s AND id != %s",
                (new_ip, new_port, target_id)
            )
            existing = cursor.fetchone()
            if existing:
                cursor.close()
                conn.close()
                return jsonify({
                    'success': False,
                    'error': f'A target with IP {new_ip}:{new_port} already exists ("{existing["name"]}")'
                }), 400

        # Build update query dynamically based on provided fields
        updates = []
        values = []

        if 'name' in data:
            updates.append('name = %s')
            values.append(data['name'].strip())
        if 'description' in data:
            updates.append('description = %s')
            values.append(data['description'].strip() if data['description'] else '')
        if 'ip_address' in data:
            updates.append('ip_address = %s')
            values.append(data['ip_address'].strip())
        if 'port' in data:
            updates.append('port = %s')
            values.append(data['port'])
        if 'is_active' in data:
            updates.append('is_active = %s')
            values.append(data['is_active'])
        if 'agent_id' in data:
            updates.append('agent_id = %s')
            values.append(data['agent_id'] if data['agent_id'] else None)

        if not updates:
            cursor.close()
            conn.close()
            return jsonify({'success': False, 'error': 'No fields to update'}), 400

        values.append(target_id)

        cursor.execute(f"""
            UPDATE simulation_targets
            SET {', '.join(updates)}
            WHERE id = %s
        """, tuple(values))

        conn.commit()
        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'message': 'Target updated successfully'
        })

    except Exception as e:
        print(f"[SimTargets] Error updating target {target_id}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@live_sim_routes.route('/targets/<int:target_id>', methods=['DELETE'])
@login_required
def delete_target(target_id):
    """Delete a target server"""
    try:
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("DELETE FROM simulation_targets WHERE id = %s", (target_id,))

        if cursor.rowcount == 0:
            cursor.close()
            conn.close()
            return jsonify({'success': False, 'error': 'Target not found'}), 404

        conn.commit()
        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'message': 'Target deleted successfully'
        })

    except Exception as e:
        print(f"[SimTargets] Error deleting target {target_id}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@live_sim_routes.route('/targets/<int:target_id>/test', methods=['POST'])
@login_required
def test_target(target_id):
    """Test connectivity AND API key authentication to a target server"""
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT id, name, ip_address, port, api_key
            FROM simulation_targets
            WHERE id = %s
        """, (target_id,))

        target = cursor.fetchone()

        if not target:
            cursor.close()
            conn.close()
            return jsonify({'success': False, 'error': 'Target not found'}), 404

        health_data = None
        api_key_valid = False
        test_status = 'failed'
        test_message = ''

        # Step 1: Try to connect to the target's health endpoint (no auth required)
        health_url = f"http://{target['ip_address']}:{target['port']}/api/simulation/health"

        try:
            response = requests.get(health_url, timeout=10)
            health_data = response.json()

            if health_data.get('success'):
                # Step 2: Test API key authentication by calling test-write endpoint
                test_write_url = f"http://{target['ip_address']}:{target['port']}/api/simulation/test-write"

                try:
                    auth_response = requests.post(
                        test_write_url,
                        headers={
                            'X-API-Key': target['api_key'],
                            'Content-Type': 'application/json'
                        },
                        json={},
                        timeout=10
                    )

                    if auth_response.status_code == 200:
                        auth_data = auth_response.json()
                        if auth_data.get('success'):
                            test_status = 'success'
                            api_key_valid = True
                            test_message = 'Connection and API key verified successfully'
                        else:
                            test_status = 'failed'
                            test_message = f"Write test failed: {auth_data.get('error', 'Unknown error')}"
                    elif auth_response.status_code == 401:
                        test_status = 'failed'
                        test_message = 'API key required but not accepted'
                    elif auth_response.status_code == 403:
                        test_status = 'failed'
                        test_message = 'Invalid API key - key on receiver does not match dashboard'
                    else:
                        test_status = 'failed'
                        test_message = f"API key test failed with status {auth_response.status_code}"

                except requests.exceptions.RequestException as e:
                    test_status = 'failed'
                    test_message = f"API key verification failed: {str(e)}"
            else:
                test_status = 'failed'
                test_message = 'Health check returned unsuccessful status'

        except requests.exceptions.ConnectionError:
            test_status = 'failed'
            test_message = 'Connection refused - is the simulation receiver running?'
        except requests.exceptions.Timeout:
            test_status = 'failed'
            test_message = 'Connection timeout - check firewall and network'
        except Exception as e:
            test_status = 'failed'
            test_message = str(e)

        # Update target with test result
        cursor.execute("""
            UPDATE simulation_targets
            SET last_tested_at = NOW(), test_status = %s
            WHERE id = %s
        """, (test_status, target_id))

        conn.commit()
        cursor.close()
        conn.close()

        return jsonify({
            'success': test_status == 'success',
            'target_id': target_id,
            'target_name': target['name'],
            'test_status': test_status,
            'message': test_message,
            'api_key_valid': api_key_valid,
            'health_data': health_data
        })

    except Exception as e:
        print(f"[SimTargets] Error testing target {target_id}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@live_sim_routes.route('/targets/<int:target_id>/regenerate-key', methods=['POST'])
@login_required
def regenerate_api_key(target_id):
    """Regenerate API key for a target server"""
    try:
        new_api_key = str(uuid.uuid4())

        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            UPDATE simulation_targets
            SET api_key = %s
            WHERE id = %s
        """, (new_api_key, target_id))

        if cursor.rowcount == 0:
            cursor.close()
            conn.close()
            return jsonify({'success': False, 'error': 'Target not found'}), 404

        conn.commit()
        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'message': 'API key regenerated successfully',
            'api_key': new_api_key,
            'note': 'Update the simulation receiver on the target server with this new key'
        })

    except Exception as e:
        print(f"[SimTargets] Error regenerating key for target {target_id}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@live_sim_routes.route('/targets/from-agents', methods=['GET'])
@login_required
def get_agents_for_targets():
    """Get list of registered agents with their simulation target configuration"""
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT
                a.id as agent_id,
                a.hostname,
                a.display_name,
                a.ip_address,
                a.status as agent_status,
                a.is_active as agent_active,
                a.last_heartbeat,
                st.id as sim_target_id,
                st.name as sim_name,
                st.port as sim_port,
                st.api_key,
                st.is_active as sim_active,
                st.test_status,
                st.last_tested_at
            FROM agents a
            LEFT JOIN simulation_targets st ON a.id = st.agent_id
            WHERE a.is_active = TRUE
            ORDER BY a.hostname
        """)

        agents = cursor.fetchall()

        for agent in agents:
            if agent.get('last_heartbeat'):
                agent['last_heartbeat'] = agent['last_heartbeat'].isoformat()
            if agent.get('last_tested_at'):
                agent['last_tested_at'] = agent['last_tested_at'].isoformat()
            # Mark if simulation is enabled
            agent['sim_enabled'] = agent.get('sim_target_id') is not None
            # Mark if this is a local agent (same machine as dashboard)
            agent['is_local'] = is_local_ip(agent.get('ip_address', ''))

        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'agents': agents,
            'count': len(agents)
        })

    except Exception as e:
        print(f"[SimTargets] Error getting agents: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@live_sim_routes.route('/targets/enable-agent/<int:agent_id>', methods=['POST'])
@login_required
def enable_simulation_for_agent(agent_id):
    """Enable simulation for an existing agent - auto-creates simulation target"""
    try:
        data = request.get_json() or {}
        port = data.get('port', 5001)
        custom_ip = data.get('ip_address', '').strip()  # Allow custom IP override

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Get agent details
        cursor.execute("""
            SELECT id, hostname, display_name, ip_address
            FROM agents WHERE id = %s AND is_active = TRUE
        """, (agent_id,))

        agent = cursor.fetchone()
        if not agent:
            cursor.close()
            conn.close()
            return jsonify({'success': False, 'error': 'Agent not found or inactive'}), 404

        # Check if already has simulation target
        cursor.execute("SELECT id FROM simulation_targets WHERE agent_id = %s", (agent_id,))
        if cursor.fetchone():
            cursor.close()
            conn.close()
            return jsonify({'success': False, 'error': 'Simulation already enabled for this agent'}), 400

        # Use custom IP if provided, otherwise use agent's registered IP
        ip_address = custom_ip if custom_ip else agent['ip_address']

        if not ip_address:
            cursor.close()
            conn.close()
            return jsonify({'success': False, 'error': 'IP address is required'}), 400

        # Check for duplicate IP:port
        cursor.execute(
            "SELECT id, name FROM simulation_targets WHERE ip_address = %s AND port = %s",
            (ip_address, port)
        )
        existing = cursor.fetchone()
        if existing:
            cursor.close()
            conn.close()
            return jsonify({
                'success': False,
                'error': f'Port {port} already in use on {ip_address} by "{existing["name"]}"'
            }), 400

        # Generate API key and create simulation target
        api_key = str(uuid.uuid4())
        name = agent['display_name'] or agent['hostname']

        cursor.execute("""
            INSERT INTO simulation_targets
            (name, description, ip_address, port, api_key, agent_id, is_active)
            VALUES (%s, %s, %s, %s, %s, %s, TRUE)
        """, (
            name,
            f"Auto-configured from agent {agent['hostname']}",
            ip_address,
            port,
            api_key,
            agent_id
        ))

        target_id = cursor.lastrowid
        conn.commit()
        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'message': 'Simulation enabled for agent',
            'target_id': target_id,
            'api_key': api_key,
            'agent_name': name,
            'ip_address': ip_address,
            'port': port
        }), 201

    except Exception as e:
        print(f"[SimTargets] Error enabling simulation for agent {agent_id}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@live_sim_routes.route('/targets/disable-agent/<int:agent_id>', methods=['POST'])
@login_required
def disable_simulation_for_agent(agent_id):
    """Disable simulation for an agent - removes simulation target"""
    try:
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("DELETE FROM simulation_targets WHERE agent_id = %s", (agent_id,))

        if cursor.rowcount == 0:
            cursor.close()
            conn.close()
            return jsonify({'success': False, 'error': 'No simulation target found for this agent'}), 404

        conn.commit()
        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'message': 'Simulation disabled for agent'
        })

    except Exception as e:
        print(f"[SimTargets] Error disabling simulation for agent {agent_id}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@live_sim_routes.route('/targets/update-agent/<int:agent_id>', methods=['PUT'])
@login_required
def update_agent_simulation_config(agent_id):
    """Update simulation configuration for an agent"""
    try:
        data = request.get_json() or {}

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Get current simulation target for this agent
        cursor.execute("""
            SELECT st.*, a.ip_address as agent_ip_address
            FROM simulation_targets st
            JOIN agents a ON st.agent_id = a.id
            WHERE st.agent_id = %s
        """, (agent_id,))

        target = cursor.fetchone()
        if not target:
            cursor.close()
            conn.close()
            return jsonify({'success': False, 'error': 'No simulation target found for this agent'}), 404

        # Build update query
        updates = []
        values = []

        if 'port' in data:
            new_port = data['port']
            # Check for duplicate IP:port
            cursor.execute(
                "SELECT id FROM simulation_targets WHERE ip_address = %s AND port = %s AND id != %s",
                (target['ip_address'], new_port, target['id'])
            )
            if cursor.fetchone():
                cursor.close()
                conn.close()
                return jsonify({'success': False, 'error': f'Port {new_port} already in use'}), 400
            updates.append('port = %s')
            values.append(new_port)

        if 'is_active' in data:
            updates.append('is_active = %s')
            values.append(data['is_active'])

        if not updates:
            cursor.close()
            conn.close()
            return jsonify({'success': False, 'error': 'No fields to update'}), 400

        values.append(target['id'])
        cursor.execute(f"""
            UPDATE simulation_targets SET {', '.join(updates)} WHERE id = %s
        """, tuple(values))

        conn.commit()
        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'message': 'Configuration updated'
        })

    except Exception as e:
        print(f"[SimTargets] Error updating agent {agent_id} simulation config: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@live_sim_routes.route('/targets/regenerate-key-agent/<int:agent_id>', methods=['POST'])
@login_required
def regenerate_api_key_for_agent(agent_id):
    """Regenerate API key for an agent's simulation target"""
    try:
        new_api_key = str(uuid.uuid4())

        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            UPDATE simulation_targets SET api_key = %s WHERE agent_id = %s
        """, (new_api_key, agent_id))

        if cursor.rowcount == 0:
            cursor.close()
            conn.close()
            return jsonify({'success': False, 'error': 'No simulation target found for this agent'}), 404

        conn.commit()
        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'message': 'API key regenerated',
            'api_key': new_api_key
        })

    except Exception as e:
        print(f"[SimTargets] Error regenerating key for agent {agent_id}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@live_sim_routes.route('/targets/test-agent/<int:agent_id>', methods=['POST'])
@login_required
def test_agent_simulation(agent_id):
    """Test connectivity AND API key for an agent's simulation target"""
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Get simulation target for this agent
        cursor.execute("""
            SELECT st.id, st.name, st.ip_address, st.port, st.api_key, a.hostname
            FROM simulation_targets st
            JOIN agents a ON st.agent_id = a.id
            WHERE st.agent_id = %s
        """, (agent_id,))

        target = cursor.fetchone()

        if not target:
            cursor.close()
            conn.close()
            return jsonify({
                'success': False,
                'error': 'No simulation target found for this agent'
            }), 404

        health_data = None
        api_key_valid = False
        test_status = 'failed'
        test_message = ''
        is_local = is_local_ip(target['ip_address'])

        if is_local:
            # LOCAL TARGET: Test write access to auth.log directly
            import os
            log_file = '/var/log/auth.log'

            if os.path.exists(log_file) and os.access(log_file, os.W_OK):
                test_status = 'success'
                api_key_valid = True  # No API key needed for local
                test_message = 'Local target: auth.log is writable (no receiver needed)'
                health_data = {'local': True, 'log_file': log_file, 'writable': True}
            elif os.path.exists(log_file):
                test_status = 'failed'
                test_message = f'Local target: No write permission to {log_file}. Run dashboard with sudo.'
                health_data = {'local': True, 'log_file': log_file, 'writable': False}
            else:
                test_status = 'failed'
                test_message = f'Local target: {log_file} does not exist'
                health_data = {'local': True, 'log_file': log_file, 'exists': False}
        else:
            # REMOTE TARGET: Test HTTP connection to simulation receiver
            health_url = f"http://{target['ip_address']}:{target['port']}/api/simulation/health"

            try:
                response = requests.get(health_url, timeout=10)
                health_data = response.json()

                if health_data.get('success'):
                    # Step 2: Test API key with test-write endpoint
                    test_write_url = f"http://{target['ip_address']}:{target['port']}/api/simulation/test-write"

                    try:
                        auth_response = requests.post(
                            test_write_url,
                            headers={
                                'X-API-Key': target['api_key'],
                                'Content-Type': 'application/json'
                            },
                            json={},
                            timeout=10
                        )

                        if auth_response.status_code == 200:
                            auth_data = auth_response.json()
                            if auth_data.get('success'):
                                test_status = 'success'
                                api_key_valid = True
                                test_message = 'Remote target: Connection and API key verified'
                            else:
                                test_status = 'failed'
                                test_message = f"Write test failed: {auth_data.get('error', 'Unknown error')}"
                        elif auth_response.status_code == 401:
                            test_status = 'failed'
                            test_message = 'API key required - receiver may not have key configured'
                        elif auth_response.status_code == 403:
                            test_status = 'failed'
                            test_message = 'Invalid API key - key on receiver does not match dashboard'
                        else:
                            test_status = 'failed'
                            test_message = f"API key test failed with status {auth_response.status_code}"

                    except requests.exceptions.RequestException as e:
                        test_status = 'failed'
                        test_message = f"API key verification failed: {str(e)}"
                else:
                    test_status = 'failed'
                    test_message = 'Health check returned unsuccessful status'

            except requests.exceptions.ConnectionError:
                test_status = 'failed'
                test_message = 'Connection refused - is simulation_receiver.py running on the agent?'
            except requests.exceptions.Timeout:
                test_status = 'failed'
                test_message = 'Connection timeout - check firewall allows port ' + str(target['port'])
            except Exception as e:
                test_status = 'failed'
                test_message = str(e)

        # Update simulation target with test result
        cursor.execute("""
            UPDATE simulation_targets
            SET last_tested_at = NOW(), test_status = %s
            WHERE id = %s
        """, (test_status, target['id']))

        conn.commit()
        cursor.close()
        conn.close()

        return jsonify({
            'success': test_status == 'success',
            'agent_id': agent_id,
            'target_name': target['name'],
            'hostname': target['hostname'],
            'test_status': test_status,
            'message': test_message,
            'api_key_valid': api_key_valid,
            'is_local': is_local,
            'health_data': health_data
        })

    except Exception as e:
        print(f"[SimTargets] Error testing agent {agent_id} simulation: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500
