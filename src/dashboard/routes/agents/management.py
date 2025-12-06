"""
SSH Guardian v3.0 - Agent Management
Handles agent CRUD operations for dashboard with Redis caching
"""

from flask import request, jsonify
import sys
from pathlib import Path

# Add project paths
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent.parent
sys.path.append(str(PROJECT_ROOT / "dbs"))
sys.path.append(str(PROJECT_ROOT / "src" / "core"))

from connection import get_connection
from cache import get_cache, cache_key
from auth import AuditLogger
from . import agent_routes


def get_current_user_id():
    """Get current user ID from request context"""
    if hasattr(request, 'current_user') and request.current_user:
        return request.current_user.get('user_id') or request.current_user.get('id')
    return None

# Cache TTLs
AGENTS_LIST_TTL = 30  # 30 seconds for agent list
AGENT_DETAILS_TTL = 60  # 1 minute for agent details


def invalidate_agents_cache():
    """Invalidate all agent-related caches"""
    cache = get_cache()
    cache.delete_pattern('agents')


@agent_routes.route('/agents/list', methods=['GET'])
def list_agents():
    """List all agents (for dashboard) with caching"""
    try:
        cache = get_cache()
        cache_k = cache_key('agents', 'list')

        # Try cache first
        cached = cache.get(cache_k)
        if cached is not None:
            return jsonify({
                'success': True,
                'agents': cached['agents'],
                'total': cached['total'],
                'from_cache': True
            })

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT
                id, agent_id, agent_uuid, hostname, display_name,
                agent_type, ip_address_primary, environment,
                status, health_status, last_heartbeat,
                version, is_active, is_approved,
                total_events_sent, created_at, updated_at,
                api_key
            FROM agents
            ORDER BY created_at DESC
        """)

        agents = cursor.fetchall()

        # Format timestamps
        for agent in agents:
            if agent['last_heartbeat']:
                agent['last_heartbeat'] = agent['last_heartbeat'].isoformat()
            if agent['created_at']:
                agent['created_at'] = agent['created_at'].isoformat()
            if agent['updated_at']:
                agent['updated_at'] = agent['updated_at'].isoformat()
            # Convert Decimal to int for total_events_sent
            if agent['total_events_sent'] is not None:
                agent['total_events_sent'] = int(agent['total_events_sent'])

        cursor.close()
        conn.close()

        # Cache the result
        cache_data = {'agents': agents, 'total': len(agents)}
        cache.set(cache_k, cache_data, AGENTS_LIST_TTL)

        return jsonify({
            'success': True,
            'agents': agents,
            'total': len(agents),
            'from_cache': False
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Failed to list agents: {str(e)}'
        }), 500


@agent_routes.route('/agents/<int:agent_id>/approve', methods=['POST'])
def approve_agent(agent_id):
    """Approve an agent"""
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Get agent info for audit log
        cursor.execute("SELECT hostname, agent_id FROM agents WHERE id = %s", (agent_id,))
        agent = cursor.fetchone()

        if not agent:
            cursor.close()
            conn.close()
            return jsonify({
                'success': False,
                'error': 'Agent not found'
            }), 404

        cursor.execute("""
            UPDATE agents
            SET is_approved = TRUE,
                approved_at = NOW(),
                updated_at = NOW()
            WHERE id = %s
        """, (agent_id,))

        conn.commit()
        cursor.close()
        conn.close()

        # Invalidate cache
        invalidate_agents_cache()

        # Audit log
        AuditLogger.log_action(
            user_id=get_current_user_id(),
            action='agent_approved',
            resource_type='agent',
            resource_id=str(agent_id),
            details={'hostname': agent['hostname'], 'agent_uuid': agent['agent_id']},
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent')
        )

        return jsonify({
            'success': True,
            'message': 'Agent approved successfully'
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Failed to approve agent: {str(e)}'
        }), 500


@agent_routes.route('/agents/<int:agent_id>/activate', methods=['POST'])
def activate_agent(agent_id):
    """Activate an agent"""
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Get agent info for audit log
        cursor.execute("SELECT hostname, agent_id FROM agents WHERE id = %s", (agent_id,))
        agent = cursor.fetchone()

        if not agent:
            cursor.close()
            conn.close()
            return jsonify({
                'success': False,
                'error': 'Agent not found'
            }), 404

        cursor.execute("""
            UPDATE agents
            SET is_active = TRUE,
                updated_at = NOW()
            WHERE id = %s
        """, (agent_id,))

        conn.commit()
        cursor.close()
        conn.close()

        # Invalidate cache
        invalidate_agents_cache()

        # Audit log
        AuditLogger.log_action(
            user_id=get_current_user_id(),
            action='agent_activated',
            resource_type='agent',
            resource_id=str(agent_id),
            details={'hostname': agent['hostname'], 'agent_uuid': agent['agent_id']},
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent')
        )

        return jsonify({
            'success': True,
            'message': 'Agent activated successfully'
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Failed to activate agent: {str(e)}'
        }), 500


@agent_routes.route('/agents/<int:agent_id>/deactivate', methods=['POST'])
def deactivate_agent(agent_id):
    """Deactivate an agent"""
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Get agent info for audit log
        cursor.execute("SELECT hostname, agent_id FROM agents WHERE id = %s", (agent_id,))
        agent = cursor.fetchone()

        if not agent:
            cursor.close()
            conn.close()
            return jsonify({
                'success': False,
                'error': 'Agent not found'
            }), 404

        cursor.execute("""
            UPDATE agents
            SET is_active = FALSE,
                status = 'offline',
                updated_at = NOW()
            WHERE id = %s
        """, (agent_id,))

        conn.commit()
        cursor.close()
        conn.close()

        # Invalidate cache
        invalidate_agents_cache()

        # Audit log
        AuditLogger.log_action(
            user_id=get_current_user_id(),
            action='agent_deactivated',
            resource_type='agent',
            resource_id=str(agent_id),
            details={'hostname': agent['hostname'], 'agent_uuid': agent['agent_id']},
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent')
        )

        return jsonify({
            'success': True,
            'message': 'Agent deactivated successfully'
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Failed to deactivate agent: {str(e)}'
        }), 500


@agent_routes.route('/agents/<int:agent_id>', methods=['GET'])
def get_agent_details(agent_id):
    """Get detailed agent information with caching"""
    try:
        cache = get_cache()
        cache_k = cache_key('agents', 'details', str(agent_id))

        # Try cache first
        cached = cache.get(cache_k)
        if cached is not None:
            return jsonify({
                'success': True,
                'agent': cached['agent'],
                'recent_heartbeats': cached['recent_heartbeats'],
                'recent_batches': cached['recent_batches'],
                'from_cache': True
            })

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Get agent details
        cursor.execute("""
            SELECT *
            FROM agents
            WHERE id = %s
        """, (agent_id,))

        agent = cursor.fetchone()

        if not agent:
            return jsonify({
                'success': False,
                'error': 'Agent not found'
            }), 404

        # Get recent heartbeats
        cursor.execute("""
            SELECT *
            FROM agent_heartbeats
            WHERE agent_id = %s
            ORDER BY heartbeat_timestamp DESC
            LIMIT 20
        """, (agent_id,))

        heartbeats = cursor.fetchall()

        # Get recent batches
        cursor.execute("""
            SELECT *
            FROM agent_log_batches
            WHERE agent_id = %s
            ORDER BY received_at DESC
            LIMIT 20
        """, (agent_id,))

        batches = cursor.fetchall()

        cursor.close()
        conn.close()

        # Format timestamps
        if agent['last_heartbeat']:
            agent['last_heartbeat'] = agent['last_heartbeat'].isoformat()
        if agent['created_at']:
            agent['created_at'] = agent['created_at'].isoformat()
        if agent['updated_at']:
            agent['updated_at'] = agent['updated_at'].isoformat()
        if agent.get('approved_at'):
            agent['approved_at'] = agent['approved_at'].isoformat()
        # Convert Decimal to int
        if agent['total_events_sent'] is not None:
            agent['total_events_sent'] = int(agent['total_events_sent'])

        for hb in heartbeats:
            if hb['heartbeat_timestamp']:
                hb['heartbeat_timestamp'] = hb['heartbeat_timestamp'].isoformat()
            # Convert Decimal fields
            for field in ['cpu_percent', 'memory_percent', 'disk_percent']:
                if field in hb and hb[field] is not None:
                    hb[field] = float(hb[field])

        for batch in batches:
            if batch['received_at']:
                batch['received_at'] = batch['received_at'].isoformat()
            if batch['processing_completed_at']:
                batch['processing_completed_at'] = batch['processing_completed_at'].isoformat()

        # Cache the result
        cache_data = {
            'agent': agent,
            'recent_heartbeats': heartbeats,
            'recent_batches': batches
        }
        cache.set(cache_k, cache_data, AGENT_DETAILS_TTL)

        return jsonify({
            'success': True,
            'agent': agent,
            'recent_heartbeats': heartbeats,
            'recent_batches': batches,
            'from_cache': False
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Failed to get agent details: {str(e)}'
        }), 500


@agent_routes.route('/agents/<int:agent_id>/regenerate-key', methods=['POST'])
def regenerate_api_key(agent_id):
    """Regenerate API key for an agent"""
    import uuid

    try:
        conn = get_connection()
        cursor = conn.cursor()

        # Generate new API key
        new_api_key = str(uuid.uuid4())

        cursor.execute("""
            UPDATE agents
            SET api_key = %s,
                updated_at = NOW()
            WHERE id = %s
        """, (new_api_key, agent_id))

        conn.commit()

        if cursor.rowcount == 0:
            return jsonify({
                'success': False,
                'error': 'Agent not found'
            }), 404

        cursor.close()
        conn.close()

        # Invalidate cache
        invalidate_agents_cache()

        return jsonify({
            'success': True,
            'message': 'API key regenerated successfully',
            'api_key': new_api_key
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Failed to regenerate API key: {str(e)}'
        }), 500


@agent_routes.route('/agents/<int:agent_id>/revoke-key', methods=['POST'])
def revoke_api_key(agent_id):
    """Revoke API key for an agent (set to NULL)"""
    try:
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            UPDATE agents
            SET api_key = NULL,
                is_active = FALSE,
                status = 'offline',
                updated_at = NOW()
            WHERE id = %s
        """, (agent_id,))

        conn.commit()

        if cursor.rowcount == 0:
            return jsonify({
                'success': False,
                'error': 'Agent not found'
            }), 404

        cursor.close()
        conn.close()

        # Invalidate cache
        invalidate_agents_cache()

        return jsonify({
            'success': True,
            'message': 'API key revoked and agent deactivated'
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Failed to revoke API key: {str(e)}'
        }), 500


@agent_routes.route('/agents/<int:agent_id>', methods=['DELETE'])
def delete_agent(agent_id):
    """Permanently delete an agent and all associated data"""
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # First, get the agent details for logging/confirmation
        cursor.execute("""
            SELECT id, agent_id, hostname, total_events_sent
            FROM agents WHERE id = %s
        """, (agent_id,))

        agent = cursor.fetchone()

        if not agent:
            cursor.close()
            conn.close()
            return jsonify({
                'success': False,
                'error': 'Agent not found'
            }), 404

        hostname = agent['hostname']
        agent_uuid = agent['agent_id']

        # Delete related data (cascaded by FK, but explicitly for clarity)
        # Delete agent heartbeats
        cursor.execute("DELETE FROM agent_heartbeats WHERE agent_id = %s", (agent_id,))
        heartbeats_deleted = cursor.rowcount

        # Delete agent log batches
        cursor.execute("DELETE FROM agent_log_batches WHERE agent_id = %s", (agent_id,))
        batches_deleted = cursor.rowcount

        # Delete agent firewall state
        cursor.execute("DELETE FROM agent_firewall_state WHERE agent_id = %s", (agent_id,))

        # Delete agent firewall rules
        cursor.execute("DELETE FROM agent_firewall_rules WHERE agent_id = %s", (agent_id,))

        # Delete agent firewall port forwards
        cursor.execute("DELETE FROM agent_port_forwards WHERE agent_id = %s", (agent_id,))

        # Delete agent firewall commands
        cursor.execute("DELETE FROM agent_firewall_commands WHERE agent_id = %s", (agent_id,))

        # Delete agent listening ports
        cursor.execute("DELETE FROM agent_listening_ports WHERE agent_id = %s", (agent_id,))

        # Delete agent system users
        cursor.execute("DELETE FROM agent_system_users WHERE agent_id = %s", (agent_id,))

        # Delete agent active connections
        cursor.execute("DELETE FROM agent_active_connections WHERE agent_id = %s", (agent_id,))

        # Delete agent command history
        cursor.execute("DELETE FROM agent_command_history WHERE agent_id = %s", (agent_id,))

        # Delete firewall suggestions
        cursor.execute("DELETE FROM firewall_suggestions WHERE agent_id = %s", (agent_id,))

        # Delete agent protected ports
        cursor.execute("DELETE FROM agent_protected_ports WHERE agent_id = %s", (agent_id,))

        # Finally, delete the agent itself
        cursor.execute("DELETE FROM agents WHERE id = %s", (agent_id,))

        conn.commit()
        cursor.close()
        conn.close()

        # Invalidate all caches
        cache = get_cache()
        cache.delete_pattern('agents')
        cache.delete_pattern(f'firewall:{agent_id}')

        # Audit log
        AuditLogger.log_action(
            user_id=get_current_user_id(),
            action='agent_deleted',
            resource_type='agent',
            resource_id=str(agent_id),
            details={
                'hostname': hostname,
                'agent_uuid': agent_uuid,
                'heartbeats_deleted': heartbeats_deleted,
                'batches_deleted': batches_deleted
            },
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent')
        )

        return jsonify({
            'success': True,
            'message': f'Agent "{hostname}" deleted successfully',
            'deleted': {
                'agent_id': agent_uuid,
                'hostname': hostname,
                'heartbeats': heartbeats_deleted,
                'batches': batches_deleted
            }
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Failed to delete agent: {str(e)}'
        }), 500
