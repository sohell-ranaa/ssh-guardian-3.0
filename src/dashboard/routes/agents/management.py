"""
SSH Guardian v3.0 - Agent Management
Handles agent CRUD operations for dashboard
"""

from flask import request, jsonify
import sys
from pathlib import Path

# Add project paths
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent.parent
sys.path.append(str(PROJECT_ROOT / "dbs"))

from connection import get_connection
from . import agent_routes


@agent_routes.route('/agents/list', methods=['GET'])
def list_agents():
    """List all agents (for dashboard)"""
    try:
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

        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'agents': agents,
            'total': len(agents)
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
        cursor = conn.cursor()

        cursor.execute("""
            UPDATE agents
            SET is_approved = TRUE,
                approved_at = NOW(),
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
        cursor = conn.cursor()

        cursor.execute("""
            UPDATE agents
            SET is_active = TRUE,
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
        cursor = conn.cursor()

        cursor.execute("""
            UPDATE agents
            SET is_active = FALSE,
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
    """Get detailed agent information"""
    try:
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

        for hb in heartbeats:
            if hb['heartbeat_timestamp']:
                hb['heartbeat_timestamp'] = hb['heartbeat_timestamp'].isoformat()

        for batch in batches:
            if batch['received_at']:
                batch['received_at'] = batch['received_at'].isoformat()
            if batch['processing_completed_at']:
                batch['processing_completed_at'] = batch['processing_completed_at'].isoformat()

        return jsonify({
            'success': True,
            'agent': agent,
            'recent_heartbeats': heartbeats,
            'recent_batches': batches
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

        return jsonify({
            'success': True,
            'message': 'API key revoked and agent deactivated'
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Failed to revoke API key: {str(e)}'
        }), 500
