"""
API Keys Routes - Dashboard API for managing agent API keys
"""
import uuid
import sys
from pathlib import Path
from flask import Blueprint, jsonify, request

# Add database path
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
sys.path.append(str(PROJECT_ROOT / "dbs"))
sys.path.append(str(PROJECT_ROOT / "src" / "core"))

from connection import get_connection
from cache import get_cache, cache_key

api_keys_routes = Blueprint('api_keys', __name__)

# Cache TTL
AGENTS_LIST_TTL = 300


def invalidate_api_keys_cache():
    """Invalidate all api_keys-related caches"""
    cache = get_cache()
    cache.delete_pattern('api_keys')


@api_keys_routes.route('/create', methods=['POST'])
def create_api_key():
    """
    Create a new agent with API key
    Body params:
    - display_name: Agent display name (required)
    - hostname: Agent hostname (required)
    - environment: Environment (production, staging, development, testing)
    - agent_type: Agent type (primary, secondary, monitor_only)
    """
    try:
        data = request.get_json()

        display_name = data.get('display_name', '').strip()
        hostname = data.get('hostname', '').strip()
        environment = data.get('environment', 'production')
        agent_type = data.get('agent_type', 'secondary')

        if not display_name or not hostname:
            return jsonify({
                'success': False,
                'error': 'display_name and hostname are required'
            }), 400

        # Generate unique identifiers
        agent_uuid = str(uuid.uuid4())
        agent_id = f"agent-{uuid.uuid4().hex[:16]}"
        api_key = str(uuid.uuid4())

        conn = get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("""
                INSERT INTO agents (
                    agent_uuid, agent_id, api_key, hostname, display_name,
                    agent_type, environment, status, health_status,
                    is_active, is_approved, created_at, updated_at
                ) VALUES (
                    %s, %s, %s, %s, %s,
                    %s, %s, 'offline', 'healthy',
                    TRUE, TRUE, NOW(), NOW()
                )
            """, (agent_uuid, agent_id, api_key, hostname, display_name,
                  agent_type, environment))

            conn.commit()
            new_agent_id = cursor.lastrowid

            cursor.close()
            conn.close()

            # Invalidate cache
            invalidate_api_keys_cache()

            return jsonify({
                'success': True,
                'message': 'Agent created successfully',
                'api_key': api_key,
                'agent_id': new_agent_id,
                'agent_uuid': agent_uuid
            })

        except Exception as e:
            conn.rollback()
            cursor.close()
            conn.close()

            # Check for duplicate hostname
            if 'Duplicate entry' in str(e):
                return jsonify({
                    'success': False,
                    'error': f'An agent with hostname "{hostname}" already exists'
                }), 400

            raise e

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@api_keys_routes.route('/list', methods=['GET'])
def list_api_keys():
    """
    List all API keys with agent info with caching
    Query params:
    - active_only: If true, only return active agents
    """
    try:
        active_only = request.args.get('active_only', 'false').lower() == 'true'

        # Generate cache key
        cache = get_cache()
        cache_k = cache_key('api_keys', 'list', f'active_{active_only}')

        # Try cache first
        cached = cache.get(cache_k)
        if cached is not None:
            cached['from_cache'] = True
            return jsonify(cached), 200

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        query = """
            SELECT
                id, agent_id, agent_uuid, hostname, display_name,
                agent_type, environment, status, health_status,
                api_key, is_active, is_approved,
                last_heartbeat, total_events_sent,
                created_at, updated_at
            FROM agents
        """

        if active_only:
            query += " WHERE is_active = TRUE"

        query += " ORDER BY created_at DESC"

        cursor.execute(query)
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

        result = {
            'success': True,
            'data': {
                'api_keys': agents,
                'total': len(agents)
            },
            'from_cache': False
        }

        # Cache the result
        cache.set(cache_k, result, AGENTS_LIST_TTL)

        return jsonify(result)

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@api_keys_routes.route('/<int:agent_id>', methods=['DELETE'])
def delete_agent(agent_id):
    """Delete an agent and its API key"""
    try:
        conn = get_connection()
        cursor = conn.cursor()

        # First check if agent exists
        cursor.execute("SELECT id FROM agents WHERE id = %s", (agent_id,))
        if not cursor.fetchone():
            cursor.close()
            conn.close()
            return jsonify({
                'success': False,
                'error': 'Agent not found'
            }), 404

        # Delete related records first
        cursor.execute("DELETE FROM agent_heartbeats WHERE agent_id = %s", (agent_id,))
        cursor.execute("DELETE FROM agent_log_batches WHERE agent_id = %s", (agent_id,))

        # Delete the agent
        cursor.execute("DELETE FROM agents WHERE id = %s", (agent_id,))

        conn.commit()
        cursor.close()
        conn.close()

        # Invalidate cache
        invalidate_api_keys_cache()

        return jsonify({
            'success': True,
            'message': 'Agent deleted successfully'
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
