"""
SSH Guardian v3.0 - Agent Authentication
API key authentication decorator for agent endpoints
"""

from flask import request, jsonify
from functools import wraps
import sys
from pathlib import Path

# Add project paths
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent.parent
sys.path.append(str(PROJECT_ROOT / "dbs"))

from connection import get_connection


def require_api_key(f):
    """Decorator to require API key authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        agent_id = request.headers.get('X-Agent-ID')

        if not api_key or not agent_id:
            return jsonify({
                'success': False,
                'error': 'Missing API key or Agent ID in headers'
            }), 401

        # Verify API key and agent_id match in database
        try:
            conn = get_connection()
            cursor = conn.cursor(dictionary=True)

            cursor.execute("""
                SELECT id, agent_id, hostname, is_active, is_approved
                FROM agents
                WHERE api_key = %s AND agent_id = %s
            """, (api_key, agent_id))

            agent = cursor.fetchone()
            cursor.close()
            conn.close()

            if not agent:
                return jsonify({
                    'success': False,
                    'error': 'Invalid API key or Agent ID'
                }), 401

            if not agent['is_active']:
                return jsonify({
                    'success': False,
                    'error': 'Agent is not active'
                }), 403

            if not agent['is_approved']:
                return jsonify({
                    'success': False,
                    'error': 'Agent is not approved yet. Please approve the agent in the dashboard.'
                }), 403

            # Add agent info to request context
            request.agent = agent

        except Exception as e:
            return jsonify({
                'success': False,
                'error': f'Authentication error: {str(e)}'
            }), 500

        return f(*args, **kwargs)

    return decorated_function
