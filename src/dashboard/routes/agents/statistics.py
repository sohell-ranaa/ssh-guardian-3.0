"""
SSH Guardian v3.0 - Agent Statistics
Provides agent analytics and statistics
"""

from flask import jsonify
import sys
from pathlib import Path

# Add project paths
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent.parent
sys.path.append(str(PROJECT_ROOT / "dbs"))

from connection import get_connection
from . import agent_routes


@agent_routes.route('/agents/stats', methods=['GET'])
def agent_stats():
    """Get agent statistics"""
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Total agents
        cursor.execute("SELECT COUNT(*) as count FROM agents")
        total_agents = cursor.fetchone()['count']

        # Active agents
        cursor.execute("SELECT COUNT(*) as count FROM agents WHERE is_active = TRUE")
        active_agents = cursor.fetchone()['count']

        # Approved agents
        cursor.execute("SELECT COUNT(*) as count FROM agents WHERE is_approved = TRUE")
        approved_agents = cursor.fetchone()['count']

        # Online agents
        cursor.execute("""
            SELECT COUNT(*) as count
            FROM agents
            WHERE status = 'online'
            AND last_heartbeat >= DATE_SUB(NOW(), INTERVAL 5 MINUTE)
        """)
        online_agents = cursor.fetchone()['count']

        # Total events from agents
        cursor.execute("SELECT SUM(total_events_sent) as count FROM agents")
        total_events = cursor.fetchone()['count'] or 0

        # Total batches
        cursor.execute("SELECT COUNT(*) as count FROM agent_log_batches")
        total_batches = cursor.fetchone()['count']

        # Recent batches (last 24h)
        cursor.execute("""
            SELECT COUNT(*) as count
            FROM agent_log_batches
            WHERE received_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
        """)
        recent_batches = cursor.fetchone()['count']

        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'stats': {
                'total_agents': total_agents,
                'active_agents': active_agents,
                'approved_agents': approved_agents,
                'online_agents': online_agents,
                'total_events_from_agents': total_events,
                'total_batches': total_batches,
                'batches_last_24h': recent_batches
            }
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Failed to get stats: {str(e)}'
        }), 500
