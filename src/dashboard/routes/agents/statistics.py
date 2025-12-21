"""
SSH Guardian v3.0 - Agent Statistics
Provides agent analytics and statistics with Redis caching
"""

from flask import jsonify
import sys
from pathlib import Path

# Add project paths
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent.parent
sys.path.append(str(PROJECT_ROOT / "dbs"))
sys.path.append(str(PROJECT_ROOT / "src" / "core"))

from connection import get_connection
from cache import get_cache, cache_key
from . import agent_routes

# Cache TTL for agent stats (30 seconds - agents change status frequently)
AGENT_STATS_TTL = 30


@agent_routes.route('/agents/stats', methods=['GET'])
def agent_stats():
    """Get agent statistics with caching"""
    try:
        cache = get_cache()
        cache_k = cache_key('agents', 'stats')

        # Try cache first
        cached = cache.get(cache_k)
        if cached is not None:
            return jsonify({
                'success': True,
                'stats': cached,
                'from_cache': True
            })

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

        # Total events (actual count from auth_events table)
        cursor.execute("SELECT COUNT(*) as count FROM auth_events")
        total_events = cursor.fetchone()['count'] or 0

        # Total batches
        cursor.execute("SELECT COUNT(*) as count FROM agent_log_batches")
        total_batches = cursor.fetchone()['count']

        # Recent batches (last 24h) - v3.1: use created_at instead of received_at
        cursor.execute("""
            SELECT COUNT(*) as count
            FROM agent_log_batches
            WHERE created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
        """)
        recent_batches = cursor.fetchone()['count']

        cursor.close()
        conn.close()

        stats = {
            'total_agents': total_agents,
            'active_agents': active_agents,
            'approved_agents': approved_agents,
            'online_agents': online_agents,
            'total_events': int(total_events),
            'total_batches': total_batches,
            'batches_last_24h': recent_batches
        }

        # Cache the result
        cache.set(cache_k, stats, AGENT_STATS_TTL)

        return jsonify({
            'success': True,
            'stats': stats,
            'from_cache': False
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Failed to get stats: {str(e)}'
        }), 500
