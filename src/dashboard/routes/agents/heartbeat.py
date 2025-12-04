"""
SSH Guardian v3.0 - Agent Heartbeat
Handles heartbeat monitoring from agents
"""

from datetime import datetime
from flask import request, jsonify
import sys
from pathlib import Path

# Add project paths
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent.parent
sys.path.append(str(PROJECT_ROOT / "dbs"))

from connection import get_connection
from . import agent_routes
from .auth import require_api_key


@agent_routes.route('/agents/heartbeat', methods=['POST'])
@require_api_key
def agent_heartbeat():
    """Receive heartbeat from agent"""
    try:
        data = request.json
        agent = request.agent

        metrics = data.get('metrics', {})
        status = data.get('status', 'online')
        health_status = data.get('health_status', 'healthy')

        conn = get_connection()
        cursor = conn.cursor()

        try:
            # Update agent status
            cursor.execute("""
                UPDATE agents
                SET last_heartbeat = NOW(),
                    status = %s,
                    health_status = %s,
                    consecutive_missed_heartbeats = 0,
                    updated_at = NOW()
                WHERE id = %s
            """, (status, health_status, agent['id']))

            # Insert heartbeat record
            cursor.execute("""
                INSERT INTO agent_heartbeats (
                    agent_id, heartbeat_timestamp,
                    cpu_usage_percent, memory_usage_percent, disk_usage_percent,
                    events_processed_last_minute, health_status
                ) VALUES (%s, NOW(), %s, %s, %s, %s, %s)
            """, (agent['id'],
                 metrics.get('cpu_usage_percent'),
                 metrics.get('memory_usage_percent'),
                 metrics.get('disk_usage_percent'),
                 metrics.get('events_processed_last_minute', 0),
                 health_status))

            conn.commit()

            return jsonify({
                'success': True,
                'message': 'Heartbeat received',
                'server_time': datetime.now().isoformat()
            })

        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Heartbeat failed: {str(e)}'
        }), 500
