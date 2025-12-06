"""
SSH Guardian v3.0 - Agent Registration
Handles agent registration and updates
"""

import uuid
import json
from flask import request, jsonify
import sys
from pathlib import Path

# Add project paths
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent.parent
sys.path.append(str(PROJECT_ROOT / "dbs"))

from connection import get_connection
from . import agent_routes


def get_real_ip():
    """Get real client IP, handling proxies and forwarded headers"""
    # Check X-Forwarded-For header (set by proxies)
    if request.headers.get('X-Forwarded-For'):
        # X-Forwarded-For can contain multiple IPs, first one is the client
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()

    # Check X-Real-IP header (set by Nginx)
    if request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP').strip()

    # Check system_info for IP addresses sent by agent
    if request.json and request.json.get('system_info', {}).get('ip_addresses'):
        ips = request.json['system_info']['ip_addresses']
        if ips and len(ips) > 0:
            return ips[0]

    # Fall back to remote_addr
    return request.remote_addr


@agent_routes.route('/agents/register', methods=['POST'])
def register_agent():
    """Register a new agent or update existing agent"""
    try:
        data = request.json

        agent_id = data.get('agent_id')
        hostname = data.get('hostname')
        system_info = data.get('system_info', {})
        version = data.get('version', '3.0.0')
        heartbeat_interval = data.get('heartbeat_interval_sec', 60)

        if not agent_id or not hostname:
            return jsonify({
                'success': False,
                'error': 'agent_id and hostname are required'
            }), 400

        # Get real client IP
        ip_address = get_real_ip()

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            # Check if agent already exists
            cursor.execute("""
                SELECT id, api_key, is_active
                FROM agents
                WHERE agent_id = %s
            """, (agent_id,))

            existing_agent = cursor.fetchone()

            if existing_agent:
                # Update existing agent - also update IP address
                cursor.execute("""
                    UPDATE agents
                    SET hostname = %s,
                        system_info = %s,
                        version = %s,
                        heartbeat_interval_sec = %s,
                        ip_address_primary = %s,
                        last_heartbeat = NOW(),
                        status = 'online',
                        updated_at = NOW()
                    WHERE agent_id = %s
                """, (hostname, json.dumps(system_info), version,
                     heartbeat_interval, ip_address, agent_id))

                conn.commit()

                return jsonify({
                    'success': True,
                    'message': 'Agent updated successfully',
                    'agent_id': agent_id,
                    'api_key': existing_agent['api_key'],
                    'is_active': existing_agent['is_active']
                })

            else:
                # Create new agent
                agent_uuid = str(uuid.uuid4())
                api_key = str(uuid.uuid4())  # Generate API key

                cursor.execute("""
                    INSERT INTO agents (
                        agent_uuid, agent_id, api_key, hostname,
                        ip_address_primary, system_info, version,
                        heartbeat_interval_sec, status, last_heartbeat,
                        is_active, is_approved
                    ) VALUES (
                        %s, %s, %s, %s, %s, %s, %s, %s, 'online', NOW(), TRUE, FALSE
                    )
                """, (agent_uuid, agent_id, api_key, hostname,
                     ip_address, json.dumps(system_info), version, heartbeat_interval))

                conn.commit()
                new_agent_id = cursor.lastrowid

                return jsonify({
                    'success': True,
                    'message': 'Agent registered successfully. Waiting for approval.',
                    'agent_id': agent_id,
                    'agent_db_id': new_agent_id,
                    'api_key': api_key,
                    'note': 'Please approve this agent in the dashboard to start receiving logs'
                }), 201

        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Registration failed: {str(e)}'
        }), 500
