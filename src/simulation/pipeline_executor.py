"""
SSH Guardian v3.0 - Pipeline Executor
Modular pipeline execution for demo scenarios with agent targeting.
Handles IP blocking, UFW command creation, and notifications.
"""

import json
import uuid as uuid_module
import sys
from pathlib import Path
from typing import Dict, Optional

PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.append(str(PROJECT_ROOT / "dbs"))

from connection import get_connection, ip_to_binary


def execute_pipeline(
    event_id: int,
    source_ip: str,
    agent_id: int,
    enrichment: dict
) -> Dict:
    """
    Execute full pipeline steps after event creation.

    Args:
        event_id: Created event ID
        source_ip: IP address to process
        agent_id: Target agent ID
        enrichment: Enrichment results containing ML and threat intel

    Returns:
        Dict with status of each pipeline step
    """
    steps = {
        'event_created': {'status': 'success', 'event_id': event_id},
        'enrichment': {'status': 'success' if enrichment else 'skipped'},
        'ip_blocked': {'status': 'skipped', 'is_blocked': False},
        'ufw_command': {'status': 'skipped', 'command_exists': False},
        'notification': {'status': 'skipped', 'count': 0}
    }

    # Extract scores from enrichment
    ml = enrichment.get('ml', {}) if enrichment else {}
    threat_intel = enrichment.get('threat_intel', {}) if enrichment else {}

    ml_risk_score = float(ml.get('risk_score', 0) or 0)
    abuseipdb_score = float(threat_intel.get('abuseipdb_score', 0) or 0)

    # Threshold check: block if risk >= 60 or abuseipdb >= 50
    should_block = ml_risk_score >= 60 or abuseipdb_score >= 50

    if not should_block:
        steps['ip_blocked'] = {
            'status': 'skipped',
            'is_blocked': False,
            'message': f'Risk score {ml_risk_score} below threshold'
        }
        return steps

    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Check existing block
        cursor.execute(
            "SELECT id FROM ip_blocks WHERE ip_address_text = %s AND is_active = TRUE",
            (source_ip,)
        )
        existing_block = cursor.fetchone()

        if existing_block:
            # Already blocked - check for existing UFW command
            block_id = existing_block['id']
            steps['ip_blocked'] = {
                'status': 'success',
                'is_blocked': True,
                'message': 'Already blocked by enrichment',
                'block_id': block_id
            }

            cursor.execute("""
                SELECT id, status FROM agent_ufw_commands
                WHERE agent_id = %s AND params_json LIKE %s
                ORDER BY created_at DESC LIMIT 1
            """, (agent_id, f'%"ip": "{source_ip}"%'))
            existing_ufw = cursor.fetchone()

            if existing_ufw:
                steps['ufw_command'] = {
                    'status': 'success',
                    'command_exists': True,
                    'command_id': existing_ufw['id'],
                    'command_status': existing_ufw['status']
                }
        else:
            # Create new block
            block_reason = f"Pipeline: ML {ml_risk_score}, AbuseIPDB {abuseipdb_score}"
            threat_level = ml.get('threat_type', 'high')
            ip_binary = ip_to_binary(source_ip)

            cursor.execute("""
                INSERT INTO ip_blocks
                (ip_address, ip_address_text, block_reason, risk_score, threat_level,
                 block_source, is_active, is_simulation, trigger_event_id, blocked_at)
                VALUES (%s, %s, %s, %s, %s, 'ml_threshold', TRUE, TRUE, %s, NOW())
            """, (ip_binary, source_ip, block_reason, int(ml_risk_score), threat_level, event_id))

            block_id = cursor.lastrowid
            conn.commit()

            steps['ip_blocked'] = {
                'status': 'success',
                'is_blocked': True,
                'block_id': block_id
            }

            # Create UFW command
            command_uuid = str(uuid_module.uuid4())
            params = json.dumps({'ip': source_ip, 'block_id': block_id})

            cursor.execute("""
                INSERT INTO agent_ufw_commands
                (agent_id, command_uuid, command_type, params_json, status, created_at)
                VALUES (%s, %s, 'deny_from', %s, 'pending', NOW())
            """, (agent_id, command_uuid, params))

            ufw_id = cursor.lastrowid
            conn.commit()

            steps['ufw_command'] = {
                'status': 'success',
                'command_exists': True,
                'command_id': ufw_id,
                'command_uuid': command_uuid
            }

            # Create notification
            cursor.execute("""
                INSERT INTO notifications
                (trigger_type, trigger_event_id, priority, title, message, channels, status, created_at)
                VALUES ('ip_blocked', %s, 'high', %s, %s, %s, 'pending', NOW())
            """, (
                event_id,
                f'IP Blocked: {source_ip}',
                f'Blocked {source_ip} - Risk: {ml_risk_score}',
                json.dumps(['dashboard'])
            ))
            conn.commit()

            steps['notification'] = {'status': 'success', 'count': 1}

        cursor.close()
        conn.close()

    except Exception as e:
        steps['ip_blocked'] = {'status': 'failed', 'error': str(e)}

    return steps


def get_available_agents() -> list:
    """Get list of available agents for targeting."""
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT id, hostname, display_name, is_active
            FROM agents WHERE is_active = TRUE
            ORDER BY hostname
        """)
        agents = cursor.fetchall()
        cursor.close()
        conn.close()
        return agents
    except Exception:
        return []
