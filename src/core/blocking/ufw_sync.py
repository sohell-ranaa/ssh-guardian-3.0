"""
SSH Guardian v3.0 - UFW Sync Module
Handles automatic UFW command creation when IPs are blocked/unblocked
"""

import sys
import uuid
import json
from pathlib import Path
from typing import Optional, Dict, Any

PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
sys.path.append(str(PROJECT_ROOT / "dbs"))

from connection import get_connection


def get_agent_for_event(event_id: int) -> Optional[int]:
    """Get agent_id from auth_events table."""
    if not event_id:
        return None
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)
        try:
            cursor.execute("SELECT agent_id FROM auth_events WHERE id = %s", (event_id,))
            result = cursor.fetchone()
            return result['agent_id'] if result else None
        finally:
            cursor.close()
            conn.close()
    except Exception as e:
        print(f"⚠️  Error getting agent for event {event_id}: {e}")
        return None


def get_all_active_agents() -> list:
    """Get all active agents for global blocking."""
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)
        try:
            cursor.execute("""
                SELECT id, hostname, display_name
                FROM agents
                WHERE is_active = TRUE
            """)
            return cursor.fetchall()
        finally:
            cursor.close()
            conn.close()
    except Exception as e:
        print(f"⚠️  Error getting active agents: {e}")
        return []


def create_ufw_block_commands(ip_address: str, block_id: int,
                               agent_id: Optional[int] = None,
                               trigger_event_id: Optional[int] = None,
                               block_all_agents: bool = False) -> Dict[str, Any]:
    """
    Create UFW deny command(s) when an IP is blocked.

    Args:
        ip_address: IP to block
        block_id: Reference to ip_blocks.id
        agent_id: Specific agent ID (if None, get from trigger_event_id)
        trigger_event_id: Event that triggered the block (to get agent)
        block_all_agents: If True, block on ALL active agents (for manual blocks)

    Returns:
        dict: {"success": bool, "commands_created": int, "agents": list, "message": str}
    """
    try:
        # Determine agent_id from trigger event if not provided
        if not agent_id and trigger_event_id:
            agent_id = get_agent_for_event(trigger_event_id)

        # Get list of agents to block on
        agents_to_block = []
        if agent_id:
            # Block only on the specific agent where attack occurred
            agents_to_block = [{'id': agent_id}]
        elif block_all_agents:
            # Block on ALL active agents (for manual blocks without agent context)
            agents_to_block = get_all_active_agents()

        if not agents_to_block:
            return {'success': True, 'commands_created': 0, 'agents': [],
                    'message': 'No agent context - specify agent_id or use block_all_agents=True'}

        conn = get_connection()
        cursor = conn.cursor()
        try:
            params = {"ip": ip_address, "block_id": block_id}
            commands_created = 0
            agent_names = []

            for agent in agents_to_block:
                cursor.execute("""
                    INSERT INTO agent_ufw_commands
                    (agent_id, command_uuid, command_type, params_json, status, created_at)
                    VALUES (%s, %s, %s, %s, %s, NOW())
                """, (agent['id'], str(uuid.uuid4()), 'deny_from', json.dumps(params), 'pending'))
                commands_created += 1
                agent_names.append(agent.get('display_name') or agent.get('hostname') or str(agent['id']))

            conn.commit()
            print(f"✅ UFW block commands created for IP {ip_address} on {commands_created} agent(s): {agent_names}")
            return {'success': True, 'commands_created': commands_created,
                    'agents': agent_names,
                    'message': f'UFW block commands created for {commands_created} agent(s)'}
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            cursor.close()
            conn.close()
    except Exception as e:
        print(f"❌ Error creating UFW block command for {ip_address}: {e}")
        return {'success': False, 'commands_created': 0, 'agents': [],
                'message': f'Failed to create UFW command: {str(e)}'}


def create_ufw_unblock_commands(ip_address: str, block_id: int) -> Dict[str, Any]:
    """
    Create UFW delete command(s) when an IP is unblocked.

    Flow:
        1. Find agents with deny commands for this IP/block
        2. If none found, create delete commands for ALL active agents
        3. Create delete commands for those agents

    Returns:
        dict: {"success": bool, "commands_created": int, "message": str}
    """
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)
        try:
            # Find agents with deny commands for this IP/block
            cursor.execute("""
                SELECT DISTINCT agent_id FROM agent_ufw_commands
                WHERE command_type = 'deny_from'
                  AND JSON_EXTRACT(params_json, '$.ip') = %s
                  AND status IN ('pending', 'sent', 'completed')
            """, (ip_address,))

            agents = cursor.fetchall()

            # If no agents found with block commands, unblock on ALL agents
            if not agents:
                all_agents = get_all_active_agents()
                agents = [{'agent_id': a['id']} for a in all_agents]

            if not agents:
                return {'success': True, 'commands_created': 0,
                        'message': 'No active agents found'}

            # Create delete commands for each agent
            params = {"ip": ip_address, "block_id": block_id}
            commands_created = 0

            for agent in agents:
                cursor.execute("""
                    INSERT INTO agent_ufw_commands
                    (agent_id, command_uuid, command_type, params_json, status, created_at)
                    VALUES (%s, %s, %s, %s, %s, NOW())
                """, (agent['agent_id'], str(uuid.uuid4()), 'delete_deny_from',
                      json.dumps(params), 'pending'))
                commands_created += 1

            conn.commit()
            print(f"✅ Created {commands_created} UFW unblock command(s) for IP {ip_address}")
            return {'success': True, 'commands_created': commands_created,
                    'message': f'Created {commands_created} UFW unblock command(s)'}
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            cursor.close()
            conn.close()
    except Exception as e:
        print(f"❌ Error creating UFW unblock commands for {ip_address}: {e}")
        return {'success': False, 'commands_created': 0,
                'message': f'Failed to create UFW unblock commands: {str(e)}'}
