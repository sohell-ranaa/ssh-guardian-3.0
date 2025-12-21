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
                ufw_command = f"ufw deny from {ip_address}"
                cursor.execute("""
                    INSERT INTO agent_ufw_commands
                    (agent_id, command_uuid, command_type, params_json, ufw_command, status, created_at)
                    VALUES (%s, %s, %s, %s, %s, %s, NOW())
                """, (agent['id'], str(uuid.uuid4()), 'deny_from', json.dumps(params), ufw_command, 'pending'))
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
                ufw_command = f"ufw delete deny from {ip_address}"
                cursor.execute("""
                    INSERT INTO agent_ufw_commands
                    (agent_id, command_uuid, command_type, params_json, ufw_command, status, created_at)
                    VALUES (%s, %s, %s, %s, %s, %s, NOW())
                """, (agent['agent_id'], str(uuid.uuid4()), 'delete_deny_from',
                      json.dumps(params), ufw_command, 'pending'))
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


def reconcile_ufw_with_ip_blocks(agent_id: Optional[int] = None) -> Dict[str, Any]:
    """
    Reconcile UFW rules with ip_blocks table.

    Compares actual UFW DENY rules (from agent_ufw_rules) with ip_blocks records.
    If an IP is marked as blocked in ip_blocks but NOT in UFW rules, mark it as unblocked.

    Args:
        agent_id: Specific agent to reconcile (None = all agents)

    Returns:
        dict: {
            'success': bool,
            'reconciled_count': int,
            'details': list of {ip, agent_id, action}
        }
    """
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            # Get all active blocks from ip_blocks
            if agent_id:
                cursor.execute("""
                    SELECT ib.id, ib.ip_address_text, ib.agent_id, ib.block_source
                    FROM ip_blocks ib
                    WHERE ib.is_active = TRUE
                      AND ib.agent_id = %s
                """, (agent_id,))
            else:
                cursor.execute("""
                    SELECT ib.id, ib.ip_address_text, ib.agent_id, ib.block_source
                    FROM ip_blocks ib
                    WHERE ib.is_active = TRUE
                      AND ib.agent_id IS NOT NULL
                """)

            active_blocks = cursor.fetchall()

            if not active_blocks:
                return {
                    'success': True,
                    'reconciled_count': 0,
                    'details': [],
                    'message': 'No active blocks to reconcile'
                }

            # Get all DENY rules from UFW (grouped by agent)
            if agent_id:
                cursor.execute("""
                    SELECT agent_id, from_ip
                    FROM agent_ufw_rules
                    WHERE action = 'DENY'
                      AND from_ip IS NOT NULL
                      AND from_ip != ''
                      AND from_ip != 'Anywhere'
                      AND agent_id = %s
                """, (agent_id,))
            else:
                cursor.execute("""
                    SELECT agent_id, from_ip
                    FROM agent_ufw_rules
                    WHERE action = 'DENY'
                      AND from_ip IS NOT NULL
                      AND from_ip != ''
                      AND from_ip != 'Anywhere'
                """)

            ufw_rules = cursor.fetchall()

            # Build a set of (agent_id, ip) tuples for quick lookup
            ufw_blocked_ips = set()
            for rule in ufw_rules:
                ufw_blocked_ips.add((rule['agent_id'], rule['from_ip']))

            # Find blocks in ip_blocks that are NOT in UFW
            reconciled = []
            for block in active_blocks:
                block_key = (block['agent_id'], block['ip_address_text'])

                if block_key not in ufw_blocked_ips:
                    # This IP is marked as blocked but not in UFW - mark as unblocked
                    cursor.execute("""
                        UPDATE ip_blocks
                        SET is_active = FALSE,
                            unblocked_at = NOW(),
                            unblock_reason = 'Auto-reconciled: Not found in UFW rules'
                        WHERE id = %s
                    """, (block['id'],))

                    # Add history record
                    cursor.execute("""
                        INSERT INTO blocking_actions
                        (action_uuid, ip_block_id, ip_address_text, action_type, action_source, reason, created_at)
                        VALUES (%s, %s, %s, 'unblocked', 'system', 'Auto-reconciled: Removed from UFW externally', NOW())
                    """, (str(uuid.uuid4()), block['id'], block['ip_address_text']))

                    reconciled.append({
                        'ip': block['ip_address_text'],
                        'agent_id': block['agent_id'],
                        'block_id': block['id'],
                        'action': 'marked_unblocked'
                    })

                    print(f"🔄 Reconciled: {block['ip_address_text']} marked as unblocked (not in UFW)")

            conn.commit()

            return {
                'success': True,
                'reconciled_count': len(reconciled),
                'details': reconciled,
                'message': f'Reconciled {len(reconciled)} IP(s) - marked as unblocked'
            }

        except Exception as e:
            conn.rollback()
            raise e
        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        print(f"❌ Error reconciling UFW with ip_blocks: {e}")
        import traceback
        traceback.print_exc()
        return {
            'success': False,
            'reconciled_count': 0,
            'details': [],
            'message': f'Reconciliation failed: {str(e)}'
        }
