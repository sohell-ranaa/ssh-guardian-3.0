"""
SSH Guardian v3.0 - Log Processor
Processes SSH log lines from agents and creates auth_events
"""

import re
import uuid
from datetime import datetime
from typing import Dict, Optional
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.append(str(PROJECT_ROOT / "dbs"))

from connection import get_connection, ip_to_binary, get_ip_version


# SSH Log Patterns
LOG_PATTERNS = {
    'failed_password': re.compile(
        r'Failed password for (?P<username>\S+) from (?P<ip>[\d\.:a-fA-F]+) port (?P<port>\d+)'
    ),
    'failed_invalid_user': re.compile(
        r'Failed password for invalid user (?P<username>\S+) from (?P<ip>[\d\.:a-fA-F]+) port (?P<port>\d+)'
    ),
    'accepted_password': re.compile(
        r'Accepted password for (?P<username>\S+) from (?P<ip>[\d\.:a-fA-F]+) port (?P<port>\d+)'
    ),
    'accepted_publickey': re.compile(
        r'Accepted publickey for (?P<username>\S+) from (?P<ip>[\d\.:a-fA-F]+) port (?P<port>\d+)'
    ),
    'invalid_user': re.compile(
        r'Invalid user (?P<username>\S+) from (?P<ip>[\d\.:a-fA-F]+)'
    ),
    'connection_closed': re.compile(
        r'Connection closed by (?:invalid user )?(?P<username>\S+)? ?(?P<ip>[\d\.:a-fA-F]+) port (?P<port>\d+)'
    ),
}


def parse_log_line(log_line: str) -> Optional[Dict]:
    """Parse SSH log line and extract information"""

    for event_name, pattern in LOG_PATTERNS.items():
        match = pattern.search(log_line)
        if match:
            data = match.groupdict()

            # Determine event type
            if 'failed' in event_name or 'invalid' in event_name:
                event_type = 'failed'
                if 'invalid' in event_name:
                    failure_reason = 'invalid_user'
                else:
                    failure_reason = 'invalid_password'
            elif 'accepted' in event_name:
                event_type = 'successful'
                failure_reason = None
            else:
                event_type = 'invalid'
                failure_reason = 'other'

            # Determine auth method
            if 'publickey' in event_name:
                auth_method = 'publickey'
            elif 'password' in event_name:
                auth_method = 'password'
            else:
                auth_method = 'other'

            return {
                'event_type': event_type,
                'auth_method': auth_method,
                'source_ip': data.get('ip'),
                'source_port': int(data.get('port', 0)) if data.get('port') else None,
                'username': data.get('username', 'unknown'),
                'failure_reason': failure_reason,
                'raw_log_line': log_line
            }

    return None


def process_log_line(log_line: str, source_type: str = 'agent',
                    agent_id: Optional[int] = None,
                    agent_batch_id: Optional[int] = None,
                    simulation_run_id: Optional[int] = None,
                    target_server_override: Optional[str] = None) -> Dict:
    """
    Process a single log line and create auth_event

    Args:
        log_line: Raw SSH log line
        source_type: Source type ('agent', 'synthetic', 'simulation')
        agent_id: Agent ID if from agent
        agent_batch_id: Batch ID if from agent batch
        simulation_run_id: Simulation run ID if from simulation
        target_server_override: Override target server name (for simulations)

    Returns:
        dict with success status and event_id or error
    """

    try:
        # Parse log line
        parsed = parse_log_line(log_line)

        if not parsed:
            return {
                'success': False,
                'error': 'Could not parse log line'
            }

        # Extract parsed data
        event_type = parsed['event_type']
        auth_method = parsed['auth_method']
        source_ip = parsed['source_ip']
        source_port = parsed['source_port']
        username = parsed['username']
        failure_reason = parsed['failure_reason']

        # Generate event UUID
        event_uuid = str(uuid.uuid4())

        # Convert IP to binary
        try:
            ip_binary = ip_to_binary(source_ip)
            ip_version = get_ip_version(source_ip)
        except Exception as e:
            return {
                'success': False,
                'error': f'Invalid IP address: {source_ip}'
            }

        # Insert into database
        conn = get_connection()
        cursor = conn.cursor()

        try:
            # Get or create hostname (use override, agent's hostname, or default)
            target_server = 'unknown'
            if target_server_override:
                target_server = target_server_override
            elif agent_id:
                cursor.execute("SELECT hostname FROM agents WHERE id = %s", (agent_id,))
                agent_row = cursor.fetchone()
                if agent_row:
                    target_server = agent_row[0]

            # Insert auth_event
            cursor.execute("""
                INSERT INTO auth_events (
                    event_uuid, timestamp, source_type, agent_id, agent_batch_id,
                    simulation_run_id, event_type, auth_method,
                    source_ip, source_ip_text, source_port,
                    target_server, target_username, failure_reason,
                    raw_log_line, processing_status
                ) VALUES (
                    %s, NOW(), %s, %s, %s,
                    %s, %s, %s,
                    %s, %s, %s,
                    %s, %s, %s,
                    %s, 'pending'
                )
            """, (
                event_uuid, source_type, agent_id, agent_batch_id,
                simulation_run_id, event_type, auth_method,
                ip_binary, source_ip, source_port,
                target_server, username, failure_reason,
                log_line
            ))

            event_id = cursor.lastrowid
            conn.commit()

            return {
                'success': True,
                'event_id': event_id,
                'event_uuid': event_uuid,
                'event_type': event_type
            }

        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        return {
            'success': False,
            'error': f'Processing error: {str(e)}'
        }
