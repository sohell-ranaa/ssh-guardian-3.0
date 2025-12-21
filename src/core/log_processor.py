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

# Enrichment module (lazy loaded)
_enrichment_module = None

def _get_enrichment_module():
    """Lazy load enrichment module to avoid circular imports"""
    global _enrichment_module
    if _enrichment_module is None:
        try:
            from core.enrichment import enrich_event
            _enrichment_module = enrich_event
        except ImportError:
            _enrichment_module = False
    return _enrichment_module


# Proactive blocker module (lazy loaded)
_proactive_blocker = None

def _get_proactive_blocker():
    """Lazy load proactive blocker to avoid circular imports"""
    global _proactive_blocker
    if _proactive_blocker is None:
        try:
            from blocking.proactive_blocker import evaluate_auth_event
            _proactive_blocker = evaluate_auth_event
        except ImportError:
            _proactive_blocker = False
    return _proactive_blocker


# SSH Log Patterns
LOG_PATTERNS = {
    'failed_password': re.compile(
        r'Failed password for (?P<username>\S+) from (?P<ip>[\d\.:a-fA-F]+) port (?P<port>\d+)'
    ),
    'failed_invalid_user': re.compile(
        r'Failed password for invalid user (?P<username>\S+) from (?P<ip>[\d\.:a-fA-F]+) port (?P<port>\d+)'
    ),
    'failed_publickey': re.compile(
        r'Failed publickey for (?P<username>\S+) from (?P<ip>[\d\.:a-fA-F]+) port (?P<port>\d+)'
    ),
    'failed_publickey_invalid': re.compile(
        r'Failed publickey for invalid user (?P<username>\S+) from (?P<ip>[\d\.:a-fA-F]+) port (?P<port>\d+)'
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
                # Skip invalid/unrecognized events - don't save them
                return None

            # Determine auth method
            if 'publickey' in event_name:
                auth_method = 'publickey'
            elif 'password' in event_name:
                auth_method = 'password'
            else:
                auth_method = 'other'

            # Extract timestamp from log line
            log_timestamp = None

            # Try ISO format first: "2025-12-20T07:10:05.913746+01:00"
            iso_match = re.match(r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})', log_line)
            if iso_match:
                try:
                    iso_str = iso_match.group(1)
                    log_timestamp = datetime.fromisoformat(iso_str)
                except (ValueError, TypeError):
                    log_timestamp = None

            # Fallback to syslog format: "Dec 20 03:30:00"
            if not log_timestamp:
                timestamp_match = re.match(r'^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})', log_line)
                if timestamp_match:
                    month_str, day_str, time_str = timestamp_match.groups()
                    try:
                        month_map = {'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4, 'May': 5, 'Jun': 6,
                                     'Jul': 7, 'Aug': 8, 'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12}
                        month = month_map.get(month_str, datetime.now().month)
                        day = int(day_str)
                        hour, minute, second = map(int, time_str.split(':'))
                        log_timestamp = datetime.now().replace(month=month, day=day, hour=hour, minute=minute, second=second, microsecond=0)
                    except (ValueError, KeyError):
                        log_timestamp = None

            return {
                'event_type': event_type,
                'auth_method': auth_method,
                'source_ip': data.get('ip'),
                'source_port': int(data.get('port', 0)) if data.get('port') else None,
                'username': data.get('username', 'unknown'),
                'failure_reason': failure_reason,
                'raw_log_line': log_line,
                'log_timestamp': log_timestamp
            }

    return None


def process_log_line(log_line: str, source_type: str = 'agent',
                    agent_id: Optional[int] = None,
                    agent_batch_id: Optional[int] = None,
                    simulation_run_id: Optional[int] = None,
                    target_server_override: Optional[str] = None,
                    skip_blocking: bool = False,
                    skip_learning: bool = False) -> Dict:
    """
    Process a single log line and create auth_event

    Args:
        log_line: Raw SSH log line
        source_type: Source type ('agent', 'synthetic', 'simulation')
        agent_id: Agent ID if from agent
        agent_batch_id: Batch ID if from agent batch
        simulation_run_id: Simulation run ID if from simulation
        target_server_override: Override target server name (for simulations)
        skip_blocking: Skip auto-blocking (analysis-only mode for simulations without agent)
        skip_learning: Skip behavioral profile learning (for simulations)

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
        # Use parsed timestamp from log or fallback to now
        event_timestamp = parsed.get('log_timestamp') or datetime.now()

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
                    %s, %s, %s, %s, %s,
                    %s, %s, %s,
                    %s, %s, %s,
                    %s, %s, %s,
                    %s, 'pending'
                )
            """, (
                event_uuid, event_timestamp, source_type, agent_id, agent_batch_id,
                simulation_run_id, event_type, auth_method,
                ip_binary, source_ip, source_port,
                target_server, username, failure_reason,
                log_line
            ))

            event_id = cursor.lastrowid
            conn.commit()

            # Trigger enrichment pipeline (GeoIP, Threat Intel, ML)
            enrichment_result = None
            try:
                enrich_event = _get_enrichment_module()
                if enrich_event:
                    enrichment_result = enrich_event(
                        event_id, source_ip, verbose=False,
                        skip_blocking=skip_blocking,
                        skip_learning=skip_learning
                    )
            except Exception as e:
                # Don't fail the event if enrichment fails
                enrichment_result = {'error': str(e)}

            # Run unified threat evaluation and store ML results
            threat_evaluation = None
            try:
                from threat_evaluator import evaluate_and_store_for_event
                event_context = {
                    'username': username,
                    'status': event_type,
                    'auth_method': auth_method,
                    'failure_reason': failure_reason,
                    'timestamp': event_timestamp.isoformat()
                }
                threat_evaluation = evaluate_and_store_for_event(
                    event_id, source_ip, event_context
                )
            except Exception as e:
                # Don't fail if threat evaluation fails
                threat_evaluation = {'error': str(e)}

            # Run proactive threat evaluation for failed logins
            # This can block threats BEFORE fail2ban threshold is reached
            proactive_result = None
            # Run proactive blocker for failed logins (may block)
            # AND for successful logins (may create behavioral alert, no block)
            if not skip_blocking:
                try:
                    evaluate_event = _get_proactive_blocker()
                    if evaluate_event:
                        proactive_result = evaluate_event({
                            'source_ip': source_ip,
                            'username': username,
                            'event_type': event_type,
                            'failure_reason': failure_reason,
                            'timestamp': event_timestamp.isoformat()
                        })
                except Exception as e:
                    # Don't fail if proactive blocking fails
                    proactive_result = {'error': str(e)}

            return {
                'success': True,
                'event_id': event_id,
                'event_uuid': event_uuid,
                'event_type': event_type,
                'enrichment': enrichment_result,
                'proactive_block': proactive_result
            }

        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        return {
            'success': False,
            'error': f'Processing error: {str(e)}'
        }
