#!/usr/bin/env python3
"""
SSH Guardian v3.0 - Standalone Agent
Single-file agent that includes UFW firewall management.
Copy this single file to your server and run it.

Features:
- Real-time SSH log monitoring (/var/log/auth.log)
- Batch submission to central server
- Automatic heartbeat monitoring
- UFW firewall collection and management
- Bidirectional sync with dashboard
- Systemd service compatible

Usage:
    sudo python3 ssh_guardian_agent_standalone.py --server https://your-server:8081 --api-key YOUR_KEY
"""

import os
import sys
import time
import json
import uuid
import socket
import re
import logging
import argparse
import subprocess
from datetime import datetime
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, asdict

# Try to import requests, install if not available
try:
    import requests
except ImportError:
    print("Installing requests...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "requests", "-q"])
    import requests

import platform


# ============================================================================
# UFW MANAGER (EMBEDDED)
# ============================================================================

@dataclass
class UFWRule:
    """Represents a single UFW rule"""
    rule_index: int
    action: str
    direction: str
    from_ip: str
    from_port: str
    to_ip: str
    to_port: str
    protocol: str
    interface: str
    comment: str
    is_v6: bool
    raw_rule: str

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class UFWStatus:
    """Overall UFW status"""
    status: str
    default_incoming: str
    default_outgoing: str
    default_routed: str
    logging_level: str
    ipv6_enabled: bool
    rules_count: int
    ufw_version: str
    last_updated: str

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class ListeningPort:
    """Represents a listening port/service"""
    port: int
    protocol: str
    address: str
    state: str
    pid: int
    process_name: str
    user: str
    is_protected: bool = False

    def to_dict(self) -> Dict:
        return asdict(self)


class UFWManager:
    """Manages UFW firewall rules"""

    PROTECTED_SERVICES = {
        22: 'SSH',
        80: 'HTTP',
        443: 'HTTPS',
        3306: 'MySQL',
        5432: 'PostgreSQL',
        6379: 'Redis',
        8081: 'SSH Guardian Dashboard',
    }

    def __init__(self):
        self.logger = logging.getLogger('UFWManager')

    def is_installed(self) -> bool:
        try:
            result = subprocess.run(['which', 'ufw'], capture_output=True, text=True, timeout=5)
            return result.returncode == 0
        except Exception:
            return False

    def get_version(self) -> str:
        try:
            result = subprocess.run(['ufw', 'version'], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                match = re.search(r'ufw (\d+\.\d+(?:\.\d+)?)', result.stdout)
                if match:
                    return match.group(1)
            return 'unknown'
        except Exception:
            return 'unknown'

    def collect_all(self) -> Dict:
        try:
            if not self.is_installed():
                return {
                    'status': UFWStatus(
                        status='not_installed',
                        default_incoming='unknown',
                        default_outgoing='unknown',
                        default_routed='unknown',
                        logging_level='unknown',
                        ipv6_enabled=False,
                        rules_count=0,
                        ufw_version='',
                        last_updated=datetime.now().isoformat()
                    ).to_dict(),
                    'rules': [],
                    'listening_ports': self._get_listening_ports(),
                    'collected_at': datetime.now().isoformat()
                }

            status = self._get_status()
            rules = self._get_rules()
            listening_ports = self._get_listening_ports()

            return {
                'status': status,
                'rules': rules,
                'listening_ports': listening_ports,
                'protected_ports': self._get_protected_ports(listening_ports),
                'collected_at': datetime.now().isoformat()
            }
        except Exception as e:
            self.logger.error(f"Error collecting UFW data: {e}")
            return {'error': str(e), 'collected_at': datetime.now().isoformat()}

    def _get_status(self) -> Dict:
        try:
            result = subprocess.run(['ufw', 'status', 'verbose'], capture_output=True, text=True, timeout=10)

            if result.returncode != 0:
                return UFWStatus(
                    status='inactive', default_incoming='unknown', default_outgoing='unknown',
                    default_routed='unknown', logging_level='unknown', ipv6_enabled=False,
                    rules_count=0, ufw_version=self.get_version(), last_updated=datetime.now().isoformat()
                ).to_dict()

            output = result.stdout
            status = 'active' if 'Status: active' in output else 'inactive'

            default_incoming, default_outgoing, default_routed = 'deny', 'allow', 'disabled'
            defaults_match = re.search(
                r'Default:\s+(\w+)\s+\(incoming\),\s+(\w+)\s+\(outgoing\)(?:,\s+(\w+)\s+\(routed\))?', output
            )
            if defaults_match:
                default_incoming = defaults_match.group(1).lower()
                default_outgoing = defaults_match.group(2).lower()
                if defaults_match.group(3):
                    default_routed = defaults_match.group(3).lower()

            logging_level = 'low'
            logging_match = re.search(r'Logging:\s+(\w+)', output)
            if logging_match:
                logging_level = logging_match.group(1).lower()

            ipv6_enabled = True
            try:
                with open('/etc/default/ufw', 'r') as f:
                    if 'IPV6=no' in f.read():
                        ipv6_enabled = False
            except:
                pass

            return UFWStatus(
                status=status, default_incoming=default_incoming, default_outgoing=default_outgoing,
                default_routed=default_routed, logging_level=logging_level, ipv6_enabled=ipv6_enabled,
                rules_count=len(self._get_rules()), ufw_version=self.get_version(),
                last_updated=datetime.now().isoformat()
            ).to_dict()

        except Exception as e:
            self.logger.error(f"Error getting UFW status: {e}")
            return {'error': str(e)}

    def _get_rules(self) -> List[Dict]:
        rules = []
        try:
            result = subprocess.run(['ufw', 'status', 'numbered'], capture_output=True, text=True, timeout=10)
            if result.returncode != 0:
                return []

            rule_pattern = re.compile(
                r'\[\s*(\d+)\]\s+(.+?)\s+(ALLOW|DENY|REJECT|LIMIT)\s+(IN|OUT|FWD)?\s*(.+?)$',
                re.MULTILINE
            )

            for match in rule_pattern.finditer(result.stdout):
                rule_index = int(match.group(1))
                to_part = match.group(2).strip()
                action = match.group(3)
                direction = match.group(4) or 'IN'
                from_part = match.group(5).strip()

                to_port, protocol, interface = '', '', ''
                if ' on ' in to_part:
                    parts = to_part.split(' on ')
                    to_part = parts[0]
                    interface = parts[1].strip()

                if '/' in to_part:
                    port_proto = to_part.split('/')
                    to_port = port_proto[0]
                    protocol = port_proto[1] if len(port_proto) > 1 else ''
                else:
                    to_port = to_part

                is_v6 = '(v6)' in from_part
                from_part = from_part.replace('(v6)', '').strip()
                from_ip = from_part if from_part else 'Anywhere'
                from_port = ''

                if ' port ' in from_ip:
                    parts = from_ip.split(' port ')
                    from_ip = parts[0].strip()
                    from_port = parts[1].strip()

                rules.append(UFWRule(
                    rule_index=rule_index, action=action, direction=direction,
                    from_ip=from_ip, from_port=from_port, to_ip='Anywhere', to_port=to_port,
                    protocol=protocol, interface=interface, comment='', is_v6=is_v6,
                    raw_rule=match.group(0).strip()
                ).to_dict())

        except Exception as e:
            self.logger.error(f"Error getting UFW rules: {e}")
        return rules

    def _get_listening_ports(self) -> List[Dict]:
        ports = []
        try:
            for proto in ['tcp', 'udp']:
                flag = '-tlnp' if proto == 'tcp' else '-ulnp'
                result = subprocess.run(['ss', flag], capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    ports.extend(self._parse_ss_output(result.stdout, proto))
        except Exception as e:
            self.logger.error(f"Error getting listening ports: {e}")
        return ports

    def _parse_ss_output(self, output: str, protocol: str) -> List[Dict]:
        ports = []
        for line in output.strip().split('\n')[1:]:
            if not line.strip():
                continue
            parts = line.split()
            if len(parts) < 5:
                continue
            try:
                local_addr = parts[4] if len(parts) > 4 else ''
                if ':' in local_addr:
                    if local_addr.startswith('['):
                        match = re.match(r'\[([^\]]+)\]:(\d+)', local_addr)
                        if match:
                            address, port = match.group(1), int(match.group(2))
                        else:
                            continue
                    else:
                        parts_addr = local_addr.rsplit(':', 1)
                        address = parts_addr[0] if parts_addr[0] != '*' else '0.0.0.0'
                        port = int(parts_addr[1])
                else:
                    continue

                pid, process_name = 0, ''
                for part in parts:
                    if part.startswith('users:'):
                        proc_match = re.search(r'\("([^"]+)",pid=(\d+)', part)
                        if proc_match:
                            process_name, pid = proc_match.group(1), int(proc_match.group(2))

                ports.append(ListeningPort(
                    port=port, protocol=protocol, address=address, state=parts[0],
                    pid=pid, process_name=process_name, user='',
                    is_protected=port in self.PROTECTED_SERVICES
                ).to_dict())
            except:
                continue
        return ports

    def _get_protected_ports(self, listening_ports: List[Dict]) -> List[Dict]:
        return [
            {'port': port, 'service': service, 'reason': 'Critical service',
             'is_listening': any(p['port'] == port for p in listening_ports)}
            for port, service in self.PROTECTED_SERVICES.items()
        ]

    def execute_command(self, command_type: str, params: Dict) -> Tuple[bool, str]:
        try:
            handlers = {
                'allow': self._allow, 'deny': self._deny, 'reject': self._reject,
                'limit': self._limit, 'delete': self._delete, 'delete_by_rule': self._delete_by_rule,
                'enable': self._enable, 'disable': self._disable, 'reset': self._reset,
                'reload': self._reload, 'default': self._set_default, 'logging': self._set_logging,
                'sync_now': lambda p: (True, 'Sync requested'), 'raw': self._execute_raw,
                'reorder': self._reorder,
            }
            handler = handlers.get(command_type)
            if handler:
                return handler(params) if command_type not in ['enable', 'disable', 'reset', 'reload'] else handler()
            return False, f"Unknown command type: {command_type}"
        except Exception as e:
            self.logger.error(f"Error executing UFW command: {e}")
            return False, str(e)

    def _reorder(self, params: Dict) -> Tuple[bool, str]:
        """Reorder UFW rules by deleting and re-inserting"""
        delete_cmd = params.get('delete_cmd')
        insert_cmd = params.get('insert_cmd')
        from_index = params.get('from_index')
        to_index = params.get('to_index')

        if not delete_cmd or not insert_cmd:
            return False, "Missing delete_cmd or insert_cmd for reorder"

        self.logger.info(f"Reordering UFW rule: #{from_index} -> #{to_index}")

        # Execute delete first
        try:
            delete_result = subprocess.run(
                delete_cmd.split(),
                capture_output=True,
                text=True,
                timeout=30
            )
            if delete_result.returncode != 0:
                return False, f"Delete failed: {delete_result.stderr}"

            # Then execute insert
            insert_result = subprocess.run(
                insert_cmd.split(),
                capture_output=True,
                text=True,
                timeout=30
            )
            if insert_result.returncode != 0:
                return False, f"Insert failed: {insert_result.stderr}"

            return True, f"Rule moved from position #{from_index} to #{to_index}"
        except subprocess.TimeoutExpired:
            return False, "Command timed out"
        except Exception as e:
            return False, str(e)

    def _allow(self, params: Dict) -> Tuple[bool, str]:
        cmd = ['ufw', 'allow']
        port, protocol = params.get('port'), params.get('protocol', '')
        from_ip = params.get('from_ip') or params.get('from')

        if from_ip and from_ip.lower() not in ['anywhere', 'any']:
            cmd.extend(['from', from_ip])
            if port:
                cmd.extend(['to', 'any', 'port', str(port)])
                if protocol:
                    cmd.extend(['proto', protocol])
        elif port:
            cmd.append(f"{port}/{protocol}" if protocol else str(port))
        else:
            return False, "Port is required for allow command"
        return self._run_ufw_command(cmd)

    def _deny(self, params: Dict) -> Tuple[bool, str]:
        cmd = ['ufw', 'deny']
        port, protocol = params.get('port'), params.get('protocol', '')
        from_ip = params.get('from_ip') or params.get('from')

        if from_ip and from_ip.lower() not in ['anywhere', 'any']:
            cmd.extend(['from', from_ip])
            if port:
                cmd.extend(['to', 'any', 'port', str(port)])
                if protocol:
                    cmd.extend(['proto', protocol])
        elif port:
            cmd.append(f"{port}/{protocol}" if protocol else str(port))
        elif from_ip:
            cmd.extend(['from', from_ip])
        else:
            return False, "Port or from_ip is required for deny command"
        return self._run_ufw_command(cmd)

    def _reject(self, params: Dict) -> Tuple[bool, str]:
        port, protocol = params.get('port'), params.get('protocol', '')
        if not port:
            return False, "Port is required for reject command"
        return self._run_ufw_command(['ufw', 'reject', f"{port}/{protocol}" if protocol else str(port)])

    def _limit(self, params: Dict) -> Tuple[bool, str]:
        port = params.get('port')
        if not port:
            return False, "Port is required for limit command"
        return self._run_ufw_command(['ufw', 'limit', f"{port}/{params.get('protocol', 'tcp')}"])

    def _delete(self, params: Dict) -> Tuple[bool, str]:
        rule_num = params.get('rule_number') or params.get('rule_index')
        if not rule_num:
            return False, "Rule number is required for delete command"
        return self._run_ufw_command(['ufw', '--force', 'delete', str(rule_num)])

    def _delete_by_rule(self, params: Dict) -> Tuple[bool, str]:
        action = params.get('action', 'allow').lower()
        port, protocol = params.get('port'), params.get('protocol', '')
        from_ip = params.get('from_ip')
        cmd = ['ufw', '--force', 'delete', action]

        if from_ip and from_ip.lower() not in ['anywhere', 'any']:
            cmd.extend(['from', from_ip])
            if port:
                cmd.extend(['to', 'any', 'port', str(port)])
                if protocol:
                    cmd.extend(['proto', protocol])
        elif port:
            cmd.append(f"{port}/{protocol}" if protocol else str(port))
        else:
            return False, "Port or specification required"
        return self._run_ufw_command(cmd)

    def _enable(self) -> Tuple[bool, str]:
        return self._run_ufw_command(['ufw', '--force', 'enable'])

    def _disable(self) -> Tuple[bool, str]:
        return self._run_ufw_command(['ufw', '--force', 'disable'])

    def _reset(self) -> Tuple[bool, str]:
        return self._run_ufw_command(['ufw', '--force', 'reset'])

    def _reload(self) -> Tuple[bool, str]:
        return self._run_ufw_command(['ufw', 'reload'])

    def _set_default(self, params: Dict) -> Tuple[bool, str]:
        direction = params.get('direction', 'incoming')
        policy = params.get('policy', 'deny')
        if direction not in ['incoming', 'outgoing', 'routed']:
            return False, f"Invalid direction: {direction}"
        if policy not in ['allow', 'deny', 'reject']:
            return False, f"Invalid policy: {policy}"
        return self._run_ufw_command(['ufw', 'default', policy, direction])

    def _set_logging(self, params: Dict) -> Tuple[bool, str]:
        level = params.get('level', 'low')
        if level not in ['off', 'low', 'medium', 'high', 'full']:
            return False, f"Invalid logging level: {level}"
        return self._run_ufw_command(['ufw', 'logging', level])

    def _execute_raw(self, params: Dict) -> Tuple[bool, str]:
        raw_cmd = params.get('command', '')
        if not raw_cmd or not raw_cmd.strip().startswith('ufw '):
            return False, "Only ufw commands are allowed"
        return self._run_ufw_command(raw_cmd.strip().split())

    def _run_ufw_command(self, cmd: List[str]) -> Tuple[bool, str]:
        try:
            self.logger.info(f"Executing: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            output = result.stdout.strip() + result.stderr.strip()
            return (result.returncode == 0, output or ("Command executed successfully" if result.returncode == 0 else "Command failed"))
        except subprocess.TimeoutExpired:
            return False, "Command timed out"
        except Exception as e:
            return False, str(e)


# ============================================================================
# CONFIGURATION
# ============================================================================

class AgentConfig:
    """Agent configuration"""

    def __init__(self, config_file: Optional[str] = None):
        self.server_url = os.getenv("SSH_GUARDIAN_SERVER", "http://localhost:8081")
        self.api_key = os.getenv("SSH_GUARDIAN_API_KEY", "")
        self.agent_id = os.getenv("SSH_GUARDIAN_AGENT_ID", self._generate_agent_id())
        self.hostname = socket.gethostname()
        self.check_interval = int(os.getenv("SSH_GUARDIAN_CHECK_INTERVAL", "30"))
        self.batch_size = int(os.getenv("SSH_GUARDIAN_BATCH_SIZE", "100"))
        self.heartbeat_interval = int(os.getenv("SSH_GUARDIAN_HEARTBEAT_INTERVAL", "60"))
        self.firewall_sync_interval = int(os.getenv("SSH_GUARDIAN_FIREWALL_SYNC_INTERVAL", "300"))
        self.auth_log_path = "/var/log/auth.log"
        self.state_file = "/var/lib/ssh-guardian/agent-state.json"
        self.log_file = "/var/log/ssh-guardian-agent.log"
        self.firewall_enabled = os.getenv("SSH_GUARDIAN_FIREWALL_ENABLED", "true").lower() == "true"

        if config_file and os.path.exists(config_file):
            self.load_from_file(config_file)

    def _generate_agent_id(self) -> str:
        return f"{socket.gethostname()}-{uuid.getnode()}"

    def load_from_file(self, config_file: str):
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)
                for key, value in config.items():
                    if hasattr(self, key):
                        setattr(self, key, value)
        except Exception as e:
            logging.error(f"Failed to load config from {config_file}: {e}")

    def save_to_file(self, config_file: str):
        config = {
            "server_url": self.server_url, "api_key": self.api_key, "agent_id": self.agent_id,
            "hostname": self.hostname, "check_interval": self.check_interval,
            "batch_size": self.batch_size, "heartbeat_interval": self.heartbeat_interval,
            "firewall_sync_interval": self.firewall_sync_interval, "firewall_enabled": self.firewall_enabled
        }
        os.makedirs(os.path.dirname(config_file), exist_ok=True)
        with open(config_file, 'w') as f:
            json.dump(config, f, indent=2)


# ============================================================================
# AGENT STATE
# ============================================================================

class AgentState:
    """Manages agent state"""

    def __init__(self, state_file: str):
        self.state_file = state_file
        self.last_inode = 0
        self.last_position = 0
        self.last_heartbeat = None
        self.total_logs_sent = 0
        self.total_batches_sent = 0
        self.agent_start_time = datetime.now().isoformat()
        self.load()

    def load(self):
        if os.path.exists(self.state_file):
            try:
                with open(self.state_file, 'r') as f:
                    data = json.load(f)
                    for key in ['last_inode', 'last_position', 'last_heartbeat', 'total_logs_sent', 'total_batches_sent', 'agent_start_time']:
                        if key in data:
                            setattr(self, key, data[key])
            except Exception as e:
                logging.error(f"Failed to load state: {e}")

    def save(self):
        try:
            os.makedirs(os.path.dirname(self.state_file), exist_ok=True)
            with open(self.state_file, 'w') as f:
                json.dump({
                    'last_inode': self.last_inode, 'last_position': self.last_position,
                    'last_heartbeat': self.last_heartbeat, 'total_logs_sent': self.total_logs_sent,
                    'total_batches_sent': self.total_batches_sent, 'agent_start_time': self.agent_start_time
                }, f, indent=2)
        except Exception as e:
            logging.error(f"Failed to save state: {e}")


# ============================================================================
# LOG COLLECTOR
# ============================================================================

class LogCollector:
    """Collects SSH authentication logs"""

    def __init__(self, auth_log_path: str, state: AgentState):
        self.auth_log_path = auth_log_path
        self.state = state

    def collect_new_logs(self) -> List[str]:
        if not os.path.exists(self.auth_log_path):
            logging.error(f"Auth log file not found: {self.auth_log_path}")
            return []

        try:
            current_inode = os.stat(self.auth_log_path).st_ino
            if current_inode != self.state.last_inode:
                logging.info(f"Log rotation detected")
                self.state.last_inode = current_inode
                self.state.last_position = 0

            with open(self.auth_log_path, 'r') as f:
                f.seek(self.state.last_position)
                new_lines = [line.strip() for line in f if line.strip() and self._is_ssh_related(line.strip())]
                self.state.last_position = f.tell()

            return new_lines
        except Exception as e:
            logging.error(f"Error collecting logs: {e}")
            return []

    def _is_ssh_related(self, line: str) -> bool:
        return any(kw in line for kw in ['sshd', 'ssh', 'Failed password', 'Accepted password', 'Accepted publickey', 'Invalid user', 'Connection closed'])


# ============================================================================
# API CLIENT
# ============================================================================

class GuardianAPIClient:
    """API client for SSH Guardian server"""

    def __init__(self, config: AgentConfig):
        self.config = config
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': f'SSH-Guardian-Agent/{self.config.agent_id}',
            'X-API-Key': self.config.api_key,
            'X-Agent-ID': self.config.agent_id
        })

    def register_agent(self) -> bool:
        try:
            payload = {
                'agent_id': self.config.agent_id,
                'hostname': self.config.hostname,
                'system_info': self._get_system_info(),
                'version': '3.0.0',
                'heartbeat_interval_sec': self.config.heartbeat_interval
            }
            response = self.session.post(f"{self.config.server_url}/api/agents/register", json=payload, timeout=30)

            if response.status_code in [200, 201]:
                data = response.json()
                logging.info(f"Agent registered: {data.get('message')}")
                if data.get('api_key'):
                    self.config.api_key = data['api_key']
                    self.session.headers['X-API-Key'] = self.config.api_key
                    try:
                        self.config.save_to_file('/etc/ssh-guardian/agent.json')
                    except:
                        pass
                return True
            logging.error(f"Registration failed: {response.status_code}")
            return False
        except Exception as e:
            logging.error(f"Registration error: {e}")
            return False

    def send_heartbeat(self, state: AgentState) -> bool:
        try:
            payload = {
                'agent_id': self.config.agent_id,
                'metrics': {
                    'cpu_usage_percent': self._get_cpu_usage(),
                    'memory_usage_percent': self._get_memory_usage(),
                    'disk_usage_percent': self._get_disk_usage(),
                    'uptime_seconds': self._get_uptime_seconds(state)
                },
                'status': 'online',
                'health_status': 'healthy'
            }
            response = self.session.post(f"{self.config.server_url}/api/agents/heartbeat", json=payload, timeout=10)
            if response.status_code == 200:
                state.last_heartbeat = datetime.now().isoformat()
                return True
            return False
        except Exception as e:
            logging.error(f"Heartbeat error: {e}")
            return False

    def submit_log_batch(self, log_lines: List[str]) -> bool:
        try:
            payload = {
                'batch_uuid': str(uuid.uuid4()),
                'agent_id': self.config.agent_id,
                'hostname': self.config.hostname,
                'log_lines': log_lines,
                'batch_size': len(log_lines),
                'source_filename': self.config.auth_log_path
            }
            response = self.session.post(f"{self.config.server_url}/api/agents/logs", json=payload, timeout=60)
            if response.status_code == 200:
                data = response.json()
                logging.info(f"Batch submitted: {len(log_lines)} logs, {data.get('events_created', 0)} events")
                return True
            return False
        except Exception as e:
            logging.error(f"Batch submission error: {e}")
            return False

    def submit_ufw_rules(self, ufw_data: Dict) -> bool:
        try:
            payload = {
                'agent_id': self.config.agent_id,
                'hostname': self.config.hostname,
                'ufw_data': ufw_data,
                'submitted_at': datetime.now().isoformat()
            }
            response = self.session.post(f"{self.config.server_url}/api/agents/ufw/sync", json=payload, timeout=60)
            if response.status_code == 200:
                data = response.json()
                logging.info(f"UFW synced: {data.get('rules_count', 0)} rules, status: {data.get('ufw_status', 'unknown')}")
                return True
            logging.error(f"UFW sync failed: {response.status_code}")
            return False
        except Exception as e:
            logging.error(f"UFW sync error: {e}")
            return False

    def get_pending_ufw_commands(self) -> List[Dict]:
        try:
            response = self.session.get(
                f"{self.config.server_url}/api/agents/ufw/commands",
                params={'agent_id': self.config.agent_id}, timeout=30
            )
            if response.status_code == 200:
                return response.json().get('commands', [])
            return []
        except Exception as e:
            logging.error(f"Error getting UFW commands: {e}")
            return []

    def report_command_result(self, command_id: str, success: bool, message: str) -> bool:
        try:
            payload = {
                'agent_id': self.config.agent_id,
                'command_id': command_id,
                'success': success,
                'message': message,
                'executed_at': datetime.now().isoformat()
            }
            response = self.session.post(f"{self.config.server_url}/api/agents/firewall/command-result", json=payload, timeout=30)
            return response.status_code == 200
        except Exception as e:
            logging.error(f"Error reporting command result: {e}")
            return False

    def _get_system_info(self) -> Dict:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
        except:
            ip = ''
        return {
            'os': platform.system(), 'os_version': platform.release(),
            'platform': platform.platform(), 'architecture': platform.machine(),
            'python_version': platform.python_version(), 'hostname': socket.gethostname(),
            'ip_addresses': [ip] if ip else []
        }

    def _get_cpu_usage(self) -> float:
        try:
            result = subprocess.run(['top', '-bn1'], capture_output=True, text=True, timeout=5)
            for line in result.stdout.split('\n'):
                if 'Cpu(s)' in line:
                    idle = float(line.split()[7].replace('%id,', ''))
                    return round(100 - idle, 2)
        except:
            pass
        return 0.0

    def _get_memory_usage(self) -> float:
        try:
            with open('/proc/meminfo', 'r') as f:
                lines = f.readlines()
                total = int(lines[0].split()[1])
                available = int(lines[2].split()[1])
                return round(((total - available) / total) * 100, 2)
        except:
            return 0.0

    def _get_disk_usage(self) -> float:
        try:
            result = subprocess.run(['df', '-h', '/'], capture_output=True, text=True, timeout=5)
            lines = result.stdout.split('\n')
            if len(lines) > 1:
                return float(lines[1].split()[4].replace('%', ''))
        except:
            pass
        return 0.0

    def _get_uptime_seconds(self, state: AgentState) -> int:
        try:
            return int((datetime.now() - datetime.fromisoformat(state.agent_start_time)).total_seconds())
        except:
            return 0


# ============================================================================
# MAIN AGENT
# ============================================================================

class SSHGuardianAgent:
    """Main SSH Guardian agent"""

    def __init__(self, config: AgentConfig):
        self.config = config
        self.state = AgentState(config.state_file)
        self.collector = LogCollector(config.auth_log_path, self.state)
        self.api_client = GuardianAPIClient(config)
        self.running = False
        self.ufw_manager = UFWManager() if config.firewall_enabled else None

    def setup_logging(self):
        log_dir = os.path.dirname(self.config.log_file)
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)

        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(self.config.log_file),
                logging.StreamHandler(sys.stdout)
            ]
        )

    def start(self):
        self.setup_logging()
        logging.info("=" * 70)
        logging.info("SSH Guardian Agent v3.0 Starting...")
        logging.info("=" * 70)
        logging.info(f"Agent ID: {self.config.agent_id}")
        logging.info(f"Hostname: {self.config.hostname}")
        logging.info(f"Server: {self.config.server_url}")
        logging.info(f"Firewall: {'UFW' if self.ufw_manager else 'Disabled'}")
        logging.info("=" * 70)

        if not self.api_client.register_agent():
            logging.error("Failed to register. Continuing anyway...")

        # Immediate UFW sync on startup
        if self.ufw_manager and self.config.firewall_enabled:
            logging.info("Performing initial UFW sync...")
            self._sync_firewall()

        self.running = True
        self.run()

    def run(self):
        last_heartbeat_time = time.time()
        last_firewall_sync_time = time.time()

        while self.running:
            try:
                new_logs = self.collector.collect_new_logs()
                if new_logs:
                    logging.info(f"Collected {len(new_logs)} new log lines")
                    for i in range(0, len(new_logs), self.config.batch_size):
                        batch = new_logs[i:i + self.config.batch_size]
                        if self.api_client.submit_log_batch(batch):
                            self.state.total_logs_sent += len(batch)
                            self.state.total_batches_sent += 1
                            self.state.save()

                current_time = time.time()

                if current_time - last_heartbeat_time >= self.config.heartbeat_interval:
                    if self.api_client.send_heartbeat(self.state):
                        last_heartbeat_time = current_time
                        self.state.save()

                if self.ufw_manager and self.config.firewall_enabled:
                    if current_time - last_firewall_sync_time >= self.config.firewall_sync_interval:
                        self._sync_firewall()
                        last_firewall_sync_time = current_time
                    self._process_firewall_commands()

                time.sleep(self.config.check_interval)

            except KeyboardInterrupt:
                logging.info("Received stop signal")
                self.stop()
            except Exception as e:
                logging.error(f"Error in agent loop: {e}")
                time.sleep(self.config.check_interval)

    def _sync_firewall(self):
        if not self.ufw_manager:
            return
        try:
            logging.info("Collecting UFW rules...")
            ufw_data = self.ufw_manager.collect_all()
            if 'error' not in ufw_data:
                self.api_client.submit_ufw_rules(ufw_data)
            else:
                logging.warning(f"UFW collection error: {ufw_data.get('error')}")
        except Exception as e:
            logging.error(f"Error syncing firewall: {e}")

    def _process_firewall_commands(self):
        if not self.ufw_manager:
            return
        try:
            commands = self.api_client.get_pending_ufw_commands()
            for cmd in commands:
                command_id = cmd.get('id')
                action = cmd.get('action') or cmd.get('command_type')
                params = cmd.get('params', {})

                logging.info(f"Processing UFW command: {action} (ID: {command_id})")
                success, message = self.ufw_manager.execute_command(action, params)
                self.api_client.report_command_result(command_id, success, message)

                if success:
                    logging.info(f"Command {command_id} executed: {message}")
                    self._sync_firewall()
                else:
                    logging.error(f"Command {command_id} failed: {message}")
        except Exception as e:
            logging.error(f"Error processing firewall commands: {e}")

    def stop(self):
        logging.info("Stopping SSH Guardian Agent...")
        self.running = False
        self.state.save()


# ============================================================================
# CLI
# ============================================================================

def main():
    parser = argparse.ArgumentParser(description='SSH Guardian v3.0 - Standalone Agent')
    parser.add_argument('--config', '-c', help='Configuration file path', default='/etc/ssh-guardian/agent.json')
    parser.add_argument('--server', '-s', help='SSH Guardian server URL')
    parser.add_argument('--api-key', '-k', help='API key for authentication')
    parser.add_argument('--agent-id', help='Custom agent ID')
    parser.add_argument('--check-interval', type=int, help='Log check interval (seconds)')
    parser.add_argument('--batch-size', type=int, help='Batch size for log submission')
    parser.add_argument('--no-firewall', action='store_true', help='Disable firewall management')

    args = parser.parse_args()

    config = AgentConfig(args.config if os.path.exists(args.config) else None)

    if args.server:
        config.server_url = args.server
    if args.api_key:
        config.api_key = args.api_key
    if args.agent_id:
        config.agent_id = args.agent_id
    if args.check_interval:
        config.check_interval = args.check_interval
    if args.batch_size:
        config.batch_size = args.batch_size
    if args.no_firewall:
        config.firewall_enabled = False

    if not config.api_key:
        print("Error: API key is required. Use --api-key or set SSH_GUARDIAN_API_KEY")
        sys.exit(1)

    agent = SSHGuardianAgent(config)
    agent.start()


if __name__ == "__main__":
    main()
